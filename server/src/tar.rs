// Unpack a .tar, .tar.gz or .zip bundle in memory (and pack a .tar.gz). Handles ustar prefixes, GNU long names and pax path records,
// and the stored and deflated entries of a zip (what Finder and Explorer make).
use flate2::read::{DeflateDecoder, MultiGzDecoder};
use std::io::Read;

use crate::problem::{Problem, Result};

pub const BUNDLE_BYTES: usize = 25 * 1024 * 1024;
pub const UNPACKED_BYTES: usize = 60 * 1024 * 1024;
pub const FILE_BYTES: usize = 10 * 1024 * 1024;
pub const MAX_FILES: usize = 2000;

#[derive(Debug, Clone)]
pub struct BundleFile {
    pub path: String,
    pub bytes: Vec<u8>,
}

fn cstr(b: &[u8], from: usize, len: usize) -> String {
    let field = &b[from..(from + len).min(b.len())];
    let end = field.iter().position(|x| *x == 0).unwrap_or(field.len());
    String::from_utf8_lossy(&field[..end]).into_owned()
}

/// parseInt(s, 8): the leading octal digits, or None when there are none.
fn octal(s: &str) -> Option<usize> {
    let s = s.trim();
    let digits: String = s.chars().take_while(|c| ('0'..='7').contains(c)).collect();
    if digits.is_empty() { None } else { usize::from_str_radix(&digits, 8).ok() }
}

fn gunzip(body: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut dec = MultiGzDecoder::new(body).take(UNPACKED_BYTES as u64 + 1);
    dec.read_to_end(&mut out).map_err(|_| Problem::new(400, "bad_bundle", "The upload is not a valid gzip file."))?;
    if out.len() > UNPACKED_BYTES {
        return Err(crate::http::too_large("The unpacked bundle", UNPACKED_BYTES));
    }
    Ok(out)
}

pub fn unpack(body: &[u8]) -> Result<Vec<BundleFile>> {
    if body.starts_with(b"PK\x03\x04") || body.starts_with(b"PK\x05\x06") {
        return unzip(body);
    }
    let owned;
    let tar: &[u8] = if body.len() >= 2 && body[0] == 0x1f && body[1] == 0x8b {
        owned = gunzip(body)?;
        &owned
    } else {
        body
    };
    if tar.len() < 512 || cstr(tar, 257, 5) != "ustar" {
        return Err(Problem::new(
            400,
            "bad_bundle",
            "The upload must be a zip, tar or tar.gz archive. Create one with: tar -czf - -C <build folder> .",
        ));
    }
    let mut files = Vec::new();
    let mut pos = 0usize;
    let mut long_name = String::new();
    while pos + 512 <= tar.len() {
        let h = &tar[pos..pos + 512];
        if h.iter().all(|x| *x == 0) {
            break;
        }
        // A size that does not parse ends the archive, as NaN does in tar.ts.
        let Some(size) = octal(&cstr(h, 124, 12)).or(if cstr(h, 124, 12).trim().is_empty() { Some(0) } else { None }) else {
            break;
        };
        let kind = if h[156] == 0 { b'0' } else { h[156] };
        let start = (pos + 512).min(tar.len());
        let data = &tar[start..(pos + 512).saturating_add(size).min(tar.len())];
        pos = pos.saturating_add(512).saturating_add(size.div_ceil(512).saturating_mul(512));
        match kind {
            b'L' => {
                long_name = cstr(data, 0, data.len());
                continue;
            }
            b'x' => {
                if let Some(p) = pax_path(data) {
                    long_name = p;
                }
                continue;
            }
            b'0' => {}
            _ => {
                long_name.clear();
                continue;
            }
        }
        let prefix = cstr(h, 345, 155);
        let name = if !long_name.is_empty() {
            std::mem::take(&mut long_name)
        } else if !prefix.is_empty() {
            format!("{prefix}/{}", cstr(h, 0, 100))
        } else {
            cstr(h, 0, 100)
        };
        files.push(BundleFile { path: name, bytes: data.to_vec() });
        if files.len() > MAX_FILES {
            return Err(Problem::new(413, "too_many_files", format!("A bundle can hold at most {MAX_FILES} files.")));
        }
    }
    Ok(files)
}

fn u16_at(b: &[u8], at: usize) -> Option<usize> {
    Some(u16::from_le_bytes(b.get(at..at + 2)?.try_into().ok()?) as usize)
}
fn u32_at(b: &[u8], at: usize) -> Option<usize> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?) as usize)
}

/// Read a zip through its central directory. Directories are skipped; encrypted and zip64 archives are refused.
fn unzip(body: &[u8]) -> Result<Vec<BundleFile>> {
    let bad = |m: &str| Problem::new(400, "bad_bundle", format!("The zip file {m}."));
    // The end-of-central-directory record sits in the last 22 bytes plus up to 64 KB of comment.
    let floor = body.len().saturating_sub(22 + 65_535);
    let eocd = (floor..=body.len().saturating_sub(22))
        .rev()
        .find(|&i| body[i..].starts_with(b"PK\x05\x06"))
        .ok_or_else(|| bad("is damaged: its table of contents is missing"))?;
    let count = u16_at(body, eocd + 10).unwrap_or(0);
    let mut at = u32_at(body, eocd + 16).unwrap_or(usize::MAX);
    if count == 0xffff || at == 0xffff_ffff {
        return Err(bad("uses zip64, which is not supported. Use a tar.gz instead"));
    }
    if count > MAX_FILES {
        return Err(Problem::new(413, "too_many_files", format!("A bundle can hold at most {MAX_FILES} files.")));
    }
    let mut files = Vec::new();
    let mut total = 0usize;
    for _ in 0..count {
        let h = body.get(at..at + 46).filter(|h| h.starts_with(b"PK\x01\x02")).ok_or_else(|| bad("is damaged"))?;
        let (flags, method) = (u16_at(h, 8).unwrap_or(0), u16_at(h, 10).unwrap_or(0));
        let (size, unpacked) = (u32_at(h, 20).unwrap_or(0), u32_at(h, 24).unwrap_or(0));
        let (name_len, extra_len, comment_len) = (u16_at(h, 28).unwrap_or(0), u16_at(h, 30).unwrap_or(0), u16_at(h, 32).unwrap_or(0));
        let local = u32_at(h, 42).unwrap_or(usize::MAX);
        let name = body.get(at + 46..at + 46 + name_len).ok_or_else(|| bad("is damaged"))?;
        // Bit 11 marks UTF-8 names; tools that leave it unset still almost always write UTF-8 or ASCII.
        let name = String::from_utf8_lossy(name).into_owned();
        at += 46 + name_len + extra_len + comment_len;
        if name.ends_with('/') {
            continue;
        }
        if flags & 1 != 0 {
            return Err(bad("is password-protected"));
        }
        if size == 0xffff_ffff || unpacked == 0xffff_ffff {
            return Err(bad("uses zip64, which is not supported. Use a tar.gz instead"));
        }
        let lh = body.get(local..local + 30).filter(|h| h.starts_with(b"PK\x03\x04")).ok_or_else(|| bad("is damaged"))?;
        let start = local + 30 + u16_at(lh, 26).unwrap_or(0) + u16_at(lh, 28).unwrap_or(0);
        let data = body.get(start..start.saturating_add(size)).ok_or_else(|| bad("is damaged"))?;
        let cap = FILE_BYTES.min(UNPACKED_BYTES - total) + 1;
        let bytes = match method {
            0 => data.to_vec(),
            8 => {
                let mut out = Vec::with_capacity(unpacked.min(cap));
                DeflateDecoder::new(data).take(cap as u64).read_to_end(&mut out).map_err(|_| bad("is damaged"))?;
                out
            }
            _ => return Err(bad(&format!("uses a compression method ({method}) Brod cannot read. Use a tar.gz instead"))),
        };
        total += bytes.len();
        if total > UNPACKED_BYTES {
            return Err(crate::http::too_large("The unpacked bundle", UNPACKED_BYTES));
        }
        files.push(BundleFile { path: name, bytes });
    }
    Ok(files)
}

/// The path record of a pax extended header: `/(?:^|\n)\d+ path=([^\n]*)\n/`.
fn pax_path(data: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(data);
    let mut rest: &str = &text;
    loop {
        let line_end = rest.find('\n')?;
        let line = &rest[..line_end];
        if let Some((len, kv)) = line.split_once(' ')
            && !len.is_empty()
            && len.chars().all(|c| c.is_ascii_digit())
            && let Some(p) = kv.strip_prefix("path=")
        {
            return Some(p.to_string());
        }
        rest = &rest[line_end + 1..];
    }
}

/// One ustar header block.
fn header(name: &[u8], size: usize, kind: u8, mtime_ms: i64) -> [u8; 512] {
    let mut h = [0u8; 512];
    let put = |h: &mut [u8; 512], s: &[u8], at: usize| h[at..at + s.len()].copy_from_slice(s);
    put(&mut h, &name[..name.len().min(100)], 0);
    put(&mut h, b"0000644\0", 100);
    put(&mut h, b"0000000\0", 108);
    put(&mut h, b"0000000\0", 116);
    put(&mut h, format!("{size:011o}\0").as_bytes(), 124);
    put(&mut h, format!("{:011o}\0", (mtime_ms / 1000).max(0)).as_bytes(), 136);
    h[156] = kind;
    put(&mut h, b"ustar\0", 257);
    put(&mut h, b"00", 263);
    put(&mut h, b"        ", 148);
    let sum: u32 = h.iter().map(|x| *x as u32).sum();
    put(&mut h, format!("{sum:06o}\0 ").as_bytes(), 148);
    h
}

/// A tar.gz of the files, the way `tar -czf` would write them, every file dated `mtime_ms`. A path longer than a ustar
/// header holds gets a pax path record.
pub fn pack(files: &[BundleFile], mtime_ms: i64) -> Vec<u8> {
    use std::io::Write;
    let mut tar = Vec::new();
    let add = |tar: &mut Vec<u8>, data: &[u8]| {
        tar.extend_from_slice(data);
        tar.resize(tar.len().div_ceil(512) * 512, 0);
    };
    for f in files {
        let name = f.path.as_bytes();
        if name.len() > 100 {
            // A pax record is "<length> path=<path>\n", where the length counts itself.
            let body = format!(" path={}\n", f.path);
            let mut len = body.len() + 1;
            while len.to_string().len() + body.len() != len {
                len += 1;
            }
            let record = format!("{len}{body}");
            tar.extend_from_slice(&header(b"PaxHeader", record.len(), b'x', mtime_ms));
            add(&mut tar, record.as_bytes());
        }
        tar.extend_from_slice(&header(name, f.bytes.len(), b'0', mtime_ms));
        add(&mut tar, &f.bytes);
    }
    tar.extend_from_slice(&[0u8; 1024]);
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(&tar).expect("writing to memory");
    e.finish().expect("writing to memory")
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write;

    pub struct Entry<'a> {
        pub name: &'a str,
        pub content: &'a [u8],
        pub prefix: Option<&'a str>,
        pub kind: u8,
    }
    pub fn entry<'a>(name: &'a str, content: &'a str) -> Entry<'a> {
        Entry { name, content: content.as_bytes(), prefix: None, kind: b'0' }
    }

    /// Build a ustar archive in memory, the way `tar -c` would.
    pub fn tar(files: &[Entry]) -> Vec<u8> {
        let mut out = Vec::new();
        for f in files {
            let mut h = [0u8; 512];
            let put = |h: &mut [u8; 512], s: &[u8], at: usize| h[at..at + s.len()].copy_from_slice(s);
            put(&mut h, f.name.as_bytes(), 0);
            put(&mut h, b"0000644\0", 100);
            put(&mut h, b"0000000\0", 108);
            put(&mut h, b"0000000\0", 116);
            put(&mut h, format!("{:011o}\0", f.content.len()).as_bytes(), 124);
            put(&mut h, b"00000000000\0", 136);
            h[156] = f.kind;
            put(&mut h, b"ustar\0", 257);
            put(&mut h, b"00", 263);
            if let Some(p) = f.prefix {
                put(&mut h, p.as_bytes(), 345);
            }
            put(&mut h, b"        ", 148);
            let sum: u32 = h.iter().map(|x| *x as u32).sum();
            put(&mut h, format!("{sum:06o}\0 ").as_bytes(), 148);
            out.extend_from_slice(&h);
            let mut data = f.content.to_vec();
            data.resize(f.content.len().div_ceil(512) * 512, 0);
            out.extend_from_slice(&data);
        }
        out.extend_from_slice(&[0u8; 1024]);
        out
    }
    pub fn gzip(b: &[u8]) -> Vec<u8> {
        let mut e = GzEncoder::new(Vec::new(), Compression::default());
        e.write_all(b).unwrap();
        e.finish().unwrap()
    }

    #[test]
    fn packs_what_it_unpacks_long_paths_included() {
        let long = format!("deep/{}.txt", "a".repeat(120));
        let files = vec![
            BundleFile { path: "index.html".into(), bytes: b"<h1>hi</h1>".to_vec() },
            BundleFile { path: long.clone(), bytes: vec![0, 159, 255] },
        ];
        let back = unpack(&pack(&files, 1_700_000_000_000)).unwrap();
        assert_eq!(back.iter().map(|f| f.path.as_str()).collect::<Vec<_>>(), ["index.html", long.as_str()]);
        assert_eq!(back[1].bytes, [0, 159, 255]);
    }

    #[test]
    fn reads_a_tar_gz_with_a_ustar_prefix_and_skips_directories() {
        let files = unpack(&gzip(&tar(&[
            Entry { name: "dist/", content: b"", prefix: None, kind: b'5' },
            Entry { name: "index.html", content: b"<h1>hi</h1>", prefix: Some("dist"), kind: b'0' },
            entry("dist/app.js", "console.log(1)"),
        ])))
        .unwrap();
        assert_eq!(files.iter().map(|f| f.path.as_str()).collect::<Vec<_>>(), ["dist/index.html", "dist/app.js"]);
        assert_eq!(files[0].bytes, b"<h1>hi</h1>");
    }

    #[test]
    fn reads_gnu_long_names_and_pax_paths() {
        let long = format!("d/{}.txt", "n".repeat(150));
        let files =
            unpack(&tar(&[Entry { name: "././@LongLink", content: long.as_bytes(), prefix: None, kind: b'L' }, entry("ignored", "long")]))
                .unwrap();
        assert_eq!(files[0].path, long);
        let pax = format!("30 mtime=1700000000.123456789\n{} path={long}\n", long.len() + 7 + 4);
        let files =
            unpack(&tar(&[Entry { name: "PaxHeader", content: pax.as_bytes(), prefix: None, kind: b'x' }, entry("short", "x")])).unwrap();
        assert_eq!(files[0].path, long);
    }

    /// Build a zip in memory: stored or deflated entries, a central directory and its end record.
    pub fn zip(files: &[(&str, &[u8], bool)]) -> Vec<u8> {
        use flate2::write::DeflateEncoder;
        let (mut out, mut dir) = (Vec::new(), Vec::new());
        for (name, content, deflate) in files {
            let data = if *deflate {
                let mut e = DeflateEncoder::new(Vec::new(), Compression::default());
                e.write_all(content).unwrap();
                e.finish().unwrap()
            } else {
                content.to_vec()
            };
            let method: u16 = if *deflate { 8 } else { 0 };
            let offset = out.len() as u32;
            let common = |v: &mut Vec<u8>| {
                v.extend_from_slice(&0u16.to_le_bytes()); // flags
                v.extend_from_slice(&method.to_le_bytes());
                v.extend_from_slice(&[0; 8]); // time, date, crc
                v.extend_from_slice(&(data.len() as u32).to_le_bytes());
                v.extend_from_slice(&(content.len() as u32).to_le_bytes());
                v.extend_from_slice(&(name.len() as u16).to_le_bytes());
                v.extend_from_slice(&0u16.to_le_bytes()); // extra
            };
            out.extend_from_slice(b"PK\x03\x04\x14\x00");
            common(&mut out);
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(&data);
            dir.extend_from_slice(b"PK\x01\x02\x14\x00\x14\x00");
            common(&mut dir);
            dir.extend_from_slice(&[0; 6]); // comment, disk, internal attrs
            dir.extend_from_slice(&[0; 4]); // external attrs
            dir.extend_from_slice(&offset.to_le_bytes());
            dir.extend_from_slice(name.as_bytes());
        }
        let at = out.len() as u32;
        out.extend_from_slice(&dir);
        out.extend_from_slice(b"PK\x05\x06\0\0\0\0");
        out.extend_from_slice(&(files.len() as u16).to_le_bytes());
        out.extend_from_slice(&(files.len() as u16).to_le_bytes());
        out.extend_from_slice(&(dir.len() as u32).to_le_bytes());
        out.extend_from_slice(&at.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out
    }

    #[test]
    fn reads_a_zip_with_stored_and_deflated_entries() {
        let html = "<h1>hi</h1>".repeat(100);
        let files =
            unpack(&zip(&[("site/", b"", false), ("site/index.html", html.as_bytes(), true), ("site/a.txt", b"plain", false)])).unwrap();
        assert_eq!(files.iter().map(|f| f.path.as_str()).collect::<Vec<_>>(), ["site/index.html", "site/a.txt"]);
        assert_eq!(files[0].bytes, html.as_bytes());
        assert_eq!(files[1].bytes, b"plain");
    }

    #[test]
    fn refuses_damaged_and_locked_zips() {
        let mut z = zip(&[("index.html", b"x", false)]);
        z.truncate(z.len() - 10);
        assert_eq!(unpack(&z).unwrap_err().code, "bad_bundle");
        let mut locked = zip(&[("index.html", b"x", false)]);
        let dir = locked.windows(4).position(|w| w == b"PK\x01\x02").unwrap();
        locked[dir + 8] = 1;
        assert!(unpack(&locked).unwrap_err().message.contains("password"));
        let big = vec![b'a'; FILE_BYTES + 10];
        assert!(unpack(&zip(&[("big.bin", &big, true)])).unwrap()[0].bytes.len() == FILE_BYTES + 1);
    }

    #[test]
    fn refuses_what_is_not_an_archive() {
        assert_eq!(unpack(b"not a tar").unwrap_err().code, "bad_bundle");
        assert_eq!(unpack(&[0x1f, 0x8b, 1, 2, 3]).unwrap_err().code, "bad_bundle");
    }

    #[test]
    fn enforces_the_limits() {
        let many: Vec<String> = (0..=MAX_FILES).map(|i| format!("f{i}.txt")).collect();
        let entries: Vec<Entry> = many.iter().map(|n| entry(n, "x")).collect();
        assert_eq!(unpack(&tar(&entries)).unwrap_err().code, "too_many_files");
        let big = vec![b'a'; UNPACKED_BYTES + 1];
        let err = unpack(&gzip(&tar(&[Entry { name: "big.txt", content: &big, prefix: None, kind: b'0' }]))).unwrap_err();
        assert_eq!((err.status, err.code.as_str(), err.message.as_str()), (413, "too_large", "The unpacked bundle is larger than 60 MB."));
    }
}
