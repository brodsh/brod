// SPDX-License-Identifier: AGPL-3.0-only
// The git formats Brod speaks, written from the format documentation with no git library and no git binary: object
// ids, trees, commits, pack files (writing undeltified packs, reading packs with OFS_DELTA and REF_DELTA), git bundles
// and pkt-lines. The mapping from Brod versions to commits is in git_export.rs; reading a repository in git_import.rs.
use std::collections::HashMap;
use std::io::Write;

use flate2::write::ZlibEncoder;
use flate2::{Compression, Decompress, FlushDecompress, Status};
use sha1::{Digest, Sha1};

pub type Oid = [u8; 20];

pub fn hex(oid: &Oid) -> String {
    hex::encode(oid)
}

pub fn parse_oid(s: &str) -> Option<Oid> {
    if s.len() != 40 {
        return None;
    }
    let mut out = [0u8; 20];
    hex::decode_to_slice(s, &mut out).ok()?;
    Some(out)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Commit = 1,
    Tree = 2,
    Blob = 3,
    Tag = 4,
}

impl Kind {
    pub fn name(self) -> &'static str {
        match self {
            Kind::Commit => "commit",
            Kind::Tree => "tree",
            Kind::Blob => "blob",
            Kind::Tag => "tag",
        }
    }
    fn from_type(t: u8) -> Option<Kind> {
        match t {
            1 => Some(Kind::Commit),
            2 => Some(Kind::Tree),
            3 => Some(Kind::Blob),
            4 => Some(Kind::Tag),
            _ => None,
        }
    }
}

/// The id of an object: sha1 of `"<kind> <length>\0"` and its content.
pub fn object_oid(kind: Kind, data: &[u8]) -> Oid {
    let mut h = Sha1::new();
    h.update(format!("{} {}\0", kind.name(), data.len()).as_bytes());
    h.update(data);
    h.finalize().into()
}

pub fn blob_oid(data: &[u8]) -> Oid {
    object_oid(Kind::Blob, data)
}

// ---------- trees ----------

pub const MODE_FILE: u32 = 0o100644;
pub const MODE_EXEC: u32 = 0o100755;
pub const MODE_DIR: u32 = 0o040000;
pub const MODE_SYMLINK: u32 = 0o120000;
pub const MODE_GITLINK: u32 = 0o160000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TreeEntry {
    pub mode: u32,
    pub name: String,
    pub oid: Oid,
}

impl TreeEntry {
    pub fn is_dir(&self) -> bool {
        self.mode == MODE_DIR
    }
}

/// A tree object's content. Git sorts entries by name as bytes, comparing a directory as if its name ended in "/".
pub fn encode_tree(entries: &mut [TreeEntry]) -> Vec<u8> {
    let key = |e: &TreeEntry| {
        let mut k = e.name.as_bytes().to_vec();
        if e.is_dir() {
            k.push(b'/');
        }
        k
    };
    entries.sort_by_key(key);
    let mut out = Vec::new();
    for e in entries.iter() {
        out.extend_from_slice(format!("{:o} ", e.mode).as_bytes());
        out.extend_from_slice(e.name.as_bytes());
        out.push(0);
        out.extend_from_slice(&e.oid);
    }
    out
}

pub fn parse_tree(data: &[u8]) -> Result<Vec<TreeEntry>, String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < data.len() {
        let sp = data[i..].iter().position(|b| *b == b' ').ok_or("a tree entry has no mode")? + i;
        let nul = data[sp..].iter().position(|b| *b == 0).ok_or("a tree entry has no name")? + sp;
        let mode =
            std::str::from_utf8(&data[i..sp]).ok().and_then(|m| u32::from_str_radix(m, 8).ok()).ok_or("a tree entry has a bad mode")?;
        let name = String::from_utf8(data[sp + 1..nul].to_vec()).map_err(|_| "a file name in the repository is not valid UTF-8")?;
        let end = nul + 21;
        if end > data.len() {
            return Err("a tree is cut short".into());
        }
        let mut oid = [0u8; 20];
        oid.copy_from_slice(&data[nul + 1..end]);
        out.push(TreeEntry { mode, name, oid });
        i = end;
    }
    Ok(out)
}

// ---------- commits ----------

pub struct Ident {
    pub name: String,
    pub email: String,
    /// Seconds since the epoch, always written in UTC (+0000).
    pub time: i64,
}

impl Ident {
    fn line(&self) -> String {
        format!("{} <{}> {} +0000", clean_ident(&self.name), clean_ident(&self.email), self.time)
    }
}

/// Names and addresses may not contain the characters that delimit them.
fn clean_ident(s: &str) -> String {
    s.chars().filter(|c| !matches!(c, '<' | '>' | '\n' | '\r' | '\0')).collect::<String>().trim().to_string()
}

pub fn encode_commit(tree: &Oid, parents: &[Oid], author: &Ident, committer: &Ident, message: &str) -> Vec<u8> {
    let mut s = format!("tree {}\n", hex(tree));
    for p in parents {
        s.push_str(&format!("parent {}\n", hex(p)));
    }
    s.push_str(&format!("author {}\ncommitter {}\n\n{message}", author.line(), committer.line()));
    s.into_bytes()
}

pub struct ParsedCommit {
    pub tree: Oid,
    pub parents: Vec<Oid>,
    pub message: String,
}

pub fn parse_commit(data: &[u8]) -> Result<ParsedCommit, String> {
    let split = data.windows(2).position(|w| w == b"\n\n");
    let (head, message) = match split {
        Some(i) => (&data[..i], &data[i + 2..]),
        None => (data, &data[data.len()..]),
    };
    let head = String::from_utf8_lossy(head);
    let (mut tree, mut parents) = (None, Vec::new());
    for line in head.lines() {
        if let Some(t) = line.strip_prefix("tree ") {
            tree = parse_oid(t.trim());
        } else if let Some(p) = line.strip_prefix("parent ") {
            parents.push(parse_oid(p.trim()).ok_or("a commit has a bad parent id")?);
        }
    }
    Ok(ParsedCommit { tree: tree.ok_or("a commit has no tree")?, parents, message: String::from_utf8_lossy(message).into_owned() })
}

// ---------- pack files ----------

impl Default for PackWriter {
    fn default() -> Self {
        PackWriter::new()
    }
}

/// Writes a pack (version 2) of undeltified objects.
pub struct PackWriter {
    out: Vec<u8>,
    count: u32,
}

impl PackWriter {
    pub fn new() -> PackWriter {
        let mut out = Vec::new();
        out.extend_from_slice(b"PACK");
        out.extend_from_slice(&2u32.to_be_bytes());
        // The object count is filled in by `finish`.
        out.extend_from_slice(&0u32.to_be_bytes());
        PackWriter { out, count: 0 }
    }

    pub fn add(&mut self, kind: Kind, data: &[u8]) {
        self.count += 1;
        let mut size = data.len();
        let mut byte = ((kind as u8) << 4) | (size & 0x0f) as u8;
        size >>= 4;
        while size > 0 {
            self.out.push(byte | 0x80);
            byte = (size & 0x7f) as u8;
            size >>= 7;
        }
        self.out.push(byte);
        let mut z = ZlibEncoder::new(std::mem::take(&mut self.out), Compression::fast());
        // Writing to a Vec cannot fail.
        let _ = z.write_all(data);
        self.out = z.finish().unwrap_or_default();
    }

    pub fn finish(mut self) -> Vec<u8> {
        self.out[8..12].copy_from_slice(&self.count.to_be_bytes());
        let sum: Oid = Sha1::digest(&self.out).into();
        self.out.extend_from_slice(&sum);
        self.out
    }
}

/// A git bundle (format v2): the refs it carries, then a pack of everything they reach. `git clone x.bundle` and
/// `git bundle verify` read it.
pub fn bundle(refs: &[(String, Oid)], pack: &[u8]) -> Vec<u8> {
    let mut out = b"# v2 git bundle\n".to_vec();
    for (name, oid) in refs {
        out.extend_from_slice(format!("{} {name}\n", hex(oid)).as_bytes());
    }
    out.push(b'\n');
    out.extend_from_slice(pack);
    out
}

#[derive(Debug)]
pub struct ParsedBundle<'a> {
    pub refs: Vec<(String, Oid)>,
    pub pack: &'a [u8],
}

/// Read a bundle's header. A bundle that needs commits the reader does not have (prerequisites) is refused: Brod
/// cannot complete it, so ask for a bundle of the whole history.
pub fn parse_bundle(data: &[u8]) -> Result<ParsedBundle<'_>, String> {
    let mut pos = 0;
    let line = |pos: &mut usize| -> Option<&[u8]> {
        let rest = &data[*pos..];
        let end = rest.iter().position(|b| *b == b'\n')?;
        *pos += end + 1;
        Some(&rest[..end])
    };
    let first = line(&mut pos).ok_or("that is not a git bundle")?;
    let v3 = match first {
        b"# v2 git bundle" => false,
        b"# v3 git bundle" => true,
        _ => return Err("that is not a git bundle (it does not start with \"# v2 git bundle\")".into()),
    };
    let mut refs = Vec::new();
    loop {
        let l = line(&mut pos).ok_or("the bundle header is cut short")?;
        if l.is_empty() {
            break;
        }
        if v3 && l.starts_with(b"@") {
            continue;
        }
        let l = std::str::from_utf8(l).map_err(|_| "the bundle header is not text")?;
        if l.starts_with('-') {
            return Err("this bundle does not contain the whole history (it has prerequisites). Create it with all the history, for example `git bundle create app.bundle main`, or import a version Brod gave you plus your commits with the url option.".into());
        }
        let (oid, name) = l.split_once(' ').ok_or("a bundle ref line is malformed")?;
        refs.push((name.to_string(), parse_oid(oid).ok_or("a bundle ref has a bad id")?));
    }
    Ok(ParsedBundle { refs, pack: &data[pos..] })
}

/// What reading a pack may allocate.
pub struct PackLimits {
    pub max_objects: usize,
    /// The largest single object, and the largest result of applying a delta.
    pub max_object_bytes: usize,
    /// All objects together, once unpacked.
    pub max_total_bytes: usize,
}

pub type Objects = HashMap<Oid, (Kind, Vec<u8>)>;

enum Raw {
    Base(Kind, Vec<u8>),
    Ofs(usize, Vec<u8>),
    Ref(Oid, Vec<u8>),
}

fn varint_size(data: &[u8], pos: &mut usize) -> Result<usize, String> {
    let mut size = 0usize;
    let mut shift = 0;
    loop {
        let b = *data.get(*pos).ok_or("a delta is cut short")?;
        *pos += 1;
        if shift > 56 {
            return Err("a delta size is too large".into());
        }
        size |= ((b & 0x7f) as usize) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            return Ok(size);
        }
    }
}

pub fn apply_delta(base: &[u8], delta: &[u8], max: usize) -> Result<Vec<u8>, String> {
    let mut i = 0;
    let src = varint_size(delta, &mut i)?;
    let dst = varint_size(delta, &mut i)?;
    if src != base.len() {
        return Err("a delta does not match its base object".into());
    }
    if dst > max {
        return Err("an object in the repository is too large".into());
    }
    let mut out = Vec::with_capacity(dst);
    while i < delta.len() {
        let op = delta[i];
        i += 1;
        if op & 0x80 != 0 {
            let (mut off, mut len) = (0usize, 0usize);
            for bit in 0..4 {
                if op & (1 << bit) != 0 {
                    off |= (*delta.get(i).ok_or("a delta is cut short")? as usize) << (8 * bit);
                    i += 1;
                }
            }
            for bit in 0..3 {
                if op & (0x10 << bit) != 0 {
                    len |= (*delta.get(i).ok_or("a delta is cut short")? as usize) << (8 * bit);
                    i += 1;
                }
            }
            if len == 0 {
                len = 0x10000;
            }
            let end = off.checked_add(len).filter(|e| *e <= base.len()).ok_or("a delta copies past its base object")?;
            out.extend_from_slice(&base[off..end]);
        } else if op != 0 {
            let end = i + op as usize;
            out.extend_from_slice(delta.get(i..end).ok_or("a delta is cut short")?);
            i = end;
        } else {
            return Err("a delta has an invalid instruction".into());
        }
        if out.len() > dst {
            return Err("a delta produces more than it declares".into());
        }
    }
    if out.len() != dst {
        return Err("a delta produces less than it declares".into());
    }
    Ok(out)
}

/// Inflate one zlib stream at the start of `input`; returns the data and how many input bytes it used.
fn inflate(input: &[u8], expected: usize) -> Result<(Vec<u8>, usize), String> {
    let mut d = Decompress::new(true);
    let mut out: Vec<u8> = Vec::with_capacity(expected + 64);
    loop {
        let (before_in, before_out) = (d.total_in(), d.total_out());
        let status = d
            .decompress_vec(&input[before_in as usize..], &mut out, FlushDecompress::None)
            .map_err(|_| "the pack contains data that does not decompress")?;
        if out.len() > expected {
            return Err("an object in the pack is larger than it declares".into());
        }
        match status {
            Status::StreamEnd => break,
            _ => {
                if d.total_in() == before_in && d.total_out() == before_out {
                    return Err("the pack is cut short".into());
                }
            }
        }
    }
    if out.len() != expected {
        return Err("an object in the pack is smaller than it declares".into());
    }
    Ok((out, d.total_in() as usize))
}

/// Read a whole pack, resolving deltas, into its objects by id. The trailing checksum is verified.
pub fn read_pack(data: &[u8], lim: &PackLimits) -> Result<Objects, String> {
    if data.len() < 32 || &data[..4] != b"PACK" {
        return Err("the data is not a git pack".into());
    }
    let version = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    if version != 2 && version != 3 {
        return Err(format!("pack version {version} is not supported"));
    }
    let count = u32::from_be_bytes([data[8], data[9], data[10], data[11]]) as usize;
    if count > lim.max_objects {
        return Err(format!("the pack has {count} objects; at most {} are accepted", lim.max_objects));
    }
    let body_end = data.len() - 20;
    let sum: Oid = Sha1::digest(&data[..body_end]).into();
    if sum[..] != data[body_end..] {
        return Err("the pack's checksum does not match (it is damaged or incomplete)".into());
    }
    let mut pos = 12;
    let mut raws: Vec<(usize, Raw)> = Vec::with_capacity(count);
    let mut total = 0usize;
    for _ in 0..count {
        let start = pos;
        let mut b = *data.get(pos).ok_or("the pack is cut short")?;
        pos += 1;
        let ty = (b >> 4) & 7;
        let mut size = (b & 0x0f) as usize;
        let mut shift = 4;
        while b & 0x80 != 0 {
            b = *data.get(pos).ok_or("the pack is cut short")?;
            pos += 1;
            if shift > 56 {
                return Err("an object size in the pack is too large".into());
            }
            size |= ((b & 0x7f) as usize) << shift;
            shift += 7;
        }
        if size > lim.max_object_bytes {
            return Err("an object in the repository is too large".into());
        }
        total = total.saturating_add(size);
        if total > lim.max_total_bytes {
            return Err("the repository is too large to import".into());
        }
        let kind = match ty {
            6 => {
                let mut c = *data.get(pos).ok_or("the pack is cut short")?;
                pos += 1;
                let mut off = (c & 0x7f) as usize;
                while c & 0x80 != 0 {
                    c = *data.get(pos).ok_or("the pack is cut short")?;
                    pos += 1;
                    off = off.checked_add(1).and_then(|o| o.checked_mul(128)).ok_or("a delta offset is too large")? | (c & 0x7f) as usize;
                }
                let base = start.checked_sub(off).filter(|_| off > 0).ok_or("a delta points before the pack")?;
                (None, Some(base), None)
            }
            7 => {
                let mut oid = [0u8; 20];
                oid.copy_from_slice(data.get(pos..pos + 20).ok_or("the pack is cut short")?);
                pos += 20;
                (None, None, Some(oid))
            }
            t => (Some(Kind::from_type(t).ok_or("the pack has an object of an unknown type")?), None, None),
        };
        let (bytes, used) = inflate(&data[pos..body_end], size)?;
        pos += used;
        raws.push((
            start,
            match kind {
                (Some(k), _, _) => Raw::Base(k, bytes),
                (_, Some(off), _) => Raw::Ofs(off, bytes),
                (_, _, Some(oid)) => Raw::Ref(oid, bytes),
                _ => unreachable!("every entry has a kind"),
            },
        ));
    }
    if pos != body_end {
        return Err("the pack has data after its last object".into());
    }

    // Resolve: bases first, then deltas whose base is known, until nothing more resolves.
    let mut by_offset: HashMap<usize, (Kind, Vec<u8>)> = HashMap::new();
    let mut objects: Objects = HashMap::new();
    let mut pending: Vec<(usize, Raw)> = Vec::new();
    for (off, raw) in raws {
        match raw {
            Raw::Base(k, bytes) => {
                objects.insert(object_oid(k, &bytes), (k, bytes.clone()));
                by_offset.insert(off, (k, bytes));
            }
            other => pending.push((off, other)),
        }
    }
    while !pending.is_empty() {
        let before = pending.len();
        let mut next = Vec::new();
        for (off, raw) in pending {
            let base = match &raw {
                Raw::Ofs(b, _) => by_offset.get(b).cloned(),
                Raw::Ref(oid, _) => objects.get(oid).cloned(),
                Raw::Base(..) => None,
            };
            match (base, raw) {
                (Some((k, base)), Raw::Ofs(_, delta) | Raw::Ref(_, delta)) => {
                    let bytes = apply_delta(&base, &delta, lim.max_object_bytes)?;
                    total = total.saturating_add(bytes.len());
                    if total > lim.max_total_bytes {
                        return Err("the repository is too large to import".into());
                    }
                    objects.insert(object_oid(k, &bytes), (k, bytes.clone()));
                    by_offset.insert(off, (k, bytes));
                }
                (_, raw) => next.push((off, raw)),
            }
        }
        if next.len() == before {
            return Err("the pack has deltas whose base object is missing (a shallow or partial fetch it could not complete)".into());
        }
        pending = next;
    }
    Ok(objects)
}

// ---------- pkt-lines ----------

pub fn pkt(data: &[u8]) -> Vec<u8> {
    let mut out = format!("{:04x}", data.len() + 4).into_bytes();
    out.extend_from_slice(data);
    out
}

pub const FLUSH: &[u8] = b"0000";

pub enum Pkt<'a> {
    Flush,
    Data(&'a [u8]),
}

/// The next pkt-line at `pos`, or None at the end of `buf`.
pub fn read_pkt<'a>(buf: &'a [u8], pos: &mut usize) -> Result<Option<Pkt<'a>>, String> {
    if *pos >= buf.len() {
        return Ok(None);
    }
    let head = buf.get(*pos..*pos + 4).ok_or("a pkt-line is cut short")?;
    let len = std::str::from_utf8(head).ok().and_then(|h| usize::from_str_radix(h, 16).ok()).ok_or("a pkt-line has a bad length")?;
    *pos += 4;
    if len == 0 {
        return Ok(Some(Pkt::Flush));
    }
    if len < 4 {
        // 0001 (delimiter) and 0002 (response end) belong to protocol v2, which Brod does not speak.
        return Err("a pkt-line has an unsupported length".into());
    }
    let body = buf.get(*pos..*pos + len - 4).ok_or("a pkt-line is cut short")?;
    *pos += len - 4;
    Ok(Some(Pkt::Data(body)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(mode: u32, name: &str, oid: Oid) -> TreeEntry {
        TreeEntry { mode, name: name.into(), oid }
    }

    #[test]
    fn blob_and_empty_tree_ids_match_git() {
        assert_eq!(hex(&blob_oid(b"")), "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391");
        assert_eq!(hex(&blob_oid(b"hello\n")), "ce013625030ba8dba906f756967f9e9ca394464a");
        assert_eq!(hex(&object_oid(Kind::Tree, b"")), "4b825dc642cb6eb9a060e54bf8d69288fbee4904");
    }

    #[test]
    fn trees_sort_a_directory_as_if_it_ended_in_a_slash() {
        let z = [0u8; 20];
        // "a.b" < "a/" because '.' (0x2e) < '/' (0x2f), though "a" < "a.b" as plain names.
        let mut e = vec![entry(MODE_DIR, "a", z), entry(MODE_FILE, "a.b", z), entry(MODE_FILE, "a0", z), entry(MODE_FILE, "B", z)];
        let encoded = encode_tree(&mut e);
        let names: Vec<&str> = e.iter().map(|x| x.name.as_str()).collect();
        assert_eq!(names, ["B", "a.b", "a", "a0"]);
        let back = parse_tree(&encoded).unwrap();
        assert_eq!(back, e);
        assert!(encoded.starts_with(b"100644 B\0"));
        assert!(encoded.windows(8).any(|w| w == b"40000 a\0"), "directories have no leading zero");
    }

    #[test]
    fn a_pack_round_trips_and_a_bundle_has_the_v2_header() {
        let mut w = PackWriter::new();
        w.add(Kind::Blob, b"hello\n");
        w.add(Kind::Blob, &vec![b'x'; 100_000]);
        w.add(Kind::Blob, b"");
        let pack = w.finish();
        let lim = PackLimits { max_objects: 10, max_object_bytes: 1 << 20, max_total_bytes: 1 << 22 };
        let objs = read_pack(&pack, &lim).unwrap();
        assert_eq!(objs.len(), 3);
        assert_eq!(objs[&blob_oid(b"hello\n")].1, b"hello\n");
        let mut bad = pack.clone();
        bad[20] ^= 1;
        assert!(read_pack(&bad, &lim).is_err(), "a changed byte breaks the checksum");
        assert!(read_pack(&pack, &PackLimits { max_objects: 2, ..lim }).is_err());

        let oid = blob_oid(b"hello\n");
        let b = bundle(&[("HEAD".into(), oid), ("refs/heads/main".into(), oid)], &pack);
        assert!(b.starts_with(b"# v2 git bundle\n"));
        let parsed = parse_bundle(&b).unwrap();
        assert_eq!(parsed.refs.len(), 2);
        assert_eq!(parsed.refs[1], ("refs/heads/main".to_string(), oid));
        assert_eq!(parsed.pack, &pack[..]);
        let with_prereq = [b"# v2 git bundle\n-".as_slice(), hex(&oid).as_bytes(), b" x\n\n"].concat();
        assert!(parse_bundle(&with_prereq).unwrap_err().contains("prerequisites"));
    }

    #[test]
    fn deltas_apply_and_bad_ones_are_refused() {
        let base = b"hello world, hello world";
        // src 24, dst 16: copy "hello world" (off 0 len 11), insert ", ok" .. build by hand.
        let mut delta = vec![24u8, 15];
        delta.extend_from_slice(&[0x80 | 0x10, 11]); // copy offset 0 (no offset bytes), size 11
        delta.extend_from_slice(&[4, b',', b' ', b'o', b'k']);
        assert_eq!(apply_delta(base, &delta, 100).unwrap(), b"hello world, ok");
        assert!(apply_delta(base, &delta, 10).is_err(), "over the size cap");
        assert!(apply_delta(b"short", &delta, 100).is_err(), "wrong base size");
        let past = [24u8, 5, 0x80 | 0x01 | 0x10, 30, 5];
        assert!(apply_delta(base, &past, 100).is_err(), "copy past the base");
    }

    #[test]
    fn pkt_lines_read_back() {
        let mut buf = pkt(b"want abc\n");
        buf.extend_from_slice(FLUSH);
        buf.extend_from_slice(&pkt(b"done\n"));
        let mut pos = 0;
        assert!(matches!(read_pkt(&buf, &mut pos).unwrap(), Some(Pkt::Data(d)) if d == b"want abc\n"));
        assert!(matches!(read_pkt(&buf, &mut pos).unwrap(), Some(Pkt::Flush)));
        assert!(matches!(read_pkt(&buf, &mut pos).unwrap(), Some(Pkt::Data(d)) if d == b"done\n"));
        assert!(read_pkt(&buf, &mut pos).unwrap().is_none());
        assert!(read_pkt(b"00zz", &mut 0).is_err());
        assert!(read_pkt(b"0010ab", &mut 0).is_err());
    }
}
