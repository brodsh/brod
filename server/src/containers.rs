// SPDX-License-Identifier: AGPL-3.0-only
// Container apps: what a source bundle with a Dockerfile becomes before a node builds it.
//
// A bundle (inline files, or a tar / tar.gz uploaded to the one-time address) with a `Dockerfile` at its top is a
// container app. Its settings come from brod.json and from deploy_app's arguments (which win):
//   port       the port the app listens on (default 8080; also given to it as PORT)
//   health     the path Brod checks before sending it traffic (default "/"; healthy is any status below 500)
//   cpu        CPUs (default 0.5)
//   memory_mb  memory in MB (default 512)
// The upload may be up to 200 MB. Brod filters the build context before it leaves for a node: it honours the
// bundle's .dockerignore, and drops node_modules/, .git/ and .next/ wherever they are (they are rebuilt inside the
// image, and only make the context large). The filtered context is kept as a plain tar in <data>/builds/ until the
// build is over.
use std::io::{Read, Write};
use std::path::Path;

use serde_json::{Map, Value, json};

use crate::problem::{Problem, Result};
use crate::tar::BundleFile;

/// The largest upload of a container source.
pub const ARCHIVE_BYTES: usize = 200 * 1024 * 1024;
/// The largest build context after filtering.
pub const CONTEXT_BYTES: u64 = 1024 * 1024 * 1024;
/// Folders never sent to a build.
pub const DROPPED: [&str; 3] = ["node_modules", ".git", ".next"];

/// How a container version runs: its settings, and once built, its image.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Spec {
    pub port: u16,
    pub health: String,
    pub cpu: f64,
    pub memory_mb: i64,
    /// The image's manifest digest in Brod's registry (apps/<app id>@<digest>), once pushed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    /// The image id (its config digest), which is what a node loads and runs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_id: Option<String>,
    /// linux/amd64 or linux/arm64: the image only runs on nodes of this architecture.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    /// Set when retention deleted the image from the registry: the version can no longer be deployed.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub pruned: bool,
}

impl Default for Spec {
    fn default() -> Spec {
        Spec { port: 8080, health: "/".into(), cpu: 0.5, memory_mb: 512, digest: None, image_id: None, platform: None, pruned: false }
    }
}

fn bad(m: impl Into<String>) -> Problem {
    Problem::new(400, "bad_container", m)
}

impl Spec {
    /// Apply settings from an object (brod.json's top level, or deploy_app's arguments). Unknown keys are left alone.
    pub fn apply(&mut self, o: &Map<String, Value>, from: &str) -> Result<()> {
        let num = |k: &str| -> Result<Option<f64>> {
            match o.get(k) {
                None | Some(Value::Null) => Ok(None),
                Some(Value::Number(n)) => Ok(n.as_f64()),
                Some(Value::String(s)) if s.trim().is_empty() => Ok(None),
                Some(Value::String(s)) => s.trim().parse::<f64>().map(Some).map_err(|_| bad(format!("\"{k}\" in {from} is a number."))),
                Some(_) => Err(bad(format!("\"{k}\" in {from} is a number."))),
            }
        };
        if let Some(p) = num("port")? {
            if p.fract() != 0.0 || !(1.0..=65535.0).contains(&p) {
                return Err(bad(format!("\"port\" in {from} is a port number from 1 to 65535.")));
            }
            self.port = p as u16;
        }
        match o.get("health") {
            None | Some(Value::Null) => {}
            Some(Value::String(h)) => {
                let h = h.trim();
                if !h.starts_with('/') || h.len() > 200 || h.chars().any(|c| c.is_control() || c == ' ') {
                    return Err(bad(format!("\"health\" in {from} is a path such as \"/healthz\".")));
                }
                self.health = h.to_string();
            }
            Some(_) => return Err(bad(format!("\"health\" in {from} is a path such as \"/healthz\"."))),
        }
        if let Some(c) = num("cpu")? {
            if !(0.1..=16.0).contains(&c) {
                return Err(bad(format!("\"cpu\" in {from} is between 0.1 and 16 CPUs.")));
            }
            self.cpu = (c * 100.0).round() / 100.0;
        }
        if let Some(m) = num("memory_mb")?.or(num("memory")?) {
            if m.fract() != 0.0 || !(64.0..=65536.0).contains(&m) {
                return Err(bad(format!("\"memory_mb\" in {from} is a whole number of MB from 64 to 65536.")));
            }
            self.memory_mb = m as i64;
        }
        Ok(())
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{}".into())
    }

    pub fn parse(s: Option<&str>) -> Spec {
        s.and_then(|s| serde_json::from_str(s).ok()).unwrap_or_default()
    }
}

/// The container settings deploy_app was given: its "runtime" and the keys Spec::apply reads. None: none given.
pub fn options_from(o: &Map<String, Value>) -> Option<Map<String, Value>> {
    let keys = ["runtime", "port", "health", "cpu", "memory_mb", "memory"];
    let m: Map<String, Value> =
        keys.iter().filter_map(|k| o.get(*k).filter(|v| !v.is_null()).map(|v| (k.to_string(), v.clone()))).collect();
    (!m.is_empty()).then_some(m)
}

/// Whether deploy_app's arguments ask for a container.
pub fn wants_container(options: Option<&Map<String, Value>>) -> bool {
    options.and_then(|o| o.get("runtime")).and_then(Value::as_str).is_some_and(|r| r.trim() == "container")
}

// ---------- .dockerignore ----------

/// The rules of a .dockerignore file, in order: (pattern, re-include).
#[derive(Debug, Default, Clone)]
pub struct Ignore {
    rules: Vec<(String, bool)>,
}

impl Ignore {
    pub fn parse(text: &str) -> Ignore {
        let mut rules = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (pat, include) = match line.strip_prefix('!') {
                Some(p) => (p.trim(), true),
                None => (line, false),
            };
            let pat = clean(pat);
            if !pat.is_empty() {
                rules.push((pat, include));
            }
        }
        Ignore { rules }
    }

    /// Whether `path` (relative, with /) is left out of the context. The last rule that matches wins; a rule matches a
    /// path or any of its parent folders, as Docker's does.
    pub fn ignored(&self, path: &str) -> bool {
        let mut out = false;
        for (pat, include) in &self.rules {
            if matches_path(pat, path) {
                out = !include;
            }
        }
        out
    }
}

/// A pattern as Docker cleans it: no leading / or ./, no trailing /, no empty or "." segments.
fn clean(p: &str) -> String {
    let segs: Vec<&str> = p.split('/').filter(|s| !s.is_empty() && *s != ".").collect();
    segs.join("/")
}

fn matches_path(pat: &str, path: &str) -> bool {
    if glob(pat.as_bytes(), path.as_bytes()) {
        return true;
    }
    path.match_indices('/').any(|(i, _)| glob(pat.as_bytes(), &path.as_bytes()[..i]))
}

/// Docker's pattern syntax: * any run of characters but /, ? one character but /, ** any run including /, [a-z] and
/// [^a-z] classes, \ to escape.
fn glob(p: &[u8], s: &[u8]) -> bool {
    match p.first() {
        None => s.is_empty(),
        Some(b'*') if p.get(1) == Some(&b'*') => {
            let rest = &p[2..];
            // "**/" also matches no folder at all.
            if rest.first() == Some(&b'/') && glob(&rest[1..], s) {
                return true;
            }
            (0..=s.len()).any(|i| glob(rest, &s[i..]))
        }
        Some(b'*') => {
            let rest = &p[1..];
            for i in 0..=s.len() {
                if i > 0 && s[i - 1] == b'/' {
                    break;
                }
                if glob(rest, &s[i..]) {
                    return true;
                }
            }
            false
        }
        Some(b'?') => !s.is_empty() && s[0] != b'/' && glob(&p[1..], &s[1..]),
        Some(b'[') => {
            let Some(c) = s.first().copied() else { return false };
            let Some(end) = p.iter().skip(1).position(|x| *x == b']').map(|e| e + 1) else {
                return c == b'[' && glob(&p[1..], &s[1..]);
            };
            let mut class = &p[1..end];
            let negate = matches!(class.first(), Some(b'^' | b'!'));
            if negate {
                class = &class[1..];
            }
            let mut hit = false;
            let mut i = 0;
            while i < class.len() {
                if i + 2 < class.len() && class[i + 1] == b'-' {
                    hit |= (class[i]..=class[i + 2]).contains(&c);
                    i += 3;
                } else {
                    hit |= class[i] == c;
                    i += 1;
                }
            }
            c != b'/' && hit != negate && glob(&p[end + 1..], &s[1..])
        }
        Some(b'\\') if p.len() > 1 => !s.is_empty() && s[0] == p[1] && glob(&p[2..], &s[1..]),
        Some(c) => !s.is_empty() && s[0] == *c && glob(&p[1..], &s[1..]),
    }
}

/// Whether a path is always left out: under node_modules/, .git/ or .next/, or macOS's ._ and .DS_Store files.
pub fn dropped(path: &str) -> bool {
    let last = path.rsplit('/').next().unwrap_or("");
    last.starts_with("._") || last == ".DS_Store" || path.split('/').any(|s| DROPPED.contains(&s))
}

// ---------- the build context ----------

/// Zero bytes after a gzip member end the stream (macOS bsdtar pads its output); see tar::gunzip_capped.
struct Gunzip<'a> {
    dec: Option<flate2::bufread::GzDecoder<&'a [u8]>>,
}

impl Read for Gunzip<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            let Some(dec) = self.dec.as_mut() else { return Ok(0) };
            let n = dec.read(buf)?;
            if n > 0 || buf.is_empty() {
                return Ok(n);
            }
            let rest = self.dec.take().map(|d| d.into_inner()).unwrap_or_default();
            if rest.iter().all(|b| *b == 0) {
                return Ok(0);
            }
            if !(rest.len() >= 2 && rest[0] == 0x1f && rest[1] == 0x8b) {
                return Err(std::io::Error::other("trailing data after gzip"));
            }
            self.dec = Some(flate2::bufread::GzDecoder::new(rest));
        }
    }
}

fn reader(archive: &[u8]) -> Box<dyn Read + '_> {
    if archive.len() >= 2 && archive[0] == 0x1f && archive[1] == 0x8b {
        Box::new(Gunzip { dec: Some(flate2::bufread::GzDecoder::new(archive)) })
    } else {
        Box::new(archive)
    }
}

fn bad_archive() -> Problem {
    Problem::new(
        400,
        "bad_bundle",
        "The upload must be a tar or tar.gz archive of the source folder. Create one with: tar -czf - -C <source folder> .",
    )
}

/// One entry of a tar: its path (cleaned), type, size, and its raw header blocks (extension headers included).
struct Entry {
    path: String,
    kind: u8,
    size: u64,
    raw: Vec<u8>,
}

fn field(h: &[u8], from: usize, len: usize) -> String {
    let f = &h[from..from + len];
    let end = f.iter().position(|x| *x == 0).unwrap_or(f.len());
    String::from_utf8_lossy(&f[..end]).into_owned()
}

fn size_of(h: &[u8]) -> Option<u64> {
    // Base-256 for sizes over 8 GB, which a context never has.
    if h[124] & 0x80 != 0 {
        return None;
    }
    let s = field(h, 124, 12);
    let digits: String = s.trim().chars().take_while(|c| ('0'..='7').contains(c)).collect();
    if digits.is_empty() { Some(0) } else { u64::from_str_radix(&digits, 8).ok() }
}

fn read_full(r: &mut dyn Read, buf: &mut [u8]) -> Result<bool> {
    let mut got = 0;
    while got < buf.len() {
        let n = r.read(&mut buf[got..]).map_err(|_| bad_archive())?;
        if n == 0 {
            return if got == 0 { Ok(false) } else { Err(bad_archive()) };
        }
        got += n;
    }
    Ok(true)
}

/// Read the next entry's headers; None at the end of the archive.
fn next_entry(r: &mut dyn Read) -> Result<Option<Entry>> {
    let mut raw = Vec::new();
    let mut long_name: Option<String> = None;
    loop {
        let mut h = [0u8; 512];
        if !read_full(r, &mut h)? || h.iter().all(|b| *b == 0) {
            return Ok(None);
        }
        if field(&h, 257, 5) != "ustar" {
            return Err(bad_archive());
        }
        let size = size_of(&h).ok_or_else(bad_archive)?;
        let kind = if h[156] == 0 { b'0' } else { h[156] };
        raw.extend_from_slice(&h);
        match kind {
            b'L' | b'x' | b'g' => {
                if size > 1024 * 1024 {
                    return Err(bad_archive());
                }
                let mut data = vec![0u8; size.div_ceil(512) as usize * 512];
                if !read_full(r, &mut data)? {
                    return Err(bad_archive());
                }
                raw.extend_from_slice(&data);
                let data = &data[..size as usize];
                if kind == b'L' {
                    let end = data.iter().position(|x| *x == 0).unwrap_or(data.len());
                    long_name = Some(String::from_utf8_lossy(&data[..end]).into_owned());
                } else if kind == b'x'
                    && let Some(p) = pax_path(data)
                {
                    long_name = Some(p);
                }
                continue;
            }
            _ => {}
        }
        let name = match long_name.take() {
            Some(n) => n,
            None => {
                let prefix = field(&h, 345, 155);
                let name = field(&h, 0, 100);
                if prefix.is_empty() { name } else { format!("{prefix}/{name}") }
            }
        };
        let mut p = name.replace('\\', "/");
        while let Some(rest) = p.strip_prefix("./") {
            p = rest.to_string();
        }
        let p = p.trim_start_matches('/').trim_end_matches('/').to_string();
        if p.split('/').any(|s| s == "..") {
            return Err(Problem::new(400, "bad_path", format!("The path \"{p}\" is not allowed.")));
        }
        // Only files take room in the archive; links and folders have no data.
        let size = if matches!(kind, b'0' | b'7') { size } else { 0 };
        return Ok(Some(Entry { path: p, kind, size, raw }));
    }
}

fn pax_path(data: &[u8]) -> Option<String> {
    String::from_utf8_lossy(data).lines().find_map(|l| l.split_once(' ').and_then(|(_, kv)| kv.strip_prefix("path=")).map(String::from))
}

fn skip(r: &mut dyn Read, size: u64) -> Result<()> {
    let padded = size.div_ceil(512) * 512;
    let copied = std::io::copy(&mut r.take(padded), &mut std::io::sink()).map_err(|_| bad_archive())?;
    if copied != padded { Err(bad_archive()) } else { Ok(()) }
}

fn read_data(r: &mut dyn Read, size: u64) -> Result<Vec<u8>> {
    let mut data = vec![0u8; size.div_ceil(512) as usize * 512];
    if !read_full(r, &mut data)? {
        return Err(bad_archive());
    }
    data.truncate(size as usize);
    Ok(data)
}

/// What the first look at an archive finds: whether it is a container source, and its .dockerignore and brod.json.
#[derive(Debug, Default)]
pub struct Survey {
    pub dockerfile: bool,
    pub dockerignore: Option<String>,
    pub manifest: Option<Vec<u8>>,
}

/// Look through a tar or tar.gz without keeping it: a regular file named Dockerfile at the top makes it a container
/// source. Not a tar at all: None (it may be a zip of a static app).
pub fn survey(archive: &[u8]) -> Result<Option<Survey>> {
    let mut r = reader(archive);
    let mut s = Survey::default();
    let first = match next_entry(&mut r) {
        Ok(Some(e)) => e,
        Ok(None) => return Ok(Some(s)),
        Err(e) if e.code == "bad_bundle" => return Ok(None),
        Err(e) => return Err(e),
    };
    let mut entry = Some(first);
    while let Some(e) = entry {
        let small = e.size <= 1024 * 1024;
        match (e.path.as_str(), e.kind) {
            ("Dockerfile", b'0' | b'7') => {
                s.dockerfile = true;
                skip(&mut r, e.size)?;
            }
            (".dockerignore", b'0' | b'7') if small => {
                s.dockerignore = Some(String::from_utf8_lossy(&read_data(&mut r, e.size)?).into_owned())
            }
            ("brod.json", b'0' | b'7') if small => s.manifest = Some(read_data(&mut r, e.size)?),
            _ => skip(&mut r, e.size)?,
        }
        entry = next_entry(&mut r)?;
    }
    Ok(Some(s))
}

/// The filtered build context written to `dest`: its file count and bytes.
#[derive(Debug, PartialEq)]
pub struct Context {
    pub files: usize,
    pub bytes: u64,
}

/// Write the build context for a source archive to `dest` as a plain tar: every entry but those .dockerignore and
/// DROPPED leave out. The Dockerfile, .dockerignore and brod.json are always kept.
pub fn write_context(archive: &[u8], ignore: &Ignore, dest: &Path) -> Result<Context> {
    let mut r = reader(archive);
    let file = std::fs::File::create(dest).map_err(Problem::internal)?;
    let mut out = std::io::BufWriter::new(file);
    let mut ctx = Context { files: 0, bytes: 0 };
    // The docker CLI takes stdin for a tar only when its first 512 bytes parse as a whole entry; a pax or GNU extension
    // header first (macOS tar writes one for extended attributes) makes it read the stream as a Dockerfile. A plain
    // header for the top folder always comes first.
    out.write_all(&crate::tar::folder_header("./", crate::util::now())).map_err(Problem::internal)?;
    while let Some(e) = next_entry(&mut r)? {
        let always = matches!(e.path.as_str(), "Dockerfile" | ".dockerignore" | "brod.json");
        let keep = !e.path.is_empty()
            && matches!(e.kind, b'0' | b'7' | b'5' | b'1' | b'2')
            && (always || (!dropped(&e.path) && !ignore.ignored(&e.path)));
        if !keep {
            skip(&mut r, e.size)?;
            continue;
        }
        if matches!(e.kind, b'0' | b'7') {
            ctx.files += 1;
            ctx.bytes += e.size;
            if ctx.bytes > CONTEXT_BYTES {
                return Err(crate::http::too_large("The build context", CONTEXT_BYTES as usize));
            }
        }
        out.write_all(&e.raw).map_err(Problem::internal)?;
        let padded = e.size.div_ceil(512) * 512;
        let copied = std::io::copy(&mut (&mut r).take(padded), &mut out).map_err(|_| bad_archive())?;
        if copied != padded {
            return Err(bad_archive());
        }
    }
    out.write_all(&[0u8; 1024]).map_err(Problem::internal)?;
    out.flush().map_err(Problem::internal)?;
    Ok(ctx)
}

/// A bundle of inline files as an archive, when it is a container source (a Dockerfile at its top).
pub fn archive_of(files: &[BundleFile]) -> Option<Vec<u8>> {
    files.iter().any(|f| f.path.trim_start_matches("./") == "Dockerfile").then(|| crate::tar::pack(files, crate::util::now()))
}

/// The container settings of a source: brod.json's top level, then deploy_app's arguments over it.
pub fn spec_of(manifest: Option<&[u8]>, options: Option<&Map<String, Value>>) -> Result<Spec> {
    let mut spec = Spec::default();
    if let Some(m) = manifest {
        match serde_json::from_slice::<Value>(m) {
            Ok(Value::Object(o)) => spec.apply(&o, "brod.json")?,
            Ok(_) => return Err(bad("brod.json is a JSON object.")),
            Err(e) => return Err(bad(format!("brod.json is not valid JSON: {e}."))),
        }
    }
    if let Some(o) = options {
        spec.apply(o, "the deploy")?;
    }
    Ok(spec)
}

/// The spec as get_status and get_deployment show it.
pub fn spec_view(spec: &Spec) -> Value {
    json!({ "port": spec.port, "health": spec.health, "cpu": spec.cpu, "memory_mb": spec.memory_mb, "image": spec.digest, "platform": spec.platform })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tar::tests::{Entry as T, entry, gzip, tar};

    #[test]
    fn dockerignore_follows_dockers_rules() {
        let i = Ignore::parse("# comment\n\n*.log\n/build\ndocs/**/*.md\n!docs/keep.md\nsecret?.txt\n[ab].bin\n**/tmp\n");
        assert!(i.ignored("app.log"));
        assert!(!i.ignored("src/app.log"), "* does not cross folders");
        assert!(i.ignored("build") && i.ignored("build/out.js"), "a folder takes its contents");
        assert!(!i.ignored("src/build"));
        assert!(i.ignored("docs/a/b/c.md") && i.ignored("docs/c.md"), "**/ also matches no folder");
        assert!(!i.ignored("docs/keep.md"), "! includes again");
        assert!(i.ignored("secret1.txt") && !i.ignored("secret12.txt"));
        assert!(i.ignored("a.bin") && !i.ignored("c.bin"));
        assert!(i.ignored("x/y/tmp/z") && i.ignored("tmp"));
        assert!(!i.ignored("main.go"));
        let all = Ignore::parse("*\n!Dockerfile\n!src\n");
        assert!(all.ignored("README.md") && !all.ignored("src/main.go") && !all.ignored("Dockerfile"));
        assert!(Ignore::parse("[^a]x").ignored("bx") && !Ignore::parse("[^a]x").ignored("ax"));
    }

    #[test]
    fn drops_dependencies_and_vcs_folders() {
        for p in ["node_modules/x/index.js", "web/node_modules/a", ".git/HEAD", "app/.next/cache/x", "._foo", "a/.DS_Store"] {
            assert!(dropped(p), "{p}");
        }
        for p in ["src/main.go", "node_modules.txt", "git/x", ".gitignore"] {
            assert!(!dropped(p), "{p}");
        }
    }

    fn names(path: &Path) -> Vec<String> {
        let bytes = std::fs::read(path).unwrap();
        let mut r: &[u8] = &bytes;
        let mut out = Vec::new();
        while let Some(e) = next_entry(&mut r).unwrap() {
            skip(&mut r, e.size).unwrap();
            out.push(e.path);
        }
        out
    }

    #[test]
    fn builds_a_filtered_context_and_reads_its_settings() {
        let long = format!("src/{}.go", "n".repeat(120));
        let pax = format!("{} path={long}\n", long.len() + 7 + 4);
        let archive = gzip(&tar(&[
            T { name: "./", content: b"", prefix: None, kind: b'5' },
            entry("./Dockerfile", "FROM scratch\n"),
            entry("./.dockerignore", "*.log\n"),
            entry("./brod.json", r#"{ "port": 3000, "health": "/healthz", "memory_mb": 256 }"#),
            entry("./main.go", "package main"),
            entry("./debug.log", "noise"),
            entry("./node_modules/left-pad/index.js", "x"),
            entry("./.git/HEAD", "ref"),
            T { name: "PaxHeader", content: pax.as_bytes(), prefix: None, kind: b'x' },
            entry("ignored", "long name content"),
        ]));
        let mut padded = archive.clone();
        padded.resize(archive.len().div_ceil(10240) * 10240, 0);
        let s = survey(&padded).unwrap().unwrap();
        assert!(s.dockerfile);
        let spec = spec_of(s.manifest.as_deref(), Some(json!({ "cpu": 1, "port": "9000" }).as_object().unwrap())).unwrap();
        assert_eq!((spec.port, spec.health.as_str(), spec.cpu, spec.memory_mb), (9000, "/healthz", 1.0, 256));
        let dir = std::env::temp_dir().join(format!("brod-ctx-{}", crate::util::random_id("", 8)));
        std::fs::create_dir_all(&dir).unwrap();
        let dest = dir.join("ctx.tar");
        let ctx = write_context(&padded, &Ignore::parse(s.dockerignore.as_deref().unwrap()), &dest).unwrap();
        assert_eq!(names(&dest), ["", "Dockerfile", ".dockerignore", "brod.json", "main.go", long.as_str()]);
        assert_eq!(ctx.files, 5);
        // A plain folder header comes first, so the docker CLI takes the stream for a tar.
        let head = std::fs::read(&dest).unwrap();
        assert_eq!((&head[..3], head[156], &head[257..262]), (&b"./\0"[..], b'5', &b"ustar"[..]));
        let _ = std::fs::remove_dir_all(dir);
        // A bundle without a top-level Dockerfile is not a container source; a zip is not a tar at all.
        assert!(!survey(&gzip(&tar(&[entry("app/Dockerfile", "FROM x")]))).unwrap().unwrap().dockerfile);
        assert!(survey(b"PK\x03\x04 zip").unwrap().is_none());
        // Climbing out of the context is refused.
        assert_eq!(survey(&tar(&[entry("../etc/passwd", "x")])).unwrap_err().code, "bad_path");
    }

    #[test]
    fn checks_the_settings() {
        let o = |v: Value| v.as_object().unwrap().clone();
        assert_eq!(Spec::default().port, 8080);
        assert_eq!(spec_of(None, None).unwrap(), Spec::default());
        for bad in [
            json!({ "port": 0 }),
            json!({ "port": 70000 }),
            json!({ "health": "healthz" }),
            json!({ "cpu": 0 }),
            json!({ "memory_mb": 10 }),
        ] {
            assert_eq!(spec_of(None, Some(&o(bad.clone()))).unwrap_err().code, "bad_container", "{bad}");
        }
        assert_eq!(spec_of(Some(b"[]"), None).unwrap_err().code, "bad_container");
        assert!(wants_container(options_from(&o(json!({ "runtime": "container", "name": "x" }))).as_ref()));
        assert!(options_from(&o(json!({ "name": "x" }))).is_none());
        let s = Spec { digest: Some("sha256:ab".into()), ..Spec::default() };
        assert_eq!(Spec::parse(Some(&s.to_json())), s);
    }
}
