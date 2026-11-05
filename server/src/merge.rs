// SPDX-License-Identifier: AGPL-3.0-only
// Three-way merge of one file (base, current, incoming) and unified diffs, for patch deploys (patch.rs).
//
// File level first: when only one side changed a file, that side wins and no text is read. When both changed a text
// file, diffy's diff3 merges the lines; overlapping edits are a conflict, reported as hunks with the base, the
// current and the incoming lines so the caller can resolve them. Both changed a binary file, or one deleted what the
// other changed, is a conflict too.
use diffy::{ConflictStyle, DiffOptions, MergeOptions};
use serde_json::{Value, json};

/// A conflicting region: the same lines as the base had, as the current version has them, and as the patch has them.
#[derive(Clone, Debug, PartialEq)]
pub struct Hunk {
    pub base: String,
    pub current: String,
    pub incoming: String,
}

/// Why a file could not be merged.
#[derive(Clone, Debug, PartialEq)]
pub struct Conflict {
    pub path: String,
    /// "text" (overlapping edits), "binary" (both changed it) or "delete_modify" (one side deleted what the other changed).
    pub kind: &'static str,
    pub hunks: Vec<Hunk>,
}

impl Conflict {
    pub fn to_json(&self) -> Value {
        let hunks: Vec<Value> =
            self.hunks.iter().map(|h| json!({ "base": h.base, "current": h.current, "incoming": h.incoming })).collect();
        json!({ "path": self.path, "kind": self.kind, "hunks": hunks })
    }
}

#[derive(Debug, PartialEq)]
pub enum Outcome {
    /// The merged content; None when the file ends up deleted.
    Resolved(Option<Vec<u8>>),
    Conflict(Conflict),
}

/// Hunks and snippets reported per conflicting file, at most.
const MAX_HUNKS: usize = 10;
const MAX_SNIPPET: usize = 2000;

/// Text we merge and diff by line: valid UTF-8 with no NUL.
pub fn is_text(b: &[u8]) -> bool {
    !b.contains(&0) && std::str::from_utf8(b).is_ok()
}

fn snippet(s: &str) -> String {
    if s.len() <= MAX_SNIPPET {
        return s.to_string();
    }
    let mut end = MAX_SNIPPET;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &s[..end])
}

/// Merge one file. `current` is what is deployed now, `incoming` what the patch makes of the base, `base` what the patch
/// started from; None is "no such file".
pub fn three_way(path: &str, base: Option<&[u8]>, current: Option<&[u8]>, incoming: Option<&[u8]>) -> Outcome {
    if current == incoming || incoming == base {
        return Outcome::Resolved(current.map(<[u8]>::to_vec));
    }
    if current == base {
        return Outcome::Resolved(incoming.map(<[u8]>::to_vec));
    }
    // Both sides changed it, differently.
    let (Some(cur), Some(inc)) = (current, incoming) else {
        let snip = |b: Option<&[u8]>| b.filter(|b| is_text(b)).map(|b| snippet(&String::from_utf8_lossy(b))).unwrap_or_default();
        return Outcome::Conflict(Conflict {
            path: path.into(),
            kind: "delete_modify",
            hunks: vec![Hunk { base: snip(base), current: snip(current), incoming: snip(incoming) }],
        });
    };
    let bs = base.unwrap_or(b"");
    if !(is_text(bs) && is_text(cur) && is_text(inc)) {
        return Outcome::Conflict(Conflict { path: path.into(), kind: "binary", hunks: Vec::new() });
    }
    let (bs, cur, inc) =
        (std::str::from_utf8(bs).unwrap_or(""), std::str::from_utf8(cur).unwrap_or(""), std::str::from_utf8(inc).unwrap_or(""));
    let mut o = MergeOptions::new();
    o.set_conflict_style(ConflictStyle::Diff3);
    match o.merge(bs, cur, inc) {
        Ok(merged) => Outcome::Resolved(Some(merged.into_bytes())),
        Err(marked) => Outcome::Conflict(Conflict { path: path.into(), kind: "text", hunks: parse_markers(&marked) }),
    }
}

/// The conflict regions of diff3-style marked text:
/// `<<<<<<<` current, `|||||||` base, `=======` incoming, `>>>>>>>`.
fn parse_markers(marked: &str) -> Vec<Hunk> {
    #[derive(PartialEq)]
    enum In {
        Outside,
        Current,
        Base,
        Incoming,
    }
    let mut state = In::Outside;
    let (mut cur, mut base, mut inc) = (String::new(), String::new(), String::new());
    let mut out = Vec::new();
    for line in marked.split_inclusive('\n') {
        match (&state, line) {
            (In::Outside, l) if l.starts_with("<<<<<<<") => state = In::Current,
            (In::Current, l) if l.starts_with("|||||||") => state = In::Base,
            (In::Current | In::Base, l) if l.starts_with("=======") => state = In::Incoming,
            (In::Incoming, l) if l.starts_with(">>>>>>>") => {
                if out.len() < MAX_HUNKS {
                    out.push(Hunk { base: snippet(&base), current: snippet(&cur), incoming: snippet(&inc) });
                }
                (cur, base, inc) = (String::new(), String::new(), String::new());
                state = In::Outside;
            }
            (In::Current, l) => cur.push_str(l),
            (In::Base, l) => base.push_str(l),
            (In::Incoming, l) => inc.push_str(l),
            (In::Outside, _) => {}
        }
    }
    out
}

/// A unified diff of one file between two versions (None: absent). Binary files only say that they differ.
pub fn unified(path: &str, from: Option<&[u8]>, to: Option<&[u8]>) -> String {
    let (a, b) = (from.unwrap_or(b""), to.unwrap_or(b""));
    if !(is_text(a) && is_text(b)) {
        return format!("Binary files a/{path} and b/{path} differ\n");
    }
    let mut o = DiffOptions::new();
    o.set_original_filename(if from.is_some() { format!("a/{path}") } else { "/dev/null".to_string() });
    o.set_modified_filename(if to.is_some() { format!("b/{path}") } else { "/dev/null".to_string() });
    let patch = o.create_patch(std::str::from_utf8(a).unwrap_or(""), std::str::from_utf8(b).unwrap_or(""));
    format!("diff --brod a/{path} b/{path}\n{patch}")
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = "one\ntwo\nthree\nfour\nfive\nsix\nseven\n";

    fn merged(base: &str, cur: &str, inc: &str) -> Outcome {
        three_way("f.txt", Some(base.as_bytes()), Some(cur.as_bytes()), Some(inc.as_bytes()))
    }

    #[test]
    fn one_side_changed_takes_that_side() {
        assert_eq!(merged(BASE, BASE, "x\n"), Outcome::Resolved(Some(b"x\n".to_vec())));
        assert_eq!(merged(BASE, "y\n", BASE), Outcome::Resolved(Some(b"y\n".to_vec())));
        assert_eq!(merged(BASE, "same\n", "same\n"), Outcome::Resolved(Some(b"same\n".to_vec())));
        assert_eq!(three_way("f", Some(b"a"), Some(b"a"), None), Outcome::Resolved(None));
        assert_eq!(three_way("f", Some(b"a"), None, Some(b"a")), Outcome::Resolved(None));
        assert_eq!(three_way("f", None, None, Some(b"new")), Outcome::Resolved(Some(b"new".to_vec())));
    }

    #[test]
    fn edits_in_different_places_merge_by_line() {
        let cur = BASE.replace("two", "TWO");
        let inc = BASE.replace("six", "SIX");
        let Outcome::Resolved(Some(out)) = merged(BASE, &cur, &inc) else { panic!("expected a clean merge") };
        assert_eq!(String::from_utf8(out).unwrap(), "one\nTWO\nthree\nfour\nfive\nSIX\nseven\n");
    }

    #[test]
    fn overlapping_edits_conflict_with_hunks() {
        let cur = BASE.replace("three", "current three");
        let inc = BASE.replace("three", "incoming three");
        let Outcome::Conflict(c) = merged(BASE, &cur, &inc) else { panic!("expected a conflict") };
        assert_eq!((c.path.as_str(), c.kind), ("f.txt", "text"));
        assert_eq!(c.hunks, vec![Hunk { base: "three\n".into(), current: "current three\n".into(), incoming: "incoming three\n".into() }]);
    }

    #[test]
    fn binary_and_delete_conflicts() {
        let out = three_way("a.png", Some(&[0, 1]), Some(&[0, 2]), Some(&[0, 3]));
        assert!(matches!(out, Outcome::Conflict(Conflict { kind: "binary", .. })));
        let out = three_way("a.txt", Some(b"a\n"), Some(b"b\n"), None);
        assert!(matches!(out, Outcome::Conflict(Conflict { kind: "delete_modify", .. })));
        // Both added the same path with different content: no common base, so overlapping.
        let out = three_way("a.txt", None, Some(b"x\n"), Some(b"y\n"));
        assert!(matches!(out, Outcome::Conflict(Conflict { kind: "text", .. })));
    }

    #[test]
    fn unified_diffs() {
        let d = unified("a.txt", Some(b"a\nb\n"), Some(b"a\nc\n"));
        assert!(d.contains("--- a/a.txt") && d.contains("+++ b/a.txt") && d.contains("-b\n") && d.contains("+c\n"), "{d}");
        assert!(unified("x.bin", Some(&[0]), Some(&[1])).starts_with("Binary files"));
        assert!(unified("n.txt", None, Some(b"hi\n")).contains("--- /dev/null"));
    }
}
