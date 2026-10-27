//! Walking the workspace's sources, shared by the tests that scan them.
//!
//! One string extractor for every scan: two of them would read a file two ways, and the
//! first one written here took `"https://"` for a comment.

#![allow(dead_code)]

use std::path::{Path, PathBuf};

pub fn crates_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.join("crates"))
        .unwrap_or_default()
}

pub fn short(p: &Path) -> String {
    p.to_string_lossy()
        .rsplit_once("crates/")
        .map(|(_, s)| s.to_string())
        .unwrap_or_else(|| p.to_string_lossy().into_owned())
}

pub fn rust_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            out.extend(rust_files(&p));
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
    out
}

/// Blanks string literals and comments, leaving code.
///
/// 🔴 A state machine, not a regex. `"(?:[^"\\]|\\.)*"` desynchronises on `'"'` — a char
/// literal holding a quote — and on `r#"…"#`, after which it pairs the end of one string
/// with the start of the next and swallows the code between them. That is not
/// hypothetical: the rename pass that preceded this test used a regex first and got five
/// false refusals out of eleven before it was replaced by this.
///
/// ⚠️ A lifetime (`'a`) is not a char literal. Treating it as one consumes everything up
/// to the next quote, which is usually most of the file.
pub fn code_only(src: &str) -> String {
    split(src).0
}

/// The code with its literals and comments blanked, and the string literals it held.
pub fn split(src: &str) -> (String, Vec<String>) {
    let b: Vec<char> = src.chars().collect();
    let mut out = String::with_capacity(src.len());
    let mut strings = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        let next = b.get(i + 1).copied();
        if c == '/' && next == Some('/') {
            while i < b.len() && b[i] != '\n' {
                i += 1;
            }
        } else if c == '/' && next == Some('*') {
            let mut depth = 1;
            i += 2;
            while i < b.len() && depth > 0 {
                if b[i] == '/' && b.get(i + 1) == Some(&'*') {
                    depth += 1;
                    i += 2;
                } else if b[i] == '*' && b.get(i + 1) == Some(&'/') {
                    depth -= 1;
                    i += 2;
                } else {
                    i += 1;
                }
            }
        } else if c == 'r' && matches!(next, Some('"') | Some('#')) {
            let mut j = i + 1;
            let mut hashes = 0;
            while j < b.len() && b[j] == '#' {
                hashes += 1;
                j += 1;
            }
            if b.get(j) == Some(&'"') {
                j += 1;
                let start = j;
                loop {
                    if j >= b.len() {
                        break;
                    }
                    if b[j] == '"' && b[j + 1..].iter().take(hashes).all(|c| *c == '#') {
                        strings.push(b[start..j].iter().collect());
                        j += 1 + hashes;
                        break;
                    }
                    j += 1;
                }
                i = j;
            } else {
                out.push(c);
                i += 1;
            }
        } else if c == '"' {
            i += 1;
            let start = i;
            while i < b.len() {
                if b[i] == '\\' {
                    i += 2;
                } else if b[i] == '"' {
                    strings.push(b[start..i].iter().collect());
                    i += 1;
                    break;
                } else {
                    i += 1;
                }
            }
        } else if c == '\'' {
            // `'\n'`, `'a'`, or a lifetime. Only the first two are literals.
            if b.get(i + 1) == Some(&'\\') {
                i += 2;
                while i < b.len() && b[i] != '\'' {
                    i += 1;
                }
                i += 1;
            } else if b.get(i + 2) == Some(&'\'') {
                i += 3;
            } else {
                i += 1;
            }
        } else {
            out.push(c);
            i += 1;
        }
    }
    (out, strings)
}
