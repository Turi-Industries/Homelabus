//! The web side holds no capability: every module of this crate but `main.rs` asks
//! `hlb_privd` instead of holding Docker, the vault or an admin client.
//!
//! 🔴 The types refused are read from the privileged side's own structs — `Privd` and
//! `InstallContext` — so a client added there is refused here the day it is added; a
//! list written in this file would drift like the thirteen before it. Matched as an
//! identifier's END, so `SwarmOrchestrator` is refused with `Orchestrator`: a handler
//! could build its own client without ever naming the trait `Privd` holds.

#![allow(clippy::expect_used)]

#[path = "../../hlb-types/tests/scan/mod.rs"]
mod scan;

use std::collections::BTreeSet;
use std::path::Path;

/// Named by `Privd`'s fields, and the web side's to read all the same.
const READ_BY_THE_WEB: &[(&str, &str)] = &[
    (
        "State",
        "the web side reads the state; only the daemon will write it",
    ),
    ("Catalog", "the web side browses the catalog it shows"),
];

/// Wrappers around a field's type, not a type of their own.
const WRAPPERS: &[&str] = &["Option", "Arc", "Box", "Vec", "String"];

fn ident(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// Every type `Privd` and `InstallContext` hold, but the ones the web reads too.
fn capabilities() -> BTreeSet<String> {
    let lib = scan::crates_root().join("hlb-privd/src/lib.rs");
    let src = std::fs::read_to_string(&lib).expect("hlb-privd's source");
    let code = scan::code_only(&src);
    let mut out = BTreeSet::new();
    for opening in ["pub struct Privd {", "pub struct InstallContext {"] {
        let body = code
            .split_once(opening)
            .unwrap_or_else(|| panic!("{opening} is gone from hlb-privd"))
            .1
            .split_once("\n}")
            .expect("its end")
            .0;
        for field in body.split(',') {
            let Some((_, ty)) = field.split_once(':') else {
                continue;
            };
            for word in ty.split(|c: char| !ident(c)) {
                let read = READ_BY_THE_WEB.iter().any(|(t, _)| *t == word);
                if word.starts_with(char::is_uppercase) && !read && !WRAPPERS.contains(&word) {
                    out.insert(word.to_string());
                }
            }
        }
    }
    out
}

/// A file's code before its test module, literals and comments blanked.
fn production(path: &Path) -> String {
    let src = std::fs::read_to_string(path).expect("source");
    let code = src
        .split_once("\n#[cfg(test)]")
        .map_or(src.as_str(), |(c, _)| c);
    scan::code_only(code)
}

/// The capability types `code` names, as identifiers or their ends.
fn named(code: &str, caps: &BTreeSet<String>) -> BTreeSet<String> {
    code.split(|c: char| !ident(c))
        .filter(|w| caps.iter().any(|c| w.ends_with(c.as_str())))
        .map(str::to_string)
        .collect()
}

#[test]
fn no_web_module_names_a_capability() {
    let caps = capabilities();
    // The floor: the two structs hold eleven such types today. Read as fewer, the
    // parsing broke and the scan below would pass on nothing.
    assert!(caps.len() >= 10, "only {caps:?} read from hlb-privd");
    for (t, why) in READ_BY_THE_WEB {
        assert!(!why.is_empty(), "{t} is exempt without a reason");
    }

    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let files = scan::rust_files(&src);
    let mut scanned = 0;
    let mut found = Vec::new();
    for f in &files {
        let code = production(f);
        let names = named(&code, &caps);
        if f.file_name().is_some_and(|n| n == "main.rs") {
            // The daemon's composition root holds them on purpose — and seeing them
            // there proves the matcher reads real code.
            assert!(
                names.len() >= 5,
                "main.rs names only {names:?}: the scan reads nothing"
            );
            continue;
        }
        scanned += 1;
        for n in names {
            found.push(format!("{}: {n}", scan::short(f)));
        }
    }
    assert!(scanned >= 30, "only {scanned} web modules read");
    assert!(
        found.is_empty(),
        "a web module holds what only hlb-privd may — ask it an intent instead:\n{}",
        found.join("\n")
    );
}
