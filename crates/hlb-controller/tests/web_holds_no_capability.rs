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
    (
        "PathBuf",
        "a path: the web side reads the Git mirror's history, which only the daemon writes",
    ),
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

/// Whether `code` reaches `hlb_privd::daemon`, by path or inside a `use` group.
fn reaches_the_daemon(code: &str) -> bool {
    code.match_indices("hlb_privd::").any(|(i, m)| {
        let rest = &code[i + m.len()..];
        rest.starts_with("daemon")
            || rest.starts_with('{')
                && rest.split_once('}').is_some_and(|(group, _)| {
                    group.split(|c: char| !ident(c)).any(|w| w == "daemon")
                })
    })
}

/// The daemon's modules — its loops, the notifier holding ntfy's credentials, the
/// memory its loops publish — are the composition root's to start: `Privd` does not
/// hold the notifier, so the scan above cannot see it.
#[test]
fn no_web_module_reaches_the_daemon() {
    assert!(reaches_the_daemon(
        "use hlb_privd::{backup, daemon::Notifier};"
    ));
    assert!(!reaches_the_daemon("use hlb_privd::{backup, Privd};"));

    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut scanned = 0;
    let mut found = Vec::new();
    for f in scan::rust_files(&src) {
        let reaches = reaches_the_daemon(&production(&f));
        if f.file_name().is_some_and(|n| n == "main.rs") {
            assert!(
                reaches,
                "main.rs starts no daemon loop: the scan reads nothing"
            );
            continue;
        }
        scanned += 1;
        if reaches {
            found.push(scan::short(&f));
        }
    }
    assert!(scanned >= 30, "only {scanned} web modules read");
    assert!(
        found.is_empty(),
        "a web module reaches the daemon — ask hlb_privd an intent instead:\n{}",
        found.join("\n")
    );
}

/// The words of a statement that writes.
const WRITES: &[&str] = &["INSERT", "UPDATE", "DELETE", "REPLACE"];

/// Each function of `src` — `(name, public, body)` — cut at the next function's header.
fn functions(src: &str) -> Vec<(String, bool, String)> {
    let mut out: Vec<(String, bool, String)> = Vec::new();
    for line in src.lines() {
        let t = line.trim_start();
        let public = t.starts_with("pub ");
        let header = t
            .trim_start_matches("pub(crate) ")
            .trim_start_matches("pub ")
            .trim_start_matches("async ")
            .strip_prefix("fn ")
            .filter(|_| line.len() - t.len() <= 4);
        match header {
            Some(rest) => {
                let name: String = rest.chars().take_while(|c| ident(*c)).collect();
                out.push((name, public, String::new()));
            }
            None => {
                if let Some((_, _, body)) = out.last_mut() {
                    body.push_str(line);
                    body.push('\n');
                }
            }
        }
    }
    out
}

/// The public methods of `hlb-state` that write: a statement among their literals, a
/// transaction opened, or a call to a function that does either.
fn state_writers() -> BTreeSet<String> {
    let dir = scan::crates_root().join("hlb-state/src");
    let mut fns = Vec::new();
    for f in scan::rust_files(&dir) {
        let src = std::fs::read_to_string(&f).expect("hlb-state's source");
        let production = src
            .split_once("\n#[cfg(test)]")
            .map_or(src.as_str(), |(c, _)| c);
        for (name, public, body) in functions(production) {
            let (code, strings) = scan::split(&body);
            let writes = strings
                .iter()
                .any(|s| s.split(|c: char| !ident(c)).any(|w| WRITES.contains(&w)))
                || code.contains(".begin(")
                || code.contains(".begin_with(");
            fns.push((name, public, code, writes));
        }
    }
    // A function calling a writer writes: until nothing changes.
    let mut writers: BTreeSet<String> = fns.iter().filter(|f| f.3).map(|f| f.0.clone()).collect();
    loop {
        let before = writers.len();
        for (name, _, code, _) in &fns {
            let calls = |w: &String| {
                code.contains(&format!("self.{w}(")) || code.contains(&format!("Self::{w}("))
            };
            if writers.iter().any(calls) {
                writers.insert(name.clone());
            }
        }
        if writers.len() == before {
            break;
        }
    }
    fns.iter()
        .filter(|f| f.1 && writers.contains(&f.0))
        .map(|f| f.0.clone())
        .collect()
}

/// 🔴 Whoever writes `hlb.db` forges a secret, a session or the audit chain, so the
/// web side writes nothing in it: every write is an intent the privileged side answers.
/// The writers are read from `hlb-state` itself — a method added there tomorrow is
/// refused here the day it is added. A web method sharing a writer's name is renamed:
/// matched by name, the scan cannot tell receivers apart.
#[test]
fn no_web_module_writes_the_state() {
    let writers = state_writers();
    // The floor: 98 writers when this was written. Read as far fewer, the parsing broke
    // and the scan below would pass on nothing.
    assert!(
        writers.len() >= 90,
        "only {} writers read: {writers:?}",
        writers.len()
    );
    for known in [
        "audit",
        "open_session",
        "upsert_app",
        "set_user_role",
        "prune_uptime_samples",
    ] {
        assert!(writers.contains(known), "{known} not read as a writer");
    }
    assert!(
        !writers.contains("installed_apps"),
        "a reader read as a writer"
    );

    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut scanned = 0;
    let mut found = Vec::new();
    for f in scan::rust_files(&src) {
        let code = production(&f);
        let called: BTreeSet<&String> = writers
            .iter()
            .filter(|w| code.contains(&format!(".{w}(")))
            .collect();
        if f.file_name().is_some_and(|n| n == "main.rs") {
            // The daemon's loops still run there, and write: seeing them proves the
            // matcher reads real code.
            assert!(
                !called.is_empty(),
                "main.rs writes nothing: the scan reads nothing"
            );
            continue;
        }
        scanned += 1;
        for w in called {
            found.push(format!("{}: {w}", scan::short(&f)));
        }
        // The Git mirror is the daemon's to write: opening it with `open_or_init`
        // creates a repository.
        if code.contains("GitMirror::open_or_init(") {
            found.push(format!("{}: GitMirror::open_or_init", scan::short(&f)));
        }
    }
    assert!(scanned >= 30, "only {scanned} web modules read");
    assert!(
        found.is_empty(),
        "a web module writes the state — ask hlb_privd an intent instead:\n{}",
        found.join("\n")
    );
}
