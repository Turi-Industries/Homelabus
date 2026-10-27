//! The vault and the state are opened through `open_vault` and `open_state`, nowhere else.
//!
//! Both default to a path relative to where `hlb` runs, and `Vault::open_or_init` creates
//! what it does not find: run from another directory, `hlb` made a new empty vault and
//! worked on it without a word. The two helpers create only where that is meant. One
//! direct call added tomorrow brings the silent vault back, so the source is read.

#![allow(clippy::expect_used)]

/// The functions allowed to call the constructors directly: the two guards, and the
/// one that reads the vault only after checking both files exist.
const GUARDS: &[&str] = &[
    "fn open_vault(",
    "fn open_state(",
    "fn with_platform_access(",
];

#[test]
fn the_vault_and_the_state_are_opened_only_through_their_guards() {
    let source = include_str!("../src/main.rs");
    let mut enclosing = "";
    let mut offenders = Vec::new();
    let mut seen = 0;
    for (n, line) in source.lines().enumerate() {
        let code = line.trim_start();
        if code.starts_with("fn ") || code.starts_with("async fn ") || code.contains(" fn ") {
            enclosing = code;
        }
        if code.starts_with("//") {
            continue;
        }
        if line.contains(concat!("Vault::", "open_or_init("))
            || line.contains(concat!("State::open(&", "cli.state)"))
        {
            seen += 1;
            if !GUARDS.iter().any(|g| enclosing.contains(g)) {
                offenders.push(format!("main.rs:{}: {}", n + 1, code));
            }
        }
    }
    // The floor: the guards themselves must have been found, or the scan reads nothing.
    assert!(
        seen >= 3,
        "only {seen} constructor calls found: the scan no longer matches"
    );
    assert!(
        offenders.is_empty(),
        "open them through open_vault / open_state:\n{}",
        offenders.join("\n")
    );
}

fn hlb(dir: &std::path::Path, args: &[&str]) -> std::process::Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_hlb"))
        .current_dir(dir)
        .env_remove("HLB_STATE")
        .env_remove("HLB_MASTER_KEY")
        .args(args)
        .output()
        .expect("hlb runs")
}

#[test]
fn a_path_given_is_created_and_a_default_one_never() {
    let dir = tempfile::tempdir().expect("a directory");
    let state = dir.path().join("state.db");
    let state = state.to_str().expect("utf-8");

    // Nothing here and nothing given: refused, and nothing written.
    let out = hlb(dir.path(), &["mesh", "sync"]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("no installation here"));
    assert!(!dir.path().join("hlb.db").exists() && !dir.path().join("hlb-master.key").exists());

    // The state given alone is created, for a command that never opens the vault: the
    // browser suite's signed-out controller is set up this way, and requiring both
    // paths broke it.
    let out = hlb(
        dir.path(),
        &["token", "create", "unused", "--state", state, "--apply"],
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Its vault, at the default path, is not created beside it: a new key could read
    // none of its secrets.
    let out = hlb(dir.path(), &["mesh", "sync", "--state", state]);
    assert!(!out.status.success());
    assert!(!dir.path().join("hlb-master.key").exists());
}
