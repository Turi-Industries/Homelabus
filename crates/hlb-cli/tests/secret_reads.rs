//! A verb that prints a secret's value records the reading first, as `hlb secret-get`.
//!
//! `tests/audited.rs` holds the verbs that CHANGE something; a reading changes nothing
//! and was outside it. `hlb metrics deadman` printed the ntfy watchdog's password in its
//! script with no entry at all — a second door to a value `secret-get` audits, and the
//! one an intruder with a shell would take. Found by CodeQL's `rust/cleartext-logging`.

#![allow(clippy::expect_used)]

use std::io::Write;
use std::process::{Command, Stdio};

fn hlb(dir: &std::path::Path, args: &[&str], stdin: &str) -> (bool, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_hlb"))
        .current_dir(dir)
        .env("HLB_STATE", dir.join("state.db"))
        .env("HLB_MASTER_KEY", dir.join("master.key"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("hlb runs");
    child
        .stdin
        .take()
        .expect("a stdin")
        .write_all(stdin.as_bytes())
        .expect("stdin written");
    let out = child.wait_with_output().expect("hlb ends");
    (
        out.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

#[test]
fn the_deadman_script_is_audited_before_it_shows_the_watchdog_password() {
    let dir = tempfile::tempdir().expect("a directory");
    let name = hlb_engine::access::ntfy_watchdog_secret();
    let password = "Wd-pass-4815162342";

    let (ok, out) = hlb(dir.path(), &["secret-set", &name], password);
    assert!(ok, "{out}");

    let (ok, out) = hlb(
        dir.path(),
        &[
            "metrics",
            "deadman",
            "--ntfy",
            "https://ntfy.example.org/watch",
        ],
        "",
    );
    assert!(ok, "{out}");
    assert!(
        out.contains(password),
        "the script no longer carries the password, so this test guards nothing:\n{out}"
    );

    let (ok, trail) = hlb(dir.path(), &["audit"], "");
    assert!(ok, "{trail}");
    assert!(
        trail
            .lines()
            .any(|l| l.contains("secret-read") && l.contains(&name)),
        "printing the watchdog's password left no audit entry:\n{trail}"
    );
    assert!(!trail.contains(password), "the value reached the audit log");
}
