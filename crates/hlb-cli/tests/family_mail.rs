//! The relatives the sealed kit is mailed to, through the binary. Without Stalwart the
//! kit is still written — and the run fails, saying nobody got it: a relative silently
//! skipped keeps a kit that restores an older house.

#![allow(clippy::expect_used)]

use std::path::Path;
use std::process::{Command, Output};

fn hlb(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_hlb"))
        .current_dir(dir)
        .env("HLB_STATE", dir.join("hlb.db"))
        .env("HLB_MASTER_KEY", dir.join("master.age"))
        .env("HLB_MAIL_DOMAIN", "home.example")
        .env_remove("HLB_STALWART_URL")
        .env_remove("HLB_STALWART_ADMIN")
        .env_remove("HLB_STALWART_PASSWORD")
        .args(args)
        .output()
        .expect("hlb runs")
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

#[test]
fn a_relative_is_added_by_preview_and_told_when_the_kit_could_not_reach_them() {
    let house = tempfile::tempdir().expect("house");
    let dir = house.path();
    let list = |dir: &Path| text(&hlb(dir, &["emergency", "relatives", "list"]).stdout);
    // The vault and the state, as `cluster init` leaves them.
    let first = hlb(dir, &["emergency", "kit"]);
    assert!(first.status.success(), "{first:?}");

    for refused in ["lena", "lena@home.example"] {
        let r = hlb(dir, &["emergency", "relatives", "add", refused, "--apply"]);
        assert!(!r.status.success(), "{refused}: {r:?}");
    }
    let preview = hlb(dir, &["emergency", "relatives", "add", "lena@example.net"]);
    assert!(preview.status.success(), "{preview:?}");
    assert!(text(&preview.stdout).contains("Preview"));
    assert!(list(dir).contains("No relative"), "a preview adds nobody");
    let added = hlb(
        dir,
        &[
            "emergency",
            "relatives",
            "add",
            "lena@example.net",
            "--apply",
        ],
    );
    assert!(added.status.success(), "{added:?}");
    assert!(list(dir).contains("lena@example.net"));

    // Split: the sheets and the sealed kit are written, the mail fails out loud.
    let family = dir.join("family");
    let split = hlb(
        dir,
        &[
            "emergency",
            "split",
            "--out",
            family.to_str().expect("utf-8"),
        ],
    );
    assert!(!split.status.success(), "nobody got it: {split:?}");
    assert!(
        text(&split.stderr).contains("mailed to nobody"),
        "{split:?}"
    );
    assert!(family.join("kit.age").exists());

    // On standard output, the sealed kit alone: what `> kit.age` writes must open.
    let sealed = hlb(dir, &["emergency", "kit", "--sealed"]);
    assert!(!sealed.status.success(), "{sealed:?}");
    let out = text(&sealed.stdout);
    assert!(
        out.starts_with("-----BEGIN AGE ENCRYPTED FILE-----"),
        "{out}"
    );
    assert!(
        out.trim_end().ends_with("-----END AGE ENCRYPTED FILE-----"),
        "{out}"
    );
    assert!(text(&sealed.stderr).contains("mailed to nobody"));

    let removed = hlb(
        dir,
        &[
            "emergency",
            "relatives",
            "remove",
            "lena@example.net",
            "--apply",
        ],
    );
    assert!(removed.status.success(), "{removed:?}");
    assert!(list(dir).contains("No relative"));
    let alone = hlb(dir, &["emergency", "kit", "--sealed"]);
    assert!(alone.status.success(), "{alone:?}");
    assert!(text(&alone.stdout).starts_with("-----BEGIN AGE ENCRYPTED FILE-----"));
}
