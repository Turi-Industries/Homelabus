//! The account verbs change nothing without `--apply`, and refuse what is not theirs.
//!
//! Run against a state of its own, with neither PocketID nor Stalwart: what is checked
//! is what the verbs decide before reaching either.

#![allow(clippy::expect_used)]

struct Install {
    dir: tempfile::TempDir,
}

impl Install {
    fn new() -> Self {
        Self {
            dir: tempfile::tempdir().expect("a directory"),
        }
    }

    fn hlb(&self, args: &[&str]) -> (bool, String) {
        let state = self.dir.path().join("state.db");
        let key = self.dir.path().join("master.key");
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_hlb"))
            .current_dir(self.dir.path())
            .env("HLB_STATE", &state)
            .env("HLB_MASTER_KEY", &key)
            .env("HLB_MAIL_DOMAIN", "example.org")
            .env_remove("HLB_POCKETID_URL")
            .env_remove("HLB_POCKETID_KEY")
            .env_remove("HLB_STALWART_URL")
            .env_remove("HLB_STALWART_ADMIN")
            .env_remove("HLB_STALWART_PASSWORD")
            .args(args)
            .output()
            .expect("hlb runs");
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        (out.status.success(), text)
    }
}

#[test]
fn a_person_is_added_only_with_apply() {
    // 🔴 `hlb user add` had no `--apply`: it recorded the account and created the
    // PocketID identity at once, while every screen advertised it with the flag.
    let i = Install::new();
    let (ok, out) = i.hlb(&["user", "add", "lena"]);
    assert!(ok, "{out}");
    assert!(out.contains("Preview"), "{out}");
    let (_, list) = i.hlb(&["user", "list"]);
    assert!(
        list.contains("No account"),
        "a preview recorded lena: {list}"
    );

    // Applied without Stalwart: recorded, its mailbox NOT — and said.
    let (ok, out) = i.hlb(&["user", "add", "lena", "--apply"]);
    assert!(!ok, "an account without its mailbox is not complete: {out}");
    assert!(out.contains("NOT opened"), "{out}");
    let (_, list) = i.hlb(&["user", "list"]);
    assert!(list.contains("lena"), "{list}");
    assert!(
        !list.contains("lena@example.org"),
        "a mailbox Stalwart never opened was recorded: {list}"
    );
}

#[test]
fn a_reserved_address_is_nobody_s_account() {
    let i = Install::new();
    let (ok, out) = i.hlb(&["user", "add", "postmaster", "--apply"]);
    assert!(!ok, "{out}");
    assert!(out.contains("reserved"), "{out}");
    let (ok, out) = i.hlb(&[
        "user",
        "add",
        "lena",
        "--email",
        "abuse@example.org",
        "--apply",
    ]);
    assert!(!ok, "{out}");
    assert!(out.contains("reserved"), "{out}");
}

#[test]
fn a_mailbox_that_is_not_the_account_s_is_refused() {
    let i = Install::new();
    let _ = i.hlb(&["user", "add", "lena", "--apply"]);

    // 🔴 Removing a mailbox the account does not have printed a tick.
    let (ok, out) = i.hlb(&["user", "mailbox", "remove", "lena", "nothing", "--apply"]);
    assert!(!ok, "{out}");
    assert!(out.contains("no mailbox"), "{out}");

    // An alias on a mailbox that is not lena's would have counted against lena while the
    // mail went elsewhere.
    let (ok, out) = i.hlb(&["user", "alias", "add", "lena", "--mailbox", "bob"]);
    assert!(!ok, "{out}");
    assert!(out.contains("no mailbox"), "{out}");
}
