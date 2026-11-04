//! `hlb secrets-forget`, through the binary. It deletes what restores nothing once gone,
//! so it asks for proof that the name was an app removed from this house: without it,
//! `secrets-forget restic` would take the password of every backup.

#![allow(clippy::expect_used)]

use std::path::Path;
use std::process::{Command, Output, Stdio};

fn hlb(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_hlb"))
        .current_dir(dir)
        .env("HLB_STATE", dir.join("hlb.db"))
        .env("HLB_MASTER_KEY", dir.join("master.age"))
        .stdin(Stdio::null())
        .args(args)
        .output()
        .expect("hlb runs")
}

fn deposit(dir: &Path, name: &str) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_hlb"))
        .current_dir(dir)
        .env("HLB_STATE", dir.join("hlb.db"))
        .env("HLB_MASTER_KEY", dir.join("master.age"))
        .args(["secret-set", name])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .expect("hlb runs");
    std::io::Write::write_all(child.stdin.as_mut().expect("stdin"), b"value").expect("write");
    assert!(child.wait().expect("ends").success(), "{name}");
}

fn text(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

fn state_of(dir: &Path) -> (tokio::runtime::Runtime, hlb_state::State) {
    let rt = tokio::runtime::Runtime::new().expect("runtime");
    let state = rt
        .block_on(hlb_state::State::open(dir.join("hlb.db")))
        .expect("state");
    (rt, state)
}

#[test]
fn a_removed_app_s_secrets_go_by_preview_then_by_name_and_nothing_else_does() {
    let house = tempfile::tempdir().expect("house");
    let dir = house.path();
    assert!(hlb(dir, &["emergency", "kit"]).status.success());
    for name in ["anubis-signing-key", "restic-repo-password", "cluster-ca"] {
        deposit(dir, name);
    }
    let vault = |dir: &Path| text(&hlb(dir, &["secrets"]));

    // Never removed from this house: no proof the name was an app's.
    for never in ["anubis", "restic", "cluster"] {
        let r = hlb(
            dir,
            &["secrets-forget", never, "--confirm", never, "--apply"],
        );
        assert!(!r.status.success(), "{never}: {}", text(&r));
        assert!(text(&r).contains("no record"), "{}", text(&r));
    }
    assert!(vault(dir).contains("anubis-signing-key"));

    let (rt, state) = state_of(dir);
    rt.block_on(state.audit(
        "cli",
        hlb_types::Role::Admin,
        hlb_state::APP_REMOVED,
        "anubis",
        "ok",
        None,
    ))
    .expect("audit");

    let preview = hlb(dir, &["secrets-forget", "anubis"]);
    assert!(preview.status.success(), "{}", text(&preview));
    assert!(text(&preview).contains("anubis-signing-key"));
    assert!(text(&preview).contains("Preview"));
    assert!(vault(dir).contains("anubis-signing-key"), "a preview acts");

    let wrong = hlb(
        dir,
        &["secrets-forget", "anubis", "--confirm", "other", "--apply"],
    );
    assert!(!wrong.status.success(), "{}", text(&wrong));
    assert!(vault(dir).contains("anubis-signing-key"));

    let done = hlb(
        dir,
        &["secrets-forget", "anubis", "--confirm", "anubis", "--apply"],
    );
    assert!(done.status.success(), "{}", text(&done));
    let left = vault(dir);
    assert!(!left.contains("anubis-signing-key"), "{left}");
    assert!(left.contains("restic-repo-password"), "{left}");
    assert!(left.contains("cluster-ca"), "{left}");

    let trail = rt
        .block_on(state.audit_for("anubis-signing-key", 5))
        .expect("audit");
    assert!(
        trail
            .iter()
            .any(|e| e.action == "secret-forget" && e.outcome == "ok"),
        "{trail:?}"
    );
}

#[test]
fn an_installed_app_s_secrets_stay_whatever_its_past() {
    let house = tempfile::tempdir().expect("house");
    let dir = house.path();
    assert!(hlb(dir, &["emergency", "kit"]).status.success());
    deposit(dir, "gitea-db-password");

    // Removed once, installed again since: what it runs on now is in the vault.
    let (rt, state) = state_of(dir);
    rt.block_on(async {
        state
            .audit(
                "cli",
                hlb_types::Role::Admin,
                hlb_state::APP_REMOVED,
                "gitea",
                "ok",
                None,
            )
            .await
            .expect("audit");
        let manifest = serde_json::from_str(
            r#"{"apiVersion":"hlb/v1","kind":"App","metadata":{"name":"gitea"},
                "spec":{"image":{"repo":"a/b","tag":"1"}}}"#,
        )
        .expect("manifest");
        state
            .upsert_app("gitea", &manifest, None)
            .await
            .expect("app");
    });

    let r = hlb(
        dir,
        &["secrets-forget", "gitea", "--confirm", "gitea", "--apply"],
    );
    assert!(!r.status.success(), "{}", text(&r));
    assert!(text(&r).contains("installed"), "{}", text(&r));
    assert!(text(&hlb(dir, &["secrets"])).contains("gitea-db-password"));
}
