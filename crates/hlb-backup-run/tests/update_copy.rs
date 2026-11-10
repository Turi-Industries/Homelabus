//! An update's prior copy of an app holding only a database, against a real server and
//! the catalog's restic: the dump is the newest, recorded as taken, and what a failed
//! migration leaves is undone by restoring with nothing named — what was written after
//! the last pass included, which is the whole reason for it.
//!
//! ```sh
//! cargo test -p hlb-backup-run --test update_copy -- --ignored --nocapture
//! ```

#![allow(clippy::expect_used, clippy::unwrap_used)]

use hlb_backup_run::restore::{Database, Restore};
use hlb_backup_run::{provider_for_update, Admins, Pass};
use hlb_updater::BackupProvider;

const NETWORK: &str = "hlb-test-updatecopy";
const SERVER: &str = "hlb-test-updatecopy-pg";
const REPO: &str = "hlb-updatecopy-repo";
const PASSWORD: &str = "admin-password";

fn docker(args: &[&str]) -> std::process::Output {
    std::process::Command::new("docker")
        .args(args)
        .output()
        .expect("docker reachable")
}

fn psql(user: &str, sql: &str) -> String {
    let db = if user == "postgres" {
        "postgres"
    } else {
        "chat"
    };
    let out = docker(&[
        "exec",
        SERVER,
        "psql",
        "-U",
        user,
        "-d",
        db,
        "-v",
        "ON_ERROR_STOP=1",
        "-tAc",
        sql,
    ]);
    assert!(
        out.status.success(),
        "psql as {user} on \"{sql}\":\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

struct Cleanup;

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = docker(&["rm", "-f", SERVER]);
        let _ = docker(&["network", "rm", NETWORK]);
        let _ = docker(&["volume", "rm", "-f", REPO]);
    }
}

#[tokio::test]
#[ignore = "needs Docker"]
async fn a_database_alone_is_copied_before_an_update_and_a_failed_migration_undone_from_it() {
    let _cleanup = Cleanup;
    let _ = docker(&["rm", "-f", SERVER]);
    let _ = docker(&["volume", "rm", "-f", REPO]);
    docker(&["network", "create", NETWORK]);
    docker(&["volume", "create", REPO]);
    let up = docker(&[
        "run",
        "-d",
        "--name",
        SERVER,
        "--network",
        NETWORK,
        "-e",
        &format!("POSTGRES_PASSWORD={PASSWORD}"),
        hlb_backup::images::POSTGRES_CLIENT,
    ]);
    assert!(
        up.status.success(),
        "{}",
        String::from_utf8_lossy(&up.stderr)
    );
    // Over TCP: the image's first server, for its initialisation, listens on the socket.
    let ready = (0..60).any(|_| {
        std::thread::sleep(std::time::Duration::from_millis(500));
        docker(&[
            "exec",
            SERVER,
            "pg_isready",
            "-h",
            "127.0.0.1",
            "-U",
            "postgres",
        ])
        .status
        .success()
    });
    assert!(ready, "PostgreSQL never answered");

    psql(
        "postgres",
        "CREATE ROLE chat LOGIN PASSWORD 'chat-password'",
    );
    for s in hlb_platform::database_statements("chat", "chat").expect("statements") {
        psql("postgres", &s);
    }
    psql("chat", "CREATE TABLE kv (k text PRIMARY KEY, v text)");
    psql("chat", "INSERT INTO kv VALUES ('a', 'été')");

    let dir = tempfile::tempdir().expect("tmp");
    let state_path = dir.path().join("hlb.db");
    let state = hlb_state::State::open(&state_path).await.expect("state");
    let vault = hlb_secrets::Vault::open_or_init(dir.path().join("k.key")).expect("vault");
    let manifest: hlb_types::Manifest = serde_yaml_ng::from_str(
        r#"
apiVersion: hlb/v1
kind: App
metadata: { name: chat }
spec:
  image: { repo: a/b, tag: "1" }
  requires:
    - { kind: database, engine: postgres }
"#,
    )
    .expect("manifest");
    state
        .upsert_app("chat", &manifest, None)
        .await
        .expect("app");
    // Critical alone: an app holding only a database owes a bulky destination nothing.
    state
        .upsert_destination("nas", REPO, "critical", None)
        .await
        .expect("destination");
    let admin = format!("postgres://postgres:{PASSWORD}@{SERVER}:5432/postgres");

    // The last pass, then what is written after it: what the copy exists for.
    let pass = Pass {
        state: &state,
        vault: &vault,
        state_path: &state_path,
        fallback_repo: None,
        network: NETWORK,
        postgres_admin: Some(&admin),
        mariadb_admin: None,
        schedule: hlb_backup::Schedule::default(),
        force: true,
        only: Some("chat"),
        orchestrator: None,
        s3_endpoint: None,
    };
    let mut events = Vec::new();
    let sum = pass.run(&mut |e| events.push(e)).await.expect("pass");
    assert_eq!(sum.failed, 0, "{events:?}");
    psql("chat", "INSERT INTO kv VALUES ('b', 'since the pass')");

    let admins = Admins {
        postgres: Some(&admin),
        mariadb: None,
    };
    let copy = provider_for_update(&state, &vault, NETWORK, admins, None, None, "chat")
        .await
        .expect("read")
        .expect("a provider")
        .snapshot("chat")
        .await
        .expect("the copy");
    let taken = state.snapshots_taken("chat").await.expect("read");
    assert!(
        copy.iter().all(|c| taken.contains(c)),
        "a copy not recorded is one the restore refuses"
    );

    // What a failed migration leaves.
    psql("chat", "DELETE FROM kv WHERE k = 'a'");
    psql("chat", "CREATE TABLE migrated (x int)");

    let restore = Restore {
        state: &state,
        vault: &vault,
        fallback_repo: None,
        network: NETWORK,
        orchestrator: None,
    };
    let source = restore
        .find_dump("chat", hlb_types::DbEngine::Postgres, "chat", None, None)
        .await
        .expect("a dump");
    assert_eq!(
        std::slice::from_ref(&source.snapshot.id),
        copy.as_slice(),
        "the newest dump is the copy, and all of it"
    );
    let db = Database {
        engine: hlb_types::DbEngine::Postgres,
        name: "chat",
        role: "chat",
        extensions: &[],
    };
    restore
        .database_in_place("chat", &db, &admin, &source)
        .await
        .expect("restored");
    assert_eq!(
        psql(
            "chat",
            "SELECT string_agg(k || '=' || v, ',' ORDER BY k) FROM kv"
        ),
        "a=été,b=since the pass"
    );
    assert_eq!(
        psql("chat", "SELECT to_regclass('migrated') IS NOT NULL"),
        "f"
    );
}
