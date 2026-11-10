//! A MariaDB database through the pass and back, against the catalog's server and
//! restic: the database comes back as the pass dumped it — a table added since gone, its
//! trigger still firing for the app's user, the server's other database untouched —,
//! and the copy the restore took first undoes it.
//!
//! ```sh
//! cargo test -p hlb-backup-run --test maria_database -- --ignored --nocapture
//! ```

#![allow(clippy::expect_used, clippy::unwrap_used)]

use hlb_backup_run::restore::{Database, Restore};
use hlb_backup_run::{Event, Pass};
use hlb_types::DbEngine;

const NETWORK: &str = "hlb-test-mariarestore";
const SERVER: &str = "hlb-test-mariarestore-db";
const PASSWORD: &str = "admin-password";

fn docker(args: &[&str]) -> std::process::Output {
    std::process::Command::new("docker")
        .args(args)
        .output()
        .expect("docker reachable")
}

/// `statement` as `user` (root's password, or the user's name followed by `-password`),
/// in `db` — `""` for none; its rows, tab-separated.
fn sql(user: &str, db: &str, statement: &str) -> String {
    let password = if user == "root" {
        PASSWORD.to_string()
    } else {
        format!("{user}-password")
    };
    let mut args = vec![
        "exec".to_string(),
        "-e".into(),
        format!("MYSQL_PWD={password}"),
        SERVER.into(),
        "mariadb".into(),
        format!("-u{user}"),
        "-N".into(),
        "-B".into(),
    ];
    if !db.is_empty() {
        args.push(db.into());
    }
    args.extend(["-e".into(), statement.into()]);
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let out = docker(&args);
    assert!(
        out.status.success(),
        "mariadb as {user} on \"{statement}\":\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// Removes the server, its network and the repository when dropped, failing or not.
struct Cleanup(&'static str);

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = docker(&["rm", "-f", SERVER]);
        let _ = docker(&["network", "rm", NETWORK]);
        let _ = docker(&["volume", "rm", "-f", self.0]);
    }
}

#[tokio::test]
#[ignore = "needs Docker"]
async fn a_mariadb_database_dumped_comes_back_whole_and_the_copy_taken_first_undoes_it() {
    let repo = "hlb-mariarestore-repo";
    let _cleanup = Cleanup(repo);
    let _ = docker(&["rm", "-f", SERVER]);
    let _ = docker(&["volume", "rm", "-f", repo]);
    docker(&["network", "create", NETWORK]);
    docker(&["volume", "create", repo]);
    // The server is the dump client's own image, as the catalog's is.
    let up = docker(&[
        "run",
        "-d",
        "--name",
        SERVER,
        "--network",
        NETWORK,
        "-e",
        &format!("MARIADB_ROOT_PASSWORD={PASSWORD}"),
        hlb_backup::images::MARIADB_CLIENT,
    ]);
    assert!(
        up.status.success(),
        "{}",
        String::from_utf8_lossy(&up.stderr)
    );
    // The image restarts the server once after initialising it.
    let ready = (0..90).any(|_| {
        std::thread::sleep(std::time::Duration::from_secs(1));
        docker(&[
            "exec",
            SERVER,
            "healthcheck.sh",
            "--connect",
            "--innodb_initialized",
        ])
        .status
        .success()
    });
    assert!(ready, "MariaDB never answered");

    // The app's user and database as `ProvisionDatabase` leaves them, and another app's
    // on the same server.
    for (app, db) in [("chat", "chat"), ("other", "other_db")] {
        sql(
            "root",
            "",
            &format!("CREATE USER '{app}'@'%' IDENTIFIED BY '{app}-password'"),
        );
        for s in hlb_platform::mariadb::database_statements(db, app).expect("statements") {
            sql("root", "", &s);
        }
    }
    sql(
        "other",
        "other_db",
        "CREATE TABLE t (v TEXT); INSERT INTO t VALUES ('kept')",
    );
    sql(
        "chat",
        "chat",
        "CREATE TABLE kv (k VARCHAR(8) PRIMARY KEY, v TEXT) ENGINE=InnoDB;
         CREATE TABLE log (k VARCHAR(8)) ENGINE=InnoDB;
         CREATE TRIGGER logged AFTER INSERT ON kv FOR EACH ROW INSERT INTO log VALUES (NEW.k);
         INSERT INTO kv VALUES ('a', 'été');",
    );

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
    - { kind: database, engine: mariadb }
"#,
    )
    .expect("manifest");
    state
        .upsert_app("chat", &manifest, None)
        .await
        .expect("app");
    state
        .upsert_destination("nas", repo, "critical,bulky", None)
        .await
        .expect("destination");

    let admin = format!("mariadb://root:{PASSWORD}@{SERVER}:3306");
    let pass = Pass {
        state: &state,
        vault: &vault,
        state_path: &state_path,
        fallback_repo: None,
        network: NETWORK,
        postgres_admin: None,
        postgres_vital_admin: None,
        mariadb_admin: Some(&admin),
        schedule: hlb_backup::Schedule::default(),
        force: true,
        only: Some("chat"),
        orchestrator: None,
        s3_endpoint: None,
    };
    let mut events = Vec::new();
    let sum = pass.run(&mut |e| events.push(e)).await.expect("pass");
    assert_eq!(sum.failed, 0, "{events:?}");
    assert!(
        events.iter().any(
            |e| matches!(e, Event::Done { what, destination, .. } if what == "chat/chat" && destination == "nas")
        ),
        "{events:?}"
    );

    // What a failed update leaves: a row changed, one added, a table a migration made.
    sql("chat", "chat", "UPDATE kv SET v = 'hiver' WHERE k = 'a'");
    sql("chat", "chat", "INSERT INTO kv VALUES ('b', 'since')");
    sql("chat", "chat", "CREATE TABLE later (x INT)");
    let rows = "SELECT GROUP_CONCAT(CONCAT(k, '=', v) ORDER BY k) FROM kv";
    let later = "SELECT COUNT(*) FROM information_schema.TABLES \
                 WHERE TABLE_SCHEMA = 'chat' AND TABLE_NAME = 'later'";

    let restore = Restore {
        state: &state,
        vault: &vault,
        fallback_repo: None,
        network: NETWORK,
        orchestrator: None,
    };
    let db = Database {
        engine: DbEngine::Mariadb,
        name: "chat",
        role: "chat",
        extensions: &[],
    };
    let source = restore
        .find_dump("chat", DbEngine::Mariadb, "chat", None, None)
        .await
        .expect("the pass's dump, recorded as taken");
    let before = restore
        .database_in_place("chat", &db, &admin, &source)
        .await
        .expect("restored");
    assert_eq!(sql("chat", "chat", rows), "a=été");
    assert_eq!(
        sql("chat", "chat", later),
        "0",
        "a table made since is gone"
    );
    sql(
        "chat",
        "chat",
        "INSERT INTO kv VALUES ('c', 'written after')",
    );
    assert_eq!(
        sql("chat", "chat", "SELECT GROUP_CONCAT(k ORDER BY k) FROM log"),
        "a,c",
        "restored by the administrator, the app's trigger still fires for the app"
    );
    assert_eq!(
        sql("other", "other_db", "SELECT v FROM t"),
        "kept",
        "restored at server level, the dump touched no other database"
    );
    assert_eq!(
        sql(
            "root",
            "",
            "SELECT COUNT(*) FROM information_schema.SCHEMA_PRIVILEGES \
             WHERE TABLE_SCHEMA = 'chat' AND GRANTEE = \"'other'@'%'\""
        ),
        "0",
        "recreated, the database is still shut to other users"
    );

    // The copy taken first undoes the restore.
    let undo = restore
        .find_dump("chat", DbEngine::Mariadb, "chat", None, Some(&before))
        .await
        .expect("the copy taken before");
    restore
        .database_in_place("chat", &db, &admin, &undo)
        .await
        .expect("undone");
    assert_eq!(sql("chat", "chat", rows), "a=hiver,b=since");
    assert_eq!(sql("chat", "chat", later), "1");

    // Asked for the latest again, the restore never takes its own copy.
    let latest = restore
        .find_dump("chat", DbEngine::Mariadb, "chat", None, None)
        .await
        .expect("latest");
    assert_eq!(latest.snapshot.id, source.snapshot.id);
    println!("✓ chat: dumped, restored whole, and the restore undone");
}
