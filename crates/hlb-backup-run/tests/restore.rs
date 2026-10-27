//! A restore, against a real restic: the volume comes back as the pass took it, what
//! was added since is gone, and the copy taken first undoes it.
//!
//! ```sh
//! cargo test -p hlb-backup-run --test restore -- --ignored --nocapture
//! ```

#![allow(clippy::expect_used, clippy::unwrap_used)]

use hlb_backup_run::placement::Place;
use hlb_backup_run::restore::Restore;
use hlb_backup_run::Pass;

fn docker(args: &[&str]) -> std::process::Output {
    std::process::Command::new("docker")
        .args(args)
        .output()
        .expect("docker reachable")
}

/// The volume's files, `name=content`, sorted.
fn files(volume: &str) -> String {
    let out = docker(&[
        "run",
        "--rm",
        "-v",
        &format!("{volume}:/d"),
        "alpine:3",
        "sh",
        "-c",
        "cd /d && for f in $(find . -type f | sort); do echo \"$f=$(cat $f)\"; done",
    ]);
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn write(volume: &str, script: &str) {
    let w = docker(&[
        "run",
        "--rm",
        "-v",
        &format!("{volume}:/d"),
        "alpine:3",
        "sh",
        "-c",
        script,
    ]);
    assert!(w.status.success(), "{w:?}");
}

#[tokio::test]
#[ignore = "needs Docker"]
async fn a_volume_comes_back_as_backed_up_and_the_restore_is_undone_by_its_copy() {
    let dir = tempfile::tempdir().expect("tmp");
    let state_path = dir.path().join("hlb.db");
    let state = hlb_state::State::open(&state_path).await.expect("state");
    let vault = hlb_secrets::Vault::open_or_init(dir.path().join("k.key")).expect("vault");

    let (data, repo) = ("hlb-restore-data", "hlb-restore-repo");
    for v in [data, repo] {
        let _ = docker(&["volume", "rm", "-f", v]);
        docker(&["volume", "create", v]);
    }
    write(
        data,
        "mkdir -p /d/sub && echo good > /d/db && echo kept > /d/sub/f",
    );

    let manifest: hlb_types::Manifest = serde_yaml_ng::from_str(
        "apiVersion: hlb/v1\nkind: App\nmetadata: { name: demo }\n\
         spec:\n  image: { repo: a/b, tag: \"1\" }\n",
    )
    .expect("manifest");
    state
        .upsert_app("demo", &manifest, None)
        .await
        .expect("app");
    state
        .add_volume("demo", data, "/unused", true, false)
        .await
        .expect("volume");
    state
        .upsert_destination("nas", repo, "critical,bulky", None)
        .await
        .expect("destination");
    let pass = Pass {
        state: &state,
        vault: &vault,
        state_path: &state_path,
        fallback_repo: None,
        network: "bridge",
        postgres_admin: None,
        mariadb_admin: None,
        schedule: hlb_backup::Schedule::default(),
        force: true,
        only: None,
        orchestrator: None,
        s3_endpoint: None,
    };
    let sum = pass.run(&mut |_| {}).await.expect("pass");
    assert_eq!(sum.failed, 0);
    let good = files(data);

    // The day it broke: a file rewritten, one added, one removed.
    write(
        data,
        "echo migrated > /d/db && echo new > /d/journal && rm /d/sub/f",
    );
    let broken = files(data);
    assert_ne!(good, broken);

    // And an intruder holding the repository's password writes the latest snapshot
    // of their own, of what they want restored.
    let password = hlb_backup_run::restic_password(&state, &vault)
        .await
        .expect("password");
    let forged = hlb_backup::Repository::new(
        hlb_backup::runner::ContainerRunner::default()
            .mount(repo, "/repo")
            .mount(data, hlb_backup_run::volume_path(data)),
        "/repo",
        password,
    )
    .backup(
        &hlb_backup_run::volume_path(data),
        &["app:demo", "kind:pre-update"],
    )
    .await
    .expect("a snapshot nobody recorded");

    let r = Restore {
        state: &state,
        vault: &vault,
        fallback_repo: None,
        network: "bridge",
        orchestrator: None,
    };
    let place = r.place_of("demo", data).await.expect("place");
    assert_eq!(place, Place::Here);
    let source = r.find("demo", data, None, None).await.expect("snapshot");
    assert_ne!(
        source.snapshot.id, forged,
        "the intruder's snapshot was taken"
    );
    assert_eq!(
        source
            .set_aside
            .iter()
            .map(|(s, _)| s.id.as_str())
            .collect::<Vec<_>>(),
        [forged.as_str()]
    );
    // A prefix of it pins nothing: refused, and said.
    let refused = r
        .find("demo", data, None, Some(&forged[..8]))
        .await
        .expect_err("a prefix of a snapshot nobody took");
    assert!(refused.contains("full id"), "{refused}");
    let before = r
        .in_place("demo", data, &place, &source)
        .await
        .expect("restore");
    assert_eq!(files(data), good, "the volume is not what was backed up");

    // The latest is still the pass's, never the copy the restore took.
    let again = r.find("demo", data, None, None).await.expect("snapshot");
    assert_eq!(again.snapshot.id, source.snapshot.id);

    // Restored the wrong day: the copy gives back what was there.
    let copy = r
        .find("demo", data, None, Some(&before[..8]))
        .await
        .expect("the copy taken first");
    r.in_place("demo", data, &place, &copy).await.expect("undo");
    assert_eq!(files(data), broken, "the copy taken first does not undo it");

    for v in [data, repo] {
        let _ = docker(&["volume", "rm", "-f", v]);
    }
}

/// `python3 -c` on the host, its standard output.
fn py(script: &str) -> String {
    let out = std::process::Command::new("python3")
        .args(["-I", "-c", script])
        .output()
        .expect("python3");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

#[tokio::test]
#[ignore = "needs Docker and python3"]
async fn a_sqlite_database_comes_back_from_its_consistent_snapshot_owned_as_it_was() {
    use std::os::unix::fs::MetadataExt;
    let dir = tempfile::tempdir().expect("tmp");
    let state_path = dir.path().join("hlb.db");
    let state = hlb_state::State::open(&state_path).await.expect("state");
    let vault = hlb_secrets::Vault::open_or_init(dir.path().join("k.key")).expect("vault");

    // The volume is a directory of this machine, bound: the pass reads it by its path.
    let host = tempfile::tempdir().expect("volume dir");
    std::fs::create_dir(host.path().join("data")).expect("sub");
    let (data, repo) = ("hlb-restore-sqlite", "hlb-restore-sqlite-repo");
    for v in [data, repo] {
        let _ = docker(&["volume", "rm", "-f", v]);
    }
    let device = format!("device={}", host.path().display());
    assert!(docker(&[
        "volume",
        "create",
        "--driver",
        "local",
        "--opt",
        "type=none",
        "--opt",
        "o=bind",
        "--opt",
        &device,
        data,
    ])
    .status
    .success());
    docker(&["volume", "create", repo]);
    let db = host.path().join("data/app.db");
    let db_s = db.display().to_string();
    // In WAL mode, and held open while the pass runs: its last rows are in the WAL.
    py(&format!(
        "import sqlite3; c=sqlite3.connect('{db_s}'); c.execute('PRAGMA journal_mode=WAL'); \
         c.execute('CREATE TABLE t (v TEXT)'); c.executemany('INSERT INTO t VALUES (?)', \
         [('good',)]*500); c.commit()"
    ));
    let mut holder = std::process::Command::new("python3")
        .args([
            "-I",
            "-c",
            &format!(
                "import sqlite3,time; c=sqlite3.connect('{db_s}'); \
                 c.execute('PRAGMA wal_autocheckpoint=0'); \
                 c.executemany('INSERT INTO t VALUES (?)', [('good',)]*500); c.commit(); \
                 time.sleep(120)"
            ),
        ])
        .spawn()
        .expect("holder");
    std::thread::sleep(std::time::Duration::from_secs(1));
    assert!(
        host.path()
            .join("data/app.db-wal")
            .metadata()
            .expect("wal")
            .len()
            > 0
    );
    let owner = std::fs::metadata(&db).expect("db").uid();
    let dir_before = std::fs::metadata(host.path().join("data")).expect("data dir");

    let manifest: hlb_types::Manifest = serde_yaml_ng::from_str(
        "apiVersion: hlb/v1\nkind: App\nmetadata: { name: demo }\n\
         spec:\n  image: { repo: a/b, tag: \"1\" }\n",
    )
    .expect("manifest");
    state
        .upsert_app("demo", &manifest, None)
        .await
        .expect("app");
    state
        .add_volume("demo", data, &host.path().display().to_string(), true, true)
        .await
        .expect("volume");
    state
        .upsert_destination("nas", repo, "critical,bulky", None)
        .await
        .expect("destination");
    let pass = Pass {
        state: &state,
        vault: &vault,
        state_path: &state_path,
        fallback_repo: None,
        network: "bridge",
        postgres_admin: None,
        mariadb_admin: None,
        schedule: hlb_backup::Schedule::default(),
        force: true,
        only: None,
        orchestrator: None,
        s3_endpoint: None,
    };
    let mut said = Vec::new();
    let sum = pass
        .run(&mut |e| said.push(format!("{e:?}")))
        .await
        .expect("pass");
    assert_eq!(sum.failed, 0, "{said:#?}");
    let _ = holder.kill();
    let _ = holder.wait();

    // The day it broke.
    py(&format!(
        "import sqlite3; c=sqlite3.connect('{db_s}'); c.execute(\"UPDATE t SET v='bad'\"); c.commit()"
    ));

    let r = Restore {
        state: &state,
        vault: &vault,
        fallback_repo: None,
        network: "bridge",
        orchestrator: None,
    };
    let place = r.place_of("demo", data).await.expect("place");
    let source = r.find("demo", data, None, None).await.expect("snapshot");
    r.in_place("demo", data, &place, &source)
        .await
        .expect("restore");
    let back = r
        .sqlite_after("demo", data, &place, &source)
        .await
        .expect("sqlite");
    assert_eq!(
        back.iter().map(|(d, _)| d.as_str()).collect::<Vec<_>>(),
        ["data/app.db"]
    );
    assert_eq!(
        py(&format!(
            "import sqlite3; c=sqlite3.connect('{db_s}'); \
             print(c.execute('PRAGMA integrity_check').fetchone()[0], \
             c.execute(\"SELECT count(*) FROM t WHERE v='good'\").fetchone()[0], \
             c.execute('SELECT count(*) FROM t').fetchone()[0])"
        )),
        "ok 1000 1000",
        "the WAL's last rows are in the consistent snapshot, and nothing else"
    );
    let meta = std::fs::metadata(&db).expect("db");
    assert_eq!(meta.uid(), owner, "owned as it was, not by root");
    // Restored at `/`, the staging volume's directories came back root's, 0755.
    let dir_after = std::fs::metadata(host.path().join("data")).expect("data dir");
    assert_eq!(
        (dir_after.uid(), dir_after.mode()),
        (dir_before.uid(), dir_before.mode()),
        "the database's directory keeps its owner and mode"
    );
    assert_eq!(
        host.path()
            .join("data/app.db-wal")
            .metadata()
            .map(|m| m.len())
            .unwrap_or(0),
        0,
        "no journal left from the live copy"
    );
    println!(
        "✓ {} put back from {}, consistent and owned as it was",
        back[0].0, back[0].1
    );

    for v in [data, repo] {
        let _ = docker(&["volume", "rm", "-f", v]);
    }
}
