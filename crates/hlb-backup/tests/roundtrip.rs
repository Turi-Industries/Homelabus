//! Backup -> destruction -> restore -> comparison, against a real restic.
//!
//! **"An untested backup is not a backup"**. Checking that restic
//! returns a snapshot id proves nothing; the only useful proof is to destroy the data and
//! observe that it comes back identical.
//!
//! ```sh
//! export DOCKER_HOST=$(docker context inspect -f '{{.Endpoints.docker.Host}}')
//! cargo test -p hlb-backup -- --ignored --test-threads=1 --nocapture
//! ```

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::path::Path;

use hlb_backup::{ContainerRunner, Repository, RetentionPolicy};

/// Everything happens in a Docker volume: the host's temp directory is not shared with
/// the Docker VM on macOS (a lesson learnt on the Caddy tests).
const WORKDIR: &str = "/work";

fn repo_in(volume: &str) -> Repository<ContainerRunner> {
    let runner = ContainerRunner::new("restic/restic:latest").mount(volume, WORKDIR);
    Repository::new(runner, format!("{WORKDIR}/repo"), "test-password")
}

/// Runs a shell command inside the shared volume.
fn in_volume(volume: &str, script: &str) -> String {
    let out = std::process::Command::new("docker")
        .args([
            "run",
            "--rm",
            "-v",
            &format!("{volume}:{WORKDIR}"),
            "alpine:3",
            "sh",
            "-c",
            script,
        ])
        .output()
        .expect("docker reachable (DOCKER_HOST?)");
    assert!(
        out.status.success(),
        "script failed: {}\n{}",
        script,
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).to_string()
}

fn make_volume(name: &str) -> String {
    let _ = std::process::Command::new("docker")
        .args(["volume", "rm", "-f", name])
        .output();
    std::process::Command::new("docker")
        .args(["volume", "create", name])
        .output()
        .expect("volume creation");
    name.to_string()
}

fn drop_volume(name: &str) {
    let _ = std::process::Command::new("docker")
        .args(["volume", "rm", "-f", name])
        .output();
}

/// Fingerprint of the content: path -> checksum.
fn fingerprint(volume: &str, dir: &str) -> BTreeMap<String, String> {
    let out = in_volume(
        volume,
        &format!("cd {dir} && find . -type f | sort | xargs -I{{}} sh -c 'echo \"{{}} $(md5sum < {{}})\"'"),
    );
    out.lines()
        .filter_map(|l| l.split_once(' '))
        .map(|(p, h)| (p.to_string(), h.trim().to_string()))
        .collect()
}

#[tokio::test]
#[ignore = "needs Docker"]
async fn data_survives_destruction_and_comes_back_identical() {
    let vol = make_volume("hlb-test-backup");
    let repo = repo_in(&vol);

    // 1. Realistic data: a directory tree, varied contents, a binary file.
    in_volume(
        &vol,
        &format!(
            "mkdir -p {WORKDIR}/data/nested/folder && \
             echo 'main content' > {WORKDIR}/data/file.txt && \
             echo 'nested' > {WORKDIR}/data/nested/folder/deep.txt && \
             head -c 4096 /dev/urandom > {WORKDIR}/data/binary.bin"
        ),
    );
    let before = fingerprint(&vol, &format!("{WORKDIR}/data"));
    assert_eq!(before.len(), 3, "three files expected: {before:?}");
    println!("✓ {} files created", before.len());

    // 2. Backup.
    repo.init().await.expect("init");
    let id = repo
        .backup(&format!("{WORKDIR}/data"), &["app:test"])
        .await
        .expect("backup");
    println!("✓ snapshot {}", &id[..8]);

    // 3. 🔴 Total destruction.
    in_volume(&vol, &format!("rm -rf {WORKDIR}/data"));
    let after_destruction = fingerprint(&vol, WORKDIR);
    assert!(
        // `./data/`, not "data": the repository beside it has a `data/` of its own.
        !after_destruction.keys().any(|k| k.starts_with("./data/")),
        "the data should have vanished"
    );
    println!("✓ data destroyed");

    // 4. Restore.
    repo.restore(&id, "/").await.expect("restore");

    // 5. Comparison, file by file.
    let after = fingerprint(&vol, &format!("{WORKDIR}/data"));
    assert_eq!(
        before, after,
        "the restored content differs from the original"
    );
    println!("✓ {} files restored identically", after.len());

    drop_volume(&vol);
}

#[tokio::test]
#[ignore = "needs Docker"]
async fn snapshots_are_listed_and_tagged() {
    let vol = make_volume("hlb-test-snapshots");
    let repo = repo_in(&vol);

    in_volume(
        &vol,
        &format!("mkdir -p {WORKDIR}/a && echo one > {WORKDIR}/a/f.txt"),
    );
    repo.init().await.expect("init");

    repo.backup(&format!("{WORKDIR}/a"), &["app:gitea"])
        .await
        .expect("1");
    in_volume(&vol, &format!("echo two > {WORKDIR}/a/f.txt"));
    repo.backup(&format!("{WORKDIR}/a"), &["app:gitea"])
        .await
        .expect("2");

    let all = repo.snapshots(None).await.expect("list");
    assert_eq!(all.len(), 2, "{all:?}");

    let filters = repo
        .snapshots(Some("app:gitea"))
        .await
        .expect("filtered list");
    assert_eq!(filters.len(), 2);

    let others = repo
        .snapshots(Some("app:inexistante"))
        .await
        .expect("filtered list");
    assert!(others.is_empty(), "the tag filter must actually filter");

    println!("✓ {} snapshots, tag filtering operational", all.len());
    drop_volume(&vol);
}

#[tokio::test]
#[ignore = "needs Docker"]
async fn point_in_time_restore_picks_the_right_version() {
    // The real case: you want the version from BEFORE the blunder, not the last one.
    let vol = make_volume("hlb-test-pitr");
    let repo = repo_in(&vol);

    in_volume(
        &vol,
        &format!("mkdir -p {WORKDIR}/d && echo 'version bonne' > {WORKDIR}/d/f.txt"),
    );
    repo.init().await.expect("init");
    let good = repo
        .backup(&format!("{WORKDIR}/d"), &["app:test"])
        .await
        .expect("1");

    in_volume(
        &vol,
        &format!("echo 'version corrompue' > {WORKDIR}/d/f.txt"),
    );
    repo.backup(&format!("{WORKDIR}/d"), &["app:test"])
        .await
        .expect("2");

    // We explicitly restore the first snapshot.
    in_volume(&vol, &format!("rm -rf {WORKDIR}/d"));
    repo.restore(&good, "/").await.expect("restore");

    let content = in_volume(&vol, &format!("cat {WORKDIR}/d/f.txt"));
    assert!(
        content.contains("version bonne"),
        "we restored the wrong version: {content}"
    );
    println!("✓ restore targeted the right snapshot");

    drop_volume(&vol);
}

#[tokio::test]
#[ignore = "needs Docker"]
async fn integrity_check_passes_on_a_healthy_repository() {
    let vol = make_volume("hlb-test-check");
    let repo = repo_in(&vol);

    in_volume(
        &vol,
        &format!("mkdir -p {WORKDIR}/d && echo x > {WORKDIR}/d/f"),
    );
    repo.init().await.expect("init");
    repo.backup(&format!("{WORKDIR}/d"), &["app:test"])
        .await
        .expect("backup");

    repo.check().await.expect("the repository must be healthy");
    println!("✓ integrity verified");

    drop_volume(&vol);
}

#[tokio::test]
#[ignore = "needs Docker"]
async fn retention_removes_old_snapshots_but_keeps_the_recent_one() {
    let vol = make_volume("hlb-test-retention");
    let repo = repo_in(&vol);

    in_volume(
        &vol,
        &format!("mkdir -p {WORKDIR}/d && echo a > {WORKDIR}/d/f"),
    );
    repo.init().await.expect("init");

    for i in 0..3 {
        in_volume(&vol, &format!("echo {i} > {WORKDIR}/d/f"));
        repo.backup(&format!("{WORKDIR}/d"), &["app:test"])
            .await
            .expect("backup");
    }
    assert_eq!(repo.snapshots(None).await.expect("list").len(), 3);

    // Keep only the last one.
    let strict = RetentionPolicy {
        hourly: 0,
        daily: 0,
        weekly: 0,
        monthly: 0,
        yearly: 1,
    };
    repo.forget(&strict, true).await.expect("forget");

    let remaining = repo.snapshots(None).await.expect("list");

    // 🔴 The assertion that counts: retention must REALLY delete.
    //
    // A `forget` that runs without error but deletes nothing is the worst case: the
    // policy looks configured, and the disk fills up anyway.
    assert_eq!(
        remaining.len(),
        1,
        "retention deleted nothing — are the snapshots grouped under different \
         hosts? {remaining:#?}"
    );
    println!("✓ 3 snapshots -> 1 kept");

    drop_volume(&vol);
}

#[tokio::test]
#[ignore = "needs Docker"]
async fn a_wrong_password_cannot_read_the_repository() {
    // The encryption must be real, not decorative.
    let vol = make_volume("hlb-test-crypto");
    let repo = repo_in(&vol);

    in_volume(
        &vol,
        &format!("mkdir -p {WORKDIR}/d && echo secret > {WORKDIR}/d/f"),
    );
    repo.init().await.expect("init");
    repo.backup(&format!("{WORKDIR}/d"), &["app:test"])
        .await
        .expect("backup");

    let intruder = Repository::new(
        ContainerRunner::new("restic/restic:latest").mount(&vol, WORKDIR),
        format!("{WORKDIR}/repo"),
        "wrong-password",
    );
    assert!(
        intruder.snapshots(None).await.is_err(),
        "a wrong password must yield nothing"
    );
    println!("✓ repository unreadable without the right password");

    drop_volume(&vol);
}

/// Sanity: the test path itself must be valid.
#[test]
fn the_workdir_is_absolute() {
    assert!(Path::new(WORKDIR).is_absolute());
}

// ── Restore verification ──────────────────────────────────────────────

/// Counts files and bytes under a path of the shared volume.
fn count_files(volume: &str, dir: &str) -> (u64, u64) {
    let out = in_volume(
        volume,
        &format!("find {dir} -type f 2>/dev/null | wc -l; find {dir} -type f -exec stat -c %s {{}} + 2>/dev/null | awk '{{s+=$1}} END {{print s+0}}'"),
    );
    let mut l = out.lines();
    let files = l.next().unwrap_or("0").trim().parse().unwrap_or(0);
    let bytes = l.next().unwrap_or("0").trim().parse().unwrap_or(0);
    (files, bytes)
}

#[tokio::test]
#[ignore = "needs Docker"]
async fn verification_confirms_a_healthy_backup() {
    let vol = make_volume("hlb-test-verif-ok");
    let repo = repo_in(&vol);

    in_volume(
        &vol,
        &format!(
            "mkdir -p {WORKDIR}/d/nested && echo one > {WORKDIR}/d/a.txt && \
             echo two > {WORKDIR}/d/nested/b.txt && head -c 2048 /dev/urandom > {WORKDIR}/d/c.bin"
        ),
    );
    repo.init().await.expect("init");
    let id = repo
        .backup(&format!("{WORKDIR}/d"), &["app:test"])
        .await
        .expect("backup");

    let v = hlb_backup::verify_by_restore(&repo, &id, &format!("{WORKDIR}/verif"), |_| async {
        Ok(count_files(&vol, &format!("{WORKDIR}/verif")))
    })
    .await
    .expect("verification");

    assert!(v.matches(), "{}", v.describe());
    assert_eq!(v.files_restored, 3);
    println!("✓ {}", v.describe());

    drop_volume(&vol);
}

#[tokio::test]
#[ignore = "needs Docker"]
async fn verification_detects_an_incomplete_restore() {
    // 🔴 THE test. Without it we would not know whether the verification verifies
    // anything at all — a check that never says "no" is of no use.
    //
    // We simulate a partial restore by deleting a file right afterwards.
    let vol = make_volume("hlb-test-verif-ko");
    let repo = repo_in(&vol);

    in_volume(
        &vol,
        &format!(
            "mkdir -p {WORKDIR}/d && echo one > {WORKDIR}/d/a.txt && echo two > {WORKDIR}/d/b.txt"
        ),
    );
    repo.init().await.expect("init");
    let id = repo
        .backup(&format!("{WORKDIR}/d"), &["app:test"])
        .await
        .expect("backup");

    let target = format!("{WORKDIR}/verif");
    let v = hlb_backup::verify_by_restore(&repo, &id, &target, |t| {
        let vol = vol.clone();
        async move {
            // A file vanishes: the restore is incomplete.
            in_volume(&vol, &format!("find {t} -name b.txt -delete"));
            Ok(count_files(&vol, &t))
        }
    })
    .await
    .expect("verification");

    assert!(!v.matches(), "the discrepancy should have been detected");
    assert!(v.describe().contains("DISCREPANCY"), "{}", v.describe());
    println!("✓ discrepancy detected: {}", v.describe());

    drop_volume(&vol);
}

#[tokio::test]
#[ignore = "needs Docker"]
async fn reading_the_data_catches_more_than_metadata() {
    // `restic check` alone only reads the metadata. --read-data-subset really re-reads
    // blocks, which catches silent corruption.
    let vol = make_volume("hlb-test-readdata");
    let repo = repo_in(&vol);

    in_volume(
        &vol,
        &format!("mkdir -p {WORKDIR}/d && head -c 65536 /dev/urandom > {WORKDIR}/d/gros.bin"),
    );
    repo.init().await.expect("init");
    repo.backup(&format!("{WORKDIR}/d"), &["app:test"])
        .await
        .expect("backup");

    repo.check_data("100%")
        .await
        .expect("the blocks must be readable");
    println!("✓ data integrity verified by re-reading");

    drop_volume(&vol);
}

/// The end-to-end restore verification, as `hlb backup verify` runs it.
///
/// 🔴 This test exists because the previous version of `verify_snapshot` used a host
/// `tempfile::tempdir()`. On macOS that directory is **not shared with the Docker VM**:
/// the count found zero files there and declared a discrepancy on a perfectly healthy
/// backup. The Docker volume is what fixes it — and only a test against a real restic
/// could show it.
#[tokio::test]
#[ignore = "needs Docker"]
async fn a_healthy_snapshot_verifies_by_actually_restoring_it() {
    // Two separate volumes: `verify_snapshot` mounts the repository alone, as the CLI
    // does with the path passed to `--backup-repo`.
    let repo_volume = make_volume("hlb-test-verify-repo");
    let data = make_volume("hlb-test-verify-data");

    in_volume(
        &data,
        &format!(
            "mkdir -p {WORKDIR}/nested && \
             printf 'hello12' > {WORKDIR}/a.txt && \
             printf 'world12345' > {WORKDIR}/nested/b.txt"
        ),
    );

    let runner = ContainerRunner::new("restic/restic:latest")
        .mount(&repo_volume, "/repo")
        .mount(&data, "/data");
    let repo = Repository::new(runner, "/repo", "test-password");

    repo.init().await.expect("init");
    let snap = repo.backup("/data", &["app:demo"]).await.expect("backup");

    let v = hlb_backup::verify_snapshot(&repo_volume, "test-password", &snap).await;

    drop_volume(&repo_volume);
    drop_volume(&data);

    let v = v.expect("verification runnable");
    assert_eq!(v.files_expected, 2, "the snapshot announces 2 files");
    assert_eq!(v.bytes_expected, 17, "7 + 10 bytes");
    assert_eq!(
        v.files_restored,
        2,
        "🔴 zero here = the disposable space is not shared with Docker: {}",
        v.describe()
    );
    assert_eq!(v.bytes_restored, 17);
    assert!(v.matches(), "{}", v.describe());

    // The block-sample re-read must have happened: without it, a same-size corruption
    // would pass for "compliant".
    let d = v.data_checked.as_ref().expect("block re-read performed");
    assert!(d.ok, "unreadable blocks: {:?}", d.detail);
    assert_eq!(d.subset, "5%");
}

/// Does a SQLite database survive a full round trip?
///
/// 🔴 This is the proof that counts. A size comparison would say "compliant" on a SQLite
/// file copied hot and nevertheless unusable: the file has the right size, its bytes are
/// returned faithfully, and SQLite refuses to open it — or worse, opens it having
/// silently lost the WAL's transactions.
///
/// So this test reads back **the data**, not the bytes.
#[tokio::test]
#[ignore = "needs Docker"]
async fn a_sqlite_database_survives_the_whole_pipeline() {
    use hlb_backup::pgdump::scheduled::{archive, Dump};

    let work = tempfile::tempdir().expect("temp directory");
    let source = work.path().join("app.db");

    // A database in WAL mode with enough rows for the WAL to matter, and which we do NOT
    // close cleanly — like a running app.
    {
        let opts = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(&source)
            .create_if_missing(true)
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal);
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(opts)
            .await
            .expect("database");

        sqlx::query("CREATE TABLE users (id INTEGER PRIMARY KEY, nom TEXT)")
            .execute(&pool)
            .await
            .expect("table");
        for i in 0..1000 {
            sqlx::query("INSERT INTO users (nom) VALUES (?1)")
                .bind(format!("user{i}"))
                .execute(&pool)
                .await
                .expect("insert");
        }
        // No `pool.close()`: the WAL stays loaded.
    }

    // 1. Consistent snapshot.
    let staging = tempfile::tempdir().expect("staging");
    let produced = hlb_backup::sqlite_snapshot_all(work.path(), staging.path())
        .await
        .expect("snapshot");
    assert_eq!(produced.len(), 1, "{produced:?}");

    // 2. Archive it into a real restic repository.
    let repo = "hlb-test-sqlite-repo";
    let _ = std::process::Command::new("docker")
        .args(["volume", "rm", "-f", repo])
        .output();
    make_volume(repo);

    let content = std::fs::read(&produced[0].staged).expect("read");
    let d = Dump {
        app: "pocket-id".into(),
        database: "app".into(),
        filename: "app.db.snapshot".into(),
        bytes: content,
    };
    let id = archive(repo, "test-password", &d).await.expect("archiving");

    // 3. Restore from the repository, into a fresh file.
    let restored = work.path().join("restored.db");
    let out = std::process::Command::new("docker")
        .args([
            "run",
            "--rm",
            "-e",
            "RESTIC_PASSWORD=test-password",
            "-v",
            &format!("{repo}:/repo"),
            "--entrypoint",
            "sh",
            "restic/restic:latest",
            "-c",
            &format!("restic -r /repo dump {id} /staging/app.db.snapshot"),
        ])
        .output()
        .expect("restic");
    assert!(
        out.status.success(),
        "restore impossible:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    std::fs::write(&restored, &out.stdout).expect("write");

    // 4. 🔴 The proof: the DATA is there, not only the bytes.
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect(&format!("sqlite://{}", restored.display()))
        .await
        .expect("🔴 the restored database must OPEN — a file copied hot fails here");

    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(n, 1000, "🔴 rows lost: the WAL was not captured");

    let last: String = sqlx::query_scalar("SELECT nom FROM users ORDER BY id DESC LIMIT 1")
        .fetch_one(&pool)
        .await
        .expect("last row");
    assert_eq!(last, "user999", "the last transaction must be there");

    let _ = std::process::Command::new("docker")
        .args(["volume", "rm", "-f", repo])
        .output();
}
