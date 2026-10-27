//! Consistent backup of SQLite databases.
//!
//! ## 🔴 Copying a SQLite file hot does not back it up
//!
//! This is the most treacherous failure in the whole backup system, because it only
//! shows **at restore time**.
//!
//! A SQLite database in WAL mode is not one file, it is three:
//!
//! | File | Content |
//! |---|---|
//! | `base.db` | the pages already integrated |
//! | `base.db-wal` | the recent transactions, not yet integrated |
//! | `base.db-shm` | the WAL's shared index |
//!
//! `restic` copies them one after another. Between copying the first and the second, the
//! application writes. The set obtained is **inconsistent**: SQLite refuses to open it,
//! or worse, opens it having silently lost the WAL's transactions.
//!
//! And nothing signals it at backup time. The snapshot has an id, its size is plausible,
//! `restic check` passes. You discover the problem on the day you restore.
//!
//! ## `VACUUM INTO` rather than a copy
//!
//! `VACUUM INTO 'path'` (SQLite 3.27+, 2019) produces a **complete and consistent**
//! database in a fresh file, in a single transaction, while the application keeps
//! writing. It is the official mechanism for exactly this need.
//!
//! Two advantages over the `sqlite3` client's old `.backup`:
//!
//! - it needs **no external binary** — we go through the same SQLite library as the rest
//!   of the project;
//! - the file produced is defragmented, so smaller to back up.
//!
//! ⚠️ It refuses to write over an existing file. That is intended: overwriting a snapshot
//! while it is being backed up would hand restic a file changing under its feet.

use std::path::{Path, PathBuf};

use crate::{Error, Result};

/// The extensions that give away a SQLite database.
///
/// ⚠️ There is no single convention: Vaultwarden uses `db.sqlite3`, PocketID
/// `pocket-id.db`, others `.sqlite`. Missing a file would mean backing it up hot without
/// knowing.
const EXTENSIONS: &[&str] = &["db", "sqlite", "sqlite3"];

/// A companion file of the engine, never a database in its own right.
///
/// 🔴 Snapshotting them separately would produce unusable files **and** give the illusion
/// of having backed up more databases than there are.
fn is_sidecar(name: &str) -> bool {
    name.ends_with("-wal") || name.ends_with("-shm") || name.ends_with("-journal")
}

/// A SQLite database found in a volume.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Found {
    pub path: PathBuf,
    /// Name of the snapshot file to produce.
    pub snapshot_name: String,
}

/// Locates the SQLite databases under a path.
pub fn discover(root: &Path) -> std::io::Result<Vec<Found>> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];

    while let Some(p) = stack.pop() {
        for e in std::fs::read_dir(&p)? {
            let e = e?;
            let m = e.metadata()?;
            if m.is_dir() {
                stack.push(e.path());
                continue;
            }
            if !m.is_file() {
                continue;
            }

            let name = e.file_name().to_string_lossy().to_string();
            if is_sidecar(&name) {
                continue;
            }

            let ext = e
                .path()
                .extension()
                .map(|x| x.to_string_lossy().to_lowercase())
                .unwrap_or_default();

            if EXTENSIONS.contains(&ext.as_str()) && looks_like_sqlite(&e.path())? {
                out.push(Found {
                    path: e.path(),
                    snapshot_name: format!("{name}.snapshot"),
                });
            }
        }
    }

    // Deterministic: the filesystem's order is not, and a snapshot whose order changed
    // would make the logs unreadable.
    out.sort();
    Ok(out)
}

/// Does the file begin with the SQLite header?
///
/// ⚠️ The extension is not enough: `.db` is used for anything and everything. Running a
/// `VACUUM INTO` on a file that is not a database would fail on every backup, and the
/// real problem would drown in the noise.
fn looks_like_sqlite(p: &Path) -> std::io::Result<bool> {
    use std::io::Read;

    // The first 16 bytes of a SQLite file are always "SQLite format 3\0".
    const MAGIC: &[u8] = b"SQLite format 3\0";
    let mut f = std::fs::File::open(p)?;
    let mut head = [0u8; 16];

    match f.read_exact(&mut head) {
        Ok(()) => Ok(head == MAGIC),
        // A file shorter than the header is not a database.
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(false),
        Err(e) => Err(e),
    }
}

/// Produces a consistent snapshot of a database.
///
/// The destination file must not exist: `VACUUM INTO` refuses to overwrite, and that is
/// a protection we do not work around.
pub async fn snapshot(source: &Path, destination: &Path) -> Result<u64> {
    if destination.exists() {
        return Err(Error::Unexpected(format!(
            "{} already exists — VACUUM INTO refuses to overwrite, and overwriting a \
             snapshot while it is being backed up would hand restic a file changing \
             under its feet",
            destination.display()
        )));
    }

    // Read-only: a backup must under no circumstances be able to modify the production
    // database, not even through a configuration accident.
    let opts = sqlx::sqlite::SqliteConnectOptions::new()
        .filename(source)
        .read_only(true)
        .create_if_missing(false);

    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(opts)
        .await
        .map_err(|e| Error::Unexpected(format!("opening {}: {e}", source.display())))?;

    // The path cannot be a bound parameter in a VACUUM.
    let dest = destination.to_string_lossy().replace('\'', "''");
    sqlx::query(&format!("VACUUM INTO '{dest}'"))
        .execute(&pool)
        .await
        .map_err(|e| Error::Unexpected(format!("snapshot of {}: {e}", source.display())))?;

    pool.close().await;

    let size = std::fs::metadata(destination)
        .map_err(|e| Error::Unexpected(format!("unreadable snapshot: {e}")))?
        .len();

    // 🔴 An empty snapshot is never normal: even a database with no table is several
    // kilobytes of header and schema.
    if size == 0 {
        return Err(Error::Unexpected(format!(
            "snapshot of {} is empty — is the database readable?",
            source.display()
        )));
    }

    tracing::info!(
        source = %source.display(),
        bytes = size,
        "consistent SQLite snapshot produced"
    );
    Ok(size)
}

/// A database's consistent snapshot, and where and whose the database is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshotted {
    /// The database's path inside the volume: where a restore puts the snapshot back.
    pub relative: PathBuf,
    /// The snapshot file, in the staging directory.
    pub staged: PathBuf,
    /// The database's owner and mode, which the snapshot is given back: restored as
    /// root, an app that drops its privileges opened its own database read-only.
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
}

/// Snapshots every database of a volume into a staging directory.
pub async fn snapshot_all(root: &Path, staging: &Path) -> Result<Vec<Snapshotted>> {
    use std::os::unix::fs::MetadataExt;
    let bases = discover(root)
        .map_err(|e| Error::Unexpected(format!("exploring {}: {e}", root.display())))?;

    if bases.is_empty() {
        // 🔴 Reported, not silent: a volume declared `sqlite: true` where no database is
        // found means the path is wrong, or the file name follows no known convention.
        // Staying quiet would suggest a backup had been made.
        return Err(Error::Unexpected(format!(
            "no SQLite database found under {} although the volume is declared \
             \"sqlite: true\" — wrong path, or unusual extension?",
            root.display()
        )));
    }

    let mut produced = Vec::new();
    for b in bases {
        let meta = std::fs::metadata(&b.path)
            .map_err(|e| Error::Unexpected(format!("reading {}: {e}", b.path.display())))?;
        let relative = b
            .path
            .strip_prefix(root)
            .map(Path::to_path_buf)
            .map_err(|_| {
                Error::Unexpected(format!(
                    "{} is outside {}",
                    b.path.display(),
                    root.display()
                ))
            })?;
        // Two databases of one name in two directories: each its own staged file.
        let dest = staging.join(relative.to_string_lossy().replace('/', "__") + ".snapshot");
        snapshot(&b.path, &dest).await?;
        produced.push(Snapshotted {
            relative,
            staged: dest,
            uid: meta.uid(),
            gid: meta.gid(),
            mode: meta.mode() & 0o7777,
        });
    }
    Ok(produced)
}

/// The tag of a database's consistent snapshot, archived where it sits in its volume.
pub const SNAPSHOT_KIND: &str = "kind:sqlite-snapshot";

/// Archives `s` to `dest` at the path the database has in its volume — under
/// `volume_path`, the volume's own path in every snapshot —, owned and moded as the
/// database is, beside an EMPTY `-wal` and `-shm`: restored over the live copy, a journal
/// left from it would be replayed onto the consistent snapshot. Its snapshot id.
///
/// 🔴 Its paths are the database's files, never the volume's own: a volume restore takes
/// a snapshot whose paths ARE the volume's, and restoring this one with `--delete` would
/// empty the volume around the database.
///
/// `tags` go beside the app, database and kind: the pass's own, which is how a volume
/// restore finds the database snapshot of the same pass.
#[allow(clippy::too_many_arguments)]
pub async fn archive_to(
    dest: &crate::destination::Destination,
    credentials: Option<&str>,
    network: Option<&str>,
    password: &str,
    app: &str,
    volume_path: &str,
    s: &Snapshotted,
    tags: &[&str],
) -> Result<String> {
    use tokio::io::AsyncWriteExt;
    let rel = s.relative.to_string_lossy().to_string();
    if rel.is_empty() || rel.starts_with('/') || rel.split('/').any(|c| c == "..") {
        return Err(Error::Unexpected(format!(
            "{rel}: not a path inside the volume"
        )));
    }
    let file = format!("{}/{rel}", volume_path.trim_end_matches('/'));
    let transit = format!("hlb-sqlite-{}", crate::verify::public_token());
    let docker = |args: Vec<String>| async move {
        let out = tokio::process::Command::new("docker")
            .args(&args)
            .output()
            .await
            .map_err(|e| Error::Unexpected(format!("docker not found: {e}")))?;
        if out.status.success() {
            Ok(())
        } else {
            Err(Error::Unexpected(
                String::from_utf8_lossy(&out.stderr).trim().to_string(),
            ))
        }
    };
    docker(vec!["volume".into(), "create".into(), transit.clone()]).await?;
    let result = async {
        let bytes = tokio::fs::read(&s.staged)
            .await
            .map_err(|e| Error::Unexpected(format!("reading the snapshot: {e}")))?;
        // The file enters the transit volume through standard input: the one path that
        // crosses the host/VM boundary. Its path, owner and mode as arguments, never
        // interpolated into the script.
        let script = r#"set -e; f="$1"; mkdir -p "$(dirname "$f")"; cat > "$f"; : > "$f-wal"; : > "$f-shm"; chown "$2:$3" "$f" "$f-wal" "$f-shm"; chmod "$4" "$f" "$f-wal" "$f-shm""#;
        let mut child = tokio::process::Command::new("docker")
            .args(["run", "--rm", "-i", "--entrypoint", "sh", "-v"])
            .arg(format!("{transit}:{volume_path}"))
            .args([crate::images::RESTIC, "-c", script, "sh", &file])
            .arg(s.uid.to_string())
            .arg(s.gid.to_string())
            .arg(format!("{:o}", s.mode))
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| Error::Unexpected(format!("docker not found: {e}")))?;
        if let Some(mut si) = child.stdin.take() {
            si.write_all(&bytes)
                .await
                .map_err(|e| Error::Unexpected(format!("sending the snapshot: {e}")))?;
            si.shutdown()
                .await
                .map_err(|e| Error::Unexpected(format!("closing the stream: {e}")))?;
        }
        let out = child
            .wait_with_output()
            .await
            .map_err(|e| Error::Unexpected(format!("transferring the snapshot: {e}")))?;
        if !out.status.success() {
            return Err(Error::Unexpected(format!(
                "snapshot not transferred: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        let (runner, location) = dest.runner(network);
        let repo = crate::restic::Repository::new(runner.mount(&transit, volume_path), location, password)
            .extra_env(dest.env(credentials)?);
        repo.init().await?;
        let (wal, shm) = (format!("{file}-wal"), format!("{file}-shm"));
        let (app_tag, db_tag) = (format!("app:{app}"), format!("db:{rel}"));
        let mut all = vec![app_tag.as_str(), db_tag.as_str(), SNAPSHOT_KIND];
        all.extend_from_slice(tags);
        repo.backup_paths(&[&file, &wal, &shm], &all).await
    }
    .await;
    if let Err(e) = docker(vec![
        "volume".into(),
        "rm".into(),
        "-f".into(),
        transit.clone(),
    ])
    .await
    {
        tracing::warn!(volume = transit, "transit volume not removed: {e}");
    }
    result
}

/// Continuous replication to S3.
///
/// ## What Litestream adds to the snapshot
///
/// The `VACUUM INTO` snapshot is consistent, but it dates from the last pass of the
/// backup loop — four hours in the default configuration. Losing the disk at 15:55
/// therefore costs up to four hours of work.
///
/// Litestream replicates the WAL continuously: the lag falls to a few seconds. It is the
/// exact counterpart of PITR for PostgreSQL.
///
/// ## 🔴 The two do not replace each other
///
/// | | What it protects against | What it does NOT protect against |
/// |---|---|---|
/// | Snapshot + restic | disk loss, corruption, **accidental deletion** | the last 4 hours |
/// | Litestream | disk loss, the last few seconds | **a deletion replicated in 2 s** |
///
/// A table erased by mistake is replicated to S3 immediately. Litestream keeps a history
/// (`retention`), but a short one: the snapshot is what stays the net for human error.
/// So we keep both.
pub mod litestream {
    /// Where to replicate.
    #[derive(Debug, Clone)]
    pub struct Replica {
        /// S3 bucket (or compatible: MinIO, Garage, Backblaze…).
        pub bucket: String,
        /// Path inside the bucket.
        pub path: String,
        /// Endpoint, for a non-Amazon S3.
        pub endpoint: Option<String>,
        /// How long the history is kept.
        pub retention: String,
    }

    impl Default for Replica {
        fn default() -> Self {
            Self {
                bucket: "homelabus".into(),
                path: "litestream".into(),
                endpoint: None,
                // 🔴 72 h and not 24: an accidental deletion on a Friday evening must
                // still be recoverable on Monday morning. With 24 h it is not — and the
                // weekend is when you look at your logs least.
                retention: "72h".into(),
            }
        }
    }

    /// Renders the `litestream.yml` for a set of databases.
    ///
    /// ⚠️ Litestream wants the path of the **live** database, not of the snapshot: it
    /// reads the WAL as it goes. Handing it the snapshot would replicate nothing, and it
    /// would emit no error — it would wait for writes that never come on a frozen
    /// file.
    pub fn render(databases: &[std::path::PathBuf], replica: &Replica) -> String {
        let mut s = String::from(
            "# Generated by Homelabus — do not edit by hand.\n\
             #\n\
             # ⚠️ Litestream does NOT REPLACE the restic snapshots: a table erased by\n\
             # mistake is replicated within seconds. The snapshot is what stays the\n\
             # net against human error.\n\
             \ndbs:\n",
        );

        for d in databases {
            s.push_str(&format!("  - path: {}\n", d.display()));
            s.push_str("    replicas:\n");
            s.push_str("      - type: s3\n");
            s.push_str(&format!("        bucket: {}\n", replica.bucket));
            s.push_str(&format!(
                "        path: {}/{}\n",
                replica.path.trim_end_matches('/'),
                d.file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_else(|| "database".into())
            ));
            if let Some(e) = &replica.endpoint {
                s.push_str(&format!("        endpoint: {e}\n"));
                // ⚠️ Indispensable outside Amazon: without it, Litestream builds
                // `bucket.endpoint`-style URLs, which MinIO and Garage do not serve.
                s.push_str("        force-path-style: true\n");
            }
            s.push_str(&format!("        retention: {}\n", replica.retention));
            // A periodic check catches a replication that diverged silently — the
            // failure mode specific to continuous replication.
            s.push_str("        validation-interval: 12h\n");
        }

        if databases.is_empty() {
            // A file with an empty `dbs:` starts Litestream replicating nothing, and
            // without saying so. Better that the file shouts it.
            s.push_str("# 🔴 NO database declared: Litestream will start replicating nothing.\n");
        }
        s
    }
}

#[cfg(test)]
mod tests_litestream {
    use super::litestream::*;
    use std::path::PathBuf;

    #[test]
    fn the_live_database_is_replicated_not_the_snapshot() {
        // ⚠️ Litestream reads the WAL as it goes. On a frozen snapshot it would emit NO
        // error and would never replicate anything.
        let y = render(&[PathBuf::from("/data/app.db")], &Replica::default());
        assert!(y.contains("path: /data/app.db"), "{y}");
        assert!(!y.contains(".snapshot"), "{y}");
    }

    #[test]
    fn retention_survives_a_weekend() {
        // 🔴 24 h is not enough: a Friday-evening deletion must still be recoverable on
        // Monday morning, and the weekend is when you look least.
        assert_eq!(Replica::default().retention, "72h");
    }

    #[test]
    fn a_non_amazon_endpoint_forces_path_style() {
        // ⚠️ Without it, Litestream builds "bucket.endpoint" URLs that MinIO and Garage
        // do not serve — the error talks about DNS, not about URL style.
        let r = Replica {
            endpoint: Some("https://minio.example.org".into()),
            ..Replica::default()
        };
        let y = render(&[PathBuf::from("/data/app.db")], &r);
        assert!(y.contains("force-path-style: true"), "{y}");
    }

    #[test]
    fn amazon_needs_no_endpoint_line() {
        let y = render(&[PathBuf::from("/data/app.db")], &Replica::default());
        assert!(!y.contains("endpoint:"), "{y}");
        assert!(!y.contains("force-path-style"), "{y}");
    }

    #[test]
    fn each_database_gets_its_own_path() {
        // Two databases replicated to the same path would overwrite each other.
        let y = render(
            &[PathBuf::from("/d/a.db"), PathBuf::from("/d/b.db")],
            &Replica::default(),
        );
        assert!(y.contains("litestream/a.db"), "{y}");
        assert!(y.contains("litestream/b.db"), "{y}");
    }

    #[test]
    fn an_empty_configuration_says_it_replicates_nothing() {
        // Litestream would start normally, replicating nothing and not saying so.
        let y = render(&[], &Replica::default());
        assert!(y.contains("NO database"), "{y}");
    }

    #[test]
    fn the_file_says_it_does_not_replace_snapshots() {
        // The underlying trap: believing continuous replication is enough. A table
        // erased by mistake is replicated within seconds.
        let y = render(&[PathBuf::from("/d/a.db")], &Replica::default());
        assert!(y.contains("does NOT REPLACE"), "{y}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Creates a real SQLite database with content.
    async fn base(path: &Path, rows: usize) {
        let opts = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            // WAL mode is what makes a hot copy dangerous: we test under the conditions
            // of the problem.
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal);

        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(opts)
            .await
            .expect("test database");

        sqlx::query("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)")
            .execute(&pool)
            .await
            .expect("table");
        for i in 0..rows {
            sqlx::query("INSERT INTO t (v) VALUES (?1)")
                .bind(format!("value-{i}"))
                .execute(&pool)
                .await
                .expect("insert");
        }
        pool.close().await;
    }

    #[tokio::test]
    async fn a_snapshot_contains_every_row() {
        // 🔴 THE test: the snapshot must contain the data, including what is still in
        // the WAL at the moment it is taken.
        let d = tempfile::tempdir().expect("temp directory");
        let src = d.path().join("app.db");
        base(&src, 500).await;

        let dest = d.path().join("app.db.snapshot");
        let size = snapshot(&src, &dest).await.expect("snapshot");
        assert!(size > 0);

        // Read the snapshot back and count.
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect(&format!("sqlite://{}", dest.display()))
            .await
            .expect("read back");

        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM t")
            .fetch_one(&pool)
            .await
            .expect("count");
        assert_eq!(n, 500, "the snapshot must contain every row");
    }

    #[tokio::test]
    async fn the_source_is_never_modified() {
        // A backup that writes into the production database would be worse than no
        // backup at all.
        let d = tempfile::tempdir().expect("temp directory");
        let src = d.path().join("app.db");
        base(&src, 10).await;

        let before = std::fs::metadata(&src).expect("stat").len();
        snapshot(&src, &d.path().join("s.db"))
            .await
            .expect("snapshot");
        let after = std::fs::metadata(&src).expect("stat").len();

        assert_eq!(before, after, "the source database must not move");
    }

    #[tokio::test]
    async fn overwriting_an_existing_snapshot_is_refused() {
        // Overwriting while restic reads would hand it a file changing under its feet.
        let d = tempfile::tempdir().expect("temp directory");
        let src = d.path().join("app.db");
        base(&src, 5).await;

        let dest = d.path().join("s.db");
        snapshot(&src, &dest).await.expect("first");
        let e = snapshot(&src, &dest).await.unwrap_err().to_string();
        assert!(e.contains("already exists"), "{e}");
    }

    #[tokio::test]
    async fn databases_are_discovered_by_content_not_extension() {
        // ⚠️ `.db` is used for anything: a VACUUM INTO on a file that is not a database
        // would fail on every backup and drown the real problem.
        let d = tempfile::tempdir().expect("temp directory");
        base(&d.path().join("real.db"), 3).await;
        std::fs::write(d.path().join("fake.db"), b"not a database at all").expect("write");
        std::fs::write(d.path().join("short.db"), b"ab").expect("write");

        let v = discover(d.path()).expect("exploration");
        assert_eq!(v.len(), 1, "{v:?}");
        assert!(v[0].path.ends_with("real.db"));
    }

    #[tokio::test]
    async fn wal_and_shm_files_are_never_treated_as_databases() {
        // 🔴 Snapshotting them separately would produce unusable files AND suggest more
        // databases than there are.
        assert!(is_sidecar("app.db-wal"));
        assert!(is_sidecar("app.db-shm"));
        assert!(is_sidecar("app.db-journal"));
        assert!(!is_sidecar("app.db"));

        let d = tempfile::tempdir().expect("temp directory");
        base(&d.path().join("app.db"), 3).await;
        // WAL mode may have left a -wal behind; we drop one explicitly.
        std::fs::write(d.path().join("app.db-wal"), b"SQLite format 3\0xxxx").expect("wal");

        let v = discover(d.path()).expect("exploration");
        assert_eq!(v.len(), 1, "{v:?}");
    }

    #[tokio::test]
    async fn nested_directories_are_explored() {
        let d = tempfile::tempdir().expect("temp directory");
        let sub = d.path().join("data").join("db");
        std::fs::create_dir_all(&sub).expect("directory tree");
        base(&sub.join("deep.sqlite3"), 2).await;

        let v = discover(d.path()).expect("exploration");
        assert_eq!(v.len(), 1, "{v:?}");
        assert_eq!(v[0].snapshot_name, "deep.sqlite3.snapshot");
    }

    #[tokio::test]
    async fn a_volume_declared_sqlite_but_empty_is_an_error() {
        // 🔴 Staying quiet would suggest a backup had been made. A volume declared
        // "sqlite: true" with no database means the path is wrong.
        let d = tempfile::tempdir().expect("temp directory");
        let staging = tempfile::tempdir().expect("staging");
        std::fs::write(d.path().join("notes.txt"), b"nothing").expect("write");

        let e = snapshot_all(d.path(), staging.path())
            .await
            .unwrap_err()
            .to_string();
        assert!(e.contains("no SQLite database"), "{e}");
        assert!(
            e.contains("wrong path"),
            "the error must point somewhere: {e}"
        );
    }

    #[tokio::test]
    async fn every_database_of_a_volume_is_snapshotted() {
        let d = tempfile::tempdir().expect("temp directory");
        let staging = tempfile::tempdir().expect("staging");
        base(&d.path().join("a.db"), 4).await;
        base(&d.path().join("b.sqlite"), 7).await;

        let v = snapshot_all(d.path(), staging.path())
            .await
            .expect("snapshots");
        assert_eq!(v.len(), 2, "{v:?}");
        for p in &v {
            assert!(p.staged.exists(), "{} missing", p.staged.display());
            assert!(std::fs::metadata(&p.staged).expect("stat").len() > 0);
        }
        let mut where_: Vec<String> = v.iter().map(|p| p.relative.display().to_string()).collect();
        where_.sort();
        assert_eq!(
            where_,
            ["a.db", "b.sqlite"],
            "each where it sits in the volume"
        );
    }

    #[tokio::test]
    async fn a_missing_source_fails_clearly() {
        let d = tempfile::tempdir().expect("temp directory");
        let e = snapshot(&d.path().join("missing.db"), &d.path().join("s.db"))
            .await
            .unwrap_err()
            .to_string();
        assert!(e.contains("opening"), "{e}");
    }
}
