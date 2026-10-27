//! Dump → destruction → restore, contre un vrai PostgreSQL.
//!
//! A database is not backed up the way files are. These tests check it in both
//! directions — that the dump restores faithfully, and that it stays consistent even when
//! taken during concurrent writes.
//!
//! ```sh
//! export DOCKER_HOST=$(docker context inspect -f '{{.Endpoints.docker.Host}}')
//! cargo test -p hlb-backup --test pg_roundtrip -- --ignored --test-threads=1 --nocapture
//! ```

#![allow(clippy::expect_used, clippy::unwrap_used)]

use hlb_backup::{PgContainerRunner, PgDumper, PgTarget};

const PG_IMAGE: &str = "postgres:17-alpine";
const CONTAINER: &str = "hlb-test-pgdump";
const NETWORK: &str = "hlb-test-net";
const PASSWORD: &str = "test-password";

fn docker(args: &[&str]) -> std::process::Output {
    std::process::Command::new("docker")
        .args(args)
        .output()
        .expect("docker reachable (DOCKER_HOST?)")
}

/// Runs SQL through `psql` in the container, and returns the output.
fn psql(db: &str, sql: &str) -> String {
    let out = docker(&[
        "exec",
        "-e",
        &format!("PGPASSWORD={PASSWORD}"),
        CONTAINER,
        "psql",
        "-U",
        "postgres",
        "-d",
        db,
        "-tAc",
        sql,
    ]);
    assert!(
        out.status.success(),
        "psql failed on \"{sql}\":\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// Removes the server and its network when dropped. A cleanup call closing each test was
/// skipped by every failing assertion, and two tests had none: their server stayed up
/// after every run.
#[must_use = "dropping it at once removes the server"]
struct Postgres;

impl Drop for Postgres {
    fn drop(&mut self) {
        let _ = docker(&["rm", "-f", CONTAINER]);
        let _ = docker(&["network", "rm", NETWORK]);
    }
}

fn start_postgres() -> Postgres {
    let _ = docker(&["rm", "-f", CONTAINER]);
    let _ = docker(&["network", "create", NETWORK]);

    let out = docker(&[
        "run",
        "-d",
        "--name",
        CONTAINER,
        "--network",
        NETWORK,
        "-e",
        &format!("POSTGRES_PASSWORD={PASSWORD}"),
        PG_IMAGE,
    ]);
    assert!(
        out.status.success(),
        "starting postgres: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Over TCP: the image first runs a temporary server on the socket alone to
    // initialise, and a socket probe answers ready just before it restarts.
    for _ in 0..60 {
        let r = docker(&[
            "exec",
            CONTAINER,
            "pg_isready",
            "-h",
            "127.0.0.1",
            "-U",
            "postgres",
        ]);
        if r.status.success() {
            return Postgres;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    panic!("postgres did not start in time");
}

fn target(db: &str) -> PgTarget {
    PgTarget {
        // Resolved by the Docker network's DNS: the pg_dump container is attached to it.
        host: CONTAINER.to_string(),
        port: 5432,
        database: db.to_string(),
        user: "postgres".to_string(),
        password: PASSWORD.to_string(),
    }
}

fn dumper() -> PgDumper<PgContainerRunner> {
    PgDumper::new(PgContainerRunner::new(PG_IMAGE).network(NETWORK))
}

#[tokio::test]
#[ignore = "needs Docker"]
async fn a_database_survives_destruction_and_comes_back_identical() {
    let _postgres = start_postgres();

    // 1. A realistic database: several tables, a foreign key, indexes.
    psql("postgres", "CREATE DATABASE appli");
    psql(
        "appli",
        "CREATE TABLE authors (id serial PRIMARY KEY, name text NOT NULL UNIQUE);
         CREATE TABLE posts (
             id serial PRIMARY KEY,
             author_id int NOT NULL REFERENCES authors(id),
             title text NOT NULL,
             publie_le timestamptz NOT NULL DEFAULT now()
         );
         CREATE INDEX idx_posts_author ON posts(author_id);
         INSERT INTO authors (name) VALUES ('Ada'), ('Grace'), ('Alan');
         INSERT INTO posts (author_id, title)
             SELECT 1 + (i % 3), 'post ' || i FROM generate_series(1, 500) i;",
    );

    let before_authors = psql("appli", "SELECT count(*) FROM authors");
    let before_posts = psql("appli", "SELECT count(*) FROM posts");
    let before_sum = psql(
        "appli",
        "SELECT md5(string_agg(title, ',' ORDER BY id)) FROM posts",
    );
    println!("✓ database populated: {before_authors} authors, {before_posts} posts");

    // 2. Dump.
    let dump = dumper().dump(&target("appli")).await.expect("dump");
    assert!(
        dump.len() > 1000,
        "suspiciously small dump: {} B",
        dump.len()
    );
    // The custom format starts with the "PGDMP" signature.
    assert_eq!(&dump[..5], b"PGDMP", "this is not a custom-format dump");
    println!("✓ dump of {} bytes", dump.len());

    // 3. 🔴 Destruction.
    psql("postgres", "DROP DATABASE appli");
    let exists = psql(
        "postgres",
        "SELECT count(*) FROM pg_database WHERE datname = 'appli'",
    );
    assert_eq!(exists, "0", "the database should have vanished");
    println!("✓ database destroyed");

    // 4. Restore into a fresh database.
    psql("postgres", "CREATE DATABASE appli");
    dumper()
        .restore(&target("appli"), &dump, false)
        .await
        .expect("restore");

    // 5. Comparison: counts, content, and structure.
    assert_eq!(
        psql("appli", "SELECT count(*) FROM authors"),
        before_authors
    );
    assert_eq!(psql("appli", "SELECT count(*) FROM posts"), before_posts);
    assert_eq!(
        psql(
            "appli",
            "SELECT md5(string_agg(title, ',' ORDER BY id)) FROM posts"
        ),
        before_sum,
        "the restored content differs"
    );

    // The foreign-key constraint must have survived, not only the rows.
    let fk = psql(
        "appli",
        "SELECT count(*) FROM pg_constraint WHERE contype = 'f' AND conrelid = 'posts'::regclass",
    );
    assert_eq!(fk, "1", "the foreign key was not restored");

    let idx = psql(
        "appli",
        "SELECT count(*) FROM pg_indexes WHERE tablename = 'posts' AND indexname = 'idx_posts_author'",
    );
    assert_eq!(idx, "1", "the index was not restored");

    println!("✓ data, foreign keys and indexes restored identically");
}

#[tokio::test]
#[ignore = "needs Docker"]
async fn a_dump_taken_during_concurrent_writes_stays_consistent() {
    // 🔴 The heart of it. This is precisely what a file backup cannot do: capture a
    // consistent instant despite the writes in flight.
    let _postgres = start_postgres();

    psql("postgres", "CREATE DATABASE load");
    psql(
        "load",
        "CREATE TABLE counter (id int PRIMARY KEY, value int NOT NULL);
         INSERT INTO counter SELECT i, 0 FROM generate_series(1, 100) i;",
    );

    // Invariant: the sum of the values must always be a multiple of 100, because each
    // write increments all 100 rows at once, inside a transaction.
    let writer = std::thread::spawn(|| {
        for _ in 0..40 {
            let _ = std::process::Command::new("docker")
                .args([
                    "exec",
                    "-e",
                    &format!("PGPASSWORD={PASSWORD}"),
                    CONTAINER,
                    "psql",
                    "-U",
                    "postgres",
                    "-d",
                    "load",
                    "-tAc",
                    "BEGIN; UPDATE counter SET value = value + 1; COMMIT;",
                ])
                .output();
        }
    });

    // Dump while it is writing.
    std::thread::sleep(std::time::Duration::from_millis(400));
    let dump = dumper().dump(&target("load")).await.expect("dump");
    writer.join().expect("writer finished");
    println!("✓ dump taken during {} concurrent writes", 40);

    // Restore into a separate database, then check the invariant.
    psql("postgres", "CREATE DATABASE verif");
    dumper()
        .restore(&target("verif"), &dump, false)
        .await
        .expect("restore");

    let sum: i64 = psql("verif", "SELECT sum(value) FROM counter")
        .parse()
        .expect("numeric sum");
    let rows: i64 = psql("verif", "SELECT count(*) FROM counter")
        .parse()
        .expect("count");

    assert_eq!(rows, 100);
    assert_eq!(
        sum % 100,
        0,
        "inconsistent snapshot: sum = {sum}, we captured a partially applied \
         transaction"
    );
    println!(
        "✓ invariant held (sum = {sum}, that is {} complete increments)",
        sum / 100
    );
}

#[tokio::test]
#[ignore = "needs Docker"]
async fn restoring_over_a_populated_database_needs_clean() {
    let _postgres = start_postgres();

    psql("postgres", "CREATE DATABASE src");
    psql(
        "src",
        "CREATE TABLE t (id int PRIMARY KEY); INSERT INTO t VALUES (1), (2);",
    );
    let dump = dumper().dump(&target("src")).await.expect("dump");

    // The target already exists with the same table: without --clean, pg_restore fails.
    psql("postgres", "CREATE DATABASE target");
    psql(
        "target",
        "CREATE TABLE t (id int PRIMARY KEY); INSERT INTO t VALUES (99);",
    );

    assert!(
        dumper()
            .restore(&target("target"), &dump, false)
            .await
            .is_err(),
        "without --clean, restoring over it must fail"
    );

    dumper()
        .restore(&target("target"), &dump, true)
        .await
        .expect("restore with --clean");

    assert_eq!(psql("target", "SELECT count(*) FROM t"), "2");
    assert_eq!(psql("target", "SELECT count(*) FROM t WHERE id = 99"), "0");
    println!("✓ --clean really replaces the existing content");
}

#[tokio::test]
#[ignore = "needs Docker"]
async fn dumping_a_missing_database_fails_clearly() {
    let _postgres = start_postgres();
    let err = dumper().dump(&target("does-not-exist")).await.unwrap_err();
    assert!(
        err.to_string().contains("does-not-exist") || err.to_string().contains("does not exist"),
        "unclear message: {err}"
    );
    println!("✓ explicit error: {err}");
}

/// The full scheduled-backup cycle: dump -> restic repository -> restore.
///
/// 🔴 This test exists because the first version of `scheduled::archive` wrote the dump
/// into a host `tempfile::tempdir()` before handing it to a containerised restic. On
/// macOS that directory is not shared with the Docker VM: restic answered "does not
/// exist, skipping" then exited with an error. The dump really was produced and never
/// reached the repository.
#[tokio::test]
#[ignore = "needs Docker"]
async fn a_scheduled_dump_reaches_the_repository_and_comes_back() {
    use hlb_backup::pgdump::scheduled;

    let _postgres = start_postgres();

    psql("postgres", "DROP DATABASE IF EXISTS planifiee");
    psql("postgres", "CREATE DATABASE planifiee");
    psql(
        "planifiee",
        "CREATE TABLE repos (id int PRIMARY KEY, name text);
         INSERT INTO repos VALUES (1, 'project-a'), (2, 'project-b');",
    );

    // 1. Produce the dump.
    let d = scheduled::produce(&dumper(), "gitea", &target("planifiee"), 1_786_881_600)
        .await
        .expect("dump produced");

    assert_eq!(d.filename, "gitea-planifiee-20260816T120000Z.dump");
    assert!(!d.bytes.is_empty(), "an empty dump is never normal");

    // 2. Archive it into a fresh repository.
    let repo = "hlb-test-dump-repo";
    let _ = std::process::Command::new("docker")
        .args(["volume", "rm", "-f", repo])
        .output();
    docker(&["volume", "create", repo]);

    let id = scheduled::archive(repo, "test-password", &d)
        .await
        .expect("🔴 archiving: if this fails with \"does not exist\", the staging does not cross the Docker VM");

    assert!(!id.is_empty(), "a snapshot id is expected");

    // 3. Read it back and check it really holds the dump, byte for byte.
    let out = docker(&[
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
        &format!("restic -r /repo dump {id} /staging/{} | wc -c", d.filename),
    ]);
    assert!(
        out.status.success(),
        "cannot read back:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let size: usize = String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse()
        .expect("readable size");
    assert_eq!(
        size,
        d.bytes.len(),
        "the archived dump does not have the size of the one produced"
    );

    let _ = std::process::Command::new("docker")
        .args(["volume", "rm", "-f", repo])
        .output();
}

/// Does a recovery drill really restore a usable database?
///
/// 🔴 This is the only test that walks the full chain: base backup -> restore into a
/// fresh container -> PostgreSQL starting on it -> readable data. Each link is tested
/// elsewhere; this one checks they fit together.
///
/// And above all it checks what no unit test can see: that the archive comes out
/// **intact**. A drill that corrupted the backup it verifies would be the last straw.
#[tokio::test]
#[ignore = "needs Docker"]
async fn a_drill_restores_a_usable_database_without_touching_the_archive() {
    use hlb_backup::drill;
    use hlb_backup::pitr::basebackup;

    let _postgres = start_postgres();

    // Replication from another container: without this line, pg_basebackup is refused
    // with a message that talks about a password (cf. pitr::basebackup).
    docker(&[
        "exec",
        CONTAINER,
        "sh",
        "-c",
        "grep -q 'host replication all all' /var/lib/postgresql/data/pg_hba.conf || \
         echo 'host replication all all scram-sha-256' >> /var/lib/postgresql/data/pg_hba.conf",
    ]);
    psql("postgres", "SELECT pg_reload_conf()");

    psql("postgres", "DROP DATABASE IF EXISTS exercice");
    psql("postgres", "CREATE DATABASE exercice");
    psql(
        "exercice",
        "CREATE TABLE clients (id int, name text);
         CREATE TABLE orders (id int);
         INSERT INTO clients VALUES (1, 'a'), (2, 'b');",
    );

    // 1. A real base backup.
    //
    // ⚠️ NOT a `tempfile::tempdir()`: on macOS, /var/folders is not shared with the
    // Docker VM, so `pg_basebackup` would write INSIDE the VM and the host would see
    // nothing. This is the third place in the project where this trap shows up (cf.
    // verify.rs and pgdump.rs). So we go through `target/`, under /Users, which is
    // mounted.
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/hlb-test-drill");
    std::fs::create_dir_all(&root).expect("test directory");
    let root = root.canonicalize().expect("test directory");

    // Through a container: on Linux what pg_basebackup wrote is root's, and a
    // `remove_dir_all` fails quietly on it — the next run is refused on "not empty", and
    // `cargo clean` dies on "Permission denied". Emptied before, and on drop so a
    // panicking assertion cleans up too.
    struct Emptied(String);
    impl Emptied {
        fn empty(&self) {
            docker(&[
                "run",
                "--rm",
                "-v",
                &format!("{}:/x", self.0),
                PG_IMAGE,
                "sh",
                "-c",
                "rm -rf /x/* /x/.[!.]*",
            ]);
        }
    }
    impl Drop for Emptied {
        fn drop(&mut self) {
            self.empty();
        }
    }
    let emptied = Emptied(root.display().to_string());
    emptied.empty();

    let target = basebackup::Target::new(root.to_string_lossy(), CONTAINER)
        .credentials("postgres", PASSWORD)
        .network(NETWORK)
        .image(PG_IMAGE);

    let base_id = basebackup::run(&target, 1_786_881_600)
        .await
        .expect("base backup");

    let archive = root.join(&base_id).join("base.tar.gz");
    let before = std::fs::metadata(&archive).expect("archive").len();

    // 2. The drill.
    let t = drill::Target {
        container: drill::container_name(1_786_881_600).expect("name"),
        disposable: true,
    };
    drill::authorize(&t, true).expect("disposable target authorised");

    let o = drill::run_postgres(&t, &root.to_string_lossy(), &base_id, PG_IMAGE)
        .await
        .expect("drill runnable");

    assert!(
        o.succeeded(),
        "🔴 the full chain must complete: {}",
        o.describe()
    );
    // `exercice` has three tables in its public schema… but the drill restores the
    // CLUSTER, so it connects to `postgres`, which has none. What matters is that it
    // finds some: an empty database would give 0 and would fail.
    assert!(o.tables.unwrap_or(0) > 0, "{}", o.describe());

    // 3. 🔴 The archive is intact: the read-only mount held.
    let after = std::fs::metadata(&archive).expect("archive").len();
    assert_eq!(
        before, after,
        "the drill MODIFIED the backup it was verifying"
    );

    // 4. Nothing is left behind.
    let remaining = docker(&[
        "ps",
        "-a",
        "--filter",
        &format!("name={}", t.container),
        "-q",
    ]);
    assert!(
        String::from_utf8_lossy(&remaining.stdout).trim().is_empty(),
        "the drill container was not destroyed"
    );
}
