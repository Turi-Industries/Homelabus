//! The pass, against a real restic: a volume and the state database reach a declared
//! destination, under the paths every older snapshot uses.
//!
//! ```sh
//! cargo test -p hlb-backup-run --test pass -- --ignored --nocapture
//! ```

#![allow(clippy::expect_used, clippy::unwrap_used)]

use hlb_backup_run::{Event, Pass};

fn docker(args: &[&str]) -> std::process::Output {
    std::process::Command::new("docker")
        .args(args)
        .output()
        .expect("docker reachable")
}

#[tokio::test]
#[ignore = "needs Docker"]
async fn a_pass_sends_volumes_and_state_to_the_declared_destination() {
    let dir = tempfile::tempdir().expect("tmp");
    let state_path = dir.path().join("hlb.db");
    let state = hlb_state::State::open(&state_path).await.expect("state");
    let vault = hlb_secrets::Vault::open_or_init(dir.path().join("k.key")).expect("vault");

    let (data, repo) = ("hlb-pass-data", "hlb-pass-repo");
    for v in [data, repo] {
        let _ = docker(&["volume", "rm", "-f", v]);
        docker(&["volume", "create", v]);
    }
    let w = docker(&[
        "run",
        "--rm",
        "-v",
        &format!("{data}:/d"),
        "alpine:3",
        "sh",
        "-c",
        "echo precious > /d/file.txt",
    ]);
    assert!(w.status.success());

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
    let mut events = Vec::new();
    let sum = pass.run(&mut |e| events.push(e)).await.expect("pass");
    for e in &events {
        println!("{e:?}");
    }
    assert_eq!(sum.failed, 0, "{events:?}");
    let done: Vec<&str> = events
        .iter()
        .filter_map(|e| match e {
            Event::Done {
                what, destination, ..
            } if destination == "nas" => Some(what.as_str()),
            _ => None,
        })
        .collect();
    assert!(done.contains(&"demo volumes"), "{done:?}");
    assert!(done.contains(&"hlb state"), "{done:?}");

    // The paths inside the snapshot are the frozen ones.
    let password = hlb_backup_run::restic_password(&state, &vault)
        .await
        .expect("pw");
    let ls = docker(&[
        "run",
        "--rm",
        "-v",
        &format!("{repo}:/repo"),
        "-e",
        &format!("RESTIC_PASSWORD={password}"),
        "restic/restic:latest",
        "-r",
        "/repo",
        "snapshots",
        "--json",
    ]);
    let out = String::from_utf8_lossy(&ls.stdout);
    assert!(out.contains(&format!("/donnees/{data}")), "{out}");

    for v in [data, repo] {
        let _ = docker(&["volume", "rm", "-f", v]);
    }
}

#[tokio::test]
#[ignore = "needs Docker and python3"]
async fn a_sqlite_database_in_an_unflagged_volume_is_snapshotted_not_only_copied_live() {
    // 🔴 CrowdSec, ntfy and Grafana keep SQLite in volumes their manifests never
    // flagged: the pass copied each live, with nothing to say so.
    let dir = tempfile::tempdir().expect("tmp");
    let state_path = dir.path().join("hlb.db");
    let state = hlb_state::State::open(&state_path).await.expect("state");
    let vault = hlb_secrets::Vault::open_or_init(dir.path().join("k.key")).expect("vault");

    // The volume is a directory of this machine, bound: the pass reads it by its path.
    let host = tempfile::tempdir().expect("volume dir");
    let (data, repo) = ("hlb-pass-unflagged", "hlb-pass-unflagged-repo");
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
    let db = host.path().join("crowdsec.db");
    let made = std::process::Command::new("python3")
        .args([
            "-I",
            "-c",
            &format!(
                "import sqlite3; c=sqlite3.connect('{}'); c.execute('CREATE TABLE t (v)'); \
                 c.execute('INSERT INTO t VALUES (1)'); c.commit()",
                db.display()
            ),
        ])
        .status()
        .expect("python3");
    assert!(made.success());

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
        .add_volume(
            "demo",
            data,
            &host.path().display().to_string(),
            true,
            false,
        )
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
    let mut events = Vec::new();
    let sum = pass.run(&mut |e| events.push(e)).await.expect("pass");
    assert_eq!(sum.failed, 0, "{events:?}");
    let snapshotted = events.iter().any(|e| {
        matches!(e, Event::Done { what, destination, .. }
            if what == &format!("demo/{data}/crowdsec.db") && destination == "nas")
    });
    assert!(snapshotted, "{events:#?}");
    // Found once, it is the volume's from then on: owed a snapshot, put back at a restore.
    let flagged = state.sqlite_volumes().await.expect("read");
    assert!(
        flagged.iter().any(|(a, v, _)| a == "demo" && v == data),
        "{flagged:?}"
    );
    assert!(state
        .backup_kinds("demo")
        .await
        .expect("kinds")
        .contains(&hlb_state::backup_kind::SQLITE));

    for v in [data, repo] {
        let _ = docker(&["volume", "rm", "-f", v]);
    }
}

/// One service whose stop and start leave a trace in its volume: the copy shows which
/// of the two it was taken during.
struct Mail {
    volume: std::path::PathBuf,
    replicas: std::sync::Mutex<u64>,
    scaled: std::sync::Mutex<Vec<u64>>,
}

const STOPPED: &str = "written-while-stopped";

#[async_trait::async_trait]
impl hlb_orchestrator::Orchestrator for Mail {
    async fn ping(&self) -> hlb_orchestrator::Result<String> {
        Ok("fake".into())
    }
    async fn deploy(&self, _: &hlb_orchestrator::ServiceSpec) -> hlb_orchestrator::Result<String> {
        unreachable!("a pass deploys nothing")
    }
    async fn update_image(&self, _: &str, _: &str) -> hlb_orchestrator::Result<()> {
        unreachable!("a pass moves no image")
    }
    async fn scale(&self, _: &str, r: u64) -> hlb_orchestrator::Result<()> {
        let marker = self.volume.join(STOPPED);
        if r == 0 {
            std::fs::write(&marker, "x").expect("marker");
        } else {
            std::fs::remove_file(&marker).expect("marker gone");
        }
        *self.replicas.lock().unwrap() = r;
        self.scaled.lock().unwrap().push(r);
        Ok(())
    }
    async fn enable_autolock(&self) -> hlb_orchestrator::Result<String> {
        unreachable!()
    }
    async fn autolock_enabled(&self) -> hlb_orchestrator::Result<bool> {
        Ok(false)
    }
    async fn cluster_init(&self, _: &str) -> hlb_orchestrator::Result<String> {
        unreachable!()
    }
    async fn join_tokens(&self) -> hlb_orchestrator::Result<hlb_orchestrator::JoinTokens> {
        unreachable!()
    }
    async fn nodes(&self) -> hlb_orchestrator::Result<Vec<hlb_orchestrator::NodeInfo>> {
        Ok(Vec::new())
    }
    async fn label_node(&self, _: &str, _: &str, _: &str) -> hlb_orchestrator::Result<()> {
        unreachable!()
    }
    async fn set_node_availability(&self, _: &str, _: &str) -> hlb_orchestrator::Result<()> {
        unreachable!()
    }
    async fn exec_in_service(
        &self,
        _: &str,
        _: &[String],
    ) -> hlb_orchestrator::Result<hlb_orchestrator::ExecOutput> {
        unreachable!()
    }
    async fn ensure_network(&self, _: &str) -> hlb_orchestrator::Result<bool> {
        Ok(false)
    }
    async fn create_volume(
        &self,
        _: &hlb_orchestrator::VolumeSpec,
    ) -> hlb_orchestrator::Result<hlb_orchestrator::VolumeInfo> {
        unreachable!()
    }
    async fn inspect_volume(
        &self,
        _: &str,
    ) -> hlb_orchestrator::Result<hlb_orchestrator::VolumeInfo> {
        unreachable!()
    }
    async fn status(&self, n: &str) -> hlb_orchestrator::Result<hlb_orchestrator::ServiceStatus> {
        let r = *self.replicas.lock().unwrap();
        Ok(hlb_orchestrator::ServiceStatus {
            name: n.into(),
            id: "id".into(),
            desired_replicas: r,
            running_replicas: r as usize,
            image: "a/b:1".into(),
            update_state: None,
        })
    }
    async fn list(&self) -> hlb_orchestrator::Result<Vec<hlb_orchestrator::ServiceStatus>> {
        Ok(vec![self.status("mail").await?])
    }
    async fn remove(&self, _: &str) -> hlb_orchestrator::Result<()> {
        unreachable!()
    }
    async fn wait_healthy(
        &self,
        n: &str,
        _: u64,
    ) -> hlb_orchestrator::Result<hlb_orchestrator::ServiceStatus> {
        self.status(n).await
    }
    async fn tasks(
        &self,
        _: Option<&str>,
    ) -> hlb_orchestrator::Result<Vec<hlb_orchestrator::TaskInfo>> {
        Ok(Vec::new())
    }
    async fn logs(
        &self,
        _: &str,
        _: u32,
    ) -> hlb_orchestrator::Result<Vec<hlb_orchestrator::LogLine>> {
        Ok(Vec::new())
    }
}

#[tokio::test]
#[ignore = "needs Docker"]
async fn a_volume_declared_copied_stopped_is_never_copied_while_its_service_runs() {
    // 🔴 restic reads a RocksDB store file after file: a flush between the SSTs and
    // the MANIFEST left Stalwart's copy naming a file it never took.
    let dir = tempfile::tempdir().expect("tmp");
    let state_path = dir.path().join("hlb.db");
    let state = hlb_state::State::open(&state_path).await.expect("state");
    let vault = hlb_secrets::Vault::open_or_init(dir.path().join("k.key")).expect("vault");

    let host = tempfile::tempdir().expect("volume dir");
    let (data, repo) = ("hlb-pass-stopped", "hlb-pass-stopped-repo");
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
    std::fs::write(host.path().join("MANIFEST-000001"), "store").expect("store");

    let manifest: hlb_types::Manifest = serde_yaml_ng::from_str(
        "apiVersion: hlb/v1\nkind: App\nmetadata: { name: mail }\n\
         spec:\n  image: { repo: a/b, tag: \"1\" }\n  requires:\n    \
         - { kind: storage, name: data, path: /data, copy: stopped }\n",
    )
    .expect("manifest");
    state
        .upsert_app("mail", &manifest, None)
        .await
        .expect("app");
    state
        .add_volume(
            "mail",
            data,
            &host.path().display().to_string(),
            true,
            false,
        )
        .await
        .expect("volume");
    // Two destinations, one stop: the service is not stopped once per copy.
    let other = format!("{repo}-2");
    let _ = docker(&["volume", "rm", "-f", &other]);
    docker(&["volume", "create", &other]);
    for (name, r) in [("nas", repo), ("offsite", other.as_str())] {
        state
            .upsert_destination(name, r, "critical,bulky", None)
            .await
            .expect("destination");
    }

    let mail = Mail {
        volume: host.path().to_path_buf(),
        replicas: std::sync::Mutex::new(1),
        scaled: std::sync::Mutex::new(Vec::new()),
    };
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
        only: Some("mail"),
        orchestrator: Some(&mail),
        s3_endpoint: None,
    };
    let mut events = Vec::new();
    let sum = pass.run(&mut |e| events.push(e)).await.expect("pass");
    assert_eq!((sum.done, sum.failed), (2, 0), "{events:#?}");
    assert_eq!(
        *mail.scaled.lock().unwrap(),
        [0, 1],
        "stopped once, started again"
    );
    assert!(!host.path().join(STOPPED).exists(), "running again");
    assert_eq!(state.held("mail").await.expect("hold"), None, "released");

    let password = hlb_backup_run::restic_password(&state, &vault)
        .await
        .expect("pw");
    for r in [repo, other.as_str()] {
        let ls = docker(&[
            "run",
            "--rm",
            "-v",
            &format!("{r}:/repo"),
            "-e",
            &format!("RESTIC_PASSWORD={password}"),
            "restic/restic:latest",
            "-r",
            "/repo",
            "ls",
            "latest",
        ]);
        let out = String::from_utf8_lossy(&ls.stdout);
        assert!(
            out.contains(&format!("/donnees/{data}/{STOPPED}")),
            "{r}: {out}"
        );
    }

    for v in [data, repo, other.as_str()] {
        let _ = docker(&["volume", "rm", "-f", v]);
    }
}

/// Removes what the PostgreSQL copy test made, however it ends.
struct PgCleanup;

const PG_APP: &str = "hlbpgcopy";
const PG_NET: &str = "hlb-pass-pgcopy";
const PG_PASSWORD: &str = "pgcopy-admin-password";

impl PgCleanup {
    fn volumes() -> [String; 4] {
        [
            format!("{PG_APP}-data"),
            hlb_backup_run::engine_copy::staging(&format!("{PG_APP}-data")),
            format!("{PG_APP}-repo"),
            format!("{PG_APP}-restored"),
        ]
    }
    fn run() {
        for c in [PG_APP, "hlbpgcopy-back"] {
            let _ = docker(&["rm", "-f", c]);
        }
        for v in Self::volumes() {
            let _ = docker(&["volume", "rm", "-f", &v]);
        }
        let _ = docker(&["network", "rm", PG_NET]);
    }
}

impl Drop for PgCleanup {
    fn drop(&mut self) {
        Self::run();
    }
}

fn pg_ready(container: &str) -> bool {
    (0..120).any(|_| {
        std::thread::sleep(std::time::Duration::from_millis(500));
        // On the socket: the restored server listens on nothing else.
        docker(&["exec", container, "pg_isready", "-U", "postgres"])
            .status
            .success()
            && docker(&[
                "exec", container, "psql", "-U", "postgres", "-Atc", "SELECT 1",
            ])
            .status
            .success()
    })
}

fn rows(container: &str) -> u64 {
    let out = docker(&[
        "exec",
        container,
        "psql",
        "-U",
        "postgres",
        "-d",
        "app",
        "-Atc",
        "SELECT count(*) FROM t",
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse()
        .expect("a count")
}

#[tokio::test]
#[ignore = "needs Docker and the catalog's PostgreSQL image"]
async fn a_postgres_directory_copied_while_written_restores_into_a_server_that_starts() {
    // 🔴 restic reading a live data directory takes each file at another instant: the
    // copy is recorded fresh and refuses to start, or starts on torn pages. The
    // catalog's own server — its image, its arguments, its access file — is copied
    // while a writer inserts, and the copy is started where nothing else runs.
    PgCleanup::run();
    let _cleanup = PgCleanup;
    let catalog = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../catalog/_platform/postgres/manifest.yaml");
    let text = std::fs::read_to_string(&catalog).expect("catalog manifest");
    let mut manifest: hlb_types::Manifest = serde_yaml_ng::from_str(&text).expect("manifest");
    manifest.metadata.name = PG_APP.into();
    let image = manifest.spec.image.reference();
    let hba = manifest
        .spec
        .files
        .iter()
        .find(|f| f.path == "/etc/postgresql/hlb_hba.conf")
        .expect("the catalog's access file")
        .content
        .clone();
    let dir = tempfile::tempdir().expect("tmp");
    let hba_path = dir.path().join("hlb_hba.conf");
    std::fs::write(&hba_path, hba).expect("hba");

    let [data, staging, repo, restored] = PgCleanup::volumes();
    docker(&["network", "create", PG_NET]);
    for v in [&data, &repo, &restored] {
        docker(&["volume", "create", v]);
    }
    let mut run = vec![
        "run".to_string(),
        "-d".into(),
        "--name".into(),
        PG_APP.into(),
        "--network".into(),
        PG_NET.into(),
        "-e".into(),
        format!("POSTGRES_PASSWORD={PG_PASSWORD}"),
        "-v".into(),
        format!("{data}:/var/lib/postgresql/data"),
        "-v".into(),
        format!("{}:/etc/postgresql/hlb_hba.conf:ro", hba_path.display()),
        image.clone(),
    ];
    run.extend(manifest.spec.args.iter().cloned());
    let args: Vec<&str> = run.iter().map(String::as_str).collect();
    let up = docker(&args);
    assert!(
        up.status.success(),
        "{}",
        String::from_utf8_lossy(&up.stderr)
    );
    assert!(pg_ready(PG_APP), "PostgreSQL never answered");
    for (db, sql) in [
        ("postgres", "CREATE DATABASE app"),
        (
            "app",
            "CREATE TABLE t (id bigserial PRIMARY KEY, pad text NOT NULL)",
        ),
    ] {
        let out = docker(&[
            "exec", PG_APP, "psql", "-U", "postgres", "-d", db, "-c", sql,
        ]);
        assert!(
            out.status.success(),
            "{sql}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    // A writer for the whole pass: pages change under the copy.
    let writer = docker(&[
        "exec",
        "-d",
        PG_APP,
        "sh",
        "-c",
        "while :; do psql -U postgres -d app -qc \
         \"INSERT INTO t (pad) SELECT repeat(md5(random()::text), 40) FROM generate_series(1, 200)\"; done",
    ]);
    assert!(writer.status.success());
    std::thread::sleep(std::time::Duration::from_secs(2));
    let before = rows(PG_APP);
    assert!(before > 0, "the writer writes");

    let state_path = dir.path().join("hlb.db");
    let state = hlb_state::State::open(&state_path).await.expect("state");
    let vault = hlb_secrets::Vault::open_or_init(dir.path().join("k.key")).expect("vault");
    state
        .upsert_app(PG_APP, &manifest, None)
        .await
        .expect("app");
    state
        .add_volume(PG_APP, &data, "/unused", true, false)
        .await
        .expect("volume");
    state
        .upsert_destination("nas", &repo, "critical,bulky", None)
        .await
        .expect("destination");
    // The URL's host is a relay the CLI may reach the server through: the copy goes to
    // the service owning the volume, never there.
    let admin = format!("postgres://postgres:{PG_PASSWORD}@relay.invalid:15432/postgres");
    let pass = Pass {
        state: &state,
        vault: &vault,
        state_path: &state_path,
        fallback_repo: None,
        network: PG_NET,
        postgres_admin: Some(&admin),
        mariadb_admin: None,
        schedule: hlb_backup::Schedule::default(),
        force: true,
        only: Some(PG_APP),
        orchestrator: None,
        s3_endpoint: None,
    };
    let mut events = Vec::new();
    let sum = pass.run(&mut |e| events.push(e)).await.expect("pass");
    assert_eq!(sum.failed, 0, "{events:#?}");
    assert!(
        events.iter().any(|e| matches!(e, Event::Done { what, .. }
            if what == &format!("{PG_APP} volumes"))),
        "{events:#?}"
    );
    assert!(rows(PG_APP) > before, "written during the pass");
    let left = docker(&[
        "run",
        "--rm",
        "-v",
        &format!("{staging}:/s"),
        "alpine:3",
        "sh",
        "-c",
        "ls -A /s | wc -l",
    ]);
    assert_eq!(
        String::from_utf8_lossy(&left.stdout).trim(),
        "0",
        "the copy emptied after its backup"
    );

    // Put back as the volume restore does: at the volume's own path, into an empty one.
    let password = hlb_backup_run::restic_password(&state, &vault)
        .await
        .expect("pw");
    let path = hlb_backup_run::volume_path(&data);
    let back = docker(&[
        "run",
        "--rm",
        "-v",
        &format!("{repo}:/repo"),
        "-v",
        &format!("{restored}:{path}"),
        "-e",
        &format!("RESTIC_PASSWORD={password}"),
        "restic/restic:latest",
        "-r",
        "/repo",
        "restore",
        "latest",
        "--target",
        "/",
        "--include",
        &path,
    ]);
    assert!(
        back.status.success(),
        "{}",
        String::from_utf8_lossy(&back.stderr)
    );
    // What `pg_basebackup` leaves and a directory read by restic never holds: where
    // recovery starts.
    let label = docker(&[
        "run",
        "--rm",
        "-v",
        &format!("{restored}:/d"),
        "alpine:3",
        "sh",
        "-c",
        "test -f /d/backup_label && stat -c %u /d/PG_VERSION",
    ]);
    assert!(
        label.status.success(),
        "no backup_label: the directory was copied live"
    );
    assert_eq!(
        String::from_utf8_lossy(&label.stdout).trim(),
        "999",
        "owned by the server's user"
    );

    // Started where nothing reaches it, nothing archived nor replicated from it.
    let mut run = vec![
        "run".to_string(),
        "-d".into(),
        "--name".into(),
        "hlbpgcopy-back".into(),
        "--network".into(),
        "none".into(),
        "-v".into(),
        format!("{restored}:/var/lib/postgresql/data"),
        "-v".into(),
        format!("{}:/etc/postgresql/hlb_hba.conf:ro", hba_path.display()),
        image,
    ];
    run.extend(manifest.spec.args.iter().cloned());
    run.extend(
        ["-c", "archive_mode=off", "-c", "listen_addresses="]
            .iter()
            .map(|s| s.to_string()),
    );
    let args: Vec<&str> = run.iter().map(String::as_str).collect();
    assert!(docker(&args).status.success());
    let started = pg_ready("hlbpgcopy-back");
    let logs = docker(&["logs", "hlbpgcopy-back"]);
    assert!(
        started,
        "the restored server did not start: {}",
        String::from_utf8_lossy(&logs.stderr)
    );
    let check = docker(&[
        "exec",
        "hlbpgcopy-back",
        "pg_amcheck",
        "-U",
        "postgres",
        "--all",
        // On a throwaway copy: the extension is not in the server's databases.
        "--install-missing",
        "--heapallindexed",
    ]);
    assert!(
        check.status.success(),
        "{}{}",
        String::from_utf8_lossy(&check.stdout),
        String::from_utf8_lossy(&check.stderr)
    );
    assert!(rows("hlbpgcopy-back") >= before, "the rows written before");
}

/// Removes what the MariaDB copy test made, however it ends.
struct MaCleanup;

const MA_APP: &str = "hlbmacopy";
const MA_BACK: &str = "hlbmacopy-back";
const MA_NET: &str = "hlb-pass-macopy";
const MA_PASSWORD: &str = "macopy-root#pass\"word";

impl MaCleanup {
    fn volumes() -> [String; 4] {
        [
            format!("{MA_APP}-data"),
            hlb_backup_run::engine_copy::staging(&format!("{MA_APP}-data")),
            format!("{MA_APP}-repo"),
            format!("{MA_APP}-restored"),
        ]
    }
    fn run() {
        for c in [MA_APP, MA_BACK] {
            let _ = docker(&["rm", "-f", c]);
        }
        for v in Self::volumes() {
            let _ = docker(&["volume", "rm", "-f", &v]);
        }
        let _ = docker(&["network", "rm", MA_NET]);
    }
}

impl Drop for MaCleanup {
    fn drop(&mut self) {
        Self::run();
    }
}

/// `sql` as root, the password out of the command line.
fn maria(container: &str, sql: &str) -> std::process::Output {
    docker(&[
        "exec",
        "-e",
        &format!("MYSQL_PWD={MA_PASSWORD}"),
        container,
        "mariadb",
        "-uroot",
        "-N",
        "-e",
        sql,
    ])
}

/// The catalog's own probe passes, which is what Swarm waits on.
fn maria_healthy(container: &str, probe: &[String]) -> bool {
    let mut args = vec!["exec", container];
    args.extend(probe.iter().map(String::as_str));
    (0..120).any(|_| {
        std::thread::sleep(std::time::Duration::from_millis(500));
        docker(&args).status.success()
    })
}

fn maria_rows(container: &str) -> u64 {
    let out = maria(container, "SELECT COUNT(*) FROM app.t");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse()
        .expect("a count")
}

/// `docker run -d` of the catalog's server: its image, environment, password file and
/// arguments, over `data`.
fn maria_server(
    manifest: &hlb_types::Manifest,
    secrets: &std::path::Path,
    name: &str,
    network: &str,
    data: &str,
) -> std::process::Output {
    let mut run = vec![
        "run".to_string(),
        "-d".into(),
        "--name".into(),
        name.into(),
        "--network".into(),
        network.into(),
        "-v".into(),
        format!("{data}:/var/lib/mysql"),
        "-v".into(),
        format!("{}:/run/secrets:ro", secrets.display()),
    ];
    for (k, v) in &manifest.spec.env {
        run.extend(["-e".to_string(), format!("{k}={v}")]);
    }
    run.push(manifest.spec.image.reference());
    run.extend(manifest.spec.args.iter().cloned());
    let args: Vec<&str> = run.iter().map(String::as_str).collect();
    docker(&args)
}

#[tokio::test]
#[ignore = "needs Docker and the catalog's MariaDB image"]
async fn a_mariadb_directory_copied_while_written_restores_into_a_server_that_starts() {
    // 🔴 The same trap as PostgreSQL's: restic reading InnoDB's files one after another
    // takes each at another instant. The catalog's own server is copied while a writer
    // inserts, and the copy started where nothing else runs, under the catalog's probe.
    MaCleanup::run();
    let _cleanup = MaCleanup;
    let catalog = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../catalog/_platform/mariadb/manifest.yaml");
    let text = std::fs::read_to_string(&catalog).expect("catalog manifest");
    let mut manifest: hlb_types::Manifest = serde_yaml_ng::from_str(&text).expect("manifest");
    manifest.metadata.name = MA_APP.into();
    let probe = manifest
        .spec
        .swarm
        .healthcheck
        .as_ref()
        .expect("the catalog's probe")
        .test
        .iter()
        .skip(1) // "CMD"
        .cloned()
        .collect::<Vec<_>>();
    let dir = tempfile::tempdir().expect("tmp");
    let secrets = dir.path().join("secrets");
    std::fs::create_dir(&secrets).expect("secrets");
    let file = manifest
        .spec
        .files
        .iter()
        .find(|f| f.path == "/run/secrets/root-password")
        .expect("the catalog's password file");
    assert!(file.content.contains("secret.root-password"));
    std::fs::write(secrets.join("root-password"), MA_PASSWORD).expect("password");
    // Read by the entrypoint once it is the image's `mysql`, as Swarm's 0444 file is.
    use std::os::unix::fs::PermissionsExt;
    for (p, mode) in [(dir.path().to_path_buf(), 0o755), (secrets.clone(), 0o755)] {
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).expect("mode");
    }
    std::fs::set_permissions(
        secrets.join("root-password"),
        std::fs::Permissions::from_mode(0o444),
    )
    .expect("mode");

    let [data, staging, repo, restored] = MaCleanup::volumes();
    docker(&["network", "create", MA_NET]);
    for v in [&data, &repo, &restored] {
        docker(&["volume", "create", v]);
    }
    let up = maria_server(&manifest, &secrets, MA_APP, MA_NET, &data);
    assert!(
        up.status.success(),
        "{}",
        String::from_utf8_lossy(&up.stderr)
    );
    assert!(maria_healthy(MA_APP, &probe), "MariaDB never answered");
    let made = maria(
        MA_APP,
        "CREATE DATABASE app; CREATE TABLE app.t \
         (id BIGINT AUTO_INCREMENT PRIMARY KEY, pad TEXT NOT NULL) ENGINE=InnoDB",
    );
    assert!(
        made.status.success(),
        "{}",
        String::from_utf8_lossy(&made.stderr)
    );
    // A writer for the whole pass: pages change under the copy.
    let writer = docker(&[
        "exec",
        "-d",
        "-e",
        &format!("MYSQL_PWD={MA_PASSWORD}"),
        MA_APP,
        "sh",
        "-c",
        "while :; do mariadb -uroot app -e \
         \"INSERT INTO t (pad) SELECT REPEAT(MD5(RAND()), 40) FROM seq_1_to_200\"; done",
    ]);
    assert!(writer.status.success());
    std::thread::sleep(std::time::Duration::from_secs(2));
    let before = maria_rows(MA_APP);
    assert!(before > 0, "the writer writes");

    let state_path = dir.path().join("hlb.db");
    let state = hlb_state::State::open(&state_path).await.expect("state");
    let vault = hlb_secrets::Vault::open_or_init(dir.path().join("k.key")).expect("vault");
    state
        .upsert_app(MA_APP, &manifest, None)
        .await
        .expect("app");
    state
        .add_volume(MA_APP, &data, "/unused", true, false)
        .await
        .expect("volume");
    state
        .upsert_destination("nas", &repo, "critical,bulky", None)
        .await
        .expect("destination");
    // The URL's host is a relay the CLI may reach the server through: the copy goes to
    // the service owning the volume, never there.
    let admin = format!("mariadb://root:{MA_PASSWORD}@relay.invalid:13306");
    let pass = Pass {
        state: &state,
        vault: &vault,
        state_path: &state_path,
        fallback_repo: None,
        network: MA_NET,
        postgres_admin: None,
        mariadb_admin: Some(&admin),
        schedule: hlb_backup::Schedule::default(),
        force: true,
        only: Some(MA_APP),
        orchestrator: None,
        s3_endpoint: None,
    };
    let mut events = Vec::new();
    let sum = pass.run(&mut |e| events.push(e)).await.expect("pass");
    assert_eq!(sum.failed, 0, "{events:#?}");
    assert!(
        events.iter().any(|e| matches!(e, Event::Done { what, .. }
            if what == &format!("{MA_APP} volumes"))),
        "{events:#?}"
    );
    assert!(maria_rows(MA_APP) > before, "written during the pass");
    let left = docker(&[
        "run",
        "--rm",
        "-v",
        &format!("{staging}:/s"),
        "alpine:3",
        "sh",
        "-c",
        "ls -A /s | wc -l",
    ]);
    assert_eq!(
        String::from_utf8_lossy(&left.stdout).trim(),
        "0",
        "the copy emptied after its backup"
    );

    // Put back as the volume restore does: at the volume's own path, into an empty one.
    let password = hlb_backup_run::restic_password(&state, &vault)
        .await
        .expect("pw");
    let path = hlb_backup_run::volume_path(&data);
    let back = docker(&[
        "run",
        "--rm",
        "-v",
        &format!("{repo}:/repo"),
        "-v",
        &format!("{restored}:{path}"),
        "-e",
        &format!("RESTIC_PASSWORD={password}"),
        "restic/restic:latest",
        "-r",
        "/repo",
        "restore",
        "latest",
        "--target",
        "/",
        "--include",
        &path,
    ]);
    assert!(
        back.status.success(),
        "{}",
        String::from_utf8_lossy(&back.stderr)
    );
    // What a prepared `mariadb-backup` leaves and a directory read by restic never
    // holds; and the probe's own file, which the tool does not copy.
    let label = docker(&[
        "run",
        "--rm",
        "-v",
        &format!("{restored}:/d"),
        "alpine:3",
        "sh",
        "-c",
        "grep -q 'backup_type = log-applied' /d/mariadb_backup_checkpoints \
         && test -f /d/.my-healthcheck.cnf && stat -c %u /d/ibdata1",
    ]);
    assert!(
        label.status.success(),
        "not a prepared mariadb-backup copy: the directory was copied live"
    );
    assert_eq!(
        String::from_utf8_lossy(&label.stdout).trim(),
        "999",
        "owned by the server's user"
    );

    // Started where nothing reaches it, by the catalog's entrypoint, judged by its probe.
    let up = maria_server(&manifest, &secrets, MA_BACK, "none", &restored);
    assert!(up.status.success());
    let started = maria_healthy(MA_BACK, &probe);
    let logs = docker(&["logs", MA_BACK]);
    assert!(
        started,
        "the restored server is not healthy: {}",
        String::from_utf8_lossy(&logs.stderr)
    );
    let check = docker(&[
        "exec",
        "-e",
        &format!("MYSQL_PWD={MA_PASSWORD}"),
        MA_BACK,
        "mariadb-check",
        "-uroot",
        "--all-databases",
        "--extended",
    ]);
    let said = String::from_utf8_lossy(&check.stdout);
    assert!(
        check.status.success() && !said.contains("error") && !said.contains("corrupt"),
        "{said}{}",
        String::from_utf8_lossy(&check.stderr)
    );
    assert!(maria_rows(MA_BACK) >= before, "the rows written before");
}
