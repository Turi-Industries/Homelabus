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
