//! A catalog manifest's assertions, read from a real container of its image.
//!
//! Run the image with the manifest's environment, then:
//!
//! ```sh
//! export HLB_ASSERT_APP=termix HLB_ASSERT_CONTAINER=p2-termix
//! # optional, for `type: sql`: the database server's admin URL
//! export HLB_ASSERT_MYSQL=mysql://root:test@localhost:53306/mysql
//! # each recovery sign-in, as the vault would give it: `secret=username:password`, `;`-separated
//! export HLB_ASSERT_SIGN_IN='admin-password=admin:Trial-pass-1'
//! cargo test -p hlb-guide --test live_assertions -- --ignored --nocapture
//! ```
//!
//! The container stands for the Swarm service: its address replaces the service name,
//! and `docker inspect` for the running task's environment.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use async_trait::async_trait;
use hlb_api::assertions::Verdict;
use hlb_guide::assertions::{read_all, Credential, LiveReader, Reader, Refused};
use hlb_types::DbServer;

struct Container {
    name: String,
    live: LiveReader,
}

fn docker(args: &[&str]) -> String {
    let out = std::process::Command::new("docker")
        .args(args)
        .output()
        .expect("docker");
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

#[async_trait]
impl Reader for Container {
    async fn post(
        &self,
        url: &str,
        headers: &[(String, String)],
        basic: Option<(&str, &str)>,
        content_type: &str,
        body: &str,
    ) -> Result<(u16, String), String> {
        self.live
            .post(url, headers, basic, content_type, body)
            .await
    }
    async fn get(&self, url: &str, host: Option<&str>) -> Result<(u16, String), String> {
        self.live.get(url, host).await
    }
    async fn task_env(&self, _: &str) -> Result<Option<Vec<String>>, String> {
        let json = docker(&["inspect", "-f", "{{json .Config.Env}}", &self.name]);
        Ok(Some(
            serde_json::from_str(&json).map_err(|e| e.to_string())?,
        ))
    }
    async fn sql(&self, e: DbServer, db: &str, q: &str) -> Result<Option<String>, String> {
        self.live.sql(e, db, q).await
    }
}

#[tokio::test]
#[ignore = "needs a container of the app's image (see the header)"]
async fn the_catalog_assertions_hold_on_the_real_image() {
    let app = std::env::var("HLB_ASSERT_APP").expect("HLB_ASSERT_APP");
    let name = std::env::var("HLB_ASSERT_CONTAINER").expect("HLB_ASSERT_CONTAINER");
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../catalog");
    let catalog = hlb_catalog::Catalog::load(root).expect("catalog");
    let m = catalog.get(&app).expect("in the catalog").manifest.clone();
    let ip = docker(&[
        "inspect",
        "-f",
        "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
        &name,
    ]);
    let service = format!("http://{app}:");
    let live = LiveReader::new(
        None,
        std::env::var("HLB_ASSERT_PG").ok(),
        std::env::var("HLB_ASSERT_MYSQL").ok(),
    )
    .reaching(move |u| u.replace(&service, &format!("http://{ip}:")));
    let credentials: Vec<Credential> = std::env::var("HLB_ASSERT_SIGN_IN")
        .unwrap_or_default()
        .split(';')
        .filter(|kv| !kv.is_empty())
        .map(|kv| {
            let (secret, login) = kv.split_once('=').expect("secret=username:password");
            let (u, p) = login.split_once(':').expect("username:password");
            Credential {
                secret: secret.into(),
                sign_in: Ok((u.into(), p.into())),
            }
        })
        .collect();
    let read = read_all(
        &Container { name, live },
        &m,
        &hlb_guide::assertions::Placed::new(),
        &credentials,
        Refused::TryAgain,
        0,
    )
    .await;
    for r in &read {
        println!("{:?}  {}  ({})", r.verdict, r.holds, r.observed);
    }
    assert!(!read.is_empty(), "{app} declares no assertion");
    assert!(
        read.iter().all(|r| r.verdict == Verdict::Holds),
        "{app}: not every assertion holds"
    );
}

/// A catalog guide's `api` automation, run on a fresh container of the app's image:
///
/// ```sh
/// export HLB_ASSERT_APP=jellyfin HLB_ASSERT_CONTAINER=p2-jelly HLB_AUTOMATE_STEP=first-account
/// export HLB_AUTOMATE_VALUES='secret.admin-password=Trial-pass-1'   # `;`-separated
/// cargo test -p hlb-guide --test live_assertions automation -- --ignored --nocapture
/// ```
#[tokio::test]
#[ignore = "needs a fresh container of the app's image (see above)"]
async fn the_catalog_automation_runs_on_the_real_image() {
    use hlb_guide::{try_automate_with, Api, AutomationOutcome, HttpApi};
    let app = std::env::var("HLB_ASSERT_APP").expect("HLB_ASSERT_APP");
    let name = std::env::var("HLB_ASSERT_CONTAINER").expect("HLB_ASSERT_CONTAINER");
    let id = std::env::var("HLB_AUTOMATE_STEP").expect("HLB_AUTOMATE_STEP");
    let values = std::env::var("HLB_AUTOMATE_VALUES").unwrap_or_default();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../catalog");
    let catalog = hlb_catalog::Catalog::load(root).expect("catalog");
    let entry = catalog.get(&app).expect("in the catalog");
    let mut step = entry
        .guide
        .steps
        .iter()
        .find(|s| s.id == id)
        .expect("the step")
        .clone();
    // What the executor does with the vault: the tokens, in the calls' bodies.
    for a in &mut step.automate {
        if let hlb_types::Automation::Api { calls, .. } = a {
            for c in calls {
                if let Some(b) = &mut c.body {
                    for kv in values.split(';').filter(|kv| !kv.is_empty()) {
                        let (k, v) = kv.split_once('=').expect("token=value");
                        *b = b.replace(&format!("{{{{ {k} }}}}"), v);
                    }
                    assert!(!b.contains("{{"), "a token left in {b}");
                }
            }
        }
    }
    let ip = docker(&[
        "inspect",
        "-f",
        "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
        &name,
    ]);
    let service = format!("http://{app}:");
    let api = HttpApi::default().reaching(move |u| u.replace(&service, &format!("http://{ip}:")));
    let port = entry.manifest.spec.ingress.first().map(|i| i.port);
    let run = || {
        try_automate_with(
            &NoSwarm,
            Some(Api {
                client: &api,
                port,
                sign_ins: &[],
            }),
            None,
            &app,
            &step,
            &[],
        )
    };
    let first = run().await;
    println!("first: {}", first.describe());
    assert_eq!(first, AutomationOutcome::Applied { method: "api" });
    let again = run().await;
    println!("again: {}", again.describe());
    assert_eq!(again, AutomationOutcome::AlreadyDone { method: "api" });
}

/// An `api` automation reaches no orchestrator.
struct NoSwarm;

#[async_trait]
impl hlb_orchestrator::Orchestrator for NoSwarm {
    async fn ping(&self) -> hlb_orchestrator::Result<String> {
        unreachable!()
    }
    async fn deploy(&self, _: &hlb_orchestrator::ServiceSpec) -> hlb_orchestrator::Result<String> {
        unreachable!()
    }
    async fn update_image(&self, _: &str, _: &str) -> hlb_orchestrator::Result<()> {
        unreachable!()
    }
    async fn scale(&self, _: &str, _: u64) -> hlb_orchestrator::Result<()> {
        unreachable!()
    }
    async fn cluster_init(&self, _: &str) -> hlb_orchestrator::Result<String> {
        unreachable!()
    }
    async fn enable_autolock(&self) -> hlb_orchestrator::Result<String> {
        unreachable!()
    }
    async fn autolock_enabled(&self) -> hlb_orchestrator::Result<bool> {
        unreachable!()
    }
    async fn join_tokens(&self) -> hlb_orchestrator::Result<hlb_orchestrator::JoinTokens> {
        unreachable!()
    }
    async fn nodes(&self) -> hlb_orchestrator::Result<Vec<hlb_orchestrator::NodeInfo>> {
        unreachable!()
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
        unreachable!()
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
    async fn status(&self, _: &str) -> hlb_orchestrator::Result<hlb_orchestrator::ServiceStatus> {
        unreachable!()
    }
    async fn list(&self) -> hlb_orchestrator::Result<Vec<hlb_orchestrator::ServiceStatus>> {
        unreachable!()
    }
    async fn remove(&self, _: &str) -> hlb_orchestrator::Result<()> {
        unreachable!()
    }
    async fn wait_healthy(
        &self,
        _: &str,
        _: u64,
    ) -> hlb_orchestrator::Result<hlb_orchestrator::ServiceStatus> {
        unreachable!()
    }
    async fn tasks(
        &self,
        _: Option<&str>,
    ) -> hlb_orchestrator::Result<Vec<hlb_orchestrator::TaskInfo>> {
        unreachable!()
    }
    async fn logs(
        &self,
        _: &str,
        _: u32,
    ) -> hlb_orchestrator::Result<Vec<hlb_orchestrator::LogLine>> {
        unreachable!()
    }
}
