//! Reconciliation loop tests.
//!
//! Half of these check what reconciliation **does not do**. That is the important
//! half: a system that over-corrects is more dangerous than one that corrects
//! nothing.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::Mutex;

use async_trait::async_trait;
use hlb_engine::{Drift, Reconciler};
use hlb_orchestrator::{Orchestrator, ServiceSpec, ServiceStatus};
use hlb_state::State;

#[derive(Default)]
struct Fake {
    observed: Mutex<Vec<ServiceStatus>>,
    deployed: Mutex<Vec<String>>,
    deployed_images: Mutex<Vec<String>>,
    scaled: Mutex<Vec<(String, u64)>>,
    updated: Mutex<Vec<(String, String)>>,
    removed: Mutex<Vec<String>>,
}

impl Fake {
    fn with(services: Vec<ServiceStatus>) -> Self {
        Self {
            observed: Mutex::new(services),
            ..Default::default()
        }
    }
}

#[async_trait]
impl Orchestrator for Fake {
    async fn ping(&self) -> hlb_orchestrator::Result<String> {
        Ok("fake".into())
    }
    async fn deploy(&self, s: &ServiceSpec) -> hlb_orchestrator::Result<String> {
        self.deployed.lock().unwrap().push(s.name.clone());
        self.deployed_images.lock().unwrap().push(s.image.clone());
        Ok("id".into())
    }
    async fn update_image(&self, n: &str, i: &str) -> hlb_orchestrator::Result<()> {
        self.updated.lock().unwrap().push((n.into(), i.into()));
        Ok(())
    }
    async fn scale(&self, n: &str, r: u64) -> hlb_orchestrator::Result<()> {
        self.scaled.lock().unwrap().push((n.into(), r));
        Ok(())
    }
    async fn enable_autolock(&self) -> hlb_orchestrator::Result<String> {
        Ok("SWMKEY-fake".into())
    }
    async fn autolock_enabled(&self) -> hlb_orchestrator::Result<bool> {
        Ok(false)
    }
    async fn cluster_init(&self, _: Option<&str>) -> hlb_orchestrator::Result<String> {
        Ok("swarm-fake".into())
    }
    async fn join_tokens(&self) -> hlb_orchestrator::Result<hlb_orchestrator::JoinTokens> {
        Ok(hlb_orchestrator::JoinTokens {
            manager: "SWMTKN-mgr".into(),
            worker: "SWMTKN-wrk".into(),
            advertise_addr: "127.0.0.1:2377".into(),
        })
    }
    async fn nodes(&self) -> hlb_orchestrator::Result<Vec<hlb_orchestrator::NodeInfo>> {
        Ok(Vec::new())
    }
    async fn label_node(&self, _: &str, _: &str, _: &str) -> hlb_orchestrator::Result<()> {
        Ok(())
    }
    async fn exec_in_service(
        &self,
        _: &str,
        _: &[String],
    ) -> hlb_orchestrator::Result<hlb_orchestrator::ExecOutput> {
        Ok(hlb_orchestrator::ExecOutput {
            exit_code: 0,
            stdout: String::new(),
            stderr: String::new(),
        })
    }
    async fn create_volume(
        &self,
        n: &str,
    ) -> hlb_orchestrator::Result<hlb_orchestrator::VolumeInfo> {
        Ok(hlb_orchestrator::VolumeInfo {
            name: n.into(),
            mountpoint: format!("/volumes/{n}"),
            existed: false,
        })
    }
    async fn inspect_volume(
        &self,
        n: &str,
    ) -> hlb_orchestrator::Result<hlb_orchestrator::VolumeInfo> {
        self.create_volume(n).await
    }
    async fn status(&self, n: &str) -> hlb_orchestrator::Result<ServiceStatus> {
        self.observed
            .lock()
            .unwrap()
            .iter()
            .find(|s| s.name == n)
            .cloned()
            .ok_or_else(|| hlb_orchestrator::Error::NotFound(n.into()))
    }
    async fn list(&self) -> hlb_orchestrator::Result<Vec<ServiceStatus>> {
        Ok(self.observed.lock().unwrap().clone())
    }
    async fn remove(&self, n: &str) -> hlb_orchestrator::Result<()> {
        self.removed.lock().unwrap().push(n.into());
        Ok(())
    }
    async fn wait_healthy(&self, n: &str, _: u64) -> hlb_orchestrator::Result<ServiceStatus> {
        self.status(n).await
    }

    async fn tasks(
        &self,
        _: Option<&str>,
    ) -> hlb_orchestrator::Result<Vec<hlb_orchestrator::TaskInfo>> {
        // A fake orchestrator has no tasks: empty is the honest answer.
        Ok(Vec::new())
    }

    async fn logs(
        &self,
        _: &str,
        _: u32,
    ) -> hlb_orchestrator::Result<Vec<hlb_orchestrator::LigneLog>> {
        Ok(Vec::new())
    }
}

fn svc(name: &str, image: &str, desired: u64, running: usize) -> ServiceStatus {
    ServiceStatus {
        name: name.into(),
        id: "id".into(),
        desired_replicas: desired,
        running_replicas: running,
        image: image.into(),
        update_state: None,
    }
}

const MANIFEST: &str = r#"
apiVersion: hlb/v1
kind: App
metadata: { name: gitea }
spec:
  image: { repo: gitea/gitea, tag: "1.24" }
  swarm:
    replicas: 2
    tier: heavy
"#;

/// A state with gitea installed and considered running.
async fn state_with_running_gitea() -> State {
    let s = State::in_memory().await.unwrap();
    let m: hlb_types::Manifest = serde_yaml_ng::from_str(MANIFEST).unwrap();
    s.upsert_app("gitea", &m, None).await.unwrap();
    s.set_app_status("gitea", "running").await.unwrap();
    s
}

#[tokio::test]
async fn a_healthy_cluster_reports_no_drift() {
    let o = Fake::with(vec![svc("gitea", "gitea/gitea:1.24", 2, 2)]);
    let s = state_with_running_gitea().await;

    let report = Reconciler::new(&o, &s).reconcile(false).await.unwrap();
    assert!(report.is_clean(), "unexpected drifts: {:?}", report.drifts);
}

#[tokio::test]
async fn a_deleted_service_is_detected_and_redeployed() {
    // Quelqu'un a fait `docker service rm gitea`.
    let o = Fake::with(vec![]);
    let s = state_with_running_gitea().await;

    let report = Reconciler::new(&o, &s).reconcile(true).await.unwrap();

    assert!(matches!(report.drifts[0], Drift::ServiceMissing { .. }));
    assert_eq!(*o.deployed.lock().unwrap(), vec!["gitea"]);
    assert_eq!(report.corrected.len(), 1);
}

#[tokio::test]
async fn manual_scaling_is_reverted_to_the_manifest() {
    // `docker service scale gitea=5`
    let o = Fake::with(vec![svc("gitea", "gitea/gitea:1.24", 5, 5)]);
    let s = state_with_running_gitea().await;

    let report = Reconciler::new(&o, &s).reconcile(true).await.unwrap();

    assert!(matches!(
        report.drifts[0],
        Drift::ReplicasDiverged {
            desired: 2,
            actual: 5,
            ..
        }
    ));
    assert_eq!(*o.scaled.lock().unwrap(), vec![("gitea".to_string(), 2)]);
}

#[tokio::test]
async fn a_manually_changed_image_is_reverted() {
    let o = Fake::with(vec![svc("gitea", "gitea/gitea:1.20", 2, 2)]);
    let s = state_with_running_gitea().await;

    let report = Reconciler::new(&o, &s).reconcile(true).await.unwrap();

    assert!(matches!(report.drifts[0], Drift::ImageDiverged { .. }));
    assert_eq!(
        *o.updated.lock().unwrap(),
        vec![("gitea".to_string(), "gitea/gitea:1.24".to_string())]
    );
}

#[tokio::test]
async fn swarm_resolving_the_digest_is_not_a_drift() {
    // Swarm commonly rewrites the reference by appending the resolved digest.
    let o = Fake::with(vec![svc("gitea", "gitea/gitea:1.24@sha256:abcdef", 2, 2)]);
    let s = state_with_running_gitea().await;

    let report = Reconciler::new(&o, &s).reconcile(false).await.unwrap();
    assert!(report.is_clean(), "faux positif : {:?}", report.drifts);
}

// ── What reconciliation must NEVER do ────────────────────────────────────────

#[tokio::test]
async fn detection_alone_never_touches_anything() {
    let o = Fake::with(vec![]);
    let s = state_with_running_gitea().await;

    let report = Reconciler::new(&o, &s).reconcile(false).await.unwrap();

    assert_eq!(report.drifts.len(), 1, "the drift is seen");
    assert!(report.corrected.is_empty());
    assert!(
        o.deployed.lock().unwrap().is_empty(),
        "no action during detection"
    );
}

#[tokio::test]
async fn an_orphan_service_is_reported_but_never_deleted() {
    // A real case: the state database was lost and rebuilt. The service may hold
    // data. Deleting it automatically would be unacceptable.
    let o = Fake::with(vec![svc("inconnue", "img:1", 1, 1)]);
    let s = State::in_memory().await.unwrap();

    let report = Reconciler::new(&o, &s).reconcile(true).await.unwrap();

    assert!(matches!(report.drifts[0], Drift::OrphanService { .. }));
    assert!(!report.drifts[0].is_correctable());
    assert!(
        o.removed.lock().unwrap().is_empty(),
        "an orphan must NEVER be deleted automatically"
    );
    assert!(report.corrected.is_empty());
}

#[tokio::test]
async fn a_failed_install_is_not_resurrected() {
    // Without this guard, we loop forever on the same error.
    let o = Fake::with(vec![]);
    let s = state_with_running_gitea().await;
    s.set_app_status("gitea", "failed").await.unwrap();

    let report = Reconciler::new(&o, &s).reconcile(true).await.unwrap();

    assert!(report.is_clean(), "a failed install must be left alone");
    assert!(o.deployed.lock().unwrap().is_empty());
}

#[tokio::test]
async fn an_install_in_progress_is_left_alone() {
    // Status "installing": the executor is working, we do not race it.
    let o = Fake::with(vec![]);
    let s = State::in_memory().await.unwrap();
    let m: hlb_types::Manifest = serde_yaml_ng::from_str(MANIFEST).unwrap();
    s.upsert_app("gitea", &m, None).await.unwrap(); // default status: installing

    let report = Reconciler::new(&o, &s).reconcile(true).await.unwrap();
    assert!(report.is_clean());
    assert!(o.deployed.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_converging_service_is_reported_but_not_forced() {
    // Swarm is starting tasks: 1/2 running. We let it finish.
    let o = Fake::with(vec![svc("gitea", "gitea/gitea:1.24", 2, 1)]);
    let s = state_with_running_gitea().await;

    let report = Reconciler::new(&o, &s).reconcile(true).await.unwrap();

    assert!(matches!(
        report.drifts[0],
        Drift::Converging {
            running: 1,
            desired: 2,
            ..
        }
    ));
    assert!(!report.drifts[0].is_correctable());
    assert!(
        o.scaled.lock().unwrap().is_empty(),
        "on n'empile pas d'ordres"
    );
    assert!(o.deployed.lock().unwrap().is_empty());
}

#[tokio::test]
async fn one_failure_does_not_stop_the_others() {
    // Unlike installation, corrections are independent of each other.
    struct HalfBroken(Fake);

    #[async_trait]
    impl Orchestrator for HalfBroken {
        async fn tasks(
            &self,
            _: Option<&str>,
        ) -> hlb_orchestrator::Result<Vec<hlb_orchestrator::TaskInfo>> {
            // A fake orchestrator has no tasks: empty is the honest answer.
            Ok(Vec::new())
        }

        async fn logs(
            &self,
            _: &str,
            _: u32,
        ) -> hlb_orchestrator::Result<Vec<hlb_orchestrator::LigneLog>> {
            Ok(Vec::new())
        }
        async fn enable_autolock(&self) -> hlb_orchestrator::Result<String> {
            Ok("SWMKEY-fake".into())
        }
        async fn autolock_enabled(&self) -> hlb_orchestrator::Result<bool> {
            Ok(false)
        }
        async fn cluster_init(&self, _: Option<&str>) -> hlb_orchestrator::Result<String> {
            Ok("swarm-fake".into())
        }
        async fn join_tokens(&self) -> hlb_orchestrator::Result<hlb_orchestrator::JoinTokens> {
            Ok(hlb_orchestrator::JoinTokens {
                manager: "SWMTKN-mgr".into(),
                worker: "SWMTKN-wrk".into(),
                advertise_addr: "127.0.0.1:2377".into(),
            })
        }
        async fn nodes(&self) -> hlb_orchestrator::Result<Vec<hlb_orchestrator::NodeInfo>> {
            Ok(Vec::new())
        }
        async fn label_node(&self, _: &str, _: &str, _: &str) -> hlb_orchestrator::Result<()> {
            Ok(())
        }
        async fn exec_in_service(
            &self,
            _: &str,
            _: &[String],
        ) -> hlb_orchestrator::Result<hlb_orchestrator::ExecOutput> {
            Ok(hlb_orchestrator::ExecOutput {
                exit_code: 0,
                stdout: String::new(),
                stderr: String::new(),
            })
        }
        async fn ping(&self) -> hlb_orchestrator::Result<String> {
            self.0.ping().await
        }
        async fn deploy(&self, s: &ServiceSpec) -> hlb_orchestrator::Result<String> {
            if s.name == "gitea" {
                return Err(hlb_orchestrator::Error::Unexpected(
                    "simulated failure".into(),
                ));
            }
            self.0.deploy(s).await
        }
        async fn update_image(&self, n: &str, i: &str) -> hlb_orchestrator::Result<()> {
            self.0.update_image(n, i).await
        }
        async fn scale(&self, n: &str, r: u64) -> hlb_orchestrator::Result<()> {
            self.0.scale(n, r).await
        }
        async fn create_volume(
            &self,
            n: &str,
        ) -> hlb_orchestrator::Result<hlb_orchestrator::VolumeInfo> {
            Ok(hlb_orchestrator::VolumeInfo {
                name: n.into(),
                mountpoint: format!("/volumes/{n}"),
                existed: false,
            })
        }
        async fn inspect_volume(
            &self,
            n: &str,
        ) -> hlb_orchestrator::Result<hlb_orchestrator::VolumeInfo> {
            self.create_volume(n).await
        }
        async fn status(&self, n: &str) -> hlb_orchestrator::Result<ServiceStatus> {
            self.0.status(n).await
        }
        async fn list(&self) -> hlb_orchestrator::Result<Vec<ServiceStatus>> {
            self.0.list().await
        }
        async fn remove(&self, n: &str) -> hlb_orchestrator::Result<()> {
            self.0.remove(n).await
        }
        async fn wait_healthy(&self, n: &str, t: u64) -> hlb_orchestrator::Result<ServiceStatus> {
            self.0.wait_healthy(n, t).await
        }
    }

    let o = HalfBroken(Fake::with(vec![]));
    let s = state_with_running_gitea().await;

    let m: hlb_types::Manifest = serde_yaml_ng::from_str(
        "apiVersion: hlb/v1\nkind: App\nmetadata: { name: vikunja }\nspec:\n  \
         image: { repo: vikunja/vikunja, tag: \"0.24\" }\n",
    )
    .unwrap();
    s.upsert_app("vikunja", &m, None).await.unwrap();
    s.set_app_status("vikunja", "running").await.unwrap();

    let report = Reconciler::new(&o, &s).reconcile(true).await.unwrap();

    assert_eq!(report.failed.len(), 1, "gitea fails");
    assert_eq!(report.corrected.len(), 1, "vikunja is repaired anyway");
    assert_eq!(*o.0.deployed.lock().unwrap(), vec!["vikunja"]);
}

/// The digest resolved during execution must win over the tag frozen in the plan.
#[tokio::test]
async fn the_deploy_uses_the_digest_resolved_earlier_in_the_same_plan() {
    use hlb_engine::Executor;

    let o = Fake::default();
    let s = State::in_memory().await.unwrap();
    let m: hlb_types::Manifest = serde_yaml_ng::from_str(MANIFEST).unwrap();
    s.upsert_app("gitea", &m, None).await.unwrap();

    // Simulates what `ResolveDigest` does just before the deployment.
    s.set_app_digest("gitea", "sha256:deadbeef").await.unwrap();

    let plan = hlb_resolver::resolve(&m, &hlb_resolver::InstallParams::default()).unwrap();
    Executor::new(&o, &s)
        .apply(true)
        .run("gitea", &plan)
        .await
        .unwrap();

    assert_eq!(
        *o.deployed_images.lock().unwrap(),
        vec!["gitea/gitea:1.24@sha256:deadbeef"],
        "the digest is what must be deployed, not the tag"
    );
}
