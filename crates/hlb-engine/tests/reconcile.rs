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
    specs: Mutex<Vec<ServiceSpec>>,
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
        self.specs.lock().unwrap().push(s.clone());
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
    async fn cluster_init(&self, _: &str) -> hlb_orchestrator::Result<String> {
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
    async fn set_node_availability(&self, _: &str, _: &str) -> hlb_orchestrator::Result<()> {
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
    async fn ensure_network(&self, _: &str) -> hlb_orchestrator::Result<bool> {
        Ok(false)
    }

    async fn create_volume(
        &self,
        spec: &hlb_orchestrator::VolumeSpec,
    ) -> hlb_orchestrator::Result<hlb_orchestrator::VolumeInfo> {
        Ok(hlb_orchestrator::VolumeInfo {
            name: spec.name.clone(),
            mountpoint: format!("/volumes/{}", spec.name),
            existed: false,
        })
    }
    async fn inspect_volume(
        &self,
        n: &str,
    ) -> hlb_orchestrator::Result<hlb_orchestrator::VolumeInfo> {
        self.create_volume(&hlb_orchestrator::VolumeSpec::docker(n))
            .await
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
    ) -> hlb_orchestrator::Result<Vec<hlb_orchestrator::LogLine>> {
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
async fn a_deleted_service_is_reported_not_recreated_without_its_volumes() {
    // Someone ran `docker service rm gitea`. Recreated here it came back with no volume
    // and no environment (found on a real cluster): it is left to `hlb install`.
    let o = Fake::with(vec![]);
    let s = state_with_running_gitea().await;

    let report = Reconciler::new(&o, &s).reconcile(true).await.unwrap();

    assert!(matches!(report.drifts[0], Drift::ServiceMissing { .. }));
    assert!(o.deployed.lock().unwrap().is_empty());
    assert!(report.corrected.is_empty());
    let why = report.drifts[0].refusal().expect("a reason");
    assert!(why.contains("hlb install"), "{why}");
    // Left alone on purpose, and gitea is down all the same.
    assert_eq!(
        report.drifts[0].summary().attention(),
        hlb_api::Attention::Critical
    );
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
    let o = Fake::with(vec![svc("unknown", "img:1", 1, 1)]);
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
async fn homelabus_own_services_are_not_orphans() {
    // The agent and the controller are managed and belong to no app: reported as
    // orphans, they were noise on every pass of the first real deployment.
    let o = Fake::with(vec![
        svc("hlb-agent", "hlb-agent:1", 1, 1),
        svc("hlb-controller", "hlb-controller:1", 1, 1),
    ]);
    let s = State::in_memory().await.unwrap();
    let report = Reconciler::new(&o, &s).reconcile(false).await.unwrap();
    assert!(report.drifts.is_empty(), "{:?}", report.drifts);
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
        "orders are not stacked up"
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
        ) -> hlb_orchestrator::Result<Vec<hlb_orchestrator::LogLine>> {
            Ok(Vec::new())
        }
        async fn enable_autolock(&self) -> hlb_orchestrator::Result<String> {
            Ok("SWMKEY-fake".into())
        }
        async fn autolock_enabled(&self) -> hlb_orchestrator::Result<bool> {
            Ok(false)
        }
        async fn cluster_init(&self, _: &str) -> hlb_orchestrator::Result<String> {
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
        async fn set_node_availability(&self, _: &str, _: &str) -> hlb_orchestrator::Result<()> {
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
            if n == "gitea" {
                return Err(hlb_orchestrator::Error::Unexpected(
                    "simulated failure".into(),
                ));
            }
            self.0.scale(n, r).await
        }
        async fn ensure_network(&self, _: &str) -> hlb_orchestrator::Result<bool> {
            Ok(false)
        }

        async fn create_volume(
            &self,
            spec: &hlb_orchestrator::VolumeSpec,
        ) -> hlb_orchestrator::Result<hlb_orchestrator::VolumeInfo> {
            Ok(hlb_orchestrator::VolumeInfo {
                name: spec.name.clone(),
                mountpoint: format!("/volumes/{}", spec.name),
                existed: false,
            })
        }
        async fn inspect_volume(
            &self,
            n: &str,
        ) -> hlb_orchestrator::Result<hlb_orchestrator::VolumeInfo> {
            self.create_volume(&hlb_orchestrator::VolumeSpec::docker(n))
                .await
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

    // Both scaled by hand: two corrections, the first of which fails.
    let o = HalfBroken(Fake::with(vec![
        svc("gitea", "gitea/gitea:1.24", 5, 5),
        svc("vikunja", "vikunja/vikunja:0.24", 3, 3),
    ]));
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
    assert_eq!(
        *o.0.scaled.lock().unwrap(),
        vec![("vikunja".to_string(), 1)]
    );
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

/// A done deployment whose service is gone is deployed again: what the reconciliation
/// now sends a missing service to.
#[tokio::test]
async fn rerunning_an_install_redeploys_a_service_deleted_since() {
    use hlb_engine::Executor;

    let o = Fake::default();
    let s = State::in_memory().await.unwrap();
    let m: hlb_types::Manifest = serde_yaml_ng::from_str(MANIFEST).unwrap();
    s.upsert_app("gitea", &m, None).await.unwrap();
    // No registry here: the digest `ResolveDigest` would have frozen.
    s.set_app_digest("gitea", "sha256:deadbeef").await.unwrap();
    let plan = hlb_resolver::resolve(&m, &hlb_resolver::InstallParams::default()).unwrap();
    let run = || async { Executor::new(&o, &s).apply(true).run("gitea", &plan).await };

    run().await.unwrap();
    assert_eq!(o.deployed.lock().unwrap().len(), 1);

    // Still running: nothing is redeployed.
    *o.observed.lock().unwrap() = vec![svc("gitea", "gitea/gitea:1.24", 2, 2)];
    run().await.unwrap();
    assert_eq!(o.deployed.lock().unwrap().len(), 1);

    // `docker service rm gitea`: the rerun brings it back, whole.
    o.observed.lock().unwrap().clear();
    run().await.unwrap();
    assert_eq!(o.deployed.lock().unwrap().len(), 2);
}

/// An NFS volume reaches Swarm with its backing, not only the local daemon.
#[tokio::test]
async fn a_volume_on_nfs_is_deployed_with_what_makes_every_node_mount_nfs() {
    use hlb_engine::{Executor, StorageConfig};
    use hlb_orchestrator::VolumeBacking;

    let o = Fake::default();
    let s = State::in_memory().await.unwrap();
    let m: hlb_types::Manifest = serde_yaml_ng::from_str(
        r#"
apiVersion: hlb/v1
kind: App
metadata: { name: jellyfin }
spec:
  image: { repo: jellyfin/jellyfin, tag: "10.10", digest: "sha256:abc" }
  requires:
    - kind: storage
      name: media
      path: /media
      tier: nfs
    - kind: storage
      name: config
      path: /config
      tier: local
"#,
    )
    .unwrap();
    s.upsert_app("jellyfin", &m, None).await.unwrap();
    let plan = hlb_resolver::resolve(&m, &hlb_resolver::InstallParams::default()).unwrap();
    Executor::new(&o, &s)
        .with_storage(StorageConfig {
            local_root: None,
            nfs_server: Some("10.42.0.3".into()),
            nfs_export: Some("/tank/apps".into()),
        })
        .apply(true)
        .run("jellyfin", &plan)
        .await
        .unwrap();

    let specs = o.specs.lock().unwrap();
    let spec = specs
        .iter()
        .find(|x| x.name == "jellyfin")
        .expect("deployed");
    // The export path is built from the DECLARED name, the one `storage init` creates:
    // `jellyfin/media`, never `jellyfin/jellyfin-media`.
    assert_eq!(
        spec.backing_of("jellyfin-media"),
        VolumeBacking::Nfs {
            server: "10.42.0.3".into(),
            export: "/tank/apps/jellyfin/media".into(),
        }
    );
    assert_eq!(spec.backing_of("jellyfin-config"), VolumeBacking::Docker);
    // The local one keeps the service on its node.
    assert!(spec.keeps_data_on_its_node());
}

/// A companion runs its own image, with its own digest: Immich's machine-learning
/// service was deployed as the server, under a digest that existed for neither.
#[tokio::test]
async fn a_companion_is_deployed_from_its_own_image_and_digest() {
    use hlb_engine::Executor;

    let o = Fake::default();
    let s = State::in_memory().await.unwrap();
    let m: hlb_types::Manifest = serde_yaml_ng::from_str(
        r#"
apiVersion: hlb/v1
kind: App
metadata: { name: immich }
spec:
  image: { repo: ghcr.io/immich-app/immich-server, tag: "v3.1.0" }
  companions:
    - name: machine-learning
      image: { repo: ghcr.io/immich-app/immich-machine-learning, tag: "v3.1.0" }
"#,
    )
    .unwrap();
    s.upsert_app("immich", &m, None).await.unwrap();
    // What two `ResolveDigest` do, the companion's last.
    for (repo, digest) in [
        ("ghcr.io/immich-app/immich-server", "sha256:server"),
        ("ghcr.io/immich-app/immich-machine-learning", "sha256:ml"),
    ] {
        assert!(s
            .set_image_digest("immich", repo, "v3.1.0", digest)
            .await
            .unwrap());
    }

    let plan = hlb_resolver::resolve(&m, &hlb_resolver::InstallParams::default()).unwrap();
    *o.observed.lock().unwrap() = vec![
        svc("immich-machine-learning", "unused", 1, 1),
        svc("immich", "unused", 1, 1),
    ];
    let out = Executor::new(&o, &s)
        .apply(true)
        .run("immich", &plan)
        .await
        .unwrap();
    assert!(out.failed.is_none(), "{:?}", out.failed);

    let specs = o.specs.lock().unwrap();
    let image_of = |name: &str| {
        specs
            .iter()
            .find(|x| x.name == name)
            .map(|x| x.image.clone())
            .expect("deployed")
    };
    assert_eq!(
        image_of("immich-machine-learning"),
        "ghcr.io/immich-app/immich-machine-learning:v3.1.0@sha256:ml"
    );
    assert_eq!(
        image_of("immich"),
        "ghcr.io/immich-app/immich-server:v3.1.0@sha256:server"
    );
}

/// Removing an app removes its companions: Immich's machine-learning service stayed
/// running, managed by nobody.
#[tokio::test]
async fn removing_an_app_removes_its_companions_too() {
    let o = Fake::default();
    let m: hlb_types::Manifest = serde_yaml_ng::from_str(
        r#"
apiVersion: hlb/v1
kind: App
metadata: { name: immich }
spec:
  image: { repo: ghcr.io/immich-app/immich-server, tag: "v3.1.0" }
  companions:
    - name: machine-learning
      image: { repo: ghcr.io/immich-app/immich-machine-learning, tag: "v3.1.0" }
"#,
    )
    .unwrap();
    hlb_engine::remove_services(&o, "immich", &m).await.unwrap();
    assert_eq!(
        *o.removed.lock().unwrap(),
        vec!["immich".to_string(), "immich-machine-learning".to_string()]
    );
}

const IMMICH: &str = r#"
apiVersion: hlb/v1
kind: App
metadata: { name: immich }
spec:
  image: { repo: ghcr.io/immich-app/immich-server, tag: "v3.1.0" }
  companions:
    - name: machine-learning
      image: { repo: ghcr.io/immich-app/immich-machine-learning, tag: "v3.1.0" }
  requires:
    - kind: cache
      engine: valkey
      dedicated: true
"#;

async fn state_with_running_immich() -> State {
    let s = State::in_memory().await.unwrap();
    let m: hlb_types::Manifest = serde_yaml_ng::from_str(IMMICH).unwrap();
    s.upsert_app("immich", &m, None).await.unwrap();
    s.set_app_status("immich", "running").await.unwrap();
    s
}

/// 🔴 A companion and a dedicated cache were reported orphans at every pass, and
/// checked for nothing: gone or scaled down, neither was ever said.
#[tokio::test]
async fn a_companion_is_its_app_s_and_is_held_to_its_manifest_like_it() {
    let healthy = vec![
        svc("immich", "ghcr.io/immich-app/immich-server:v3.1.0", 1, 1),
        svc(
            "immich-machine-learning",
            "ghcr.io/immich-app/immich-machine-learning:v3.1.0",
            1,
            1,
        ),
        svc("immich-valkey", "valkey:latest", 1, 1),
    ];
    let s = state_with_running_immich().await;
    let o = Fake::with(healthy.clone());
    let report = Reconciler::new(&o, &s).reconcile(false).await.unwrap();
    assert!(report.is_clean(), "{:?}", report.drifts);

    // The companion gone, the cache scaled down, the companion on another image.
    let o = Fake::with(vec![
        healthy[0].clone(),
        svc("immich-valkey", "valkey:latest", 0, 0),
    ]);
    let report = Reconciler::new(&o, &s).reconcile(true).await.unwrap();
    assert!(
        report.drifts.iter().any(|d| matches!(d,
            Drift::ServiceMissing { app, .. } if app == "immich-machine-learning")),
        "{:?}",
        report.drifts
    );
    assert!(!report
        .drifts
        .iter()
        .any(|d| matches!(d, Drift::OrphanService { .. })));
    assert_eq!(
        *o.scaled.lock().unwrap(),
        vec![("immich-valkey".to_string(), 1)]
    );

    let o = Fake::with(vec![
        healthy[0].clone(),
        svc(
            "immich-machine-learning",
            "ghcr.io/immich-app/immich-machine-learning:v3.0.0",
            1,
            1,
        ),
        healthy[2].clone(),
    ]);
    Reconciler::new(&o, &s).reconcile(true).await.unwrap();
    assert_eq!(
        *o.updated.lock().unwrap(),
        vec![(
            "immich-machine-learning".to_string(),
            "ghcr.io/immich-app/immich-machine-learning:v3.1.0".to_string()
        )]
    );
}

/// A failed install's companion is still its app's: not an orphan either.
#[tokio::test]
async fn a_failed_install_s_companion_is_not_an_orphan() {
    let s = state_with_running_immich().await;
    s.set_app_status("immich", "failed").await.unwrap();
    let o = Fake::with(vec![svc(
        "immich-machine-learning",
        "ghcr.io/immich-app/immich-machine-learning:v3.1.0",
        1,
        1,
    )]);
    let report = Reconciler::new(&o, &s).reconcile(false).await.unwrap();
    assert!(report.is_clean(), "{:?}", report.drifts);
}

/// 🔴 `hlb stop` lived in Swarm only: the next pass read the zero as drift and started
/// the app again within a minute.
#[tokio::test]
async fn reconciliation_does_not_scale_a_stopped_app_back_up() {
    let s = state_with_running_gitea().await;
    assert!(s.set_app_replicas("gitea", Some(0)).await.unwrap());
    let o = Fake::with(vec![svc("gitea", "gitea/gitea:1.24", 0, 0)]);
    let report = Reconciler::new(&o, &s).reconcile(true).await.unwrap();
    assert!(report.is_clean(), "{:?}", report.drifts);
    assert!(o.scaled.lock().unwrap().is_empty());

    // A count decided by `hlb scale` is the one kept against a hand's.
    assert!(s.set_app_replicas("gitea", Some(3)).await.unwrap());
    let o = Fake::with(vec![svc("gitea", "gitea/gitea:1.24", 2, 2)]);
    Reconciler::new(&o, &s).reconcile(true).await.unwrap();
    assert_eq!(*o.scaled.lock().unwrap(), vec![("gitea".to_string(), 3)]);
}

/// A stopped app redeployed — `hlb redeploy`, an upgrade — stays stopped.
#[tokio::test]
async fn a_redeployment_keeps_the_count_stop_decided() {
    use hlb_engine::Executor;
    let s = state_with_running_gitea().await;
    let mut m: hlb_types::Manifest = serde_yaml_ng::from_str(MANIFEST).unwrap();
    m.spec.image.digest = Some("sha256:abc".into());
    s.upsert_app("gitea", &m, None).await.unwrap();
    s.set_app_replicas("gitea", Some(0)).await.unwrap();
    let o = Fake::default();
    let plan = hlb_resolver::resolve(&m, &hlb_resolver::InstallParams::default()).unwrap();
    Executor::new(&o, &s)
        .apply(true)
        .run("gitea", &plan)
        .await
        .unwrap();
    let specs = o.specs.lock().unwrap();
    let gitea = specs.iter().find(|x| x.name == "gitea").expect("deployed");
    assert_eq!(gitea.replicas, 0);
}

#[tokio::test]
async fn a_service_held_for_a_copy_is_left_stopped_until_the_hold_lapses() {
    // 🔴 A restore — and a pass stopping a store for its copy — scales to zero: with
    // `--reconcile-apply`, the next minute started the app again on a volume half
    // written.
    let o = Fake::with(vec![svc("gitea", "gitea/gitea:1.24", 0, 0)]);
    let s = state_with_running_gitea().await;
    s.hold_services(&["gitea".to_string()], "restore of gitea-data", 3600)
        .await
        .expect("hold");

    let report = Reconciler::new(&o, &s).reconcile(true).await.unwrap();
    assert!(o.scaled.lock().unwrap().is_empty(), "{report:?}");
    assert!(matches!(&report.drifts[0], Drift::Held { why, .. } if why.contains("restore")));
    assert!(report.drifts[0].refusal().is_some());

    // Lapsed — the pass that held it died —: taken back like any other drift.
    s.hold_services(&["gitea".to_string()], "restore of gitea-data", -1)
        .await
        .expect("hold");
    Reconciler::new(&o, &s).reconcile(true).await.unwrap();
    assert_eq!(*o.scaled.lock().unwrap(), vec![("gitea".to_string(), 2)]);

    // Released, nothing of it is left.
    s.release_services(&["gitea".to_string()])
        .await
        .expect("release");
    assert_eq!(s.held("gitea").await.expect("read"), None);
}

/// A Garage answering what it was given, or failing as told.
struct Store(Result<hlb_objstore::Inventory, String>);

#[async_trait]
impl hlb_engine::reconcile::StoreInventory for Store {
    async fn inventory(&self) -> Result<hlb_objstore::Inventory, String> {
        self.0.clone()
    }
}

fn held(buckets: &[&str], keys: &[(&str, &str)]) -> Store {
    Store(Ok(hlb_objstore::Inventory {
        buckets: buckets.iter().map(|b| b.to_string()).collect(),
        keys: keys
            .iter()
            .map(|(n, i)| (n.to_string(), i.to_string()))
            .collect(),
    }))
}

const FLUXER: &str = r#"
apiVersion: hlb/v1
kind: App
metadata: { name: fluxer }
spec:
  image: { repo: fluxer/api, tag: "1" }
  requires:
    - kind: object-storage
    - kind: object-storage
      bucket: fluxer-uploads
    - kind: object-storage
      bucket: fluxer-staging
      backup: false
"#;

/// Fluxer running, its key id `GKfluxer` in the vault as provisioning leaves it.
async fn state_with_running_fluxer(dir: &std::path::Path) -> (State, hlb_secrets::Vault) {
    let s = State::in_memory().await.unwrap();
    let m: hlb_types::Manifest = serde_yaml_ng::from_str(FLUXER).unwrap();
    s.upsert_app("fluxer", &m, None).await.unwrap();
    s.set_app_status("fluxer", "running").await.unwrap();
    let v = hlb_secrets::Vault::open_or_init(dir.join("k.key")).unwrap();
    s.store_secret_if_absent(
        &hlb_types::capability::s3_key_secrets("fluxer").0,
        &v.encrypt("GKfluxer").unwrap(),
        "S3 access key id",
    )
    .await
    .unwrap();
    (s, v)
}

fn fluxer_runs() -> Fake {
    Fake::with(vec![svc("fluxer", "fluxer/api:1", 1, 1)])
}

#[tokio::test]
async fn an_app_whose_buckets_and_key_garage_holds_has_no_storage_drift() {
    let dir = tempfile::tempdir().unwrap();
    let (s, v) = state_with_running_fluxer(dir.path()).await;
    let o = fluxer_runs();
    let g = held(
        &["fluxer", "fluxer-uploads", "fluxer-staging"],
        &[("fluxer", "GKfluxer")],
    );
    let report = Reconciler::new(&o, &s)
        .with_store(&g, Some(&v))
        .reconcile(true)
        .await
        .unwrap();
    assert!(report.is_clean(), "{:?}", report.drifts);
}

#[tokio::test]
async fn storage_garage_lost_is_named_with_its_fix_and_left_alone() {
    // 🔴 Garage wiped and rebuilt: Fluxer ran 1/1 against `No such key`, and
    // reconciliation said nothing — every service was where it should be.
    let dir = tempfile::tempdir().unwrap();
    let (s, v) = state_with_running_fluxer(dir.path()).await;
    let o = fluxer_runs();
    let g = held(&["fluxer"], &[]);
    let report = Reconciler::new(&o, &s)
        .with_store(&g, Some(&v))
        .reconcile(true)
        .await
        .unwrap();
    let [d] = report.drifts.as_slice() else {
        panic!("{:?}", report.drifts)
    };
    let Drift::StorageLost { app, buckets, key } = d else {
        panic!("{d:?}")
    };
    assert_eq!(app, "fluxer");
    let names: Vec<&str> = buckets.iter().map(|b| b.name.as_str()).collect();
    assert_eq!(names, ["fluxer-uploads", "fluxer-staging"]);
    assert_eq!(key.as_deref(), Some("its key fluxer"));
    assert!(!d.is_correctable() && d.refusal().is_some());
    // The restore names the BUCKET, and only one whose objects a backup holds: the
    // staging bucket comes back empty, and the description says so.
    assert_eq!(
        d.fix().as_deref(),
        Some("hlb redeploy fluxer --apply, then hlb backup restore fluxer fluxer-uploads")
    );
    assert!(
        d.to_string().contains("fluxer-staging (not backed up"),
        "{d}"
    );
    assert!(report.corrected.is_empty());
    assert!(o.deployed.lock().unwrap().is_empty());
    // 🔴 Refused is a decision, not "fine": painted green, the issues list dropped it
    // and the lab's dashboard stayed calm over a Fluxer without its key.
    assert_eq!(d.summary().attention(), hlb_api::Attention::Critical);
    assert_eq!(
        hlb_api::issues::group([(
            hlb_api::issues::Cause::Drift,
            d.summary().attention(),
            Some(app.clone())
        )])
        .len(),
        1
    );
}

#[tokio::test]
async fn a_key_of_the_app_s_name_that_is_not_the_one_it_signs_with_is_lost_too() {
    // A key made again by hand under the same name: Garage "has" it, and the app's
    // signature still names the old one.
    let dir = tempfile::tempdir().unwrap();
    let (s, v) = state_with_running_fluxer(dir.path()).await;
    let o = fluxer_runs();
    let g = held(
        &["fluxer", "fluxer-uploads", "fluxer-staging"],
        &[("fluxer", "GKother")],
    );
    let report = Reconciler::new(&o, &s)
        .with_store(&g, Some(&v))
        .reconcile(false)
        .await
        .unwrap();
    assert!(
        matches!(report.drifts.as_slice(), [Drift::StorageLost { buckets, key: Some(k), .. }]
            if buckets.is_empty() && k.contains("signs with")),
        "{:?}",
        report.drifts
    );
}

#[tokio::test]
async fn a_garage_that_does_not_answer_is_said_never_read_as_holding_everything() {
    let dir = tempfile::tempdir().unwrap();
    let (s, v) = state_with_running_fluxer(dir.path()).await;
    let o = fluxer_runs();
    let g = Store(Err("connection refused".into()));
    let report = Reconciler::new(&o, &s)
        .with_store(&g, Some(&v))
        .reconcile(false)
        .await
        .unwrap();
    assert!(
        matches!(report.drifts.as_slice(), [Drift::StorageUnread { why }] if why == "connection refused"),
        "{:?}",
        report.drifts
    );
    // Not read is never painted as fine.
    assert_eq!(
        report.drifts[0].summary().attention(),
        hlb_api::Attention::Notice
    );
}

#[tokio::test]
async fn garage_is_not_asked_when_no_running_app_holds_a_bucket() {
    // A Garage down on an installation whose apps hold no bucket is no gap of theirs.
    let o = Fake::with(vec![svc("gitea", "gitea/gitea:1.24", 2, 2)]);
    let s = state_with_running_gitea().await;
    let g = Store(Err("connection refused".into()));
    let report = Reconciler::new(&o, &s)
        .with_store(&g, None)
        .reconcile(false)
        .await
        .unwrap();
    assert!(report.is_clean(), "{:?}", report.drifts);
}

struct Portal(Result<Option<Vec<String>>, String>);

#[async_trait]
impl hlb_engine::PortalClient for Portal {
    async fn callbacks(&self) -> Result<Option<Vec<String>>, String> {
        self.0.clone()
    }
}

fn accepting(urls: &[&str]) -> Portal {
    Portal(Ok(Some(urls.iter().map(|u| u.to_string()).collect())))
}

async fn state_behind_portal() -> State {
    let s = State::in_memory().await.unwrap();
    let portal: hlb_types::Manifest = serde_yaml_ng::from_str(
        r#"
apiVersion: hlb/v1
kind: App
metadata: { name: oauth2-proxy }
spec:
  image: { repo: a/portal, tag: "1" }
  requires:
    - { kind: sso, mode: native, redirectPaths: ["/oauth2/callback"] }
"#,
    )
    .unwrap();
    let wiki: hlb_types::Manifest = serde_yaml_ng::from_str(
        r#"
apiVersion: hlb/v1
kind: App
metadata: { name: wiki }
spec:
  image: { repo: a/wiki, tag: "1" }
  requires:
    - { kind: sso, mode: proxy-only }
"#,
    )
    .unwrap();
    s.upsert_app("oauth2-proxy", &portal, Some("auth.example.test"))
        .await
        .unwrap();
    s.upsert_app("wiki", &wiki, Some("wiki.example.test"))
        .await
        .unwrap();
    s
}

const AUTH: &str = "https://auth.example.test/oauth2/callback";
const WIKI: &str = "https://wiki.example.test/oauth2/callback";
const OLD: &str = "https://old.example.test/oauth2/callback";

#[tokio::test]
async fn a_callback_no_installed_app_has_is_reported_and_left_alone() {
    let s = state_behind_portal().await;
    let o = Fake::with(Vec::new());
    let portal = accepting(&[AUTH, WIKI, OLD]);
    let report = Reconciler::new(&o, &s)
        .with_portal(&portal)
        .reconcile(true)
        .await
        .unwrap();
    let orphans: Vec<&Drift> = report
        .drifts
        .iter()
        .filter(|d| matches!(d, Drift::OrphanCallback { .. }))
        .collect();
    assert_eq!(
        orphans,
        vec![&Drift::OrphanCallback { url: OLD.into() }],
        "the portal's own and the app's are claimed"
    );
    assert!(!orphans[0].is_correctable());
    assert_eq!(
        orphans[0].fix().as_deref(),
        Some("hlb portal drop-callback https://old.example.test/oauth2/callback --apply")
    );
    assert!(report
        .corrected
        .iter()
        .all(|d| !matches!(d, Drift::OrphanCallback { .. })));
}

#[tokio::test]
async fn no_portal_installed_or_answering_reports_no_callback() {
    let orphans = |report: hlb_engine::Report| {
        report
            .drifts
            .iter()
            .filter(|d| matches!(d, Drift::OrphanCallback { .. }))
            .count()
    };
    let o = Fake::with(Vec::new());

    // A client of that name with no portal installed is not the portal's.
    let empty = State::in_memory().await.unwrap();
    let portal = accepting(&[OLD]);
    let report = Reconciler::new(&o, &empty)
        .with_portal(&portal)
        .reconcile(false)
        .await
        .unwrap();
    assert_eq!(orphans(report), 0);

    let s = state_behind_portal().await;
    for silent in [Portal(Err("refused".into())), Portal(Ok(None))] {
        let report = Reconciler::new(&o, &s)
            .with_portal(&silent)
            .reconcile(false)
            .await
            .unwrap();
        assert_eq!(orphans(report), 0);
    }
}
