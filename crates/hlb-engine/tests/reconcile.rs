//! Tests de la boucle de réconciliation (§2.1).
//!
//! La moitié de ces tests vérifient ce que la réconciliation **ne fait pas**. C'est le
//! plus important : un système qui corrige trop est plus dangereux qu'un système qui
//! ne corrige rien.

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

/// État avec gitea installée et considérée en marche.
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
    assert!(report.is_clean(), "écarts inattendus : {:?}", report.drifts);
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
        Drift::ReplicasDiverged { desired: 2, actual: 5, .. }
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
    // Swarm réécrit couramment la référence en y ajoutant le digest résolu.
    let o = Fake::with(vec![svc(
        "gitea",
        "gitea/gitea:1.24@sha256:abcdef",
        2,
        2,
    )]);
    let s = state_with_running_gitea().await;

    let report = Reconciler::new(&o, &s).reconcile(false).await.unwrap();
    assert!(report.is_clean(), "faux positif : {:?}", report.drifts);
}

// ── Ce que la réconciliation ne doit JAMAIS faire ────────────────────────────

#[tokio::test]
async fn detection_alone_never_touches_anything() {
    let o = Fake::with(vec![]);
    let s = state_with_running_gitea().await;

    let report = Reconciler::new(&o, &s).reconcile(false).await.unwrap();

    assert_eq!(report.drifts.len(), 1, "l'écart est bien vu");
    assert!(report.corrected.is_empty());
    assert!(o.deployed.lock().unwrap().is_empty(), "aucune action en détection");
}

#[tokio::test]
async fn an_orphan_service_is_reported_but_never_deleted() {
    // Cas réel : base d'état perdue puis reconstruite. Le service porte peut-être
    // des données. Le supprimer automatiquement serait inacceptable.
    let o = Fake::with(vec![svc("inconnue", "img:1", 1, 1)]);
    let s = State::in_memory().await.unwrap();

    let report = Reconciler::new(&o, &s).reconcile(true).await.unwrap();

    assert!(matches!(report.drifts[0], Drift::OrphanService { .. }));
    assert!(!report.drifts[0].is_correctable());
    assert!(
        o.removed.lock().unwrap().is_empty(),
        "un orphelin ne doit JAMAIS être supprimé automatiquement"
    );
    assert!(report.corrected.is_empty());
}

#[tokio::test]
async fn a_failed_install_is_not_resurrected() {
    // Sans ce garde-fou, on boucle indéfiniment sur la même erreur.
    let o = Fake::with(vec![]);
    let s = state_with_running_gitea().await;
    s.set_app_status("gitea", "failed").await.unwrap();

    let report = Reconciler::new(&o, &s).reconcile(true).await.unwrap();

    assert!(report.is_clean(), "une install en échec doit être ignorée");
    assert!(o.deployed.lock().unwrap().is_empty());
}

#[tokio::test]
async fn an_install_in_progress_is_left_alone() {
    // Statut « installing » : l'exécuteur travaille, on ne se met pas en concurrence.
    let o = Fake::with(vec![]);
    let s = State::in_memory().await.unwrap();
    let m: hlb_types::Manifest = serde_yaml_ng::from_str(MANIFEST).unwrap();
    s.upsert_app("gitea", &m, None).await.unwrap(); // statut par défaut : installing

    let report = Reconciler::new(&o, &s).reconcile(true).await.unwrap();
    assert!(report.is_clean());
    assert!(o.deployed.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_converging_service_is_reported_but_not_forced() {
    // Swarm démarre les tâches : 1/2 en cours. On le laisse finir.
    let o = Fake::with(vec![svc("gitea", "gitea/gitea:1.24", 2, 1)]);
    let s = state_with_running_gitea().await;

    let report = Reconciler::new(&o, &s).reconcile(true).await.unwrap();

    assert!(matches!(
        report.drifts[0],
        Drift::Converging { running: 1, desired: 2, .. }
    ));
    assert!(!report.drifts[0].is_correctable());
    assert!(o.scaled.lock().unwrap().is_empty(), "on n'empile pas d'ordres");
    assert!(o.deployed.lock().unwrap().is_empty());
}

#[tokio::test]
async fn one_failure_does_not_stop_the_others() {
    // Contrairement à l'installation, les corrections sont indépendantes.
    struct HalfBroken(Fake);

    #[async_trait]
    impl Orchestrator for HalfBroken {
        async fn ping(&self) -> hlb_orchestrator::Result<String> {
            self.0.ping().await
        }
        async fn deploy(&self, s: &ServiceSpec) -> hlb_orchestrator::Result<String> {
            if s.name == "gitea" {
                return Err(hlb_orchestrator::Error::Unexpected("échec simulé".into()));
            }
            self.0.deploy(s).await
        }
        async fn update_image(&self, n: &str, i: &str) -> hlb_orchestrator::Result<()> {
            self.0.update_image(n, i).await
        }
        async fn scale(&self, n: &str, r: u64) -> hlb_orchestrator::Result<()> {
            self.0.scale(n, r).await
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
        async fn wait_healthy(
            &self,
            n: &str,
            t: u64,
        ) -> hlb_orchestrator::Result<ServiceStatus> {
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

    assert_eq!(report.failed.len(), 1, "gitea échoue");
    assert_eq!(report.corrected.len(), 1, "vikunja est quand même réparée");
    assert_eq!(*o.0.deployed.lock().unwrap(), vec!["vikunja"]);
}
