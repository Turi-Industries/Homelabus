//! Tests du pipeline de mise à jour, avec un orchestrateur simulé.
//!
//! Le plan (§12bis) insiste : « la logique de rollback ne s'exercera jamais en
//! conditions réelles avant le jour où tu en auras désespérément besoin — il faut donc
//! la tester exprès ».

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::Mutex;

use async_trait::async_trait;
use hlb_orchestrator::{Orchestrator, ServiceSpec, ServiceStatus, UpdateState};
use hlb_state::State;
use hlb_updater::{apply, Candidate, UpdateKind, UpdateOutcome};

/// Orchestrateur scriptable : on lui dicte la suite d'états que Swarm renverra.
struct Fake {
    /// États successifs rendus par `status`, consommés un par un.
    script: Mutex<Vec<ServiceStatus>>,
    pushed: Mutex<Vec<(String, String)>>,
}

impl Fake {
    fn returning(states: Vec<ServiceStatus>) -> Self {
        Self {
            script: Mutex::new(states),
            pushed: Mutex::new(Vec::new()),
        }
    }
}

#[async_trait]
impl Orchestrator for Fake {
    async fn ping(&self) -> hlb_orchestrator::Result<String> {
        Ok("fake".into())
    }
    async fn deploy(&self, _: &ServiceSpec) -> hlb_orchestrator::Result<String> {
        Ok("id".into())
    }
    async fn update_image(&self, n: &str, i: &str) -> hlb_orchestrator::Result<()> {
        self.pushed.lock().unwrap().push((n.into(), i.into()));
        Ok(())
    }
    async fn scale(&self, _: &str, _: u64) -> hlb_orchestrator::Result<()> {
        Ok(())
    }
    async fn status(&self, _: &str) -> hlb_orchestrator::Result<ServiceStatus> {
        let mut s = self.script.lock().unwrap();
        if s.len() > 1 {
            Ok(s.remove(0))
        } else {
            s.first().cloned().ok_or(hlb_orchestrator::Error::NotFound("vide".into()))
        }
    }
    async fn list(&self) -> hlb_orchestrator::Result<Vec<ServiceStatus>> {
        Ok(vec![])
    }
    async fn remove(&self, _: &str) -> hlb_orchestrator::Result<()> {
        Ok(())
    }
    async fn wait_healthy(&self, n: &str, _: u64) -> hlb_orchestrator::Result<ServiceStatus> {
        self.status(n).await
    }
}

fn status(image: &str, state: Option<UpdateState>, running: usize) -> ServiceStatus {
    ServiceStatus {
        name: "gitea".into(),
        id: "id".into(),
        desired_replicas: 1,
        running_replicas: running,
        image: image.into(),
        update_state: state,
    }
}

const MANIFEST: &str = r#"
apiVersion: hlb/v1
kind: App
metadata: { name: gitea }
spec:
  image: { repo: gitea/gitea, tag: "1.24", digest: "sha256:ancienne" }
  update: { channel: minor, backupBefore: false }
"#;

async fn state_with_gitea() -> State {
    let s = State::in_memory().await.unwrap();
    let m: hlb_types::Manifest = serde_yaml_ng::from_str(MANIFEST).unwrap();
    s.upsert_app("gitea", &m, None).await.unwrap();
    s.set_app_status("gitea", "running").await.unwrap();
    s
}

fn candidate() -> Candidate {
    Candidate {
        app: "gitea".into(),
        kind: UpdateKind::NewVersion { to_tag: "1.25".into() },
        from_tag: "1.24".into(),
        from_digest: Some("sha256:ancienne".into()),
        to_digest: "sha256:nouvelle".into(),
        in_window: true,
        needs_backup: false,
    }
}

/// Un service jamais mis à jour n'a pas d'`UpdateStatus` : le succès doit quand même
/// être constaté, en regardant ce qui tourne réellement.
#[tokio::test]
async fn success_is_detected_even_without_an_update_status() {
    let o = Fake::returning(vec![status("gitea/gitea:1.25@sha256:nouvelle", None, 1)]);
    let s = state_with_gitea().await;

    let outcome = apply(&o, &s, &candidate(), 10).await.expect("mise à jour");

    assert!(outcome.is_success(), "{outcome:?}");
    assert_eq!(s.app_manifest("gitea").await.unwrap().spec.image.tag, "1.25");
}

/// Après un rollback, le service est convergé — mais sur l'ancienne image. Se fier au
/// seul « convergé » conclurait à tort au succès.
#[tokio::test]
async fn a_converged_service_on_the_old_image_is_not_a_success() {
    let o = Fake::returning(vec![status(
        "gitea/gitea:1.24@sha256:ancienne",
        Some(UpdateState::RollbackCompleted),
        1,
    )]);
    let s = state_with_gitea().await;

    let outcome = apply(&o, &s, &candidate(), 10).await.expect("mise à jour");
    assert!(matches!(outcome, UpdateOutcome::RolledBack { .. }), "{outcome:?}");
}

#[tokio::test]
async fn a_successful_update_freezes_the_new_version() {
    let o = Fake::returning(vec![status(
        "gitea/gitea:1.25@sha256:nouvelle",
        Some(UpdateState::Completed),
        1,
    )]);
    let s = state_with_gitea().await;

    let outcome = apply(&o, &s, &candidate(), 10).await.expect("mise à jour");

    assert!(outcome.is_success(), "{outcome:?}");

    // L'état reflète la nouvelle version.
    let m = s.app_manifest("gitea").await.unwrap();
    assert_eq!(m.spec.image.tag, "1.25");
    assert_eq!(m.spec.image.digest.as_deref(), Some("sha256:nouvelle"));

    // Et on a bien poussé le digest, pas le tag.
    assert_eq!(
        o.pushed.lock().unwrap()[0].1,
        "gitea/gitea:1.25@sha256:nouvelle"
    );
}

#[tokio::test]
async fn a_rolled_back_update_leaves_the_state_untouched() {
    // 🔴 Le test le plus important du module.
    //
    // Si on écrivait le nouveau digest ici, la réconciliation tenterait ensuite de
    // « corriger » le cluster vers une image dont on sait qu'elle ne démarre pas —
    // en boucle.
    let o = Fake::returning(vec![
        status("gitea/gitea:1.24@sha256:ancienne", Some(UpdateState::Updating), 1),
        status("gitea/gitea:1.24@sha256:ancienne", Some(UpdateState::RollbackStarted), 1),
        status("gitea/gitea:1.24@sha256:ancienne", Some(UpdateState::RollbackCompleted), 1),
    ]);
    let s = state_with_gitea().await;

    let outcome = apply(&o, &s, &candidate(), 30).await.expect("mise à jour");

    assert!(matches!(outcome, UpdateOutcome::RolledBack { .. }), "{outcome:?}");
    assert!(!outcome.is_success());

    let m = s.app_manifest("gitea").await.unwrap();
    assert_eq!(m.spec.image.tag, "1.24", "le tag doit rester l'ancien");
    assert_eq!(
        m.spec.image.digest.as_deref(),
        Some("sha256:ancienne"),
        "le digest doit rester l'ancien"
    );
}

#[tokio::test]
async fn the_service_never_goes_down_during_a_rollback() {
    // C'est tout l'intérêt de start-first : les anciennes tâches restent debout
    // pendant que les nouvelles échouent à démarrer.
    let o = Fake::returning(vec![
        status("gitea/gitea:1.24@sha256:ancienne", Some(UpdateState::RollbackStarted), 1),
        status("gitea/gitea:1.24@sha256:ancienne", Some(UpdateState::RollbackCompleted), 1),
    ]);
    let s = state_with_gitea().await;

    apply(&o, &s, &candidate(), 30).await.expect("mise à jour");

    // Le statut de l'app n'a pas basculé en échec : le service tourne toujours.
    let apps = s.installed_apps().await.unwrap();
    assert_eq!(apps[0].1, "running");
}

#[tokio::test]
async fn a_paused_update_needs_a_human() {
    let o = Fake::returning(vec![status(
        "gitea/gitea:1.24@sha256:ancienne",
        Some(UpdateState::Paused),
        1,
    )]);
    let s = state_with_gitea().await;

    let outcome = apply(&o, &s, &candidate(), 10).await.expect("mise à jour");
    assert_eq!(outcome, UpdateOutcome::Paused);

    // L'état reste sur l'ancienne version.
    assert_eq!(s.app_manifest("gitea").await.unwrap().spec.image.tag, "1.24");
}

#[tokio::test]
async fn an_inconclusive_update_is_never_reported_as_applied() {
    // Bascule encore en cours sur l'ANCIENNE image quand le délai expire : Swarm n'a
    // ni abouti ni annulé. On ne suppose rien.
    let o = Fake::returning(vec![status(
        "gitea/gitea:1.24@sha256:ancienne",
        Some(UpdateState::Updating),
        1,
    )]);
    let s = state_with_gitea().await;

    let outcome = apply(&o, &s, &candidate(), 3).await.expect("mise à jour");

    assert_eq!(outcome, UpdateOutcome::Inconclusive);
    assert!(!outcome.is_success());
    assert_eq!(
        s.app_manifest("gitea").await.unwrap().spec.image.tag,
        "1.24",
        "sans conclusion, l'état ne bouge pas"
    );
}

#[tokio::test]
async fn a_digest_only_update_keeps_the_tag() {
    // Cas des tags roulants : `8-alpine` republié.
    let o = Fake::returning(vec![status(
        "gitea/gitea:1.24@sha256:nouvelle",
        Some(UpdateState::Completed),
        1,
    )]);
    let s = state_with_gitea().await;

    let mut c = candidate();
    c.kind = UpdateKind::DigestOnly;

    let outcome = apply(&o, &s, &c, 10).await.expect("mise à jour");
    assert!(outcome.is_success());

    let m = s.app_manifest("gitea").await.unwrap();
    assert_eq!(m.spec.image.tag, "1.24", "le tag roulant ne change pas");
    assert_eq!(m.spec.image.digest.as_deref(), Some("sha256:nouvelle"));
}
