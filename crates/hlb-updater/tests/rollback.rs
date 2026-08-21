//! Update pipeline tests, against a scripted orchestrator.
//!
//! Rollback logic never exercises itself in real conditions before the day you
//! desperately need it, so it has to be tested deliberately.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::Mutex;

use async_trait::async_trait;
use hlb_orchestrator::{Orchestrator, ServiceSpec, ServiceStatus, UpdateState};
use hlb_state::State;
use hlb_updater::{apply, Candidate, UpdateKind, UpdateOutcome};

/// A scriptable orchestrator: it is told the sequence of states Swarm will return.
struct Fake {
    /// Successive states returned by `status`, consumed one at a time.
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
    async fn status(&self, _: &str) -> hlb_orchestrator::Result<ServiceStatus> {
        let mut s = self.script.lock().unwrap();
        if s.len() > 1 {
            Ok(s.remove(0))
        } else {
            s.first()
                .cloned()
                .ok_or(hlb_orchestrator::Error::NotFound("vide".into()))
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
        kind: UpdateKind::NewVersion {
            to_tag: "1.25".into(),
        },
        from_tag: "1.24".into(),
        from_digest: Some("sha256:ancienne".into()),
        to_digest: "sha256:nouvelle".into(),
        in_window: true,
        needs_backup: false,
    }
}

/// A service never updated has no `UpdateStatus`: success must still be established,
/// by looking at what is actually running.
#[tokio::test]
async fn success_is_detected_even_without_an_update_status() {
    let o = Fake::returning(vec![status("gitea/gitea:1.25@sha256:nouvelle", None, 1)]);
    let s = state_with_gitea().await;

    let outcome = apply(&o, &s, &candidate(), 10).await.expect("update");

    assert!(outcome.is_success(), "{outcome:?}");
    assert_eq!(
        s.app_manifest("gitea").await.unwrap().spec.image.tag,
        "1.25"
    );
}

/// After a rollback the service is converged - but on the old image. Trusting
/// "converged" alone would wrongly conclude success.
#[tokio::test]
async fn a_converged_service_on_the_old_image_is_not_a_success() {
    let o = Fake::returning(vec![status(
        "gitea/gitea:1.24@sha256:ancienne",
        Some(UpdateState::RollbackCompleted),
        1,
    )]);
    let s = state_with_gitea().await;

    let outcome = apply(&o, &s, &candidate(), 10).await.expect("update");
    assert!(
        matches!(outcome, UpdateOutcome::RolledBack { .. }),
        "{outcome:?}"
    );
}

#[tokio::test]
async fn a_successful_update_freezes_the_new_version() {
    let o = Fake::returning(vec![status(
        "gitea/gitea:1.25@sha256:nouvelle",
        Some(UpdateState::Completed),
        1,
    )]);
    let s = state_with_gitea().await;

    let outcome = apply(&o, &s, &candidate(), 10).await.expect("update");

    assert!(outcome.is_success(), "{outcome:?}");

    // The state reflects the new version.
    let m = s.app_manifest("gitea").await.unwrap();
    assert_eq!(m.spec.image.tag, "1.25");
    assert_eq!(m.spec.image.digest.as_deref(), Some("sha256:nouvelle"));

    // And the digest was pushed, not the tag.
    assert_eq!(
        o.pushed.lock().unwrap()[0].1,
        "gitea/gitea:1.25@sha256:nouvelle"
    );
}

#[tokio::test]
async fn a_rolled_back_update_leaves_the_state_untouched() {
    // 🔴 The most important test in this module.
    //
    // If the new digest were written here, reconciliation would then try to "correct"
    // the cluster towards an image known not to start - in a loop.
    let o = Fake::returning(vec![
        status(
            "gitea/gitea:1.24@sha256:ancienne",
            Some(UpdateState::Updating),
            1,
        ),
        status(
            "gitea/gitea:1.24@sha256:ancienne",
            Some(UpdateState::RollbackStarted),
            1,
        ),
        status(
            "gitea/gitea:1.24@sha256:ancienne",
            Some(UpdateState::RollbackCompleted),
            1,
        ),
    ]);
    let s = state_with_gitea().await;

    let outcome = apply(&o, &s, &candidate(), 30).await.expect("update");

    assert!(
        matches!(outcome, UpdateOutcome::RolledBack { .. }),
        "{outcome:?}"
    );
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
    // This is the whole point of start-first: the old tasks stay up while the new ones
    // fail to start.
    let o = Fake::returning(vec![
        status(
            "gitea/gitea:1.24@sha256:ancienne",
            Some(UpdateState::RollbackStarted),
            1,
        ),
        status(
            "gitea/gitea:1.24@sha256:ancienne",
            Some(UpdateState::RollbackCompleted),
            1,
        ),
    ]);
    let s = state_with_gitea().await;

    apply(&o, &s, &candidate(), 30).await.expect("update");

    // The app's status did not flip to failed: the service is still running.
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

    let outcome = apply(&o, &s, &candidate(), 10).await.expect("update");
    assert_eq!(outcome, UpdateOutcome::Paused);

    // The state stays on the old version.
    assert_eq!(
        s.app_manifest("gitea").await.unwrap().spec.image.tag,
        "1.24"
    );
}

#[tokio::test]
async fn an_inconclusive_update_is_never_reported_as_applied() {
    // The switch is still in progress on the OLD image when the deadline expires:
    // Swarm has neither completed nor rolled back. Nothing is assumed.
    let o = Fake::returning(vec![status(
        "gitea/gitea:1.24@sha256:ancienne",
        Some(UpdateState::Updating),
        1,
    )]);
    let s = state_with_gitea().await;

    let outcome = apply(&o, &s, &candidate(), 3).await.expect("update");

    assert_eq!(outcome, UpdateOutcome::Inconclusive);
    assert!(!outcome.is_success());
    assert_eq!(
        s.app_manifest("gitea").await.unwrap().spec.image.tag,
        "1.24",
        "with no conclusion, the state does not move"
    );
}

#[tokio::test]
async fn a_digest_only_update_keeps_the_tag() {
    // The rolling tag case: `8-alpine` republished.
    let o = Fake::returning(vec![status(
        "gitea/gitea:1.24@sha256:nouvelle",
        Some(UpdateState::Completed),
        1,
    )]);
    let s = state_with_gitea().await;

    let mut c = candidate();
    c.kind = UpdateKind::DigestOnly;

    let outcome = apply(&o, &s, &c, 10).await.expect("update");
    assert!(outcome.is_success());

    let m = s.app_manifest("gitea").await.unwrap();
    assert_eq!(m.spec.image.tag, "1.24", "le tag roulant ne change pas");
    assert_eq!(m.spec.image.digest.as_deref(), Some("sha256:nouvelle"));
}
