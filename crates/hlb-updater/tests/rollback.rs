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

/// One reading of Swarm: the service, and the image its live tasks run.
type Step = (ServiceStatus, String);

/// A scriptable orchestrator: it is told the sequence of states Swarm will return.
struct Fake {
    /// Successive states returned by `status`, consumed one at a time.
    script: Mutex<Vec<Step>>,
    /// The reading `tasks` answers from: the last one `status` returned.
    current: Mutex<Option<Step>>,
    pushed: Mutex<Vec<(String, String)>>,
}

impl Fake {
    fn returning(states: Vec<Step>) -> Self {
        Self {
            script: Mutex::new(states),
            current: Mutex::new(None),
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
    async fn status(&self, _: &str) -> hlb_orchestrator::Result<ServiceStatus> {
        let mut s = self.script.lock().unwrap();
        let step = if s.len() > 1 {
            s.remove(0)
        } else {
            s.first()
                .cloned()
                .ok_or(hlb_orchestrator::Error::NotFound("empty".into()))?
        };
        *self.current.lock().unwrap() = Some(step.clone());
        Ok(step.0)
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
        let Some((st, image)) = self.current.lock().unwrap().clone() else {
            return Ok(Vec::new());
        };
        Ok((0..st.running_replicas)
            .map(|i| hlb_orchestrator::TaskInfo {
                id: format!("t{i}"),
                service: st.name.clone(),
                slot: Some(i as u64 + 1),
                node_id: None,
                desired_state: "running".into(),
                state: "running".into(),
                image: image.clone(),
                message: None,
                err: None,
                updated_at: None,
            })
            .collect())
    }

    async fn logs(
        &self,
        _: &str,
        _: u32,
    ) -> hlb_orchestrator::Result<Vec<hlb_orchestrator::LogLine>> {
        Ok(Vec::new())
    }
}

/// A reading where the live tasks run what the spec names.
fn status(image: &str, state: Option<UpdateState>, running: usize) -> Step {
    during(image, image, state, running)
}

/// A reading where the spec names `spec` and the live tasks still run `running_image`.
fn during(spec: &str, running_image: &str, state: Option<UpdateState>, running: usize) -> Step {
    (
        ServiceStatus {
            name: "gitea".into(),
            id: "id".into(),
            desired_replicas: 1,
            running_replicas: running,
            image: spec.into(),
            update_state: state,
        },
        running_image.into(),
    )
}

const MANIFEST: &str = r#"
apiVersion: hlb/v1
kind: App
metadata: { name: gitea }
spec:
  image: { repo: gitea/gitea, tag: "1.24", digest: "sha256:previous" }
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
        from_digest: Some("sha256:previous".into()),
        to_digest: "sha256:update".into(),
        in_window: true,
        needs_backup: false,
        maturity: hlb_updater::Maturity::Mature,
        companions: Vec::new(),
    }
}

/// A service never updated has no `UpdateStatus`: success must still be established,
/// by looking at what is actually running.
#[tokio::test]
async fn success_is_detected_even_without_an_update_status() {
    let o = Fake::returning(vec![status("gitea/gitea:1.25@sha256:update", None, 1)]);
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
        "gitea/gitea:1.24@sha256:previous",
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

/// 🔴 Found on the lab, moving PocketID from v1 to v2: the spec names the new digest
/// at once, the old task is still the one running, and "converged on the new image"
/// read the two together. Swarm then rolled the update back — after `hlb` had said
/// "applied" and frozen v2 into the state.
#[tokio::test]
async fn the_spec_naming_the_new_digest_is_not_the_new_digest_running() {
    let o = Fake::returning(vec![
        during(
            "gitea/gitea:1.25@sha256:update",
            "gitea/gitea:1.24@sha256:previous",
            Some(UpdateState::Completed),
            1,
        ),
        during(
            "gitea/gitea:1.25@sha256:update",
            "gitea/gitea:1.24@sha256:previous",
            Some(UpdateState::Updating),
            1,
        ),
        status(
            "gitea/gitea:1.24@sha256:previous",
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
    assert_eq!(
        s.app_manifest("gitea")
            .await
            .unwrap()
            .spec
            .image
            .digest
            .as_deref(),
        Some("sha256:previous")
    );
}

/// The new task runs but Swarm is still watching it: it can yet fail and roll back.
#[tokio::test]
async fn a_new_task_swarm_is_still_watching_is_not_applied_yet() {
    let o = Fake::returning(vec![during(
        "gitea/gitea:1.25@sha256:update",
        "gitea/gitea:1.25@sha256:update",
        Some(UpdateState::Updating),
        1,
    )]);
    let s = state_with_gitea().await;

    let outcome = apply(&o, &s, &candidate(), 3).await.expect("update");
    assert_eq!(outcome, UpdateOutcome::Inconclusive);
}

/// A rollback the old image cannot finish leaves nothing running: a human, now.
#[tokio::test]
async fn a_rollback_that_cannot_finish_needs_a_human() {
    let o = Fake::returning(vec![status(
        "gitea/gitea:1.24@sha256:previous",
        Some(UpdateState::RollbackPaused),
        0,
    )]);
    let s = state_with_gitea().await;

    let outcome = apply(&o, &s, &candidate(), 10).await.expect("update");
    assert_eq!(outcome, UpdateOutcome::Paused);
}

#[tokio::test]
async fn a_successful_update_freezes_the_new_version() {
    let o = Fake::returning(vec![status(
        "gitea/gitea:1.25@sha256:update",
        Some(UpdateState::Completed),
        1,
    )]);
    let s = state_with_gitea().await;

    let outcome = apply(&o, &s, &candidate(), 10).await.expect("update");

    assert!(outcome.is_success(), "{outcome:?}");

    // The state reflects the new version.
    let m = s.app_manifest("gitea").await.unwrap();
    assert_eq!(m.spec.image.tag, "1.25");
    assert_eq!(m.spec.image.digest.as_deref(), Some("sha256:update"));

    // And the digest was pushed, not the tag.
    assert_eq!(
        o.pushed.lock().unwrap()[0].1,
        "gitea/gitea:1.25@sha256:update"
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
            "gitea/gitea:1.24@sha256:previous",
            Some(UpdateState::Updating),
            1,
        ),
        status(
            "gitea/gitea:1.24@sha256:previous",
            Some(UpdateState::RollbackStarted),
            1,
        ),
        status(
            "gitea/gitea:1.24@sha256:previous",
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
    assert_eq!(m.spec.image.tag, "1.24", "the tag must stay the old one");
    assert_eq!(
        m.spec.image.digest.as_deref(),
        Some("sha256:previous"),
        "the digest must stay the old one"
    );
}

#[tokio::test]
async fn the_service_never_goes_down_during_a_rollback() {
    // This is the whole point of start-first: the old tasks stay up while the new ones
    // fail to start.
    let o = Fake::returning(vec![
        status(
            "gitea/gitea:1.24@sha256:previous",
            Some(UpdateState::RollbackStarted),
            1,
        ),
        status(
            "gitea/gitea:1.24@sha256:previous",
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
        "gitea/gitea:1.24@sha256:previous",
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
        "gitea/gitea:1.24@sha256:previous",
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
        "gitea/gitea:1.24@sha256:update",
        Some(UpdateState::Completed),
        1,
    )]);
    let s = state_with_gitea().await;

    let mut c = candidate();
    c.kind = UpdateKind::DigestOnly;

    let outcome = apply(&o, &s, &c, 10).await.expect("update");
    assert!(outcome.is_success());

    let m = s.app_manifest("gitea").await.unwrap();
    assert_eq!(m.spec.image.tag, "1.24", "the rolling tag does not change");
    assert_eq!(m.spec.image.digest.as_deref(), Some("sha256:update"));
}

const WITH_COMPANION: &str = r#"
apiVersion: hlb/v1
kind: App
metadata: { name: gitea }
spec:
  image: { repo: gitea/gitea, tag: "1.24", digest: "sha256:previous" }
  update: { channel: minor, backupBefore: false }
  companions:
    - name: ml
      image: { repo: acme/ml, tag: "1.0", digest: "sha256:ml-previous" }
"#;

fn with_companion() -> Candidate {
    let mut c = candidate();
    c.companions.push(hlb_updater::CompanionMove {
        name: "ml".into(),
        service: "gitea-ml".into(),
        to: hlb_types::Image {
            repo: "acme/ml".into(),
            tag: "1.1".into(),
            digest: Some("sha256:ml-update".into()),
            built_here: false,
        },
        maturity: hlb_updater::Maturity::Mature,
    });
    c
}

/// The companions move before their app, as they were installed, and each is frozen
/// into the state once it runs.
#[tokio::test]
async fn companions_switch_before_their_app() {
    let s = State::in_memory().await.unwrap();
    let m: hlb_types::Manifest = serde_yaml_ng::from_str(WITH_COMPANION).unwrap();
    s.upsert_app("gitea", &m, None).await.unwrap();
    let o = Fake::returning(vec![
        status("acme/ml:1.1@sha256:ml-update", None, 1),
        status("gitea/gitea:1.25@sha256:update", None, 1),
    ]);

    let out = apply(&o, &s, &with_companion(), 5).await.unwrap();
    assert!(out.is_success(), "{out:?}");
    let pushed: Vec<String> = o
        .pushed
        .lock()
        .unwrap()
        .iter()
        .map(|p| p.0.clone())
        .collect();
    assert_eq!(pushed, ["gitea-ml", "gitea"]);
    let m = s.app_manifest("gitea").await.unwrap();
    assert_eq!(m.spec.companions[0].image.tag, "1.1");
    assert_eq!(m.spec.image.tag, "1.25");
}

/// A companion that does not come up stops the update before its app is touched.
#[tokio::test]
async fn a_companion_that_does_not_start_leaves_its_app_alone() {
    let s = State::in_memory().await.unwrap();
    let m: hlb_types::Manifest = serde_yaml_ng::from_str(WITH_COMPANION).unwrap();
    s.upsert_app("gitea", &m, None).await.unwrap();
    let o = Fake::returning(vec![status(
        "acme/ml:1.0@sha256:ml-previous",
        Some(UpdateState::RollbackCompleted),
        1,
    )]);

    let out = apply(&o, &s, &with_companion(), 5).await.unwrap();
    assert!(matches!(out, UpdateOutcome::RolledBack { .. }), "{out:?}");
    assert_eq!(o.pushed.lock().unwrap().len(), 1, "the app was switched");
    let m = s.app_manifest("gitea").await.unwrap();
    assert_eq!(m.spec.companions[0].image.tag, "1.0");
    assert_eq!(m.spec.image.digest.as_deref(), Some("sha256:previous"));
}
