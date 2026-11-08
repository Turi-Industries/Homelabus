//! Applying an update, and watching the rollback.
//!
//! The Swarm policy (`failure_action: rollback`, `start-first` unless the service keeps
//! its data on its node) is hard-coded in `hlb-orchestrator`: Swarm rolls back on its
//! own if the new tasks do not start.
//!
//! This module's job is therefore to **watch** that switch, not to drive it: push the
//! new image, see what Swarm does with it, and report the result honestly - including
//! when it rolled back.

use std::time::Duration;

use hlb_orchestrator::{Orchestrator, UpdateState};
use hlb_state::State;

use crate::{Candidate, Error, Result, UpdateKind};

/// The outcome of an update attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateOutcome {
    /// The new version is running and healthy.
    Applied { digest: String },
    /// Swarm detected the failure and returned to the old version, with no downtime.
    RolledBack { reason: String },
    /// Swarm paused the switch: human intervention needed.
    Paused,
    /// The deadline passed with no clear conclusion.
    Inconclusive,
}

impl UpdateOutcome {
    pub fn is_success(&self) -> bool {
        matches!(self, Self::Applied { .. })
    }
}

/// Applies an update and waits for its outcome.
///
/// `timeout_secs` bounds the observation: beyond it, `Inconclusive` is reported rather
/// than waiting forever. An unresolved state is **never** reported as successful.
pub async fn apply<O: Orchestrator + ?Sized>(
    orch: &O,
    state: &State,
    candidate: &Candidate,
    timeout_secs: u64,
) -> Result<UpdateOutcome> {
    let app = &candidate.app;

    // The companions first, the order they were installed in. One that does not come up
    // stops the update there: the app is not switched beside it.
    for c in &candidate.companions {
        let Some(digest) = c.to.digest.as_deref() else {
            continue;
        };
        tracing::info!(app, companion = %c.name, image = %c.to.reference(), "switching");
        orch.update_image(&c.service, &c.to.reference())
            .await
            .map_err(Error::from)?;
        let outcome = watch(orch, &c.service, digest, timeout_secs).await?;
        if !outcome.is_success() {
            tracing::warn!(app, companion = %c.name, "companion not switched, the app stays");
            return Ok(outcome);
        }
        // Frozen at once: the state says what runs, the app's switch still to come.
        let mut m = state.app_manifest(app).await?;
        if let Some(frozen) = m.spec.companions.iter_mut().find(|f| f.name == c.name) {
            frozen.image = c.to.clone();
        }
        let domain = state.app_domain(app).await?;
        state.upsert_app(app, &m, domain.as_deref()).await?;
    }

    // Deployment is always by digest: that is what determines what runs.
    let m = state.app_manifest(app).await?;
    let (target_repo, target_tag) = match &candidate.kind {
        UpdateKind::NewVersion { to_tag } => (m.spec.image.repo.clone(), to_tag.clone()),
        UpdateKind::Catalog { repo, tag } => (repo.clone(), tag.clone()),
        UpdateKind::DigestOnly => (m.spec.image.repo.clone(), m.spec.image.tag.clone()),
        UpdateKind::Companions => {
            return Ok(UpdateOutcome::Applied {
                digest: candidate.to_digest.clone(),
            })
        }
    };
    let reference = format!("{target_repo}:{target_tag}@{}", candidate.to_digest);

    tracing::info!(app, %reference, "switching");
    orch.update_image(app, &reference)
        .await
        .map_err(Error::from)?;

    let outcome = watch(orch, app, &candidate.to_digest, timeout_secs).await?;

    match &outcome {
        UpdateOutcome::Applied { digest } => {
            // The new version is only frozen into the state once it is running.
            let mut m = state.app_manifest(app).await?;
            m.spec.image.repo = target_repo;
            m.spec.image.tag = target_tag;
            m.spec.image.digest = Some(digest.clone());
            let domain = state.app_domain(app).await?;
            state.upsert_app(app, &m, domain.as_deref()).await?;
            if let Some(status) = status_after_update(state, app).await? {
                state.set_app_status(app, status).await?;
            }
        }
        UpdateOutcome::RolledBack { .. } | UpdateOutcome::Paused => {
            // 🔴 The state is NOT modified: the deployed version stays the old one.
            // Writing the new digest here would suggest a successful update, and
            // reconciliation would then try to "correct" towards an image known not to
            // start.
            tracing::warn!(
                app,
                "update rolled back, the state stays on the old version"
            );
        }
        UpdateOutcome::Inconclusive => {
            tracing::warn!(app, "outcome undetermined within the deadline");
        }
    }

    Ok(outcome)
}

/// What an app's status becomes once its new image runs — `None`: it stays as it is.
///
/// 🔴 Not `running` whatever came before: a `partial` app has actions recorded as
/// unimplemented, and an update moving its image does none of them. Set `running`, it
/// looked whole — and its inbox line saying what was missing went away. A plan that
/// failed is not repaired by an image either.
async fn status_after_update(state: &State, app: &str) -> Result<Option<&'static str>> {
    use hlb_state::ActionStatus;
    let journal = state.plan_actions(app).await?;
    if journal.iter().any(|a| a.status == ActionStatus::Failed) {
        return Ok(None);
    }
    Ok(Some(
        if journal
            .iter()
            .any(|a| a.status == ActionStatus::Unimplemented)
        {
            "partial"
        } else {
            "running"
        },
    ))
}

/// Watches the switch until it concludes or times out.
///
/// ⚠️ Swarm's `UpdateStatus` alone cannot be trusted: a service that has **never** been
/// updated has none at all (`nil`), and a switch with no effective change produces none
/// either. So **reality** is checked first - is the service running the target digest? -
/// and `UpdateStatus` is only consulted to detect failures.
async fn watch<O: Orchestrator + ?Sized>(
    orch: &O,
    app: &str,
    target_digest: &str,
    timeout_secs: u64,
) -> Result<UpdateOutcome> {
    let deadline = std::time::Instant::now() + Duration::from_secs(timeout_secs);

    while std::time::Instant::now() < deadline {
        let st = orch.status(app).await.map_err(Error::from)?;

        // Failures are read from UpdateStatus, and they win: a service can be
        // converged *on the old image* after a rollback.
        match st.update_state {
            Some(UpdateState::RollbackCompleted) => {
                return Ok(UpdateOutcome::RolledBack {
                    reason: "the new tasks did not start".into(),
                });
            }
            Some(UpdateState::RollbackStarted) => {
                // Let the rollback finish before concluding.
                tracing::info!(app, "rollback in progress");
                tokio::time::sleep(Duration::from_secs(2)).await;
                continue;
            }
            // A rollback that could not finish: the old image would not start either —
            // PocketID 1.16 refusing the schema 2.18 had migrated. Nobody is serving.
            Some(UpdateState::Paused | UpdateState::RollbackPaused) => {
                return Ok(UpdateOutcome::Paused)
            }
            _ => {}
        }

        // Success is observed, not inferred from a status field — nor from the SPEC,
        // which names the new digest the moment the update is accepted. 🔴 On a
        // `stop-first` service the old task is still running then: "1/1 on the new
        // digest" read the spec and the old task together, and an update Swarm went on
        // to roll back was reported applied and frozen into the state. The tasks
        // running are what is counted, once Swarm has finished watching them.
        let finished = matches!(st.update_state, None | Some(UpdateState::Completed));
        if finished && st.is_converged() {
            let on_target = orch
                .tasks(Some(app))
                .await
                .map_err(Error::from)?
                .iter()
                .filter(|t| t.is_alive() && t.image.contains(target_digest))
                .count();
            if on_target as u64 >= st.desired_replicas {
                return Ok(UpdateOutcome::Applied {
                    digest: target_digest.to_string(),
                });
            }
        }

        tokio::time::sleep(Duration::from_secs(2)).await;
    }

    Ok(UpdateOutcome::Inconclusive)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_applied_counts_as_success() {
        assert!(UpdateOutcome::Applied { digest: "x".into() }.is_success());
        assert!(!UpdateOutcome::RolledBack { reason: "y".into() }.is_success());
        assert!(!UpdateOutcome::Paused.is_success());
        // 🔴 The most important part: an undetermined result is not a success.
        assert!(!UpdateOutcome::Inconclusive.is_success());
    }

    #[tokio::test]
    async fn an_update_keeps_a_partial_app_partial() {
        let s = State::in_memory().await.expect("state");
        let m: hlb_types::Manifest = serde_yaml_ng::from_str(
            "apiVersion: hlb/v1\nkind: App\nmetadata: { name: gitea }\nspec:\n  image: { repo: gitea/gitea, tag: \"1\" }\n",
        )
        .expect("manifest");
        s.upsert_app("gitea", &m, None).await.expect("app");
        s.record_plan(
            "gitea",
            &[
                ("DeployService".into(), "deploy gitea".into()),
                ("CreateOidcClient".into(), "client".into()),
            ],
        )
        .await
        .expect("plan");
        s.set_action_status("gitea", 0, hlb_state::ActionStatus::Done, None)
            .await
            .expect("done");
        s.set_action_status("gitea", 1, hlb_state::ActionStatus::Unimplemented, None)
            .await
            .expect("unimplemented");
        assert_eq!(
            status_after_update(&s, "gitea").await.expect("read"),
            Some("partial")
        );
        s.set_action_status("gitea", 1, hlb_state::ActionStatus::Failed, Some("x"))
            .await
            .expect("failed");
        assert_eq!(status_after_update(&s, "gitea").await.expect("read"), None);
        s.set_action_status("gitea", 1, hlb_state::ActionStatus::Done, None)
            .await
            .expect("done");
        assert_eq!(
            status_after_update(&s, "gitea").await.expect("read"),
            Some("running")
        );
    }
}
