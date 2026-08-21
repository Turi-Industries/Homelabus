//! Applying an update, and watching the rollback.
//!
//! The Swarm policy (`start-first` + `failure_action: rollback`) is hard-coded in
//! `hlb-orchestrator`: the service never goes down during the switch, and Swarm rolls
//! back on its own if the new tasks do not start.
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
    /// La nouvelle version tourne et est saine.
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
pub async fn apply<O: Orchestrator>(
    orch: &O,
    state: &State,
    candidate: &Candidate,
    timeout_secs: u64,
) -> Result<UpdateOutcome> {
    let app = &candidate.app;

    // Deployment is always by digest: that is what determines what runs.
    let m = state.app_manifest(app).await?;
    let target_tag = match &candidate.kind {
        UpdateKind::NewVersion { to_tag } => to_tag.clone(),
        UpdateKind::DigestOnly => m.spec.image.tag.clone(),
    };
    let reference = format!(
        "{}:{}@{}",
        m.spec.image.repo, target_tag, candidate.to_digest
    );

    tracing::info!(app, %reference, "bascule");
    orch.update_image(app, &reference)
        .await
        .map_err(Error::from)?;

    let outcome = watch(orch, app, &candidate.to_digest, timeout_secs).await?;

    match &outcome {
        UpdateOutcome::Applied { digest } => {
            // The new version is only frozen into the state once it is running.
            let mut m = state.app_manifest(app).await?;
            m.spec.image.tag = target_tag;
            m.spec.image.digest = Some(digest.clone());
            let domain = state.app_domain(app).await?;
            state.upsert_app(app, &m, domain.as_deref()).await?;
            state.set_app_status(app, "running").await?;
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

/// Watches the switch until it concludes or times out.
///
/// ⚠️ Swarm's `UpdateStatus` alone cannot be trusted: a service that has **never** been
/// updated has none at all (`nil`), and a switch with no effective change produces none
/// either. So **reality** is checked first - is the service running the target digest? -
/// and `UpdateStatus` is only consulted to detect failures.
async fn watch<O: Orchestrator>(
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
                // On laisse le rollback se terminer avant de conclure.
                tracing::info!(app, "rollback en cours");
                tokio::time::sleep(Duration::from_secs(2)).await;
                continue;
            }
            Some(UpdateState::Paused) => return Ok(UpdateOutcome::Paused),
            _ => {}
        }

        // Success is observed, not inferred from a status field.
        if st.is_converged() && st.image.contains(target_digest) {
            return Ok(UpdateOutcome::Applied {
                digest: target_digest.to_string(),
            });
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
}
