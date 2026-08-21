//! Application d'une mise à jour, avec surveillance du rollback (§7).
//!
//! La politique Swarm (`start-first` + `failure_action: rollback`) est codée en dur
//! dans `hlb-orchestrator` : le service ne tombe jamais pendant la bascule, et Swarm
//! revient tout seul si les nouvelles tâches ne démarrent pas.
//!
//! Le rôle de ce module est donc de **surveiller** cette bascule, pas de la piloter :
//! on pousse la nouvelle image, on regarde ce que Swarm en fait, et on rapporte
//! honnêtement le résultat — y compris quand il a annulé.

use std::time::Duration;

use hlb_orchestrator::{Orchestrator, UpdateState};
use hlb_state::State;

use crate::{Candidate, Error, Result, UpdateKind};

/// Issue d'une tentative de mise à jour.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateOutcome {
    /// La nouvelle version tourne et est saine.
    Applied { digest: String },
    /// Swarm a détecté l'échec et est revenu à l'ancienne version, sans coupure.
    RolledBack { reason: String },
    /// Swarm a mis la bascule en pause : intervention humaine nécessaire.
    Paused,
    /// Le délai est écoulé sans conclusion nette.
    Inconclusive,
}

impl UpdateOutcome {
    pub fn is_success(&self) -> bool {
        matches!(self, Self::Applied { .. })
    }
}

/// Applique une mise à jour et attend son issue.
///
/// `timeout_secs` borne l'observation : au-delà, on rapporte `Inconclusive` plutôt que
/// d'attendre indéfiniment. Un état non conclu n'est **jamais** rapporté comme réussi.
pub async fn apply<O: Orchestrator>(
    orch: &O,
    state: &State,
    candidate: &Candidate,
    timeout_secs: u64,
) -> Result<UpdateOutcome> {
    let app = &candidate.app;

    // On déploie toujours par digest : c'est lui qui détermine ce qui tourne (§7).
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
            // On ne fige la nouvelle version dans l'état qu'une fois qu'elle tourne.
            let mut m = state.app_manifest(app).await?;
            m.spec.image.tag = target_tag;
            m.spec.image.digest = Some(digest.clone());
            let domain = state.app_domain(app).await?;
            state.upsert_app(app, &m, domain.as_deref()).await?;
            state.set_app_status(app, "running").await?;
        }
        UpdateOutcome::RolledBack { .. } | UpdateOutcome::Paused => {
            // 🔴 L'état n'est PAS modifié : la version déployée reste l'ancienne.
            // Écrire le nouveau digest ici ferait croire à une mise à jour réussie,
            // et la réconciliation tenterait ensuite de « corriger » vers une image
            // dont on sait qu'elle ne démarre pas.
            tracing::warn!(
                app,
                "mise à jour annulée, l'état reste sur l'ancienne version"
            );
        }
        UpdateOutcome::Inconclusive => {
            tracing::warn!(app, "issue indéterminée dans le délai imparti");
        }
    }

    Ok(outcome)
}

/// Observe la bascule jusqu'à conclusion ou expiration.
///
/// ⚠️ On ne peut pas se fier au seul `UpdateStatus` de Swarm : un service qui n'a
/// **jamais** été mis à jour n'en a pas du tout (`nil`), et une bascule sans
/// changement effectif n'en produit pas non plus. On vérifie donc d'abord la
/// **réalité** — le service tourne-t-il le digest visé ? — et on ne consulte
/// `UpdateStatus` que pour détecter les échecs.
async fn watch<O: Orchestrator>(
    orch: &O,
    app: &str,
    target_digest: &str,
    timeout_secs: u64,
) -> Result<UpdateOutcome> {
    let deadline = std::time::Instant::now() + Duration::from_secs(timeout_secs);

    while std::time::Instant::now() < deadline {
        let st = orch.status(app).await.map_err(Error::from)?;

        // Les échecs se lisent dans UpdateStatus, et priment : un service peut être
        // converge *sur l'ancienne image* après un rollback.
        match st.update_state {
            Some(UpdateState::RollbackCompleted) => {
                return Ok(UpdateOutcome::RolledBack {
                    reason: "les nouvelles tâches n'ont pas démarré".into(),
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

        // Le succès se constate, il ne se déduit pas d'un champ de statut.
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
        // 🔴 Le plus important : un résultat indéterminé n'est pas un succès.
        assert!(!UpdateOutcome::Inconclusive.is_success());
    }
}
