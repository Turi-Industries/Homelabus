//! Le pipeline de mise à jour (§7 du plan).
//!
//! ```text
//! 1. Veille        nouveau digest ? nouvelle version ?
//! 2. Politique     le canal autorise-t-il ce saut ?
//! 3. Fenêtre       on est dans la fenêtre de maintenance ?
//! 4. Sauvegarde    🔴 AVANT toute chose
//! 5. Déploiement   start-first, parallelism 1
//! 6. Vérification  healthcheck
//! 7a. OK           on fige le nouveau digest
//! 7b. KO           rollback automatique par Swarm
//! ```
//!
//! 🔴 **La règle la plus importante de ce module** : si le manifest promet une
//! sauvegarde préalable et qu'aucun fournisseur de sauvegarde n'est branché, la mise à
//! jour est **refusée**. Une migration de schéma n'est pas réversible par un rollback
//! d'image — prétendre avoir sauvegardé serait le pire mensonge possible.

pub mod apply;
pub mod window;

pub use apply::{apply, UpdateOutcome};
pub use window::MaintenanceWindow;

use hlb_registry::{best_upgrade, ImageRef, RegistryClient};
use hlb_state::State;
use hlb_types::UpdateChannel;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    State(#[from] hlb_state::Error),

    #[error(transparent)]
    Registry(#[from] hlb_registry::Error),

    #[error(transparent)]
    Window(#[from] window::ParseError),

    #[error(transparent)]
    Orchestrator(#[from] hlb_orchestrator::Error),

    #[error("« {app} » exige une sauvegarde avant mise à jour, mais aucun \
             fournisseur de sauvegarde n'est configuré — mise à jour refusée")]
    BackupRequired { app: String },
}

pub type Result<T> = std::result::Result<T, Error>;

/// Ce qui change entre la version déployée et celle qui est disponible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateKind {
    /// Même tag, digest différent : l'éditeur a republié (cas des tags roulants).
    DigestOnly,
    /// Nouvelle version, autorisée par le canal.
    NewVersion { to_tag: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub app: String,
    pub kind: UpdateKind,
    pub from_tag: String,
    pub from_digest: Option<String>,
    pub to_digest: String,
    /// La mise à jour est-elle applicable **maintenant** ?
    pub in_window: bool,
    /// Le manifest exige-t-il une sauvegarde préalable ?
    pub needs_backup: bool,
}

impl Candidate {
    pub fn describe(&self) -> String {
        match &self.kind {
            UpdateKind::DigestOnly => {
                format!("{} : {} republié", self.app, self.from_tag)
            }
            UpdateKind::NewVersion { to_tag } => {
                format!("{} : {} → {to_tag}", self.app, self.from_tag)
            }
        }
    }
}

/// Interroge les registres pour toutes les apps installées.
///
/// Purement en lecture : rien n'est modifié, rien n'est déployé.
pub async fn check<T: chrono::Datelike + chrono::Timelike>(
    state: &State,
    registry: &RegistryClient,
    now: &T,
) -> Result<Vec<Candidate>> {
    let mut out = Vec::new();

    for (app, status) in state.installed_apps().await? {
        // On ne propose rien pour une app en échec ou en cours d'installation :
        // il y a un problème plus urgent à régler.
        if status != "running" && status != "partial" {
            continue;
        }

        let m = state.app_manifest(&app).await?;
        let channel = m.spec.update.channel;

        let image = ImageRef::parse(&format!("{}:{}", m.spec.image.repo, m.spec.image.tag));

        // Le canal `pin` ne coupe pas la veille : on veut être *informé* d'une
        // nouveauté sur Vaultwarden, simplement pas l'appliquer tout seul.
        let candidate_tag = if channel == UpdateChannel::Pin {
            None
        } else {
            let tags = registry.list_tags(&image).await?;
            best_upgrade(&m.spec.image.tag, &tags, channel)
        };

        let (kind, target) = match candidate_tag {
            Some(t) => {
                let target = ImageRef::parse(&format!("{}:{t}", m.spec.image.repo));
                (UpdateKind::NewVersion { to_tag: t }, target)
            }
            None => (UpdateKind::DigestOnly, image.clone()),
        };

        let to_digest = registry.resolve_digest(&target).await?;

        // Rien de neuf : même tag, même digest.
        if kind == UpdateKind::DigestOnly && m.spec.image.digest.as_deref() == Some(&to_digest) {
            continue;
        }

        let in_window = match &m.spec.update.window {
            Some(w) => MaintenanceWindow::parse(w)?.is_open_at(now),
            // Sans fenêtre déclarée, la mise à jour est applicable à tout moment.
            None => true,
        };

        out.push(Candidate {
            app: app.clone(),
            kind,
            from_tag: m.spec.image.tag.clone(),
            from_digest: m.spec.image.digest.clone(),
            to_digest,
            in_window,
            needs_backup: m.spec.update.backup_before,
        });
    }

    Ok(out)
}

/// Ce que peut fournir un moteur de sauvegarde. Non implémenté pour l'instant :
/// le trait existe pour que le refus du §7 soit explicite, pas contourné.
#[async_trait::async_trait]
pub trait BackupProvider: Send + Sync {
    async fn snapshot(&self, app: &str) -> std::result::Result<String, String>;
}

/// Vérifie qu'une mise à jour a le droit d'être appliquée maintenant.
///
/// Séparé de l'exécution pour être testable sans orchestrateur.
pub fn authorize(
    candidate: &Candidate,
    backup: Option<&dyn BackupProvider>,
    force_window: bool,
) -> Result<()> {
    if candidate.needs_backup && backup.is_none() {
        return Err(Error::BackupRequired {
            app: candidate.app.clone(),
        });
    }
    if !candidate.in_window && !force_window {
        // Pas une erreur : simplement pas maintenant. L'appelant filtre là-dessus.
        tracing::debug!(app = %candidate.app, "hors fenêtre de maintenance");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(needs_backup: bool) -> Candidate {
        Candidate {
            app: "gitea".into(),
            kind: UpdateKind::NewVersion { to_tag: "1.25".into() },
            from_tag: "1.24".into(),
            from_digest: Some("sha256:old".into()),
            to_digest: "sha256:new".into(),
            in_window: true,
            needs_backup,
        }
    }

    #[test]
    fn an_update_requiring_backup_is_refused_without_a_provider() {
        // 🔴 Le cœur du §7 : une migration de schéma n'est pas réversible par un
        // rollback d'image. Sans sauvegarde, on ne joue pas.
        let err = authorize(&candidate(true), None, false).unwrap_err();
        assert!(matches!(err, Error::BackupRequired { .. }), "{err}");
    }

    #[test]
    fn an_update_not_requiring_backup_passes() {
        assert!(authorize(&candidate(false), None, false).is_ok());
    }

    #[test]
    fn the_description_says_what_changes() {
        assert_eq!(candidate(false).describe(), "gitea : 1.24 → 1.25");

        let mut c = candidate(false);
        c.kind = UpdateKind::DigestOnly;
        assert_eq!(c.describe(), "gitea : 1.24 republié");
    }
}
