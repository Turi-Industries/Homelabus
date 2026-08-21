//! The update pipeline.
//!
//! ```text
//! 1. Watch        new digest? new version?
//! 2. Policy       does the channel allow this jump?
//! 3. Window       are we inside the maintenance window?
//! 4. Backup       🔴 BEFORE anything else
//! 5. Deploy       start-first, parallelism 1
//! 6. Verify       healthcheck
//! 7a. OK          freeze the new digest
//! 7b. KO          automatic rollback by Swarm
//! ```
//!
//! 🔴 **This module's most important rule**: if the manifest promises a prior backup
//! and no backup provider is wired in, the update is **refused**. A schema migration is
//! not reversible by an image rollback - claiming to have backed up would be the worst
//! possible lie.

pub mod apply;
pub mod scan;
pub mod window;

pub use apply::{apply, UpdateOutcome};
pub use scan::{audit, Report as ScanReport, Verdict};
pub use window::MaintenanceWindow;

use hlb_registry::{best_upgrade, ImageRef, RegistryClient};
use hlb_state::State;
use hlb_types::UpdateChannel;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("analyse de l'image : {0}")]
    Scan(String),

    #[error(transparent)]
    State(#[from] hlb_state::Error),

    #[error(transparent)]
    Registry(#[from] hlb_registry::Error),

    #[error(transparent)]
    Window(#[from] window::ParseError),

    #[error(transparent)]
    Orchestrator(#[from] hlb_orchestrator::Error),

    #[error(
        "\"{app}\" requires a backup before updating, but no \
             backup provider is configured - update refused"
    )]
    BackupRequired { app: String },
}

pub type Result<T> = std::result::Result<T, Error>;

/// What differs between the deployed version and the available one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateKind {
    /// Same tag, different digest: the publisher republished (rolling tags).
    DigestOnly,
    /// A new version, allowed by the channel.
    NewVersion { to_tag: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub app: String,
    pub kind: UpdateKind,
    pub from_tag: String,
    pub from_digest: Option<String>,
    pub to_digest: String,
    /// Can the update be applied **now**?
    pub in_window: bool,
    /// Does the manifest require a prior backup?
    pub needs_backup: bool,
}

impl Candidate {
    pub fn describe(&self) -> String {
        match &self.kind {
            UpdateKind::DigestOnly => {
                format!("{}: {} republished", self.app, self.from_tag)
            }
            UpdateKind::NewVersion { to_tag } => {
                format!("{} : {} → {to_tag}", self.app, self.from_tag)
            }
        }
    }
}

/// Queries the registries for every installed app.
///
/// Read-only: nothing is modified, nothing is deployed.
pub async fn check<T: chrono::Datelike + chrono::Timelike>(
    state: &State,
    registry: &RegistryClient,
    now: &T,
) -> Result<Vec<Candidate>> {
    let mut out = Vec::new();

    for (app, status) in state.installed_apps().await? {
        // Nothing is proposed for a failed or installing app: there is a more urgent
        // problem to deal with.
        if status != "running" && status != "partial" {
            continue;
        }

        let m = state.app_manifest(&app).await?;
        let channel = m.spec.update.channel;

        let image = ImageRef::parse(&format!("{}:{}", m.spec.image.repo, m.spec.image.tag));

        // The `pin` channel does not stop the watch: we want to be *informed* about a
        // new Vaultwarden release, just not to apply it automatically.
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

        // Nothing new: same tag, same digest.
        if kind == UpdateKind::DigestOnly && m.spec.image.digest.as_deref() == Some(&to_digest) {
            continue;
        }

        let in_window = match &m.spec.update.window {
            Some(w) => MaintenanceWindow::parse(w)?.is_open_at(now),
            // With no declared window, the update can be applied at any time.
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

/// What a backup engine must provide for an update requiring a prior backup to be
/// allowed.
#[async_trait::async_trait]
pub trait BackupProvider: Send + Sync {
    /// Takes a snapshot of the app and returns its id.
    async fn snapshot(&self, app: &str) -> std::result::Result<String, String>;
}

/// Checks an update is allowed to be applied right now.
///
/// Separate from execution so it is testable without an orchestrator.
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
        // Not an error: simply not now. The caller filters on this.
        tracing::debug!(app = %candidate.app, "outside the maintenance window");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(needs_backup: bool) -> Candidate {
        Candidate {
            app: "gitea".into(),
            kind: UpdateKind::NewVersion {
                to_tag: "1.25".into(),
            },
            from_tag: "1.24".into(),
            from_digest: Some("sha256:old".into()),
            to_digest: "sha256:new".into(),
            in_window: true,
            needs_backup,
        }
    }

    #[test]
    fn an_update_requiring_backup_is_refused_without_a_provider() {
        // 🔴 The heart of it: a schema migration is not reversible by an image
        // rollback. Without a backup, we do not play.
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
        assert_eq!(c.describe(), "gitea: 1.24 republished");
    }
}
