//! The backup pass the controller runs: on its schedule, and for one app when someone
//! asks ("back up now").
//!
//! 🔴 One configuration and one pass, `hlb_backup_run::Pass`, for both. The route used
//! to drive a provider built at startup over `--backup-repo` alone: it wrote to that
//! one repository, marked every declared destination done, recorded no destination,
//! knew only the volumes of the apps installed before the controller started, and
//! never dumped a database.

use std::path::PathBuf;

use hlb_backup_run::{Event, Summary};
use hlb_state::State;

/// What a pass is told about this installation, beyond the state.
#[derive(Debug, Clone)]
pub struct PassConfig {
    pub master_key: PathBuf,
    /// The state database's file, for its own snapshot.
    pub state_path: PathBuf,
    /// `--backup-repo`: served when no destination is declared.
    pub fallback_repo: Option<String>,
    pub network: String,
    pub postgres_admin: Option<String>,
    pub mariadb_admin: Option<String>,
}

impl PassConfig {
    /// Runs the pass — the installation's, or `only` that app's. The vault is opened
    /// for the pass and never created: a missing key is an error, said.
    pub async fn run(
        &self,
        state: &State,
        only: Option<&str>,
        force: bool,
        report: &mut (dyn FnMut(Event) + Send),
    ) -> hlb_backup_run::Result<Summary> {
        let vault = hlb_secrets::Vault::open(&self.master_key)?;
        // Where each volume is: a volume of another node is backed up there.
        let orch = hlb_orchestrator::SwarmOrchestrator::connect().ok();
        hlb_backup_run::Pass {
            state,
            vault: &vault,
            state_path: &self.state_path,
            fallback_repo: self.fallback_repo.as_deref(),
            network: &self.network,
            postgres_admin: self.postgres_admin.as_deref(),
            mariadb_admin: self.mariadb_admin.as_deref(),
            schedule: hlb_backup::Schedule::default(),
            force,
            only,
            orchestrator: orch
                .as_ref()
                .map(|o| o as &dyn hlb_orchestrator::Orchestrator),
            // On the overlay: Garage resolves.
            s3_endpoint: Some(hlb_backup_run::bucket::S3_URL),
        }
        .run(report)
        .await
    }
}

/// "Back up now": one app, everything it holds, whether due or not.
///
/// A trait so the route's reading of each outcome is tested without restic.
#[async_trait::async_trait]
pub trait BackUpNow: Send + Sync {
    /// Where an app goes when no destination is declared.
    fn fallback_repo(&self) -> Option<&str>;

    async fn back_up(
        &self,
        state: &State,
        app: &str,
        report: &mut (dyn FnMut(Event) + Send),
    ) -> Result<Summary, String>;
}

#[async_trait::async_trait]
impl BackUpNow for PassConfig {
    fn fallback_repo(&self) -> Option<&str> {
        self.fallback_repo.as_deref()
    }

    async fn back_up(
        &self,
        state: &State,
        app: &str,
        report: &mut (dyn FnMut(Event) + Send),
    ) -> Result<Summary, String> {
        self.run(state, Some(app), true, report)
            .await
            .map_err(|e| e.to_string())
    }
}
