//! The backup pass the controller runs: on its schedule, and for one app when someone
//! asks ("back up now").
//!
//! 🔴 One configuration and one pass, `hlb_backup_run::Pass`, for both. The route used
//! to drive a provider built at startup over `--backup-repo` alone: it wrote to that
//! one repository, marked every declared destination done, recorded no destination,
//! knew only the volumes of the apps installed before the controller started, and
//! never dumped a database.

use std::path::PathBuf;

use hlb_api::{ActionResult, ActionStep, StepState};
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
    pub postgres_vital_admin: Option<String>,
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
        let orch = hlb_orchestrator::SwarmOrchestrator::connect().await.ok();
        hlb_backup_run::Pass {
            state,
            vault: &vault,
            state_path: &self.state_path,
            fallback_repo: self.fallback_repo.as_deref(),
            network: &self.network,
            postgres_admin: self.postgres_admin.as_deref(),
            postgres_vital_admin: self.postgres_vital_admin.as_deref(),
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

/// "Back up now", for one app: the destinations it would go to, then what the pass did.
pub(crate) async fn back_up(p: &crate::Privd, i: hlb_api::intent::BackUp) -> ActionResult {
    let hlb_api::intent::BackUp { app, apply } = i;
    let fallback = p.backup.as_ref().and_then(|b| b.fallback_repo());
    let mut blockers = Vec::new();
    let held = match p.state.backup_kinds(&app).await {
        Ok(k) => k,
        Err(_) => {
            blockers.push(format!("no installed app is called {app}"));
            Vec::new()
        }
    };
    let dests = hlb_backup_run::destinations_of_app(&p.state, &app, fallback)
        .await
        .unwrap_or_default();
    if blockers.is_empty() && held.is_empty() {
        blockers.push(format!(
            "{app} holds nothing to back up — no volume, database or SQLite file: no \
             copy is owed"
        ));
    } else if blockers.is_empty() && dests.is_empty() {
        blockers.push(
            "no destination configured — \"hlb backup dest add <name> --location \
             <path>\""
                .to_string(),
        );
    }

    let mut steps: Vec<ActionStep> = dests
        .iter()
        .map(|d| ActionStep {
            description: format!("back up {app} to \"{}\"", d.name),
            // 🔴 In preview, `Planned`. Never `Done`: that would be claiming to have
            // backed up.
            state: StepState::Planned,
            error: None,
        })
        .collect();

    let applied = apply && blockers.is_empty();
    if applied {
        steps = match &p.backup {
            // 🔴 What the pass did, one line per item and destination — the outcome it
            // recorded there. Nothing it did not report is shown done: a destination
            // it never reached keeps no green line.
            Some(b) => {
                let mut reported = Vec::new();
                let outcome = b
                    .back_up(&p.state, &app, &mut |e| reported.push(step_of(e)))
                    .await;
                if let Err(e) = outcome {
                    reported.push(ActionStep {
                        description: format!("back up {app}"),
                        state: StepState::Failed,
                        error: Some(e),
                    });
                }
                if reported.is_empty() {
                    reported.push(ActionStep {
                        description: format!("back up {app}"),
                        state: StepState::Failed,
                        error: Some(format!(
                            "the backup pass took nothing of {app} — a failed install is \
                             not backed up"
                        )),
                    });
                }
                reported
            }
            None => steps
                .into_iter()
                .map(|step| ActionStep {
                    state: StepState::Unimplemented,
                    error: Some("this controller runs no backup pass".into()),
                    ..step
                })
                .collect(),
        };
    }

    ActionResult {
        applied,
        // 🔴 Same family as deleting with no volume: "to 0 destinations" reads as an
        // action that is going to go somewhere. The summary is the line you read FIRST
        // — it must say what will really happen, not recite a counter at zero.
        summary: match dests.len() {
            _ if held.is_empty() => format!("back up {app} — it holds nothing to back up"),
            0 => format!("back up {app} — no destination: nothing would go anywhere"),
            n => format!(
                "back up {app} to {}",
                hlb_api::plural(n as u64, "destination", "destinations")
            ),
        },
        steps,
        cli_command: format!("hlb backup run --app {app} --force"),
        blockers,
        warnings: Vec::new(),
        confirmation_required: None,
    }
}

/// One event of a backup pass, as the step it is.
fn step_of(e: Event) -> ActionStep {
    match e {
        Event::Done {
            what,
            destination,
            snapshot,
        } => ActionStep {
            description: format!(
                "{what} → \"{destination}\" ({})",
                snapshot.chars().take(8).collect::<String>()
            ),
            state: StepState::Done,
            error: None,
        },
        Event::Failed {
            what,
            destination,
            error,
        } => ActionStep {
            description: match destination {
                Some(d) => format!("{what} → \"{d}\""),
                None => what,
            },
            state: StepState::Failed,
            error: Some(error),
        },
        // Deliberately not backed up: incomplete, never done and never a failure.
        Event::NotCovered { what, why } => ActionStep {
            description: what,
            state: StepState::Unimplemented,
            error: Some(why),
        },
    }
}
