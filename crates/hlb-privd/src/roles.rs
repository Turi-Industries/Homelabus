//! The roles, made true where they are read: PocketID's groups, the apps' clients and
//! quotas, and the portal's groups in the Caddyfile.

use hlb_api::intent::{PortalRoles, RolesSynced, SyncRoles};
use hlb_api::{ActionStep, StepState};
use hlb_engine::roles::{Outcome, Report, RoleSync};
use hlb_users::access::{self, Entry};

use crate::Privd;

impl Privd {
    /// Runs the sync, as the daemon's loop reads it: the engine's report, whole.
    pub async fn sync_roles(&self, apply: bool) -> Result<Report, String> {
        let (Some(orch), Some(install)) = (&self.orchestrator, &self.install) else {
            return Err("the controller has no vault or no Docker: `hlb role sync --apply` runs it from a manager".into());
        };
        let reach = |u: &str| u.to_string();
        RoleSync {
            state: &self.state,
            vault: &install.vault,
            orchestrator: orch.as_ref(),
            reach: &reach,
            http: &hlb_guide::HttpApi::default(),
            now: crate::now(),
        }
        .run(apply)
        .await
        .map_err(|e| e.to_string())
    }
}

pub(crate) async fn sync(p: &Privd, i: SyncRoles) -> Result<RolesSynced, String> {
    let report = p.sync_roles(i.apply).await?;
    let steps = report
        .lines
        .iter()
        .map(|l| {
            let (state, error) = match &l.outcome {
                Outcome::ToDo => (StepState::Planned, None),
                Outcome::Done => (StepState::Done, None),
                // Not done, and not a failure: retried at the next pass.
                Outcome::Waiting(why) => (StepState::Planned, Some(why.clone())),
                // 🔴 Never `Done`: Homelabus could not do it.
                Outcome::NotConfigured(why) => (StepState::Unimplemented, Some(why.clone())),
                Outcome::Failed(why) => (StepState::Failed, Some(why.clone())),
            };
            ActionStep {
                description: format!("{}: {}", l.subject, l.change),
                state,
                error,
            }
        })
        .collect();
    Ok(RolesSynced {
        steps,
        notes: report.notes,
    })
}

pub(crate) async fn portal(p: &Privd, i: PortalRoles) -> Result<(), String> {
    let behind_portal = match p.state.app_manifest(&i.app).await {
        Ok(m) => access::entry_of(&m) == Some(Entry::Portal),
        Err(_) => false,
    };
    if !behind_portal {
        return Ok(());
    }
    let (Some(orch), Some(install)) = (&p.orchestrator, &p.install) else {
        return Err(
            "the controller reaches no Docker: `hlb ingress --apply` publishes the routes".into(),
        );
    };
    hlb_engine::ingress::publish(orch.as_ref(), &p.state, Some(&install.vault))
        .await
        .map(|_| ())
        .map_err(|e| format!("the portal still checks the old roles — {e}"))
}
