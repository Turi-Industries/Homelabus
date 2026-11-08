//! Updates applied with nobody there: what the policy lets go alone, in its window.
//!
//! The same pass as `hlb update apply` (`hlb_updater::run`), with no override: the scan,
//! maturity, the window and the copy first all hold. Only the apps the daily watch saw an
//! update for are asked about again, so an hourly pass spends little of a registry's
//! rate limit.

use std::collections::{BTreeMap, BTreeSet};

use hlb_orchestrator::Orchestrator;
use hlb_state::State;
use hlb_types::Manifest;
use hlb_updater::policy::{judge, Decision};
use hlb_updater::run::{Actor, Overrides, Progress, Ran, Refusal, Update};
use hlb_updater::{BackupProvider, Candidate, UpdateOutcome};

/// What one pass did with one app.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Done {
    /// The switch ran: its run is recorded, and notified by the update notices.
    Switched { app: String, outcome: UpdateOutcome },
    /// Refused before anything changed, with nobody there to decide: said aloud.
    Refused { app: String, why: Refusal },
    /// Its update could not even start (no copy possible, the state unreadable…).
    Failed { app: String, error: String },
}

/// What the pass is given.
pub struct Pass<'a> {
    pub state: &'a State,
    pub vault: &'a hlb_secrets::Vault,
    pub registry: &'a hlb_registry::RegistryClient,
    pub orchestrator: &'a dyn Orchestrator,
    /// Each installed app's manifest in the source it follows.
    pub catalog: &'a BTreeMap<String, Manifest>,
    pub network: &'a str,
    pub postgres_admin: Option<&'a str>,
    pub mariadb_admin: Option<&'a str>,
    pub fallback_repo: Option<&'a str>,
    pub scanner: &'a dyn hlb_updater::run::Scanner,
}

/// The apps with an update seen and not applied: the only ones worth asking a registry.
pub async fn waiting(state: &State, now: i64) -> hlb_state::Result<BTreeSet<String>> {
    Ok(state
        .update_lags(now)
        .await?
        .waiting
        .into_iter()
        .map(|l| l.app)
        .collect())
}

impl Pass<'_> {
    /// Applies every automatic update due now, one app after another. 🔴 It stops at the
    /// first switch that did not end applied: a second rollback in a row says more about
    /// the cluster than about the apps.
    pub async fn run(&self) -> Vec<Done> {
        let at = crate::now();
        let apps = match waiting(self.state, at).await {
            Ok(a) if a.is_empty() => return Vec::new(),
            Ok(a) => a,
            Err(e) => {
                tracing::warn!("no automatic update looked at: {e}");
                return Vec::new();
            }
        };
        let local = chrono::Local::now().naive_local();
        let checked = match hlb_updater::check_apps(
            self.state,
            self.registry,
            &local,
            at,
            self.catalog,
            Some(&apps),
        )
        .await
        {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("no automatic update looked at: {e}");
                return Vec::new();
            }
        };

        let mut done = Vec::new();
        for c in &checked.candidates {
            // Waiting for its window or its maturity is the ordinary case: nothing to say.
            if !c.in_window || c.maturity.refusal(at).is_some() {
                continue;
            }
            let installed = match self.state.app_manifest(&c.app).await {
                Ok(m) => m,
                Err(e) => {
                    done.push(failed(c, e));
                    continue;
                }
            };
            let house = self.state.update_automatic(&c.app).await.ok().flatten();
            let decision = judge(
                self.registry,
                c,
                &installed,
                self.catalog.get(&c.app),
                house,
            )
            .await;
            if let Decision::OneClick { why } | Decision::Manual { why } = &decision {
                tracing::info!(app = %c.app, "waits for a person: {why}");
                continue;
            }
            let d = self.one(c, at).await;
            let stop = !matches!(
                d,
                Done::Switched {
                    outcome: UpdateOutcome::Applied { .. },
                    ..
                } | Done::Refused { .. }
            );
            done.push(d);
            if stop {
                break;
            }
        }
        done
    }

    async fn one(&self, c: &Candidate, at: i64) -> Done {
        let app = c.app.as_str();
        let s3 = match self.state.buckets_to_backup(app).await {
            Ok(b) if b.is_empty() => None,
            Ok(_) => Some(hlb_objstore::S3_URL),
            Err(e) => return failed(c, e),
        };
        let provider = match hlb_backup_run::provider_for_update(
            self.state,
            self.vault,
            self.network,
            hlb_backup_run::Admins {
                postgres: self.postgres_admin,
                mariadb: self.mariadb_admin,
            },
            s3,
            self.fallback_repo,
            app,
        )
        .await
        {
            Ok(p) => p,
            Err(e) => return failed(c, e),
        };
        let update = Update {
            orchestrator: self.orchestrator,
            state: self.state,
            in_catalog: self.catalog.get(app).map(|m| &m.spec.image),
            backup: provider.as_ref().map(|p| p as &dyn BackupProvider),
            scanner: self.scanner,
            overrides: Overrides::default(),
            actor: Actor {
                name: "controller",
                role: hlb_types::Role::Admin,
            },
            now: at,
        };
        let mut progress = |p: Progress| match p {
            Progress::Copied { snapshot } => tracing::info!(app, %snapshot, "copied first"),
            Progress::Switching { describe } => tracing::info!(app, "{describe}"),
            _ => {}
        };
        match update.run(c, &mut progress).await {
            Ok(Ran::Switched(outcome)) => Done::Switched {
                app: app.to_string(),
                outcome,
            },
            Ok(Ran::Refused(why)) => Done::Refused {
                app: app.to_string(),
                why,
            },
            Err(e) => failed(c, e),
        }
    }
}

fn failed(c: &Candidate, e: impl std::fmt::Display) -> Done {
    Done::Failed {
        app: c.app.clone(),
        error: e.to_string(),
    }
}

/// What a refusal or a failure says to the admin. A switch says nothing here: its run is
/// recorded and the update notices say it, success included.
pub fn notice(d: &Done) -> Option<hlb_notify::Notification> {
    let (app, body) = match d {
        Done::Switched { .. } => return None,
        Done::Refused { app, why } => (
            app,
            match why {
                Refusal::Vulnerable { described } => {
                    format!("its scan blocks it, nothing switched:\n{described}")
                }
                Refusal::CopyFailed { error } => {
                    format!("the copy owed first failed, nothing switched: {error}")
                }
                // Filtered before the pass runs: said in case one slips through.
                Refusal::OutsideWindow => "outside its window".to_string(),
                Refusal::Immature { why } => why.clone(),
            },
        ),
        Done::Failed { app, error } => (app, format!("it could not start: {error}")),
    };
    Some(hlb_notify::Notification::important(
        &format!("update:{app}"),
        &format!("{app}'s automatic update did not run"),
        &format!("{body}\n\n`hlb update apply {app}` to look at it."),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_switch_is_said_by_its_run_and_a_refusal_here() {
        let switched = Done::Switched {
            app: "gitea".into(),
            outcome: UpdateOutcome::Applied {
                digest: "sha256:new".into(),
            },
        };
        assert!(notice(&switched).is_none());
        let refused = Done::Refused {
            app: "gitea".into(),
            why: Refusal::CopyFailed {
                error: "destination unreachable".into(),
            },
        };
        let n = notice(&refused).expect("said");
        assert!(n.body.contains("destination unreachable"), "{}", n.body);
        assert!(n.body.contains("hlb update apply gitea"));
    }
}
