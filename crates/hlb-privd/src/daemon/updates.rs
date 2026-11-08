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
use hlb_updater::policy::{decide, guarded, notes_source, notes_target, Decision, Why};
use hlb_updater::run::{Actor, Overrides, Progress, Ran, Refusal, Update};
use hlb_updater::{BackupProvider, Candidate, UpdateKind, UpdateOutcome};

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
    /// Decides who applies each update waiting, records it for the inbox, then applies
    /// what needs nobody now — automatic, or approved by a person — one app after
    /// another. 🔴 It stops at the first switch that did not end applied: a second
    /// rollback in a row says more about the cluster than about the apps.
    pub async fn run(&self) -> Vec<Done> {
        let at = crate::now();
        let apps = match waiting(self.state, at).await {
            Ok(a) => a,
            Err(e) => {
                tracing::warn!("no automatic update looked at: {e}");
                return Vec::new();
            }
        };
        let checked = if apps.is_empty() {
            hlb_updater::Checked::default()
        } else {
            let local = chrono::Local::now().naive_local();
            match hlb_updater::check_apps(
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
            }
        };

        // What could not be read keeps what was decided before: unread is not applied.
        let mut keep: BTreeSet<String> =
            checked.unreadable.iter().map(|(a, _)| a.clone()).collect();
        let mut due = Vec::new();
        for c in &checked.candidates {
            keep.insert(c.app.clone());
            match self.decide(c, at).await {
                Ok(true) if c.in_window && c.maturity.refusal(at).is_none() => due.push(c),
                // Waiting for its window, its maturity or a person: the ordinary case.
                Ok(_) => {}
                Err(e) => tracing::warn!(app = %c.app, "its update could not be decided: {e}"),
            }
        }

        let mut done = Vec::new();
        for c in due {
            let d = self.one(c, at).await;
            if let Some(refused) = refusal(&d) {
                let json = serde_json::to_string(&refused).unwrap_or_default();
                if let Err(e) = self
                    .state
                    .refuse_update(&c.app, &c.to_digest, &json, at)
                    .await
                {
                    tracing::warn!(app = %c.app, "its refusal could not be recorded: {e}");
                }
            }
            let applied = matches!(
                d,
                Done::Switched {
                    outcome: UpdateOutcome::Applied { .. },
                    ..
                }
            );
            if applied {
                keep.remove(&c.app);
            }
            let stop = !applied && !matches!(d, Done::Refused { .. });
            done.push(d);
            if stop {
                break;
            }
        }
        if let Err(e) = self.state.keep_update_decisions(&keep).await {
            tracing::warn!("the updates waiting could not be tidied: {e}");
        }
        done
    }

    /// Decides who applies `c` and records it, the release notes read for the person
    /// who will approve it. `true` when it goes on with nobody: automatic, or approved
    /// since its last refusal.
    async fn decide(&self, c: &Candidate, at: i64) -> Result<bool, String> {
        use hlb_api::updates::{ReleaseNote, UpdateMove, UpdateWho};
        let installed = self
            .state
            .app_manifest(&c.app)
            .await
            .map_err(|e| e.to_string())?;
        let catalog = self.catalog.get(&c.app);
        let house = self
            .state
            .update_automatic(&c.app)
            .await
            .map_err(|e| e.to_string())?;
        let mut decision = decide(c, &installed, house);
        let mut notes = None;
        if let (Some(github), Some(to)) = (notes_source(&installed, catalog), notes_target(c)) {
            let read = self.registry.release_notes(github, &c.from_tag, to).await;
            decision = guarded(
                decision,
                read.as_ref()
                    .map(|n| hlb_registry::notes::warning(n, to))
                    .map_err(|e| e.to_string()),
            );
            notes = read.ok().map(|n| {
                n.into_iter()
                    .map(|n| ReleaseNote {
                        tag: n.tag,
                        url: n.url,
                    })
                    .collect::<Vec<_>>()
            });
        }
        let (who, why) = match decision {
            Decision::Automatic => (UpdateWho::Automatic, None),
            Decision::OneClick { why } => (UpdateWho::OneClick, Some(wire(why))),
            Decision::Manual { why } => (UpdateWho::Manual, Some(wire(why))),
        };
        let (moves, to_tag) = match &c.kind {
            UpdateKind::DigestOnly => (UpdateMove::Rebuild, None),
            UpdateKind::NewVersion { to_tag } => (UpdateMove::Version, Some(to_tag.clone())),
            UpdateKind::Catalog { tag, .. } => (UpdateMove::Catalog, Some(tag.clone())),
            UpdateKind::Companions => (UpdateMove::Companions, None),
        };
        self.state
            .record_update_decision(&hlb_state::UpdateDecision {
                app: c.app.clone(),
                digest: c.to_digest.clone(),
                from_tag: c.from_tag.clone(),
                kind: moves.as_stored().into(),
                to_tag,
                who: who.as_stored().into(),
                why: why.and_then(|w| serde_json::to_string(&w).ok()),
                notes: notes.and_then(|n| serde_json::to_string(&n).ok()),
                decided_at: at,
                refused: None,
                refused_at: None,
                approved_by: None,
                approved_at: None,
            })
            .await
            .map_err(|e| e.to_string())?;
        // Read back: the approval and the refusal are the state's, kept across passes.
        let recorded = self
            .state
            .update_decision(&c.app)
            .await
            .map_err(|e| e.to_string())?
            .and_then(|d| d.waiting());
        Ok(recorded.is_some_and(|w| w.who != UpdateWho::Manual && w.needs().is_none()))
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

/// What the inbox says the pass refused. `None` for a switch that applied, and for a
/// refusal that only says "not yet" — it is tried again when its time comes.
fn refusal(d: &Done) -> Option<hlb_api::updates::UpdateRefusal> {
    use hlb_api::updates::UpdateRefusal as R;
    Some(match d {
        Done::Switched { outcome, .. } => match outcome {
            UpdateOutcome::Applied { .. } => return None,
            UpdateOutcome::RolledBack { reason } => R::RolledBack {
                reason: reason.clone(),
            },
            UpdateOutcome::Paused => R::Paused,
            UpdateOutcome::Inconclusive => R::Inconclusive,
        },
        Done::Refused { why, .. } => match why {
            Refusal::Vulnerable { described } => R::Vulnerable {
                described: described.clone(),
            },
            Refusal::CopyFailed { error } => R::CopyFailed {
                error: error.clone(),
            },
            Refusal::OutsideWindow | Refusal::Immature { .. } => return None,
        },
        Done::Failed { error, .. } => R::Failed {
            error: error.clone(),
        },
    })
}

/// The policy's reason as the wire carries it.
fn wire(why: Why) -> hlb_api::updates::UpdateWhy {
    use hlb_api::updates::{UpdateJump, UpdateReach, UpdateWhy as W};
    use hlb_updater::policy::Jump;
    match why {
        Why::Major => W::Major,
        Why::BeyondReach {
            jump,
            reach,
            by_house,
        } => W::BeyondReach {
            jump: match jump {
                Jump::Patch => UpdateJump::Patch,
                Jump::Minor => UpdateJump::Minor,
                Jump::Major => UpdateJump::Major,
            },
            reach: match reach {
                hlb_types::Automatic::None => UpdateReach::None,
                hlb_types::Automatic::Patch => UpdateReach::Patch,
                hlb_types::Automatic::Minor => UpdateReach::Minor,
            },
            by_house,
        },
        Why::NotesSay { tag, word } => W::NotesSay { tag, word },
        Why::NotesMissing { tag } => W::NotesMissing { tag },
        Why::NotesUnreadable { error } => W::NotesUnreadable { error },
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

    /// 🔴 A rollback recorded, or the next hour's pass tries the same image again; a
    /// "not yet" not recorded, or an update waiting for its window would need a person.
    #[test]
    fn a_rollback_takes_the_update_back_to_a_person_and_a_not_yet_does_not() {
        use hlb_api::updates::UpdateRefusal;
        let rolled = Done::Switched {
            app: "gitea".into(),
            outcome: UpdateOutcome::RolledBack {
                reason: "task exited".into(),
            },
        };
        assert_eq!(
            refusal(&rolled),
            Some(UpdateRefusal::RolledBack {
                reason: "task exited".into()
            })
        );
        let applied = Done::Switched {
            app: "gitea".into(),
            outcome: UpdateOutcome::Applied {
                digest: "sha256:new".into(),
            },
        };
        assert_eq!(refusal(&applied), None);
        for why in [
            Refusal::OutsideWindow,
            Refusal::Immature {
                why: "3 days old".into(),
            },
        ] {
            let d = Done::Refused {
                app: "gitea".into(),
                why,
            };
            assert_eq!(refusal(&d), None, "{d:?}");
        }
        let failed = Done::Failed {
            app: "gitea".into(),
            error: "no destination".into(),
        };
        assert!(matches!(
            refusal(&failed),
            Some(UpdateRefusal::Failed { .. })
        ));
    }
}
