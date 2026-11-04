//! Reading what an app's backups hold, for the CLI and the daemon alike: two copies of
//! the backup pass drifted once, and this answers the same question.
//!
//! - Its volumes: restored into a disposable space and counted against the snapshot, a
//!   sample of the repository's blocks read again.
//! - Its databases: each dump restored into a disposable server of the installed image,
//!   its tables counted against what the dump names ([`crate::dump_reading`]).
//!
//! ⚠️ Not read: SQLite snapshots and buckets. And nothing starts: a store copied live
//! passes the volume's count and might not open.

use hlb_backup::{Class, Destination};
use hlb_secrets::Vault;
use hlb_state::{backup_kind, State};

use crate::dump_reading::{self, Reading};
use crate::restore::{databases_of, Restore};
use crate::{credentials, effective_destinations, restic_password, Result};

/// The most a reading nobody asked for takes from a destination that may bill by
/// transfer. Asked by hand there is no limit: that person chose to pay.
pub const UNASKED_BILLED_LIMIT: u64 = 5 * 1024 * 1024 * 1024;

/// The largest dump read unasked: it is held in memory on the way to the server, by a
/// daemon the whole house depends on.
pub const UNASKED_DUMP_LIMIT: u64 = 1024 * 1024 * 1024;

/// What a server's files may take for its compressed dump, room being judged against it.
/// A margin rather than a figure: a dump's ratio depends on what the app stores.
const DUMP_GROWTH: u64 = 4;

/// One thing read back.
#[derive(Debug)]
pub struct Part {
    /// `volumes`, or `database <name>`.
    pub what: String,
    pub snapshot: String,
    pub destination: String,
    pub outcome: std::result::Result<String, String>,
}

/// An app's backups read back, recorded as one verification.
#[derive(Debug)]
pub struct ReadBack {
    pub parts: Vec<Part>,
}

impl ReadBack {
    pub fn matches(&self) -> bool {
        self.parts.iter().all(|p| p.outcome.is_ok())
    }

    /// What failed, or else what was read: said in one line to a person.
    pub fn describe(&self) -> String {
        let failed: Vec<&Part> = self.parts.iter().filter(|p| p.outcome.is_err()).collect();
        let said = if failed.is_empty() {
            self.parts.iter().collect()
        } else {
            failed
        };
        said.iter()
            .map(|p| {
                let (Ok(text) | Err(text)) = &p.outcome;
                format!("{} on {}: {text}", p.what, p.destination)
            })
            .collect::<Vec<_>>()
            .join("; ")
    }
}

/// Reads back what `app`'s backups hold and records what was seen; `None` when it has no
/// backup yet, which is nothing to verify and above all no "verified". `unasked`: nobody
/// typed this, so it stays within what a person would have accepted.
pub async fn app(
    state: &State,
    vault: &Vault,
    network: &str,
    fallback: Option<&str>,
    app: &str,
    unasked: bool,
) -> Result<Option<ReadBack>> {
    let mut parts = Vec::new();
    parts.extend(volumes(state, vault, network, fallback, app, unasked).await?);
    parts.extend(databases(state, vault, network, fallback, app, unasked).await?);
    let Some(first) = parts.first() else {
        return Ok(None);
    };
    let snapshot = first.snapshot.clone();
    let read = ReadBack { parts };
    // 🔴 A discrepancy is recorded as a FAILURE: `hlb backup status` must keep reporting
    // this app as unverified. One row for all of it: read per part, a good dump read last
    // would have hidden the volumes that failed before it.
    let detail = (!read.matches()).then(|| read.describe());
    state
        .record_verification(app, &snapshot, read.matches(), detail.as_deref())
        .await?;
    Ok(Some(read))
}

/// 🔴 A VOLUME snapshot, read from the destination holding it: the newest row of any kind
/// was a dump, read from `--backup-repo` whatever its destination, and its verification
/// said the app's volumes restored.
async fn volumes(
    state: &State,
    vault: &Vault,
    network: &str,
    fallback: Option<&str>,
    app: &str,
    unasked: bool,
) -> Result<Option<Part>> {
    let dests = effective_destinations(state, app, Class::Bulky, fallback).await?;
    let Some((snapshot, d)) = newest(state, app, backup_kind::VOLUME, &dests).await? else {
        return Ok(None);
    };
    let outcome = match credentials(state, vault, d).await {
        Ok(creds) => {
            let password = restic_password(state, vault).await?;
            hlb_backup::verify_snapshot_on(
                d,
                creds.as_deref(),
                Some(network),
                &password,
                &snapshot,
                unasked.then_some(UNASKED_BILLED_LIMIT),
            )
            .await
            .map_err(|e| e.to_string())
            .and_then(|v| {
                if v.matches() {
                    Ok(v.describe())
                } else {
                    Err(v.describe())
                }
            })
        }
        Err(e) => Err(e.to_string()),
    };
    Ok(Some(Part {
        what: "volumes".into(),
        snapshot,
        destination: d.name.clone(),
        outcome,
    }))
}

async fn databases(
    state: &State,
    vault: &Vault,
    network: &str,
    fallback: Option<&str>,
    app: &str,
    unasked: bool,
) -> Result<Vec<Part>> {
    let dests = effective_destinations(state, app, Class::Critical, fallback).await?;
    // None taken yet: the backups say so. Read here, a new app would fail on its first
    // night for a dump nothing was due to take.
    let Some((_, holder)) = newest(state, app, backup_kind::SQL_DUMP, &dests).await? else {
        return Ok(Vec::new());
    };
    let restore = Restore {
        state,
        vault,
        fallback_repo: fallback,
        network,
        orchestrator: None,
    };
    let manifest = state.app_manifest(app).await?;
    let mut parts = Vec::new();
    for (engine, name, extensions) in databases_of(&manifest, app) {
        let (mut snapshot, mut destination) = (String::new(), holder.name.clone());
        let outcome = async {
            let source = restore
                .find_dump(app, engine, &name, Some(&holder.name), None)
                .await?;
            snapshot.clone_from(&source.snapshot.id);
            destination.clone_from(&source.destination.name);
            let server = engine.service_name();
            let image = state
                .app_manifest(server)
                .await
                .map_err(|e| format!("no installed {server} to take its image from: {e}"))?
                .spec
                .image
                .reference();
            let d = &source.destination;
            let password = restic_password(state, vault)
                .await
                .map_err(|e| e.to_string())?;
            let creds = credentials(state, vault, d)
                .await
                .map_err(|e| e.to_string())?;
            let env = d.env(creds.as_deref()).map_err(|e| e.to_string())?;
            let (runner, location) = d.runner(Some(network));
            let repo = hlb_backup::Repository::new(runner, location, &password).extra_env(env);
            let [path] = source.snapshot.paths.as_slice() else {
                return Err(format!(
                    "snapshot {} holds more than one dump",
                    source.snapshot.id
                ));
            };
            let bytes = repo
                .stats(&source.snapshot.id)
                .await
                .map_err(|e| e.to_string())?
                .bytes;
            let room = hlb_backup::verify::room_here()
                .await
                .map_err(|e| e.to_string())?;
            if let Some(why) = refused(bytes, room, unasked, d.is_s3()) {
                return Err(why);
            }
            let mut dump = Vec::new();
            repo.dump(&source.snapshot.id, path, &mut dump)
                .await
                .map_err(|e| format!("the dump could not be read back: {e}"))?;
            let tables = dump_reading::read(
                &Reading {
                    engine,
                    image: &image,
                    name: &name,
                    role: app,
                    extensions,
                },
                &dump,
            )
            .await?;
            if tables.matches() {
                let plural = if tables.restored == 1 { "" } else { "s" };
                Ok(format!(
                    "{} table{plural} restored into a disposable {server}, as its dump names them",
                    tables.restored
                ))
            } else {
                Err(format!(
                    "DISCREPANCY — {} tables restored, its dump names {}",
                    tables.restored, tables.listed
                ))
            }
        }
        .await;
        parts.push(Part {
            what: format!("database {name}"),
            snapshot,
            destination,
            outcome,
        });
    }
    Ok(parts)
}

/// Why a dump of `bytes` is not read back, before it is fetched.
fn refused(bytes: u64, room: u64, unasked: bool, billed: bool) -> Option<String> {
    if unasked && bytes > UNASKED_DUMP_LIMIT {
        return Some(format!(
            "not restored: a dump of {bytes} bytes is over the {UNASKED_DUMP_LIMIT} read \
             unasked. hlb backup verify <app> reads it when asked"
        ));
    }
    let limit = (unasked && billed).then_some(UNASKED_BILLED_LIMIT);
    hlb_backup::verify::refusal(bytes, u64::MAX, limit)
        .or_else(|| hlb_backup::verify::refusal(bytes.saturating_mul(DUMP_GROWTH), room, None))
}

/// A destination that may bill for the reading is taken only when no other holds one.
async fn newest<'a>(
    state: &State,
    app: &str,
    kind: &str,
    dests: &'a [Destination],
) -> Result<Option<(String, &'a Destination)>> {
    let (billed, free): (Vec<&Destination>, Vec<&Destination>) =
        dests.iter().partition(|d| d.is_s3());
    for set in [free, billed] {
        let names: Vec<String> = set.iter().map(|d| d.name.clone()).collect();
        if let Some((snapshot, name)) = state.latest_snapshot(app, kind, &names).await? {
            let holder = set.into_iter().find(|d| d.name == name);
            return Ok(holder.map(|d| (snapshot, d)));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn destination(name: &str, location: &str) -> Destination {
        Destination {
            name: name.into(),
            location: location.into(),
            classes: vec![Class::Bulky],
            credentials_secret: None,
        }
    }

    #[tokio::test]
    async fn a_destination_that_may_bill_is_read_only_when_no_other_holds_a_snapshot() {
        let s = State::in_memory().await.expect("state");
        let dests = [
            destination("nas", "/srv/restic"),
            destination("offsite", "s3:https://s3.example.org/hlb"),
        ];

        s.record_backup_to("gitea", backup_kind::VOLUME, "offsite", Some("o1"), None)
            .await
            .expect("record");
        let found = newest(&s, "gitea", backup_kind::VOLUME, &dests)
            .await
            .expect("read")
            .expect("one");
        assert_eq!((found.0.as_str(), found.1.name.as_str()), ("o1", "offsite"));

        s.record_backup_to("gitea", backup_kind::VOLUME, "nas", Some("n1"), None)
            .await
            .expect("record");
        s.record_backup_to("gitea", backup_kind::VOLUME, "offsite", Some("o2"), None)
            .await
            .expect("record");
        let found = newest(&s, "gitea", backup_kind::VOLUME, &dests)
            .await
            .expect("read")
            .expect("one");
        assert_eq!((found.0.as_str(), found.1.name.as_str()), ("n1", "nas"));
    }

    #[tokio::test]
    async fn a_dump_is_not_read_as_the_app_s_volumes() {
        let s = State::in_memory().await.expect("state");
        let dests = [destination("nas", "/srv/restic")];
        s.record_backup_to("gitea", backup_kind::SQL_DUMP, "nas", Some("d1"), None)
            .await
            .expect("record");
        assert!(newest(&s, "gitea", backup_kind::VOLUME, &dests)
            .await
            .expect("read")
            .is_none());
    }

    #[test]
    fn a_large_dump_is_read_unasked_only_within_the_limits_and_always_within_the_disk() {
        let huge = 100 * UNASKED_DUMP_LIMIT;
        assert!(refused(UNASKED_DUMP_LIMIT, huge, true, false).is_none());
        assert!(refused(UNASKED_DUMP_LIMIT + 1, huge, true, false)
            .expect("refused")
            .contains("hlb backup verify"));
        assert!(refused(UNASKED_DUMP_LIMIT + 1, huge, false, true).is_none());
        // Four times the dump does not fit, though the dump itself would.
        assert!(refused(1000, 3000, false, false)
            .expect("refused")
            .contains("do not fit"));
    }

    #[test]
    fn one_failed_part_fails_the_app_and_is_what_is_said() {
        let part = |what: &str, outcome| Part {
            what: what.to_string(),
            snapshot: "s".into(),
            destination: "nas".into(),
            outcome,
        };
        let read = ReadBack {
            parts: vec![
                part("volumes", Ok("48 files".to_string())),
                part("database a", Err("DISCREPANCY".to_string())),
                part("database b", Ok("3 tables".to_string())),
            ],
        };
        assert!(!read.matches());
        assert_eq!(read.describe(), "database a on nas: DISCREPANCY");
    }
}
