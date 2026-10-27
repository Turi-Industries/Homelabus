//! Each destination proved again every week, and kept to the retention policy when it
//! can be erased anyway.
//!
//! 🔴 Until 2026-10-19 nothing applied a retention: every repository only grew, until
//! the disk that also carries the databases was full. Forgetting old snapshots is also
//! what an intruder holding the credential does, so it runs only where the proof —
//! taken in the same pass, never remembered from the day the destination was declared —
//! says the destination is erasable anyway. One that cannot be erased (rest-server
//! `--append-only`, a bucket whose policy denies deleting versions) is its owner's to
//! prune, and one not proven is left as it is.

use hlb_backup::erasure::Erasure;
use hlb_backup::{Destination, RetentionPolicy};
use hlb_secrets::Vault;
use hlb_state::State;

use crate::erasure::Reach;
use crate::{credentials, load_destinations, restic_password};

/// How often a destination is proved: a policy changed after the last proof is found
/// within a week.
pub const EVERY_S: i64 = 7 * 86_400;

/// What became of the retention on one destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Retention {
    /// `restic forget --prune` ran with the policy.
    Applied,
    /// Not applied, and why: out of reach, or not proven.
    Left(String),
    Failed(String),
}

/// One destination's upkeep.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
    pub destination: String,
    pub proof: Erasure,
    pub retention: Retention,
}

/// The destinations whose last proof is older than [`EVERY_S`], proved, then pruned
/// where erasable.
pub async fn run(
    state: &State,
    vault: &Vault,
    network: &str,
    reach: Reach<'_>,
    policy: &RetentionPolicy,
    now: i64,
) -> crate::Result<Vec<Line>> {
    let mut out = Vec::new();
    for d in load_destinations(state).await? {
        let last = state.destination_proof(&d.name, &d.location).await?;
        if last.is_some_and(|(_, _, at)| now - at < EVERY_S) {
            continue;
        }
        let proof = crate::erasure::prove(state, vault, network, reach, &d).await;
        let retention = match &proof {
            Erasure::Erasable { .. } => apply(state, vault, network, &d, policy).await,
            Erasure::Kept { .. } => {
                Retention::Left("it cannot be erased: its owner prunes it".into())
            }
            Erasure::Unproven { .. } => {
                Retention::Left("not proven: nothing is forgotten on a guess".into())
            }
        };
        out.push(Line {
            destination: d.name.clone(),
            proof,
            retention,
        });
    }
    Ok(out)
}

async fn apply(
    state: &State,
    vault: &Vault,
    network: &str,
    d: &Destination,
    policy: &RetentionPolicy,
) -> Retention {
    // A policy keeping nothing would erase every snapshot at the first forget.
    if !policy.keeps_something() {
        return Retention::Failed("the retention policy keeps nothing".into());
    }
    let run = async {
        let password = restic_password(state, vault).await?;
        let env = d.env(credentials(state, vault, d).await?.as_deref())?;
        let (runner, location) = d.runner(Some(network));
        hlb_backup::Repository::new(runner, location, password)
            .extra_env(env)
            .forget(policy, true)
            .await?;
        Ok::<_, crate::Error>(())
    };
    match run.await {
        Ok(()) => Retention::Applied,
        Err(e) => Retention::Failed(e.to_string()),
    }
}
