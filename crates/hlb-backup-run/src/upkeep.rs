//! Each destination proved again every week, and kept to the retention policy when it
//! can be erased anyway.
//!
//! 🔴 Until 2026-10-19 nothing applied a retention: every repository only grew, until
//! the disk that also carries the databases was full. Forgetting old snapshots is also
//! what an intruder holding the credential does, so it runs only where the proof —
//! taken in the same pass, never remembered from the day the destination was declared —
//! says the destination is erasable anyway. One that cannot be erased (rest-server
//! `--append-only`, a bucket whose policy denies deleting versions) is its owner's to
//! prune — [`owner_script`] hands them the very passes the upkeep would run —, and one
//! not proven is left as it is.

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
            Erasure::Kept { .. } => Retention::Left(format!(
                "it cannot be erased: its owner prunes it, from another machine — \
                     hlb backup dest prune-script {}",
                d.name
            )),
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

/// The script a destination's owner runs, from a machine of their own, to prune what
/// Homelabus cannot: the upkeep's own passes ([`hlb_backup::restic::forget_passes`]),
/// with a credential that may delete.
///
/// Holds no secret — the repository's password is the emergency kit's, the credential
/// the owner's — and no unmasked location. Never run from the cluster, on a schedule
/// or otherwise: whoever takes it would then hold what erases the copy kept out of reach.
pub fn owner_script(d: &Destination, policy: &RetentionPolicy) -> crate::Result<String> {
    let passes = hlb_backup::restic::forget_passes(policy, true)?;
    // Root declared both, but they land in a script: a line break would be a command.
    let plain = |s: &str| s.replace(|c: char| c.is_control(), "?");
    let p = policy;
    let mut out = format!(
        "#!/bin/sh
# Prunes the backup destination \"{name}\" to Homelabus's retention policy
# (hourly {}, daily {}, weekly {}, monthly {}, yearly {}).
# Homelabus writes to {location}
# with a credential meant not to erase it: this copy is pruned by you alone.
#
# Run it from a machine of yours, with restic (https://restic.net), never from
# the cluster — whoever takes the cluster would then hold what erases this copy:
#   RESTIC_REPOSITORY  the same repository, through a credential that MAY delete,
#                      not the one Homelabus writes with
#   RESTIC_PASSWORD    the backup repositories' password, 2. on the emergency kit
",
        p.hourly,
        p.daily,
        p.weekly,
        p.monthly,
        p.yearly,
        name = plain(&d.name),
        location = plain(&d.masked_location()),
    );
    if d.is_s3() {
        out.push_str(
            "#   AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY  that credential's
# A versioned bucket keeps what this deletes as old versions: the space comes
# back when the bucket's lifecycle expires them.
",
        );
    }
    out.push_str(
        "set -eu
: \"${RESTIC_REPOSITORY:?the repository, through a credential that may delete}\"
: \"${RESTIC_PASSWORD:?the repositories' password, 2. on the emergency kit}\"
",
    );
    for args in passes {
        out.push_str(&format!("restic {}\n", args.join(" ")));
    }
    out.push_str("restic snapshots --compact\n");
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dest(location: &str) -> Destination {
        Destination {
            name: "offsite".into(),
            location: location.into(),
            classes: vec![hlb_backup::Class::Critical],
            credentials_secret: None,
        }
    }

    #[test]
    fn the_owner_runs_the_upkeep_s_own_passes() {
        let policy = RetentionPolicy::default();
        let script = owner_script(&dest("rest:http://h:8000/r"), &policy).expect("script");
        let run: Vec<&str> = script
            .lines()
            .filter(|l| l.starts_with("restic forget"))
            .collect();
        let passes = hlb_backup::restic::forget_passes(&policy, true).expect("passes");
        assert_eq!(run.len(), passes.len(), "{script}");
        for (line, args) in run.iter().zip(&passes) {
            assert_eq!(*line, format!("restic {}", args.join(" ")));
        }
        assert!(script.starts_with("#!/bin/sh\n"), "{script}");
        assert!(script.contains("set -eu"), "{script}");
    }

    #[test]
    fn the_script_holds_no_credential_and_refuses_an_empty_policy() {
        let script = owner_script(
            &dest("s3:https://AKIAXYZ:s3cr3tv4lue@s3.example/b"),
            &RetentionPolicy::default(),
        )
        .expect("script");
        assert!(
            !script.contains("AKIAXYZ") && !script.contains("s3cr3tv4lue"),
            "{script}"
        );
        assert!(script.contains("lifecycle"), "{script}");

        let none = RetentionPolicy {
            hourly: 0,
            daily: 0,
            weekly: 0,
            monthly: 0,
            yearly: 0,
        };
        assert!(owner_script(&dest("rest:http://h/r"), &none).is_err());
    }

    #[test]
    fn a_line_break_in_a_location_stays_in_its_comment() {
        let script = owner_script(
            &dest("rest:http://h/r\nrm -rf /"),
            &RetentionPolicy::default(),
        )
        .expect("script");
        assert!(!script.lines().any(|l| l.starts_with("rm")), "{script}");
    }
}
