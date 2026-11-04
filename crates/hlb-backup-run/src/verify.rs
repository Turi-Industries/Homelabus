//! Reading an app's volumes back, for the CLI and the daemon alike: two copies of the
//! backup pass drifted once, and this answers the same question.
//!
//! ⚠️ What it proves is that restic returns what it took, and that a sample of its blocks
//! reads. It starts nothing: a database's directory copied live passes it and might not
//! open.

use hlb_backup::{Class, Destination, Verification};
use hlb_secrets::Vault;
use hlb_state::{backup_kind, State};

use crate::{credentials, effective_destinations, restic_password, Result};

/// The most a verification nobody asked for reads from a destination that may bill by
/// transfer. Asked by hand, there is no limit: that person chose to pay.
pub const UNASKED_BILLED_LIMIT: u64 = 5 * 1024 * 1024 * 1024;

/// One app's volumes read back, recorded.
#[derive(Debug)]
pub struct ReadBack {
    pub snapshot: String,
    pub destination: String,
    pub outcome: std::result::Result<Verification, String>,
}

impl ReadBack {
    pub fn matches(&self) -> bool {
        self.outcome.as_ref().is_ok_and(Verification::matches)
    }

    pub fn describe(&self) -> String {
        match &self.outcome {
            Ok(v) => v.describe(),
            Err(e) => e.clone(),
        }
    }
}

/// Reads back `app`'s newest volume snapshot and records what was seen; `None` when it
/// has none, which is nothing to verify and above all no "verified".
///
/// 🔴 A VOLUME snapshot, read from the destination holding it: the newest row of any
/// kind was a dump, read from `--backup-repo` whatever its destination, and its
/// verification said the app's volumes restored. A destination that may bill for the
/// reading is taken only when no other holds one.
pub async fn app(
    state: &State,
    vault: &Vault,
    network: &str,
    fallback: Option<&str>,
    app: &str,
    billed_limit: Option<u64>,
) -> Result<Option<ReadBack>> {
    let dests = effective_destinations(state, app, Class::Bulky, fallback).await?;
    let Some((snapshot, d)) = newest(state, app, &dests).await? else {
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
                billed_limit,
            )
            .await
            .map_err(|e| e.to_string())
        }
        Err(e) => Err(e.to_string()),
    };

    let read = ReadBack {
        snapshot,
        destination: d.name.clone(),
        outcome,
    };
    // 🔴 A discrepancy is recorded as a FAILURE: `hlb backup status` must keep reporting
    // this app as unverified.
    let detail = (!read.matches()).then(|| read.describe());
    state
        .record_verification(app, &read.snapshot, read.matches(), detail.as_deref())
        .await?;
    Ok(Some(read))
}

async fn newest<'a>(
    state: &State,
    app: &str,
    dests: &'a [Destination],
) -> Result<Option<(String, &'a Destination)>> {
    let (billed, free): (Vec<&Destination>, Vec<&Destination>) =
        dests.iter().partition(|d| d.is_s3());
    for set in [free, billed] {
        let names: Vec<String> = set.iter().map(|d| d.name.clone()).collect();
        if let Some((snapshot, name)) = state
            .latest_snapshot(app, backup_kind::VOLUME, &names)
            .await?
        {
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
        let found = newest(&s, "gitea", &dests)
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
        let found = newest(&s, "gitea", &dests)
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
        assert!(newest(&s, "gitea", &dests).await.expect("read").is_none());
    }
}
