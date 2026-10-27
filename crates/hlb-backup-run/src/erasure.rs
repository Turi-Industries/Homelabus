//! Proving a destination cannot be erased: a witness written with the destination's
//! own credential, then an attempt — with that same credential — to delete it.
//! [`hlb_backup::erasure`] says what each answer means; this makes the calls.

use hlb_backup::erasure::{self, Erasure, Proof, S3Steps};
use hlb_backup::Destination;
use hlb_objstore::s3::{Bucket, Location};
use hlb_secrets::Vault;
use hlb_state::State;

use crate::{credentials, restic_password};

/// The tag of a proof's witness snapshot: no `app:` tag, so no restore ever lists it.
const WITNESS_TAG: &str = "kind:witness";

/// Where to connect to an endpoint from where this runs: an S3 on the cluster's overlay
/// (`garage:3900`) does not resolve on a node.
pub type Reach<'a> = &'a (dyn Fn(&str) -> String + Sync);

/// Proves `d`, and records what was found.
pub async fn prove(
    state: &State,
    vault: &Vault,
    network: &str,
    reach: Reach<'_>,
    d: &Destination,
) -> Erasure {
    let found = match erasure::proof_for(d) {
        Proof::Path => erasure::path(),
        Proof::Rest => rest(state, vault, network, d)
            .await
            .unwrap_or_else(|why| Erasure::Unproven { why }),
        Proof::S3 => s3(state, vault, reach, d)
            .await
            .unwrap_or_else(|why| Erasure::Unproven { why }),
    };
    // Recorded whatever it found: a destination proved erasable is said so until it is
    // proved otherwise, not forgotten.
    let _ = state
        .record_destination_proof(&d.name, &d.location, found.verdict(), found.detail(), now())
        .await;
    found
}

/// A witness snapshot, then `restic forget` of it.
async fn rest(
    state: &State,
    vault: &Vault,
    network: &str,
    d: &Destination,
) -> Result<Erasure, String> {
    let password = restic_password(state, vault)
        .await
        .map_err(|e| e.to_string())?;
    let (runner, location) = d.runner(Some(network));
    let repo = hlb_backup::Repository::new(runner, location, password);
    repo.init().await.map_err(|e| e.to_string())?;
    // A file every restic container has: the witness is its being there, not its
    // content.
    let witness = repo
        .backup("/etc/hostname", &[WITNESS_TAG])
        .await
        .map_err(|e| format!("the witness could not be written: {e}"))?;
    let forget = repo
        .forget_snapshot(&witness)
        .await
        .map_err(|e| e.to_string());
    Ok(erasure::rest(forget, &witness))
}

/// A witness object, then a delete of the very version it was given, then a read of
/// that version.
async fn s3(
    state: &State,
    vault: &Vault,
    reach: Reach<'_>,
    d: &Destination,
) -> Result<Erasure, String> {
    let creds = credentials(state, vault, d)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("\"{}\" has no credentials in the vault", d.name))?;
    let (access, secret) = creds
        .split_once(':')
        .ok_or("unreadable credentials, expected access_key:secret_key")?;
    let mut location = Location::parse(&d.location)
        .ok_or_else(|| format!("\"{}\" is not an S3 location restic reads", d.location))?;
    location.endpoint = reach(&location.endpoint);
    let witness = location.key(&format!("hlb-witness/{}", now()));
    let bucket = Bucket::connect(location, access, secret)
        .await
        .map_err(|e| e.to_string())?;

    let mut steps = S3Steps {
        versioning: bucket.versioning().await.ok(),
        ..S3Steps::default()
    };
    let put = bucket
        .put(&witness, b"Homelabus: a backup destination's proof")
        .await
        .map_err(|e| e.to_string())?;
    steps.put = Some((put.status, put.version_id.clone()));
    if let (true, Some(version)) = ((200..300).contains(&put.status), &put.version_id) {
        let delete = bucket
            .delete(&witness, Some(version))
            .await
            .map_err(|e| e.to_string())?;
        steps.delete_version = Some(delete.status);
        steps.get_version = bucket
            .get(&witness, Some(version))
            .await
            .ok()
            .map(|r| r.status);
    }
    // Hidden from a listing, the witness kept as a version: what a delete does where
    // versions are kept, and the end of it where they are not.
    let _ = bucket.delete(&witness, None).await;
    Ok(erasure::s3(&steps, &witness))
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default()
}
