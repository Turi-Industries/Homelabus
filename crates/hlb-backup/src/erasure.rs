//! Whether whoever holds a destination's credential can erase the backups on it.
//!
//! The copy that matters after an intrusion is the one the intruder could not reach:
//! they hold the cluster, so they hold every credential it backs up with. A
//! destination counts as safe only once a witness written there with that credential
//! has outlived an attempt, with the same credential, to delete it — "the policy says
//! so" proves nothing, and a policy is one line away from saying otherwise.
//!
//! | Destination | What is tried | Safe when |
//! |---|---|---|
//! | a path | nothing | never: the machine's root erases it |
//! | `rest:` | `restic forget` of a witness snapshot | the server refuses it (`--append-only`) |
//! | `s3:` | deleting the VERSION of a witness object | the bucket is versioned and the delete is refused |
//!
//! On a versioned bucket an ordinary delete is never refused: it hides the object
//! behind a marker and keeps it, which is what makes the bucket safe — and why restic's
//! own `forget` says nothing there.

use crate::destination::Destination;

/// What the proof found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Erasure {
    /// The witness outlived the attempt to delete it.
    Kept { how: String },
    /// Whoever holds the credential — or the machine — can erase it.
    Erasable { why: String },
    /// The proof could not run to its end: nothing is known.
    Unproven { why: String },
}

impl Erasure {
    /// The word stored, and read back by [`Erasure::from_stored`].
    ///
    /// ⚠️ A stored value: renaming one makes every proof already recorded unreadable.
    pub fn verdict(&self) -> &'static str {
        match self {
            Self::Kept { .. } => "kept",
            Self::Erasable { .. } => "erasable",
            Self::Unproven { .. } => "unproven",
        }
    }

    pub fn detail(&self) -> &str {
        match self {
            Self::Kept { how } => how,
            Self::Erasable { why } | Self::Unproven { why } => why,
        }
    }

    pub fn from_stored(verdict: &str, detail: &str) -> Self {
        let detail = detail.to_string();
        match verdict {
            "kept" => Self::Kept { how: detail },
            "erasable" => Self::Erasable { why: detail },
            _ => Self::Unproven { why: detail },
        }
    }

    pub fn describe(&self) -> String {
        match self {
            Self::Kept { how } => format!("cannot be erased with its credential — {how}"),
            Self::Erasable { why } => format!("⚠️ can be erased — {why}"),
            Self::Unproven { why } => format!("not proven — {why}"),
        }
    }
}

/// How a destination is proved, read from its location.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proof {
    /// Nothing to try: a directory is the machine's.
    Path,
    Rest,
    S3,
}

pub fn proof_for(d: &Destination) -> Proof {
    if d.is_s3() {
        Proof::S3
    } else if d.location.trim_start().starts_with("rest:") {
        Proof::Rest
    } else {
        Proof::Path
    }
}

/// A directory: not tried, since whoever is root where it is mounted erases it.
pub fn path() -> Erasure {
    Erasure::Erasable {
        why: "a directory: whoever is root on the machine holding it erases it — \
              a restic REST server in --append-only mode, or a versioned S3 bucket, is not"
            .into(),
    }
}

/// `restic forget` of a witness snapshot: refused, the server keeps what it was given.
pub fn rest(forget: Result<(), String>, witness: &str) -> Erasure {
    match forget {
        Ok(()) => Erasure::Erasable {
            why: format!(
                "the witness snapshot {} was deleted: start the REST server with \
                 --append-only",
                short(witness)
            ),
        },
        // rest-server answers a deletion it refuses with 403 (0.13.0, tried), which
        // restic prints as `unexpected HTTP response (403): 403 Forbidden`. 🔴 That
        // shape, never a bare "403": the error names the witness by its hex id, and an
        // id holding "403" made any failure — a lock held — read as the server's refusal.
        Err(e) if e.contains("response (403)") || e.contains("403 Forbidden") => Erasure::Kept {
            how: format!(
                "the server refused to delete the witness snapshot {}",
                short(witness)
            ),
        },
        Err(e) => Erasure::Unproven {
            why: format!("deleting the witness failed for another reason: {e}"),
        },
    }
}

/// What the S3 calls of a proof answered, in order; `None` for a step not reached.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct S3Steps {
    /// `GetBucketVersioning`: its status code, and `<Status>` if any.
    pub versioning: Option<(u16, Option<String>)>,
    /// Writing the witness: its status code, and the version id the bucket gave it.
    pub put: Option<(u16, Option<String>)>,
    /// Deleting that version.
    pub delete_version: Option<u16>,
    /// Reading that version back.
    pub get_version: Option<u16>,
}

pub fn s3(steps: &S3Steps, witness: &str) -> Erasure {
    let lifecycle = "a lifecycle rule expiring old versions would still erase them: \
                     refuse s3:PutLifecycleConfiguration to this credential (not tried — \
                     trying writes a rule)";
    let Some((put, version)) = &steps.put else {
        return Erasure::Unproven {
            why: "the witness was never written".into(),
        };
    };
    if !(200..300).contains(put) {
        return Erasure::Unproven {
            why: format!("writing the witness {witness} was answered {put}"),
        };
    }
    // What the bucket says of itself first: Garage gives every object a version id and
    // keeps none of them.
    let unversioned = match &steps.versioning {
        Some((200, Some(s))) if s == "Enabled" => None,
        Some((200, Some(s))) => Some(format!("versioning is {s}")),
        Some((200 | 501, None)) => Some("the bucket keeps no versions".to_string()),
        // Not allowed to ask: the witness's version answers instead.
        _ => version
            .is_none()
            .then(|| "the witness got no version".to_string()),
    };
    if let Some(said) = unversioned {
        return Erasure::Erasable {
            why: format!("{said}: a deletion is final — and this credential writes, so it deletes"),
        };
    }
    let Some(version) = version else {
        return Erasure::Unproven {
            why: "the bucket says it is versioned, and the witness got no version".into(),
        };
    };
    match (steps.delete_version, steps.get_version) {
        (Some(d), Some(200)) if (200..300).contains(&d) => Erasure::Unproven {
            why: format!("deleting the witness's version was answered {d}, and it is still there"),
        },
        (Some(d), _) if (200..300).contains(&d) => Erasure::Erasable {
            why: format!(
                "the credential deleted the witness's version {version}: whoever holds it \
                 erases every version — DENY it s3:DeleteObjectVersion (on MinIO, leaving \
                 it out is not enough: s3:DeleteObject deletes versions too)"
            ),
        },
        (Some(403), Some(200)) => Erasure::Kept {
            how: format!(
                "versioned, and deleting the witness's version was refused; {witness} is \
                 still there. ⚠️ {lifecycle}"
            ),
        },
        (Some(403), other) => Erasure::Unproven {
            why: format!("the witness's version could not be read back ({other:?})"),
        },
        (other, _) => Erasure::Unproven {
            why: format!("deleting the witness's version was answered {other:?}"),
        },
    }
}

fn short(id: &str) -> &str {
    &id[..id.len().min(8)]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dest(location: &str) -> Destination {
        Destination {
            name: "d".into(),
            location: location.into(),
            classes: Vec::new(),
            credentials_secret: None,
        }
    }

    #[test]
    fn each_kind_of_destination_has_its_own_proof() {
        assert_eq!(proof_for(&dest("/mnt/nas/restic")), Proof::Path);
        assert_eq!(proof_for(&dest("rest:http://nas:8000/")), Proof::Rest);
        assert_eq!(proof_for(&dest("s3:http://garage:3900/b")), Proof::S3);
        assert!(matches!(path(), Erasure::Erasable { .. }));
    }

    #[test]
    fn a_rest_server_is_safe_only_when_it_refused() {
        assert!(matches!(rest(Ok(()), "abc"), Erasure::Erasable { .. }));
        // What restic 0.19.1 printed against rest-server 0.13.0 --append-only.
        let refused = "Remove(<snapshot/17948f6013>) failed: unexpected HTTP response \
                       (403): 403 Forbidden";
        assert!(matches!(
            rest(Err(refused.into()), "abc"),
            Erasure::Kept { .. }
        ));
        assert!(matches!(
            rest(Err("dial tcp: connection refused".into()), "abc"),
            Erasure::Unproven { .. }
        ));
    }

    #[test]
    fn a_witness_id_holding_403_is_not_a_refusal() {
        // Found by review: the error carries the witness's id, and "403" anywhere in it
        // recorded a destination as out of reach — then never pruned, never warned.
        let witness = "7a403b".to_string() + &"0".repeat(58);
        let locked = format!(
            "restic forget {witness} failed: unable to create lock in backend: repository \
             is already locked by PID 4031 on deb1"
        );
        assert!(matches!(
            rest(Err(locked), &witness),
            Erasure::Unproven { .. }
        ));
    }

    #[test]
    fn a_bucket_is_safe_only_when_a_version_outlived_its_deletion() {
        let w = "hlb-witness/1";
        let versioned = |delete, get| S3Steps {
            versioning: Some((200, Some("Enabled".into()))),
            put: Some((200, Some("v1".into()))),
            delete_version: Some(delete),
            get_version: Some(get),
        };
        assert!(matches!(s3(&versioned(403, 200), w), Erasure::Kept { .. }));
        assert!(matches!(
            s3(&versioned(204, 404), w),
            Erasure::Erasable { .. }
        ));
        assert!(matches!(
            s3(&versioned(403, 404), w),
            Erasure::Unproven { .. }
        ));
        // Accepted and still there: the store ignored the version it was given.
        assert!(matches!(
            s3(&versioned(204, 200), w),
            Erasure::Unproven { .. }
        ));
        // Garage 2.4.1: a version id on the witness, and no versioning — a version id
        // proves nothing.
        let garage = S3Steps {
            versioning: Some((200, None)),
            put: Some((200, Some("8111796e".into()))),
            delete_version: Some(204),
            get_version: Some(404),
        };
        let e = s3(&garage, w);
        assert!(matches!(e, Erasure::Erasable { .. }), "{e:?}");
        assert!(e.detail().contains("keeps no versions"), "{e:?}");
        let suspended = S3Steps {
            versioning: Some((200, Some("Suspended".into()))),
            put: Some((200, None)),
            ..S3Steps::default()
        };
        assert!(matches!(s3(&suspended, w), Erasure::Erasable { .. }));
        // Not allowed to ask the bucket: the witness's version decides.
        let unasked = S3Steps {
            versioning: Some((403, None)),
            ..versioned(403, 200)
        };
        assert!(matches!(s3(&unasked, w), Erasure::Kept { .. }));
        assert!(matches!(
            s3(&S3Steps::default(), w),
            Erasure::Unproven { .. }
        ));
    }

    #[test]
    fn a_stored_verdict_reads_back_as_itself() {
        for e in [
            Erasure::Kept { how: "a".into() },
            Erasure::Erasable { why: "b".into() },
            Erasure::Unproven { why: "c".into() },
        ] {
            assert_eq!(Erasure::from_stored(e.verdict(), e.detail()), e);
        }
    }
}
