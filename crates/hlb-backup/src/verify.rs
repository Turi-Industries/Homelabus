//! Restore verification.
//!
//! > "An untested backup is not a backup."
//!
//! The trap is believing you verified something when you proved nothing:
//!
//! | What is often done | What it proves |
//! |---|---|
//! | The snapshot has an id | restic answered |
//! | `restic check` passes | the metadata is coherent |
//! | `restic check --read-data` passes | the blocks are readable and uncorrupted |
//! | **Restore and compare** | **the data really comes back** |
//!
//! Only the last line answers the question you are actually asking. So that is the one
//! implemented here: restore into a disposable space, then compare what came out to what
//! the snapshot claims to contain.
//!
//! ## 🔴 What a size comparison does NOT see
//!
//! Counting files and bytes catches a missing or truncated file. It **does not see** a
//! flipped bit on disk: the file is still the same size, the count adds up, and the
//! verification announces "compliant" on a corrupted backup.
//!
//! That is exactly the failure we fear — silent, progressive, and invisible until the
//! day of the restore. Hence re-reading a **sample of blocks**
//! (`restic check --read-data-subset`) on top of the comparison. We do not re-read all
//! of it every time: on a repository of several hundred gigabytes that would take hours
//! and nobody would ever run the verification again.

use crate::restic::{Repository, Runner};
use crate::Result;

/// What a verification established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verification {
    pub snapshot_id: String,
    /// Number of files actually restored.
    pub files_restored: u64,
    /// Bytes actually restored.
    pub bytes_restored: u64,
    /// What the snapshot announced.
    pub files_expected: u64,
    pub bytes_expected: u64,
    /// Re-read of a sample of blocks. `None` = not performed.
    ///
    /// Kept apart from the rest because it answers a different question: the comparison
    /// says "everything came back", this one says "what came back is not rotten".
    pub data_checked: Option<DataCheck>,
}

/// Result of re-reading a sample of blocks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataCheck {
    /// Proportion re-read, as passed to restic ("5%", "1/10"…).
    pub subset: String,
    pub ok: bool,
    pub detail: Option<String>,
}

impl Verification {
    /// Does the restore match what the snapshot announced?
    ///
    /// 🔴 A failed block re-read fails the whole verification, even if the counts add
    /// up. Files all present and all of the right size, but corrupted, do not amount to
    /// a backup.
    pub fn matches(&self) -> bool {
        self.files_restored == self.files_expected
            && self.bytes_restored == self.bytes_expected
            && self.data_checked.as_ref().is_none_or(|d| d.ok)
    }

    pub fn describe(&self) -> String {
        // Corruption first: it is the gravest diagnosis, and the only one the counts
        // would not show.
        if let Some(d) = self.data_checked.as_ref().filter(|d| !d.ok) {
            return format!(
                "🔴 CORRUPTED — {} files / {} bytes restored correctly, but re-reading \
                 {} failed: {}",
                self.files_restored,
                self.bytes_restored,
                d.subset,
                d.detail.as_deref().unwrap_or("unreadable blocks")
            );
        }

        if self.matches() {
            let extra = match &self.data_checked {
                Some(d) => format!(", {} of blocks re-read without error", d.subset),
                // Say when we did NOT verify: without that, "compliant" suggests a
                // guarantee we never gave.
                None => ", without block re-reading".to_string(),
            };
            format!(
                "{} files / {} bytes restored, matching the snapshot{extra}",
                self.files_restored, self.bytes_restored
            )
        } else {
            format!(
                "DISCREPANCY — restored {} files / {} bytes, the snapshot announced \
                 {} / {}",
                self.files_restored, self.bytes_restored, self.files_expected, self.bytes_expected
            )
        }
    }
}

/// A snapshot's statistics, as restic reports them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stats {
    pub files: u64,
    pub bytes: u64,
}

impl<R: Runner> Repository<R> {
    /// What the snapshot claims to contain: **regular files only**.
    ///
    /// ⚠️ We do not use `restic stats`: its `total_file_count` also counts directories
    /// (a backup of 2 files across 2 levels announces 4). A verification built on it
    /// would compare apples and oranges.
    ///
    /// `restic ls --json` distinguishes the types, which gives a count comparable to
    /// what is really found on disk after a restore.
    pub async fn stats(&self, snapshot: &str) -> Result<Stats> {
        let out = self.exec_public(&["ls", snapshot, "--json"]).await?;

        let mut s = Stats { files: 0, bytes: 0 };
        // JSON output line by line: one object per entry.
        for line in out.stdout.lines() {
            let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
                continue;
            };
            if v.get("type").and_then(|t| t.as_str()) == Some("file") {
                s.files += 1;
                s.bytes += v.get("size").and_then(|x| x.as_u64()).unwrap_or(0);
            }
        }
        Ok(s)
    }

    /// Checks the integrity **and the real readability** of a subset of the data.
    ///
    /// `restic check` alone only reads the metadata: a corrupted block on disk would go
    /// unnoticed. `--read-data-subset` re-reads a sample of it, which catches silent
    /// corruption without re-reading the whole repository every time.
    pub async fn check_data(&self, subset: &str) -> Result<()> {
        self.exec_public(&["check", "--read-data-subset", subset])
            .await?;
        Ok(())
    }
}

/// Restores a snapshot into a disposable space and compares it to the announced
/// content.
///
/// `count_target` must return the `(files, bytes)` really present at the restored
/// location — the caller is the one that knows how to inspect that space (Docker volume,
/// local path, remote mount).
pub async fn verify_by_restore<R, F, Fut>(
    repo: &Repository<R>,
    snapshot: &str,
    scratch: &str,
    count_target: F,
) -> Result<Verification>
where
    R: Runner,
    F: FnOnce(String) -> Fut,
    Fut: std::future::Future<Output = Result<(u64, u64)>>,
{
    let expected = repo.stats(snapshot).await?;

    repo.restore(snapshot, scratch).await?;
    let (files, bytes) = count_target(scratch.to_string()).await?;

    let v = Verification {
        snapshot_id: snapshot.to_string(),
        files_restored: files,
        bytes_restored: bytes,
        files_expected: expected.files,
        bytes_expected: expected.bytes,
        data_checked: None,
    };

    if v.matches() {
        tracing::info!(snapshot, "{}", v.describe());
    } else {
        // Never pass over this in silence: it is exactly the case where you believed
        // you had a backup and you do not.
        tracing::error!(snapshot, "{}", v.describe());
    }
    Ok(v)
}

/// The default proportion of blocks re-read.
///
/// 5 % catches diffuse corruption over a few successive verifications, without making
/// each pass last long enough that you stop running them. Re-reading 100 % every time is
/// the best way to end up re-reading nothing at all.
pub const DEFAULT_SUBSET: &str = "5%";

/// Adds a block-sample re-read to a verification.
///
/// Separated from `verify_by_restore` so the caller can choose: on a remote repository
/// billed by transfer, re-reading blocks costs money.
pub async fn with_data_check<R: Runner>(
    mut v: Verification,
    repo: &Repository<R>,
    subset: &str,
) -> Verification {
    let r = repo.check_data(subset).await;

    v.data_checked = Some(DataCheck {
        subset: subset.to_string(),
        ok: r.is_ok(),
        detail: r.err().map(|e| e.to_string()),
    });

    if !v.matches() {
        tracing::error!(snapshot = %v.snapshot_id, "{}", v.describe());
    }
    v
}

/// The image used for verification.
///
/// The same one as for backups, deliberately: it is already present on the machine, it
/// embeds busybox (`find`, `stat`, `awk`), and therefore adds no download to an already
/// slow operation.
const IMAGE: &str = crate::images::RESTIC;

/// Verifies a snapshot end to end: a real restore, then a comparison.
///
/// ## 🔴 Why a Docker volume and not a temporary directory
///
/// On macOS (colima, Docker Desktop), the host's temp directory **is not shared with the
/// Docker VM**. A `tempfile::tempdir()` mounted into the container would appear empty
/// there: restic would write inside the VM, the host would see nothing, the count would
/// fall to zero and you would conclude the backup was empty — on a perfectly healthy
/// backup.
///
/// The disposable space is therefore a **Docker volume**, and the counting happens in a
/// container, on the same side of the boundary as the restored files.
pub async fn verify_snapshot(
    repo_location: &str,
    password: &str,
    snapshot: &str,
) -> Result<Verification> {
    let dest = crate::destination::Destination {
        name: "default".into(),
        location: repo_location.to_string(),
        classes: vec![crate::destination::Class::Bulky],
        credentials_secret: None,
    };
    verify_snapshot_on(&dest, None, None, password, snapshot).await
}

/// [`verify_snapshot`], read from the DESTINATION that holds the snapshot — local, S3
/// or REST, with its credentials.
///
/// 🔴 A snapshot lives in the repository it was written to: asked of `--backup-repo`,
/// one on the off-site was "not found", and recorded as a failed verification of
/// backups that were fine. `credentials` is the secret's VALUE, out of the vault.
pub async fn verify_snapshot_on(
    dest: &crate::destination::Destination,
    credentials: Option<&str>,
    network: Option<&str>,
    password: &str,
    snapshot: &str,
) -> Result<Verification> {
    let env = dest.env(credentials)?;
    // A unique name: two concurrent verifications must not mix, and a reused volume
    // would carry the leftovers of the previous one — which would inflate the count and
    // let an incomplete backup pass.
    let volume = format!("hlb-verif-{}", token());
    docker(&["volume", "create", &volume]).await?;

    let (runner, location) = dest.runner(network);
    let repo = Repository::new(
        runner.mount(&volume, "/verif"),
        location,
        password.to_string(),
    )
    .extra_env(env);
    let result = check_in(&volume, &repo, snapshot).await;

    // Unconditional cleanup: a failure must not leave behind a volume carrying a
    // cleartext copy of the data.
    if let Err(e) = docker(&["volume", "rm", "-f", &volume]).await {
        tracing::warn!(volume, "verification volume not removed: {e}");
    }
    result
}

async fn check_in<R: Runner>(
    volume: &str,
    repo: &Repository<R>,
    snapshot: &str,
) -> Result<Verification> {
    let vol = volume.to_string();
    let v = verify_by_restore(repo, snapshot, "/verif", move |_| async move {
        count_in_volume(&vol).await
    })
    .await?;

    // The comparison does not see a flipped bit: the file keeps its size.
    Ok(with_data_check(v, repo, DEFAULT_SUBSET).await)
}

/// Counts the restored regular files, from inside a container.
async fn count_in_volume(volume: &str) -> Result<(u64, u64)> {
    // `-exec ... +` groups the arguments: a `\;` would launch one `stat` per file,
    // which would make verifying a large volume endless.
    let script = "find /verif -type f -exec stat -c %s {} + 2>/dev/null \
                  | awk '{s+=$1} END {print NR, s+0}'";

    let out = docker(&[
        "run",
        "--rm",
        "--entrypoint",
        "sh",
        "-v",
        &format!("{volume}:/verif"),
        IMAGE,
        "-c",
        script,
    ])
    .await?;

    parse_count(&out)
}

/// Parses the "<files> <bytes>" output of the counting script.
fn parse_count(output: &str) -> Result<(u64, u64)> {
    let last = output.lines().rfind(|l| !l.trim().is_empty()).unwrap_or("");

    let mut it = last.split_whitespace();
    match (
        it.next().and_then(|v| v.parse::<u64>().ok()),
        it.next().and_then(|v| v.parse::<u64>().ok()),
    ) {
        (Some(f), Some(o)) => Ok((f, o)),
        // 🔴 Never (0, 0) by default: an unreadable count is not an empty volume.
        // Confusing them would turn a tooling failure into "empty backup", and
        // conversely would mask a genuinely empty backup.
        _ => Err(crate::Error::Unexpected(format!(
            "unreadable count: \"{}\"",
            output.trim()
        ))),
    }
}

async fn docker(args: &[&str]) -> Result<String> {
    let out = tokio::process::Command::new("docker")
        .args(args)
        .output()
        .await
        .map_err(|e| crate::Error::ResticMissing(format!("docker not found: {e}")))?;

    if !out.status.success() {
        return Err(crate::Error::Restic {
            command: format!("docker {}", args.first().unwrap_or(&"")),
            stderr: String::from_utf8_lossy(&out.stderr).trim().to_string(),
        });
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

/// Exposed for the other modules that create disposable volumes.
pub fn public_token() -> String {
    token()
}

/// A unique suffix, with no randomness dependency.
///
/// ⚠️ The timestamp **alone** is not enough: on macOS, `SystemTime::now()` does not have
/// the nanosecond resolution its type announces, and two close calls return the same
/// value. Two verifications started together would then share the same volume — and
/// would count each other's files.
///
/// The counter settles the case within one process, the PID that of two processes
/// started in the same clock tick.
fn token() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);

    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);

    format!(
        "{t:x}-{:x}-{:x}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verification(restored: (u64, u64), expected: (u64, u64)) -> Verification {
        Verification {
            snapshot_id: "abc".into(),
            files_restored: restored.0,
            bytes_restored: restored.1,
            files_expected: expected.0,
            bytes_expected: expected.1,
            data_checked: None,
        }
    }

    fn with_blocks(v: Verification, ok: bool) -> Verification {
        Verification {
            data_checked: Some(DataCheck {
                subset: "5%".into(),
                ok,
                detail: (!ok).then(|| "pack 3f2a corrupted".to_string()),
            }),
            ..v
        }
    }

    #[test]
    fn an_exact_restore_matches() {
        assert!(verification((12, 4096), (12, 4096)).matches());
    }

    #[test]
    fn a_missing_file_is_detected() {
        // The case that matters: the restore "worked" but data is missing.
        let v = verification((11, 4096), (12, 4096));
        assert!(!v.matches());
        assert!(v.describe().contains("DISCREPANCY"), "{}", v.describe());
    }

    #[test]
    fn a_truncated_file_is_detected() {
        // Same number of files, but content missing.
        assert!(!verification((12, 2048), (12, 4096)).matches());
    }

    #[test]
    fn an_empty_restore_is_never_a_success() {
        // 🔴 A restore that produces nothing must above all not pass.
        let v = verification((0, 0), (12, 4096));
        assert!(!v.matches());
        assert!(v.describe().contains("DISCREPANCY"));
    }

    #[test]
    fn the_description_is_readable_in_both_cases() {
        assert!(verification((3, 100), (3, 100))
            .describe()
            .contains("matching"));
        assert!(verification((3, 100), (4, 100))
            .describe()
            .contains("announced"));
    }

    #[test]
    fn identical_sizes_do_not_prove_intact_data() {
        // 🔴 The hole this re-read fills: every file present, every one of the right
        // size, and yet rotten. The counts alone would say "compliant" on an unusable
        // backup.
        let v = with_blocks(verification((12, 4096), (12, 4096)), false);

        assert!(!v.matches(), "corruption must fail the verification");
        assert!(v.describe().contains("CORRUPTED"), "{}", v.describe());
        assert!(v.describe().contains("3f2a"), "the cause must be visible");
    }

    #[test]
    fn a_clean_block_read_is_reported() {
        let v = with_blocks(verification((12, 4096), (12, 4096)), true);
        assert!(v.matches());
        assert!(v.describe().contains("5%"), "{}", v.describe());
    }

    #[test]
    fn a_verification_without_block_reading_says_so() {
        // Without this mention, "compliant" would suggest a guarantee we never gave.
        let v = verification((12, 4096), (12, 4096));
        assert!(v.matches());
        assert!(
            v.describe().contains("without block re-reading"),
            "{}",
            v.describe()
        );
    }

    #[test]
    fn a_missing_file_stays_the_headline_even_with_clean_blocks() {
        // The blocks present can be healthy while others are missing: the "data is
        // missing" diagnosis stays the right one.
        let v = with_blocks(verification((11, 4096), (12, 4096)), true);
        assert!(!v.matches());
        assert!(v.describe().contains("DISCREPANCY"), "{}", v.describe());
    }

    #[test]
    fn the_default_subset_is_a_sample_not_everything() {
        // Re-reading 100 % every time would make verification last long enough that
        // you stop running it.
        assert_eq!(DEFAULT_SUBSET, "5%");
        assert_ne!(DEFAULT_SUBSET, "100%");
    }

    #[test]
    fn a_count_output_is_parsed() {
        assert_eq!(parse_count("2 17\n").expect("parsable"), (2, 17));
        assert_eq!(parse_count("0 0\n").expect("parsable"), (0, 0));
        // A line of noise before the result must not get in the way.
        assert_eq!(
            parse_count("warning: bla\n5 4096\n").expect("parsable"),
            (5, 4096)
        );
    }

    #[test]
    fn an_unreadable_count_is_never_taken_for_an_empty_volume() {
        // 🔴 Returning (0, 0) on unreadable output would turn a tooling failure into
        // "empty backup" — and would mask a genuinely empty backup the day there is one.
        assert!(parse_count("").is_err());
        assert!(parse_count("docker: command not found").is_err());
        assert!(parse_count("2").is_err(), "one field alone is not enough");
    }

    #[test]
    fn scratch_volumes_never_collide() {
        // 🔴 A reused volume would carry the leftovers of the previous verification.
        // The timestamp alone is NOT enough: on macOS, two close calls to
        // `SystemTime::now()` return the same value — this test showed it.
        let tokens: std::collections::BTreeSet<String> = (0..100).map(|_| token()).collect();
        assert_eq!(tokens.len(), 100, "collision between close tokens");
    }
}
