//! Filesystem snapshots: ZFS and btrfs.
//!
//! ## What this brings, and what it does not
//!
//! A ZFS or btrfs snapshot is **near instantaneous** and makes a rollback take minutes
//! where restic takes hours. It is the right tool for the logical incident: an update
//! that goes wrong, a manipulation you regret.
//!
//! 🔴 **It is NOT a backup**, and confusing the two is the costliest trap. A snapshot
//! lives on the same pool as the data: the disk dies, the snapshot dies with it. It
//! protects against **nothing** that makes you lose a disk.
//!
//! | | Protects against | Does not protect against |
//! |---|---|---|
//! | Snapshot | logical error, failed update | disk loss, fire, theft |
//! | restic | everything above | nothing (but slow) |
//!
//! The two complement each other, neither replaces the other. The PLAN puts it as "to
//! be combined with restic, not to replace it".
//!
//! ## 🔴 Why this command never deletes anything
//!
//! Automatic snapshot rotation is tempting — they take space, and ZFS does it happily.
//! But a snapshot deleted at the wrong moment loses exactly the rollback point you were
//! after, and the mistake only shows when you need it.
//!
//! This command creates and lists. Deletion stays a human decision, with `zfs destroy`
//! or `btrfs subvolume delete` in front of your eyes.

use crate::{Error, Result};

/// The path's filesystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Filesystem {
    Zfs,
    Btrfs,
}

impl Filesystem {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Zfs => "zfs",
            Self::Btrfs => "btrfs",
        }
    }
}

/// An existing snapshot.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Snapshot {
    /// Full name, as the tool returns it.
    pub name: String,
    /// What follows the `@` (ZFS) or the last `/` (btrfs).
    pub label: String,
}

/// A snapshot's name, timestamped.
///
/// ⚠️ A lexicographically sortable format, like the base backups and the dumps: that is
/// what lets you find the most recent one without parsing a date.
///
/// 🔴 The characters are deliberately restricted. ZFS refuses `:` in a snapshot name,
/// and an `@` would make the name ambiguous — the tool would fail on a message that
/// talks about syntax without saying which character is the problem.
pub fn snapshot_label(pattern: &str, at: i64) -> Result<String> {
    if pattern.is_empty() || pattern.len() > 40 {
        return Err(Error::Unexpected(format!(
            "pattern \"{pattern}\": 1 to 40 characters"
        )));
    }
    if !pattern
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(Error::Unexpected(format!(
            "pattern \"{pattern}\": only alphanumeric characters, \"-\" and \"_\" are \
             allowed. ZFS refuses \":\" and \"@\" in a snapshot name, and then fails on \
             a message that does not say which character is the problem."
        )));
    }

    let (y, m, d, hh, mm, ss) = crate::pitr::civil_public(at);
    Ok(format!(
        "hlb-{pattern}-{y:04}{m:02}{d:02}T{hh:02}{mm:02}{ss:02}Z"
    ))
}

/// Detects a path's filesystem.
///
/// ⚠️ `df -T` does not exist on macOS and BSD; `stat -f` does not produce the same
/// output on Linux. So we ask the tools themselves, which know how to answer for their
/// own volumes — and no answer means "neither one nor the other", which is the useful
/// information.
pub async fn detect(path: &str) -> Option<Filesystem> {
    // ZFS: `zfs list -H -o name <path>` answers if the path is a dataset.
    if let Ok(o) = tokio::process::Command::new("zfs")
        .args(["list", "-H", "-o", "name", path])
        .output()
        .await
    {
        if o.status.success() {
            return Some(Filesystem::Zfs);
        }
    }

    if let Ok(o) = tokio::process::Command::new("btrfs")
        .args(["subvolume", "show", path])
        .output()
        .await
    {
        if o.status.success() {
            return Some(Filesystem::Btrfs);
        }
    }
    None
}

/// The creation command, without running it.
///
/// Separated from execution so it can be tested: this is the part where a syntax error
/// costs you a snapshot that does not exist while you believe it was taken.
pub fn create_command(fs: Filesystem, dataset: &str, label: &str) -> Vec<String> {
    match fs {
        // `-r`: recursive. A parent dataset without its children gives a partial
        // snapshot — and the whole tree is exactly what we want to freeze at once.
        Filesystem::Zfs => vec![
            "zfs".into(),
            "snapshot".into(),
            "-r".into(),
            format!("{dataset}@{label}"),
        ],
        // btrfs: `-r` here means "read-only", which is different but just as desirable
        // — a writable snapshot is no longer a rollback point.
        Filesystem::Btrfs => vec![
            "btrfs".into(),
            "subvolume".into(),
            "snapshot".into(),
            "-r".into(),
            dataset.into(),
            format!("{dataset}/.snapshots/{label}"),
        ],
    }
}

/// Creates the snapshot.
pub async fn create(fs: Filesystem, dataset: &str, label: &str) -> Result<String> {
    let cmd = create_command(fs, dataset, label);

    // btrfs requires the destination directory to exist.
    if fs == Filesystem::Btrfs {
        let _ = tokio::fs::create_dir_all(format!("{dataset}/.snapshots")).await;
    }

    let out = tokio::process::Command::new(&cmd[0])
        .args(&cmd[1..])
        .output()
        .await
        .map_err(|e| Error::Unexpected(format!("{} not found: {e}", cmd[0])))?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        return Err(Error::Unexpected(explain(fs, &stderr)));
    }

    Ok(label.to_string())
}

/// Enriches the errors whose raw message points nowhere.
fn explain(fs: Filesystem, stderr: &str) -> String {
    let b = stderr.to_lowercase();

    if b.contains("permission denied") || b.contains("not authorized") {
        return format!(
            "{stderr}\n\n\
             🔴 Creating a snapshot needs root, or a delegation:\n\
             \x20   zfs allow <user> snapshot,mount <pool>"
        );
    }
    if b.contains("dataset does not exist") || b.contains("not a subvolume") {
        return format!(
            "{stderr}\n\n\
             The path is not a {} — a snapshot can only cover a dataset ({}) or a\n\
             subvolume (btrfs), never a plain directory.",
            fs.as_str(),
            if fs == Filesystem::Zfs {
                "ZFS"
            } else {
                "btrfs"
            }
        );
    }
    if b.contains("already exists") {
        return format!(
            "{stderr}\n\n\
             A snapshot already carries this name. We NEVER overwrite: that would\n\
             destroy the rollback point you believe you are creating."
        );
    }
    stderr.to_string()
}

/// The listing command.
pub fn list_command(fs: Filesystem, dataset: &str) -> Vec<String> {
    match fs {
        Filesystem::Zfs => vec![
            "zfs".into(),
            "list".into(),
            "-H".into(),
            "-t".into(),
            "snapshot".into(),
            "-o".into(),
            "name".into(),
            "-s".into(),
            "creation".into(),
            "-r".into(),
            dataset.into(),
        ],
        Filesystem::Btrfs => vec![
            "btrfs".into(),
            "subvolume".into(),
            "list".into(),
            "-s".into(),
            dataset.into(),
        ],
    }
}

/// The snapshots Homelabus created.
///
/// 🔴 We list **only our own** (the `hlb-` prefix). Showing the NAS's snapshots, or
/// another tool's, would suggest they can be deleted — and a snapshot deleted at the
/// wrong moment loses exactly the rollback point you were after.
pub fn parse_list(fs: Filesystem, output: &str) -> Vec<Snapshot> {
    let mut out: Vec<Snapshot> = output
        .lines()
        .filter_map(|l| {
            let l = l.trim();
            if l.is_empty() {
                return None;
            }
            let label = match fs {
                Filesystem::Zfs => l.split('@').nth(1)?,
                // `btrfs subvolume list` returns "ID 256 gen 9 top level 5 path <path>".
                Filesystem::Btrfs => l.rsplit('/').next()?,
            };
            label.starts_with("hlb-").then(|| Snapshot {
                name: l.to_string(),
                label: label.to_string(),
            })
        })
        .collect();

    // The timestamped format sorts chronologically: the most recent last.
    out.sort();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const J0: i64 = 1_786_881_600;

    #[test]
    fn labels_sort_chronologically() {
        // Finding the most recent rollback point must be a sort on names.
        let a = snapshot_label("before-maj", J0).expect("label");
        let b = snapshot_label("before-maj", J0 + 3600).expect("label");
        assert_eq!(a, "hlb-before-maj-20260816T120000Z");
        assert!(a < b);
    }

    #[test]
    fn characters_zfs_refuses_are_rejected_early() {
        // 🔴 ZFS refuses ":" and "@", and fails on a syntax message that does not say
        // which character is the problem.
        assert!(snapshot_label("before:maj", J0).is_err());
        assert!(snapshot_label("before@maj", J0).is_err());
        assert!(snapshot_label("with space", J0).is_err());
        assert!(snapshot_label("", J0).is_err());

        let e = snapshot_label("a:b", J0).unwrap_err().to_string();
        assert!(e.contains("ZFS refuses"), "{e}");
    }

    #[test]
    fn ordinary_labels_pass() {
        assert!(snapshot_label("before-maj", J0).is_ok());
        assert!(snapshot_label("avant_maj_gitea", J0).is_ok());
        assert!(snapshot_label("test123", J0).is_ok());
    }

    #[test]
    fn the_zfs_snapshot_is_recursive() {
        // ⚠️ A parent dataset without its children gives a PARTIAL snapshot, while the
        // whole tree is exactly what we want to freeze at once.
        let c = create_command(Filesystem::Zfs, "tank/hlb", "hlb-x-20260816T120000Z");
        assert!(c.contains(&"-r".to_string()), "{c:?}");
        assert_eq!(c.last().expect("target"), "tank/hlb@hlb-x-20260816T120000Z");
    }

    #[test]
    fn the_btrfs_snapshot_is_read_only() {
        // A writable snapshot is no longer a rollback point: you can unintentionally
        // destroy the very thing you meant to come back to.
        let c = create_command(Filesystem::Btrfs, "/data", "hlb-x-20260816T120000Z");
        assert!(c.contains(&"-r".to_string()), "{c:?}");
        assert!(c.last().expect("target").contains(".snapshots/"), "{c:?}");
    }

    #[test]
    fn the_two_filesystems_do_not_share_a_syntax() {
        // Transposing one's command to the other would fail — or worse, would create
        // something unexpected.
        let z = create_command(Filesystem::Zfs, "tank/x", "l");
        let b = create_command(Filesystem::Btrfs, "/x", "l");
        assert_ne!(z[0], b[0]);
        assert!(z.iter().any(|a| a.contains('@')));
        assert!(!b.iter().any(|a| a.contains('@')));
    }

    #[test]
    fn only_our_own_snapshots_are_listed() {
        // 🔴 Showing the NAS's would suggest they can be deleted.
        let output = "tank/hlb@hlb-before-maj-20260816T120000Z\n\
                      tank/hlb@autoznap_2026-08-16_12.00.00_hourly\n\
                      tank/hlb@hlb-before-maj-20260817T120000Z\n";
        let v = parse_list(Filesystem::Zfs, output);

        assert_eq!(v.len(), 2, "{v:?}");
        assert!(v.iter().all(|s| s.label.starts_with("hlb-")));
        // The most recent last.
        assert!(v[0].label < v[1].label);
    }

    #[test]
    fn an_empty_listing_is_not_an_error() {
        assert!(parse_list(Filesystem::Zfs, "").is_empty());
        assert!(parse_list(Filesystem::Btrfs, "\n\n").is_empty());
    }

    #[test]
    fn a_permission_error_says_how_to_delegate() {
        let m = explain(Filesystem::Zfs, "cannot create snapshot: permission denied");
        assert!(m.contains("zfs allow"), "{m}");
    }

    #[test]
    fn a_plain_directory_is_explained() {
        // The raw error says "dataset does not exist", which sends you looking for a
        // typo when the path is simply a plain directory.
        let m = explain(Filesystem::Zfs, "cannot open 'x': dataset does not exist");
        assert!(m.contains("plain directory"), "{m}");
    }

    #[test]
    fn an_existing_snapshot_is_never_overwritten() {
        let m = explain(Filesystem::Zfs, "snapshot already exists");
        assert!(m.contains("rollback point"), "{m}");
    }
}
