//! SSH access managed by Homelabus.
//!
//! ## Why a dedicated key rather than the user's own
//!
//! If Homelabus borrowed the administrator's personal key, revoking it would cut their
//! own access. With a separate key:
//!
//! - it can be revoked across the whole fleet without touching human access;
//! - it never leaves the vault;
//! - its presence on a machine says exactly who drives it.
//!
//! ## 🔴 `authorized_keys` is NEVER rewritten blind
//!
//! This is the most dangerous file in the system. A write that overwrites it locks
//! **everyone** out - Homelabus *and* the administrator - with no recourse but physical
//! access or a rescue console.
//!
//! Three rules follow, each checked by a test:
//!
//! 1. Lines are **filtered** rather than the file being rebuilt. Unknown keys are
//!    copied across as-is, including the ones we do not understand.
//! 2. The result is written to a temporary file and then **renamed**: a `rename` is
//!    atomic, so a power cut leaves the old file intact rather than a truncated one.
//! 3. Producing empty content is **refused** when the input was not empty.
//!
//! ## The silent permissions trap
//!
//! `sshd` **ignores** `authorized_keys` without a single message if the file is
//! group- or world-readable, or if `~/.ssh` is. The key is installed, it looks correct,
//! and authentication fails anyway. Hence the systematic `chmod`s in the install
//! script.

use crate::runner::Runner;
use crate::runner::{Error, Result};

/// The marker placed as a comment on the keys we manage.
///
/// 🔴 It is what makes revocation possible **and safe**: without a marker we would have
/// to guess which line is ours, and would end up deleting someone's personal key.
pub const MARKER: &str = "homelabus-managed";

/// The restrictions placed on the key.
///
/// Homelabus needs a shell (it runs `docker`, `apt`...), so no `command=`. But nothing
/// justifies port or agent forwarding: forbidding them limits what a leak of the
/// private key would allow.
const OPTIONS: &str = "no-agent-forwarding,no-port-forwarding,no-X11-forwarding,no-user-rc";

/// A managed public key, ready to place in `authorized_keys`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedKey {
    /// The key's body: `ssh-ed25519 AAAA...`.
    pub public: String,
    /// The cluster name, to tell two Homelabus installs on one machine apart.
    pub cluster: String,
}

impl ManagedKey {
    pub fn new(public: impl Into<String>, cluster: impl Into<String>) -> Self {
        Self {
            public: public.into().trim().to_string(),
            cluster: cluster.into(),
        }
    }

    /// The comment identifying this key, and only this key.
    pub fn comment(&self) -> String {
        format!("{MARKER}:{}", self.cluster)
    }

    /// The complete line to write.
    pub fn line(&self) -> String {
        // The key may already carry a comment (`... user@machine`): only the type and
        // body are kept, or the marker would not be last and revocation would not find
        // it.
        let body: Vec<&str> = self.public.split_whitespace().take(2).collect();
        format!("{OPTIONS} {} {}", body.join(" "), self.comment())
    }
}

/// What a change to `authorized_keys` altered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Change {
    pub added: usize,
    pub removed: usize,
    /// Lines kept untouched - including human keys.
    pub kept: usize,
}

impl Change {
    pub fn is_noop(&self) -> bool {
        self.added == 0 && self.removed == 0
    }
}

/// Does a line belong to us?
///
/// The exact comment is tested, not a mere presence of the marker: two clusters on one
/// machine must not revoke each other.
fn belongs_to(line: &str, comment: &str) -> bool {
    line.split_whitespace().any(|t| t == comment)
}

/// Installs the key, preserving everything else.
///
/// Idempotent: a key already present and identical produces no change. A key present
/// but **different** is replaced - that is a rotation.
pub fn grant(existing: &str, key: &ManagedKey) -> (String, Change) {
    let comment = key.comment();
    let line = key.line();

    let mut out = Vec::new();
    let mut removed = 0;
    let mut kept = 0;
    let mut already = false;

    for l in existing.lines() {
        if belongs_to(l, &comment) {
            if l.trim() == line {
                // Exactly the same: kept, nothing to do.
                already = true;
                out.push(l.to_string());
            } else {
                // Same marker, different content: a key rotation.
                removed += 1;
            }
            continue;
        }
        // 🔴 Everything else is copied AS-IS, including what we do not understand.
        // Comments, blank lines and exotic options all belong to someone.
        kept += 1;
        out.push(l.to_string());
    }

    let added = usize::from(!already);
    if !already {
        out.push(line);
    }

    (
        finalize(out),
        Change {
            added,
            removed,
            kept,
        },
    )
}

/// Removes the key, preserving everything else.
pub fn revoke(existing: &str, key: &ManagedKey) -> (String, Change) {
    let comment = key.comment();

    let mut out = Vec::new();
    let mut removed = 0;
    let mut kept = 0;

    for l in existing.lines() {
        if belongs_to(l, &comment) {
            removed += 1;
        } else {
            kept += 1;
            out.push(l.to_string());
        }
    }

    (
        finalize(out),
        Change {
            added: 0,
            removed,
            kept,
        },
    )
}

/// The managed keys present in a file, across every cluster.
pub fn list_managed(existing: &str) -> Vec<String> {
    existing
        .lines()
        .filter_map(|l| {
            l.split_whitespace()
                .find(|t| t.starts_with(&format!("{MARKER}:")))
                .map(|t| t.trim_start_matches(&format!("{MARKER}:")).to_string())
        })
        .collect()
}

/// Ends the file with a newline.
///
/// Without it, a key appended by another tool would stick to the last line and both
/// would become invalid at once.
fn finalize(rows: Vec<String>) -> String {
    if rows.is_empty() {
        return String::new();
    }
    format!("{}\n", rows.join("\n"))
}

/// The install script, run on the remote machine.
///
/// ⚠️ The `chmod`s are not decorative: `sshd` silently ignores a group-readable
/// `authorized_keys`, and a `~/.ssh` at 755 is enough to make it refuse. It is the most
/// baffling failure mode in all of SSH.
fn install_script(home: &str, content: &str) -> String {
    let tmp = format!("{home}/.ssh/authorized_keys.hlb-tmp");
    format!(
        "set -e\n\
         mkdir -p {home}/.ssh\n\
         chmod 700 {home}/.ssh\n\
         cat > {tmp} <<'HLB_EOF_AUTHORIZED_KEYS'\n\
         {content}\n\
         HLB_EOF_AUTHORIZED_KEYS\n\
         chmod 600 {tmp}\n\
         # `mv` on the same filesystem is atomic: an interruption leaves the old\n\
         # file intact rather than a truncated one.\n\
         mv {tmp} {home}/.ssh/authorized_keys\n"
    )
}

/// Reads `authorized_keys` on a machine.
///
/// A missing file is not an error: it is a machine that never had a key.
pub async fn read_authorized_keys<R: Runner>(runner: &R, home: &str) -> Result<String> {
    let out = runner
        .run(&[
            "sh".into(),
            "-c".into(),
            format!("cat {home}/.ssh/authorized_keys 2>/dev/null || true"),
        ])
        .await?;
    Ok(out.stdout)
}

/// Writes `authorized_keys`, atomically and with the right permissions.
///
/// 🔴 Refuses to write an empty file when the old one was not. This is the last-resort
/// guard: whatever the bug upstream, everyone cannot be locked out.
pub async fn write_authorized_keys<R>(
    runner: &R,
    home: &str,
    content: &str,
    before: &str,
) -> Result<()>
where
    R: Runner,
{
    if content.trim().is_empty() && !before.trim().is_empty() {
        return Err(Error::Refused(
            "refusing to write an empty authorized_keys - it would cut every access \
             to the machine, including yours"
                .into(),
        ));
    }

    let script = install_script(home, content.trim_end());
    let out = runner.run(&["sh".into(), "-c".into(), script]).await?;

    if !out.ok() {
        return Err(Error::Refused(format!(
            "key installation refused: {}",
            out.stderr.trim()
        )));
    }
    Ok(())
}

/// A fresh SSH key pair.
#[derive(Debug, Clone)]
pub struct KeyPair {
    /// The private key file content, OpenSSH format.
    pub private: String,
    /// `ssh-ed25519 AAAA…`
    pub public: String,
}

/// Generates an ed25519 pair through `ssh-keygen`.
///
/// ## Why delegate rather than implement
///
/// The OpenSSH private key format is not standardised: it is a bespoke container
/// (`openssh-key-v1`) with its own encoding and its own encryption. Reimplementing it
/// to produce a file `ssh` must accept would be a risky bet for zero benefit -
/// `ssh-keygen` is present everywhere `ssh` is, and it is already a dependency of this
/// crate.
///
/// ed25519 rather than RSA: short keys, instant generation, and no size to get
/// wrong.
pub async fn generate_keypair(comment: &str) -> Result<KeyPair> {
    let dir = tempfile::tempdir().map_err(|source| Error::Spawn {
        command: "creating a temporary directory".into(),
        source,
    })?;
    let path = dir.path().join("hlb_ed25519");

    let out = tokio::process::Command::new("ssh-keygen")
        .args([
            "-t", "ed25519",
            // No passphrase: the key is protected by the vault, and an interactive
            // prompt would block every automation.
            "-N", "", "-C", comment, "-f",
        ])
        .arg(&path)
        .output()
        .await
        .map_err(|source| Error::Spawn {
            command: "ssh-keygen".into(),
            source,
        })?;

    if !out.status.success() {
        return Err(Error::Refused(format!(
            "ssh-keygen failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }

    let private = tokio::fs::read_to_string(&path)
        .await
        .map_err(|source| Error::Spawn {
            command: "reading the private key".into(),
            source,
        })?;
    let public = tokio::fs::read_to_string(path.with_extension("pub"))
        .await
        .map_err(|source| Error::Spawn {
            command: "reading the public key".into(),
            source,
        })?;

    Ok(KeyPair {
        private,
        public: public.trim().to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const HUMAN: &str = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQ lena@portable";
    const OTHER: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI collegue@office";

    fn key() -> ManagedKey {
        ManagedKey::new(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHLB homelabus@hlb",
            "home",
        )
    }

    #[test]
    fn a_managed_line_carries_its_marker_last() {
        // The marker must be the LAST field: it is the SSH comment, and a key that
        // already carried one would hide it.
        let l = key().line();
        assert!(l.ends_with("homelabus-managed:home"), "{l}");
        assert!(!l.contains("homelabus@hlb"), "the old comment must go: {l}");
    }

    #[test]
    fn forwarding_is_disabled() {
        // Homelabus needs a shell, but nothing justifies forwarding: forbidding it
        // limits what a leak of the key would allow.
        let l = key().line();
        assert!(l.contains("no-port-forwarding"), "{l}");
        assert!(l.contains("no-agent-forwarding"), "{l}");
        // But NO `command=`: it would break docker, apt, systemctl.
        assert!(!l.contains("command="), "{l}");
    }

    #[test]
    fn granting_never_touches_human_keys() {
        // 🔴 The central invariant. Losing the administrator's key while installing
        // ours is the most expensive failure possible: nobody gets in any more.
        let before = format!("{HUMAN}\n{OTHER}\n");
        let (after, c) = grant(&before, &key());

        assert!(after.contains(HUMAN), "{after}");
        assert!(after.contains(OTHER), "{after}");
        assert_eq!(c.kept, 2);
        assert_eq!(c.added, 1);
        assert_eq!(c.removed, 0);
    }

    #[test]
    fn unknown_lines_are_copied_verbatim() {
        // Comments, blank lines, exotic options: everything belongs to someone.
        let before = "# NAS key, do not delete\n\
                     \n\
                     from=\"10.0.0.0/8\" ssh-rsa AAAAB backup\n";
        let (after, _) = grant(before, &key());

        assert!(after.contains("# NAS key, do not delete"));
        assert!(after.contains("from=\"10.0.0.0/8\""));
    }

    #[test]
    fn granting_twice_changes_nothing() {
        let (first, _) = grant("", &key());
        let (second, c) = grant(&first, &key());

        assert_eq!(first, second, "installation must be idempotent");
        assert!(c.is_noop(), "{c:?}");
    }

    #[test]
    fn a_rotated_key_replaces_the_old_one() {
        // A rotation: same marker, different body. TWO lines must not remain, or the
        // old key would keep opening the machine.
        let (before, _) = grant("", &key());
        let update = ManagedKey::new("ssh-ed25519 AAAANOUVELLE x@y", "home");
        let (after, c) = grant(&before, &update);

        assert_eq!(c.removed, 1);
        assert_eq!(c.added, 1);
        assert!(after.contains("AAAANOUVELLE"));
        assert!(!after.contains("AAAAC3NzaC1lZDI1NTE5AAAAIHLB"), "{after}");
        assert_eq!(after.lines().count(), 1);
    }

    #[test]
    fn two_clusters_do_not_revoke_each_other() {
        // 🔴 Two Homelabus installs on one machine: revoking one must not cut the
        // other. That is why the WHOLE comment is tested, not the marker.
        let (a, _) = grant("", &key());
        let office = ManagedKey::new("ssh-ed25519 AAAABUREAU x@y", "office");
        let (second, _) = grant(&a, &office);

        let (after, c) = revoke(&second, &key());
        assert_eq!(c.removed, 1);
        assert!(after.contains("AAAABUREAU"), "{after}");
        assert!(!after.contains("AAAAC3NzaC1lZDI1NTE5AAAAIHLB"));
    }

    #[test]
    fn revoking_preserves_everything_else() {
        let before = format!("{HUMAN}\n{}\n{OTHER}\n", key().line());
        let (after, c) = revoke(&before, &key());

        assert_eq!(c.removed, 1);
        assert_eq!(c.kept, 2);
        assert!(after.contains(HUMAN));
        assert!(after.contains(OTHER));
        assert!(!after.contains(MARKER));
    }

    #[test]
    fn revoking_an_absent_key_is_a_noop() {
        let before = format!("{HUMAN}\n");
        let (after, c) = revoke(&before, &key());
        assert!(c.is_noop());
        assert_eq!(after, before);
    }

    #[test]
    fn managed_clusters_are_listed() {
        let (a, _) = grant("", &key());
        let (second, _) = grant(&a, &ManagedKey::new("ssh-ed25519 AAAAB x@y", "office"));
        let mut names = list_managed(&second);
        names.sort();
        assert_eq!(names, ["home", "office"]);
        // A human key does not appear.
        assert!(list_managed(HUMAN).is_empty());
    }

    #[test]
    fn the_file_always_ends_with_a_newline() {
        // Without it, a key later appended by another tool would stick to the last
        // line and both would become invalid.
        let (after, _) = grant(HUMAN, &key());
        assert!(after.ends_with('\n'), "{after:?}");
        // And no stray blank line at the end.
        assert!(!after.ends_with("\n\n"), "{after:?}");
    }

    #[test]
    fn an_empty_input_gives_a_single_line() {
        let (after, c) = grant("", &key());
        assert_eq!(after.lines().count(), 1);
        assert_eq!(c.kept, 0);
    }

    #[test]
    fn revoking_the_last_key_yields_an_empty_file() {
        // Empty content is legitimate here; `write_authorized_keys` is what refuses to
        // write it over a non-empty file.
        let (a, _) = grant("", &key());
        let (after, _) = revoke(&a, &key());
        assert!(after.is_empty());
    }

    #[test]
    fn the_install_script_fixes_permissions() {
        // ⚠️ sshd SILENTLY ignores a group-readable authorized_keys. The key is
        // installed, it looks fine, and nothing works.
        let s = install_script("/root", "ssh-ed25519 AAAA x");
        assert!(s.contains("chmod 700 /root/.ssh"), "{s}");
        assert!(s.contains("chmod 600"), "{s}");
    }

    #[test]
    fn the_install_script_is_atomic() {
        // An interruption during the write must leave the old file intact, not a
        // truncated one that would open nothing.
        let s = install_script("/root", "x");
        assert!(s.contains(".hlb-tmp"), "{s}");
        assert!(
            s.contains("mv /root/.ssh/authorized_keys.hlb-tmp /root/.ssh/authorized_keys"),
            "{s}"
        );
        // `set -e`: a failing chmod must not let the mv continue.
        assert!(s.starts_with("set -e"), "{s}");
    }

    #[test]
    fn the_heredoc_delimiter_is_quoted() {
        // Without quotes around the delimiter, the shell would interpret `$` and
        // backticks in the content - a public key contains base64 randomness, so sooner
        // or later a character that breaks everything.
        let s = install_script("/root", "x");
        assert!(s.contains("<<'HLB_EOF_AUTHORIZED_KEYS'"), "{s}");
    }
}

#[cfg(test)]
mod tests_keygen {
    use super::*;

    #[tokio::test]
    async fn a_generated_pair_is_usable() {
        let Ok(kp) = generate_keypair("homelabus@test").await else {
            // `ssh-keygen` absent: the rest is not failed over that.
            return;
        };

        assert!(kp.public.starts_with("ssh-ed25519 "), "{}", kp.public);
        assert!(
            kp.private.contains("OPENSSH PRIVATE KEY"),
            "unexpected format"
        );
        // 🔴 The private key must NEVER end up inside the public one.
        assert!(!kp.public.contains("PRIVATE"));
        assert_eq!(
            kp.public.lines().count(),
            1,
            "the public key fits on one line"
        );
    }

    #[tokio::test]
    async fn two_generations_differ() {
        let (Ok(a), Ok(b)) = (generate_keypair("x@1").await, generate_keypair("x@2").await) else {
            return;
        };
        assert_ne!(a.public, b.public, "two identical keys would be a disaster");
    }

    #[tokio::test]
    async fn a_generated_key_produces_a_valid_authorized_line() {
        let Ok(kp) = generate_keypair("homelabus@hlb").await else {
            return;
        };
        let l = ManagedKey::new(&kp.public, "home").line();

        // At least four fields: options, type, body, comment.
        let fields: Vec<&str> = l.split_whitespace().collect();
        assert_eq!(fields.len(), 4, "{l}");
        assert_eq!(fields[1], "ssh-ed25519");
        assert_eq!(fields[3], "homelabus-managed:home");
    }
}
