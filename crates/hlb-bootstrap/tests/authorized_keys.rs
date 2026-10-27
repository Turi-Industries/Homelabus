//! Real manipulation of `authorized_keys`.
//!
//! 🔴 This is the file that, written badly, locks you out for good. The unit tests
//! check how the lines are computed; these check that the **script** run on the machine
//! does what it says - permissions included, because `sshd` silently ignores a file
//! that is too permissive.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use hlb_bootstrap::access::{self, ManagedKey};
use hlb_bootstrap::LocalRunner;

const HUMAN: &str = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQ lena@portable";

fn key() -> ManagedKey {
    ManagedKey::new(
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHLB homelabus@hlb",
        "hlb",
    )
}

/// A fake `$HOME` with a pre-existing `authorized_keys`.
fn home_with(content: &str) -> tempfile::TempDir {
    let d = tempfile::tempdir().expect("temp dir");
    let ssh = d.path().join(".ssh");
    std::fs::create_dir_all(&ssh).expect("mkdir");
    std::fs::write(ssh.join("authorized_keys"), content).expect("write");
    d
}

fn read(d: &tempfile::TempDir) -> String {
    std::fs::read_to_string(d.path().join(".ssh/authorized_keys")).expect("read")
}

#[tokio::test]
async fn a_real_grant_preserves_the_human_key() {
    let d = home_with(&format!("{HUMAN}\n"));
    let home = d.path().to_string_lossy().to_string();
    let r = LocalRunner;

    let before = access::read_authorized_keys(&r, &home).await.expect("read");
    assert!(before.contains(HUMAN));

    let (after, ch) = access::grant(&before, &key());
    access::write_authorized_keys(&r, &home, &after, &before)
        .await
        .expect("write");

    let final_ = read(&d);
    assert!(final_.contains(HUMAN), "🔴 human key lost:\n{final_}");
    assert!(final_.contains("homelabus-managed:hlb"), "{final_}");
    assert_eq!(ch.kept, 1);
}

#[tokio::test]
async fn permissions_are_what_sshd_demands() {
    // ⚠️ sshd ignores authorized_keys WITHOUT SAYING A WORD if it is group-readable,
    // or if ~/.ssh is. It is the most baffling failure mode in SSH.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let d = home_with("");
        let home = d.path().to_string_lossy().to_string();
        let r = LocalRunner;

        // The permissions are deliberately degraded before the write.
        std::fs::set_permissions(
            d.path().join(".ssh"),
            std::fs::Permissions::from_mode(0o777),
        )
        .expect("chmod");

        let (after, _) = access::grant("", &key());
        access::write_authorized_keys(&r, &home, &after, "")
            .await
            .expect("write");

        let m_dir = std::fs::metadata(d.path().join(".ssh")).expect("stat");
        let m_f = std::fs::metadata(d.path().join(".ssh/authorized_keys")).expect("stat");

        assert_eq!(
            m_dir.permissions().mode() & 0o777,
            0o700,
            "~/.ssh must be 700"
        );
        assert_eq!(
            m_f.permissions().mode() & 0o777,
            0o600,
            "the file must be 600"
        );
    }
}

#[tokio::test]
async fn an_empty_write_over_a_populated_file_is_refused() {
    // 🔴 The last-resort guard. Whatever the bug upstream, it must not be possible to
    // cut every access to a machine.
    let d = home_with(&format!("{HUMAN}\n"));
    let home = d.path().to_string_lossy().to_string();

    let r = access::write_authorized_keys(&LocalRunner, &home, "", HUMAN).await;

    assert!(r.is_err(), "an empty write must be REFUSED");
    let m = r.unwrap_err().to_string();
    assert!(m.contains("cut every access"), "{m}");

    // And the file is intact.
    assert!(read(&d).contains(HUMAN));
}

#[tokio::test]
async fn a_grant_then_revoke_round_trip_leaves_no_trace() {
    let d = home_with(&format!("{HUMAN}\n"));
    let home = d.path().to_string_lossy().to_string();
    let r = LocalRunner;

    let before = access::read_authorized_keys(&r, &home).await.expect("read");
    let (granted, _) = access::grant(&before, &key());
    access::write_authorized_keys(&r, &home, &granted, &before)
        .await
        .expect("install");

    let reread_content = access::read_authorized_keys(&r, &home)
        .await
        .expect("reread");
    let (revoked, ch) = access::revoke(&reread_content, &key());
    access::write_authorized_keys(&r, &home, &revoked, &reread_content)
        .await
        .expect("removal");

    let final_ = read(&d);
    assert_eq!(ch.removed, 1);
    assert!(
        final_.contains(HUMAN),
        "the human key survives the full cycle"
    );
    assert!(!final_.contains("homelabus-managed"), "{final_}");
}

#[tokio::test]
async fn a_missing_file_is_not_an_error() {
    // A brand-new machine never had a key: that is not a failure.
    let d = tempfile::tempdir().expect("temp dir");
    let home = d.path().to_string_lossy().to_string();

    let c = access::read_authorized_keys(&LocalRunner, &home)
        .await
        .expect("no error on a missing file");
    assert!(c.trim().is_empty());
}

#[tokio::test]
async fn exotic_content_survives_the_heredoc() {
    // The content travels through a shell heredoc. Without a quoted delimiter, `$`,
    // backticks and quotes would be interpreted - and a public key is random base64, so
    // sooner or later it contains something that breaks everything.
    let trap_line = "command=\"echo $HOME `id`\" ssh-rsa AAAA'B$C`d` trap_line@x";
    let d = home_with(&format!("{trap_line}\n"));
    let home = d.path().to_string_lossy().to_string();
    let r = LocalRunner;

    let before = access::read_authorized_keys(&r, &home).await.expect("read");
    let (after, _) = access::grant(&before, &key());
    access::write_authorized_keys(&r, &home, &after, &before)
        .await
        .expect("write");

    assert!(
        read(&d).contains(trap_line),
        "content altered:\n{}",
        read(&d)
    );
}
