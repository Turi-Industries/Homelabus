//! The key written here is the key OpenSSH reads: `ssh-keygen` derives the same public
//! half from it, prints the same fingerprint, and what it writes reads back here.

use std::process::Command;

use hlb_termix::NodeKey;

fn ssh_keygen(args: &[&str]) -> Option<String> {
    let out = Command::new("ssh-keygen").args(args).output().ok()?;
    assert!(
        out.status.success(),
        "ssh-keygen {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

#[test]
fn ssh_keygen_reads_the_key_and_agrees_on_its_fingerprint() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("k");
    let key = NodeKey::generate("homelabus-managed:termix");
    std::fs::write(&path, key.openssh_private()).expect("written");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("0600");
    }
    let file = path.to_str().expect("utf-8 path");

    // `ssh-keygen` absent: nothing to compare with, and nothing failed.
    let Some(public) = ssh_keygen(&["-y", "-f", file]) else {
        return;
    };
    assert_eq!(public, key.public_line());

    let listed = ssh_keygen(&["-l", "-f", file]).expect("listed");
    assert_eq!(
        listed.split_whitespace().nth(1),
        Some(key.fingerprint().as_str())
    );
}

#[test]
fn a_key_ssh_keygen_wrote_reads_back_here() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("k");
    let file = path.to_str().expect("utf-8 path");
    if ssh_keygen(&[
        "-q",
        "-t",
        "ed25519",
        "-N",
        "",
        "-C",
        "made-by-openssh",
        "-f",
        file,
    ])
    .is_none()
    {
        return;
    }
    let key = NodeKey::from_openssh(&std::fs::read_to_string(&path).expect("read"))
        .expect("an OpenSSH key");
    let public = std::fs::read_to_string(dir.path().join("k.pub")).expect("public");
    assert_eq!(key.public_line(), public.trim());
}
