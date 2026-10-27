//! The node script against real `sshd`s — Debian's (PAM) and Alpine's (no PAM, where a
//! locked account refuses every key): the account it makes is reached by the key from
//! the address the line names, and from no other; a second run changes nothing; a
//! line someone added by hand survives a rotation.
//!
//! ```sh
//! cargo test -p hlb-termix --test live_node -- --ignored --nocapture
//! ```

#![allow(clippy::expect_used)]

use std::process::Command;

use hlb_termix::node::{self, Outcome};
use hlb_termix::NodeKey;

const NET: &str = "hlb-termix-live";
const SUBNET: &str = "172.31.250.0/24";
const SERVER: &str = "172.31.250.10";
const ALLOWED: &str = "172.31.250.20";
const OTHER: &str = "172.31.250.30";

fn docker(args: &[&str]) -> (bool, String) {
    let out = Command::new("docker").args(args).output().expect("docker");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.success(), text)
}

/// Removes a container — or, `None`, the network — whatever the test's outcome.
struct Cleanup(Option<String>);

impl Drop for Cleanup {
    fn drop(&mut self) {
        match &self.0 {
            Some(c) => docker(&["rm", "-f", c]),
            None => docker(&["network", "rm", NET]),
        };
    }
}

fn run_script(server: &str, lines: &[String], check: bool) -> Outcome {
    let script = node::host_script("hlb-termix", &node::marker("termix"), lines, check);
    let (ok, out) = docker(&["exec", server, "sh", "-c", &script]);
    assert!(ok, "the script failed: {out}");
    let lines: Vec<String> = out.lines().map(str::to_string).collect();
    Outcome::read(&lines).unwrap_or_else(|| panic!("the script did not end: {out}"))
}

/// `id -un` on the server, through the key, from `from`.
fn ssh_from(from: &str, name: &str, key: &NodeKey) -> (bool, String) {
    let script = format!(
        "apk add -q openssh-client >/dev/null && umask 077 && printf '%s' \"$KEY\" > /k && \
         ssh -i /k -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=10 \
         hlb-termix@{SERVER} id -un"
    );
    docker(&[
        "run",
        "--rm",
        "--name",
        name,
        "--network",
        NET,
        "--ip",
        from,
        "-e",
        &format!("KEY={}", key.openssh_private()),
        "alpine:3",
        "sh",
        "-c",
        &script,
    ])
}

fn exercise(image: &str, start: &str) {
    let server = format!("hlb-termix-sshd-{}", image.replace([':', '/', '.'], "-"));
    let _ = docker(&["rm", "-f", &server]);
    let (ok, out) = docker(&[
        "run",
        "-d",
        "--name",
        &server,
        "--network",
        NET,
        "--ip",
        SERVER,
        image,
        "sh",
        "-c",
        start,
    ]);
    assert!(ok, "{out}");
    let _guard = Cleanup(Some(server.clone()));
    let mut up = false;
    for _ in 0..120 {
        // Port 22 listening: neither `pgrep` (absent from Debian's slim image) nor the
        // process's name (`sshd: … [listener]` since OpenSSH split it) says so reliably.
        if docker(&[
            "exec",
            &server,
            "sh",
            "-c",
            "grep -q ':0016 00000000:0000 0A' /proc/net/tcp",
        ])
        .0
        {
            up = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    assert!(up, "{image}: sshd never started");

    let key = NodeKey::generate("homelabus-managed:termix");
    let line = |k: &NodeKey| {
        node::line(
            &k.public_body(),
            &[ALLOWED.to_string()],
            &node::marker("termix"),
        )
    };

    let first = run_script(&server, &[line(&key)], false);
    assert!(first.created && first.written, "{image}: {first:?}");
    assert!(
        first
            .host_key
            .as_deref()
            .is_some_and(|h| h.starts_with("SHA256:")),
        "{image}: {first:?}"
    );
    assert!(first.refused.is_empty(), "{image}: {first:?}");

    let again = run_script(&server, &[line(&key)], false);
    assert!(!again.created && !again.written, "{image}: {again:?}");

    let (ok, out) = ssh_from(ALLOWED, &format!("{server}-allowed"), &key);
    assert!(
        ok && out.lines().any(|l| l.trim() == "hlb-termix"),
        "{image}: {out}"
    );
    let (ok, out) = ssh_from(OTHER, &format!("{server}-other"), &key);
    assert!(
        !ok,
        "{image}: the key opened the node from elsewhere: {out}"
    );

    // No right beyond a shell: neither root's group nor docker's.
    let (_, groups) = docker(&["exec", &server, "id", "-Gn", "hlb-termix"]);
    for g in ["root", "sudo", "wheel", "docker"] {
        assert!(
            !groups.split_whitespace().any(|x| x == g),
            "{image}: {groups}"
        );
    }

    // A person's own line in the account survives; a rotation's two keys both open,
    // then the former one stops.
    let (ok, out) = docker(&[
        "exec",
        &server,
        "sh",
        "-c",
        "echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIByhand someone@laptop' >> /home/hlb-termix/.ssh/authorized_keys",
    ]);
    assert!(ok, "{out}");
    let next = NodeKey::generate("homelabus-managed:termix");
    let check = run_script(&server, &[line(&key), line(&next)], true);
    assert!(check.written, "{image}: a check sees the change");
    let (_, before) = docker(&[
        "exec",
        &server,
        "cat",
        "/home/hlb-termix/.ssh/authorized_keys",
    ]);
    assert!(
        !before.contains(&next.public_body()),
        "{image}: a check wrote"
    );
    run_script(&server, &[line(&key), line(&next)], false);
    assert!(
        ssh_from(ALLOWED, &format!("{server}-old"), &key).0,
        "{image}"
    );
    assert!(
        ssh_from(ALLOWED, &format!("{server}-new"), &next).0,
        "{image}"
    );
    run_script(&server, &[line(&next)], false);
    assert!(
        !ssh_from(ALLOWED, &format!("{server}-gone"), &key).0,
        "{image}: the former key still opens"
    );
    let (_, after) = docker(&[
        "exec",
        &server,
        "cat",
        "/home/hlb-termix/.ssh/authorized_keys",
    ]);
    assert!(after.contains("someone@laptop"), "{image}: {after}");
    let (_, mode) = docker(&[
        "exec",
        &server,
        "stat",
        "-c",
        "%a %U",
        "/home/hlb-termix/.ssh/authorized_keys",
    ]);
    assert_eq!(mode.trim(), "600 hlb-termix", "{image}");

    // sshd letting only someone else in shuts the account out: said, not silent.
    let (ok, out) = docker(&[
        "exec",
        &server,
        "sh",
        "-c",
        "echo 'AllowUsers root' >> /etc/ssh/sshd_config",
    ]);
    assert!(ok, "{out}");
    let shut = run_script(&server, &[line(&next)], true);
    assert!(
        shut.refused.iter().any(|r| r.contains("allowusers")),
        "{image}: {shut:?}"
    );
}

#[test]
#[ignore = "needs Docker and the network"]
fn the_account_is_reached_by_its_key_from_termix_only() {
    let _ = docker(&["network", "rm", NET]);
    let (ok, out) = docker(&["network", "create", "--subnet", SUBNET, NET]);
    assert!(ok, "{out}");
    let _net = Cleanup(None);

    // Alpine: no PAM, so sshd reads the account's lock itself — the trap "!" was.
    exercise(
        "alpine:3",
        "apk add -q openssh && ssh-keygen -A && exec /usr/sbin/sshd -D -e",
    );
    exercise(
        "debian:bookworm-slim",
        "apt-get update -qq && apt-get install -y -qq openssh-server >/dev/null && \
         mkdir -p /run/sshd && exec /usr/sbin/sshd -D -e",
    );
}
