//! The host itself: its journal capped, its kernel hardened.
//!
//! Two files of Homelabus's own, each only NARROWING what the machine already does — the
//! rule `provision` keeps for what it adds to a machine it did not set up. Neither touches
//! what Docker, Swarm or the mesh need: forwarding, bridges, `rp_filter` and the
//! connection tracking stay the distribution's and Docker's.
//!
//! ## 🔴 Why the journal is capped
//!
//! A sibling installation's disk filled with logs and its site answered 500 for two and a
//! half days — and its backups failed in silence, having nowhere to write. journald's own
//! default is 10 % of the file system, up to 4 GB, and on a small root disk next to
//! Docker's images that is the margin a node did not have.

use crate::distro::{Distro, Family};
use crate::provision::{Action, Phase, Step};

/// journald's drop-in: the distribution's `journald.conf` is left as it is.
pub const JOURNALD_PATH: &str = "/etc/systemd/journald.conf.d/90-homelabus.conf";

pub const JOURNALD_CONFIG: &str = "\
# Written by Homelabus: the journal never grows without bound.
[Journal]
SystemMaxUse=500M
SystemKeepFree=1G
MaxRetentionSec=1month
";

/// Read after the distribution's own files (`99-` stays the machine owner's).
pub const SYSCTL_PATH: &str = "/etc/sysctl.d/90-homelabus.conf";

/// Each line a kernel setting no node needs otherwise. A key the running kernel lacks
/// (Yama, on a kernel built without it) is skipped by `sysctl -e`, never a failure.
pub const SYSCTL_CONFIG: &str = "\
# Written by Homelabus. Nothing here touches forwarding, bridges or rp_filter:
# Docker, Swarm's overlay and the WireGuard mesh set what they need themselves.

# Redirects neither accepted (a rerouted gateway) nor sent (a node is not a router).
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv6.conf.all.accept_redirects=0
net.ipv6.conf.default.accept_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.conf.all.accept_source_route=0
net.ipv6.conf.all.accept_source_route=0
net.ipv4.tcp_syncookies=1

# Kernel addresses and its log for root only; ptrace to a process's own parent.
kernel.kptr_restrict=2
kernel.dmesg_restrict=1
kernel.yama.ptrace_scope=1
# eBPF for root only: a recurring class of privilege escalation.
kernel.unprivileged_bpf_disabled=1
net.core.bpf_jit_harden=2
# No core dump of a setuid program: its memory holds what it was trusted with.
fs.suid_dumpable=0
";

/// The steps that put both in place and make them hold now, not at the next boot.
///
/// The file steps are `Configuration`, the activation `Services` — the phase a test
/// container, with no init, leaves out.
pub fn steps(distro: &Distro) -> (Vec<Step>, Vec<String>) {
    let mut steps = Vec::new();
    let mut notes = Vec::new();
    let install = |what: &str, path: &str, content: &str| Step {
        phase: Phase::Configuration,
        what: what.to_string(),
        action: Action::Install {
            path: path.to_string(),
            content: content.to_string(),
            mode: 0o644,
        },
    };
    let run = |what: &str, argv: &[&str]| Step {
        phase: Phase::Services,
        what: what.to_string(),
        action: Action::Run(argv.iter().map(|s| s.to_string()).collect()),
    };

    steps.push(install("kernel hardening", SYSCTL_PATH, SYSCTL_CONFIG));
    // `-e`: a key this kernel does not have is skipped, where procps and BusyBox would
    // otherwise both stop on it.
    steps.push(run(
        "apply the kernel hardening now",
        &["sysctl", "-q", "-e", "-p", SYSCTL_PATH],
    ));

    match distro.family {
        // Alpine logs through BusyBox's syslogd, which rotates at 200 KB on its own.
        Family::Alpine => notes.push(
            "the journal is BusyBox's syslog, which bounds itself: nothing to cap".to_string(),
        ),
        _ => {
            steps.push(install(
                "cap the system journal",
                JOURNALD_PATH,
                JOURNALD_CONFIG,
            ));
            // journald reads its configuration at start only.
            steps.push(run(
                "apply the journal's cap now",
                &["systemctl", "restart", "systemd-journald"],
            ));
        }
    }
    (steps, notes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys() -> Vec<&'static str> {
        SYSCTL_CONFIG
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(|l| l.split_once('=').expect("key=value").0)
            .collect()
    }

    #[test]
    fn the_hardening_leaves_what_the_cluster_needs_alone() {
        // Swarm's overlay and Docker's NAT forward; the mesh and the bridges route; a
        // strict `rp_filter` drops VXLAN replies arriving through WireGuard.
        for k in keys() {
            for needed in [
                "forwarding",
                "ip_forward",
                "bridge",
                "rp_filter",
                "conntrack",
            ] {
                assert!(!k.contains(needed), "{k} is the cluster's, not ours");
            }
        }
        assert!(
            keys().len() >= 15,
            "the walk read the settings: {:?}",
            keys()
        );
    }

    #[test]
    fn every_setting_is_set_once() {
        let mut k = keys();
        let n = k.len();
        k.sort();
        k.dedup();
        assert_eq!(k.len(), n, "a key set twice: the second silently wins");
    }

    #[test]
    fn the_journal_is_capped_by_size_and_by_age() {
        for line in ["SystemMaxUse=", "SystemKeepFree=", "MaxRetentionSec="] {
            assert!(JOURNALD_CONFIG.contains(line), "{line}");
        }
        assert!(
            JOURNALD_CONFIG.contains("[Journal]"),
            "no section is no setting"
        );
    }

    #[test]
    fn a_file_is_written_before_it_is_applied() {
        let d =
            Distro::parse("ID=debian\nVERSION_ID=12\nPRETTY_NAME=\"Debian 12\"\n").expect("debian");
        let (steps, _) = steps(&d);
        let at = |needle: &str| {
            steps
                .iter()
                .position(|s| match &s.action {
                    Action::Install { path, .. } => path == needle,
                    Action::Run(argv) => argv.iter().any(|a| a == needle),
                })
                .expect(needle)
        };
        assert!(at(SYSCTL_PATH) < at("-p"));
        assert!(at(JOURNALD_PATH) < at("systemd-journald"));
        // Activating is what a container under test cannot do.
        for s in &steps {
            match s.action {
                Action::Install { .. } => assert_eq!(s.phase, Phase::Configuration),
                Action::Run(_) => assert_eq!(s.phase, Phase::Services),
            }
        }
    }

    #[test]
    fn alpine_gets_the_kernel_hardening_and_no_journald() {
        let d = Distro::parse("ID=alpine\nVERSION_ID=3.20.0\nPRETTY_NAME=\"Alpine\"\n")
            .expect("alpine");
        let (steps, notes) = steps(&d);
        assert!(steps.iter().all(|s| !s.describe().contains("journald")));
        assert!(steps.iter().any(|s| s.describe().contains(SYSCTL_PATH)));
        assert_eq!(notes.len(), 1, "a decision not to act is said");
    }
}
