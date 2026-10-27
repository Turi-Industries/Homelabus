//! The operating system's own updates.
//!
//! Two halves, kept apart on purpose:
//!
//! - **Security updates, unattended**, on every node, for everything except the
//!   container engine.
//! - **Everything else** — Docker, containerd, a new kernel and the reboot it needs —
//!   through `hlb node upgrade`, one node at a time, after its services were moved away.
//!
//! ## 🔴 Why Docker is excluded from the unattended half
//!
//! Upgrading the engine restarts it, and restarting it restarts every task on the node.
//! Unattended upgrades run on a timer that fires at the same hour on every node — with
//! Docker among them, the whole cluster restarts in the same hour, managers included, and
//! a Raft quorum that loses two managers at once stops scheduling anything. The same goes
//! for `needrestart`, which Ubuntu runs after each upgrade and which restarts the services
//! using an updated library: the engine among them, unless told otherwise.
//!
//! ## Never a reboot
//!
//! A reboot drains nothing. A node that reboots on its own takes its tasks down without
//! Swarm having moved them first — for a database, that is an outage. The kernel is
//! updated unattended; the reboot that activates it waits for `hlb node upgrade`, and the
//! agent reports the node as waiting for one.

use crate::distro::{Distro, Family, PackageManager};

/// What is excluded from unattended upgrades on the APT side.
///
/// ⚠️ Entries are regular expressions matched from the start of the name: `docker-ce`
/// covers `docker-ce-cli` and `docker-ce-rootless-extras` too.
pub const ENGINE_PACKAGES: &[&str] = &[
    "docker-ce",
    "containerd.io",
    "docker.io",
    "containerd",
    "runc",
];

/// How the unattended half is set up on a distribution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unattended {
    /// `unattended-upgrades`, with the distribution's security origins.
    Apt,
    /// `dnf-automatic`, security advisories only. `dnf5` from Fedora 41.
    DnfAutomatic { dnf5: bool },
    /// Not automated, and why. Shown in the plan, never left silent.
    NotAutomated(&'static str),
}

impl Unattended {
    pub fn for_distro(distro: &Distro) -> Self {
        match distro.family {
            Family::Debian => Self::Apt,
            Family::RedHat => {
                if distro.id == "amzn" {
                    return Self::NotAutomated(
                        "Amazon Linux publishes its updates as versioned releases — \
                         `hlb node upgrade` applies them",
                    );
                }
                let fedora_major = distro
                    .version_id
                    .as_deref()
                    .and_then(|v| v.split('.').next())
                    .and_then(|v| v.parse::<u32>().ok());
                Self::DnfAutomatic {
                    dnf5: distro.id == "fedora" && fedora_major.is_some_and(|v| v >= 41),
                }
            }
            Family::Arch => Self::NotAutomated(
                "Arch does not support unattended upgrades: a partial upgrade breaks the \
                 system — `hlb node upgrade` upgrades it whole",
            ),
            Family::Alpine => Self::NotAutomated(
                "Alpine has no unattended-upgrade tool — `hlb node upgrade` applies them",
            ),
            Family::Suse => Self::NotAutomated(
                "not automated on openSUSE yet — `hlb node upgrade` applies them",
            ),
        }
    }

    /// The package that provides it.
    pub fn package(&self) -> Option<&'static str> {
        match self {
            Self::Apt => Some("unattended-upgrades"),
            Self::DnfAutomatic { dnf5: false } => Some("dnf-automatic"),
            Self::DnfAutomatic { dnf5: true } => Some("dnf5-plugin-automatic"),
            Self::NotAutomated(_) => None,
        }
    }

    /// The timer to enable, on systemd.
    pub fn timer(&self) -> Option<&'static str> {
        match self {
            // Debian's package enables its own timers; `20auto-upgrades` is the switch.
            Self::Apt => None,
            Self::DnfAutomatic { dnf5: false } => Some("dnf-automatic.timer"),
            Self::DnfAutomatic { dnf5: true } => Some("dnf5-automatic.timer"),
            Self::NotAutomated(_) => None,
        }
    }

    /// The files that switch it on, as `(path, content)`. Written only when Homelabus
    /// installed the tool: an existing configuration is somebody's decision.
    pub fn enabling_files(&self) -> Vec<(&'static str, String)> {
        match self {
            Self::Apt => vec![(
                "/etc/apt/apt.conf.d/20auto-upgrades",
                "APT::Periodic::Update-Package-Lists \"1\";\n\
                 APT::Periodic::Unattended-Upgrade \"1\";\n"
                    .to_string(),
            )],
            // The same keys in both generations. `reboot` is left out: `never` is the
            // default in both, and dnf 4's older releases refuse a key they do not know.
            Self::DnfAutomatic { .. } => vec![(
                "/etc/dnf/automatic.conf",
                "[commands]\n\
                 upgrade_type = security\n\
                 download_updates = yes\n\
                 apply_updates = yes\n\
                 \n\
                 [emitters]\n\
                 emit_via = stdio\n"
                    .to_string(),
            )],
            Self::NotAutomated(_) => Vec::new(),
        }
    }

    /// The files that keep the engine out of it, as `(path, content)`. Added even next
    /// to an existing configuration: they only narrow it, and they are what stops every
    /// node restarting its containers in the same hour.
    pub fn guard_files(&self, needrestart: bool) -> Vec<(&'static str, String)> {
        match self {
            Self::Apt => {
                let mut files = vec![("/etc/apt/apt.conf.d/52hlb-unattended-upgrades", {
                    let mut s = String::from(
                        "// Written by Homelabus. `hlb node upgrade` upgrades the container\n\
                         // engine one node at a time: restarting it restarts every task on\n\
                         // the node, and this runs at the same hour on every node.\n\
                         Unattended-Upgrade::Package-Blacklist {\n",
                    );
                    for p in ENGINE_PACKAGES {
                        s.push_str(&format!("    \"{p}\";\n"));
                    }
                    s.push_str(
                        "};\n\
                         // A reboot drains nothing: `hlb node upgrade` moves the services\n\
                         // away first.\n\
                         Unattended-Upgrade::Automatic-Reboot \"false\";\n\
                         // Old kernels fill /boot, and the next one then fails to install.\n\
                         Unattended-Upgrade::Remove-Unused-Kernel-Packages \"true\";\n",
                    );
                    s
                })];
                if needrestart {
                    files.push((
                        "/etc/needrestart/conf.d/hlb.conf",
                        "# Written by Homelabus: restarting the engine restarts every\n\
                         # container on the node. `hlb node upgrade` does it, drained.\n\
                         $nrconf{override_rc}{qr(^docker)} = 0;\n\
                         $nrconf{override_rc}{qr(^containerd)} = 0;\n"
                            .to_string(),
                    ));
                }
                files
            }
            // Docker's own repository publishes no security advisories, so
            // `upgrade_type = security` never selects it.
            Self::DnfAutomatic { .. } | Self::NotAutomated(_) => Vec::new(),
        }
    }
}

/// The commands of a full upgrade, engine included, for `hlb node upgrade`.
///
/// `full-upgrade` rather than `upgrade` on APT: a new kernel is a NEW package, and
/// `upgrade` holds it back forever. `--force-confold` keeps a configuration file someone
/// edited instead of stopping on a question nobody is there to answer.
pub fn full_upgrade(distro: &Distro) -> Vec<Vec<String>> {
    let v = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    match distro.package_manager() {
        PackageManager::Apt => vec![
            v(&["apt-get", "update"]),
            v(&[
                "env",
                "DEBIAN_FRONTEND=noninteractive",
                "apt-get",
                "-o",
                "Dpkg::Options::=--force-confold",
                "-o",
                "Dpkg::Options::=--force-confdef",
                "full-upgrade",
                "-y",
            ]),
        ],
        PackageManager::Dnf => vec![v(&["dnf", "upgrade", "-y", "--refresh"])],
        PackageManager::Apk => vec![v(&["apk", "upgrade", "--update-cache"])],
        PackageManager::Pacman => vec![v(&["pacman", "-Syu", "--noconfirm"])],
        PackageManager::Zypper => {
            // Tumbleweed only moves forward with `dup`; on Leap it would switch
            // vendors under your feet.
            if distro.id == "opensuse-tumbleweed" {
                vec![v(&["zypper", "--non-interactive", "dup"])]
            } else {
                vec![v(&["zypper", "--non-interactive", "update"])]
            }
        }
    }
}

/// Removing what nothing needs any more: dependencies left behind by an upgrade, and
/// the kernels older than the running one and the one before it.
///
/// Only what the package manager itself installed as a dependency — never a package
/// someone asked for. Arch, Alpine and openSUSE have no equivalent that distinguishes the
/// two safely, so nothing is removed there.
pub fn autoremove(distro: &Distro) -> Option<Vec<String>> {
    let v = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    match distro.package_manager() {
        PackageManager::Apt => Some(v(&[
            "env",
            "DEBIAN_FRONTEND=noninteractive",
            "apt-get",
            "autoremove",
            "--purge",
            "-y",
        ])),
        PackageManager::Dnf => Some(v(&["dnf", "autoremove", "-y"])),
        PackageManager::Apk | PackageManager::Pacman | PackageManager::Zypper => None,
    }
}

/// The script that answers "does this node need a reboot?" on the node: `yes`, `no`.
///
/// Two signals, either one enough:
///
/// - Debian's flag file, which also covers libc and the microcode.
/// - The running kernel is not the newest one installed. On Arch the running kernel's
///   modules are even DELETED by the upgrade, and the next module to load fails.
pub const REBOOT_PROBE: &str = "if [ -f /var/run/reboot-required ]; then echo yes; exit 0; fi; \
     echo \"running=$(uname -r)\"; \
     ls -1 /lib/modules 2>/dev/null | sed 's/^/installed=/'";

/// Reads the output of [`REBOOT_PROBE`]. `None` when it says nothing usable — an unknown
/// state, which is not "no reboot needed".
pub fn reboot_required(probe_output: &str) -> Option<bool> {
    let mut running = None;
    let mut installed = Vec::new();
    for line in probe_output.lines() {
        let line = line.trim();
        if line == "yes" {
            return Some(true);
        }
        if let Some(r) = line.strip_prefix("running=") {
            running = Some(r.to_string());
        } else if let Some(i) = line.strip_prefix("installed=") {
            installed.push(i.to_string());
        }
    }
    let running = running?;
    if installed.is_empty() {
        return None;
    }
    if !installed.contains(&running) {
        return Some(true);
    }
    let newest = installed
        .iter()
        .max_by(|a, b| compare_kernels(a, b))
        .cloned()?;
    Some(compare_kernels(&newest, &running) == std::cmp::Ordering::Greater)
}

/// Orders kernel release strings numerically: `6.1.0-26-amd64` after `6.1.0-9-amd64`,
/// which a string comparison gets backwards.
fn compare_kernels(a: &str, b: &str) -> std::cmp::Ordering {
    let nums = |s: &str| -> Vec<u64> {
        s.split(|c: char| !c.is_ascii_digit())
            .filter(|p| !p.is_empty())
            .filter_map(|p| p.parse().ok())
            .collect()
    };
    nums(a).cmp(&nums(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn distro(os_release: &str) -> Distro {
        Distro::parse(os_release).expect("parsable")
    }

    #[test]
    fn the_engine_is_kept_out_of_unattended_upgrades() {
        let files = Unattended::Apt.guard_files(false);
        let (_, conf) = files
            .iter()
            .find(|(p, _)| p.contains("apt.conf.d"))
            .expect("the blacklist");
        for p in ["docker-ce", "containerd.io", "docker.io", "containerd"] {
            assert!(conf.contains(&format!("\"{p}\";")), "{p} not excluded");
        }
        assert!(conf.contains("Automatic-Reboot \"false\""));
    }

    #[test]
    fn needrestart_is_told_to_leave_the_engine_alone_where_it_runs() {
        assert!(!Unattended::Apt
            .guard_files(false)
            .iter()
            .any(|(p, _)| p.contains("needrestart")));
        let files = Unattended::Apt.guard_files(true);
        let (_, conf) = files
            .iter()
            .find(|(p, _)| p.contains("needrestart"))
            .expect("the override");
        assert!(conf.contains("qr(^docker)} = 0"));
    }

    #[test]
    fn dnf_automatic_applies_security_advisories_only() {
        let u = Unattended::for_distro(&distro("ID=rocky\nVERSION_ID=9.4\nPRETTY_NAME=x\n"));
        assert_eq!(u, Unattended::DnfAutomatic { dnf5: false });
        let (_, conf) = &u.enabling_files()[0];
        assert!(conf.contains("upgrade_type = security"));
        assert!(conf.contains("apply_updates = yes"));
        assert_eq!(u.timer(), Some("dnf-automatic.timer"));
    }

    #[test]
    fn fedora_41_moved_to_dnf5() {
        let u = Unattended::for_distro(&distro("ID=fedora\nVERSION_ID=41\nPRETTY_NAME=x\n"));
        assert_eq!(u, Unattended::DnfAutomatic { dnf5: true });
        assert_eq!(u.package(), Some("dnf5-plugin-automatic"));
        let u = Unattended::for_distro(&distro("ID=fedora\nVERSION_ID=40\nPRETTY_NAME=x\n"));
        assert_eq!(u, Unattended::DnfAutomatic { dnf5: false });
    }

    #[test]
    fn a_distribution_left_unautomated_says_why() {
        for id in ["arch", "alpine", "opensuse-leap"] {
            match Unattended::for_distro(&distro(&format!("ID={id}\nPRETTY_NAME=x\n"))) {
                Unattended::NotAutomated(why) => assert!(why.contains("hlb node upgrade")),
                other => panic!("{id}: {other:?}"),
            }
        }
    }

    #[test]
    fn a_full_upgrade_takes_new_kernels_and_asks_nothing() {
        let cmds = full_upgrade(&distro("ID=debian\nPRETTY_NAME=x\n"));
        let upgrade = cmds.last().expect("a command").join(" ");
        assert!(upgrade.contains("full-upgrade"));
        assert!(upgrade.contains("noninteractive"));
        assert!(upgrade.contains("--force-confold"));
    }

    #[test]
    fn nothing_is_autoremoved_where_the_package_manager_cannot_tell_a_wanted_package() {
        assert!(autoremove(&distro("ID=arch\nPRETTY_NAME=x\n")).is_none());
        assert!(autoremove(&distro("ID=debian\nPRETTY_NAME=x\n"))
            .expect("apt")
            .contains(&"autoremove".to_string()));
    }

    #[test]
    fn debians_flag_file_means_a_reboot() {
        assert_eq!(reboot_required("yes\n"), Some(true));
    }

    #[test]
    fn a_newer_installed_kernel_means_a_reboot() {
        let out = "running=6.1.0-9-amd64\ninstalled=6.1.0-26-amd64\ninstalled=6.1.0-9-amd64\n";
        assert_eq!(reboot_required(out), Some(true));
    }

    #[test]
    fn the_running_kernel_being_the_newest_means_none() {
        let out = "running=6.1.0-26-amd64\ninstalled=6.1.0-26-amd64\ninstalled=6.1.0-9-amd64\n";
        assert_eq!(reboot_required(out), Some(false));
    }

    #[test]
    fn a_running_kernel_whose_modules_are_gone_means_a_reboot() {
        // Arch deletes the old kernel's modules on upgrade.
        let out = "running=6.11.1-arch1-1\ninstalled=6.11.3-arch1-1\n";
        assert_eq!(reboot_required(out), Some(true));
    }

    #[test]
    fn an_unreadable_probe_is_unknown_not_fine() {
        assert_eq!(reboot_required(""), None);
        assert_eq!(reboot_required("running=6.1.0\n"), None);
    }
}
