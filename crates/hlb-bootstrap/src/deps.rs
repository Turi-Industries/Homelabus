//! The dependencies installed automatically.
//!
//! **Principle: you install nothing by hand.** The only manual step in the project is
//! downloading the `hlb` binary. Everything else is derived and installed.
//!
//! ## The three rules that avoid nasty surprises
//!
//! 1. **A floor version, not a fixed one.** A Docker that is too old breaks Swarm; a
//!    Docker pinned to the patch blocks security fixes.
//! 2. **Nothing is installed without being announced.** A plan is produced, a script is
//!    not endured - the same principle as everywhere else.
//! 3. 🔴 **Never upgrade what we did not install.** Overwriting the Docker
//!    configuration of an existing machine is the best way to break something else. We
//!    add, we do not replace.

use crate::distro::{Distro, PackageManager};

/// A dependency and the reason it is there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dependency {
    /// Canonical name, independent of the distribution.
    pub name: &'static str,
    /// Why it is there. Shown in the plan: nobody should have to guess.
    pub reason: &'static str,
    /// The minimum version required, when it matters.
    pub min_version: Option<&'static str>,
    /// Essential, or merely recommended?
    pub required: bool,
}

impl Dependency {
    /// How to find out whether it is there.
    ///
    /// ⚠️ Rarely the canonical name: the WireGuard tools install `wg`, smartmontools
    /// installs `smartctl`, nothing is called `nfs-server`, and `ca-certificates` is no
    /// binary at all. Probing by name reports them missing on every machine that has
    /// them — and a plan that offers to install what is already there stops being read.
    pub fn probe(&self) -> Probe {
        match self.name {
            "wireguard-tools" => Probe::Binary("wg"),
            "nftables" => Probe::Binary("nft"),
            "smartmontools" => Probe::Binary("smartctl"),
            "nfs-server" => Probe::Binary("exportfs"),
            "nfs-client" => Probe::Binary("mount.nfs"),
            "ntp" => Probe::Clock,
            "ca-certificates" => Probe::Package,
            n => Probe::Binary(n),
        }
    }

    /// The package name on this distribution.
    ///
    /// The names diverge more than you would think: `wireguard-tools` on Debian and
    /// Alpine, `wireguard-tools` on Fedora too, but `nfs-common` becomes `nfs-utils`
    /// almost everywhere else.
    pub fn package_for(&self, pm: PackageManager) -> &'static str {
        match (self.name, pm) {
            ("nfs-client", PackageManager::Apt) => "nfs-common",
            ("nfs-client", _) => "nfs-utils",
            // The tools only: the module is a decision of its own, `zfs::source`.
            ("zfs", PackageManager::Apt) => "zfsutils-linux",
            ("zfs", PackageManager::Dnf) => "zfs",
            ("zfs", PackageManager::Pacman) => "zfs-utils",
            ("zfs", _) => "zfs",
            ("nfs-server", PackageManager::Apt) => "nfs-kernel-server",
            ("nfs-server", _) => "nfs-utils",
            ("ntp", PackageManager::Apk) => "chrony",
            ("ntp", _) => "chrony",
            ("ca-certificates", PackageManager::Pacman) => "ca-certificates",
            (n, _) => n,
        }
    }
}

/// How a dependency's presence is observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Probe {
    /// A binary on the `PATH`.
    Binary(&'static str),
    /// The package manager's own record, for what installs no binary.
    Package,
    /// Any NTP client systemd reports active, or chrony. What matters is ONE client
    /// keeping the clock: installing chrony next to a running systemd-timesyncd gives
    /// two daemons fighting over it.
    Clock,
}

/// The canonical name of the container engine, installed by [`crate::docker`] rather
/// than as one more package: where it comes from is a decision of its own.
pub const DOCKER: &str = "docker";

/// The oldest Docker Engine accepted. Swarm itself needs 25 — 24 drops
/// `no_new_privileges` from a service's spec without a word (`hardening_reaches_swarm`,
/// measured on 24.0.9 to 27.5.1) — and the floor is the current major, which every
/// source [`crate::docker::source`] picks installs.
pub const DOCKER_FLOOR: &str = "29.0";

/// The base dependencies, present on every node.
pub const BASE: &[Dependency] = &[
    Dependency {
        name: "docker",
        reason: "the orchestrator itself",
        min_version: Some(DOCKER_FLOOR),
        required: true,
    },
    Dependency {
        name: "wireguard-tools",
        reason: "encrypted mesh between nodes - Swarm must never listen on the public IP",
        min_version: None,
        required: true,
    },
    Dependency {
        name: "nftables",
        reason: "keeps Swarm's ports on the mesh: VXLAN has no authentication",
        min_version: None,
        required: true,
    },
    Dependency {
        name: "restic",
        reason: "the backup engine",
        min_version: None,
        required: true,
    },
    Dependency {
        name: "ca-certificates",
        reason: "TLS verification for registries and repositories",
        min_version: None,
        required: true,
    },
    Dependency {
        name: "ntp",
        reason: "🔴 the clock - drift breaks Swarm AND certificate validation",
        min_version: None,
        required: true,
    },
    Dependency {
        name: "smartmontools",
        reason: "disk health reported by the agent",
        min_version: None,
        required: false,
    },
];

/// What a STORAGE node needs on top of the base.
///
/// ⚠️ Separate from `BASE` on purpose: installing ZFS on every node would pull a kernel
/// module onto machines that will never hold a disk, and a kernel module is exactly the
/// thing that stops a machine booting after an upgrade.
pub const STORAGE: &[Dependency] = &[
    Dependency {
        name: "zfs",
        reason: "the pool that holds the application data",
        min_version: None,
        required: true,
    },
    Dependency {
        name: "nfs-server",
        reason: "exporting the datasets to the other nodes",
        min_version: None,
        required: false,
    },
];

/// What was observed on the machine, for one dependency.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Presence {
    /// Absent: to be installed.
    Missing,
    /// Present and sufficient: **left alone**.
    Satisfied { version: Option<String> },
    /// Present but too old.
    TooOld { found: String, required: String },
}

impl Presence {
    pub fn needs_install(&self) -> bool {
        matches!(self, Self::Missing | Self::TooOld { .. })
    }
}

/// A decision, ready to be shown before execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub dependency: Dependency,
    pub package: &'static str,
    pub presence: Presence,
}

impl Decision {
    pub fn describe(&self) -> String {
        match &self.presence {
            Presence::Satisfied { version } => format!(
                "✓ {} already present{} - left alone",
                self.dependency.name,
                version
                    .as_ref()
                    .map(|v| format!(" ({v})"))
                    .unwrap_or_default()
            ),
            Presence::Missing => format!(
                "+ {} ({}) — {}",
                self.dependency.name, self.package, self.dependency.reason
            ),
            Presence::TooOld { found, required } => format!(
                "↑ {} {found} → ≥ {required} — {}",
                self.dependency.name, self.dependency.reason
            ),
        }
    }
}

/// The dependency installation plan.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DependencyPlan {
    pub decisions: Vec<Decision>,
}

impl DependencyPlan {
    /// The packages to install through the distribution's own repositories.
    ///
    /// Docker is not among them: its package name, repository and signing key depend
    /// on the distribution's version, and [`crate::docker::source`] decides them.
    pub fn to_install(&self) -> Vec<&'static str> {
        self.decisions
            .iter()
            .filter(|d| d.dependency.name != DOCKER && d.presence.needs_install())
            .map(|d| d.package)
            .collect()
    }

    /// What was decided about Docker.
    pub fn docker(&self) -> Option<&Decision> {
        self.decisions.iter().find(|d| d.dependency.name == DOCKER)
    }

    /// Is anything indispensable missing?
    pub fn missing_required(&self) -> Vec<&'static str> {
        self.decisions
            .iter()
            .filter(|d| d.dependency.required && d.presence.needs_install())
            .map(|d| d.dependency.name)
            .collect()
    }

    pub fn is_satisfied(&self) -> bool {
        self.decisions.iter().all(|d| !d.presence.needs_install())
    }
}

/// Builds the plan from what was observed.
///
/// `observed` maps the canonical name to the detected version (`None` means absent).
pub fn plan(distro: &Distro, observed: &[(&str, Option<String>)]) -> DependencyPlan {
    plan_for(distro, observed, false)
}

/// Same, for a node that will carry the storage.
///
/// ⚠️ `storage` is a DECISION, not a detection. Installing ZFS wherever a pool happens
/// to exist would pull a kernel module onto a machine that only borrowed a disk once —
/// and a kernel module is what stops a machine booting after an upgrade.
pub fn plan_for(
    distro: &Distro,
    observed: &[(&str, Option<String>)],
    storage: bool,
) -> DependencyPlan {
    let pm = distro.package_manager();

    let wanted: Vec<&Dependency> = if storage {
        BASE.iter().chain(STORAGE.iter()).collect()
    } else {
        BASE.iter().collect()
    };

    let decisions = wanted
        .into_iter()
        .map(|dep| {
            let found = observed
                .iter()
                .find(|(n, _)| *n == dep.name)
                .and_then(|(_, v)| v.clone());

            let presence = match (found, dep.min_version) {
                (None, _) => Presence::Missing,
                // 🔴 Present and with no version requirement: nothing is touched.
                // An empty version: present, with nothing worth printing about it.
                (Some(v), None) => Presence::Satisfied {
                    version: Some(v).filter(|v| !v.is_empty()),
                },
                (Some(v), Some(min)) => {
                    if version_at_least(&v, min) {
                        Presence::Satisfied { version: Some(v) }
                    } else {
                        Presence::TooOld {
                            found: v,
                            required: min.to_string(),
                        }
                    }
                }
            };

            Decision {
                dependency: dep.clone(),
                package: dep.package_for(pm),
                presence,
            }
        })
        .collect();

    DependencyPlan { decisions }
}

/// `found >= required`, compared component by component.
///
/// Tolerant about the form: `24.0.7`, `24.0.7-ce`, `v24.0` are all accepted. Suffixes
/// are ignored - `24.0.7-ce` and `24.0.7` are the same version here.
pub fn version_at_least(found: &str, required: &str) -> bool {
    let parse = |s: &str| -> Vec<u64> {
        s.trim()
            .trim_start_matches('v')
            .split(['.', '-', '+', '~'])
            .take_while(|p| p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty())
            .filter_map(|p| p.parse().ok())
            .collect()
    };

    let f = parse(found);
    let r = parse(required);
    if f.is_empty() {
        // Unreadable version: we cannot claim it is sufficient.
        return false;
    }

    for i in 0..r.len().max(f.len()) {
        let a = f.get(i).copied().unwrap_or(0);
        let b = r.get(i).copied().unwrap_or(0);
        match a.cmp(&b) {
            std::cmp::Ordering::Greater => return true,
            std::cmp::Ordering::Less => return false,
            std::cmp::Ordering::Equal => {}
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn debian() -> Distro {
        Distro::parse("ID=debian\nPRETTY_NAME=\"Debian 12\"\n").expect("distro")
    }

    fn alpine() -> Distro {
        Distro::parse("ID=alpine\nPRETTY_NAME=\"Alpine\"\n").expect("distro")
    }

    #[test]
    fn an_empty_machine_needs_everything_required() {
        let p = plan(&debian(), &[]);
        let missing = p.missing_required();
        assert!(missing.contains(&"docker"));
        assert!(missing.contains(&"restic"));
        assert!(missing.contains(&"ntp"));
        assert!(!p.is_satisfied());
    }

    #[test]
    fn an_existing_recent_docker_is_left_alone() {
        // 🔴 The most important rule: we add, we do not replace. Overwriting the
        // Docker configuration of an existing machine breaks something else.
        let p = plan(&debian(), &[("docker", Some("29.9.2".into()))]);
        let docker = p
            .decisions
            .iter()
            .find(|d| d.dependency.name == "docker")
            .expect("docker present");

        assert!(matches!(docker.presence, Presence::Satisfied { .. }));
        assert!(!p.to_install().contains(&"docker"));
        assert!(docker.describe().contains("left alone"));
    }

    #[test]
    fn a_too_old_docker_is_flagged_for_upgrade() {
        // Debian stable sometimes ships a Docker that does not handle Swarm properly.
        let p = plan(&debian(), &[("docker", Some("20.10.5".into()))]);
        let docker = p
            .decisions
            .iter()
            .find(|d| d.dependency.name == "docker")
            .expect("docker");

        assert!(matches!(docker.presence, Presence::TooOld { .. }));
        assert!(
            docker.describe().contains("20.10.5"),
            "{}",
            docker.describe()
        );
        assert!(docker.describe().contains(DOCKER_FLOOR));
    }

    #[test]
    fn zfs_is_never_installed_on_a_node_that_did_not_ask_for_it() {
        // 🔴 ZFS pulls a kernel module. On a machine that will never hold a disk that
        // is pure risk: a module that fails to build against a new kernel is how a node
        // stops booting after an upgrade. Storage is a decision, never a detection.
        let d = debian();
        let observed: Vec<(&str, Option<String>)> = BASE
            .iter()
            .chain(STORAGE.iter())
            .map(|d| (d.name, None))
            .collect();

        let plain = plan_for(&d, &observed, false);
        assert!(
            !plain.to_install().iter().any(|p| p.contains("zfs")),
            "ZFS on an ordinary node: {:?}",
            plain.to_install()
        );

        let storage = plan_for(&d, &observed, true);
        assert!(
            storage.to_install().contains(&"zfsutils-linux"),
            "the storage node did not get ZFS: {:?}",
            storage.to_install()
        );
    }

    #[test]
    fn a_package_with_no_matching_binary_is_probed_by_one_that_exists() {
        // ⚠️ Nothing on the system is called `nfs-server`. Probing by the package name
        // would report it missing on every machine that has it — and a plan that offers
        // to install what is already there stops being read.
        let nfs = STORAGE
            .iter()
            .find(|d| d.name == "nfs-server")
            .expect("declared");
        assert_eq!(nfs.probe(), Probe::Binary("exportfs"));
    }

    #[test]
    fn what_installs_no_binary_of_its_own_name_is_probed_by_what_it_does_install() {
        // The first version probed `wireguard-tools`, `smartmontools` and
        // `ca-certificates` as binaries: all three were "missing" on every machine, and
        // every run offered to install them again.
        let probe = |name| {
            BASE.iter()
                .find(|d| d.name == name)
                .expect("declared")
                .probe()
        };
        assert_eq!(probe("wireguard-tools"), Probe::Binary("wg"));
        assert_eq!(probe("smartmontools"), Probe::Binary("smartctl"));
        assert_eq!(probe("ca-certificates"), Probe::Package);
    }

    #[test]
    fn docker_is_never_handed_to_the_package_manager_by_name() {
        // `apt-get install docker` installs a system-tray applet, not Docker Engine:
        // the package name depends on where Docker comes from, decided elsewhere.
        let p = plan(&debian(), &[]);
        assert!(!p.to_install().contains(&"docker"));
        assert!(p.docker().is_some_and(|d| d.presence.needs_install()));
        assert!(!p.is_satisfied());
    }

    #[test]
    fn package_names_differ_across_distributions() {
        let dep = Dependency {
            name: "nfs-client",
            reason: "NFS mounts",
            min_version: None,
            required: false,
        };
        assert_eq!(dep.package_for(PackageManager::Apt), "nfs-common");
        assert_eq!(dep.package_for(PackageManager::Dnf), "nfs-utils");
        assert_eq!(dep.package_for(PackageManager::Apk), "nfs-utils");
    }

    #[test]
    fn the_plan_explains_why_each_package_is_there() {
        // Nobody should have to guess why the system installs a package.
        let p = plan(&alpine(), &[]);
        for d in &p.decisions {
            if d.presence.needs_install() {
                assert!(
                    !d.dependency.reason.is_empty(),
                    "{} has no justification",
                    d.dependency.name
                );
                assert!(d.describe().contains(d.dependency.reason));
            }
        }
    }

    #[test]
    fn an_optional_dependency_does_not_block() {
        let p = plan(&debian(), &[]);
        // smartmontools is recommended, not required.
        assert!(!p.missing_required().contains(&"smartmontools"));
        // But it still appears in what is proposed for installation.
        assert!(p.to_install().contains(&"smartmontools"));
    }

    #[test]
    fn a_fully_equipped_machine_needs_nothing() {
        let observed: Vec<(&str, Option<String>)> = BASE
            .iter()
            .map(|d| (d.name, Some("99.0.0".to_string())))
            .collect();
        assert!(plan(&debian(), &observed).is_satisfied());
    }

    #[test]
    fn version_comparison_handles_real_world_forms() {
        assert!(version_at_least("24.0.7", "24.0"));
        assert!(version_at_least("27.3.1", "24.0"));
        assert!(version_at_least("24.0", "24.0"));
        assert!(!version_at_least("20.10.5", "24.0"));
        assert!(!version_at_least("23.0.9", "24.0"));

        // Common distribution package suffixes.
        assert!(version_at_least("24.0.7-ce", "24.0"));
        assert!(version_at_least("v24.0.7", "24.0"));
        assert!(version_at_least("26.1.3+dfsg1", "24.0"));
    }

    #[test]
    fn an_unreadable_version_is_never_assumed_sufficient() {
        // 🔴 When in doubt, we do not claim it is fine.
        assert!(!version_at_least("unreadable", "24.0"));
        assert!(!version_at_least("", "24.0"));
    }

    #[test]
    fn the_clock_dependency_is_required() {
        // Clock drift breaks Swarm AND TLS validation - the kind of failure whose
        // cause is very hard to track down.
        let ntp = BASE.iter().find(|d| d.name == "ntp").expect("ntp declared");
        assert!(ntp.required);
        assert!(ntp.reason.contains("clock"));
    }
}
