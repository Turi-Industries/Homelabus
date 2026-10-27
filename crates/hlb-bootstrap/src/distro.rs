//! Distribution detection.
//!
//! `/etc/os-release` is the only standardised mechanism (freedesktop) and has been
//! present everywhere since about 2012. It is parsed rather than guessing from the
//! presence of `apt` or `dnf`: a machine can have both, and the `ID_LIKE` field gives
//! the family for derivatives we do not know about yet.

use std::collections::BTreeMap;

/// The families we know how to drive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    Debian,
    RedHat,
    Alpine,
    Arch,
    Suse,
}

impl Family {
    pub fn package_manager(&self) -> PackageManager {
        match self {
            Self::Debian => PackageManager::Apt,
            Self::RedHat => PackageManager::Dnf,
            Self::Alpine => PackageManager::Apk,
            Self::Arch => PackageManager::Pacman,
            Self::Suse => PackageManager::Zypper,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Debian => "debian",
            Self::RedHat => "redhat",
            Self::Alpine => "alpine",
            Self::Arch => "arch",
            Self::Suse => "suse",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageManager {
    Apt,
    Dnf,
    Apk,
    Pacman,
    Zypper,
}

impl PackageManager {
    /// The command that installs packages, **non-interactively**.
    ///
    /// 🔴 Non-interactive mode is not a detail: a "do you want to continue?" prompt on
    /// a remote node blocks the bootstrap indefinitely, with no error message, until
    /// the timeout.
    pub fn install_command(&self, packages: &[&str]) -> Vec<String> {
        let p: Vec<String> = packages.iter().map(|s| s.to_string()).collect();
        match self {
            Self::Apt => [
                vec![
                    "env".into(),
                    "DEBIAN_FRONTEND=noninteractive".into(),
                    "apt-get".into(),
                    "install".into(),
                    "-y".into(),
                    "--no-install-recommends".into(),
                ],
                p,
            ]
            .concat(),
            Self::Dnf => [vec!["dnf".into(), "install".into(), "-y".into()], p].concat(),
            Self::Apk => [vec!["apk".into(), "add".into(), "--no-cache".into()], p].concat(),
            Self::Pacman => [
                vec![
                    "pacman".into(),
                    "-S".into(),
                    "--noconfirm".into(),
                    "--needed".into(),
                ],
                p,
            ]
            .concat(),
            Self::Zypper => [
                vec![
                    "zypper".into(),
                    "--non-interactive".into(),
                    "install".into(),
                ],
                p,
            ]
            .concat(),
        }
    }

    /// Refreshes the package index. Needed before installing on the families that do
    /// not do it themselves.
    pub fn refresh_command(&self) -> Option<Vec<String>> {
        match self {
            Self::Apt => Some(vec!["apt-get".into(), "update".into()]),
            Self::Dnf => None, // dnf refreshes from its own metadata.
            Self::Apk => None, // `--no-cache` takes care of it.
            // `-Syu`, never `-Sy`: refreshing the index then installing against it
            // without upgrading is a partial upgrade, which Arch does not support — a
            // new package linked against libraries the system does not have yet.
            Self::Pacman => Some(vec!["pacman".into(), "-Syu".into(), "--noconfirm".into()]),
            Self::Zypper => Some(vec![
                "zypper".into(),
                "--non-interactive".into(),
                "refresh".into(),
            ]),
        }
    }

    /// How to tell whether a package is present.
    pub fn query_command(&self, package: &str) -> Vec<String> {
        match self {
            Self::Apt => vec![
                "dpkg-query".into(),
                "-W".into(),
                "-f=${Status}".into(),
                package.into(),
            ],
            Self::Dnf => vec!["rpm".into(), "-q".into(), package.into()],
            Self::Apk => vec!["apk".into(), "info".into(), "-e".into(), package.into()],
            Self::Pacman => vec!["pacman".into(), "-Q".into(), package.into()],
            Self::Zypper => vec!["rpm".into(), "-q".into(), package.into()],
        }
    }
}

/// What we have learned about the machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Distro {
    /// `ID` de os-release : `debian`, `ubuntu`, `rocky`…
    pub id: String,
    pub version_id: Option<String>,
    pub pretty_name: String,
    pub family: Family,
    /// `VERSION_CODENAME`: `bookworm`, `noble`… What an APT repository is keyed on.
    pub codename: Option<String>,
    /// `UBUNTU_CODENAME`, carried by Ubuntu's derivatives (Mint, Pop!_OS). Their own
    /// codename (`wilma`) names nothing in a third-party repository.
    pub ubuntu_codename: Option<String>,
}

impl Distro {
    /// Parses the content of `/etc/os-release`.
    ///
    /// Returns `None` when the file does not allow a conclusion — refusing clearly
    /// beats installing packages with the wrong package manager.
    pub fn parse(os_release: &str) -> Option<Self> {
        let fields: BTreeMap<&str, String> = os_release
            .lines()
            .filter_map(|l| {
                let l = l.trim();
                if l.is_empty() || l.starts_with('#') {
                    return None;
                }
                let (k, v) = l.split_once('=')?;
                // Values can be quoted, with single or double quotes.
                let v = v.trim().trim_matches('"').trim_matches('\'');
                Some((k.trim(), v.to_string()))
            })
            .collect();

        let id = fields.get("ID")?.to_lowercase();
        let id_like = fields
            .get("ID_LIKE")
            .map(|s| s.to_lowercase())
            .unwrap_or_default();

        let family = Self::family_of(&id, &id_like)?;

        Some(Self {
            pretty_name: fields
                .get("PRETTY_NAME")
                .cloned()
                .unwrap_or_else(|| id.clone()),
            version_id: fields.get("VERSION_ID").cloned(),
            codename: fields
                .get("VERSION_CODENAME")
                .filter(|c| !c.is_empty())
                .cloned(),
            ubuntu_codename: fields
                .get("UBUNTU_CODENAME")
                .filter(|c| !c.is_empty())
                .cloned(),
            id,
            family,
        })
    }

    /// The family, derived from `ID` and then `ID_LIKE`.
    ///
    /// `ID_LIKE` is what handles unknown derivatives: Linux Mint announces
    /// `ID_LIKE=ubuntu debian`, Alma and Rocky `ID_LIKE="rhel centos fedora"`. Without
    /// it, every new derivative would need a code change.
    fn family_of(id: &str, id_like: &str) -> Option<Family> {
        let known = |s: &str| match s {
            "debian" | "ubuntu" | "raspbian" | "linuxmint" | "pop" | "devuan" => {
                Some(Family::Debian)
            }
            "rhel" | "centos" | "fedora" | "rocky" | "almalinux" | "ol" | "amzn" => {
                Some(Family::RedHat)
            }
            "alpine" => Some(Family::Alpine),
            "arch" | "manjaro" | "endeavouros" => Some(Family::Arch),
            "opensuse" | "opensuse-leap" | "opensuse-tumbleweed" | "sles" | "suse" => {
                Some(Family::Suse)
            }
            _ => None,
        };

        known(id).or_else(|| id_like.split_whitespace().find_map(known))
    }

    pub fn package_manager(&self) -> PackageManager {
        self.family.package_manager()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEBIAN_12: &str = r#"
PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
NAME="Debian GNU/Linux"
VERSION_ID="12"
VERSION="12 (bookworm)"
ID=debian
HOME_URL="https://www.debian.org/"
"#;

    const UBUNTU_24: &str = r#"
PRETTY_NAME="Ubuntu 24.04.1 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
ID=ubuntu
ID_LIKE=debian
"#;

    const ROCKY_9: &str = r#"
NAME="Rocky Linux"
VERSION="9.4 (Blue Onyx)"
ID="rocky"
ID_LIKE="rhel centos fedora"
VERSION_ID="9.4"
PRETTY_NAME="Rocky Linux 9.4 (Blue Onyx)"
"#;

    const ALPINE: &str = r#"
NAME="Alpine Linux"
ID=alpine
VERSION_ID=3.20.3
PRETTY_NAME="Alpine Linux v3.20"
"#;

    #[test]
    fn debian_is_recognised() {
        let d = Distro::parse(DEBIAN_12).expect("parsable");
        assert_eq!(d.id, "debian");
        assert_eq!(d.family, Family::Debian);
        assert_eq!(d.version_id.as_deref(), Some("12"));
        assert_eq!(d.package_manager(), PackageManager::Apt);
    }

    #[test]
    fn a_derivative_falls_back_to_its_family() {
        // ubuntu is known directly, but the logic must work through ID_LIKE too.
        assert_eq!(
            Distro::parse(UBUNTU_24).expect("parsable").family,
            Family::Debian
        );
        assert_eq!(
            Distro::parse(ROCKY_9).expect("parsable").family,
            Family::RedHat
        );
    }

    #[test]
    fn an_unknown_derivative_is_handled_through_id_like() {
        // 🔴 This is what avoids a code change for every new derivative.
        let unknown = "ID=ma-distro-maison\nID_LIKE=\"debian\"\nPRETTY_NAME=\"Maison\"\n";
        let d = Distro::parse(unknown).expect("parsable");
        assert_eq!(d.family, Family::Debian);
        assert_eq!(d.id, "ma-distro-maison");
    }

    #[test]
    fn a_truly_unknown_distro_is_refused() {
        // Refusing beats installing with the wrong package manager.
        let y = "ID=exotique\nPRETTY_NAME=\"Exotique\"\n";
        assert!(Distro::parse(y).is_none());
    }

    #[test]
    fn a_file_without_id_is_refused() {
        assert!(Distro::parse("PRETTY_NAME=\"Sans identifiant\"\n").is_none());
        assert!(Distro::parse("").is_none());
    }

    #[test]
    fn quotes_and_comments_are_handled() {
        let y = "# commentaire\nID='alpine'\nPRETTY_NAME=\"Alpine Linux\"\n\n";
        let d = Distro::parse(y).expect("parsable");
        assert_eq!(d.id, "alpine");
        assert_eq!(d.pretty_name, "Alpine Linux");
    }

    #[test]
    fn alpine_is_recognised() {
        let d = Distro::parse(ALPINE).expect("parsable");
        assert_eq!(d.family, Family::Alpine);
        assert_eq!(d.package_manager(), PackageManager::Apk);
    }

    #[test]
    fn install_commands_are_non_interactive() {
        // 🔴 A "do you want to continue?" prompt on a remote node blocks the bootstrap
        // with no message, until the timeout.
        for pm in [
            PackageManager::Apt,
            PackageManager::Dnf,
            PackageManager::Apk,
            PackageManager::Pacman,
            PackageManager::Zypper,
        ] {
            let cmd = pm.install_command(&["restic"]).join(" ");
            // Each family has its own flag: -y, --noconfirm, --non-interactive,
            // DEBIAN_FRONTEND, or no prompt at all (apk).
            let non_interactive = [
                "-y",
                "noninteractive",
                "--no-cache",
                "--noconfirm",
                "--non-interactive",
            ];
            assert!(
                non_interactive.iter().any(|f| cmd.contains(f)),
                "{pm:?} : commande interactive → {cmd}"
            );
            assert!(cmd.contains("restic"), "{cmd}");
        }
    }

    #[test]
    fn apt_avoids_pulling_recommended_packages() {
        // On a 4 GB node, apt's "recommends" pull dozens of useless packages -
        // sometimes a graphical server.
        let cmd = PackageManager::Apt.install_command(&["restic"]).join(" ");
        assert!(cmd.contains("--no-install-recommends"), "{cmd}");
    }

    #[test]
    fn several_packages_are_passed_together() {
        // One call rather than one per package: the managers resolve dependencies
        // better, and it is far faster.
        let cmd = PackageManager::Apk.install_command(&["restic", "wireguard-tools"]);
        assert!(cmd.contains(&"restic".to_string()));
        assert!(cmd.contains(&"wireguard-tools".to_string()));
    }

    #[test]
    fn refresh_is_only_declared_where_it_is_needed() {
        assert!(PackageManager::Apt.refresh_command().is_some());
        // apk --no-cache and dnf manage their own metadata.
        assert!(PackageManager::Apk.refresh_command().is_none());
        assert!(PackageManager::Dnf.refresh_command().is_none());
    }
}
