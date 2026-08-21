//! Détection de la distribution (§2ter.3).
//!
//! Le plan promet « n'importe quelle distribution serveur ». Tenir cette promesse
//! demande une abstraction, pas une pile de `if`.
//!
//! `/etc/os-release` est le seul mécanisme normalisé (freedesktop) et présent partout
//! depuis ~2012. On le parse plutôt que de deviner à partir de la présence de `apt`
//! ou `dnf` : une machine peut avoir les deux, et le champ `ID_LIKE` donne la famille
//! pour les dérivées qu'on ne connaît pas encore.

use std::collections::BTreeMap;

/// Les familles qu'on sait piloter.
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
    /// La commande qui installe des paquets, **sans interaction**.
    ///
    /// 🔴 Le mode non interactif n'est pas un détail : une invite « voulez-vous
    /// continuer ? » sur un nœud distant bloque le bootstrap indéfiniment, sans
    /// message d'erreur, jusqu'au délai d'attente.
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

    /// Rafraîchit l'index des paquets. Nécessaire avant une installation sur les
    /// familles qui ne le font pas d'elles-mêmes.
    pub fn refresh_command(&self) -> Option<Vec<String>> {
        match self {
            Self::Apt => Some(vec!["apt-get".into(), "update".into()]),
            Self::Dnf => None, // dnf rafraîchit selon ses métadonnées.
            Self::Apk => None, // `--no-cache` s'en charge.
            Self::Pacman => Some(vec!["pacman".into(), "-Sy".into(), "--noconfirm".into()]),
            Self::Zypper => Some(vec![
                "zypper".into(),
                "--non-interactive".into(),
                "refresh".into(),
            ]),
        }
    }

    /// Comment savoir si un paquet est présent.
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

/// Ce qu'on a appris de la machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Distro {
    /// `ID` de os-release : `debian`, `ubuntu`, `rocky`…
    pub id: String,
    pub version_id: Option<String>,
    pub pretty_name: String,
    pub family: Family,
}

impl Distro {
    /// Analyse le contenu de `/etc/os-release`.
    ///
    /// Renvoie `None` si le fichier ne permet pas de conclure — mieux vaut refuser
    /// clairement que d'installer des paquets avec le mauvais gestionnaire.
    pub fn parse(os_release: &str) -> Option<Self> {
        let champs: BTreeMap<&str, String> = os_release
            .lines()
            .filter_map(|l| {
                let l = l.trim();
                if l.is_empty() || l.starts_with('#') {
                    return None;
                }
                let (k, v) = l.split_once('=')?;
                // Les valeurs peuvent être entre guillemets, simples ou doubles.
                let v = v.trim().trim_matches('"').trim_matches('\'');
                Some((k.trim(), v.to_string()))
            })
            .collect();

        let id = champs.get("ID")?.to_lowercase();
        let id_like = champs
            .get("ID_LIKE")
            .map(|s| s.to_lowercase())
            .unwrap_or_default();

        let family = Self::family_of(&id, &id_like)?;

        Some(Self {
            pretty_name: champs
                .get("PRETTY_NAME")
                .cloned()
                .unwrap_or_else(|| id.clone()),
            version_id: champs.get("VERSION_ID").cloned(),
            id,
            family,
        })
    }

    /// La famille, déduite de `ID` puis de `ID_LIKE`.
    ///
    /// `ID_LIKE` est ce qui permet de gérer les dérivées inconnues : Linux Mint
    /// annonce `ID_LIKE=ubuntu debian`, Alma et Rocky `ID_LIKE="rhel centos fedora"`.
    /// Sans lui, chaque nouvelle dérivée demanderait une modification du code.
    fn family_of(id: &str, id_like: &str) -> Option<Family> {
        let connue = |s: &str| match s {
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

        connue(id).or_else(|| id_like.split_whitespace().find_map(connue))
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
        let d = Distro::parse(DEBIAN_12).expect("analysable");
        assert_eq!(d.id, "debian");
        assert_eq!(d.family, Family::Debian);
        assert_eq!(d.version_id.as_deref(), Some("12"));
        assert_eq!(d.package_manager(), PackageManager::Apt);
    }

    #[test]
    fn a_derivative_falls_back_to_its_family() {
        // ubuntu est connue directement, mais la logique doit aussi marcher via ID_LIKE.
        assert_eq!(
            Distro::parse(UBUNTU_24).expect("analysable").family,
            Family::Debian
        );
        assert_eq!(
            Distro::parse(ROCKY_9).expect("analysable").family,
            Family::RedHat
        );
    }

    #[test]
    fn an_unknown_derivative_is_handled_through_id_like() {
        // 🔴 C'est ce qui évite de modifier le code à chaque nouvelle dérivée.
        let inconnue = "ID=ma-distro-maison\nID_LIKE=\"debian\"\nPRETTY_NAME=\"Maison\"\n";
        let d = Distro::parse(inconnue).expect("analysable");
        assert_eq!(d.family, Family::Debian);
        assert_eq!(d.id, "ma-distro-maison");
    }

    #[test]
    fn a_truly_unknown_distro_is_refused() {
        // Mieux vaut refuser que d'installer avec le mauvais gestionnaire.
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
        let d = Distro::parse(y).expect("analysable");
        assert_eq!(d.id, "alpine");
        assert_eq!(d.pretty_name, "Alpine Linux");
    }

    #[test]
    fn alpine_is_recognised() {
        let d = Distro::parse(ALPINE).expect("analysable");
        assert_eq!(d.family, Family::Alpine);
        assert_eq!(d.package_manager(), PackageManager::Apk);
    }

    #[test]
    fn install_commands_are_non_interactive() {
        // 🔴 Une invite « voulez-vous continuer ? » sur un nœud distant bloque le
        // bootstrap sans message, jusqu'au délai d'attente.
        for pm in [
            PackageManager::Apt,
            PackageManager::Dnf,
            PackageManager::Apk,
            PackageManager::Pacman,
            PackageManager::Zypper,
        ] {
            let cmd = pm.install_command(&["restic"]).join(" ");
            // Chaque famille a son propre drapeau : -y, --noconfirm,
            // --non-interactive, DEBIAN_FRONTEND, ou l'absence d'invite (apk).
            let non_interactif = [
                "-y",
                "noninteractive",
                "--no-cache",
                "--noconfirm",
                "--non-interactive",
            ];
            assert!(
                non_interactif.iter().any(|f| cmd.contains(f)),
                "{pm:?} : commande interactive → {cmd}"
            );
            assert!(cmd.contains("restic"), "{cmd}");
        }
    }

    #[test]
    fn apt_avoids_pulling_recommended_packages() {
        // Sur un nœud à 4 Go, les « recommandés » d'apt tirent des dizaines de paquets
        // inutiles — parfois un serveur graphique.
        let cmd = PackageManager::Apt.install_command(&["restic"]).join(" ");
        assert!(cmd.contains("--no-install-recommends"), "{cmd}");
    }

    #[test]
    fn several_packages_are_passed_together() {
        // Un seul appel plutôt qu'un par paquet : les gestionnaires résolvent mieux
        // les dépendances, et c'est bien plus rapide.
        let cmd = PackageManager::Apk.install_command(&["restic", "wireguard-tools"]);
        assert!(cmd.contains(&"restic".to_string()));
        assert!(cmd.contains(&"wireguard-tools".to_string()));
    }

    #[test]
    fn refresh_is_only_declared_where_it_is_needed() {
        assert!(PackageManager::Apt.refresh_command().is_some());
        // apk --no-cache et dnf gèrent leurs métadonnées seuls.
        assert!(PackageManager::Apk.refresh_command().is_none());
        assert!(PackageManager::Dnf.refresh_command().is_none());
    }
}
