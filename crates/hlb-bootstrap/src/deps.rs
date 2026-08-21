//! Les dépendances installées automatiquement (§2ter.6).
//!
//! **Principe : tu n'installes rien à la main.** Le seul geste manuel du projet, c'est
//! de télécharger le binaire `hlb`. Tout le reste est déduit et installé.
//!
//! ## Les trois règles qui évitent les mauvaises surprises
//!
//! 1. **Version plancher, pas version fixe.** Un Docker trop ancien casse Swarm ; un
//!    Docker figé au patch près bloque les correctifs de sécurité.
//! 2. **Rien n'est installé sans être annoncé.** On produit un plan, on ne subit pas
//!    un script — c'est le même principe que partout ailleurs.
//! 3. 🔴 **Ne jamais mettre à niveau ce qu'on n'a pas installé.** Écraser la
//!    configuration Docker d'une machine existante est le meilleur moyen de casser
//!    autre chose. On ajoute, on ne remplace pas.

use crate::distro::{Distro, PackageManager};

/// Une dépendance et la raison de sa présence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dependency {
    /// Nom canonique, indépendant de la distribution.
    pub name: &'static str,
    /// Pourquoi elle est là. Affiché dans le plan : personne ne doit avoir à deviner.
    pub reason: &'static str,
    /// Version minimale exigée, si elle compte.
    pub min_version: Option<&'static str>,
    /// Indispensable, ou simplement recommandée ?
    pub required: bool,
}

impl Dependency {
    /// Le nom du paquet sur cette distribution.
    ///
    /// Les noms divergent plus qu'on ne le croit : `wireguard-tools` chez Debian et
    /// Alpine, `wireguard-tools` chez Fedora aussi, mais `nfs-common` devient
    /// `nfs-utils` presque partout ailleurs.
    pub fn package_for(&self, pm: PackageManager) -> &'static str {
        match (self.name, pm) {
            ("nfs-client", PackageManager::Apt) => "nfs-common",
            ("nfs-client", _) => "nfs-utils",
            ("ntp", PackageManager::Apk) => "chrony",
            ("ntp", _) => "chrony",
            ("ca-certificates", PackageManager::Pacman) => "ca-certificates",
            (n, _) => n,
        }
    }
}

/// Les dépendances de base, présentes sur tout nœud.
pub const BASE: &[Dependency] = &[
    Dependency {
        name: "docker",
        reason: "l'orchestrateur lui-même",
        min_version: Some("24.0"),
        required: true,
    },
    Dependency {
        name: "wireguard-tools",
        reason: "mesh chiffré entre nœuds — Swarm ne doit jamais écouter sur l'IP publique",
        min_version: None,
        required: true,
    },
    Dependency {
        name: "restic",
        reason: "moteur de sauvegarde",
        min_version: None,
        required: true,
    },
    Dependency {
        name: "ca-certificates",
        reason: "vérification TLS des registres et des dépôts",
        min_version: None,
        required: true,
    },
    Dependency {
        name: "ntp",
        reason: "🔴 horloge — une dérive casse Swarm ET la validation des certificats",
        min_version: None,
        required: true,
    },
    Dependency {
        name: "smartmontools",
        reason: "santé disque remontée par l'agent",
        min_version: None,
        required: false,
    },
];

/// Ce qu'on a constaté sur la machine, pour une dépendance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Presence {
    /// Absente : à installer.
    Missing,
    /// Présente et suffisante : **on n'y touche pas**.
    Satisfied { version: Option<String> },
    /// Présente mais trop ancienne.
    TooOld { found: String, required: String },
}

impl Presence {
    pub fn needs_install(&self) -> bool {
        matches!(self, Self::Missing | Self::TooOld { .. })
    }
}

/// Une décision, prête à être affichée avant exécution.
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
                "✓ {} déjà présent{} — laissé tel quel",
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

/// Le plan d'installation des dépendances.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DependencyPlan {
    pub decisions: Vec<Decision>,
}

impl DependencyPlan {
    /// Les paquets à installer réellement.
    pub fn to_install(&self) -> Vec<&'static str> {
        self.decisions
            .iter()
            .filter(|d| d.presence.needs_install())
            .map(|d| d.package)
            .collect()
    }

    /// Manque-t-il quelque chose d'indispensable ?
    pub fn missing_required(&self) -> Vec<&'static str> {
        self.decisions
            .iter()
            .filter(|d| d.dependency.required && d.presence.needs_install())
            .map(|d| d.dependency.name)
            .collect()
    }

    pub fn is_satisfied(&self) -> bool {
        self.to_install().is_empty()
    }
}

/// Construit le plan à partir de ce qu'on a observé.
///
/// `observed` associe le nom canonique à la version détectée (`None` = absent).
pub fn plan(distro: &Distro, observed: &[(&str, Option<String>)]) -> DependencyPlan {
    let pm = distro.package_manager();

    let decisions = BASE
        .iter()
        .map(|dep| {
            let trouve = observed
                .iter()
                .find(|(n, _)| *n == dep.name)
                .and_then(|(_, v)| v.clone());

            let presence = match (trouve, dep.min_version) {
                (None, _) => Presence::Missing,
                // 🔴 Présent et sans exigence de version : on ne touche à rien.
                (Some(v), None) => Presence::Satisfied { version: Some(v) },
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

/// `found >= required`, comparé composant par composant.
///
/// Tolérant sur la forme : `24.0.7`, `24.0.7-ce`, `v24.0` sont tous acceptés. Les
/// suffixes sont ignorés — `24.0.7-ce` et `24.0.7` sont la même version pour nous.
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
        // Version illisible : on ne peut pas affirmer qu'elle suffit.
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
        let manquants = p.missing_required();
        assert!(manquants.contains(&"docker"));
        assert!(manquants.contains(&"restic"));
        assert!(manquants.contains(&"ntp"));
        assert!(!p.is_satisfied());
    }

    #[test]
    fn an_existing_recent_docker_is_left_alone() {
        // 🔴 La règle la plus importante : on ajoute, on ne remplace pas. Écraser la
        // configuration Docker d'une machine existante casse autre chose.
        let p = plan(&debian(), &[("docker", Some("27.3.1".into()))]);
        let docker = p
            .decisions
            .iter()
            .find(|d| d.dependency.name == "docker")
            .expect("docker présent");

        assert!(matches!(docker.presence, Presence::Satisfied { .. }));
        assert!(!p.to_install().contains(&"docker"));
        assert!(docker.describe().contains("laissé tel quel"));
    }

    #[test]
    fn a_too_old_docker_is_flagged_for_upgrade() {
        // Debian stable livre parfois un Docker qui ne gère pas Swarm correctement.
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
        assert!(docker.describe().contains("24.0"));
    }

    #[test]
    fn package_names_differ_across_distributions() {
        let dep = Dependency {
            name: "nfs-client",
            reason: "montages NFS",
            min_version: None,
            required: false,
        };
        assert_eq!(dep.package_for(PackageManager::Apt), "nfs-common");
        assert_eq!(dep.package_for(PackageManager::Dnf), "nfs-utils");
        assert_eq!(dep.package_for(PackageManager::Apk), "nfs-utils");
    }

    #[test]
    fn the_plan_explains_why_each_package_is_there() {
        // Personne ne doit avoir à deviner pourquoi le système installe un paquet.
        let p = plan(&alpine(), &[]);
        for d in &p.decisions {
            if d.presence.needs_install() {
                assert!(
                    !d.dependency.reason.is_empty(),
                    "{} sans justification",
                    d.dependency.name
                );
                assert!(d.describe().contains(d.dependency.reason));
            }
        }
    }

    #[test]
    fn an_optional_dependency_does_not_block() {
        let p = plan(&debian(), &[]);
        // smartmontools est recommandé, pas exigé.
        assert!(!p.missing_required().contains(&"smartmontools"));
        // Mais il figure quand même dans ce qu'on propose d'installer.
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

        // Suffixes courants des paquets distribution.
        assert!(version_at_least("24.0.7-ce", "24.0"));
        assert!(version_at_least("v24.0.7", "24.0"));
        assert!(version_at_least("26.1.3+dfsg1", "24.0"));
    }

    #[test]
    fn an_unreadable_version_is_never_assumed_sufficient() {
        // 🔴 Dans le doute, on ne prétend pas que c'est bon.
        assert!(!version_at_least("inconnue", "24.0"));
        assert!(!version_at_least("", "24.0"));
    }

    #[test]
    fn the_clock_dependency_is_required() {
        // Une dérive d'horloge casse Swarm ET la validation TLS — c'est le genre de
        // panne dont la cause est très difficile à retrouver.
        let ntp = BASE.iter().find(|d| d.name == "ntp").expect("ntp déclaré");
        assert!(ntp.required);
        assert!(ntp.reason.contains("horloge"));
    }
}
