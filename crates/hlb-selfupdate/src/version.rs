//! Versions et compatibilité agent ↔ controller (§7bis).
//!
//! ## 🔴 Pourquoi la compatibilité est le cœur du problème
//!
//! Mettre à jour Homelabus, c'est remplacer l'outil qui pilote tout **pendant qu'il
//! pilote tout**. Le remplacement ne peut pas être atomique sur plusieurs machines :
//! il existe forcément une fenêtre où des agents en version N parlent à un controller
//! en N+1, ou l'inverse.
//!
//! Sans règle explicite, cette fenêtre casse le cluster — et elle le casse **au pire
//! moment**, quand l'administrateur est en train de faire une manipulation délicate.
//!
//! La règle retenue : **à l'intérieur d'une même version majeure, les deux sens
//! fonctionnent**. Une majeure différente refuse, et le dit avant d'avoir touché à
//! quoi que ce soit.
//!
//! ## Le numéro de protocole, distinct du numéro de version
//!
//! ⚠️ La version du binaire (`0.1.0`) et la version du **protocole** entre agent et
//! controller sont deux choses différentes. Un correctif qui ne change rien au
//! dialogue ne doit pas rendre les agents incompatibles ; à l'inverse, un changement
//! de format de rapport dans une version de correctif doit le signaler.
//!
//! D'où [`PROTOCOL`], incrémenté seulement quand le dialogue change.

use serde::{Deserialize, Serialize};

/// Version du dialogue agent ↔ controller.
///
/// 🔴 À incrémenter **uniquement** quand le format des échanges change de façon
/// incompatible. La confondre avec la version du binaire ferait refuser des agents
/// parfaitement fonctionnels à chaque correctif.
pub const PROTOCOL: u32 = 1;

/// Une version sémantique.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Version {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl Version {
    pub const fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    /// La version de ce binaire, lue au moment de la compilation.
    pub fn current() -> Self {
        Self::parse(env!("CARGO_PKG_VERSION")).unwrap_or(Self::new(0, 0, 0))
    }

    pub fn parse(s: &str) -> Option<Self> {
        // On tolère un « v » de tête : les étiquettes Git en portent souvent un, et
        // refuser « v0.2.0 » ferait échouer la mise à jour sur un détail cosmétique.
        let s = s.trim().trim_start_matches('v');
        // Et un suffixe de pré-version : `0.2.0-rc1` reste la 0.2.0 pour la
        // comparaison de compatibilité.
        let s = s.split(['-', '+']).next()?;

        let mut it = s.split('.');
        let major = it.next()?.parse().ok()?;
        let minor = it.next()?.parse().ok()?;
        let patch = it.next().unwrap_or("0").parse().ok()?;
        if it.next().is_some() {
            return None;
        }
        Some(Self {
            major,
            minor,
            patch,
        })
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// Le verdict de compatibilité entre deux composants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Compatibility {
    /// Les deux se comprennent.
    Ok,
    /// 🔴 Incompatibles : la mise à jour doit s'arrêter avant de commencer.
    Incompatible { reason: String },
}

impl Compatibility {
    pub fn is_ok(&self) -> bool {
        matches!(self, Self::Ok)
    }

    pub fn describe(&self) -> String {
        match self {
            Self::Ok => "compatibles".to_string(),
            Self::Incompatible { reason } => reason.clone(),
        }
    }
}

/// Un agent en version `agent` peut-il dialoguer avec un controller en `controller` ?
///
/// 🔴 La question se pose **dans les deux sens**, parce que la mise à jour n'est pas
/// atomique : les agents passent en premier (§7bis), donc pendant un moment on a des
/// agents N+1 face à un controller N. Puis, si un nœud était éteint, on aura un agent
/// N face à un controller N+1.
///
/// Une règle qui ne couvrirait qu'un sens laisserait l'autre casser en silence.
pub fn compatible(agent: Version, controller: Version) -> Compatibility {
    if agent.major != controller.major {
        return Compatibility::Incompatible {
            reason: format!(
                "agent {agent} et controller {controller} : versions MAJEURES \
                 différentes. Une majeure change le dialogue de façon incompatible ; \
                 mettre à jour l'un sans l'autre couperait le pilotage du cluster."
            ),
        };
    }
    Compatibility::Ok
}

/// Deux protocoles se comprennent-ils ?
pub fn protocol_compatible(agent: u32, controller: u32) -> Compatibility {
    if agent == controller {
        return Compatibility::Ok;
    }
    Compatibility::Incompatible {
        reason: format!(
            "protocole {agent} côté agent, {controller} côté controller — le format \
             des échanges a changé. Mets à jour l'agent avant le controller (§7bis)."
        ),
    }
}

/// Le type de saut entre deux versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Jump {
    /// Rien à faire.
    None,
    /// Correctif : sans risque connu.
    Patch,
    /// Mineure : fonctionnalités ajoutées, schéma possiblement migré.
    Minor,
    /// 🔴 Majeure : rupture assumée, validation manuelle indispensable.
    Major,
    /// 🔴 Retour en arrière. Jamais fait par `update` — c'est `rollback`.
    Downgrade,
}

impl Jump {
    pub fn between(from: Version, to: Version) -> Self {
        use std::cmp::Ordering::*;
        match to.cmp(&from) {
            Equal => Self::None,
            Less => Self::Downgrade,
            Greater if to.major > from.major => Self::Major,
            Greater if to.minor > from.minor => Self::Minor,
            Greater => Self::Patch,
        }
    }

    /// Faut-il une validation explicite au-delà de `--apply` ?
    pub fn needs_confirmation(&self) -> bool {
        matches!(self, Self::Major | Self::Downgrade)
    }

    pub fn describe(&self) -> &'static str {
        match self {
            Self::None => "aucun changement",
            Self::Patch => "correctif",
            Self::Minor => "version mineure",
            Self::Major => "🔴 version MAJEURE — rupture assumée",
            Self::Downgrade => "🔴 RETOUR EN ARRIÈRE",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_parse_in_the_forms_that_exist_in_the_wild() {
        assert_eq!(Version::parse("1.2.3"), Some(Version::new(1, 2, 3)));
        // Les étiquettes Git portent souvent un « v » : le refuser ferait échouer la
        // mise à jour sur un détail cosmétique.
        assert_eq!(Version::parse("v1.2.3"), Some(Version::new(1, 2, 3)));
        // Une pré-version reste la même version pour la compatibilité.
        assert_eq!(Version::parse("1.2.3-rc1"), Some(Version::new(1, 2, 3)));
        assert_eq!(Version::parse("1.2"), Some(Version::new(1, 2, 0)));
    }

    #[test]
    fn nonsense_is_refused() {
        assert_eq!(Version::parse("abc"), None);
        assert_eq!(Version::parse("1.2.3.4"), None);
        assert_eq!(Version::parse(""), None);
    }

    #[test]
    fn versions_order_as_expected() {
        assert!(Version::new(1, 0, 0) > Version::new(0, 9, 9));
        assert!(Version::new(0, 2, 0) > Version::new(0, 1, 99));
        assert!(Version::new(0, 1, 2) > Version::new(0, 1, 1));
    }

    #[test]
    fn compatibility_is_checked_in_both_directions() {
        // 🔴 La mise à jour n'est pas atomique : les agents passent d'abord, donc on
        // a d'abord des agents N+1 face à un controller N, puis l'inverse si un nœud
        // était éteint. Une règle à sens unique laisserait l'autre casser en silence.
        let n = Version::new(0, 1, 0);
        let n_plus = Version::new(0, 2, 0);

        assert!(compatible(n_plus, n).is_ok(), "agent en avance");
        assert!(compatible(n, n_plus).is_ok(), "agent en retard");
    }

    #[test]
    fn a_major_difference_is_refused_before_anything_is_touched() {
        let c = compatible(Version::new(1, 0, 0), Version::new(0, 9, 0));
        assert!(!c.is_ok());
        assert!(c.describe().contains("MAJEURES"), "{}", c.describe());
        // Le message doit dire la CONSÉQUENCE, pas juste le constat.
        assert!(
            c.describe().contains("couperait le pilotage"),
            "{}",
            c.describe()
        );
    }

    #[test]
    fn the_protocol_number_is_not_the_binary_version() {
        // ⚠️ Les confondre ferait refuser des agents parfaitement fonctionnels à
        // chaque correctif.
        assert!(protocol_compatible(1, 1).is_ok());
        assert!(!protocol_compatible(1, 2).is_ok());

        // Deux binaires de versions différentes mais de même protocole s'entendent.
        assert!(compatible(Version::new(0, 1, 0), Version::new(0, 3, 5)).is_ok());
    }

    #[test]
    fn a_protocol_mismatch_says_what_to_do() {
        let c = protocol_compatible(1, 2);
        assert!(
            c.describe().contains("agent avant le controller"),
            "{}",
            c.describe()
        );
    }

    #[test]
    fn jumps_are_classified() {
        let v = Version::new(0, 2, 3);
        assert_eq!(Jump::between(v, v), Jump::None);
        assert_eq!(Jump::between(v, Version::new(0, 2, 4)), Jump::Patch);
        assert_eq!(Jump::between(v, Version::new(0, 3, 0)), Jump::Minor);
        assert_eq!(Jump::between(v, Version::new(1, 0, 0)), Jump::Major);
        assert_eq!(Jump::between(v, Version::new(0, 2, 2)), Jump::Downgrade);
    }

    #[test]
    fn only_risky_jumps_demand_extra_confirmation() {
        // Un correctif ne doit pas demander trois validations : à force, on les
        // enchaîne sans lire, et celle qui comptait passe aussi.
        assert!(!Jump::Patch.needs_confirmation());
        assert!(!Jump::Minor.needs_confirmation());
        assert!(Jump::Major.needs_confirmation());
        assert!(Jump::Downgrade.needs_confirmation());
    }

    #[test]
    fn a_downgrade_is_never_an_update() {
        // 🔴 Revenir en arrière passe par `rollback`, qui restaure AUSSI le schéma.
        // Le faire passer pour une mise à jour laisserait la base en version N+1
        // sous un binaire N — l'état dont on ne peut plus sortir.
        assert_eq!(
            Jump::between(Version::new(0, 3, 0), Version::new(0, 2, 0)),
            Jump::Downgrade
        );
        assert!(Jump::Downgrade.describe().contains("RETOUR EN ARRIÈRE"));
    }

    #[test]
    fn the_current_version_is_readable() {
        // Si ça échoue, `Version::current()` renverrait 0.0.0 et toute comparaison
        // conclurait à une mise à jour disponible en permanence.
        let v = Version::current();
        assert_ne!(v, Version::new(0, 0, 0), "version du paquet illisible");
    }
}
