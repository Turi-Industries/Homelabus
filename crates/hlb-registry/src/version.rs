//! Comparaison de versions et politique de canal (§7 du plan).
//!
//! Les tags du monde réel sont irréguliers : `1.24`, `1.24.3`, `v1.24.3`, `17-alpine`,
//! `8-alpine`, `0.24`. Il faut donc un analyseur tolérant, mais **strict sur ce qui
//! compte** :
//!
//! 🔴 **Le suffixe doit correspondre.** `17-alpine` peut monter vers `18-alpine`, mais
//! jamais vers `18` ni `18-bookworm` : ce serait changer de distribution de base sous
//! les pieds du service, avec des chemins et des bibliothèques différents.

use hlb_types::UpdateChannel;

/// Une version extraite d'un tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    pub major: u64,
    pub minor: Option<u64>,
    pub patch: Option<u64>,
    /// Ce qui suit la version : `alpine`, `bookworm`, `rootless`…
    pub suffix: Option<String>,
    /// Le tag d'origine, conservé tel quel pour le déploiement.
    pub raw: String,
}

impl Version {
    /// Analyse un tag. Renvoie `None` si ce n'est pas une version exploitable
    /// (`latest`, `stable`, `main`, un sha…).
    pub fn parse(tag: &str) -> Option<Self> {
        let body = tag.strip_prefix('v').unwrap_or(tag);

        // Le suffixe commence au premier « - ».
        let (numbers, suffix) = match body.split_once('-') {
            Some((n, s)) => (n, Some(s.to_string())),
            None => (body, None),
        };

        let mut parts = numbers.split('.');
        let major: u64 = parts.next()?.parse().ok()?;
        let minor = parts.next().and_then(|p| p.parse().ok());
        let patch = parts.next().and_then(|p| p.parse().ok());

        // Un quatrième segment signale un schéma qu'on ne sait pas comparer.
        if parts.next().is_some() {
            return None;
        }

        Some(Self {
            major,
            minor,
            patch,
            suffix,
            raw: tag.to_string(),
        })
    }

    /// Ordre entre versions de même famille. Les champs absents valent 0.
    fn cmp_numeric(&self, other: &Self) -> std::cmp::Ordering {
        (self.major, self.minor.unwrap_or(0), self.patch.unwrap_or(0)).cmp(&(
            other.major,
            other.minor.unwrap_or(0),
            other.patch.unwrap_or(0),
        ))
    }

    /// Même variante d'image (même base, même saveur) ?
    ///
    /// 🔴 C'est un garde-fou : sans lui, `17-alpine` pourrait « monter » vers
    /// `18-bookworm`, ce qui change tout l'environnement d'exécution.
    pub fn same_flavor(&self, other: &Self) -> bool {
        self.suffix == other.suffix
    }

    /// Nombre de composants numériques du tag : `15` → 1, `15.18` → 2, `1.37.1` → 3.
    pub fn precision(&self) -> u8 {
        1 + u8::from(self.minor.is_some()) + u8::from(self.patch.is_some())
    }

    /// La montée de `self` vers `candidate` est-elle autorisée par `channel` ?
    pub fn allows(&self, candidate: &Self, channel: UpdateChannel) -> bool {
        if !self.same_flavor(candidate) {
            return false;
        }

        // 🔴 La précision du tag ne doit jamais changer.
        //
        // `postgres:15-alpine` est un tag *roulant* : il suit toujours le dernier
        // 15.x. Le « faire monter » vers `15.18-alpine` l'épinglerait, et il
        // cesserait de suivre — on aurait changé la sémantique du déploiement en
        // croyant appliquer une mise à jour.
        //
        // Pour un tag roulant, ce n'est pas le tag qui change mais le **digest** :
        // c'est le veilleur de digest qui détecte la nouveauté, pas ce sélecteur.
        if self.precision() != candidate.precision() {
            return false;
        }
        if candidate.cmp_numeric(self) != std::cmp::Ordering::Greater {
            return false;
        }

        match channel {
            // Jamais de mise à jour automatique.
            UpdateChannel::Pin => false,
            // Interdit par la validation des manifests ; refusé ici par sécurité.
            UpdateChannel::Latest => false,
            UpdateChannel::Patch => {
                candidate.major == self.major && candidate.minor == self.minor
            }
            UpdateChannel::Minor => candidate.major == self.major,
        }
    }
}

/// Choisit la meilleure mise à jour disponible, ou `None` s'il n'y a rien à faire.
pub fn best_upgrade(current_tag: &str, tags: &[String], channel: UpdateChannel) -> Option<String> {
    let current = Version::parse(current_tag)?;

    let mut best: Option<Version> = None;
    for t in tags {
        let Some(v) = Version::parse(t) else { continue };
        if !current.allows(&v, channel) {
            continue;
        }
        let better = match &best {
            None => true,
            Some(b) => v.cmp_numeric(b) == std::cmp::Ordering::Greater,
        };
        if better {
            best = Some(v);
        }
    }

    best.map(|v| v.raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use UpdateChannel::{Minor, Patch, Pin};

    fn v(s: &str) -> Version {
        Version::parse(s).unwrap_or_else(|| panic!("« {s} » devrait être analysable"))
    }

    #[test]
    fn parses_common_shapes() {
        assert_eq!(v("1.24.3").major, 1);
        assert_eq!(v("1.24.3").minor, Some(24));
        assert_eq!(v("1.24.3").patch, Some(3));
        assert_eq!(v("v1.24.3").major, 1);
        assert_eq!(v("17").minor, None);
        assert_eq!(v("17-alpine").suffix.as_deref(), Some("alpine"));
        assert_eq!(v("0.24").major, 0);
    }

    #[test]
    fn rejects_non_versions() {
        for t in ["latest", "stable", "main", "sha-abc123", "edge"] {
            assert!(Version::parse(t).is_none(), "« {t} » ne devrait pas passer");
        }
    }

    #[test]
    fn patch_stays_within_the_minor() {
        assert!(v("1.24.3").allows(&v("1.24.4"), Patch));
        assert!(!v("1.24.3").allows(&v("1.25.0"), Patch));
        assert!(!v("1.24.3").allows(&v("2.0.0"), Patch));
    }

    #[test]
    fn minor_stays_within_the_major() {
        assert!(v("1.24.3").allows(&v("1.25.0"), Minor));
        assert!(v("1.24.3").allows(&v("1.24.4"), Minor));
        assert!(
            !v("1.24.3").allows(&v("2.0.0"), Minor),
            "une majeure ne doit JAMAIS être automatique (§7)"
        );
    }

    #[test]
    fn pin_never_allows_anything() {
        assert!(!v("1.24.3").allows(&v("1.24.4"), Pin));
        assert!(!v("1.24.3").allows(&v("1.25.0"), Pin));
    }

    #[test]
    fn downgrades_and_identity_are_refused() {
        assert!(!v("1.24.3").allows(&v("1.24.2"), Minor));
        assert!(!v("1.24.3").allows(&v("1.24.3"), Minor));
    }

    #[test]
    fn the_flavor_must_match() {
        // 🔴 Le garde-fou : changer de base sous les pieds du service.
        assert!(!v("17-alpine").allows(&v("18"), Minor));
        assert!(!v("17-alpine").allows(&v("18-bookworm"), Minor));
        assert!(!v("17").allows(&v("18-alpine"), Minor));
        assert!(!v("17-alpine").allows(&v("18-alpine"), Minor), "une majeure reste interdite");
    }

    #[test]
    fn a_rolling_tag_never_becomes_pinned() {
        // `15-alpine` suit le dernier 15.x. L'épingler serait un changement de
        // sémantique déguisé en mise à jour.
        assert!(!v("15-alpine").allows(&v("15.18-alpine"), Minor));
        assert!(!v("17").allows(&v("17.4"), Minor));

        // Et l'inverse est tout aussi faux.
        assert!(!v("17.2").allows(&v("18"), Minor));
    }

    #[test]
    fn a_rolling_tag_updates_through_its_digest_not_its_name() {
        // Conséquence : rien à faire côté sélecteur de tag. C'est voulu.
        let tags: Vec<String> = ["15-alpine", "15.18-alpine", "16-alpine"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(
            best_upgrade("15-alpine", &tags, Minor),
            None,
            "un tag roulant se met à jour par son digest"
        );
    }

    #[test]
    fn alpine_minors_upgrade_within_the_major() {
        assert!(v("17.2-alpine").allows(&v("17.4-alpine"), Minor));
        assert!(!v("17.2-alpine").allows(&v("18.0-alpine"), Minor));
    }

    #[test]
    fn best_upgrade_picks_the_highest_allowed() {
        let tags: Vec<String> = ["1.24.1", "1.24.5", "1.24.3", "1.25.0", "2.0.0", "latest"]
            .iter()
            .map(|s| s.to_string())
            .collect();

        assert_eq!(best_upgrade("1.24.2", &tags, Patch).as_deref(), Some("1.24.5"));
        assert_eq!(best_upgrade("1.24.2", &tags, Minor).as_deref(), Some("1.25.0"));
        assert_eq!(best_upgrade("1.24.2", &tags, Pin), None);
    }

    #[test]
    fn best_upgrade_ignores_other_flavors() {
        let tags: Vec<String> = ["17.4", "17.4-alpine", "17.9-bookworm"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(
            best_upgrade("17.2-alpine", &tags, Minor).as_deref(),
            Some("17.4-alpine"),
            "seule la saveur alpine est éligible"
        );
    }

    #[test]
    fn nothing_to_do_returns_none() {
        let tags = vec!["1.24.0".to_string()];
        assert_eq!(best_upgrade("1.24.0", &tags, Minor), None);
    }

    #[test]
    fn an_unparseable_current_tag_blocks_updates() {
        // Mieux vaut ne rien faire que deviner.
        assert_eq!(best_upgrade("latest", &["1.0.0".into()], Minor), None);
    }
}
