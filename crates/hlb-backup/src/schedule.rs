//! Ordonnancement des sauvegardes (§8.1).
//!
//! 🔴 **Intervalle depuis la dernière réussite, pas cron.**
//!
//! Un `cron` déclenche à des instants absolus : si la machine est éteinte à 3 h, la
//! sauvegarde de 3 h n'a simplement pas lieu, et rien ne le signale. Sur un homelab
//! qui redémarre, se met en veille ou passe une nuit sur onduleur, ça produit des
//! trous silencieux dans l'historique.
//!
//! On raisonne donc en **« ça fait combien de temps que ça n'a pas réussi ? »**. Au
//! retour d'une coupure de trois jours, la sauvegarde part immédiatement au lieu
//! d'attendre le prochain créneau. Et un échec ne repousse pas l'échéance : tant que
//! rien n'a réussi, le travail reste dû.

use std::time::Duration;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Schedule {
    /// Intervalle visé entre deux sauvegardes réussies.
    #[serde(with = "duree_lisible")]
    pub every: Duration,
}

impl Default for Schedule {
    /// Quatre heures : le défaut du §8.1 pour les volumes.
    fn default() -> Self {
        Self {
            every: Duration::from_secs(4 * 3600),
        }
    }
}

impl Schedule {
    pub fn every(d: Duration) -> Self {
        Self { every: d }
    }

    /// Une sauvegarde est-elle due ?
    ///
    /// `last_success` est l'âge de la dernière réussite. `None` = jamais réussi, donc
    /// dû immédiatement : une app qui n'a jamais été sauvegardée est le cas le plus
    /// urgent, pas le moins.
    pub fn is_due(&self, since_last_success: Option<Duration>) -> bool {
        match since_last_success {
            None => true,
            Some(age) => age >= self.every,
        }
    }

    /// Dans combien de temps, si ce n'est pas dû maintenant ?
    pub fn time_until_due(&self, since_last_success: Option<Duration>) -> Duration {
        match since_last_success {
            None => Duration::ZERO,
            Some(age) => self.every.saturating_sub(age),
        }
    }

    /// Au-delà de ce seuil, l'absence de sauvegarde devient une alerte (§8bis).
    ///
    /// Trois intervalles manqués : assez pour écarter un simple redémarrage, assez
    /// peu pour ne pas laisser pourrir la situation.
    pub fn is_overdue(&self, since_last_success: Option<Duration>) -> bool {
        match since_last_success {
            None => false, // Jamais sauvegardé n'est pas « en retard », c'est « à faire ».
            Some(age) => age >= self.every * 3,
        }
    }

    /// Le seuil de péremption : trois intervalles manqués.
    ///
    /// Un seul intervalle raté est le fonctionnement normal d'un homelab — nœud qui
    /// redémarre, NAS momentanément absent. Trois, c'est une panne.
    pub fn overdue_after(&self) -> Duration {
        self.every * 3
    }
}

/// Sérialise les durées en « 4h », « 30m », « 7d » plutôt qu'en secondes.
mod duree_lisible {
    use super::Duration;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
        let secs = d.as_secs();
        let texte = if secs % 86400 == 0 && secs > 0 {
            format!("{}d", secs / 86400)
        } else if secs % 3600 == 0 && secs > 0 {
            format!("{}h", secs / 3600)
        } else if secs % 60 == 0 && secs > 0 {
            format!("{}m", secs / 60)
        } else {
            format!("{secs}s")
        };
        s.serialize_str(&texte)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        let s = String::deserialize(d)?;
        parse(&s).ok_or_else(|| serde::de::Error::custom(format!(
            "durée « {s} » invalide — attendu par ex. 30m, 4h, 7d"
        )))
    }

    pub fn parse(s: &str) -> Option<Duration> {
        let s = s.trim();
        let (nombre, unite) = s.split_at(s.len().checked_sub(1)?);
        let n: u64 = nombre.parse().ok()?;
        let secs = match unite {
            "s" => n,
            "m" => n * 60,
            "h" => n * 3600,
            "d" => n * 86400,
            _ => return None,
        };
        // Une durée nulle ferait tourner la boucle en continu.
        (secs > 0).then(|| Duration::from_secs(secs))
    }
}

pub use duree_lisible::parse as parse_duration;

#[cfg(test)]
mod tests {
    use super::*;

    const H: u64 = 3600;

    #[test]
    fn never_backed_up_is_immediately_due() {
        // 🔴 Le cas le plus urgent, pas le moins.
        assert!(Schedule::default().is_due(None));
        assert_eq!(Schedule::default().time_until_due(None), Duration::ZERO);
    }

    #[test]
    fn due_once_the_interval_has_passed() {
        let s = Schedule::every(Duration::from_secs(4 * H));
        assert!(!s.is_due(Some(Duration::from_secs(3 * H))));
        assert!(s.is_due(Some(Duration::from_secs(4 * H))));
        assert!(s.is_due(Some(Duration::from_secs(5 * H))));
    }

    #[test]
    fn a_long_outage_triggers_immediately_on_return() {
        // C'est tout l'intérêt face à cron : trois jours d'arrêt ne produisent pas
        // trois jours de trou silencieux, mais une sauvegarde dès le retour.
        let s = Schedule::every(Duration::from_secs(4 * H));
        assert!(s.is_due(Some(Duration::from_secs(72 * H))));
        assert_eq!(s.time_until_due(Some(Duration::from_secs(72 * H))), Duration::ZERO);
    }

    #[test]
    fn the_countdown_is_reported() {
        let s = Schedule::every(Duration::from_secs(4 * H));
        assert_eq!(
            s.time_until_due(Some(Duration::from_secs(H))),
            Duration::from_secs(3 * H)
        );
    }

    #[test]
    fn overdue_needs_three_missed_intervals() {
        let s = Schedule::every(Duration::from_secs(4 * H));
        assert!(!s.is_overdue(Some(Duration::from_secs(8 * H))));
        assert!(s.is_overdue(Some(Duration::from_secs(12 * H))));
    }

    #[test]
    fn never_backed_up_is_not_overdue() {
        // Nuance : « jamais fait » appelle une action, pas une alerte de dérive.
        assert!(!Schedule::default().is_overdue(None));
    }

    #[test]
    fn durations_parse_from_readable_forms() {
        assert_eq!(parse_duration("30m"), Some(Duration::from_secs(1800)));
        assert_eq!(parse_duration("4h"), Some(Duration::from_secs(4 * H)));
        assert_eq!(parse_duration("7d"), Some(Duration::from_secs(7 * 86400)));
        assert_eq!(parse_duration("45s"), Some(Duration::from_secs(45)));
    }

    #[test]
    fn malformed_or_zero_durations_are_rejected() {
        for bad in ["", "4", "h", "4x", "-1h", "0h", "0s"] {
            assert!(parse_duration(bad).is_none(), "« {bad} » devrait échouer");
        }
    }

    #[test]
    fn yaml_roundtrip_keeps_the_readable_form() {
        let s = Schedule::every(Duration::from_secs(4 * H));
        let y = serde_yaml_ng::to_string(&s).expect("sérialisable");
        assert!(y.contains("4h"), "{y}");
        assert_eq!(serde_yaml_ng::from_str::<Schedule>(&y).expect("analysable"), s);
    }
}
