//! Politique de rétention (§9bis du plan).
//!
//! 🔴 **Obligatoire, jamais optionnelle.** Un dépôt restic qui grossit sans rétention
//! finit par remplir le disque et fait tomber la machine qu'il était censé protéger.
//! C'est pour ça qu'il n'y a pas d'`Option<RetentionPolicy>` dans ce crate : une
//! politique existe toujours, avec un défaut raisonnable.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetentionPolicy {
    pub hourly: u32,
    pub daily: u32,
    pub weekly: u32,
    pub monthly: u32,
    pub yearly: u32,
}

impl Default for RetentionPolicy {
    /// Le défaut du §8.4 : dense sur le court terme, clairsemé sur le long.
    ///
    /// Une erreur se remarque en général dans les heures ou les jours ; au-delà, on
    /// garde surtout de quoi remonter loin en cas de découverte tardive (une
    /// corruption silencieuse, un fichier supprimé il y a des mois).
    fn default() -> Self {
        Self {
            hourly: 24,
            daily: 14,
            weekly: 8,
            monthly: 12,
            yearly: 3,
        }
    }
}

impl RetentionPolicy {
    /// Les arguments `forget` de restic correspondants.
    pub fn to_args(&self) -> Vec<String> {
        let mut a = Vec::new();
        for (flag, n) in [
            ("--keep-hourly", self.hourly),
            ("--keep-daily", self.daily),
            ("--keep-weekly", self.weekly),
            ("--keep-monthly", self.monthly),
            ("--keep-yearly", self.yearly),
        ] {
            if n > 0 {
                a.push(flag.to_string());
                a.push(n.to_string());
            }
        }
        a
    }

    /// Une politique qui ne garde rien effacerait tout au premier `forget`.
    pub fn keeps_something(&self) -> bool {
        self.hourly + self.daily + self.weekly + self.monthly + self.yearly > 0
    }

    /// Combien de temps, au minimum, peut-on remonter ?
    pub fn horizon_days(&self) -> u32 {
        let mut d = 0;
        if self.yearly > 0 {
            d = d.max(self.yearly * 365);
        }
        if self.monthly > 0 {
            d = d.max(self.monthly * 30);
        }
        if self.weekly > 0 {
            d = d.max(self.weekly * 7);
        }
        if self.daily > 0 {
            d = d.max(self.daily);
        }
        d
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_keeps_a_meaningful_history() {
        let p = RetentionPolicy::default();
        assert!(p.keeps_something());
        // Trois ans : de quoi couvrir une corruption découverte très tard.
        assert!(p.horizon_days() >= 1000, "{} jours", p.horizon_days());
    }

    #[test]
    fn args_map_to_restic_flags() {
        let p = RetentionPolicy {
            hourly: 24,
            daily: 7,
            weekly: 0,
            monthly: 6,
            yearly: 0,
        };
        let a = p.to_args();
        assert_eq!(
            a,
            vec!["--keep-hourly", "24", "--keep-daily", "7", "--keep-monthly", "6"]
        );
        // Les valeurs nulles sont omises plutôt que passées à 0 : `--keep-weekly 0`
        // signifierait « n'en garde aucune », ce qui n'est pas la même chose.
        assert!(!a.contains(&"--keep-weekly".to_string()));
    }

    #[test]
    fn an_empty_policy_is_detected() {
        // 🔴 Elle effacerait tout au premier `forget`. L'appelant doit refuser.
        let p = RetentionPolicy {
            hourly: 0,
            daily: 0,
            weekly: 0,
            monthly: 0,
            yearly: 0,
        };
        assert!(!p.keeps_something());
        assert!(p.to_args().is_empty());
    }

    #[test]
    fn yaml_roundtrip() {
        let y = "hourly: 24\ndaily: 14\nweekly: 8\nmonthly: 12\nyearly: 3\n";
        let p: RetentionPolicy = serde_yaml_ng::from_str(y).expect("analysable");
        assert_eq!(p, RetentionPolicy::default());
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let y = "hourly: 24\ndaily: 14\nweekly: 8\nmonthly: 12\nyearly: 3\nquotidien: 5\n";
        assert!(serde_yaml_ng::from_str::<RetentionPolicy>(y).is_err());
    }
}
