//! Surveillance de l'espace disque (§9bis).
//!
//! > « C'est la panne numéro un des homelabs, loin devant les défaillances
//! > matérielles : les logs remplissent le disque, et *tout* s'arrête d'un coup —
//! > y compris les bases de données, souvent avec corruption à la clé. »
//!
//! Deux idées structurent ce module :
//!
//! 1. **Des seuils progressifs**, pas une alerte unique à 95 %. À ce stade il est
//!    déjà trop tard pour faire quoi que ce soit de propre.
//! 2. **Une projection**, pas seulement un pourcentage. « 71 % » ne dit rien ;
//!    « plein dans 6 jours au rythme actuel » dit quoi faire et quand.

use serde::{Deserialize, Serialize};

/// Ce que le système doit s'autoriser à faire, selon le remplissage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DiskPressure {
    /// Rien à signaler.
    Normal,
    /// On prévient, sans rien changer.
    Notice,
    /// On purge ce qui est jetable : images inutilisées, caches.
    Reclaim,
    /// 🔴 On refuse tout nouveau déploiement et toute mise à jour.
    Freeze,
    /// 🔴 Mode dégradé : on arrête le non-essentiel pour protéger les bases.
    Critical,
}

impl DiskPressure {
    /// Peut-on encore déployer ou mettre à jour ?
    ///
    /// 🔴 Refuser tôt vaut mieux que remplir le disque au milieu d'un `docker pull`
    /// et laisser la machine dans un état à moitié cassé.
    pub fn allows_deploy(&self) -> bool {
        *self < Self::Freeze
    }

    /// Faut-il libérer de la place automatiquement ?
    pub fn should_reclaim(&self) -> bool {
        *self >= Self::Reclaim
    }

    pub fn describe(&self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Notice => "à surveiller",
            Self::Reclaim => "purge automatique des images inutilisées",
            Self::Freeze => "🔴 déploiements et mises à jour refusés",
            Self::Critical => "🔴 mode dégradé — protection des bases de données",
        }
    }
}

/// Les seuils du §9bis.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Thresholds {
    pub notice: f64,
    pub reclaim: f64,
    pub freeze: f64,
    pub critical: f64,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            notice: 75.0,
            reclaim: 85.0,
            freeze: 90.0,
            critical: 95.0,
        }
    }
}

impl Thresholds {
    pub fn pressure_for(&self, used_percent: f64) -> DiskPressure {
        if used_percent >= self.critical {
            DiskPressure::Critical
        } else if used_percent >= self.freeze {
            DiskPressure::Freeze
        } else if used_percent >= self.reclaim {
            DiskPressure::Reclaim
        } else if used_percent >= self.notice {
            DiskPressure::Notice
        } else {
            DiskPressure::Normal
        }
    }
}

/// L'état d'un système de fichiers, à un instant donné.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DiskUsage {
    pub path: String,
    pub total_mb: u64,
    pub used_mb: u64,
    pub free_mb: u64,
}

impl DiskUsage {
    /// Le taux d'occupation **réel**, calculé sur l'espace utilisable.
    ///
    /// 🔴 Ce n'est PAS `used / total`. Sur presque tout système de fichiers,
    /// `used + free < total` :
    ///
    /// - ext4 réserve 5 % à root par défaut ;
    /// - APFS et btrfs comptent des métadonnées hors des deux colonnes.
    ///
    /// Utiliser `total` comme dénominateur sous-estime donc l'occupation — de 5 %
    /// sur une machine Linux ordinaire, bien davantage ailleurs. Les seuils du
    /// §9bis se déclencheraient d'autant trop tard, c'est-à-dire quand il est déjà
    /// trop tard. C'est aussi ce que `df` affiche dans sa colonne « Capacity ».
    pub fn used_percent(&self) -> f64 {
        let utilisable = self.used_mb + self.free_mb;
        if utilisable == 0 {
            return 0.0;
        }
        (self.used_mb as f64 / utilisable as f64) * 100.0
    }

    pub fn pressure(&self, t: &Thresholds) -> DiskPressure {
        t.pressure_for(self.used_percent())
    }
}

/// Projection à partir de deux mesures espacées dans le temps.
///
/// C'est ce qui transforme « 71 % » en information exploitable. Un disque à 71 %
/// stable depuis six mois n'appelle aucune action ; le même à 71 % qui gagne 3 %
/// par jour en appelle une aujourd'hui.
#[derive(Debug, Clone, PartialEq)]
pub struct Projection {
    pub days_until_full: Option<f64>,
    pub mb_per_day: f64,
}

impl Projection {
    /// `elapsed_hours` doit être > 0 ; deux mesures au même instant ne projettent rien.
    pub fn between(older: &DiskUsage, newer: &DiskUsage, elapsed_hours: f64) -> Option<Self> {
        if elapsed_hours <= 0.0 {
            return None;
        }

        let croissance_mb = newer.used_mb as f64 - older.used_mb as f64;
        let mb_per_day = croissance_mb / elapsed_hours * 24.0;

        // Un disque qui se vide ou reste stable ne se remplira jamais : ne pas
        // annoncer une date, plutôt que d'en inventer une absurde.
        let days_until_full = if mb_per_day > 0.0 {
            Some(newer.free_mb as f64 / mb_per_day)
        } else {
            None
        };

        Some(Self { days_until_full, mb_per_day })
    }

    /// Faut-il alerter ? Une semaine laisse le temps d'agir sans réveiller personne.
    pub fn is_concerning(&self) -> bool {
        self.days_until_full.is_some_and(|d| d < 7.0)
    }

    pub fn describe(&self) -> String {
        match self.days_until_full {
            None => "stable ou en décroissance".into(),
            Some(d) if d < 1.0 => format!(
                "🔴 plein dans moins de 24 h au rythme actuel (+{:.0} Mo/jour)",
                self.mb_per_day
            ),
            Some(d) => format!(
                "plein dans {d:.0} jour(s) au rythme actuel (+{:.0} Mo/jour)",
                self.mb_per_day
            ),
        }
    }
}

/// Plafond de journalisation appliqué à tout conteneur (§9bis).
///
/// 🔴 Sans ça, un conteneur bavard écrit indéfiniment. **C'est le défaut de Docker,
/// et c'est un piège** : la configuration par défaut n'a aucune limite de taille.
pub const LOG_MAX_SIZE: &str = "10m";
pub const LOG_MAX_FILES: &str = "3";

#[cfg(test)]
mod tests {
    use super::*;

    fn usage(total: u64, used: u64) -> DiskUsage {
        DiskUsage {
            path: "/".into(),
            total_mb: total,
            used_mb: used,
            free_mb: total - used,
        }
    }

    #[test]
    fn thresholds_escalate_progressively() {
        let t = Thresholds::default();
        assert_eq!(t.pressure_for(50.0), DiskPressure::Normal);
        assert_eq!(t.pressure_for(78.0), DiskPressure::Notice);
        assert_eq!(t.pressure_for(86.0), DiskPressure::Reclaim);
        assert_eq!(t.pressure_for(91.0), DiskPressure::Freeze);
        assert_eq!(t.pressure_for(97.0), DiskPressure::Critical);
    }

    #[test]
    fn deployment_is_refused_before_the_disk_is_full() {
        // 🔴 Refuser à 90 % vaut mieux que remplir le disque au milieu d'un
        // `docker pull` et laisser la machine à moitié cassée.
        assert!(DiskPressure::Normal.allows_deploy());
        assert!(DiskPressure::Notice.allows_deploy());
        assert!(DiskPressure::Reclaim.allows_deploy());
        assert!(!DiskPressure::Freeze.allows_deploy());
        assert!(!DiskPressure::Critical.allows_deploy());
    }

    #[test]
    fn reclaiming_starts_before_freezing() {
        assert!(!DiskPressure::Notice.should_reclaim());
        assert!(DiskPressure::Reclaim.should_reclaim());
        assert!(DiskPressure::Freeze.should_reclaim());
    }

    #[test]
    fn usage_percentage_is_computed() {
        assert!((usage(100_000, 75_000).used_percent() - 75.0).abs() < 0.01);
        assert_eq!(usage(100_000, 0).used_percent(), 0.0);
    }

    #[test]
    fn reserved_space_does_not_hide_the_real_pressure() {
        // 🔴 Bug trouvé en lançant l'agent pour de vrai : `used + free < total`
        // presque partout (réserve root d'ext4, métadonnées APFS). Calculer sur
        // `total` sous-estimait l'occupation et retardait tous les seuils.
        //
        // Cas observé sur la machine de développement : 12 Go utilisés, 7 Go
        // libres, mais 233 Go de « total ». Le disque est plein à 63 %, pas à 5 %.
        let d = DiskUsage {
            path: "/".into(),
            total_mb: 233_752,
            used_mb: 12_057,
            free_mb: 6_964,
        };
        let p = d.used_percent();
        assert!(p > 60.0 && p < 70.0, "occupation calculée : {p:.1} %");

        // Le calcul naïf aurait donné 5 % et masqué complètement la situation.
        let naif = d.used_mb as f64 / d.total_mb as f64 * 100.0;
        assert!(naif < 10.0, "témoin du calcul erroné : {naif:.1} %");
    }

    #[test]
    fn ext4_root_reserve_changes_the_decision() {
        // 100 Go déclarés, 88 utilisés, 5 libres — les 7 Go manquants sont la
        // réserve root d'ext4.
        let d = DiskUsage {
            path: "/".into(),
            total_mb: 100_000,
            used_mb: 88_000,
            free_mb: 5_000,
        };
        let t = Thresholds::default();

        // Le calcul naïf dit 88 % → « purge les images » : on continue à déployer.
        let naif = t.pressure_for(88.0);
        assert_eq!(naif, DiskPressure::Reclaim);
        assert!(naif.allows_deploy());

        // Le calcul juste dit 94,6 % → on refuse les déploiements. Ce n'est pas un
        // écart cosmétique : c'est une décision opposée.
        assert!(d.used_percent() > 94.0, "{:.1} %", d.used_percent());
        assert_eq!(d.pressure(&t), DiskPressure::Freeze);
        assert!(!d.pressure(&t).allows_deploy());
    }

    #[test]
    fn an_empty_disk_does_not_divide_by_zero() {
        let u = DiskUsage { path: "/".into(), total_mb: 0, used_mb: 0, free_mb: 0 };
        assert_eq!(u.used_percent(), 0.0);
        assert_eq!(u.pressure(&Thresholds::default()), DiskPressure::Normal);
    }

    #[test]
    fn growth_is_projected_into_a_date() {
        // 1 Go consommé en 24 h, 7 Go libres → une semaine.
        let p = Projection::between(&usage(100_000, 90_000), &usage(100_000, 91_000), 24.0)
            .expect("projection");
        assert!((p.mb_per_day - 1000.0).abs() < 1.0);
        assert!((p.days_until_full.expect("date") - 9.0).abs() < 0.1);
    }

    #[test]
    fn a_stable_disk_never_announces_a_date() {
        // 🔴 Inventer « plein dans 4000 jours » serait du bruit ; ne rien dire est
        // l'information juste.
        let p = Projection::between(&usage(100_000, 50_000), &usage(100_000, 50_000), 24.0)
            .expect("projection");
        assert_eq!(p.days_until_full, None);
        assert!(!p.is_concerning());
        assert!(p.describe().contains("stable"));
    }

    #[test]
    fn a_shrinking_disk_is_not_concerning() {
        let p = Projection::between(&usage(100_000, 60_000), &usage(100_000, 50_000), 24.0)
            .expect("projection");
        assert_eq!(p.days_until_full, None);
        assert!(p.mb_per_day < 0.0);
    }

    #[test]
    fn fast_growth_is_flagged() {
        // 5 Go/jour avec 10 Go libres → deux jours.
        let p = Projection::between(&usage(100_000, 85_000), &usage(100_000, 90_000), 24.0)
            .expect("projection");
        assert!(p.is_concerning(), "{}", p.describe());
        assert!(p.describe().contains("jour"));
    }

    #[test]
    fn imminent_saturation_is_stated_plainly() {
        let p = Projection::between(&usage(100_000, 95_000), &usage(100_000, 99_000), 24.0)
            .expect("projection");
        assert!(p.describe().contains("moins de 24 h"), "{}", p.describe());
    }

    #[test]
    fn two_measurements_at_the_same_instant_project_nothing() {
        assert!(Projection::between(&usage(100, 50), &usage(100, 60), 0.0).is_none());
    }

    #[test]
    fn a_week_is_the_alerting_horizon() {
        // Assez tôt pour agir, assez tard pour ne pas réveiller pour rien.
        let dans_dix_jours = Projection { days_until_full: Some(10.0), mb_per_day: 100.0 };
        let dans_trois_jours = Projection { days_until_full: Some(3.0), mb_per_day: 100.0 };
        assert!(!dans_dix_jours.is_concerning());
        assert!(dans_trois_jours.is_concerning());
    }

    #[test]
    fn the_log_cap_is_declared() {
        // Le défaut de Docker n'a AUCUNE limite : un conteneur bavard écrit jusqu'à
        // saturation. C'est la cause la plus fréquente du problème qu'on surveille.
        assert_eq!(LOG_MAX_SIZE, "10m");
        assert_eq!(LOG_MAX_FILES, "3");
    }
}
