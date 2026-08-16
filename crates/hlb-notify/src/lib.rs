//! Notifications (§8bis).
//!
//! 🔴 **Un système d'alerte mal réglé est pire que pas d'alerte du tout.** Au bout de
//! trois semaines de faux positifs, plus personne ne les lit — et la vraie panne
//! passe inaperçue au milieu du bruit.
//!
//! Deux règles en découlent :
//!
//! 1. **On alerte sur les symptômes, pas sur les causes.** « CPU à 85 % » n'appelle
//!    aucune action ; « gitea répond en plus de 5 s depuis 10 min » si.
//! 2. **Les heures calmes.** Ce qui n'est pas critique attend le matin. Réveiller
//!    quelqu'un pour une mise à jour disponible garantit qu'il coupera les alertes.

pub mod ntfy;

pub use ntfy::NtfyClient;

use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("notification impossible ({url}) : {source}")]
    Http {
        url: String,
        #[source]
        source: reqwest::Error,
    },

    #[error("le service de notification a répondu {0}")]
    Rejected(u16),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Les quatre niveaux du §8bis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    /// Journaux seulement.
    Debug,
    /// Tableau de bord seulement — jamais poussé.
    Info,
    /// Groupé, une fois par jour.
    Important,
    /// 🔴 Poussé immédiatement, y compris la nuit.
    Critical,
}

impl Level {
    /// Doit-on pousser cette alerte vers le téléphone ?
    pub fn is_pushed(&self) -> bool {
        *self >= Self::Important
    }

    /// Traverse-t-elle les heures calmes ?
    ///
    /// Seul le critique. Tout le reste attend : une mise à jour disponible à 3 h du
    /// matin ne justifie pas de réveiller quelqu'un.
    pub fn ignores_quiet_hours(&self) -> bool {
        *self == Self::Critical
    }

    /// Priorité ntfy (1 = min, 5 = urgent).
    pub fn ntfy_priority(&self) -> u8 {
        match self {
            Self::Debug => 1,
            Self::Info => 2,
            Self::Important => 4,
            Self::Critical => 5,
        }
    }

    pub fn tag(&self) -> &'static str {
        match self {
            Self::Debug => "mag",
            Self::Info => "information_source",
            Self::Important => "warning",
            Self::Critical => "rotating_light",
        }
    }
}

/// Une notification prête à partir.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notification {
    pub level: Level,
    pub title: String,
    pub body: String,
    /// De quoi ça parle : sert à regrouper et à ne pas répéter.
    pub subject: String,
}

impl Notification {
    pub fn new(level: Level, subject: &str, title: &str, body: &str) -> Self {
        Self {
            level,
            title: title.to_string(),
            body: body.to_string(),
            subject: subject.to_string(),
        }
    }

    pub fn critical(subject: &str, title: &str, body: &str) -> Self {
        Self::new(Level::Critical, subject, title, body)
    }

    pub fn important(subject: &str, title: &str, body: &str) -> Self {
        Self::new(Level::Important, subject, title, body)
    }
}

/// Fenêtre pendant laquelle on n'envoie que le critique.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuietHours {
    pub from_hour: u32,
    pub to_hour: u32,
}

impl Default for QuietHours {
    fn default() -> Self {
        Self { from_hour: 22, to_hour: 8 }
    }
}

impl QuietHours {
    /// Est-on dans les heures calmes ?
    ///
    /// La fenêtre franchit minuit dans le cas courant (22 h → 8 h), ce qui demande
    /// un test différent d'un simple encadrement.
    pub fn contains(&self, hour: u32) -> bool {
        if self.from_hour <= self.to_hour {
            hour >= self.from_hour && hour < self.to_hour
        } else {
            hour >= self.from_hour || hour < self.to_hour
        }
    }

    /// Cette notification doit-elle partir maintenant ?
    pub fn allows(&self, level: Level, hour: u32) -> bool {
        if !level.is_pushed() {
            return false;
        }
        level.ignores_quiet_hours() || !self.contains(hour)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_important_and_above_are_pushed() {
        // Une info qui vibre dans la poche est exactement ce qui fait couper les
        // notifications au bout de trois semaines.
        assert!(!Level::Debug.is_pushed());
        assert!(!Level::Info.is_pushed());
        assert!(Level::Important.is_pushed());
        assert!(Level::Critical.is_pushed());
    }

    #[test]
    fn only_critical_wakes_you_up() {
        assert!(!Level::Important.ignores_quiet_hours());
        assert!(Level::Critical.ignores_quiet_hours());
    }

    #[test]
    fn quiet_hours_cross_midnight() {
        // 🔴 22 h → 8 h franchit minuit : un simple encadrement ne marcherait pas.
        let q = QuietHours::default();
        assert!(q.contains(23));
        assert!(q.contains(3));
        assert!(q.contains(7));
        assert!(!q.contains(8), "la borne de fin est exclue");
        assert!(!q.contains(12));
        assert!(q.contains(22), "la borne de début est incluse");
    }

    #[test]
    fn a_window_within_the_day_also_works() {
        let q = QuietHours { from_hour: 9, to_hour: 17 };
        assert!(q.contains(12));
        assert!(!q.contains(20));
        assert!(!q.contains(3));
    }

    #[test]
    fn an_important_alert_waits_for_the_morning() {
        let q = QuietHours::default();
        assert!(!q.allows(Level::Important, 3));
        assert!(q.allows(Level::Important, 14));
    }

    #[test]
    fn a_critical_alert_goes_through_at_night() {
        // 🔴 Disque plein, quorum perdu, sauvegarde échouée deux fois : ça ne peut
        // pas attendre le matin.
        let q = QuietHours::default();
        assert!(q.allows(Level::Critical, 3));
        assert!(q.allows(Level::Critical, 14));
    }

    #[test]
    fn info_never_goes_out_even_in_daytime() {
        // Le tableau de bord suffit : pousser une info transformerait le téléphone
        // en journal d'événements.
        let q = QuietHours::default();
        assert!(!q.allows(Level::Info, 14));
        assert!(!q.allows(Level::Debug, 14));
    }

    #[test]
    fn levels_are_ordered_by_urgency() {
        assert!(Level::Debug < Level::Info);
        assert!(Level::Info < Level::Important);
        assert!(Level::Important < Level::Critical);
    }

    #[test]
    fn ntfy_priority_grows_with_the_level() {
        assert!(Level::Critical.ntfy_priority() > Level::Important.ntfy_priority());
        assert!(Level::Important.ntfy_priority() > Level::Info.ntfy_priority());
        assert_eq!(Level::Critical.ntfy_priority(), 5);
    }

    #[test]
    fn the_shorthand_constructors_set_the_right_level() {
        assert_eq!(
            Notification::critical("disque", "Disque plein", "…").level,
            Level::Critical
        );
        assert_eq!(
            Notification::important("maj", "Mise à jour", "…").level,
            Level::Important
        );
    }
}
