//! Notifications.
//!
//! 🔴 **A badly tuned alerting system is worse than no alerting at all.** After three
//! weeks of false positives nobody reads them any more, and the real outage goes
//! unnoticed in the noise.
//!
//! Two rules follow:
//!
//! 1. **Alert on symptoms, not on causes.** "CPU at 85 %" calls for no action;
//!    "gitea has been answering in over 5 s for 10 min" does.
//! 2. **Quiet hours.** Anything not critical waits for the morning. Waking someone for
//!    an available update guarantees they will turn alerts off.

pub mod ntfy;

pub use ntfy::NtfyClient;

use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("could not notify ({url}): {source}")]
    Http {
        url: String,
        #[source]
        source: reqwest::Error,
    },

    #[error("the notification service answered {0}")]
    Rejected(u16),
}

pub type Result<T> = std::result::Result<T, Error>;

/// The four alert levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    /// Logs only.
    Debug,
    /// Dashboard only - never pushed.
    Info,
    /// Batched, once a day.
    Important,
    /// 🔴 Pushed immediately, at night included.
    Critical,
}

impl Level {
    /// Should this alert be pushed to the phone?
    pub fn is_pushed(&self) -> bool {
        *self >= Self::Important
    }

    /// Does it cross quiet hours?
    ///
    /// Only critical does. Everything else waits: an update available at 3 a.m. does
    /// not justify waking anyone.
    pub fn ignores_quiet_hours(&self) -> bool {
        *self == Self::Critical
    }

    /// ntfy priority (1 = min, 5 = urgent).
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

/// A notification ready to go out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notification {
    pub level: Level,
    pub title: String,
    pub body: String,
    /// What it is about: used to group and to avoid repeating.
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

/// Window during which only critical alerts are sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuietHours {
    pub from_hour: u32,
    pub to_hour: u32,
}

impl Default for QuietHours {
    fn default() -> Self {
        Self {
            from_hour: 22,
            to_hour: 8,
        }
    }
}

impl QuietHours {
    /// Are we inside quiet hours?
    ///
    /// The window crosses midnight in the common case (22:00 -> 08:00), which needs a
    /// different test from a plain range check.
    pub fn contains(&self, hour: u32) -> bool {
        if self.from_hour <= self.to_hour {
            hour >= self.from_hour && hour < self.to_hour
        } else {
            hour >= self.from_hour || hour < self.to_hour
        }
    }

    /// Should this notification go out now?
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
        // An info-level buzz in the pocket is exactly what makes people turn
        // notifications off after three weeks.
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
        // 🔴 22:00 -> 08:00 crosses midnight: a plain range check would not work.
        let q = QuietHours::default();
        assert!(q.contains(23));
        assert!(q.contains(3));
        assert!(q.contains(7));
        assert!(!q.contains(8), "the end bound is exclusive");
        assert!(!q.contains(12));
        assert!(q.contains(22), "the start bound is inclusive");
    }

    #[test]
    fn a_window_within_the_day_also_works() {
        let q = QuietHours {
            from_hour: 9,
            to_hour: 17,
        };
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
        // 🔴 Full disk, lost quorum, a backup that failed twice: none of it can wait
        // for the morning.
        let q = QuietHours::default();
        assert!(q.allows(Level::Critical, 3));
        assert!(q.allows(Level::Critical, 14));
    }

    #[test]
    fn info_never_goes_out_even_in_daytime() {
        // The dashboard is enough: pushing info would turn the phone into an event
        // log.
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
            Notification::critical("disk", "Disk full", "...").level,
            Level::Critical
        );
        assert_eq!(
            Notification::important("update", "Update available", "...").level,
            Level::Important
        );
    }
}
