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
    /// Pushed in the daytime; during quiet hours it is HELD and delivered when they
    /// end (the controller keeps it in its state, one per subject).
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
        self.decide(level, hour) == Delivery::Sent
    }

    /// What becomes of a notification at this hour, before any network call.
    pub fn decide(&self, level: Level, hour: u32) -> Delivery {
        if !level.is_pushed() {
            Delivery::NotPushed
        } else if level.ignores_quiet_hours() || !self.contains(hour) {
            Delivery::Sent
        } else {
            Delivery::Held
        }
    }
}

/// What [`NtfyClient::send_at`] did with a notification.
///
/// 🔴 `Held` is not `Sent`: it was a `bool` once, held read as said, and an Important
/// notice raised at night was dropped — the alert loop never raised it again, an update
/// run was marked notified. A held notification must be kept and sent later.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivery {
    /// ntfy took it.
    Sent,
    /// Quiet hours: to be sent once they end.
    Held,
    /// A level never pushed (info, debug): the screen is where it is read.
    NotPushed,
}

/// The hour of the day at `unix_s` in the installation's zone (`Europe/Paris`), UTC
/// without one or for a name the database does not know.
pub fn local_hour(zone: Option<&str>, unix_s: i64) -> u32 {
    local_time(zone, unix_s).0
}

/// `(hour, minute)` at `unix_s` in the zone, as [`local_hour`] reads it.
pub fn local_time(zone: Option<&str>, unix_s: i64) -> (u32, u32) {
    use chrono::Timelike;
    let t = local_datetime(zone, unix_s);
    (t.hour(), t.minute())
}

/// The date and time at `unix_s` in the zone, as [`local_hour`] reads it: what a
/// maintenance window naming a weekday is matched against.
pub fn local_datetime(zone: Option<&str>, unix_s: i64) -> chrono::NaiveDateTime {
    let utc = chrono::DateTime::from_timestamp(unix_s, 0).unwrap_or_default();
    match zone.and_then(|z| z.parse::<chrono_tz::Tz>().ok()) {
        Some(tz) => utc.with_timezone(&tz).naive_local(),
        None => utc.naive_utc(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_local_day_is_the_zone_s_not_utc_s() {
        use chrono::{Datelike, Timelike, Weekday};
        // Sunday 2026-11-08 23:30 UTC is already Monday 00:30 in Paris.
        let at = 1_794_180_600;
        let utc = local_datetime(None, at);
        assert_eq!((utc.weekday(), utc.hour()), (Weekday::Sun, 23));
        let paris = local_datetime(Some("Europe/Paris"), at);
        assert_eq!(
            (paris.weekday(), paris.hour(), paris.minute()),
            (Weekday::Mon, 0, 30)
        );
        assert_eq!(local_time(Some("Europe/Paris"), at), (0, 30));
    }

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
    fn quiet_hours_are_read_in_the_installation_s_zone() {
        // 2026-07-01 06:30 UTC is 08:30 in Paris (summer time) and 02:30 in Montreal.
        let t = 1_782_887_400;
        assert_eq!(local_time(None, t), (6, 30));
        assert_eq!(local_hour(Some("Europe/Paris"), t), 8);
        assert_eq!(local_hour(Some("America/Montreal"), t), 2);
        assert_eq!(
            local_hour(Some("Not/AZone"), t),
            6,
            "an unknown zone is UTC"
        );
        let q = QuietHours::default();
        assert!(q.allows(Level::Important, local_hour(Some("Europe/Paris"), t)));
        assert!(!q.allows(Level::Important, local_hour(Some("America/Montreal"), t)));
    }

    #[test]
    fn a_pushed_notification_in_quiet_hours_is_held_not_dropped() {
        let q = QuietHours::default();
        assert_eq!(q.decide(Level::Important, 3), Delivery::Held);
        assert_eq!(q.decide(Level::Important, 14), Delivery::Sent);
        assert_eq!(q.decide(Level::Critical, 3), Delivery::Sent);
        assert_eq!(q.decide(Level::Info, 14), Delivery::NotPushed);
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
