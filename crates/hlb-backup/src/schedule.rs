//! Backup scheduling.
//!
//! 🔴 **Interval since the last success, not cron.**
//!
//! A `cron` fires at absolute instants: if the machine is off at 3 a.m., the 3 a.m.
//! backup simply does not happen, and nothing says so. On a homelab that reboots, goes
//! to sleep or spends a night on a UPS, that produces silent holes in the history.
//!
//! So we reason in terms of **"how long since this last succeeded?"**. Coming back from
//! a three-day outage, the backup starts immediately instead of waiting for the next
//! slot. And a failure does not push the deadline back: until something succeeds, the
//! work stays due.

use std::time::Duration;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Schedule {
    /// Target interval between two successful backups.
    #[serde(with = "readable_duration")]
    pub every: Duration,
}

impl Default for Schedule {
    /// Four hours: the default for volumes.
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

    /// Is a backup due?
    ///
    /// `since_last_success` is the age of the last success. `None` = never succeeded, so
    /// due immediately: an app that has never been backed up is the most urgent case,
    /// not the least.
    pub fn is_due(&self, since_last_success: Option<Duration>) -> bool {
        match since_last_success {
            None => true,
            Some(age) => age >= self.every,
        }
    }

    /// How long until it is due, if it is not due now?
    pub fn time_until_due(&self, since_last_success: Option<Duration>) -> Duration {
        match since_last_success {
            None => Duration::ZERO,
            Some(age) => self.every.saturating_sub(age),
        }
    }

    /// Past this threshold, the absence of a backup becomes an alert.
    ///
    /// Three missed intervals: enough to rule out a mere reboot, few enough not to let
    /// the situation rot.
    pub fn is_overdue(&self, since_last_success: Option<Duration>) -> bool {
        match since_last_success {
            None => false, // Never backed up is not "overdue", it is "to be done".
            Some(age) => age >= self.every * 3,
        }
    }

    /// The staleness threshold: three missed intervals.
    ///
    /// One missed interval is normal homelab operation — a node rebooting, a NAS briefly
    /// away. Three is a failure.
    pub fn overdue_after(&self) -> Duration {
        self.every * 3
    }
}

/// Serialises durations as "4h", "30m", "7d" rather than as seconds.
mod readable_duration {
    use super::Duration;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
        let secs = d.as_secs();
        let text = if secs.is_multiple_of(86400) && secs > 0 {
            format!("{}d", secs / 86400)
        } else if secs.is_multiple_of(3600) && secs > 0 {
            format!("{}h", secs / 3600)
        } else if secs.is_multiple_of(60) && secs > 0 {
            format!("{}m", secs / 60)
        } else {
            format!("{secs}s")
        };
        s.serialize_str(&text)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        let s = String::deserialize(d)?;
        parse(&s).ok_or_else(|| {
            serde::de::Error::custom(format!(
                "invalid duration \"{s}\" — expected e.g. 30m, 4h, 7d"
            ))
        })
    }

    pub fn parse(s: &str) -> Option<Duration> {
        let s = s.trim();
        let (count, unit) = s.split_at(s.len().checked_sub(1)?);
        let n: u64 = count.parse().ok()?;
        let secs = match unit {
            "s" => n,
            "m" => n * 60,
            "h" => n * 3600,
            "d" => n * 86400,
            _ => return None,
        };
        // A zero duration would make the loop spin continuously.
        (secs > 0).then(|| Duration::from_secs(secs))
    }
}

pub use readable_duration::parse as parse_duration;

#[cfg(test)]
mod tests {
    use super::*;

    const H: u64 = 3600;

    #[test]
    fn never_backed_up_is_immediately_due() {
        // 🔴 The most urgent case, not the least.
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
        // This is the whole point against cron: three days of downtime do not produce
        // three days of silent hole, but a backup as soon as we are back.
        let s = Schedule::every(Duration::from_secs(4 * H));
        assert!(s.is_due(Some(Duration::from_secs(72 * H))));
        assert_eq!(
            s.time_until_due(Some(Duration::from_secs(72 * H))),
            Duration::ZERO
        );
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
        // A nuance: "never done" calls for an action, not a drift alert.
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
            assert!(parse_duration(bad).is_none(), "\"{bad}\" should fail");
        }
    }

    #[test]
    fn yaml_roundtrip_keeps_the_readable_form() {
        let s = Schedule::every(Duration::from_secs(4 * H));
        let y = serde_yaml_ng::to_string(&s).expect("serialisable");
        assert!(y.contains("4h"), "{y}");
        assert_eq!(
            serde_yaml_ng::from_str::<Schedule>(&y).expect("parsable"),
            s
        );
    }
}
