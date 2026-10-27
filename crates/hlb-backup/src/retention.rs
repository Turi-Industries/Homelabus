//! Retention policy.
//!
//! 🔴 **Mandatory, never optional.** A restic repository that grows with no retention
//! ends up filling the disk and bringing down the machine it was meant to protect. That
//! is why there is no `Option<RetentionPolicy>` in this crate: a policy always exists,
//! with a sensible default.

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
    /// The default: dense in the short term, sparse in the long.
    ///
    /// A mistake is usually noticed within hours or days; beyond that, what you keep is
    /// mostly the ability to go far back on a late discovery (a silent corruption, a
    /// file deleted months ago).
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
    /// The corresponding restic `forget` arguments.
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

    /// A policy that keeps nothing would erase everything on the first `forget`.
    pub fn keeps_something(&self) -> bool {
        self.hourly + self.daily + self.weekly + self.monthly + self.yearly > 0
    }

    /// How far back can we go, at a minimum?
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
        // Three years: enough to cover a corruption discovered very late.
        assert!(p.horizon_days() >= 1000, "{} days", p.horizon_days());
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
            vec![
                "--keep-hourly",
                "24",
                "--keep-daily",
                "7",
                "--keep-monthly",
                "6"
            ]
        );
        // Zero values are omitted rather than passed as 0: `--keep-weekly 0` would
        // mean "keep none of them", which is not the same thing.
        assert!(!a.contains(&"--keep-weekly".to_string()));
    }

    #[test]
    fn an_empty_policy_is_detected() {
        // 🔴 It would erase everything on the first `forget`. The caller must refuse.
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
        let p: RetentionPolicy = serde_yaml_ng::from_str(y).expect("parsable");
        assert_eq!(p, RetentionPolicy::default());
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let y = "hourly: 24\ndaily: 14\nweekly: 8\nmonthly: 12\nyearly: 3\nquotidien: 5\n";
        assert!(serde_yaml_ng::from_str::<RetentionPolicy>(y).is_err());
    }
}
