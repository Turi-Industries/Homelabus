//! Disk space monitoring.
//!
//! This is the number one homelab failure, well ahead of hardware faults: the logs fill
//! the disk, and *everything* stops at once - databases included, often with corruption
//! along the way.
//!
//! Two ideas structure this module:
//!
//! 1. **Progressive thresholds**, not a single alert at 95 %. By then it is already too
//!    late to do anything clean.
//! 2. **A projection**, not just a percentage. "71 %" says nothing; "full in 6 days at
//!    the current rate" says what to do and when.

use serde::{Deserialize, Serialize};

/// What the system should allow itself to do, given how full the disk is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DiskPressure {
    /// Nothing to report.
    Normal,
    /// Warn, without changing anything.
    Notice,
    /// Prune what is disposable: unused images, caches.
    Reclaim,
    /// 🔴 Refuse every new deployment and every update.
    Freeze,
    /// 🔴 Degraded mode: stop the non-essential to protect the databases.
    Critical,
}

impl DiskPressure {
    /// Can we still deploy or update?
    ///
    /// 🔴 Refusing early beats filling the disk in the middle of a `docker pull` and
    /// leaving the machine half broken.
    pub fn allows_deploy(&self) -> bool {
        *self < Self::Freeze
    }

    /// Should space be freed automatically?
    pub fn should_reclaim(&self) -> bool {
        *self >= Self::Reclaim
    }

    pub fn describe(&self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Notice => "worth watching",
            Self::Reclaim => "automatic pruning of unused images",
            Self::Freeze => "🔴 deployments and updates refused",
            Self::Critical => "🔴 degraded mode - protecting the databases",
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

/// A filesystem's state at a given instant.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DiskUsage {
    pub path: String,
    pub total_mb: u64,
    pub used_mb: u64,
    pub free_mb: u64,
}

impl DiskUsage {
    /// The **real** usage rate, computed over usable space.
    ///
    /// 🔴 This is NOT `used / total`. On almost every filesystem,
    /// `used + free < total`:
    ///
    /// - ext4 reserves 5 % for root by default;
    /// - APFS and btrfs count metadata outside both columns.
    ///
    /// Using `total` as the denominator therefore underestimates usage - by 5 % on an
    /// ordinary Linux machine, far more elsewhere. The thresholds would fire that much
    /// too late, which is to say when it is already too late. This is also what `df`
    /// shows in its "Capacity" column.
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

/// A projection from two measurements spaced apart in time.
///
/// This is what turns "71 %" into usable information. A disk at 71 % that has been
/// stable for six months calls for no action; the same 71 % gaining 3 % a day calls for
/// one today.
#[derive(Debug, Clone, PartialEq)]
pub struct Projection {
    pub days_until_full: Option<f64>,
    pub mb_per_day: f64,
}

impl Projection {
    /// `elapsed_hours` must be > 0; two measurements at the same instant project nothing.
    pub fn between(older: &DiskUsage, newer: &DiskUsage, elapsed_hours: f64) -> Option<Self> {
        if elapsed_hours <= 0.0 {
            return None;
        }

        let croissance_mb = newer.used_mb as f64 - older.used_mb as f64;
        let mb_per_day = croissance_mb / elapsed_hours * 24.0;

        // A disk that is emptying or holding steady will never fill: announce no date
        // rather than inventing an absurd one.
        let days_until_full = if mb_per_day > 0.0 {
            Some(newer.free_mb as f64 / mb_per_day)
        } else {
            None
        };

        Some(Self {
            days_until_full,
            mb_per_day,
        })
    }

    /// Should this alert? A week leaves time to act without waking anyone.
    pub fn is_concerning(&self) -> bool {
        self.days_until_full.is_some_and(|d| d < 7.0)
    }

    pub fn describe(&self) -> String {
        match self.days_until_full {
            None => "stable or shrinking".into(),
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

/// The logging cap applied to every container.
///
/// 🔴 Without it, a chatty container writes forever. **This is Docker's default, and it
/// is a trap**: the default configuration has no size limit at all.
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
        // 🔴 Refusing at 90 % beats filling the disk in the middle of a `docker pull`
        // and leaving the machine half broken.
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
        // 🔴 A bug found by running the agent for real: `used + free < total` almost
        // everywhere (ext4's root reserve, APFS metadata). Computing over `total`
        // underestimated usage and delayed every threshold.
        //
        // Observed on the development machine: 12 GB used, 7 GB free, but 233 GB of
        // "total". The disk is 63 % full, not 5 %.
        let d = DiskUsage {
            path: "/".into(),
            total_mb: 233_752,
            used_mb: 12_057,
            free_mb: 6_964,
        };
        let p = d.used_percent();
        assert!(p > 60.0 && p < 70.0, "computed usage: {p:.1} %");

        // The naive computation would have given 5 % and hidden the situation entirely.
        let naive = d.used_mb as f64 / d.total_mb as f64 * 100.0;
        assert!(
            naive < 10.0,
            "witness to the wrong computation: {naive:.1} %"
        );
    }

    #[test]
    fn ext4_root_reserve_changes_the_decision() {
        // 100 GB declared, 88 used, 5 free - the missing 7 GB are ext4's root
        // reserve.
        let d = DiskUsage {
            path: "/".into(),
            total_mb: 100_000,
            used_mb: 88_000,
            free_mb: 5_000,
        };
        let t = Thresholds::default();

        // The naive computation says 88 % → "prune images": deployment continues.
        let naive = t.pressure_for(88.0);
        assert_eq!(naive, DiskPressure::Reclaim);
        assert!(naive.allows_deploy());

        // The correct computation says 94.6 % → deployments are refused. That is not a
        // cosmetic difference: it is the opposite decision.
        assert!(d.used_percent() > 94.0, "{:.1} %", d.used_percent());
        assert_eq!(d.pressure(&t), DiskPressure::Freeze);
        assert!(!d.pressure(&t).allows_deploy());
    }

    #[test]
    fn an_empty_disk_does_not_divide_by_zero() {
        let u = DiskUsage {
            path: "/".into(),
            total_mb: 0,
            used_mb: 0,
            free_mb: 0,
        };
        assert_eq!(u.used_percent(), 0.0);
        assert_eq!(u.pressure(&Thresholds::default()), DiskPressure::Normal);
    }

    #[test]
    fn growth_is_projected_into_a_date() {
        // 1 GB consumed in 24 h, 7 GB free → one week.
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
        // Early enough to act, late enough not to wake anyone for nothing.
        let dans_dix_jours = Projection {
            days_until_full: Some(10.0),
            mb_per_day: 100.0,
        };
        let dans_trois_jours = Projection {
            days_until_full: Some(3.0),
            mb_per_day: 100.0,
        };
        assert!(!dans_dix_jours.is_concerning());
        assert!(dans_trois_jours.is_concerning());
    }

    #[test]
    fn the_log_cap_is_declared() {
        // Docker's default has NO limit: a chatty container writes until saturation.
        // That is the most frequent cause of the problem being watched.
        assert_eq!(LOG_MAX_SIZE, "10m");
        assert_eq!(LOG_MAX_FILES, "3");
    }
}
