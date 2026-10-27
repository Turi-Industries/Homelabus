//! "If I lose everything right now, what do I get back, and from when?" (batch 9.2)
//!
//! ## Why this calculation exists
//!
//! Every piece of the answer already existed — age per destination, number of
//! up-to-date copies, age of the last verification, freshness of the recovery drills,
//! PITR window — but **spread over four screens**. Nobody adds that up in their head,
//! and it is nevertheless the only question that matters on the day.
//!
//! ## 🔴 Two numbers, not one
//!
//! - **RPO**: how much data you would lose. That is the age of the most recent backup
//!   **that really protects** — so on an up-to-date destination, not on the one that has
//!   failed twelve times.
//! - **Confidence**: what you know about that backup. A fresh copy never restored is a
//!   hypothesis, not a guarantee.
//!
//! Confusing them would give "RPO of 2 h" for a backup nobody has ever managed to read
//! back.

use crate::destination::{Coverage, State};
use crate::drill::Readiness;

/// What you would get back, and with what confidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Restorability {
    pub app: String,
    /// Seconds of data you would lose. `None` = **nothing to restore**.
    ///
    /// ⚠️ Distinct from a very large RPO: `None` means no copy exists, anywhere.
    /// Confusing them would display "RPO: 3 months" for an app that has never been
    /// backed up.
    pub rpo_s: Option<i64>,
    /// How many copies really protect (the 3-2-1 number).
    pub copies: usize,
    /// 🔴 The age of the MOST RECENT stale copy, when there is no up-to-date copy.
    ///
    /// "No up-to-date copy" covers two opposite situations: never backed up (nothing
    /// exists, `None`) and stale backups (copies exist, they are old). They are not
    /// repaired the same way — one calls for configuring a destination, the other for
    /// understanding why the existing one stopped working.
    pub stale_since_s: Option<i64>,
    /// Age of the last SUCCESSFUL verification by real restore. `None` = never.
    pub verified_s_ago: Option<i64>,
    /// 🔴 The latest verification failed, whatever succeeded before it: the copy read
    /// back last did not restore, and an older success says nothing about today's.
    pub verification_failed: bool,
    /// The oldest reachable restore point, through PITR.
    ///
    /// `None` when the app has no continuous archiving: you can then only restore at the
    /// instants of the backups, not between them.
    pub pitr_depth_s: Option<i64>,
    /// Are the recovery drills up to date?
    ///
    /// ⚠️ We reuse `drill::Readiness` rather than build a twin: two types carrying the
    /// same judgement would end up answering the same question differently, and the
    /// backup screen is what would show them side by side.
    pub drills: Readiness,
}

/// The state of the restore drills.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrillsState {
    UpToDate {
        days: i64,
    },
    Du {
        days: i64,
    },
    Stale {
        days: i64,
    },
    /// 🔴 Never drilled: we do not know whether a restore works.
    Never,
}

/// The level of confidence the restore can be given.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Confidence {
    /// 🔴 Nothing to restore, or nothing that has ever been read back.
    Nothing,
    /// Copies exist, but nobody has checked they restore.
    Assumed,
    /// A restore succeeded, but a long time ago.
    Previous,
    /// Restore verified recently, several copies.
    Verified,
}

impl Confidence {
    pub fn describe(&self) -> &'static str {
        match self {
            Self::Nothing => "none: nothing proves anything at all would come back",
            Self::Assumed => "supposed: copies exist, none has ever been read back",
            Self::Previous => "old: the last successful restore goes back a long way",
            Self::Verified => "verified: a restore succeeded recently",
        }
    }
}

/// Past this, a verification no longer reassures: the drill targets once a month.
pub const VERIFICATION_STALE_S: i64 = 45 * 86_400;

impl Restorability {
    /// The calculation, from what the state already knows.
    pub fn compute(
        coverage: &Coverage,
        verified_s_ago: Option<i64>,
        pitr_depth_s: Option<i64>,
        drills: Readiness,
    ) -> Self {
        // 🔴 The RPO is measured on UP-TO-DATE destinations only. Taking the most
        // recent across all destinations would give the RPO of a stale copy — that is, a
        // reassuring number drawn from a backup that no longer protects.
        let rpo_s = coverage
            .per_destination
            .iter()
            .filter_map(|(_, e)| match e {
                State::Fresh { age_s } => Some(*age_s),
                // A stale or never-served destination does not count.
                State::Stale { .. } | State::Never => None,
            })
            .min();

        // The most recent of the stale ones: it no longer protects, but its existence
        // changes the diagnosis and the remedy entirely.
        let stale_since_s = (rpo_s.is_none())
            .then(|| {
                coverage
                    .per_destination
                    .iter()
                    .filter_map(|(_, e)| match e {
                        State::Stale { age_s } => Some(*age_s),
                        State::Fresh { .. } | State::Never => None,
                    })
                    .min()
            })
            .flatten();

        Self {
            app: coverage.app.clone(),
            rpo_s,
            stale_since_s,
            copies: coverage.up_to_date_copies(),
            verified_s_ago,
            verification_failed: false,
            pitr_depth_s,
            drills,
        }
    }

    /// Whether the latest verification failed — see [`Self::verification_failed`].
    pub fn with_failed_verification(mut self, failed: bool) -> Self {
        self.verification_failed = failed;
        self
    }

    /// The confidence it can be given.
    pub fn confidence(&self) -> Confidence {
        // Nothing to restore: the question of confidence does not even arise.
        if self.rpo_s.is_none() || self.copies == 0 {
            return Confidence::Nothing;
        }
        // The last read-back failed: what proved the restore once proves nothing now.
        if self.verification_failed {
            return Confidence::Nothing;
        }
        match self.verified_s_ago {
            // 🔴 Never read back: a backup never restored is a hypothesis. Saying
            // "supposed" rather than "good" is the whole point.
            None => Confidence::Assumed,
            Some(age) if age > VERIFICATION_STALE_S => Confidence::Previous,
            Some(_) if self.copies >= 2 => Confidence::Verified,
            // A single copy, even verified: losing that destination takes everything
            // with it. That is not the same level of confidence.
            Some(_) => Confidence::Previous,
        }
    }

    /// The answer in one sentence.
    pub fn verdict(&self) -> String {
        let Some(rpo) = self.rpo_s else {
            // 🔴 The two opposite situations, named separately. "NO copy" shown next to
            // a destination dated three weeks ago reads as a contradiction, and you end
            // up doubting the whole screen.
            return match self.stale_since_s {
                Some(age) => format!(
                    "NO up-to-date copy: the most recent one is {} old, and backups \
                     have stopped succeeding since.",
                    humanise(age)
                ),
                None => "NO restore possible: this application has NEVER been backed \
                         up."
                .to_string(),
            };
        };

        let base = format!(
            "you would lose roughly {} of data, from {}",
            humanise(rpo),
            match self.copies {
                1 => "the single up-to-date copy".to_string(),
                n => format!("{n} up-to-date copies"),
            }
        );

        match self.pitr_depth_s {
            // Continuous archiving changes the nature of the answer: you can aim at an
            // instant, not only at a backup.
            Some(p) => format!(
                "{base}. Restore possible at any instant in the past {}.",
                humanise(p)
            ),
            None => format!("{base}. Restore possible at the instants of the backups."),
        }
    }

    /// What it would take to be at ease.
    ///
    /// 🔴 Returned in order of urgency, and empty when all is well: a list of advice
    /// displayed permanently stops being read.
    pub fn remedies(&self) -> Vec<String> {
        let mut v = Vec::new();

        if self.rpo_s.is_none() {
            // The remedy follows the diagnosis: configure what does not exist, or
            // understand why what exists stopped working.
            v.push(match self.stale_since_s {
                Some(_) => "understand why the backups are failing: \"hlb backup \
                            status\" names the destination and its consecutive failure \
                            count"
                    .to_string(),
                None => "configure a backup: \"hlb backup dest add <name> \
                         --location <path> --apply\""
                    .to_string(),
            });
            // No point advising to verify a backup that does not exist.
            return v;
        }

        if self.copies < 2 {
            v.push(
                "add a second destination: a single copy disappears with the machine \
                 carrying it"
                    .to_string(),
            );
        }

        if self.verification_failed {
            v.push(
                "find out why the last restore verification failed: \"hlb backup verify \
                 <app>\" says what did not come back"
                    .to_string(),
            );
        }

        match self.verified_s_ago {
            None => v.push(
                "verify a restore: \"hlb backup verify <app>\" — a backup never read \
                 back is a hypothesis"
                    .to_string(),
            ),
            Some(age) if age > VERIFICATION_STALE_S => v.push(format!(
                "re-verify a restore: the last one goes back {}",
                humanise(age)
            )),
            Some(_) => {}
        }

        if matches!(self.drills, Readiness::Never | Readiness::Overdue { .. }) {
            v.push(
                "run a recovery drill: \"hlb dr exercise\" — it is the only reliable \
                 indicator"
                    .to_string(),
            );
        }

        v
    }
}

/// A duration, roughly.
fn humanise(s: i64) -> String {
    match s {
        s if s < 90 => format!("{s} s"),
        s if s < 5_400 => format!("{} min", s / 60),
        s if s < 172_800 => format!("{} h", s / 3_600),
        s => format!("{} d", s / 86_400),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::destination::Coverage;

    fn coverage(app: &str, dests: Vec<(&str, State)>) -> Coverage {
        Coverage {
            app: app.into(),
            per_destination: dests.into_iter().map(|(n, e)| (n.to_string(), e)).collect(),
            classes: vec![crate::Class::Critical, crate::Class::Bulky],
        }
    }

    #[test]
    fn the_rpo_ignores_destinations_that_no_longer_protect() {
        // 🔴 The heart of the calculation: a destination stale for three weeks must NOT
        // supply the RPO. Otherwise we would display "2 h" based on a copy that no
        // longer protects.
        let c = coverage(
            "immich",
            vec![
                ("nas", State::Fresh { age_s: 7_200 }),
                ("offsite", State::Stale { age_s: 1_800 }),
            ],
        );
        let r = Restorability::compute(&c, Some(86_400), None, Readiness::Ready { days: 3 });
        assert_eq!(r.rpo_s, Some(7_200), "the stale one was taken into account");
    }

    #[test]
    fn nothing_to_restore_is_not_a_very_old_rpo() {
        // ⚠️ "No copy" and "RPO of three months" are repaired differently, and
        // confusing them would send you looking for why the backup is slow instead of
        // configuring it.
        let c = coverage("seafile", vec![("nas", State::Never)]);
        let r = Restorability::compute(&c, None, None, Readiness::Never);

        assert_eq!(r.rpo_s, None);
        assert_eq!(r.confidence(), Confidence::Nothing);
        assert!(r.verdict().contains("NEVER"), "{}", r.verdict());
        // And the remedy is to configure, not to verify.
        assert!(r.remedies()[0].contains("configure"), "{:?}", r.remedies());
        assert_eq!(
            r.remedies().len(),
            1,
            "no useless advice: {:?}",
            r.remedies()
        );
    }

    #[test]
    fn stale_copies_are_not_the_same_diagnosis_as_no_copies_at_all() {
        // 🔴 The CLAUDE.md trap, transposed to the verdict: "NO copy" shown next to a
        // destination dated three weeks ago reads as a contradiction. And the two are
        // not repaired the same way.
        let never = coverage("brand-new", vec![("nas", State::Never)]);
        let stale = coverage(
            "abandoned",
            vec![
                ("nas", State::Stale { age_s: 21 * 86_400 }),
                ("offsite", State::Stale { age_s: 30 * 86_400 }),
            ],
        );

        let a = Restorability::compute(&never, None, None, Readiness::Never);
        let b = Restorability::compute(&stale, None, None, Readiness::Never);

        // Both with no up-to-date copy, so both with no RPO…
        assert_eq!(a.rpo_s, None);
        assert_eq!(b.rpo_s, None);
        assert_eq!(a.confidence(), Confidence::Nothing);
        assert_eq!(b.confidence(), Confidence::Nothing);

        // …but they do not SAY the same thing, and do not advise the same thing.
        assert!(a.verdict().contains("NEVER"), "{}", a.verdict());
        assert!(b.verdict().contains("21 d"), "{}", b.verdict());
        assert_ne!(a.verdict(), b.verdict());
        assert!(a.remedies()[0].contains("configure"), "{:?}", a.remedies());
        assert!(b.remedies()[0].contains("failing"), "{:?}", b.remedies());
    }

    #[test]
    fn a_fresh_backup_never_restored_is_only_supposed() {
        // 🔴 The point: a backup never read back is a hypothesis, not a
        // guarantee. Showing it as "good" is exactly the lie we avoid.
        let c = coverage(
            "gitea",
            vec![
                ("nas", State::Fresh { age_s: 3_600 }),
                ("offsite", State::Fresh { age_s: 7_200 }),
            ],
        );
        let r = Restorability::compute(&c, None, None, Readiness::Ready { days: 2 });

        assert_eq!(r.copies, 2);
        assert_eq!(r.confidence(), Confidence::Assumed);
        assert!(r.confidence().describe().contains("ever been read back"));
        assert!(r.remedies().iter().any(|x| x.contains("verify")));
    }

    #[test]
    fn one_verified_copy_is_not_as_good_as_two() {
        // Losing that single destination takes everything, verified or not.
        let one = coverage("gitea", vec![("nas", State::Fresh { age_s: 600 })]);
        let two = coverage(
            "gitea",
            vec![
                ("nas", State::Fresh { age_s: 600 }),
                ("offsite", State::Fresh { age_s: 900 }),
            ],
        );

        let r1 = Restorability::compute(&one, Some(86_400), None, Readiness::Ready { days: 1 });
        let r2 = Restorability::compute(&two, Some(86_400), None, Readiness::Ready { days: 1 });

        assert!(r1.confidence() < r2.confidence());
        assert_eq!(r2.confidence(), Confidence::Verified);
        assert!(r1
            .remedies()
            .iter()
            .any(|x| x.contains("second destination")));
    }

    #[test]
    fn an_old_verification_downgrades_confidence() {
        let c = coverage(
            "gitea",
            vec![
                ("nas", State::Fresh { age_s: 600 }),
                ("offsite", State::Fresh { age_s: 900 }),
            ],
        );
        let r = Restorability::compute(
            &c,
            Some(VERIFICATION_STALE_S + 86_400),
            None,
            Readiness::Ready { days: 1 },
        );
        assert_eq!(r.confidence(), Confidence::Previous);
        assert!(r.remedies().iter().any(|x| x.contains("re-verify")));
    }

    #[test]
    fn continuous_archiving_changes_what_the_answer_means() {
        // Without PITR you restore at the instants of the backups. With it, at any
        // instant — a difference of kind, not of degree.
        let c = coverage("postgres", vec![("nas", State::Fresh { age_s: 300 })]);

        let sans = Restorability::compute(&c, Some(3_600), None, Readiness::Ready { days: 1 });
        assert!(sans.verdict().contains("at the instants of the backups"));

        let with_pitr = Restorability::compute(
            &c,
            Some(3_600),
            Some(7 * 86_400),
            Readiness::Ready { days: 1 },
        );
        assert!(
            with_pitr.verdict().contains("any instant"),
            "{}",
            with_pitr.verdict()
        );
    }

    #[test]
    fn a_healthy_app_gets_no_advice_at_all() {
        // 🔴 A list of advice displayed permanently stops being read.
        let c = coverage(
            "gitea",
            vec![
                ("nas", State::Fresh { age_s: 600 }),
                ("offsite", State::Fresh { age_s: 900 }),
            ],
        );
        let r = Restorability::compute(&c, Some(86_400), None, Readiness::Ready { days: 3 });
        assert!(r.remedies().is_empty(), "{:?}", r.remedies());
    }

    #[test]
    fn never_drilled_is_named_as_a_remedy() {
        // A drill never run is the only reliable indicator that is missing.
        let c = coverage(
            "gitea",
            vec![
                ("nas", State::Fresh { age_s: 600 }),
                ("offsite", State::Fresh { age_s: 900 }),
            ],
        );
        let r = Restorability::compute(&c, Some(86_400), None, Readiness::Never);
        assert!(r.remedies().iter().any(|x| x.contains("drill")));
    }

    #[test]
    fn a_verification_failed_after_a_success_lowers_the_confidence() {
        // 🔴 Found by review: only successes were read, so a restore that failed last
        // night left the app "verified" by the one that worked a week ago.
        let c = coverage(
            "gitea",
            vec![
                ("nas", State::Fresh { age_s: 600 }),
                ("offsite", State::Fresh { age_s: 900 }),
            ],
        );
        let r = Restorability::compute(&c, Some(86_400), None, Readiness::Ready { days: 3 });
        assert_eq!(r.confidence(), Confidence::Verified);

        let r = r.with_failed_verification(true);
        assert_eq!(r.confidence(), Confidence::Nothing);
        assert!(
            r.remedies()
                .iter()
                .any(|m| m.contains("verification failed")),
            "{:?}",
            r.remedies()
        );
    }
}
