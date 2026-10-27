//! The alert rules.
//!
//! ## 🔴 Why Homelabus evaluates them itself rather than using Alertmanager
//!
//! The canonical chain is `vmalert → Alertmanager → webhook → ntfy`. It is not taken
//! here, for a precise reason: `hlb-notify` already carries the four levels and the
//! quiet hours, tested. Handing routing to Alertmanager would mean **restating** those
//! rules in its configuration, in another syntax, untested - and two definitions of
//! "what deserves waking someone" always end up diverging. So there is one authority,
//! and VictoriaMetrics only does what it does best: store and answer.
//!
//! ## 🔴 The central invariant: an absent metric is not a metric at zero
//!
//! Same trap as `hlb_backup_age_seconds`: emitting `0` for an app that was never backed
//! up would mean "backed up just now", and the alert would never fire for the apps most
//! at risk. So the metric is **absent**.
//!
//! Direct consequence here: a rule that finds nothing must **never** conclude "all is
//! well". It concludes "I do not know", which is a distinct and visible state - see
//! [`Evaluation::Unknown`]. An all-green dashboard because the scrape died is exactly
//! the failure this module exists to prevent.

use hlb_notify::{Level, Notification};

/// What a rule concludes after querying.
#[derive(Debug, Clone, PartialEq)]
pub enum Evaluation {
    /// The threshold is respected.
    Ok,
    /// The threshold is breached, with the observed value.
    Triggered { value: f64 },
    /// 🔴 No data. **This is not `Ok`.**
    ///
    /// The scrape may have died, the target may be unreachable. Confusing this with
    /// `Ok` produces a green dashboard while the cluster burns.
    Unknown { reason: String },
}

/// The comparison that decides whether to fire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Comparison {
    /// Fires above the threshold (backup age, disk usage...).
    Above,
    /// Fires below it (reachable nodes, live replicas...).
    Below,
}

/// An alert rule.
#[derive(Debug, Clone)]
pub struct Rule {
    /// A short, stable identifier — used as the notification subject.
    pub name: &'static str,
    /// The PromQL query to run.
    pub query: &'static str,
    pub comparison: Comparison,
    pub threshold: f64,
    pub level: Level,
    /// What the person needs to understand, in one sentence.
    pub explanation: &'static str,
    /// 🔴 Is the absence of data itself an alert?
    ///
    /// For most rules, yes: if `hlb_app_up` disappears, the controller or the scrape
    /// has died, which is more serious than most thresholds. See [`Rule::juger`].
    pub alarming_absence: bool,
    /// The label naming what crossed the threshold (`app`, `node`), when the query
    /// keeps one series per subject. 🔴 A rule read as one number was said once: a
    /// second app failing while the first still did was never notified at all.
    pub subject: Option<&'static str>,
}

impl Rule {
    /// Turns a query result into an evaluation.
    ///
    /// `values` is empty when the query returned nothing.
    pub fn judge(&self, values: &[f64]) -> Evaluation {
        let Some(worst) = (match self.comparison {
            // Judged on the worst case: a single app with no backup deserves the
            // alert, and an average would drown it.
            Comparison::Above => values
                .iter()
                .cloned()
                .fold(None, |a: Option<f64>, v| Some(a.map_or(v, |x| x.max(v)))),
            Comparison::Below => values
                .iter()
                .cloned()
                .fold(None, |a: Option<f64>, v| Some(a.map_or(v, |x| x.min(v)))),
        }) else {
            return Evaluation::Unknown {
                reason: "no data".into(),
            };
        };

        let crossed = match self.comparison {
            Comparison::Above => worst > self.threshold,
            Comparison::Below => worst < self.threshold,
        };

        if crossed {
            Evaluation::Triggered { value: worst }
        } else {
            Evaluation::Ok
        }
    }

    /// The subjects whose own series crosses the threshold, sorted — empty for a rule
    /// read as one number, or when the series carry no such label.
    pub fn breaching(&self, samples: &[crate::Sample]) -> Vec<String> {
        let Some(label) = self.subject else {
            return Vec::new();
        };
        let mut out: Vec<String> = samples
            .iter()
            .filter(|s| match self.comparison {
                Comparison::Above => s.value > self.threshold,
                Comparison::Below => s.value < self.threshold,
            })
            .filter_map(|s| s.labels.get(label).cloned())
            .collect();
        out.sort();
        out.dedup();
        out
    }

    /// [`Self::notification`], naming the subjects that cross the threshold.
    pub fn notification_naming(&self, e: &Evaluation, subjects: &[String]) -> Option<Notification> {
        let mut n = self.notification(e)?;
        if matches!(e, Evaluation::Triggered { .. }) && !subjects.is_empty() {
            n.title = format!("{}: {}", self.name, subjects.join(", "));
        }
        Some(n)
    }

    /// The notification to send, or `None` when there is nothing to say.
    ///
    /// 🔴 An `Unknown` evaluation on an `alarming_absence` rule produces a
    /// notification **of its own**, distinct from a normal firing: "I do not know" and
    /// "all is well" must never produce the same output.
    pub fn notification(&self, e: &Evaluation) -> Option<Notification> {
        match e {
            Evaluation::Ok => None,

            Evaluation::Triggered { value } => Some(Notification::new(
                self.level,
                self.name,
                self.name,
                &format!(
                    "{} (measured: {value:.2}, threshold: {})",
                    self.explanation, self.threshold
                ),
            )),

            Evaluation::Unknown { reason } if self.alarming_absence => Some(Notification::new(
                // 🔴 The level is NOT the rule's: not knowing is an observability
                // problem, not the problem the rule watches. Reporting it at the rule's
                // level would suggest the threshold is breached, when we do not know
                // whether it is.
                Level::Important,
                self.name,
                &format!("{}: no more data", self.name),
                &format!(
                    "Rule \"{}\" can no longer be evaluated ({reason}). \
                     This is NOT \"all is well\": the scrape or the target has \
                     probably died, and this check has been blind ever since.",
                    self.name
                ),
            )),

            Evaluation::Unknown { .. } => None,
        }
    }
}

/// The rules shipped with Homelabus.
///
/// They query metrics the controller already exposes: nothing more to instrument, and
/// each corresponds to a failure that really cost something.
pub fn default_rules() -> Vec<Rule> {
    vec![
        Rule {
            name: "backup-absent",
            // 🔴 No threshold on `hlb_backup_age_seconds`: the metric is ABSENT when
            // nothing ever succeeded. A 1 for each app holding data that has none —
            // named, so a second app never backed up is a notification of its own.
            // - `hlb_backup_copies` is emitted for the apps holding something to back
            //   up, and those only: counted over `hlb_app_up`, Valkey and LibreSpeed
            //   were "never backed up" forever.
            // - `or count(hlb_app_up) * 0`: every app backed up is a zero — but no
            //   `hlb_app_up` at all is still the scrape that died, never "all is well".
            query: "(hlb_backup_copies * 0 + 1) unless on(app) hlb_backup_age_seconds \
                    or count(hlb_app_up) * 0",
            comparison: Comparison::Above,
            threshold: 0.0,
            level: Level::Critical,
            explanation: "Some apps have NO successful backup. \
                          They may be running perfectly - which is the worst state \
                          of the system, and the one that looks healthiest.",
            subject: Some("app"),
            alarming_absence: true,
        },
        Rule {
            name: "backup-late",
            query: "hlb_backup_age_seconds",
            comparison: Comparison::Above,
            // 48 h: a daily backup can skip one night without that being an incident.
            // Two nights is a failure.
            threshold: 172_800.0,
            level: Level::Important,
            explanation: "A backup is more than 48 h old.",
            subject: Some("app"),
            alarming_absence: false,
        },
        Rule {
            name: "single-copy",
            // 🔴 The number of CONFIGURED destinations says nothing about the number
            // of copies. Three destinations with two failing is not 3-2-1 - and it is
            // exactly the state an aggregated dashboard would pass off as healthy.
            query: "hlb_backup_copies",
            comparison: Comparison::Below,
            threshold: 2.0,
            level: Level::Important,
            explanation: "An app has only ONE up-to-date copy left. The other \
                          destinations are configured but failing - configured \
                          is not protected.",
            subject: Some("app"),
            alarming_absence: false,
        },
        Rule {
            name: "verification-stale",
            // 🔴 A backup never restored is not a backup, it is a hypothesis.
            query: "hlb_backup_verification_age_seconds",
            comparison: Comparison::Above,
            threshold: 2_678_400.0, // 31 days
            level: Level::Important,
            explanation: "No verified restore for over a month. \
                          A backup never restored is a hypothesis.",
            subject: Some("app"),
            alarming_absence: false,
        },
        Rule {
            name: "app-failed",
            query: "hlb_app_up",
            comparison: Comparison::Below,
            threshold: 1.0,
            level: Level::Critical,
            explanation: "An app has failed.",
            subject: Some("app"),
            alarming_absence: true,
        },
        Rule {
            name: "node-unreachable",
            query: "hlb_node_reachable",
            comparison: Comparison::Below,
            threshold: 1.0,
            level: Level::Critical,
            explanation: "A node has stopped answering.",
            subject: Some("node"),
            alarming_absence: true,
        },
        Rule {
            name: "disk-full",
            query: "hlb_disk_used_ratio",
            comparison: Comparison::Above,
            // 🔴 85 % and not 95 %: beyond that, PostgreSQL and restic have no room
            // left to work, and that is precisely when you would want to back up before
            // intervening. Alerting too late amounts to not alerting.
            threshold: 0.85,
            level: Level::Important,
            explanation: "A disk is over 85 %. Beyond that, backups and dumps \
                          have no room left to run.",
            subject: Some("node"),
            alarming_absence: false,
        },
        Rule {
            name: "blocking-guides",
            query: "sum(hlb_blocking_guides)",
            comparison: Comparison::Above,
            threshold: 0.0,
            level: Level::Info,
            explanation: "Manual actions are blocking an installation.",
            subject: None,
            alarming_absence: false,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(comparison: Comparison, threshold: f64, alarming_absence: bool) -> Rule {
        Rule {
            name: "trial",
            query: "x",
            comparison,
            threshold,
            level: Level::Critical,
            explanation: "explanation",
            alarming_absence,
            subject: Some("app"),
        }
    }

    #[test]
    fn no_data_is_never_ok() {
        // 🔴 The module's invariant. A rule with no data does NOT conclude "all is
        // well": the scrape may have died, and a green dashboard while the cluster
        // burns is the failure being avoided.
        let e = rule(Comparison::Above, 10.0, true).judge(&[]);
        assert!(matches!(e, Evaluation::Unknown { .. }), "{e:?}");
        assert_ne!(e, Evaluation::Ok);
    }

    #[test]
    fn missing_data_alerts_on_its_own() {
        // And that ignorance is SAID, instead of being swallowed silently.
        let r = rule(Comparison::Above, 10.0, true);
        let n = r
            .notification(&r.judge(&[]))
            .expect("absent data must produce a notification");

        assert!(n.body.contains("NOT \"all is well\""), "{}", n.body);
        assert!(n.body.contains("blind"), "{}", n.body);
    }

    #[test]
    fn not_knowing_is_not_reported_as_the_threshold_being_crossed() {
        // 🔴 The level of absent data is not the rule's. Sending a "critical" would
        // suggest the threshold is breached, when whether it is is precisely what we do
        // not know. This is an observability problem, not a threshold one.
        let r = rule(Comparison::Above, 10.0, true);
        assert_eq!(r.level, Level::Critical);

        let n = r.notification(&r.judge(&[])).expect("notification");
        assert_eq!(n.level, Level::Important);

        // A real breach, on the other hand, keeps the rule's own level.
        let d = r.notification(&r.judge(&[42.0])).expect("notification");
        assert_eq!(d.level, Level::Critical);
    }

    #[test]
    fn silence_is_allowed_only_when_it_was_declared_harmless() {
        // Some rules legitimately have nothing to say when the metric is missing - but
        // that is an EXPLICIT choice, never the default.
        let r = rule(Comparison::Above, 10.0, false);
        assert!(r.notification(&r.judge(&[])).is_none());
    }

    #[test]
    fn the_worst_case_decides_never_the_average() {
        // 🔴 A single app with no backup deserves the alert. An average would drown it
        // under the healthy ones - the more of them there are, the more effectively.
        let above = rule(Comparison::Above, 10.0, false);
        assert_eq!(
            above.judge(&[1.0, 2.0, 99.0]),
            Evaluation::Triggered { value: 99.0 }
        );

        // And symmetrically for low thresholds: a single downed node is enough.
        let low = rule(Comparison::Below, 1.0, false);
        assert_eq!(
            low.judge(&[1.0, 1.0, 0.0]),
            Evaluation::Triggered { value: 0.0 }
        );
        assert_eq!(low.judge(&[1.0, 1.0]), Evaluation::Ok);
    }

    #[test]
    fn the_threshold_is_strict() {
        // Exactly at the threshold nothing fires: otherwise a disk at exactly 85 %
        // would alert permanently without anything getting worse.
        let r = rule(Comparison::Above, 0.85, false);
        assert_eq!(r.judge(&[0.85]), Evaluation::Ok);
        assert!(matches!(r.judge(&[0.8501]), Evaluation::Triggered { .. }));
    }

    #[test]
    fn never_backed_up_outranks_everything_else() {
        // 🔴 The same hierarchy as in the UI: an app running perfectly with no backup
        // is the worst state of the system, and the one that looks healthiest on a
        // dashboard.
        let r = default_rules();
        let absent = r
            .iter()
            .find(|x| x.name == "backup-absent")
            .expect("rule present");

        assert_eq!(absent.level, Level::Critical);
        assert!(
            absent.alarming_absence,
            "if this rule itself goes quiet, that must be known"
        );

        let lag = r
            .iter()
            .find(|x| x.name == "backup-late")
            .expect("rule present");
        assert!(
            absent.level > lag.level,
            "never backed up is more serious than overdue"
        );
    }

    #[test]
    fn the_never_backed_up_rule_does_not_read_an_absent_metric() {
        // 🔴 The heart of the trap: `hlb_backup_age_seconds` is ABSENT for an app that
        // was never backed up. A threshold over it would therefore never see those apps
        // - exactly the ones to detect. The apps owed one are those WITHOUT it.
        let r = default_rules();
        let absent = r
            .iter()
            .find(|x| x.name == "backup-absent")
            .expect("rule present");
        assert!(
            absent
                .query
                .contains("unless on(app) hlb_backup_age_seconds"),
            "the rule must name the apps lacking the metric, not compare it: {}",
            absent.query
        );
    }

    #[test]
    fn apps_holding_nothing_are_never_owed_a_backup() {
        // 🔴 Found by review: counted over `hlb_app_up`, every stateless app was a
        // permanent `backup-absent`, and a rule already firing notified no real loss.
        let r = default_rules();
        let absent = r
            .iter()
            .find(|x| x.name == "backup-absent")
            .expect("rule present");
        let (owed, alive) = absent.query.split_once(" or ").expect("owed, or alive");
        assert!(owed.starts_with("(hlb_backup_copies"), "{owed}");
        // The scrape alive with every app backed up is a zero; dead, it is no series.
        assert!(alive.trim() == "count(hlb_app_up) * 0", "{alive}");
        assert!(
            !absent.query.contains("vector("),
            "a dead scrape must stay unknown: {}",
            absent.query
        );
    }

    #[test]
    fn a_rule_watching_subjects_reads_each_one_s_own_series() {
        // 🔴 `min(hlb_app_up)` answered one number: gitea failing, then immich, was one
        // notification — the second failure was never said.
        for r in default_rules() {
            let Some(label) = r.subject else { continue };
            for agg in ["min(", "max(", "sum(", "avg("] {
                assert!(
                    !r.query.starts_with(agg),
                    "{} names its {label}s, yet aggregates them away: {}",
                    r.name,
                    r.query
                );
            }
        }
        let failed = default_rules()
            .into_iter()
            .find(|r| r.name == "app-failed")
            .expect("rule");
        let sample = |app: &str, value| crate::Sample {
            labels: [("app".to_string(), app.to_string())].into(),
            value,
        };
        let samples = [
            sample("immich", 0.0),
            sample("gitea", 0.0),
            sample("n8n", 1.0),
        ];
        assert_eq!(failed.breaching(&samples), ["gitea", "immich"]);
        let e = failed.judge(&samples.iter().map(|s| s.value).collect::<Vec<_>>());
        let n = failed
            .notification_naming(&e, &failed.breaching(&samples))
            .expect("notification");
        assert_eq!(n.title, "app-failed: gitea, immich");
    }

    #[test]
    fn every_rule_explains_itself() {
        // An alert that does not say what it wants is an alert people end up ignoring,
        // and an ignored alert protects nothing.
        for r in default_rules() {
            assert!(!r.explanation.is_empty(), "{} has no explanation", r.name);
            assert!(
                r.explanation.len() > 15,
                "{}: explanation too short to act on",
                r.name
            );
            assert!(!r.query.is_empty(), "{} has no query", r.name);
        }
    }

    #[test]
    fn a_disk_alert_leaves_room_to_act() {
        // 🔴 Alerting at 95 % amounts to not alerting: PostgreSQL and restic then have
        // no room left to work, and that is precisely when you would want to back up
        // before intervening.
        let r = default_rules();
        let d = r.iter().find(|x| x.name == "disk-full").expect("rule");
        assert!(
            d.threshold <= 0.85,
            "threshold trop tardif : {}",
            d.threshold
        );
    }
}
