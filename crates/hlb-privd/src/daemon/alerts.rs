//! The alert rules, evaluated on a timer.
//!
//! 🔴 **A loop never panics.** An error is logged and the next pass retries.

use std::sync::Arc;

use super::notify::{Notifier, Said};

/// Periodic evaluation of the alert rules.
///
/// ## What was missing
///
/// `hlb_metrics::default_rules()` existed, and was evaluated **only by the CLI** —
/// so only when someone typed `hlb metrics check`. There was no continuous monitoring:
/// the rules described what needed watching without anyone watching it.
///
/// ## 🔴 A muted alert is still an alert
///
/// Muting stops the **notification**, not the **display**. Making a muted alert vanish
/// from the state would give a green dashboard for a known, unresolved problem — the
/// same family of mistake as `Freshness`.
pub struct AlertLoop {
    source: Arc<dyn Measure>,
    notif: Notifier,
    /// Where the mutes are: read on every pass, so a mute set from the interface or
    /// the CLI applies at the next evaluation, and one set before a restart still does.
    state: Arc<hlb_state::State>,
    /// The current state of the alerts, which the web side asks for
    /// (`Intent::Alerts`). An `RwLock` because several screens can read while a single
    /// pass writes.
    pub active: AlertsState,
    rules: Vec<hlb_metrics::Rule>,
    /// What each firing rule was last SAID at: its level and the subjects named. In
    /// memory, like the alerts: a restart says again what still fires.
    said: tokio::sync::Mutex<std::collections::BTreeMap<&'static str, SaidAs>>,
    /// When the previous pass ran: an alert's age grows by the time really elapsed,
    /// whatever `--alerts-secs` says.
    last_pass: tokio::sync::Mutex<Option<i64>>,
}

/// What a firing rule was last notified at.
#[derive(Debug, Clone)]
struct SaidAs {
    level: hlb_api::AlertLevel,
    subjects: std::collections::BTreeSet<String>,
}

/// Where the rules' series come from: VictoriaMetrics, or a test's own numbers.
#[async_trait::async_trait]
pub trait Measure: Send + Sync {
    async fn samples(&self, query: &str) -> Result<Vec<hlb_metrics::Sample>, String>;
}

/// What one evaluation pass produced.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct AlertReport {
    pub evaluated: usize,
    pub triggered: usize,
    /// 🔴 Rules we could **not** evaluate. This is not "zero alerts": it is blind
    /// monitoring, and it must be counted separately.
    pub unknowns: usize,
    /// Said now: sent, or logged with no ntfy.
    pub notified: usize,
    /// Kept for the end of quiet hours.
    pub held: usize,
    /// The rules notified or held this pass.
    pub said: Vec<String>,
}

impl AlertLoop {
    /// The loop over a source of series: VictoriaMetrics, or a test's numbers.
    pub fn new(source: Arc<dyn Measure>, notif: Notifier, state: Arc<hlb_state::State>) -> Self {
        Self {
            source,
            notif,
            state,
            active: Default::default(),
            rules: hlb_metrics::rules::default_rules(),
            said: Default::default(),
            last_pass: Default::default(),
        }
    }

    /// One evaluation pass.
    pub async fn tick(&self, now: i64) -> AlertReport {
        let mut report = AlertReport::default();
        let mut updates = Vec::new();

        // The first-seen dates of the previous pass: an alert that persists keeps its
        // age, or "for 3 days" would become "just now" on every pass, and you would
        // never see that it is lasting.
        let previous_alerts = self.active.read().await.clone();
        let elapsed = {
            let mut last = self.last_pass.lock().await;
            let e = last.map_or(DEFAULT_INTERVAL_S, |l| (now - l).max(0));
            *last = Some(now);
            e
        };
        // ⚠️ A table that cannot be read means no mute applies this pass: the alerts
        // notify. Silence on a broken database is the worse of the two failures.
        let mutes = match self.state.alert_mutes(now).await {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!("alert mutes unreadable, none applied this pass: {e}");
                Vec::new()
            }
        };
        let mut said = self.said.lock().await;

        for r in &self.rules {
            report.evaluated += 1;

            let (e, subjects) = match self.source.samples(r.query).await {
                Ok(samples) => {
                    let values: Vec<f64> = samples.iter().map(|s| s.value).collect();
                    (r.judge(&values), r.breaching(&samples))
                }
                Err(reason) => (hlb_metrics::Evaluation::Unknown { reason }, Vec::new()),
            };

            let (level, value) = match &e {
                hlb_metrics::Evaluation::Ok => {
                    // Resolved: its return is news again.
                    said.remove(r.name);
                    continue;
                }
                hlb_metrics::Evaluation::Triggered { value } => {
                    report.triggered += 1;
                    (level_of(r.level), Some(*value))
                }
                hlb_metrics::Evaluation::Unknown { .. } => {
                    report.unknowns += 1;
                    if !r.alarming_absence {
                        continue;
                    }
                    (hlb_api::AlertLevel::Unknown, None)
                }
            };

            let previous = previous_alerts.iter().find(|a| a.rule == r.name);
            let since_s = match previous {
                Some(a) => a.since_s + elapsed,
                None => 0,
            };

            let mut alert = hlb_api::ActiveAlert {
                rule: r.name.to_string(),
                level,
                explanation: r.explanation.to_string(),
                value,
                threshold: r.threshold,
                since_s,
                muted_until: None,
                muted_by: None,
                mute_reason: None,
            };
            alert.apply_mutes(&mutes);

            // 🔴 The notification respects the mute, and is said once per news — not
            // on every pass, or you would turn notifications off wholesale. News is a
            // rule not said yet (first seen, or first seen MUTED and unmuted since), a
            // level above the one said (unknown → triggered), or a subject not named
            // yet: a second app failing while the first still does.
            let known = said.get(r.name).cloned();
            let subjects: std::collections::BTreeSet<String> = subjects.into_iter().collect();
            let news = match &known {
                None => true,
                Some(k) => level > k.level || !subjects.is_subset(&k.subjects),
            };
            let triggered = matches!(e, hlb_metrics::Evaluation::Triggered { .. });
            if !alert.is_muted(now) && news {
                let named: Vec<String> = subjects.iter().cloned().collect();
                if let Some(n) = r.notification_naming(&e, &named) {
                    match self.notif.say(&n, now).await {
                        Ok(how) => {
                            match how {
                                Said::Held => report.held += 1,
                                Said::Sent | Said::Logged => report.notified += 1,
                            }
                            report.said.push(r.name.to_string());
                            let mut was = known
                                .as_ref()
                                .map(|k| k.subjects.clone())
                                .unwrap_or_default();
                            if triggered {
                                was.clear();
                            }
                            said.insert(
                                r.name,
                                SaidAs {
                                    level: known.as_ref().map_or(level, |k| k.level.max(level)),
                                    subjects: was.into_iter().chain(subjects).collect(),
                                },
                            );
                        }
                        // Not said: the next pass tries again.
                        Err(e) => tracing::warn!(rule = r.name, "alert not notified: {e}"),
                    }
                }
            } else if let (Some(k), true) = (said.get_mut(r.name), triggered) {
                // A subject that recovered leaves the set: failing again is news.
                k.subjects = subjects;
            }

            updates.push(alert);
        }
        drop(said);

        // Sorted by severity: what matters must be at the top without the interface
        // having to redo that sort.
        updates.sort_by(|a, b| b.level.cmp(&a.level).then_with(|| a.rule.cmp(&b.rule)));
        *self.active.write().await = updates;
        report
    }
}

/// The alert state, shared between the loop that writes and the API that reads.
pub type AlertsState = Arc<tokio::sync::RwLock<Vec<hlb_api::ActiveAlert>>>;

/// Default interval between two evaluations.
pub const DEFAULT_INTERVAL_S: i64 = 60;

fn level_of(l: hlb_notify::Level) -> hlb_api::AlertLevel {
    match l {
        hlb_notify::Level::Debug | hlb_notify::Level::Info => hlb_api::AlertLevel::Info,
        hlb_notify::Level::Important => hlb_api::AlertLevel::Important,
        hlb_notify::Level::Critical => hlb_api::AlertLevel::Critical,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // AlertLoop (lot 3.4)
    // -----------------------------------------------------------------------

    async fn alert_loop() -> AlertLoop {
        // No ntfy, no VictoriaMetrics: we exercise the state logic, not the network.
        // That is exactly what the split allows.
        let state = Arc::new(hlb_state::State::in_memory().await.expect("state"));
        loop_on(state)
    }

    fn loop_on(state: Arc<hlb_state::State>) -> AlertLoop {
        AlertLoop::new(
            Arc::new(Unreachable),
            Notifier::new(None, state.clone()),
            state,
        )
    }

    /// VictoriaMetrics down: every query fails.
    struct Unreachable;

    #[async_trait::async_trait]
    impl Measure for Unreachable {
        async fn samples(&self, _: &str) -> Result<Vec<hlb_metrics::Sample>, String> {
            Err("VictoriaMetrics unreachable".into())
        }
    }

    /// Series a test sets per query; any other query answers nothing (unknown).
    #[derive(Default)]
    struct Numbers(std::sync::Mutex<std::collections::BTreeMap<String, Vec<hlb_metrics::Sample>>>);

    impl Numbers {
        fn set(&self, rule: &str, label: &str, values: &[(&str, f64)]) {
            let query = hlb_metrics::rules::default_rules()
                .into_iter()
                .find(|r| r.name == rule)
                .expect("rule")
                .query;
            let samples = values
                .iter()
                .map(|(subject, value)| hlb_metrics::Sample {
                    labels: [(label.to_string(), subject.to_string())].into(),
                    value: *value,
                })
                .collect();
            self.0.lock().expect("lock").insert(query.into(), samples);
        }
    }

    #[async_trait::async_trait]
    impl Measure for Numbers {
        async fn samples(&self, query: &str) -> Result<Vec<hlb_metrics::Sample>, String> {
            Ok(self
                .0
                .lock()
                .expect("lock")
                .get(query)
                .cloned()
                .unwrap_or_default())
        }
    }

    async fn measured(notif: Option<Arc<hlb_notify::NtfyClient>>) -> (AlertLoop, Arc<Numbers>) {
        let state = Arc::new(hlb_state::State::in_memory().await.expect("state"));
        let numbers = Arc::new(Numbers::default());
        let b = AlertLoop::new(numbers.clone(), Notifier::new(notif, state.clone()), state);
        (b, numbers)
    }

    fn said(r: &AlertReport, rule: &str) -> bool {
        r.said.iter().any(|s| s == rule)
    }

    #[tokio::test]
    async fn a_second_app_failing_is_a_notification_of_its_own() {
        let (b, n) = measured(None).await;
        n.set("app-failed", "app", &[("gitea", 0.0), ("n8n", 1.0)]);
        assert!(said(&b.tick(1_000).await, "app-failed"));
        assert!(
            !said(&b.tick(1_060).await, "app-failed"),
            "said once per news"
        );

        n.set("app-failed", "app", &[("gitea", 0.0), ("immich", 0.0)]);
        assert!(
            said(&b.tick(1_120).await, "app-failed"),
            "immich failing while gitea still does was never said"
        );
        // gitea recovers, then fails again: news.
        n.set("app-failed", "app", &[("immich", 0.0)]);
        assert!(!said(&b.tick(1_180).await, "app-failed"));
        n.set("app-failed", "app", &[("gitea", 0.0), ("immich", 0.0)]);
        assert!(said(&b.tick(1_240).await, "app-failed"));
    }

    #[tokio::test]
    async fn an_alert_rising_from_unknown_to_triggered_is_said_again() {
        let (b, n) = measured(None).await;
        // No series: "no more data", said at Important.
        assert!(said(&b.tick(1_000).await, "app-failed"));
        n.set("app-failed", "app", &[("gitea", 0.0)]);
        assert!(
            said(&b.tick(1_060).await, "app-failed"),
            "an app failing after a blind spell was never said"
        );
    }

    #[tokio::test]
    async fn an_alert_first_seen_muted_is_said_once_the_mute_ends() {
        let (b, n) = measured(None).await;
        mute_everything(&b.state, 2_000).await;
        n.set("app-failed", "app", &[("gitea", 0.0)]);
        assert!(!said(&b.tick(1_000).await, "app-failed"));
        assert!(
            said(&b.tick(2_000).await, "app-failed"),
            "still firing once unmuted, and never said"
        );
    }

    #[tokio::test]
    async fn an_alert_ntfy_refused_is_tried_again() {
        use std::sync::atomic::Ordering;
        let ntfy = super::super::notify::fake_ntfy().await;
        let client = hlb_notify::NtfyClient::new(&ntfy.url, "hlb");
        let (b, n) = measured(Some(Arc::new(client))).await;
        n.set("app-failed", "app", &[("gitea", 0.0)]);
        // Noon UTC, no quiet hours: refused, so nothing counts as said.
        let noon = 1_782_907_200;
        ntfy.refusing.store(true, Ordering::SeqCst);
        assert!(!said(&b.tick(noon).await, "app-failed"));
        assert!(
            ntfy.hits.load(Ordering::SeqCst) > 0,
            "the floor: it was tried"
        );
        ntfy.refusing.store(false, Ordering::SeqCst);
        assert!(said(&b.tick(noon + 60).await, "app-failed"));
    }

    #[tokio::test]
    async fn an_alert_s_age_is_the_time_really_elapsed() {
        let (b, n) = measured(None).await;
        n.set("app-failed", "app", &[("gitea", 0.0)]);
        b.tick(1_000).await;
        b.tick(1_300).await;
        let active = b.active.read().await;
        let a = active
            .iter()
            .find(|a| a.rule == "app-failed")
            .expect("alert");
        assert_eq!(a.since_s, 300, "a five-minute interval counted as one");
    }

    /// Mutes every rule until `until`, the way the route and the CLI do: in the table.
    async fn mute_everything(state: &hlb_state::State, until: i64) {
        for r in hlb_metrics::rules::default_rules() {
            state
                .mute_alert(&hlb_api::AlertMute {
                    rule: r.name.into(),
                    until,
                    by: "lena".into(),
                    reason: "test".into(),
                })
                .await
                .expect("mute");
        }
    }

    fn alert(rule: &str, level: hlb_api::AlertLevel, since: i64) -> hlb_api::ActiveAlert {
        hlb_api::ActiveAlert {
            rule: rule.into(),
            level,
            explanation: "quelque chose".into(),
            value: Some(1.0),
            threshold: 0.0,
            since_s: since,
            muted_until: None,
            muted_by: None,
            mute_reason: None,
        }
    }

    #[tokio::test]
    async fn an_unreachable_metrics_base_produces_unknown_not_silence() {
        // 🔴 The case that counts: VictoriaMetrics is unreachable. Reporting nothing
        // would give a green dashboard while ALL monitoring is blind. The rules marked
        // `alarming_absence` must surface.
        let b = alert_loop().await;
        let r = b.tick(1_000).await;

        assert!(r.evaluated > 0, "no rule evaluated");
        assert!(
            r.unknowns > 0,
            "an unreachable database must produce unknowns"
        );

        let active = b.active.read().await;
        assert!(
            active
                .iter()
                .any(|a| a.level == hlb_api::AlertLevel::Unknown),
            "no \"non-evaluable\" alert: monitoring would be blind in silence"
        );
    }

    #[tokio::test]
    async fn alerts_are_sorted_worst_first() {
        // The interface must not have to re-sort: what matters is at the top.
        let b = alert_loop().await;
        b.tick(1_000).await;

        let active = b.active.read().await;
        for f in active.windows(2) {
            assert!(
                f[0].level >= f[1].level,
                "sort broken: {:?} before {:?}",
                f[0].level,
                f[1].level
            );
        }
    }

    #[tokio::test]
    async fn a_persisting_alert_keeps_its_age() {
        // 🔴 An alert that has lasted three days and one that has just appeared are not
        // handled the same: the first has been ignored, or its remedy does not work.
        // Resetting the age on every pass would erase that information.
        let b = alert_loop().await;
        b.tick(1_000).await;
        let after_one = b.active.read().await.clone();
        assert!(!after_one.is_empty());

        b.tick(1_060).await;
        let after_two = b.active.read().await.clone();

        let av = after_one.first().expect("an alert");
        let ap = after_two
            .iter()
            .find(|a| a.rule == av.rule)
            .expect("the same alert");
        assert!(ap.since_s > av.since_s, "the age must grow");
    }

    #[tokio::test]
    async fn a_silence_survives_a_new_evaluation() {
        // A mute that dropped on the next pass would be of no use: you would set it
        // again every minute.
        let b = alert_loop().await;
        b.tick(1_000).await;
        mute_everything(&b.state, 9_999).await;

        b.tick(1_060).await;
        b.tick(1_120).await;
        let active = b.active.read().await;
        assert!(!active.is_empty());
        assert!(
            active.iter().all(|a| a.muted_until == Some(9_999)),
            "the mute was lost on the next pass"
        );
        assert!(active.iter().all(|a| a.muted_by.as_deref() == Some("lena")));
        assert!(active
            .iter()
            .all(|a| a.mute_reason.as_deref() == Some("test")));
    }

    #[tokio::test]
    async fn a_mute_survives_a_restart_and_keeps_the_notification_quiet() {
        // 🔴 The defect this table fixed: mutes lived in the loop's memory, so a
        // restart lifted them all and the first pass notified everything again.
        let state = Arc::new(hlb_state::State::in_memory().await.expect("state"));
        let unmuted = loop_on(state.clone()).tick(1_000).await;
        assert!(
            unmuted.notified > 0,
            "the floor: with no mute, a first pass notifies — or the assertion below \
             proves nothing"
        );

        mute_everything(&state, 9_999).await;
        let restarted = loop_on(state.clone());
        let r = restarted.tick(1_000).await;
        assert_eq!(
            r.notified, 0,
            "a stored mute did not silence the first pass"
        );
    }

    #[tokio::test]
    async fn a_lifted_or_ended_mute_stops_applying() {
        let b = alert_loop().await;
        mute_everything(&b.state, 2_000).await;
        b.tick(1_000).await;
        assert!(b
            .active
            .read()
            .await
            .iter()
            .all(|a| a.muted_until.is_some()));

        // Ended: past `until`, nobody needed to delete it.
        b.tick(2_000).await;
        assert!(b
            .active
            .read()
            .await
            .iter()
            .all(|a| a.muted_until.is_none()));

        mute_everything(&b.state, 9_999).await;
        for r in hlb_metrics::rules::default_rules() {
            b.state.unmute_alert(r.name).await.expect("lift");
        }
        b.tick(2_060).await;
        assert!(b
            .active
            .read()
            .await
            .iter()
            .all(|a| a.muted_until.is_none()));
    }

    #[tokio::test]
    async fn a_silenced_alert_stays_in_the_list() {
        // 🔴 Muting stops the NOTIFICATION, not the DISPLAY. Making it vanish would
        // give a green dashboard for a known, unresolved problem.
        let b = alert_loop().await;
        b.tick(1_000).await;
        let before = b.active.read().await.len();

        mute_everything(&b.state, 9_999).await;
        b.tick(1_060).await;

        let after = b.active.read().await;
        assert_eq!(after.len(), before, "a muted alert vanished from the list");
        // Downgraded one notch, never `Ok`: muted is not resolved.
        for a in after.iter() {
            assert_ne!(
                a.attention(1_060),
                hlb_api::Attention::Ok,
                "{} reads as resolved",
                a.rule
            );
        }
    }

    #[test]
    fn every_notify_level_maps_to_an_alert_level() {
        // An exhaustive `match`: adding a level to `hlb_notify` must fail compilation
        // here rather than silently fall back on "info".
        assert_eq!(
            level_of(hlb_notify::Level::Debug),
            hlb_api::AlertLevel::Info
        );
        assert_eq!(level_of(hlb_notify::Level::Info), hlb_api::AlertLevel::Info);
        assert_eq!(
            level_of(hlb_notify::Level::Important),
            hlb_api::AlertLevel::Important
        );
        assert_eq!(
            level_of(hlb_notify::Level::Critical),
            hlb_api::AlertLevel::Critical
        );
    }

    #[test]
    fn an_alert_report_counts_unknowns_separately() {
        // "Zero fired" with ten unknowns is not "all is well".
        let r = AlertReport {
            evaluated: 10,
            triggered: 0,
            unknowns: 10,
            notified: 0,
            held: 0,
            said: Vec::new(),
        };
        assert_ne!(r.unknowns, 0);
        assert_eq!(r.triggered, 0);
    }

    #[test]
    fn an_alert_that_has_never_been_seen_starts_at_zero() {
        let a = alert("x", hlb_api::AlertLevel::Critical, 0);
        assert_eq!(a.since_s, 0);
        assert!(!a.is_muted(1_000));
    }
}
