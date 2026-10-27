//! The controller's background loops.
//!
//! What turns a collection of manual commands into an autonomous system.
//!
//! **Each loop is a `tick()` separated from its scheduling.** A test calls `tick()`
//! directly and observes the result; it never waits for a real interval. A loop that can
//! only be tested by sleeping is not tested.
//!
//! 🔴 **A loop never panics.** An error is logged and the next pass retries. A
//! controller that dies on a transient error — a registry briefly unreachable, a node
//! rebooting — is worse than one that retries: someone then has to notice it is dead.
//!

use std::sync::Arc;
use std::time::Duration;

use hlb_engine::Reconciler;
use hlb_orchestrator::Orchestrator;
use hlb_state::State;

/// Report of one loop pass. Used by the tests and by supervision.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TickReport {
    pub examined: usize,
    pub acted: usize,
    pub errors: Vec<String>,
}

impl TickReport {
    pub fn is_clean(&self) -> bool {
        self.errors.is_empty()
    }
}

/// Periodic reconciliation: the real state must match the desired state.
pub struct ReconcileLoop<O: Orchestrator> {
    orchestrator: Arc<O>,
    state: Arc<State>,
    /// False by default: observe before correcting.
    apply: bool,
    /// Where the loop publishes what it saw — and what it refused to touch.
    drifts: Option<DriftState>,
    /// When a pass last reconciled, for the heartbeat.
    reconciled: Option<LastReconciled>,
}

/// When reconciliation last completed a pass, in seconds since the epoch. Shared with
/// the heartbeat: a loop that died or hangs stops moving it, and the beat stops.
pub type LastReconciled = Arc<std::sync::atomic::AtomicI64>;

/// Did reconciliation complete a pass recently enough to claim it runs? Two intervals
/// and a minute: one pass may run long, two missed is a loop that stopped.
pub fn reconciled_recently(last: i64, now: i64, interval_s: u64) -> bool {
    let window = 2 * interval_s as i64 + 60;
    last > 0 && now - last <= window
}

impl<O: Orchestrator> ReconcileLoop<O> {
    pub fn new(orchestrator: Arc<O>, state: Arc<State>) -> Self {
        Self {
            orchestrator,
            state,
            apply: false,
            drifts: None,
            reconciled: None,
        }
    }

    /// Record, on every pass that completes, when it did.
    pub fn reports_to(mut self, last: LastReconciled) -> Self {
        self.reconciled = Some(last);
        self
    }

    pub fn apply(mut self, yes: bool) -> Self {
        self.apply = yes;
        self
    }

    /// Publish the observed gaps on every pass.
    pub fn published_in(mut self, drifts: DriftState) -> Self {
        self.drifts = Some(drifts);
        self
    }

    pub async fn tick(&self) -> TickReport {
        let mut r = TickReport::default();

        match Reconciler::new(&*self.orchestrator, &self.state)
            .reconcile(self.apply)
            .await
        {
            Ok(report) => {
                r.examined = report.drifts.len();
                r.acted = report.corrected.len();
                for d in &report.drifts {
                    tracing::info!("gap: {d}");
                }

                if let Some(t) = &self.reconciled {
                    t.store(crate::auth::now(), std::sync::atomic::Ordering::Relaxed);
                }
                if let Some(shared) = &self.drifts {
                    // 🔴 CORRECTED gaps are not republished: they are no longer gaps.
                    // Leaving them would make the system look permanently adrift when
                    // it has just done its job.
                    *shared.write().await = report
                        .drifts
                        .iter()
                        .filter(|d| !report.corrected.contains(d))
                        .map(|d| hlb_api::DriftSummary {
                            target: d.app().to_string(),
                            description: d.to_string(),
                            corrigible: d.is_correctable(),
                            refusal: d.refusal().map(str::to_string),
                        })
                        .collect();
                }
            }
            Err(e) => {
                // We log and hand back: the next pass will retry.
                tracing::warn!("reconciliation impossible this pass: {e}");
                r.errors.push(e.to_string());
            }
        }

        self.sample_uptime().await;
        r
    }

    /// One uptime sample per EXPOSED app, every tick — no new timer, no new
    /// remote call: reuses this loop's own cadence and the app list it already reads
    /// for reconciliation.
    ///
    /// ⚠️ Reuses `portal::service_state`/`maintenance_titles` rather than
    /// reimplementing the running/partial/maintenance mapping: history must agree
    /// with what the live status page showed that day, or the two would silently
    /// drift apart.
    async fn sample_uptime(&self) {
        let Ok(apps) = self.state.installed_apps().await else {
            return;
        };
        let now = crate::auth::now();
        let maintenance = crate::portal::maintenance_titles(&self.state, now).await;

        for (name, status) in apps {
            // Only the EXPOSED apps: they are the only ones the status page shows, and
            // sampling the rest would just be unread rows.
            let Ok(Some(_)) = self.state.app_domain(&name).await else {
                continue;
            };
            let announced = maintenance.iter().any(|t| t.contains(&name));
            let state = crate::portal::service_state(&status, announced);
            if let Err(e) = self.state.record_uptime_sample(&name, state).await {
                tracing::warn!("uptime sample not recorded for {name}: {e}");
            }
        }
    }
}

/// Periodic backup of the apps whose deadline has passed.
pub struct BackupLoop {
    state: Arc<State>,
    schedule: hlb_backup::Schedule,
}

impl BackupLoop {
    pub fn new(state: Arc<State>, schedule: hlb_backup::Schedule) -> Self {
        Self { state, schedule }
    }

    /// The apps that are due, without running anything.
    ///
    /// Separated from execution: deciding *what* to back up is logic we want to be able
    /// to test without a restic repository or Docker.
    pub async fn due_apps(&self) -> Result<Vec<String>, hlb_state::Error> {
        let mut due = Vec::new();
        for (app, status) in self.state.installed_apps().await? {
            // A failed app has a more urgent problem than its backup.
            if status == "failed" {
                continue;
            }
            let Some(age) = self.age(&app).await? else {
                continue;
            };
            if self.schedule.is_due(age) {
                due.push(app);
            }
        }
        Ok(due)
    }

    /// The apps whose lack of a backup deserves an alert.
    pub async fn overdue_apps(&self) -> Result<Vec<String>, hlb_state::Error> {
        let mut late = Vec::new();
        for (app, _) in self.state.installed_apps().await? {
            let Some(age) = self.age(&app).await? else {
                continue;
            };
            if self.schedule.is_overdue(age) {
                late.push(app);
            }
        }
        Ok(late)
    }

    /// `app`'s backup age, the oldest of its kinds deciding (`State::backup_age`);
    /// `None` when it holds nothing to back up.
    ///
    /// 🔴 Read across kinds, the dump every pass records kept an app whose volumes were
    /// no longer backed up "ten minutes old": "no longer backed up" never fired.
    async fn age(&self, app: &str) -> Result<Option<Option<Duration>>, hlb_state::Error> {
        if self.state.backup_kinds(app).await?.is_empty() {
            return Ok(None);
        }
        Ok(Some(
            self.state
                .backup_age(app)
                .await?
                .map(|s| Duration::from_secs(s.max(0) as u64)),
        ))
    }
}

/// Purged of the expired temporary aliases.
///
/// 🔴 **Without this loop, "temporary" is a lie.** Stalwart has no notion of expiry: an
/// account's alias list is a plain list, and what is written there stays. An address
/// given to a merchant "for thirty days" keeps receiving indefinitely if nobody comes to
/// remove it.
///
/// ## 🔴 A failed purge must SHOW
///
/// This is the property that sets this loop apart from the others. A reconciliation that
/// fails leaves the cluster as it is — annoying but honest. A purge that fails leaves
/// doors **open that their owner believes closed**, and the silence sustains the belief.
/// So the report surfaces the number of addresses still open, and not only the number of
/// errors.
pub struct AliasPurgeLoop {
    state: Arc<State>,
    mail: Option<Arc<hlb_mail::Stalwart>>,
    default_domain: String,
}

/// What one purge pass produced.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PurgeReport {
    /// Expired aliases found still active.
    pub due: usize,
    /// Actually removed from the server.
    pub retires: usize,
    pub errors: Vec<String>,
}

impl PurgeReport {
    /// How many addresses stay open while believed closed.
    ///
    /// 🔴 This is THE number to watch — not the error count. An error-free purge that
    /// removed nothing leaves as many doors open as a purge that failed loudly.
    ///
    pub fn still_open(&self) -> usize {
        self.due.saturating_sub(self.retires)
    }

    pub fn is_clean(&self) -> bool {
        self.still_open() == 0
    }
}

impl AliasPurgeLoop {
    pub fn new(
        state: Arc<State>,
        mail: Option<Arc<hlb_mail::Stalwart>>,
        default_domain: impl Into<String>,
    ) -> Self {
        Self {
            state,
            mail,
            default_domain: default_domain.into(),
        }
    }

    pub async fn tick(&self) -> PurgeReport {
        let mut r = PurgeReport::default();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        let due = match self.state.aliases_to_purge(now).await {
            Ok(v) => v,
            Err(e) => {
                r.errors.push(e.to_string());
                return r;
            }
        };
        r.due = due.len();

        let Some(mail) = &self.mail else {
            if r.due > 0 {
                // 🔴 We mark NOTHING as purged. Doing so without removing the alias
                // would be the worst of both worlds: the address would still receive,
                // and nothing would say so any more.
                tracing::error!(
                    open = r.due,
                    "purge impossible (Stalwart not configured): these expired addresses \
                     STILL RECEIVE, and their owner believes them closed"
                );
                r.errors.push("Stalwart not configured".into());
            }
            return r;
        };

        for (user, mailbox, local) in due {
            let dom = self
                .state
                .mailboxes(&user)
                .await
                .ok()
                .and_then(|v| {
                    v.into_iter()
                        .find(|(l, ..)| l == &mailbox)
                        .map(|(_, d, _)| d)
                })
                .unwrap_or_else(|| self.default_domain.clone());

            // The state is only marked AFTER the actual removal.
            match mail.remove_alias(&format!("{mailbox}@{dom}"), &local).await {
                Ok(_) => match self.state.deactivate_alias(&user, &local).await {
                    Ok(()) => {
                        r.retires += 1;
                        tracing::info!(user, alias = %local, "expired alias removed");
                    }
                    Err(e) => r.errors.push(format!("{local} : {e}")),
                },
                // A failure does not block the following ones: each door closed is a
                // gain, even if the next one resists.
                Err(e) => r.errors.push(format!("{local} : {e}")),
            }
        }

        if !r.is_clean() {
            tracing::error!(
                open = r.still_open(),
                "🔴 expired addresses STILL active after the purge"
            );
        }
        r
    }
}

/// Prunes uptime samples past the retained window — mirrors
/// `AliasPurgeLoop`'s shape, the one working precedent for a scheduled
/// `DELETE FROM ... WHERE <ts> < ?` loop. Run once a day: at the sampling cadence,
/// 90 days of history is small enough that pruning does not need to be frequent.
pub struct UptimeRetentionLoop {
    state: Arc<State>,
    days: i64,
}

impl UptimeRetentionLoop {
    pub fn new(state: Arc<State>, days: i64) -> Self {
        Self { state, days }
    }

    /// Returns how many rows were removed, or the error — never panics: same "a loop
    /// never panics" rule as every other one here.
    pub async fn tick(&self) -> Result<u64, String> {
        self.state
            .prune_uptime_samples(self.days)
            .await
            .map_err(|e| e.to_string())
    }
}

/// The heartbeat: "who watches the watchman?".
///
/// The controller writes a timestamp **outside the cluster**. A trivial `cron` on the
/// NAS notices it has not moved and alerts — see `hlb metrics deadman`, which produces
/// that script. It is the only thing that will warn you if the controller dies, since it
/// is the controller that sends every other alert.
///
/// ## 🔴 The beat is CONDITIONAL, never periodic
///
/// The first version beat on every timer tick, checking nothing. That is this
/// mechanism's trap: such a beat proves a thread is still alive, and **nothing else**.
/// The controller can have its reconciliation loop stuck, its Docker unreachable and its
/// database unreadable, and keep beating imperturbably.
///
/// The watchdog would then stay green over an unusable system — which is worse than no
/// deadman at all, because you trust it. So the beat goes through
/// [`hlb_metrics::Beat::should_emit`], and **stays silent** when something is wrong:
/// silence is the signal.
pub struct Heartbeat {
    path: std::path::PathBuf,
}

impl Heartbeat {
    pub fn new(path: impl Into<std::path::PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Beats if — and only if — the system is in a state to claim it.
    ///
    /// Returns `true` if the beat went out.
    pub async fn beat_if_healthy(&self, health: &hlb_metrics::Health) -> std::io::Result<bool> {
        match hlb_metrics::Beat::should_emit(health) {
            hlb_metrics::Emission::Emit => {
                self.beat().await?;
                Ok(true)
            }
            hlb_metrics::Emission::Withhold { failures } => {
                // 🔴 We stay SILENT, and say why in the logs. Beating here would leave
                // the watchdog green over a broken system.
                tracing::error!(
                    failures = failures.join(", "),
                    "heartbeat WITHHELD: the watchdog will alert, that is intended"
                );
                Ok(false)
            }
        }
    }

    /// Writes the beat, unconditionally.
    ///
    /// ⚠️ Reserved for the tests and for [`Self::beat_if_healthy`]. Calling it directly from
    /// a loop recreates exactly the defect described at the top of this type.
    pub async fn beat(&self) -> std::io::Result<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // Atomic write: a reader must never see a half-written file and wrongly conclude
        // the controller is dead.
        let tmp = self.path.with_extension("tmp");
        tokio::fs::write(&tmp, format!("{now}\n")).await?;
        tokio::fs::rename(&tmp, &self.path).await
    }
}

/// Runs a periodic task until shutdown.
///
/// The first pass happens immediately: at startup you want to know the cluster's state
/// right away, not in a quarter of an hour.
/// Periodic evaluation of the alert rules.
///
/// ## What was missing
///
/// `hlb_metrics::default_rules()` existed, and was evaluated **only by the CLI** —
/// so only when someone typed `hlb metrics check`. There was no continuous monitoring:
/// the rules described what needed watching without anyone watching it.
///
///
/// ## 🔴 A muted alert is still an alert
///
/// Muting stops the **notification**, not the **display**. Making a muted alert vanish
/// from the state would give a green dashboard for a known, unresolved problem — the
/// same family of mistake as `Freshness`.
pub struct AlertLoop {
    source: Arc<dyn Measure>,
    notif: crate::notify::Notifier,
    /// Where the mutes are: read on every pass, so a mute set from the interface or
    /// the CLI applies at the next evaluation, and one set before a restart still does.
    state: Arc<hlb_state::State>,
    /// The current state of the alerts, shared with the API.
    ///
    /// Same pattern as `LastPoll`: the loop writes, the API reads. An `RwLock` because
    /// several screens can read while a single pass writes.
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

#[async_trait::async_trait]
impl Measure for crate::promql::Metrics {
    async fn samples(&self, query: &str) -> Result<Vec<hlb_metrics::Sample>, String> {
        // Through the relay: its allowlist applies to our own rules too, which
        // guarantees no shipped rule queries anything other than the expected metrics.
        self.instant_samples(query).await
    }
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
    pub fn new(
        metrics: Arc<crate::promql::Metrics>,
        notif: crate::notify::Notifier,
        state: Arc<hlb_state::State>,
    ) -> Self {
        Self::measuring(metrics, notif, state)
    }

    /// The loop over any source of series.
    pub fn measuring(
        source: Arc<dyn Measure>,
        notif: crate::notify::Notifier,
        state: Arc<hlb_state::State>,
    ) -> Self {
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
                                crate::notify::Said::Held => report.held += 1,
                                crate::notify::Said::Sent | crate::notify::Said::Logged => {
                                    report.notified += 1
                                }
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

/// Tells someone about every image update that ended — an applied one too: an updater
/// that stays silent when it succeeds cannot be told from one that does nothing.
///
/// A notice ntfy refused stays unsent and is tried at the next pass; one quiet hours
/// held is kept in the state for the morning and counts as said, like one logged with
/// no ntfy at all.
pub async fn notify_update_runs(state: &State, notif: &crate::notify::Notifier, now: i64) {
    let runs = match state.unnotified_update_runs().await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("update outcomes unreadable: {e}");
            return;
        }
    };
    for run in runs {
        let n = update_notice(&run);
        if let Err(e) = notif.say(&n, now).await {
            tracing::warn!(app = %run.app, "update notice kept for the next pass: {e}");
            return;
        }
        if let Err(e) = state.mark_update_run_notified(run.id, now).await {
            tracing::warn!(app = %run.app, "update notice sent, not marked: {e}");
        }
    }
}

/// What an update's outcome says, and how loudly.
pub fn update_notice(run: &hlb_state::UpdateRun) -> hlb_notify::Notification {
    use hlb_state::UpdateRunOutcome as O;
    let subject = format!("update:{}", run.app);
    let detail = if run.detail.is_empty() {
        String::new()
    } else {
        format!(" — {}", run.detail)
    };
    match run.outcome {
        O::Applied => hlb_notify::Notification::important(
            &subject,
            &format!("{} updated", run.app),
            &format!("{} → {}", run.from_image, run.to_image),
        ),
        O::RolledBack => hlb_notify::Notification::important(
            &subject,
            &format!("{}'s update was rolled back", run.app),
            &format!(
                "it still runs {}; {} did not start{detail}",
                run.from_image, run.to_image
            ),
        ),
        // Neither image is serving: the old one would not start on what the new one
        // had already migrated.
        O::Paused => hlb_notify::Notification::critical(
            &subject,
            &format!("{}'s update stopped half-way", run.app),
            &format!(
                "{} → {}: Swarm paused it and nothing may be serving{detail}",
                run.from_image, run.to_image
            ),
        ),
        O::Inconclusive => hlb_notify::Notification::important(
            &subject,
            &format!("{}'s update did not conclude", run.app),
            &format!(
                "{} → {}: no outcome within the deadline — hlb ps says where it stands{detail}",
                run.from_image, run.to_image
            ),
        ),
    }
}

/// The alert state, shared between the loop that writes and the API that reads.
pub type AlertsState = Arc<tokio::sync::RwLock<Vec<hlb_api::ActiveAlert>>>;

/// The gaps of the last reconciliation pass, deliberate refusals included.
///
/// Same pattern as the alerts: the loop writes, the API reads. Without this sharing, the
/// system's non-actions never left the logs — that is, nowhere.
pub type DriftState = Arc<tokio::sync::RwLock<Vec<hlb_api::DriftSummary>>>;

/// Default interval between two evaluations.
pub const DEFAULT_INTERVAL_S: i64 = 60;

fn level_of(l: hlb_notify::Level) -> hlb_api::AlertLevel {
    match l {
        hlb_notify::Level::Debug | hlb_notify::Level::Info => hlb_api::AlertLevel::Info,
        hlb_notify::Level::Important => hlb_api::AlertLevel::Important,
        hlb_notify::Level::Critical => hlb_api::AlertLevel::Critical,
    }
}

pub async fn every<F, Fut>(
    interval: Duration,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
    mut f: F,
) where
    F: FnMut() -> Fut + Send,
    Fut: std::future::Future<Output = ()> + Send,
{
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = ticker.tick() => f().await,
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    return;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {

    fn run(outcome: hlb_state::UpdateRunOutcome) -> hlb_state::UpdateRun {
        hlb_state::UpdateRun {
            id: 0,
            app: "gitea".into(),
            ran_at: 0,
            from_image: "gitea/gitea:1.24@sha256:a".into(),
            to_image: "gitea/gitea:1.24.7@sha256:b".into(),
            outcome,
            detail: String::new(),
        }
    }

    #[test]
    fn an_applied_update_is_pushed_like_a_failed_one() {
        use hlb_state::UpdateRunOutcome as O;
        let applied = update_notice(&run(O::Applied));
        assert!(
            applied.level.is_pushed(),
            "a success said nowhere is silence"
        );
        assert!(applied.body.contains("1.24.7"), "{}", applied.body);
        assert!(update_notice(&run(O::RolledBack)).level.is_pushed());
        assert_eq!(
            update_notice(&run(O::Paused)).level,
            hlb_notify::Level::Critical,
            "nothing may be serving"
        );
    }

    #[tokio::test]
    async fn every_update_outcome_is_said_once() {
        let s = State::in_memory().await.expect("state");
        s.record_update_run(&run(hlb_state::UpdateRunOutcome::Applied))
            .await
            .expect("recorded");
        let s = Arc::new(s);
        notify_update_runs(&s, &crate::notify::Notifier::new(None, s.clone()), 10).await;
        assert!(s.unnotified_update_runs().await.expect("read").is_empty());
    }

    #[tokio::test]
    async fn an_update_notice_ntfy_refused_is_not_marked_said() {
        let s = Arc::new(State::in_memory().await.expect("state"));
        s.record_update_run(&run(hlb_state::UpdateRunOutcome::Applied))
            .await
            .expect("recorded");
        // Nothing listens there; noon UTC, no quiet hours.
        let client = Arc::new(hlb_notify::NtfyClient::new("http://127.0.0.1:9", "hlb"));
        let notif = crate::notify::Notifier::new(Some(client), s.clone());
        notify_update_runs(&s, &notif, 1_782_907_200).await;
        assert_eq!(s.unnotified_update_runs().await.expect("read").len(), 1);
    }

    #[tokio::test]
    async fn an_update_applied_at_night_is_kept_for_the_morning() {
        let s = Arc::new(State::in_memory().await.expect("state"));
        s.record_update_run(&run(hlb_state::UpdateRunOutcome::Applied))
            .await
            .expect("recorded");
        let client = Arc::new(hlb_notify::NtfyClient::new("http://127.0.0.1:9", "hlb"));
        let notif = crate::notify::Notifier::new(Some(client), s.clone());
        // 03:00 UTC: held, not sent — kept, so marking it said loses nothing.
        notify_update_runs(&s, &notif, 1_782_874_800).await;
        assert!(s.unnotified_update_runs().await.expect("read").is_empty());
        assert_eq!(s.held_notifications().await.expect("held").len(), 1);
    }

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
            Arc::new(crate::promql::Metrics::new("http://127.0.0.1:1")),
            crate::notify::Notifier::new(None, state.clone()),
            state,
        )
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
        let b = AlertLoop::measuring(
            numbers.clone(),
            crate::notify::Notifier::new(notif, state.clone()),
            state,
        );
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
        let ntfy = crate::notify::fake_ntfy().await;
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

    fn manifest(name: &str) -> hlb_types::Manifest {
        let y = format!(
            "apiVersion: hlb/v1\nkind: App\nmetadata: {{ name: {name} }}\n\
             spec:\n  image: {{ repo: a/b, tag: \"1\" }}\n"
        );
        serde_yaml_ng::from_str(&y).expect("test manifest")
    }

    async fn state_with(apps: &[(&str, &str)]) -> Arc<State> {
        let s = State::in_memory().await.expect("base");
        for (name, status) in apps {
            s.upsert_app(name, &manifest(name), None)
                .await
                .expect("upsert");
            s.set_app_status(name, status).await.expect("status");
            s.add_volume(name, &format!("{name}-data"), "/data", true, false)
                .await
                .expect("volume");
        }
        Arc::new(s)
    }

    #[tokio::test]
    async fn an_app_whose_volumes_stopped_is_overdue_whatever_its_dumps() {
        // 🔴 Found by review: the overdue alert read the age of ANY kind, and the dump
        // every pass records kept "no longer backed up" from ever firing.
        let s = state_with(&[("gitea", "running")]).await;
        s.record_backup_to("gitea", "volume", "nas", Some("v1"), None)
            .await
            .expect("volume");
        s.backdate_backup("gitea", "nas", 3 * 86_400)
            .await
            .expect("three days ago");
        s.record_backup_to("gitea", "sql-dump", "nas", Some("d1"), None)
            .await
            .expect("dump");
        let l = BackupLoop::new(s, hlb_backup::Schedule::default());
        assert_eq!(l.overdue_apps().await.expect("late"), vec!["gitea"]);
    }

    #[tokio::test]
    async fn an_app_holding_nothing_is_never_due_nor_overdue() {
        let s = State::in_memory().await.expect("base");
        s.upsert_app("valkey", &manifest("valkey"), None)
            .await
            .expect("upsert");
        let l = BackupLoop::new(Arc::new(s), hlb_backup::Schedule::default());
        assert!(l.due_apps().await.expect("dues").is_empty());
        assert!(l.overdue_apps().await.expect("late").is_empty());
    }

    #[tokio::test]
    async fn a_never_backed_up_app_is_due() {
        let s = state_with(&[("gitea", "running")]).await;
        let l = BackupLoop::new(s, hlb_backup::Schedule::default());
        assert_eq!(l.due_apps().await.expect("dues"), vec!["gitea"]);
    }

    #[tokio::test]
    async fn a_failed_app_is_skipped() {
        // It has a more urgent problem than its backup.
        let s = state_with(&[("gitea", "failed")]).await;
        let l = BackupLoop::new(s, hlb_backup::Schedule::default());
        assert!(l.due_apps().await.expect("dues").is_empty());
    }

    #[tokio::test]
    async fn a_recently_backed_up_app_is_not_due() {
        let s = state_with(&[("gitea", "running")]).await;
        s.record_backup("gitea", "volume", Some("abc"), None)
            .await
            .expect("backup");

        let l = BackupLoop::new(s, hlb_backup::Schedule::default());
        assert!(l.due_apps().await.expect("dues").is_empty());
    }

    #[tokio::test]
    async fn a_failed_backup_leaves_the_app_due() {
        // 🔴 A failure does not push the deadline back.
        let s = state_with(&[("gitea", "running")]).await;
        s.record_backup("gitea", "volume", None, Some("disque plein"))
            .await
            .expect("failure");

        let l = BackupLoop::new(s, hlb_backup::Schedule::default());
        assert_eq!(l.due_apps().await.expect("dues"), vec!["gitea"]);
    }

    #[tokio::test]
    async fn never_backed_up_is_due_but_not_overdue() {
        let s = state_with(&[("gitea", "running")]).await;
        let l = BackupLoop::new(s, hlb_backup::Schedule::default());
        assert_eq!(l.due_apps().await.expect("dues"), vec!["gitea"]);
        assert!(
            l.overdue_apps().await.expect("retards").is_empty(),
            "\"never done\" calls for an action, not a drift alert"
        );
    }

    #[tokio::test]
    async fn the_heartbeat_is_written_atomically() {
        let dir = tempfile::tempdir().expect("folder temporary");
        let p = dir.path().join("heartbeat");
        let h = Heartbeat::new(&p);

        h.beat().await.expect("beat");
        let content = tokio::fs::read_to_string(&p).await.expect("read");
        assert!(
            content.trim().parse::<u64>().is_ok(),
            "horodatage : {content:?}"
        );

        // No temporary file must remain.
        assert!(!p.with_extension("tmp").exists());

        // A second beat overwrites cleanly.
        h.beat().await.expect("second beat");
        assert!(tokio::fs::read_to_string(&p)
            .await
            .expect("read")
            .trim()
            .parse::<u64>()
            .is_ok());
    }

    #[tokio::test]
    async fn a_purge_without_stalwart_marks_nothing() {
        // 🔴 Marking an alias "purged" without having removed it from the server would
        // be the worst of both worlds: the address would still receive, AND nothing
        // would say so. The silence would sustain the belief that the door is closed.
        let s = Arc::new(State::in_memory().await.expect("state"));
        s.upsert_user("lena", "standard", None)
            .await
            .expect("account");
        s.add_mailbox("lena", "lena", "example.fr", true)
            .await
            .expect("mailbox");
        s.add_alias("lena", "lena", "old", Some(1), None, None)
            .await
            .expect("expired alias");

        let l = AliasPurgeLoop::new(s.clone(), None, "example.fr");
        let r = l.tick().await;

        assert_eq!(r.due, 1);
        assert_eq!(r.retires, 0);
        assert_eq!(r.still_open(), 1, "the address still receives");
        assert!(!r.is_clean());

        // And the state was NOT touched: the alias stays reported as active.
        let remaining = s.aliases_to_purge(9_999_999_999).await.expect("relecture");
        assert_eq!(remaining.len(), 1, "nothing was marked purged");
    }

    #[tokio::test]
    async fn a_clean_purge_has_nothing_left_open() {
        // No expired alias: nothing to do, and the report must say so without
        // fabricate an alert.
        let s = Arc::new(State::in_memory().await.expect("state"));
        s.upsert_user("lena", "standard", None)
            .await
            .expect("account");
        s.add_mailbox("lena", "lena", "example.fr", true)
            .await
            .expect("mailbox");
        // Permanent: never due.
        s.add_alias("lena", "lena", "contact", None, None, None)
            .await
            .expect("alias permanent");

        let r = AliasPurgeLoop::new(s, None, "example.fr").tick().await;
        assert_eq!(r.due, 0);
        assert!(r.is_clean());
        assert!(
            r.errors.is_empty(),
            "no alert for a permanent one: {:?}",
            r.errors
        );
    }

    #[tokio::test]
    async fn the_retention_loop_does_not_prune_what_is_still_fresh() {
        // 🔴 The pruning boundary itself (what counts as "old enough") is
        // `State::prune_uptime_samples`'s own, already tested with a backdated row —
        // this checks the LOOP's wiring: it must not touch a sample recorded moments
        // ago, and it must report how many rows it actually removed.
        let s = Arc::new(State::in_memory().await.expect("state"));
        s.record_uptime_sample("gitea", hlb_api::ServiceState::Operational)
            .await
            .expect("sample");

        let removed = UptimeRetentionLoop::new(s.clone(), 90)
            .tick()
            .await
            .expect("prune");
        assert_eq!(removed, 0);

        let history = s.uptime_history("gitea", 1).await.expect("history");
        assert_eq!(history[0].1, Some(hlb_api::ServiceState::Operational));
    }

    #[test]
    fn what_matters_is_what_stays_open_not_the_error_count() {
        // 🔴 An error-free purge that removed nothing leaves as many doors open as a
        // purge that failed loudly. That is the first number
        // to watch.
        let silent = PurgeReport {
            due: 5,
            retires: 0,
            errors: vec![],
        };
        assert_eq!(silent.still_open(), 5);
        assert!(!silent.is_clean(), "no error, and yet five doors left open");

        let noisy = PurgeReport {
            due: 5,
            retires: 5,
            errors: vec!["a warning".into()],
        };
        assert!(
            noisy.is_clean(),
            "everything is closed again: the noise changes nothing"
        );
    }

    #[tokio::test]
    async fn a_sick_controller_does_not_beat() {
        // 🔴 The defect this test guards really existed: the beat went out on every
        // timer tick, checking nothing. Such a beat only proves a thread survived — the
        // controller could have an unreadable database and a dead Docker, and leave the
        // watchdog green over an unusable system. Which is WORSE than no deadman, since
        // you trust it.
        let dir = tempfile::tempdir().expect("folder temporary");
        let p = dir.path().join("beat");
        let h = Heartbeat::new(&p);

        let sick = hlb_metrics::Health {
            readable_state: true,
            orchestrator_reachable: false,
            recent_reconciliation: true,
        };
        assert!(
            !h.beat_if_healthy(&sick).await.expect("decision"),
            "must not beat"
        );
        assert!(
            !p.exists(),
            "no file must be written: the silence IS the signal"
        );

        let healthy = hlb_metrics::Health {
            readable_state: true,
            orchestrator_reachable: true,
            recent_reconciliation: true,
        };
        assert!(
            h.beat_if_healthy(&healthy).await.expect("decision"),
            "must beat"
        );
        assert!(p.exists(), "a healthy system does write its beat");
    }

    #[tokio::test]
    async fn a_stale_beat_is_never_refreshed_by_a_sick_controller() {
        // A nastier case: the controller beat while it was fine, then went down. The
        // file already exists — it must NOT be refreshed any more, or the watchdog will
        // never see the silence.
        let dir = tempfile::tempdir().expect("folder temporary");
        let p = dir.path().join("beat");
        let h = Heartbeat::new(&p);

        h.beat().await.expect("beat initial");
        let before = tokio::fs::read_to_string(&p).await.expect("read");

        // Time passes, and the system goes down.
        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
        let sick = hlb_metrics::Health {
            readable_state: false,
            orchestrator_reachable: true,
            recent_reconciliation: true,
        };
        assert!(!h.beat_if_healthy(&sick).await.expect("decision"));

        let after = tokio::fs::read_to_string(&p).await.expect("read");
        assert_eq!(before, after, "the timestamp must AGE, not refresh");
    }

    #[test]
    fn a_reconciliation_loop_that_stopped_is_not_recent() {
        assert!(reconciled_recently(1_000, 1_060, 60));
        assert!(reconciled_recently(1_000, 1_180, 60), "one long pass");
        assert!(!reconciled_recently(1_000, 1_181, 60), "two passes missed");
        assert!(!reconciled_recently(0, 10, 60), "never reconciled");
    }

    #[tokio::test]
    async fn a_pass_reports_when_it_reconciled_and_publishes_only_what_is_left() {
        let state = state_with(&[("demo", "running")]).await;
        let orch = Arc::new(crate::api::tests::FakeOrch::running(vec![
            hlb_orchestrator::ServiceStatus {
                name: "demo".into(),
                id: "id".into(),
                image: "a/b:1".into(),
                desired_replicas: 0,
                running_replicas: 0,
                update_state: None,
            },
        ]));
        let drifts: DriftState = Default::default();
        let last: LastReconciled = Arc::new(std::sync::atomic::AtomicI64::new(0));
        let rl = ReconcileLoop::new(orch, state)
            .apply(true)
            .published_in(drifts.clone())
            .reports_to(last.clone());

        let r = rl.tick().await;
        assert_eq!((r.examined, r.acted), (1, 1), "{r:?}");
        assert!(
            drifts.read().await.is_empty(),
            "a corrected gap was published as a gap: {:?}",
            drifts.read().await
        );
        assert!(
            last.load(std::sync::atomic::Ordering::Relaxed) > 0,
            "the heartbeat cannot know this pass ran"
        );
    }

    #[tokio::test]
    async fn a_tick_report_without_errors_is_clean() {
        assert!(TickReport::default().is_clean());
        let r = TickReport {
            errors: vec!["boum".into()],
            ..Default::default()
        };
        assert!(!r.is_clean());
    }

    #[tokio::test]
    async fn the_periodic_runner_stops_on_shutdown() {
        let (tx, rx) = tokio::sync::watch::channel(false);
        let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let c = counter.clone();

        let h = tokio::spawn(every(Duration::from_millis(10), rx, move || {
            let c = c.clone();
            async move {
                c.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        }));

        tokio::time::sleep(Duration::from_millis(60)).await;
        tx.send(true).expect("stop signal");
        h.await.expect("the loop must terminate");

        let n = counter.load(std::sync::atomic::Ordering::SeqCst);
        assert!(n >= 2, "the loop ran {n} times");
    }
}
