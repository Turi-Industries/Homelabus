//! The daemon's timers, and the loops that only read the state or a file.
//!
//! **Each loop is a `tick()` separated from its scheduling.** A test calls `tick()`
//! directly and observes the result; it never waits for a real interval. A loop that can
//! only be tested by sleeping is not tested.
//!
//! 🔴 **A loop never panics.** An error is logged and the next pass retries. A
//! daemon that dies on a transient error — a registry briefly unreachable, a node
//! rebooting — is worse than one that retries: someone then has to notice it is dead.

use std::sync::Arc;
use std::time::Duration;

use hlb_state::State;

/// One uptime sample per EXPOSED app, every tick — no new timer, no new
/// remote call: runs after each reconciliation pass, at its cadence.
///
/// ⚠️ Judged by `ServiceState::of` and `State::maintenance_titles`, as the live status
/// page is: history must agree with what the page showed that day.
pub async fn sample_uptime(state: &State) {
    let Ok(apps) = state.installed_apps().await else {
        return;
    };
    let maintenance = state.maintenance_titles(crate::now()).await;

    for (name, status) in apps {
        // Only the EXPOSED apps: they are the only ones the status page shows, and
        // sampling the rest would just be unread rows.
        let Ok(Some(_)) = state.app_domain(&name).await else {
            continue;
        };
        let announced = maintenance.iter().any(|t| t.contains(&name));
        let service = hlb_api::ServiceState::of(&status, announced);
        if let Err(e) = state.record_uptime_sample(&name, service).await {
            tracing::warn!("uptime sample not recorded for {name}: {e}");
        }
    }
}

/// Did reconciliation complete a pass recently enough to claim it runs? Two intervals
/// and a minute: one pass may run long, two missed is a loop that stopped.
pub fn reconciled_recently(last: i64, now: i64, interval_s: u64) -> bool {
    let window = 2 * interval_s as i64 + 60;
    last > 0 && now - last <= window
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

/// Which apps' backups to read back now. Looked at often and one at a time: read together,
/// a house's whole backup would come back through one disk on one night.
pub struct VerifyLoop {
    state: Arc<State>,
}

impl VerifyLoop {
    /// A week between readings: read on a week's notice, a broken backup costs at most
    /// a week's worth of believing in it.
    const EVERY_S: i64 = 7 * 86_400;
    /// A failure is read again a day later, not at the next tick: every hour, a refusal
    /// about disk space would be an hourly notification.
    const AFTER_FAILURE_S: i64 = 86_400;

    pub fn new(state: Arc<State>) -> Self {
        Self { state }
    }

    /// The apps due, longest unread first, a never-read one before any other. Reproducible:
    /// names break ties. Separate from reading, which takes a repository and Docker.
    pub async fn due_apps(&self) -> Result<Vec<String>, hlb_state::Error> {
        let mut due = Vec::new();
        for (app, status) in self.state.installed_apps().await? {
            // As the backups: a failed app has a more urgent problem.
            if status == "failed" || self.state.backup_kinds(&app).await?.is_empty() {
                continue;
            }
            let age = self
                .state
                .seconds_since_last_verification_attempt(&app)
                .await?;
            let failed = self.state.last_verification_failed(&app).await?;
            if Self::is_due(age, failed) {
                due.push((age, app));
            }
        }
        Ok(Self::longest_unread_first(due))
    }

    fn is_due(age: Option<i64>, failed: bool) -> bool {
        let wait = if failed {
            Self::AFTER_FAILURE_S
        } else {
            Self::EVERY_S
        };
        age.is_none_or(|a| a >= wait)
    }

    fn longest_unread_first(mut apps: Vec<(Option<i64>, String)>) -> Vec<String> {
        apps.sort_by_key(|(age, app)| (std::cmp::Reverse(age.unwrap_or(i64::MAX)), app.clone()));
        apps.into_iter().map(|(_, app)| app).collect()
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

/// [`every`], its first pass only once `delay` has gone by: for a task that costs something
/// each time, which a daemon restarting in a loop would otherwise run at each start.
pub async fn every_after<F, Fut>(
    delay: Duration,
    interval: Duration,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
    mut f: F,
) where
    F: FnMut() -> Fut + Send,
    Fut: std::future::Future<Output = ()> + Send,
{
    let mut ticker = tokio::time::interval_at(tokio::time::Instant::now() + delay, interval);
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

/// Runs a periodic task until shutdown.
///
/// The first pass happens immediately: at startup you want to know the cluster's state
/// right away, not in a quarter of an hour.
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
    use super::*;

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
    async fn an_app_never_read_back_is_due_and_one_just_read_is_not() {
        let s = state_with(&[("gitea", "running"), ("vikunja", "running")]).await;
        let l = VerifyLoop::new(s.clone());
        assert_eq!(l.due_apps().await.expect("due"), ["gitea", "vikunja"]);

        s.record_verification("gitea", "abc", true, None)
            .await
            .expect("record");
        assert_eq!(l.due_apps().await.expect("due"), ["vikunja"]);
    }

    #[tokio::test]
    async fn a_failed_reading_is_not_read_again_at_the_next_tick() {
        let s = state_with(&[("gitea", "running")]).await;
        s.record_verification("gitea", "abc", false, Some("does not fit"))
            .await
            .expect("record");
        assert!(VerifyLoop::new(s).due_apps().await.expect("due").is_empty());
    }

    #[test]
    fn a_failed_reading_waits_a_day_and_a_good_one_a_week() {
        let day = 86_400;
        assert!(VerifyLoop::is_due(None, false));
        assert!(!VerifyLoop::is_due(Some(day - 1), true));
        assert!(VerifyLoop::is_due(Some(day), true));
        assert!(!VerifyLoop::is_due(Some(7 * day - 1), false));
        assert!(VerifyLoop::is_due(Some(7 * day), false));
    }

    #[test]
    fn the_never_read_come_first_then_the_longest_unread_and_names_break_ties() {
        let order = VerifyLoop::longest_unread_first(vec![
            (Some(10), "young".to_string()),
            (Some(99), "old".to_string()),
            (None, "zulu".to_string()),
            (None, "alpha".to_string()),
            (Some(99), "also-old".to_string()),
        ]);
        assert_eq!(order, ["alpha", "zulu", "also-old", "old", "young"]);
    }

    #[tokio::test]
    async fn an_app_holding_only_a_database_is_due() {
        let y = "apiVersion: hlb/v1\nkind: App\nmetadata: { name: notes }\n\
                 spec:\n  image: { repo: a/b, tag: \"1\" }\n  requires:\n    \
                 - { kind: database, engine: postgres }\n";
        let m: hlb_types::Manifest = serde_yaml_ng::from_str(y).expect("test manifest");
        let s = Arc::new(State::in_memory().await.expect("state"));
        s.upsert_app("notes", &m, None).await.expect("upsert");
        s.set_app_status("notes", "running").await.expect("status");
        assert_eq!(VerifyLoop::new(s).due_apps().await.expect("due"), ["notes"]);
    }

    #[tokio::test]
    async fn a_failed_app_and_one_holding_no_volume_are_never_due() {
        let s = state_with(&[("gitea", "failed")]).await;
        s.upsert_app("nothing", &manifest("nothing"), None)
            .await
            .expect("upsert");
        s.set_app_status("nothing", "running")
            .await
            .expect("status");
        assert!(VerifyLoop::new(s).due_apps().await.expect("due").is_empty());
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
