//! The house on its battery: the UPS read through NUT every few seconds, and when the
//! outage lasts, the apps stopped in waves — those nothing uses first, the databases they
//! wrote to last — then started again in the reverse order once the mains are steady.
//! What to do is `hlb_engine::power::decide`'s; this pass runs it against Swarm.
//!
//! 🔴 Where it stands is in the state, never here: the battery may run out mid-wave, and
//! a daemon coming back must find the waves it was stopping — Swarm says 0 by then, the
//! row says what to give back.

use std::time::Duration;

use hlb_backup_run::restore;
use hlb_engine::power::{self, Decision};
use hlb_notify::Notification;
use hlb_orchestrator::Orchestrator;
use hlb_state::{PowerPhase, PowerStop, State, UpsPolicy};
use hlb_types::Role;

use super::Notifier;

const ACTOR: &str = "controller";

/// What a hold taken for the power says, followed by why. A stored value.
pub const POWER_HOLD: &str = "power: ";

/// How long a power stop holds its services away from reconciliation. An outage ends by
/// [`restore::start`]; the hold only outlives a house that never reads its UPS again.
const HOLD_SECS: i64 = 30 * 24 * 3600;

/// How long a wave started again is given to run before the next one starts anyway.
const START_TIMEOUT: Duration = Duration::from_secs(180);

const SUBJECT: &str = "power";

/// One pass: reads the UPS, records the reading, and stops, keeps down or starts the waves.
pub async fn pass(
    state: &State,
    orchestrator: &dyn Orchestrator,
    notif: &Notifier,
    now: i64,
) -> hlb_state::Result<()> {
    let policy = state.ups_policy().await?;
    let stop = state.power_stop().await?;
    let Some(server) = policy.server.clone() else {
        // The UPS turned off while the apps were down for it: nothing would ever read the
        // mains back, and they would stay down for good.
        if let Some(stop) = stop {
            start_waves(
                state,
                orchestrator,
                notif,
                &stop,
                now,
                "no UPS is read any more",
            )
            .await?;
        }
        return Ok(());
    };
    let reading = power::read(&server, &policy.ups).await;
    if let Err(why) = &reading {
        tracing::warn!("the UPS was not read: {why}");
    }
    let ups = state
        .record_ups(now, reading.as_ref().map_err(String::as_str))
        .await?;
    match power::decide(&policy, &ups, stop.as_ref(), now) {
        Decision::Wait => match stop {
            Some(stop) if stop.phase == PowerPhase::Stopped => {
                keep_down(state, orchestrator, &stop).await
            }
            _ => Ok(()),
        },
        Decision::Stop(reason) => {
            stop_waves(state, orchestrator, notif, &policy, &reason, stop, now).await
        }
        Decision::Start => match stop {
            Some(stop) => {
                start_waves(state, orchestrator, notif, &stop, now, "the mains are back").await
            }
            None => Ok(()),
        },
    }
}

/// Stops every wave, in order. A new stop is written — waves and replicas — BEFORE the
/// first service stops; one already recorded is run again from what it recorded.
///
/// A wave that does not stop whole is said and passed: the next ones still have a
/// chance to stop clean, and waiting on it would spend the battery they need.
async fn stop_waves(
    state: &State,
    o: &dyn Orchestrator,
    notif: &Notifier,
    policy: &UpsPolicy,
    reason: &str,
    stop: Option<PowerStop>,
    now: i64,
) -> hlb_state::Result<()> {
    let waves = match stop {
        Some(s) => {
            if s.phase != PowerPhase::Stopping {
                // On battery again while starting: the waves started so far go down again.
                state.set_power_phase(PowerPhase::Stopping, now).await?;
                notif.tell(&begun(reason, policy)).await;
            }
            s.waves
        }
        None => {
            let waves = power::waves(state, o).await?;
            if !state.begin_power_stop(reason, &waves, now).await? {
                return Ok(());
            }
            state
                .audit(
                    ACTOR,
                    Role::Admin,
                    "power-stop",
                    &policy.ups,
                    "begun",
                    Some(reason),
                )
                .await?;
            // Said before the first wave: ntfy is a service like the others, and stops
            // with the apps nothing uses.
            notif.tell(&begun(reason, policy)).await;
            waves
        }
    };
    let why = format!("{POWER_HOLD}{reason}");
    let mut stuck = Vec::new();
    for wave in &waves {
        if let Err(e) = restore::stop_held(o, state, wave, &why, HOLD_SECS).await {
            tracing::warn!("power: a wave did not stop whole: {e}");
            stuck.push(e);
        }
    }
    state
        .set_power_phase(PowerPhase::Stopped, crate::now())
        .await?;
    let (outcome, detail) = if stuck.is_empty() {
        ("ok", format!("{} waves stopped", waves.len()))
    } else {
        ("partial", stuck.join("; "))
    };
    tracing::info!("power: the apps are stopped ({detail})");
    state
        .audit(
            ACTOR,
            Role::Admin,
            "power-stop",
            &policy.ups,
            outcome,
            Some(&detail),
        )
        .await?;
    Ok(())
}

/// While stopped, puts down again what something else started: a backup's copy or a
/// restore ending starts its services and releases their hold, an update redeploys.
async fn keep_down(state: &State, o: &dyn Orchestrator, stop: &PowerStop) -> hlb_state::Result<()> {
    let Ok(services) = o.list().await else {
        return Ok(());
    };
    let why = format!("{POWER_HOLD}{}", stop.reason);
    for wave in &stop.waves {
        let mut up = Vec::new();
        for (s, replicas) in wave {
            let started = services
                .iter()
                .any(|st| &st.name == s && st.desired_replicas > 0);
            if started || state.held(s).await?.is_none() {
                up.push((s.clone(), *replicas));
            }
        }
        if up.is_empty() {
            continue;
        }
        tracing::warn!(
            "power: {} came back while the house is on battery; stopped again",
            up.iter()
                .map(|(s, _)| s.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
        if let Err(e) = restore::stop_held(o, state, &up, &why, HOLD_SECS).await {
            tracing::warn!("power: {e}");
        }
    }
    Ok(())
}

/// Starts the waves again, the last stopped first, each given its time to run before
/// the next: an app started before its database crash-loops.
///
/// ⚠️ A start begun is finished before the UPS is read again: at worst a few minutes,
/// and the next pass stops everything again if the mains went.
async fn start_waves(
    state: &State,
    o: &dyn Orchestrator,
    notif: &Notifier,
    stop: &PowerStop,
    now: i64,
    why: &str,
) -> hlb_state::Result<()> {
    if stop.phase != PowerPhase::Starting {
        state.set_power_phase(PowerPhase::Starting, now).await?;
    }
    let mut late = Vec::new();
    for wave in stop.waves.iter().rev() {
        if let Err(e) = restore::start(o, state, wave).await {
            late.push(e);
        }
        late.extend(running(o, wave).await);
    }
    state.clear_power_stop().await?;
    let (outcome, detail) = if late.is_empty() {
        ("ok", format!("{why}: every app runs again"))
    } else {
        ("partial", format!("{why}: {}", late.join("; ")))
    };
    tracing::info!("power: {detail}");
    state
        .audit(
            ACTOR,
            Role::Admin,
            "power-start",
            "house",
            outcome,
            Some(&detail),
        )
        .await?;
    let minutes = (crate::now() - stop.started_at).max(0) / 60;
    let title = if late.is_empty() {
        "The apps run again after the power cut"
    } else {
        "Some apps did not start again after the power cut"
    };
    notif
        .tell(&Notification::important(
            SUBJECT,
            title,
            &format!(
                "{detail}. They were stopped {minutes} min ({}).",
                stop.reason
            ),
        ))
        .await;
    Ok(())
}

/// Waits until each service of `wave` runs what it was given; what still does not after
/// [`START_TIMEOUT`] is returned, said, and not waited for.
async fn running(o: &dyn Orchestrator, wave: &[(String, u64)]) -> Vec<String> {
    let deadline = tokio::time::Instant::now() + START_TIMEOUT;
    loop {
        let mut short = Vec::new();
        for (s, _) in wave {
            let up = o
                .status(s)
                .await
                .is_ok_and(|st| st.running_replicas as u64 >= st.desired_replicas);
            if !up {
                short.push(s.clone());
            }
        }
        if short.is_empty() {
            return Vec::new();
        }
        if tokio::time::Instant::now() > deadline {
            return short
                .into_iter()
                .map(|s| format!("{s} does not run after {} s", START_TIMEOUT.as_secs()))
                .collect();
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

fn begun(reason: &str, policy: &UpsPolicy) -> Notification {
    Notification::critical(
        SUBJECT,
        "Power cut: the apps are stopping",
        &format!(
            "{reason}. The apps stop now, those nothing uses first, the databases last, so \
             that nothing is writing when the battery runs out. They start again once the \
             mains have been back {} min. The machines themselves are shut down by NUT's \
             upsmon at low battery, where it is set up to.",
            policy.steady_s / 60
        ),
    )
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use hlb_orchestrator::{ServiceSpec, ServiceStatus};

    use super::*;

    /// Swarm, as far as stopping and starting go: a scale is obeyed at once, and the
    /// services in `lost` no longer answer once scaled — a node gone mid-wave.
    #[derive(Default)]
    struct Fake {
        services: Mutex<Vec<ServiceStatus>>,
        scaled: Mutex<Vec<(String, u64)>>,
        lost: BTreeSet<String>,
    }

    impl Fake {
        fn running(names: &[&str]) -> Self {
            Self {
                services: Mutex::new(
                    names
                        .iter()
                        .map(|n| ServiceStatus {
                            name: n.to_string(),
                            id: "id".into(),
                            desired_replicas: 1,
                            running_replicas: 1,
                            global: false,
                            image: "img".into(),
                            update_state: None,
                        })
                        .collect(),
                ),
                ..Default::default()
            }
        }

        fn scaled(&self) -> Vec<(String, u64)> {
            self.scaled.lock().unwrap().clone()
        }

        fn desired(&self, name: &str) -> u64 {
            self.services
                .lock()
                .unwrap()
                .iter()
                .find(|s| s.name == name)
                .map_or(0, |s| s.desired_replicas)
        }
    }

    #[async_trait]
    impl Orchestrator for Fake {
        async fn ping(&self) -> hlb_orchestrator::Result<String> {
            Ok("fake".into())
        }
        async fn deploy(&self, _: &ServiceSpec) -> hlb_orchestrator::Result<String> {
            Ok("id".into())
        }
        async fn update_image(&self, _: &str, _: &str) -> hlb_orchestrator::Result<()> {
            Ok(())
        }
        async fn scale(&self, n: &str, r: u64) -> hlb_orchestrator::Result<()> {
            self.scaled.lock().unwrap().push((n.into(), r));
            for s in self.services.lock().unwrap().iter_mut() {
                if s.name == n {
                    s.desired_replicas = r;
                    s.running_replicas = r as usize;
                }
            }
            Ok(())
        }
        async fn enable_autolock(&self) -> hlb_orchestrator::Result<String> {
            Ok(String::new())
        }
        async fn autolock_enabled(&self) -> hlb_orchestrator::Result<bool> {
            Ok(false)
        }
        async fn cluster_init(&self, _: &str) -> hlb_orchestrator::Result<String> {
            Ok(String::new())
        }
        async fn join_tokens(&self) -> hlb_orchestrator::Result<hlb_orchestrator::JoinTokens> {
            Err(hlb_orchestrator::Error::NotFound("tokens".into()))
        }
        async fn nodes(&self) -> hlb_orchestrator::Result<Vec<hlb_orchestrator::NodeInfo>> {
            Ok(Vec::new())
        }
        async fn label_node(&self, _: &str, _: &str, _: &str) -> hlb_orchestrator::Result<()> {
            Ok(())
        }
        async fn set_node_availability(&self, _: &str, _: &str) -> hlb_orchestrator::Result<()> {
            Ok(())
        }
        async fn exec_in_service(
            &self,
            _: &str,
            _: &[String],
        ) -> hlb_orchestrator::Result<hlb_orchestrator::ExecOutput> {
            Err(hlb_orchestrator::Error::NotFound("exec".into()))
        }
        async fn ensure_network(&self, _: &str) -> hlb_orchestrator::Result<bool> {
            Ok(false)
        }
        async fn create_volume(
            &self,
            _: &hlb_orchestrator::VolumeSpec,
        ) -> hlb_orchestrator::Result<hlb_orchestrator::VolumeInfo> {
            Err(hlb_orchestrator::Error::NotFound("volume".into()))
        }
        async fn inspect_volume(
            &self,
            n: &str,
        ) -> hlb_orchestrator::Result<hlb_orchestrator::VolumeInfo> {
            Err(hlb_orchestrator::Error::NotFound(n.into()))
        }
        async fn status(&self, n: &str) -> hlb_orchestrator::Result<ServiceStatus> {
            if self.lost.contains(n) {
                return Err(hlb_orchestrator::Error::NotFound(n.into()));
            }
            self.services
                .lock()
                .unwrap()
                .iter()
                .find(|s| s.name == n)
                .cloned()
                .ok_or_else(|| hlb_orchestrator::Error::NotFound(n.into()))
        }
        async fn list(&self) -> hlb_orchestrator::Result<Vec<ServiceStatus>> {
            Ok(self.services.lock().unwrap().clone())
        }
        async fn remove(&self, _: &str) -> hlb_orchestrator::Result<()> {
            Ok(())
        }
        async fn wait_healthy(&self, n: &str, _: u64) -> hlb_orchestrator::Result<ServiceStatus> {
            self.status(n).await
        }
        async fn tasks(
            &self,
            _: Option<&str>,
        ) -> hlb_orchestrator::Result<Vec<hlb_orchestrator::TaskInfo>> {
            Ok(Vec::new())
        }
        async fn logs(
            &self,
            _: &str,
            _: u32,
        ) -> hlb_orchestrator::Result<Vec<hlb_orchestrator::LogLine>> {
            Ok(Vec::new())
        }
    }

    fn wave(names: &[&str]) -> Vec<(String, u64)> {
        names.iter().map(|n| (n.to_string(), 1)).collect()
    }

    /// The apps nothing uses, then Gitea, then the database Gitea writes to.
    fn waves() -> Vec<Vec<(String, u64)>> {
        vec![
            wave(&["ntfy", "vikunja"]),
            wave(&["gitea"]),
            wave(&["postgres"]),
        ]
    }

    async fn setup() -> (Arc<State>, Notifier) {
        let state = Arc::new(State::in_memory().await.expect("state"));
        let notif = Notifier::new(None, state.clone());
        (state, notif)
    }

    fn policy() -> UpsPolicy {
        UpsPolicy {
            server: Some("127.0.0.1:1".into()),
            ups: "house".into(),
            ..UpsPolicy::default()
        }
    }

    /// A stop recorded and interrupted — the daemon restarted mid-wave.
    async fn recorded(state: &State) -> PowerStop {
        assert!(state
            .begin_power_stop("on battery for 5 min", &waves(), 1000)
            .await
            .expect("begin"));
        state.power_stop().await.expect("read").expect("a stop")
    }

    #[tokio::test]
    async fn the_waves_stop_consumers_first_and_stay_held() {
        let (state, notif) = setup().await;
        let o = Fake::running(&["ntfy", "vikunja", "gitea", "postgres"]);
        let stop = recorded(&state).await;
        let reason = stop.reason.clone();
        stop_waves(&state, &o, &notif, &policy(), &reason, Some(stop), 1000)
            .await
            .expect("stop");
        let order: Vec<String> = o.scaled().into_iter().map(|(s, _)| s).collect();
        assert_eq!(order, ["ntfy", "vikunja", "gitea", "postgres"]);
        assert!(o.scaled().iter().all(|(_, r)| *r == 0));
        // Held, or reconciliation starts each again within the minute.
        let why = state.held("postgres").await.expect("held").expect("a hold");
        assert!(why.starts_with(POWER_HOLD), "{why}");
        let stop = state.power_stop().await.expect("read").expect("kept");
        assert_eq!(stop.phase, PowerPhase::Stopped);
        // The replicas to give back are the row's, not Swarm's 0.
        assert_eq!(stop.waves, waves());
    }

    #[tokio::test]
    async fn a_wave_that_fails_does_not_keep_the_next_running() {
        let (state, notif) = setup().await;
        let mut o = Fake::running(&["ntfy", "vikunja", "gitea", "postgres"]);
        o.lost.insert("gitea".into());
        let stop = recorded(&state).await;
        let reason = stop.reason.clone();
        stop_waves(&state, &o, &notif, &policy(), &reason, Some(stop), 1000)
            .await
            .expect("stop");
        assert_eq!(o.desired("postgres"), 0, "the database stops all the same");
        let audit = state.audit_trail(5).await.expect("audit");
        assert!(
            audit
                .iter()
                .any(|a| a.action == "power-stop" && a.outcome == "partial"),
            "the wave that failed is recorded"
        );
    }

    #[tokio::test]
    async fn the_waves_start_again_in_reverse_and_the_stop_ends() {
        let (state, notif) = setup().await;
        let o = Fake::running(&["ntfy", "vikunja", "gitea", "postgres"]);
        let stop = recorded(&state).await;
        let reason = stop.reason.clone();
        stop_waves(&state, &o, &notif, &policy(), &reason, Some(stop), 1000)
            .await
            .expect("stop");
        o.scaled.lock().unwrap().clear();
        let stop = state.power_stop().await.expect("read").expect("a stop");
        start_waves(&state, &o, &notif, &stop, 2000, "the mains are back")
            .await
            .expect("start");
        let order: Vec<String> = o.scaled().into_iter().map(|(s, _)| s).collect();
        assert_eq!(order[..2], ["postgres", "gitea"]);
        assert!(o.scaled().iter().all(|(_, r)| *r == 1));
        assert!(state.power_stop().await.expect("read").is_none());
        assert!(state.held("gitea").await.expect("held").is_none());
    }

    #[tokio::test]
    async fn what_comes_back_while_on_battery_is_stopped_again() {
        let (state, notif) = setup().await;
        let o = Fake::running(&["ntfy", "vikunja", "gitea", "postgres"]);
        let stop = recorded(&state).await;
        let reason = stop.reason.clone();
        stop_waves(&state, &o, &notif, &policy(), &reason, Some(stop), 1000)
            .await
            .expect("stop");
        // A backup's copy ends: it starts its service and releases the hold.
        restore::start(&o, &state, &wave(&["gitea"]))
            .await
            .expect("copy ends");
        assert_eq!(o.desired("gitea"), 1);
        let stop = state.power_stop().await.expect("read").expect("a stop");
        keep_down(&state, &o, &stop).await.expect("keep down");
        assert_eq!(o.desired("gitea"), 0);
        assert!(state.held("gitea").await.expect("held").is_some());
    }

    #[tokio::test]
    async fn turning_the_ups_off_mid_stop_starts_the_apps() {
        let (state, notif) = setup().await;
        let o = Fake::running(&["ntfy", "vikunja", "gitea", "postgres"]);
        let stop = recorded(&state).await;
        let reason = stop.reason.clone();
        stop_waves(&state, &o, &notif, &policy(), &reason, Some(stop), 1000)
            .await
            .expect("stop");
        // No server set: the policy's default.
        pass(&state, &o, &notif, 2000).await.expect("pass");
        assert_eq!(o.desired("postgres"), 1);
        assert!(state.power_stop().await.expect("read").is_none());
    }
}
