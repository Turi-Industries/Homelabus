//! The nodes rebooted into the kernel they installed, inside the house's window, one at a
//! time — the steps and their reasons are `hlb_updater::reboot`'s; this pass runs them
//! against Swarm and keeps where it stands in the state.
//!
//! 🔴 Where it stands is never kept in memory: the node rebooted may be the one this
//! daemon runs on, and a daemon coming back must find the node it left drained.

use hlb_notify::{Level, Notification};
use hlb_orchestrator::{NodeInfo, Orchestrator};
use hlb_state::{NodeReboot, RebootPhase, State};
use hlb_updater::reboot::{self, Advance, Choice};

const ACTOR: &str = "controller";
const ACTION: &str = "node-reboot";

/// One pass: moves a reboot under way on, or — in the window, at most hourly — asks
/// every node whether it waits for one and starts the first that may go.
/// `last_probe`: when the nodes were last asked, in this daemon's memory — a restart
/// asks again, which costs a job per node.
pub async fn pass(
    state: &State,
    orchestrator: &dyn Orchestrator,
    last_probe: &mut Option<i64>,
    now: i64,
) -> hlb_state::Result<Vec<Notification>> {
    match state.node_reboot().await? {
        Some(r) => under_way(state, orchestrator, &r, now).await,
        None => start(state, orchestrator, last_probe, now).await,
    }
}

async fn under_way(
    state: &State,
    orchestrator: &dyn Orchestrator,
    r: &NodeReboot,
    now: i64,
) -> hlb_state::Result<Vec<Notification>> {
    if r.phase == RebootPhase::Stopped {
        return Ok(Vec::new());
    }
    let nodes = match orchestrator.nodes().await {
        Ok(n) => n,
        Err(e) => {
            // A manager going down with the node is the usual reason: the next pass.
            tracing::info!(
                node = r.hostname,
                "reboot: the nodes could not be listed: {e}"
            );
            return Ok(Vec::new());
        }
    };
    let left = if r.phase == RebootPhase::Draining {
        match orchestrator.tasks(None).await {
            // Global services (the agent) never leave a node: only replicated ones count.
            Ok(tasks) => tasks
                .iter()
                .filter(|t| t.node_id.as_deref() == Some(r.node_id.as_str()))
                .filter(|t| t.slot.is_some() && t.is_alive())
                .count(),
            Err(e) => {
                tracing::info!(
                    node = r.hostname,
                    "reboot: the tasks could not be listed: {e}"
                );
                return Ok(Vec::new());
            }
        }
    } else {
        0
    };
    let node = nodes.iter().find(|n| n.id == r.node_id);
    match reboot::advance(r, &nodes, left, now) {
        Advance::Wait => Ok(Vec::new()),
        Advance::GiveUp { why, undrain } => {
            give_up(state, orchestrator, r, &why, undrain, now).await
        }
        Advance::Reboot => {
            let Some(node) = node else {
                return Ok(Vec::new());
            };
            match send(orchestrator, node).await {
                Ok(()) => {
                    state
                        .set_node_reboot_phase(&r.node_id, RebootPhase::Rebooting, now, None)
                        .await?;
                    tracing::info!(node = r.hostname, "reboot: drained, command sent");
                    Ok(Vec::new())
                }
                Err(why) => give_up(state, orchestrator, r, &why, true, now).await,
            }
        }
        Advance::Check => {
            let Some(node) = node else {
                return Ok(Vec::new());
            };
            let probe = match ask(orchestrator, node).await {
                Ok(p) if p.uptime_s.is_some() => p,
                Ok(_) | Err(_) if now - r.phase_at < reboot::BACK_WITHIN_S => {
                    // Back, but its Docker may still be starting: the next pass.
                    return Ok(Vec::new());
                }
                Ok(_) => {
                    let why = format!("{} does not say how long it has been up", r.hostname);
                    return give_up(state, orchestrator, r, &why, false, now).await;
                }
                Err(why) => return give_up(state, orchestrator, r, &why, false, now).await,
            };
            if let Err(why) = reboot::came_back(r, &probe, now) {
                // It never went down: its services may come back.
                return give_up(state, orchestrator, r, &why, true, now).await;
            }
            if r.drained {
                if let Err(e) = orchestrator
                    .set_node_availability(&r.node_id, "active")
                    .await
                {
                    let why = format!("{} rebooted, and could not be put back: {e}", r.hostname);
                    return give_up(state, orchestrator, r, &why, false, now).await;
                }
            }
            state.clear_node_reboot(&r.node_id).await?;
            let still = probe.required == Some(true);
            let detail = if still {
                "rebooted, and still runs an older kernel than the newest installed: \
                 check its bootloader"
            } else {
                "rebooted into its newest kernel"
            };
            state
                .audit(
                    ACTOR,
                    hlb_types::Role::Admin,
                    ACTION,
                    &r.hostname,
                    "ok",
                    Some(detail),
                )
                .await?;
            tracing::info!(node = r.hostname, "reboot: {detail}");
            let title = format!("{} rebooted", r.hostname);
            Ok(vec![if still {
                Notification::important(&subject(&r.hostname), &title, detail)
            } else {
                Notification::new(Level::Info, &subject(&r.hostname), &title, detail)
            }])
        }
    }
}

async fn start(
    state: &State,
    orchestrator: &dyn Orchestrator,
    last_probe: &mut Option<i64>,
    now: i64,
) -> hlb_state::Result<Vec<Notification>> {
    // A reboot under way finishes; none begins on the battery.
    if super::power::under_way(state).await {
        return Ok(Vec::new());
    }
    let policy = state.reboot_policy().await?;
    let zone = state.timezone().await?;
    match reboot::due(&policy, zone.as_deref(), now, *last_probe) {
        Ok(true) => {}
        Ok(false) => return Ok(Vec::new()),
        Err(e) => {
            tracing::warn!("reboot: the house's window does not read: {e}");
            return Ok(Vec::new());
        }
    }
    *last_probe = Some(now);
    let nodes = match orchestrator.nodes().await {
        Ok(n) => n,
        Err(e) => {
            tracing::warn!("reboot: the nodes could not be listed: {e}");
            return Ok(Vec::new());
        }
    };
    let mut waiting = Vec::new();
    for n in nodes.iter().filter(|n| n.is_ready()) {
        match ask(orchestrator, n).await {
            Ok(p) if p.required == Some(true) => waiting.push(n.id.clone()),
            Ok(p) if p.required.is_none() => {
                tracing::info!(
                    node = n.hostname,
                    "reboot: it did not say whether it waits for one"
                )
            }
            Ok(_) => {}
            Err(why) => tracing::info!(node = n.hostname, "reboot: not asked: {why}"),
        }
    }
    if waiting.is_empty() {
        return Ok(Vec::new());
    }
    // 🔴 Unknown is not "none": read as none, this daemon's own node would be drained.
    let local = match orchestrator.local_node().await {
        Ok(Some(id)) => id,
        Ok(None) | Err(_) => {
            tracing::warn!("reboot: which node this daemon runs on is unknown: none started");
            return Ok(Vec::new());
        }
    };
    let (chosen, left) = reboot::choose(&nodes, &waiting, Some(&local), policy.accept_downtime);
    for (host, why) in &left {
        // The agent's reading puts it in the inbox (`node_reboot_pending`): a person's.
        tracing::info!(node = host, "reboot: left to a person: {why}");
    }
    let Some(Choice { node, drain }) = chosen else {
        return Ok(Vec::new());
    };
    // 🔴 The row first: the command may stop this very daemon before it writes anything.
    let phase = if drain {
        RebootPhase::Draining
    } else {
        RebootPhase::Rebooting
    };
    if !state
        .begin_node_reboot(&node.id, &node.hostname, phase, drain, now)
        .await?
    {
        return Ok(Vec::new());
    }
    let begun = NodeReboot {
        node_id: node.id.clone(),
        hostname: node.hostname.clone(),
        phase,
        drained: drain,
        started_at: now,
        phase_at: now,
        detail: None,
    };
    state
        .audit(
            ACTOR,
            hlb_types::Role::Admin,
            ACTION,
            &node.hostname,
            "started",
            Some(if drain {
                "drained first"
            } else {
                "not drained: the house accepted the downtime"
            }),
        )
        .await?;
    if drain {
        if let Err(e) = orchestrator.set_node_availability(&node.id, "drain").await {
            let why = format!("{} could not be drained: {e}", node.hostname);
            return give_up(state, orchestrator, &begun, &why, true, now).await;
        }
        tracing::info!(node = node.hostname, "reboot: draining");
        return Ok(Vec::new());
    }
    match send(orchestrator, &node).await {
        Ok(()) => {
            tracing::info!(node = node.hostname, "reboot: command sent, not drained");
            Ok(Vec::new())
        }
        Err(why) => give_up(state, orchestrator, &begun, &why, false, now).await,
    }
}

/// Stops, tells a person, and blocks the next reboots until one runs `hlb node upgrade`.
async fn give_up(
    state: &State,
    orchestrator: &dyn Orchestrator,
    r: &NodeReboot,
    why: &str,
    undrain: bool,
    now: i64,
) -> hlb_state::Result<Vec<Notification>> {
    let mut why = why.to_string();
    if undrain && r.drained {
        if let Err(e) = orchestrator
            .set_node_availability(&r.node_id, "active")
            .await
        {
            why = format!("{why}; and it could not be put back in service: {e}");
        }
    } else if r.drained {
        why = format!("{why}; it stays drained");
    }
    state
        .set_node_reboot_phase(&r.node_id, RebootPhase::Stopped, now, Some(&why))
        .await?;
    state
        .audit(
            ACTOR,
            hlb_types::Role::Admin,
            ACTION,
            &r.hostname,
            "failed",
            Some(&why),
        )
        .await?;
    tracing::warn!(node = r.hostname, "reboot stopped: {why}");
    Ok(vec![Notification::critical(
        &subject(&r.hostname),
        &format!("{} was not rebooted", r.hostname),
        &format!(
            "{why}.\nNo machine reboots on its own until `hlb node upgrade {}` succeeds.",
            r.hostname
        ),
    )])
}

fn subject(host: &str) -> String {
    format!("node-reboot:{host}")
}

async fn ask(orchestrator: &dyn Orchestrator, node: &NodeInfo) -> Result<reboot::Probe, String> {
    let out = orchestrator
        .run_job(&reboot::probe_job(node), reboot::JOB_TIMEOUT_S)
        .await
        .map_err(|e| e.to_string())?;
    reboot::read_probe(&out)
}

async fn send(orchestrator: &dyn Orchestrator, node: &NodeInfo) -> Result<(), String> {
    let out = orchestrator
        .run_job(&reboot::reboot_job(node), reboot::JOB_TIMEOUT_S)
        .await
        .map_err(|e| format!("the reboot could not be sent: {e}"))?;
    reboot::read_reboot(&out).map_err(|e| format!("the reboot could not be sent: {e}"))
}
