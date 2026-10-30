//! What changes the Swarm itself: a service's replicas, a node's availability.

use hlb_api::intent::{NodeAvailability, Scale};
use hlb_api::{ActionResult, ActionStep, StepState};

use crate::Privd;

pub(crate) async fn scale(p: &Privd, i: Scale) -> ActionResult {
    let Scale {
        app,
        replicas,
        apply,
    } = i;
    let mut blockers = Vec::new();

    let Some(target) = replicas else {
        blockers.push("replica count missing (\"replicas\" in the body)".to_string());
        return ActionResult {
            applied: false,
            summary: format!("resize {app}"),
            steps: Vec::new(),
            cli_command: format!("hlb scale {app} <n> --apply"),
            blockers,
            warnings: Vec::new(),
            confirmation_required: None,
        };
    };

    // 🔴 Going down to zero is not a resize, it is a shutdown — and it almost never
    // happens deliberately from an interface. We refuse it here: `hlb stop` exists and
    // says what it does.
    if target == 0 {
        blockers.push(
            "zero replicas stops the application — use \"hlb stop\" if that is the intent"
                .to_string(),
        );
    }

    let current = match &p.orchestrator {
        Some(o) => o.status(&app).await.ok().map(|st| st.desired_replicas),
        None => None,
    };

    if current.is_none() {
        blockers.push(format!(
            "\"{app}\" is not deployed, or Docker is unreachable"
        ));
    }

    let applied = apply && blockers.is_empty();
    let mut step = ActionStep {
        description: match current {
            Some(a) => format!(
                "move {app} from {a} to {}",
                hlb_api::plural(target, "replica", "replicas")
            ),
            None => format!(
                "move {app} to {}",
                hlb_api::plural(target, "replica", "replicas")
            ),
        },
        state: StepState::Planned,
        error: None,
    };

    if applied {
        match &p.orchestrator {
            Some(o) => match o.scale(&app, target).await {
                Ok(()) => {
                    step.state = StepState::Done;
                    // Kept in the state, or reconciliation puts the manifest's count
                    // back within a minute. The manifest's own count gives it back.
                    if let Ok(m) = p.state.app_manifest(&app).await {
                        let decided = (target != m.spec.swarm.replicas).then_some(target);
                        if let Err(e) = p.state.set_app_replicas(&app, decided).await {
                            step.error = Some(format!(
                                "scaled, but not kept: reconciliation may undo it — {e}"
                            ));
                        }
                    }
                }
                Err(e) => {
                    step.state = StepState::Failed;
                    step.error = Some(e.to_string());
                }
            },
            None => {
                step.state = StepState::Failed;
                step.error = Some("Docker unreachable".into());
            }
        }
    }

    ActionResult {
        applied,
        summary: format!(
            "{app} to {}",
            hlb_api::plural(target, "replica", "replicas")
        ),
        steps: vec![step],
        cli_command: format!("hlb scale {app} {target} --apply"),
        blockers,
        warnings: Vec::new(),
        confirmation_required: None,
    }
}

pub(crate) async fn node_availability(p: &Privd, i: NodeAvailability) -> ActionResult {
    let NodeAvailability {
        node: id,
        availability: targeted,
        confirmed,
        apply,
    } = i;
    let mut blockers = Vec::new();
    let mut warnings = Vec::new();
    let mut confirmation_required = None;

    if !matches!(targeted.as_str(), "active" | "pause" | "drain") {
        blockers.push("availability expected: \"active\", \"pause\" or \"drain\"".to_string());
    }

    // 🔴 Draining the LAST healthy node would empty the cluster: every app would stop,
    // and there would be nowhere left to place them. Swarm accepts it without
    // complaint — it is on us to refuse.
    if targeted == "drain" {
        if let Some(o) = &p.orchestrator {
            // Unread, every guard below would pass on an empty list.
            let nodes = match o.nodes().await {
                Ok(n) => n,
                Err(e) => {
                    blockers.push(format!("the cluster's nodes could not be read: {e}"));
                    Vec::new()
                }
            };
            let healthy = nodes
                .iter()
                .filter(|n| n.is_ready() && n.availability == "active")
                .count();
            // ⚠️ id OR hostname. Docker addresses a node by either, so `{id}` here can
            // legitimately be a hostname — and matching on the identifier alone made
            // this check quietly answer "the target is not active", which skips the
            // guard below and drains the last node the caller asked about.
            let target_is_active = nodes
                .iter()
                .any(|n| (n.id == id || n.hostname == id) && n.availability == "active");
            if target_is_active && healthy <= 1 {
                blockers.push(
                    "this is the last active node: draining it would stop ALL the \
                     applications, with nowhere to place them"
                        .to_string(),
                );
            }
            // 🔴 The CLI's own rule, `cluster::maintenance`: one node at a time, the
            // managers' quorum, the services whose data stays on this node. Skipped
            // here, a drain clicked while another node was out left the moved services
            // nowhere to go, and PostgreSQL stopped without a word of warning.
            if target_is_active && blockers.is_empty() {
                match hlb_orchestrator::cluster::maintenance(&nodes, &id) {
                    hlb_orchestrator::cluster::Maintenance::Go => {}
                    hlb_orchestrator::cluster::Maintenance::Downtime(why) => {
                        warnings.push(why);
                        confirmation_required = Some(id.clone());
                        if apply && confirmed.as_deref() != Some(id.as_str()) {
                            blockers.push(format!(
                                "the downtime is not accepted — send back \
                                 {{\"confirmed\": \"{id}\"}} to drain it anyway"
                            ));
                        }
                    }
                    hlb_orchestrator::cluster::Maintenance::Refused(why) => blockers.push(why),
                }
            }
        }
    }

    let applied = apply && blockers.is_empty();
    let mut step = ActionStep {
        description: format!("move node {id} to \"{targeted}\""),
        state: StepState::Planned,
        error: None,
    };

    if applied {
        match &p.orchestrator {
            Some(o) => match o.set_node_availability(&id, &targeted).await {
                Ok(()) => step.state = StepState::Done,
                Err(e) => {
                    step.state = StepState::Failed;
                    step.error = Some(e.to_string());
                }
            },
            // ⚠️ NOT a failure: no orchestrator means Docker is unreachable or we are
            // in demonstration mode. Recording it as failed would put a red line in the
            // audit log for something nobody attempted.
            None => {
                step.state = StepState::Unimplemented;
                step.error =
                    Some("no orchestrator: Docker unreachable, or demonstration mode".into());
            }
        }
    }

    ActionResult {
        applied,
        summary: format!("node {id} to \"{targeted}\""),
        steps: vec![step],
        cli_command: format!("docker node update --availability {targeted} {id}"),
        blockers,
        warnings,
        confirmation_required,
    }
}

/// The cluster's nodes, as Swarm lists them. `None` = no orchestrator.
pub(crate) async fn nodes(p: &Privd) -> Option<Result<Vec<hlb_types::swarm::NodeInfo>, String>> {
    let o = p.orchestrator.as_ref()?;
    Some(o.nodes().await.map_err(|e| e.to_string()))
}
