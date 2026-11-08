//! The controller's HTTP API.
//!
//! ## What replaced "read-only"
//!
//! This module long forbade every mutating verb, and a test checked it. That was the
//! right rule for phase 2.5: a UI that does not act cannot break anything.
//!
//! It is no longer right, because the interface must now install, back up, restore and
//! manage accounts. Three rules replace it, and **they protect more** than the ban they
//! lift:
//!
//! 1. **Preview by default.** An action route returns the plan and does nothing; it
//!    only acts with `?apply=true`. It is the exact transposition of
//!    `Executor::apply(true)` — the CLI and the API behave the same.
//! 2. **Authorization in the signature.** Every mutating route takes an
//!    [`Authorized<…>`](crate::auth::Authorized), so the check cannot be forgotten.
//! 3. **Audit log.** Every mutating route records who, what, when and the outcome.
//!
//! Each is locked by a test that walks the router: adding a mutating route without
//! respecting all three makes the suite fail.

use std::sync::Arc;

use axum::extract::State as AxumState;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use utoipa::OpenApi;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::extract::{Json, Path, Query};
use hlb_api::{AppSummary, AuditItem, GuideItem, Health, SecretItem};

use hlb_state::State;

use crate::auth::{Authorized, CanActOnSelf, CanManageAccounts, CanOperate, CanRead};
use crate::error::{ActionReply, ApiError, ApiResult};

use crate::agents::AgentStatus;
use crate::metrics::{self, AppMetrics};

/// What the daemon's agent poller last found, by agent address.
///
/// ⚠️ Unanswered reads as no node, logged: the inbox still fails loudly then, since the
/// alerts and the gaps it also asks for are errors when the daemon cannot be reached.
pub(crate) async fn fleet_now(s: &AppState) -> std::collections::BTreeMap<String, AgentStatus> {
    match s.privd().ask(hlb_api::intent::Fleet {}).await {
        Ok(wire) => hlb_privd::fleet::from_wire(wire),
        Err(e) => {
            tracing::warn!("the fleet could not be asked for: {e}");
            Default::default()
        }
    }
}

pub struct AppState {
    pub state: Arc<State>,
    /// 🔴 The only way to Docker, the vault and the admin clients: private to
    /// `hlb-privd`, so a handler wanting one of them does not compile.
    pub privd: hlb_privd::Privd,
    pub started_at: std::time::Instant,
    pub version: &'static str,
    /// Web UI directory. `None` = API only.
    pub ui_dir: Option<std::path::PathBuf>,
    /// 🔴 `true` = open API, with no authentication.
    ///
    /// Exists only because an existing deployment must not break all at once. The
    /// controller refuses to start in this state without an explicit
    /// `--insecure-no-auth`: open must be a DECISION, never a default.
    pub no_auth: bool,
    /// Sign-in through PocketID. Empty = not configured, or its issuer not reached
    /// yet: only API tokens authenticate, and `/auth/signin` answers `503` **while
    /// saying which, and how to enable it** rather than a 404 that would suggest a bug.
    pub signin: Arc<crate::signin::SignInSlot>,
    /// Rate limiting. See `crate::throughput` for what it protects.
    pub throughput: Arc<crate::throughput::RateLimiter>,
    /// The domain of the addresses created.
    pub mail_domain: String,
    /// The application catalog. `None` = directory absent or unreadable; the screens
    /// say so rather than show an empty list.
    pub catalog: hlb_privd::catalog::SharedCatalog,
    /// Where that catalog was read from — needed to serve each application's own
    /// `icon.png`, which is a FILE beside its manifest rather than a parsed field.
    pub catalog_dir: std::path::PathBuf,
    /// Themes this installation declared in files, loaded once at startup.
    ///
    /// 🔴 They WIDEN `hlb_api::THEMES`, never replace it. Every place that offers or
    /// checks a theme name must consider shipped ∪ custom, or a perfectly valid choice
    /// gets refused by one half of the system and accepted by the other.
    pub custom_themes: Vec<hlb_api::CustomTheme>,
    /// Where those themes were read from — needed to serve the typeface a theme names,
    /// which is a FILE beside its YAML rather than a parsed field. Exactly the reason
    /// `catalog_dir` exists beside `catalog`.
    pub themes_dir: std::path::PathBuf,
    /// 🔴 Is the status page public?
    ///
    /// `false` by default: a public status page reveals the list of what runs at your
    /// place and the calendar of your outages. That is a choice you make, not a default
    /// you discover.
    pub public_status: bool,
    /// Demonstration mode: some views are fabricated for want of an orchestrator.
    pub demo: bool,
    /// The deadman's heartbeat file, when one is configured.
    ///
    /// ⚠️ Used by the checklist, which must distinguish "no deadman" from "silent
    /// deadman" — the second is an alert, the first an absence.
    pub beat: Option<std::path::PathBuf>,
    /// The Git mirror, when configured: the only place that keeps the history
    /// of the manifests.
    pub mirror: Option<std::path::PathBuf>,
    /// The controller's public URL, as an outside client sees it.
    ///
    /// ⚠️ `None` = unknown. The Bitwarden wizard SAYS so rather than paste
    /// "http://127.0.0.1:8420" into a field Bitwarden will call from the phone, where
    /// that address does not mean the same machine.
    pub public_url: Option<String>,
    /// The time-series database. `None` = not deployed: the graphs show "unavailable"
    /// **while saying how to install it**, rather than a flat curve.
    pub series: Option<Arc<crate::promql::Metrics>>,
    /// 🔴 `true` = croire `X-Forwarded-For`.
    ///
    /// To be set ONLY if a trusted proxy really is in front: otherwise every attacker
    /// gives themselves a fresh counter on every request, and the rate limit limits
    /// nothing while giving the impression of the opposite.
    pub trusted_proxy: bool,
}

impl AppState {
    /// The privileged side, which every handler asks instead of holding Docker, the
    /// vault or an admin client itself.
    pub fn privd(&self) -> &hlb_privd::Privd {
        &self.privd
    }

    /// Appends an entry to the audit chain, which only the privileged side writes.
    pub async fn append_audit(
        &self,
        actor: &str,
        role: hlb_types::Role,
        action: &str,
        target: &str,
        outcome: &str,
        detail: Option<&str>,
    ) -> Result<(), String> {
        let asked = hlb_api::intent::Audit {
            actor: actor.to_string(),
            role,
            action: action.to_string(),
            target: target.to_string(),
            outcome: outcome.to_string(),
            detail: detail.map(str::to_string),
        };
        self.record(asked).await
    }

    /// Asks the privileged side for a record of the state, which only it writes: an
    /// answer that did not come back and a refusal read alike.
    pub async fn record<A, T>(&self, intent: A) -> Result<T, String>
    where
        A: hlb_api::intent::Ask<Answer = Result<T, String>>,
    {
        self.record_confirmed(None, intent).await
    }

    /// The same, with the passkey that confirmed it when there is one.
    pub async fn record_confirmed<A, T>(
        &self,
        proof: Option<hlb_api::intent::Proof>,
        intent: A,
    ) -> Result<T, String>
    where
        A: hlb_api::intent::Ask<Answer = Result<T, String>>,
    {
        self.privd
            .ask_confirmed(proof, intent)
            .await
            .map_err(|e| e.to_string())?
    }
}

/// The MIME types the browser needs.
///
/// 🔴 Not decorative: a module script served as `application/octet-stream` is
/// **refused** by the browser under strict MIME checking, and the console names the
/// type it got without saying which one it wanted.
fn mime_of(file: &str) -> &'static str {
    match file.rsplit('.').next() {
        Some("js") => "text/javascript",
        Some("html") => "text/html; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("json") => "application/json",
        // ⚠️ The web app manifest has its own type. Served as `application/json`,
        // Chrome accepts it but Safari REFUSES to install the page,
        // without a message: the "Add to home screen" entry is simply missing.
        Some("webmanifest") => "application/manifest+json",
        // Likewise for the icon: an SVG served as octet-stream is not displayed at all.
        Some("svg") => "image/svg+xml",
        // ⚠️ A font is not BROKEN by octet-stream, but a proxy or a policy that filters
        // on content type has no way to tell it from a download.
        Some("png") => "image/png",
        Some("ttf") => "font/ttf",
        Some("woff2") => "font/woff2",
        Some("ico") => "image/x-icon",
        _ => "application/octet-stream",
    }
}

/// A safe file name?
///
/// 🔴 Without this check, `GET /../../etc/shadow` escapes the UI directory. The server
/// often runs as root on a cluster node: the stake is not theoretical.
/// theoretical.
fn name_on(file: &str) -> bool {
    !file.is_empty()
        && !file.contains("..")
        && !file.starts_with('/')
        && !file.contains('\\')
        // A null byte truncates the path on the filesystem side.
        && !file.contains('\0')
}

async fn ui_index(AxumState(s): AxumState<Arc<AppState>>) -> Response {
    serve(&s, "index.html").await
}

async fn ui_file(AxumState(s): AxumState<Arc<AppState>>, Path(file): Path<String>) -> Response {
    serve(&s, &file).await
}

async fn serve(s: &AppState, file: &str) -> Response {
    let Some(dir) = &s.ui_dir else {
        return (
            StatusCode::NOT_FOUND,
            "web UI not deployed — start the controller with --ui-dir\n",
        )
            .into_response();
    };

    if !name_on(file) {
        return (StatusCode::BAD_REQUEST, "file name refused\n").into_response();
    }

    match tokio::fs::read(dir.join(file)).await {
        Ok(bytes) => ([(axum::http::header::CONTENT_TYPE, mime_of(file))], bytes).into_response(),
        // 🔴 The interface routes in the browser: `/apps/gitea` is no file, and without
        // this a reload or a shared link answers 404 on a screen that exists.
        Err(_) if is_screen(file) => match tokio::fs::read(dir.join("index.html")).await {
            Ok(bytes) => (
                [(axum::http::header::CONTENT_TYPE, mime_of("index.html"))],
                bytes,
            )
                .into_response(),
            Err(_) => (StatusCode::NOT_FOUND, "index.html absent\n").into_response(),
        },
        Err(_) => (StatusCode::NOT_FOUND, "file absent\n").into_response(),
    }
}

/// A path the interface's own router answers, rather than a file or the server's.
///
/// ⚠️ Not under a prefix the server routes — `/api/nope` answered with the interface's
/// page is a 200 of HTML that `openapi-fetch` fails to parse as JSON, far from the typo
/// that caused it. The prefixes are read from the document, so a route added under a
/// new one is covered without anyone remembering this function. And not a file the
/// interface ships: a missing script answered with HTML is refused by the browser under
/// a MIME type that hides which file was missing.
///
/// 🔴 A file is a name with an extension [`mime_of`] KNOWS, not any name with a dot.
/// "Has a dot" refused every machine (`/nodes/10.0.0.2:8421`) and every account named
/// `firstname.lastname` on a reload or a shared link — the router reaches them, so no
/// test that moves through it could see it.
fn is_screen(file: &str) -> bool {
    let first = file.split('/').next().unwrap_or("");
    let server = crate::openapi::routes()
        .iter()
        .any(|r| r.path.trim_start_matches('/').split('/').next() == Some(first));
    let last = file.rsplit('/').next().unwrap_or("");
    let shipped = last.contains('.') && mime_of(last) != "application/octet-stream";
    !server && !shipped
}

/// The cluster's nodes.
///
/// 🔴 An unreachable node **still appears**, marked as such. Filtering it would give a
/// list of healthy nodes, and the machine you know nothing about would be exactly the
/// one you would not see.
#[utoipa::path(
    get,
    path = "/api/nodes",
    responses(
        (status = 200, body = Vec<hlb_api::NodeSummary>)
    ),
    extensions(
        ("x-hlb-requires" = json!("read"))
    )
)]
async fn nodes(
    _auth: Authorized<CanRead>,
    AxumState(s): AxumState<Arc<AppState>>,
) -> Json<Vec<hlb_api::NodeSummary>> {
    Json(nodes_summary(&s).await)
}

/// The node inventory, as the API presents it.
///
/// Extracted from the handler because the causal chain needs it too: it climbs from a
/// failed task to the node that carried it. Two divergent assemblies of the same node
/// would end up giving two different diagnoses.
pub(crate) async fn nodes_summary(s: &AppState) -> Vec<hlb_api::NodeSummary> {
    let now = crate::auth::now();
    let poll = fleet_now(s).await;
    let thresholds = hlb_agent::disk::Thresholds::default();

    // The tasks, to say what each node hosts. A failure here must not deprive us of the
    // node list: we show the nodes without their tasks.
    let view = swarm(s, None).await;
    let tasks = view.as_ref().map(task_summaries).unwrap_or_default();
    // The level is a label on the Swarm node, found by hostname — the one name the agent
    // and Swarm share, as for the detail's availability.
    let protection = |hostname: Option<&str>| match &view {
        Some(v) => v
            .nodes
            .iter()
            .find(|n| hostname == Some(n.hostname.as_str()))
            .and_then(|n| n.protection.as_deref())
            .and_then(hlb_api::ProtectionLevel::from_label),
        None if s.demo => crate::demo::protection(hostname),
        None => None,
    };

    let mut out = Vec::new();
    for (address, status) in poll.iter() {
        let r = status.report();

        // ⚠️ The report's hostname is only for display; the ADDRESS is the identity
        // (see `NodeSummary::address`).
        let hostname = r.map(|r| r.hostname.clone());
        let on_this_node: Vec<String> = tasks
            .iter()
            .filter(|t| t.alive)
            .filter(|t| {
                t.node
                    .as_deref()
                    .is_some_and(|n| hostname.as_deref().is_some_and(|h| n == h) || n == address)
            })
            .map(|t| t.service.clone())
            .collect();

        out.push(hlb_api::NodeSummary {
            address: address.clone(),
            hostname,
            reachable: r.is_some(),
            detail: match status {
                crate::agents::AgentStatus::Unreachable { detail } => Some(detail.clone()),
                crate::agents::AgentStatus::Reporting(_) => None,
            },
            report_age_s: r.map(|r| now.saturating_sub(r.at as i64)),
            cpu_busy: r.and_then(|r| r.cpu_busy),
            load_per_core: r.and_then(|r| r.load_per_core()),
            memory_used: r.and_then(|r| r.memory_used()),
            swap_used: r.and_then(|r| match (r.swap_total_mb, r.swap_used_mb) {
                (Some(t), Some(u)) if t > 0 => Some(u as f64 / t as f64),
                _ => None,
            }),
            disks: r
                .map(|r| {
                    r.disks
                        .iter()
                        .map(|d| hlb_api::DiskSummary {
                            path: d.path.clone(),
                            used: d.used_percent() / 100.0,
                            total_mb: d.total_mb,
                            free_mb: d.free_mb,
                            pressure: crate::metrics::tier(d.pressure(&thresholds)),
                        })
                        .collect()
                })
                .unwrap_or_default(),
            uptime_s: r.and_then(|r| r.system.as_ref()).and_then(|y| y.uptime_s),
            distro: r
                .and_then(|r| r.system.as_ref())
                .and_then(|y| y.distro.clone()),
            kernel: r
                .and_then(|r| r.system.as_ref())
                .and_then(|y| y.kernel.clone()),
            agent_version: r.map(|r| r.agent_version.clone()),
            protocol: r.map(|r| r.protocol),
            tasks: on_this_node,
            reboot_pending: r.and_then(|r| r.reboot_required),
            protection: protection(r.map(|r| r.hostname.as_str())),
        });
    }

    // The nodes needing attention first: across ten machines, the one that does not
    // answer would get lost in the middle of an alphabetical sort.
    out.sort_by(|a, b| {
        b.attention()
            .cmp(&a.attention())
            .then_with(|| a.address.cmp(&b.address))
    });
    out
}

/// A single node's detail: the same `NodeSummary` the
/// list already has, plus full per-task detail and network interfaces — genuinely new
/// data `nodes_summary()` never carried, not a relayout of it.
#[utoipa::path(
    get,
    path = "/api/nodes/{address}/detail",
    responses(
        (status = 200, body = hlb_api::NodeDetail)
    ),
    extensions(
        ("x-hlb-requires" = json!("read"))
    )
)]
async fn node_detail(
    _auth: Authorized<CanRead>,
    AxumState(s): AxumState<Arc<AppState>>,
    Path(address): Path<String>,
) -> ApiResult<hlb_api::NodeDetail> {
    let Some(summary) = nodes_summary(&s)
        .await
        .into_iter()
        .find(|n| n.address == address)
    else {
        return Err(ApiError::NotFound(format!("unknown node \"{address}\"")));
    };

    // Same predicate `nodes_summary()` already uses to attribute a task to a node: by
    // hostname, the address only a fallback for a node whose hostname is not known
    // (unreachable, or never reported).
    let hostname = summary.hostname.clone();
    let on_this_node = |node: &Option<String>| {
        node.as_deref()
            .is_some_and(|n| hostname.as_deref().is_some_and(|h| n == h) || n == address)
    };

    let tasks = match swarm(&s, None).await {
        Some(v) => task_summaries(&v)
            .into_iter()
            .filter(|t| on_this_node(&t.node))
            .collect(),
        // ⚠️ Same precedent as `app_detail`'s own demo branch: without an orchestrator,
        // the Containers tab would be empty in the one mode this project's own Commands
        // section recommends as "the fastest way to see the UI."
        None if s.demo => crate::demo::node_tasks(hostname.as_deref().unwrap_or(&address)),
        None => Vec::new(),
    };

    // Collected by the agent since the first release, in the poller's pass already —
    // simply never read until now. No demo branch needed: demo mode's own pass
    // (`demo::nodes`) already fabricates `interfaces` on every reachable node.
    let interfaces = fleet_now(&s)
        .await
        .get(&address)
        .and_then(|status| status.report())
        .map(|r| {
            r.interfaces
                .iter()
                .map(|i| hlb_api::InterfaceSummary {
                    name: i.name.clone(),
                    rx_bytes: i.rx_bytes,
                    tx_bytes: i.tx_bytes,
                })
                .collect()
        })
        .unwrap_or_default();

    // 🔴 Matched on the HOSTNAME, the only name the two sides share: the agent knows a
    // machine by the address it answers on, Swarm by an identifier it generated
    // itself. A node whose hostname has never been reported stays `None` rather than
    // being guessed — draining the wrong machine empties it silently, and the mistake
    // only shows when the apps have already moved.
    let swarm = match swarm(&s, None).await {
        Some(v) => v
            .nodes
            .into_iter()
            .find(|n| summary.hostname.as_deref() == Some(n.hostname.as_str()))
            .map(|n| hlb_api::SwarmNode {
                id: n.id,
                availability: n.availability,
            }),
        // Same precedent as the Containers tab just above: without this, the one mode
        // the Commands section recommends for looking at the interface would show a
        // node detail with no availability at all.
        None if s.demo => crate::demo::swarm_node(summary.hostname.as_deref()),
        None => None,
    };

    Ok(Json(hlb_api::NodeDetail {
        summary,
        tasks,
        interfaces,
        swarm,
    }))
}

/// The cluster's topology, grouped by failure domain.
///
/// 🔴 The screen that on its own justifies the interface's existence: on the
/// command line you see three nodes and believe you are protected; here you see that
/// two of them are two VMs on the same hardware.
#[utoipa::path(
    get,
    path = "/api/topology",
    responses(
        (status = 200, body = hlb_api::Topology)
    ),
    extensions(
        ("x-hlb-requires" = json!("read"))
    )
)]
async fn topology(
    _auth: Authorized<CanRead>,
    AxumState(s): AxumState<Arc<AppState>>,
) -> Json<hlb_api::Topology> {
    Json(topology_now(&s).await)
}

pub(crate) async fn topology_now(s: &AppState) -> hlb_api::Topology {
    let Some(hlb_api::intent::SwarmView { nodes, tasks }) = swarm(s, None).await else {
        // In demonstration mode, a fabricated topology: without it, the screen that
        // justifies the interface's existence would be empty and impossible to write.
        if s.demo {
            return crate::demo::topology();
        }
        // ⚠️ Otherwise we do not return an empty topology — which would read as "no
        // node", that is, a destroyed cluster. The case is distinguished by
        // `total_nodes: 0`, and the screen says so.
        return hlb_api::Topology {
            domains: Vec::new(),
            violations: Vec::new(),
            managers: Vec::new(),
            total_nodes: 0,
        };
    };

    // Only LIVE replicas count for anti-affinity: a dead task shares nothing any more,
    // and including it would surface violations that are already resolved.
    let placements: Vec<(String, String)> = tasks
        .iter()
        .filter(|t| t.is_alive())
        .filter_map(|t| t.node_id.clone().map(|n| (t.service.clone(), n)))
        .collect();

    let violations = hlb_types::swarm::anti_affinity_violations(&placements, &nodes);
    let groups = hlb_types::swarm::group_by_domain(&nodes);
    let total = nodes.len();

    hlb_api::Topology {
        // What the failure simulator needs to know to judge the quorum.
        managers: nodes
            .iter()
            .filter(|n| n.role == hlb_types::swarm::NodeRole::Manager)
            .map(|n| n.id.clone())
            .collect(),
        domains: groups
            .iter()
            .map(|g| hlb_api::DomainSummary {
                concentrated: g.concentrated(total),
                name: g.name.clone(),
                nodes: g
                    .nodes
                    .iter()
                    .filter_map(|id| nodes.iter().find(|n| &n.id == id))
                    .map(|n| hlb_api::NodeInDomain {
                        services: placements
                            .iter()
                            .filter(|(_, node)| node == &n.id)
                            .map(|(svc, _)| svc.clone())
                            .collect(),
                        id: n.id.clone(),
                        hostname: n.hostname.clone(),
                        tier: n.tier.clone(),
                        reachable: n.is_ready(),
                    })
                    .collect(),
            })
            .collect(),
        violations: violations
            .iter()
            .map(|v| hlb_api::ViolationSummary {
                total_violation: v.total_violation(),
                explanation: v.describe(),
                service: v.service.clone(),
                domain: v.domain.clone(),
                replicas: v.replicas,
                total: v.total,
            })
            .collect(),
        total_nodes: total,
    }
}

/// The Swarm tasks, with their placement and their error.
#[utoipa::path(
    get,
    path = "/api/tasks",
    responses(
        (status = 200, body = Vec<hlb_api::TaskSummary>)
    ),
    extensions(
        ("x-hlb-requires" = json!("read"))
    )
)]
async fn tasks(
    _auth: Authorized<CanRead>,
    AxumState(s): AxumState<Arc<AppState>>,
) -> Json<Vec<hlb_api::TaskSummary>> {
    Json(
        swarm(&s, None)
            .await
            .map(|v| task_summaries(&v))
            .unwrap_or_default(),
    )
}

/// What runs where, asked of the privileged side. `None` = no orchestrator.
pub(crate) async fn swarm(
    s: &AppState,
    service: Option<&str>,
) -> Option<hlb_api::intent::SwarmView> {
    s.privd()
        .ask(hlb_api::intent::Swarm {
            service: service.map(str::to_string),
        })
        .await
        .ok()
        .flatten()
}

/// The tasks as the API shows them.
///
/// 🔴 `node` is the node's HOSTNAME — what the agent, the node screens and the causal
/// chain know a machine by. A task carries Swarm's id for it, and that id was passed
/// through: compared with hostnames and addresses, it matched none, and on a real
/// cluster every node listed no service and no failure reached its machine. Only the
/// demonstration, whose tasks name hostnames, showed them. A node Swarm no longer lists
/// keeps its id.
pub(crate) fn task_summaries(view: &hlb_api::intent::SwarmView) -> Vec<hlb_api::TaskSummary> {
    let nodes = &view.nodes;
    view.tasks
        .iter()
        .cloned()
        .map(|t| hlb_api::TaskSummary {
            alive: t.is_alive(),
            failed: t.has_failed(),
            explanation: t.explanation().map(str::to_string),
            node: t.node_id.map(|id| {
                nodes
                    .iter()
                    .find(|n| n.id == id && !n.hostname.is_empty())
                    .map_or(id, |n| n.hostname.clone())
            }),
            id: t.id,
            service: t.service,
            slot: t.slot,
            state: t.state,
            desired_state: t.desired_state,
            image: Some(t.image).filter(|i| !i.is_empty()),
        })
        .collect()
}

/// The backup history.
#[utoipa::path(
    get,
    path = "/api/backups",
    responses(
        (status = 200, body = Vec<hlb_api::BackupRun>)
    ),
    extensions(
        ("x-hlb-requires" = json!("read"))
    )
)]
async fn backups(
    _auth: Authorized<CanRead>,
    AxumState(s): AxumState<Arc<AppState>>,
) -> ApiResult<Vec<hlb_api::BackupRun>> {
    Ok(Json(
        s.state
            .backup_history_all(200)
            .await?
            .into_iter()
            .map(|r| hlb_api::BackupRun {
                id: r.id,
                app: r.app,
                kind: r.kind,
                destination: r.destination,
                succeeded: r.status == "ok",
                error: r.error,
                when: r.finished_at,
            })
            .collect(),
    ))
}

/// The real backup coverage, app by app.
#[utoipa::path(
    get,
    path = "/api/coverage",
    responses(
        (status = 200, body = Vec<hlb_api::CoverageSummary>)
    ),
    extensions(
        ("x-hlb-requires" = json!("read"))
    )
)]
async fn coverage(
    _auth: Authorized<CanRead>,
    AxumState(s): AxumState<Arc<AppState>>,
) -> Json<Vec<hlb_api::CoverageSummary>> {
    Json(coverage_now(&s).await)
}

pub(crate) async fn coverage_now(s: &AppState) -> Vec<hlb_api::CoverageSummary> {
    let mut out: Vec<hlb_api::CoverageSummary> =
        crate::coverage::all_of_them(&s.state, STALENESS_THRESHOLD_S)
            .await
            .into_iter()
            .map(|c| hlb_api::CoverageSummary {
                up_to_date_copies: c.up_to_date_copies(),
                per_destination: c
                    .per_destination
                    .iter()
                    .map(|(name, state)| {
                        let age = match state {
                            // 🔴 `None` = never served, which is NOT "a very long time
                            // ago". The type keeps the distinction.
                            hlb_backup::DestinationState::Never => None,
                            hlb_backup::DestinationState::Fresh { age_s }
                            | hlb_backup::DestinationState::Stale { age_s } => Some(*age_s),
                        };
                        (name.clone(), age)
                    })
                    .collect(),
                app: c.app,
            })
            .collect();

    out.sort_by(|a, b| {
        b.attention()
            .cmp(&a.attention())
            .then_with(|| a.app.cmp(&b.app))
    });
    out
}

/// An app manifest's successive versions, with their diff (batch 9.11).
#[utoipa::path(
    get,
    path = "/api/apps/{name}/versions",
    responses(
        (status = 200, body = Vec<hlb_api::VersionManifest>)
    ),
    extensions(
        ("x-hlb-requires" = json!("read"))
    )
)]
async fn manifest_versions(
    _auth: Authorized<CanRead>,
    AxumState(s): AxumState<Arc<AppState>>,
    Path(name): Path<String>,
) -> Json<Vec<hlb_api::VersionManifest>> {
    // ⚠️ Without a Git mirror there is NO history — and an empty list says that
    // correctly: the state only keeps the current version, there is nothing to
    // reconstruct. The screen then shows how to enable the mirror.
    let Some(path) = &s.mirror else {
        return Json(Vec::new());
    };
    // Opened, never initialised: the daemon writes the mirror, and a repository the
    // first visit to this screen created would be one more thing the web side wrote.
    match hlb_gitops::GitMirror::open(path) {
        Ok(m) => Json(crate::diff::versions(&m, &name, 20)),
        Err(_) => Json(Vec::new()),
    }
}

/// The unified timeline (batch 9.5).
#[utoipa::path(
    get,
    path = "/api/timeline",
    responses(
        (status = 200, body = Vec<hlb_api::Event>)
    ),
    extensions(
        ("x-hlb-requires" = json!("read"))
    )
)]
async fn timeline(
    _auth: Authorized<CanRead>,
    AxumState(s): AxumState<Arc<AppState>>,
) -> Json<Vec<hlb_api::Event>> {
    Json(crate::timeline::events(&s.state, 200).await)
}

/// A CSV export of a tabular view (batch 11.5).
///
/// ⚠️ The log and the accounts require more than `Lire`: the first says who did what,
/// the second who exists. They are the two tables you do not put in everyone's hands,
/// even with no secret value.
#[utoipa::path(
    get,
    path = "/api/export/{what}",
    responses(
        (status = 200, content_type = "text/csv", body = String)
    ),
    extensions(
        ("x-hlb-requires" = json!("read"))
    )
)]
async fn export_csv(
    auth: Authorized<CanRead>,
    AxumState(s): AxumState<Arc<AppState>>,
    Path(what): Path<String>,
) -> Result<Response, ApiError> {
    let (csv, name) = match what.as_str() {
        "audit" => {
            if let Some(refusal) = auth
                .identity()
                .role
                .refusal(hlb_types::rbac::Action::ManageAccounts)
            {
                return Err(ApiError::Forbidden(refusal));
            }
            (
                // Whole: an export cut at 5,000 rows was "the full log" missing its oldest.
                crate::export::audit(&s.state.audit_trail(EVERYTHING).await.unwrap_or_default()),
                "journal.csv",
            )
        }
        "backups" => (
            crate::export::backups(
                &s.state
                    .backup_history_all(EVERYTHING)
                    .await
                    .unwrap_or_default(),
            ),
            "backups.csv",
        ),
        "accounts" => {
            if let Some(refusal) = auth
                .identity()
                .role
                .refusal(hlb_types::rbac::Action::ManageAccounts)
            {
                return Err(ApiError::Forbidden(refusal));
            }
            (
                crate::export::accounts(&crate::accounts::resumes(&s).await),
                "accounts.csv",
            )
        }
        // 🔴 An unknown view returns 404, never an empty file: an empty CSV reads as
        // "there was nothing", which is false and undetectable.
        _ => {
            return Err(ApiError::NotFound(format!(
                "\"{what}\" is not an exportable view"
            )))
        }
    };

    Ok((
        [
            (
                axum::http::header::CONTENT_TYPE,
                "text/csv; charset=utf-8".to_string(),
            ),
            (
                axum::http::header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{name}\""),
            ),
        ],
        csv,
    )
        .into_response())
}

/// The runbook, in Markdown, generated from the real state (batch 10.3).
///
/// 🔴 Requires `CanManageAccounts`: the document describes the installation's full
/// inventory and the recovery procedure. It carries no secret, but it is a
/// card.
#[utoipa::path(
    get,
    path = "/api/runbook",
    responses(
        (status = 200, content_type = "text/markdown", body = String)
    ),
    extensions(
        ("x-hlb-requires" = json!("manage-accounts"))
    )
)]
async fn runbook(
    _auth: Authorized<CanManageAccounts>,
    AxumState(s): AxumState<Arc<AppState>>,
) -> impl axum::response::IntoResponse {
    let nodes = nodes_summary(&s).await;
    let text = crate::runbook::generate(&s.state, &nodes, crate::auth::now()).await;
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/markdown; charset=utf-8",
        )],
        text,
    )
}

/// The break-glass access safeguards (batch 10.2).
#[utoipa::path(
    get,
    path = "/api/recovery",
    responses(
        (status = 200, body = hlb_api::breakglass::BreakGlass)
    ),
    extensions(
        ("x-hlb-requires" = json!("manage-accounts"))
    )
)]
async fn breakglass(
    _auth: Authorized<CanManageAccounts>,
    AxumState(s): AxumState<Arc<AppState>>,
) -> Json<hlb_api::breakglass::BreakGlass> {
    Json(hlb_api::breakglass::BreakGlass {
        safeguards: crate::recovery::state(&s.state, crate::recovery::kit_now(&s).await.as_deref())
            .await,
    })
}

/// The secrets and what rotating them would involve (batch 10.1).
///
/// 🔴 Requires `CanManageAccounts` and not `CanRead`: the list of secrets describes what
/// the installation is wired to. It carries no value — but knowing a
/// "gitea-db-password" exists is already a map.
#[utoipa::path(
    get,
    path = "/api/secrets/rotation",
    responses(
        (status = 200, body = Vec<hlb_api::rotation::SecretToRotate>)
    ),
    extensions(
        ("x-hlb-requires" = json!("manage-accounts"))
    )
)]
async fn secret_rotation(
    _auth: Authorized<CanManageAccounts>,
    AxumState(s): AxumState<Arc<AppState>>,
) -> Json<Vec<hlb_api::rotation::SecretToRotate>> {
    Json(rotation_now(&s).await)
}

pub(crate) async fn rotation_now(s: &AppState) -> Vec<hlb_api::rotation::SecretToRotate> {
    let secrets = s.state.secrets_ages().await.unwrap_or_default();
    secrets
        .into_iter()
        .map(
            |(name, usage, age_s, never_rotated)| hlb_api::rotation::SecretToRotate {
                nature: hlb_api::rotation::Nature::infer(&name, &usage),
                app: hlb_api::rotation::app_of(&name),
                name,
                usage,
                age_s,
                never_rotated,
            },
        )
        .collect()
}

/// The installation checklist (batch 9.7).
#[utoipa::path(
    get,
    path = "/api/health",
    responses(
        (status = 200, body = Vec<hlb_api::HealthCheck>)
    ),
    extensions(
        ("x-hlb-requires" = json!("read"))
    )
)]
async fn installation_health(
    _auth: Authorized<CanRead>,
    AxumState(s): AxumState<Arc<AppState>>,
) -> Json<Vec<hlb_api::HealthCheck>> {
    Json(crate::health::checks(&s.state, s.beat.as_deref(), crate::auth::now()).await)
}

/// What each app declares, and what is really published (batch 9.10).
#[utoipa::path(
    get,
    path = "/api/exposure",
    responses(
        (status = 200, body = Vec<hlb_api::ExposureSummary>)
    ),
    extensions(
        ("x-hlb-requires" = json!("read"))
    )
)]
async fn exposure(
    _auth: Authorized<CanRead>,
    AxumState(s): AxumState<Arc<AppState>>,
) -> Json<Vec<hlb_api::ExposureSummary>> {
    Json(
        crate::exposure::findings(&s.state)
            .await
            .into_iter()
            .map(|(route, _)| route)
            .collect(),
    )
}

/// The house's domain: the last reading, what moved since the baseline, what the CAA
/// lets each account do, and what the logs hold under a key the house does not.
#[utoipa::path(
    get,
    path = "/api/domain",
    responses(
        (status = 200, body = hlb_api::domain::DomainView)
    ),
    extensions(
        ("x-hlb-requires" = json!("read"))
    )
)]
async fn domain(
    _auth: Authorized<CanRead>,
    AxumState(s): AxumState<Arc<AppState>>,
) -> ApiResult<hlb_api::domain::DomainView> {
    let now = crate::auth::now();
    match crate::domain::view(&s.state, now).await? {
        hlb_api::domain::DomainView::NoExposure if s.demo => Ok(Json(crate::demo::domain(now))),
        v => Ok(Json(v)),
    }
}

/// The gaps between what should be running and what is running (batch 9.8).
#[utoipa::path(
    get,
    path = "/api/drift",
    responses(
        (status = 200, body = Vec<hlb_api::DriftSummary>)
    ),
    extensions(
        ("x-hlb-requires" = json!("read"))
    )
)]
async fn drifts(
    _auth: Authorized<CanRead>,
    AxumState(s): AxumState<Arc<AppState>>,
) -> ApiResult<Vec<hlb_api::DriftSummary>> {
    Ok(Json(drifts_now(&s).await?))
}

/// The active alerts.
///
/// 🔴 Includes the **muted** ones: they stay visible, marked, with their deadline.
/// Filtering them here would give a green dashboard for a known, unresolved problem.
#[utoipa::path(
    get,
    path = "/api/alerts",
    responses(
        (status = 200, body = Vec<hlb_api::AlertAt>)
    ),
    extensions(
        ("x-hlb-requires" = json!("read"))
    )
)]
async fn alerts(
    _auth: Authorized<CanRead>,
    AxumState(s): AxumState<Arc<AppState>>,
) -> ApiResult<Vec<hlb_api::AlertAt>> {
    Ok(Json(alerts_now(&s).await?))
}

pub(crate) async fn alerts_now(s: &AppState) -> Result<Vec<hlb_api::AlertAt>, ApiError> {
    let now = crate::auth::now();
    // The table, read at answer time: a mute set a second ago shows now, not at the
    // loop's next pass — the screen that set it would otherwise look like it failed.
    let mutes = s.state.alert_mutes(now).await?;
    Ok(active_alerts(s)
        .await?
        .into_iter()
        .map(|mut a| {
            a.apply_mutes(&mutes);
            a.at(now)
        })
        .collect())
}

/// The alerts the daemon's last evaluation found, mutes not applied.
pub(crate) async fn active_alerts(s: &AppState) -> Result<Vec<hlb_api::ActiveAlert>, ApiError> {
    s.privd()
        .ask(hlb_api::intent::Alerts {})
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))
}

/// The gaps reconciliation's last pass left.
///
/// ⚠️ Unanswered is an error, never "no gap": the inbox would say nothing needs anyone
/// while the daemon that knows could not be asked.
pub(crate) async fn drifts_now(s: &AppState) -> Result<Vec<hlb_api::DriftSummary>, ApiError> {
    s.privd()
        .ask(hlb_api::intent::Drifts {})
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))
}

/// A time series, relayed to VictoriaMetrics.
///
/// 🔴 **Always** returns `200` with an [`hlb_api::Series`], even on a problem: an
/// unreachable time-series database is not a controller outage, it is information to
/// display. Returning `503` would force every screen to handle two shapes of failure —
/// and the second would end up showing an empty curve.
#[utoipa::path(
    get,
    path = "/api/v1/metrics/series",
    params(SeriesQuery),
    responses(
        (status = 200, body = hlb_api::Series)
    ),
    extensions(
        ("x-hlb-requires" = json!("read")),
        ("x-hlb-client" = json!("none in this repository — `Series` is the thing to wire a chart to on the day cadvisor is in the catalog, and ROADMAP carries the measurement that says it is not"))
    )
)]
async fn series(
    _auth: Authorized<CanRead>,
    AxumState(s): AxumState<Arc<AppState>>,
    Query(q): Query<SeriesQuery>,
) -> Json<hlb_api::Series> {
    let Some(m) = &s.series else {
        return Json(hlb_api::Series::Unavailable {
            reason: "no time-series database configured. Start the controller with \
                     --metrics-url, after \"hlb install victoriametrics --apply\""
                .into(),
        });
    };

    // The ratio by default: it is the shape of most of our metrics.
    let unit = q.unit.unwrap_or(hlb_api::Unit::Ratio);

    Json(
        m.range(
            &q.q,
            q.since.unwrap_or(3_600),
            q.step.unwrap_or(60),
            unit,
            crate::auth::now(),
        )
        .await,
    )
}

#[derive(serde::Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
struct SeriesQuery {
    q: String,
    /// Depth in seconds. Default: one hour.
    since: Option<i64>,
    /// Sampling step in seconds. Default: one minute.
    step: Option<i64>,
    /// ⚠️ The type the answer carries, not a second spelling of it: this parameter
    /// accepted `octets_par_seconde` and `secondes` while the series it answered said
    /// `bytespersecond` and `seconds`, so a client echoing a unit back got a ratio.
    unit: Option<hlb_api::Unit>,
}

/// The installation's visual identity.
///
/// 🔴 **Without authentication, deliberately.** The sign-in screen must carry the house
/// name and colours: that is what distinguishes a legitimate page from a phishing page.
/// Requiring a token to read it would make the sign-in screen anonymous, so exactly the
/// one an attacker knows how to imitate.
///
/// What leaks is the house name and a colour — what is shown to anyone who opens the
/// page anyway. No operational data goes through here.
#[utoipa::path(
    get,
    path = "/api/appearance",
    responses(
        (status = 200, body = hlb_api::Brand)
    ),
    extensions(
        ("x-hlb-public" = json!(true))
    )
)]
async fn appearance(AxumState(s): AxumState<Arc<AppState>>) -> ApiResult<hlb_api::Brand> {
    Ok(Json(s.state.brand().await?))
}

/// The logo, as PNG — an uploaded SVG was rasterised on the way in.
#[utoipa::path(
    get,
    path = "/api/appearance/logo",
    responses(
        (status = 200, content_type = "image/png", body = crate::openapi::Binary)
    ),
    extensions(
        ("x-hlb-public" = json!(true))
    )
)]
async fn appearance_logo(AxumState(s): AxumState<Arc<AppState>>) -> Result<Response, ApiError> {
    match s.state.logo().await? {
        Some(png) => Ok((
            [
                (axum::http::header::CONTENT_TYPE, "image/png"),
                // One hour: enough not to re-download it on every screen, little enough
                // that a logo change shows the same day.
                (axum::http::header::CACHE_CONTROL, "public, max-age=3600"),
            ],
            png,
        )
            .into_response()),
        // 404 rather than an empty image: the interface then paints its monogram,
        // instead of a transparent rectangle you would take for a bug.
        None => Err(ApiError::NotFound("no logo".into())),
    }
}

/// An application's brand logo, in PNG.
///
/// 🔴 Unauthenticated, like `appearance_logo` and for a weaker version of the same
/// reason: it is decoration. What leaks is which applications this catalog offers —
/// which is the catalog, shipped with the source, identical on every installation.
/// Nothing about what is INSTALLED here goes through it.
///
/// The icon lives beside the manifest it belongs to, so adding an application is adding
/// one folder — wherever the catalog read it from: `catalog/apps`, `_platform`, or the
/// official index's cache, which carries each version's files.
#[utoipa::path(
    get,
    path = "/api/catalog/{name}/icon",
    responses(
        (status = 200, content_type = "image/png", body = crate::openapi::Binary)
    ),
    extensions(
        ("x-hlb-public" = json!(true))
    )
)]
async fn catalog_icon(
    AxumState(s): AxumState<Arc<AppState>>,
    Path(name): Path<String>,
) -> Result<Response, ApiError> {
    // 🔴 The name comes from the URL and is about to become a path. It is not
    // sanitised, it is REFUSED unless it has the shape a catalog folder name may take:
    // stripping `..` and `/` handles the two tricks you thought of, an allowlist handles
    // the ones you did not. `hlb catalog validate` already holds manifest names to this
    // same shape, so nothing legitimate is turned away.
    let plausible = !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    if !plausible {
        return Err(ApiError::NotFound("no icon".into()));
    }

    let path = s.catalog.get().and_then(|c| catalog_icon_path(&c, &name));
    if let Some(path) = path {
        if let Ok(png) = tokio::fs::read(&path).await {
            return Ok((
                [
                    (axum::http::header::CONTENT_TYPE, "image/png"),
                    // An application's mark changes about never; an hour still means a
                    // replaced logo shows up the same day.
                    (axum::http::header::CACHE_CONTROL, "public, max-age=3600"),
                ],
                png,
            )
                .into_response());
        }
    }

    // 404 rather than a placeholder image: the interface paints a monogram instead,
    // which reads better than a generic grey square. It knows beforehand, from
    // `CatalogItem.icon`, and never asks for an icon that is not there.
    Err(ApiError::NotFound("no icon".into()))
}

/// Where an application's icon is, if it has one — what both the icon route and the
/// catalog listing's `icon` read, so the listing cannot promise an icon the route
/// would refuse.
pub(crate) fn catalog_icon_path(
    catalog: &hlb_catalog::Catalog,
    name: &str,
) -> Option<std::path::PathBuf> {
    // The official catalog's alone: a third-party source's logo is its owner's to
    // vouch for, and a bare name is the official app's whatever a source holds.
    let e = catalog.get(name).ok().filter(|e| e.source.is_none())?;
    Some(e.path.parent()?.join("icon.png")).filter(|p| p.is_file())
}

/// Every theme a person may pick — the shipped ones, then the installation's — painted
/// as they will be, brand accent included.
///
/// 🔴 Unauthenticated, like `appearance` and for the same reason: the sign-in screen
/// must be able to look like the house. What leaks is a palette.
///
/// ⚠️ The shipped ones too, since 2026-10-05. Under egui they were compiled into the
/// interface and serving them would have made a second copy; a browser has no copy, and
/// a theme the API does not serve is a name in Settings that paints nothing.
#[utoipa::path(
    get,
    path = "/api/themes",
    responses(
        (status = 200, body = Vec<hlb_api::Theme>)
    ),
    extensions(
        ("x-hlb-public" = json!(true))
    )
)]
async fn themes(AxumState(s): AxumState<Arc<AppState>>) -> ApiResult<Vec<hlb_api::Theme>> {
    let accent = s.state.brand().await?.accent;
    let shipped = hlb_api::THEMES
        .iter()
        .filter_map(|n| hlb_api::Theme::shipped(n, accent));
    let declared = s
        .custom_themes
        .iter()
        .filter_map(|t| hlb_api::Theme::declared(t, accent));
    Ok(Json(shipped.chain(declared).collect()))
}

/// The typeface a theme names, served out of the themes directory.
///
/// 🔴 Unauthenticated, like [`themes`] and `appearance`: the sign-in screen is drawn
/// before anyone has a session, and it must be drawn in the house's letters. What leaks
/// is a font file the installation put there on purpose.
///
/// ⚠️ The name is re-validated HERE, not trusted because the loader accepted it. The
/// loader runs at startup on a file; this runs on a URL, and the two are the same string
/// only as long as nothing else ever writes a theme into the state. `face_problem` is
/// the one spelling of the rule, called from both ends.
#[utoipa::path(
    get,
    path = "/api/themes/{name}/font/{family}",
    responses(
        (status = 200, content(
            (crate::openapi::Binary = "font/woff2"),
            (crate::openapi::Binary = "font/woff"),
            (crate::openapi::Binary = "font/ttf"),
            (crate::openapi::Binary = "font/otf")
        ))
    ),
    extensions(
        ("x-hlb-public" = json!(true)),
        ("x-hlb-client" = json!("the interface, never by name: each theme served by `/api/themes` carries this route as its `typeface_url`, and `web/src/lib/theme.ts` loads whatever URL the server wrote there"))
    )
)]
async fn theme_font(
    AxumState(s): AxumState<Arc<AppState>>,
    Path((name, family)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let no_typeface = || ApiError::NotFound("no such typeface".into());
    let Some(family) = hlb_api::FontFamilyKind::parse(&family) else {
        return Err(ApiError::NotFound("no such font family".into()));
    };
    let Some(theme) = s
        .custom_themes
        .iter()
        .find(|t| t.name.eq_ignore_ascii_case(&name))
    else {
        return Err(ApiError::NotFound("no such theme".into()));
    };
    let Some(face) = theme.face(family) else {
        // Not an error: most themes name no face and the interface asks anyway.
        return Err(ApiError::NotFound("this theme names no typeface".into()));
    };
    if hlb_api::CustomTheme::face_problem(face).is_some() {
        return Err(no_typeface());
    }

    let Some(mime) = hlb_api::CustomTheme::face_mime(face) else {
        return Err(no_typeface());
    };

    match tokio::fs::read(s.themes_dir.join(face)).await {
        Ok(bytes) => Ok((
            [
                (axum::http::header::CONTENT_TYPE, mime),
                // A theme's face changes about never; an hour still means a replaced
                // file shows up the same day. `catalog_icon`'s reasoning, and its number.
                (axum::http::header::CACHE_CONTROL, "public, max-age=3600"),
            ],
            bytes,
        )
            .into_response()),
        Err(_) => Err(no_typeface()),
    }
}

/// Changes the visual identity.
#[utoipa::path(
    put,
    path = "/api/appearance",
    request_body = hlb_api::Brand,
    responses(
        (status = 200, body = hlb_api::Brand)
    ),
    extensions(
        ("x-hlb-requires" = json!("operate")),
        ("x-hlb-preview" = json!(false))
    )
)]
async fn change_appearance(
    auth: Authorized<CanOperate>,
    AxumState(s): AxumState<Arc<AppState>>,
    Json(m): Json<hlb_api::Brand>,
) -> ApiResult<hlb_api::Brand> {
    if m.name.trim().is_empty() || m.product.trim().is_empty() {
        return Err(ApiError::Unprocessable(
            "the house name and the product name cannot be empty — the header would \
             become a white space you would take for a loading defect"
                .into(),
        ));
    }

    // 🔴 Checked against every theme the accent can land on: shipped and declared. The
    // brand colours everybody's interface, whatever theme each person picked.
    let shipped = hlb_api::THEMES
        .iter()
        .filter_map(|n| hlb_api::palette::Palette::shipped(n).map(|p| (*n, p)));
    let declared = s
        .custom_themes
        .iter()
        .filter_map(|t| t.palette().map(|p| (t.name.as_str(), p)));
    let problems = m.accent_problems(shipped.chain(declared));
    if !problems.is_empty() {
        return Err(ApiError::Unprocessable(problems.join("; ")));
    }

    s.record(hlb_api::intent::SetBrand { brand: m.clone() })
        .await
        .map_err(ApiError::Internal)?;

    let _ = s
        .append_audit(
            auth.actor().name(),
            auth.identity().role,
            "appearance",
            &m.name,
            "ok",
            Some(&format!("brand \"{} · {}\"", m.product, m.name)),
        )
        .await;

    Ok(Json(m))
}

/// Uploads a logo — PNG or SVG, the latter rasterized server-side by `set_logo`. An
/// empty body removes it.
#[utoipa::path(
    post,
    path = "/api/appearance/logo",
    request_body(content((crate::openapi::Binary = "image/png"), (crate::openapi::Binary = "image/svg+xml"))),
    responses(
        (status = 204, description = "Set, or removed when the body was empty")
    ),
    extensions(
        ("x-hlb-requires" = json!("operate")),
        ("x-hlb-preview" = json!(false))
    )
)]
async fn upload_logo(
    auth: Authorized<CanOperate>,
    AxumState(s): AxumState<Arc<AppState>>,
    crate::extract::Bytes(body): crate::extract::Bytes,
) -> Result<StatusCode, ApiError> {
    let removal = body.is_empty();
    let logo = if removal { None } else { Some(body.as_ref()) };

    // Prepared HERE — format detection, SVG rasterization, size — so an uploaded SVG
    // is parsed by the side holding no privilege, and its `LogoError` maps to the right
    // HTTP status rather than a generic 500.
    let png = match logo.map(hlb_state::prepare_logo).transpose() {
        Ok(png) => png,
        Err(e @ hlb_state::LogoError::TooLarge { .. }) => {
            return Err(ApiError::PayloadTooLarge(e.to_string()))
        }
        Err(
            e @ (hlb_state::LogoError::UnrecognisedFormat
            | hlb_state::LogoError::InvalidSvg(_)
            | hlb_state::LogoError::RasterizeFailed(_)),
        ) => return Err(ApiError::UnsupportedMediaType(e.to_string())),
    };
    s.record(hlb_api::intent::SetLogo { png })
        .await
        .map_err(ApiError::Internal)?;

    let _ = s
        .append_audit(
            auth.actor().name(),
            auth.identity().role,
            "appearance-logo",
            "logo",
            "ok",
            Some(if removal { "removed" } else { "set" }),
        )
        .await;

    Ok(StatusCode::NO_CONTENT)
}

/// Creates a disposable alias, in the format Bitwarden / addy.io expects.
///
/// 🔴 The request must act FOR someone. Two ways: a token bound to an account, or a
/// signed-in person. A service token — an operations script's — is not entitled to act
/// on anyone's behalf, **even in the admin role**: otherwise stealing it would grant the
/// power to create addresses on anyone's mailbox. Privilege does not replace identity.
/// identity.
#[utoipa::path(
    post,
    path = "/api/v1/aliases",
    request_body = hlb_users::CreationRequest,
    responses(
        (status = 201, body = hlb_users::AliasCreated)
    ),
    extensions(
        ("x-hlb-requires" = json!("act-on-self")),
        ("x-hlb-preview" = json!(false))
    )
)]
async fn create_alias(
    auth: Authorized<CanActOnSelf>,
    AxumState(s): AxumState<Arc<AppState>>,
    Json(request): Json<hlb_users::CreationRequest>,
) -> Result<(StatusCode, Json<hlb_users::AliasCreated>), ApiError> {
    // ⚠️ The targeted mailbox only lives on the TOKEN: the addy.io protocol has no field
    // for choosing it. A signed-in person therefore has none, and gets their default
    // mailbox — which is the expected behaviour from an interface where they can
    // choose one explicitly.
    let (account_user, targeted_mailbox) = match auth.actor() {
        crate::auth::Actor::Token { name, .. } => {
            s.state.token_target(name).await.unwrap_or((None, None))
        }
        crate::auth::Actor::Person { user } => (Some(user.clone()), None),
        crate::auth::Actor::Anonymous => (None, None),
    };

    let Some(user) = account_user else {
        return Err(ApiError::Forbidden(
            "this request acts on nobody's behalf. Bind the token to an account — \
             \"hlb token create <name> --role user --user <account>\" — or sign in: \
             a service token cannot create an alias on someone's behalf"
                .into(),
        ));
    };

    let description = request.description.clone().unwrap_or_default();
    let address = s
        .privd()
        .ask(hlb_api::intent::CreateAlias {
            account: user,
            mailbox: targeted_mailbox,
            domain: request.domain,
            description: request.description,
        })
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?
        .map_err(|r| match r {
            hlb_api::intent::Refusal::Conflict(m) => ApiError::Conflict(m),
            hlb_api::intent::Refusal::Unprocessable(m) => ApiError::Unprocessable(m),
            hlb_api::intent::Refusal::TooMany(m) => ApiError::TooMany(m),
            hlb_api::intent::Refusal::Internal(m) => ApiError::Internal(m),
        })?;

    // 201: Bitwarden accepts 200 as well as 201, and 201 is the right code for a
    // creation.
    Ok((
        StatusCode::CREATED,
        Json(hlb_users::AliasCreated::new(address, description)),
    ))
}

#[derive(serde::Deserialize, utoipa::ToSchema)]
struct CreateMailboxRequest {
    local: String,
}

/// Creates the SIGNED-IN account's own mailbox — the self-service replacement for the
/// CLI hint (`hlb user mailbox add <account> <local>`) `my_mailbox.rs` used to show to
/// someone who has no terminal to run it from.
///
/// Order mirrors `hlb user mailbox add` exactly (`MailboxCmd::Add` in
/// `hlb-cli/src/main.rs`): quota check → Stalwart-configured check (refuse, never
/// stub) → `ensure_account` → `add_mailbox`, never reversed — the same
/// half-created-account fix `hlb user mailbox add` already got on 2026-08-23.
///
/// ⚠️ Answers `ActionResult` (`hlb_api`), unlike `create_alias`'s custom shape:
/// the interface parses an action's response body as `ActionResult`, the type the
/// schema declares for it. A raw `{"error": ...}` here would be invisible in the very UI this route
/// exists to serve. `create_alias`'s shape is
/// dictated by the addy.io/Bitwarden contract instead (see CLAUDE.md) — a constraint
/// this route does not share, so it follows `purge_my_alias`/`disable_my_alias`'s
/// idiom instead: always 200, `applied`/`blockers` carry the real outcome.
#[utoipa::path(
    post,
    path = "/api/me/mailbox",
    request_body = CreateMailboxRequest,
    responses(
        (status = 200, body = hlb_api::ActionResult),
        (status = 422, description = "Nothing could be planned: the body's `blockers` say why", body = hlb_api::ActionResult)
    ),
    extensions(
        ("x-hlb-requires" = json!("act-on-self")),
        ("x-hlb-preview" = json!(false))
    )
)]
async fn create_my_mailbox(
    auth: Authorized<CanActOnSelf>,
    AxumState(s): AxumState<Arc<AppState>>,
    Json(request): Json<CreateMailboxRequest>,
) -> ActionReply {
    let answer = s
        .privd()
        .ask(hlb_api::intent::CreateMailbox {
            account: auth.identity().actor.for_account().map(str::to_string),
            local: request.local,
        })
        .await
        .map_err(crate::actions::privd_error)?;
    let r = match answer {
        hlb_api::intent::Acted::Planned(r) => r,
        hlb_api::intent::Acted::Unplannable(m) => return Err(ApiError::Internal(m).into()),
    };
    Ok(Json(r))
}

/// Every route of the API, and the document that describes it.
///
/// 🔴 One `routes!` per handler and nothing else: the path comes from the handler's own
/// `#[utoipa::path]`, so the router and the document cannot disagree, and the invariant
/// tests — which walk the document, since axum cannot enumerate its router — see every
/// route this serves. A route added with a bare `.route(` would escape them all: the
/// test refusing anonymous callers, the one requiring a role, the one requiring a
/// preview.
pub fn api() -> OpenApiRouter<Arc<AppState>> {
    OpenApiRouter::with_openapi(crate::openapi::ApiDoc::openapi())
        // ⚠️ Open: it is Swarm's probe.
        .routes(routes!(healthz))
        .routes(routes!(list_apps))
        .routes(routes!(get_app, crate::actions::delete_app))
        .routes(routes!(list_todo))
        // Names and purposes only — never the values, not even behind the API.
        .routes(routes!(list_secrets))
        .routes(routes!(list_audit))
        .routes(routes!(prometheus))
        // Who am I: the interface's first request, and it is what decides which screens
        // to show.
        .routes(routes!(crate::signin::me))
        .routes(routes!(crate::signin::my_aliases))
        .routes(routes!(crate::me::my_identity, crate::me::change_my_names))
        .routes(routes!(crate::me::choose_default_mailbox))
        .routes(routes!(
            crate::me::my_sessions,
            crate::me::close_my_other_sessions
        ))
        .routes(routes!(crate::me::close_my_session))
        .routes(routes!(crate::me::my_devices, crate::me::add_my_device))
        .routes(routes!(crate::me::revoke_my_device))
        // Sign-in: these two routes are necessarily open — you cannot require
        // authentication of someone who is coming to authenticate.
        .routes(routes!(crate::signin::start))
        .routes(routes!(crate::signin::return_to))
        .routes(routes!(crate::passkey::passkey_returned))
        .routes(routes!(crate::signin::signout))
        // 🔴 Open: the sign-in screen must carry the house name and colours, or it
        // looks like every phishing page in the world.
        .routes(routes!(appearance, change_appearance))
        .routes(routes!(appearance_logo, upload_logo))
        .routes(routes!(catalog_icon))
        .routes(routes!(themes))
        .routes(routes!(theme_font))
        .routes(routes!(series))
        .routes(routes!(crate::history::history))
        .routes(routes!(alerts))
        .routes(routes!(crate::mutes::mute, crate::mutes::unmute))
        .routes(routes!(nodes))
        .routes(routes!(node_detail))
        .routes(routes!(crate::actions::node_availability))
        .routes(routes!(tasks))
        .routes(routes!(topology))
        .routes(routes!(crate::actions::catalog))
        .routes(routes!(crate::accounts::list))
        .routes(routes!(crate::accounts::change_role))
        .routes(routes!(crate::accounts::change_roles))
        .routes(routes!(crate::roles::access))
        .routes(routes!(crate::roles::sync_access))
        .routes(routes!(crate::roles::put_role, crate::roles::delete_role))
        .routes(routes!(crate::roles::role_quota))
        .routes(routes!(crate::roles::allow_role, crate::roles::deny_role))
        .routes(routes!(crate::roles::person_quota))
        .routes(routes!(
            crate::accounts::invitations,
            crate::accounts::create_invitation
        ))
        .routes(routes!(crate::accounts::revoke_invitation))
        // 🔴 WITHOUT authentication: it is the invited person who calls, and they do
        // not have an account yet. The invitation IS the authorization, and its
        // consumption is atomic.
        .routes(routes!(crate::accounts::signup))
        .routes(routes!(crate::portal::portal))
        .routes(routes!(
            crate::portal::announcements,
            crate::portal::publish
        ))
        .routes(routes!(crate::portal::remove))
        .routes(routes!(crate::portal::follow_up))
        .routes(routes!(crate::portal::private_status))
        .routes(routes!(crate::issues::issues))
        .routes(routes!(crate::issues::set_aside, crate::issues::bring_back))
        .routes(routes!(crate::portal::preferences))
        .routes(routes!(crate::portal::change_theme))
        .routes(routes!(crate::portal::arrange_home))
        .routes(routes!(crate::portal::change_density))
        // 🔴 Without authentication, and served ONLY if `--status-public`. The handler
        // refuses by itself otherwise, saying how to open it rather than letting you
        // believe in an outage.
        .routes(routes!(crate::portal::status))
        .routes(routes!(backups))
        .routes(routes!(coverage))
        .routes(routes!(app_detail))
        .routes(routes!(drifts))
        .routes(routes!(exposure))
        .routes(routes!(domain))
        .routes(routes!(installation_health))
        .routes(routes!(timeline))
        .routes(routes!(secret_rotation))
        .routes(routes!(breakglass))
        .routes(routes!(crate::recovery::attest))
        .routes(routes!(runbook))
        .routes(routes!(
            crate::actions::list_plans,
            crate::actions::record_plan
        ))
        .routes(routes!(export_csv))
        .routes(routes!(manifest_versions))
        .routes(routes!(crate::actions::install_app))
        .routes(routes!(crate::actions::upgrade_app))
        .routes(routes!(crate::actions::resize))
        .routes(routes!(crate::actions::backup_run))
        .routes(routes!(crate::actions::destination))
        .routes(routes!(crate::actions::check_guide))
        .routes(routes!(crate::bitwarden::assistant))
        .routes(routes!(create_my_mailbox))
        // 🔴 An addy.io-compatible API: it is BITWARDEN that imposes this route and this
        // shape, read from its source. See `hlb_users::forwarder`.
        .routes(routes!(create_alias))
        .routes(routes!(crate::actions::purge_my_alias))
        .routes(routes!(crate::actions::disable_my_alias))
}

pub fn router(state: Arc<AppState>) -> Router {
    let (api, _) = api().split_for_parts();
    // The document describes the routes above, not itself: it is read by the build
    // that generates the client, never by a screen.
    api.route("/api/openapi.json", get(openapi_document))
        // ⚠️ Last: `/{*file}` catches everything left, including `/api/…` if it were
        // placed before. The UI would then mask the API without the slightest message.
        .route("/", get(ui_index))
        .route("/{*file}", get(ui_file))
        // 🔴 As a global layer rather than route by route: a route added tomorrow
        // inherits the limit without anyone having to think about it. The same
        // reasoning as the authorization extractor — what can be forgotten ends up
        // being forgotten.
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::signin::reissue,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            throttle,
        ))
        .with_state(state)
}

/// The OpenAPI document, built once.
async fn openapi_document() -> Json<&'static utoipa::openapi::OpenApi> {
    static DOCUMENT: std::sync::OnceLock<utoipa::openapi::OpenApi> = std::sync::OnceLock::new();
    Json(DOCUMENT.get_or_init(crate::openapi::document))
}

/// The rate-limiting layer.
async fn throttle(
    AxumState(s): AxumState<Arc<AppState>>,
    query: axum::extract::Request,
    suite: axum::middleware::Next,
) -> Response {
    // ⚠️ Read from the extensions rather than through an extractor: `ConnectInfo` is
    // only present if the server is mounted with `into_make_service_with_connect_info`,
    // and a mandatory extractor would make EVERY test request fail, since they have no
    // socket. Here its absence degrades precision, not the service.
    let pair = query
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|c| c.0.ip());

    if crate::throughput::exempt(query.method(), query.uri().path()) {
        return suite.run(query).await;
    }

    let class = crate::throughput::Class::of(query.method(), query.uri().path());
    let who = crate::throughput::client(query.headers(), pair, s.trusted_proxy);

    match s.throughput.check(&who, class, crate::auth::now()) {
        crate::throughput::Verdict::Allowed => suite.run(query).await,
        crate::throughput::Verdict::Refused { retry_after_s } => {
            tracing::warn!(client = %who, ?class, "rate exceeded");
            ApiError::RateLimited { retry_after_s }.into_response()
        }
    }
}

#[utoipa::path(
    get,
    path = "/healthz",
    responses(
        (status = 200, body = hlb_api::Health)
    ),
    extensions(
        ("x-hlb-public" = json!(true))
    )
)]
async fn healthz(AxumState(s): AxumState<Arc<AppState>>) -> Json<Health> {
    Json(Health {
        status: "ok".into(),
        version: s.version.to_string(),
        uptime_secs: s.started_at.elapsed().as_secs(),
        source: SOURCE.to_string(),
    })
}

/// The source of this build: `HLB_SOURCE` when it was compiled, else this version's tag
/// upstream. The image workflow names the exact commit, of whichever repository built it
/// — a fork's interface then points at the fork, not here, without anyone remembering to.
/// An empty one is a Docker `ARG` nobody passed, not a source.
const SOURCE: &str = match option_env!("HLB_SOURCE") {
    Some(source) if !source.is_empty() => source,
    _ => concat!(
        "https://github.com/Turi-Industries/Homelabus/tree/v",
        env!("CARGO_PKG_VERSION")
    ),
};

pub(crate) async fn summarise(
    s: &AppState,
    name: &str,
    status: String,
) -> Result<AppSummary, ApiError> {
    let m = s.state.app_manifest(name).await?;
    Ok(AppSummary {
        name: name.to_string(),
        status,
        image: m.spec.image.reference(),
        domain: s.state.app_domain(name).await?,
        last_backup_secs: s.state.backup_age(name).await?,
        holds_data: !s.state.backup_kinds(name).await?.is_empty(),
        last_verification_secs: s.state.seconds_since_last_verification(name).await?,
        blocking_guides: s.state.unverified_blocking(name).await? as i64,
    })
}

#[utoipa::path(
    get,
    path = "/api/apps",
    responses(
        (status = 200, body = Vec<AppSummary>)
    ),
    extensions(
        ("x-hlb-requires" = json!("read"))
    )
)]
async fn list_apps(
    _auth: Authorized<CanRead>,
    AxumState(s): AxumState<Arc<AppState>>,
) -> ApiResult<Vec<AppSummary>> {
    let mut out = Vec::new();
    for (name, status) in s.state.installed_apps().await? {
        out.push(summarise(&s, &name, status).await?);
    }
    Ok(Json(out))
}

#[utoipa::path(
    get,
    path = "/api/apps/{name}",
    responses(
        (status = 200, body = AppSummary)
    ),
    extensions(
        ("x-hlb-requires" = json!("read"))
    )
)]
async fn get_app(
    _auth: Authorized<CanRead>,
    AxumState(s): AxumState<Arc<AppState>>,
    Path(name): Path<String>,
) -> ApiResult<AppSummary> {
    let Some((_, status)) = s
        .state
        .installed_apps()
        .await?
        .into_iter()
        .find(|(n, _)| n == &name)
    else {
        return Err(ApiError::NotFound(format!("unknown app \"{name}\"")));
    };

    summarise(&s, &name, status).await.map(Json)
}

/// The app's jobs from its frozen manifest, each with its last run.
async fn jobs_of(state: &hlb_state::State, app: &str) -> Vec<hlb_api::jobs::JobState> {
    let Ok(m) = state.app_manifest(app).await else {
        return Vec::new();
    };
    let runs = state.job_runs().await.unwrap_or_default();
    m.spec
        .jobs
        .iter()
        .map(|j| {
            let last = runs.iter().find(|r| r.app == app && r.job == j.id);
            hlb_api::jobs::JobState {
                id: j.id.clone(),
                does: j.does.clone(),
                every: match j.every {
                    hlb_types::Period::Day => "day",
                    hlb_types::Period::Week => "week",
                }
                .into(),
                last_run_at: last.map(|r| r.ran_at),
                succeeded: last.map(|r| r.succeeded),
                output: last.map(|r| r.output.clone()).unwrap_or_default(),
                next_run_at: hlb_engine::jobs::next_run(j, last),
            }
        })
        .collect()
}

/// An application's full detail.
///
/// ## What is NOT here
///
/// 🔴 No secret value. The environment variables are returned **as they are in the
/// manifest**, tokens included (`{{ db.password }}`). That is deliberate: the value must
/// not cross the API, and a visible token says what the app is wired to — which
/// asterisks do not.
#[utoipa::path(
    get,
    path = "/api/apps/{name}/detail",
    responses(
        (status = 200, body = hlb_api::AppDetail)
    ),
    extensions(
        ("x-hlb-requires" = json!("read"))
    )
)]
async fn app_detail(
    _auth: Authorized<CanRead>,
    AxumState(s): AxumState<Arc<AppState>>,
    Path(name): Path<String>,
) -> ApiResult<hlb_api::AppDetail> {
    let Some((_, status)) = s
        .state
        .installed_apps()
        .await?
        .into_iter()
        .find(|(n, _)| n == &name)
    else {
        return Err(ApiError::NotFound(format!("unknown app \"{name}\"")));
    };

    let summary = summarise(&s, &name, status).await?;

    // ⚠️ The manifest FROZEN at deployment, not the current catalog's: it is what
    // is running we want to read, not what we would install today.
    let manifest = s.state.app_manifest(&name).await.ok();

    // Each source is optional: an error on one must not deprive you of the whole
    // screen. A half-filled detail stays useful; a 500 does not.
    let tasks = match swarm(&s, Some(&name)).await {
        Some(v) => task_summaries(&v),
        // ⚠️ The same precedent as the topology: without an orchestrator, the demo
        // fabricates tasks. Without them the causal chain would stop at the first link
        // everywhere, and the screen we want to write would be invisible.
        None if s.demo => crate::demo::tasks(&name),
        None => Vec::new(),
    };

    let coverage = {
        let source = crate::coverage::SourceState(&s.state);
        let c = hlb_backup::coverage_of(&source, &name, STALENESS_THRESHOLD_S).await;
        // An app holding nothing has no coverage to show: not "no destination", not
        // "never backed up".
        c.needs_backup().then(|| hlb_api::CoverageSummary {
            up_to_date_copies: c.up_to_date_copies(),
            per_destination: c
                .per_destination
                .iter()
                .map(|(name, state)| {
                    let age = match state {
                        hlb_backup::DestinationState::Never => None,
                        hlb_backup::DestinationState::Fresh { age_s }
                        | hlb_backup::DestinationState::Stale { age_s } => Some(*age_s),
                    };
                    (name.clone(), age)
                })
                .collect(),
            app: c.app,
        })
    };

    // 🔴 The sum nobody does in their head: RPO, copies, verification, drills and PITR
    // window reduced to a verdict and an ordered list of remedies.
    let restorability = Some(crate::coverage::in_summary(
        &crate::coverage::restorability(&s.state, &name, STALENESS_THRESHOLD_S).await,
    ));

    let detail = hlb_api::AppDetail {
        // Filled in just after: the causal chain needs the assembled detail.
        diagnostic: None,
        restorability,
        capabilities: manifest
            .as_ref()
            .map(|m| {
                m.spec
                    .requires
                    .iter()
                    .map(|c| hlb_api::Need::of(c, &name))
                    .collect()
            })
            .unwrap_or_default(),
        env: manifest
            .as_ref()
            .map(|m| {
                m.spec
                    .env
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect()
            })
            .unwrap_or_default(),
        image: manifest.as_ref().map(|m| m.spec.image.reference()),
        manifest: manifest
            .as_ref()
            .and_then(|m| serde_yaml_ng::to_string(m).ok()),
        volumes: s
            .state
            .app_volumes(&name)
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|(name, path, backup, sqlite)| hlb_api::VolumeSummary {
                name,
                path,
                backup,
                sqlite,
            })
            .collect(),
        guides: s
            .state
            .pending_guides()
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|(app, ..)| app == &name)
            .map(|(app, id, title, blocking)| GuideItem {
                app,
                id,
                title,
                blocking,
            })
            .collect(),
        backups: s
            .state
            .backup_history(&name, 50)
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|r| hlb_api::BackupRun {
                id: r.id,
                app: r.app,
                kind: r.kind,
                destination: r.destination,
                succeeded: r.status == "ok",
                error: r.error,
                when: r.finished_at,
            })
            .collect(),
        journal: s
            .state
            .audit_for(&name, 30)
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|e| AuditItem {
                id: e.id,
                at: e.at,
                actor: e.actor,
                role: e.role,
                action: e.action,
                target: e.target,
                outcome: e.outcome,
                detail: e.detail,
            })
            .collect(),
        domain: s.state.app_domain(&name).await.ok().flatten(),
        catalog_changes: crate::actions::catalog_changes(&s, &name).await,
        assertions: crate::assertions::of_app(&s.state, &name, crate::auth::now()).await,
        jobs: jobs_of(&s.state, &name).await,
        coverage,
        tasks,
        summary,
    };

    // 🔴 The causal chain: the server is the only one that sees the tasks, the nodes and
    // the alerts at the same time. The interface shows them on three screens and cannot
    // make the link — which is exactly what separates a dashboard from a
    // diagnostic.
    let diagnostic =
        hlb_api::diagnostic::explain(&detail, &nodes_summary(&s).await, &active_alerts(&s).await?);

    Ok(Json(hlb_api::AppDetail {
        diagnostic: Some(diagnostic),
        ..detail
    }))
}

#[utoipa::path(
    get,
    path = "/api/todo",
    responses(
        (status = 200, body = Vec<GuideItem>)
    ),
    extensions(
        ("x-hlb-requires" = json!("read"))
    )
)]
async fn list_todo(
    _auth: Authorized<CanRead>,
    AxumState(s): AxumState<Arc<AppState>>,
) -> ApiResult<Vec<GuideItem>> {
    Ok(Json(
        s.state
            .pending_guides()
            .await?
            .into_iter()
            .map(|(app, id, title, blocking)| GuideItem {
                app,
                id,
                title,
                blocking,
            })
            .collect(),
    ))
}

#[derive(Debug, Default, serde::Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
struct AuditQuery {
    /// Words that must all appear in the actor, action, target or detail.
    q: Option<String>,
    /// `ok`, `refused` or `failed`.
    outcome: Option<String>,
    /// From 1, the newest first.
    page: Option<u64>,
}

/// A limit that is none: an export is the whole record, or it is a sample.
const EVERYTHING: usize = i64::MAX as usize;

/// Entries an audit page holds.
const AUDIT_PAGE: u64 = 50;

/// The audit log, a page at a time, newest first.
///
/// 🔴 Searched HERE, not in the browser: the log only grows, and the hundred entries it
/// used to send whole were cut without a word — a search over them could not find last
/// month.
#[utoipa::path(
    get,
    path = "/api/audit",
    params(AuditQuery),
    responses(
        (status = 200, body = hlb_api::AuditPage)
    ),
    extensions(
        ("x-hlb-requires" = json!("read"))
    )
)]
async fn list_audit(
    _auth: Authorized<CanRead>,
    AxumState(s): AxumState<Arc<AppState>>,
    Query(q): Query<AuditQuery>,
) -> ApiResult<hlb_api::AuditPage> {
    let words: Vec<String> =
        q.q.as_deref()
            .unwrap_or("")
            .split_whitespace()
            .map(str::to_string)
            .collect();
    let outcome = q.outcome.as_deref().filter(|o| !o.is_empty());
    let page = q.page.unwrap_or(1).max(1);
    let (entries, matched, total) = s
        .state
        .audit_search(
            &words,
            outcome,
            ((page - 1) * AUDIT_PAGE) as usize,
            AUDIT_PAGE as usize,
        )
        .await?;
    Ok(Json(hlb_api::AuditPage {
        entries: entries
            .into_iter()
            .map(|e| AuditItem {
                id: e.id,
                at: e.at,
                actor: e.actor,
                role: e.role,
                action: e.action,
                target: e.target,
                outcome: e.outcome,
                detail: e.detail,
            })
            .collect(),
        matched,
        total,
        page_size: AUDIT_PAGE,
    }))
}

/// Exposition Prometheus.
///
/// Plain text, not JSON: it is the exposure format collectors expect.
#[utoipa::path(
    get,
    path = "/metrics",
    responses(
        (status = 200, content_type = "text/plain; version=0.0.4", body = String)
    ),
    extensions(
        ("x-hlb-requires" = json!("read"))
    )
)]
async fn prometheus(
    _auth: Authorized<CanRead>,
    AxumState(s): AxumState<Arc<AppState>>,
) -> Result<Response, ApiError> {
    let mut apps = Vec::new();

    for (name, status) in s.state.installed_apps().await? {
        // 🔴 An app whose state cannot be read must not make the WHOLE batch fail: the
        // collector would also lose the others' metrics, and one app's failure would
        // make the whole supervision blind.
        // The oldest of what the app holds — its volumes, its dumps — never the newest
        // row of any kind: a dump every pass hid volumes no longer backed up.
        let (b, v, g) = (
            s.state.backup_age(&name).await.ok().flatten(),
            s.state
                .seconds_since_last_verification(&name)
                .await
                .ok()
                .flatten(),
            s.state.unverified_blocking(&name).await.unwrap_or(0),
        );
        apps.push(AppMetrics {
            name,
            status,
            last_backup_secs: b,
            last_verification_secs: v,
            blocking_guides: g as i64,
        });
    }

    // The real backup coverage: it is what carries `hlb_backup_copies`, the 3-2-1 number
    // the `single-copy` rule expected and that existed
    // part.
    let coverages = crate::coverage::all_of_them(&s.state, STALENESS_THRESHOLD_S).await;

    let nodes = fleet_now(&s).await;
    Ok((
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        metrics::render_with_coverage(&apps, &nodes, &coverages),
    )
        .into_response())
}

/// Past this, a backup no longer counts as an up-to-date copy.
///
/// Twelve hours: the target interval is four hours, and three missed cycles mean
/// something is broken.
pub const STALENESS_THRESHOLD_S: i64 = 12 * 3_600;

#[utoipa::path(
    get,
    path = "/api/secrets",
    responses(
        (status = 200, body = Vec<SecretItem>)
    ),
    extensions(
        ("x-hlb-requires" = json!("read"))
    )
)]
async fn list_secrets(
    _auth: Authorized<CanRead>,
    AxumState(s): AxumState<Arc<AppState>>,
) -> ApiResult<Vec<SecretItem>> {
    Ok(Json(
        s.state
            .secret_names()
            .await?
            .into_iter()
            .map(|(name, purpose)| SecretItem { name, purpose })
            .collect(),
    ))
}

#[cfg(test)]
pub(crate) mod tests {
    /// A source's string literals, comments excluded.
    ///
    /// ⚠️ A state machine, not a split on `//`: the split cut `"https://"` in half, and
    /// every quote after it in the file was read the wrong way round — which the
    /// directory walk below found in `signin.rs` the day it started reading it.
    fn strings_of(source: &str) -> Vec<String> {
        let mut out = Vec::new();
        let mut current = String::new();
        let mut inside = false;
        let mut chars = source.chars().peekable();

        while let Some(c) = chars.next() {
            if inside {
                match c {
                    '\\' => {
                        chars.next();
                    }
                    '"' => {
                        out.push(std::mem::take(&mut current));
                        inside = false;
                    }
                    _ => current.push(c),
                }
                continue;
            }
            match c {
                '/' if chars.peek() == Some(&'/') => {
                    for c in chars.by_ref() {
                        if c == '\n' {
                            break;
                        }
                    }
                }
                // `'"'` is a character, not the start of a string; `'a` is a lifetime.
                '\'' => {
                    let mut look = chars.clone();
                    match (look.next(), look.next()) {
                        (Some('\\'), _) => {
                            chars.next();
                            chars.next();
                            chars.next();
                        }
                        (Some(_), Some('\'')) => {
                            chars.next();
                            chars.next();
                        }
                        _ => {}
                    }
                }
                '"' => inside = true,
                _ => {}
            }
        }
        out
    }

    /// A request as `lena`, a person — not the service token a test app stands for.
    async fn as_lena(
        st: &Arc<State>,
        verb: &str,
        uri: &str,
        body: &str,
    ) -> (StatusCode, serde_json::Value) {
        let (value, token) = hlb_types::token::generate(
            "lena-laptop",
            hlb_types::Role::Admin,
            [5u8; hlb_types::token::TOKEN_BYTES],
        );
        st.store_token(&token).await.expect("token");
        st.set_token_user("lena-laptop", Some("lena"))
            .await
            .expect("binding");
        let mut s = base_state(st.clone(), false);
        s.demo = true;
        let response = router(Arc::new(s))
            .oneshot(
                Request::builder()
                    .method(verb)
                    .uri(uri)
                    .header("authorization", format!("Bearer {value}"))
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .expect("request"),
            )
            .await
            .expect("response");
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .expect("body");
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
        )
    }

    #[tokio::test]
    async fn a_line_set_aside_stays_listed_and_comes_back_worse() {
        let st = Arc::new(State::in_memory().await.expect("state"));
        st.upsert_user("lena", "unlimited", None)
            .await
            .expect("user");
        st.upsert_destination("nas", "/mnt/nas/restic", "critical,bulky", None)
            .await
            .expect("destination");
        st.upsert_app("garage", &manifest("gitea"), None)
            .await
            .expect("app");
        st.add_volume("garage", "garage-data", "/data", true, false)
            .await
            .expect("volume");
        st.set_app_status("garage", "running")
            .await
            .expect("status");
        let never = r#"{"cause":{"kind":"never_backed_up"},"for_s":86400}"#;

        let (status, v) = as_lena(&st, "PUT", "/api/issues/aside", never).await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{v}");
        let (_, issues) = as_lena(&st, "GET", "/api/issues", "").await;
        let line = |v: &serde_json::Value| {
            v.as_array()
                .expect("issues")
                .iter()
                .find(|i| i["cause"]["kind"] == "never_backed_up")
                .cloned()
                .expect("the line is still listed")
        };
        assert!(line(&issues)["aside_until"].is_i64(), "{issues}");

        // A second application never backed up: not what was set aside.
        st.upsert_app("seafile", &manifest("gitea"), None)
            .await
            .expect("app");
        st.add_volume("seafile", "seafile-data", "/data", true, false)
            .await
            .expect("volume");
        st.set_app_status("seafile", "running")
            .await
            .expect("status");
        let (_, issues) = as_lena(&st, "GET", "/api/issues", "").await;
        assert!(line(&issues)["aside_until"].is_null(), "{issues}");

        // And a week is the most: one with no end is a problem deleted.
        let forever = r#"{"cause":{"kind":"never_backed_up"},"for_s":99999999}"#;
        let (status, _) = as_lena(&st, "PUT", "/api/issues/aside", forever).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn a_refused_attempt_leaves_a_trace() {
        // 🔴 Found by trying: a viewer attempting to DELETE an app received a 403 and
        // left no trace. Someone probing what they can destroy therefore went invisible
        // — which is exactly what an audit log exists to show.
        // ⚠️ The state is shared with the router: we keep a reference to re-read the log
        // AFTER the request, which the API would not allow a viewer to do.
        let st = Arc::new(State::in_memory().await.expect("state"));
        let (value, token) = hlb_types::token::generate(
            "obs",
            hlb_types::Role::Viewer,
            [7u8; hlb_types::token::TOKEN_BYTES],
        );
        st.store_token(&token).await.expect("token");

        let r = router(shared_state(st.clone(), false));

        let response = r
            .oneshot(
                axum::http::Request::builder()
                    .method("DELETE")
                    .uri("/api/apps/gitea?apply=true")
                    .header("authorization", format!("Bearer {value}"))
                    .body(axum::body::Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let journal = st.audit_trail(10).await.expect("journal");
        let refusal = journal
            .iter()
            .find(|e| e.outcome == "refused")
            .expect("the refusal must be logged");

        assert_eq!(refusal.actor, "obs");
        // ⚠️ "refused" and not "failed": the system protected, it did not break down.
        // Confusing them would send you looking for an incident where a guard worked.
        assert_ne!(refusal.outcome, "failed");
        assert!(
            refusal.target.contains("/api/apps/gitea"),
            "{}",
            refusal.target
        );
        assert!(
            refusal
                .detail
                .as_deref()
                .is_some_and(|d| d.contains("admin")),
            "the detail must name the required role"
        );
    }

    /// Every file the interface and the CLI are built from, concatenated.
    ///
    /// ⚠️ Every FILE, not every `.rs`. `/api/runbook` reaches a reader through
    /// `i18n/ftl/*/security.ftl` — the curl command the security screen prints — and a
    /// walk that filtered on the extension would report a live route as dead. Anything
    /// that does not read as UTF-8 is skipped rather than refused.
    ///
    /// 🔴 Except what is GENERATED and what only tests. The interface's `schema.d.ts`
    /// and `requires.ts` are made from the OpenAPI document and name every route in
    /// it: read as consumers, they vouch for all of them and the test can never fail. The
    /// generated paths are read from `web/.gitignore`, which is where they are declared
    /// generated, so a new generated file is skipped without being listed here.
    fn sources_under(dir: &std::path::Path, out: &mut String, files: &mut usize) {
        let web = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../web");
        let generated: Vec<std::path::PathBuf> = std::fs::read_to_string(web.join(".gitignore"))
            .unwrap_or_default()
            .lines()
            .filter_map(|l| l.strip_prefix("/src/"))
            .map(|l| web.join("src").join(l))
            .collect();
        walk_sources(dir, &generated, out, files);
    }

    fn walk_sources(
        dir: &std::path::Path,
        generated: &[std::path::PathBuf],
        out: &mut String,
        files: &mut usize,
    ) {
        for entry in std::fs::read_dir(dir).expect("client source directory") {
            let path = entry.expect("entry").path();
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default();
            if generated.iter().any(|g| path.starts_with(g)) || name.ends_with(".test.ts") {
                continue;
            }
            if path.is_dir() {
                walk_sources(&path, generated, out, files);
            } else if let Ok(text) = std::fs::read_to_string(&path) {
                out.push_str(&text);
                *files += 1;
            }
        }
    }

    /// Does a client ask for **this** route, and not merely for one below it?
    ///
    /// The route is matched WHOLE, template included: the interface writes
    /// `format!("/api/apps/{name}/detail")`, and Rust's inline captures put the
    /// template in the source exactly as the router spells it. Matching the part
    /// before the `{` instead — which this test did until 2026-08-28 — lets a longer
    /// sibling cover a shorter route, and `/api/apps/{name}` is precisely the route
    /// whose death started this test.
    ///
    /// ⚠️ It matches the path and NOT the method, so a `DELETE /api/apps/{name}` in a
    /// screen still vouches for the `GET`. Closing that means reading the method out of
    /// the caller's own struct, which is a different test's worth of fragility.
    fn requested(clients: &str, route: &str) -> bool {
        let mut from = 0;
        while let Some(hit) = clients[from..].find(route) {
            let after = from + hit + route.len();
            // A `/` here means the client asked for something UNDER this route.
            if !clients[after..].starts_with('/') {
                return true;
            }
            from = after;
        }
        false
    }

    #[tokio::test]
    async fn every_theme_is_served_painted_as_it_will_be() {
        // Under egui the three shipped palettes were compiled into the interface, and
        // this route served only the declared ones; a browser has no copy, so a shipped
        // theme the route left out would be a name in Settings that paints nothing.
        let d = tempfile::tempdir().expect("tmp");
        std::fs::write(d.path().join("Inter-Regular.ttf"), b"font bytes").expect("write");
        let st = State::in_memory().await.expect("state");
        let accent = [0x2E, 0x7D, 0x32];
        st.set_brand(&hlb_api::Brand {
            accent: Some(accent),
            ..Default::default()
        })
        .await
        .expect("brand");

        let mut app = shared_state(Arc::new(st), true);
        {
            let s = Arc::get_mut(&mut app).expect("sole owner");
            s.themes_dir = d.path().to_path_buf();
            s.custom_themes = vec![hlb_api::CustomTheme {
                // A space, which the font URL must survive.
                name: "Maison claire".into(),
                base: "light".into(),
                background: "#F4F6F9".into(),
                surface: "#FFFFFF".into(),
                raised_surface: "#EBEFF4".into(),
                border: "#D3DAE3".into(),
                text: "#14181D".into(),
                muted_text: "#56616E".into(),
                accent: "#4A46C7".into(),
                on_accent: "#FFFFFF".into(),
                ok: "#0FA484".into(),
                attention: "#7A5206".into(),
                critical: "#C02A46".into(),
                info: "#1C5CA8".into(),
                typeface: Some("Inter-Regular.ttf".into()),
                typeface_mono: None,
                scale: Some(1.2),
            }];
        }

        let (status, v) = get(router(app.clone()), "/api/themes").await;
        assert_eq!(status, StatusCode::OK, "{v}");
        let themes: Vec<hlb_api::Theme> = serde_json::from_value(v).expect("themes");
        let names: Vec<&str> = themes.iter().map(|t| t.name.as_str()).collect();
        let mut expected: Vec<&str> = hlb_api::THEMES.to_vec();
        expected.push("Maison claire");
        assert_eq!(names, expected);

        // The brand's accent on every one of them, with the text ON it chosen by the
        // palette rule rather than left to a stylesheet.
        for t in &themes {
            assert_eq!(t.colours.accent, "#2E7D32", "{}", t.name);
        }
        let dark = hlb_api::palette::Palette::shipped("Dark")
            .expect("shipped")
            .with_accent(accent);
        assert_eq!(
            themes[0].colours.on_accent,
            hlb_api::palette::hex(dark.on_accent)
        );

        let declared = &themes[3];
        assert!(!declared.shipped);
        assert_eq!(declared.base, hlb_api::palette::Base::Light);
        let url = declared.typeface_url.clone().expect("a face URL");
        assert_eq!(url, "/api/themes/Maison%20claire/font/proportional");
        assert_eq!(declared.typeface_mono_url, None);

        let font = router(app)
            .oneshot(
                Request::builder()
                    .uri(&url)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(
            font.status(),
            StatusCode::OK,
            "the URL served must be one that serves"
        );
    }

    #[tokio::test]
    async fn a_themed_typeface_is_served_and_a_path_is_not() {
        // 🔴 The name in the URL is about to become a path. `face_problem` is the one
        // spelling of the rule and it is called HERE too, not just by the loader: the
        // two see the same string only as long as nothing else ever writes a theme in.
        let d = tempfile::tempdir().expect("tmp");
        std::fs::write(d.path().join("Inter-Regular.ttf"), b"font bytes").expect("write");

        let st = State::in_memory().await.expect("state");
        let mut app = shared_state(Arc::new(st), true);
        {
            let s = Arc::get_mut(&mut app).expect("sole owner");
            s.themes_dir = d.path().to_path_buf();
            s.custom_themes = vec![hlb_api::CustomTheme {
                name: "Maison".into(),
                base: "dark".into(),
                background: "#0F1216".into(),
                surface: "#171B21".into(),
                raised_surface: "#1E242B".into(),
                border: "#2A323B".into(),
                text: "#E6EAEF".into(),
                muted_text: "#96A1AD".into(),
                accent: "#7B8CFF".into(),
                on_accent: "#0F1216".into(),
                ok: "#38C7B4".into(),
                attention: "#FFC94D".into(),
                critical: "#F05C5C".into(),
                info: "#7EA4F8".into(),
                typeface: Some("Inter-Regular.ttf".into()),
                typeface_mono: None,
                scale: None,
            }];
        }

        let get = async |app: Arc<AppState>, uri: &str| {
            router(app)
                .oneshot(
                    axum::http::Request::builder()
                        .uri(uri)
                        .body(axum::body::Body::empty())
                        .expect("request"),
                )
                .await
                .expect("response")
        };

        let ok = get(app.clone(), "/api/themes/Maison/font/proportional").await;
        assert_eq!(ok.status(), StatusCode::OK);
        assert_eq!(
            ok.headers()
                .get(axum::http::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("font/ttf"),
            "a proxy filtering on content type must be able to tell a font from a download"
        );

        // The family this theme does not name: a 404, not the other family's file.
        let none = get(app.clone(), "/api/themes/Maison/font/monospace").await;
        assert_eq!(none.status(), StatusCode::NOT_FOUND);

        // And the two shapes that must never reach the filesystem.
        for uri in [
            "/api/themes/Maison/font/serif",
            "/api/themes/Absente/font/proportional",
        ] {
            assert_eq!(
                get(app.clone(), uri).await.status(),
                StatusCode::NOT_FOUND,
                "{uri}"
            );
        }

        // 🔴 The reason the handler re-validates instead of trusting the loader: a theme
        // that reached the state WITHOUT passing through `themes::load` — which is what
        // this test itself does — must not turn the appearance API into a file reader.
        std::fs::write(d.path().join("secret.ttf"), b"not yours").expect("write");
        let st = State::in_memory().await.expect("state");
        let mut traversal = shared_state(Arc::new(st), true);
        {
            let s = Arc::get_mut(&mut traversal).expect("sole owner");
            s.themes_dir = d.path().join("sub");
            std::fs::create_dir(&s.themes_dir).expect("mkdir");
            let mut theme = app.custom_themes[0].clone();
            theme.typeface = Some("../".to_string() + "secret.ttf");
            s.custom_themes = vec![theme];
        }
        let refused = get(traversal, "/api/themes/Maison/font/proportional").await;
        assert_eq!(
            refused.status(),
            StatusCode::NOT_FOUND,
            "a typeface with a separator in it must never be looked for"
        );
    }

    #[test]
    fn no_read_route_is_dead() {
        // 🔴 Batch 12.3. `/api/apps/{name}` already existed and was consumed by nobody:
        // with fifty routes, that kind of debt multiplies without anything saying so,
        // and you end up maintaining code nothing calls.
        //
        // 🔴 This test carried TWO hand-maintained lists and both had drifted into
        // blankets — measured 2026-08-28. It read four named files of the interface,
        // under a comment inviting a fifth to be added by hand; the Fluent catalogue
        // was not among them, and it is where `/api/runbook` is named. And it exempted
        // SIXTEEN paths as "the CLI and the scripts", when `hlb-cli` requests none of
        // them: its one `/api/v1/query` goes to VictoriaMetrics, and its `/api/apps` is
        // inside a `println!`. Of those sixteen, eight were already requested by a
        // screen, four could never have failed (the mutating routes are not declared
        // with `.route("`, and `/metrics` is not under `/api/`), one was listed twice,
        // and THREE were hiding routes nobody calls.
        //
        // Both lists are derived now. The consumers are whatever files the interface
        // and the CLI are built from, walked. `openapi-fetch` spells a path exactly as
        // the router does, template included (`"/api/apps/{name}"`), so `requested`
        // matches a TypeScript call the way it matched a Rust `format!`. The exemptions
        // are each route's `x-hlb-client` extension, written on the handler itself,
        // where every reader of it sees it — a blanket declared here was invisible from
        // there.
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut clients = String::new();
        let mut files = 0;
        for crate_source in ["../../web/src", "../hlb-cli/src"] {
            sources_under(&root.join(crate_source), &mut clients, &mut files);
        }
        // A walk that finds nothing marks every route dead — or, once the exemptions
        // are in, excuses everything. Anchor it.
        assert!(
            files > 60,
            "only {files} client sources walked — is the path right?"
        );

        let mut dead = Vec::new();
        let mut checked = 0;
        for r in crate::openapi::routes() {
            if r.mutates() || !r.path.starts_with("/api/") {
                continue;
            }
            checked += 1;
            if let Some(reason) = &r.client {
                // An empty marker would exempt as well as a reasoned one, and would be
                // the blanket coming back one route at a time.
                assert!(
                    reason.len() > 20,
                    "{}: `{}` must say WHO calls it and why it stays, not merely be \
                     present — found \"{reason}\"",
                    r.path,
                    crate::openapi::CLIENT
                );
                continue;
            }
            if !requested(&clients, &r.path) {
                dead.push(r.path.clone());
            }
        }

        // Same anchor at the other end: a walk that stops finding routes passes.
        assert!(
            checked > 30,
            "only {checked} read routes seen — has the document stopped being walked?"
        );
        assert!(
            dead.is_empty(),
            "declared routes nobody consumes: {dead:?} — either a screen is \
             missing, or the route is to be removed, or its `x-hlb-client` names who \
             calls it from outside this repository"
        );
    }

    /// Every `.rs` file of this crate, cut at its tests — what they hold are fixtures,
    /// not text anyone is shown.
    ///
    /// ⚠️ Walked, not listed: the two tests below each named six or seven files by hand
    /// until 2026-10-05, out of twenty-six, and the refusals written since in
    /// `bitwarden.rs`, `signin.rs` and this file were checked by neither.
    fn crate_sources() -> Vec<(String, String)> {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut out: Vec<(String, String)> = std::fs::read_dir(&dir)
            .expect("source directory")
            .map(|e| e.expect("entry").path())
            .filter(|p| p.extension().is_some_and(|e| e == "rs"))
            .map(|p| {
                let name = p.file_name().map(|n| n.to_string_lossy().into_owned());
                let text = std::fs::read_to_string(&p).expect("source");
                let code = text
                    .split("\n#[cfg(test)]")
                    .next()
                    .unwrap_or("")
                    .to_string();
                (name.unwrap_or_default(), code)
            })
            .collect();
        out.sort();
        // A walk that found nothing would pass on nothing.
        assert!(out.len() >= 20, "only {} source files", out.len());
        out
    }

    #[test]
    fn no_server_text_carries_a_collapsed_line_continuation() {
        // 🔴 The project's documented trap, on the server side this time. Without the
        // trailing "\\", the Rust indentation stays IN the string, and the text shows
        // with a gap in the middle. Found while reading the generated runbook: the
        // paragraph started fifteen spaces from the margin.
        //
        // ⚠️ The scan is done LINE BY LINE, like the interface's. Extracting the strings
        // of the whole file would make the test fail on every legitimate continuation:
        // my extractor eats the newline but not the indentation that follows, where
        // rustc eats both. Line by line, a continuation is a distinct fragment whose
        // leading indentation is removed by `trim`.
        let gap = "  ";
        for (file, source) in &crate_sources() {
            for (n, line) in source.lines().enumerate() {
                let code = line.split("//").next().unwrap_or("");
                for text in strings_of(code) {
                    assert!(
                        !text.trim().contains(gap),
                        "{file} line {}: \"{text}\" carries swallowed indentation \
                         — a continuation backslash is missing",
                        n + 1
                    );
                }
            }
        }
    }

    #[test]
    fn no_text_the_interface_shows_uses_the_parenthesised_plural() {
        // 🔴 The tic the project forbids itself, locked on the server side too. It had
        // stayed there four times — in the summary of an install, of a backup and of a
        // resize — because the test only covered the interface. And those sentences are
        // built HERE and displayed as they are.
        //
        // ⚠️ An ASSEMBLED pattern: writing it out would make this test fail on its own code.
        let tic = format!("({})", "s");
        for (file, source) in &crate_sources() {
            for text in strings_of(source) {
                assert!(
                    !text.contains(&tic),
                    "{file}: \"{text}\" — hlb_api::plural exists for that"
                );
            }
        }
    }

    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use hlb_api::{ActionResult, StepState};
    use tower::ServiceExt;

    fn manifest(name: &str) -> hlb_types::Manifest {
        let y = format!(
            "apiVersion: hlb/v1\nkind: App\nmetadata: {{ name: {name} }}\n\
             spec:\n  image: {{ repo: a/b, tag: \"1\" }}\n"
        );
        serde_yaml_ng::from_str(&y).expect("test manifest")
    }

    /// A test's application state, in a single place.
    ///
    /// Five copies of the same literal meant five places to fix every time
    /// than `AppState` gaining a field.
    fn app_state(st: State, no_auth: bool) -> Arc<AppState> {
        shared_state(Arc::new(st), no_auth)
    }

    /// The same thing, but with a state the caller keeps: enough to re-read the log
    /// after a request the API would not allow to be re-read.
    fn shared_state(st: Arc<State>, no_auth: bool) -> Arc<AppState> {
        Arc::new(base_state(st, no_auth))
    }

    /// The demonstration's live parts — machines, drift, alerts — laid over `st`, the
    /// way `--demo` lays them, for a test reading what the loops would have filled in.
    pub(crate) async fn demo_state(st: State) -> AppState {
        let mut s = base_state(Arc::new(st), true);
        s.demo = true;
        let now = crate::auth::now();
        s.privd = hlb_privd::Privd::new(s.state.clone())
            .with_mail(None, "local")
            .with_fleet(Arc::new(tokio::sync::RwLock::new(crate::demo::nodes_at(
                now as u64,
                crate::demo::Scale::Large,
            ))))
            .with_published(
                Arc::new(tokio::sync::RwLock::new(crate::demo::alerts(now))),
                Arc::new(tokio::sync::RwLock::new(crate::demo::drifts())),
            );
        s
    }

    /// An `AppState` with nothing configured, for a test to fill in what it needs.
    pub(crate) fn base_state(st: Arc<State>, no_auth: bool) -> AppState {
        AppState {
            custom_themes: Vec::new(),
            themes_dir: std::path::PathBuf::new(),
            catalog_dir: "../../catalog".into(),
            privd: hlb_privd::Privd::new(st.clone()).with_mail(None, "local"),
            state: st,
            started_at: std::time::Instant::now(),
            version: "test",
            ui_dir: None,
            no_auth,
            signin: Default::default(),
            throughput: Arc::new(crate::throughput::RateLimiter::new()),
            trusted_proxy: false,
            series: None,
            beat: None,
            mirror: None,
            public_url: None,
            demo: false,
            catalog: Default::default(),
            public_status: false,
            mail_domain: "local".into(),
        }
    }

    /// `base_state` with the catalog on both sides: the screens browse it, and the
    /// privileged side installs from it.
    fn state_with_catalog(st: State, cat: hlb_catalog::Catalog) -> AppState {
        let mut s = base_state(Arc::new(st), true);
        let cat = Arc::new(cat);
        s.privd = hlb_privd::Privd::new(s.state.clone())
            .with_mail(None, &s.mail_domain)
            .with_catalog(Some(cat.clone()));
        s.catalog = hlb_privd::catalog::SharedCatalog::new(Some(cat));
        s
    }

    /// An orchestrator that records what it was asked to do.
    ///
    /// 🔴 It never fails: these tests are about the DECISIONS the route takes before
    /// calling Docker — refusing to empty the cluster, refusing to act without
    /// `?apply=true`. A fake that failed would test error handling instead, and the
    /// refusals would pass for the wrong reason.
    #[derive(Default)]
    pub(crate) struct FakeOrch {
        nodes: Vec<hlb_orchestrator::NodeInfo>,
        tasks: Vec<hlb_orchestrator::TaskInfo>,
        /// What `list` answers: the services Swarm runs.
        pub(crate) services: Vec<hlb_orchestrator::ServiceStatus>,
        drained: std::sync::Mutex<Vec<(String, String)>>,
        removed: std::sync::Mutex<Vec<String>>,
        deployed: std::sync::Mutex<Vec<String>>,
    }

    impl FakeOrch {
        /// Swarm running these services, and nothing else to say.
        pub(crate) fn running(services: Vec<hlb_orchestrator::ServiceStatus>) -> Self {
            Self {
                services,
                ..Default::default()
            }
        }

        /// `(id, availability)` for each node, the hostname being the id.
        fn with_nodes(spec: &[(&str, &str)]) -> Self {
            let named: Vec<(&str, &str, &str)> =
                spec.iter().map(|(id, a)| (*id, *id, *a)).collect();
            Self::with_named_nodes(&named)
        }

        /// `(id, hostname, availability)` — the two names apart.
        ///
        /// 🔴 Swarm's identifier and the machine's hostname are different strings, and
        /// every test that spelled them the same could not tell which one the code
        /// under test had matched on. That is exactly how the last-active-node refusal
        /// came to compare only identifiers while Docker accepts either.
        fn with_named_nodes(spec: &[(&str, &str, &str)]) -> Self {
            Self {
                nodes: spec
                    .iter()
                    .map(|(id, hostname, availability)| hlb_orchestrator::NodeInfo {
                        data: Vec::new(),
                        ingress: false,
                        addr: None,
                        id: (*id).to_string(),
                        hostname: (*hostname).to_string(),
                        role: hlb_orchestrator::NodeRole::Worker,
                        status: "ready".into(),
                        availability: (*availability).to_string(),
                        tier: None,
                        protection: None,
                        disk_tangs: Vec::new(),
                        is_leader: false,
                        memory_mb: None,
                        failure_domain: None,
                    })
                    .collect(),
                ..Default::default()
            }
        }
    }

    #[async_trait::async_trait]
    impl hlb_orchestrator::Orchestrator for FakeOrch {
        async fn ping(&self) -> hlb_orchestrator::Result<String> {
            Ok("fake".into())
        }
        async fn deploy(
            &self,
            spec: &hlb_orchestrator::ServiceSpec,
        ) -> hlb_orchestrator::Result<String> {
            self.deployed.lock().expect("mutex").push(spec.name.clone());
            Ok("id".into())
        }
        async fn update_image(&self, _: &str, _: &str) -> hlb_orchestrator::Result<()> {
            Ok(())
        }
        async fn scale(&self, _: &str, _: u64) -> hlb_orchestrator::Result<()> {
            Ok(())
        }
        async fn cluster_init(&self, _: &str) -> hlb_orchestrator::Result<String> {
            Ok("swarm".into())
        }
        async fn enable_autolock(&self) -> hlb_orchestrator::Result<String> {
            Ok("SWMKEY".into())
        }
        async fn autolock_enabled(&self) -> hlb_orchestrator::Result<bool> {
            Ok(false)
        }
        async fn join_tokens(&self) -> hlb_orchestrator::Result<hlb_orchestrator::JoinTokens> {
            Ok(hlb_orchestrator::JoinTokens {
                manager: "SWMTKN-mgr".into(),
                worker: "SWMTKN-wrk".into(),
                advertise_addr: "127.0.0.1:2377".into(),
            })
        }
        async fn nodes(&self) -> hlb_orchestrator::Result<Vec<hlb_orchestrator::NodeInfo>> {
            Ok(self.nodes.clone())
        }
        async fn label_node(&self, _: &str, _: &str, _: &str) -> hlb_orchestrator::Result<()> {
            Ok(())
        }
        async fn set_node_availability(
            &self,
            node: &str,
            availability: &str,
        ) -> hlb_orchestrator::Result<()> {
            self.drained
                .lock()
                .expect("mutex")
                .push((node.into(), availability.into()));
            Ok(())
        }
        async fn exec_in_service(
            &self,
            _: &str,
            _: &[String],
        ) -> hlb_orchestrator::Result<hlb_orchestrator::ExecOutput> {
            Ok(hlb_orchestrator::ExecOutput {
                exit_code: 0,
                stdout: String::new(),
                stderr: String::new(),
            })
        }
        async fn ensure_network(&self, _: &str) -> hlb_orchestrator::Result<bool> {
            Ok(false)
        }

        async fn create_volume(
            &self,
            spec: &hlb_orchestrator::VolumeSpec,
        ) -> hlb_orchestrator::Result<hlb_orchestrator::VolumeInfo> {
            Ok(hlb_orchestrator::VolumeInfo {
                name: spec.name.clone(),
                mountpoint: format!("/var/lib/docker/volumes/{}", spec.name),
                existed: false,
            })
        }
        async fn inspect_volume(
            &self,
            n: &str,
        ) -> hlb_orchestrator::Result<hlb_orchestrator::VolumeInfo> {
            Ok(hlb_orchestrator::VolumeInfo {
                name: n.into(),
                mountpoint: format!("/var/lib/docker/volumes/{n}"),
                existed: false,
            })
        }
        async fn status(
            &self,
            name: &str,
        ) -> hlb_orchestrator::Result<hlb_orchestrator::ServiceStatus> {
            Ok(hlb_orchestrator::ServiceStatus {
                name: name.into(),
                id: "id".into(),
                image: "x/y:1".into(),
                desired_replicas: 1,
                running_replicas: 1,
                global: false,
                update_state: None,
            })
        }
        async fn list(&self) -> hlb_orchestrator::Result<Vec<hlb_orchestrator::ServiceStatus>> {
            Ok(self.services.clone())
        }
        async fn remove(&self, name: &str) -> hlb_orchestrator::Result<()> {
            self.removed.lock().expect("mutex").push(name.into());
            Ok(())
        }
        async fn wait_healthy(
            &self,
            name: &str,
            _: u64,
        ) -> hlb_orchestrator::Result<hlb_orchestrator::ServiceStatus> {
            self.status(name).await
        }
        async fn tasks(
            &self,
            _: Option<&str>,
        ) -> hlb_orchestrator::Result<Vec<hlb_orchestrator::TaskInfo>> {
            Ok(self.tasks.clone())
        }
        async fn logs(
            &self,
            _: &str,
            _: u32,
        ) -> hlb_orchestrator::Result<Vec<hlb_orchestrator::LogLine>> {
            Ok(Vec::new())
        }
    }

    #[tokio::test]
    async fn a_pass_reports_when_it_reconciled_and_publishes_only_what_is_left() {
        let state = Arc::new(State::in_memory().await.expect("base"));
        state
            .upsert_app("demo", &manifest("demo"), None)
            .await
            .expect("upsert");
        state
            .set_app_status("demo", "running")
            .await
            .expect("status");
        let orch = Arc::new(FakeOrch::running(vec![hlb_orchestrator::ServiceStatus {
            name: "demo".into(),
            id: "id".into(),
            image: "a/b:1".into(),
            desired_replicas: 0,
            running_replicas: 0,
            global: false,
            update_state: None,
        }]));
        let drifts: hlb_privd::daemon::DriftState = Default::default();
        let last: hlb_privd::daemon::LastReconciled =
            Arc::new(std::sync::atomic::AtomicI64::new(0));
        let rl = hlb_privd::daemon::ReconcileLoop::new(orch, state)
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

    /// "Back up now" whose pass reports what the test chooses.
    struct FakeBackup {
        events: Vec<hlb_backup_run::Event>,
        fails: Option<String>,
        called: std::sync::Mutex<Vec<String>>,
    }

    impl FakeBackup {
        fn reporting(events: Vec<hlb_backup_run::Event>) -> Arc<Self> {
            Arc::new(Self {
                events,
                fails: None,
                called: Default::default(),
            })
        }
    }

    #[async_trait::async_trait]
    impl hlb_privd::backup::BackUpNow for FakeBackup {
        fn fallback_repo(&self) -> Option<&str> {
            None
        }

        async fn back_up(
            &self,
            _: &State,
            app: &str,
            report: &mut (dyn FnMut(hlb_backup_run::Event) + Send),
        ) -> std::result::Result<hlb_backup_run::Summary, String> {
            self.called.lock().expect("mutex").push(app.into());
            for e in &self.events {
                report(e.clone());
            }
            match &self.fails {
                Some(e) => Err(e.clone()),
                None => Ok(Default::default()),
            }
        }
    }

    fn state_with_backup(st: State, b: Arc<FakeBackup>) -> Arc<AppState> {
        let mut e = base_state(Arc::new(st), true);
        e.privd = hlb_privd::Privd::new(e.state.clone())
            .with_mail(None, &e.mail_domain)
            .with_backup(Some(b));
        Arc::new(e)
    }

    /// A state carrying an orchestrator, to exercise the routes that really act.
    ///
    /// ⚠️ A fake, not a mock that records: what the tests below check is the DECISION
    /// (refuse, or go through), not the Docker call. The call itself is covered by the
    /// `#[ignore]`d Swarm integration tests, which need a real cluster.
    fn state_with_orchestrator(
        st: State,
        o: Arc<dyn hlb_orchestrator::Orchestrator>,
    ) -> Arc<AppState> {
        let mut e = base_state(Arc::new(st), true);
        e.privd = hlb_privd::Privd::new(e.state.clone())
            .with_mail(None, &e.mail_domain)
            .with_orchestrator(Some(o));
        Arc::new(e)
    }

    /// A state whose status page is published.
    ///
    /// One more constructor rather than an extra parameter on `state`: publishing the
    /// status is the exception, and signalling it through the function's NAME makes the
    /// test readable without going to read its arguments.
    fn public_status_state(st: State) -> Arc<AppState> {
        let mut e = app_state(st, false);
        // `Arc::get_mut`: the state has just been created, nobody else holds it.
        if let Some(m) = Arc::get_mut(&mut e) {
            m.public_status = true;
        }
        e
    }

    async fn app() -> Router {
        let st = State::in_memory().await.expect("base");
        st.upsert_app("gitea", &manifest("gitea"), Some("git.example.fr"))
            .await
            .expect("upsert");
        st.set_app_status("gitea", "running").await.expect("status");
        st.add_guide("gitea", "first-admin", "Create the admin", true)
            .await
            .expect("guide");

        router(app_state(st, true))
    }

    async fn get(r: Router, uri: &str) -> (StatusCode, serde_json::Value) {
        let resp = r
            .oneshot(
                Request::builder()
                    .uri(uri)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .expect("body");
        let v = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, v)
    }

    /// Sends a JSON body with the given verb and returns the decoded answer.
    async fn send(r: Router, verb: &str, uri: &str, body: &str) -> (StatusCode, serde_json::Value) {
        let resp = r
            .oneshot(
                Request::builder()
                    .method(verb)
                    .uri(uri)
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .expect("request"),
            )
            .await
            .expect("response");
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .expect("body");
        let v = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, v)
    }

    #[tokio::test]
    async fn a_destination_signs_with_its_own_secret_and_no_other() {
        // 🔴 The backup pass decrypts the secret a destination names and signs requests
        // to its location with it: an `operate` caller naming another secret, or moving
        // the location, would send a key's signatures and the copies where they chose.
        let st = Arc::new(State::in_memory().await.expect("state"));
        st.upsert_destination(
            "mine",
            "s3:s3.example/b",
            "critical",
            Some("backup-dest-mine"),
        )
        .await
        .expect("declared by the CLI");
        let r = || router(shared_state(st.clone(), true));
        let body = |location: &str, secret: &str| {
            format!(
                r#"{{"location": "{location}", "credentials_secret": "{secret}", "classes": "bulky"}}"#
            )
        };

        for (location, secret) in [
            ("s3:s3.example/b", "backup-dest-offsite"),
            ("s3:evil.example/b", "backup-dest-mine"),
        ] {
            let (status, v) = send(
                r(),
                "PUT",
                "/api/backup/destinations/mine?apply=true",
                &body(location, secret),
            )
            .await;
            assert_eq!(
                (status, &v["applied"]),
                (StatusCode::OK, &false.into()),
                "{v}"
            );
            assert!(v["blockers"][0]
                .as_str()
                .expect("a blocker")
                .contains("hlb backup dest add"));
        }
        assert_eq!(st.destinations().await.expect("read")[0].2, "critical");

        let (_, v) = send(
            r(),
            "PUT",
            "/api/backup/destinations/mine?apply=true",
            &body("s3:s3.example/b", "backup-dest-mine"),
        )
        .await;
        assert_eq!(v["applied"], true, "{v}");
        assert_eq!(
            st.destinations().await.expect("read"),
            vec![(
                "mine".to_string(),
                "s3:s3.example/b".to_string(),
                "bulky".to_string(),
                Some("backup-dest-mine".to_string()),
            )]
        );
    }

    async fn post(r: Router, uri: &str, body: &str) -> (StatusCode, serde_json::Value) {
        send(r, "POST", uri, body).await
    }

    async fn delete(r: Router, uri: &str, body: &str) -> (StatusCode, serde_json::Value) {
        send(r, "DELETE", uri, body).await
    }

    /// Three people, two of them administrators: the selection decides who is left.
    async fn people() -> Arc<State> {
        let st = Arc::new(State::in_memory().await.expect("state"));
        // A role per level, named after it, beside the three a new installation has.
        for level in [hlb_types::Role::User, hlb_types::Role::Viewer] {
            let r =
                hlb_users::RoleDef::new(level.as_str(), level, hlb_users::MailLimits::standard());
            st.put_role(&r, "test").await.expect("role");
        }
        for (name, role) in [("lena", "admin"), ("camille", "admin"), ("sacha", "user")] {
            st.upsert_user(name, "standard", None).await.expect("user");
            st.set_user_role(name, role, None).await.expect("role");
        }
        st
    }

    #[tokio::test]
    async fn a_selection_gets_its_role_as_one_plan_with_a_step_each() {
        let st = people().await;
        let (s, v) = post(
            router(shared_state(st.clone(), true)),
            "/api/accounts/role/viewer?apply=true",
            r#"{"accounts":["sacha","camille","sacha"]}"#,
        )
        .await;
        assert_eq!(s, StatusCode::OK, "{v}");
        assert_eq!(v["steps"].as_array().expect("steps").len(), 2, "{v}");
        assert_eq!(
            st.user_role("sacha").await.expect("role"),
            hlb_types::Role::Viewer
        );
        assert_eq!(
            st.user_role("camille").await.expect("role"),
            hlb_types::Role::Viewer
        );
    }

    #[tokio::test]
    async fn a_selection_holding_every_administrator_is_refused() {
        // Each of the two has another administrator; together they leave none.
        let st = people().await;
        let (s, v) = post(
            router(shared_state(st.clone(), true)),
            "/api/accounts/role/user?apply=true",
            r#"{"accounts":["lena","camille"]}"#,
        )
        .await;
        assert_eq!(
            (s, &v["applicable"]),
            (StatusCode::OK, &serde_json::json!(false)),
            "{v}"
        );
        assert!(v["blockers"][0]
            .as_str()
            .expect("blocker")
            .contains("EVERY administrator"));
        assert_eq!(
            st.user_role("lena").await.expect("role"),
            hlb_types::Role::Admin
        );
    }

    /// An installed app signing in through its own client, with a floor and a quota.
    async fn with_gitea(st: &State) {
        let m: hlb_types::Manifest = serde_yaml_ng::from_str(
            "apiVersion: hlb/v1\nkind: App\nmetadata: { name: gitea }\nspec:\n  \
             image: { repo: gitea/gitea, tag: \"1\" }\n  \
             requires: [ { kind: sso, mode: native, redirectPaths: [/cb] } ]\n  \
             access:\n    floor: viewer\n    admins: { level: admin, means: every repository }\n    \
             quota: { claim: { name: gitea_quota, unit: GiB } }\n",
        )
        .expect("manifest");
        st.upsert_app("gitea", &m, Some("git.example.org"))
            .await
            .expect("app");
    }

    #[tokio::test]
    async fn a_role_below_an_app_s_floor_is_never_let_in() {
        let st = people().await;
        with_gitea(&st).await;
        let r = router(shared_state(st.clone(), true));
        let (s, v) = post(r.clone(), "/api/apps/gitea/roles/user?apply=true", "{}").await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
        assert!(
            v["blockers"][0]
                .as_str()
                .expect("why")
                .contains("\"viewer\" roles and above"),
            "{v}"
        );
        assert!(st.app_roles().await.expect("allowed").is_empty());

        let (_, v) = post(r.clone(), "/api/apps/gitea/roles/admin", "{}").await;
        assert_eq!(v["applied"], false, "a preview first: {v}");
        assert!(
            v["warnings"][0]
                .as_str()
                .expect("warning")
                .contains("every repository"),
            "what administering it gives, before it is given: {v}"
        );
        let (_, v) = post(r, "/api/apps/gitea/roles/admin?apply=true", "{}").await;
        assert_eq!(v["applied"], true, "{v}");
        assert!(st.app_roles().await.expect("allowed")["gitea"].contains("admin"));
    }

    #[tokio::test]
    async fn giving_an_admin_role_says_what_it_administers() {
        let st = people().await;
        with_gitea(&st).await;
        st.allow_role("gitea", "admin", "test")
            .await
            .expect("allowed");
        let (_, v) = post(
            router(shared_state(st.clone(), true)),
            "/api/accounts/sacha/role/admin",
            "{}",
        )
        .await;
        let w = v["warnings"].to_string();
        assert!(
            w.contains("ADMIN") && w.contains("gitea: every repository"),
            "{v}"
        );
    }

    #[tokio::test]
    async fn a_role_someone_holds_is_not_deleted() {
        let st = people().await;
        let (s, v) = delete(
            router(shared_state(st.clone(), true)),
            "/api/roles/user?apply=true",
            "",
        )
        .await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
        assert!(
            v["blockers"][0].as_str().expect("why").contains("sacha"),
            "{v}"
        );
        assert!(st.role("user").await.expect("role").is_some());
    }

    #[tokio::test]
    async fn a_person_s_own_quota_says_who_set_it() {
        let st = people().await;
        with_gitea(&st).await;
        st.allow_role("gitea", "admin", "test")
            .await
            .expect("allowed");
        st.set_role_quota("admin", "gitea", Some(10 << 30))
            .await
            .expect("quota");
        let r = router(shared_state(st.clone(), true));
        let (_, v) = post(
            r.clone(),
            "/api/accounts/lena/quota/gitea?apply=true",
            r#"{"bytes": 214748364800}"#,
        )
        .await;
        assert_eq!(v["applied"], true, "{v}");
        let (_, accounts) = get(r, "/api/accounts").await;
        let lena = accounts
            .as_array()
            .expect("list")
            .iter()
            .find(|a| a["name"] == "lena")
            .expect("lena");
        assert_eq!(lena["quotas"][0]["bytes"], 214_748_364_800_u64, "{lena}");
        assert_eq!(lena["quotas"][0]["own"], true);
        assert_eq!(lena["quotas"][0]["set_by"], "anonymous", "{lena}");
        let camille = accounts
            .as_array()
            .expect("list")
            .iter()
            .find(|a| a["name"] == "camille")
            .expect("camille");
        assert_eq!(
            camille["quotas"][0]["bytes"],
            10_u64 << 30,
            "the role's: {camille}"
        );
    }

    #[tokio::test]
    async fn a_single_role_is_never_given_to_a_name_nobody_has_either() {
        let st = people().await;
        let (_, v) = post(
            router(shared_state(st.clone(), true)),
            "/api/accounts/nobody/role/admin?apply=true",
            "{}",
        )
        .await;
        assert_eq!(v["applied"], false, "{v}");
        assert!(!st
            .users_with_roles()
            .await
            .expect("roles")
            .iter()
            .any(|h| h.user == "nobody"));
    }

    #[tokio::test]
    async fn a_role_is_never_given_to_a_name_nobody_has() {
        let st = people().await;
        let (s, v) = post(
            router(shared_state(st.clone(), true)),
            "/api/accounts/role/user?apply=true",
            r#"{"accounts":["sacha","nobody"]}"#,
        )
        .await;
        assert_eq!(
            (s, &v["applicable"]),
            (StatusCode::OK, &serde_json::json!(false)),
            "{v}"
        );
        assert!(
            !v["cli_command"]
                .as_str()
                .expect("command")
                .contains("nobody"),
            "{v}"
        );
        assert!(
            v.to_string().contains("unknown account \\\"nobody\\\""),
            "{v}"
        );
        // Refused whole: not the known half applied and the other half dropped.
        assert_eq!(
            st.user_role("sacha").await.expect("role"),
            hlb_types::Role::User
        );
    }

    #[tokio::test]
    async fn every_refusal_answers_the_same_shape() {
        // The 401 and the 403s came from the authorization extractor as bare text, the
        // 404s from the handlers as JSON: a generated client types ONE error body, and a
        // refusal in the other shape is a blank screen where a sentence should be.
        let closed = router(app_state(State::in_memory().await.expect("state"), false));
        let resp = closed
            .oneshot(
                Request::builder()
                    .uri("/api/apps")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            resp.headers()
                .get(axum::http::header::WWW_AUTHENTICATE)
                .and_then(|v| v.to_str().ok()),
            Some("Bearer"),
            "a 401 without it does not say how to authenticate"
        );
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .expect("body");
        serde_json::from_slice::<hlb_api::ErrorBody>(&bytes).expect("401 body");

        let r = app().await;
        for (verb, uri) in [
            ("GET", "/api/apps/nope"),
            ("GET", "/api/apps/nope/detail"),
            ("GET", "/api/nodes/10.0.0.9/detail"),
            ("GET", "/api/export/nothing"),
            ("GET", "/api/catalog/nope/icon"),
            ("POST", "/api/recovery/no-such-safeguard"),
        ] {
            let (status, v) = send(r.clone(), verb, uri, "{}").await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{verb} {uri}: {v}");
            let body: hlb_api::ErrorBody =
                serde_json::from_value(v.clone()).expect("the shared error body");
            assert!(!body.error.is_empty(), "{verb} {uri}: {v}");
        }

        // What axum refuses before a handler runs: it answered these in plain text.
        for (verb, uri, body, expected) in [
            (
                "POST",
                "/api/apps/gitea/install",
                "{not json",
                StatusCode::BAD_REQUEST,
            ),
            (
                "POST",
                "/api/apps/gitea/install",
                r#""a string, not an object""#,
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (
                "POST",
                "/api/apps/gitea/install?apply=maybe",
                "{}",
                StatusCode::BAD_REQUEST,
            ),
            (
                "DELETE",
                "/api/announcements/not-a-number",
                "{}",
                StatusCode::BAD_REQUEST,
            ),
            ("GET", "/api/v1/metrics/series", "", StatusCode::BAD_REQUEST),
        ] {
            let (status, v) = send(r.clone(), verb, uri, body).await;
            assert_eq!(status, expected, "{verb} {uri}: {v}");
            let body: hlb_api::ErrorBody = serde_json::from_value(v.clone())
                .unwrap_or_else(|_| panic!("{verb} {uri} answers {v}, not the error body"));
            assert!(!body.error.is_empty(), "{verb} {uri}: {v}");
        }
    }

    #[tokio::test]
    async fn a_brand_accent_that_reads_as_an_alert_is_refused() {
        // 🔴 Copper, the accent this project first chose: under deuteranopia it merges
        // with "critical", and every primary button on every screen reads as an alert.
        let r = app().await;
        let brand = |hex: [u8; 3]| {
            serde_json::json!({ "name": "Maison", "product": "Homelabus", "accent": hex })
                .to_string()
        };
        let (s, v) = send(
            r.clone(),
            "PUT",
            "/api/appearance",
            &brand([0xE0, 0x7A, 0x3F]),
        )
        .await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
        let error = v["error"].as_str().unwrap_or_default();
        assert!(
            error.contains("\"critical\"") && error.contains("Dark"),
            "{error}"
        );
        let (_, stored) = get(r.clone(), "/api/appearance").await;
        assert_eq!(
            stored["accent"],
            serde_json::Value::Null,
            "refused, not stored"
        );

        let (s, v) = send(r, "PUT", "/api/appearance", &brand([0x7B, 0x8C, 0xFF])).await;
        assert_eq!(s, StatusCode::OK, "a cool accent passes: {v}");
    }

    #[tokio::test]
    async fn draining_a_node_really_reaches_the_orchestrator() {
        // 🔴 This route used to build a correct preview and then return
        // "unimplemented". The point of the test is that `?apply=true` now ARRIVES:
        // a preview that never acts is honest, and useless.
        let st = State::in_memory().await.expect("base");
        let o = Arc::new(FakeOrch::with_nodes(&[
            ("node-a", "active"),
            ("node-b", "active"),
        ]));
        let e = state_with_orchestrator(st, o.clone());

        let (s, v) = post(
            router(e),
            "/api/nodes/node-a/availability?apply=true",
            r#"{"availability":"drain"}"#,
        )
        .await;

        assert_eq!(s, StatusCode::OK);
        assert_eq!(v["applied"], true, "{v}");
        assert_eq!(
            o.drained.lock().expect("mutex").as_slice(),
            [("node-a".to_string(), "drain".to_string())],
            "the orchestrator must have been called"
        );
        assert!(
            v["steps"].to_string().contains(r#""state":"done""#),
            "the step must be reported as done: {}",
            v["steps"]
        );
    }

    #[tokio::test]
    async fn a_preview_never_drains_anything() {
        // Preview by default: visiting the screen must not empty a node.
        let st = State::in_memory().await.expect("base");
        let o = Arc::new(FakeOrch::with_nodes(&[
            ("node-a", "active"),
            ("node-b", "active"),
        ]));
        let e = state_with_orchestrator(st, o.clone());

        let (s, v) = post(
            router(e),
            "/api/nodes/node-a/availability",
            r#"{"availability":"drain"}"#,
        )
        .await;

        assert_eq!(s, StatusCode::OK);
        assert_eq!(v["applied"], false);
        assert!(
            o.drained.lock().expect("mutex").is_empty(),
            "a preview called the orchestrator"
        );
    }

    #[tokio::test]
    async fn draining_the_last_active_node_is_refused_before_docker() {
        // 🔴 Swarm accepts this without complaint and empties the cluster: every app
        // stops with nowhere left to place it. The refusal is ours, and it must happen
        // BEFORE the call — a blocker that only reports afterwards has already drained.
        let st = State::in_memory().await.expect("base");
        let o = Arc::new(FakeOrch::with_nodes(&[
            ("node-a", "active"),
            ("node-b", "drain"),
        ]));
        let e = state_with_orchestrator(st, o.clone());

        let (s, v) = post(
            router(e),
            "/api/nodes/node-a/availability?apply=true",
            r#"{"availability":"drain"}"#,
        )
        .await;

        assert_eq!(s, StatusCode::OK, "a refusal is not a server error");
        assert_eq!(v["applied"], false);
        assert!(
            v["blockers"].to_string().contains("last active node"),
            "the refusal must name what it protects: {}",
            v["blockers"]
        );
        assert!(
            o.drained.lock().expect("mutex").is_empty(),
            "the node was drained despite the blocker"
        );
    }

    #[tokio::test]
    async fn the_last_active_node_is_protected_under_its_hostname_too() {
        // 🔴 Docker addresses a node by identifier OR by hostname, so `{id}` here is
        // legitimately either. Matching on the identifier alone made the guard answer
        // "the target is not active" for every call made by name, skip its own refusal,
        // and drain the last node in the cluster — a silent hole in the one check that
        // stands between a click and every application stopping at once.
        let st = State::in_memory().await.expect("base");
        let o = Arc::new(FakeOrch::with_named_nodes(&[
            ("n-heavy", "swarm-heavy", "active"),
            ("n-small1", "small-01", "drain"),
        ]));
        let e = state_with_orchestrator(st, o.clone());

        let (s, v) = post(
            router(e),
            "/api/nodes/swarm-heavy/availability?apply=true",
            r#"{"availability":"drain"}"#,
        )
        .await;

        assert_eq!(s, StatusCode::OK);
        assert_eq!(v["applied"], false, "{v}");
        assert!(
            v["blockers"].to_string().contains("last active node"),
            "addressed by hostname, the refusal did not fire: {}",
            v["blockers"]
        );
        assert!(
            o.drained.lock().expect("mutex").is_empty(),
            "the last node was drained despite the blocker"
        );
    }

    #[tokio::test]
    async fn a_second_node_is_not_drained_while_another_is_out() {
        // 🔴 One node at a time, as `hlb node upgrade` holds it: with node-c drained,
        // draining node-a leaves what moved off node-c one machine to run on.
        let st = State::in_memory().await.expect("base");
        let o = Arc::new(FakeOrch::with_nodes(&[
            ("node-a", "active"),
            ("node-b", "active"),
            ("node-c", "drain"),
        ]));
        let e = state_with_orchestrator(st, o.clone());

        let (s, v) = post(
            router(e),
            "/api/nodes/node-a/availability?apply=true",
            r#"{"availability":"drain"}"#,
        )
        .await;

        assert_eq!(s, StatusCode::OK);
        assert_eq!(v["applied"], false, "{v}");
        assert!(
            v["blockers"].to_string().contains("one node at a time"),
            "{}",
            v["blockers"]
        );
        assert!(o.drained.lock().expect("mutex").is_empty());
    }

    #[tokio::test]
    async fn draining_a_node_holding_data_is_downtime_the_person_confirms() {
        let st = State::in_memory().await.expect("base");
        let mut fake = FakeOrch::with_nodes(&[("node-a", "active"), ("node-b", "active")]);
        fake.nodes[0].data = vec!["postgres".into()];
        let o = Arc::new(fake);
        let e = state_with_orchestrator(st, o.clone());
        let r = router(e);

        let (_, v) = post(
            r.clone(),
            "/api/nodes/node-a/availability",
            r#"{"availability":"drain"}"#,
        )
        .await;
        assert!(v["warnings"].to_string().contains("postgres"), "{v}");
        assert_eq!(v["confirmation_required"], "node-a", "{v}");
        assert_eq!(
            v["blockers"],
            serde_json::json!([]),
            "a warning, not a blocker"
        );

        let (_, v) = post(
            r.clone(),
            "/api/nodes/node-a/availability?apply=true",
            r#"{"availability":"drain"}"#,
        )
        .await;
        assert_eq!(v["applied"], false, "unconfirmed: {v}");
        assert!(o.drained.lock().expect("mutex").is_empty());

        let (_, v) = post(
            r,
            "/api/nodes/node-a/availability?apply=true",
            r#"{"availability":"drain","confirmed":"node-a"}"#,
        )
        .await;
        assert_eq!(v["applied"], true, "{v}");
        assert_eq!(o.drained.lock().expect("mutex").len(), 1);
    }

    #[tokio::test]
    async fn a_task_names_its_node_by_hostname_not_by_swarm_id() {
        // 🔴 What the node screens and the causal chain match on: a Swarm id passed
        // through matched no machine on a real cluster.
        let st = State::in_memory().await.expect("base");
        let mut o = FakeOrch::with_named_nodes(&[("x7k2", "deb2", "active")]);
        o.tasks = vec![hlb_orchestrator::TaskInfo {
            id: "t1".into(),
            service: "postgres".into(),
            slot: Some(1),
            node_id: Some("x7k2".into()),
            desired_state: "running".into(),
            state: "running".into(),
            image: String::new(),
            message: None,
            err: None,
            updated_at: None,
        }];
        let e = state_with_orchestrator(st, Arc::new(o));
        let tasks = task_summaries(&swarm(&e, None).await.expect("orchestrator"));
        assert_eq!(tasks[0].node.as_deref(), Some("deb2"), "{tasks:?}");
    }

    #[tokio::test]
    async fn a_node_detail_carries_swarms_own_identifier_and_availability() {
        // 🔴 The detail is keyed by the AGENT ADDRESS (10.0.0.1:8421) and the
        // availability endpoint is addressed by Swarm's identifier. Without this field
        // the interface has no way to name the machine it wants to drain — and the
        // hostname is the only string the two sides share, so that is what the join is
        // made on.
        let st = State::in_memory().await.expect("base");
        let o = Arc::new(FakeOrch::with_named_nodes(&[(
            "n-heavy",
            "swarm-heavy",
            "drain",
        )]));
        let mut e = base_state(Arc::new(st), true);
        e.privd = hlb_privd::Privd::new(e.state.clone())
            .with_mail(None, &e.mail_domain)
            .with_orchestrator(Some(o))
            .with_fleet(Arc::new(tokio::sync::RwLock::new(crate::demo::nodes(
                crate::auth::now() as u64,
            ))));
        let e = Arc::new(e);

        let (s, v) = get(router(e), "/api/nodes/10.0.0.1:8421/detail").await;

        assert_eq!(s, StatusCode::OK, "{v}");
        assert_eq!(v["swarm"]["id"], "n-heavy", "{v}");
        assert_eq!(v["swarm"]["availability"], "drain", "{v}");
    }

    #[tokio::test]
    async fn a_node_swarm_does_not_know_carries_no_identifier() {
        // ⚠️ `None`, never a guess. An agent reports machines Swarm has never heard of
        // — that is what a node being set up looks like — and inventing an identifier
        // for one would point the drain button at whatever Docker matched instead.
        let st = State::in_memory().await.expect("base");
        let o = Arc::new(FakeOrch::with_named_nodes(&[(
            "n-other",
            "another-machine",
            "active",
        )]));
        let mut e = base_state(Arc::new(st), true);
        e.privd = hlb_privd::Privd::new(e.state.clone())
            .with_mail(None, &e.mail_domain)
            .with_orchestrator(Some(o))
            .with_fleet(Arc::new(tokio::sync::RwLock::new(crate::demo::nodes(
                crate::auth::now() as u64,
            ))));
        let e = Arc::new(e);

        let (s, v) = get(router(e), "/api/nodes/10.0.0.1:8421/detail").await;

        assert_eq!(s, StatusCode::OK, "{v}");
        assert_eq!(v["swarm"], serde_json::Value::Null, "{v}");
    }

    #[tokio::test]
    async fn bringing_the_last_node_back_is_always_allowed() {
        // ⚠️ The symmetric case: `active` on the last node REPAIRS the cluster. A rule
        // written as "refuse when only one node is left" would block the way out of the
        // very situation it exists to prevent.
        let st = State::in_memory().await.expect("base");
        let o = Arc::new(FakeOrch::with_nodes(&[("node-a", "drain")]));
        let e = state_with_orchestrator(st, o.clone());

        let (s, v) = post(
            router(e),
            "/api/nodes/node-a/availability?apply=true",
            r#"{"availability":"active"}"#,
        )
        .await;

        assert_eq!(s, StatusCode::OK);
        assert_eq!(v["applied"], true, "{v}");
        assert_eq!(o.drained.lock().expect("mutex").len(), 1);
    }

    #[tokio::test]
    async fn deleting_an_app_stops_the_service_then_forgets_it() {
        // 🔴 The ORDER is the point. Forgetting the app first would leave a Swarm
        // service nobody manages: invisible on every screen, and reconciliation would
        // read it as an orphan it must never touch.
        let st = State::in_memory().await.expect("base");
        st.upsert_app("gitea", &manifest("gitea"), None)
            .await
            .expect("app");
        let o = Arc::new(FakeOrch::default());
        let e = state_with_orchestrator(st, o.clone());

        let (s, v) = delete(
            router(e.clone()),
            "/api/apps/gitea?apply=true",
            r#"{"confirmed":"gitea"}"#,
        )
        .await;

        assert_eq!(s, StatusCode::OK);
        assert_eq!(v["applied"], true, "{v}");
        assert_eq!(
            o.removed.lock().expect("mutex").as_slice(),
            ["gitea".to_string()]
        );
        assert!(
            e.state
                .installed_apps()
                .await
                .expect("apps")
                .iter()
                .all(|(n, _)| n != "gitea"),
            "the app is still known after being deleted"
        );
    }

    #[tokio::test]
    async fn a_deletion_without_its_confirmation_touches_nothing() {
        // Repeating the name is what stops a purge typed on the wrong app.
        let st = State::in_memory().await.expect("base");
        st.upsert_app("gitea", &manifest("gitea"), None)
            .await
            .expect("app");
        let o = Arc::new(FakeOrch::default());
        let e = state_with_orchestrator(st, o.clone());

        let (s, v) = delete(router(e.clone()), "/api/apps/gitea?apply=true", "{}").await;

        assert_eq!(s, StatusCode::OK);
        assert_eq!(v["applied"], false);
        assert!(o.removed.lock().expect("mutex").is_empty());
        assert_eq!(
            e.state.installed_apps().await.expect("apps").len(),
            1,
            "the app was forgotten without a confirmation"
        );
    }

    /// A state whose daemon confirms destructions through a PocketID at `idp.example`.
    fn confirming_state(st: State, o: Arc<FakeOrch>) -> Arc<AppState> {
        let mut e = base_state(Arc::new(st), true);
        let base = "https://idp.example";
        e.privd = hlb_privd::Privd::new(e.state.clone())
            .with_mail(None, &e.mail_domain)
            .with_orchestrator(Some(o))
            .confirming_through(hlb_identity::oidc::Oidc::with_endpoints(
                hlb_identity::oidc::Endpoints {
                    issuer: base.into(),
                    authorization_endpoint: format!("{base}/authorize"),
                    token_endpoint: format!("{base}/token"),
                    userinfo_endpoint: format!("{base}/userinfo"),
                    end_session_endpoint: None,
                },
                "hlb",
                "secret",
                format!("https://hlb.example{}", hlb_api::intent::CALLBACK),
            ));
        Arc::new(e)
    }

    #[tokio::test]
    async fn a_deletion_waits_for_a_passkey_and_its_preview_does_not() {
        let st = State::in_memory().await.expect("base");
        st.upsert_app("gitea", &manifest("gitea"), None)
            .await
            .expect("app");
        let o = Arc::new(FakeOrch::default());
        let e = confirming_state(st, o.clone());

        let (s, v) = delete(router(e.clone()), "/api/apps/gitea", "{}").await;
        assert_eq!(s, StatusCode::OK, "a preview asked for a passkey: {v}");

        let resp = router(e.clone())
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/api/apps/gitea?apply=true")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"confirmed":"gitea"}"#))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(resp.status(), StatusCode::PRECONDITION_REQUIRED);
        let url = resp
            .headers()
            .get(crate::passkey::URL_HEADER)
            .and_then(|v| v.to_str().ok())
            .expect("the address to present a passkey at");
        assert!(url.starts_with("https://idp.example/authorize?"), "{url}");
        assert!(url.contains("&prompt=login"), "{url}");
        assert!(o.removed.lock().expect("mutex").is_empty());

        // A proof PocketID never gave is the daemon's to refuse: nothing moves.
        let resp = router(e.clone())
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/api/apps/gitea?apply=true")
                    .header("content-type", "application/json")
                    .header(crate::passkey::STATE_HEADER, "made-up")
                    .header(crate::passkey::CODE_HEADER, "made-up")
                    .body(Body::from(r#"{"confirmed":"gitea"}"#))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert!(!resp.status().is_success(), "{}", resp.status());
        assert!(o.removed.lock().expect("mutex").is_empty());
        assert_eq!(e.state.installed_apps().await.expect("apps").len(), 1);
    }

    #[tokio::test]
    async fn an_app_that_could_not_be_stopped_is_never_forgotten() {
        // 🔴 No orchestrator: the service may well still be running. Forgetting the app
        // anyway would hide it from every screen — the failure mode this whole project
        // exists to avoid. The step says "not implemented", and the app STAYS.
        let st = State::in_memory().await.expect("base");
        st.upsert_app("gitea", &manifest("gitea"), None)
            .await
            .expect("app");
        let e = app_state(st, true); // no orchestrator

        let (s, v) = delete(
            router(e.clone()),
            "/api/apps/gitea?apply=true",
            r#"{"confirmed":"gitea"}"#,
        )
        .await;

        assert_eq!(s, StatusCode::OK);
        assert!(
            !v["steps"].to_string().contains("forget"),
            "the app was forgotten although nothing stopped it: {}",
            v["steps"]
        );
        assert_eq!(
            e.state.installed_apps().await.expect("apps").len(),
            1,
            "the app must survive a deletion that could not stop it"
        );
    }

    /// An app with one destination, so the backup route has somewhere to go.
    async fn app_with_destination(st: &State) {
        st.upsert_app("gitea", &manifest("gitea"), None)
            .await
            .expect("app");
        // Something to back up: an app holding nothing is owed no copy.
        st.add_volume("gitea", "gitea-data", "/data", true, false)
            .await
            .expect("volume");
        st.upsert_destination("nas", "/srv/backups", "critical,bulky", None)
            .await
            .expect("destination");
    }

    fn done(what: &str, destination: &str) -> hlb_backup_run::Event {
        hlb_backup_run::Event::Done {
            what: what.into(),
            destination: destination.into(),
            snapshot: "abcdef1234".into(),
        }
    }

    #[tokio::test]
    async fn back_up_now_shows_each_destination_as_the_pass_left_it() {
        // 🔴 The route wrote one repository and marked EVERY declared destination
        // done. A destination the pass did not reach keeps no green line, and the one
        // it failed on says why.
        let st = State::in_memory().await.expect("base");
        app_with_destination(&st).await;
        st.upsert_destination("offsite", "s3:x/y", "critical,bulky", None)
            .await
            .expect("destination");
        let b = FakeBackup::reporting(vec![
            done("gitea volumes", "nas"),
            hlb_backup_run::Event::Failed {
                what: "gitea volumes".into(),
                destination: Some("offsite".into()),
                error: "repository unreachable".into(),
            },
        ]);
        let e = state_with_backup(st, b.clone());

        let (s, v) = post(router(e), "/api/apps/gitea/backup?apply=true", "{}").await;

        assert_eq!(s, StatusCode::OK, "a failed backup is not a server error");
        assert_eq!(v["applied"], true, "{v}");
        assert_eq!(b.called.lock().expect("mutex").as_slice(), ["gitea"]);
        let steps = v["steps"].as_array().expect("steps");
        let state_of = |dest: &str| {
            steps
                .iter()
                .find(|s| s["description"].as_str().is_some_and(|d| d.contains(dest)))
                .map(|s| s["state"].clone())
        };
        assert_eq!(
            state_of("nas"),
            Some(serde_json::json!("done")),
            "{steps:?}"
        );
        assert_eq!(
            state_of("offsite"),
            Some(serde_json::json!("failed")),
            "{steps:?}"
        );
        assert!(v["steps"].to_string().contains("repository unreachable"));
    }

    #[tokio::test]
    async fn a_destination_the_pass_never_reached_is_never_shown_done() {
        let st = State::in_memory().await.expect("base");
        app_with_destination(&st).await;
        st.upsert_destination("offsite", "s3:x/y", "critical,bulky", None)
            .await
            .expect("destination");
        let e = state_with_backup(
            st,
            FakeBackup::reporting(vec![done("gitea volumes", "nas")]),
        );

        let (_, v) = post(router(e), "/api/apps/gitea/backup?apply=true", "{}").await;

        let steps = v["steps"].as_array().expect("steps");
        assert!(
            !steps.iter().any(|s| s["state"] == "done"
                && s["description"]
                    .as_str()
                    .is_some_and(|d| d.contains("offsite"))),
            "{steps:?}"
        );
        assert_eq!(steps.iter().filter(|s| s["state"] == "done").count(), 1);
    }

    #[tokio::test]
    async fn a_pass_that_could_not_run_is_a_failure_said() {
        let st = State::in_memory().await.expect("base");
        app_with_destination(&st).await;
        let b = Arc::new(FakeBackup {
            events: Vec::new(),
            fails: Some("the vault's key is missing".into()),
            called: Default::default(),
        });
        let e = state_with_backup(st, b);

        let (_, v) = post(router(e), "/api/apps/gitea/backup?apply=true", "{}").await;

        assert_eq!(v["steps"][0]["state"], "failed", "{v}");
        assert!(v["steps"].to_string().contains("key is missing"));
    }

    #[tokio::test]
    async fn a_preview_never_backs_anything_up() {
        let st = State::in_memory().await.expect("base");
        app_with_destination(&st).await;
        let b = FakeBackup::reporting(vec![done("gitea volumes", "nas")]);
        let e = state_with_backup(st, b.clone());

        let (s, v) = post(router(e), "/api/apps/gitea/backup", "{}").await;

        assert_eq!(s, StatusCode::OK);
        assert_eq!(v["applied"], false);
        assert_eq!(v["steps"][0]["state"], "planned", "{v}");
        assert!(b.called.lock().expect("mutex").is_empty());
    }

    #[tokio::test]
    async fn an_app_holding_nothing_is_owed_no_backup_and_told_so() {
        let st = State::in_memory().await.expect("base");
        st.upsert_app("valkey", &manifest("valkey"), None)
            .await
            .expect("app");
        st.upsert_destination("nas", "/srv/backups", "critical,bulky", None)
            .await
            .expect("destination");
        let b = FakeBackup::reporting(Vec::new());
        let e = state_with_backup(st, b.clone());

        let (s, v) = post(router(e), "/api/apps/valkey/backup?apply=true", "{}").await;

        assert_eq!(s, StatusCode::OK, "{v}");
        assert_eq!(v["applied"], false, "{v}");
        assert!(v["blockers"].to_string().contains("holds nothing"), "{v}");
        assert!(b.called.lock().expect("mutex").is_empty());
    }

    #[tokio::test]
    async fn without_a_backup_pass_nothing_reads_as_done() {
        // ⚠️ `Unimplemented`, not `Failed`: a controller running no pass (the
        // demonstration) is a configuration, not a backup that went wrong.
        let st = State::in_memory().await.expect("base");
        app_with_destination(&st).await;
        let e = app_state(st, true); // no pass

        let (s, v) = post(router(e), "/api/apps/gitea/backup?apply=true", "{}").await;

        assert_eq!(s, StatusCode::OK);
        assert_eq!(v["steps"][0]["state"], "unimplemented", "{v}");
    }

    #[tokio::test]
    async fn my_aliases_are_mine_and_the_worst_comes_first() {
        // 🔴 Two properties in one call. The list is scoped to the SIGNED-IN account —
        // reading someone else's aliases would expose the map of who they write to.
        // And an expired alias that STILL receives comes first: it is the only line
        // that betrays the promise made to its owner.
        let st = State::in_memory().await.expect("base");
        st.upsert_user("lena", "standard", None)
            .await
            .expect("user");
        st.upsert_user("sacha", "standard", None)
            .await
            .expect("user");

        let now = crate::auth::now();
        st.add_alias("lena", "lena", "shop-ok", None, Some("shop"), None)
            .await
            .expect("alias");
        // Expired three days ago and never purged: still receiving.
        st.add_alias(
            "lena",
            "lena",
            "leaky",
            Some(now - 3 * 86_400),
            Some("news"),
            None,
        )
        .await
        .expect("alias");
        st.add_alias("sacha", "sacha", "not-mine", None, None, None)
            .await
            .expect("alias");

        let (value, stored) = hlb_types::token::generate("t", hlb_types::Role::User, [7u8; 32]);
        st.store_token(&stored).await.expect("token");
        st.set_token_user("t", Some("lena")).await.expect("bind");

        let (s, v) = get_with_token(
            router(app_state(st, false)),
            "/api/me/aliases",
            Some(&value),
        )
        .await;

        assert_eq!(s, StatusCode::OK);
        let list = v.as_array().expect("list");
        assert_eq!(list.len(), 2, "someone else's aliases leaked in: {v}");
        assert_eq!(
            list[0]["state"], "expired-but-active",
            "the open door must come first: {v}"
        );
    }

    #[tokio::test]
    async fn devices_never_read_are_not_shown_as_none() {
        // "No device" would tell someone their old phone's password is gone when
        // nobody asked Stalwart: a house without mail, or a token bound to nobody.
        let st = State::in_memory().await.expect("base");
        st.upsert_user("lena", "standard", None)
            .await
            .expect("user");
        let lena = bound_token(&st, "lena", hlb_types::Role::User).await;
        let (nobody, stored) = hlb_types::token::generate("svc", hlb_types::Role::User, [9u8; 32]);
        st.store_token(&stored).await.expect("token");
        let r = router(app_state(st, false));

        for token in [&lena, &nobody] {
            let (s, v) = get_with_token(r.clone(), "/api/me/devices", Some(token)).await;
            assert_eq!(s, StatusCode::OK);
            assert_eq!(v["devices"], serde_json::json!([]), "{v}");
            assert!(v["unreadable"].is_string(), "read as none: {v}");
        }
    }

    #[tokio::test]
    async fn a_service_token_has_no_aliases_of_its_own() {
        // A token bound to nobody acts on nobody's behalf: picking an account for it
        // would hand it someone else's addresses.
        let st = State::in_memory().await.expect("base");
        st.upsert_user("lena", "standard", None)
            .await
            .expect("user");
        st.add_alias("lena", "lena", "shop", None, None, None)
            .await
            .expect("alias");

        let (value, stored) = hlb_types::token::generate("svc", hlb_types::Role::Admin, [9u8; 32]);
        st.store_token(&stored).await.expect("token");

        let (s, v) = get_with_token(
            router(app_state(st, false)),
            "/api/me/aliases",
            Some(&value),
        )
        .await;

        assert_eq!(s, StatusCode::OK);
        assert_eq!(v.as_array().expect("list").len(), 0, "{v}");
    }

    #[tokio::test]
    async fn healthz_reports_liveness() {
        let (s, v) = get(app().await, "/healthz").await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(v["status"], "ok");
        assert_eq!(v["version"], "test");
    }

    #[tokio::test]
    async fn apps_are_listed_with_their_backup_state() {
        let (s, v) = get(app().await, "/api/apps").await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(v[0]["name"], "gitea");
        assert_eq!(v[0]["domain"], "git.example.fr");
        assert_eq!(v[0]["last_backup_secs"], serde_json::Value::Null);
        assert_eq!(v[0]["blocking_guides"], 1);
    }

    #[tokio::test]
    async fn an_unknown_app_gives_404_not_500() {
        let (s, v) = get(app().await, "/api/apps/does-not-exist").await;
        assert_eq!(s, StatusCode::NOT_FOUND);
        assert!(v["error"].as_str().expect("message").contains("unknown"));
    }

    #[tokio::test]
    async fn pending_guides_are_exposed() {
        let (_, v) = get(app().await, "/api/todo").await;
        assert_eq!(v[0]["id"], "first-admin");
        assert_eq!(v[0]["blocking"], true);
    }

    #[tokio::test]
    async fn the_audit_trail_is_exposed() {
        let (s, v) = get(app().await, "/api/audit").await;
        assert_eq!(s, StatusCode::OK);
        assert!(v["entries"].is_array());
        // The page says what it is a page of: a list cut without a count reads as whole.
        assert!(v["matched"].is_u64() && v["total"].is_u64());
        assert_eq!(v["page_size"], AUDIT_PAGE);
    }

    #[tokio::test]
    async fn secrets_expose_names_never_values() {
        let (s, v) = get(app().await, "/api/secrets").await;
        assert_eq!(s, StatusCode::OK);
        // The type simply carries no "value" field.
        let raw = serde_json::to_string(&v).expect("serialisable");
        assert!(!raw.contains("value"), "{raw}");
        assert!(!raw.contains("secret_value"), "{raw}");
    }

    async fn text(r: Router, uri: &str) -> (StatusCode, String, String) {
        let resp = r
            .oneshot(
                Request::builder()
                    .uri(uri)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        let status = resp.status();
        let ct = resp
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .expect("body");
        (status, ct, String::from_utf8_lossy(&bytes).into_owned())
    }

    #[tokio::test]
    async fn metrics_are_served_as_prometheus_text() {
        let (s, ct, body) = text(app().await, "/metrics").await;
        assert_eq!(s, StatusCode::OK);
        // An `application/json` would make the collector reject the whole batch.
        assert!(ct.starts_with("text/plain"), "{ct}");
        assert!(
            body.contains("hlb_app_up{app=\"gitea\",status=\"running\"} 1"),
            "{body}"
        );
        assert!(
            body.contains("hlb_blocking_guides{app=\"gitea\"} 1"),
            "{body}"
        );
        // Never backed up: no age sample (cf. metrics::render).
        assert!(!body.contains("hlb_backup_age_seconds{app="), "{body}");
    }

    #[tokio::test]
    async fn metrics_never_leak_secret_values() {
        // The exposure endpoint is the most likely to be scraped by a third party.
        let (_, _, body) = text(app().await, "/metrics").await;
        assert!(!body.contains("PrivateKey"), "{body}");
        assert!(!body.to_lowercase().contains("password"), "{body}");
    }

    /// A protected API, and the value of the token that opens it.
    async fn protected_app() -> (Router, String) {
        let st = State::in_memory().await.expect("base");
        st.upsert_app("gitea", &manifest("gitea"), None)
            .await
            .expect("upsert");

        let (value, stored) =
            hlb_types::generate_token("test", hlb_types::Role::Viewer, [42u8; 32]);
        st.store_token(&stored).await.expect("token");

        let r = router(app_state(st, false));
        (r, value)
    }

    /// Like `get`, but with an optional token and the body decoded.
    async fn get_with_token(
        r: Router,
        uri: &str,
        token: Option<&str>,
    ) -> (StatusCode, serde_json::Value) {
        let mut req = Request::builder().uri(uri);
        if let Some(j) = token {
            req = req.header("Authorization", format!("Bearer {j}"));
        }
        let resp = r
            .oneshot(req.body(Body::empty()).expect("request"))
            .await
            .expect("response");
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .expect("body");
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
        )
    }

    async fn get_route_with_token(r: Router, route: &str, token: Option<&str>) -> StatusCode {
        let mut req = Request::builder().uri(route);
        if let Some(j) = token {
            req = req.header("Authorization", format!("Bearer {j}"));
        }
        r.oneshot(req.body(Body::empty()).expect("request"))
            .await
            .expect("response")
            .status()
    }

    #[tokio::test]
    async fn a_wrong_token_is_refused_like_no_token() {
        // ⚠️ An identical answer: distinguishing would tell an attacker whether a value
        // they tried exists.
        let (r, _) = protected_app().await;
        assert_eq!(
            get_route_with_token(r, "/api/apps", Some("FAUXJETON")).await,
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn a_valid_token_gets_through() {
        let (r, token) = protected_app().await;
        assert_eq!(
            get_route_with_token(r, "/api/apps", Some(&token)).await,
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn health_stays_open_for_probes() {
        // A liveness probe cannot carry a token: Swarm does not give it one. Closing
        // /healthz would make the controller restart in a loop.
        let (r, _) = protected_app().await;
        assert_eq!(
            get_route_with_token(r, "/healthz", None).await,
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn the_open_mode_is_explicit_not_a_default() {
        // 🔴 `no_auth` only exists so as not to break an existing deployment, and the
        // controller refuses to start in this state without an explicit flag.
        let (s, _) = get(app().await, "/api/apps").await;
        assert_eq!(s, StatusCode::OK, "open mode must stay open");
    }

    #[test]
    fn assets_are_served_with_the_mime_the_browser_demands() {
        // 🔴 A module script served as application/octet-stream is refused outright,
        // with a message that does not say what it expected.
        assert_eq!(mime_of("_app/immutable/entry/start.js"), "text/javascript");
        // ⚠️ An SVG served as octet-stream is not displayed at all: the PWA's icon would
        // be empty, and nothing would say why.
        assert_eq!(mime_of("icone.svg"), "image/svg+xml");
        assert_eq!(mime_of("fonts/NotoSans-Regular.woff2"), "font/woff2");
        assert!(mime_of("index.html").starts_with("text/html"));
    }

    #[test]
    fn path_traversal_is_refused() {
        // 🔴 The controller often runs as root on a node: escaping the UI directory is
        // not a theoretical risk.
        assert!(!name_on("../../etc/shadow"));
        assert!(!name_on("/etc/passwd"));
        assert!(!name_on("a/../../b"));
        assert!(!name_on(""));
        assert!(name_on("_app/immutable/entry/start.js"));
        assert!(name_on("index.html"));
    }

    #[tokio::test]
    async fn without_a_ui_directory_the_root_says_so() {
        // A silent 404 would suggest a controller outage.
        let (s, _, body) = text(app().await, "/").await;
        assert_eq!(s, StatusCode::NOT_FOUND);
        assert!(body.contains("--ui-dir"), "{body}");
    }

    #[tokio::test]
    async fn a_screen_reloaded_gets_the_interface_and_a_missing_file_does_not() {
        let dir = tempfile::tempdir().expect("tmp");
        std::fs::write(dir.path().join("index.html"), "<!doctype html>the shell").expect("index");
        std::fs::create_dir_all(dir.path().join("_app/immutable")).expect("dirs");
        std::fs::write(dir.path().join("_app/immutable/start.js"), "export {}").expect("js");
        let st = State::in_memory().await.expect("base");
        let mut s = base_state(Arc::new(st), true);
        s.ui_dir = Some(dir.path().to_path_buf());
        let r = router(Arc::new(s));

        // A reload, or a link someone shared, on a screen the browser routes.
        for screen in [
            "/",
            "/apps/gitea",
            "/apps/gitea/history",
            "/settings",
            // A dot is not an extension: an address, a name.
            "/nodes/10.0.0.2:8421",
            "/accounts/alex.garcia",
        ] {
            let (s, ct, body) = text(r.clone(), screen).await;
            assert_eq!(s, StatusCode::OK, "{screen}");
            assert!(ct.starts_with("text/html"), "{screen}: {ct}");
            assert!(body.contains("the shell"), "{screen}");
        }
        let (s, ct, _) = text(r.clone(), "/_app/immutable/start.js").await;
        assert_eq!((s, ct.as_str()), (StatusCode::OK, "text/javascript"));

        // Under a prefix the server routes, and a file that is not there: a 404 that
        // says so, never the interface's page.
        for absent in [
            "/api/does-not-exist",
            "/auth/nowhere",
            "/_app/immutable/gone.js",
            "/favicon.ico",
        ] {
            let (s, _, body) = text(r.clone(), absent).await;
            assert_eq!(s, StatusCode::NOT_FOUND, "{absent}");
            assert!(!body.contains("the shell"), "{absent}");
        }
    }

    #[tokio::test]
    async fn a_verb_no_route_declares_is_still_rejected() {
        // The old rule — "no mutating verb anywhere" — has been lifted: the API must now
        // install, back up and manage accounts. What stays true, and what we check here,
        // is that a mutating verb on a read route is not silently accepted.
        // is not silently accepted.
        for method in ["POST", "PUT", "DELETE", "PATCH"] {
            let r = app().await;
            let resp = r
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri("/api/apps")
                        .body(Body::empty())
                        .expect("request"),
                )
                .await
                .expect("response");
            assert_eq!(
                resp.status(),
                StatusCode::METHOD_NOT_ALLOWED,
                "{method} /api/apps should be refused"
            );
        }
    }

    #[tokio::test]
    async fn no_route_acts_without_apply() {
        // 🔴 The project's CENTRAL INVARIANT, transposed to HTTP: the default mode
        // changes nothing. Visiting a screen must never become an execution.
        //
        // The test walks the document the router is built from: an action added
        // without respecting the rule makes it fail.
        for m in crate::openapi::routes() {
            // ⚠️ The extension, not a list of paths to maintain: a route that changes
            // something and declares no choice fails
            // `every_route_declares_who_may_call_it`.
            if m.preview != Some(true) {
                continue;
            }

            let st = State::in_memory().await.expect("base");
            st.upsert_app("gitea", &manifest("gitea"), None)
                .await
                .expect("app");
            st.add_guide("gitea", "first-admin", "Create the admin", true)
                .await
                .expect("guide");
            let state = app_state(st, true);
            let r = router(state.clone());

            let uri = m
                .path
                .replace("{name}", "gitea")
                .replace("{app}", "gitea")
                .replace("{name}", "nas")
                .replace("{reference}", "a1b2c3d4")
                .replace("{account}", "lena")
                .replace("{role}", "viewer")
                // ⚠️ `{id}` does not mean the same thing depending on the route: a node,
                // a guide identifier, or an announcement integer. A single replacement
                // would give URIs the router refuses, and the test would believe the
                // route was at fault.
                .replace(
                    "{id}",
                    if m.path.contains("/nodes/") {
                        "n1"
                    } else if m.path.contains("/announcements/") {
                        "1"
                    } else {
                        "first-admin"
                    },
                );

            let resp = r
                .oneshot(
                    Request::builder()
                        .method(m.verb.as_str())
                        .uri(&uri)
                        .header("content-type", "application/json")
                        .body(Body::from("{}"))
                        .expect("request"),
                )
                .await
                .expect("response");

            // ⚠️ The status code is NOT what we check. A route can refuse to plan (422:
            // catalog absent, unknown app) — that is a perfectly valid "nothing was
            // done". What matters is `applied`.
            let status = resp.status();
            assert!(
                status == StatusCode::OK || status == StatusCode::UNPROCESSABLE_ENTITY,
                "{} {uri} answers {status}",
                m.verb
            );

            let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
                .await
                .expect("body");
            let v: serde_json::Value =
                serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);

            assert_eq!(
                v["applied"], false,
                "{} {uri} ACTED without ?apply=true",
                m.verb
            );
            // And nothing must be marked as done.
            if let Some(steps) = v["steps"].as_array() {
                for e in steps {
                    assert_eq!(
                        e["state"], "planned",
                        "{} {uri}: a step is marked done in preview",
                        m.verb
                    );
                }
            }
        }
    }

    /// Who may call each route, as the document declares it.
    fn declared() -> &'static [crate::openapi::Route] {
        let routes = crate::openapi::routes();
        // Sixty-eight on 2026-10-05: a walk that stopped finding them would pass.
        assert!(
            routes.len() >= 60,
            "only {} routes in the document",
            routes.len()
        );
        routes
    }

    /// The action an id names, among those a route can require.
    fn action_named(id: &str) -> hlb_types::rbac::Action {
        *crate::auth::MARKERS
            .iter()
            .find(|a| a.name() == id)
            .unwrap_or_else(|| panic!("\"{id}\" names no action"))
    }

    #[test]
    fn every_route_declares_who_may_call_it() {
        // 🔴 The tests below walk these declarations, so a route that makes none is a
        // route none of them checks. Exactly one of the two: an action required, or
        // open on purpose — and a route that changes something says whether it
        // previews, since doubt there must be a decision, not a default.
        for r in declared() {
            let at = format!("{} {}", r.verb, r.path);
            match (&r.requires, r.public) {
                (Some(id), false) => {
                    action_named(id);
                }
                (None, true) => {}
                (Some(_), true) => panic!("{at} is public AND requires an action"),
                (None, false) => panic!(
                    "{at} declares neither `{}` nor `{}`",
                    crate::openapi::REQUIRES,
                    crate::openapi::PUBLIC
                ),
            }
            assert_eq!(
                r.preview.is_some(),
                r.mutates(),
                "{at}: `{}` is declared on every route that changes something, and \
                 only there",
                crate::openapi::PREVIEW
            );
        }
    }

    #[test]
    fn public_routes_are_an_explicit_short_list() {
        // 🔴 A route made public by inattention opens the whole system, and nothing
        // would say so. The list is therefore locked. What changes something has one
        // legitimate exception: the request of someone who does not have an account
        // yet and carries their own authorization. What reads is what a person sees
        // before signing in — the house's name, colours and letters — plus Swarm's
        // probe, the way to sign in and back from a passkey, and the status page that
        // refuses by itself until someone opens it.
        let public: Vec<String> = declared()
            .iter()
            .filter(|r| r.public)
            .map(|r| format!("{} {}", r.verb, r.path))
            .collect();
        let expected = [
            "POST /api/signup",
            "GET /api/appearance",
            "GET /api/appearance/logo",
            "GET /api/catalog/{name}/icon",
            "GET /api/themes",
            "GET /api/themes/{name}/font/{family}",
            "GET /auth/confirmed",
            "GET /auth/return_to",
            "GET /auth/signin",
            "GET /healthz",
            "GET /status",
        ];
        let mut sorted: Vec<&str> = public.iter().map(String::as_str).collect();
        sorted.sort_unstable();
        let mut wanted = expected.to_vec();
        wanted.sort_unstable();
        assert_eq!(sorted, wanted);
    }

    #[test]
    fn opting_out_of_preview_is_an_explicit_short_list() {
        // 🔴 The safeguard's safeguard: `preview: false` must stay the exception. If the
        // list grows, the rule is emptying out — and the test says so before you notice
        // it in use.
        let sans: Vec<&str> = declared()
            .iter()
            .filter(|r| r.preview == Some(false))
            .map(|r| r.path.as_str())
            .collect();

        // The only legitimate exemptions: idempotent configuration, signing out, the
        // addy.io contract imposed by Bitwarden, and the same "nothing to preview"
        // class of self-service personal-resource creation the alias route already
        // established.
        let expected_items = [
            "/api/appearance",
            "/api/appearance/logo",
            "/api/preferences/theme",
            "/api/preferences/home",
            "/api/preferences/density",
            // Setting an inbox line aside: what one person sees, undone in one click.
            "/api/issues/aside",
            // Muting an alert: a declaration undone in one click, like attesting a
            // safeguard — and it changes nothing on the infrastructure.
            "/api/alerts/{rule}/mute",
            "/auth/signout",
            "/api/v1/aliases",
            // Attesting a break-glass safeguard is a DECLARATION, not an action on the
            // infrastructure: nothing deploys, nothing is destroyed, and you untick it
            // in one click. There is literally nothing to preview.
            "/api/recovery/{id}",
            // Recording a plan executes nothing: it is the preview you file away, not an
            // action being launched.
            "/api/plans",
            // The token's value only exists at the moment of creation: a preview would
            // either show it a first time, or describe a creation that did not happen.
            // Neither makes sense.
            "/api/bitwarden",
            // Same reasoning as `/api/v1/aliases`, minus the Bitwarden contract:
            // "create my own mailbox" has no plan to preview ahead of the creation
            // itself.
            "/api/me/mailbox",
        ];
        for c in &sans {
            assert!(
                expected_items.contains(c),
                "\"{c}\" skips the preview with no documented reason"
            );
        }
    }

    #[tokio::test]
    async fn every_route_refuses_an_anonymous_caller() {
        // 🔴 The API exposes the fleet's state, the audit log and the NAMES of the
        // secrets. A single forgotten route is enough to give it all away. This read
        // five routes named by hand until 2026-10-05; it walks the document now, so a
        // route added tomorrow is in it.
        let mut checked = 0;
        for r in declared() {
            if r.public {
                continue;
            }
            let (router, _) = protected_app().await;
            let resp = router
                .oneshot(
                    Request::builder()
                        .method(r.verb.as_str())
                        .uri(&r.path)
                        .header("content-type", "application/json")
                        .body(Body::from("{}"))
                        .expect("request"),
                )
                .await
                .expect("response");
            assert_eq!(
                resp.status(),
                StatusCode::UNAUTHORIZED,
                "{} {} accepts an anonymous caller",
                r.verb,
                r.path
            );
            checked += 1;
        }
        assert!(checked >= 50, "only {checked} private routes checked");
    }

    /// What a route answers a caller holding `role`, through a real token.
    async fn status_for(r: &crate::openapi::Route, role: hlb_types::Role) -> StatusCode {
        let st = State::in_memory().await.expect("base");
        let (value, stored) = hlb_types::generate_token("caller", role, [7u8; 32]);
        st.store_token(&stored).await.expect("token");
        // Bound to a person: an act-on-self route refuses a service token whatever its
        // role, and that refusal is the handler's, not the threshold's. A person holding
        // the same level — a bound token never does more than its person.
        if st.role(role.as_str()).await.expect("role").is_none() {
            let def =
                hlb_users::RoleDef::new(role.as_str(), role, hlb_users::MailLimits::standard());
            st.put_role(&def, "test").await.expect("role");
        }
        st.upsert_user("lena", role.as_str(), None)
            .await
            .expect("person");
        st.set_user_role("lena", role.as_str(), None)
            .await
            .expect("role");
        st.set_token_user("caller", Some("lena"))
            .await
            .expect("binding");
        router(app_state(st, false))
            .oneshot(
                Request::builder()
                    .method(r.verb.as_str())
                    .uri(&r.path)
                    .header("Authorization", format!("Bearer {value}"))
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .expect("request"),
            )
            .await
            .expect("response")
            .status()
    }

    #[tokio::test]
    async fn every_route_refuses_a_role_below_its_threshold() {
        // The role was authenticated but NEVER matched: `Role::allows` had no caller in
        // production. A `viewer` token could create aliases.
        for r in declared() {
            let Some(id) = &r.requires else { continue };
            let action = action_named(id);
            let Some(too_low) = hlb_types::Role::all()
                .into_iter()
                .find(|role| !role.allows(action))
            else {
                // An action even the lowest role allows: nothing to check.
                continue;
            };
            assert_eq!(
                status_for(r, too_low).await,
                StatusCode::FORBIDDEN,
                "{} {} accepts role {}",
                r.verb,
                r.path,
                too_low.as_str()
            );
        }
    }

    #[tokio::test]
    async fn every_route_lets_through_the_role_it_declares() {
        // The other half: a route whose declaration says LESS than its handler requires
        // would pass the test above — a role below an understated threshold is below
        // the real one too — and the document would promise a screen to people the
        // handler then refuses. The lowest role the declaration allows must get past
        // authorization; what the handler answers next is not this test's business.
        for r in declared() {
            let Some(id) = &r.requires else { continue };
            let action = action_named(id);
            let lowest = action.minimum_role();
            let status = status_for(r, lowest).await;
            assert!(
                status != StatusCode::UNAUTHORIZED && status != StatusCode::FORBIDDEN,
                "{} {} refuses role {} with {status}, which its declaration \"{id}\" allows",
                r.verb,
                r.path,
                lowest.as_str()
            );
        }
    }

    /// A state that can really install: catalog, orchestrator and vault.
    ///
    /// The vault lives in a `TempDir` the caller keeps alive — dropping it would remove
    /// the master key under the executor's feet.
    fn state_that_can_install(
        st: State,
        cat: hlb_catalog::Catalog,
        o: Arc<FakeOrch>,
        key: &std::path::Path,
    ) -> Arc<AppState> {
        let mut e = base_state(Arc::new(st), true);
        let cat = Arc::new(cat);
        let install = hlb_privd::InstallContext {
            vault: hlb_secrets::Vault::open_or_init(key).expect("vault"),
            registry: hlb_registry::RegistryClient::new(),
            // 🔴 No database client: the executor must record the provisioning as
            // unimplemented instead of skipping it. That is the case this test locks.
            postgres: None,
            mariadb: None,
            storage: Default::default(),
            api: hlb_guide::HttpApi::default(),
        };
        e.privd = hlb_privd::Privd::new(e.state.clone())
            .with_mail(None, &e.mail_domain)
            .with_catalog(Some(cat.clone()))
            .with_orchestrator(Some(o))
            .with_install(Some(Arc::new(install)));
        e.catalog = hlb_privd::catalog::SharedCatalog::new(Some(cat));
        Arc::new(e)
    }

    #[tokio::test]
    async fn installing_really_deploys_through_the_executor() {
        // 🔴 The route used to preview the real plan and then report every action as
        // unimplemented. It now runs the SAME executor as `hlb install`. The proof is
        // that the deploy REACHED the orchestrator — not that the response looks green.
        //
        // valkey on purpose: it declares no blocking guide, so nothing legitimately
        // stops the run before it starts.
        let Ok(cat) = hlb_catalog::Catalog::load("../../catalog") else {
            return;
        };
        let dir = tempfile::tempdir().expect("tempdir");
        let st = State::in_memory().await.expect("base");
        let o = Arc::new(FakeOrch::default());
        let e = state_that_can_install(st, cat, o.clone(), &dir.path().join("key"));

        let (s, v) = post(
            router(e.clone()),
            "/api/apps/valkey/install?apply=true",
            "{}",
        )
        .await;

        assert_eq!(s, StatusCode::OK, "{v}");
        assert_eq!(v["applied"], true, "{v}");
        assert_eq!(
            o.deployed.lock().expect("mutex").as_slice(),
            ["valkey".to_string()],
            "the executor never reached the orchestrator"
        );
        assert!(
            e.state
                .installed_apps()
                .await
                .expect("apps")
                .iter()
                .any(|(n, _)| n == "valkey"),
            "the app was deployed without being recorded"
        );
    }

    /// A catalog of valkey alone, its guide a blocking prerequisite whose check is a
    /// TCP connection to `target`.
    fn catalog_with_prerequisite(dir: &std::path::Path, target: &str) -> hlb_catalog::Catalog {
        let app = dir.join("valkey");
        std::fs::create_dir_all(&app).expect("dir");
        std::fs::write(
            app.join("manifest.yaml"),
            include_str!("../../../catalog/_platform/valkey/manifest.yaml"),
        )
        .expect("manifest");
        std::fs::write(
            app.join("guide.yaml"),
            format!(
                r#"
steps:
  - id: port
    title: Open the port
    phase: pre-install
    severity: blocking
    verify:
      type: tcp
      target: "{target}"
"#
            ),
        )
        .expect("guide");
        hlb_catalog::Catalog::load(dir).expect("catalog")
    }

    /// A port nothing listens on.
    fn closed_port() -> String {
        let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = l.local_addr().expect("addr").to_string();
        drop(l);
        addr
    }

    #[tokio::test]
    async fn a_prerequisite_its_check_proves_done_does_not_stop_the_interface_s_install() {
        // 🔴 The route counted the plan's prerequisites without checking them: every app
        // whose guide starts with a DNS record — ten in the catalog — could never be
        // installed from the interface, even under a wildcard record.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let open = listener.local_addr().expect("addr").to_string();
        let dir = tempfile::tempdir().expect("tempdir");
        let cat = catalog_with_prerequisite(&dir.path().join("catalog"), &open);
        let st = State::in_memory().await.expect("base");
        let o = Arc::new(FakeOrch::default());
        let e = state_that_can_install(st, cat, o.clone(), &dir.path().join("key"));

        let (s, v) = post(router(e.clone()), "/api/apps/valkey/install", "{}").await;
        assert_eq!(s, StatusCode::OK, "{v}");
        assert_eq!(v["blockers"], serde_json::json!([]), "{v}");
        assert!(
            e.state.installed_apps().await.expect("apps").is_empty(),
            "a preview records nothing"
        );

        let (s, v) = post(
            router(e.clone()),
            "/api/apps/valkey/install?apply=true",
            "{}",
        )
        .await;
        assert_eq!(s, StatusCode::OK, "{v}");
        assert_eq!(v["applied"], true, "{v}");
        assert_eq!(
            o.deployed.lock().expect("mutex").as_slice(),
            ["valkey".to_string()]
        );
        assert_eq!(
            e.state.verified_guides("valkey").await.expect("guides"),
            vec!["port"],
            "observed done, recorded so"
        );
        drop(listener);
    }

    #[tokio::test]
    async fn a_prerequisite_its_check_finds_undone_still_stops_the_interface_s_install() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cat = catalog_with_prerequisite(&dir.path().join("catalog"), &closed_port());
        let st = State::in_memory().await.expect("base");
        let o = Arc::new(FakeOrch::default());
        let e = state_that_can_install(st, cat, o.clone(), &dir.path().join("key"));
        let (s, v) = post(
            router(e.clone()),
            "/api/apps/valkey/install?apply=true",
            "{}",
        )
        .await;
        assert_eq!(s, StatusCode::OK, "{v}");
        assert_eq!(v["applied"], false, "{v}");
        assert!(v["blockers"].to_string().contains("Open the port"), "{v}");
        assert!(o.deployed.lock().expect("mutex").is_empty());
        assert!(e.state.installed_apps().await.expect("apps").is_empty());
    }

    #[tokio::test]
    async fn an_attestation_the_check_contradicts_is_refused_unless_forced() {
        // 🔴 The interface's "attest" marked a step handled without its check: a step the
        // machine could see undone opened what it guarded. `hlb ack` checks first.
        let dir = tempfile::tempdir().expect("tempdir");
        let cat = catalog_with_prerequisite(&dir.path().join("catalog"), &closed_port());
        let st = State::in_memory().await.expect("base");
        let m = cat.get("valkey").expect("valkey").manifest.clone();
        st.upsert_app("valkey", &m, None).await.expect("app");
        st.add_guide("valkey", "port", "Open the port", true)
            .await
            .expect("guide");
        let o = Arc::new(FakeOrch::default());
        let e = state_that_can_install(st, cat, o, &dir.path().join("key"));

        let (s, v) = post(router(e.clone()), "/api/todo/valkey/port?apply=true", "{}").await;
        assert_eq!(s, StatusCode::OK, "{v}");
        assert_eq!(v["applied"], false, "{v}");
        assert!(v["blockers"].to_string().contains("not done"), "{v}");
        assert_eq!(
            e.state.unverified_blocking("valkey").await.expect("read"),
            1
        );

        let (s, v) = post(
            router(e.clone()),
            "/api/todo/valkey/port?apply=true",
            r#"{"force":true}"#,
        )
        .await;
        assert_eq!(s, StatusCode::OK, "{v}");
        assert_eq!(v["applied"], true, "{v}");
        assert_eq!(v["cli_command"], "hlb ack valkey/port --force", "{v}");
        assert_eq!(
            e.state.unverified_blocking("valkey").await.expect("read"),
            0
        );
        // Recorded as forced, or the nightly re-check reopens it.
        assert!(e.state.verified_guide_ages("valkey").await.expect("read")[0].2);
    }

    #[tokio::test]
    async fn a_failed_install_resumes_from_the_interface() {
        // 🔴 A failed install was "already installed" to the route, and the upgrade it
        // named had nothing to apply: the interface had no way out.
        let Ok(cat) = hlb_catalog::Catalog::load("../../catalog") else {
            return;
        };
        let dir = tempfile::tempdir().expect("tempdir");
        let st = State::in_memory().await.expect("base");
        let o = Arc::new(FakeOrch::default());
        let e = state_that_can_install(st, cat, o.clone(), &dir.path().join("key"));
        let (s, v) = post(
            router(e.clone()),
            "/api/apps/valkey/install?apply=true",
            "{}",
        )
        .await;
        assert_eq!(
            (s, &v["applied"]),
            (StatusCode::OK, &serde_json::json!(true)),
            "{v}"
        );

        e.state
            .set_app_status("valkey", "failed")
            .await
            .expect("failed");
        let (s, v) = post(
            router(e.clone()),
            "/api/apps/valkey/install?apply=true",
            "{}",
        )
        .await;
        assert_eq!(s, StatusCode::OK, "{v}");
        assert_eq!(v["applied"], true, "{v}");

        // A running one is still the upgrade's.
        let (_, v) = post(
            router(e.clone()),
            "/api/apps/valkey/install?apply=true",
            "{}",
        )
        .await;
        assert_eq!(v["applied"], false, "{v}");
        assert!(
            v["blockers"].to_string().contains("already installed"),
            "{v}"
        );
    }

    #[tokio::test]
    async fn a_catalog_change_is_previewed_then_applied_to_the_running_service() {
        // The case found on a real cluster: an app frozen with what the catalog has
        // since changed. Rerunning its install skipped every deployment done; the
        // upgrade shows the change, then deploys it.
        let Ok(cat) = hlb_catalog::Catalog::load("../../catalog") else {
            return;
        };
        let dir = tempfile::tempdir().expect("tempdir");
        let st = State::in_memory().await.expect("base");
        let o = Arc::new(FakeOrch::default());
        let e = state_that_can_install(st, cat, o.clone(), &dir.path().join("key"));
        let (s, v) = post(
            router(e.clone()),
            "/api/apps/valkey/install?apply=true",
            "{}",
        )
        .await;
        assert_eq!(s, StatusCode::OK, "{v}");

        let mut older = e.state.app_manifest("valkey").await.expect("frozen");
        older.spec.swarm.replicas = 2;
        e.state
            .upsert_app("valkey", &older, None)
            .await
            .expect("older");
        assert_eq!(
            crate::actions::catalog_changes(&e, "valkey").await,
            vec!["spec.swarm.replicas: 2 → 1".to_string()]
        );
        let found = crate::issues::findings(&e, false).await.expect("findings");
        assert!(found
            .iter()
            .any(|(c, _, s)| *c == hlb_api::issues::Cause::CatalogChanged
                && s.as_deref() == Some("valkey")));

        let (s, v) = post(router(e.clone()), "/api/apps/valkey/upgrade", "").await;
        assert_eq!(s, StatusCode::OK, "{v}");
        assert_eq!(v["applied"], false, "a preview changed something: {v}");
        assert_eq!(
            v["steps"][0]["description"],
            "catalog: spec.swarm.replicas: 2 → 1"
        );
        assert_eq!(v["blockers"].as_array().map(Vec::len), Some(0), "{v}");

        let (s, v) = post(router(e.clone()), "/api/apps/valkey/upgrade?apply=true", "").await;
        assert_eq!(s, StatusCode::OK, "{v}");
        assert_eq!(v["applied"], true, "{v}");
        assert_eq!(
            o.deployed.lock().expect("mutex").len(),
            2,
            "not deployed again"
        );
        assert_eq!(
            e.state
                .app_manifest("valkey")
                .await
                .expect("frozen")
                .spec
                .swarm
                .replicas,
            1
        );
        assert!(crate::actions::catalog_changes(&e, "valkey")
            .await
            .is_empty());
    }

    /// The guide is frozen at install like the manifest, so a catalog that changed the
    /// guide alone is an upgrade too — or the frozen one would never move.
    #[tokio::test]
    async fn a_guide_changed_in_the_catalog_alone_is_upgraded_and_frozen_again() {
        let Ok(cat) = hlb_catalog::Catalog::load("../../catalog") else {
            return;
        };
        let dir = tempfile::tempdir().expect("tempdir");
        let st = State::in_memory().await.expect("base");
        let o = Arc::new(FakeOrch::default());
        let e = state_that_can_install(st, cat, o.clone(), &dir.path().join("key"));
        let (s, v) = post(
            router(e.clone()),
            "/api/apps/valkey/install?apply=true",
            "{}",
        )
        .await;
        assert_eq!(s, StatusCode::OK, "{v}");
        let frozen = |e: Arc<AppState>| async move {
            e.state
                .app_guide("valkey")
                .await
                .expect("read")
                .expect("frozen at install")
                .steps
                .into_iter()
                .map(|s| s.id)
                .collect::<Vec<_>>()
        };
        assert!(frozen(e.clone()).await.is_empty(), "the catalog's: none");

        let older: hlb_types::Guide =
            serde_yaml_ng::from_str("steps:\n  - { id: old, title: Gone since }\n").expect("guide");
        e.state
            .set_app_guide("valkey", Some(&older))
            .await
            .expect("older");
        assert_eq!(
            crate::actions::catalog_changes(&e, "valkey").await,
            vec!["guide: step old removed".to_string()]
        );

        let (s, v) = post(router(e.clone()), "/api/apps/valkey/upgrade?apply=true", "").await;
        assert_eq!(s, StatusCode::OK, "{v}");
        assert_eq!(v["applied"], true, "{v}");
        assert!(frozen(e.clone()).await.is_empty(), "frozen again: {v}");
        assert!(crate::actions::catalog_changes(&e, "valkey")
            .await
            .is_empty());
    }

    /// 🔴 Found on the lab on 2026-10-18: an app sending mail needs the mail domain to
    /// name its account, and the upgrade passed none — "mail_domain is required", where
    /// the install takes the exposure's.
    #[tokio::test]
    async fn an_upgrade_names_the_sending_account_in_the_exposures_domain() {
        let Ok(cat) = hlb_catalog::Catalog::load("../../catalog") else {
            return;
        };
        let dir = tempfile::tempdir().expect("tempdir");
        let st = State::in_memory().await.expect("base");
        st.set_exposure(&hlb_state::Exposure {
            domain: "lab.example.fr".into(),
            certificates: hlb_state::Certificates::Internal,
            acme_email: None,
            dns_provider: None,
            staging: false,
            controller_host: None,
            acme_ca: None,
            acme_ca_root: None,
        })
        .await
        .expect("exposure");
        let mut older = cat.get("vikunja").expect("vikunja").manifest.clone();
        older.spec.swarm.replicas = 2;
        st.upsert_app("vikunja", &older, Some("tasks.lab.example.fr"))
            .await
            .expect("installed");
        let o = Arc::new(FakeOrch::default());
        let e = state_that_can_install(st, cat, o, &dir.path().join("key"));

        let (s, v) = post(router(e), "/api/apps/vikunja/upgrade", "").await;
        assert_eq!(s, StatusCode::OK, "{v}");
        let steps = v["steps"].to_string();
        assert!(
            steps.contains("create sending account vikunja@lab.example.fr"),
            "{v}"
        );
    }

    /// 🔴 Found on the lab on 2026-10-18: the manifest was frozen before the plan ran,
    /// the plan failed, and the next upgrade found nothing to apply — the change never
    /// reached the running service.
    #[tokio::test]
    async fn an_upgrade_that_does_not_finish_keeps_the_manifest_it_had() {
        let Ok(cat) = hlb_catalog::Catalog::load("../../catalog") else {
            return;
        };
        let st = State::in_memory().await.expect("base");
        st.set_exposure(&hlb_state::Exposure {
            domain: "example.fr".into(),
            certificates: hlb_state::Certificates::Internal,
            acme_email: None,
            dns_provider: None,
            staging: false,
            controller_host: None,
            acme_ca: None,
            acme_ca_root: None,
        })
        .await
        .expect("exposure");
        let mut older = cat.get("vikunja").expect("vikunja").manifest.clone();
        older.spec.swarm.replicas = 2;
        st.upsert_app("vikunja", &older, Some("tasks.example.fr"))
            .await
            .expect("installed");
        // No orchestrator: nothing in the plan can run.
        let e = Arc::new(state_with_catalog(st, cat));
        let (s, v) = post(
            router(e.clone()),
            "/api/apps/vikunja/upgrade?apply=true",
            "",
        )
        .await;
        assert_eq!(s, StatusCode::OK, "{v}");
        let frozen = e.state.app_manifest("vikunja").await.expect("frozen");
        assert_eq!(frozen.spec.swarm.replicas, 2, "{v}");
    }

    #[tokio::test]
    async fn a_prerequisite_stops_an_install_before_any_change() {
        // 🔴 The invariant, over the API this time: LibreSpeed needs its DNS record
        // first, and the check finds none for a name no DNS knows. A post-install step
        // ("close sign-ups") holds back the route instead — it cannot be done before
        // the app runs.
        let Ok(cat) = hlb_catalog::Catalog::load("../../catalog") else {
            return;
        };
        let dir = tempfile::tempdir().expect("tempdir");
        let st = State::in_memory().await.expect("base");
        let o = Arc::new(FakeOrch::default());
        let e = state_that_can_install(st, cat, o.clone(), &dir.path().join("key"));

        let (s, v) = post(
            router(e),
            "/api/apps/librespeed/install?apply=true",
            r#"{"domain":"speed.example.invalid"}"#,
        )
        .await;

        assert_eq!(s, StatusCode::OK);
        assert_eq!(v["applied"], false, "{v}");
        assert!(
            o.deployed.lock().expect("mutex").is_empty(),
            "a prerequisite did not stop the deployment"
        );
    }

    #[tokio::test]
    async fn an_install_without_a_vault_says_so_rather_than_half_installing() {
        // ⚠️ No orchestrator and no vault: every step says what is missing. The
        // alternative — a half-install with no secrets behind it — is the state that
        // looks healthy and has no credentials.
        let Ok(cat) = hlb_catalog::Catalog::load("../../catalog") else {
            return;
        };
        let st = State::in_memory().await.expect("base");
        let e = Arc::new(state_with_catalog(st, cat));

        let (s, v) = post(
            router(e.clone()),
            "/api/apps/valkey/install?apply=true",
            "{}",
        )
        .await;

        assert_eq!(s, StatusCode::OK);
        assert!(
            v["steps"].to_string().contains("master-key"),
            "the steps must say what is missing: {}",
            v["steps"]
        );
        // Recorded with nothing to run it, the app was left "installing" for good.
        assert!(e.state.installed_apps().await.expect("apps").is_empty());
    }

    #[tokio::test]
    async fn installing_previews_the_real_plan() {
        // 🔴 The preview shows the REAL plan, produced by the same resolver as the
        // command line. A preview that diverged from the execution would be worse than
        // no preview: you would trust it.
        let Ok(cat) = hlb_catalog::Catalog::load("../../catalog") else {
            // The repository's catalog is not there (running outside the tree): we do
            // not fail the suite for that.
            return;
        };

        let st = State::in_memory().await.expect("base");
        let e = state_with_catalog(st, cat);
        let r = router(Arc::new(e));

        let resp = r
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/apps/gitea/install")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"domain":"git.example.fr","mail_domain":"example.fr"}"#,
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .expect("body");
        let v: serde_json::Value = serde_json::from_slice(&bytes).expect("json");

        assert_eq!(v["applied"], false, "a preview does nothing");
        let steps = v["steps"].as_array().expect("steps");
        assert!(
            steps.len() > 3,
            "gitea's real plan takes several actions: {steps:?}"
        );
        // And the plan names what it will really do: a database, an OIDC client.
        let everything = v["steps"].to_string();
        assert!(
            everything.contains("base") || everything.contains("Postgres"),
            "{everything}"
        );

        assert!(
            v["cli_command"]
                .as_str()
                .unwrap_or("")
                .contains("--domain git.example.fr"),
            "the equivalent command must carry the chosen domain"
        );
    }

    /// Gitea sends mail since 2026-10-18: with no exposure and no mail domain, the
    /// resolver's "parameter mail_domain is required" came back as a bare 422.
    #[tokio::test]
    async fn installing_without_a_mail_domain_says_where_to_give_one() {
        let Ok(cat) = hlb_catalog::Catalog::load("../../catalog") else {
            return;
        };
        let st = State::in_memory().await.expect("base");
        let e = Arc::new(state_with_catalog(st, cat));

        let (s, v) = post(
            router(e),
            "/api/apps/gitea/install",
            r#"{"domain":"git.example.fr"}"#,
        )
        .await;
        assert_eq!(s, StatusCode::OK, "{v}");
        assert_eq!(v["applied"], false);
        assert!(
            v["blockers"]
                .to_string()
                .contains("mail domain is required"),
            "{v}"
        );
    }

    #[tokio::test]
    async fn installing_without_a_domain_is_blocked_not_guessed() {
        // An app that exposes a service needs a domain. Guessing it would produce wrong
        // OIDC callback URLs, and the app would fail at sign-in with a
        // unrelated message.
        let Ok(cat) = hlb_catalog::Catalog::load("../../catalog") else {
            return;
        };
        let st = State::in_memory().await.expect("base");
        let r = router(Arc::new(state_with_catalog(st, cat)));

        let resp = r
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/apps/gitea/install?apply=true")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .expect("request"),
            )
            .await
            .expect("response");

        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .expect("body");
        let v: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        assert_eq!(v["applied"], false);
        assert!(
            v["blockers"].to_string().contains("domain"),
            "{}",
            v["blockers"]
        );
    }

    #[tokio::test]
    async fn scaling_to_zero_is_refused_because_it_is_a_stop() {
        // Going down to zero is not a resize, it is a shutdown — and it almost never
        // happens deliberately from a numeric field.
        let st = State::in_memory().await.expect("base");
        let r = router(app_state(st, true));

        let resp = r
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/apps/gitea/scale?apply=true")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"replicas":0}"#))
                    .expect("request"),
            )
            .await
            .expect("response");

        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .expect("body");
        let v: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        assert_eq!(v["applied"], false);
        assert!(
            v["blockers"].to_string().contains("stops the application"),
            "{}",
            v["blockers"]
        );
    }

    #[tokio::test]
    async fn a_destination_is_declared_by_root_never_from_here() {
        // 🔴 A local location is bound read-write by the backup pass: declared from here,
        // `/` or `/etc` would be mounted into a container running as root.
        let st = State::in_memory().await.expect("base");
        let app = app_state(st, true);
        let state = app.state.clone();
        let r = router(app);

        let resp = r
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/backup/destinations/nas?apply=true")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"location":"/","classes":"critical,bulky"}"#))
                    .expect("request"),
            )
            .await
            .expect("response");

        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .expect("body");
        let v: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        assert_eq!(v["applied"], false);
        assert!(
            v["blockers"].to_string().contains("hlb backup dest add"),
            "the refusal names who declares one: {}",
            v["blockers"]
        );
        assert!(state.destinations().await.expect("destinations").is_empty());
    }

    #[tokio::test]
    async fn an_unknown_backup_class_is_named_not_silently_dropped() {
        // A misspelled class would create a destination that accepts nothing, and that
        // would therefore never receive a backup — with nothing saying so.
        let st = State::in_memory().await.expect("base");
        let r = router(app_state(st, true));

        let resp = r
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/backup/destinations/nas?apply=true")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"location":"/mnt/nas","classes":"importante"}"#,
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");

        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .expect("body");
        let v: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        assert_eq!(v["applied"], false);
        assert!(
            v["blockers"].to_string().contains("importante"),
            "{}",
            v["blockers"]
        );
    }

    #[tokio::test]
    async fn the_uncounted_prefix_reaches_no_route_of_the_api() {
        // The interface's fixed files go uncounted by the rate limit; a path that climbs
        // out of their directory must not land on the API with that exemption.
        let st = State::in_memory().await.expect("base");
        st.upsert_user("lena", "standard", None)
            .await
            .expect("account");
        let r = router(app_state(st, false));
        for path in [
            "/_app/immutable/../../api/accounts",
            "/_app/immutable/%2e%2e/%2e%2e/api/accounts",
        ] {
            let resp = r
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(path)
                        .body(Body::empty())
                        .expect("request"),
                )
                .await
                .expect("response");
            let status = resp.status();
            let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
                .await
                .expect("body");
            assert!(!status.is_success(), "{path} answered {status}");
            assert!(
                !String::from_utf8_lossy(&bytes).contains("lena"),
                "{path} leaked an account"
            );
        }
    }

    #[tokio::test]
    async fn a_value_out_of_bounds_is_refused_not_cut_to_fit() {
        // 🔴 Ninety days used to become thirty without a word, and the link expired two
        // months before the person who made it expected. Refused now, saying why —
        // before the handler, whatever route the body goes to.
        let st = State::in_memory().await.expect("base");
        let r = router(app_state(st, true));
        let post = |uri: &'static str, body: String| {
            r.clone().oneshot(
                Request::builder()
                    .method("POST")
                    .uri(uri)
                    .header("content-type", "application/json")
                    .header(crate::auth::UI_HEADER, "1")
                    .body(Body::from(body))
                    .expect("request"),
            )
        };
        let long = post(
            "/api/invitations",
            format!(r#"{{"duration_s":{}}}"#, 90 * 86_400),
        )
        .await
        .expect("response");
        assert_eq!(long.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let bytes = axum::body::to_bytes(long.into_body(), 1 << 20)
            .await
            .expect("body");
        let error: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        assert!(
            error["error"]
                .as_str()
                .is_some_and(|e| e.contains("\"duration_s\"")),
            "{error}"
        );

        let note = post(
            "/api/alerts/disk-full/mute",
            format!(
                r#"{{"for_s":60,"reason":"{}"}}"#,
                "x".repeat(crate::limits::SHORT + 1)
            ),
        )
        .await
        .expect("response");
        assert_eq!(note.status(), StatusCode::UNPROCESSABLE_ENTITY);

        let within = post(
            "/api/invitations",
            format!(r#"{{"duration_s":{}}}"#, crate::limits::INVITATION_MAX_S),
        )
        .await
        .expect("response");
        assert_eq!(within.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn an_invitation_can_only_create_one_account() {
        // 🔴 The link is single-use. Reusing it would create a second account with the
        // same rights, in the name of someone who asked for nothing.
        let st = State::in_memory().await.expect("base");
        st.create_invitation(
            "link-test",
            "lena",
            "standard",
            crate::auth::now(),
            3_600,
            1,
            None,
        )
        .await
        .expect("invitation");

        let state = app_state(st, false);
        let signup = |r: Router, name: &str| {
            let body = format!(r#"{{"invitation":"link-test","name":"{name}"}}"#);
            async move {
                let resp = r
                    .oneshot(
                        Request::builder()
                            .method("POST")
                            .uri("/api/signup?apply=true")
                            .header("content-type", "application/json")
                            .body(Body::from(body))
                            .expect("request"),
                    )
                    .await
                    .expect("response");
                let status = resp.status();
                let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
                    .await
                    .expect("body");
                (
                    status,
                    serde_json::from_slice::<serde_json::Value>(&bytes)
                        .unwrap_or(serde_json::Value::Null),
                )
            }
        };

        let (s1, v1) = signup(router(state.clone()), "alice").await;
        assert_eq!(s1, StatusCode::OK, "{v1}");
        assert_eq!(v1["applied"], true);

        let (s2, v2) = signup(router(state.clone()), "mallory").await;
        assert_eq!(
            s2,
            StatusCode::UNPROCESSABLE_ENTITY,
            "a single-use link served twice: {v2}"
        );

        // And the second account does not exist.
        let accounts = state.state.users().await.expect("accounts");
        assert!(accounts.iter().any(|(n, _, _)| n == "alice"));
        assert!(!accounts.iter().any(|(n, _, _)| n == "mallory"));
    }

    #[tokio::test]
    async fn registration_preview_does_not_burn_the_link() {
        // ⚠️ You must be able to check your name is free without consuming the link.
        let st = State::in_memory().await.expect("base");
        st.create_invitation(
            "link-test",
            "lena",
            "standard",
            crate::auth::now(),
            3_600,
            1,
            None,
        )
        .await
        .expect("invitation");
        let state = app_state(st, false);

        let r = router(state.clone());
        let resp = r
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/signup")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"invitation":"link-test","name":"alice"}"#))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(resp.status(), StatusCode::OK);

        // The link still works.
        let remaining = state
            .state
            .invitations(crate::auth::now())
            .await
            .expect("invitations");
        assert!(remaining[0].usable(), "the preview burnt the link");
    }

    #[tokio::test]
    async fn an_invalid_name_is_refused_before_the_link_is_spent() {
        // A name refused after consumption would waste the link on a typo.
        let st = State::in_memory().await.expect("base");
        st.create_invitation(
            "link-test",
            "lena",
            "standard",
            crate::auth::now(),
            3_600,
            1,
            None,
        )
        .await
        .expect("invitation");
        let state = app_state(st, false);

        let r = router(state.clone());
        let resp = r
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/signup?apply=true")
                    .header("content-type", "application/json")
                    // Capitals and a space: invalid as an address local part.
                    .body(Body::from(
                        r#"{"invitation":"link-test","name":"Alice Martin"}"#,
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);

        let remaining = state
            .state
            .invitations(crate::auth::now())
            .await
            .expect("invitations");
        assert!(remaining[0].usable(), "the link was wasted by a typo");
    }

    #[tokio::test]
    async fn a_half_created_account_is_visible_and_repairable() {
        // 🔴 The heart of batch 6: PocketID not being wired in, the account is created
        // `WithoutIdentity`. That is NOT a silent failure — the state is named, visible,
        // and a re-run repairs it.
        let st = State::in_memory().await.expect("base");
        st.create_invitation(
            "link-test",
            "lena",
            "standard",
            crate::auth::now(),
            3_600,
            1,
            None,
        )
        .await
        .expect("invitation");
        let state = app_state(st, false);

        let r = router(state.clone());
        let resp = r
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/signup?apply=true")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"invitation":"link-test","name":"alice"}"#))
                    .expect("request"),
            )
            .await
            .expect("response");

        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .expect("body");
        let v: serde_json::Value = serde_json::from_slice(&bytes).expect("json");

        // Applied, but INCOMPLETE — and the verdict says so.
        assert_eq!(v["applied"], true);
        assert!(
            v["steps"]
                .to_string()
                .contains(r#""state":"unimplemented""#),
            "the steps not done must be marked: {}",
            v["steps"]
        );

        // And the account's state is named.
        let c = state.state.account("alice").await.expect("account");
        assert_eq!(c.coherence(), hlb_users::Coherence::Empty);
        assert!(
            c.coherence().describe().contains("no identity"),
            "{}",
            c.coherence().describe()
        );
    }

    #[tokio::test]
    async fn the_status_page_is_closed_until_someone_opens_it() {
        // 🔴 A public status page reveals the list of what runs at your place and the
        // calendar of your outages. The closed default is a decision, not an oversight.
        let st = State::in_memory().await.expect("base");
        let r = router(app_state(st, false));

        let resp = r
            .oneshot(
                Request::builder()
                    .uri("/status")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 16)
            .await
            .expect("body");
        let text = String::from_utf8_lossy(&bytes);
        // The refusal says HOW to open it, so it is not read as an outage.
        assert!(text.contains("--status-public"), "{text}");
    }

    #[tokio::test]
    async fn an_open_status_page_never_leaks_the_inventory() {
        // ⚠️ When it is public, it shows only the EXPOSED services: listing postgres or
        // valkey would draw up the installation's inventory for whoever reads it.
        let st = State::in_memory().await.expect("base");
        st.upsert_app("gitea", &manifest("gitea"), Some("git.example.fr"))
            .await
            .expect("app");
        st.set_app_status("gitea", "running").await.expect("status");
        // A platform service: no domain, so not exposed.
        st.upsert_app("postgres", &manifest("postgres"), None)
            .await
            .expect("app");
        st.set_app_status("postgres", "running")
            .await
            .expect("status");

        let r = router(public_status_state(st));

        let resp = r
            .oneshot(
                Request::builder()
                    .uri("/status")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(resp.status(), StatusCode::OK);

        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .expect("body");
        let v: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        let services = v["services"].as_array().expect("services");
        assert_eq!(
            services.len(),
            1,
            "an unexposed service leaked: {services:?}"
        );
        assert_eq!(services[0]["name"], "gitea");
    }

    #[tokio::test]
    async fn a_removal_s_preview_says_what_it_leaves_behind() {
        // 🔴 "No volume declared: nothing will be left" was read before confirming, and
        // Anubis's signing key stayed in the vault. Zero volumes must not read as "the
        // data stays" either.
        let st = State::in_memory().await.expect("base");
        st.upsert_app("gitea", &manifest("gitea"), None)
            .await
            .expect("app");
        st.store_secret_if_absent("gitea-jwt-secret", b"x", "jwt")
            .await
            .expect("secret");
        st.store_secret_if_absent("restic-repo-password", b"x", "repository")
            .await
            .expect("secret");
        let r = router(app_state(st, true));

        let resp = r
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/api/apps/gitea")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .expect("request"),
            )
            .await
            .expect("response");
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .expect("body");
        let said = String::from_utf8_lossy(&bytes);
        assert!(!said.contains("nothing will be left"), "{said}");
        assert!(!said.contains("the data stays"), "{said}");
        assert!(said.contains("1 secret stays in the vault"), "{said}");
        assert!(said.contains("hlb secrets-forget gitea"), "{said}");
    }

    #[tokio::test]
    async fn a_removal_s_preview_says_the_database_stays() {
        let st = State::in_memory().await.expect("base");
        let m: hlb_types::Manifest = serde_yaml_ng::from_str(
            "apiVersion: hlb/v1\nkind: App\nmetadata: { name: gitea }\n\
             spec:\n  image: { repo: a/b, tag: \"1\" }\n  requires:\n\
             \x20   - { kind: database, engine: postgres }\n",
        )
        .expect("test manifest");
        st.upsert_app("gitea", &m, None).await.expect("app");
        let r = router(app_state(st, true));

        let resp = r
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/api/apps/gitea")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .expect("request"),
            )
            .await
            .expect("response");
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .expect("body");
        let said = String::from_utf8_lossy(&bytes);
        assert!(said.contains("postgres database"), "{said}");
    }

    #[tokio::test]
    async fn a_preview_still_leaves_a_trace() {
        // Knowing someone looked at what a purge would do is information. But it is NOT
        // logged as an execution.
        let st = State::in_memory().await.expect("base");
        st.upsert_app("gitea", &manifest("gitea"), None)
            .await
            .expect("app");
        let app = app_state(st, true);
        let state = app.state.clone();
        let r = router(app);

        let _ = r
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/api/apps/gitea")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .expect("request"),
            )
            .await
            .expect("response");

        let journal = state.audit_trail(10).await.expect("journal");
        let e = journal
            .iter()
            .find(|e| e.action == "app-remove")
            .expect("the preview must leave a trace");
        assert_eq!(e.outcome, "preview", "a preview is not an execution");
    }

    #[tokio::test]
    async fn destroying_needs_the_target_named_back() {
        // 🔴 The role is not enough: a tired administrator at 2 a.m. is still an
        // administrator. Repeating the name stops a purge typed on the wrong app.
        let st = State::in_memory().await.expect("base");
        st.upsert_app("gitea", &manifest("gitea"), None)
            .await
            .expect("app");
        let r = router(app_state(st, true));

        let resp = r
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/api/apps/gitea?apply=true")
                    .header("content-type", "application/json")
                    // No confirmation.
                    .body(Body::from("{}"))
                    .expect("request"),
            )
            .await
            .expect("response");

        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .expect("body");
        let v: serde_json::Value = serde_json::from_slice(&bytes).expect("json");

        assert_eq!(v["applied"], false, "applied without confirmation");
        let blockers = v["blockers"].as_array().expect("blockers");
        assert!(
            blockers
                .iter()
                .any(|b| b.as_str().unwrap_or("").contains("confirmed")),
            "{blockers:?}"
        );
    }

    #[tokio::test]
    async fn a_wrong_confirmation_does_not_pass() {
        // Confirming "vikunja" to delete "gitea" is exactly the accident the named
        // confirmation exists to catch.
        let st = State::in_memory().await.expect("base");
        st.upsert_app("gitea", &manifest("gitea"), None)
            .await
            .expect("app");
        let r = router(app_state(st, true));

        let resp = r
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/api/apps/gitea?apply=true")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"confirmed":"vikunja"}"#))
                    .expect("request"),
            )
            .await
            .expect("response");

        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .expect("body");
        let v: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        assert_eq!(v["applied"], false, "a wrong confirmation was accepted");
    }

    #[tokio::test]
    async fn an_applied_action_never_claims_more_than_it_did() {
        // 🔴 "Unimplemented is never Done". An action whose executor is not wired must
        // SAY so, not show a success.
        let st = State::in_memory().await.expect("base");
        st.upsert_app("gitea", &manifest("gitea"), None)
            .await
            .expect("app");
        // A SQLite volume: what a critical-only destination receives.
        st.add_volume("gitea", "gitea-data", "/data", true, true)
            .await
            .expect("volume");
        st.upsert_destination("nas", "/mnt/nas", "critical", None)
            .await
            .expect("destination");
        let r = router(app_state(st, true));

        let resp = r
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/apps/gitea/backup?apply=true")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .expect("request"),
            )
            .await
            .expect("response");

        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .expect("body");
        let v: serde_json::Value = serde_json::from_slice(&bytes).expect("json");

        assert_eq!(v["applied"], true);
        let steps = v["steps"].as_array().expect("steps");
        assert!(
            steps.iter().all(|e| e["state"] == "unimplemented"),
            "a step claims to have backed up: {steps:?}"
        );
    }

    #[tokio::test]
    async fn a_guide_can_actually_be_attested() {
        // The nominal path: an action that IS wired up.
        let st = State::in_memory().await.expect("base");
        st.upsert_app("gitea", &manifest("gitea"), None)
            .await
            .expect("app");
        st.add_guide("gitea", "first-admin", "Create the admin", true)
            .await
            .expect("guide");
        let app = app_state(st, true);
        let state = app.state.clone();
        let r = router(app);

        let resp = r
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/todo/gitea/first-admin?apply=true")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .expect("request"),
            )
            .await
            .expect("response");

        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .expect("body");
        let v: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        assert_eq!(v["applied"], true);
        assert_eq!(v["steps"][0]["state"], "done");

        // And the guide is no longer pending.
        assert_eq!(state.unverified_blocking("gitea").await.expect("guides"), 0);
    }

    #[tokio::test]
    async fn a_missing_time_series_database_is_said_not_drawn_flat() {
        // 🔴 With no time-series database, the route returns "unavailable" WITH the
        // remedy — and above all not an empty series, which would be drawn as a flat
        // line at zero and would read as "all calm".
        let (s, v) = get_with_token(
            app().await,
            "/api/v1/metrics/series?q=hlb_cpu_used_ratio",
            None,
        )
        .await;
        assert_eq!(
            s,
            StatusCode::OK,
            "a missing database is not a controller outage"
        );
        let reason = v["reason"].as_str().expect("a reason");
        assert!(reason.contains("--metrics-url"), "{reason}");
        assert!(v["points"].is_null(), "no series must be fabricated");
    }

    #[tokio::test]
    async fn a_plain_user_token_cannot_read_the_console() {
        // 🔴 The `account_user` role is that of a person who has an account. Opening
        // /api/audit and /api/secrets to them would hand the inventory of the secrets
        // and the history of operations to anyone with a mailbox.
        for route in [
            "/api/apps",
            "/api/todo",
            "/api/audit",
            "/api/secrets",
            "/metrics",
        ] {
            let st = State::in_memory().await.expect("base");
            let (value, stored) =
                hlb_types::generate_token("portal", hlb_types::Role::User, [9u8; 32]);
            st.store_token(&stored).await.expect("token");
            let r = router(app_state(st, false));

            let s = get_route_with_token(r, route, Some(&value)).await;
            assert_eq!(s, StatusCode::FORBIDDEN, "{route} open to a plain user");
        }
    }

    #[tokio::test]
    async fn a_refusal_says_which_role_is_needed() {
        // A bare 403 leaves you guessing whether you are on the wrong screen, whether
        // the system is broken, or whether a right is missing.
        let st = State::in_memory().await.expect("base");
        let (value, stored) = hlb_types::generate_token("portal", hlb_types::Role::User, [9u8; 32]);
        st.store_token(&stored).await.expect("token");
        let r = router(app_state(st, false));

        let resp = r
            .oneshot(
                Request::builder()
                    .uri("/api/apps")
                    .header("Authorization", format!("Bearer {value}"))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let body = axum::body::to_bytes(resp.into_body(), 1 << 16)
            .await
            .expect("body");
        let text = String::from_utf8_lossy(&body);
        assert!(
            text.contains("viewer"),
            "the required role must be named: {text}"
        );
        assert!(text.contains("user"), "the held role must be named: {text}");
    }

    #[tokio::test]
    async fn a_mute_set_by_the_route_is_seen_at_once_and_audited() {
        let st = Arc::new(State::in_memory().await.expect("base"));
        let mut app = base_state(st.clone(), true);
        let firing = vec![hlb_api::ActiveAlert {
            rule: "disk-full".into(),
            level: hlb_api::AlertLevel::Critical,
            explanation: "a filesystem is above 85 % usage".into(),
            value: Some(0.96),
            threshold: 0.85,
            since_s: 0,
            muted_until: None,
            muted_by: None,
            mute_reason: None,
        }];
        app.privd = app.privd.with_published(
            Arc::new(tokio::sync::RwLock::new(firing)),
            Default::default(),
        );
        let r = router(Arc::new(app));

        // Refused, and nothing stored.
        let (s, _) = post(
            r.clone(),
            "/api/alerts/disk-plein/mute",
            r#"{"for_s":3600,"reason":"x"}"#,
        )
        .await;
        assert_eq!(
            s,
            StatusCode::NOT_FOUND,
            "a rule nobody evaluates must not be muted"
        );
        let week = hlb_api::MUTE_MAX_S + 1;
        let (s, _) = post(
            r.clone(),
            "/api/alerts/disk-full/mute",
            &format!(r#"{{"for_s":{week},"reason":"x"}}"#),
        )
        .await;
        assert_eq!(
            s,
            StatusCode::UNPROCESSABLE_ENTITY,
            "a mute with no real end"
        );
        let (s, _) = post(
            r.clone(),
            "/api/alerts/disk-full/mute",
            r#"{"for_s":3600,"reason":"  "}"#,
        )
        .await;
        assert_eq!(
            s,
            StatusCode::UNPROCESSABLE_ENTITY,
            "a mute nobody can explain"
        );
        assert!(st.alert_mutes(0).await.expect("read").is_empty());

        let (s, _) = post(
            r.clone(),
            "/api/alerts/disk-full/mute",
            r#"{"for_s":3600,"reason":"purge under way"}"#,
        )
        .await;
        assert_eq!(s, StatusCode::NO_CONTENT);

        // Seen at once, before any evaluation pass — still listed, one notch lower.
        let (_, v) = get(r.clone(), "/api/alerts").await;
        let a = &v[0];
        assert_eq!(a["rule"], "disk-full", "a muted alert must stay listed");
        assert_eq!(a["mute"]["reason"], "purge under way");
        assert!(a["mute"]["remaining_s"].as_i64().is_some_and(|s| s > 3_500));
        assert_eq!(
            a["attention"], "notice",
            "critical, muted: one notch lower, never ok"
        );

        let log = st.audit_for("disk-full", 5).await.expect("audit");
        assert!(log.iter().any(|e| e.action == "alert-mute"), "{log:?}");

        let (s, _) = delete(r.clone(), "/api/alerts/disk-full/mute", "").await;
        assert_eq!(s, StatusCode::NO_CONTENT);
        let (_, v) = get(r.clone(), "/api/alerts").await;
        assert_eq!(v[0]["mute"], serde_json::Value::Null);
        let (s, _) = delete(r, "/api/alerts/disk-full/mute", "").await;
        assert_eq!(s, StatusCode::NOT_FOUND, "nothing left to lift");
    }

    #[tokio::test]
    async fn a_home_is_arranged_only_with_cards_that_exist() {
        let st = State::in_memory().await.expect("base");
        st.upsert_user("lena", "standard", None)
            .await
            .expect("account");
        let (value, stored) = hlb_types::generate_token("home", hlb_types::Role::User, [4u8; 32]);
        st.store_token(&stored).await.expect("token");
        st.set_token_user("home", Some("lena")).await.expect("link");
        let r = router(app_state(st, false));

        let put = |body: &'static str| {
            r.clone().oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/preferences/home")
                    .header("Authorization", format!("Bearer {value}"))
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .expect("request"),
            )
        };
        // Refused, and nothing stored: a stored unknown name would be a card silently
        // missing from the home.
        for refused in [
            r#"{"home":[{"widget":"apps","w":1,"h":1},{"widget":"weather","w":1,"h":1}]}"#,
            r#"{"home":[{"widget":"apps","w":1,"h":1},{"widget":"apps","w":2,"h":1}]}"#,
            r#"{"home":[{"widget":"apps","w":5,"h":1}]}"#,
            r#"{"home":[{"widget":"apps","w":1,"h":0}]}"#,
            r#"{"home":[{"widget":"apps","w":1,"h":1,"x":3}]}"#,
            r#"{"home":["apps"]}"#,
        ] {
            let answer = put(refused).await.expect("response");
            assert_eq!(
                answer.status(),
                StatusCode::UNPROCESSABLE_ENTITY,
                "{refused}"
            );
        }

        let (_, before) = get_json_with_token(r.clone(), "/api/preferences", &value).await;
        assert_eq!(before["home"], serde_json::Value::Null, "never arranged");
        assert_eq!(
            before["home_default"],
            serde_json::to_value(hlb_api::HomeTile::DEFAULT).expect("json")
        );

        let layout = r#"{"home":[{"widget":"nodes","w":4,"h":3},{"widget":"uptime","w":1,"h":1}]}"#;
        let ok = put(layout).await.expect("response");
        assert_eq!(ok.status(), StatusCode::NO_CONTENT);
        let (_, after) = get_json_with_token(r.clone(), "/api/preferences", &value).await;
        assert_eq!(
            after["home"],
            serde_json::json!([{"widget":"nodes","w":4,"h":3},{"widget":"uptime","w":1,"h":1}])
        );

        let back = put(r#"{"home":null}"#).await.expect("response");
        assert_eq!(back.status(), StatusCode::NO_CONTENT);
        let (_, reset) = get_json_with_token(r, "/api/preferences", &value).await;
        assert_eq!(reset["home"], serde_json::Value::Null);
    }

    async fn get_json_with_token(
        r: Router,
        uri: &str,
        token: &str,
    ) -> (StatusCode, serde_json::Value) {
        let resp = r
            .oneshot(
                Request::builder()
                    .uri(uri)
                    .header("Authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .expect("body");
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
        )
    }

    #[tokio::test]
    async fn the_quota_applies_over_http_too() {
        // 🔴 The defect fixed: a comment claimed "the quota applies HERE too" while
        // `add_alias` was called directly. An `guest` profile, limited to ZERO
        // permanent aliases, created as many as it liked over HTTP.
        let st = State::in_memory().await.expect("base");
        st.upsert_user("guest", "guest", None)
            .await
            .expect("account");
        st.add_mailbox("guest", "guest", "home.example", true)
            .await
            .expect("mailbox");

        let (value, stored) = hlb_types::generate_token("bw", hlb_types::Role::Operator, [3u8; 32]);
        st.store_token(&stored).await.expect("token");
        st.set_token_user("bw", Some("guest"))
            .await
            .expect("rattachement");

        let r = router(app_state(st, false));

        let resp = r
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/aliases")
                    .header("Authorization", format!("Bearer {value}"))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"description":"Generated by Bitwarden (amazon.fr)"}"#,
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(
            resp.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "the guest profile is entitled to no permanent alias"
        );
    }

    /// Posts to `/api/me/mailbox` as a token bound to `user`, and returns the parsed
    /// `ActionResult` — the route always answers 200, `applied`/`blockers` carry the
    /// real outcome (see `create_my_mailbox`'s own doc comment for why).
    async fn try_create_mailbox(r: Router, value: &str, local: &str) -> ActionResult {
        let resp = r
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/me/mailbox")
                    .header("Authorization", format!("Bearer {value}"))
                    .header("content-type", "application/json")
                    .body(Body::from(format!(r#"{{"local":"{local}"}}"#)))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 16)
            .await
            .expect("body");
        serde_json::from_slice(&bytes).expect("ActionResult")
    }

    #[tokio::test]
    async fn mailbox_creation_refuses_when_the_quota_is_exhausted() {
        // The guest profile allows exactly ONE mailbox — already used by the one
        // `add_mailbox` sets up here — mirroring `hlb user mailbox add`'s own quota
        // check, which this route must apply exactly like the CLI does.
        let st = State::in_memory().await.expect("base");
        st.upsert_user("guest", "guest", None)
            .await
            .expect("account");
        st.add_mailbox("guest", "guest", "home.example", true)
            .await
            .expect("mailbox");

        let (value, stored) = hlb_types::generate_token("bw", hlb_types::Role::Operator, [5u8; 32]);
        st.store_token(&stored).await.expect("token");
        st.set_token_user("bw", Some("guest"))
            .await
            .expect("rattachement");

        let r = try_create_mailbox(router(app_state(st, false)), &value, "second").await;
        assert!(
            !r.applied,
            "the quota must refuse this, not create anything"
        );
        assert!(
            r.blockers.iter().any(|b| b.contains("mailbox limit")),
            "{:?}",
            r.blockers
        );
    }

    #[tokio::test]
    async fn mailbox_creation_refuses_without_mail_configured() {
        // 🔴 Refusing rather than recording a mailbox that does not exist on the
        // server: a half-created account looks functional and only shows on the
        // first lost email. `app_state` sets `mail: None`, the same "Stalwart not
        // configured" state `hlb user mailbox add` refuses on.
        let st = State::in_memory().await.expect("base");
        st.upsert_user("lena", "standard", None)
            .await
            .expect("account");

        let (value, stored) = hlb_types::generate_token("bw", hlb_types::Role::Operator, [6u8; 32]);
        st.store_token(&stored).await.expect("token");
        st.set_token_user("bw", Some("lena"))
            .await
            .expect("rattachement");

        let r = try_create_mailbox(router(app_state(st, false)), &value, "lena").await;
        assert!(!r.applied);
        assert!(
            r.blockers
                .iter()
                .any(|b| b.contains("mail is not configured")),
            "{:?}",
            r.blockers
        );
        assert_eq!(
            r.steps[0].state,
            StepState::Planned,
            "nothing was attempted"
        );
    }

    #[tokio::test]
    async fn a_service_token_never_acts_for_someone() {
        // Privilege does not replace identity: an unbound ADMIN token must be refused
        // where a bound token passes.
        let st = State::in_memory().await.expect("base");
        let (value, stored) =
            hlb_types::generate_token("service", hlb_types::Role::Admin, [4u8; 32]);
        st.store_token(&stored).await.expect("token");

        let r = router(app_state(st, false));

        let resp = r
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/aliases")
                    .header("Authorization", format!("Bearer {value}"))
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    /// An app state whose mail goes to `fake`, at `home.example`.
    fn with_mail(st: State, fake: &crate::fake_mail::stalwart::FakeStalwart) -> Arc<AppState> {
        let mut s = base_state(Arc::new(st), false);
        s.mail_domain = "home.example".into();
        s.privd = hlb_privd::Privd::new(s.state.clone())
            .with_mail(Some(fake.client.clone()), &s.mail_domain);
        Arc::new(s)
    }

    /// A `user` token bound to `user`, its value.
    async fn bound_token(st: &State, user: &str, role: hlb_types::Role) -> String {
        let (value, stored) = hlb_types::generate_token(&format!("t-{user}"), role, [8u8; 32]);
        st.store_token(&stored).await.expect("token");
        st.set_token_user(&format!("t-{user}"), Some(user))
            .await
            .expect("bound");
        value
    }

    async fn post_alias(r: Router, token: &str) -> StatusCode {
        r.oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/aliases")
                .header("Authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"description":"Generated by Bitwarden (amazon.fr)"}"#,
                ))
                .expect("request"),
        )
        .await
        .expect("response")
        .status()
    }

    #[tokio::test]
    async fn an_alias_is_refused_rather_than_recorded_without_mail() {
        // 🔴 The route wrote the state alone: Bitwarden filled in an address every mail
        // to which bounced.
        let st = State::in_memory().await.expect("base");
        st.upsert_user("lena", "standard", None)
            .await
            .expect("account");
        st.add_mailbox("lena", "lena", "home.example", true)
            .await
            .expect("mailbox");
        let token = bound_token(&st, "lena", hlb_types::Role::User).await;
        let e = app_state(st, false);
        assert_eq!(
            post_alias(router(e.clone()), &token).await,
            StatusCode::CONFLICT
        );
        assert!(e.state.aliases("lena").await.expect("aliases").is_empty());
    }

    #[tokio::test]
    async fn an_alias_reaches_stalwart_before_it_is_recorded() {
        let fake = crate::fake_mail::stalwart::start(&["lena"]).await;
        let st = State::in_memory().await.expect("base");
        st.upsert_user("lena", "standard", None)
            .await
            .expect("account");
        st.add_mailbox("lena", "lena", "home.example", true)
            .await
            .expect("mailbox");
        let token = bound_token(&st, "lena", hlb_types::Role::User).await;
        let e = with_mail(st, &fake);
        assert_eq!(
            post_alias(router(e.clone()), &token).await,
            StatusCode::CREATED
        );

        let recorded = e.state.aliases("lena").await.expect("aliases");
        assert_eq!(recorded.len(), 1);
        let held = fake.held.lock().expect("fake").accounts["lena"].clone();
        assert_eq!(held, vec![recorded[0].1.clone()], "Stalwart has the alias");
    }

    #[tokio::test]
    async fn a_mailbox_is_never_an_account_that_is_not_yours() {
        // 🔴 `ensure_account` kept an existing account: anyone could ask for
        // `vikunja@` — an app's own — or `postmaster@`, and receive its mail.
        let fake = crate::fake_mail::stalwart::start(&["vikunja", "handmade"]).await;
        let st = State::in_memory().await.expect("base");
        st.upsert_app("vikunja", &manifest("vikunja"), None)
            .await
            .expect("app");
        st.upsert_user("lena", "standard", None)
            .await
            .expect("account");
        st.upsert_user("sacha", "standard", None)
            .await
            .expect("account");
        st.add_mailbox("sacha", "contact", "home.example", true)
            .await
            .expect("mailbox");
        let token = bound_token(&st, "lena", hlb_types::Role::User).await;
        let e = with_mail(st, &fake);

        for (local, why) in [
            ("vikunja", "app"),
            ("postmaster", "reserved"),
            ("contact", "another account"),
            ("handmade", "exists already"),
            ("Lena Durand", "unusable"),
        ] {
            let r = try_create_mailbox(router(e.clone()), &token, local).await;
            assert!(!r.applied, "{local} was given to lena");
            assert!(
                r.blockers.iter().any(|b| b.contains(why)),
                "{local}: {:?}",
                r.blockers
            );
        }
        assert!(e.state.mailboxes("lena").await.expect("list").is_empty());

        let r = try_create_mailbox(router(e.clone()), &token, "shop").await;
        assert!(r.applied, "{:?}", r.blockers);
        assert_eq!(r.steps[0].state, StepState::Done, "{:?}", r.steps);
        assert!(fake
            .held
            .lock()
            .expect("fake")
            .accounts
            .contains_key("shop"));
        assert_eq!(
            e.state
                .mailbox_owner("shop", "home.example")
                .await
                .expect("owner"),
            Some("lena".into())
        );
    }

    #[tokio::test]
    async fn a_token_never_does_more_than_the_person_it_acts_for() {
        let st = State::in_memory().await.expect("base");
        st.upsert_user("lena", "standard", None)
            .await
            .expect("account");
        let token = bound_token(&st, "lena", hlb_types::Role::Admin).await;
        let resp = router(app_state(st, false))
            .oneshot(
                Request::builder()
                    .uri("/api/apps")
                    .header("Authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "an admin token bound to a standard account read the operations"
        );
    }

    #[tokio::test]
    async fn the_bitwarden_token_can_do_nothing_but_aliases() {
        let st = State::in_memory().await.expect("base");
        st.upsert_user("lena", "admin", None)
            .await
            .expect("account");
        st.add_mailbox("lena", "lena", "home.example", true)
            .await
            .expect("mailbox");
        let mut s = base_state(Arc::new(st), true);
        s.public_url = Some("https://hlb.home.example".into());
        let e = Arc::new(s);
        let (status, v) = post(router(e.clone()), "/api/bitwarden", r#"{"account":"lena"}"#).await;
        assert_eq!(status, StatusCode::OK, "{v}");
        let tokens = e.state.list_tokens().await.expect("tokens");
        assert!(
            tokens.iter().any(|(_, role, _)| role == "user"),
            "{tokens:?}"
        );
    }

    #[tokio::test]
    async fn the_bitwarden_assistant_never_takes_over_another_token() {
        let st = State::in_memory().await.expect("base");
        st.upsert_user("lena", "admin", None)
            .await
            .expect("account");
        st.add_mailbox("lena", "lena", "home.example", true)
            .await
            .expect("mailbox");
        let (_, deadman) =
            hlb_types::token::generate("deadman", hlb_types::Role::Operator, [7; 32]);
        st.store_token(&deadman).await.expect("deadman");
        let mut s = base_state(Arc::new(st), true);
        s.public_url = Some("https://hlb.home.example".into());
        let e = Arc::new(s);
        let role = |e: Arc<AppState>| async move {
            e.state
                .list_tokens()
                .await
                .expect("tokens")
                .into_iter()
                .find(|(n, ..)| n == "deadman")
                .map(|(_, r, _)| r)
        };

        let (status, v) = post(
            router(e.clone()),
            "/api/bitwarden",
            r#"{"account":"lena","name":"deadman"}"#,
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "{v}");
        assert_eq!(role(e.clone()).await.as_deref(), Some("operator"));

        // Her own, issued again: the common case of a lost phone.
        let body = r#"{"account":"lena","name":"bw-lena"}"#;
        let (status, v) = post(router(e.clone()), "/api/bitwarden", body).await;
        assert_eq!(status, StatusCode::OK, "{v}");
        let (status, v) = post(router(e.clone()), "/api/bitwarden", body).await;
        assert_eq!(status, StatusCode::OK, "{v}");
    }

    #[tokio::test]
    async fn a_domain_that_is_not_one_is_refused_over_http() {
        // 🔴 Written into the Caddyfile as is, a newline and a brace opened a site of
        // their own.
        let dir = tempfile::tempdir().expect("tempdir");
        let cat = catalog_with_prerequisite(&dir.path().join("catalog"), &closed_port());
        let st = State::in_memory().await.expect("base");
        let o = Arc::new(FakeOrch::default());
        let e = state_that_can_install(st, cat, o, &dir.path().join("key"));
        let body = serde_json::json!({
            "domain": "x.example.org {\n\tfile_server\n}\ny.example.org"
        })
        .to_string();
        let (_, v) = post(
            router(e.clone()),
            "/api/apps/valkey/install?apply=true",
            &body,
        )
        .await;
        assert_eq!(v["applied"], false, "{v}");
        assert!(
            v["blockers"].to_string().contains("not a domain name"),
            "{v}"
        );
        assert!(e.state.installed_apps().await.expect("apps").is_empty());
    }

    #[tokio::test]
    async fn a_session_s_cookie_lives_as_long_as_the_session() {
        // 🔴 The server slid the session, the cookie kept its first twelve hours: a
        // whole day's work ended signed out.
        let st = State::in_memory().await.expect("base");
        st.upsert_user("lena", "admin", None)
            .await
            .expect("account");
        st.open_session(
            "cookie-value",
            "lena",
            None,
            crate::auth::now(),
            crate::auth::SESSION_DURATION_S,
            None,
        )
        .await
        .expect("session");
        let resp = router(app_state(st, false))
            .oneshot(
                Request::builder()
                    .uri("/api/apps")
                    .header("Cookie", format!("{}=cookie-value", crate::auth::COOKIE))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(resp.status(), StatusCode::OK);
        let set = resp
            .headers()
            .get(axum::http::header::SET_COOKIE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        assert!(set.contains("cookie-value"), "{set}");
        assert!(
            set.contains(&format!("Max-Age={}", crate::auth::SESSION_DURATION_S)),
            "{set}"
        );
    }

    #[tokio::test]
    async fn a_signup_preview_names_nothing_taken_without_a_link_that_opens() {
        let st = State::in_memory().await.expect("base");
        st.upsert_user("alice", "standard", None)
            .await
            .expect("account");
        st.create_invitation(
            "link-test",
            "lena",
            "standard",
            crate::auth::now(),
            3_600,
            1,
            None,
        )
        .await
        .expect("invitation");
        let e = app_state(st, false);
        let (_, v) = post(
            router(e.clone()),
            "/api/signup",
            r#"{"invitation":"guessed","name":"alice"}"#,
        )
        .await;
        assert!(!v["blockers"].to_string().contains("taken"), "{v}");
        let (_, v) = post(
            router(e.clone()),
            "/api/signup",
            r#"{"invitation":"link-test","name":"alice"}"#,
        )
        .await;
        assert!(v["blockers"].to_string().contains("taken"), "{v}");
    }

    #[tokio::test]
    async fn a_signup_never_takes_an_account_stalwart_already_holds() {
        let fake = crate::fake_mail::stalwart::start(&["vikunja"]).await;
        let st = State::in_memory().await.expect("base");
        st.create_invitation(
            "link-test",
            "lena",
            "standard",
            crate::auth::now(),
            3_600,
            1,
            None,
        )
        .await
        .expect("invitation");
        let e = with_mail(st, &fake);
        let (status, v) = post(
            router(e.clone()),
            "/api/signup?apply=true",
            r#"{"invitation":"link-test","name":"vikunja"}"#,
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
        assert!(
            e.state.invitations(crate::auth::now()).await.expect("list")[0].usable(),
            "the link was spent on a name that could not be had"
        );
        assert!(e.state.users().await.expect("users").is_empty());
    }

    #[tokio::test]
    async fn a_purge_removes_the_alias_at_its_mailbox_s_domain() {
        let fake = crate::fake_mail::stalwart::start(&[]).await;
        fake.held
            .lock()
            .expect("fake")
            .accounts
            .insert("lena".into(), vec!["old-x1".into()]);
        let st = State::in_memory().await.expect("base");
        st.upsert_user("lena", "standard", None)
            .await
            .expect("account");
        st.add_mailbox("lena", "lena", "other.fr", true)
            .await
            .expect("mailbox");
        st.add_alias("lena", "lena", "old-x1", Some(1), None, None)
            .await
            .expect("alias");
        let token = bound_token(&st, "lena", hlb_types::Role::User).await;
        let e = with_mail(st, &fake);
        let resp = router(e.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/my-aliases/old-x1/purge?apply=true")
                    .header("Authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 16)
            .await
            .expect("body");
        let r: ActionResult = serde_json::from_slice(&bytes).expect("ActionResult");
        assert!(r.applied, "{:?}", r.blockers);
        assert!(
            r.steps[0].description.contains("old-x1@other.fr"),
            "{:?}",
            r.steps
        );
        assert_eq!(r.steps[0].state, StepState::Done, "{:?}", r.steps);
        assert!(fake.held.lock().expect("fake").accounts["lena"].is_empty());
    }

    /// A sign-in configured against an issuer nobody calls.
    fn signing_in(st: State) -> Router {
        let endpoints = hlb_identity::oidc::Endpoints {
            issuer: "https://id.home.example".into(),
            authorization_endpoint: "https://id.home.example/authorize".into(),
            token_endpoint: "https://id.home.example/token".into(),
            userinfo_endpoint: "https://id.home.example/userinfo".into(),
            end_session_endpoint: None,
        };
        let o = hlb_identity::oidc::Oidc::with_endpoints(
            endpoints,
            "hlb",
            "s",
            "https://hlb.home.example/auth/return_to",
        );
        let mut s = base_state(Arc::new(st), false);
        s.signin = Arc::new(crate::signin::SignInSlot::ready(
            crate::signin::SignIn::new(o, "https://hlb.home.example"),
        ));
        router(Arc::new(s))
    }

    #[tokio::test]
    async fn a_sign_in_returns_only_to_the_browser_that_started_it() {
        // 🔴 A return carrying someone else's code and state signed this browser in as
        // them.
        let st = State::in_memory().await.expect("base");
        let r = signing_in(st);
        let started = r
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/auth/signin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(started.status(), StatusCode::FOUND);
        let cookie = started
            .headers()
            .get_all(axum::http::header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .find(|c| c.starts_with("hlb_signin="))
            .expect("a state cookie")
            .to_string();
        let state = cookie
            .trim_start_matches("hlb_signin=")
            .split(';')
            .next()
            .expect("value")
            .to_string();

        let back = |cookie: Option<String>| {
            let r = r.clone();
            let state = state.clone();
            async move {
                let mut b = Request::builder().uri(format!("/auth/return_to?code=c&state={state}"));
                if let Some(c) = cookie {
                    b = b.header("Cookie", c);
                }
                let resp = r
                    .oneshot(b.body(Body::empty()).expect("request"))
                    .await
                    .expect("response");
                let bytes = axum::body::to_bytes(resp.into_body(), 1 << 16)
                    .await
                    .expect("body");
                String::from_utf8_lossy(&bytes).to_string()
            }
        };
        let elsewhere = back(None).await;
        assert!(
            elsewhere.contains("not started from this browser"),
            "{elsewhere}"
        );
        let other = back(Some("hlb_signin=another".into())).await;
        assert!(other.contains("not started from this browser"), "{other}");
        // The browser that started it gets past the check: to the exchange, which fails
        // here since no issuer answers.
        let here = back(Some(format!("hlb_signin={state}"))).await;
        assert!(!here.contains("not started from this browser"), "{here}");
    }

    #[tokio::test]
    async fn an_announcement_of_an_unknown_level_or_audience_is_refused() {
        // The handler parses with a fallback — an unknown level is `info` — so the
        // body's bounds (`limits.rs`) are what keeps a mistyped incident from going out
        // as information.
        let st = State::in_memory().await.expect("base");
        let e = app_state(st, true);
        for body in [
            r#"{"title":"Down","body":"Mail is down","level":"incidnet"}"#,
            r#"{"title":"Down","body":"Mail is down","level":"incident","audience":"admins"}"#,
        ] {
            let (status, v) = post(router(e.clone()), "/api/announcements?apply=true", body).await;
            assert!(status.is_client_error(), "{status} {v}");
        }
        assert!(e
            .state
            .announcements(hlb_types::Role::Admin, crate::auth::now(), true)
            .await
            .expect("announcements")
            .is_empty());
    }
}
