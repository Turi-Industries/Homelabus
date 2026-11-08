//! The routes that **act** (batch 5).
//!
//! ## The three rules, and why they beat "read-only"
//!
//! The API long forbade every mutating verb, and a test checked it. That was right for a
//! read-only interface; it stopped being right the moment it had to install,
//! back up and restore.
//!
//! Three rules replace the ban, and **protect more**:
//!
//! 1. **Preview by default.** A route returns the plan and does nothing; it only acts
//!    with `?apply=true`. An exact transposition of `Executor::apply(true)` — the CLI and
//!    the API behave the same, and the default changes nothing.
//! 2. **Authorization in the signature.** `Authorized<CanOperate>`: the compiler demands
//!    it, so it cannot be forgotten.
//! 3. **Audit log.** Who, what, when, with the real outcome.
//!
//! Each is locked by a test that walks the list used to **build** the router: a route
//! added without respecting them makes the suite fail.
//!
//! ## 🔴 And the named confirmation, for what destroys
//!
//! The role is not enough: a tired administrator at 2 a.m. is still an administrator.
//! The operations in `hlb_types::needs_confirmation` require **repeating the target's
//! name** — so that a `--purge` typed on the wrong app does not
//! go through.

use std::sync::Arc;

use crate::extract::{Json, Path, Query};
use axum::extract::State as AxumState;
use hlb_api::intent::Acted;
use hlb_api::{ActionResult, ActionStep, StepState};

use crate::api::AppState;
use crate::auth::{Authorized, CanActOnSelf, CanDestroy, CanOperate};
use crate::error::{ActionError, ActionReply};

/// The parameters common to every action.
#[derive(Debug, Default, serde::Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ActionQuery {
    /// 🔴 Absent or `false` = **preview**. That is the default, and it changes nothing.
    #[serde(default)]
    pub apply: bool,
}

/// The body of a destructive operation.
#[derive(Debug, Default, serde::Deserialize, utoipa::ToSchema)]
pub struct Confirmation {
    /// The target's exact name, repeated by the caller.
    #[serde(default)]
    pub confirmed: Option<String>,
}

/// Checks the named confirmation of a destructive operation.
///
/// ⚠️ Compares **exactly**, with no normalisation: accepting "Gitea" for "gitea" would
/// weaken the only protection left once the role has already been granted.
pub fn valid_confirmation(c: &Confirmation, target: &str) -> bool {
    c.confirmed.as_deref() == Some(target)
}

/// Logs an action and returns the response.
///
/// 🔴 Everything goes through here **always**: that is what guarantees no mutating route
/// escapes the log. A test checks it route by route.
pub(crate) async fn respond(
    s: &AppState,
    identity: &crate::auth::Identity,
    action: &str,
    target: &str,
    r: ActionResult,
) -> ActionReply {
    audit(s, identity, action, target, &r).await;
    Ok(Json(r))
}

/// Logs an action whose answer carries more than its result — what [`respond`] does,
/// for a route answering its own type.
pub(crate) async fn audit(
    s: &AppState,
    identity: &crate::auth::Identity,
    action: &str,
    target: &str,
    r: &ActionResult,
) {
    // The real outcome, not the intent: an action that failed halfway is a failure, even
    // if it started correctly.
    let issue = if !r.applied {
        // A preview is not an action: logging it as "ok" would suggest an execution. We
        // name it all the same — knowing someone looked at what a purge would do is
        // information.
        "preview"
    } else if r.succeeded() {
        "ok"
    } else {
        "failed"
    };

    let _ = s
        .append_audit(
            identity.actor.name(),
            identity.role,
            action,
            target,
            issue,
            Some(&r.verdict()),
        )
        .await;
}

/// The privileged side could not answer: a fault of ours, never the caller's.
pub(crate) fn privd_error<T>(e: hlb_privd::Error) -> ActionError<T> {
    ActionError::from(crate::error::ApiError::Internal(e.to_string()))
}

// ---------------------------------------------------------------------------
// Installation
// ---------------------------------------------------------------------------

/// What we choose in order to install an app.
#[derive(Debug, Default, serde::Deserialize, utoipa::ToSchema)]
pub struct InstallRequest {
    // ⚠️ A saved plan stores this body VERBATIM and replays it later. Renaming a field
    // here silently drops it from every plan already recorded: the plan replays without
    // its domain and deploys an app reachable nowhere, with no error to say why. Add
    // `serde(alias = "<old>")` if one ever has to change.
    /// The public domain. Required if the app exposes anything.
    #[serde(default)]
    pub domain: Option<String>,
    /// The mail domain, for the `MailAccount` capabilities.
    #[serde(default)]
    pub mail_domain: Option<String>,
}

/// The catalog, with what you need to know before installing.
#[utoipa::path(
    get,
    path = "/api/catalog",
    responses(
        (status = 200, body = Vec<hlb_api::CatalogItem>)
    ),
    extensions(
        ("x-hlb-requires" = json!("read"))
    )
)]
pub async fn catalog(
    _auth: crate::auth::Authorized<crate::auth::CanRead>,
    AxumState(s): AxumState<Arc<AppState>>,
) -> Json<Vec<hlb_api::CatalogItem>> {
    let Some(cat) = s.catalog.get() else {
        // ⚠️ An empty list would read as "catalog with no applications". A missing
        // catalog is a configuration problem, not an empty catalog — and the screen
        // must be able to say so.
        return Json(Vec::new());
    };

    // Installed is this entry's app: `community/foo` is not installed by the official
    // `foo`, which holds the name it would install as.
    let mut installed: Vec<String> = Vec::new();
    for (n, _) in s.state.installed_apps().await.unwrap_or_default() {
        let source = s.state.app_source(&n).await.ok().flatten();
        installed.push(hlb_catalog::qualified(source.as_deref(), &n));
    }

    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let mut out: Vec<hlb_api::CatalogItem> = cat
        .entries()
        .map(|e| {
            let m = &e.manifest;
            hlb_api::CatalogItem {
                quality: e
                    .quality
                    .clone()
                    .or_else(|| {
                        s.demo
                            .then(|| crate::demo::catalog_quality(&e.name()))
                            .flatten()
                    })
                    .map(|q| hlb_api::CatalogQuality::of(&q, &today)),
                installed: installed.contains(&e.name()),
                // The icons served are the official catalog's.
                icon: e.source.is_none()
                    && crate::api::catalog_icon_path(&cat, &m.metadata.name).is_some(),
                display_name: m
                    .metadata
                    .display_name
                    .clone()
                    .unwrap_or_else(|| m.metadata.name.clone()),
                name: e.name(),
                category: m.metadata.category.clone(),
                homepage: m.metadata.homepage.clone(),
                image: m.spec.image.reference(),
                capabilities: m
                    .spec
                    .requires
                    .iter()
                    .map(|c| hlb_api::Need::of(c, &m.metadata.name))
                    .collect(),
                // An app with no ingress has nothing to expose: asking it for a domain
                // would have you enter an unused value.
                requests_domain: !m.spec.ingress.is_empty(),
                // 🔴 The MANUAL prerequisites first, listed before you even start:
                // discovering at the sixth screen that a DNS record was needed is what
                // makes people abandon an install halfway.
                prerequisites: e
                    .guide
                    .steps
                    .iter()
                    .filter(|g| g.phase == hlb_types::Phase::PreInstall)
                    .map(|g| g.title.clone())
                    .collect(),
            }
        })
        .collect();

    out.sort_by(|a, b| a.name.cmp(&b.name));
    Json(out)
}

/// Installs an application.
///
/// ## 🔴 The preview shows the REAL PLAN
///
/// Not an approximate description: the resolver produces the same actions as
/// `hlb install`, and it is that list we display. A preview that diverged from the
/// execution would be worse than no preview — you would trust it.
#[utoipa::path(
    post,
    path = "/api/apps/{name}/install",
    params(crate::actions::ActionQuery),
    request_body = Option<InstallRequest>,
    responses(
        (status = 200, body = hlb_api::ActionResult),
        (status = 422, description = "Nothing could be planned: the body's `blockers` say why", body = hlb_api::ActionResult)
    ),
    extensions(
        ("x-hlb-requires" = json!("operate")),
        ("x-hlb-preview" = json!(true))
    )
)]
pub async fn install_app(
    auth: Authorized<CanOperate>,
    AxumState(s): AxumState<Arc<AppState>>,
    Path(app): Path<String>,
    Query(q): Query<ActionQuery>,
    body: Option<Json<InstallRequest>>,
) -> ActionReply {
    let request = body.map(|Json(d)| d).unwrap_or_default();
    // The catalog is public: the web side reads what an app needs to place it.
    let manifest = s
        .catalog
        .get()
        .and_then(|c| c.get(&app).ok().map(|e| e.manifest.clone()));
    let answer = s
        .privd()
        .ask(hlb_api::intent::Install {
            app: app.clone(),
            domain: request.domain,
            mail_domain: request.mail_domain,
            apply: q.apply,
        })
        .await
        .map_err(privd_error)?;
    let mut r = match answer {
        Acted::Planned(r) => r,
        Acted::Unplannable(m) => {
            return action_error(&s, auth.identity(), "app-install", &app, &m).await
        }
    };
    if let Some(manifest) = manifest {
        r.warnings.extend(capacity_warnings(&s, &manifest).await);
    }
    respond(&s, auth.identity(), "app-install", &app, r).await
}

/// 🔴 The capacity budget, BEFORE scheduling. An app placed on a tier with no memory
/// returns no clear error: the container is killed by the kernel and `wait_healthy`
/// times out, which sends you looking at the health probe.
///
/// ⚠️ A WARNING, not a blocker: available memory moves, and refusing the install on a
/// measurement from thirty seconds ago would be wrong more often than right.
async fn capacity_warnings(s: &AppState, manifest: &hlb_types::Manifest) -> Vec<String> {
    let tier = manifest
        .spec
        .swarm
        .tier
        .clone()
        .unwrap_or_else(|| "light".to_string());
    let fleet = fleet_per_tier(s).await;
    let mut warnings: Vec<String> = crate::capacity::budget(&fleet, &tier)
        .needing(manifest.spec.swarm.memory)
        .warning()
        .into_iter()
        .collect();
    // A companion is placed on its own: Immich's model server is not split with it.
    for c in &manifest.spec.companions {
        let t = c.tier.clone().unwrap_or_else(|| tier.clone());
        if let Some(w) = crate::capacity::budget(&fleet, &t)
            .needing(c.memory)
            .warning()
        {
            if !warnings.contains(&w) {
                warnings.push(format!("{}: {w}", c.name));
            }
        }
    }
    warnings
}

/// What the catalog has changed in an installed app, field by field. Empty when it
/// matches — and when no catalog is loaded, or the app left it: nothing to compare.
pub async fn catalog_changes(s: &AppState, app: &str) -> Vec<String> {
    s.privd()
        .ask(hlb_api::intent::CatalogChanges { app: app.into() })
        .await
        .unwrap_or_default()
}

/// Brings an installed app to its catalog manifest.
///
/// The images stay as installed — `hlb update` moves those, after its backup — and what
/// would strand data is refused before anything changes: the same decisions as `hlb
/// upgrade`, from `hlb_engine::upgrade`.
#[utoipa::path(
    post,
    path = "/api/apps/{name}/upgrade",
    params(crate::actions::ActionQuery),
    responses(
        (status = 200, body = hlb_api::ActionResult),
        (status = 422, description = "Nothing could be planned: the body's `blockers` say why", body = hlb_api::ActionResult)
    ),
    extensions(
        ("x-hlb-requires" = json!("operate")),
        ("x-hlb-preview" = json!(true))
    )
)]
pub async fn upgrade_app(
    auth: Authorized<CanOperate>,
    AxumState(s): AxumState<Arc<AppState>>,
    Path(app): Path<String>,
    Query(q): Query<ActionQuery>,
) -> ActionReply {
    let answer = s
        .privd()
        .ask(hlb_api::intent::Upgrade {
            app: app.clone(),
            apply: q.apply,
        })
        .await
        .map_err(privd_error)?;
    match answer {
        Acted::Planned(r) => respond(&s, auth.identity(), "app-upgrade", &app, r).await,
        Acted::Unplannable(m) => action_error(&s, auth.identity(), "app-upgrade", &app, &m).await,
    }
}

/// An action that could not even be planned.
///
/// Logged as a failure: not knowing what to do is a result, and keeping quiet about it
/// would leave a screen with no explanation.
pub(crate) async fn action_error(
    s: &AppState,
    identity: &crate::auth::Identity,
    action: &str,
    target: &str,
    message: &str,
) -> ActionReply {
    let r = ActionResult {
        applied: false,
        summary: message.to_string(),
        steps: Vec::new(),
        cli_command: String::new(),
        blockers: vec![message.to_string()],
        warnings: Vec::new(),
        confirmation_required: None,
    };
    let _ = s
        .append_audit(
            identity.actor.name(),
            identity.role,
            action,
            target,
            "failed",
            Some(message),
        )
        .await;
    Err(ActionError::Unplannable(Box::new(r)))
}

// ---------------------------------------------------------------------------
// Backups
// ---------------------------------------------------------------------------

/// Triggers a backup.
#[utoipa::path(
    post,
    path = "/api/apps/{name}/backup",
    params(crate::actions::ActionQuery),
    responses(
        (status = 200, body = hlb_api::ActionResult),
        (status = 422, description = "Nothing could be planned: the body's `blockers` say why", body = hlb_api::ActionResult)
    ),
    extensions(
        ("x-hlb-requires" = json!("operate")),
        ("x-hlb-preview" = json!(true))
    )
)]
pub async fn backup_run(
    auth: Authorized<CanOperate>,
    AxumState(s): AxumState<Arc<AppState>>,
    Path(app): Path<String>,
    Query(q): Query<ActionQuery>,
) -> ActionReply {
    let r = s
        .privd()
        .ask(hlb_api::intent::BackUp {
            app: app.clone(),
            apply: q.apply,
        })
        .await
        .map_err(privd_error)?;
    respond(&s, auth.identity(), "backup-run", &app, r).await
}

// ---------------------------------------------------------------------------
// Guides
// ---------------------------------------------------------------------------

/// How a manual action is attested.
#[derive(Debug, Default, serde::Deserialize, utoipa::ToSchema)]
pub struct AckRequest {
    /// Attest even though the step's own check says it is not done — `hlb ack <app>/<id> --force`.
    #[serde(default)]
    pub force: bool,
}

/// Attests that a manual action was done.
///
/// A step with a check is checked FIRST, as `hlb ack` does: proven done, it is recorded
/// as observed; proven NOT done, the attestation is refused unless forced — taking a
/// word the machine can see is false is exactly the lie the system must refuse.
#[utoipa::path(
    post,
    path = "/api/todo/{app}/{id}",
    params(crate::actions::ActionQuery),
    request_body = Option<AckRequest>,
    responses(
        (status = 200, body = hlb_api::ActionResult),
        (status = 422, description = "Nothing could be planned: the body's `blockers` say why", body = hlb_api::ActionResult)
    ),
    extensions(
        ("x-hlb-requires" = json!("operate")),
        ("x-hlb-preview" = json!(true))
    )
)]
pub async fn check_guide(
    auth: Authorized<CanOperate>,
    AxumState(s): AxumState<Arc<AppState>>,
    Path((app, id)): Path<(String, String)>,
    Query(q): Query<ActionQuery>,
    body: Option<Json<AckRequest>>,
) -> ActionReply {
    let r = s
        .privd()
        .ask(hlb_api::intent::AttestGuide {
            app: app.clone(),
            id,
            force: body.is_some_and(|Json(b)| b.force),
            apply: q.apply,
        })
        .await
        .map_err(privd_error)?;
    respond(&s, auth.identity(), "guide-verify", &app, r).await
}

// ---------------------------------------------------------------------------
// Scaling and updating
// ---------------------------------------------------------------------------

#[derive(Debug, Default, serde::Deserialize, utoipa::ToSchema)]
pub struct ScaleRequest {
    #[serde(default)]
    pub replicas: Option<u64>,
}

/// Changes an application's replica count.
#[utoipa::path(
    post,
    path = "/api/apps/{name}/scale",
    params(crate::actions::ActionQuery),
    request_body = Option<ScaleRequest>,
    responses(
        (status = 200, body = hlb_api::ActionResult),
        (status = 422, description = "Nothing could be planned: the body's `blockers` say why", body = hlb_api::ActionResult)
    ),
    extensions(
        ("x-hlb-requires" = json!("operate")),
        ("x-hlb-preview" = json!(true))
    )
)]
pub async fn resize(
    auth: Authorized<CanOperate>,
    AxumState(s): AxumState<Arc<AppState>>,
    Path(app): Path<String>,
    Query(q): Query<ActionQuery>,
    body: Option<Json<ScaleRequest>>,
) -> ActionReply {
    let request = body.map(|Json(d)| d).unwrap_or_default();
    let r = s
        .privd()
        .ask(hlb_api::intent::Scale {
            app: app.clone(),
            replicas: request.replicas,
            apply: q.apply,
        })
        .await
        .map_err(privd_error)?;
    respond(&s, auth.identity(), "app-scale", &app, r).await
}

// ---------------------------------------------------------------------------
// Backup destinations
// ---------------------------------------------------------------------------

#[derive(Debug, Default, serde::Deserialize, utoipa::ToSchema)]
pub struct DestinationRequest {
    /// Refused unless it is the recorded one: the location is `hlb backup dest add`'s.
    #[serde(default)]
    pub location: Option<String>,
    /// `critical`, `bulky`, or both separated by a comma.
    #[serde(default)]
    pub classes: Option<String>,
    /// The NAME of the secret the destination signs with, never its value — refused
    /// unless it is the recorded one.
    #[serde(default)]
    pub credentials_secret: Option<String>,
}

/// Changes the classes of data a declared backup destination receives.
#[utoipa::path(
    put,
    path = "/api/backup/destinations/{name}",
    params(crate::actions::ActionQuery),
    request_body = Option<DestinationRequest>,
    responses(
        (status = 200, body = hlb_api::ActionResult),
        (status = 422, description = "Nothing could be planned: the body's `blockers` say why", body = hlb_api::ActionResult)
    ),
    extensions(
        ("x-hlb-requires" = json!("operate")),
        ("x-hlb-preview" = json!(true))
    )
)]
pub async fn destination(
    auth: Authorized<CanOperate>,
    AxumState(s): AxumState<Arc<AppState>>,
    Path(name): Path<String>,
    Query(q): Query<ActionQuery>,
    body: Option<Json<DestinationRequest>>,
) -> ActionReply {
    let d = body.map(|Json(d)| d).unwrap_or_default();
    let mut blockers = Vec::new();

    // 🔴 The place and the secret are root's: the pass binds a local location
    // read-write and signs an S3 one's requests with the secret named, so a caller who
    // chose either would mount any host path, or send the off-site's copies — still
    // fresh on every screen — to a server of theirs. This side changes the classes.
    let recorded = s
        .state
        .destinations()
        .await
        .unwrap_or_default()
        .into_iter()
        .find(|(n, ..)| *n == name);
    let whose = "a destination's location and credentials are declared by `hlb backup \
                   dest add`, as root on a manager";
    let (location, secret) = match recorded {
        Some((_, location, _, secret)) => (location, secret),
        None => {
            blockers.push(format!("no destination \"{name}\": {whose}"));
            (d.location.clone().unwrap_or_default(), None)
        }
    };
    if let Some(asked) = d.location.as_deref().filter(|l| *l != location) {
        blockers.push(format!(
            "location \"{asked}\" is not \"{name}\"'s, {location}: {whose}"
        ));
    }
    if let Some(c) = d
        .credentials_secret
        .as_deref()
        .filter(|c| Some(*c) != secret.as_deref())
    {
        blockers.push(format!(
            "credentials_secret \"{c}\" is not the one \"{name}\" signs with: {whose}"
        ));
    }

    let classes = d.classes.clone().unwrap_or_else(|| "critical".to_string());
    let known: Vec<&str> = classes
        .split(',')
        .map(str::trim)
        .filter(|c| hlb_backup::Class::parse(c).is_none())
        .collect();
    if !known.is_empty() {
        blockers.push(format!(
            "{} unknown: {} — expected \"critical\" or \"bulky\"",
            hlb_api::plural(known.len() as u64, "class", "classes"),
            known.join(", ")
        ));
    }

    let applied = q.apply && blockers.is_empty();
    let mut step = ActionStep {
        description: format!("send destination \"{name}\" ({location}) the classes [{classes}]"),
        state: StepState::Planned,
        error: None,
    };

    if applied {
        let asked = hlb_api::intent::SetDestinationClasses {
            name: name.clone(),
            classes: classes.clone(),
        };
        match s.record(asked).await {
            Ok(()) => step.state = StepState::Done,
            Err(e) => {
                step.state = StepState::Failed;
                step.error = Some(e.to_string());
            }
        }
    }

    // `dest add` without a key forgets the one stored: an S3 destination's line asks it.
    let key = if secret.is_some() {
        " --access-key <key>"
    } else {
        ""
    };
    let r = ActionResult {
        applied,
        summary: format!("destination \"{name}\""),
        steps: vec![step],
        cli_command: format!(
            "hlb backup dest add {name} --location {location} --classes {classes}{key}"
        ),
        blockers,
        warnings: Vec::new(),
        confirmation_required: None,
    };

    respond(&s, auth.identity(), "backup-dest", &name, r).await
}

// ---------------------------------------------------------------------------
// Nodes
// ---------------------------------------------------------------------------

#[derive(Debug, Default, serde::Deserialize, utoipa::ToSchema)]
pub struct NodeRequest {
    /// `active`, `pause` or `drain`.
    #[serde(default)]
    pub availability: Option<String>,
    /// The node's name repeated, when the preview says draining it stops applications
    /// (`confirmation_required`) — what `hlb node upgrade <node> --accept-downtime` says.
    #[serde(default)]
    pub confirmed: Option<String>,
}

/// Changes a node's availability (drain, summary).
#[utoipa::path(
    post,
    path = "/api/nodes/{id}/availability",
    params(crate::actions::ActionQuery),
    request_body = Option<NodeRequest>,
    responses(
        (status = 200, body = hlb_api::ActionResult),
        (status = 422, description = "Nothing could be planned: the body's `blockers` say why", body = hlb_api::ActionResult),
        (status = 428, description = "Applying it needs a passkey: present one where the header says, then send it again", body = hlb_api::ErrorBody, headers(("x-hlb-passkey-url" = String, description = "Where to present the passkey")))
    ),
    extensions(
        ("x-hlb-requires" = json!("operate")),
        ("x-hlb-preview" = json!(true))
    )
)]
pub async fn node_availability(
    auth: Authorized<CanOperate>,
    AxumState(s): AxumState<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
    Query(q): Query<ActionQuery>,
    body: Option<Json<NodeRequest>>,
) -> ActionReply {
    let d = body.map(|Json(d)| d).unwrap_or_default();
    let asked = hlb_api::intent::NodeAvailability {
        node: id.clone(),
        availability: d.availability.unwrap_or_default(),
        confirmed: d.confirmed,
        apply: q.apply,
    };
    let proof = crate::passkey::confirm(&s, &headers, vec![asked.clone().into()]).await?;
    let r = s
        .privd()
        .ask_confirmed(proof, asked)
        .await
        .map_err(privd_error)?;
    respond(&s, auth.identity(), "node-availability", &id, r).await
}

// ---------------------------------------------------------------------------
// Destructif
// ---------------------------------------------------------------------------

/// Deletes an application.
///
/// 🔴 Requires `CanDestroy` **and** the named confirmation.
#[utoipa::path(
    delete,
    path = "/api/apps/{name}",
    params(crate::actions::ActionQuery),
    request_body = Option<Confirmation>,
    responses(
        (status = 200, body = hlb_api::ActionResult),
        (status = 422, description = "Nothing could be planned: the body's `blockers` say why", body = hlb_api::ActionResult),
        (status = 428, description = "Applying it needs a passkey: present one where the header says, then send it again", body = hlb_api::ErrorBody, headers(("x-hlb-passkey-url" = String, description = "Where to present the passkey")))
    ),
    extensions(
        ("x-hlb-requires" = json!("destroy")),
        ("x-hlb-preview" = json!(true))
    )
)]
pub async fn delete_app(
    auth: Authorized<CanDestroy>,
    AxumState(s): AxumState<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Path(app): Path<String>,
    Query(q): Query<ActionQuery>,
    body: Option<Json<Confirmation>>,
) -> ActionReply {
    let asked = hlb_api::intent::Remove {
        app: app.clone(),
        confirmed: body.and_then(|Json(c)| c.confirmed),
        apply: q.apply,
    };
    let proof = crate::passkey::confirm(&s, &headers, vec![asked.clone().into()]).await?;
    let r = s
        .privd()
        .ask_confirmed(proof, asked)
        .await
        .map_err(privd_error)?;
    respond(&s, auth.identity(), hlb_state::APP_REMOVED, &app, r).await
}

/// Purges one of the SIGNED-IN account's own expired-but-still-active aliases.
///
/// 🔴 Scoped to `for_account()`, exactly like `my_aliases`: never a name taken from the
/// URL, or one person could purge another's alias. And the state is marked ONLY AFTER
/// the removal succeeds on Stalwart — the reverse would claim the address closed while
/// it still receives.
#[utoipa::path(
    post,
    path = "/api/v1/my-aliases/{local}/purge",
    params(crate::actions::ActionQuery),
    responses(
        (status = 200, body = hlb_api::ActionResult),
        (status = 422, description = "Nothing could be planned: the body's `blockers` say why", body = hlb_api::ActionResult)
    ),
    extensions(
        ("x-hlb-requires" = json!("act-on-self")),
        ("x-hlb-preview" = json!(true))
    )
)]
pub async fn purge_my_alias(
    auth: Authorized<CanActOnSelf>,
    AxumState(s): AxumState<Arc<AppState>>,
    Path(local): Path<String>,
    Query(q): Query<ActionQuery>,
) -> ActionReply {
    // ⚠️ The preview is always allowed, even with nothing bound to act for: that is
    // the only way to see why nothing can happen. Only `apply` is refused.
    let r = s
        .privd()
        .ask(hlb_api::intent::PurgeAlias {
            account: auth.identity().actor.for_account().map(str::to_string),
            local: local.clone(),
            apply: q.apply,
        })
        .await
        .map_err(privd_error)?;
    respond(&s, auth.identity(), "alias-purge", &local, r).await
}

/// Disables one of the SIGNED-IN account's own aliases without deleting it.
///
/// 🔴 Routes it to a "Disabled" folder rather than the inbox — the alias stays present
/// on Stalwart, so what still writes to it keeps being counted there. Deleting it
/// outright would teach nothing more. See `hlb_users::sieve`.
#[utoipa::path(
    post,
    path = "/api/v1/my-aliases/{local}/disable",
    params(crate::actions::ActionQuery),
    responses(
        (status = 200, body = hlb_api::ActionResult),
        (status = 422, description = "Nothing could be planned: the body's `blockers` say why", body = hlb_api::ActionResult)
    ),
    extensions(
        ("x-hlb-requires" = json!("act-on-self")),
        ("x-hlb-preview" = json!(true))
    )
)]
pub async fn disable_my_alias(
    auth: Authorized<CanActOnSelf>,
    AxumState(s): AxumState<Arc<AppState>>,
    Path(local): Path<String>,
    Query(q): Query<ActionQuery>,
) -> ActionReply {
    // ⚠️ The preview is always allowed, even with nothing bound to act for — see
    // `purge_my_alias`.
    let account = auth.identity().actor.for_account().map(str::to_string);
    let mut blockers = Vec::new();

    match &account {
        None => blockers.push("this request acts on nobody's behalf — sign in first".into()),
        Some(acct) => {
            let rows = s.state.aliases(acct).await.unwrap_or_default();
            if !rows.iter().any(|(_, l, ..)| l == &local) {
                blockers.push(format!("no such alias: {local}"));
            }
        }
    }

    let applied = q.apply && blockers.is_empty();
    let address = format!("{local}@{}", s.mail_domain);
    let mut steps = vec![ActionStep {
        description: format!("route {address} to the \"Disabled\" folder"),
        state: StepState::Planned,
        error: None,
    }];

    if applied {
        if let Some(acct) = &account {
            let asked = hlb_api::intent::SetAliasFolder {
                user: acct.to_string(),
                local: local.clone(),
                folder: Some("Disabled".into()),
            };
            match s.record(asked).await {
                Ok(()) => steps[0].state = StepState::Done,
                Err(e) => {
                    steps[0].state = StepState::Failed;
                    steps[0].error = Some(e.to_string());
                }
            }
        }
    }

    let r = ActionResult {
        applied,
        summary: format!(
            "disable {address}: it stays on the server, out of the inbox — apply \
             \"hlb user alias sieve <account>\" afterwards for it to take effect"
        ),
        steps,
        cli_command: format!(
            "hlb user alias disable {} {local}",
            account.as_deref().unwrap_or("<account>")
        ),
        blockers,
        warnings: Vec::new(),
        confirmation_required: None,
    };

    respond(&s, auth.identity(), "alias-disable", &local, r).await
}

/// The fleet, reduced to what the capacity budget needs: a tier and a memory figure.
///
/// ⚠️ The join goes through the HOSTNAME: the Swarm inventory knows the labels, the
/// agent reports know the memory, and the two share no key. It is the same rule as in
/// the API, and it has no better home as long as the hostname is the only bridge.
/// hostname remains the only bridge.
async fn fleet_per_tier(s: &AppState) -> Vec<(Option<String>, Option<u64>)> {
    let nodes = match s.privd().ask(hlb_api::intent::Nodes {}).await {
        Ok(Some(n)) => n.unwrap_or_default(),
        // ⚠️ The demo has fabricated nodes, as for the topology: without them, every
        // install preview would carry a "no node on this tier" warning, and you would
        // never see the normal screen.
        Ok(None) if s.demo => return crate::demo::fleet_per_tier(),
        // With no orchestrator we know NO tier. Returning an empty list makes you
        // conclude "no node on this tier", which is exactly what we know.
        Ok(None) | Err(_) => return Vec::new(),
    };

    let poll = crate::api::fleet_now(s).await;
    nodes
        .iter()
        .map(|n| {
            let memory = poll
                .values()
                .filter_map(|st| st.report())
                .find(|r| r.hostname == n.hostname)
                .and_then(|r| r.memory_available_mb);
            (n.tier.clone(), memory)
        })
        .collect()
}

/// What gets recorded.
#[derive(serde::Deserialize, utoipa::ToSchema)]
pub struct PlanRequest {
    pub name: String,
    pub method: String,
    pub path: String,
    #[serde(default)]
    pub body: String,
    pub summary: String,
    #[serde(default)]
    pub note: Option<String>,
}

/// Records a plan under a name (batch 10.4).
///
/// ⚠️ A configuration route: it executes NOTHING. Forcing a preview on it would mean
/// previewing the recording of a preview, which makes no sense — and the recording is
/// reversible with one "forget".
#[utoipa::path(
    post,
    path = "/api/plans",
    request_body = PlanRequest,
    responses(
        (status = 200, body = hlb_api::ActionResult),
        (status = 422, description = "Nothing could be planned: the body's `blockers` say why", body = hlb_api::ActionResult)
    ),
    extensions(
        ("x-hlb-requires" = json!("operate")),
        ("x-hlb-preview" = json!(false))
    )
)]
pub async fn record_plan(
    auth: crate::auth::Authorized<crate::auth::CanOperate>,
    AxumState(s): AxumState<Arc<AppState>>,
    Json(d): Json<PlanRequest>,
) -> ActionReply {
    // 🔴 A plan targeting an unknown route would be accepted here and would fail at
    // execution, weeks later, on a 404 that points nowhere. We check against the
    // document the router is built with.
    if plannable(&d.method, &d.path).is_none() {
        return action_error(
            &s,
            auth.identity(),
            "plan-record",
            &d.name,
            &format!("\"{} {}\" is not a known action", d.method, d.path),
        )
        .await;
    }

    let actor = auth.identity().actor.name().to_string();
    let asked = hlb_api::intent::SaveNamedPlan {
        name: d.name.clone(),
        method: d.method.clone(),
        path: d.path.clone(),
        body: d.body.clone(),
        summary: d.summary.clone(),
        by: actor.clone(),
        note: d.note.clone(),
    };
    if let Err(e) = s.record(asked).await {
        return action_error(&s, auth.identity(), "plan-record", &d.name, &e.to_string()).await;
    }

    let r = ActionResult {
        applied: true,
        summary: format!("plan \"{}\" recorded", d.name),
        steps: vec![ActionStep {
            description: d.summary.clone(),
            state: StepState::Done,
            error: None,
        }],
        cli_command: String::new(),
        blockers: Vec::new(),
        warnings: Vec::new(),
        confirmation_required: None,
    };
    respond(&s, auth.identity(), "plan-record", &d.name, r).await
}

/// The route a plan of this request would replay, if it is one a plan may name: a
/// route with a preview, which a replay asks with `apply=false` — any other would act
/// —, and not a public one, whose body carries what opens it.
fn plannable(method: &str, path: &str) -> Option<&'static crate::openapi::Route> {
    // A segment a fetch resolves (`..`), cuts (`?`, `#`) or the router reads as another
    // (`//`) would send the replay elsewhere than the route matched here.
    let plain = path
        .split('/')
        .skip(1)
        .all(|seg| !seg.is_empty() && seg != "." && seg != ".." && !seg.contains(['?', '#']));
    crate::openapi::routes().iter().find(|r| {
        plain
            && r.verb == method
            && r.preview == Some(true)
            && !r.public
            && compatible_paths(&r.path, path)
    })
}

/// Does a route path (`/api/apps/{name}/install`) accept this concrete path?
///
/// ⚠️ Segment-by-segment comparison: a `{param}` accepts anything, the rest must match
/// exactly. A prefix comparison would let "/api/apps/gitea/install/really" through,
/// which does not exist.
fn compatible_paths(template: &str, concrete: &str) -> bool {
    let g: Vec<&str> = template.split('/').collect();
    let c: Vec<&str> = concrete.split('/').collect();
    g.len() == c.len()
        && g.iter()
            .zip(&c)
            .all(|(a, b)| (a.starts_with('{') && a.ends_with('}')) || a == b)
}

/// The recorded plans.
#[utoipa::path(
    get,
    path = "/api/plans",
    responses(
        (status = 200, body = Vec<hlb_api::NamedPlan>)
    ),
    extensions(
        ("x-hlb-requires" = json!("read"))
    )
)]
pub async fn list_plans(
    _auth: crate::auth::Authorized<crate::auth::CanRead>,
    AxumState(s): AxumState<Arc<AppState>>,
) -> Json<Vec<hlb_api::NamedPlan>> {
    Json(
        s.state
            .named_plans()
            .await
            .unwrap_or_default()
            .into_iter()
            .map(
                |(name, method, path, body, summary, created_by, age_s)| hlb_api::NamedPlan {
                    route: plannable(&method, &path).map(|r| r.path.clone()),
                    name,
                    summary,
                    method,
                    path,
                    body,
                    created_by,
                    age_s,
                },
            )
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_saved_plan_can_only_target_a_route_that_exists() {
        // 🔴 A plan targeting an unknown route would be accepted here and would fail at
        // execution, weeks later, on a 404 that points nowhere — at the precise moment
        // you were counting on it.
        let exists = |method: &str, path: &str| super::plannable(method, path).is_some();

        assert!(exists("POST", "/api/apps/gitea/install"));
        assert!(exists("POST", "/api/apps/immich/backup"));
        assert!(!exists("POST", "/api/apps/gitea/invent"));
        assert!(!exists("DELETE", "/api/apps/gitea/install"));
        // A read is not an action: replaying one would do nothing worth a name.
        assert!(!exists("GET", "/api/apps/gitea"));
    }

    #[test]
    fn a_plan_replays_a_preview_and_nothing_else() {
        // 🔴 Replaying asks the route with `apply=false`, which a route declaring no
        // preview ignores: the Bitwarden assistant would mint a token at the replay.
        // A public route's body carries what opens it (a sign-up's invitation), and
        // the plans list is read by every viewer.
        let exists = |method: &str, path: &str| super::plannable(method, path).is_some();
        assert!(!exists("POST", "/api/bitwarden"));
        assert!(!exists("POST", "/api/plans"));
        assert!(!exists("POST", "/api/signup"));
        // What a fetch resolves or cuts away addresses another route than the one
        // matched here.
        assert!(!exists("POST", "/api/apps/../install"));
        assert!(!exists("POST", "/api/apps/./install"));
        assert!(!exists("POST", "/api/apps/x?apply=true/install"));
        assert!(!exists("POST", "/api/apps/x#/install"));
        assert!(!exists("POST", "/api/apps//install"));
    }

    #[test]
    fn a_path_template_never_matches_a_longer_path() {
        // ⚠️ A prefix comparison would let "…/install/really" through, which does not
        // exist — and the plan would fail at execution.
        assert!(compatible_paths(
            "/api/apps/{name}/install",
            "/api/apps/gitea/install"
        ));
        assert!(!compatible_paths(
            "/api/apps/{name}/install",
            "/api/apps/gitea/install/for-real"
        ));
        assert!(!compatible_paths(
            "/api/apps/{name}/install",
            "/api/apps/gitea"
        ));
        // And a parameter accepts any segment, but ONE only.
        assert!(!compatible_paths("/api/recovery/{id}", "/api/recovery/a/b"));
    }

    use super::*;

    #[test]
    fn a_confirmation_must_match_exactly() {
        // ⚠️ Accepting "Gitea" for "gitea" would weaken the only protection left once
        // the role has already been granted.
        let correct = Confirmation {
            confirmed: Some("gitea".into()),
        };
        assert!(valid_confirmation(&correct, "gitea"));
        assert!(!valid_confirmation(&correct, "vikunja"));

        let wrong_case = Confirmation {
            confirmed: Some("Gitea".into()),
        };
        assert!(!valid_confirmation(&wrong_case, "gitea"), "case matters");

        let empty = Confirmation { confirmed: None };
        assert!(!valid_confirmation(&empty, "gitea"));
    }

    #[test]
    fn apply_defaults_to_false() {
        // 🔴 The central invariant: the absence of the parameter means PREVIEW. A
        // default of `true` would turn visiting a screen into an execution.
        let q: ActionQuery = serde_json::from_str("{}").expect("default");
        assert!(!q.apply);
    }
}
