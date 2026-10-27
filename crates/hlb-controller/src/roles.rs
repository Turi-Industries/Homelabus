//! Roles as data: what they are, who holds them, which apps let them in, the quotas
//! they carry — and the sync that makes PocketID and the apps hold the same.
//!
//! The rule is `hlb_users::access`, the writing `hlb_engine::roles`; this is the HTTP
//! side. Every change is previewed first, like any action, and an applied one asks
//! for a sync at once rather than at the loop's next pass: removing someone's access
//! is done in a hurry.

use std::sync::Arc;

use crate::extract::{Json, Path, Query};
use axum::extract::State as AxumState;
use hlb_api::roles::{AccessOverview, AppAccess, PersonQuotaRequest, QuotaRequest, RoleRequest};
use hlb_api::{ActionResult, ActionStep, StepState};
use hlb_engine::roles::{human, Inputs, Outcome, RoleSync};
use hlb_users::access::{self, Entry};
use hlb_users::{MailLimits, RoleDef};

use crate::actions::ActionQuery;
use crate::api::AppState;
use crate::auth::{Authorized, CanManageAccounts};
use crate::error::{ActionError, ActionReply, ApiResult};

fn mail_api(m: &MailLimits) -> hlb_api::roles::MailLimits {
    hlb_api::roles::MailLimits {
        max_mailboxes: m.max_mailboxes,
        max_permanent_aliases: m.max_permanent_aliases,
        max_temporary_aliases: m.max_temporary_aliases,
        max_duration_s: m.max_duration_s,
        quota_bytes: m.quota_bytes,
    }
}

fn openings(o: Vec<access::Opening>) -> Vec<hlb_api::roles::Opening> {
    o.into_iter()
        .map(|o| hlb_api::roles::Opening {
            app: o.app,
            display_name: o.display_name,
            means: o.means,
        })
        .collect()
}

/// The roles and the apps, as the people screens show them.
pub async fn overview(s: &AppState) -> Result<AccessOverview, hlb_engine::Error> {
    let inputs = Inputs::read(&s.state).await?;
    let installed = inputs.installed();
    let desired = inputs.desired();
    let roles = inputs
        .roles
        .iter()
        .map(|r| hlb_api::roles::RoleSummary {
            id: r.id.clone(),
            name: r.name.clone(),
            level: r.level.as_str().to_string(),
            mail: mail_api(&r.mail),
            quotas: r.quotas.clone(),
            holders: inputs
                .people
                .iter()
                .filter(|p| p.role.as_deref() == Some(r.id.as_str()))
                .map(|p| p.name.clone())
                .collect(),
            apps: installed
                .iter()
                .filter(|a| a.allowed.contains(&r.id))
                .map(|a| a.manifest.metadata.name.clone())
                .collect(),
            opens: openings(access::opens(r, &installed)),
        })
        .collect();
    let apps = installed
        .iter()
        .filter_map(|a| {
            let m = a.manifest;
            let name = &m.metadata.name;
            let entry = access::entry_of(m)?;
            Some(AppAccess {
                app: name.clone(),
                display_name: m
                    .metadata
                    .display_name
                    .clone()
                    .unwrap_or_else(|| name.clone()),
                entry: match entry {
                    Entry::Client => hlb_api::roles::Entry::Client,
                    Entry::Portal => hlb_api::roles::Entry::Portal,
                },
                floor: access::floor_of(m).as_str().to_string(),
                allowed: a.allowed.iter().cloned().collect(),
                closed: desired.doors.get(name).is_none_or(|d| d.closed()),
                quota: m.spec.access.as_ref().is_some_and(|a| a.quota.is_some()),
            })
        })
        .collect();
    Ok(AccessOverview {
        roles,
        apps,
        notes: desired.notes.iter().map(ToString::to_string).collect(),
    })
}

/// The roles, and who may enter each app.
#[utoipa::path(
    get,
    path = "/api/access",
    responses(
        (status = 200, body = AccessOverview)
    ),
    extensions(
        ("x-hlb-requires" = json!("manage-accounts"))
    )
)]
pub async fn access(
    _auth: Authorized<CanManageAccounts>,
    AxumState(s): AxumState<Arc<AppState>>,
) -> ApiResult<AccessOverview> {
    overview(&s)
        .await
        .map(Json)
        .map_err(|e| crate::error::ApiError::Internal(e.to_string()))
}

fn planned(description: String) -> ActionStep {
    ActionStep {
        description,
        state: StepState::Planned,
        error: None,
    }
}

fn result(
    summary: String,
    steps: Vec<ActionStep>,
    cli: String,
    blockers: Vec<String>,
    warnings: Vec<String>,
    applied: bool,
) -> ActionResult {
    ActionResult {
        applied,
        summary,
        steps,
        cli_command: cli,
        blockers,
        warnings,
        confirmation_required: None,
    }
}

/// Logs the action, asks for a sync when something changed, and answers — 422 when
/// nothing could even be planned.
async fn answer(
    s: &Arc<AppState>,
    auth: &crate::auth::Identity,
    action: &str,
    target: &str,
    r: ActionResult,
) -> ActionReply {
    let outcome = if !r.applied {
        "preview"
    } else if r.succeeded() {
        "ok"
    } else {
        "failed"
    };
    let _ = s
        .state
        .audit(
            auth.actor.name(),
            auth.role,
            action,
            target,
            outcome,
            Some(&r.verdict()),
        )
        .await;
    if r.applied && r.succeeded() {
        sync_soon(s.clone());
    }
    if !r.blockers.is_empty() && r.steps.is_empty() {
        return Err(ActionError::Unplannable(Box::new(r)));
    }
    Ok(Json(r))
}

fn apply_step(step: &mut ActionStep, done: Result<(), String>) {
    match done {
        Ok(()) => step.state = StepState::Done,
        Err(e) => {
            step.state = StepState::Failed;
            step.error = Some(e);
        }
    }
}

/// What a role's level change opens, said before it is made.
async fn opening_warnings(
    s: &AppState,
    role: &RoleDef,
    before: Option<hlb_types::Role>,
) -> Vec<String> {
    let mut w = Vec::new();
    if role.level == hlb_types::Role::Admin && before != Some(hlb_types::Role::Admin) {
        w.push(format!(
            "\"{}\" becomes an ADMIN role: whoever holds it grants rights and destroys data",
            role.label()
        ));
    }
    if before.is_none_or(|b| b < role.level) {
        for o in hlb_engine::roles::opened_by(&s.state, role)
            .await
            .unwrap_or_default()
        {
            w.push(format!("it administers {}: {}", o.display_name, o.means));
        }
    }
    w
}

/// Creates a role, or changes one's name, level and mail limits.
#[utoipa::path(
    post,
    path = "/api/roles/{role}",
    params(crate::actions::ActionQuery),
    request_body = Option<RoleRequest>,
    responses(
        (status = 200, body = hlb_api::ActionResult),
        (status = 422, description = "Nothing could be planned: the body's `blockers` say why", body = hlb_api::ActionResult)
    ),
    extensions(
        ("x-hlb-requires" = json!("manage-accounts")),
        ("x-hlb-preview" = json!(true))
    )
)]
pub async fn put_role(
    auth: Authorized<CanManageAccounts>,
    AxumState(s): AxumState<Arc<AppState>>,
    Path(id): Path<String>,
    Query(q): Query<ActionQuery>,
    body: Option<Json<RoleRequest>>,
) -> ActionReply {
    let d = body.map(|Json(d)| d).unwrap_or_default();
    let mut blockers = Vec::new();
    if !hlb_types::access::valid_role_id(&id) {
        blockers.push(format!(
            "\"{id}\": a role id is lowercase letters, digits and hyphens, up to 40 — it names a PocketID group, and never changes"
        ));
    }
    let current = s.state.role(&id).await.ok().flatten();
    let level = match d.level.as_deref() {
        Some(l) => match hlb_types::Role::parse(l) {
            Some(l) => l,
            None => {
                blockers.push(format!(
                    "unknown level \"{l}\" — user, viewer, operator, admin"
                ));
                hlb_types::Role::User
            }
        },
        None => current.as_ref().map_or(hlb_types::Role::User, |r| r.level),
    };
    let name = d
        .name
        .clone()
        .or_else(|| current.as_ref().map(|r| r.name.clone()))
        .unwrap_or_else(|| id.clone());
    if !(2..=50).contains(&name.chars().count()) {
        blockers.push(format!(
            "\"{name}\": a role's name is 2 to 50 characters — PocketID's limit for a group"
        ));
    }
    let mail = match &d.mail {
        Some(m) => MailLimits {
            max_mailboxes: m.max_mailboxes,
            max_permanent_aliases: m.max_permanent_aliases,
            max_temporary_aliases: m.max_temporary_aliases,
            max_duration_s: m.max_duration_s,
            quota_bytes: m.quota_bytes,
        },
        None => current
            .as_ref()
            .map_or_else(MailLimits::standard, |r| r.mail.clone()),
    };
    let role = RoleDef {
        id: id.clone(),
        name: name.clone(),
        level,
        mail,
        quotas: current
            .as_ref()
            .map(|r| r.quotas.clone())
            .unwrap_or_default(),
    };

    // 🔴 The last administrator's role cannot lose its level: nobody could grant
    // rights any more, and only SQLite edited by hand would repair it.
    if let Some(c) = &current {
        if c.level == hlb_types::Role::Admin && level != hlb_types::Role::Admin {
            // Read or refused: an empty list here would have let the last one go.
            let holders = s.state.users_with_roles().await?;
            let others = holders.iter().any(|h| {
                h.level == hlb_types::Role::Admin && h.role.as_deref() != Some(id.as_str())
            });
            if !others
                && holders
                    .iter()
                    .any(|h| h.role.as_deref() == Some(id.as_str()))
            {
                blockers.push(format!(
                    "\"{id}\" is the only role holding administrators — keep it admin, or give someone another admin role first"
                ));
            }
        }
    }
    let warnings = opening_warnings(&s, &role, current.as_ref().map(|r| r.level)).await;

    let applied = q.apply && blockers.is_empty();
    let mut step = planned(match &current {
        None => format!(
            "create the role \"{name}\" ({id}), level {}",
            level.as_str()
        ),
        Some(c) => format!(
            "role \"{id}\": \"{}\" level {} → \"{name}\" level {}",
            c.name,
            c.level.as_str(),
            level.as_str()
        ),
    });
    if applied {
        apply_step(
            &mut step,
            s.state
                .put_role(&role, auth.actor().name())
                .await
                .map_err(|e| e.to_string()),
        );
    }
    let r = result(
        format!("role \"{id}\""),
        if blockers.is_empty() {
            vec![step]
        } else {
            Vec::new()
        },
        format!(
            "hlb role set {id} --name \"{name}\" --level {} --apply",
            level.as_str()
        ),
        blockers,
        warnings,
        applied,
    );
    answer(&s, auth.identity(), "role-set", &id, r).await
}

/// Deletes a role nothing uses.
#[utoipa::path(
    delete,
    path = "/api/roles/{role}",
    params(crate::actions::ActionQuery),
    responses(
        (status = 200, body = hlb_api::ActionResult),
        (status = 422, description = "Nothing could be planned: the body's `blockers` say why", body = hlb_api::ActionResult)
    ),
    extensions(
        ("x-hlb-requires" = json!("manage-accounts")),
        ("x-hlb-preview" = json!(true))
    )
)]
pub async fn delete_role(
    auth: Authorized<CanManageAccounts>,
    AxumState(s): AxumState<Arc<AppState>>,
    Path(id): Path<String>,
    Query(q): Query<ActionQuery>,
) -> ActionReply {
    let mut blockers = Vec::new();
    if s.state.role(&id).await.ok().flatten().is_none() {
        blockers.push(format!("no role \"{id}\""));
    } else if let Ok(Some(why)) = s.state.role_in_use(&id, crate::auth::now()).await {
        blockers.push(format!("\"{id}\" is {why}"));
    }
    let applied = q.apply && blockers.is_empty();
    let mut step = planned(format!("delete the role \"{id}\" and its PocketID group"));
    if applied {
        apply_step(
            &mut step,
            s.state
                .delete_role(&id)
                .await
                .map(|_| ())
                .map_err(|e| e.to_string()),
        );
    }
    let r = result(
        format!("delete the role \"{id}\""),
        if blockers.is_empty() {
            vec![step]
        } else {
            Vec::new()
        },
        format!("hlb role delete {id} --apply"),
        blockers,
        Vec::new(),
        applied,
    );
    answer(&s, auth.identity(), "role-delete", &id, r).await
}

/// Is this installed app one that takes a quota?
async fn quota_app(s: &AppState, app: &str) -> Option<String> {
    match s.state.app_manifest(app).await {
        Err(_) => Some(format!("\"{app}\" is not installed")),
        Ok(m) if m.spec.access.as_ref().is_none_or(|a| a.quota.is_none()) => Some(format!(
            "{app} takes no quota from Homelabus — its manifest declares none"
        )),
        Ok(_) => None,
    }
}

/// A role's storage quota in an app; no `bytes` removes it.
#[utoipa::path(
    post,
    path = "/api/roles/{role}/quota/{app}",
    params(crate::actions::ActionQuery),
    request_body = Option<QuotaRequest>,
    responses(
        (status = 200, body = hlb_api::ActionResult),
        (status = 422, description = "Nothing could be planned: the body's `blockers` say why", body = hlb_api::ActionResult)
    ),
    extensions(
        ("x-hlb-requires" = json!("manage-accounts")),
        ("x-hlb-preview" = json!(true))
    )
)]
pub async fn role_quota(
    auth: Authorized<CanManageAccounts>,
    AxumState(s): AxumState<Arc<AppState>>,
    Path((id, app)): Path<(String, String)>,
    Query(q): Query<ActionQuery>,
    body: Option<Json<QuotaRequest>>,
) -> ActionReply {
    let bytes = body.and_then(|Json(d)| d.bytes);
    let mut blockers = Vec::new();
    if s.state.role(&id).await.ok().flatten().is_none() {
        blockers.push(format!("no role \"{id}\""));
    }
    blockers.extend(quota_app(&s, &app).await);
    let applied = q.apply && blockers.is_empty();
    let said = bytes.map_or("none".to_string(), human);
    let mut step = planned(format!("\"{id}\" in {app}: quota {said}"));
    if applied {
        apply_step(
            &mut step,
            s.state
                .set_role_quota(&id, &app, bytes)
                .await
                .map_err(|e| e.to_string()),
        );
    }
    let cli = match bytes {
        Some(b) => format!(
            "hlb role quota {id} {app} --gib {} --apply",
            hlb_types::access::QuotaUnit::GiB.amount(b)
        ),
        None => format!("hlb role quota {id} {app} --none --apply"),
    };
    let r = result(
        format!("\"{id}\"'s quota in {app}"),
        if blockers.is_empty() {
            vec![step]
        } else {
            Vec::new()
        },
        cli,
        blockers,
        Vec::new(),
        applied,
    );
    answer(&s, auth.identity(), "role-quota", &format!("{id}/{app}"), r).await
}

/// Republishes the routes when the app sits behind the portal: its groups are in the
/// Caddyfile, and nothing else carries them to Caddy.
async fn republish(s: &AppState, app: &str) -> Result<(), String> {
    let behind_portal = match s.state.app_manifest(app).await {
        Ok(m) => access::entry_of(&m) == Some(Entry::Portal),
        Err(_) => false,
    };
    if !behind_portal {
        return Ok(());
    }
    let (Some(orch), Some(install)) = (&s.orchestrator, &s.install) else {
        return Err(
            "the controller reaches no Docker: `hlb ingress --apply` publishes the routes".into(),
        );
    };
    hlb_engine::ingress::publish(orch.as_ref(), &s.state, Some(&install.vault))
        .await
        .map(|_| ())
        .map_err(|e| format!("the portal still checks the old roles — {e}"))
}

/// Lets a role into an installed app.
#[utoipa::path(
    post,
    path = "/api/apps/{app}/roles/{role}",
    params(crate::actions::ActionQuery),
    responses(
        (status = 200, body = hlb_api::ActionResult),
        (status = 422, description = "Nothing could be planned: the body's `blockers` say why", body = hlb_api::ActionResult)
    ),
    extensions(
        ("x-hlb-requires" = json!("manage-accounts")),
        ("x-hlb-preview" = json!(true))
    )
)]
pub async fn allow_role(
    auth: Authorized<CanManageAccounts>,
    AxumState(s): AxumState<Arc<AppState>>,
    Path((app, id)): Path<(String, String)>,
    Query(q): Query<ActionQuery>,
) -> ActionReply {
    let mut blockers = Vec::new();
    let mut warnings = Vec::new();
    let role = s.state.role(&id).await.ok().flatten();
    match (&role, s.state.app_manifest(&app).await) {
        (None, _) => blockers.push(format!("no role \"{id}\"")),
        (_, Err(_)) => blockers.push(format!("\"{app}\" is not installed")),
        (Some(r), Ok(m)) => {
            if let Some(why) = access::refusal(r, &m) {
                blockers.push(why);
            } else if let Some(admins) = m.spec.access.as_ref().and_then(|a| a.admins.as_ref()) {
                if r.level >= admins.level {
                    warnings.push(format!(
                        "whoever holds \"{}\" administers {app}: {}",
                        r.label(),
                        admins.means
                    ));
                }
            }
        }
    }
    let applied = q.apply && blockers.is_empty();
    let mut step = planned(format!("let \"{id}\" into {app}"));
    if applied {
        let done = match s.state.allow_role(&app, &id, auth.actor().name()).await {
            Ok(_) => republish(&s, &app).await,
            Err(e) => Err(e.to_string()),
        };
        apply_step(&mut step, done);
    }
    let r = result(
        format!("let \"{id}\" into {app}"),
        if blockers.is_empty() {
            vec![step]
        } else {
            Vec::new()
        },
        format!("hlb role allow {id} {app} --apply"),
        blockers,
        warnings,
        applied,
    );
    answer(&s, auth.identity(), "role-allow", &format!("{app}/{id}"), r).await
}

/// Stops letting a role into an app.
#[utoipa::path(
    delete,
    path = "/api/apps/{app}/roles/{role}",
    params(crate::actions::ActionQuery),
    responses(
        (status = 200, body = hlb_api::ActionResult),
        (status = 422, description = "Nothing could be planned: the body's `blockers` say why", body = hlb_api::ActionResult)
    ),
    extensions(
        ("x-hlb-requires" = json!("manage-accounts")),
        ("x-hlb-preview" = json!(true))
    )
)]
pub async fn deny_role(
    auth: Authorized<CanManageAccounts>,
    AxumState(s): AxumState<Arc<AppState>>,
    Path((app, id)): Path<(String, String)>,
    Query(q): Query<ActionQuery>,
) -> ActionReply {
    let mut blockers = Vec::new();
    let mut warnings = Vec::new();
    let allowed = s.state.app_roles().await.unwrap_or_default();
    let now_in = allowed.get(&app).cloned().unwrap_or_default();
    if !now_in.contains(&id) {
        blockers.push(format!("{app} does not let \"{id}\" in"));
    } else if now_in.len() == 1 {
        warnings.push(format!(
            "no other role is let into {app}: it closes for everyone"
        ));
    }
    let applied = q.apply && blockers.is_empty();
    let mut step = planned(format!("stop letting \"{id}\" into {app}"));
    if applied {
        let done = match s.state.deny_role(&app, &id).await {
            Ok(_) => republish(&s, &app).await,
            Err(e) => Err(e.to_string()),
        };
        apply_step(&mut step, done);
    }
    let r = result(
        format!("stop letting \"{id}\" into {app}"),
        if blockers.is_empty() {
            vec![step]
        } else {
            Vec::new()
        },
        format!("hlb role deny {id} {app} --apply"),
        blockers,
        warnings,
        applied,
    );
    answer(&s, auth.identity(), "role-deny", &format!("{app}/{id}"), r).await
}

/// A person's own quota in an app, over their role's — or their role's again.
#[utoipa::path(
    post,
    path = "/api/accounts/{account}/quota/{app}",
    params(crate::actions::ActionQuery),
    request_body = Option<PersonQuotaRequest>,
    responses(
        (status = 200, body = hlb_api::ActionResult),
        (status = 422, description = "Nothing could be planned: the body's `blockers` say why", body = hlb_api::ActionResult)
    ),
    extensions(
        ("x-hlb-requires" = json!("manage-accounts")),
        ("x-hlb-preview" = json!(true))
    )
)]
pub async fn person_quota(
    auth: Authorized<CanManageAccounts>,
    AxumState(s): AxumState<Arc<AppState>>,
    Path((account, app)): Path<(String, String)>,
    Query(q): Query<ActionQuery>,
    body: Option<Json<PersonQuotaRequest>>,
) -> ActionReply {
    let d = body.map(|Json(d)| d).unwrap_or_default();
    let mut blockers = Vec::new();
    if !s
        .state
        .users()
        .await
        .unwrap_or_default()
        .iter()
        .any(|(n, _, _)| n == &account)
    {
        blockers.push(format!("unknown account \"{account}\""));
    }
    blockers.extend(quota_app(&s, &app).await);
    if d.none && d.bytes.is_some() {
        blockers.push("a quota, or none at all — not both".into());
    }
    let (quota, said, cli) = match (d.none, d.bytes) {
        (false, None) => (
            None,
            "their role's".to_string(),
            format!("hlb user quota {account} {app} --role --apply"),
        ),
        (true, _) => (
            Some(None),
            "none at all".to_string(),
            format!("hlb user quota {account} {app} --none --apply"),
        ),
        (false, Some(bytes)) => (
            Some(Some(bytes)),
            human(bytes),
            format!(
                "hlb user quota {account} {app} --gib {} --apply",
                hlb_types::access::QuotaUnit::GiB.amount(bytes)
            ),
        ),
    };
    let applied = q.apply && blockers.is_empty();
    let mut step = planned(format!("{account} in {app}: quota {said}"));
    if applied {
        apply_step(
            &mut step,
            s.state
                .set_person_quota(&account, &app, quota, auth.actor().name())
                .await
                .map_err(|e| e.to_string()),
        );
    }
    let r = result(
        format!("{account}'s quota in {app}"),
        if blockers.is_empty() {
            vec![step]
        } else {
            Vec::new()
        },
        cli,
        blockers,
        Vec::new(),
        applied,
    );
    answer(
        &s,
        auth.identity(),
        "user-quota",
        &format!("{account}/{app}"),
        r,
    )
    .await
}

/// Runs the sync: what PocketID and the apps hold, made to match.
pub async fn sync(s: &AppState, apply: bool) -> Result<hlb_engine::roles::Report, String> {
    let (Some(orch), Some(install)) = (&s.orchestrator, &s.install) else {
        return Err("the controller has no vault or no Docker: `hlb role sync --apply` runs it from a manager".into());
    };
    let reach = |u: &str| u.to_string();
    RoleSync {
        state: &s.state,
        vault: &install.vault,
        orchestrator: orch.as_ref(),
        reach: &reach,
        now: crate::auth::now(),
    }
    .run(apply)
    .await
    .map_err(|e| e.to_string())
}

/// A sync now, in the background: an applied change reaches PocketID in seconds, not
/// at the loop's next pass.
pub fn sync_soon(s: Arc<AppState>) {
    if s.demo {
        return;
    }
    tokio::spawn(async move {
        match sync(&s, true).await {
            Ok(r) if r.failed() => tracing::error!(
                "role sync: {}",
                r.lines
                    .iter()
                    .filter_map(|l| match &l.outcome {
                        Outcome::Failed(e) => Some(format!("{} — {}: {e}", l.subject, l.change)),
                        _ => None,
                    })
                    .collect::<Vec<_>>()
                    .join(" · ")
            ),
            Ok(_) => {}
            Err(e) => tracing::warn!("role sync: {e}"),
        }
    });
}

/// The sync as an action: preview what would change, then apply it.
#[utoipa::path(
    post,
    path = "/api/access/sync",
    params(crate::actions::ActionQuery),
    responses(
        (status = 200, body = hlb_api::ActionResult),
        (status = 422, description = "Nothing could be planned: the body's `blockers` say why", body = hlb_api::ActionResult)
    ),
    extensions(
        ("x-hlb-requires" = json!("manage-accounts")),
        ("x-hlb-preview" = json!(true))
    )
)]
pub async fn sync_access(
    auth: Authorized<CanManageAccounts>,
    AxumState(s): AxumState<Arc<AppState>>,
    Query(q): Query<ActionQuery>,
) -> ActionReply {
    let (steps, blockers, warnings) = match sync(&s, q.apply).await {
        Err(e) => (Vec::new(), vec![e], Vec::new()),
        Ok(report) => (
            report
                .lines
                .iter()
                .map(|l| {
                    let (state, error) = match &l.outcome {
                        Outcome::ToDo => (StepState::Planned, None),
                        Outcome::Done => (StepState::Done, None),
                        // Not done, and not a failure: retried at the next pass.
                        Outcome::Waiting(why) => (StepState::Planned, Some(why.clone())),
                        // 🔴 Never `Done`: Homelabus could not do it.
                        Outcome::NotConfigured(why) => {
                            (StepState::Unimplemented, Some(why.clone()))
                        }
                        Outcome::Failed(why) => (StepState::Failed, Some(why.clone())),
                    };
                    ActionStep {
                        description: format!("{}: {}", l.subject, l.change),
                        state,
                        error,
                    }
                })
                .collect(),
            Vec::new(),
            report.notes,
        ),
    };
    let r = result(
        "make PocketID and the apps hold the roles".into(),
        steps,
        "hlb role sync --apply".into(),
        blockers,
        warnings,
        q.apply,
    );
    let outcome = if !r.applied {
        "preview"
    } else if r.succeeded() {
        "ok"
    } else {
        "failed"
    };
    let _ = s
        .state
        .audit(
            auth.actor().name(),
            auth.identity().role,
            "role-sync",
            "-",
            outcome,
            Some(&r.verdict()),
        )
        .await;
    if !r.blockers.is_empty() {
        return Err(ActionError::Unplannable(Box::new(r)));
    }
    Ok(Json(r))
}
