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
        .state
        .audit(
            identity.actor.name(),
            identity.role,
            action,
            target,
            issue,
            Some(&r.verdict()),
        )
        .await;
    if r.applied {
        mirror(s, action, target).await;
    }

    Ok(Json(r))
}

/// What moves the desired state goes to the Git mirror at once: exported at startup
/// and after a reconciliation only, an install from the interface reached it at the
/// next restart — and the history screen, which reads the mirror, never showed it.
async fn mirror(s: &AppState, action: &str, target: &str) {
    if !matches!(action, "app-install" | "app-upgrade" | "app-remove") {
        return;
    }
    let Some(path) = &s.mirror else { return };
    if let Err(e) = crate::diff::export(path, &s.state, &format!("{action} {target}")).await {
        tracing::warn!("Git mirror not updated after {action} {target}: {e}");
    }
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
    let Some(cat) = &s.catalog else {
        // ⚠️ An empty list would read as "catalog with no applications". A missing
        // catalog is a configuration problem, not an empty catalog — and the screen
        // must be able to say so.
        return Json(Vec::new());
    };

    let installed: Vec<String> = s
        .state
        .installed_apps()
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|(n, _)| n)
        .collect();

    let mut out: Vec<hlb_api::CatalogItem> = cat
        .entries()
        .map(|e| {
            let m = &e.manifest;
            hlb_api::CatalogItem {
                installed: installed.contains(&m.metadata.name),
                icon: crate::api::catalog_icon_path(&s.catalog_dir, &m.metadata.name).is_some(),
                display_name: m
                    .metadata
                    .display_name
                    .clone()
                    .unwrap_or_else(|| m.metadata.name.clone()),
                name: m.metadata.name.clone(),
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
    let mut blockers = Vec::new();

    let Some(cat) = &s.catalog else {
        return action_error(
            &s,
            auth.identity(),
            "app-install",
            &app,
            "no catalog loaded — start the controller with --catalog <directory>",
        )
        .await;
    };

    let input = match cat.get(&app) {
        Ok(e) => e,
        Err(e) => {
            return action_error(&s, auth.identity(), "app-install", &app, &e.to_string()).await
        }
    };

    // A recorded app that is not running — a failed or interrupted install — resumes
    // here, as `hlb install` resumes it: refused, the interface had no way out of a
    // failed install, and sent people to an upgrade with nothing to apply.
    let recorded = s
        .state
        .installed_apps()
        .await
        .unwrap_or_default()
        .into_iter()
        .find(|(n, _)| n == &app)
        .map(|(_, status)| status);
    if recorded
        .as_deref()
        .is_some_and(|st| st != "failed" && st != "installing")
    {
        blockers.push(format!(
            "\"{app}\" is already installed — the catalog's changes reach it through \
             \"hlb upgrade {app}\", a new image through \"hlb update apply {app}\""
        ));
    }

    // 🔴 The storage check happens HERE, with the other blockers, not when the executor
    // reaches the volume. By then the manifest is frozen and the app is recorded: you
    // would be left with a half-installed app whose first action failed.
    if let Some(ctx) = &s.install {
        blockers.extend(ctx.storage.blockers_for(&input.manifest));
    }

    // An app with a route and no domain named takes `<app>.<domain>` once the exposure
    // is configured — as `hlb install` does. The mail domain follows the same way.
    let exposure = s.state.exposure().await.ok().flatten();
    let named = request.domain.clone().filter(|d| !d.trim().is_empty());
    let domain = match (&named, &exposure) {
        (Some(d), _) => Some(d.clone()),
        (None, Some(e)) if !input.manifest.spec.ingress.is_empty() => Some(e.default_domain(&app)),
        _ => None,
    };
    if input.manifest.spec.ingress.is_empty() {
        // Nothing to expose: a domain supplied would be ignored, better say so.
    } else if domain.is_none() {
        blockers.push(
            "this application exposes a service: a domain is required (\"domain\" \
             in the request body), or one for the installation with \"hlb config \
             exposure\""
                .to_string(),
        );
    }

    // The ingress refuses what would leave it unplaced, or serving names nobody chose.
    if let Some(o) = &s.orchestrator {
        blockers.extend(hlb_engine::ingress::app_blockers(o.as_ref(), &input.manifest).await);
        if input.manifest.metadata.name == hlb_types::manifest::INGRESS_SERVICE {
            blockers.extend(hlb_engine::ingress::blockers(o.as_ref(), &s.state).await);
        }
    }

    // An app recorded resumes from the manifest and the domains it was installed with.
    let mail_domain = request
        .mail_domain
        .clone()
        .or_else(|| exposure.as_ref().map(|e| e.domain.clone()));
    let basis = match hlb_engine::install::basis(
        &s.state,
        &app,
        &input.manifest,
        domain.clone(),
        mail_domain,
    )
    .await
    {
        Ok(Ok(b)) => Some(b),
        Ok(Err(refusal)) => {
            blockers.push(refusal);
            None
        }
        Err(e) => {
            return action_error(&s, auth.identity(), "app-install", &app, &e.to_string()).await
        }
    };
    let domain = basis.as_ref().and_then(|b| b.domain.clone()).or(domain);
    let params = hlb_resolver::InstallParams {
        domain: domain.clone(),
        mail_domain: basis.as_ref().and_then(|b| b.mail_domain.clone()),
        timezone: s.state.timezone().await.ok().flatten(),
        ..Default::default()
    };

    // ⚠️ We do NOT plan if a blocker is already known: the resolver would fail on the
    // same gap with a technical message ("domain parameter required"), and that message
    // would mask ours, which says what to do.
    let Some(basis) = basis.filter(|_| blockers.is_empty()) else {
        let r = ActionResult {
            applied: false,
            summary: format!("install {app} — impossible as things stand"),
            steps: Vec::new(),
            cli_command: format!("hlb install {app} --domain <domain> --apply"),
            blockers,
            warnings: Vec::new(),
            confirmation_required: None,
        };
        return respond(&s, auth.identity(), "app-install", &app, r).await;
    };

    // 🔴 The REAL plan, produced by the same resolver as the command line.
    let plan = match hlb_resolver::resolve_with_guide(&basis.manifest, &input.guide, &params) {
        Ok(p) => p,
        // Only the resolver knows which needs take a mailbox name: a list kept here
        // would miss the next one, and its error says nothing of what to do.
        Err(hlb_resolver::Error::MissingParam("mail_domain")) => {
            let r = ActionResult {
                applied: false,
                summary: format!("install {app} — impossible as things stand"),
                steps: Vec::new(),
                cli_command: format!("hlb install {app} --mail-domain <domain> --apply"),
                blockers: vec!["this application sends mail: a mail domain is required \
                     (\"mail_domain\" in the request body), or one for the installation \
                     with \"hlb config exposure\""
                    .to_string()],
                warnings: Vec::new(),
                confirmation_required: None,
            };
            return respond(&s, auth.identity(), "app-install", &app, r).await;
        }
        Err(e) => {
            return action_error(&s, auth.identity(), "app-install", &app, &e.to_string()).await
        }
    };

    // The blocking guides stop BEFORE any change: no point deploying an app whose DNS
    // does not exist. They come from the plan, so after it — and each is CHECKED first,
    // as the executor checks it: under a wildcard record "create the DNS record" is
    // already true, and counted unchecked it refused for good every app whose guide
    // starts with one.
    let blocking: Vec<String> = match hlb_engine::prerequisites(
        &s.state,
        s.install.as_ref().map(|c| &c.vault),
        &app,
        &plan,
        domain.as_deref(),
    )
    .await
    {
        Ok(found) => found
            .open
            .iter()
            .map(|a| format!("a manual action is required first: {a}"))
            .collect(),
        Err(e) => {
            return action_error(&s, auth.identity(), "app-install", &app, &e.to_string()).await
        }
    };

    let applied = q.apply && blocking.is_empty();

    let mut steps: Vec<ActionStep> = plan
        .actions
        .iter()
        .map(|a| ActionStep {
            description: a.to_string(),
            state: StepState::Planned,
            error: None,
        })
        .collect();

    if applied {
        match (&s.orchestrator, &s.install) {
            (Some(o), Some(ctx)) => {
                // The manifest is frozen NOW, and only once something can run it:
                // recorded with no orchestrator, the app was left "installing" with
                // nothing behind it. Same order as the CLI — recording before
                // executing is what makes the run resumable if it stops halfway.
                if let Err(e) = hlb_engine::install::record(&s.state, &app, &basis).await {
                    return action_error(&s, auth.identity(), "app-install", &app, &e.to_string())
                        .await;
                }
                let ex = platform_executor(&s, o.as_ref(), ctx);
                match ex.run(&app, &plan).await {
                    // 🔴 The steps come back from the EXECUTOR, not from the plan we
                    // previewed: an action recorded as unimplemented must show as such.
                    // Copying the plan and painting it green is exactly how
                    // "Unimplemented is never Done" gets broken.
                    // 🔴 The steps are read back from the JOURNAL, not from the plan
                    // we previewed. The executor records each action's real outcome —
                    // done, failed, unimplemented — and copying the plan and painting
                    // it green is exactly how "Unimplemented is never Done" gets
                    // broken. `Outcome` only carries counts; the journal carries which.
                    Ok(_) => steps = steps_from_journal(&s.state, &app, steps).await,
                    Err(e) => {
                        return action_error(
                            &s,
                            auth.identity(),
                            "app-install",
                            &app,
                            &e.to_string(),
                        )
                        .await
                    }
                }
            }
            _ => {
                for e in &mut steps {
                    e.state = StepState::Unimplemented;
                    e.error = Some(
                        "installing needs an orchestrator and a readable vault: check \
                         Docker and --master-key"
                            .into(),
                    );
                }
            }
        }
    }

    let command = match &named {
        Some(d) => format!("hlb install {app} --domain {d} --apply"),
        None => format!("hlb install {app} --apply"),
    };

    // 🔴 The capacity budget, BEFORE scheduling. An app placed on a tier with no
    // memory returns no clear error: the container is killed by the kernel and
    // `wait_healthy` times out, which sends you looking at the health probe.
    //
    // ⚠️ It is a WARNING, not a blocker: available memory moves, and refusing the
    // install on a measurement from thirty seconds ago would be wrong too
    // often than right.
    let tier = input
        .manifest
        .spec
        .swarm
        .tier
        .clone()
        .unwrap_or_else(|| "light".to_string());
    let fleet = fleet_per_tier(&s).await;
    let mut warnings: Vec<String> = crate::capacity::budget(&fleet, &tier)
        .needing(input.manifest.spec.swarm.memory)
        .warning()
        .into_iter()
        .collect();
    // A companion is placed on its own: Immich's model server is not split with it.
    for c in &input.manifest.spec.companions {
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

    let r = ActionResult {
        applied,
        summary: format!(
            "install {app} — {}",
            hlb_api::plural(plan.actions.len() as u64, "action", "actions")
        ),
        steps,
        cli_command: command,
        blockers: blocking,
        warnings,
        confirmation_required: None,
    };

    respond(&s, auth.identity(), "app-install", &app, r).await
}

/// The executor with every building block the controller holds, applying — one place
/// for installing and upgrading: two copies would drift, and the one used less would be
/// the one deploying without its database.
fn platform_executor<'a>(
    s: &'a AppState,
    o: &'a (dyn hlb_orchestrator::Orchestrator + 'a),
    ctx: &'a crate::api::InstallContext,
) -> hlb_engine::Executor<'a, dyn hlb_orchestrator::Orchestrator + 'a> {
    let mut ex = hlb_engine::Executor::new(o, &s.state)
        .with_vault(&ctx.vault)
        .with_registry(&ctx.registry)
        .with_storage(ctx.storage.clone())
        // The same bouncer as `hlb`'s: published without it here, an install from the
        // interface would undo what the command line had set up.
        .with_api(&ctx.api)
        .apply(true);
    if let Some(pg) = &ctx.postgres {
        ex = ex.with_postgres(pg);
    }
    if let Some(my) = &ctx.mariadb {
        ex = ex.with_mariadb(my);
    }
    if let Some(id) = &s.identity {
        ex = ex.with_identity(id);
    }
    if let Some(m) = &s.mail {
        ex = ex.with_mail(m);
    }
    ex
}

/// What the catalog has changed in an installed app, field by field. Empty when it
/// matches — and when no catalog is loaded, or the app left it: nothing to compare.
pub async fn catalog_changes(s: &AppState, app: &str) -> Vec<String> {
    let (Some(cat), Ok(frozen)) = (&s.catalog, s.state.app_manifest(app).await) else {
        return Vec::new();
    };
    let Ok(entry) = cat.get(app) else {
        return Vec::new();
    };
    hlb_engine::upgrade::changes(
        &frozen,
        &hlb_engine::upgrade::next(&frozen, &entry.manifest),
    )
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
    let Some(cat) = &s.catalog else {
        return action_error(
            &s,
            auth.identity(),
            "app-upgrade",
            &app,
            "no catalog loaded — start the controller with --catalog <directory>",
        )
        .await;
    };
    let frozen = match s.state.app_manifest(&app).await {
        Ok(m) => m,
        Err(_) => {
            let message = format!("\"{app}\" is not installed");
            return action_error(&s, auth.identity(), "app-upgrade", &app, &message).await;
        }
    };
    let input = match cat.get(&app) {
        Ok(e) => e,
        Err(e) => {
            return action_error(&s, auth.identity(), "app-upgrade", &app, &e.to_string()).await
        }
    };

    let next = hlb_engine::upgrade::next(&frozen, &input.manifest);
    let changes = hlb_engine::upgrade::changes(&frozen, &next);
    let mut blockers = hlb_engine::upgrade::refusals(&frozen, &next);
    // An upgrade that stopped after redeploying keeps the manifest it deployed: the
    // catalog matches it, and its plan still has to finish.
    let interrupted = hlb_engine::upgrade::interrupted(&s.state, &app)
        .await
        .unwrap_or(false);
    if changes.is_empty() && !interrupted {
        blockers.push(format!("\"{app}\" matches the catalog: nothing to apply"));
    }
    if let Some(ctx) = &s.install {
        blockers.extend(ctx.storage.blockers_for(&next));
    }
    // What an install refuses, an upgrade refuses too.
    if let Some(o) = &s.orchestrator {
        blockers.extend(hlb_engine::ingress::app_blockers(o.as_ref(), &next).await);
    }

    // The mail domain the install took, or an app sending mail cannot name its account.
    let mail_domain = match hlb_engine::install::mail_domain(&s.state, &app, None).await {
        Ok(d) => d,
        Err(e) => {
            return action_error(&s, auth.identity(), "app-upgrade", &app, &e.to_string()).await
        }
    };
    let params = hlb_resolver::InstallParams {
        domain: s.state.app_domain(&app).await.ok().flatten(),
        mail_domain,
        timezone: s.state.timezone().await.ok().flatten(),
        ..Default::default()
    };
    let plan = match hlb_resolver::resolve_with_guide(&next, &input.guide, &params) {
        Ok(p) => p,
        Err(e) => {
            return action_error(&s, auth.identity(), "app-upgrade", &app, &e.to_string()).await
        }
    };
    // From the STATE, not the plan: an installed app's steps were handled when it was
    // installed, and read from the plan they refused every upgrade for good. What is
    // still unacknowledged blocks — the executor refuses on the same reading.
    blockers.extend(
        s.state
            .pending_guides()
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|(a, _, _, blocking)| a == &app && *blocking)
            .map(|(_, id, title, _)| format!("a manual action is required first: {title} [{id}]")),
    );

    let applied = q.apply && blockers.is_empty();
    // What changes first, then the plan that applies it.
    let mut steps: Vec<ActionStep> = changes
        .iter()
        .map(|c| ActionStep {
            description: format!("catalog: {c}"),
            state: StepState::Planned,
            error: None,
        })
        .chain(plan.actions.iter().map(|a| ActionStep {
            description: a.to_string(),
            state: StepState::Planned,
            error: None,
        }))
        .collect();

    if applied {
        let status = s
            .state
            .installed_apps()
            .await
            .unwrap_or_default()
            .into_iter()
            .find(|(n, _)| n == &app)
            .map(|(_, st)| st)
            .unwrap_or_else(|| "running".to_string());
        // Frozen, then the whole plan again: its actions keep what exists, and a
        // deployment updates its service in place rather than being skipped as done.
        let frozen_now = s
            .state
            .upsert_app(&app, &next, params.domain.as_deref())
            .await;
        let reset = match frozen_now {
            Ok(()) => s.state.reset_plan(&app).await,
            Err(e) => Err(e),
        };
        if let Err(e) = reset {
            return action_error(&s, auth.identity(), "app-upgrade", &app, &e.to_string()).await;
        }
        for step in steps.iter_mut().take(changes.len()) {
            step.state = StepState::Done;
        }
        match (&s.orchestrator, &s.install) {
            (Some(o), Some(ctx)) => match platform_executor(&s, o.as_ref(), ctx)
                .run(&app, &plan)
                .await
            {
                Ok(_) => {
                    let planned = steps.split_off(changes.len());
                    steps.extend(steps_from_journal(&s.state, &app, planned).await);
                }
                Err(e) => {
                    let _ = hlb_engine::upgrade::settle(
                        &s.state,
                        &app,
                        &frozen,
                        &status,
                        params.domain.as_deref(),
                    )
                    .await;
                    return action_error(&s, auth.identity(), "app-upgrade", &app, &e.to_string())
                        .await;
                }
            },
            _ => {
                for e in steps.iter_mut().skip(changes.len()) {
                    e.state = StepState::Unimplemented;
                    e.error = Some(
                        "upgrading needs an orchestrator and a readable vault: check Docker \
                         and --master-key"
                            .into(),
                    );
                }
            }
        }
        // 🔴 The frozen manifest moves with what runs: back when nothing was
        // redeployed, kept when the new spec was — and the app keeps the status, so the
        // route, it had.
        match hlb_engine::upgrade::settle(
            &s.state,
            &app,
            &frozen,
            &status,
            params.domain.as_deref(),
        )
        .await
        {
            Ok(hlb_engine::upgrade::Settled::Reverted) => {
                for step in steps.iter_mut().take(changes.len()) {
                    step.state = StepState::Planned;
                }
            }
            Ok(
                hlb_engine::upgrade::Settled::Finished
                | hlb_engine::upgrade::Settled::Partial
                | hlb_engine::upgrade::Settled::Interrupted,
            ) => {}
            Err(e) => {
                return action_error(&s, auth.identity(), "app-upgrade", &app, &e.to_string()).await
            }
        }
    }

    let r = ActionResult {
        applied,
        summary: format!(
            "upgrade {app} — {}",
            hlb_api::plural(changes.len() as u64, "change", "changes")
        ),
        steps,
        cli_command: format!("hlb upgrade {app} --apply"),
        blockers,
        warnings: hlb_engine::upgrade::image_notes(&frozen, &input.manifest),
        confirmation_required: None,
    };
    respond(&s, auth.identity(), "app-upgrade", &app, r).await
}

/// An action that could not even be planned.
///
/// Logged as a failure: not knowing what to do is a result, and keeping quiet about it
/// would leave a screen with no explanation.
async fn action_error(
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
        .state
        .audit(
            identity.actor.name(),
            identity.role,
            action,
            target,
            "failed",
            Some(message),
        )
        .await;
    // A run that stopped halfway still froze its manifest: the mirror says so.
    mirror(s, action, target).await;
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
    let fallback = s.backup.as_ref().and_then(|b| b.fallback_repo());
    let mut blockers = Vec::new();
    let held = match s.state.backup_kinds(&app).await {
        Ok(k) => k,
        Err(_) => {
            blockers.push(format!("no installed app is called {app}"));
            Vec::new()
        }
    };
    let dests = hlb_backup_run::destinations_of_app(&s.state, &app, fallback)
        .await
        .unwrap_or_default();
    if blockers.is_empty() && held.is_empty() {
        blockers.push(format!(
            "{app} holds nothing to back up — no volume, database or SQLite file: no \
             copy is owed"
        ));
    } else if blockers.is_empty() && dests.is_empty() {
        blockers.push(
            "no destination configured — \"hlb backup dest add <name> --location \
             <path>\""
                .to_string(),
        );
    }

    let mut steps: Vec<ActionStep> = dests
        .iter()
        .map(|d| ActionStep {
            description: format!("back up {app} to \"{}\"", d.name),
            // 🔴 In preview, `Planned`. Never `Done`: that would be claiming to have
            // backed up.
            state: StepState::Planned,
            error: None,
        })
        .collect();

    let applied = q.apply && blockers.is_empty();
    if applied {
        steps = match &s.backup {
            // 🔴 What the pass did, one line per item and destination — the outcome it
            // recorded there. Nothing it did not report is shown done: a destination
            // it never reached keeps no green line.
            Some(b) => {
                let mut reported = Vec::new();
                let outcome = b
                    .back_up(&s.state, &app, &mut |e| reported.push(step_of(e)))
                    .await;
                if let Err(e) = outcome {
                    reported.push(ActionStep {
                        description: format!("back up {app}"),
                        state: StepState::Failed,
                        error: Some(e),
                    });
                }
                if reported.is_empty() {
                    reported.push(ActionStep {
                        description: format!("back up {app}"),
                        state: StepState::Failed,
                        error: Some(format!(
                            "the backup pass took nothing of {app} — a failed install is \
                             not backed up"
                        )),
                    });
                }
                reported
            }
            None => steps
                .into_iter()
                .map(|step| ActionStep {
                    state: StepState::Unimplemented,
                    error: Some("this controller runs no backup pass".into()),
                    ..step
                })
                .collect(),
        };
    }

    let r = ActionResult {
        applied,
        // 🔴 Same family as deleting with no volume: "to 0 destinations" reads as an
        // action that is going to go somewhere. The summary is the line you read FIRST
        // — it must say what will really happen, not recite a counter at zero.
        summary: match dests.len() {
            _ if held.is_empty() => format!("back up {app} — it holds nothing to back up"),
            0 => format!("back up {app} — no destination: nothing would go anywhere"),
            n => format!(
                "back up {app} to {}",
                hlb_api::plural(n as u64, "destination", "destinations")
            ),
        },
        steps,
        cli_command: format!("hlb backup run --app {app} --force"),
        blockers,
        warnings: Vec::new(),
        confirmation_required: None,
    };

    respond(&s, auth.identity(), "backup-run", &app, r).await
}

/// One event of a backup pass, as the step it is.
fn step_of(e: hlb_backup_run::Event) -> ActionStep {
    use hlb_backup_run::Event;
    match e {
        Event::Done {
            what,
            destination,
            snapshot,
        } => ActionStep {
            description: format!(
                "{what} → \"{destination}\" ({})",
                snapshot.chars().take(8).collect::<String>()
            ),
            state: StepState::Done,
            error: None,
        },
        Event::Failed {
            what,
            destination,
            error,
        } => ActionStep {
            description: match destination {
                Some(d) => format!("{what} → \"{d}\""),
                None => what,
            },
            state: StepState::Failed,
            error: Some(error),
        },
        // Deliberately not backed up: incomplete, never done and never a failure.
        Event::NotCovered { what, why } => ActionStep {
            description: what,
            state: StepState::Unimplemented,
            error: Some(why),
        },
    }
}

/// Rereads what the executor actually recorded for each action.
///
/// ⚠️ Falls back to the previewed steps if the journal cannot be read: showing the plan
/// is less wrong than showing nothing, and the caller already knows the run happened.
async fn steps_from_journal(
    state: &hlb_state::State,
    app: &str,
    previewed: Vec<ActionStep>,
) -> Vec<ActionStep> {
    let Ok(records) = state.plan_actions(app).await else {
        return previewed;
    };
    if records.is_empty() {
        return previewed;
    }
    records
        .into_iter()
        .map(|r| ActionStep {
            description: r.description,
            state: match r.status {
                hlb_state::ActionStatus::Done => StepState::Done,
                hlb_state::ActionStatus::Failed => StepState::Failed,
                hlb_state::ActionStatus::Unimplemented => StepState::Unimplemented,
                // Still pending after a run: the executor stopped before reaching it,
                // which happens on the first failure. `Planned` says "not attempted",
                // and that is the truth.
                hlb_state::ActionStatus::Pending => StepState::Planned,
            },
            error: r.error,
        })
        .collect()
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
    let force = body.is_some_and(|Json(b)| b.force);
    let exists = s
        .state
        .pending_guides()
        .await
        .unwrap_or_default()
        .into_iter()
        .any(|(a, i, ..)| a == app && i == id);

    let mut blockers = Vec::new();
    if !exists {
        blockers.push(format!(
            "no action \"{id}\" pending for {app} — already done, or wrong \
             identifier"
        ));
    }

    // The step's check, when the catalog has one: what the machine can see beats what
    // anyone attests.
    let check = s
        .catalog
        .as_ref()
        .and_then(|c| c.get(&app).ok())
        .and_then(|e| e.guide.steps.iter().find(|st| st.id == id).cloned());
    let mut observed = None;
    let mut overridden = false;
    if let (true, Some(step)) = (exists, check) {
        let domain = s
            .state
            .app_domain(&app)
            .await
            .ok()
            .flatten()
            .unwrap_or_default();
        let outcome = hlb_engine::guide_verifier(&s.state, s.install.as_ref().map(|c| &c.vault))
            .await
            .check(&step, &[("domain", domain.as_str())])
            .await;
        if outcome.is_verified() {
            observed = Some(outcome.describe());
        } else if !outcome.may_attest() && !force {
            blockers.push(format!(
                "the check says it is not done: {} — attest anyway with \"force\"",
                outcome.describe()
            ));
        } else if !outcome.may_attest() {
            overridden = true;
        }
    }

    let applied = q.apply && blockers.is_empty();
    let mut step = ActionStep {
        description: match &observed {
            Some(seen) => format!("record \"{id}\" for {app} as done — observed: {seen}"),
            None => format!("attest that \"{id}\" was done for {app}"),
        },
        state: StepState::Planned,
        error: None,
    };

    if applied {
        let handled = if overridden {
            s.state.force_guide(&app, &id).await
        } else {
            s.state.verify_guide(&app, &id).await
        };
        match handled {
            Ok(true) => {
                step.state = StepState::Done;
                // A handled step can open an `after-guide` route.
                if let Some(o) = &s.orchestrator {
                    let vault = s.install.as_ref().map(|c| &c.vault);
                    if let Err(e) = hlb_engine::ingress::publish(o.as_ref(), &s.state, vault).await
                    {
                        step.error =
                            Some(format!("handled, but the routes were not republished: {e}"));
                    }
                }
            }
            // ⚠️ `false` = nothing was updated. That is not a technical error, but it is
            // not a success either: showing it as done would suggest a non-existent
            // guide had been validated.
            Ok(false) => {
                step.state = StepState::Failed;
                step.error = Some(format!("no action \"{id}\" to attest for {app}"));
            }
            Err(e) => {
                step.state = StepState::Failed;
                step.error = Some(e.to_string());
            }
        }
    }

    let r = ActionResult {
        applied,
        // 🔴 The message says this is an ATTESTATION. Ticking without having done it
        // unblocks a deployment that will fail later, with an unrelated message.
        summary: format!("attest \"{id}\" for {app} — this is an attestation, not a checkbox"),
        steps: vec![step],
        cli_command: if force {
            format!("hlb ack {app}/{id} --force")
        } else {
            format!("hlb ack {app}/{id}")
        },
        blockers,
        warnings: Vec::new(),
        confirmation_required: None,
    };

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
    let mut blockers = Vec::new();

    let Some(target) = request.replicas else {
        blockers.push("replica count missing (\"replicas\" in the body)".to_string());
        let r = ActionResult {
            applied: false,
            summary: format!("resize {app}"),
            steps: Vec::new(),
            cli_command: format!("hlb scale {app} <n> --apply"),
            blockers,
            warnings: Vec::new(),
            confirmation_required: None,
        };
        return respond(&s, auth.identity(), "app-scale", &app, r).await;
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

    let current = match &s.orchestrator {
        Some(o) => o.status(&app).await.ok().map(|st| st.desired_replicas),
        None => None,
    };

    if current.is_none() {
        blockers.push(format!(
            "\"{app}\" is not deployed, or Docker is unreachable"
        ));
    }

    let applied = q.apply && blockers.is_empty();
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
        match &s.orchestrator {
            Some(o) => match o.scale(&app, target).await {
                Ok(()) => {
                    step.state = StepState::Done;
                    // Kept in the state, or reconciliation puts the manifest's count
                    // back within a minute. The manifest's own count gives it back.
                    if let Ok(m) = s.state.app_manifest(&app).await {
                        let decided = (target != m.spec.swarm.replicas).then_some(target);
                        if let Err(e) = s.state.set_app_replicas(&app, decided).await {
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

    let r = ActionResult {
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
    };

    respond(&s, auth.identity(), "app-scale", &app, r).await
}

// ---------------------------------------------------------------------------
// Destinations de backup
// ---------------------------------------------------------------------------

#[derive(Debug, Default, serde::Deserialize, utoipa::ToSchema)]
pub struct DestinationRequest {
    #[serde(default)]
    pub location: Option<String>,
    /// `critical`, `bulky`, or both separated by a comma.
    #[serde(default)]
    pub classes: Option<String>,
    /// 🔴 The NAME of the secret carrying the credentials, **never their value**.
    ///
    /// Passing it through would send "backup-dest-offsite" as the S3 access key, and the
    /// server would answer "invalid signature" — an error that points
    /// nowhere.
    #[serde(default)]
    pub credentials_secret: Option<String>,
}

/// Declares or updates a backup destination.
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

    let location = d.location.clone().unwrap_or_default();
    if location.trim().is_empty() {
        blockers.push(
            "location missing: a local path (/mnt/nas/restic) or an S3 URL \
             (s3:host/bucket)"
                .to_string(),
        );
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

    // ⚠️ An S3 destination with no credentials will be of no use, and the failure will
    // only show on the first backup — hours later.
    if location.starts_with("s3:") && d.credentials_secret.is_none() {
        blockers.push(
            "an S3 destination needs a credentials secret \
             (\"credentials_secret\") — without it, the first backup will fail on \
             \"invalid signature\""
                .to_string(),
        );
    }

    let applied = q.apply && blockers.is_empty();
    let mut step = ActionStep {
        description: format!("declare destination \"{name}\" to {location} [{classes}]"),
        state: StepState::Planned,
        error: None,
    };

    if applied {
        match s
            .state
            .upsert_destination(&name, &location, &classes, d.credentials_secret.as_deref())
            .await
        {
            Ok(()) => step.state = StepState::Done,
            Err(e) => {
                step.state = StepState::Failed;
                step.error = Some(e.to_string());
            }
        }
    }

    let r = ActionResult {
        applied,
        summary: format!("destination \"{name}\""),
        steps: vec![step],
        cli_command: format!(
            "hlb backup dest add {name} --location {location} --classes {classes}"
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
        (status = 422, description = "Nothing could be planned: the body's `blockers` say why", body = hlb_api::ActionResult)
    ),
    extensions(
        ("x-hlb-requires" = json!("operate")),
        ("x-hlb-preview" = json!(true))
    )
)]
pub async fn node_availability(
    auth: Authorized<CanOperate>,
    AxumState(s): AxumState<Arc<AppState>>,
    Path(id): Path<String>,
    Query(q): Query<ActionQuery>,
    body: Option<Json<NodeRequest>>,
) -> ActionReply {
    let d = body.map(|Json(d)| d).unwrap_or_default();
    let mut blockers = Vec::new();

    let mut warnings = Vec::new();
    let mut confirmation_required = None;

    let targeted = d.availability.clone().unwrap_or_default();
    if !matches!(targeted.as_str(), "active" | "pause" | "drain") {
        blockers.push("availability expected: \"active\", \"pause\" or \"drain\"".to_string());
    }

    // 🔴 Draining the LAST healthy node would empty the cluster: every app would stop,
    // and there would be nowhere left to place them. Swarm accepts it without
    // complaint — it is on us to refuse.
    if targeted == "drain" {
        if let Some(o) = &s.orchestrator {
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
                        if q.apply && d.confirmed.as_deref() != Some(id.as_str()) {
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

    let applied = q.apply && blockers.is_empty();
    let mut step = ActionStep {
        description: format!("move node {id} to \"{targeted}\""),
        state: StepState::Planned,
        error: None,
    };

    if applied {
        match &s.orchestrator {
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

    let r = ActionResult {
        applied,
        summary: format!("node {id} to \"{targeted}\""),
        steps: vec![step],
        cli_command: format!("docker node update --availability {targeted} {id}"),
        blockers,
        warnings,
        confirmation_required,
    };

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
        (status = 422, description = "Nothing could be planned: the body's `blockers` say why", body = hlb_api::ActionResult)
    ),
    extensions(
        ("x-hlb-requires" = json!("destroy")),
        ("x-hlb-preview" = json!(true))
    )
)]
pub async fn delete_app(
    auth: Authorized<CanDestroy>,
    AxumState(s): AxumState<Arc<AppState>>,
    Path(app): Path<String>,
    Query(q): Query<ActionQuery>,
    body: Option<Json<Confirmation>>,
) -> ActionReply {
    let installed = s
        .state
        .installed_apps()
        .await
        .unwrap_or_default()
        .into_iter()
        .any(|(n, _)| n == app);

    let mut blockers = Vec::new();
    if !installed {
        blockers.push(format!("\"{app}\" is not installed"));
    }

    let confirmed = body
        .map(|Json(c)| valid_confirmation(&c, &app))
        .unwrap_or(false);

    // ⚠️ The preview is always allowed: it is even the only way to know what the
    // deletion would take. It is the APPLICATION that requires the confirmation.
    if q.apply && !confirmed {
        blockers.push(format!(
            "confirmation missing — send back \"{{\"confirmed\": \"{app}\"}}\". Repeating \
             the name is what stops a purge typed on the wrong app"
        ));
    }

    let applied = q.apply && blockers.is_empty();

    let volumes = s.state.app_volumes(&app).await.unwrap_or_default();
    let mut steps = vec![ActionStep {
        description: format!("remove the {app} service from Swarm"),
        state: StepState::Planned,
        error: None,
    }];
    for (name, _, backup, _) in &volumes {
        steps.push(ActionStep {
            description: format!(
                "the volume \"{name}\" is KEPT{}",
                if *backup {
                    " (backed up)"
                } else {
                    " — and it is NOT backed up"
                }
            ),
            state: StepState::Planned,
            error: None,
        });
    }

    if applied {
        // 1. The Swarm service. First, because it is the only step that STOPS
        //    something: forgetting the app while it still runs would leave a service
        //    nobody manages any more, invisible to every screen.
        let manifest = s.state.app_manifest(&app).await;
        match (&s.orchestrator, manifest) {
            (Some(o), Ok(m)) => match hlb_engine::remove_services(o.as_ref(), &app, &m).await {
                Ok(_) => steps[0].state = StepState::Done,
                Err(e) => {
                    steps[0].state = StepState::Failed;
                    steps[0].error = Some(e.to_string());
                }
            },
            (Some(_), Err(e)) => {
                steps[0].state = StepState::Failed;
                steps[0].error = Some(format!("its manifest could not be read: {e}"));
            }
            (None, _) => {
                steps[0].state = StepState::Unimplemented;
                steps[0].error =
                    Some("no orchestrator: Docker unreachable, or demonstration mode".into());
            }
        }

        // 2. The volumes are KEPT — and the step says so, which is why it is `Done`
        //    and not skipped: "nothing was done to this volume" is the outcome we
        //    promised, and a step left `Planned` would read as unfinished work.
        for e in steps.iter_mut().skip(1) {
            e.state = StepState::Done;
        }

        // 3. Forget the app, only if the service really went away. Forgetting it after
        //    a failed removal would hide a running service from every screen, and the
        //    next reconciliation would call it an orphan it must not touch.
        if steps[0].state == StepState::Done {
            let mut e = ActionStep {
                description: format!("forget {app}: manifest, plan and guides"),
                state: StepState::Planned,
                error: None,
            };
            match s.state.forget_app(&app).await {
                Ok(()) => e.state = StepState::Done,
                Err(err) => {
                    e.state = StepState::Failed;
                    e.error = Some(err.to_string());
                }
            }
            steps.push(e);

            // 4. Its route goes with it: left in the Caddyfile it would answer 502 at
            //    its name, and the exposure screen would call it published.
            if let Some(o) = &s.orchestrator {
                let vault = s.install.as_ref().map(|c| &c.vault);
                if let Err(err) = hlb_engine::ingress::publish(o.as_ref(), &s.state, vault).await {
                    steps.push(ActionStep {
                        description: format!("withdraw {app}'s route"),
                        state: StepState::Failed,
                        error: Some(err.to_string()),
                    });
                }
            }
        }
    }

    let r = ActionResult {
        applied,
        // 🔴 Zero volumes is NOT "the data stays". Found at run time: "0 volume is
        // kept, the data stays" promises a survival with no object — and it is
        // precisely the sentence you read before confirming a
        // suppression.
        summary: match volumes.len() {
            0 => format!(
                "delete {app} — no volume declared: nothing will be left of this \
                 application"
            ),
            n => format!(
                "delete {app} — {} {} kept{}, the data stays",
                hlb_api::plural(n as u64, "volume", "volumes"),
                if n > 1 { "are" } else { "is" },
                if n > 1 { "s" } else { "" }
            ),
        },
        steps,
        cli_command: format!("hlb remove {app} --confirm {app} --apply"),
        blockers,
        warnings: Vec::new(),
        confirmation_required: Some(app.clone()),
    };

    respond(&s, auth.identity(), "app-remove", &app, r).await
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
    let account = auth.identity().actor.for_account().map(str::to_string);
    let mut blockers = Vec::new();
    // (mailbox local part, its domain), once we know the alias is eligible.
    let mut target: Option<(String, String)> = None;

    match &account {
        None => blockers.push("this request acts on nobody's behalf — sign in first".into()),
        Some(acct) => {
            let rows = s.state.aliases(acct).await.unwrap_or_default();
            match rows.into_iter().find(|(_, l, ..)| l == &local) {
                None => blockers.push(format!("no such alias: {local}")),
                // 🔴 Purge is for the expired-but-still-active bug case, not a general
                // "delete this alias" button: a permanent or still-valid alias is not
                // what it exists to fix, and the button must not become a second,
                // unlabelled way to delete one.
                Some((mailbox, _, expires_at, active, ..)) => {
                    let eligible =
                        active && matches!(expires_at, Some(e) if crate::auth::now() >= e);
                    // The alias lives at its MAILBOX's domain, which is not always the
                    // installation's: removed at the other one, nothing was removed.
                    let domain = s
                        .state
                        .mailboxes(acct)
                        .await
                        .unwrap_or_default()
                        .into_iter()
                        .find(|(l, ..)| l == &mailbox)
                        .map(|(_, d, _)| d);
                    if !eligible {
                        blockers.push("not expired-and-still-active: nothing to purge".into());
                    } else if let Some(domain) = domain {
                        target = Some((mailbox, domain));
                    } else {
                        blockers.push(format!(
                            "its mailbox \"{mailbox}\" is no longer yours — the alias \
                             cannot be found on the mail server from here"
                        ));
                    }
                }
            }
        }
    }

    if s.mail.is_none() {
        // 🔴 Refuse rather than record a purge that removed nothing: it would claim
        // the address is closed while it still receives, and nothing would say so.
        blockers.push(
            "Stalwart is not configured on this controller — refusing rather than \
             recording a removal that never happened"
                .into(),
        );
    }

    let applied = q.apply && blockers.is_empty();
    let domain = target
        .as_ref()
        .map_or(s.mail_domain.as_str(), |(_, d)| d.as_str());
    let address = format!("{local}@{domain}");
    let mut steps = vec![ActionStep {
        description: format!("remove {address} from Stalwart"),
        state: StepState::Planned,
        error: None,
    }];

    if applied {
        // Both present whenever `blockers` is empty: `target` only stays `None` when a
        // blocker was pushed alongside it.
        if let (Some(account), Some((mailbox, domain)), Some(mail)) = (&account, &target, &s.mail) {
            let mailbox_address = format!("{mailbox}@{domain}");
            match mail.remove_alias(&mailbox_address, &local).await {
                // Removed but not recorded is said: the screen would go on showing an
                // open door that is closed, and the next purge would try it again.
                Ok(_) => match s.state.deactivate_alias(account, &local).await {
                    Ok(_) => steps[0].state = StepState::Done,
                    Err(e) => {
                        steps[0].state = StepState::Failed;
                        steps[0].error = Some(format!(
                            "removed from Stalwart, but not recorded as removed: {e}"
                        ));
                    }
                },
                Err(e) => {
                    steps[0].state = StepState::Failed;
                    steps[0].error = Some(e.to_string());
                }
            }
        }
    }

    let r = ActionResult {
        applied,
        summary: format!("purge {address}: remove it from Stalwart for good, it stops receiving"),
        steps,
        cli_command: format!("hlb user alias purged --alias {local} --apply"),
        blockers,
        warnings: Vec::new(),
        confirmation_required: None,
    };

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
            match s
                .state
                .set_alias_folder(acct, &local, Some("Disabled"))
                .await
            {
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
    let nodes = match &s.orchestrator {
        Some(o) => o.nodes().await.unwrap_or_default(),
        // ⚠️ The demo has fabricated nodes, as for the topology: without them, every
        // install preview would carry a "no node on this tier" warning, and you would
        // never see the normal screen.
        None if s.demo => return crate::demo::fleet_per_tier(),
        // With no orchestrator we know NO tier. Returning an empty list makes you
        // conclude "no node on this tier", which is exactly what we know.
        None => return Vec::new(),
    };

    let poll = s.last_poll.read().await;
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
    let known = crate::openapi::routes()
        .iter()
        .any(|r| r.mutates() && r.verb == d.method && compatible_paths(&r.path, &d.path));

    if !known {
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
    if let Err(e) = s
        .state
        .save_named_plan(
            &d.name,
            &d.method,
            &d.path,
            &d.body,
            &d.summary,
            &actor,
            d.note.as_deref(),
        )
        .await
    {
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
                |(name, method, path, _body, summary, created_by, age_s)| hlb_api::NamedPlan {
                    name,
                    summary,
                    method,
                    path,
                    created_by,
                    age_s,
                },
            )
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn an_install_from_the_interface_reaches_the_git_mirror_at_once() {
        let st = std::sync::Arc::new(hlb_state::State::in_memory().await.expect("state"));
        let m: hlb_types::Manifest = serde_yaml_ng::from_str(
            "apiVersion: hlb/v1\nkind: App\nmetadata: { name: gitea }\n\
             spec:\n  image: { repo: a/b, tag: \"1\" }\n",
        )
        .expect("manifest");
        st.upsert_app("gitea", &m, None).await.expect("app");
        let dir = tempfile::tempdir().expect("dir");
        let mut s = crate::api::tests::base_state(st, true);
        s.mirror = Some(dir.path().to_path_buf());
        let who = crate::auth::Identity {
            role: hlb_types::Role::Admin,
            actor: crate::auth::Actor::Person {
                user: "lena".into(),
            },
        };
        let applied = |applied| hlb_api::ActionResult {
            applied,
            summary: "install gitea".into(),
            steps: Vec::new(),
            cli_command: String::new(),
            blockers: Vec::new(),
            warnings: Vec::new(),
            confirmation_required: None,
        };
        let versions = || {
            hlb_gitops::GitMirror::open_or_init(dir.path())
                .expect("mirror")
                .versions("gitea", 10)
                .expect("versions")
                .len()
        };

        let _ = super::respond(&s, &who, "app-install", "gitea", applied(false)).await;
        assert_eq!(versions(), 0, "a preview moved nothing");
        let _ = super::respond(&s, &who, "app-install", "gitea", applied(true)).await;
        assert_eq!(
            versions(),
            1,
            "the install waited for a restart to be mirrored"
        );
    }

    #[test]
    fn removing_an_app_without_volumes_promises_nothing() {
        // 🔴 Found by running the preview: "0 volume is kept, the data stays" promises
        // a survival with no object. It is the sentence you read just before confirming
        // a deletion — it must say what will really
        // happen.
        //
        // ⚠️ The summary is built in `delete_app`; we reproduce here the only rule
        // that matters, and a real call checks it end to end in
        // `every_mutating_route_previews_without_acting`.
        let phrase = |n: usize| match n {
            0 => "no volume declared: nothing will be left".to_string(),
            n => format!("{n} kept"),
        };
        assert!(phrase(0).contains("nothing will be left"));
        assert!(!phrase(0).contains("the data stays"));
        assert!(phrase(2).contains("kept"));
    }

    #[test]
    fn a_saved_plan_can_only_target_a_route_that_exists() {
        // 🔴 A plan targeting an unknown route would be accepted here and would fail at
        // execution, weeks later, on a 404 that points nowhere — at the precise moment
        // you were counting on it.
        let exists = |method: &str, path: &str| {
            crate::openapi::routes()
                .iter()
                .any(|r| r.mutates() && r.verb == method && compatible_paths(&r.path, path))
        };

        assert!(exists("POST", "/api/apps/gitea/install"));
        assert!(exists("POST", "/api/apps/immich/backup"));
        assert!(!exists("POST", "/api/apps/gitea/invent"));
        assert!(!exists("DELETE", "/api/apps/gitea/install"));
        // A read is not an action: replaying one would do nothing worth a name.
        assert!(!exists("GET", "/api/apps/gitea"));
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
