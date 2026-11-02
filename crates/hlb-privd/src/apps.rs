//! What installs, upgrades and removes an application, and attests its manual steps.
//!
//! Each is re-derived here from the catalog and the state: the web side names the app
//! and the domains a person chose, never a manifest, an image or a plan.

use hlb_api::intent::{Acted, AttestGuide, Install, Remove, Upgrade};
use hlb_api::{ActionResult, ActionStep, StepState};
use hlb_orchestrator::Orchestrator;

use crate::{InstallContext, Privd};

/// An app that is not installed, or not yet: what the catalog has, what the state
/// holds, and the plan the same resolver as the command line derives from them.
pub(crate) async fn install(p: &Privd, i: Install) -> Acted {
    let Install {
        app,
        domain: named,
        mail_domain,
        apply,
    } = i;
    let mut blockers = Vec::new();

    let Some(cat) = &p.catalog else {
        return Acted::Unplannable(
            "no catalog loaded — start the controller with --catalog <directory>".into(),
        );
    };

    let input = match cat.get(&app) {
        Ok(e) => e,
        Err(e) => return Acted::Unplannable(e.to_string()),
    };
    // `community/foo` installs as `foo`; the command line names it as asked.
    let asked = app;
    let app = input.manifest.metadata.name.clone();

    // A recorded app that is not running — a failed or interrupted install — resumes
    // here, as `hlb install` resumes it: refused, the interface had no way out of a
    // failed install, and sent people to an upgrade with nothing to apply.
    let recorded = p
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
    if let Some(ctx) = &p.install {
        blockers.extend(ctx.storage.blockers_for(&input.manifest));
    }

    // An app with a route and no domain named takes `<app>.<domain>` once the exposure
    // is configured — as `hlb install` does. The mail domain follows the same way.
    let exposure = p.state.exposure().await.ok().flatten();
    let named = named.filter(|d| !d.trim().is_empty());
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
    if let Some(o) = &p.orchestrator {
        blockers.extend(hlb_engine::ingress::app_blockers(o.as_ref(), &input.manifest).await);
        if input.manifest.metadata.name == hlb_types::manifest::INGRESS_SERVICE {
            blockers.extend(hlb_engine::ingress::blockers(o.as_ref(), &p.state).await);
        }
    }

    // An app recorded resumes from the manifest and the domains it was installed with.
    let mail_domain = mail_domain.or_else(|| exposure.as_ref().map(|e| e.domain.clone()));
    let basis = match hlb_engine::install::basis(
        &p.state,
        &app,
        hlb_engine::install::Origin {
            source: input.source.as_deref(),
            index: input.index,
        },
        &input.manifest,
        &input.guide,
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
        Err(e) => return Acted::Unplannable(e.to_string()),
    };
    let domain = basis.as_ref().and_then(|b| b.domain.clone()).or(domain);
    let params = hlb_resolver::InstallParams {
        domain: domain.clone(),
        mail_domain: basis.as_ref().and_then(|b| b.mail_domain.clone()),
        timezone: p.state.timezone().await.ok().flatten(),
        ..Default::default()
    };

    // ⚠️ We do NOT plan if a blocker is already known: the resolver would fail on the
    // same gap with a technical message ("domain parameter required"), and that message
    // would mask ours, which says what to do.
    let Some(basis) = basis.filter(|_| blockers.is_empty()) else {
        return Acted::Planned(ActionResult {
            applied: false,
            summary: format!("install {app} — impossible as things stand"),
            steps: Vec::new(),
            cli_command: format!("hlb install {asked} --domain <domain> --apply"),
            blockers,
            warnings: Vec::new(),
            confirmation_required: None,
        });
    };

    // 🔴 The REAL plan, produced by the same resolver as the command line.
    let plan = match hlb_resolver::resolve_with_guide(&basis.manifest, &basis.guide, &params) {
        Ok(p) => p,
        // Only the resolver knows which needs take a mailbox name: a list kept here
        // would miss the next one, and its error says nothing of what to do.
        Err(hlb_resolver::Error::MissingParam("mail_domain")) => {
            return Acted::Planned(ActionResult {
                applied: false,
                summary: format!("install {app} — impossible as things stand"),
                steps: Vec::new(),
                cli_command: format!("hlb install {asked} --mail-domain <domain> --apply"),
                blockers: vec!["this application sends mail: a mail domain is required \
                     (\"mail_domain\" in the request body), or one for the installation \
                     with \"hlb config exposure\""
                    .to_string()],
                warnings: Vec::new(),
                confirmation_required: None,
            });
        }
        Err(e) => return Acted::Unplannable(e.to_string()),
    };

    // The blocking guides stop BEFORE any change: no point deploying an app whose DNS
    // does not exist. They come from the plan, so after it — and each is CHECKED first,
    // as the executor checks it: under a wildcard record "create the DNS record" is
    // already true, and counted unchecked it refused for good every app whose guide
    // starts with one.
    let blocking: Vec<String> = match hlb_engine::prerequisites(
        &p.state,
        p.install.as_ref().map(|c| &c.vault),
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
        Err(e) => return Acted::Unplannable(e.to_string()),
    };

    let applied = apply && blocking.is_empty();

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
        match (&p.orchestrator, &p.install) {
            (Some(o), Some(ctx)) => {
                // The manifest is frozen NOW, and only once something can run it:
                // recorded with no orchestrator, the app was left "installing" with
                // nothing behind it. Same order as the CLI — recording before
                // executing is what makes the run resumable if it stops halfway.
                if let Err(e) = hlb_engine::install::record(&p.state, &app, &basis).await {
                    return Acted::Unplannable(e.to_string());
                }
                let ex = platform_executor(p, o.as_ref(), ctx);
                match ex.run(&app, &plan).await {
                    // 🔴 The steps are read back from the JOURNAL, not from the plan
                    // we previewed. The executor records each action's real outcome —
                    // done, failed, unimplemented — and copying the plan and painting
                    // it green is exactly how "Unimplemented is never Done" gets
                    // broken. `Outcome` only carries counts; the journal carries which.
                    Ok(_) => steps = steps_from_journal(&p.state, &app, steps).await,
                    Err(e) => return Acted::Unplannable(e.to_string()),
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
        Some(d) => format!("hlb install {asked} --domain {d} --apply"),
        None => format!("hlb install {asked} --apply"),
    };

    Acted::Planned(ActionResult {
        applied,
        summary: format!(
            "install {app} — {}",
            hlb_api::plural(plan.actions.len() as u64, "action", "actions")
        ),
        steps,
        cli_command: command,
        blockers: blocking,
        warnings: Vec::new(),
        confirmation_required: None,
    })
}

/// The executor with every building block this side holds, applying — one place for
/// installing and upgrading: two copies would drift, and the one used less would be
/// the one deploying without its database.
fn platform_executor<'a>(
    p: &'a Privd,
    o: &'a (dyn Orchestrator + 'a),
    ctx: &'a InstallContext,
) -> hlb_engine::Executor<'a, dyn Orchestrator + 'a> {
    let mut ex = hlb_engine::Executor::new(o, &p.state)
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
    if let Some(id) = &p.identity {
        ex = ex.with_identity(id);
    }
    if let Some(m) = &p.mail {
        ex = ex.with_mail(m);
    }
    ex
}

/// What the catalog has changed in an installed app, field by field. Empty when it
/// matches — and when no catalog is loaded, or the app left it: nothing to compare.
pub(crate) async fn catalog_changes(p: &Privd, app: &str) -> Vec<String> {
    let (Some(cat), Ok(frozen)) = (&p.catalog, p.state.app_manifest(app).await) else {
        return Vec::new();
    };
    let source = p.state.app_source(app).await.ok().flatten();
    let Ok(entry) = cat.followed(app, source.as_deref()) else {
        return Vec::new();
    };
    let guide = p.state.app_guide(app).await.ok().flatten();
    let mut changes = hlb_engine::upgrade::changes(
        &frozen,
        &hlb_engine::upgrade::next(&frozen, &entry.manifest),
    );
    changes.extend(hlb_engine::upgrade::guide_changes(
        guide.as_ref(),
        &entry.guide,
    ));
    changes
}

/// Brings an installed app to its catalog manifest; what would strand data is refused
/// before anything changes, by `hlb_engine::upgrade`'s decisions.
pub(crate) async fn upgrade(p: &Privd, i: Upgrade) -> Acted {
    let Upgrade { app, apply } = i;
    let Some(cat) = &p.catalog else {
        return Acted::Unplannable(
            "no catalog loaded — start the controller with --catalog <directory>".into(),
        );
    };
    let Ok(frozen) = p.state.app_manifest(&app).await else {
        return Acted::Unplannable(format!("\"{app}\" is not installed"));
    };
    let source = p.state.app_source(&app).await.ok().flatten();
    let input = match cat.followed(&app, source.as_deref()) {
        Ok(e) => e,
        Err(e) => return Acted::Unplannable(e.to_string()),
    };

    let frozen_guide = match p.state.app_guide(&app).await {
        Ok(g) => g,
        Err(e) => return Acted::Unplannable(e.to_string()),
    };
    let next = hlb_engine::upgrade::next(&frozen, &input.manifest);
    let mut changes = hlb_engine::upgrade::changes(&frozen, &next);
    changes.extend(hlb_engine::upgrade::guide_changes(
        frozen_guide.as_ref(),
        &input.guide,
    ));
    let mut blockers = hlb_engine::upgrade::refusals(&frozen, &next);
    // An upgrade that stopped after redeploying keeps the manifest it deployed: the
    // catalog matches it, and its plan still has to finish.
    let interrupted = hlb_engine::upgrade::interrupted(&p.state, &app)
        .await
        .unwrap_or(false);
    if changes.is_empty() && !interrupted {
        blockers.push(format!("\"{app}\" matches the catalog: nothing to apply"));
    }
    if let Some(ctx) = &p.install {
        blockers.extend(ctx.storage.blockers_for(&next));
    }
    // What an install refuses, an upgrade refuses too.
    if let Some(o) = &p.orchestrator {
        blockers.extend(hlb_engine::ingress::app_blockers(o.as_ref(), &next).await);
    }

    // The mail domain the install took, or an app sending mail cannot name its account.
    let mail_domain = match hlb_engine::install::mail_domain(&p.state, &app, None).await {
        Ok(d) => d,
        Err(e) => return Acted::Unplannable(e.to_string()),
    };
    let params = hlb_resolver::InstallParams {
        domain: p.state.app_domain(&app).await.ok().flatten(),
        mail_domain,
        timezone: p.state.timezone().await.ok().flatten(),
        ..Default::default()
    };
    let plan = match hlb_resolver::resolve_with_guide(&next, &input.guide, &params) {
        Ok(p) => p,
        Err(e) => return Acted::Unplannable(e.to_string()),
    };
    // From the STATE, not the plan: an installed app's steps were handled when it was
    // installed, and read from the plan they refused every upgrade for good. What is
    // still unacknowledged blocks — the executor refuses on the same reading.
    blockers.extend(
        p.state
            .pending_guides()
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|(a, _, _, blocking)| a == &app && *blocking)
            .map(|(_, id, title, _)| format!("a manual action is required first: {title} [{id}]")),
    );

    let applied = apply && blockers.is_empty();
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
        let status = p
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
        let frozen_now = match p
            .state
            .upsert_app(&app, &next, params.domain.as_deref())
            .await
        {
            Ok(()) => p.state.set_app_guide(&app, Some(&input.guide)).await,
            Err(e) => Err(e),
        };
        let reset = match frozen_now {
            Ok(()) => p.state.reset_plan(&app).await,
            Err(e) => Err(e),
        };
        if let Err(e) = reset {
            return Acted::Unplannable(e.to_string());
        }
        for step in steps.iter_mut().take(changes.len()) {
            step.state = StepState::Done;
        }
        match (&p.orchestrator, &p.install) {
            (Some(o), Some(ctx)) => {
                match platform_executor(p, o.as_ref(), ctx).run(&app, &plan).await {
                    Ok(_) => {
                        let planned = steps.split_off(changes.len());
                        steps.extend(steps_from_journal(&p.state, &app, planned).await);
                    }
                    Err(e) => {
                        let _ = hlb_engine::upgrade::settle(
                            &p.state,
                            &app,
                            &frozen,
                            frozen_guide.as_ref(),
                            &status,
                            params.domain.as_deref(),
                        )
                        .await;
                        return Acted::Unplannable(e.to_string());
                    }
                }
            }
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
            &p.state,
            &app,
            &frozen,
            frozen_guide.as_ref(),
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
            Err(e) => return Acted::Unplannable(e.to_string()),
        }
    }

    Acted::Planned(ActionResult {
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
    })
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

/// Attests a manual step, checked FIRST as `hlb ack` checks it: proven done, it is
/// recorded as observed; proven NOT done, refused unless forced.
pub(crate) async fn attest_guide(p: &Privd, i: AttestGuide) -> ActionResult {
    let AttestGuide {
        app,
        id,
        force,
        apply,
    } = i;
    let exists = p
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

    // The step's check, when the app's guide has one: what the machine can see beats
    // what anyone attests.
    let guide = hlb_engine::install::installed_guide(&p.state, &app, || {
        p.catalog
            .as_ref()
            .and_then(|c| c.get(&app).ok())
            .map(|e| e.guide.clone())
    })
    .await;
    let check = match guide {
        Ok(g) => g.steps.into_iter().find(|st| st.id == id),
        Err(e) => {
            blockers.push(format!("{app}'s guide could not be read: {e}"));
            None
        }
    };
    let mut observed = None;
    let mut overridden = false;
    if let (true, Some(step)) = (exists, check) {
        let domain = p
            .state
            .app_domain(&app)
            .await
            .ok()
            .flatten()
            .unwrap_or_default();
        let outcome = hlb_engine::guide_verifier(&p.state, p.install.as_ref().map(|c| &c.vault))
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

    let applied = apply && blockers.is_empty();
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
            p.state.force_guide(&app, &id).await
        } else {
            p.state.verify_guide(&app, &id).await
        };
        match handled {
            Ok(true) => {
                step.state = StepState::Done;
                // A handled step can open an `after-guide` route.
                if let Err(e) = p.republish().await {
                    step.error = Some(format!("handled, but the routes were not republished: {e}"));
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

    ActionResult {
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
    }
}

/// Removes an application's services and forgets it; its volumes are kept.
///
/// 🔴 The named confirmation is checked HERE: the web side vouches for who asks, not
/// for what they confirmed.
pub(crate) async fn remove(p: &Privd, i: Remove) -> ActionResult {
    let Remove {
        app,
        confirmed,
        apply,
    } = i;
    let installed = p
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

    // ⚠️ Compared exactly, with no normalisation: accepting "Gitea" for "gitea" would
    // weaken the only protection left once the role has already been granted. And
    // the preview is always allowed: it is the only way to know what the deletion
    // would take. It is the APPLICATION that requires the confirmation.
    if apply && confirmed.as_deref() != Some(app.as_str()) {
        blockers.push(format!(
            "confirmation missing — send back \"{{\"confirmed\": \"{app}\"}}\". Repeating \
             the name is what stops a purge typed on the wrong app"
        ));
    }

    let applied = apply && blockers.is_empty();

    let volumes = p.state.app_volumes(&app).await.unwrap_or_default();
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
        let manifest = p.state.app_manifest(&app).await;
        match (&p.orchestrator, manifest) {
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
            match p.state.forget_app(&app).await {
                Ok(()) => e.state = StepState::Done,
                Err(err) => {
                    e.state = StepState::Failed;
                    e.error = Some(err.to_string());
                }
            }
            steps.push(e);

            // 4. Its route goes with it: left in the Caddyfile it would answer 502 at
            //    its name, and the exposure screen would call it published.
            if let Err(err) = p.republish().await {
                steps.push(ActionStep {
                    description: format!("withdraw {app}'s route"),
                    state: StepState::Failed,
                    error: Some(err),
                });
            }
        }
    }

    ActionResult {
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
    }
}
