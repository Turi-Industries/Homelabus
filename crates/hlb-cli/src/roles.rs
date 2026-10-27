//! `hlb role`, and the two `hlb user` verbs that give a person a role or a quota.
//!
//! The rule is `hlb_users::access`; the writing `hlb_engine::roles`. Each change is
//! previewed first, and an applied one runs the sync at once: PocketID's groups and
//! the apps' restrictions are what really decide who enters, and leaving them to the
//! controller's next pass would leave someone removed in a hurry still inside.

use std::process::ExitCode;

use hlb_engine::roles::{human, Outcome, Report, RoleSync};
use hlb_orchestrator::{Orchestrator, SwarmOrchestrator};
use hlb_state::State;
use hlb_users::{MailLimits, RoleDef};

use crate::{open_state, open_vault, relay, Cli, RoleCmd, ACTOR_ROLE};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn gib(v: f64) -> Option<u64> {
    let b = (v * (1u64 << 30) as f64).round();
    (b >= 1.0 && b.is_finite()).then_some(b as u64)
}

/// Runs the sync and says what it found or did.
pub async fn sync(cli: &Cli, state: &State, apply: bool) -> Result<Report> {
    let vault = open_vault(cli)?;
    let orch = SwarmOrchestrator::connect().await?;
    let network = cli.platform_network.clone();
    let reach = move |u: &str| relay::reach(u, &network);
    let report = RoleSync {
        state,
        vault: &vault,
        orchestrator: &orch as &dyn Orchestrator,
        reach: &reach,
        now: crate::now(),
    }
    .run(apply)
    .await?;
    print(&report, apply);
    Ok(report)
}

fn print(r: &Report, apply: bool) {
    if r.lines.is_empty() {
        println!(
            "PocketID and the apps hold the roles ({} already as they should be).",
            r.unchanged
        );
    }
    for l in &r.lines {
        let (mark, why) = match &l.outcome {
            Outcome::ToDo => ("·", None),
            Outcome::Done => ("✓", None),
            Outcome::Waiting(w) => ("…", Some(w)),
            Outcome::NotConfigured(w) => ("⚠️", Some(w)),
            Outcome::Failed(w) => ("🔴", Some(w)),
        };
        println!("{mark} {}: {}", l.subject, l.change);
        if let Some(w) = why {
            println!("    {w}");
        }
    }
    for n in &r.notes {
        println!("⚠️  {n}");
    }
    if !apply && r.lines.iter().any(|l| l.outcome == Outcome::ToDo) {
        println!("\nRe-run with --apply to make it so.");
    }
}

/// After an applied change: the sync, at once — or why it did not run.
pub(crate) async fn follow(cli: &Cli, state: &State) {
    println!();
    if let Err(e) = sync(cli, state, true).await {
        println!("⚠️  PocketID and the apps are not told yet ({e}): the controller's next");
        println!("   pass does it, or `hlb role sync --apply` from a manager.");
    }
}

fn no_role(id: &str, roles: &[RoleDef]) -> String {
    format!(
        "no role \"{id}\" — {}",
        roles
            .iter()
            .map(|r| r.id.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    )
}

/// What giving this role opens: the ADMIN level, and every app it administers.
async fn say_openings(state: &State, role: &RoleDef) -> Result<()> {
    if role.level == hlb_types::Role::Admin {
        println!(
            "⚠️  \"{}\" is an ADMIN role: it grants rights and destroys data.",
            role.label()
        );
    }
    for o in hlb_engine::roles::opened_by(state, role).await? {
        println!("⚠️  It administers {}: {}", o.display_name, o.means);
    }
    Ok(())
}

pub async fn run(cli: &Cli, cmd: &RoleCmd) -> Result<ExitCode> {
    let state = open_state(cli).await?;
    match cmd {
        RoleCmd::List => list(&state).await,
        RoleCmd::Sync { apply } => {
            let r = sync(cli, &state, *apply).await?;
            if *apply {
                state
                    .audit(
                        "cli",
                        ACTOR_ROLE,
                        "role-sync",
                        "-",
                        if r.failed() { "failed" } else { "ok" },
                        None,
                    )
                    .await?;
            }
            Ok(if r.failed() {
                ExitCode::FAILURE
            } else {
                ExitCode::SUCCESS
            })
        }
        RoleCmd::Set {
            id,
            name,
            level,
            mailboxes,
            permanent_aliases,
            temporary_aliases,
            alias_days,
            mail_gib,
            apply,
        } => {
            if !hlb_types::access::valid_role_id(id) {
                eprintln!("\"{id}\": lowercase letters, digits and hyphens, up to 40 — it names a PocketID group, and never changes");
                return Ok(ExitCode::FAILURE);
            }
            let current = state.role(id).await?;
            let level = match level {
                Some(l) => match hlb_types::Role::parse(l) {
                    Some(l) => l,
                    None => {
                        eprintln!("unknown level \"{l}\" — user, viewer, operator, admin");
                        return Ok(ExitCode::FAILURE);
                    }
                },
                None => current.as_ref().map_or(hlb_types::Role::User, |r| r.level),
            };
            let mut role = current
                .clone()
                .unwrap_or_else(|| RoleDef::new(id, level, MailLimits::standard()));
            role.level = level;
            if let Some(n) = name {
                role.name = n.clone();
            }
            if !(2..=50).contains(&role.name.chars().count()) {
                eprintln!(
                    "\"{}\": a role's name is 2 to 50 characters — PocketID's limit for a group",
                    role.name
                );
                return Ok(ExitCode::FAILURE);
            }
            let m = &mut role.mail;
            if let Some(v) = mailboxes {
                m.max_mailboxes = *v;
            }
            if let Some(v) = permanent_aliases {
                m.max_permanent_aliases = *v;
            }
            if let Some(v) = temporary_aliases {
                m.max_temporary_aliases = *v;
            }
            if let Some(d) = alias_days {
                m.max_duration_s = d.saturating_mul(86_400);
            }
            if let Some(g) = mail_gib {
                m.quota_bytes = gib(*g);
            }
            // 🔴 The last administrators' role keeps its level: nobody could grant rights.
            if let Some(c) = &current {
                if c.level == hlb_types::Role::Admin && level != hlb_types::Role::Admin {
                    let holders = state.users_with_roles().await?;
                    let others = holders.iter().any(|h| {
                        h.level == hlb_types::Role::Admin && h.role.as_deref() != Some(id.as_str())
                    });
                    if !others
                        && holders
                            .iter()
                            .any(|h| h.role.as_deref() == Some(id.as_str()))
                    {
                        eprintln!("🔴 \"{id}\" holds every administrator: keep it admin, or give one of them another admin role first.");
                        return Ok(ExitCode::FAILURE);
                    }
                }
            }
            match &current {
                None => println!("Create \"{}\" ({id}), level {}.", role.name, level.as_str()),
                Some(c) => println!(
                    "\"{id}\": \"{}\" {} → \"{}\" {}.",
                    c.name,
                    c.level.as_str(),
                    role.name,
                    level.as_str()
                ),
            }
            if current.as_ref().is_none_or(|c| c.level < level) {
                say_openings(&state, &role).await?;
            }
            if !apply {
                println!("\nRe-run with --apply.");
                return Ok(ExitCode::SUCCESS);
            }
            state.put_role(&role, "cli").await?;
            state
                .audit("cli", ACTOR_ROLE, "role-set", id, "ok", None)
                .await?;
            println!("✓ role \"{id}\"");
            follow(cli, &state).await;
            Ok(ExitCode::SUCCESS)
        }
        RoleCmd::Delete { id, apply } => {
            if state.role(id).await?.is_none() {
                eprintln!("{}", no_role(id, &state.roles().await?));
                return Ok(ExitCode::FAILURE);
            }
            if let Some(why) = state.role_in_use(id, crate::now()).await? {
                eprintln!("🔴 \"{id}\" is {why}.");
                return Ok(ExitCode::FAILURE);
            }
            println!("Delete the role \"{id}\" and its PocketID group.");
            if !apply {
                println!("\nRe-run with --apply.");
                return Ok(ExitCode::SUCCESS);
            }
            state.delete_role(id).await?;
            state
                .audit("cli", ACTOR_ROLE, "role-delete", id, "ok", None)
                .await?;
            println!("✓ deleted");
            follow(cli, &state).await;
            Ok(ExitCode::SUCCESS)
        }
        RoleCmd::Allow { role, app, apply } => {
            let Some(r) = state.role(role).await? else {
                eprintln!("{}", no_role(role, &state.roles().await?));
                return Ok(ExitCode::FAILURE);
            };
            let Ok(m) = state.app_manifest(app).await else {
                eprintln!("{app} is not installed.");
                return Ok(ExitCode::FAILURE);
            };
            if let Some(why) = hlb_users::access::refusal(&r, &m) {
                eprintln!("🔴 {why}");
                return Ok(ExitCode::FAILURE);
            }
            println!("Let \"{}\" into {app}.", r.label());
            if let Some(a) = m.spec.access.as_ref().and_then(|a| a.admins.as_ref()) {
                if r.level >= a.level {
                    println!("⚠️  Whoever holds it administers {app}: {}", a.means);
                }
            }
            if !apply {
                println!("\nRe-run with --apply.");
                return Ok(ExitCode::SUCCESS);
            }
            state.allow_role(app, role, "cli").await?;
            state
                .audit(
                    "cli",
                    ACTOR_ROLE,
                    "role-allow",
                    &format!("{app}/{role}"),
                    "ok",
                    None,
                )
                .await?;
            println!("✓ {app} lets \"{role}\" in");
            republish(&state, cli, &m).await;
            follow(cli, &state).await;
            Ok(ExitCode::SUCCESS)
        }
        RoleCmd::Deny { role, app, apply } => {
            let allowed = state.app_roles().await?.remove(app).unwrap_or_default();
            if !allowed.contains(role) {
                eprintln!("{app} does not let \"{role}\" in.");
                return Ok(ExitCode::FAILURE);
            }
            println!("Stop letting \"{role}\" into {app}.");
            if allowed.len() == 1 {
                println!("⚠️  No other role is let in: {app} closes for everyone.");
            }
            if !apply {
                println!("\nRe-run with --apply.");
                return Ok(ExitCode::SUCCESS);
            }
            state.deny_role(app, role).await?;
            state
                .audit(
                    "cli",
                    ACTOR_ROLE,
                    "role-deny",
                    &format!("{app}/{role}"),
                    "ok",
                    None,
                )
                .await?;
            println!("✓ {app} no longer lets \"{role}\" in");
            if let Ok(m) = state.app_manifest(app).await {
                republish(&state, cli, &m).await;
            }
            follow(cli, &state).await;
            Ok(ExitCode::SUCCESS)
        }
        RoleCmd::Quota {
            role,
            app,
            gib: g,
            none,
            apply,
        } => {
            if state.role(role).await?.is_none() {
                eprintln!("{}", no_role(role, &state.roles().await?));
                return Ok(ExitCode::FAILURE);
            }
            if let Some(why) = takes_no_quota(&state, app).await {
                eprintln!("{why}");
                return Ok(ExitCode::FAILURE);
            }
            let bytes = match (g, none) {
                (Some(v), false) => match gib(*v) {
                    Some(b) => Some(b),
                    None => {
                        eprintln!("--gib {v}: a quota is more than nothing — --none for none");
                        return Ok(ExitCode::FAILURE);
                    }
                },
                (None, true) => None,
                _ => {
                    eprintln!("--gib <size>, or --none");
                    return Ok(ExitCode::FAILURE);
                }
            };
            println!(
                "\"{role}\" in {app}: quota {}.",
                bytes.map_or("none".to_string(), human)
            );
            if !apply {
                println!("\nRe-run with --apply.");
                return Ok(ExitCode::SUCCESS);
            }
            state.set_role_quota(role, app, bytes).await?;
            state
                .audit(
                    "cli",
                    ACTOR_ROLE,
                    "role-quota",
                    &format!("{role}/{app}"),
                    "ok",
                    None,
                )
                .await?;
            println!("✓ set");
            follow(cli, &state).await;
            Ok(ExitCode::SUCCESS)
        }
    }
}

async fn takes_no_quota(state: &State, app: &str) -> Option<String> {
    match state.app_manifest(app).await {
        Err(_) => Some(format!("{app} is not installed.")),
        Ok(m) if m.spec.access.as_ref().is_none_or(|a| a.quota.is_none()) => Some(format!(
            "{app} takes no quota from Homelabus — its manifest declares none."
        )),
        Ok(_) => None,
    }
}

/// An app behind the portal has its roles in the Caddyfile: published again.
async fn republish(state: &State, cli: &Cli, m: &hlb_types::Manifest) {
    if hlb_users::access::entry_of(m) != Some(hlb_users::access::Entry::Portal) {
        return;
    }
    let done = async {
        let vault = open_vault(cli)?;
        let orch = SwarmOrchestrator::connect().await?;
        hlb_engine::ingress::publish(&orch, state, Some(&vault)).await?;
        Ok::<_, Box<dyn std::error::Error>>(())
    }
    .await;
    match done {
        Ok(()) => println!("✓ the portal checks the new roles"),
        Err(e) => {
            println!("⚠️  the portal still checks the old roles ({e}) — `hlb ingress --apply`")
        }
    }
}

async fn list(state: &State) -> Result<ExitCode> {
    let inputs = hlb_engine::roles::Inputs::read(state).await?;
    let installed = inputs.installed();
    let desired = inputs.desired();
    for r in &inputs.roles {
        let holders: Vec<&str> = inputs
            .people
            .iter()
            .filter(|p| p.role.as_deref() == Some(r.id.as_str()))
            .map(|p| p.name.as_str())
            .collect();
        println!("{}  \"{}\"  {}", r.id, r.name, r.level.as_str());
        println!(
            "    held by: {}",
            if holders.is_empty() {
                "nobody".to_string()
            } else {
                holders.join(", ")
            }
        );
        let apps: Vec<&str> = installed
            .iter()
            .filter(|a| a.allowed.contains(&r.id))
            .map(|a| a.manifest.metadata.name.as_str())
            .collect();
        println!(
            "    enters: {}",
            if apps.is_empty() {
                "no app".to_string()
            } else {
                apps.join(", ")
            }
        );
        for (app, b) in &r.quotas {
            println!("    quota in {app}: {}", human(*b));
        }
        for o in hlb_users::access::opens(r, &installed) {
            println!("    administers {}: {}", o.display_name, o.means);
        }
        println!();
    }
    for (app, door) in &desired.doors {
        let floor = installed
            .iter()
            .find(|a| &a.manifest.metadata.name == app)
            .map(|a| hlb_users::access::floor_of(a.manifest))
            .unwrap_or_default();
        println!(
            "{app}: {}{}",
            if door.closed() {
                "CLOSED — no role is let in".to_string()
            } else {
                door.groups
                    .iter()
                    .map(|g| g.trim_start_matches("hlb-"))
                    .collect::<Vec<_>>()
                    .join(", ")
            },
            if floor > hlb_types::Role::User {
                format!("  (\"{}\" roles and above)", floor.as_str())
            } else {
                String::new()
            }
        );
    }
    for n in &desired.notes {
        println!("⚠️  {n}");
    }
    Ok(ExitCode::SUCCESS)
}

/// `hlb user role`.
pub async fn user_role(
    cli: &Cli,
    state: &State,
    name: &str,
    role: Option<&str>,
    apply: bool,
) -> Result<ExitCode> {
    // A role granted to a non-existent account would be an orphan row nobody re-reads:
    // an account created later under the same name would inherit it.
    if !state.users().await?.iter().any(|(n, _, _)| n == name) {
        eprintln!("unknown account \"{name}\" — \"hlb user list\" for the list");
        return Ok(ExitCode::FAILURE);
    }
    let current = state.role_of(name).await?;
    let Some(request) = role else {
        println!(
            "{name}: {} — level {}, {}",
            current.label(),
            current.level.as_str(),
            current.level.describe()
        );
        return Ok(ExitCode::SUCCESS);
    };
    let roles = state.roles().await?;
    let Some(r) = roles.iter().find(|r| r.id == request).cloned() else {
        eprintln!("{}", no_role(request, &roles));
        return Ok(ExitCode::FAILURE);
    };

    // 🔴 Demoting the last administrator would leave a system where nobody can grant
    // rights any more: it would only be repairable by editing SQLite by hand.
    if current.level == hlb_types::Role::Admin
        && r.level != hlb_types::Role::Admin
        && !state.has_other_admin(name).await?
    {
        eprintln!("🔴 {name} is the ONLY administrator. Demoting them would leave a system where nobody can grant rights any more.");
        eprintln!("   Appoint someone else first:  hlb user role <other> admin --apply");
        return Ok(ExitCode::FAILURE);
    }

    println!(
        "{name}: \"{}\" ({}) → \"{}\" ({})",
        current.label(),
        current.level.as_str(),
        r.label(),
        r.level.as_str()
    );
    if r.level > current.level {
        println!("⚠️  This is a privilege ELEVATION.");
    }
    if r.id != current.id {
        say_openings(state, &r).await?;
    }
    if !apply {
        println!("\nRe-run with --apply to apply it.");
        return Ok(ExitCode::SUCCESS);
    }
    state.set_user_role(name, &r.id, Some("cli")).await?;
    state
        .audit(
            "cli",
            ACTOR_ROLE,
            "user-role",
            name,
            "ok",
            Some(&format!("{} -> {}", current.label(), r.id)),
        )
        .await?;
    println!("✓ {name} → {}", r.label());
    follow(cli, state).await;
    Ok(ExitCode::SUCCESS)
}

/// `hlb user quota`.
#[allow(clippy::too_many_arguments)]
pub async fn user_quota(
    cli: &Cli,
    state: &State,
    name: &str,
    app: &str,
    g: Option<f64>,
    none: bool,
    role: bool,
    apply: bool,
) -> Result<ExitCode> {
    if !state.users().await?.iter().any(|(n, _, _)| n == name) {
        eprintln!("unknown account \"{name}\"");
        return Ok(ExitCode::FAILURE);
    }
    if let Some(why) = takes_no_quota(state, app).await {
        eprintln!("{why}");
        return Ok(ExitCode::FAILURE);
    }
    let (quota, said) = match (g, none, role) {
        (Some(v), false, false) => match gib(v) {
            Some(b) => (Some(Some(b)), human(b)),
            None => {
                eprintln!("--gib {v}: a quota is more than nothing — --none for none");
                return Ok(ExitCode::FAILURE);
            }
        },
        (None, true, false) => (Some(None), "none at all".to_string()),
        (None, false, true) => (None, "their role's".to_string()),
        _ => {
            eprintln!("--gib <size>, --none, or --role");
            return Ok(ExitCode::FAILURE);
        }
    };
    println!("{name} in {app}: quota {said}.");
    if !apply {
        println!("\nRe-run with --apply.");
        return Ok(ExitCode::SUCCESS);
    }
    state.set_person_quota(name, app, quota, "cli").await?;
    state
        .audit(
            "cli",
            ACTOR_ROLE,
            "user-quota",
            &format!("{name}/{app}"),
            "ok",
            Some(&said),
        )
        .await?;
    println!("✓ set");
    follow(cli, state).await;
    Ok(ExitCode::SUCCESS)
}
