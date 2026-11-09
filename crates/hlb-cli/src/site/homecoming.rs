//! `hlb site return`: what the site wrote while it served, brought home.
//!
//! An app declares how (`spec.lifeboat.returns`); `whole` is the one way so far: its
//! databases and volumes, read off the site with its services stopped, replace the
//! house's. They go through the house's backups first (`kind:from-site`), so the
//! restores that put them back are the ones `hlb backup restore` runs — each backing up
//! what the house holds before replacing it — and the site's copy outlives the site.
//!
//! The order keeps one copy written at a time: the house's held stopped, the site's
//! stopped, everything read, everything restored, the house started and healthy, and
//! only then the door sent home. Anything failing before the door gives the site back
//! its apps: a rerun reads them again, unchanged.

use std::process::ExitCode;

use hlb_backup_run::lifeboat::{Brought, Server, Site as Target};
use hlb_backup_run::placement::Place;
use hlb_backup_run::restore::{self, Database, Failure, Restore};
use hlb_bootstrap::Runner;
use hlb_engine::lifeboat;
use hlb_orchestrator::{Orchestrator as _, SwarmOrchestrator};
use hlb_resolver::Action;
use hlb_secrets::Vault;
use hlb_state::State;
use hlb_types::manifest::Returns;
use hlb_types::DbEngine;

use crate::{open_state, open_vault, Cli, ACTOR_ROLE};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// How long a service brought home may take to be healthy.
const HEALTHY_WITHIN_SECS: u64 = 300;

/// How long a site service may take to stop.
const STOP_WITHIN: std::time::Duration = std::time::Duration::from_secs(120);

/// One app coming home.
struct Coming {
    app: String,
    /// Its PostgreSQL databases: `(name, extensions)`.
    databases: Vec<(String, Vec<String>)>,
    /// Its backed-up volumes, each with the image of the service mounting it — which
    /// the site holds — and where it lives at home.
    volumes: Vec<(String, String, Place)>,
    /// Its services and their replicas at home.
    services: Vec<(String, u64)>,
}

/// What `app` brings home, or why it cannot come.
async fn coming(
    state: &State,
    house: &SwarmOrchestrator,
    restore: &Restore<'_>,
    app: &str,
) -> std::result::Result<Coming, String> {
    let m = state.app_manifest(app).await.map_err(|e| e.to_string())?;
    // 🔴 Exhaustive: a way home added to `Returns` must decide what it reads here.
    match m.spec.lifeboat.as_ref().map(|l| l.returns) {
        Some(Returns::Whole) => {}
        None => {
            return Err(format!(
                "{app}'s manifest declares no way home (`spec.lifeboat.returns`)"
            ))
        }
    }
    let mut databases = Vec::new();
    for (engine, name, extensions) in restore::databases_of(&m, app) {
        match engine {
            DbEngine::Postgres => databases.push((name, extensions.to_vec())),
            DbEngine::Mariadb => return Err(format!("{app}'s MariaDB: the site runs none")),
        }
    }
    let backed_up: Vec<String> = state
        .volumes_to_backup(app)
        .await
        .map_err(|e| e.to_string())?
        .into_iter()
        .map(|(n, _)| n)
        .collect();
    let plan = lifeboat::plan_of(state, app)
        .await
        .map_err(|e| e.to_string())?;
    let mut volumes: Vec<(String, String, Place)> = Vec::new();
    let mut declared: Vec<(String, u64)> = Vec::new();
    for a in lifeboat::services(&plan) {
        let Action::DeployService {
            name,
            image,
            mounts,
            replicas,
            ..
        } = a
        else {
            continue;
        };
        declared.push((name.clone(), *replicas));
        for (vol, _) in mounts {
            if !backed_up.contains(vol) || volumes.iter().any(|(v, _, _)| v == vol) {
                continue;
            }
            // Located before anything stops: a stopped service on NFS runs nowhere.
            let place = restore
                .place_of(app, vol)
                .await
                .unwrap_or_else(Place::Unknown);
            if let Place::Unknown(why) = &place {
                return Err(format!("{vol}: {why}"));
            }
            volumes.push((vol.clone(), image.clone(), place));
        }
    }
    // 🔴 Never fewer than the plan declares: held stopped by the promotion, a service
    // reads 0 here, and given back 0 the door would go home to nothing.
    let running = restore::replicas(house, &hlb_engine::services_of(app, &m)).await;
    let services = running
        .into_iter()
        .map(|(s, r)| {
            let floor = declared
                .iter()
                .find(|(n, _)| *n == s)
                .map_or(0, |(_, d)| *d);
            (s, r.max(floor))
        })
        .collect();
    Ok(Coming {
        app: app.to_string(),
        databases,
        volumes,
        services,
    })
}

fn said(c: &Coming) -> String {
    let mut parts: Vec<String> = c
        .databases
        .iter()
        .map(|(d, _)| format!("database {d}"))
        .collect();
    parts.extend(c.volumes.iter().map(|(v, _, _)| format!("volume {v}")));
    if parts.is_empty() {
        "nothing it wrote is kept".into()
    } else {
        parts.join(", ")
    }
}

pub async fn run(cli: &Cli, apply: bool) -> Result<ExitCode> {
    let state = open_state(cli).await?;
    let vault = open_vault(cli)?;
    let Some(s) = super::load(&state, &vault).await? else {
        println!("The house has no site.  hlb site add <ssh-host> --apply");
        return Ok(ExitCode::SUCCESS);
    };
    let (tmp, ssh) = super::lifeboat::ssh_to(&state, &vault, &s).await?;
    let Some(since) = super::promote::since(&ssh).await? else {
        println!(
            "{} is not promoted: the house serves its apps already.",
            s.name
        );
        return Ok(ExitCode::SUCCESS);
    };
    let house = SwarmOrchestrator::connect().await?;
    let restore = Restore {
        state: &state,
        vault: &vault,
        fallback_repo: cli.backup_repo.as_deref(),
        network: &cli.platform_network,
        orchestrator: Some(&house),
    };
    let mut all = Vec::new();
    let mut refused = Vec::new();
    for app in super::lifeboat::apps(&state, &vault).await? {
        match coming(&state, &house, &restore, &app).await {
            Ok(c) => all.push(c),
            Err(why) => refused.push(why),
        }
    }
    println!("Bringing home what {} served since {since}:", s.name);
    for c in &all {
        println!("  {} — {}", c.app, said(c));
    }
    for why in &refused {
        eprintln!("  🔴 {why}");
    }
    let databases = all.iter().any(|c| !c.databases.is_empty());
    if databases && cli.postgres_admin.is_none() {
        refused.push("PostgreSQL's administrator is in no vault here (--postgres-admin)".into());
        eprintln!(
            "  🔴 {}",
            refused.last().map(String::as_str).unwrap_or_default()
        );
    }
    if !refused.is_empty() {
        eprintln!("\nNothing was changed: the site keeps serving.");
        return Ok(ExitCode::FAILURE);
    }

    if !apply {
        println!();
        println!("Would stop the house's own copies, and the site's; read each database and");
        println!("volume on the site into the house's backups (kind:from-site); restore each");
        println!("over the house's, what the house holds backed up first; start them at home");
        println!("until healthy; send their names home from the door; and take the site's");
        println!("Caddy and its certificates away.");
        println!("🔴 What the house's own copies wrote since the promotion is replaced: it");
        println!("   stays in the snapshot each restore takes first.");
        println!("Rerun with --apply.");
        return Ok(ExitCode::SUCCESS);
    }

    let socket = tmp.path().join("docker.sock");
    let _bridge = ssh.docker_socket(&socket).await?;
    let site = SwarmOrchestrator::connect_unix(&socket).await?;
    let scratch = tmp.path();
    let outcome = bring(
        cli, &state, &vault, &house, &restore, &site, &socket, scratch, &all,
    )
    .await;
    let door = match &outcome {
        Ok(_) => Some(send_home(&state, &vault, &ssh, &s).await),
        Err(e) => {
            eprintln!("\n🔴 {e}");
            back_to_site(&state, &house, &ssh, &all).await;
            None
        }
    };
    let (ok, detail) = match (&outcome, &door) {
        (Err(e), _) => (false, e.clone()),
        (Ok(lines), Some(Err(e))) => (false, format!("{}; the door: {e}", lines.join("; "))),
        (Ok(lines), _) => (true, lines.join("; ")),
    };
    state
        .audit(
            "cli",
            ACTOR_ROLE,
            "site-return",
            &s.name,
            if ok { "ok" } else { "failed" },
            Some(&detail),
        )
        .await?;
    if let Some(Err(e)) = door {
        eprintln!("\n🔴 Everything is home and started, but the door still sends their names to");
        eprintln!("   the site, where nothing serves them: {e}");
        eprintln!("   hlb site sync --apply");
        return Ok(ExitCode::FAILURE);
    }
    if !ok {
        return Ok(ExitCode::FAILURE);
    }
    println!("✓ the door sends every name home");
    // Left running for the dumps, it would serve a copy of each database read until the
    // nightly lifeboat, which leaves everything stopped. Not before the door: a return
    // failing there gives the site its apps back, PostgreSQL first.
    if all.iter().any(|c| !c.databases.is_empty()) {
        if let Err(e) = site.scale(lifeboat::POSTGRES, 0).await {
            eprintln!("⚠️  the site's PostgreSQL still runs ({e}): the next lifeboat stops it");
        }
    }
    // Its certificates' keys: none waits on the VPS for the next promotion.
    site.remove(hlb_ingress::front_door::SITE_CADDY).await.ok();
    for v in [lifeboat::CADDY_DATA, lifeboat::CADDY_CONFIG] {
        if let Err(e) = remove_volume(&site, v).await {
            eprintln!("⚠️  {v} stays on the site ({e}): the next lifeboat removes it");
        }
    }
    println!(
        "\n✓ {} brought home. The site's lifeboat is rebuilt by the next nightly run.",
        all.iter()
            .map(|c| c.app.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );
    Ok(ExitCode::SUCCESS)
}

/// The door sent home: the mark removed first, which the door reads to choose its file.
async fn send_home(
    state: &State,
    vault: &Vault,
    ssh: &hlb_bootstrap::SshRunner,
    s: &hlb_mesh::site::Site,
) -> std::result::Result<(), String> {
    let out = ssh
        .run(&["rm".into(), "-f".into(), lifeboat::PROMOTED_MARK.into()])
        .await
        .map_err(|e| e.to_string())?;
    if !out.ok() {
        return Err(format!(
            "{} kept: {}",
            lifeboat::PROMOTED_MARK,
            out.stderr.trim()
        ));
    }
    let names = super::lifeboat::names(state, vault)
        .await
        .map_err(|e| e.to_string())?;
    let own = super::watch::own_names(state)
        .await
        .map_err(|e| e.to_string())?;
    super::door::deploy(ssh, s, &names, &own).await?;
    // The page judges the private apps closed again, once the door says they are.
    let swap = super::watch::swap_to(hlb_engine::site_watch::GATUS_HOME);
    let out = ssh.run(&swap).await.map_err(|e| e.to_string())?;
    if !out.ok() {
        return Err(format!(
            "the status page still reads the site as serving: {}",
            out.stderr.trim()
        ));
    }
    Ok(())
}

/// Removes a volume once the service holding it is gone: its task takes a moment to stop.
async fn remove_volume(site: &SwarmOrchestrator, name: &str) -> std::result::Result<(), String> {
    let mut last = String::new();
    for _ in 0..30 {
        match site.remove_volume(name).await {
            Ok(()) => return Ok(()),
            Err(e) => last = e.to_string(),
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    Err(last)
}

/// Everything up to a house serving again: stopped on both sides, read, restored,
/// started and healthy. What it did, line by line.
#[allow(clippy::too_many_arguments)]
async fn bring(
    cli: &Cli,
    state: &State,
    vault: &Vault,
    house: &SwarmOrchestrator,
    restore: &Restore<'_>,
    site: &SwarmOrchestrator,
    socket: &std::path::Path,
    scratch: &std::path::Path,
    all: &[Coming],
) -> std::result::Result<Vec<String>, String> {
    let mut lines = Vec::new();
    let mut say = |line: String| {
        println!("  ✓ {line}");
        lines.push(line);
    };

    // The house's copies held, if the promotion did not: from here on one copy writes.
    for c in all {
        let at = match c.volumes.first() {
            Some((_, _, place)) => restore.node_of(place).await,
            None => None,
        };
        restore::stop_for_restore(
            house,
            state,
            &c.services,
            lifeboat::HOUSE_HOLD,
            at.as_deref(),
        )
        .await
        .map_err(|n| n.message().to_string())?;
        state
            .hold_services(&c.services, lifeboat::HOUSE_HOLD, lifeboat::HOUSE_HOLD_SECS)
            .await
            .map_err(|e| e.to_string())?;
    }
    say("the house's own copies stopped".into());

    // The site's apps stopped, its PostgreSQL left running for the dumps.
    for c in all {
        let m = state
            .app_manifest(&c.app)
            .await
            .map_err(|e| e.to_string())?;
        for svc in hlb_engine::services_of(&c.app, &m) {
            site.scale(&svc, 0)
                .await
                .map_err(|e| format!("stopping {svc} on the site: {e}"))?;
            if !hlb_orchestrator::wait_stopped(site, &svc, STOP_WITHIN)
                .await
                .map_err(|e| e.to_string())?
            {
                return Err(format!("{svc} still runs on the site"));
            }
        }
    }
    say("stopped on the site".into());

    let target = Target {
        docker: site,
        socket,
        network: lifeboat::NETWORK,
    };
    let admin = match state.secret(lifeboat::ADMIN_SECRET).await {
        Ok(Some(ct)) => Some(vault.decrypt(&ct).map_err(|e| e.to_string())?),
        Ok(None) => None,
        Err(e) => return Err(e.to_string()),
    };
    let pg_image = if all.iter().any(|c| !c.databases.is_empty()) {
        let plan = lifeboat::plan_of(state, lifeboat::POSTGRES)
            .await
            .map_err(|e| e.to_string())?;
        lifeboat::services(&plan).into_iter().find_map(|a| match a {
            Action::DeployService { image, .. } => Some(image.clone()),
            _ => None,
        })
    } else {
        None
    };

    // Read whole before anything at home is touched.
    let mut read: Vec<(Vec<Brought>, Vec<Brought>)> = Vec::new();
    for c in all {
        let mut dbs = Vec::new();
        for (name, extensions) in &c.databases {
            let (Some(image), Some(admin)) = (&pg_image, &admin) else {
                return Err("the site's PostgreSQL is unknown to the house".into());
            };
            let server = Server {
                image,
                admin_password: admin,
            };
            let db = Database {
                engine: DbEngine::Postgres,
                name,
                role: &c.app,
                extensions,
            };
            let b = restore
                .database_from_site(&c.app, &db, &target, &server)
                .await
                .map_err(|e| format!("{}'s database {name}: {e}", c.app))?;
            say(format!(
                "{name} read off the site ({} KB), snapshot {}",
                b.bytes / 1024,
                b.source.snapshot.short_id()
            ));
            dbs.push(b);
        }
        let mut vols = Vec::new();
        for (vol, image, _) in &c.volumes {
            let b = restore
                .volume_from_site(&c.app, vol, &target, image, scratch)
                .await
                .map_err(|e| format!("{}'s volume {vol}: {e}", c.app))?;
            say(format!(
                "{vol} read off the site ({} KB), snapshot {}",
                b.bytes / 1024,
                b.source.snapshot.short_id()
            ));
            vols.push(b);
        }
        read.push((dbs, vols));
    }

    // Restored over the house's, each backing up what it replaces.
    let admin_url = cli.postgres_admin.as_deref().unwrap_or_default();
    for (c, (dbs, vols)) in all.iter().zip(&read) {
        for ((name, extensions), b) in c.databases.iter().zip(dbs) {
            let db = Database {
                engine: DbEngine::Postgres,
                name,
                role: &c.app,
                extensions,
            };
            let before = restore
                .database_in_place(&c.app, &db, admin_url, &b.source)
                .await
                .map_err(|f| failed(&c.app, name, f))?;
            say(format!(
                "{name} restored at home; what it held is {}",
                short(&before)
            ));
        }
        for ((vol, _, place), b) in c.volumes.iter().zip(vols) {
            let before = restore
                .in_place(&c.app, vol, place, &b.source)
                .await
                .map_err(|f| failed(&c.app, vol, f))?;
            say(format!(
                "{vol} restored at home; what it held is {}",
                short(&before)
            ));
        }
    }

    for c in all {
        restore::start(house, state, &c.services).await?;
        for (svc, _) in &c.services {
            house
                .wait_healthy(svc, HEALTHY_WITHIN_SECS)
                .await
                .map_err(|e| format!("{svc} never became healthy at home: {e}"))?;
        }
        say(format!("{} healthy at home", c.app));
    }
    Ok(lines)
}

fn short(id: &str) -> &str {
    &id[..8.min(id.len())]
}

fn failed(app: &str, what: &str, f: Failure) -> String {
    match f {
        Failure::Refused(e) => format!("{app}'s {what} was not restored: {e}"),
        Failure::Interrupted { before, error } => format!(
            "{app}'s {what} stopped halfway ({error}); what the house held is snapshot {}",
            short(&before)
        ),
    }
}

/// A return that stopped before the door: the site serves again, the house's copies
/// stay held. Nothing at home has been given to anyone, so a rerun reads the site again.
async fn back_to_site(
    state: &State,
    house: &SwarmOrchestrator,
    ssh: &hlb_bootstrap::SshRunner,
    all: &[Coming],
) {
    // 🔴 The larger of the count read before and the one running now: a failure after
    // the house started released the promotion's hold, and held again at the 0 read
    // before, the next return would start them at 0 and send the door home to nothing.
    let before: Vec<(String, u64)> = all.iter().flat_map(|c| c.services.clone()).collect();
    let names: Vec<String> = before.iter().map(|(s, _)| s.clone()).collect();
    let now = restore::replicas(house, &names).await;
    let services: Vec<(String, u64)> = before
        .iter()
        .map(|(s, r)| {
            let running = now.iter().find(|(n, _)| n == s).map_or(0, |(_, r)| *r);
            (s.clone(), (*r).max(running))
        })
        .collect();
    if let Err(e) = restore::stop_held(
        house,
        state,
        &services,
        lifeboat::HOUSE_HOLD,
        lifeboat::HOUSE_HOLD_SECS,
    )
    .await
    {
        eprintln!("   ⚠️  the house's own copies could not be held stopped: {e}");
    }
    let served = ssh
        .run(&[lifeboat::PROMOTE_SCRIPT.into(), "--apply".into()])
        .await;
    match served {
        Ok(o) if o.ok() => {
            eprintln!("   The site serves them again; the house's copies stay stopped.");
            eprintln!("   Rerun `hlb site return --apply`: it reads the site again.");
        }
        Ok(o) => eprintln!(
            "   🔴 and the site did not start again: {}\n   {} --apply on the site",
            o.stderr.trim(),
            lifeboat::PROMOTE_SCRIPT
        ),
        Err(e) => eprintln!(
            "   🔴 and the site could not be reached to start again: {e}\n   {} --apply on the site",
            lifeboat::PROMOTE_SCRIPT
        ),
    }
}
