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

use hlb_backup::wal_ship;
use hlb_backup_run::lifeboat::{Brought, Reader, Server, Site as Target};
use hlb_backup_run::placement::Place;
use hlb_backup_run::restore::{self, Database, Failure, Restore};
use hlb_bootstrap::Runner;
use hlb_engine::lifeboat;
use hlb_orchestrator::{Orchestrator as _, SwarmOrchestrator};
use hlb_resolver::Action;
use hlb_secrets::Vault;
use hlb_state::State;
use hlb_types::manifest::Returns;
use hlb_types::{DbEngine, DbServer, VITAL_POSTGRES};

use crate::{open_state, open_vault, Cli, ACTOR_ROLE};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// How long a service brought home may take to be healthy.
const HEALTHY_WITHIN_SECS: u64 = 300;

/// How long a site service may take to stop.
const STOP_WITHIN: std::time::Duration = std::time::Duration::from_secs(120);

/// One PostgreSQL database coming home.
struct ComingDb {
    name: String,
    extensions: Vec<String>,
    /// Where it lives at home, and so on the site: the shared server's restored there
    /// by dump, the vital one's the standby the promotion made the server.
    server: DbServer,
    /// The app's role, and the vault entry of its password: what reads it off the
    /// vital server, whose administrator never went to the site.
    role: String,
    password_secret: String,
}

/// One app coming home.
struct Coming {
    app: String,
    databases: Vec<ComingDb>,
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
    let plan = lifeboat::plan_of(state, app)
        .await
        .map_err(|e| e.to_string())?;
    let mut databases = Vec::new();
    for (engine, name, extensions) in restore::databases_of(&m, app) {
        match engine {
            DbEngine::Postgres => {}
            DbEngine::Mariadb => return Err(format!("{app}'s MariaDB: the site runs none")),
        }
        let server = state
            .database_server(app, &name)
            .await
            .map_err(|e| e.to_string())?
            .unwrap_or(DbServer::Postgres);
        let (role, password_secret) = plan
            .actions
            .iter()
            .find_map(|a| match a {
                Action::ProvisionDatabase {
                    database,
                    role,
                    password_secret,
                    ..
                } if *database == name => Some((role.clone(), password_secret.clone())),
                _ => None,
            })
            .ok_or_else(|| format!("{app}'s database {name} is provisioned by no plan"))?;
        databases.push(ComingDb {
            name,
            extensions: extensions.to_vec(),
            server,
            role,
            password_secret,
        });
    }
    let backed_up: Vec<String> = state
        .volumes_to_backup(app)
        .await
        .map_err(|e| e.to_string())?
        .into_iter()
        .map(|(n, _)| n)
        .collect();
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
        .map(|d| format!("database {}", d.name))
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
    // Each into the server it lives on at home: a vital app's, the vital one.
    for c in &all {
        for d in &c.databases {
            if let Err(none) = cli
                .admin_of(&state, &c.app, &d.name, DbEngine::Postgres)
                .await?
            {
                if !refused.contains(&none) {
                    eprintln!("  🔴 {none}");
                    refused.push(none);
                }
            }
        }
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
        println!("Caddy and its certificates away. The pushers of the vital SQLite databases");
        println!("and volumes are stopped first, what they pushed to the site emptied once");
        println!("home, and each pusher started again.");
        println!("🔴 What the house's own copies wrote since the promotion is replaced: it");
        println!("   stays in the snapshot each restore takes first.");
        println!("Rerun with --apply.");
        return Ok(ExitCode::SUCCESS);
    }

    let socket = tmp.path().join("docker.sock");
    let _bridge = ssh.docker_socket(&socket).await?;
    let site = SwarmOrchestrator::connect_unix(&socket).await?;
    let scratch = tmp.path();
    // Stopped first: a pusher running would push the house's database as it is
    // replaced. Left stopped if the return fails, the site serving again.
    super::litestream::stop(&state, &vault, &house).await?;
    super::volumes::stop(&state, &vault, &house).await?;
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
    super::litestream::resume(&state, &vault, &ssh, &house).await;
    super::volumes::resume(&state, &vault, &ssh, &house).await;
    // Left running for the dumps, it would serve a copy of each database read until the
    // nightly lifeboat, which leaves everything stopped. Not before the door: a return
    // failing there gives the site its apps back, PostgreSQL first.
    // The vital server's promoted standby too: it has left the house's timeline, and
    // the next lifeboat seeds another.
    for server in [DbServer::Postgres, DbServer::PostgresVital] {
        if !all
            .iter()
            .any(|c| c.databases.iter().any(|d| d.server == server))
        {
            continue;
        }
        let name = server.service_name();
        if let Err(e) = site.scale(name, 0).await {
            eprintln!("⚠️  the site's {name} still runs ({e}): the next lifeboat stops it");
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
    let on = |server: DbServer| {
        all.iter()
            .any(|c| c.databases.iter().any(|d| d.server == server))
    };
    let pg_image = if on(DbServer::Postgres) {
        image_of(state, lifeboat::POSTGRES).await?
    } else {
        None
    };
    let vital_image = if on(DbServer::PostgresVital) {
        // What the house wrote that never reached the site, said before it is replaced.
        say(written_past(house, site).await);
        image_of(state, VITAL_POSTGRES).await?
    } else {
        None
    };

    // Read whole before anything at home is touched.
    let mut read: Vec<(Vec<Brought>, Vec<Brought>)> = Vec::new();
    for c in all {
        let mut dbs = Vec::new();
        for d in &c.databases {
            let name = &d.name;
            let role_password;
            let reader = match d.server {
                DbServer::PostgresVital => {
                    let Some(image) = &vital_image else {
                        return Err(format!("{VITAL_POSTGRES}'s image is unknown to the house"));
                    };
                    role_password = match state.secret(&d.password_secret).await {
                        Ok(Some(ct)) => vault.decrypt(&ct).map_err(|e| e.to_string())?,
                        Ok(None) => {
                            return Err(format!("{}: no {} in the vault", c.app, d.password_secret))
                        }
                        Err(e) => return Err(e.to_string()),
                    };
                    Reader {
                        image,
                        host: VITAL_POSTGRES,
                        user: &d.role,
                        password: &role_password,
                    }
                }
                DbServer::Postgres | DbServer::Mariadb => {
                    let (Some(image), Some(admin)) = (&pg_image, &admin) else {
                        return Err("the site's PostgreSQL is unknown to the house".into());
                    };
                    Server {
                        image,
                        admin_password: admin,
                    }
                    .reader()
                }
            };
            let db = Database {
                engine: DbEngine::Postgres,
                name,
                role: &d.role,
                extensions: &d.extensions,
            };
            let b = restore
                .database_from_site(&c.app, &db, &target, &reader)
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
    for (c, (dbs, vols)) in all.iter().zip(&read) {
        for (d, b) in c.databases.iter().zip(dbs) {
            let name = &d.name;
            let admin_url = cli
                .admin_of(state, &c.app, name, DbEngine::Postgres)
                .await
                .map_err(|e| e.to_string())??;
            let db = Database {
                engine: DbEngine::Postgres,
                name,
                role: &d.role,
                extensions: &d.extensions,
            };
            let before = restore
                .database_in_place(&c.app, &db, &admin_url, &b.source)
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

/// The image `service`'s plan deploys.
async fn image_of(state: &State, service: &str) -> std::result::Result<Option<String>, String> {
    let plan = lifeboat::plan_of(state, service)
        .await
        .map_err(|e| e.to_string())?;
    Ok(lifeboat::services(&plan).into_iter().find_map(|a| match a {
        Action::DeployService { image, .. } => Some(image.clone()),
        _ => None,
    }))
}

/// One question to a PostgreSQL service, as its own `postgres` over its socket.
async fn ask(
    on: &SwarmOrchestrator,
    service: &str,
    cmd: &str,
) -> std::result::Result<String, String> {
    let out = on
        .exec_in_service(service, &["sh".into(), "-c".into(), cmd.into()])
        .await
        .map_err(|e| e.to_string())?;
    if !out.ok() {
        return Err(out.stderr.trim().to_string());
    }
    Ok(out.stdout)
}

/// The house's vital server's position against where the site's standby took over.
/// Said, never a reason to stop: the return replaces it either way.
async fn written_past(house: &SwarmOrchestrator, site: &SwarmOrchestrator) -> String {
    let position = ask(
        house,
        VITAL_POSTGRES,
        &format!("psql -U postgres -XqtA -c '{}'", wal_ship::POSITION_SQL),
    )
    .await
    .and_then(|o| wal_ship::parse_position(&o).ok_or_else(|| format!("read {:?}", o.trim())));
    let history = ask(site, VITAL_POSTGRES, "cat \"$PGDATA\"/pg_wal/*.history").await;
    match (position, history) {
        (Ok(p), Ok(h)) => wal_ship::written_past(p, &h),
        (Err(e), _) => format!("the house's {VITAL_POSTGRES} could not say where it is: {e}"),
        (_, Err(e)) => format!("the site's {VITAL_POSTGRES} could not say where it took over: {e}"),
    }
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
    let mut argv = vec![lifeboat::PROMOTE_SCRIPT.to_string(), "--apply".into()];
    match restore::stop_held(
        house,
        state,
        &services,
        lifeboat::HOUSE_HOLD,
        lifeboat::HOUSE_HOLD_SECS,
    )
    .await
    {
        // Said, though the site is still marked and waits for nobody: a mark lost
        // would have it wait for a house whose link is up, and refuse.
        Ok(()) => argv.push("--house-stopped".into()),
        Err(e) => eprintln!("   ⚠️  the house's own copies could not be held stopped: {e}"),
    }
    let served = ssh.run(&argv).await;
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
