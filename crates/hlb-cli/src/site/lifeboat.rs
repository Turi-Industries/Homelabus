//! `hlb site lifeboat`: the house's vital apps rebuilt on its site from their backups,
//! started once, proved healthy, and stopped — what the site would serve the night the
//! house is down.
//!
//! The house reads the backups and pushes the result to the site's Docker, reached over
//! the SSH the site already trusts (`docker system dial-stdio`): the VPS never holds the
//! restic password, nor the house's PostgreSQL administrator.

use std::process::ExitCode;
use std::time::Instant;

use hlb_backup::wal_ship;
use hlb_backup_run::lifeboat::{Server, Site as Target};
use hlb_backup_run::restore::{Database, Restore};
use hlb_bootstrap::Runner;
use hlb_engine::lifeboat::{self, Selection};
use hlb_mesh::site::Site;
use hlb_orchestrator::{Orchestrator as _, SwarmOrchestrator};
use hlb_resolver::Action;
use hlb_secrets::Vault;
use hlb_state::State;
use hlb_types::{DbServer, Manifest, VITAL_POSTGRES};

use crate::{
    existing_ssh_key, open_state, open_vault, parse_ssh_target, write_temporary_key, Cli,
    ACTOR_ROLE,
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// What last night's run left on the site: its services and volumes, removed before the
/// next. A stored name.
const CARRIED: &str = "site-lifeboat-carried";

/// How long a service carried may take to be healthy: an image pulled on the site, a
/// database restored behind it.
const HEALTHY_WITHIN_SECS: u64 = 300;

/// The scope its rehearsal is recorded under, beside the recovery drills.
const SCOPE: &str = "lifeboat";

/// The apps installed and running, with their frozen manifests.
async fn installed(state: &State) -> Result<Vec<(String, Manifest)>> {
    let mut out = Vec::new();
    for (app, status) in state.installed_apps().await? {
        // A failed or half-installed app was never what the house serves.
        if status != "running" {
            continue;
        }
        out.push((app.clone(), state.app_manifest(&app).await?));
    }
    Ok(out)
}

fn say(sel: &Selection) {
    for (app, why) in &sel.refused {
        println!("  🔴 {app} cannot be carried: {why}");
    }
    for n in &sel.notes {
        println!("  ⚠️  {n}");
    }
}

/// One carried database, and the server it lives on at home.
struct Placed {
    app: String,
    database: String,
    server: DbServer,
}

/// Each carried database with the server it lives on at home, which decides the site's:
/// the shared server's restored from its dump into a PostgreSQL of the site's own, the
/// vital server's replayed there continuously by a standby.
async fn placed(state: &State, sel: &Selection) -> Result<Vec<Placed>> {
    let mut out = Vec::new();
    for (app, database) in &sel.postgres {
        let server = state
            .database_server(app, database)
            .await?
            .unwrap_or(DbServer::Postgres);
        out.push(Placed {
            app: app.clone(),
            database: database.clone(),
            server,
        });
    }
    Ok(out)
}

/// The servers the site runs for `placed`, once each.
fn servers(placed: &[Placed]) -> Vec<DbServer> {
    let mut out: Vec<DbServer> = placed.iter().map(|p| p.server).collect();
    out.sort();
    out.dedup();
    out
}

/// The site's memory against what the selection may take; why not, otherwise.
fn memory_refusal(
    sel: &Selection,
    installed: &[(String, Manifest)],
    servers: &[DbServer],
    s: &Site,
) -> std::result::Result<u64, String> {
    let caddy = installed
        .iter()
        .find(|(n, _)| n == hlb_types::manifest::INGRESS_SERVICE)
        .map(|(_, m)| m);
    let needed = lifeboat::memory_mib(sel, installed, servers, caddy)?;
    let Some(has) = s.memory_mb else {
        return Err(format!(
            "{} MB needed, and the site's memory was never read",
            needed
        ));
    };
    if needed > has {
        return Err(format!(
            "{needed} MB of limits, {has} MB on the site: it would be killed for memory \
             the night it serves"
        ));
    }
    Ok(needed)
}

pub async fn run(cli: &Cli, apply: bool) -> Result<ExitCode> {
    let state = open_state(cli).await?;
    let vault = open_vault(cli)?;
    let Some(s) = super::load(&state, &vault).await? else {
        println!("The house has no site.  hlb site add <ssh-host> --apply");
        return Ok(ExitCode::SUCCESS);
    };
    let installed = installed(&state).await?;
    let sel = lifeboat::select(&installed);
    println!("Lifeboat on {}:", s.name);
    if sel.is_empty() {
        say(&sel);
        println!("  nothing vital to carry: an app is carried once its manifest says");
        println!("  `criticality: vital`.");
        return Ok(ExitCode::SUCCESS);
    }
    for app in &sel.apps {
        println!("  {app}");
    }
    let placed = placed(&state, &sel).await?;
    for p in &placed {
        match p.server {
            DbServer::PostgresVital => println!(
                "  {} — {}'s database, replayed on the site by a standby of {VITAL_POSTGRES}",
                p.database, p.app
            ),
            DbServer::Postgres | DbServer::Mariadb => println!(
                "  {} — {}'s database, on a PostgreSQL of the site's own",
                p.database, p.app
            ),
        }
    }
    say(&sel);
    let memory = match memory_refusal(&sel, &installed, &servers(&placed), &s) {
        Ok(mb) => mb,
        Err(why) => {
            eprintln!("\n🔴 {why}. Nothing was sent.");
            return Ok(ExitCode::FAILURE);
        }
    };
    println!(
        "  memory: {memory} MB of limits, {} MB on the site",
        s.memory_mb.unwrap_or_default()
    );

    if !apply {
        println!();
        println!("Would remove last night's lifeboat on the site, send each app's latest");
        println!("backup there, start it once until healthy, record the rehearsal, and");
        println!("stop it. The site never receives the restic password, nor the house's");
        println!("PostgreSQL administrator. Each archive is refused past a tenth of the");
        println!("site's disk left free.");
        println!("Would leave beside it, stopped, the site's own Caddy and the promotion");
        println!(
            "({}), which starts them the night the house is down.",
            lifeboat::PROMOTE_SCRIPT
        );
        if placed.iter().any(|p| p.server == DbServer::PostgresVital) {
            println!("Would take a base backup of {VITAL_POSTGRES} now, start the apps once on a");
            println!("copy of it, then seed the standby from it: that one keeps running, and");
            println!("replays the WAL the house pushes until the promotion makes it the server.");
        }
        println!("Rerun with --apply.");
        return Ok(ExitCode::SUCCESS);
    }

    let started = Instant::now();
    let outcome = rebuild(cli, &state, &vault, &s, &sel, &placed).await;
    let secs = started.elapsed().as_secs();
    let (ok, detail) = match &outcome {
        Ok(lines) => (true, lines.join("; ")),
        Err(e) => (false, e.to_string()),
    };
    state
        .record_drill(SCOPE, ok, None, secs as i64, &detail)
        .await?;
    state
        .audit(
            "cli",
            ACTOR_ROLE,
            "site-lifeboat",
            &s.name,
            if ok { "ok" } else { "failed" },
            Some(&detail),
        )
        .await?;
    match outcome {
        Ok(_) => {
            println!(
                "\n✓ The lifeboat started healthy on {} in {secs} s, and is stopped.",
                s.name
            );
            if placed.iter().any(|p| p.server == DbServer::PostgresVital) {
                println!(
                    "  Its standby of {VITAL_POSTGRES} runs, replaying what the house pushes."
                );
            }
            Ok(ExitCode::SUCCESS)
        }
        Err(e) => {
            eprintln!("\n🔴 The lifeboat: {e}");
            eprintln!("   Recorded as a failed rehearsal. What reached the site stays, stopped");
            eprintln!("   or not: the next run removes it first.");
            Ok(ExitCode::FAILURE)
        }
    }
}

/// The services and volumes a run puts on the site.
#[derive(Default, serde::Serialize, serde::Deserialize)]
struct Carried {
    services: Vec<String>,
    volumes: Vec<String>,
    /// The names the site serves once promoted: what the door's promoted file sends
    /// it, written again at each `hlb site sync`.
    #[serde(default)]
    names: Vec<String>,
    /// The apps carried: what the return brings home, whatever was installed since.
    #[serde(default)]
    apps: Vec<String>,
}

/// The apps the lifeboat last left on the site — chosen again from what is installed
/// when that run predates their record.
pub async fn apps(state: &State, vault: &Vault) -> Result<Vec<String>> {
    let apps = carried(state, vault).await?.apps;
    if !apps.is_empty() {
        return Ok(apps);
    }
    Ok(lifeboat::select(&installed(state).await?).apps)
}

/// The names the lifeboat left on the site, for the door's promoted file.
pub async fn names(state: &State, vault: &Vault) -> Result<Vec<String>> {
    Ok(carried(state, vault).await?.names)
}

async fn carried(state: &State, vault: &Vault) -> Result<Carried> {
    Ok(match state.secret(CARRIED).await? {
        Some(ct) => serde_json::from_str(&vault.decrypt(&ct)?)?,
        None => Carried::default(),
    })
}

async fn remember(state: &State, vault: &Vault, c: &Carried) -> Result<()> {
    let ct = vault.encrypt(&serde_json::to_string(c)?)?;
    match state.secret(CARRIED).await? {
        Some(_) => state.rotate_secret(CARRIED, &ct).await?,
        None => {
            state
                .store_secret_if_absent(CARRIED, &ct, "what the lifeboat left on the site")
                .await?;
        }
    }
    Ok(())
}

/// The site PostgreSQL's administrator, drawn once.
async fn site_admin(state: &State, vault: &Vault) -> Result<String> {
    if let Some(ct) = state.secret(lifeboat::ADMIN_SECRET).await? {
        return Ok(vault.decrypt(&ct)?);
    }
    let pw = hlb_secrets::generate_password(32);
    state
        .store_secret_if_absent(
            lifeboat::ADMIN_SECRET,
            &vault.encrypt(&pw)?,
            "the administrator of the site's PostgreSQL, the lifeboat's",
        )
        .await?;
    Box::pin(site_admin(state, vault)).await
}

/// `df` of Docker's directory on the site: (free, total) bytes.
async fn free_on(hub: &dyn Runner) -> std::result::Result<(u64, u64), String> {
    let out = hub
        .run(&[
            "df".into(),
            "-B1".into(),
            "--output=avail,size".into(),
            "/var/lib/docker".into(),
        ])
        .await
        .map_err(|e| e.to_string())?;
    if !out.ok() {
        return Err(format!("df on the site: {}", out.stderr.trim()));
    }
    parse_df(&out.stdout).ok_or_else(|| format!("df on the site: {:?}", out.stdout.trim()))
}

fn parse_df(out: &str) -> Option<(u64, u64)> {
    let mut nums = out.lines().nth(1)?.split_whitespace();
    Some((nums.next()?.parse().ok()?, nums.next()?.parse().ok()?))
}

/// Removes `name`'s volumes once the service using them is gone: Docker refuses a
/// volume a container still holds, and a removed service's take a moment to stop.
async fn remove_volume(site: &SwarmOrchestrator, name: &str) -> Result<()> {
    let mut last = None;
    for _ in 0..30 {
        match site.remove_volume(name).await {
            Ok(()) => return Ok(()),
            Err(e) => last = Some(e),
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    Err(format!(
        "volume {name} is still in use on the site: {}",
        last.map(|e| e.to_string()).unwrap_or_default()
    )
    .into())
}

/// The site over SSH, as the lifeboat reaches it: its Docker is bridged from there. The
/// directory holds the key; the caller's scratch space too.
pub(super) async fn ssh_to(
    state: &State,
    vault: &Vault,
    s: &Site,
) -> Result<(tempfile::TempDir, hlb_bootstrap::SshRunner)> {
    let kp = existing_ssh_key(state, vault)
        .await?
        .ok_or("Homelabus has no SSH key of its own: the site cannot be reached")?;
    let tmp = tempfile::tempdir()?;
    let key_path = write_temporary_key(tmp.path(), &kp.private)?;
    let (host, user, port) = parse_ssh_target(&s.ssh);
    let mut ssh = hlb_bootstrap::SshRunner::new(&host).identity(key_path.to_string_lossy());
    if let Some(u) = &user {
        ssh = ssh.user(u);
    }
    if let Some(p) = port {
        ssh = ssh.port(p);
    }
    Ok((tmp, ssh))
}

/// The run itself; what it did, line by line, for the rehearsal's record.
async fn rebuild(
    cli: &Cli,
    state: &State,
    vault: &Vault,
    s: &Site,
    sel: &Selection,
    placed: &[Placed],
) -> Result<Vec<String>> {
    let (tmp, ssh) = ssh_to(state, vault, s).await?;
    // 🔴 A promoted site's lifeboat is serving: removed and rebuilt from last night's
    // backups, it would lose what people wrote there since.
    if let Some(since) = ssh.read_file(lifeboat::PROMOTED_MARK).await? {
        return Err(format!(
            "{} is promoted since {}: its lifeboat is serving, and is left as it is \
             until `hlb site return`",
            s.name,
            since.trim()
        )
        .into());
    }
    // Refused before anything is touched: a house the site cannot serve TLS for.
    let exposure = state.exposure().await?;
    let tls = lifeboat::site_tls(exposure.as_ref())?;
    let caddy = state
        .app_manifest(hlb_types::manifest::INGRESS_SERVICE)
        .await?;
    let mut routes = Vec::new();
    for app in &sel.apps {
        let m = state.app_manifest(app).await?;
        let cleared = state.unverified_blocking(app).await? == 0;
        routes.extend(hlb_ingress::routes_from_manifest(
            &m,
            state.app_domain(app).await?.as_deref(),
            cleared,
        ));
    }
    let socket = tmp.path().join("docker.sock");
    let _bridge = ssh.docker_socket(&socket).await?;
    let site = SwarmOrchestrator::connect_unix(&socket).await?;
    let mut said = Vec::new();

    // Last night's first: what it left is the state of then, and a volume filled over
    // it would keep files the backup no longer has.
    let before = carried(state, vault).await?;
    let on = |server: DbServer| placed.iter().any(|p| p.server == server);
    // The base the standby is seeded from, taken now: the site's WAL reaches back only
    // to the base its last prune kept, and a base older than that is followed by
    // nothing.
    let base = if on(DbServer::PostgresVital) {
        // Last night's standby stopped first: its volume is about to be refilled.
        let had = before.services.iter().any(|s| s == VITAL_POSTGRES);
        if had {
            stop(&site, VITAL_POSTGRES).await?;
        }
        match fresh_base(cli, state, vault).await {
            Ok(ids) => ids,
            Err(e) => {
                if had {
                    site.scale(VITAL_POSTGRES, 1).await.ok();
                }
                return Err(e);
            }
        }
    } else {
        Vec::new()
    };
    let mut plans = Vec::new();
    let mut now = Carried {
        apps: sel.apps.clone(),
        ..Carried::default()
    };
    let pg_plan = if on(DbServer::Postgres) {
        Some(lifeboat::plan_of(state, lifeboat::POSTGRES).await?)
    } else {
        None
    };
    if let Some(p) = &pg_plan {
        collect(p, &mut now);
    }
    // Started before the apps, as the shared one is: a server, rendered and filled as
    // an app's services are.
    if on(DbServer::PostgresVital) {
        let plan = lifeboat::plan_of(state, VITAL_POSTGRES).await?;
        collect(&plan, &mut now);
        plans.push((VITAL_POSTGRES.to_string(), plan));
    }
    for app in &sel.apps {
        let plan = lifeboat::plan_of(state, app).await?;
        collect(&plan, &mut now);
        plans.push((app.clone(), plan));
    }
    let apps_services = now.services.clone();
    now.services
        .push(hlb_ingress::front_door::SITE_CADDY.to_string());
    now.volumes.push(lifeboat::CADDY_DATA.to_string());
    now.volumes.push(lifeboat::CADDY_CONFIG.to_string());
    let mut services: Vec<&String> = before.services.iter().chain(&now.services).collect();
    services.sort();
    services.dedup();
    for svc in services {
        site.remove(svc).await.ok();
    }
    let mut volumes: Vec<&String> = before.volumes.iter().chain(&now.volumes).collect();
    volumes.sort();
    volumes.dedup();
    for v in volumes {
        remove_volume(&site, v).await?;
    }
    // Recorded before anything is deployed: a run cut short leaves what it names.
    remember(state, vault, &now).await?;
    site.ensure_network(lifeboat::NETWORK).await?;

    let admin = site_admin(state, vault).await?;
    // Each database rendered where it lives at home: the site's servers carry the same
    // names, the shared one restored there, the vital one's standby.
    let exec = hlb_engine::Executor::new(&site, state)
        .with_vault(vault)
        .with_network(lifeboat::NETWORK)
        .withholding(lifeboat::WITHHELD)
        .replacing_secret(&lifeboat::admin_entry(), &admin)
        .replacing_secret(&lifeboat::admin_entry_of(VITAL_POSTGRES), &admin);
    let restore = Restore {
        state,
        vault,
        fallback_repo: cli.backup_repo.as_deref(),
        network: &cli.platform_network,
        orchestrator: None,
    };
    let target = Target {
        docker: &site,
        socket: &socket,
        network: lifeboat::NETWORK,
    };

    if let Some(plan) = &pg_plan {
        let mut image = String::new();
        for action in lifeboat::services(plan) {
            let spec = lifeboat::for_site(exec.render_service(lifeboat::POSTGRES, action).await?);
            image = spec.image.clone();
            println!("  … {} starting", spec.name);
            site.deploy(&spec).await?;
            site.wait_healthy(&spec.name, HEALTHY_WITHIN_SECS).await?;
        }
        let server = Server {
            image: &image,
            admin_password: &admin,
        };
        for (app, plan) in &plans {
            for a in &plan.actions {
                // Where the state says it lives: the lifeboat's plan places every
                // database on the shared server.
                let Action::ProvisionDatabase {
                    server: _,
                    database,
                    role,
                    password_secret,
                    extensions,
                    connection_limit,
                } = a
                else {
                    continue;
                };
                if !placed.iter().any(|p| {
                    &p.app == app && &p.database == database && p.server == DbServer::Postgres
                }) {
                    continue;
                }
                let ct = state
                    .secret(password_secret)
                    .await?
                    .ok_or_else(|| format!("{app}: no {password_secret} in the vault"))?;
                let db = Database {
                    engine: hlb_types::DbEngine::Postgres,
                    name: database,
                    role,
                    extensions,
                };
                let sent = restore
                    .database_to_site(
                        app,
                        &db,
                        &vault.decrypt(&ct)?,
                        *connection_limit,
                        &target,
                        &server,
                    )
                    .await
                    .map_err(|e| format!("{app}'s database {database}: {e}"))?;
                let line = format!(
                    "{database} from {} ({} KB)",
                    &sent.snapshot[..8],
                    sent.bytes / 1024
                );
                println!("  ✓ {line}");
                said.push(line);
            }
        }
    }

    let mut vital_spec = None;
    for (app, plan) in &plans {
        let backed_up: Vec<String> = state
            .volumes_to_backup(app)
            .await?
            .into_iter()
            .map(|(name, _)| name)
            .collect();
        let mut specs = Vec::new();
        for action in lifeboat::services(plan) {
            let mut spec = lifeboat::for_site(exec.render_service(app, action).await?);
            if app == VITAL_POSTGRES {
                // Started on the base as a server of its own, archiving nothing: the
                // apps' rehearsal writes, and a standby takes none.
                spec.args.extend(wal_ship::standby_args());
                vital_spec = Some(spec.clone());
            }
            specs.push(spec);
        }
        let mut filled = Vec::new();
        for spec in &specs {
            for (vol, _) in &spec.mounts {
                if !backed_up.contains(vol) || filled.contains(vol) {
                    continue;
                }
                let sent = restore
                    .volume_to_site(app, vol, &target, &spec.image, tmp.path(), || free_on(&ssh))
                    .await
                    .map_err(|e| format!("{app}: {e}"))?;
                if app == VITAL_POSTGRES {
                    is_base(&sent, &base)?;
                }
                let mut line = format!(
                    "{vol} from {} ({} KB)",
                    &sent.snapshot[..8],
                    sent.bytes / 1024
                );
                if !sent.sqlite.is_empty() {
                    line.push_str(&format!(", SQLite {}", sent.sqlite.join(", ")));
                }
                println!("  ✓ {line}");
                said.push(line);
                filled.push(vol.clone());
            }
        }
        for spec in &specs {
            println!("  … {} starting", spec.name);
            site.deploy(spec).await?;
            site.wait_healthy(&spec.name, HEALTHY_WITHIN_SECS)
                .await
                .map_err(|e| format!("{} never became healthy on the site: {e}", spec.name))?;
            said.push(format!("{} healthy", spec.name));
        }
    }

    // The site's own Caddy, stopped beside them: its file checked by its binary now,
    // not found wrong the night it is needed.
    let overlay = site
        .network_subnets(lifeboat::NETWORK)
        .await?
        .into_iter()
        .next()
        .ok_or("the lifeboat's network has no subnet on the site")?;
    let ingress = lifeboat::site_ingress(
        routes,
        tls,
        &overlay,
        exposure.as_ref().and_then(|e| e.acme_ca_root.clone()),
    )?;
    let caddy_spec = lifeboat::site_caddy(&caddy, &ingress);
    let mut check = caddy_spec.clone();
    check.name = format!("{}-check", caddy_spec.name);
    check.command = [
        "caddy",
        "validate",
        "--config",
        lifeboat::CADDYFILE,
        "--adapter",
        "caddyfile",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    check.healthcheck = None;
    let checked = site.run_job(&check.job(), HEALTHY_WITHIN_SECS).await?;
    if !checked.succeeded {
        return Err(format!(
            "the site's Caddy refuses its file: {}",
            checked.output.join(" / ")
        )
        .into());
    }
    site.deploy(&caddy_spec).await?;
    said.push(format!("{} ready, stopped", caddy_spec.name));

    // The promotion, and the door's file it puts in place.
    let script = lifeboat::promote_script(&lifeboat::start_order(&apps_services), &ingress.names);
    hlb_bootstrap::provision::install_file(&ssh, lifeboat::PROMOTE_SCRIPT, &script, 0o700).await?;
    now.names = ingress.names.clone();
    remember(state, vault, &now).await?;
    let own = super::watch::own_names(state).await?;
    super::door::deploy(&ssh, s, &ingress.names, &own).await?;
    println!(
        "  ✓ promotion ready: {} on {}",
        lifeboat::PROMOTE_SCRIPT,
        ingress.names.join(", ")
    );

    // Stopped, apps first: ready, and holding nothing the night nobody needs it.
    for svc in now.services.iter().rev() {
        site.scale(svc, 0).await?;
    }

    // The vital server's rehearsal wrote into its copy: the standby starts from the
    // base again, and stays.
    if let Some(spec) = vital_spec {
        let line = seed_standby(state, &site, &ssh, &restore, &target, spec, &base, &tmp).await?;
        println!("  ✓ {line}");
        said.push(line);
    }
    Ok(said)
}

/// `name` scaled to nothing, and gone: a task still stopping may still write. A service
/// not there is stopped.
async fn stop(site: &SwarmOrchestrator, name: &str) -> Result<()> {
    if site.scale(name, 0).await.is_err() {
        return Ok(());
    }
    // The tasks' own state: `running_replicas` reads 0 while the container still stops.
    if hlb_orchestrator::wait_stopped(site, name, std::time::Duration::from_secs(60)).await? {
        return Ok(());
    }
    Err(format!("{name} is still running on the site a minute after it was stopped").into())
}

/// A pass of the vital server alone, now: the snapshots it took.
async fn fresh_base(cli: &Cli, state: &State, vault: &Vault) -> Result<Vec<String>> {
    println!("  … a base backup of {VITAL_POSTGRES}");
    let orch = SwarmOrchestrator::connect().await?;
    let pass = hlb_backup_run::Pass {
        state,
        vault,
        state_path: &cli.state,
        fallback_repo: cli.backup_repo.as_deref(),
        network: &cli.platform_network,
        postgres_admin: cli.postgres_admin.as_deref(),
        postgres_vital_admin: cli.postgres_vital_admin.as_deref(),
        mariadb_admin: cli.mariadb_admin.as_deref(),
        schedule: hlb_backup::Schedule::default(),
        force: true,
        only: Some(VITAL_POSTGRES),
        orchestrator: Some(&orch),
        // It keeps no bucket.
        s3_endpoint: None,
    };
    let mut taken = Vec::new();
    let mut failed = Vec::new();
    pass.run(&mut |e| match e {
        hlb_backup_run::Event::Done { snapshot, .. } => taken.push(snapshot),
        hlb_backup_run::Event::Failed {
            what,
            destination,
            error,
        } => failed.push(match destination {
            Some(d) => format!("{what} → {d}: {error}"),
            None => format!("{what}: {error}"),
        }),
        hlb_backup_run::Event::NotCovered { what, why } => {
            failed.push(format!("{what} not backed up: {why}"))
        }
    })
    .await?;
    if taken.is_empty() {
        return Err(format!(
            "no base backup of {VITAL_POSTGRES} was taken, and last night's standby is \
             left replaying: {}",
            failed.join("; ")
        )
        .into());
    }
    // One destination is enough: the base is read back from the newest.
    for f in failed {
        println!("  ⚠️  {f}");
    }
    Ok(taken)
}

/// 🔴 The base sent is the one just taken, never an older one a destination answered
/// with: the site's WAL would not reach back to it, and the standby would wait for ever
/// on a segment nobody has, healthy all the while.
fn is_base(sent: &hlb_backup_run::lifeboat::Sent, base: &[String]) -> Result<()> {
    if base.contains(&sent.snapshot) {
        return Ok(());
    }
    Err(format!(
        "{VITAL_POSTGRES}'s data came from {}, not from the base just taken",
        &sent.snapshot[..8.min(sent.snapshot.len())]
    )
    .into())
}

/// The vital server's standby on the site: its rehearsal removed with what it wrote,
/// the base restored again and signalled, started with the WAL the house pushes.
#[allow(clippy::too_many_arguments)]
async fn seed_standby(
    state: &State,
    site: &SwarmOrchestrator,
    ssh: &hlb_bootstrap::SshRunner,
    restore: &Restore<'_>,
    target: &Target<'_>,
    rehearsed: hlb_orchestrator::ServiceSpec,
    base: &[String],
    tmp: &tempfile::TempDir,
) -> Result<String> {
    site.remove(VITAL_POSTGRES).await?;
    let data = data_volume(&state.app_manifest(VITAL_POSTGRES).await?)
        .ok_or_else(|| format!("{VITAL_POSTGRES} declares no volume copied by pg_basebackup"))?;
    let mut from = String::new();
    for (vol, _) in &rehearsed.mounts {
        if *vol != data {
            continue;
        }
        remove_volume(site, vol).await?;
        let sent = restore
            .volume_to_site(
                VITAL_POSTGRES,
                vol,
                target,
                &rehearsed.image,
                tmp.path(),
                || free_on(ssh),
            )
            .await
            .map_err(|e| format!("{VITAL_POSTGRES}: {e}"))?;
        is_base(&sent, base)?;
        hlb_backup_run::lifeboat::mark_standby(target, &rehearsed.image, vol).await?;
        from = sent.snapshot[..8.min(sent.snapshot.len())].to_string();
    }
    if from.is_empty() {
        return Err(format!("{VITAL_POSTGRES} as rendered mounts no {data}").into());
    }
    // The receiver makes it at its first file: a bind of a path not there is refused.
    let made = ssh
        .run(&[
            "install".into(),
            "-d".into(),
            "-o".into(),
            wal_ship::POSTGRES_UID.to_string(),
            "-g".into(),
            wal_ship::POSTGRES_UID.to_string(),
            "-m".into(),
            "700".into(),
            wal_ship::SITE_DIR.into(),
        ])
        .await?;
    if !made.ok() {
        return Err(format!("{} on the site: {}", wal_ship::SITE_DIR, made.stderr.trim()).into());
    }
    let spec = standby(rehearsed);
    println!("  … {} starting as a standby", spec.name);
    site.deploy(&spec).await?;
    site.wait_healthy(&spec.name, HEALTHY_WITHIN_SECS)
        .await
        .map_err(|e| format!("{VITAL_POSTGRES}'s standby never became healthy: {e}"))?;
    // Only once the new standby runs: a seeding that failed keeps every segment.
    let pruned = ssh
        .run(&["sh".into(), "-c".into(), wal_ship::prune_script()])
        .await?;
    let kept = match pruned.stdout.trim() {
        _ if !pruned.ok() => format!("⚠️ the site's WAL was not pruned: {}", pruned.stderr.trim()),
        "" => format!(
            "the site's WAL kept whole: no base is {} hours old yet",
            wal_ship::KEEP_HOURS
        ),
        b => format!("the site's WAL kept from base {b}"),
    };
    println!("  ✓ {kept}");
    Ok(format!(
        "{VITAL_POSTGRES} replaying on the site, from {from}; {kept}"
    ))
}

/// The volume holding the server's data directory: the one its base backup copies.
pub(super) fn data_volume(m: &Manifest) -> Option<String> {
    m.spec.requires.iter().find_map(|c| match c {
        hlb_types::Capability::Storage { name, copy, .. }
            if copy.engine() == Some(hlb_types::DbEngine::Postgres) =>
        {
            Some(format!("{}-{name}", m.metadata.name))
        }
        _ => None,
    })
}

/// The rehearsed vital server made the standby: the WAL the house pushed, read where
/// the receiver writes it.
fn standby(rehearsed: hlb_orchestrator::ServiceSpec) -> hlb_orchestrator::ServiceSpec {
    let mut spec = rehearsed.bind(wal_ship::SITE_DIR, wal_ship::STANDBY_DIR, false);
    spec.replicas = 1;
    spec
}

/// The services and volumes a plan puts on the site.
fn collect(plan: &hlb_resolver::Plan, into: &mut Carried) {
    for a in lifeboat::services(plan) {
        if let Action::DeployService { name, mounts, .. } = a {
            into.services.push(name.clone());
            into.volumes.extend(mounts.iter().map(|(v, _)| v.clone()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn catalog_vital() -> Manifest {
        let catalog = hlb_catalog::Catalog::load(std::path::Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../catalog"
        )))
        .expect("catalog");
        catalog
            .get(VITAL_POSTGRES)
            .expect("in the catalog")
            .manifest
            .clone()
    }

    #[test]
    fn the_standby_is_seeded_into_the_volume_the_base_backup_copies() {
        assert_eq!(
            data_volume(&catalog_vital()).as_deref(),
            Some("postgres-vital-data")
        );
    }

    #[test]
    fn the_standby_reads_what_the_receiver_writes_and_archives_nothing() {
        let mut rehearsed = hlb_orchestrator::ServiceSpec::new(VITAL_POSTGRES, "pg:17");
        rehearsed.args = vec!["postgres".into()];
        rehearsed.args.extend(wal_ship::standby_args());
        rehearsed.replicas = 0;
        let spec = standby(rehearsed);
        assert_eq!(spec.replicas, 1, "it runs every day");
        assert_eq!(
            spec.binds,
            vec![hlb_orchestrator::Bind {
                source: wal_ship::SITE_DIR.into(),
                target: wal_ship::STANDBY_DIR.into(),
                read_only: false,
            }],
            "read and cleaned where the receiver writes"
        );
        assert!(spec.args.ends_with(&wal_ship::standby_args()));
    }

    #[test]
    fn only_the_base_just_taken_seeds_the_standby() {
        let sent = |id: &str| hlb_backup_run::lifeboat::Sent {
            snapshot: id.into(),
            bytes: 1,
            sqlite: vec![],
        };
        let base = vec!["aaaaaaaa1111".to_string()];
        assert!(is_base(&sent("aaaaaaaa1111"), &base).is_ok());
        let older = is_base(&sent("bbbbbbbb2222"), &base).expect_err("an older base");
        assert!(older.to_string().contains("bbbbbbbb"), "{older}");
    }

    #[test]
    fn df_reads_free_then_total() {
        let out = "      Avail     1B-blocks\n30000000000 42006183936\n";
        assert_eq!(super::parse_df(out), Some((30_000_000_000, 42_006_183_936)));
        assert_eq!(super::parse_df("df: /var/lib/docker: No such file"), None);
    }
}
