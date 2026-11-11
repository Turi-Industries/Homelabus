//! `hlb site lifeboat`: the house's vital apps rebuilt on its site from their backups,
//! started once, proved healthy, and stopped — what the site would serve the night the
//! house is down.
//!
//! The house reads the backups and pushes the result to the site's Docker, reached over
//! the SSH the site already trusts (`docker system dial-stdio`): the VPS never holds the
//! restic password, nor the house's PostgreSQL administrator.

use std::process::ExitCode;
use std::time::Instant;

use hlb_backup_run::lifeboat::{Server, Site as Target};
use hlb_backup_run::restore::{Database, Restore};
use hlb_bootstrap::Runner;
use hlb_engine::lifeboat::{self, Selection};
use hlb_mesh::site::Site;
use hlb_orchestrator::{Orchestrator as _, SwarmOrchestrator};
use hlb_resolver::Action;
use hlb_secrets::Vault;
use hlb_state::State;
use hlb_types::Manifest;

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

/// The site's memory against what the selection may take; why not, otherwise.
fn memory_refusal(
    sel: &Selection,
    installed: &[(String, Manifest)],
    s: &Site,
) -> std::result::Result<u64, String> {
    let postgres = installed
        .iter()
        .find(|(n, _)| n == lifeboat::POSTGRES)
        .map(|(_, m)| m);
    let caddy = installed
        .iter()
        .find(|(n, _)| n == hlb_types::manifest::INGRESS_SERVICE)
        .map(|(_, m)| m);
    let needed = lifeboat::memory_mib(sel, installed, postgres, caddy)?;
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
    for (app, db) in &sel.postgres {
        println!("  {db} — {app}'s database, on a PostgreSQL of the site's own");
    }
    say(&sel);
    let memory = match memory_refusal(&sel, &installed, &s) {
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
        println!("Rerun with --apply.");
        return Ok(ExitCode::SUCCESS);
    }

    let started = Instant::now();
    let outcome = rebuild(cli, &state, &vault, &s, &sel).await;
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
    let mut plans = Vec::new();
    let mut now = Carried {
        apps: sel.apps.clone(),
        ..Carried::default()
    };
    let pg_plan = if sel.postgres.is_empty() {
        None
    } else {
        Some(lifeboat::plan_of(state, lifeboat::POSTGRES).await?)
    };
    if let Some(p) = &pg_plan {
        collect(p, &mut now);
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
    let exec = hlb_engine::Executor::new(&site, state)
        .with_vault(vault)
        .with_network(lifeboat::NETWORK)
        // The site runs one PostgreSQL: a vital app's database moved home to the vital
        // server is there too.
        .databases_on(hlb_types::DbServer::shared(hlb_types::DbEngine::Postgres))
        .withholding(lifeboat::WITHHELD)
        .replacing_secret(&lifeboat::admin_entry(), &admin);
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
                // The site's own server takes it, whichever held it at home.
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

    for (app, plan) in &plans {
        let backed_up: Vec<String> = state
            .volumes_to_backup(app)
            .await?
            .into_iter()
            .map(|(name, _)| name)
            .collect();
        let mut specs = Vec::new();
        for action in lifeboat::services(plan) {
            specs.push(lifeboat::for_site(exec.render_service(app, action).await?));
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
    Ok(said)
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
    #[test]
    fn df_reads_free_then_total() {
        let out = "      Avail     1B-blocks\n30000000000 42006183936\n";
        assert_eq!(super::parse_df(out), Some((30_000_000_000, 42_006_183_936)));
        assert_eq!(super::parse_df("df: /var/lib/docker: No such file"), None);
    }
}
