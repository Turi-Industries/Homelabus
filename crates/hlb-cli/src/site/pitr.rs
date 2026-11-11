//! The vital server's point-in-time restore: its bases are the backups' copies of its
//! data directory, its WAL is on the site — the house's archive empties as the site
//! acknowledges.
//!
//! 🔴 **A copy, never production rewound.** What one person deleted comes back without
//! everyone else losing what they wrote since: the restore replays into a throwaway
//! server and hands back a dump of the app's database, which `hlb backup restore
//! --database` puts back if the owner wants it.

use std::process::ExitCode;

use hlb_backup::pitr::{self, BaseBackup};
use hlb_backup::wal_ship::{self, SiteLabels};
use hlb_backup_run::restore::Restore;
use hlb_secrets::Vault;
use hlb_state::State;
use hlb_types::VITAL_POSTGRES;

use super::Site;
use crate::{open_state, open_vault, Cli};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// The bases Homelabus took of the vital server, and what the site keeps of its WAL.
async fn gather(
    cli: &Cli,
    state: &State,
    vault: &Vault,
    s: &Site,
) -> Result<(Vec<BaseBackup>, SiteLabels)> {
    let manifest = state.app_manifest(VITAL_POSTGRES).await?;
    let volume = super::lifeboat::data_volume(&manifest)
        .ok_or_else(|| format!("{VITAL_POSTGRES} declares no volume copied by pg_basebackup"))?;
    let restore = Restore {
        state,
        vault,
        fallback_repo: cli.backup_repo.as_deref(),
        network: &cli.platform_network,
        orchestrator: None,
    };
    let bases = restore
        .taken_of(VITAL_POSTGRES, &volume)
        .await?
        .iter()
        .filter_map(|snap| {
            Some(BaseBackup {
                id: snap.id.clone(),
                finished_at: snap.epoch()?,
            })
        })
        .collect();
    let (_key_dir, hub) = super::reach(state, vault, s).await?;
    let out = hub
        .run(&["sh".into(), "-c".into(), wal_ship::site_labels_script()])
        .await?;
    if !out.ok() {
        return Err(format!(
            "{} did not say what it keeps: {}",
            s.name,
            out.stderr.trim()
        )
        .into());
    }
    Ok((bases, wal_ship::parse_site_labels(&out.stdout)))
}

/// The site, or why there is none to restore from.
async fn site(state: &State, vault: &Vault) -> Result<Option<Site>> {
    let s = super::load(state, vault).await?;
    if s.is_none() {
        println!("The house has no site: {VITAL_POSTGRES} exists only with one, and its WAL");
        println!("is kept there.  hlb site add <ssh-host> --apply");
    }
    Ok(s)
}

/// `hlb backup pitr window --server postgres-vital`.
pub async fn window(cli: &Cli) -> Result<ExitCode> {
    let state = open_state(cli).await?;
    let vault = open_vault(cli)?;
    let Some(s) = site(&state, &vault).await? else {
        return Ok(ExitCode::FAILURE);
    };
    let (bases, labels) = gather(cli, &state, &vault, &s).await?;
    let usable = wal_ship::usable_bases(&bases, &labels);
    println!(
        "{VITAL_POSTGRES}: {} taken, {} with their WAL on {}",
        hlb_api::plural(bases.len() as u64, "base", "bases"),
        usable.len(),
        s.name
    );
    for b in &usable {
        println!(
            "  {}  {}",
            pitr::iso8601(b.finished_at),
            &b.id[..8.min(b.id.len())]
        );
    }
    println!();
    let Some(received) = labels.received else {
        println!(
            "🔴 {} has received no WAL: nothing can be replayed.",
            s.name
        );
        println!("   hlb site status");
        return Ok(ExitCode::FAILURE);
    };
    match pitr::recoverable_window(&usable, received) {
        Some(w) => {
            println!("Recoverable window: {}", w.describe());
            println!(
                "  The site keeps its WAL back to a base {} hours old at least; the newest",
                wal_ship::KEEP_HOURS
            );
            println!("  instant is its last file received. A while the site was promoted is out");
            println!("  of reach: the house's server never followed the site's timeline.");
            println!();
            println!(
                "  hlb backup pitr restore --server {VITAL_POSTGRES} --app <app> --to \"<UTC>\""
            );
            Ok(ExitCode::SUCCESS)
        }
        None => {
            println!("No recoverable window: no base the site still has the WAL of.");
            println!("  The next lifeboat seeds one:  hlb site lifeboat --apply");
            Ok(ExitCode::FAILURE)
        }
    }
}

/// One of the app's databases on the vital server, as the restore archives it.
struct OnVital {
    name: String,
    role: String,
    extensions: Vec<String>,
}

/// `app`'s PostgreSQL databases that live on the vital server, each with its role.
async fn on_vital(state: &State, app: &str) -> Result<Vec<OnVital>> {
    use hlb_resolver::Action;
    let m = state.app_manifest(app).await?;
    let plan = hlb_engine::lifeboat::plan_of(state, app).await?;
    let mut out = Vec::new();
    for (engine, name, extensions) in hlb_backup_run::restore::databases_of(&m, app) {
        if engine != hlb_types::DbEngine::Postgres
            || state.database_server(app, &name).await? != Some(hlb_types::DbServer::PostgresVital)
        {
            continue;
        }
        let role = plan
            .actions
            .iter()
            .find_map(|a| match a {
                Action::ProvisionDatabase { database, role, .. } if *database == name => {
                    Some(role.clone())
                }
                _ => None,
            })
            .ok_or_else(|| format!("{app}'s database {name} is provisioned by no plan"))?;
        out.push(OnVital {
            name,
            role,
            extensions: extensions.to_vec(),
        });
    }
    Ok(out)
}

/// `hlb backup pitr restore --server postgres-vital --app <app> --to "<UTC>"`.
pub async fn restore(cli: &Cli, app: &str, to: &str, apply: bool) -> Result<ExitCode> {
    let Some(target) = pitr::parse_utc(to) else {
        eprintln!("Unreadable instant: \"{to}\"");
        eprintln!("Expected, in UTC: \"2026-11-11 09:58:00\"");
        return Ok(ExitCode::FAILURE);
    };
    let state = open_state(cli).await?;
    let vault = open_vault(cli)?;
    let Some(s) = site(&state, &vault).await? else {
        return Ok(ExitCode::FAILURE);
    };
    let dbs = on_vital(&state, app).await?;
    if dbs.is_empty() {
        eprintln!("{app} keeps no database on {VITAL_POSTGRES}: its dumps are what restores it.");
        eprintln!("  hlb backup restore {app} --database");
        return Ok(ExitCode::FAILURE);
    }
    let (bases, labels) = gather(cli, &state, &vault, &s).await?;
    let usable = wal_ship::usable_bases(&bases, &labels);
    let received = labels.received.unwrap_or(0);
    let base = match pitr::base_for(&usable, target, received) {
        Ok(b) => b.clone(),
        Err(e) => {
            eprintln!("{}", e.describe());
            if let Some(w) = pitr::recoverable_window(&usable, received) {
                eprintln!("  Recoverable: {}", w.describe());
            }
            return Ok(ExitCode::FAILURE);
        }
    };
    let names: Vec<&str> = dbs.iter().map(|d| d.name.as_str()).collect();
    println!("{app} as it was at {}:", pitr::iso8601(target));
    println!(
        "  base {} ({}), then the WAL {} keeps",
        &base.id[..8.min(base.id.len())],
        pitr::iso8601(base.finished_at),
        s.name
    );
    println!("  replayed in a throwaway server here, no network; production untouched");
    println!("  dumped out of it: {}", names.join(", "));
    if !apply {
        println!();
        println!(
            "  Each dump is kept in the backups, restored only by its id. Rerun with --apply."
        );
        return Ok(ExitCode::SUCCESS);
    }

    let outcome = replay_and_dump(cli, &state, &vault, &s, app, &dbs, &base, target).await;
    let (result, detail) = match &outcome {
        Ok(kept) => ("ok", kept.join("; ")),
        Err(e) => ("failed", e.to_string()),
    };
    state
        .audit(
            "cli",
            crate::ACTOR_ROLE,
            "pitr-restore",
            app,
            result,
            Some(&format!("to {}: {detail}", pitr::iso8601(target))),
        )
        .await?;
    match outcome {
        Ok(_) => Ok(ExitCode::SUCCESS),
        Err(e) => {
            eprintln!("🔴 {e}");
            Ok(ExitCode::FAILURE)
        }
    }
}

/// The base and the site's WAL into two volumes here, replayed, each database dumped and
/// kept. The container and both volumes are removed whatever happened.
#[allow(clippy::too_many_arguments)]
async fn replay_and_dump(
    cli: &Cli,
    state: &State,
    vault: &Vault,
    s: &Site,
    app: &str,
    dbs: &[OnVital],
    base: &BaseBackup,
    target: i64,
) -> Result<Vec<String>> {
    use hlb_backup::replay;
    use hlb_orchestrator::SwarmOrchestrator;
    let image = state
        .app_manifest(VITAL_POSTGRES)
        .await?
        .spec
        .image
        .reference();
    let volume = super::lifeboat::data_volume(&state.app_manifest(VITAL_POSTGRES).await?)
        .ok_or_else(|| format!("{VITAL_POSTGRES} declares no volume copied by pg_basebackup"))?;
    let container = replay::container_name(crate::now());
    let (data, wal) = (format!("{container}-data"), format!("{container}-wal"));
    let home = SwarmOrchestrator::connect().await?;
    let (tmp, ssh) = super::lifeboat::ssh_to(state, vault, s).await?;
    let socket = tmp.path().join("docker.sock");
    let _bridge = ssh.docker_socket(&socket).await?;
    let site = SwarmOrchestrator::connect_unix(&socket).await?;
    let restore = Restore {
        state,
        vault,
        fallback_repo: cli.backup_repo.as_deref(),
        network: &cli.platform_network,
        orchestrator: None,
    };

    let run = async {
        println!("  … the base from the backups");
        let b = restore
            .snapshot_into(
                VITAL_POSTGRES,
                &volume,
                &base.id,
                &home,
                &data,
                &image,
                tmp.path(),
            )
            .await?;
        println!(
            "  ✓ base {} ({} KB)",
            &base.id[..8.min(base.id.len())],
            b / 1024
        );
        let w =
            hlb_backup_run::lifeboat::wal_from_site(&site, &home, &image, &wal, tmp.path()).await?;
        println!("  ✓ the WAL {} keeps ({} KB)", s.name, w / 1024);
        replay::start(&container, &image, &data, &wal, None, target).await?;
        let stopped = replay::wait_promoted(&container).await?;
        println!("  ✓ replayed to {}", pitr::iso8601(target));
        for l in &stopped {
            println!("      {l}");
        }
        let mut kept = Vec::new();
        for d in dbs {
            let bytes = replay::dump(&container, &d.name).await?;
            let db = hlb_backup_run::restore::Database {
                engine: hlb_types::DbEngine::Postgres,
                name: &d.name,
                role: &d.role,
                extensions: &d.extensions,
            };
            let brought = restore.pitr_dump(app, &db, bytes, target).await?;
            let id = brought.source.snapshot.id.clone();
            println!(
                "  ✓ {} as it was, {} KB, kept as snapshot {}",
                d.name,
                brought.bytes / 1024,
                &id[..8]
            );
            println!(
                "      hlb backup restore {app} --database {} --snapshot {id}",
                d.name
            );
            kept.push(format!("{} kept as {id}", d.name));
        }
        Ok::<_, String>(kept)
    }
    .await;

    replay::remove(&container).await;
    for v in [&data, &wal] {
        if let Err(e) = home.remove_volume(v).await {
            eprintln!("⚠️  {v} not removed: {e}");
        }
    }
    Ok(run?)
}
