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
        .run(&[
            "sh".into(),
            "-c".into(),
            wal_ship::site_labels_script(),
        ])
        .await?;
    if !out.ok() {
        return Err(format!("{} did not say what it keeps: {}", s.name, out.stderr.trim()).into());
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
        println!("  {}  {}", pitr::iso8601(b.finished_at), &b.id[..8.min(b.id.len())]);
    }
    println!();
    let Some(received) = labels.received else {
        println!("🔴 {} has received no WAL: nothing can be replayed.", s.name);
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
            println!("  hlb backup pitr restore --server {VITAL_POSTGRES} --app <app> --to \"<UTC>\"");
            Ok(ExitCode::SUCCESS)
        }
        None => {
            println!("No recoverable window: no base the site still has the WAL of.");
            println!("  The next lifeboat seeds one:  hlb site lifeboat --apply");
            Ok(ExitCode::FAILURE)
        }
    }
}
