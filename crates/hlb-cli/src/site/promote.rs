//! `hlb site promote`: the site serves the house's vital apps while the house is down.
//!
//! The promotion itself is the script the lifeboat leaves on the VPS each night
//! (`hlb_engine::lifeboat::PROMOTE_SCRIPT`): the night it is needed there may be no house
//! to run `hlb` from, only SSH to the VPS. This verb runs that same script, so both ways
//! do one thing — a house still up enough to run `hlb`, a planned move, or a rehearsal.

use std::process::ExitCode;

use hlb_backup_run::restore;
use hlb_bootstrap::Runner;
use hlb_engine::lifeboat;

use crate::{open_state, open_vault, Cli, ACTOR_ROLE};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// When the site was promoted, read off its mark; `None` while it is not.
pub async fn since(site: &dyn Runner) -> Result<Option<String>> {
    Ok(site
        .read_file(lifeboat::PROMOTED_MARK)
        .await?
        .map(|s| s.trim().to_string()))
}

/// Stops the house's own copies of the carried apps, held until the return. Their names.
async fn hold_house(
    state: &hlb_state::State,
    vault: &hlb_secrets::Vault,
) -> std::result::Result<Vec<String>, String> {
    let o = hlb_orchestrator::SwarmOrchestrator::connect()
        .await
        .map_err(|e| format!("this machine's Docker: {e}"))?;
    let mut services = Vec::new();
    for app in super::lifeboat::apps(state, vault)
        .await
        .map_err(|e| e.to_string())?
    {
        let m = state.app_manifest(&app).await.map_err(|e| e.to_string())?;
        services.extend(restore::replicas(&o, &hlb_engine::services_of(&app, &m)).await);
    }
    restore::stop_held(
        &o,
        state,
        &services,
        lifeboat::HOUSE_HOLD,
        lifeboat::HOUSE_HOLD_SECS,
    )
    .await?;
    Ok(services.into_iter().map(|(s, _)| s).collect())
}

pub async fn run(cli: &Cli, apply: bool) -> Result<ExitCode> {
    let state = open_state(cli).await?;
    let vault = open_vault(cli)?;
    let Some(s) = super::load(&state, &vault).await? else {
        println!("The house has no site.  hlb site add <ssh-host> --apply");
        return Ok(ExitCode::SUCCESS);
    };
    let (_key_dir, site) = super::reach(&state, &vault, &s).await?;
    // A script that was never left there is a lifeboat that never ran: said apart, or
    // the shell's "not found" would read as a broken promotion.
    if site.read_file(lifeboat::PROMOTE_SCRIPT).await?.is_none() {
        eprintln!(
            "🔴 {} has no promotion: the lifeboat never ran there.  hlb site lifeboat --apply",
            s.name
        );
        return Ok(ExitCode::FAILURE);
    }
    if let Some(since) = since(site.as_ref()).await? {
        println!("{} is promoted since {since}.", s.name);
        if !apply {
            println!("Rerun with --apply to start again what stopped since.");
            return Ok(ExitCode::SUCCESS);
        }
    }

    let mut argv = vec![lifeboat::PROMOTE_SCRIPT.to_string()];
    if apply {
        // First, or the house's copies take writes the site never sees, for the LAN.
        match hold_house(&state, &vault).await {
            Ok(held) if held.is_empty() => {}
            Ok(held) => println!(
                "✓ the house's own {} stopped, held until the return",
                held.join(", ")
            ),
            Err(e) => eprintln!(
                "⚠️  the house's own copies could not be stopped ({e}): what they take \
                 meanwhile is replaced at the return"
            ),
        }
        println!("Promoting {}: each service started, then the door.", s.name);
        argv.push("--apply".into());
    } else {
        println!(
            "Would stop the house's own copies first, held until the return: two copies \
             written at once cannot be merged."
        );
    }
    let out = site.run(&argv).await;
    let (ok, detail) = match &out {
        Ok(o) => {
            print!("{}", o.stdout);
            eprint!("{}", o.stderr);
            (o.ok(), o.stderr.trim().to_string())
        }
        Err(e) => (false, e.to_string()),
    };
    // Everything started and the door swapped, a name still without its certificate:
    // promoted, which the message for a promotion that stopped would deny.
    let uncertified = matches!(&out, Ok(o) if o.status == lifeboat::PROMOTED_WITHOUT_CERTIFICATE);
    if !apply {
        return Ok(if ok {
            ExitCode::SUCCESS
        } else {
            ExitCode::FAILURE
        });
    }
    state
        .audit(
            "cli",
            ACTOR_ROLE,
            "site-promote",
            &s.name,
            if ok {
                "ok"
            } else if uncertified {
                "no-certificate"
            } else {
                "failed"
            },
            (!detail.is_empty()).then_some(detail.as_str()),
        )
        .await?;
    if ok {
        println!();
        println!(
            "⚠️  The apps carried are served from {} — the private ones",
            s.name
        );
        println!("   among them open to the internet — until `hlb site return`. The");
        println!("   nightly lifeboat leaves them as they are meanwhile. They hold what the");
        println!("   lifeboat's backups held: what the house wrote after is in its own copy.");
        Ok(ExitCode::SUCCESS)
    } else if uncertified {
        eprintln!();
        eprintln!(
            "🔴 {} is promoted, its door swapped, but a name above has no",
            s.name
        );
        eprintln!("   certificate: its visitors are refused until one comes. Its public");
        eprintln!("   records must name the site.  hlb site status");
        Ok(ExitCode::FAILURE)
    } else {
        if let Err(e) = &out {
            eprintln!("🔴 {} unreachable over SSH: {e}", s.name);
        }
        // The script marks the site before it starts anything, and switches the door
        // last: a promotion cut short is marked, its door still home.
        eprintln!("🔴 The promotion stopped: unless it says it was promoted, the door");
        eprintln!("   still sends every name home. The site is marked promoted all the");
        eprintln!("   same, so the nightly lifeboat leaves what started there. Rerun it:");
        eprintln!("   what is up stays up, the rest starts.");
        Ok(ExitCode::FAILURE)
    }
}
