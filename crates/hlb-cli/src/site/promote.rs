//! `hlb site promote`: the site serves the house's vital apps while the house is down.
//!
//! The promotion itself is the script the lifeboat leaves on the VPS each night
//! (`hlb_engine::lifeboat::PROMOTE_SCRIPT`): the night it is needed there may be no house
//! to run `hlb` from, only SSH to the VPS. This verb runs that same script, so both ways
//! do one thing — a house still up enough to run `hlb`, a planned move, or a rehearsal.

use std::process::ExitCode;

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
        println!("Promoting {}: each service started, then the door.", s.name);
        argv.push("--apply".into());
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
            if ok { "ok" } else { "failed" },
            (!detail.is_empty()).then_some(detail.as_str()),
        )
        .await?;
    if ok {
        println!();
        println!(
            "⚠️  The apps carried are served from {} — the private ones",
            s.name
        );
        println!("   among them open to the internet — until they are brought home. The");
        println!("   nightly lifeboat leaves them as they are meanwhile.");
        Ok(ExitCode::SUCCESS)
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
