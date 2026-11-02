//! `hlb catalog source`: the third-party directories read beside the official catalog.

use std::process::ExitCode;

use hlb_catalog::Catalog;
use hlb_state::State;

use crate::{open_state, Cli, SourceCmd, ACTOR_ROLE};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// The official catalog and the third-party sources added to it. A source that cannot
/// be read is said and left out: the official apps never go with it.
pub async fn catalog_with_sources(cli: &Cli, state: &State) -> Result<Catalog> {
    let mut c = Catalog::load(&cli.catalog)?;
    for (name, dir) in state.catalog_sources().await? {
        if let Err(e) = c.add_source(&name, &dir) {
            eprintln!("⚠️  catalog source \"{name}\" ({dir}) left out: {e}");
        }
    }
    Ok(c)
}

pub async fn run(cli: &Cli, cmd: &SourceCmd) -> Result<ExitCode> {
    let state = open_state(cli).await?;
    match cmd {
        SourceCmd::List => {
            let sources = state.catalog_sources().await?;
            if sources.is_empty() {
                println!("No source beside the official catalog.");
            }
            for (name, dir) in sources {
                let mut c = Catalog::default();
                match c.add_source(&name, &dir) {
                    Ok(()) => println!(
                        "  {name:<14} {dir}  ({}, {} set aside)",
                        hlb_api::plural(c.len() as u64, "app", "apps"),
                        c.left_out().count()
                    ),
                    Err(e) => println!("  {name:<14} {dir}  🔴 unreadable: {e}"),
                }
            }
            Ok(ExitCode::SUCCESS)
        }

        SourceCmd::Add {
            name,
            directory,
            apply,
        } => {
            // Stored absolute: the controller and privd read it from another directory.
            let dir = match std::fs::canonicalize(directory) {
                Ok(d) => d.display().to_string(),
                Err(e) => {
                    eprintln!("🔴 {}: {e}", directory.display());
                    return Ok(ExitCode::FAILURE);
                }
            };
            // Read now, with the official catalog: what it would set aside is said
            // before it is added, not at the first install.
            let mut c = Catalog::load(&cli.catalog)?;
            if let Err(e) = c.add_source(name, &dir) {
                eprintln!("🔴 {e}");
                return Ok(ExitCode::FAILURE);
            }
            if state
                .catalog_sources()
                .await?
                .iter()
                .any(|(n, _)| n == name)
            {
                eprintln!("🔴 source \"{name}\" is added already — `hlb catalog source remove {name} --apply` first");
                return Ok(ExitCode::FAILURE);
            }
            let prefix = format!("{name}{}", hlb_catalog::SEPARATOR);
            for e in c.entries().filter(|e| e.source.as_deref() == Some(name)) {
                println!("  + {}", e.name());
            }
            for (app, why) in c.left_out().filter(|(a, _)| a.starts_with(&prefix)) {
                println!("  ✗ {app}: {why}");
            }
            if !*apply {
                println!("\nPreview: nothing added. Run again with --apply.");
                return Ok(ExitCode::SUCCESS);
            }
            state.add_catalog_source(name, &dir).await?;
            state
                .audit(
                    "cli",
                    ACTOR_ROLE,
                    "catalog-source-add",
                    name,
                    "ok",
                    Some(&dir),
                )
                .await?;
            println!("\n✓ \"{name}\" added: its apps install as `hlb install {name}/<app>`.");
            Ok(ExitCode::SUCCESS)
        }

        SourceCmd::Remove { name, apply } => {
            if !state
                .catalog_sources()
                .await?
                .iter()
                .any(|(n, _)| n == name)
            {
                eprintln!("🔴 no source \"{name}\"");
                return Ok(ExitCode::FAILURE);
            }
            let mut from = Vec::new();
            for (app, _) in state.installed_apps().await? {
                if state.app_source(&app).await?.as_deref() == Some(name.as_str()) {
                    from.push(app);
                }
            }
            if !from.is_empty() {
                // They run from their frozen manifests; only their upgrades need it.
                println!(
                    "Installed from it, kept running, upgraded no more until it is back: {}",
                    from.join(", ")
                );
            }
            if !*apply {
                println!("Preview: nothing removed. Run again with --apply.");
                return Ok(ExitCode::SUCCESS);
            }
            state.remove_catalog_source(name).await?;
            state
                .audit("cli", ACTOR_ROLE, "catalog-source-remove", name, "ok", None)
                .await?;
            println!("✓ \"{name}\" removed.");
            Ok(ExitCode::SUCCESS)
        }
    }
}
