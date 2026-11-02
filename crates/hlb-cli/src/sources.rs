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
    for src in state.catalog_sources().await? {
        if let Err(e) = add(&mut c, &src) {
            eprintln!(
                "⚠️  catalog source \"{}\" ({}) left out: {e}",
                src.name, src.directory
            );
        }
    }
    Ok(c)
}

/// One source into `c` — a fetched one held to its key again each time it is read.
fn add(c: &mut Catalog, src: &hlb_state::CatalogSource) -> std::result::Result<(), String> {
    match &src.signed {
        Some(signed) => c
            .add_signed_source(
                &src.name,
                &src.directory,
                &signed.key,
                chrono::Utc::now().timestamp(),
            )
            .map_err(|e| e.to_string()),
        None => c
            .add_source(&src.name, &src.directory)
            .map_err(|e| e.to_string()),
    }
}

pub async fn run(cli: &Cli, cmd: &SourceCmd) -> Result<ExitCode> {
    let state = open_state(cli).await?;
    match cmd {
        SourceCmd::List => {
            let sources = state.catalog_sources().await?;
            if sources.is_empty() {
                println!("No source beside the official catalog.");
            }
            for src in sources {
                let (name, dir) = (&src.name, &src.directory);
                let mut c = Catalog::default();
                match add(&mut c, &src) {
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
                .any(|s| &s.name == name)
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
            state
                .add_catalog_source(&hlb_state::CatalogSource {
                    name: name.clone(),
                    directory: dir.clone(),
                    signed: None,
                })
                .await?;
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
                .any(|s| &s.name == name)
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
