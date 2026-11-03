//! `hlb catalog source`: the third-party catalogs read beside the official one — a
//! directory, or a signed index served over HTTPS and kept in a cache beside the state.
//!
//! The fetching itself is `hlb_engine::sources`', which the controller's nightly pass
//! runs too.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use hlb_catalog::{index, Catalog};
use hlb_engine::sources::{self, address, client, signed_index, stage};
use hlb_state::{CatalogSource, SignedSource, State};

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
fn add(c: &mut Catalog, src: &CatalogSource) -> std::result::Result<(), String> {
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

/// Where a fetched source is kept: beside the state, which privd and the controller
/// read from another working directory. Not under `catalog/`: in a checkout that is the
/// official catalog, and a source's cache would be read as an app of it.
fn cache_dir(cli: &Cli, name: &str) -> PathBuf {
    let state = std::path::absolute(&cli.state).unwrap_or_else(|_| cli.state.clone());
    hlb_state::source_cache(state.parent().unwrap_or(Path::new(".")), name)
}

fn day(at: i64) -> String {
    chrono::DateTime::from_timestamp(at, 0)
        .map(|d| d.format("%Y-%m-%d").to_string())
        .unwrap_or_else(|| at.to_string())
}

/// What a source adds to the official catalog, and what it sets aside, said before it
/// is added rather than at the first install.
fn show(c: &Catalog, name: &str) {
    let prefix = format!("{name}{}", hlb_catalog::SEPARATOR);
    for e in c.entries().filter(|e| e.source.as_deref() == Some(name)) {
        println!("  + {}", e.name());
    }
    for (app, why) in c.left_out().filter(|(a, _)| a.starts_with(&prefix)) {
        println!("  ✗ {app}: {why}");
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
                let name = &src.name;
                let at = match &src.signed {
                    Some(s) => s.url.clone(),
                    None => src.directory.clone(),
                };
                let mut c = Catalog::default();
                match add(&mut c, &src) {
                    Ok(()) => println!(
                        "  {name:<14} {at}  ({}, {} set aside)",
                        hlb_api::plural(c.len() as u64, "app", "apps"),
                        c.left_out().count()
                    ),
                    Err(e) => println!("  {name:<14} {at}  🔴 unreadable: {e}"),
                }
            }
            Ok(ExitCode::SUCCESS)
        }

        SourceCmd::Add {
            name,
            location,
            key,
            apply,
        } => {
            if name == hlb_catalog::OFFICIAL {
                eprintln!("🔴 {}", hlb_catalog::Error::Reserved);
                return Ok(ExitCode::FAILURE);
            }
            // Checked before the name becomes a path under the cache.
            if !hlb_catalog::is_source_name(name) {
                eprintln!(
                    "🔴 \"{name}\": a source's name is lower-case letters, digits and dashes"
                );
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
            match (address(location), key) {
                (None, None) => add_directory(cli, &state, name, location, *apply).await,
                (Some(Ok(url)), Some(key)) => {
                    add_signed(cli, &state, name, &url, key.trim(), *apply).await
                }
                (Some(Err(e)), _) => {
                    eprintln!("🔴 {e}");
                    Ok(ExitCode::FAILURE)
                }
                (Some(Ok(_)), None) => {
                    eprintln!(
                        "🔴 a source served over the network is held to its owner's key: \
                         give it with --key"
                    );
                    Ok(ExitCode::FAILURE)
                }
                (None, Some(_)) => {
                    eprintln!("🔴 a directory is read as it is, unsigned: --key is for an address");
                    Ok(ExitCode::FAILURE)
                }
            }
        }

        SourceCmd::Fetch { name } => {
            // The official source's row, from what this `hlb` carries: written here too,
            // so a house without the controller fetches it.
            let official = sources::Official::carried(cache_dir(cli, hlb_catalog::OFFICIAL));
            sources::ensure_official(&state, official.as_ref()).await?;
            let sources = state.catalog_sources().await?;
            let mut chosen: Vec<_> = sources
                .iter()
                .filter(|s| name.as_ref().is_none_or(|n| &s.name == n))
                .collect();
            if let Some(n) = name {
                match chosen.first() {
                    None => {
                        eprintln!("🔴 no source \"{n}\"");
                        return Ok(ExitCode::FAILURE);
                    }
                    Some(s) if s.signed.is_none() => {
                        eprintln!("🔴 \"{n}\" is a directory, read as it is: nothing to fetch");
                        return Ok(ExitCode::FAILURE);
                    }
                    Some(_) => {}
                }
            }
            chosen.retain(|s| s.signed.is_some());
            if chosen.is_empty() {
                println!("No source served over the network.");
            }
            let mut failed = false;
            for src in chosen {
                if let Err(e) = fetch(&state, src).await {
                    // One source unreachable never keeps the others stale.
                    eprintln!("🔴 {}: {}", src.name, e.trim_start_matches("🔴 "));
                    failed = true;
                }
            }
            Ok(if failed {
                ExitCode::FAILURE
            } else {
                ExitCode::SUCCESS
            })
        }

        SourceCmd::Remove { name, apply } => {
            if name == hlb_catalog::OFFICIAL {
                // Its row is written again from the binary at the next fetch: removed,
                // only the replay bar its counter holds would go.
                eprintln!(
                    "🔴 the official catalog is not removed: it is what this hlb carries, \
                     read whatever is added beside it"
                );
                return Ok(ExitCode::FAILURE);
            }
            let Some(src) = state
                .catalog_sources()
                .await?
                .into_iter()
                .find(|s| &s.name == name)
            else {
                eprintln!("🔴 no source \"{name}\"");
                return Ok(ExitCode::FAILURE);
            };
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
            if src.signed.is_some() {
                println!("Its cache, {}, is deleted with it.", src.directory);
            }
            if !*apply {
                println!("Preview: nothing removed. Run again with --apply.");
                return Ok(ExitCode::SUCCESS);
            }
            state.remove_catalog_source(name).await?;
            // Only a fetched source's cache, which hlb wrote: a directory added is the
            // owner's, and stays.
            if src.signed.is_some() && Path::new(&src.directory).exists() {
                std::fs::remove_dir_all(&src.directory)?;
            }
            state
                .audit("cli", ACTOR_ROLE, "catalog-source-remove", name, "ok", None)
                .await?;
            println!("✓ \"{name}\" removed.");
            Ok(ExitCode::SUCCESS)
        }
    }
}

async fn add_directory(
    cli: &Cli,
    state: &State,
    name: &str,
    directory: &str,
    apply: bool,
) -> Result<ExitCode> {
    // Stored absolute: the controller and privd read it from another directory.
    let dir = match std::fs::canonicalize(directory) {
        Ok(d) => d.display().to_string(),
        Err(e) => {
            eprintln!("🔴 {directory}: {e}");
            return Ok(ExitCode::FAILURE);
        }
    };
    let mut c = Catalog::load(&cli.catalog)?;
    if let Err(e) = c.add_source(name, &dir) {
        eprintln!("🔴 {e}");
        return Ok(ExitCode::FAILURE);
    }
    show(&c, name);
    if !apply {
        println!("\nPreview: nothing added. Run again with --apply.");
        return Ok(ExitCode::SUCCESS);
    }
    state
        .add_catalog_source(&CatalogSource {
            name: name.to_string(),
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

/// A source served over the network. Its index and files are downloaded even for a
/// preview — reading changes nothing — so what it would add is said from what it serves.
async fn add_signed(
    cli: &Cli,
    state: &State,
    name: &str,
    url: &str,
    key: &str,
    apply: bool,
) -> Result<ExitCode> {
    let cache = cache_dir(cli, name);
    let staged = cache.with_extension("new");
    let client = client()?;
    let fetched = match signed_index(&client, url, name, key, None).await {
        Ok(f) => stage(&client, url, key, f, &cache, &staged).await,
        Err(e) => Err(e),
    };
    let staged_ok = match fetched {
        Ok(s) => s,
        Err(e) => {
            eprintln!("🔴 {}", e.trim_start_matches("🔴 "));
            return Ok(ExitCode::FAILURE);
        }
    };
    let mut c = Catalog::load(&cli.catalog)?;
    let read = c.add_signed_source(name, &staged, key, chrono::Utc::now().timestamp());
    if let Err(e) = read {
        let _ = std::fs::remove_dir_all(&staged);
        eprintln!("🔴 {e}");
        return Ok(ExitCode::FAILURE);
    }
    let idx = &staged_ok.index;
    println!(
        "Index {} of \"{name}\", valid until {}:",
        idx.counter,
        day(idx.expires)
    );
    if let Err(e) = &staged_ok.quality {
        println!("  ⚠️  its quality file is left out: {e}");
    }
    show(&c, name);
    if !apply {
        std::fs::remove_dir_all(&staged)?;
        println!("\nPreview: nothing added. Run again with --apply.");
        return Ok(ExitCode::SUCCESS);
    }
    index::swap_in(&staged, &cache, name, key)?;
    let directory = cache.display().to_string();
    state
        .add_catalog_source(&CatalogSource {
            name: name.to_string(),
            directory: directory.clone(),
            signed: Some(SignedSource {
                url: url.to_string(),
                key: key.to_string(),
                counter: None,
            }),
        })
        .await?;
    state
        .raise_catalog_source_counter(name, idx.counter)
        .await?;
    state
        .audit(
            "cli",
            ACTOR_ROLE,
            "catalog-source-add",
            name,
            "ok",
            Some(&format!("{url}, index {}", idx.counter)),
        )
        .await?;
    println!(
        "\n✓ \"{name}\" added, kept in {directory}: its apps install as `hlb install \
         {name}/<app>`, and `hlb catalog source fetch {name}` brings its next index."
    );
    Ok(ExitCode::SUCCESS)
}

/// Brings a source's cache to the index it serves now. The cache is replaced only once
/// the new one verifies whole, so a fetch that fails leaves the source as it was.
async fn fetch(state: &State, src: &CatalogSource) -> std::result::Result<(), String> {
    let Some(f) = sources::fetch(state, src, "cli", ACTOR_ROLE).await? else {
        return Ok(());
    };
    let (name, counter) = (&src.name, f.index.counter);
    match f.files {
        None => println!("  {name}: index {counter}, already held"),
        Some((downloaded, kept)) => println!(
            "  ✓ {name}: index {counter}, {} downloaded, {kept} kept",
            hlb_api::plural(downloaded as u64, "file", "files"),
        ),
    }
    if let Some(e) = &f.quality_refused {
        println!("  ⚠️  {name}: its quality file is left out: {e}");
    }
    if let Err(e) = index::current(&f.index, chrono::Utc::now().timestamp()) {
        // The newest it serves is stale: its owner has not signed another.
        println!(
            "  ⚠️  {name}: {e} — nothing new installs from it until its owner signs a fresh one"
        );
    } else {
        println!("    valid until {}", day(f.index.expires));
    }
    for (app, version, why) in &f.revoked {
        println!(
            "  🔴 \"{app}\" runs {version}, which {name} revoked: {why}\n     \
             `hlb upgrade {app}` takes the newest version it still offers"
        );
    }
    Ok(())
}
