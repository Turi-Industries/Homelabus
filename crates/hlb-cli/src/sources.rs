//! `hlb catalog source`: the third-party catalogs read beside the official one — a
//! directory, or a signed index served over HTTPS and kept in a cache beside the state.
//!
//! The network is here and nowhere below: `hlb_catalog::index` says whether what was
//! downloaded is what the source's key signed, and never fetches anything itself.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use hlb_catalog::{index, Catalog};
use hlb_state::{CatalogSource, SignedSource, State};
use hlb_types::index::{Index, FILE, SIGNATURE_FILE};

use crate::{open_state, Cli, SourceCmd, ACTOR_ROLE};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// The most one response may weigh. An index and an app's files are text: a source
/// serving more is broken or hostile, and is not given the disk to fill.
const MOST_BYTES: usize = 8 << 20;

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
    state
        .parent()
        .unwrap_or(Path::new("."))
        .join("catalog-sources")
        .join(name)
}

/// Whether `location` is an address, and the refusal if it is one not to fetch from.
/// Plain HTTP is accepted on this machine only — a mirror beside it, or a test: the
/// signature would catch a changed file, but not a network withholding the fresh index.
fn address(location: &str) -> Option<std::result::Result<String, String>> {
    if !location.contains("://") {
        return None;
    }
    let url = match reqwest::Url::parse(location) {
        Ok(u) => u,
        Err(e) => return Some(Err(format!("{location}: {e}"))),
    };
    let loopback = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    Some(match url.scheme() {
        "https" => Ok(location.trim_end_matches('/').to_string()),
        "http" if loopback => Ok(location.trim_end_matches('/').to_string()),
        _ => Err(format!(
            "{location}: a source is fetched over https:// (plain http only from this machine)"
        )),
    })
}

async fn get(client: &reqwest::Client, url: &str) -> std::result::Result<Vec<u8>, String> {
    let mut r = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("{url}: {e}"))?;
    if !r.status().is_success() {
        return Err(format!("{url}: HTTP {}", r.status().as_u16()));
    }
    let mut body = Vec::new();
    while let Some(chunk) = r.chunk().await.map_err(|e| format!("{url}: {e}"))? {
        body.extend_from_slice(&chunk);
        if body.len() > MOST_BYTES {
            return Err(format!("{url}: over {} MiB, refused", MOST_BYTES >> 20));
        }
    }
    Ok(body)
}

/// The signed index served under `url`, refused unless `key` signed it for `name` and
/// it is no older than `seen` — before a single file it names is downloaded.
async fn signed_index(
    client: &reqwest::Client,
    url: &str,
    name: &str,
    key: &str,
    seen: Option<u64>,
) -> std::result::Result<(Index, Vec<u8>, String), String> {
    let bytes = get(client, &format!("{url}/{FILE}")).await?;
    let sig = get(client, &format!("{url}/{SIGNATURE_FILE}")).await?;
    let sig = String::from_utf8_lossy(&sig).into_owned();
    let idx = index::accept(&bytes, &sig, name, key, seen).map_err(|e| e.to_string())?;
    Ok((idx, bytes, sig))
}

/// What a fetch did: the index read, and the files downloaded and kept.
struct Staged {
    index: Index,
    downloaded: usize,
    kept: usize,
}

/// Writes the index into `staged`, every file it names copied from `cache` when the
/// cache holds it already, downloaded otherwise. Nothing here is trusted yet:
/// `index::swap_in` checks it whole before it replaces the cache.
async fn stage(
    client: &reqwest::Client,
    url: &str,
    (idx, bytes, sig): (Index, Vec<u8>, String),
    cache: &Path,
    staged: &Path,
) -> std::result::Result<Staged, String> {
    let io = |p: &Path| {
        let p = p.display().to_string();
        move |e: std::io::Error| format!("{p}: {e}")
    };
    if staged.exists() {
        // A fetch that stopped halfway: nothing in it was ever read.
        std::fs::remove_dir_all(staged).map_err(io(staged))?;
    }
    std::fs::create_dir_all(staged).map_err(io(staged))?;
    std::fs::write(staged.join(FILE), &bytes).map_err(io(staged))?;
    std::fs::write(staged.join(SIGNATURE_FILE), &sig).map_err(io(staged))?;
    // A packaging fix is a new version directory whose files are mostly the last
    // one's: found by digest, not by path. `holds` reads each again, so the cache's
    // index, unverified here, can only point at a file, never vouch for one.
    let mut held = std::collections::HashMap::new();
    if let Ok(old) = index::read(&cache.join(FILE)) {
        for (rel, digest) in index::files(&old).unwrap_or_default() {
            held.entry(digest).or_insert(rel);
        }
    }
    let (mut downloaded, mut kept) = (0, 0);
    for (rel, digest) in index::files(&idx).map_err(|e| e.to_string())? {
        let to = staged.join(&rel);
        if let Some(parent) = to.parent() {
            std::fs::create_dir_all(parent).map_err(io(parent))?;
        }
        let from = [Some(&rel), held.get(&digest)]
            .into_iter()
            .flatten()
            .find(|r| index::holds(cache, r, &digest));
        if let Some(from) = from {
            std::fs::copy(cache.join(from), &to).map_err(io(&to))?;
            kept += 1;
        } else {
            let body = get(client, &format!("{url}/{rel}")).await?;
            std::fs::write(&to, body).map_err(io(&to))?;
            downloaded += 1;
        }
    }
    Ok(Staged {
        index: idx,
        downloaded,
        kept,
    })
}

fn client() -> std::result::Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .map_err(|e| e.to_string())
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
        Ok(f) => stage(&client, url, f, &cache, &staged).await,
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
    let Some(signed) = &src.signed else {
        return Ok(());
    };
    let (name, key, url) = (&src.name, &signed.key, &signed.url);
    let cache = PathBuf::from(&src.directory);
    let client = client()?;
    let fetched = signed_index(&client, url, name, key, signed.counter).await?;
    let counter = fetched.0.counter;
    let unchanged = Some(counter) == signed.counter
        && index::verify(&cache, name, key).is_ok_and(|held| held.counter == counter);
    let idx = if unchanged {
        println!("  {name}: index {counter}, already held");
        fetched.0
    } else {
        let staged = cache.with_extension("new");
        let swapped = match stage(&client, url, fetched, &cache, &staged).await {
            Ok(s) => index::swap_in(&staged, &cache, name, key)
                .map(|_| s)
                .map_err(|e| e.to_string()),
            Err(e) => Err(e),
        };
        // What did not verify is not left lying beside the cache.
        let s = swapped.inspect_err(|_| {
            let _ = std::fs::remove_dir_all(&staged);
        })?;
        state
            .raise_catalog_source_counter(name, counter)
            .await
            .map_err(|e| e.to_string())?;
        state
            .audit(
                "cli",
                ACTOR_ROLE,
                "catalog-source-fetch",
                name,
                "ok",
                Some(&format!("index {counter}")),
            )
            .await
            .map_err(|e| e.to_string())?;
        println!(
            "  ✓ {name}: index {counter}, {} downloaded, {} kept",
            hlb_api::plural(s.downloaded as u64, "file", "files"),
            s.kept
        );
        s.index
    };
    if let Err(e) = index::current(&idx, chrono::Utc::now().timestamp()) {
        // The newest it serves is stale: its owner has not signed another.
        println!(
            "  ⚠️  {name}: {e} — nothing new installs from it until its owner signs a fresh one"
        );
    } else {
        println!("    valid until {}", day(idx.expires));
    }
    // 🔴 A revoked version keeps running until someone moves it: said where the
    // revocation arrives, and every day after in the inbox.
    let e = |e: hlb_state::Error| e.to_string();
    for (app, _) in state.installed_apps().await.map_err(e)? {
        if state.app_source(&app).await.map_err(e)?.as_deref() != Some(name.as_str()) {
            continue;
        }
        let Some(version) = state.app_release(&app).await.map_err(e)?.version else {
            continue;
        };
        if let Some(why) = idx.revocation(&app, &version) {
            println!(
                "  🔴 \"{app}\" runs {version}, which {name} revoked: {why}\n     \
                 `hlb upgrade {app}` takes the newest version it still offers"
            );
        }
    }
    Ok(())
}
