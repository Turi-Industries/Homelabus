//! `hlb catalog key` and `hlb catalog index`: a source's signing key, and the signed
//! index it publishes (`hlb_catalog::index`). Files only — no installation is read.

use std::path::Path;
use std::process::ExitCode;

use hlb_catalog::index;

use crate::{IndexCmd, KeyCmd};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

/// The passphrase, from the terminal unechoed — or stdin's first line, for a script.
fn passphrase(stdin: bool, prompt: &str) -> Result<String> {
    if stdin {
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        return Ok(line.trim_end_matches(['\r', '\n']).to_string());
    }
    Ok(rpassword::prompt_password(prompt)?)
}

/// The seed a key file holds, opened with its passphrase.
fn open_key(path: &Path, stdin: bool) -> Result<[u8; 32]> {
    let sealed = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let pass = passphrase(stdin, "Passphrase of the signing key: ")?;
    let seed = hlb_secrets::open_with_passphrase(&sealed, &pass)?;
    Ok(<[u8; 32]>::try_from(seed.as_slice())
        .map_err(|_| format!("{}: not a signing key", path.display()))?)
}

pub fn key(cmd: &KeyCmd) -> Result<ExitCode> {
    match cmd {
        KeyCmd::Generate {
            file,
            passphrase_stdin,
        } => {
            // Overwritten, the key that signed the published index is gone, and every
            // installation trusting it refuses the next one.
            if file.exists() {
                eprintln!("🔴 {} exists — a key is never overwritten", file.display());
                return Ok(ExitCode::FAILURE);
            }
            let pass = passphrase(*passphrase_stdin, "Passphrase for the new key: ")?;
            if !*passphrase_stdin && pass != passphrase(false, "Again: ")? {
                eprintln!("🔴 the two passphrases differ");
                return Ok(ExitCode::FAILURE);
            }
            if pass.chars().count() < 12 {
                eprintln!("🔴 12 characters at least: the file is all that stands between a copy and a signed catalog");
                return Ok(ExitCode::FAILURE);
            }
            let mut seed = [0u8; 32];
            hlb_secrets::fill_random(&mut seed);
            let sealed = hlb_secrets::seal_with_passphrase(&seed, &pass)?;
            hlb_secrets::write_private_file(file, &sealed, false)?;
            println!("✓ signing key written to {} (0600)", file.display());
            println!("  public key: {}", index::public_key(&seed));
            println!("  Keep a copy offline: lost, every installation must be given a new public key by hand.");
            Ok(ExitCode::SUCCESS)
        }
    }
}

pub fn run(cmd: &IndexCmd) -> Result<ExitCode> {
    match cmd {
        IndexCmd::Build {
            catalog,
            out,
            source,
            previous,
        } => {
            let idx = index::build(catalog, source, previous.as_deref(), out, now())?;
            let versions: usize = idx.apps.values().map(Vec::len).sum();
            println!(
                "✓ index {} of \"{source}\" built in {}: {}, {versions} versions, expiring {}",
                idx.counter,
                out.display(),
                hlb_api::plural(idx.apps.len() as u64, "app", "apps"),
                expiry(idx.expires)
            );
            println!(
                "  Not signed: `hlb catalog index sign {} --key <file>`.",
                out.display()
            );
            Ok(ExitCode::SUCCESS)
        }

        IndexCmd::Sign {
            dir,
            key,
            published,
            first,
            passphrase_stdin,
        } => {
            // The published index is what a replay is judged against: signing without
            // it must be said, never the default.
            let published = match (published, first) {
                (Some(p), false) => Some(index::read(p)?),
                (None, true) => None,
                _ => {
                    eprintln!(
                        "🔴 give the index the source serves today (--published <index.json>), \
                         or --first for a source that has published none"
                    );
                    return Ok(ExitCode::FAILURE);
                }
            };
            let seed = open_key(key, *passphrase_stdin)?;
            let idx = index::sign(dir, &seed, published.as_ref(), now())?;
            println!(
                "✓ index {} of \"{}\" signed by {}, expiring {}",
                idx.counter,
                idx.source,
                index::public_key(&seed),
                expiry(idx.expires)
            );
            Ok(ExitCode::SUCCESS)
        }

        IndexCmd::Verify { dir, source, key } => {
            let idx = index::verify(dir, source, key)?;
            let versions: usize = idx.apps.values().map(Vec::len).sum();
            println!(
                "✓ index {} of \"{source}\": signed by that key, {} and {versions} versions as signed",
                idx.counter,
                hlb_api::plural(idx.apps.len() as u64, "app", "apps"),
            );
            match index::current(&idx, now()) {
                Ok(()) => println!("  current until {}", expiry(idx.expires)),
                Err(e) => {
                    println!("  🔴 {e}: nothing new is installed from it");
                    return Ok(ExitCode::FAILURE);
                }
            }
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn expiry(at: i64) -> String {
    chrono::DateTime::from_timestamp(at, 0)
        .map(|d| d.format("%Y-%m-%d %H:%M UTC").to_string())
        .unwrap_or_else(|| at.to_string())
}
