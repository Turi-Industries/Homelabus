//! `hlb secrets-seal`: the vault's master key sealed to this machine
//! (`hlb_bootstrap::seal`), its path left as a link to the memory it is unsealed to.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use hlb_api::breakglass::EMERGENCY_KIT;
use hlb_bootstrap::provision::{self, Provision};
use hlb_bootstrap::seal::{self, Binding, Probe};
use hlb_bootstrap::{LocalRunner, Runner};
use hlb_secrets::Vault;

use crate::{open_state, open_vault, Cli, ACTOR_ROLE};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub async fn run(cli: &Cli, apply: bool) -> Result<ExitCode> {
    let state = open_state(cli).await?;
    let vault = open_vault(cli)?;
    // The link goes where the key is named, not where a link already there points.
    let key = std::path::absolute(&cli.master_key)?;

    if hlb_secrets::sealed_target(&key).is_some() && !apply {
        println!("✓ The master key is sealed to this machine:");
        println!("  {} → {}", key.display(), seal::UNSEALED);
        println!("  unsealed into memory at boot by {}.", seal::UNIT);
        return Ok(ExitCode::SUCCESS);
    }

    // 🔴 Sealed to a TPM, the key dies with the machine's board: the printed kit is
    // then its only copy, and one printed before today's material restores nothing.
    let now = hlb_backup_run::kit::fingerprint(&state, &vault).await?;
    if state.breakglass_note(EMERGENCY_KIT).await?.as_deref() != Some(now.as_str()) {
        eprintln!("🔴 No emergency kit printed with today's material: not sealed.");
        eprintln!("   Sealed to this machine, the key is lost with it; the kit is then the");
        eprintln!("   only copy. Print it, keep it away from the cluster, then run this again:");
        eprintln!("     hlb emergency kit");
        return Ok(ExitCode::FAILURE);
    }

    let runner = LocalRunner;
    if !runner
        .run(&["systemd-creds".into(), "--version".into()])
        .await?
        .ok()
    {
        eprintln!("🔴 This machine has no systemd-creds (systemd 250 or later): not sealed.");
        return Ok(ExitCode::FAILURE);
    }
    let os = runner
        .read_file("/etc/os-release")
        .await?
        .unwrap_or_default();
    let install_libraries = hlb_bootstrap::Distro::parse(&os)
        .map(|d| d.package_manager().install_command(&[seal::TPM_PACKAGE]));
    let mut probe = probe(&runner).await?;
    if probe == Probe::MissingLibraries {
        let Some(install) = install_libraries else {
            eprintln!("🔴 This machine has a TPM systemd cannot use, and its distribution");
            eprintln!(
                "   is not identified: install {} by hand, then run this again.",
                seal::TPM_PACKAGE
            );
            return Ok(ExitCode::FAILURE);
        };
        if !apply {
            println!("This machine has a TPM systemd cannot use yet: it lacks the TPM's");
            println!("libraries. Would install them first —");
            println!("  {}", install.join(" "));
            println!("— then seal the vault's master key with the TPM.\n\n  Re-run with --apply.");
            return Ok(ExitCode::SUCCESS);
        }
        println!("  install the TPM's libraries ({})", seal::TPM_PACKAGE);
        if !runner.run(&install).await?.ok() {
            eprintln!("🔴 installing {} failed: not sealed.", seal::TPM_PACKAGE);
            return Ok(ExitCode::FAILURE);
        }
        probe = self::probe(&runner).await?;
    }
    let Probe::Sealer(sealer) = probe else {
        eprintln!("🔴 the TPM is still unusable with its libraries installed: not sealed.");
        return Ok(ExitCode::FAILURE);
    };
    // Sealed again — after a rekey — the key is read through the link.
    let steps = Provision {
        steps: seal::steps(&key.to_string_lossy(), sealer),
        notes: Vec::new(),
    };

    if !apply {
        println!("Would seal the vault's master key to this machine, with");
        println!("  {}.\n", sealer.describe());
        for (i, s) in steps.steps.iter().enumerate() {
            println!("  {}. {}", i + 1, s.describe());
        }
        println!(
            "  {}. check the key unsealed is the vault's, then replace {} by a link to {}",
            steps.steps.len() + 1,
            key.display(),
            seal::UNSEALED
        );
        println!("\n  The key then lives in memory only, unsealed at each boot before Docker");
        println!("  starts. If it cannot be — a TPM replaced — `hlb` says so and the kit's");
        println!("  key, in a file named by HLB_MASTER_KEY, opens the vault.");
        println!("\n  Re-run with --apply.");
        return Ok(ExitCode::SUCCESS);
    }

    if let Err(e) = provision::execute(&runner, &steps, |s| println!("  {}", s.what)).await {
        eprintln!("🔴 {e}");
        eprintln!("   The key file is untouched.");
        return Ok(ExitCode::FAILURE);
    }

    // Nothing replaces the key file before the memory holds the same key.
    match Vault::open(seal::UNSEALED) {
        Ok(v) if v.public_key() == vault.public_key() => {}
        Ok(_) => {
            eprintln!(
                "🔴 {} holds another key: the key file is untouched.",
                seal::UNSEALED
            );
            return Ok(ExitCode::FAILURE);
        }
        Err(e) => {
            eprintln!("🔴 the key unsealed cannot be read ({e}): the key file is untouched.");
            return Ok(ExitCode::FAILURE);
        }
    }
    link_in_place(&key, Path::new(seal::UNSEALED))?;
    state
        .audit(
            "cli",
            ACTOR_ROLE,
            "secrets-seal",
            "vault",
            "ok",
            Some(sealer.as_str()),
        )
        .await?;

    println!("\n✓ Sealed with {}.", sealer.describe());
    println!("  {} → {}", key.display(), seal::UNSEALED);
    println!("\n⚠️  A controller already running holds the old file open until it restarts:");
    println!("     docker service update --force hlb-controller");
    println!("   The file's blocks stay on the disk until overwritten; only disk");
    println!("   encryption, or a rekey after sealing, makes an old image of it useless.");
    Ok(ExitCode::SUCCESS)
}

/// The driver, then each binding tried in turn: what this machine can seal with.
async fn probe(runner: &LocalRunner) -> Result<Probe> {
    let has = runner
        .run(&["systemd-creds".into(), "has-tpm2".into()])
        .await?;
    let driver = seal::has_driver(&has.stdout);
    let mut trials = Vec::new();
    if driver {
        for b in Binding::ALL {
            let o = runner.run(&seal::trial(b)).await?;
            let ok = o.ok();
            trials.push((b, if ok { Ok(()) } else { Err(o.stderr) }));
            if ok {
                break;
            }
        }
    }
    Ok(seal::decide(driver, &trials))
}

/// Replaces `key` by a link to `target` in one rename: interrupted, the key is either
/// the file it was or the link, never missing.
fn link_in_place(key: &Path, target: &Path) -> std::io::Result<()> {
    let mut staged = PathBuf::from(key);
    staged.set_extension("hlb-link");
    let _ = std::fs::remove_file(&staged);
    std::os::unix::fs::symlink(target, &staged)?;
    std::fs::rename(&staged, key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_key_file_becomes_the_link_in_one_rename() {
        let d = tempfile::tempdir().expect("temp dir");
        let key = d.path().join("hlb-master.key");
        let v = Vault::init(&key).expect("init");
        let memory = d.path().join("unsealed");
        std::fs::copy(&key, &memory).expect("copy");

        link_in_place(&key, &memory).expect("link");

        assert_eq!(std::fs::read_link(&key).expect("a link"), memory);
        let reopened = Vault::open(&key).expect("opens through the link");
        assert_eq!(reopened.public_key(), v.public_key());
        let left: Vec<_> = std::fs::read_dir(d.path())
            .expect("read dir")
            .map(|e| e.expect("entry").file_name())
            .collect();
        assert_eq!(left.len(), 2, "nothing staged left behind: {left:?}");
    }
}
