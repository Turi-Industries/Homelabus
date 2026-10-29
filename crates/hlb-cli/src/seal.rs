//! `hlb secrets-seal`: the vault's master key sealed to this machine
//! (`hlb_bootstrap::seal`), its path left as a link to the memory it is unsealed to. And
//! `hlb cluster autolock`, whose unlock key is sealed the same way
//! (`hlb_bootstrap::unlock`).

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use hlb_api::breakglass::EMERGENCY_KIT;
use hlb_backup_run::kit::SWARM_UNLOCK_SECRET;
use hlb_bootstrap::provision::{self, Provision};
use hlb_bootstrap::seal::{self, Binding, Probe, Sealer};
use hlb_bootstrap::{unlock, LocalRunner, Runner};
use hlb_orchestrator::cluster::NodeRole;
use hlb_orchestrator::Orchestrator;
use hlb_secrets::Vault;
use hlb_state::State;

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
    if !kit_is_current(&state, &vault).await? {
        return Ok(ExitCode::FAILURE);
    }
    let runner = LocalRunner;
    let sealer = match sealer(&runner, apply, "the vault's master key").await? {
        Ready::Sealer(s) => s,
        Ready::Previewed => return Ok(ExitCode::SUCCESS),
        Ready::Refused => return Ok(ExitCode::FAILURE),
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

/// `hlb cluster autolock`: Swarm's Raft log encrypted at rest, its key in the vault and
/// on the kit, then sealed to each manager — this one directly, the others over the SSH
/// address the mesh recorded — so a restart unlocks it alone.
pub async fn autolock(cli: &Cli, orch: &impl Orchestrator, apply: bool) -> Result<ExitCode> {
    let state = open_state(cli).await?;

    if !orch.autolock_enabled().await? {
        if !apply {
            println!("Would enable encryption at rest for Swarm secrets.");
            println!();
            println!("  What it changes: after a restart, every manager demands the unlock");
            println!("  key before starting again. Run this again once it is on, the kit");
            println!("  printed with the key: it seals the key to each manager, which then");
            println!("  unlocks itself after each start of Docker.");
            println!();
            println!("  🔴 The key goes to the vault and onto the emergency kit. If both");
            println!("  disappear with the machine, the cluster is not recovered.");
            println!();
            println!("  Re-run with --apply.");
            return Ok(ExitCode::SUCCESS);
        }
        let key = orch.enable_autolock().await?;
        let vault = open_vault(cli)?;
        let ct = vault.encrypt(&key)?;
        state
            .store_secret_if_absent(SWARM_UNLOCK_SECRET, &ct, "Swarm unlock after restart")
            .await?;
        state
            .audit("cli", ACTOR_ROLE, "cluster-autolock", "swarm", "ok", None)
            .await?;
        println!("✓ Autolock active. Key recorded in the vault.");
        println!();
        println!("  Until it is sealed, a restarted manager waits for `docker swarm unlock`.");
        println!("  The emergency kit does not hold the key yet: print it, keep it away from");
        println!("  the cluster, then seal the key to each manager:");
        println!("    hlb emergency kit");
        println!("    hlb cluster autolock --apply");
        return Ok(ExitCode::SUCCESS);
    }

    let Some(ct) = state.secret(SWARM_UNLOCK_SECRET).await? else {
        // 🔴 The worst possible state: encrypted, but the key is nowhere. On the next
        // full restart the cluster stays locked and its secrets are lost for good.
        println!("✓ Autolock is already active.");
        println!();
        println!("🔴 But the unlock key is NOT in the vault.");
        println!("   Retrieve it now and keep it offline:");
        println!("     docker swarm unlock-key");
        return Ok(ExitCode::FAILURE);
    };
    let vault = open_vault(cli)?;
    let key = vault.decrypt(&ct)?;
    let mut managers: Vec<String> = orch
        .nodes()
        .await?
        .into_iter()
        .filter(|n| n.role == NodeRole::Manager)
        .map(|n| n.hostname)
        .collect();
    managers.sort();
    let here = crate::local_hostname().await;
    // The cluster's SSH key only when a manager is elsewhere: it is made on first use.
    let mut reach = None;
    if managers.iter().any(|m| *m != here) {
        let kp = crate::cluster_ssh_key(&state, &vault).await?;
        let dir = tempfile::tempdir()?;
        let path = crate::write_temporary_key(dir.path(), &kp.private)?;
        reach = Some((crate::load_mesh(&state, &vault).await?, dir, path));
    }

    // Each manager's credential dies with its board: the kit holds the copy that does not.
    let mut kit = None;
    let mut failed = false;
    let mut to_apply = false;
    for m in &managers {
        println!("{m}:");
        let runner: Box<dyn Runner> = if *m == here {
            Box::new(LocalRunner)
        } else {
            let recorded = reach.as_ref().and_then(|(mesh, _, path)| {
                let (h, u, p) = crate::parse_ssh_target(mesh.get(m)?.ssh.as_ref()?);
                Some(crate::build_runner(
                    Some(&h),
                    u.as_deref(),
                    p,
                    path.to_str(),
                ))
            });
            let Some(r) = recorded else {
                // Joined by hand: nothing says how to reach it.
                println!("  ⚠️  no SSH address recorded: not sealed. After a restart it waits for");
                println!("     `docker swarm unlock` and the kit's key.");
                continue;
            };
            r
        };
        // One manager out of reach leaves the others to seal.
        let sealing = match seal_unlock(&*runner, &key, apply, &mut kit, &state, &vault).await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("  🔴 {e}");
                failed = true;
                continue;
            }
        };
        match sealing {
            Sealing::Sealed => println!("  ✓ sealed: it unlocks itself after each start of Docker"),
            Sealing::Would => to_apply = true,
            Sealing::Done(sealer) => {
                state
                    .audit(
                        "cli",
                        ACTOR_ROLE,
                        "swarm-unlock-seal",
                        m,
                        "ok",
                        Some(sealer.as_str()),
                    )
                    .await?;
                println!("  ✓ sealed with {}", sealer.as_str());
            }
            Sealing::Refused => failed = true,
        }
    }
    if failed {
        return Ok(ExitCode::FAILURE);
    }
    if to_apply {
        println!(
            "\nAfter each start of Docker, {} hands the key to `docker swarm",
            unlock::UNIT
        );
        println!("unlock`. If it cannot be unsealed — a TPM replaced — the manager waits for that");
        println!("command, the kit's key on its standard input.\n\n  Re-run with --apply.");
    }
    Ok(ExitCode::SUCCESS)
}

enum Sealing {
    /// Already: with `--apply` it is sealed again all the same.
    Sealed,
    /// Previewed.
    Would,
    Done(Sealer),
    /// Said why.
    Refused,
}

/// Swarm's unlock key sealed to the manager `runner` reaches.
async fn seal_unlock(
    runner: &dyn Runner,
    key: &str,
    apply: bool,
    kit: &mut Option<bool>,
    state: &State,
    vault: &Vault,
) -> Result<Sealing> {
    // A key rotated by hand leaves the vault's stale: sealed, it would unlock nothing.
    let live = runner
        .run(&[
            "docker".into(),
            "swarm".into(),
            "unlock-key".into(),
            "-q".into(),
        ])
        .await?;
    if live.stdout.trim() != key.trim() {
        eprintln!("  🔴 the vault's unlock key is not the Swarm's — rotated by hand? Not sealed.");
        eprintln!("     Put the live one in the vault, print the kit, then run this again:");
        eprintln!(
            "       docker swarm unlock-key -q | hlb secret-set {SWARM_UNLOCK_SECRET} --rotate"
        );
        return Ok(Sealing::Refused);
    }
    let sealed = runner
        .run(&["test".into(), "-f".into(), unlock::CREDENTIAL.into()])
        .await?
        .ok();
    if sealed && !apply {
        return Ok(Sealing::Sealed);
    }
    // Asked once: a stale kit is said once, and refuses every manager.
    let current = match *kit {
        Some(c) => c,
        None => *kit.insert(kit_is_current(state, vault).await?),
    };
    if !current {
        return Ok(Sealing::Refused);
    }
    let sealer = match self::sealer(runner, apply, "Swarm's unlock key").await? {
        Ready::Sealer(s) => s,
        Ready::Previewed => return Ok(Sealing::Would),
        Ready::Refused => return Ok(Sealing::Refused),
    };
    let steps = Provision {
        steps: unlock::steps(sealer),
        notes: Vec::new(),
    };
    if !apply {
        println!("  would seal its unlock key with {}.", sealer.describe());
        println!(
            "  0. the key, from the vault, into {} (memory)",
            unlock::STAGED
        );
        for (i, s) in steps.steps.iter().enumerate() {
            println!("  {}. {}", i + 1, s.describe());
        }
        return Ok(Sealing::Would);
    }
    runner.write_file(unlock::STAGED, key).await?;
    let done = provision::execute(runner, &steps, |s| println!("  {}", s.what)).await;
    // Whatever failed, the key leaves no copy outside the vault and its credential.
    let _ = runner
        .run(&["rm".into(), "-f".into(), unlock::STAGED.into()])
        .await;
    if let Err(e) = done {
        eprintln!("  🔴 {e}");
        return Ok(Sealing::Refused);
    }
    Ok(Sealing::Done(sealer))
}

/// Is the kit in the drawer the one printed with today's material? Says why not.
async fn kit_is_current(state: &State, vault: &Vault) -> Result<bool> {
    let now = hlb_backup_run::kit::fingerprint(state, vault).await?;
    if state.breakglass_note(EMERGENCY_KIT).await?.as_deref() == Some(now.as_str()) {
        return Ok(true);
    }
    eprintln!("🔴 No emergency kit printed with today's material: not sealed.");
    eprintln!("   Sealed to this machine, the key is lost with it; the kit is then the");
    eprintln!("   only copy. Print it, keep it away from the cluster, then run this again:");
    eprintln!("     hlb emergency kit");
    Ok(false)
}

enum Ready {
    Sealer(Sealer),
    /// Its TPM's libraries would be installed first: said.
    Previewed,
    /// Said why.
    Refused,
}

/// What this machine can seal `what` with — its TPM's libraries installed first, with
/// `apply`, when systemd lacks them.
async fn sealer(runner: &dyn Runner, apply: bool, what: &str) -> Result<Ready> {
    if !runner
        .run(&["systemd-creds".into(), "--version".into()])
        .await?
        .ok()
    {
        eprintln!("🔴 This machine has no systemd-creds (systemd 250 or later): not sealed.");
        return Ok(Ready::Refused);
    }
    let os = runner
        .read_file("/etc/os-release")
        .await?
        .unwrap_or_default();
    let install_libraries = hlb_bootstrap::Distro::parse(&os)
        .map(|d| d.package_manager().install_command(&[seal::TPM_PACKAGE]));
    let mut probe = probe(runner).await?;
    if probe == Probe::MissingLibraries {
        let Some(install) = install_libraries else {
            eprintln!("🔴 This machine has a TPM systemd cannot use, and its distribution");
            eprintln!(
                "   is not identified: install {} by hand, then run this again.",
                seal::TPM_PACKAGE
            );
            return Ok(Ready::Refused);
        };
        if !apply {
            println!("This machine has a TPM systemd cannot use yet: it lacks the TPM's");
            println!("libraries. Would install them first —");
            println!("  {}", install.join(" "));
            println!("— then seal {what} with the TPM.\n\n  Re-run with --apply.");
            return Ok(Ready::Previewed);
        }
        println!("  install the TPM's libraries ({})", seal::TPM_PACKAGE);
        if !runner.run(&install).await?.ok() {
            eprintln!("🔴 installing {} failed: not sealed.", seal::TPM_PACKAGE);
            return Ok(Ready::Refused);
        }
        probe = self::probe(runner).await?;
    }
    match probe {
        Probe::Sealer(s) => Ok(Ready::Sealer(s)),
        Probe::MissingLibraries => {
            eprintln!("🔴 the TPM is still unusable with its libraries installed: not sealed.");
            Ok(Ready::Refused)
        }
    }
}

/// The driver, then each binding tried in turn: what this machine can seal with.
async fn probe(runner: &dyn Runner) -> Result<Probe> {
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
