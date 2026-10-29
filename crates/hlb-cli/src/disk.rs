//! `hlb node bind-disk`: a node's encrypted disk opened at boot by its TPM AND one of
//! the house's Tangs (`hlb_bootstrap::disk`), the kit's recovery key enrolled, the
//! install passphrase taken out.

use std::process::ExitCode;

use hlb_backup_run::kit;
use hlb_bootstrap::disk::{self, Disk, Keys, Tang};
use hlb_bootstrap::protection::Tpm;
use hlb_bootstrap::provision::{self, Provision};
use hlb_bootstrap::Runner;
use hlb_orchestrator::Orchestrator;

use crate::{open_state, open_vault, Cli, ACTOR_ROLE};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// The one-time passphrase `hlb node preseed --encrypt` installs a node's disk under.
pub const INSTALL_PASSPHRASE_PREFIX: &str = "luks-install-";

#[allow(clippy::too_many_arguments)]
pub async fn run(
    cli: &Cli,
    orch: &impl Orchestrator,
    node: &str,
    host: Option<&str>,
    user: Option<&str>,
    port: Option<u16>,
    passphrase_stdin: bool,
    apply: bool,
) -> Result<ExitCode> {
    let state = open_state(cli).await?;
    let vault = open_vault(cli)?;
    let nodes = orch.nodes().await?;
    let Some(target) = nodes
        .iter()
        .find(|n| n.hostname == node || n.id == node)
        .cloned()
    else {
        eprintln!("🔴 no node \"{node}\" in the cluster — see `hlb cluster status`.");
        return Ok(ExitCode::FAILURE);
    };
    let mut others: Vec<String> = nodes
        .iter()
        .map(|n| n.hostname.clone())
        .filter(|n| *n != target.hostname)
        .collect();
    others.sort();
    // Decided 2026-10-29: until the VPS, the Tangs live on the house's other nodes.
    if others.is_empty() {
        eprintln!(
            "🔴 {} is the only node: no other machine of the house can hold",
            target.hostname
        );
        eprintln!("   its Tang, and a disk bound to its TPM alone opens for whoever carries");
        eprintln!("   the machine away. Refused until a second node, or the VPS's Tang.");
        return Ok(ExitCode::FAILURE);
    }

    let dir = tempfile::tempdir()?;
    let Some(runner) = crate::reach_node(
        &state,
        &vault,
        &target.hostname,
        host,
        user,
        port,
        dir.path(),
    )
    .await?
    else {
        eprintln!(
            "🔴 no SSH address recorded for {}: pass --host.",
            target.hostname
        );
        return Ok(ExitCode::FAILURE);
    };
    let runner = runner.as_ref();
    println!("Machine: {}\n", target.hostname);
    if !hlb_bootstrap::observe::is_root(runner).await? {
        eprintln!(
            "🔴 not root on {}: a disk's key slots are root's.",
            target.hostname
        );
        return Ok(ExitCode::FAILURE);
    }
    let signals = hlb_bootstrap::observe::protection(runner).await?;
    match signals.tpm {
        Tpm::Seals | Tpm::MissingLibraries => {}
        other => {
            eprintln!("🔴 its TPM cannot hold the binding ({other:?}): the disk would open with a");
            eprintln!(
                "   Tang alone, which answers whoever is in the house. Not done yet (level C)."
            );
            return Ok(ExitCode::FAILURE);
        }
    }
    let disk = match read_disk(runner).await? {
        Ok(d) => d,
        Err(why) => {
            eprintln!("🔴 {why}");
            return Ok(ExitCode::FAILURE);
        }
    };
    println!(
        "Disk: {} — {} key slot(s), {} Clevis binding(s)",
        disk.device,
        disk.keyslots,
        disk.bindings.len()
    );
    // Refused now rather than after the Tangs are installed for nothing.
    if let Err(why) = disk::plan(&disk, None, &[placeholder()]) {
        eprintln!("🔴 {why}");
        return Ok(ExitCode::FAILURE);
    }

    // 🔴 The recovery key is on the printed kit before any slot changes: once the
    // passphrase is out, it is the one way in when the TPM or the Tangs are gone.
    let (recovery, made) = kit::recovery_key(&state, &vault, &target.hostname).await?;
    if !crate::seal::kit_current(&state, &vault).await? {
        if made {
            println!("Its recovery key was just made, and is in the vault.");
        }
        eprintln!("🔴 No emergency kit printed with it: nothing is bound. Once the passphrase");
        eprintln!("   is out, the kit's key is the only way into this disk without its TPM.");
        eprintln!("   Print it, keep it away from the house, then run this again:");
        eprintln!("     hlb emergency kit");
        return Ok(ExitCode::FAILURE);
    }

    let mesh = crate::load_mesh(&state, &vault).await?;
    println!("\nTangs — one must answer for the disk to open alone:");
    let mut tangs = Vec::new();
    let mut tang_runners = Vec::new();
    for name in &others {
        let address = mesh.get(name).and_then(|p| {
            p.endpoint
                .as_deref()
                .map(endpoint_host)
                .or_else(|| p.ssh.as_deref().map(|s| crate::parse_ssh_target(s).0))
        });
        let Some(address) = address else {
            println!("  · {name}: no address on the house's network recorded — left out");
            continue;
        };
        let Some(r) = crate::reach_node(&state, &vault, name, None, None, None, dir.path()).await?
        else {
            println!("  · {name}: no SSH address recorded — left out");
            continue;
        };
        println!("  · {name}: {}", disk::tang_url(&address));
        tang_runners.push((name.clone(), address, r));
    }
    if tang_runners.is_empty() {
        eprintln!("🔴 no other node can be reached to hold a Tang: nothing is bound.");
        return Ok(ExitCode::FAILURE);
    }

    if !apply {
        let steps = disk::tang_steps();
        println!("\nWould make each of them a Tang, started by systemd before Docker:");
        for (i, s) in steps.iter().enumerate() {
            println!("  {}. {}", i + 1, s.describe());
        }
        println!("  {}. read its signing keys, to pin them", steps.len() + 1);
        let steps = disk::plan(&disk, None, &[placeholder()])?;
        println!("\nThen on {}:", target.hostname);
        for (i, s) in steps.iter().enumerate() {
            println!("  {}. {}", i + 1, s.what);
        }
        println!("\n  The kit's recovery key and the disk's passphrase reach it through");
        println!("  standard input into memory, never a command line.");
        // Level A's verified boot is step 5 of the plan; until then every node is here.
        println!("\n⚠️  Boot is not verified: whoever has the machine INSIDE the house, a Tang");
        println!("   answering, can still get a shell at boot. And after a power cut of");
        println!("   the whole house, the recovery key is typed on one node — the others open");
        println!("   as its Tang comes back.");
        println!("\n  Re-run with --apply.");
        return Ok(ExitCode::SUCCESS);
    }

    let passphrase = if passphrase_stdin {
        let mut p = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut p)?;
        Some(p.trim_end_matches(['\r', '\n']).to_string())
    } else {
        let name = format!("{INSTALL_PASSPHRASE_PREFIX}{}", target.hostname);
        match state.secret(&name).await? {
            Some(ct) => Some(vault.decrypt(&ct)?),
            None => None,
        }
    };

    for (name, address, r) in &tang_runners {
        println!("\n{name}:");
        let steps = Provision {
            steps: disk::tang_steps(),
            notes: Vec::new(),
        };
        if let Err(e) = provision::execute(r.as_ref(), &steps, |s| println!("  {}", s.what)).await {
            eprintln!("  ⚠️  not a Tang: {e}");
            continue;
        }
        let keys = r
            .run(&["sh".into(), "-c".into(), disk::TANG_READ_KEYS.into()])
            .await?;
        // One signing key, or the pin would name a key the next rotation drops.
        match disk::signing_thumbprints(&keys.stdout).as_slice() {
            [thp] => tangs.push(Tang {
                url: disk::tang_url(address),
                thp: thp.clone(),
            }),
            other => eprintln!(
                "  ⚠️  {} signing keys found, one expected: left out",
                other.len()
            ),
        }
    }
    if tangs.is_empty() {
        eprintln!("🔴 no Tang answered: nothing is bound.");
        return Ok(ExitCode::FAILURE);
    }

    println!("\n{}:", target.hostname);
    let outcome = bind(runner, &disk, &recovery, passphrase.as_deref(), &tangs).await;
    // Whatever happened, neither secret stays on the node.
    let _ = runner
        .run(&[
            "rm".into(),
            "-f".into(),
            disk::STAGED_PASSPHRASE.into(),
            disk::STAGED_RECOVERY.into(),
        ])
        .await;
    if let Err(e) = outcome {
        eprintln!("  🔴 {e}");
        eprintln!("     Run this again: what is done is skipped.");
        return Ok(ExitCode::FAILURE);
    }
    let detail = tangs
        .iter()
        .map(|t| t.url.as_str())
        .collect::<Vec<_>>()
        .join(" ");
    state
        .audit(
            "cli",
            ACTOR_ROLE,
            "node-bind-disk",
            &target.hostname,
            "ok",
            Some(&detail),
        )
        .await?;
    println!(
        "\n✓ {} opens at boot with its TPM and one of:",
        target.hostname
    );
    for t in &tangs {
        println!("    {}", t.url);
    }
    println!("  Otherwise, the recovery key printed on the kit under its name.");
    Ok(ExitCode::SUCCESS)
}

/// The secrets staged, tried, and the steps they leave run.
async fn bind(
    runner: &dyn Runner,
    disk: &Disk,
    recovery: &str,
    passphrase: Option<&str>,
    tangs: &[Tang],
) -> std::result::Result<(), String> {
    let e = |e: hlb_bootstrap::runner::Error| e.to_string();
    runner
        .write_file(disk::STAGED_RECOVERY, recovery)
        .await
        .map_err(e)?;
    let opens = |file: &str| {
        vec![
            "cryptsetup".to_string(),
            "open".into(),
            "--test-passphrase".into(),
            "--key-file".into(),
            file.into(),
            disk.device.clone(),
        ]
    };
    let recovery_opens = runner
        .run(&opens(disk::STAGED_RECOVERY))
        .await
        .map_err(e)?
        .ok();
    let passphrase_opens = match passphrase {
        Some(p) => {
            runner
                .write_file(disk::STAGED_PASSPHRASE, p)
                .await
                .map_err(e)?;
            runner
                .run(&opens(disk::STAGED_PASSPHRASE))
                .await
                .map_err(e)?
                .ok()
        }
        None => false,
    };
    if !recovery_opens && !passphrase_opens && passphrase.is_none() {
        return Err(format!(
            "the vault holds no install passphrase for this disk, and the recovery key does \
             not open it yet: give the disk's passphrase on standard input with \
             --passphrase-stdin ({})",
            disk.device
        ));
    }
    let keys = Keys {
        passphrase: passphrase_opens,
        recovery: recovery_opens,
    };
    let steps = Provision {
        steps: disk::plan(disk, Some(keys), tangs)?,
        notes: Vec::new(),
    };
    provision::execute(runner, &steps, |s| println!("  {}", s.what))
        .await
        .map_err(|e| e.to_string())
}

/// What the disk holds, read without a secret. `Ok(Err)` is a refusal.
async fn read_disk(runner: &dyn Runner) -> Result<std::result::Result<Disk, String>> {
    let crypttab = runner.read_file("/etc/crypttab").await?.unwrap_or_default();
    let device = match disk::device(&crypttab) {
        Ok(d) => d,
        Err(why) => return Ok(Err(why)),
    };
    let dump = runner
        .run(&[
            "cryptsetup".into(),
            "luksDump".into(),
            "--dump-json-metadata".into(),
            device.clone(),
        ])
        .await?;
    let Some(keyslots) = disk::parse_keyslots(&dump.stdout).filter(|_| dump.ok()) else {
        return Ok(Err(format!(
            "{device}'s LUKS header cannot be read (a LUKS1 disk, or an old cryptsetup): {}",
            dump.stderr.trim()
        )));
    };
    // Clevis absent lists nothing, though a binding may be there: its tokens say so.
    let list = runner
        .run(&[
            "clevis".into(),
            "luks".into(),
            "list".into(),
            "-d".into(),
            device.clone(),
        ])
        .await;
    let bindings = match list {
        Ok(o) if o.ok() => disk::parse_bindings(&o.stdout),
        _ if dump.stdout.contains("\"clevis\"") => {
            return Ok(Err(format!(
                "{device} carries a Clevis token and Clevis is not installed to read it: \
                 a binding Homelabus cannot see"
            )))
        }
        _ => Vec::new(),
    };
    Ok(Ok(Disk {
        device,
        keyslots,
        bindings,
    }))
}

/// `10.0.0.2:51820` → `10.0.0.2`; `[fd00::2]:51820` → `fd00::2`.
fn endpoint_host(endpoint: &str) -> String {
    if let Some(rest) = endpoint.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(rest).to_string();
    }
    match endpoint.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') && p.parse::<u16>().is_ok() => h.to_string(),
        _ => endpoint.to_string(),
    }
}

/// A Tang standing for those not read yet, in a preview.
fn placeholder() -> Tang {
    Tang {
        url: disk::tang_url("<node>"),
        thp: "<its thumbprint>".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_tang_is_reached_at_its_endpoint_host() {
        assert_eq!(endpoint_host("10.77.0.11:51820"), "10.77.0.11");
        assert_eq!(endpoint_host("[fd00::2]:51820"), "fd00::2");
        assert_eq!(endpoint_host("nas.lan"), "nas.lan");
    }
}
