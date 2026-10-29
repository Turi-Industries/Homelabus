//! `hlb node verify-boot`: level A on a node `bind-disk` bound — a kernel image signed by
//! a key of its own, the disk resealed to the PCRs it boots with (`hlb_bootstrap::boot`).
//!
//! Four visits, each read from the node rather than remembered: the key made and handed
//! to shim, its enrolment at the console, the UKI installed and booted once, the disk
//! sealed to that boot. A person is needed twice — at the console for the key, and for
//! the one boot whose PCR 7 nothing could predict, opened by the kit's key.

use std::process::ExitCode;

use hlb_backup_run::kit;
use hlb_bootstrap::boot::{self, Stage};
use hlb_bootstrap::disk;
use hlb_bootstrap::protection::{Tpm, Virt, SYSTEMD_FOR_A};
use hlb_bootstrap::provision::{self, Provision, Step};
use hlb_bootstrap::Runner;
use hlb_orchestrator::Orchestrator;

use crate::{open_state, open_vault, Cli, ACTOR_ROLE};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// The one-time password MokManager asks for, until the key is enrolled.
pub const MOK_PASSWORD_PREFIX: &str = "mok-enrolment-";

#[allow(clippy::too_many_arguments)]
pub async fn run(
    cli: &Cli,
    orch: &impl Orchestrator,
    node: &str,
    host: Option<&str>,
    user: Option<&str>,
    port: Option<u16>,
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
    let name = target.hostname.as_str();
    let dir = tempfile::tempdir()?;
    let Some(runner) =
        crate::reach_node(&state, &vault, name, host, user, port, dir.path()).await?
    else {
        eprintln!("🔴 no SSH address recorded for {name}: pass --host.");
        return Ok(ExitCode::FAILURE);
    };
    let runner = runner.as_ref();
    println!("Machine: {name}\n");
    if !hlb_bootstrap::observe::is_root(runner).await? {
        eprintln!("🔴 not root on {name}: the boot chain and the disk's slots are root's.");
        return Ok(ExitCode::FAILURE);
    }

    // The signals, not the assessed level: a VM reads D by design and still runs all of
    // this, which is how it is proven on the lab.
    let signals = hlb_bootstrap::observe::protection(runner).await?;
    let mut missing = Vec::new();
    if !signals.uefi {
        missing.push("a legacy BIOS: shim and a signed kernel need UEFI".to_string());
    }
    if signals.uefi && signals.secure_boot != Some(true) {
        missing.push("Secure Boot is not on: an unsigned kernel would boot as well".into());
    }
    if !matches!(signals.tpm, Tpm::Seals | Tpm::MissingLibraries) {
        missing.push(format!(
            "its TPM cannot hold the binding ({:?})",
            signals.tpm
        ));
    }
    match signals.systemd {
        Some(v) if v >= SYSTEMD_FOR_A => {}
        v => missing.push(format!(
            "systemd {}: no `ukify` to build the kernel image — {SYSTEMD_FOR_A} has it \
             (Debian 13)",
            v.map_or_else(|| "unknown".to_string(), |v| v.to_string())
        )),
    }
    if !missing.is_empty() {
        eprintln!("🔴 {name} cannot reach level A:");
        for m in &missing {
            eprintln!("   · {m}");
        }
        return Ok(ExitCode::FAILURE);
    }
    if let Virt::Virtual(kind) = &signals.virt {
        println!("⚠️  A virtual machine ({kind}): its boot verified, its host still reads its");
        println!("   memory and its TPM — it stays level D.\n");
    }

    let disk = match crate::disk::read_disk(runner).await? {
        Ok(d) => d,
        Err(why) => {
            eprintln!("🔴 {why}");
            return Ok(ExitCode::FAILURE);
        }
    };
    if let Some(why) = boot::refusal(&disk) {
        eprintln!("🔴 {why}");
        return Ok(ExitCode::FAILURE);
    }
    // Its Tangs are the binding's: `bind-disk` pinned them, and moves them.
    let Some(tangs) = disk.bindings.iter().find_map(|b| b.tangs.clone()) else {
        eprintln!("🔴 the disk is not bound to its TPM AND a Tang: `hlb node bind-disk` first.");
        return Ok(ExitCode::FAILURE);
    };

    let exists = |path: &'static str| async move {
        runner
            .run(&["test".into(), "-e".into(), path.into()])
            .await
            .map(|o| o.ok())
    };
    let mok = if exists(boot::MOK_DER).await? {
        let out = runner
            .run(&["mokutil".into(), "--test-key".into(), boot::MOK_DER.into()])
            .await?;
        match boot::parse_mok(&out.stdout) {
            Some(m) => Some(m),
            None => {
                eprintln!(
                    "🔴 shim's view of the boot key cannot be read: {}",
                    out.stderr.trim()
                );
                return Ok(ExitCode::FAILURE);
            }
        }
    } else {
        None
    };
    let uki_booted = exists(boot::STUB_INFO).await?;
    let stage = boot::stage(mok, uki_booted);
    let password_name = format!("{MOK_PASSWORD_PREFIX}{name}");

    match stage {
        Stage::Key => {
            println!("Stage 1 of 4: a boot key of its own, for shim to trust.");
            let steps = boot::key_steps(name);
            if !apply {
                preview(&steps);
                println!("\n  Then, at its console, the next boot asks for a one-time password");
                println!("  shown at --apply. Re-run with --apply.");
                return Ok(ExitCode::SUCCESS);
            }
            let password = match state.secret(&password_name).await? {
                Some(ct) => vault.decrypt(&ct)?,
                None => {
                    let mut random = [0u8; 64];
                    hlb_secrets::fill_random(&mut random);
                    let p = boot::enrolment_password(&random)
                        .ok_or("too few random bytes for the enrolment password")?;
                    let purpose = format!("one-time MOK enrolment password of {name}");
                    state
                        .store_secret_if_absent(&password_name, &vault.encrypt(&p)?, &purpose)
                        .await?;
                    p
                }
            };
            runner
                .write_file(boot::STAGED_MOK_PASSWORD, &password)
                .await?;
            let outcome = execute(runner, steps).await;
            let _ = runner
                .run(&[
                    "rm".into(),
                    "-f".into(),
                    boot::STAGED_MOK_PASSWORD.into(),
                    boot::STAGED_MOK_HASH.into(),
                ])
                .await;
            if let Err(e) = outcome {
                eprintln!("  🔴 {e}");
                eprintln!("     Run this again: what is done is skipped.");
                return Ok(ExitCode::FAILURE);
            }
            audit(&state, name, "key").await?;
            enrolment(name, &password);
        }
        Stage::Enrolment => {
            println!("Stage 2 of 4: the boot key waits for a person at the console.");
            match state.secret(&password_name).await? {
                Some(ct) => enrolment(name, &vault.decrypt(&ct)?),
                None => {
                    eprintln!("🔴 its enrolment password is not in the vault: on {name},");
                    eprintln!("   `mokutil --revoke-import`, then run this again for a new one.");
                    return Ok(ExitCode::FAILURE);
                }
            }
        }
        Stage::Setup => {
            println!("Stage 3 of 4: the boot key is enrolled — the kernel image (UKI) built,");
            println!("signed, resealed after every initrd, and booted once.");
            let booted = runner.read_file("/proc/cmdline").await?.unwrap_or_default();
            let steps = boot::setup_steps(&disk.device, &tangs, &booted);
            // Kept from a UKI boot of before: the reseal seals now, and the boot opens.
            let pcr7_kept = exists(boot::PCR7).await?;
            if !apply {
                preview(&steps);
                println!("\n  The kit's recovery key reaches it through standard input into");
                println!("  memory, to add the reseal's slot; never a command line.");
                after_setup(&state, &vault, name, pcr7_kept).await?;
                println!("\n  Re-run with --apply.");
                return Ok(ExitCode::SUCCESS);
            }
            // 🔴 The boot after this one is opened by the kit's key: it must be printed.
            let (recovery, made) = kit::recovery_key(&state, &vault, name).await?;
            if made || !crate::seal::kit_current(&state, &vault).await? {
                eprintln!(
                    "🔴 No emergency kit printed with {name}'s recovery key: nothing is done."
                );
                eprintln!("   The UKI's first boot is opened by that key. Print it, then run");
                eprintln!("   this again:  hlb emergency kit");
                return Ok(ExitCode::FAILURE);
            }
            runner.write_file(disk::STAGED_RECOVERY, &recovery).await?;
            let outcome = execute(runner, steps).await;
            let _ = runner
                .run(&["rm".into(), "-f".into(), disk::STAGED_RECOVERY.into()])
                .await;
            if let Err(e) = outcome {
                eprintln!("  🔴 {e}");
                eprintln!("     Run this again: what is done is skipped.");
                return Ok(ExitCode::FAILURE);
            }
            audit(&state, name, "setup").await?;
            // Enrolled: the password opens nothing any more.
            if state.secret(&password_name).await?.is_some() {
                state.forget_secret(&password_name).await?;
            }
            after_setup(&state, &vault, name, pcr7_kept).await?;
        }
        Stage::Seal => {
            println!("Stage 4 of 4: booted by its UKI — the disk sealed to this boot.");
            let steps = boot::seal_steps(&disk.device);
            if !apply {
                preview(&steps);
                println!(
                    "\n  The binding to GRUB's boot goes: GRUB then opens nothing without the"
                );
                println!("  kit's key. Re-run with --apply.");
                return Ok(ExitCode::SUCCESS);
            }
            if let Err(e) = execute(runner, steps).await {
                eprintln!("  🔴 {e}");
                eprintln!("     Run this again: what is done is skipped.");
                return Ok(ExitCode::FAILURE);
            }
            audit(&state, name, "sealed").await?;
            if state.secret(&password_name).await?.is_some() {
                state.forget_secret(&password_name).await?;
            }
            println!("\n✓ {name} boots verified: its signed kernel image, the disk opened by its");
            println!("  TPM at that boot's PCRs AND one of:");
            for t in &tangs {
                println!("    {}", t.url);
            }
            println!("  Every new kernel or initrd is resealed by `hlb-uki` before the next");
            println!("  boot; a reseal that fails says so, and that boot waits for the kit's key.");
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn preview(steps: &[Step]) {
    println!("\nWould do:");
    for (i, s) in steps.iter().enumerate() {
        println!("  {}. {}", i + 1, s.what);
    }
}

async fn execute(runner: &dyn Runner, steps: Vec<Step>) -> std::result::Result<(), String> {
    let p = Provision {
        steps,
        notes: Vec::new(),
    };
    provision::execute(runner, &p, |s| println!("  {}", s.what))
        .await
        .map_err(|e| e.to_string())
}

async fn audit(state: &hlb_state::State, node: &str, stage: &str) -> Result<()> {
    state
        .audit(
            "cli",
            ACTOR_ROLE,
            "node-verify-boot",
            node,
            "ok",
            Some(stage),
        )
        .await?;
    Ok(())
}

/// What a person does at the console for shim to enrol the key.
fn enrolment(node: &str, password: &str) {
    println!("\nAt {node}'s console, reboot it. A blue screen, MokManager, waits 10 s for a");
    println!("key: press one, then Enroll MOK → Continue → Yes, type the password");
    println!("\n    {password}\n");
    // Measured on enc3: a boot past MokManager's 10 s drops the request — mokutil then
    // says "not enrolled", and stage 1 imports it again.
    println!("then Reboot. Missed, shim drops the request at that boot: run this again for");
    println!("a new one. Enrolled, run this again for what comes next:");
    println!("    hlb node verify-boot {node} --apply");
}

/// What the boot after stage 3 costs.
async fn after_setup(
    state: &hlb_state::State,
    vault: &hlb_secrets::Vault,
    node: &str,
    pcr7_kept: bool,
) -> Result<()> {
    println!("\nThen reboot it: the next boot only is the UKI's.");
    if pcr7_kept {
        println!("  A UKI boot of before left its PCR 7: it opens alone.");
    } else {
        // 🔴 PCR 7 names the certificate that verified the second stage: the MOK's here,
        // Debian's under GRUB, and only a boot through it reads it.
        let mesh = crate::load_mesh(state, vault).await?;
        let address = mesh
            .get(node)
            .and_then(|p| p.endpoint.as_deref().map(crate::disk::endpoint_host))
            .unwrap_or_else(|| "<its address>".into());
        println!("  ⚠️  That boot waits for the kit's recovery key: the PCR 7 a UKI boot");
        println!("  produces is read from one. Type the key printed under {node}:");
        println!("    ssh -p {} root@{address}", disk::UNLOCK_PORT);
    }
    println!("  Once it is up, seal it to that boot:");
    println!("    hlb node verify-boot {node} --apply");
    Ok(())
}
