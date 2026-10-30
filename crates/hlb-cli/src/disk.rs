//! `hlb node bind-disk`: a node's encrypted disk opened at boot by its TPM AND one of
//! the house's Tangs (`hlb_bootstrap::disk`), the kit's recovery key enrolled, the
//! install passphrase taken out.

use std::process::ExitCode;

use hlb_backup_run::kit;
use hlb_bootstrap::boot;
use hlb_bootstrap::disk::{self, Disk, Keys, Tang};
use hlb_bootstrap::protection::Tpm;
use hlb_bootstrap::provision::{self, Provision};
use hlb_bootstrap::Runner;
use hlb_orchestrator::{cluster, NodeInfo, Orchestrator};

use crate::{open_state, open_vault, Cli, ACTOR_ROLE};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// The one-time passphrase a node's disk is installed under (`--encrypt` of `hlb node
/// preseed`).
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
    let others = tang_candidates(
        nodes
            .iter()
            .map(|n| n.hostname.clone())
            .filter(|n| *n != target.hostname)
            .collect(),
        &target.disk_tangs,
    );
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
    let authorized = runner
        .read_file("/root/.ssh/authorized_keys")
        .await?
        .unwrap_or_default();
    let unlock = disk::unlock_keys(&authorized);
    // Refused now rather than after the Tangs are installed for nothing.
    if let Err(why) = disk::plan(&disk, None, &[placeholder()], &unlock) {
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
        // Their keys are read at --apply; until then a Tang already in the binding is
        // taken as unchanged, or every preview of a bound disk would announce a rebind.
        if tang_runners.len() > disk::MAX_TANGS {
            println!(
                "  The first {} that answer are bound — the disk's header holds no more;",
                disk::MAX_TANGS
            );
            println!("  the others stand in for one that does not.");
        }
        let expected: Vec<Tang> = tang_runners
            .iter()
            .take(disk::MAX_TANGS)
            .map(|(_, address, _)| {
                let url = disk::tang_url(address);
                let thp = disk
                    .bindings
                    .iter()
                    .flat_map(|b| b.tangs.iter().flatten())
                    .find(|t| t.url == url)
                    .map_or_else(|| placeholder().thp, |t| t.thp.clone());
                Tang { url, thp }
            })
            .collect();
        let steps = disk::plan(&disk, None, &expected, &unlock)?;
        println!("\nThen on {}:", target.hostname);
        for (i, s) in steps.iter().enumerate() {
            println!("  {}. {}", i + 1, s.what);
        }
        println!("\n  The kit's recovery key and the disk's passphrase reach it through");
        println!("  standard input into memory, never a command line.");
        if disk.verified {
            println!("\n  Boot verified (level A): `hlb-uki` reseals the disk to the boot AND the");
            println!("  Tangs above, with no Tang needing to answer. After a power cut of the");
        } else {
            println!(
                "\n⚠️  Boot is not verified: whoever has the machine INSIDE the house, a Tang"
            );
            println!("   answering, can still get a shell at boot (`hlb node verify-boot`).");
            println!("   And after a power cut of the");
        }
        println!("   whole house, the recovery key is typed on one node — the others open");
        println!("   as its Tang comes back.");
        if unlock.is_empty() {
            println!("\n⚠️  root has no key that may unlock it: the recovery key is typed at its");
            println!("   console only.");
        } else {
            println!(
                "\n  The recovery key can be typed over SSH at boot, port {}: dropbear's",
                disk::UNLOCK_PORT
            );
            println!("  host key lies in clear on /boot — whoever holds the machine can pose");
            println!("  as it. Check the fingerprint printed at the end before typing.");
        }
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
        if tangs.len() == disk::MAX_TANGS {
            println!("\n{name}: not needed, {} Tangs answered", disk::MAX_TANGS);
            continue;
        }
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
            [thp] => tangs.push((
                name.clone(),
                Tang {
                    url: disk::tang_url(address),
                    thp: thp.clone(),
                },
            )),
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

    let (holders, tangs): (Vec<String>, Vec<Tang>) = tangs.into_iter().unzip();
    println!("\n{}:", target.hostname);
    let outcome = bind(
        runner,
        &disk,
        &recovery,
        passphrase.as_deref(),
        &tangs,
        &unlock,
    )
    .await;
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
    // Out of the disk now (or never in it): kept, it would be a key to nothing that
    // still reads as one.
    let install = format!("{INSTALL_PASSPHRASE_PREFIX}{}", target.hostname);
    if state.secret(&install).await?.is_some() {
        state.forget_secret(&install).await?;
        println!("  the install passphrase, forgotten by the vault");
    }
    // Read back when a node joins or leaves: the binding pins these Tangs, and nothing
    // else knows which disk depends on which node.
    let label = holders.join(",");
    if let Err(e) = orch
        .label_node(&target.id, cluster::LABEL_DISK_TANGS, &label)
        .await
    {
        eprintln!("  ⚠️  bound, but its Tangs are not recorded on the node ({e}): a node");
        eprintln!("     leaving will not say this disk needs binding again. Run this again.");
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
    if !unlock.is_empty() {
        let fingerprint = runner
            .run(&[
                "dropbearkey".into(),
                "-y".into(),
                "-f".into(),
                disk::UNLOCK_HOST_KEY.into(),
            ])
            .await?;
        let address = mesh
            .get(&target.hostname)
            .and_then(|p| p.endpoint.as_deref().map(endpoint_host))
            .or_else(|| host.map(str::to_string))
            .unwrap_or_else(|| "<its address>".into());
        println!("  Typed from elsewhere, once it waits at boot:");
        println!("    ssh -p {} root@{address}", disk::UNLOCK_PORT);
        match fingerprint
            .stdout
            .lines()
            .find_map(|l| l.strip_prefix("Fingerprint: "))
        {
            Some(f) => println!("  where it must show the key {f} — note it now."),
            None => println!("  ⚠️  its host key could not be read: check it at the console."),
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// The one-time passphrase `node`'s disk is installed under (`--encrypt` of `hlb node
/// preseed`):
/// the vault's when there is one, so a preseed rendered twice installs under the same
/// passphrase, and `bind-disk` reads what the disk was really made with.
pub async fn install_passphrase(cli: &Cli, node: &str) -> Result<String> {
    let state = open_state(cli).await?;
    let vault = open_vault(cli)?;
    let name = format!("{INSTALL_PASSPHRASE_PREFIX}{node}");
    if let Some(ct) = state.secret(&name).await? {
        return Ok(vault.decrypt(&ct)?);
    }
    // The recovery key's shape — letters and dashes the preseed carries unquoted — but
    // never the key itself: this one is written into a file left on a USB stick.
    let passphrase = hlb_secrets::recovery_key();
    let purpose = format!("install passphrase of {node}'s disk, until bind-disk");
    if !state
        .store_secret_if_absent(&name, &vault.encrypt(&passphrase)?, &purpose)
        .await?
    {
        return Box::pin(install_passphrase(cli, node)).await;
    }
    state
        .audit("cli", ACTOR_ROLE, "node-preseed-encrypt", node, "ok", None)
        .await?;
    Ok(passphrase)
}

/// The nodes to try as Tangs, in order: those the binding names already, so a disk
/// bound again keeps them and nothing is rebound for nothing, then the others by name.
fn tang_candidates(mut others: Vec<String>, bound: &[String]) -> Vec<String> {
    others.sort_by_key(|n| (!bound.contains(n), n.clone()));
    others
}

/// A bound node whose Tangs a join or a departure changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rebind {
    pub node: String,
    /// Its Tangs still in the house; empty when the departure took the last one.
    pub left: Vec<String>,
}

/// The bound nodes to bind again once `joined` joined (a Tang more to hold) or `gone`
/// left (one fewer). Sorted, so the advice reads the same on every run.
pub fn rebinds(nodes: &[NodeInfo], joined: Option<&str>, gone: Option<&str>) -> Vec<Rebind> {
    let mut out: Vec<Rebind> = nodes
        .iter()
        .filter(|n| !n.disk_tangs.is_empty())
        .filter(|n| Some(n.hostname.as_str()) != joined && Some(n.hostname.as_str()) != gone)
        // A disk holding all the Tangs its header has room for gains nothing by a join.
        .filter(|n| {
            (joined.is_some() && n.disk_tangs.len() < disk::MAX_TANGS)
                || gone.is_some_and(|g| n.disk_tangs.iter().any(|t| t == g))
        })
        .map(|n| Rebind {
            node: n.hostname.clone(),
            left: n
                .disk_tangs
                .iter()
                .filter(|t| Some(t.as_str()) != gone)
                .cloned()
                .collect(),
        })
        .collect();
    out.sort_by(|a, b| a.node.cmp(&b.node));
    out
}

/// Says which disks to bind again; `true` when one is left with no Tang at all.
pub fn print_rebinds(rebinds: &[Rebind], joined: Option<&str>, gone: Option<&str>) -> bool {
    if rebinds.is_empty() {
        return false;
    }
    let mut orphaned = false;
    println!();
    for r in rebinds {
        if r.left.is_empty() {
            orphaned = true;
            eprintln!(
                "🔴 {}'s disk opened with the Tang of {} alone: at its next boot it",
                r.node,
                gone.unwrap_or("?")
            );
            eprintln!("   waits for the kit's recovery key, typed at its console.");
        } else if let Some(g) = gone {
            println!(
                "⚠️  {}'s disk opens with {} still, and with {g}'s Tang wherever that",
                r.node,
                r.left.join(", ")
            );
            println!("   machine now answers, until it is bound again.");
        } else if let Some(j) = joined {
            println!(
                "  · {}'s disk opens with {}: {j} can hold a Tang for it too.",
                r.node,
                r.left.join(", ")
            );
        }
    }
    println!("  Bind again, to the Tangs of the house as it is now:");
    for r in rebinds {
        println!("    hlb node bind-disk {} --apply", r.node);
    }
    orphaned
}

/// The secrets staged, tried, and the steps they leave run.
async fn bind(
    runner: &dyn Runner,
    disk: &Disk,
    recovery: &str,
    passphrase: Option<&str>,
    tangs: &[Tang],
    unlock: &str,
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
    let reseal_opens = disk.verified && runner.run(&opens(boot::RESEAL_KEY)).await.map_err(e)?.ok();
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
        reseal: reseal_opens,
    };
    let steps = Provision {
        steps: disk::plan(disk, Some(keys), tangs, unlock)?,
        notes: Vec::new(),
    };
    provision::execute(runner, &steps, |s| println!("  {}", s.what))
        .await
        .map_err(|e| e.to_string())
}

/// What the disk holds, read without a secret. `Ok(Err)` is a refusal.
pub(crate) async fn read_disk(runner: &dyn Runner) -> Result<std::result::Result<Disk, String>> {
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
    // From the tokens, not `clevis luks list`: they keep each Tang's key.
    let bindings = disk::parse_bindings(&dump.stdout);
    let verified = runner.read_file(boot::POLICY).await?.is_some();
    Ok(Ok(Disk {
        device,
        keyslots,
        bindings,
        verified,
    }))
}

/// `10.0.0.2:51820` → `10.0.0.2`; `[fd00::2]:51820` → `fd00::2`.
pub(crate) fn endpoint_host(endpoint: &str) -> String {
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

    fn node(name: &str, tangs: &[&str]) -> NodeInfo {
        NodeInfo {
            id: format!("id-{name}"),
            hostname: name.into(),
            role: cluster::NodeRole::Worker,
            status: "ready".into(),
            availability: "active".into(),
            tier: None,
            protection: None,
            disk_tangs: tangs.iter().map(|s| s.to_string()).collect(),
            is_leader: false,
            memory_mb: None,
            failure_domain: None,
            data: Vec::new(),
            ingress: false,
            addr: None,
        }
    }

    fn house() -> Vec<NodeInfo> {
        vec![
            node("deb1", &[]),
            node("deb2", &[]),
            node("enc1", &["deb1", "deb2"]),
            node("enc2", &["deb2"]),
        ]
    }

    #[test]
    fn a_node_leaving_names_the_disks_its_tang_opened() {
        let r = rebinds(&house(), None, Some("deb2"));
        assert_eq!(
            r,
            vec![
                Rebind {
                    node: "enc1".into(),
                    left: vec!["deb1".into()]
                },
                Rebind {
                    node: "enc2".into(),
                    left: Vec::new()
                },
            ]
        );
        assert!(rebinds(&house(), None, Some("deb3")).is_empty());
    }

    #[test]
    fn a_node_joining_names_every_bound_disk_but_its_own() {
        let mut h = house();
        h.push(node("deb3", &["deb1"]));
        let r: Vec<String> = rebinds(&h, Some("deb3"), None)
            .into_iter()
            .map(|r| r.node)
            .collect();
        assert_eq!(r, ["enc1", "enc2"]);
    }

    #[test]
    fn a_join_leaves_a_disk_with_a_full_header_alone() {
        let mut h = house();
        h.push(node("enc3", &["deb1", "deb2", "enc1"]));
        h.push(node("deb3", &[]));
        let r: Vec<String> = rebinds(&h, Some("deb3"), None)
            .into_iter()
            .map(|r| r.node)
            .collect();
        assert_eq!(r, ["enc1", "enc2"]);
        // A departure from it is still said.
        assert_eq!(rebinds(&h, None, Some("enc1"))[0].node, "enc3");
    }

    #[test]
    fn the_tangs_bound_already_are_tried_first() {
        let names = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(
            tang_candidates(
                names(&["enc2", "deb1", "enc1", "deb2"]),
                &names(&["enc2", "deb2"])
            ),
            names(&["deb2", "enc2", "deb1", "enc1"])
        );
    }

    #[test]
    fn a_disk_left_with_no_tang_is_red() {
        assert!(print_rebinds(
            &rebinds(&house(), None, Some("deb2")),
            None,
            Some("deb2")
        ));
        assert!(!print_rebinds(
            &rebinds(&house(), None, Some("deb1")),
            None,
            Some("deb1")
        ));
    }

    #[test]
    fn a_tang_is_reached_at_its_endpoint_host() {
        assert_eq!(endpoint_host("10.77.0.11:51820"), "10.77.0.11");
        assert_eq!(endpoint_host("[fd00::2]:51820"), "fd00::2");
        assert_eq!(endpoint_host("nas.lan"), "nas.lan");
    }
}
