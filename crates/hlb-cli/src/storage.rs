//! `hlb storage encrypt`: a storage node's app datasets encrypted under a key of its own
//! (`hlb_bootstrap::zfs`), kept in the vault and on the emergency kit, and loaded at
//! boot before Docker and the NFS server may start.
//!
//! ZFS cannot encrypt a dataset in place. Each plain volume is copied — `zfs send` into
//! an encrypted `zfs recv` — while its app is stopped, checked against the original,
//! swapped in by two renames, and the original destroyed. Every intermediate shape has
//! a name a later run reads back (`zfs::migrations`), so an interrupted run resumes.

use std::process::ExitCode;

use hlb_backup_run::kit;
use hlb_backup_run::restore;
use hlb_bootstrap::provision::{self, Provision};
use hlb_bootstrap::zfs::{self, Migration};
use hlb_bootstrap::Runner;
use hlb_orchestrator::{Orchestrator, SwarmOrchestrator};

use crate::{open_state, open_vault, Cli, ACTOR_ROLE};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// The node, and how to reach it.
pub struct Target<'a> {
    pub node: &'a str,
    pub pool: Option<&'a str>,
    pub root: &'a str,
    pub host: Option<&'a str>,
    pub user: Option<&'a str>,
    pub port: Option<u16>,
}

/// One volume, with what it needs and what its copy carries.
struct Volume {
    name: String,
    app: String,
    migration: Migration,
    /// Its local properties as `-o` options, for a volume still to copy.
    carried: Vec<String>,
    referenced: Option<u64>,
}

pub async fn encrypt(cli: &Cli, t: Target<'_>, apply: bool) -> Result<ExitCode> {
    let state = open_state(cli).await?;
    let vault = open_vault(cli)?;
    let orch = SwarmOrchestrator::connect().await?;
    let Some(target) = orch
        .nodes()
        .await?
        .into_iter()
        .find(|n| n.hostname == t.node || n.id == t.node)
    else {
        eprintln!(
            "🔴 no node \"{}\" in the cluster — see `hlb cluster status`.",
            t.node
        );
        return Ok(ExitCode::FAILURE);
    };
    let node = target.hostname.as_str();
    let dir = tempfile::tempdir()?;
    let Some(runner) =
        crate::reach_node(&state, &vault, node, t.host, t.user, t.port, dir.path()).await?
    else {
        eprintln!("🔴 no SSH address recorded for {node}: pass --host.");
        return Ok(ExitCode::FAILURE);
    };
    let runner = runner.as_ref();
    println!("Machine: {node}\n");
    if !hlb_bootstrap::observe::is_root(runner).await? {
        eprintln!("🔴 not root on {node}: its pools and its boot are root's.");
        return Ok(ExitCode::FAILURE);
    }
    // The datasets are unlocked by a systemd unit Docker waits for; OpenRC has neither.
    if !run(runner, &["test", "-d", "/run/systemd/system"])
        .await?
        .ok()
    {
        eprintln!("🔴 {node} does not run systemd: nothing would unlock its datasets at");
        eprintln!("   boot, nor keep Docker from starting over them. Not built for OpenRC.");
        return Ok(ExitCode::FAILURE);
    }

    let base = match zfs::read_pools(runner).await? {
        Ok((imported, importable)) => {
            match zfs::PoolDecision::decide(&imported, &importable, t.pool) {
                zfs::PoolDecision::Ready { pool } => Some(format!("{pool}/{}", t.root)),
                zfs::PoolDecision::Ambiguous { pools } => {
                    eprintln!(
                        "🔴 several pools ({}): name the one holding the apps with --pool.",
                        pools.join(", ")
                    );
                    return Ok(ExitCode::FAILURE);
                }
                other => {
                    println!("{}.", other.describe());
                    None
                }
            }
        }
        Err(zfs::Unread::Missing) => {
            eprintln!("🔴 `zpool` is not available on {node}: ZFS is not installed there —");
            eprintln!("   hlb node deps <host> --apply on a storage node.");
            return Ok(ExitCode::FAILURE);
        }
        Err(zfs::Unread::Failed(why)) => {
            eprintln!("🔴 `zpool` failed on {node}, so what its disks hold is unknown:");
            eprintln!("   {}", why.replace('\n', "\n   "));
            return Ok(ExitCode::FAILURE);
        }
    };

    let volumes = match &base {
        Some(base) => match volumes(runner, base).await? {
            Ok(v) => v,
            Err(why) => {
                eprintln!("🔴 {why}");
                return Ok(ExitCode::FAILURE);
            }
        },
        None => Vec::new(),
    };

    // 🔴 The key is in the vault, and on a kit printed since, before any dataset knows
    // it: a pool encrypted under a key that exists only on its own machine dies with
    // that machine's root disk.
    let (key, made) = kit::zfs_key(&state, &vault, node).await?;
    let on_node = runner.read_file(zfs::KEY_FILE).await?;
    match on_node.as_deref().map(str::trim) {
        Some(k) if k == key => println!("Key: in the vault and at {} already.", zfs::KEY_FILE),
        Some(_) => {
            eprintln!(
                "🔴 {node} has another key at {}: datasets encrypted under it would",
                zfs::KEY_FILE
            );
            eprintln!("   no longer open at boot. Not replaced — whose is it? (zfs list -o");
            eprintln!("   name,keylocation,encryptionroot)");
            return Ok(ExitCode::FAILURE);
        }
        None => println!(
            "Key: {}{node} in the vault{}, written to {} (0400).",
            kit::ZFS_KEY_PREFIX,
            if made { ", made just now" } else { "" },
            zfs::KEY_FILE
        ),
    }

    // Read back, so a second run's preview does not list as work what is already there.
    let boot = zfs::boot_steps();
    let mut in_place = Vec::new();
    for s in &boot {
        in_place.push(match &s.action {
            provision::Action::Install { path, content, .. } => {
                runner.read_file(path).await?.as_deref() == Some(content.as_str())
            }
            provision::Action::Run(_) => false,
        });
    }
    let enabled = run(runner, &["systemctl", "is-enabled", zfs::LOAD_KEY_UNIT])
        .await?
        .first_line()
        .as_deref()
        == Some("enabled");
    let boot_current = enabled
        && boot
            .iter()
            .zip(&in_place)
            .all(|(s, &done)| done || matches!(s.action, provision::Action::Run(_)));
    println!("\nAt every boot:");
    if boot_current {
        println!(
            "  ✓ {} and its drop-ins, in place and enabled",
            zfs::LOAD_KEY_UNIT
        );
    } else {
        for (s, done) in boot.iter().zip(&in_place) {
            println!("  {} {}", if *done { "✓" } else { "→" }, s.describe());
        }
    }

    let mut stuck = false;
    match &base {
        Some(base) => println!("\nVolumes under {base}:"),
        None => println!("\nNo pool imported: the key and the boot unit only. `hlb storage init`"),
    }
    if base.is_none() {
        println!("there creates the datasets encrypted.");
    }
    for v in &volumes {
        let size = v
            .referenced
            .map(size)
            .unwrap_or_else(|| "size unread".into());
        match &v.migration {
            Migration::Done => println!("  ✓ {} — encrypted", v.name),
            Migration::Foreign => println!(
                "  · {} — encrypted by something else: left alone, and not unlocked at boot",
                v.name
            ),
            Migration::Copy { stale } => {
                println!("  → {} — copied encrypted, {size}", v.name);
                if *stale {
                    println!("      the copy an interrupted run left is discarded first");
                }
            }
            Migration::Finish => println!(
                "  → {} — an interrupted run's copy put in place and checked",
                v.name
            ),
            Migration::Clean => println!("  → {} — its plain original destroyed", v.name),
            Migration::Stuck(why) => {
                stuck = true;
                println!("  🔴 {why}");
            }
        }
    }

    let mut downtime = Vec::new();
    for app in apps_to_stop(&volumes) {
        let services = services(&state, &orch, &app).await;
        let running: Vec<&str> = services
            .iter()
            .filter(|(_, r)| *r > 0)
            .map(|(s, _)| s.as_str())
            .collect();
        if !running.is_empty() {
            downtime.push(format!("{app}: {}", running.join(", ")));
        }
    }
    if !downtime.is_empty() {
        println!("\nStopped while its volumes are copied, then started again:");
        for d in &downtime {
            println!("  {d}");
        }
        println!("  An app that uses a stopped one — its database, its cache — sees it gone");
        println!("  meanwhile.");
    }
    if volumes
        .iter()
        .any(|v| matches!(v.migration, Migration::Copy { .. }))
    {
        println!("\n⚠️  The plain blocks a copy frees stay on the disks until ZFS writes over");
        println!("   them: a disk taken now still holds what was there. Written from now on,");
        println!("   nothing reaches them in clear.");
    }
    let signals = hlb_bootstrap::observe::protection(runner).await?;
    if signals.root_encrypted != Some(true) {
        println!("\n⚠️  {node}'s own disk is not encrypted: the key lies on it in clear. A data");
        println!("   disk taken alone gives nothing; the whole machine gives everything");
        println!("   (`hlb node preseed {node} --disk <by-id> --ssh-key <key> --encrypt`).");
    }
    if stuck {
        eprintln!("\n🔴 Nothing is done while a volume is in a shape no run of Homelabus leaves.");
        return Ok(ExitCode::FAILURE);
    }
    let volumes_done = volumes
        .iter()
        .all(|v| matches!(v.migration, Migration::Done | Migration::Foreign));
    if boot_current && on_node.is_some() && volumes_done {
        println!("\n✓ Nothing to do: {node}'s datasets are encrypted and unlocked at boot.");
        return Ok(ExitCode::SUCCESS);
    }
    if !crate::seal::kit_current(&state, &vault).await? {
        eprintln!("\n🔴 No emergency kit printed with this key: nothing is encrypted. Its pool");
        eprintln!("   carried to another machine opens with the kit's key alone. Print it,");
        eprintln!("   keep it away from the house, then run this again:");
        eprintln!("     hlb emergency kit");
        return Ok(ExitCode::FAILURE);
    }
    if !apply {
        println!("\n  Re-run with --apply.");
        return Ok(ExitCode::SUCCESS);
    }

    println!();
    if on_node.is_none() {
        // No newline: `keyformat=hex` reads the file as the key.
        provision::install_file(runner, zfs::KEY_FILE, &key, 0o400).await?;
        println!("  the key, at {}", zfs::KEY_FILE);
    }
    provision::execute(
        runner,
        &Provision {
            steps: boot,
            notes: Vec::new(),
        },
        |s| println!("  {}", s.what),
    )
    .await?;

    let mut encrypted = 0;
    for app in apps_to_touch(&volumes) {
        let mine: Vec<&Volume> = volumes.iter().filter(|v| v.app == app).collect();
        let services = if mine.iter().any(|v| v.touches_the_live_volume()) {
            services(&state, &orch, &app).await
        } else {
            Vec::new()
        };
        println!("\n{app}:");
        if let Err(e) = restore::stop(&orch, &services).await {
            restore::start(&orch, &services).await?;
            eprintln!("  🔴 {e}: nothing of {app} was touched.");
            return Ok(ExitCode::FAILURE);
        }
        let mut outcome = Ok(());
        for v in &mine {
            outcome = migrate(runner, v).await;
            if outcome.is_err() {
                break;
            }
            encrypted += 1;
        }
        // Whatever happened: each step leaves the volume where the app finds it.
        restore::start(&orch, &services).await?;
        if let Err(e) = outcome {
            eprintln!("  🔴 {e}");
            eprintln!("     {app} is started again. Run this again: what is done is skipped.");
            return Ok(ExitCode::FAILURE);
        }
    }

    // What the boot runs, run now: every dataset under the key mounted, or say so.
    let check = run(runner, &[zfs::LOAD_KEY_SCRIPT]).await?;
    if !check.ok() {
        eprintln!("🔴 the boot's check fails now: {}", check.stderr.trim());
        eprintln!("   Docker would not start at the next boot.");
        return Ok(ExitCode::FAILURE);
    }
    state
        .audit(
            "cli",
            ACTOR_ROLE,
            "storage-encrypt",
            node,
            "ok",
            Some(&format!("{encrypted} volume(s)")),
        )
        .await?;
    println!("\n✓ {node}'s datasets are encrypted under its key, unlocked at boot before");
    println!("  Docker and the NFS server. Without the key, neither starts.");
    Ok(ExitCode::SUCCESS)
}

impl Volume {
    /// Stopping the app is needed: the volume it writes is read, or replaced.
    fn touches_the_live_volume(&self) -> bool {
        matches!(self.migration, Migration::Copy { .. } | Migration::Finish)
    }
}

/// The volumes under `base`, with what each needs. `Err` names what refuses it.
async fn volumes(
    runner: &dyn Runner,
    base: &str,
) -> Result<std::result::Result<Vec<Volume>, String>> {
    let listed = runner.run(&zfs::list_datasets(base)).await?;
    if !listed.ok() {
        // `storage init` has not run: nothing to encrypt yet.
        if listed.stderr.contains("does not exist") {
            return Ok(Ok(Vec::new()));
        }
        return Ok(Err(format!("zfs list {base}: {}", listed.stderr.trim())));
    }
    let datasets = zfs::parse_datasets(&listed.stdout);
    let mut out = Vec::new();
    for (name, mut migration) in zfs::migrations(base, &datasets) {
        let mut carried = Vec::new();
        // Read now, not at --apply: a property the copy cannot carry is refused in
        // the preview, before any app is stopped.
        if matches!(migration, Migration::Copy { .. }) {
            let local = run(
                runner,
                &[
                    "zfs",
                    "get",
                    "-H",
                    "-s",
                    "local",
                    "-o",
                    "property,value",
                    "all",
                    &name,
                ],
            )
            .await?;
            if !local.ok() {
                return Ok(Err(format!("zfs get {name}: {}", local.stderr.trim())));
            }
            match zfs::carried_properties(&name, &local.stdout) {
                Ok(c) => carried = c,
                Err(why) => migration = Migration::Stuck(why),
            }
        }
        let app = name
            .strip_prefix(base)
            .and_then(|r| r.trim_start_matches('/').split('/').next())
            .unwrap_or_default()
            .to_string();
        let referenced = datasets
            .iter()
            .find(|d| d.name == name)
            .and_then(|d| d.referenced);
        out.push(Volume {
            name,
            app,
            migration,
            carried,
            referenced,
        });
    }
    Ok(Ok(out))
}

/// The apps whose volumes are copied or swapped, in name order.
fn apps_to_stop(volumes: &[Volume]) -> Vec<String> {
    let mut apps: Vec<String> = volumes
        .iter()
        .filter(|v| v.touches_the_live_volume())
        .map(|v| v.app.clone())
        .collect();
    apps.dedup();
    apps
}

/// The apps with anything left to do, in name order.
fn apps_to_touch(volumes: &[Volume]) -> Vec<String> {
    let mut apps: Vec<String> = volumes
        .iter()
        .filter(|v| {
            matches!(
                v.migration,
                Migration::Copy { .. } | Migration::Finish | Migration::Clean
            )
        })
        .map(|v| v.app.clone())
        .collect();
    apps.dedup();
    apps
}

/// The services of `app` that are deployed, with their replicas — none when it is not
/// installed: a dataset `storage init` made for an app never installed has no writer.
async fn services(
    state: &hlb_state::State,
    orch: &dyn Orchestrator,
    app: &str,
) -> Vec<(String, u64)> {
    match state.app_manifest(app).await {
        Ok(manifest) => restore::replicas(orch, &hlb_engine::services_of(app, &manifest)).await,
        Err(_) => Vec::new(),
    }
}

/// Takes `v` one step at a time to encrypted, each step leaving a shape
/// [`zfs::migrations`] reads back.
async fn migrate(runner: &dyn Runner, v: &Volume) -> std::result::Result<(), String> {
    let name = v.name.as_str();
    let copy = format!("{name}{}", zfs::COPY_SUFFIX);
    let plain = format!("{name}{}", zfs::PLAIN_SUFFIX);
    let snapshot = format!("{name}@{}", zfs::SNAPSHOT);
    match &v.migration {
        Migration::Copy { stale } => {
            if *stale {
                zfs_ok(runner, "discard the stale copy", &["destroy", "-r", &copy]).await?;
            }
            // A snapshot an interrupted run took holds the volume as it was then.
            if zfs_exists(runner, &snapshot).await? {
                zfs_ok(runner, "drop the old snapshot", &["destroy", &snapshot]).await?;
            }
            unheld(runner, name).await?;
            zfs_ok(runner, "snapshot", &["snapshot", &snapshot]).await?;
            println!("  {name}: copying…");
            let script = zfs::copy_script(name, &v.carried);
            let o = run(runner, &["sh", "-c", &script])
                .await
                .map_err(|e| e.to_string())?;
            if !o.ok() {
                return Err(format!("{name}: the copy failed — {}", o.stderr.trim()));
            }
            unheld(runner, name).await?;
            zfs_ok(runner, "set the original aside", &["rename", name, &plain]).await?;
            swap_in(runner, name, &copy, &plain).await
        }
        Migration::Finish => {
            unheld(runner, &plain).await?;
            swap_in(runner, name, &copy, &plain).await
        }
        Migration::Clean => destroy_original(runner, name, &plain).await,
        Migration::Done | Migration::Foreign | Migration::Stuck(_) => Ok(()),
    }
}

/// Waits until nothing but its own mount point holds `name` — its app's containers
/// may still be tearing down — or refuses, naming what does (`zfs::holders_script`).
async fn unheld(runner: &dyn Runner, name: &str) -> std::result::Result<(), String> {
    let path = zfs_get(runner, "mountpoint", name).await?;
    let mut waited = 0;
    loop {
        let o = run(runner, &["sh", "-c", &zfs::holders_script(&path)])
            .await
            .map_err(|e| e.to_string())?;
        let holders: Vec<&str> = o.stdout.lines().filter(|l| !l.is_empty()).collect();
        if holders.is_empty() {
            return Ok(());
        }
        if waited >= 30 {
            return Err(format!(
                "{name} is still mounted at {}: something besides its app uses it — \
                 stop that, then run this again",
                holders.join(", ")
            ));
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        waited += 2;
    }
}

/// Renames the copy into place, mounts it, and compares it with the original set aside
/// — put back as it was if they differ.
async fn swap_in(
    runner: &dyn Runner,
    name: &str,
    copy: &str,
    plain: &str,
) -> std::result::Result<(), String> {
    if let Err(e) = zfs_ok(runner, "put the copy in place", &["rename", copy, name]).await {
        // The original goes back where the app looks for it.
        let _ = zfs_ok(runner, "put the original back", &["rename", plain, name]).await;
        return Err(e);
    }
    // 🔴 Any failure from here puts the original back: started over a copy left
    // unmounted, the app would write into the empty directory beneath it, in clear.
    if let Err(e) = check_copy(runner, name, plain).await {
        let _ = zfs_ok(runner, "set the copy aside", &["rename", name, copy]).await;
        let _ = zfs_ok(runner, "put the original back", &["rename", plain, name]).await;
        return Err(format!(
            "{e} — {name} is put back as it was, its copy kept as {copy} to look at"
        ));
    }
    println!("  {name}: encrypted, the same files as before");
    destroy_original(runner, name, plain).await
}

/// Mounts the copy now at `name`, and compares its files with the original's.
async fn check_copy(
    runner: &dyn Runner,
    name: &str,
    plain: &str,
) -> std::result::Result<(), String> {
    // Received unmounted, it stays so through the rename.
    if zfs_get(runner, "mounted", name).await? != "yes" {
        zfs_ok(runner, "mount it", &["mount", name]).await?;
    }
    let new = tree(runner, &zfs_get(runner, "mountpoint", name).await?).await?;
    let old = tree(runner, &zfs_get(runner, "mountpoint", plain).await?).await?;
    if new != old {
        return Err(format!("{name}: its copy does not hold the same files"));
    }
    Ok(())
}

async fn destroy_original(
    runner: &dyn Runner,
    name: &str,
    plain: &str,
) -> std::result::Result<(), String> {
    zfs_ok(
        runner,
        "destroy the plain original",
        &["destroy", "-r", plain],
    )
    .await?;
    // The copy kept the snapshot it was received with.
    let snapshot = format!("{name}@{}", zfs::SNAPSHOT);
    if zfs_exists(runner, &snapshot).await? {
        zfs_ok(runner, "drop the snapshot", &["destroy", &snapshot]).await?;
    }
    println!("  {name}: the plain original destroyed");
    Ok(())
}

/// The hash of the file list under `path` (`zfs::tree_script`).
async fn tree(runner: &dyn Runner, path: &str) -> std::result::Result<String, String> {
    let o = run(runner, &["sh", "-c", &zfs::tree_script(path)])
        .await
        .map_err(|e| e.to_string())?;
    match o.first_line() {
        Some(h) if o.ok() => Ok(h),
        _ => Err(format!("listing {path}: {}", o.stderr.trim())),
    }
}

async fn zfs_ok(runner: &dyn Runner, what: &str, args: &[&str]) -> std::result::Result<(), String> {
    let mut argv = vec!["zfs"];
    argv.extend_from_slice(args);
    let o = run(runner, &argv).await.map_err(|e| e.to_string())?;
    if o.ok() {
        Ok(())
    } else {
        Err(format!("{what} ({}): {}", argv.join(" "), o.stderr.trim()))
    }
}

async fn zfs_exists(runner: &dyn Runner, name: &str) -> std::result::Result<bool, String> {
    Ok(run(
        runner,
        &["zfs", "list", "-H", "-o", "name", "-t", "all", name],
    )
    .await
    .map_err(|e| e.to_string())?
    .ok())
}

async fn zfs_get(
    runner: &dyn Runner,
    property: &str,
    name: &str,
) -> std::result::Result<String, String> {
    let o = run(runner, &["zfs", "get", "-H", "-o", "value", property, name])
        .await
        .map_err(|e| e.to_string())?;
    match o.first_line() {
        Some(v) if o.ok() => Ok(v),
        _ => Err(format!("zfs get {property} {name}: {}", o.stderr.trim())),
    }
}

async fn run(
    runner: &dyn Runner,
    argv: &[&str],
) -> hlb_bootstrap::runner::Result<hlb_bootstrap::runner::Output> {
    runner
        .run(&argv.iter().map(|a| a.to_string()).collect::<Vec<_>>())
        .await
}

/// Bytes as a person reads them, to the megabyte.
fn size(bytes: u64) -> String {
    match bytes {
        b if b >= 1_000_000_000 => format!("{:.1} GB", b as f64 / 1e9),
        b if b >= 1_000_000 => format!("{} MB", b / 1_000_000),
        _ => "under 1 MB".to_string(),
    }
}
