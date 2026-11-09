//! `hlb site`: a site of the house's own — a rented VPS — prepared over SSH as a node is,
//! linked to the house by a tunnel of its own (`hlb_mesh::site`), running a Swarm of its
//! own.
//!
//! 🔴 **Never a member of the house's Swarm, nor a peer of its mesh.** Two sites cannot
//! keep Raft through losing the bigger one, and a manager reads every secret. What the VPS
//! is given, it is given on purpose, one step at a time.
//!
//! One site, for now: a second would need an interface and a network of its own, and
//! nothing asks for one yet.

use std::collections::BTreeMap;
use std::process::ExitCode;

use hlb_bootstrap::mesh::Tunnel;
use hlb_bootstrap::provision::{self, Init, Provision};
use hlb_bootstrap::{Distro, Runner};
use hlb_mesh::site::{self, Site};
use hlb_secrets::Vault;
use hlb_state::State;

use crate::{
    adopt_machine, build_runner, cluster_ssh_key, existing_ssh_key, hostname_of, load_mesh,
    local_hostname, open_state, open_vault, parse_ssh_target, provision_machine, ssh_target,
    write_temporary_key, Cli, ACTOR_ROLE,
};

mod door;
pub mod lifeboat;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// The vault's entry holding the site and its members. A stored name.
pub const TOPOLOGY: &str = "site-topology";

/// The VPS's private key in the vault. A stored name.
const HUB_KEY: &str = "site-hub-key";

/// A house node's private key on the link, in the vault. A stored name.
fn member_key(node: &str) -> String {
    format!("site-member-key-{node}")
}

/// The link's tunnel, as the bootstrap puts it in place on either end.
const TUNNEL: Tunnel<'static> = Tunnel {
    label: "the site link",
    unit: site::UNIT,
    interface: site::INTERFACE,
    config_path: site::CONFIG_PATH,
    firewall_path: site::FIREWALL_PATH,
};

/// A handshake older than this is a link down: with a keepalive every 25 s, WireGuard
/// renews its session every two minutes while the tunnel lives.
const STALE_AFTER_SECS: u64 = 180;

pub async fn load(state: &State, vault: &Vault) -> Result<Option<Site>> {
    Ok(match state.secret(TOPOLOGY).await? {
        Some(ct) => Some(serde_json::from_str(&vault.decrypt(&ct)?)?),
        None => None,
    })
}

async fn save(state: &State, vault: &Vault, s: &Site) -> Result<()> {
    let ct = vault.encrypt(&serde_json::to_string(s)?)?;
    match state.secret(TOPOLOGY).await? {
        Some(_) => state.rotate_secret(TOPOLOGY, &ct).await?,
        None => {
            state
                .store_secret_if_absent(TOPOLOGY, &ct, "the site and the house nodes linked to it")
                .await?;
        }
    }
    Ok(())
}

/// A private key from the vault, drawn and stored first when there is none.
///
/// Stored BEFORE the topology names its public half: the other way round, a failure in
/// between leaves a member whose configuration nobody can produce.
async fn key(state: &State, vault: &Vault, name: &str, what: &str) -> Result<hlb_mesh::KeyPair> {
    if let Some(ct) = state.secret(name).await? {
        return Ok(hlb_mesh::KeyPair::from_private(&vault.decrypt(&ct)?)?);
    }
    let kp = hlb_mesh::KeyPair::generate();
    state
        .store_secret_if_absent(name, &vault.encrypt(&kp.private)?, what)
        .await?;
    Ok(kp)
}

/// A house node to link, and how to reach it.
struct HouseNode {
    name: String,
    /// `None` on this machine.
    ssh: Option<String>,
}

/// The house's nodes, as the mesh knows them; this machine alone without a mesh — then
/// nothing says where the others are.
async fn house_nodes(state: &State, vault: &Vault) -> Result<(Vec<HouseNode>, bool)> {
    let local = local_hostname().await;
    let mesh = load_mesh(state, vault).await?;
    let mut out: Vec<HouseNode> = mesh
        .peers()
        .map(|p| HouseNode {
            name: p.name.clone(),
            ssh: if p.name == local { None } else { p.ssh.clone() },
        })
        .collect();
    let meshed = !out.is_empty();
    if !meshed {
        out.push(HouseNode {
            name: local,
            ssh: None,
        });
    }
    Ok((out, meshed))
}

/// Puts one end's configuration and rules in place, and brings the link up or
/// synchronises it.
async fn put_in_place(
    runner: &dyn Runner,
    config: &str,
    firewall: &str,
) -> std::result::Result<(), String> {
    let os = runner
        .read_file("/etc/os-release")
        .await
        .map_err(|e| e.to_string())?
        .unwrap_or_default();
    let distro = Distro::parse(&os).ok_or_else(|| "distribution not identified".to_string())?;
    let steps =
        hlb_bootstrap::mesh::steps(Init::for_family(distro.family), &TUNNEL, config, firewall)?;
    provision::execute(
        runner,
        &Provision {
            steps,
            notes: Vec::new(),
        },
        |_| {},
    )
    .await
    .map_err(|e| e.to_string())
}

/// Links every house node to the site, then proves each one reaches it.
///
/// The VPS learns every member first: a member brought up before the hub knows its key
/// sends handshakes nobody answers.
async fn link(
    state: &State,
    vault: &Vault,
    s: &mut Site,
    hub: &dyn Runner,
) -> Result<Vec<(String, std::result::Result<(), String>)>> {
    let (house, meshed) = house_nodes(state, vault).await?;
    if !meshed {
        println!("⚠️  The house has no mesh: only this machine is linked, nothing says where");
        println!("   the others are. A node running Caddy elsewhere is not reached.");
    }
    for gone in s
        .members
        .iter()
        .map(|m| m.name.clone())
        .filter(|m| !house.iter().any(|h| &h.name == m))
        .collect::<Vec<_>>()
    {
        s.remove_member(&gone);
        println!("  {gone} is no longer in the house: unlinked");
    }
    let mut keys = BTreeMap::new();
    for h in &house {
        let kp = key(
            state,
            vault,
            &member_key(&h.name),
            &format!("WireGuard private key of {} on the site link", h.name),
        )
        .await?;
        s.add_member(&h.name, &kp.public)?;
        keys.insert(h.name.clone(), kp.private);
    }
    save(state, vault, s).await?;

    let hub_key = key(state, vault, HUB_KEY, "WireGuard private key of the site").await?;
    put_in_place(hub, &s.render_hub(&hub_key.private), &site::hub_firewall())
        .await
        .map_err(|e| format!("{}: {e}", s.name))?;
    println!(
        "  ✓ {} knows {}",
        s.name,
        hlb_api::plural(s.members.len() as u64, "house node", "house nodes")
    );

    let kp = cluster_ssh_key(state, vault).await?;
    let tmp = tempfile::tempdir()?;
    let key_path = write_temporary_key(tmp.path(), &kp.private)?;
    let mut out = Vec::new();
    for h in &house {
        let runner: Box<dyn Runner> = match &h.ssh {
            None => Box::new(hlb_bootstrap::LocalRunner),
            Some(t) => {
                let (host, user, port) = parse_ssh_target(t);
                build_runner(Some(&host), user.as_deref(), port, key_path.to_str())
            }
        };
        let config = s
            .render_member(&h.name, &keys[&h.name])
            .ok_or("a member just added is missing")?;
        let mut r = put_in_place(runner.as_ref(), &config, &site::member_firewall()).await;
        if r.is_ok() {
            r = match runner
                .run(&hlb_bootstrap::mesh::reachability_check(
                    &site::HUB.to_string(),
                ))
                .await
            {
                Ok(o) if o.ok() => Ok(()),
                _ => Err(format!(
                    "linked, but {} does not answer through it: UDP {} filtered on the way?",
                    site::HUB,
                    site::PORT
                )),
            };
        }
        out.push((h.name.clone(), r));
    }
    Ok(out)
}

fn say_linked(results: &[(String, std::result::Result<(), String>)], site: &str) -> bool {
    let mut all = true;
    for (node, r) in results {
        match r {
            Ok(()) => println!("  ✓ {node} reaches {site}"),
            Err(e) => {
                all = false;
                eprintln!("  🔴 {node}: {e}");
            }
        }
    }
    if !all {
        eprintln!("   Once fixed: hlb site sync --apply");
    }
    all
}

/// The VPS's own Swarm, one node, its control API on the link's address alone.
async fn own_swarm(hub: &dyn Runner) -> std::result::Result<&'static str, String> {
    let state = hub
        .run(&[
            "docker".into(),
            "info".into(),
            "--format".into(),
            "{{.Swarm.LocalNodeState}}".into(),
        ])
        .await
        .map_err(|e| e.to_string())?;
    if !state.ok() {
        return Err(format!("Docker does not answer: {}", state.stderr.trim()));
    }
    if state.stdout.trim() == "active" {
        return Ok("already running");
    }
    let addr = site::HUB.to_string();
    let init = hub
        .run(&[
            "docker".into(),
            "swarm".into(),
            "init".into(),
            "--advertise-addr".into(),
            addr.clone(),
            "--listen-addr".into(),
            format!("{addr}:2377"),
        ])
        .await
        .map_err(|e| e.to_string())?;
    if init.ok() {
        Ok("created")
    } else {
        Err(init.stderr.trim().to_string())
    }
}

/// Whether the house's Caddy, as frozen, publishes the port the door relays HTTPS to.
///
/// A Caddy installed before the relay existed listens on 80 and 443 only: the door
/// opens, its health checks pass on 80, and every visitor's HTTPS is refused at home —
/// found on the lab, whose Caddy predated it.
fn relays_https(caddy: &hlb_types::Manifest) -> bool {
    caddy
        .spec
        .security
        .published_ports
        .contains(&hlb_types::manifest::PublishedPort::tcp(
            hlb_ingress::caddyfile::RELAY_HTTPS_PORT,
        ))
}

/// Puts the front door in place, or brings it up to date, and says what visitors need
/// for it to be theirs.
async fn open_door(state: &State, vault: &Vault, hub: &dyn Runner, s: &Site) -> bool {
    let names = match lifeboat::names(state, vault).await {
        Ok(n) => n,
        Err(e) => {
            eprintln!("\n🔴 The front door: what the lifeboat serves could not be read: {e}");
            return false;
        }
    };
    match door::deploy(hub, s, &names).await {
        Ok(how) => {
            if let Ok(caddy) = state
                .app_manifest(hlb_types::manifest::INGRESS_SERVICE)
                .await
            {
                if !relays_https(&caddy) {
                    eprintln!(
                        "\n🔴 The front door is {}, and leads nowhere for HTTPS: the house's",
                        how.says()
                    );
                    eprintln!(
                        "   Caddy was installed before the relay and does not publish {}.",
                        hlb_ingress::caddyfile::RELAY_HTTPS_PORT
                    );
                    eprintln!("   hlb upgrade caddy --apply");
                    return false;
                }
            }
            println!(
                "\nThe front door: {} — {}.",
                how.says(),
                hlb_api::plural(s.members.len() as u64, "house node", "house nodes")
            );
            println!(
                "   Visitors come through it once the house's names point at {} (their A",
                s.endpoint
            );
            println!("   records): until then they still arrive home directly.");
            true
        }
        Err(e) => {
            eprintln!("\n🔴 The front door: {e}");
            eprintln!(
                "   The one running, if any, is untouched. Once fixed: hlb site sync --apply"
            );
            false
        }
    }
}

/// What `hlb site add` was given.
pub struct Add<'a> {
    pub host: &'a str,
    pub user: Option<&'a str>,
    pub port: Option<u16>,
    pub identity: Option<&'a str>,
    pub name: &'a str,
    pub endpoint: Option<&'a str>,
    pub apply: bool,
}

/// A site's name: it is in a file name and a configuration comment.
fn valid_name(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= 32
        && n.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && !n.starts_with('-')
}

pub async fn add(cli: &Cli, a: Add<'_>) -> Result<ExitCode> {
    if !valid_name(a.name) {
        eprintln!(
            "🔴 \"{}\": a site's name is lower-case letters, digits and dashes.",
            a.name
        );
        return Ok(ExitCode::FAILURE);
    }
    let state = open_state(cli).await?;
    let vault = open_vault(cli)?;
    if let Some(s) = load(&state, &vault).await? {
        if s.ssh != ssh_target(a.host, a.user, a.port) {
            eprintln!(
                "🔴 The house already has its site, {} at {}. Nothing was touched.",
                s.name, s.ssh
            );
            eprintln!("   One site for now; `hlb site sync --apply` brings it up to date.");
            return Ok(ExitCode::FAILURE);
        }
    }

    let first = build_runner(Some(a.host), a.user, a.port, a.identity);
    println!("Site : {} ({})\n", a.name, first.label());
    let obs = hlb_bootstrap::observe(first.as_ref()).await?;
    let report = hlb_bootstrap::preflight::run(&obs);
    for c in &report.checks {
        println!("  {}", c.describe());
    }
    println!();
    if !report.can_proceed() {
        eprintln!("🔴 Blocking points above — nothing was installed on this machine.");
        return Ok(ExitCode::FAILURE);
    }
    let Some(distro) = report.distro else {
        eprintln!("🔴 unidentified distribution: cannot install the dependencies.");
        return Ok(ExitCode::FAILURE);
    };
    let endpoint = a.endpoint.unwrap_or(a.host);
    let (house, meshed) = house_nodes(&state, &vault).await?;

    if !a.apply {
        println!(
            "Would prepare this machine as the house's site \"{}\":",
            a.name
        );
        let mb = |v: Option<u64>| v.map_or("unknown".to_string(), |v| format!("{v} MB"));
        println!("  memory  : {}", mb(obs.total_memory_mb));
        println!("  disk    : {} free", mb(obs.free_disk_mb));
        println!(
            "  link    : {} on {}, the house's nodes opening their tunnels to",
            site::INTERFACE,
            Site::cidr()
        );
        println!("            {endpoint}:{} (UDP) —", site::PORT);
        for h in &house {
            println!("              {}", h.name);
        }
        if !meshed {
            println!(
                "            ⚠️  no mesh: this machine alone, nothing says where the others are"
            );
        }
        println!(
            "            the VPS reaching their ports {:?} and nothing else.",
            site::HOUSE_PORTS
        );
        println!("  Swarm   : one of its own, one node — never joined to the house's.");
        println!(
            "  door    : {} on 80 and 443, relaying TCP home undecrypted —",
            hlb_ingress::front_door::SERVICE
        );
        println!(
            "            the certificates stay at home. {}",
            hlb_ingress::front_door::IMAGE
        );
        println!();
        if !provision_machine(first.as_ref(), &distro, false, false, false).await? {
            return Ok(ExitCode::FAILURE);
        }
        println!();
        println!("  Rerun with --apply.");
        return Ok(ExitCode::SUCCESS);
    }

    let Some((_key_dir, ours)) =
        adopt_machine(&state, &vault, a.host, a.user, a.port, a.identity).await?
    else {
        return Ok(ExitCode::FAILURE);
    };
    // A machine nothing of the house runs on yet: a reboot costs nothing.
    if !provision_machine(ours.as_ref(), &distro, false, true, true).await? {
        return Ok(ExitCode::FAILURE);
    }
    let hub = key(&state, &vault, HUB_KEY, "WireGuard private key of the site").await?;
    let mut s = match load(&state, &vault).await? {
        Some(s) => s,
        None => Site {
            name: a.name.to_string(),
            endpoint: endpoint.to_string(),
            ssh: ssh_target(a.host, a.user, a.port),
            public_key: hub.public.clone(),
            memory_mb: obs.total_memory_mb,
            free_disk_mb: obs.free_disk_mb,
            members: Vec::new(),
        },
    };
    save(&state, &vault, &s).await?;
    state
        .audit("cli", ACTOR_ROLE, "site-add", a.name, "ok", None)
        .await?;

    println!("\nThe link:");
    let results = link(&state, &vault, &mut s, ours.as_ref()).await?;
    let linked = say_linked(&results, &s.name);

    match own_swarm(ours.as_ref()).await {
        Ok(how) => println!("\nIts own Swarm: {how}, listening on {} only.", site::HUB),
        Err(e) => {
            eprintln!("\n🔴 Its own Swarm: {e}");
            return Ok(ExitCode::FAILURE);
        }
    }
    let door = open_door(&state, &vault, ours.as_ref(), &s).await;
    let name = hostname_of(ours.as_ref()).await.unwrap_or_default();
    println!(
        "\nSite {} ready ({name}). `hlb site status` reads the link.",
        s.name
    );
    Ok(if linked && door {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

/// The site's runner, through Homelabus's key. The directory holds that key.
///
/// Never makes the key: `status` only reads, and a site exists only once the key did.
async fn reach(
    state: &State,
    vault: &Vault,
    s: &Site,
) -> Result<(tempfile::TempDir, Box<dyn Runner>)> {
    let kp = existing_ssh_key(state, vault)
        .await?
        .ok_or("Homelabus has no SSH key of its own: the site cannot be reached")?;
    let tmp = tempfile::tempdir()?;
    let key_path = write_temporary_key(tmp.path(), &kp.private)?;
    let (host, user, port) = parse_ssh_target(&s.ssh);
    let r = build_runner(Some(&host), user.as_deref(), port, key_path.to_str());
    Ok((tmp, r))
}

pub async fn sync(cli: &Cli, apply: bool) -> Result<ExitCode> {
    let state = open_state(cli).await?;
    let vault = open_vault(cli)?;
    let Some(mut s) = load(&state, &vault).await? else {
        println!("The house has no site.  hlb site add <ssh-host> --apply");
        return Ok(ExitCode::SUCCESS);
    };
    if !apply {
        let (house, _) = house_nodes(&state, &vault).await?;
        println!("Would push {}'s link to it and to:", s.name);
        for h in &house {
            let new = if s.member(&h.name).is_none() {
                " (new)"
            } else {
                ""
            };
            println!("  {}{new}", h.name);
        }
        for m in s
            .members
            .iter()
            .filter(|m| !house.iter().any(|h| h.name == m.name))
        {
            println!("  {} — no longer in the house: unlinked", m.name);
        }
        println!(
            "and its front door ({}) to the nodes linked.",
            hlb_ingress::front_door::SERVICE
        );
        println!("Rerun with --apply.");
        return Ok(ExitCode::SUCCESS);
    }
    let (_key_dir, hub) = reach(&state, &vault, &s).await?;
    let results = link(&state, &vault, &mut s, hub.as_ref()).await?;
    let linked = say_linked(&results, &s.name);
    // Opened even when a node failed to link: its health check keeps it out of the door.
    let door = open_door(&state, &vault, hub.as_ref(), &s).await;
    let all = linked && door;
    let outcome = if all { "ok" } else { "partial" };
    state
        .audit("cli", ACTOR_ROLE, "site-sync", &s.name, outcome, None)
        .await?;
    Ok(if all {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

/// `wg show <if> latest-handshakes`: a public key and an epoch per line, 0 for never.
fn handshakes(out: &str) -> BTreeMap<String, u64> {
    out.lines()
        .filter_map(|l| {
            let (k, t) = l.split_once(char::is_whitespace)?;
            Some((k.trim().to_string(), t.trim().parse().ok()?))
        })
        .collect()
}

/// How one member's link reads, from its latest handshake.
#[derive(Debug, PartialEq, Eq)]
enum Link {
    /// No handshake ever: the member never reached the VPS.
    Never,
    Up {
        age: u64,
    },
    Down {
        age: u64,
    },
}

fn judge(epoch: Option<u64>, now: u64) -> Link {
    match epoch {
        None | Some(0) => Link::Never,
        Some(t) => {
            let age = now.saturating_sub(t);
            if age > STALE_AFTER_SECS {
                Link::Down { age }
            } else {
                Link::Up { age }
            }
        }
    }
}

pub async fn status(cli: &Cli) -> Result<ExitCode> {
    let state = open_state(cli).await?;
    let vault = open_vault(cli)?;
    let Some(s) = load(&state, &vault).await? else {
        println!("The house has no site.  hlb site add <ssh-host> --apply");
        return Ok(ExitCode::SUCCESS);
    };
    let mb = |v: Option<u64>| v.map_or("unknown".to_string(), |v| format!("{v} MB"));
    println!("Site {} — {} (SSH {})", s.name, s.endpoint, s.ssh);
    println!(
        "  memory {}, disk {} free when added",
        mb(s.memory_mb),
        mb(s.free_disk_mb)
    );

    let (_key_dir, hub) = reach(&state, &vault, &s).await?;
    let out = hub
        .run(&[
            "wg".into(),
            "show".into(),
            site::INTERFACE.into(),
            "latest-handshakes".into(),
        ])
        .await;
    let seen = match out {
        Ok(o) if o.ok() => handshakes(&o.stdout),
        Ok(o) => {
            eprintln!("🔴 {}'s link does not answer: {}", s.name, o.stderr.trim());
            return Ok(ExitCode::FAILURE);
        }
        Err(e) => {
            eprintln!("🔴 {} unreachable over SSH: {e}", s.name);
            return Ok(ExitCode::FAILURE);
        }
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default();
    let mut all = true;
    for m in &s.members {
        match judge(seen.get(&m.public_key).copied(), now) {
            Link::Up { age } => println!("  ✓ {} ({}) — handshake {age} s ago", m.name, m.address),
            Link::Down { age } => {
                all = false;
                println!(
                    "  🔴 {} ({}) — last handshake {age} s ago",
                    m.name, m.address
                );
            }
            Link::Never => {
                all = false;
                println!("  🔴 {} ({}) — never reached it", m.name, m.address);
            }
        }
    }
    Ok(if all {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshakes_are_read_by_public_key() {
        let h = handshakes("abc=\t1700000000\ndef=\t0\nnonsense\n");
        assert_eq!(h.get("abc="), Some(&1_700_000_000));
        assert_eq!(h.get("def="), Some(&0));
        assert_eq!(h.len(), 2);
    }

    #[test]
    fn a_link_is_judged_by_its_last_handshake() {
        assert_eq!(judge(None, 1000), Link::Never);
        assert_eq!(judge(Some(0), 1000), Link::Never, "0 is WireGuard's never");
        assert_eq!(judge(Some(900), 1000), Link::Up { age: 100 });
        assert_eq!(judge(Some(800), 1000), Link::Down { age: 200 });
    }

    #[test]
    fn a_site_name_fits_a_file_name() {
        assert!(valid_name("vps"));
        assert!(valid_name("vps-2"));
        for bad in ["", "VPS", "-vps", "a/b", "vps 2", &"x".repeat(33)] {
            assert!(!valid_name(bad), "{bad:?}");
        }
    }

    #[test]
    fn the_house_opens_to_the_site_what_the_front_door_relays_to() {
        assert_eq!(Site::cidr(), hlb_ingress::front_door::SITE_NETWORK);
        assert_eq!(
            site::HOUSE_PORTS,
            [80, hlb_ingress::caddyfile::RELAY_HTTPS_PORT],
            "a port the door relays to and the house drops is a door that never opens"
        );
    }

    #[test]
    fn a_caddy_frozen_before_the_relay_is_told_apart() {
        let catalog = hlb_catalog::Catalog::load(std::path::Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../catalog"
        )))
        .expect("catalog");
        let caddy = catalog
            .get(hlb_types::manifest::INGRESS_SERVICE)
            .expect("caddy in the catalog")
            .manifest
            .clone();
        assert!(super::relays_https(&caddy), "the catalog's Caddy relays");
        let mut before = caddy;
        before
            .spec
            .security
            .published_ports
            .retain(|p| p.port != hlb_ingress::caddyfile::RELAY_HTTPS_PORT);
        assert!(!super::relays_https(&before));
    }

    #[test]
    fn the_link_never_writes_the_meshs_files() {
        let mesh = crate::MESH_TUNNEL;
        assert_ne!(TUNNEL.unit, mesh.unit);
        assert_ne!(TUNNEL.interface, mesh.interface);
        assert_ne!(TUNNEL.config_path, mesh.config_path);
        assert_ne!(TUNNEL.firewall_path, mesh.firewall_path);
    }
}
