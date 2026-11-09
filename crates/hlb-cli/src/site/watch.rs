//! The site's watch, put in place by `hlb site add` and `sync` after the door: the
//! site's ntfy, Gatus probing every name the house serves, and the edge serving both
//! under the site's own names (`hlb_engine::site_watch`).
//!
//! Gatus's configuration is a file of the VPS, two of them waiting beside it — the
//! house's and the promoted site's — so that the promotion, run on the VPS with no
//! house to ask, swaps the page as it swaps the door.

use std::net::Ipv4Addr;
use std::time::Duration;

use hlb_bootstrap::provision;
use hlb_bootstrap::Runner;
use hlb_engine::site_watch::{
    self, ANNOUNCED, CONFIG_DIR, GATUS_BEFORE, GATUS_HOME, GATUS_LIVE, GATUS_PROMOTED,
};
use hlb_engine::{ingress::CONTROLLER_SERVICE, lifeboat};
use hlb_ingress::status_page::{self, Page, Probe};
use hlb_mesh::site::Site;
use hlb_orchestrator::{Orchestrator as _, SwarmOrchestrator};
use hlb_secrets::Vault;
use hlb_state::State;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// How long ntfy, Gatus and the edge may take to run, their images' first pull included.
const HEALTHY_WITHIN_SECS: u64 = 180;

/// Where a configuration is checked: Gatus reads `config/config.yaml` when told no
/// other path, so the check needs no variable on its command line.
const CHECK_DIR: &str = "/etc/hlb/site-watch-check";

/// How long Gatus is given to refuse a configuration: it parses the file before it
/// listens, and exits at once on one it cannot read.
const REFUSES_WITHIN: Duration = Duration::from_secs(4);

/// What the watch serves, said to the owner.
pub struct Watching {
    pub page: String,
    pub alerts: String,
    pub probes: usize,
}

/// The site's own names, as the door sends them to the edge — none where the watch
/// cannot run: a door detouring a name to an edge that does not exist is a dead name.
pub async fn own_names(state: &State) -> Result<Vec<String>> {
    let exposure = state.exposure().await?;
    let Some(e) = exposure.as_ref() else {
        return Ok(Vec::new());
    };
    if lifeboat::site_tls(Some(e)).is_err() || taken(state, &e.domain).await?.is_some() {
        return Ok(Vec::new());
    }
    Ok(names(&e.domain))
}

fn names(domain: &str) -> Vec<String> {
    let mut n = vec![
        site_watch::status_host(domain),
        site_watch::alerts_host(domain),
    ];
    n.sort();
    n
}

/// A house route already answering one of the site's names: its visitors would be
/// sent to the site's page instead.
async fn taken(state: &State, domain: &str) -> Result<Option<String>> {
    let own = names(domain);
    Ok(state
        .published_ingress()
        .await?
        .into_iter()
        .map(|(host, _, _)| host)
        .find(|h| own.iter().any(|o| o.eq_ignore_ascii_case(h))))
}

/// A secret of the watch's, drawn once.
async fn drawn(
    state: &State,
    vault: &Vault,
    name: &str,
    purpose: &str,
    draw: fn() -> String,
) -> Result<String> {
    if let Some(ct) = state.secret(name).await? {
        return Ok(vault.decrypt(&ct)?);
    }
    state
        .store_secret_if_absent(name, &vault.encrypt(&draw())?, purpose)
        .await?;
    let ct = state
        .secret(name)
        .await?
        .ok_or_else(|| format!("{name} was stored and is not in the vault"))?;
    Ok(vault.decrypt(&ct)?)
}

/// Every name the house's Caddy last published, by what the family calls it.
///
/// What was PUBLISHED, not what the manifests ask: a name the house does not serve is
/// not one a visitor reaches.
async fn probes(state: &State) -> Result<Vec<Probe>> {
    let mut out = Vec::new();
    for (host, app, public) in state.published_ingress().await? {
        let title = if app == CONTROLLER_SERVICE {
            "Homelabus".to_string()
        } else {
            state
                .app_manifest(&app)
                .await
                .ok()
                .and_then(|m| m.metadata.display_name)
                .unwrap_or_else(|| app.clone())
        };
        out.push(Probe {
            title,
            host,
            public,
        });
    }
    Ok(out)
}

/// The house's Caddy on the site link: the member running on the node labelled for the
/// ingress — or the only member, which nothing else could be. `None` otherwise.
async fn house_address(s: &Site) -> Option<Ipv4Addr> {
    if let [only] = s.members.as_slice() {
        return Some(only.address);
    }
    let nodes = SwarmOrchestrator::connect()
        .await
        .ok()?
        .nodes()
        .await
        .ok()?;
    let ingress = nodes.iter().find(|n| n.ingress)?;
    s.member(&ingress.hostname).map(|m| m.address)
}

fn argv(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| s.to_string()).collect()
}

async fn run(
    hub: &dyn Runner,
    what: &str,
    cmd: Vec<String>,
) -> std::result::Result<String, String> {
    let out = hub.run(&cmd).await.map_err(|e| format!("{what}: {e}"))?;
    if out.ok() {
        Ok(out.stdout)
    } else {
        Err(format!("{what}: {}", out.stderr.trim()))
    }
}

/// Runs Gatus on `content` with no network: still running after a few seconds, it
/// accepted the file.
///
/// 🔴 Checked before it is put in place: Gatus watching a file it cannot parse keeps
/// the last one it could — until its next restart, which then fails, page and alerts
/// with it.
async fn check(hub: &dyn Runner, content: &str) -> std::result::Result<(), String> {
    provision::install_file(hub, &format!("{CHECK_DIR}/config.yaml"), content, 0o600)
        .await
        .map_err(|e| e.to_string())?;
    let mount = format!(
        "type=bind,src={CHECK_DIR},dst={},readonly",
        site_watch::MOUNTED_AT
    );
    let id = run(
        hub,
        "starting Gatus on its new configuration",
        argv(&[
            "docker",
            "run",
            "-d",
            "--network",
            "none",
            "--read-only",
            "--tmpfs",
            "/data",
            "--cap-drop",
            "ALL",
            "--mount",
            &mount,
            status_page::IMAGE,
        ]),
    )
    .await?;
    let id = id.trim().to_string();
    tokio::time::sleep(REFUSES_WITHIN).await;
    let running = run(
        hub,
        "reading the check's container",
        argv(&["docker", "inspect", "-f", "{{.State.Running}}", &id]),
    )
    .await;
    let logs = if running.as_deref().map(str::trim) == Ok("true") {
        None
    } else {
        let out = hub
            .run(&argv(&["docker", "logs", "--tail", "40", &id]))
            .await
            .map(|o| format!("{}{}", o.stdout, o.stderr))
            .unwrap_or_default();
        Some(out)
    };
    hub.run(&argv(&["docker", "rm", "-f", &id])).await.ok();
    hub.run(&argv(&["rm", "-f", &format!("{CHECK_DIR}/config.yaml")]))
        .await
        .ok();
    running?;
    match logs {
        None => Ok(()),
        Some(l) => Err(format!("Gatus refuses its configuration: {}", refusal(&l))),
    }
}

/// Why Gatus stopped: its `panic:` line — the log ends on a Go stack, whose last line
/// names `main.go` and nothing else (measured on v5.38.0).
fn refusal(logs: &str) -> &str {
    logs.lines()
        .find_map(|l| l.trim().strip_prefix("panic: "))
        .or_else(|| logs.trim().lines().last())
        .unwrap_or("it stopped and said nothing")
}

/// Puts `content` at `name` in the watch's directory, checked first; whether it moved.
async fn put(hub: &dyn Runner, name: &str, content: &str) -> std::result::Result<bool, String> {
    let path = format!("{CONFIG_DIR}/{name}");
    if hub
        .read_file(&path)
        .await
        .map_err(|e| e.to_string())?
        .as_deref()
        == Some(content)
    {
        return Ok(false);
    }
    check(hub, content).await?;
    // It holds ntfy's token: root's alone, which Gatus runs as.
    provision::install_file(hub, &path, content, 0o600)
        .await
        .map_err(|e| e.to_string())?;
    Ok(true)
}

/// The shell lines putting `from` in Gatus's place — a copy renamed over it, so Gatus
/// never reads half a file. Shared by the promotion and the return.
pub fn swap_to(from: &str) -> Vec<String> {
    argv(&[
        "sh",
        "-c",
        &format!(
            "[ ! -f {CONFIG_DIR}/{from} ] || {{ cp {CONFIG_DIR}/{from} {CONFIG_DIR}/{GATUS_LIVE}.new \
             && mv -f {CONFIG_DIR}/{GATUS_LIVE}.new {CONFIG_DIR}/{GATUS_LIVE}; }}"
        ),
    ])
}

/// Puts the watch in place on the site, or brings it up to date.
pub async fn deploy(state: &State, vault: &Vault, s: &Site) -> Result<Watching> {
    let exposure = state.exposure().await?;
    // Refused before anything is touched: the edge asks for its certificates as the
    // lifeboat's Caddy does, never with the house's authority nor its DNS token.
    let tls = lifeboat::site_tls(exposure.as_ref())?;
    let e = exposure
        .as_ref()
        .ok_or("the house's exposure was never configured")?;
    if let Some(host) = taken(state, &e.domain).await? {
        return Err(format!(
            "{host} is already a house route: the site's page would take its visitors"
        )
        .into());
    }
    let status = site_watch::status_host(&e.domain);
    let alerts = site_watch::alerts_host(&e.domain);
    let page_url = format!("https://{status}");
    let caddy = state
        .app_manifest(hlb_types::manifest::INGRESS_SERVICE)
        .await?;

    let reader = drawn(
        state,
        vault,
        site_watch::READER_SECRET,
        "the owner's phone, reading the site's alerts",
        || hlb_secrets::generate_password(32),
    )
    .await?;
    let token = drawn(
        state,
        vault,
        site_watch::TOKEN_SECRET,
        "the site's Gatus, publishing its alerts",
        site_watch::draw_token,
    )
    .await?;

    let ack = drawn(
        state,
        vault,
        site_watch::ACK_SECRET,
        "the site's alerts' button, announcing on the status page",
        site_watch::draw_token,
    )
    .await?;
    let announcer = drawn(
        state,
        vault,
        site_watch::ANNOUNCER_SECRET,
        "the site's announcer, reading the alerts and their acknowledgements",
        site_watch::draw_token,
    )
    .await?;

    let push_token = drawn(
        state,
        vault,
        site_watch::PUSH_SECRET,
        "the house's daemon, pushing its heartbeats to the site's Gatus",
        || hlb_secrets::generate_password(32),
    )
    .await?;

    let probes = probes(state).await?;
    let page = Page {
        probes: probes.clone(),
        house: house_address(s).await,
        token: token.clone(),
        url: page_url.clone(),
        push_token,
        alerts_url: format!("https://{alerts}"),
        ack_token: ack.clone(),
    };
    if status_page::probes_nothing(&page) {
        return Err(
            "the house publishes no name and its Caddy's node is unknown: the \
                    page would probe nothing, and Gatus refuses to start so"
                .into(),
        );
    }
    let served = super::lifeboat::names(state, vault).await?;

    let (tmp, ssh) = super::lifeboat::ssh_to(state, vault, s).await?;
    let socket = tmp.path().join("docker.sock");
    let _bridge = ssh.docker_socket(&socket).await?;
    let site = SwarmOrchestrator::connect_unix(&socket).await?;
    site.ensure_network(site_watch::NETWORK).await?;
    let door = site
        .service_address(hlb_ingress::front_door::SERVICE, site_watch::NETWORK)
        .await?
        .ok_or("the front door is not on the watch's network: hlb site sync --apply")?;
    let subnet = site
        .network_subnets(site_watch::NETWORK)
        .await?
        .into_iter()
        .next()
        .ok_or("the watch's network has no subnet on the site")?;

    // The two files first, then the one running, chosen as the door chooses its own.
    let home = status_page::render(&page, &[]);
    let promoted = status_page::render(&page, &served);
    put(&ssh, GATUS_HOME, &home).await?;
    put(&ssh, GATUS_PROMOTED, &promoted).await?;
    let is_promoted = ssh.read_file(lifeboat::PROMOTED_MARK).await?.is_some();
    put(
        &ssh,
        GATUS_LIVE,
        if is_promoted { &promoted } else { &home },
    )
    .await?;

    let tokens = site_watch::Tokens {
        gatus: token,
        ack,
        announcer,
    };
    let ntfy = site_watch::ntfy(&site_watch::ntfy_config(&alerts, &reader, &tokens));
    site.deploy(&ntfy).await?;
    site.wait_healthy(&ntfy.name, HEALTHY_WITHIN_SECS).await?;

    // Before the announcer and Gatus mount it: Swarm refuses a bind on a path that
    // does not exist. Root's, which both run as.
    let announced = format!("{CONFIG_DIR}/{ANNOUNCED}");
    run(
        &ssh,
        "creating the announcements' directory",
        argv(&["install", "-d", "-m", "0755", &announced]),
    )
    .await?;
    let announcer = site_watch::announcer(&tokens.announcer, &status_page::texts(&page, &served));
    site.deploy(&announcer).await?;
    site.wait_healthy(&announcer.name, HEALTHY_WITHIN_SECS)
        .await?;
    // The owner's words reach the page from the site itself: the house may be down.
    provision::install_file(
        &ssh,
        site_watch::ANNOUNCE_COMMAND,
        &site_watch::announce_command(),
        0o700,
    )
    .await?;

    let hosts: Vec<String> = probes.iter().map(|p| p.host.clone()).collect();
    let acme_root = e.acme_ca_root.as_deref();
    let gatus = site_watch::gatus(&hosts, &door, acme_root);
    site.deploy(&gatus).await?;
    site.wait_healthy(&gatus.name, HEALTHY_WITHIN_SECS).await?;
    // The page ran from this file before it read a directory: nothing reads it now.
    run(
        &ssh,
        "removing the page's former file",
        argv(&["rm", "-f", &format!("{CONFIG_DIR}/{GATUS_BEFORE}")]),
    )
    .await?;

    let mut ingress = site_watch::edge_caddyfile(&e.domain, tls, &subnet);
    ingress.acme_root = e.acme_ca_root.clone();
    let edge = site_watch::edge(&caddy, &ingress);
    let mut validate = edge.clone();
    validate.name = format!("{}-check", edge.name);
    validate.command = argv(&[
        "caddy",
        "validate",
        "--config",
        lifeboat::CADDYFILE,
        "--adapter",
        "caddyfile",
    ]);
    validate.healthcheck = None;
    let checked = site.run_job(&validate.job(), HEALTHY_WITHIN_SECS).await?;
    if !checked.succeeded {
        return Err(format!(
            "the site's edge refuses its file: {}",
            checked.output.join(" / ")
        )
        .into());
    }
    site.deploy(&edge).await?;
    site.wait_healthy(&edge.name, HEALTHY_WITHIN_SECS).await?;

    Ok(Watching {
        page: page_url,
        alerts: format!("https://{alerts}"),
        probes: probes.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_swap_renames_a_copy_and_skips_a_file_never_written() {
        let line = swap_to(GATUS_PROMOTED).join(" ");
        assert!(
            line.contains(&format!("[ ! -f {CONFIG_DIR}/{GATUS_PROMOTED} ] ||")),
            "{line}"
        );
        assert!(
            line.contains(&format!(
                "mv -f {CONFIG_DIR}/{GATUS_LIVE}.new {CONFIG_DIR}/{GATUS_LIVE}"
            )),
            "{line}"
        );
    }

    #[test]
    fn a_refusal_is_read_off_the_panic_not_the_stack() {
        let logs = "2026/11/09 [config.LoadConfiguration] Reading configuration\n\
                    panic: error parsing config: yaml: line 1: did not find expected ','\n\
                    \n\
                    goroutine 1 [running]:\n\
                    main.main()\n\
                    \t/app/main.go:32 +0x21a\n";
        assert_eq!(
            refusal(logs),
            "error parsing config: yaml: line 1: did not find expected ','"
        );
        assert_eq!(refusal(""), "it stopped and said nothing");
    }

    #[test]
    fn the_site_s_names_are_its_status_and_its_alerts() {
        assert_eq!(
            names("example.fr"),
            vec!["alerts.example.fr", "status.example.fr"]
        );
    }
}
