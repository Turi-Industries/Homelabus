//! The site's name server: Knot, a secondary of the house's zone, the only server the
//! internet asks (`hlb_ingress::zone` says why the house's is hidden).
//!
//! As the door's, its configuration is a file in a directory mounted read-only, checked
//! by the image that will run it before it replaces the one running, and reloaded in
//! place: a Swarm config is immutable, and a new task would leave the domain unanswered
//! while it starts.

use std::time::Duration;

use hlb_bootstrap::provision;
use hlb_bootstrap::Runner;
use hlb_ingress::zone::{
    self, TransferKey, PORT, SITE_CONFIG_DIR, SITE_IMAGE, SITE_PORT, SITE_SERVICE, SITE_VOLUME,
    SOCKET,
};
use hlb_mesh::site::Site;

/// What became of the name server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Created,
    /// Its service was made by another revision of this code: removed and made again.
    Replaced,
    Reloaded,
    Unchanged,
}

impl Outcome {
    pub fn says(self) -> &'static str {
        match self {
            Outcome::Created => "started",
            Outcome::Replaced => "rebuilt to this revision",
            Outcome::Reloaded => "reloaded with the new configuration",
            Outcome::Unchanged => "already up to date",
        }
    }
}

/// The label carrying the fingerprint of the arguments the service was created with.
/// A stored name.
const SPEC_LABEL: &str = "homelabus.site-knot.spec";

/// Where the configuration directory is mounted: where the image looks.
const MOUNTED_AT: &str = "/etc/knot";

/// The file Knot runs.
const LIVE: &str = "knot.conf";

/// Knot's own user in its image: the configuration holds the key, readable by it alone.
const KNOT_GROUP: &str = "53";

/// How long a new task may take to run, the image's first pull included.
const START_WITHIN: Duration = Duration::from_secs(90);

/// How long the site may take to hold the house's serial: told by NOTIFY, it asks at
/// once, and a transfer of a house's zone is a few kilobytes.
const TRANSFER_WITHIN: Duration = Duration::from_secs(60);

fn at(name: &str) -> String {
    format!("{SITE_CONFIG_DIR}/{name}")
}

fn staged() -> String {
    at("knot.conf.new")
}

fn argv(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| s.to_string()).collect()
}

async fn run(hub: &dyn Runner, what: &str, cmd: Vec<String>) -> Result<String, String> {
    let out = hub.run(&cmd).await.map_err(|e| format!("{what}: {e}"))?;
    if out.ok() {
        Ok(out.stdout)
    } else {
        Err(format!("{what}: {}", out.stderr.trim()))
    }
}

/// The site's configuration for this site's members: a house node's address on the
/// link is where Knot runs, whichever it is.
pub fn config(s: &Site, apex: &str, key: &TransferKey) -> String {
    let house: Vec<_> = s.members.iter().map(|m| m.address).collect();
    zone::site_conf(apex, &house, key)
}

/// The service's arguments after `docker service create`, its label left out.
fn spec() -> Vec<String> {
    let config = format!("type=bind,src={SITE_CONFIG_DIR},dst={MOUNTED_AT},readonly");
    let storage = format!("type=volume,src={SITE_VOLUME},dst={}", zone::STORAGE);
    // Host mode: the routing mesh would hand Knot the ingress network's address for
    // every client, and a resolver's address is what a response-rate limit counts.
    let tcp = format!("mode=host,target={PORT},published={SITE_PORT},protocol=tcp");
    let udp = format!("mode=host,target={PORT},published={SITE_PORT},protocol=udp");
    let health = format!("knotc -s {SOCKET} status");
    let start = format!(
        "mkdir -p {0}/run && exec knotd -c {MOUNTED_AT}/{LIVE}",
        zone::STORAGE
    );
    [
        "--name",
        SITE_SERVICE,
        "--publish",
        &tcp,
        "--publish",
        &udp,
        "--mount",
        &config,
        "--mount",
        &storage,
        // A text configuration is compiled into a database under /tmp at start.
        "--mount",
        "type=tmpfs,dst=/tmp,tmpfs-mode=1777",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--user",
        "53:53",
        "--health-cmd",
        &health,
        // Two tasks cannot hold one host port: the old one stops first.
        "--update-order",
        "stop-first",
        "--detach",
        "--quiet",
        SITE_IMAGE,
        "sh",
        "-c",
        &start,
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

fn fingerprint() -> String {
    hlb_types::token::sha256_hex(spec().join("\0").as_bytes())[..16].to_string()
}

/// Puts `content` in place unless it is there already; whether it was written.
///
/// 🔴 A configuration the image refuses never replaces what is there: checked staged,
/// by the same binary, before the rename.
async fn put(hub: &dyn Runner, content: &str) -> Result<bool, String> {
    let path = at(LIVE);
    if hub
        .read_file(&path)
        .await
        .map_err(|e| e.to_string())?
        .as_deref()
        == Some(content)
    {
        return Ok(false);
    }
    provision::install_file(hub, &staged(), content, 0o640)
        .await
        .map_err(|e| e.to_string())?;
    let group = format!("root:{KNOT_GROUP}");
    run(
        hub,
        "handing the configuration to Knot's user",
        argv(&["chown", &group, &staged()]),
    )
    .await?;
    run(
        hub,
        "opening its directory to Knot's user",
        argv(&["chmod", "755", SITE_CONFIG_DIR]),
    )
    .await?;
    let src = format!("type=bind,src={SITE_CONFIG_DIR},dst={MOUNTED_AT},readonly");
    let file = format!("{MOUNTED_AT}/knot.conf.new");
    run(
        hub,
        "Knot refuses its configuration",
        argv(&[
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--read-only",
            "--tmpfs",
            "/tmp:mode=1777",
            "--cap-drop",
            "ALL",
            "--user",
            "53:53",
            "--mount",
            &src,
            SITE_IMAGE,
            "knotc",
            "-c",
            &file,
            "conf-check",
        ]),
    )
    .await?;
    run(
        hub,
        "putting the configuration in place",
        argv(&["mv", "-f", &staged(), &path]),
    )
    .await?;
    Ok(true)
}

/// Puts the name server in place on the site, or brings it up to date.
pub async fn deploy(
    hub: &dyn Runner,
    s: &Site,
    apex: &str,
    key: &TransferKey,
) -> Result<Outcome, String> {
    if s.members.is_empty() {
        return Err("no house node is linked: there is nothing to transfer the zone from".into());
    }
    let changed = put(hub, &config(s, apex, key)).await?;

    let label = format!("{{{{index .Spec.Labels \"{SPEC_LABEL}\"}}}}");
    let inspected = hub
        .run(&argv(&[
            "docker",
            "service",
            "inspect",
            "--format",
            &label,
            SITE_SERVICE,
        ]))
        .await
        .map_err(|e| e.to_string())?;
    let want = fingerprint();
    let outcome = if !inspected.ok() {
        Outcome::Created
    } else if inspected.stdout.trim() != want {
        // `service update` cannot drop a flag an older spec had: made again whole.
        run(
            hub,
            "removing the name server of an older revision",
            argv(&["docker", "service", "rm", SITE_SERVICE]),
        )
        .await?;
        Outcome::Replaced
    } else if changed {
        knotc(hub, &["reload"]).await?;
        return Ok(Outcome::Reloaded);
    } else {
        return Ok(Outcome::Unchanged);
    };

    let mut create = argv(&["docker", "service", "create", "--label"]);
    create.push(format!("{SPEC_LABEL}={want}"));
    create.extend(spec());
    // A replaced service's ports are released while its task stops: tried again then.
    let tries = if outcome == Outcome::Replaced { 10 } else { 1 };
    for left in (0..tries).rev() {
        match run(hub, "creating the name server's service", create.clone()).await {
            Ok(_) => break,
            Err(e) if left == 0 => return Err(e),
            Err(_) => tokio::time::sleep(Duration::from_secs(1)).await,
        }
    }
    running(hub).await?;
    Ok(outcome)
}

/// The running task's container.
async fn container(hub: &dyn Runner) -> Result<String, String> {
    let filter = format!("label=com.docker.swarm.service.name={SITE_SERVICE}");
    let ids = run(
        hub,
        "finding the name server's container",
        argv(&["docker", "ps", "-q", "--filter", &filter]),
    )
    .await?;
    ids.split_whitespace()
        .next()
        .map(str::to_string)
        .ok_or(format!(
            "no task of {SITE_SERVICE} runs: `docker service ps {SITE_SERVICE}` says why"
        ))
}

/// `knotc` in the running Knot, over its socket.
async fn knotc(hub: &dyn Runner, args: &[&str]) -> Result<String, String> {
    let id = container(hub).await?;
    let mut cmd = argv(&["docker", "exec", &id, "knotc", "-s", SOCKET]);
    cmd.extend(argv(args));
    run(hub, "asking the site's Knot", cmd).await
}

/// The serial the site serves for `apex`, asked as a resolver asks it; `None` before
/// its first transfer.
async fn serial(hub: &dyn Runner, apex: &str) -> Result<Option<u32>, String> {
    let id = container(hub).await?;
    let port = PORT.to_string();
    let out = hub
        .run(&argv(&[
            "docker",
            "exec",
            &id,
            "kdig",
            "@127.0.0.1",
            "-p",
            &port,
            "+norec",
            apex,
            "SOA",
        ]))
        .await
        .map_err(|e| e.to_string())?;
    Ok(out
        .stdout
        .lines()
        .find(|l| !l.starts_with(';') && l.contains("\tSOA\t"))
        .and_then(zone::soa_serial))
}

/// Waits for the site to serve `want`, the serial the house just published.
pub async fn holds(hub: &dyn Runner, apex: &str, want: u32) -> Result<(), String> {
    let started = std::time::Instant::now();
    loop {
        let got = serial(hub, apex).await?;
        // RFC 1982 arithmetic is not needed: Knot's serial is a timestamp, and the site
        // may only ever be behind.
        if got.is_some_and(|g| g >= want) {
            return Ok(());
        }
        if started.elapsed() >= TRANSFER_WITHIN {
            let got = got.map_or("nothing".to_string(), |g| format!("serial {g}"));
            return Err(format!(
                "the site serves {got}, the house {want}, after {} s: the transfer goes over \
                 the site link to port {PORT} of the node running Knot — `docker service logs \
                 {SITE_SERVICE}` on the site says what it was answered",
                TRANSFER_WITHIN.as_secs()
            ));
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

/// Waits for the name server's task to run, and says why it does not — port 53 already
/// taken by a resolver the provider installed is the likely one.
async fn running(hub: &dyn Runner) -> Result<(), String> {
    let started = std::time::Instant::now();
    loop {
        let states = run(
            hub,
            "reading the name server's task",
            argv(&[
                "docker",
                "service",
                "ps",
                "--no-trunc",
                "--format",
                "{{.CurrentState}}\t{{.Error}}",
                SITE_SERVICE,
            ]),
        )
        .await?;
        // Newest first: the task Swarm is on now.
        let newest = states.lines().next().unwrap_or_default();
        if newest.starts_with("Running") {
            return Ok(());
        }
        if started.elapsed() >= START_WITHIN {
            let (state, error) = newest.split_once('\t').unwrap_or((newest, ""));
            return Err(format!(
                "its task does not run ({}){}",
                state.trim(),
                if error.trim().is_empty() {
                    String::new()
                } else {
                    format!(": {}", error.trim())
                }
            ));
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_internet_asks_53_and_knot_binds_no_privileged_port() {
        let spec = spec().join(" ");
        assert!(
            spec.contains("mode=host,target=10053,published=53,protocol=udp"),
            "{spec}"
        );
        assert!(
            spec.contains("mode=host,target=10053,published=53,protocol=tcp"),
            "{spec}"
        );
        assert!(spec.contains("--cap-drop ALL"), "{spec}");
        assert!(spec.contains("--user 53:53"), "{spec}");
        assert!(spec.contains("--read-only"), "{spec}");
        assert!(
            spec.contains(&format!("dst={MOUNTED_AT},readonly")),
            "{spec}"
        );
    }

    #[test]
    fn the_name_server_runs_the_configuration_put_in_place() {
        let spec = spec().join(" ");
        assert!(
            spec.contains(&format!("knotd -c {MOUNTED_AT}/{LIVE}")),
            "{spec}"
        );
        assert!(
            spec.contains(&format!("knotc -s {SOCKET} status")),
            "{spec}"
        );
        assert!(staged().starts_with(SITE_CONFIG_DIR));
        assert_ne!(staged(), at(LIVE));
    }
}
