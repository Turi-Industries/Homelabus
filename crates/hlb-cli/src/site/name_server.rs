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
pub fn config(s: &Site, key: &TransferKey) -> String {
    let house: Vec<_> = s.members.iter().map(|m| m.address).collect();
    zone::site_conf(&house, key)
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

/// Where port 53 stood before the name server took it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Port {
    /// Nothing held it, or the name server already does.
    Free,
    /// systemd-resolved's stub listener held it, and was turned off.
    StubTurnedOff,
}

/// Turns systemd-resolved's stub listener off.
const STUB_OFF: &str = "/etc/systemd/resolved.conf.d/homelabus-site-knot.conf";

/// Where systemd-resolved writes the upstream servers it was given, which the machine
/// asks directly once its stub is gone.
const UPSTREAM_RESOLV: &str = "/run/systemd/resolve/resolv.conf";

/// The programs listening on port 53, by name, from `ss -p`.
fn holders(ss: &str) -> Vec<String> {
    let mut names: Vec<String> = ss
        .lines()
        .filter_map(|l| l.split_once("users:((\"")?.1.split_once('"'))
        .map(|(name, _)| name.to_string())
        .collect();
    names.sort();
    names.dedup();
    names
}

/// Docker holding 53 is the published port of a task: the name server's own, the one
/// service of a site publishing 53. 🔴 `dockerd` itself binds it, not only
/// `docker-proxy`: the lab's VPS showed `dockerd` once the name server ran.
fn docker(holder: &str) -> bool {
    matches!(holder, "dockerd" | "docker-proxy")
}

async fn listening(hub: &dyn Runner) -> Result<Vec<String>, String> {
    let out = run(
        hub,
        "reading what listens on port 53",
        argv(&["ss", "-Hlntup", "sport", "=", ":53"]),
    )
    .await?;
    Ok(holders(&out))
}

/// Frees port 53 for the name server.
///
/// 🔴 Debian's and Ubuntu's cloud images run systemd-resolved, whose stub holds
/// 127.0.0.53:53: Docker then cannot bind 0.0.0.0:53, and the task fails at every start
/// with nothing in `docker service ps`'s newest line to say why — met on the lab's VPS.
/// The machine keeps resolving: it asks the upstream servers resolved was given.
/// Anything else on 53 is the owner's to stop — refused, never killed.
pub async fn free_port(hub: &dyn Runner) -> Result<Port, String> {
    let held = listening(hub).await?;
    let others: Vec<&String> = held.iter().filter(|h| !docker(h)).collect();
    if others.is_empty() {
        return Ok(Port::Free);
    }
    if others.iter().any(|h| *h != "systemd-resolve") {
        return Err(format!(
            "port 53 on the site is held by {}: the internet's questions must reach Knot \
             there — stop it, then run this again",
            others
                .iter()
                .map(|h| h.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    provision::install_file(hub, STUB_OFF, "[Resolve]\nDNSStubListener=no\n", 0o644)
        .await
        .map_err(|e| e.to_string())?;
    let resolv = hub
        .read_file("/etc/resolv.conf")
        .await
        .map_err(|e| e.to_string())?
        .unwrap_or_default();
    // The stub's address, once nothing answers there, would leave the machine resolving
    // nothing — its updates and image pulls included.
    if resolv.contains("127.0.0.53") {
        run(
            hub,
            "pointing the machine at its upstream resolvers",
            argv(&["ln", "-sf", UPSTREAM_RESOLV, "/etc/resolv.conf"]),
        )
        .await?;
    }
    run(
        hub,
        "restarting systemd-resolved without its stub",
        argv(&["systemctl", "restart", "systemd-resolved"]),
    )
    .await?;
    let held = listening(hub).await?;
    if held.iter().any(|h| !docker(h)) {
        return Err(format!(
            "port 53 on the site is still held by {} after systemd-resolved's stub was \
             turned off ({STUB_OFF})",
            held.join(", ")
        ));
    }
    Ok(Port::StubTurnedOff)
}

/// Puts the name server in place on the site, or brings it up to date.
pub async fn deploy(hub: &dyn Runner, s: &Site, key: &TransferKey) -> Result<Outcome, String> {
    if s.members.is_empty() {
        return Err("no house node is linked: there is nothing to transfer the zone from".into());
    }
    let changed = put(hub, &config(s, key)).await?;

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
        // A service up to date may still have no task running — one failing to bind 53
        // is retried by Swarm for ever.
        running(hub).await?;
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
            return Err(not_running(&states));
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

/// Why no task runs, from `docker service ps`'s lines, newest first.
///
/// The newest is often a task Swarm just made again, `Ready` with no error yet: the
/// reason is on the latest one that failed.
fn not_running(states: &str) -> String {
    let newest = states.lines().next().unwrap_or_default();
    let state = newest.split_once('\t').map_or(newest, |(s, _)| s).trim();
    let error = states
        .lines()
        .filter_map(|l| l.split_once('\t'))
        .map(|(_, e)| e.trim().trim_matches('"'))
        .find(|e| !e.is_empty());
    match error {
        Some(e) => format!("its task does not run ({state}): {e}"),
        None => format!("its task does not run ({state})"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    use hlb_bootstrap::runner::{Output, Result as RunResult};

    /// What `ss` printed on the lab's VPS, a Debian 12 cloud image.
    const RESOLVED: &str = "\
udp UNCONN 0 0 127.0.0.54:53 0.0.0.0:* users:((\"systemd-resolve\",pid=391,fd=19))
udp UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:* users:((\"systemd-resolve\",pid=391,fd=17))
tcp LISTEN 0 4096 127.0.0.53%lo:53 0.0.0.0:* users:((\"systemd-resolve\",pid=391,fd=18))
";

    /// A VPS: what listens on 53 before and after resolved restarts, files in a map.
    struct Vps {
        before: &'static str,
        after: &'static str,
        restarted: Mutex<bool>,
        files: Mutex<BTreeMap<String, String>>,
        ran: Mutex<Vec<String>>,
    }

    impl Vps {
        fn new(before: &'static str, after: &'static str, resolv: &str) -> Self {
            let files = BTreeMap::from([("/etc/resolv.conf".to_string(), resolv.to_string())]);
            Vps {
                before,
                after,
                restarted: Mutex::new(false),
                files: Mutex::new(files),
                ran: Mutex::new(Vec::new()),
            }
        }
        fn ran(&self) -> Vec<String> {
            self.ran.lock().expect("lock").clone()
        }
    }

    #[async_trait::async_trait]
    impl Runner for Vps {
        async fn run(&self, argv: &[String]) -> RunResult<Output> {
            let line = argv.join(" ");
            self.ran.lock().expect("lock").push(line.clone());
            let mut restarted = self.restarted.lock().expect("lock");
            let stdout = if line.starts_with("ss ") {
                if *restarted { self.after } else { self.before }.to_string()
            } else {
                if line.starts_with("systemctl restart systemd-resolved") {
                    *restarted = true;
                }
                if line.starts_with("mv -f") {
                    let mut f = self.files.lock().expect("lock");
                    if let Some(c) = f.remove(&argv[2]) {
                        f.insert(argv[3].clone(), c);
                    }
                }
                String::new()
            };
            Ok(Output {
                status: 0,
                stdout,
                stderr: String::new(),
            })
        }
        async fn read_file(&self, path: &str) -> RunResult<Option<String>> {
            Ok(self.files.lock().expect("lock").get(path).cloned())
        }
        async fn write_file(&self, path: &str, content: &str) -> RunResult<()> {
            self.files
                .lock()
                .expect("lock")
                .insert(path.into(), content.into());
            Ok(())
        }
        fn label(&self) -> String {
            "vps".into()
        }
    }

    #[tokio::test]
    async fn resolveds_stub_gives_port_53_up_and_the_machine_still_resolves() {
        let vps = Vps::new(RESOLVED, "", "nameserver 127.0.0.53\noptions edns0\n");
        assert_eq!(free_port(&vps).await, Ok(Port::StubTurnedOff));
        let files = vps.files.lock().expect("lock").clone();
        assert_eq!(
            files.get(STUB_OFF).map(String::as_str),
            Some("[Resolve]\nDNSStubListener=no\n")
        );
        let ran = vps.ran();
        let relinked = ran
            .iter()
            .position(|c| *c == format!("ln -sf {UPSTREAM_RESOLV} /etc/resolv.conf"))
            .expect("resolv.conf points at the upstream servers");
        let restarted = ran
            .iter()
            .position(|c| c == "systemctl restart systemd-resolved")
            .expect("resolved restarted");
        assert!(relinked < restarted, "{ran:?}");
    }

    #[tokio::test]
    async fn a_machine_not_asking_the_stub_keeps_its_resolv_conf() {
        let vps = Vps::new(RESOLVED, "", "nameserver 9.9.9.9\n");
        assert_eq!(free_port(&vps).await, Ok(Port::StubTurnedOff));
        assert!(
            !vps.ran().iter().any(|c| c.starts_with("ln ")),
            "{:?}",
            vps.ran()
        );
    }

    #[tokio::test]
    async fn the_name_servers_own_port_is_left_alone() {
        // The first as the lab's VPS printed it, its name server running.
        for ours in [
            "udp UNCONN 0 0 0.0.0.0:53 0.0.0.0:* users:((\"dockerd\",pid=512,fd=81))\n",
            "udp UNCONN 0 0 0.0.0.0:53 0.0.0.0:* users:((\"docker-proxy\",pid=9,fd=7))\n",
        ] {
            let vps = Vps::new(ours, ours, "nameserver 127.0.0.53\n");
            assert_eq!(free_port(&vps).await, Ok(Port::Free), "{ours}");
            assert!(!vps.ran().iter().any(|c| c.starts_with("systemctl")));
            assert!(!vps.files.lock().expect("lock").contains_key(STUB_OFF));
        }
    }

    #[tokio::test]
    async fn another_server_on_53_is_named_and_never_stopped() {
        let dnsmasq = "udp UNCONN 0 0 0.0.0.0:53 0.0.0.0:* users:((\"dnsmasq\",pid=9,fd=4))\n";
        let vps = Vps::new(dnsmasq, dnsmasq, "nameserver 127.0.0.53\n");
        let refused = free_port(&vps).await.expect_err("dnsmasq holds 53");
        assert!(refused.contains("dnsmasq"), "{refused}");
        assert!(!vps.ran().iter().any(|c| c.starts_with("systemctl")));
    }

    #[tokio::test]
    async fn a_stub_still_listening_after_the_restart_is_reported() {
        let vps = Vps::new(RESOLVED, RESOLVED, "nameserver 127.0.0.53\n");
        let refused = free_port(&vps).await.expect_err("still held");
        assert!(refused.contains("systemd-resolve"), "{refused}");
    }

    #[test]
    fn why_no_task_runs_is_read_on_the_latest_failure() {
        let states = "Ready less than a second ago\t\n\
                      Failed 1 second ago\t\"failed to bind host port 0.0.0.0:53/tcp: address already in use\"\n\
                      Failed 6 seconds ago\t\"an older reason\"\n";
        assert_eq!(
            not_running(states),
            "its task does not run (Ready less than a second ago): failed to bind host port \
             0.0.0.0:53/tcp: address already in use"
        );
        assert_eq!(
            not_running("Pending 3 seconds ago\t\n"),
            "its task does not run (Pending 3 seconds ago)"
        );
    }

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
