//! Pre-bootstrap checks.
//!
//! The principle: **you approve a plan, you do not endure a script.** These checks run
//! before any modification and produce a readable verdict.
//!
//! Every refusal here corresponds to a documented trap - not to decorative caution. A
//! bootstrap failing halfway on a half-configured machine is far worse than a clean
//! refusal at the start.

use crate::deps::DOCKER_FLOOR;
use crate::distro::Distro;
use crate::docker::DaemonConfig;

/// A finding's severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    /// Informational: nothing to do.
    Ok,
    /// Worth knowing, but we continue.
    Warning,
    /// 🔴 On refuse de continuer.
    Blocking,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    pub name: &'static str,
    pub level: Level,
    pub detail: String,
    /// What to do. Empty when there is nothing to do.
    pub remedy: Option<String>,
}

impl Check {
    fn ok(name: &'static str, detail: impl Into<String>) -> Self {
        Self {
            name,
            level: Level::Ok,
            detail: detail.into(),
            remedy: None,
        }
    }
    fn warn(name: &'static str, detail: impl Into<String>, remedy: impl Into<String>) -> Self {
        Self {
            name,
            level: Level::Warning,
            detail: detail.into(),
            remedy: Some(remedy.into()),
        }
    }
    fn block(name: &'static str, detail: impl Into<String>, remedy: impl Into<String>) -> Self {
        Self {
            name,
            level: Level::Blocking,
            detail: detail.into(),
            remedy: Some(remedy.into()),
        }
    }

    pub fn describe(&self) -> String {
        let brand = match self.level {
            Level::Ok => "✓",
            Level::Warning => "🟠",
            Level::Blocking => "🔴",
        };
        let mut s = format!("{brand} {}: {}", self.name, self.detail);
        if let Some(r) = &self.remedy {
            s.push_str(&format!("\n     → {r}"));
        }
        s
    }
}

/// What was observed on the machine, before judging.
#[derive(Debug, Clone, Default)]
pub struct Observation {
    pub os_release: String,
    /// Output of `docker --version`, if the command exists.
    pub docker_version: Option<String>,
    /// Docker installed through snap? Its confinement breaks some mounts.
    pub docker_is_snap: bool,
    /// Podman present instead of Docker?
    pub podman_present: bool,
    pub total_memory_mb: Option<u64>,
    pub free_disk_mb: Option<u64>,
    /// Is the clock synchronised? (`timedatectl`, `chronyc`...)
    pub clock_synced: Option<bool>,
    /// The effective user. The bootstrap needs administration rights.
    pub is_root: bool,
    /// cgroups v2: modern Docker depends on it for resource limits.
    pub cgroups_v2: Option<bool>,
    /// `/etc/docker/daemon.json`, when there is one.
    pub daemon_json: Option<String>,
    /// Waiting for a reboot to run its newest kernel? `None`: could not tell.
    pub reboot_required: Option<bool>,
}

#[derive(Debug, Clone, Default)]
pub struct Report {
    pub checks: Vec<Check>,
    pub distro: Option<Distro>,
}

impl Report {
    /// Can the bootstrap start?
    pub fn can_proceed(&self) -> bool {
        !self.checks.iter().any(|c| c.level == Level::Blocking)
    }

    pub fn blocking(&self) -> Vec<&Check> {
        self.checks
            .iter()
            .filter(|c| c.level == Level::Blocking)
            .collect()
    }

    pub fn warnings(&self) -> Vec<&Check> {
        self.checks
            .iter()
            .filter(|c| c.level == Level::Warning)
            .collect()
    }
}

/// Minimum memory for a usable node. Below it, Swarm starts but everything collapses
/// on the first app.
const MIN_MEMORY_MB: u64 = 1800;

/// Minimum space: Docker images are large, and a full disk is the number-one homelab
/// failure.
const MIN_DISK_MB: u64 = 8192;

pub fn run(obs: &Observation) -> Report {
    let mut checks = Vec::new();

    // 1. Rights. Without them, nothing that follows can succeed.
    if obs.is_root {
        checks.push(Check::ok("privileges", "administrator"));
    } else {
        checks.push(Check::block(
            "privileges",
            "the bootstrap installs packages and configures the network",
            "run it again with sudo, or from an administrator account",
        ));
    }

    // 2. Distribution.
    let distro = Distro::parse(&obs.os_release);
    match &distro {
        Some(d) => checks.push(Check::ok(
            "distribution",
            format!("{} (family {})", d.pretty_name, d.family.as_str()),
        )),
        None => checks.push(Check::block(
            "distribution",
            "cannot identify the distribution from /etc/os-release",
            "unsupported distribution - open an issue with the contents of \
             /etc/os-release",
        )),
    }

    // 3. 🔴 Podman. It emulates the container API but NOT Swarm: we would fail far
    // later, with an incomprehensible message.
    if obs.podman_present && obs.docker_version.is_none() {
        checks.push(Check::block(
            "container engine",
            "Podman detected, Docker absent - Podman does not implement Swarm",
            "install Docker Engine, or choose another node",
        ));
    }

    // 4. 🔴 Docker from snap. The confinement blocks some volume mounts, and the
    // failure happens when an app is deployed, not here.
    if obs.docker_is_snap {
        checks.push(Check::block(
            "docker",
            "Docker installed through snap: its confinement breaks volume mounts",
            "snap remove docker, then let Homelabus install the official package",
        ));
    } else {
        match &obs.docker_version {
            // 🔴 Not replaced: it was not installed by Homelabus, and swapping the
            // engine under someone's containers is how a machine loses its other uses.
            Some(v) if !crate::deps::version_at_least(v, DOCKER_FLOOR) => {
                checks.push(Check::block(
                    "docker",
                    format!("{v} - Swarm here needs {DOCKER_FLOOR} or newer"),
                    "remove it (the distribution's `docker.io` is the usual one), then run \
                     this again: Homelabus installs Docker's own packages",
                ))
            }
            Some(v) => checks.push(Check::ok("docker", format!("present ({v})"))),
            None => checks.push(Check::ok("docker", "absent - will be installed")),
        }
    }

    // 4b. An existing daemon.json is never rewritten — so what it says is judged here.
    match crate::docker::judge_daemon_config(obs.daemon_json.as_deref()) {
        DaemonConfig::Absent | DaemonConfig::Fine => {}
        DaemonConfig::LiveRestore => checks.push(Check::block(
            "docker configuration",
            "\"live-restore\": true in /etc/docker/daemon.json - Swarm refuses to run with it",
            "set it to false (or remove it), then restart Docker",
        )),
        DaemonConfig::Unreadable(e) => checks.push(Check::block(
            "docker configuration",
            format!("/etc/docker/daemon.json does not parse ({e}) - Docker will not start"),
            "fix or remove the file",
        )),
        DaemonConfig::UnboundedLogs => checks.push(Check::warn(
            "docker configuration",
            "container logs are never rotated - one chatty container fills the disk",
            "add \"log-opts\": {\"max-size\": \"10m\", \"max-file\": \"3\"} to \
             /etc/docker/daemon.json and restart Docker",
        )),
    }

    // An existing Docker keeps its proxy: said, never rewritten.
    if obs.docker_version.is_some() && crate::docker::userland_proxy_on(obs.daemon_json.as_deref())
    {
        checks.push(Check::warn(
            "docker configuration",
            "Docker's userland proxy is on - an IPv6 client of the ingress arrives as the \
             bridge's gateway, a private address, and private routes answer it",
            "add \"userland-proxy\": false to /etc/docker/daemon.json and restart Docker, \
             or publish no AAAA record for this node",
        ));
    }

    // 5. Memory.
    match obs.total_memory_mb {
        Some(m) if m < MIN_MEMORY_MB => checks.push(Check::block(
            "memory",
            format!("{m} MB - not enough for a usable Swarm node"),
            format!("at least {MIN_MEMORY_MB} MB are needed"),
        )),
        Some(m) if m < 4096 => checks.push(Check::warn(
            "memory",
            format!("{m} MB - a constrained node"),
            "keep this node on the \"light\" tier: no database on it",
        )),
        Some(m) => checks.push(Check::ok("memory", format!("{m} MB"))),
        None => checks.push(Check::warn(
            "memory",
            "not detected",
            "check by hand that there are at least 2 GB",
        )),
    }

    // 6. Disk.
    match obs.free_disk_mb {
        Some(d) if d < MIN_DISK_MB => checks.push(Check::block(
            "disk",
            format!("{d} MB free - the Docker images will not fit"),
            format!("free up space: at least {MIN_DISK_MB} MB"),
        )),
        Some(d) => checks.push(Check::ok("disk", format!("{d} MB free"))),
        None => checks.push(Check::warn("disk", "not detected", "check the free space")),
    }

    // 7. 🔴 The clock. Drift breaks Swarm's Raft encryption AND certificate
    // validation. The symptom - "certificate not yet valid", nodes drifting apart -
    // never suggests the clock.
    match obs.clock_synced {
        Some(true) => checks.push(Check::ok("clock", "synchronised")),
        Some(false) => checks.push(Check::warn(
            "clock",
            "not synchronised - breaks Swarm and TLS validation",
            "chrony will be installed; then check the synchronisation succeeds",
        )),
        None => checks.push(Check::warn(
            "clock",
            "synchronisation state unknown",
            "make sure an NTP service is running",
        )),
    }

    // 8. cgroups v2 - needed for resource limits.
    match obs.cgroups_v2 {
        Some(true) => checks.push(Check::ok("cgroups", "v2")),
        Some(false) => checks.push(Check::warn(
            "cgroups",
            "v1 - per-container resource limits will be partial",
            "a reboot with systemd.unified_cgroup_hierarchy=1 enables them. \
             🔴 Homelabus NEVER reboots a machine on its own: that is yours to do",
        )),
        None => {}
    }

    // 9. A pending reboot. Not blocking: it is the next `hlb node upgrade`'s job, and
    // joining first lets that one drain the node properly.
    if obs.reboot_required == Some(true) {
        checks.push(Check::warn(
            "reboot",
            "a newer kernel is installed than the one running",
            "`hlb node upgrade` reboots it once its services have moved away",
        ));
    }

    Report { checks, distro }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn healthy() -> Observation {
        Observation {
            os_release: "ID=debian\nPRETTY_NAME=\"Debian 12\"\n".into(),
            docker_version: Some("29.9.2".into()),
            docker_is_snap: false,
            podman_present: false,
            total_memory_mb: Some(16384),
            free_disk_mb: Some(102_400),
            clock_synced: Some(true),
            is_root: true,
            cgroups_v2: Some(true),
            daemon_json: Some(crate::docker::DAEMON_CONFIG.into()),
            reboot_required: Some(false),
        }
    }

    #[test]
    fn an_existing_docker_proxying_ipv6_is_said_without_blocking() {
        for daemon_json in [None, Some(r#"{"log-driver": "local"}"#.to_string())] {
            let mut o = healthy();
            o.daemon_json = daemon_json;
            let r = run(&o);
            assert!(r.can_proceed());
            assert!(
                r.warnings()
                    .iter()
                    .any(|c| c.detail.contains("userland proxy")),
                "{:?}",
                r.warnings()
            );
        }
        // Docker yet to be installed gets Homelabus's own file.
        let mut o = healthy();
        (o.docker_version, o.daemon_json) = (None, None);
        assert!(run(&o).warnings().is_empty());
    }

    #[test]
    fn a_docker_below_the_floor_blocks_rather_than_being_replaced() {
        let mut o = healthy();
        o.docker_version = Some("20.10.24+dfsg1".into());
        let r = run(&o);
        assert!(!r.can_proceed());
        assert!(r.blocking()[0].detail.contains("20.10.24"));
    }

    #[test]
    fn live_restore_blocks_before_swarm_refuses_it() {
        let mut o = healthy();
        o.daemon_json = Some(r#"{"live-restore": true}"#.into());
        assert!(!run(&o).can_proceed());
    }

    #[test]
    fn unrotated_logs_warn_but_do_not_block() {
        let mut o = healthy();
        o.daemon_json = Some("{}".into());
        let r = run(&o);
        assert!(r.can_proceed());
        assert!(r.warnings().iter().any(|c| c.detail.contains("rotated")));
    }

    #[test]
    fn a_pending_reboot_is_said_without_blocking() {
        let mut o = healthy();
        o.reboot_required = Some(true);
        let r = run(&o);
        assert!(r.can_proceed());
        assert!(r.warnings().iter().any(|c| c.name == "reboot"));
    }

    #[test]
    fn a_healthy_machine_passes() {
        let r = run(&healthy());
        assert!(r.can_proceed(), "{:?}", r.blocking());
        assert!(r.warnings().is_empty());
        assert!(r.distro.is_some());
    }

    #[test]
    fn without_privileges_nothing_starts() {
        let mut o = healthy();
        o.is_root = false;
        let r = run(&o);
        assert!(!r.can_proceed());
        assert!(r.blocking()[0]
            .remedy
            .as_ref()
            .expect("remedy")
            .contains("sudo"));
    }

    #[test]
    fn podman_without_docker_is_refused_early() {
        // 🔴 Podman does not implement Swarm. Without this check the failure would
        // happen far later with an incomprehensible message.
        let mut o = healthy();
        o.podman_present = true;
        o.docker_version = None;
        let r = run(&o);

        assert!(!r.can_proceed());
        assert!(r.blocking()[0].detail.contains("Swarm"));
    }

    #[test]
    fn podman_alongside_docker_is_fine() {
        // Having both is not a problem: Docker is what will be used.
        let mut o = healthy();
        o.podman_present = true;
        assert!(run(&o).can_proceed());
    }

    #[test]
    fn snap_docker_is_refused() {
        // The snap confinement breaks volume mounts - and the failure would happen
        // when an app is deployed, not here.
        let mut o = healthy();
        o.docker_is_snap = true;
        let r = run(&o);

        assert!(!r.can_proceed());
        let b = r.blocking()[0];
        assert!(b.detail.contains("snap"));
        assert!(b.remedy.as_ref().expect("remedy").contains("snap remove"));
    }

    #[test]
    fn an_unknown_distribution_is_refused_rather_than_guessed() {
        let mut o = healthy();
        o.os_release = "ID=exotique\n".into();
        let r = run(&o);
        assert!(!r.can_proceed());
        assert!(r.distro.is_none());
    }

    #[test]
    fn a_small_node_warns_without_blocking() {
        // 4 GB nodes must pass, with a useful warning.
        let mut o = healthy();
        o.total_memory_mb = Some(3900);
        let r = run(&o);

        assert!(r.can_proceed());
        let w = r.warnings();
        assert!(w
            .iter()
            .any(|c| c.remedy.as_ref().is_some_and(|r| r.contains("light"))));
    }

    #[test]
    fn a_tiny_node_is_refused() {
        let mut o = healthy();
        o.total_memory_mb = Some(512);
        assert!(!run(&o).can_proceed());
    }

    #[test]
    fn insufficient_disk_blocks() {
        let mut o = healthy();
        o.free_disk_mb = Some(2000);
        let r = run(&o);
        assert!(!r.can_proceed());
        assert!(r.blocking()[0].detail.contains("Docker images"));
    }

    #[test]
    fn an_unsynced_clock_warns_loudly() {
        // Not blocking - chrony will be installed - but it must be said: the symptom
        // of drift never suggests the clock.
        let mut o = healthy();
        o.clock_synced = Some(false);
        let r = run(&o);

        assert!(r.can_proceed());
        assert!(r.warnings().iter().any(|c| c.name == "clock"));
    }

    #[test]
    fn cgroups_v1_says_a_reboot_is_needed_but_never_does_it() {
        // 🔴 Homelabus never reboots a machine on its own.
        let mut o = healthy();
        o.cgroups_v2 = Some(false);
        let r = run(&o);

        assert!(r.can_proceed());
        let w = r
            .warnings()
            .into_iter()
            .find(|c| c.name == "cgroups")
            .expect("finding");
        let remedy = w.remedy.as_ref().expect("remedy");
        assert!(remedy.contains("NEVER"), "{remedy}");
        assert!(remedy.contains("yours to do"));
    }

    #[test]
    fn every_problem_comes_with_a_remedy() {
        // A diagnosis with no remedy forces the user to search alone.
        let mut o = healthy();
        o.is_root = false;
        o.docker_is_snap = true;
        o.total_memory_mb = Some(100);
        o.clock_synced = Some(false);

        for c in run(&o).checks.iter().filter(|c| c.level != Level::Ok) {
            assert!(c.remedy.is_some(), "{} has no remedy", c.name);
        }
    }

    #[test]
    fn descriptions_are_readable() {
        let r = run(&healthy());
        for c in &r.checks {
            assert!(c.describe().contains(c.name));
        }
    }
}
