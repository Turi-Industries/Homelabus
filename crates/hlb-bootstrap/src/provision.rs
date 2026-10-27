//! Turning a bare machine into a node: the ordered steps, then their execution.
//!
//! [`plan`] is pure — it decides from what [`crate::observe`] saw, and everything it
//! will do can be printed before anything is done. [`execute`] runs the steps in order
//! and stops at the first failure: a later step always assumes the earlier ones held, and
//! pressing on after a failed repository setup would install whatever the distribution
//! happens to carry under the same name.
//!
//! 🔴 **What exists on the machine is not rewritten.** Docker's `daemon.json` is written
//! only when Homelabus installs Docker; the unattended-upgrade switch only when it
//! installs the tool. What is always added are files of its own that only NARROW an
//! existing setup — keeping the engine out of unattended upgrades.

use crate::deps::{DependencyPlan, Presence};
use crate::distro::{Distro, Family, PackageManager};
use crate::docker::{self, Source};
use crate::runner::{self, Runner};
use crate::updates::Unattended;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{what}: {detail}")]
    Step { what: String, detail: String },

    #[error(transparent)]
    Runner(#[from] runner::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

/// What a step does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Run(Vec<String>),
    /// Puts a file in place atomically, with this mode. Skipped when already identical.
    Install {
        path: String,
        content: String,
        mode: u32,
    },
}

/// Which part of the setup a step belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Packages,
    Repository,
    Configuration,
    /// Starting services. A container used for testing has no init to talk to: this is
    /// the phase such a test leaves out.
    Services,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    pub phase: Phase,
    /// What it is for, in a sentence. Printed in the preview.
    pub what: String,
    pub action: Action,
}

impl Step {
    pub fn describe(&self) -> String {
        match &self.action {
            Action::Run(argv) => format!("{} — {}", self.what, argv.join(" ")),
            Action::Install { path, mode, .. } => {
                format!("{} — {path} ({mode:o})", self.what)
            }
        }
    }
}

/// What was observed beyond the dependencies themselves.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Facts {
    /// The content of `/etc/docker/daemon.json`, when there is one.
    pub daemon_json: Option<String>,
    /// Is `needrestart` installed? Ubuntu ships it, and it restarts the engine.
    pub needrestart: bool,
    /// Is the unattended-upgrade tool already installed?
    pub unattended_installed: bool,
    /// Packages installed that stand in the way of Docker's own.
    pub docker_conflicts: Vec<String>,
    /// `uname -r`: ZFS's module is built, or packaged, per kernel.
    pub kernel: Option<String>,
    /// Is Debian's `contrib` already configured for this release?
    pub debian_contrib: bool,
}

/// The steps, and what was deliberately not done.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Provision {
    pub steps: Vec<Step>,
    /// Shown alongside the steps: a decision not to act must be visible.
    pub notes: Vec<String>,
}

impl Provision {
    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }
}

/// Decides the steps.
///
/// `Err` is a refusal, worded for a person: the preflight raises the same ones first,
/// so reaching one here means something changed between the two.
pub fn plan(
    distro: &Distro,
    deps: &DependencyPlan,
    facts: &Facts,
) -> std::result::Result<Provision, String> {
    let pm = distro.package_manager();
    let mut p = Provision::default();
    let run = |phase, what: &str, argv: Vec<String>| Step {
        phase,
        what: what.to_string(),
        action: Action::Run(argv),
    };
    let install = |phase, what: &str, path: &str, content: String, mode| Step {
        phase,
        what: what.to_string(),
        action: Action::Install {
            path: path.to_string(),
            content,
            mode,
        },
    };

    // -- What to install ------------------------------------------------------------
    let unattended = Unattended::for_distro(distro);
    let mut packages = deps.to_install();
    let install_unattended = !facts.unattended_installed && unattended.package().is_some();
    if install_unattended {
        packages.extend(unattended.package());
    }
    let needs_zfs = deps
        .decisions
        .iter()
        .any(|d| d.dependency.name == "zfs" && d.presence.needs_install());
    let zfs = if needs_zfs {
        Some(crate::zfs::source(
            distro,
            facts.kernel.as_deref(),
            facts.debian_contrib,
        )?)
    } else {
        None
    };
    if let Some(z) = &zfs {
        packages.extend(z.packages.iter().map(String::as_str));
    }

    let docker_source = match deps.docker().map(|d| &d.presence) {
        Some(Presence::Missing) => {
            let source = docker::source(distro);
            let conflicts: Vec<&String> = facts
                .docker_conflicts
                .iter()
                .filter(|c| source.conflicts().contains(&c.as_str()))
                .collect();
            if !conflicts.is_empty() {
                return Err(format!(
                    "installed packages conflict with Docker's own: {} — remove them, then \
                     run this again",
                    conflicts
                        .iter()
                        .map(|c| c.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
            Some(source)
        }
        Some(Presence::TooOld { found, required }) => {
            return Err(format!(
                "Docker {found} is installed, and Swarm here needs {required} or newer. It \
                 was not installed by Homelabus, so it is not replaced: remove it, then run \
                 this again to get Docker's own packages"
            ));
        }
        Some(Presence::Satisfied { .. }) | None => None,
    };

    // -- 1. The distribution's packages -------------------------------------------
    // restic is not in the base repositories of RHEL and its rebuilds: EPEL carries it.
    let needs_restic = deps
        .decisions
        .iter()
        .any(|d| d.dependency.name == "restic" && d.presence.needs_install());
    if needs_restic {
        if let Some(argv) = epel(distro)? {
            p.steps.push(run(
                Phase::Repository,
                "EPEL, where restic is published for this distribution",
                argv,
            ));
        }
    }
    if let Some((path, content)) = zfs.as_ref().and_then(|z| z.repository.clone()) {
        p.steps.push(install(
            Phase::Repository,
            "Debian's contrib, where ZFS is published",
            &path,
            content,
            0o644,
        ));
    }
    if !packages.is_empty() {
        if let Some(refresh) = pm.refresh_command() {
            p.steps
                .push(run(Phase::Packages, "refresh the package index", refresh));
        }
        if pm == PackageManager::Pacman {
            p.notes.push(
                "the refresh upgrades the whole system: if that brings a new kernel, the \
                 running one loses its modules, and nothing starts before a reboot"
                    .to_string(),
            );
        }
        p.steps.push(run(
            Phase::Packages,
            "install the dependencies",
            pm.install_command(&packages),
        ));
    }

    // -- 2. Docker -------------------------------------------------------------------
    if let Some(source) = &docker_source {
        for (path, content) in source.repository_files() {
            p.steps.push(install(
                Phase::Repository,
                "Docker's repository",
                &path,
                content,
                0o644,
            ));
        }
        if matches!(source, Source::Apt { .. }) {
            if let Some(refresh) = pm.refresh_command() {
                p.steps
                    .push(run(Phase::Repository, "read Docker's repository", refresh));
            }
        }

        // BEFORE the packages: they start the daemon, and a daemon started without
        // it would need a restart to pick it up.
        if facts.daemon_json.is_none() {
            p.steps.push(install(
                Phase::Configuration,
                "Docker's configuration: rotated logs",
                docker::DAEMON_JSON,
                docker::DAEMON_CONFIG.to_string(),
                0o644,
            ));
        } else {
            p.notes.push(format!(
                "{} already exists and is left as it is",
                docker::DAEMON_JSON
            ));
        }

        p.steps.push(run(
            Phase::Packages,
            &format!("install Docker from {}", source.describe()),
            pm.install_command(&source.packages()),
        ));
    }

    // -- 3. Unattended security updates ------------------------------------------
    match &unattended {
        Unattended::NotAutomated(why) => {
            p.notes
                .push(format!("security updates are not automated: {why}"));
        }
        _ => {
            if install_unattended {
                for (path, content) in unattended.enabling_files() {
                    p.steps.push(install(
                        Phase::Configuration,
                        "unattended security updates",
                        path,
                        content,
                        0o644,
                    ));
                }
            } else {
                p.notes.push(format!(
                    "{} was already installed: its configuration is left as it is",
                    unattended.package().unwrap_or("the updater")
                ));
            }
            for (path, content) in unattended.guard_files(facts.needrestart) {
                p.steps.push(install(
                    Phase::Configuration,
                    "keep the container engine out of unattended upgrades",
                    path,
                    content,
                    0o644,
                ));
            }
        }
    }

    // -- 4. The host -----------------------------------------------------------------
    // Always: files of our own that only narrow, put back if someone edited them.
    let (host, host_notes) = crate::host::steps(distro);
    p.notes.extend(host_notes);
    let (host_services, host_files): (Vec<Step>, Vec<Step>) =
        host.into_iter().partition(|s| s.phase == Phase::Services);
    p.steps.extend(host_files);

    // -- 5. Services -----------------------------------------------------------------
    p.steps.extend(host_services);
    let init = Init::for_family(distro.family);
    // Docker always: an installed engine that is not running cannot join anything,
    // and enabling one that already runs changes nothing.
    p.steps.extend(
        init.enable_now("docker")
            .into_iter()
            .map(|argv| run(Phase::Services, "start Docker, and at every boot", argv)),
    );
    // chrony only when installed now: an existing one may be off in favour of another
    // NTP client, and two clients fight over the clock.
    let chrony_installed_now = deps
        .decisions
        .iter()
        .any(|d| d.dependency.name == "ntp" && d.presence.needs_install());
    if chrony_installed_now {
        let unit = match distro.family {
            Family::Debian => "chrony",
            _ => "chronyd",
        };
        p.steps.extend(
            init.enable_now(unit)
                .into_iter()
                .map(|argv| run(Phase::Services, "keep the clock synchronised", argv)),
        );
    }
    // The package loads the module at the next boot, not now: until then every `zpool`
    // fails, and the storage commands come right after this one.
    if zfs.is_some() {
        p.steps.push(run(
            Phase::Services,
            "load ZFS's module",
            vec!["modprobe".into(), "zfs".into()],
        ));
        // Alpine ships the import and mount services switched off: after a reboot the
        // pool stayed exported and /tank/apps was a plain directory on the root disk,
        // where every bind mount would have written. In sysinit, so before Docker.
        if init == Init::OpenRc {
            for service in ["zfs-import", "zfs-mount"] {
                p.steps.push(run(
                    Phase::Services,
                    "import and mount the pool at every boot",
                    vec![
                        "rc-update".into(),
                        "add".into(),
                        service.into(),
                        "sysinit".into(),
                    ],
                ));
            }
        }
    }
    if install_unattended {
        if let Some(timer) = unattended.timer() {
            p.steps.extend(
                init.enable_now(timer)
                    .into_iter()
                    .map(|argv| run(Phase::Services, "apply security updates every day", argv)),
            );
        }
    }

    if packages.is_empty() && docker_source.is_none() {
        p.notes
            .push("every dependency is already present".to_string());
    }

    Ok(p)
}

/// How EPEL is enabled, where a dependency needs it. `Ok(None)`: not needed here.
///
/// Rocky, Alma and CentOS ship `epel-release` in their own repositories, signed by
/// them; Oracle Linux names it after its release. RHEL itself needs a subscription
/// repository enabled first, which is the machine owner's decision — refused, with the
/// commands.
fn epel(distro: &Distro) -> std::result::Result<Option<Vec<String>>, String> {
    if distro.family != Family::RedHat || distro.id == "fedora" {
        return Ok(None);
    }
    let major = distro
        .version_id
        .as_deref()
        .and_then(|v| v.split('.').next())
        .unwrap_or("9");
    let install = |pkg: String| Some(vec!["dnf".to_string(), "install".into(), "-y".into(), pkg]);
    match distro.id.as_str() {
        "rocky" | "almalinux" | "centos" => Ok(install("epel-release".into())),
        "ol" => Ok(install(format!("oracle-epel-release-el{major}"))),
        "rhel" => Err(format!(
            "restic comes from EPEL, which RHEL only reaches through a subscription \
             repository: `subscription-manager repos --enable codeready-builder-for-rhel-{major}-$(arch)-rpms` \
             then `dnf install https://dl.fedoraproject.org/pub/epel/epel-release-latest-{major}.noarch.rpm`, \
             and run this again"
        )),
        _ => Ok(None),
    }
}

/// The init system, which decides how a service is started.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Init {
    Systemd,
    OpenRc,
}

impl Init {
    pub fn for_family(family: Family) -> Self {
        match family {
            Family::Alpine => Self::OpenRc,
            _ => Self::Systemd,
        }
    }

    /// Enable at boot and start now. Idempotent on both.
    pub fn enable_now(&self, unit: &str) -> Vec<Vec<String>> {
        match self {
            Self::Systemd => vec![vec![
                "systemctl".into(),
                "enable".into(),
                "--now".into(),
                unit.into(),
            ]],
            Self::OpenRc => vec![
                vec![
                    "rc-update".into(),
                    "add".into(),
                    unit.into(),
                    "default".into(),
                ],
                // `rc-service start` on a started service is an error on some
                // versions: start only what is not running.
                vec![
                    "sh".into(),
                    "-c".into(),
                    format!("rc-service {unit} status >/dev/null 2>&1 || rc-service {unit} start"),
                ],
            ],
        }
    }
}

/// Runs the steps in order, calling `on_step` before each one. Stops at the first
/// failure.
pub async fn execute(
    runner: &dyn Runner,
    provision: &Provision,
    mut on_step: impl FnMut(&Step),
) -> Result<()> {
    for step in &provision.steps {
        on_step(step);
        match &step.action {
            Action::Run(argv) => {
                let out = runner.run(argv).await?;
                if !out.ok() {
                    return Err(Error::Step {
                        what: step.what.clone(),
                        detail: last_lines(&out.stderr, &out.stdout),
                    });
                }
            }
            Action::Install {
                path,
                content,
                mode,
            } => install_file(runner, path, content, *mode).await?,
        }
    }
    Ok(())
}

/// Puts a file in place: written beside it, narrowed to `mode`, then renamed over it.
///
/// The rename is what makes it safe to interrupt. A `daemon.json` cut in half by a
/// dropped SSH connection stops Docker from starting at all — and with it every service
/// on the node, at the next boot rather than now.
pub async fn install_file(runner: &dyn Runner, path: &str, content: &str, mode: u32) -> Result<()> {
    if runner.read_file(path).await?.as_deref() == Some(content) {
        return Ok(());
    }
    let fail = |what: &str, out: &runner::Output| Error::Step {
        what: format!("{what} {path}"),
        detail: last_lines(&out.stderr, &out.stdout),
    };

    if let Some((dir, _)) = path.rsplit_once('/') {
        if !dir.is_empty() {
            let out = runner
                .run(&["mkdir".into(), "-p".into(), dir.into()])
                .await?;
            if !out.ok() {
                return Err(fail("creating the directory of", &out));
            }
        }
    }

    let tmp = format!("{path}.hlb-new");
    runner.write_file(&tmp, content).await?;
    let out = runner
        .run(&["chmod".into(), format!("{mode:o}"), tmp.clone()])
        .await?;
    if !out.ok() {
        return Err(fail("setting the mode of", &out));
    }
    let out = runner
        .run(&["mv".into(), "-f".into(), tmp, path.into()])
        .await?;
    if !out.ok() {
        return Err(fail("putting in place", &out));
    }
    Ok(())
}

/// The end of a command's output: where a package manager says what went wrong.
fn last_lines(stderr: &str, stdout: &str) -> String {
    let text = if stderr.trim().is_empty() {
        stdout
    } else {
        stderr
    };
    let lines: Vec<&str> = text.trim().lines().collect();
    let start = lines.len().saturating_sub(5);
    lines[start..].join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deps;

    fn distro(os_release: &str) -> Distro {
        Distro::parse(os_release).expect("parsable")
    }

    fn bookworm() -> Distro {
        distro("ID=debian\nVERSION_ID=12\nVERSION_CODENAME=bookworm\nPRETTY_NAME=\"Debian 12\"\n")
    }

    fn present(names: &[&'static str]) -> Vec<(&'static str, Option<String>)> {
        names
            .iter()
            .map(|n| (*n, Some("99.0".to_string())))
            .collect()
    }

    fn all_present() -> Vec<(&'static str, Option<String>)> {
        present(&deps::BASE.iter().map(|d| d.name).collect::<Vec<_>>())
    }

    fn positions(p: &Provision, pred: impl Fn(&Step) -> bool) -> Vec<usize> {
        p.steps
            .iter()
            .enumerate()
            .filter(|(_, s)| pred(s))
            .map(|(i, _)| i)
            .collect()
    }

    fn runs(s: &Step, needle: &str) -> bool {
        matches!(&s.action, Action::Run(a) if a.join(" ").contains(needle))
    }

    fn writes(s: &Step, path: &str) -> bool {
        matches!(&s.action, Action::Install { path: p, .. } if p == path)
    }

    #[test]
    fn a_bare_debian_gets_dockers_repository_before_dockers_packages() {
        let d = bookworm();
        let p = plan(&d, &deps::plan(&d, &[]), &Facts::default()).expect("a plan");

        let repo = positions(&p, |s| writes(s, "/etc/apt/sources.list.d/docker.sources"));
        let key = positions(&p, |s| writes(s, "/etc/apt/keyrings/docker.asc"));
        let engine = positions(&p, |s| runs(s, "docker-ce"));
        assert_eq!(repo.len(), 1);
        assert_eq!(engine.len(), 1);
        assert!(key[0] < engine[0] && repo[0] < engine[0]);
        // The index is refreshed between the repository and the install, or apt does
        // not know the package exists.
        let refresh = positions(&p, |s| runs(s, "apt-get update"));
        assert!(refresh.iter().any(|r| *r > repo[0] && *r < engine[0]));
    }

    #[test]
    fn daemon_json_is_in_place_before_the_package_starts_the_daemon() {
        let d = bookworm();
        let p = plan(&d, &deps::plan(&d, &[]), &Facts::default()).expect("a plan");
        let conf = positions(&p, |s| writes(s, docker::DAEMON_JSON));
        let engine = positions(&p, |s| runs(s, "docker-ce"));
        assert_eq!(conf.len(), 1);
        assert!(conf[0] < engine[0]);
    }

    #[test]
    fn an_existing_daemon_json_is_never_rewritten() {
        let d = bookworm();
        let facts = Facts {
            daemon_json: Some("{\"debug\": true}".into()),
            ..Facts::default()
        };
        let p = plan(&d, &deps::plan(&d, &[]), &facts).expect("a plan");
        assert!(positions(&p, |s| writes(s, docker::DAEMON_JSON)).is_empty());
        assert!(p.notes.iter().any(|n| n.contains("left as it is")));
    }

    #[test]
    fn a_present_docker_is_left_alone_but_started() {
        let d = bookworm();
        let p = plan(
            &d,
            &deps::plan(&d, &all_present()),
            &Facts {
                unattended_installed: true,
                ..Facts::default()
            },
        )
        .expect("a plan");
        assert!(positions(&p, |s| runs(s, "docker-ce")).is_empty());
        assert!(positions(&p, |s| writes(s, docker::DAEMON_JSON)).is_empty());
        assert_eq!(
            positions(&p, |s| runs(s, "systemctl enable --now docker")).len(),
            1
        );
    }

    #[test]
    fn a_machine_with_everything_still_gets_its_host_hardened() {
        let d = bookworm();
        let p = plan(
            &d,
            &deps::plan(&d, &all_present()),
            &Facts {
                unattended_installed: true,
                ..Facts::default()
            },
        )
        .expect("a plan");
        assert_eq!(
            positions(&p, |s| writes(s, crate::host::SYSCTL_PATH)).len(),
            1
        );
        assert_eq!(
            positions(&p, |s| writes(s, crate::host::JOURNALD_PATH)).len(),
            1
        );
        // The files go in with the configuration, before anything starts.
        let last_file = positions(&p, |s| s.phase != Phase::Services)
            .into_iter()
            .max()
            .expect("files");
        let first_service = positions(&p, |s| s.phase == Phase::Services)
            .into_iter()
            .min()
            .expect("services");
        assert!(last_file < first_service);
    }

    #[test]
    fn a_docker_too_old_is_refused_not_replaced() {
        let d = bookworm();
        let mut seen = all_present();
        seen.retain(|(n, _)| *n != "docker");
        seen.push(("docker", Some("20.10.24".into())));
        let refusal = plan(&d, &deps::plan(&d, &seen), &Facts::default()).expect_err("refused");
        assert!(refusal.contains("20.10.24"));
        assert!(refusal.contains("not replaced"));
    }

    #[test]
    fn a_conflicting_package_stops_the_plan_before_the_repository_is_added() {
        let d = bookworm();
        let facts = Facts {
            docker_conflicts: vec!["containerd".into()],
            ..Facts::default()
        };
        let refusal = plan(&d, &deps::plan(&d, &[]), &facts).expect_err("refused");
        assert!(refusal.contains("containerd"));
    }

    #[test]
    fn unattended_updates_are_switched_on_only_when_homelabus_installs_the_tool() {
        let d = bookworm();
        let fresh = plan(&d, &deps::plan(&d, &all_present()), &Facts::default()).expect("plan");
        assert_eq!(
            positions(&fresh, |s| writes(s, "/etc/apt/apt.conf.d/20auto-upgrades")).len(),
            1
        );
        assert!(positions(&fresh, |s| runs(s, "unattended-upgrades")).len() == 1);

        let existing = plan(
            &d,
            &deps::plan(&d, &all_present()),
            &Facts {
                unattended_installed: true,
                ..Facts::default()
            },
        )
        .expect("plan");
        assert!(positions(&existing, |s| writes(
            s,
            "/etc/apt/apt.conf.d/20auto-upgrades"
        ))
        .is_empty());
        // The guard is added either way: it only narrows.
        assert_eq!(
            positions(&existing, |s| writes(
                s,
                "/etc/apt/apt.conf.d/52hlb-unattended-upgrades"
            ))
            .len(),
            1
        );
    }

    #[test]
    fn an_existing_clock_client_is_not_started_over_another() {
        let d = bookworm();
        let p = plan(&d, &deps::plan(&d, &all_present()), &Facts::default()).expect("plan");
        assert!(positions(&p, |s| runs(s, "chrony")).is_empty());

        let mut seen = all_present();
        seen.retain(|(n, _)| *n != "ntp");
        let p = plan(&d, &deps::plan(&d, &seen), &Facts::default()).expect("plan");
        assert_eq!(positions(&p, |s| runs(s, "enable --now chrony")).len(), 1);
    }

    #[test]
    fn alpine_starts_its_services_through_openrc() {
        let d = distro("ID=alpine\nVERSION_ID=3.20.3\nPRETTY_NAME=x\n");
        let p = plan(&d, &deps::plan(&d, &[]), &Facts::default()).expect("plan");
        assert!(positions(&p, |s| runs(s, "systemctl")).is_empty());
        assert!(!positions(&p, |s| runs(s, "rc-update add docker default")).is_empty());
        assert!(p.notes.iter().any(|n| n.contains("not automated")));
    }

    #[test]
    fn rocky_gets_dnf_automatic_and_its_timer() {
        let d = distro("ID=rocky\nID_LIKE=\"rhel centos fedora\"\nVERSION_ID=9.4\nPRETTY_NAME=x\n");
        let p = plan(&d, &deps::plan(&d, &[]), &Facts::default()).expect("plan");
        assert!(!positions(&p, |s| writes(s, "/etc/yum.repos.d/docker-ce.repo")).is_empty());
        assert!(!positions(&p, |s| writes(s, "/etc/dnf/automatic.conf")).is_empty());
        assert!(!positions(&p, |s| runs(s, "enable --now dnf-automatic.timer")).is_empty());
    }

    #[test]
    fn restic_brings_epel_on_rhel_rebuilds_and_only_there() {
        let rocky =
            distro("ID=rocky\nID_LIKE=\"rhel centos fedora\"\nVERSION_ID=9.4\nPRETTY_NAME=x\n");
        let p = plan(&rocky, &deps::plan(&rocky, &[]), &Facts::default()).expect("plan");
        let epel = positions(&p, |s| runs(s, "epel-release"));
        let restic = positions(&p, |s| runs(s, "restic"));
        assert_eq!(epel.len(), 1);
        assert!(epel[0] < restic[0]);

        let fedora = distro("ID=fedora\nVERSION_ID=41\nPRETTY_NAME=x\n");
        let p = plan(&fedora, &deps::plan(&fedora, &[]), &Facts::default()).expect("plan");
        assert!(positions(&p, |s| runs(s, "epel")).is_empty());

        let rhel = distro("ID=rhel\nVERSION_ID=9.4\nPRETTY_NAME=x\n");
        let refusal = plan(&rhel, &deps::plan(&rhel, &[]), &Facts::default()).expect_err("refused");
        assert!(refusal.contains("codeready-builder"));
    }

    fn storage(d: &Distro, facts: &Facts) -> std::result::Result<Provision, String> {
        plan(d, &deps::plan_for(d, &all_present(), true), facts)
    }

    fn kernel(release: &str) -> Facts {
        Facts {
            kernel: Some(release.into()),
            ..Facts::default()
        }
    }

    #[test]
    fn a_debian_storage_node_gets_contrib_and_the_module_not_only_the_tools() {
        // Found on a real Debian 12: `zfsutils-linux` has no candidate without contrib,
        // and with `--no-install-recommends` it would arrive without its module.
        let d = bookworm();
        let p = storage(&d, &kernel("6.1.0-53-cloud-amd64")).expect("a plan");
        let contrib = positions(&p, |s| writes(s, crate::zfs::DEBIAN_CONTRIB));
        let refresh = positions(&p, |s| runs(s, "apt-get update"));
        let install = positions(&p, |s| runs(s, "zfsutils-linux"));
        assert_eq!(contrib.len(), 1);
        assert!(contrib[0] < refresh[0] && refresh[0] < install[0]);
        for pkg in [
            "zfs-dkms",
            "linux-headers-6.1.0-53-cloud-amd64",
            "linux-headers-cloud-amd64",
        ] {
            assert!(runs(&p.steps[install[0]], pkg), "{pkg} is not installed");
        }
        // Loaded now: otherwise every `zpool` fails until the next boot.
        let load = positions(&p, |s| runs(s, "modprobe zfs"));
        assert!(load.len() == 1 && load[0] > install[0]);
        let Action::Install { content, .. } = &p.steps[contrib[0]].action else {
            panic!("contrib is a file");
        };
        assert!(content.contains("Suites: bookworm bookworm-updates"));
        assert!(content.contains("Suites: bookworm-security"));
    }

    #[test]
    fn a_debian_13_storage_node_gets_the_headers_of_its_next_kernel_too() {
        // Trixie writes `+deb13` where bookworm wrote an ABI number: read as three
        // dashes, no metapackage was installed and the next kernel had no headers.
        let d = distro("ID=debian\nVERSION_ID=13\nVERSION_CODENAME=trixie\nPRETTY_NAME=x\n");
        for (release, flavour) in [
            ("6.12.43+deb13-amd64", "linux-headers-amd64"),
            ("6.12.43+deb13-cloud-amd64", "linux-headers-cloud-amd64"),
        ] {
            let p = storage(&d, &kernel(release)).expect("a plan");
            let install = positions(&p, |s| runs(s, "zfs-dkms"));
            assert_eq!(install.len(), 1, "{release}");
            for pkg in [format!("linux-headers-{release}"), flavour.to_string()] {
                assert!(
                    runs(&p.steps[install[0]], &pkg),
                    "{release}: {pkg} is not installed"
                );
            }
        }
    }

    #[test]
    fn contrib_already_configured_is_not_added_twice() {
        let d = bookworm();
        let facts = Facts {
            debian_contrib: true,
            ..kernel("6.1.0-53-amd64")
        };
        let p = storage(&d, &facts).expect("a plan");
        assert!(positions(&p, |s| writes(s, crate::zfs::DEBIAN_CONTRIB)).is_empty());
        assert_eq!(positions(&p, |s| runs(s, "zfs-dkms")).len(), 1);
    }

    #[test]
    fn ubuntu_gets_the_tools_alone_its_kernel_carries_the_module() {
        let d = distro("ID=ubuntu\nVERSION_ID=24.04\nVERSION_CODENAME=noble\nPRETTY_NAME=x\n");
        let p = storage(&d, &kernel("6.8.0-45-generic")).expect("a plan");
        assert_eq!(positions(&p, |s| runs(s, "zfsutils-linux")).len(), 1);
        assert!(positions(&p, |s| runs(s, "dkms") || runs(s, "linux-headers")).is_empty());
        assert!(positions(&p, |s| writes(s, crate::zfs::DEBIAN_CONTRIB)).is_empty());
    }

    #[test]
    fn alpine_gets_the_module_built_for_its_kernel_flavour() {
        let d = distro("ID=alpine\nVERSION_ID=3.20.3\nPRETTY_NAME=x\n");
        let p = storage(&d, &kernel("6.6.58-0-lts")).expect("a plan");
        assert_eq!(positions(&p, |s| runs(s, "zfs-lts")).len(), 1);
        // Found on a real Alpine: the pool was not imported after a reboot.
        for service in ["zfs-import", "zfs-mount"] {
            let needle = format!("rc-update add {service} sysinit");
            assert_eq!(positions(&p, |s| runs(s, &needle)).len(), 1, "{needle}");
        }
    }

    #[test]
    fn a_storage_node_where_zfs_is_not_packaged_is_refused_before_anything_runs() {
        for os in [
            "ID=rocky\nID_LIKE=\"rhel centos fedora\"\nVERSION_ID=9.4\nPRETTY_NAME=Rocky\n",
            "ID=arch\nPRETTY_NAME=Arch\n",
            "ID=opensuse-leap\nVERSION_ID=15.6\nPRETTY_NAME=Leap\n",
        ] {
            let d = distro(os);
            let refusal = storage(&d, &kernel("6.6.0-1-default")).expect_err(os);
            assert!(refusal.contains("openzfs.github.io"), "{refusal}");
            // The same machine without storage still gets its plan.
            plan(&d, &deps::plan(&d, &all_present()), &kernel("6.6.0-1")).expect(os);
        }
    }

    #[test]
    fn arch_is_told_its_upgrade_may_need_a_reboot_before_anything_starts() {
        // Found on a real Arch: `pacman -Syu` brought 7.2.10 under a running 7.2.9,
        // whose modules were gone, and Docker failed on nf_tables.
        let d = distro("ID=arch\nPRETTY_NAME=Arch\n");
        let p = plan(&d, &deps::plan(&d, &[]), &Facts::default()).expect("plan");
        assert!(
            p.notes.iter().any(|n| n.contains("reboot")),
            "{:?}",
            p.notes
        );
        let p = plan(
            &bookworm(),
            &deps::plan(&bookworm(), &[]),
            &Facts::default(),
        )
        .expect("plan");
        assert!(!p.notes.iter().any(|n| n.contains("loses its modules")));
    }

    #[test]
    fn services_start_after_everything_they_need_is_installed() {
        let d = bookworm();
        let p = plan(&d, &deps::plan(&d, &[]), &Facts::default()).expect("plan");
        let first_service = p
            .steps
            .iter()
            .position(|s| s.phase == Phase::Services)
            .expect("a service");
        assert!(p.steps[first_service..]
            .iter()
            .all(|s| s.phase == Phase::Services));
    }
}
