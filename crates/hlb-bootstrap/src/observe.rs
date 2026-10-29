//! Observing a machine, local or remote.
//!
//! Separate from judgement: this module only **observes**, [`crate::preflight`]
//! decides. That boundary makes the whole line of reasoning testable against fabricated
//! observations, without provisioning a VM.
//!
//! No command here modifies anything. That is what makes `hlb node check` safe to run
//! against a production machine.

use crate::deps::Probe;
use crate::distro::{Distro, PackageManager};
use crate::provision::Facts;
use crate::runner::{Result, Runner};
use crate::updates::Unattended;

/// Queries the machine and gathers everything the preflight needs.
pub async fn observe(runner: &dyn Runner) -> Result<crate::preflight::Observation> {
    let os_release = runner
        .read_file("/etc/os-release")
        .await?
        .unwrap_or_default();

    Ok(crate::preflight::Observation {
        os_release,
        docker_version: docker_version(runner).await?,
        docker_is_snap: docker_is_snap(runner).await?,
        podman_present: binary_exists(runner, "podman").await?,
        total_memory_mb: total_memory_mb(runner).await?,
        free_disk_mb: free_disk_mb(runner, "/var/lib").await?,
        clock_synced: clock_synced(runner).await?,
        is_root: is_root(runner).await?,
        cgroups_v2: cgroups_v2(runner).await?,
        daemon_json: runner
            .read_file(crate::docker::DAEMON_JSON)
            .await?
            .filter(|c| !c.trim().is_empty()),
        reboot_required: reboot_required(runner).await?,
    })
}

/// Observes each known dependency: `None` when absent, its version — or what it printed
/// for one — when present.
///
/// Presence is decided by [`Dependency::probe`](crate::deps::Dependency::probe), never
/// by asking for a version: `restic` refuses `--version` and `exportfs` has none, and
/// reading a refusal as absence offers to install them again on every run.
pub async fn dependencies(
    runner: &dyn Runner,
    distro: &Distro,
) -> Result<Vec<(&'static str, Option<String>)>> {
    let pm = distro.package_manager();
    let mut out = Vec::new();
    for dep in crate::deps::BASE
        .iter()
        .chain(crate::deps::STORAGE)
        .chain(crate::deps::TPM)
    {
        let present = match dep.probe() {
            Probe::Binary(bin) => binary_exists(runner, bin).await?,
            Probe::Package => package_installed(runner, pm, dep.package_for(pm)).await?,
            Probe::Clock => {
                if binary_exists(runner, "chronyd").await? {
                    true
                } else if let Some(client) = active_time_client(runner).await? {
                    out.push((dep.name, Some(format!("via {client}"))));
                    continue;
                } else {
                    false
                }
            }
        };
        if !present {
            out.push((dep.name, None));
            continue;
        }
        // The version only matters where there is a floor; elsewhere presence is all.
        let version = match (dep.min_version, dep.probe()) {
            (Some(_), Probe::Binary(bin)) => runner
                .run(&[bin.to_string(), "--version".to_string()])
                .await
                .ok()
                .filter(|o| o.ok())
                .and_then(|o| o.first_line())
                .map(|l| extract_version(&l)),
            _ => None,
        };
        out.push((dep.name, Some(version.unwrap_or_default())));
    }
    Ok(out)
}

/// The time-sync client systemd runs, when it runs one.
///
/// `NTP=yes` in `timedatectl show` says a client is enabled — systemd-timesyncd, or
/// whichever unit provides `time-sync.target`. Not `NTPSynchronized`: a client that has
/// not reached a server YET is still the one to keep.
async fn active_time_client(runner: &dyn Runner) -> Result<Option<String>> {
    let out = runner.run(&["timedatectl".into(), "show".into()]).await;
    let Ok(o) = out else { return Ok(None) };
    if !o.ok() || !o.stdout.lines().any(|l| l.trim() == "NTP=yes") {
        return Ok(None);
    }
    let timesyncd = runner
        .run(&[
            "systemctl".into(),
            "is-active".into(),
            "systemd-timesyncd".into(),
        ])
        .await
        .map(|o| o.ok())
        .unwrap_or(false);
    Ok(Some(
        if timesyncd {
            "systemd-timesyncd"
        } else {
            "the system's NTP client"
        }
        .to_string(),
    ))
}

/// What the provisioning plan needs beyond the dependencies.
pub async fn facts(runner: &dyn Runner, distro: &Distro) -> Result<Facts> {
    let pm = distro.package_manager();
    let source = crate::docker::source(distro);
    let mut docker_conflicts = Vec::new();
    for pkg in source.conflicts() {
        if package_installed(runner, pm, pkg).await? {
            docker_conflicts.push(pkg.to_string());
        }
    }
    let unattended = Unattended::for_distro(distro);
    let unattended_installed = match unattended.package() {
        Some(pkg) => package_installed(runner, pm, pkg).await?,
        None => false,
    };
    Ok(Facts {
        daemon_json: runner
            .read_file(crate::docker::DAEMON_JSON)
            .await?
            .filter(|c| !c.trim().is_empty()),
        needrestart: binary_exists(runner, "needrestart").await?,
        unattended_installed,
        docker_conflicts,
        kernel: runner
            .run(&["uname".into(), "-r".into()])
            .await
            .ok()
            .filter(|o| o.ok())
            .and_then(|o| o.first_line()),
        debian_contrib: match (pm, distro.codename.as_deref()) {
            (PackageManager::Apt, Some(codename)) => debian_contrib(runner, codename).await?,
            _ => false,
        },
    })
}

/// What the TPM can seal with: the driver, then each binding tried in turn. A
/// throwaway value is sealed and unsealed in memory; nothing on the machine changes.
pub async fn tpm(runner: &dyn Runner) -> Result<crate::seal::Probe> {
    let has = runner
        .run(&["systemd-creds".into(), "has-tpm2".into()])
        .await?;
    trials(runner, crate::seal::has_driver(&has.stdout)).await
}

async fn trials(runner: &dyn Runner, driver: bool) -> Result<crate::seal::Probe> {
    use crate::seal::{self, Binding};
    let mut trials = Vec::new();
    if driver {
        for b in Binding::ALL {
            let o = runner.run(&seal::trial(b)).await?;
            let ok = o.ok();
            trials.push((b, if ok { Ok(()) } else { Err(o.stderr) }));
            if ok {
                break;
            }
        }
    }
    Ok(seal::decide(driver, &trials))
}

/// Whether a TPM 2.0's driver is loaded — what makes its libraries worth installing.
pub async fn tpm_driver(runner: &dyn Runner) -> bool {
    runner
        .run(&["systemd-creds".into(), "has-tpm2".into()])
        .await
        .is_ok_and(|o| o.status != 127 && crate::seal::has_driver(&o.stdout))
}

/// Everything a protection level is read from. Changes nothing.
pub async fn protection(runner: &dyn Runner) -> Result<crate::protection::Signals> {
    use crate::protection as p;
    let sh = |script: &str| vec!["sh".to_string(), "-c".to_string(), script.to_string()];
    // A missing binary is an error from the runner; here it is a signal not read.
    let read = |o: Result<crate::runner::Output>| o.ok().filter(|o| o.ok()).map(|o| o.stdout);

    let uefi = runner
        .run(&sh("test -d /sys/firmware/efi"))
        .await
        .is_ok_and(|o| o.ok());
    let secure_boot = read(
        runner
            .run(&sh(
                "od -An -tu1 /sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c",
            ))
            .await,
    )
    .and_then(|o| p::parse_secure_boot(&o));

    let has_tpm2 = runner
        .run(&["systemd-creds".into(), "has-tpm2".into()])
        .await
        .ok()
        // `has-tpm2` exits non-zero whenever something is missing, and still prints —
        // but 127 is the shell's "no such command", which SSH returns as an answer.
        .filter(|o| o.status != 127)
        .map(|o| o.stdout);
    let root = is_root(runner).await?;
    let probe = match &has_tpm2 {
        Some(h) if root && crate::seal::has_driver(h) => Some(trials(runner, true).await?),
        _ => None,
    };
    let version_major = runner
        .read_file("/sys/class/tpm/tpm0/tpm_version_major")
        .await?;

    let virt = runner
        .run(&["systemd-detect-virt".into()])
        .await
        .ok()
        .map(|o| (o.stdout.clone(), o.ok()));

    let systemd = read(runner.run(&["systemctl".into(), "--version".into()]).await)
        .and_then(|o| p::parse_systemd_version(&o));
    let dkms = read(runner.run(&["dkms".into(), "status".into()]).await)
        .map(|o| p::parse_dkms(&o))
        .unwrap_or_default();
    let root_encrypted = read(
        runner
            .run(&sh("lsblk -nso TYPE \"$(findmnt -nvo SOURCE /)\""))
            .await,
    )
    .map(|o| p::parse_root_types(&o));

    Ok(p::Signals {
        uefi,
        secure_boot,
        tpm: p::tpm(
            root,
            has_tpm2.as_deref(),
            probe.as_ref(),
            version_major.as_deref(),
        ),
        virt: p::parse_virt(virt.as_ref().map(|(o, ok)| (o.as_str(), *ok))),
        systemd,
        dkms,
        root_encrypted,
    })
}

/// Is `contrib` configured for this release? Read from the sources themselves —
/// `--no-release-info` answers before any index was downloaded.
async fn debian_contrib(runner: &dyn Runner, codename: &str) -> Result<bool> {
    let out = runner
        .run(&[
            "apt-get".into(),
            "indextargets".into(),
            "--no-release-info".into(),
            "--format".into(),
            "$(RELEASE) $(COMPONENT) $(IDENTIFIER)".into(),
        ])
        .await;
    Ok(match out {
        Ok(o) if o.ok() => o
            .stdout
            .lines()
            .any(|l| l.trim() == format!("{codename} contrib Packages")),
        _ => false,
    })
}

/// Is a package installed, according to the package manager?
///
/// ⚠️ `dpkg-query` succeeds on a package that was REMOVED but left its configuration
/// behind (`deinstall ok config-files`): the status has to be read, not the exit code.
async fn package_installed(runner: &dyn Runner, pm: PackageManager, pkg: &str) -> Result<bool> {
    let out = runner.run(&pm.query_command(pkg)).await;
    Ok(match out {
        Ok(o) if o.ok() => match pm {
            PackageManager::Apt => o.stdout.contains("install ok installed"),
            _ => true,
        },
        _ => false,
    })
}

/// Extracts the first version-looking token from a line such as
/// "Docker version 27.3.1, build ce1223035a".
pub fn extract_version(line: &str) -> String {
    line.split_whitespace()
        .find(|t| {
            let t = t.trim_start_matches('v').trim_end_matches(',');
            t.contains('.') && t.chars().next().is_some_and(|c| c.is_ascii_digit())
        })
        .map(|t| t.trim_start_matches('v').trim_end_matches(',').to_string())
        .unwrap_or_else(|| line.to_string())
}

async fn binary_exists(runner: &dyn Runner, name: &str) -> Result<bool> {
    // `command -v` is POSIX; `which` is not, and is missing on minimal images.
    let out = runner
        .run(&["sh".into(), "-c".into(), format!("command -v {name}")])
        .await?;
    Ok(out.ok())
}

async fn docker_version(runner: &dyn Runner) -> Result<Option<String>> {
    let out = runner
        .run(&[
            "docker".into(),
            "version".into(),
            "--format".into(),
            "{{.Server.Version}}".into(),
        ])
        .await;

    // The binary can be absent (Err) or the daemon unreachable (status != 0). In both
    // cases we cannot claim a usable Docker is there.
    match out {
        Ok(o) if o.ok() => Ok(o.first_line()),
        _ => Ok(None),
    }
}

/// Docker installed through snap? Its confinement breaks some volume mounts.
async fn docker_is_snap(runner: &dyn Runner) -> Result<bool> {
    let out = runner
        .run(&["sh".into(), "-c".into(), "command -v docker".into()])
        .await?;
    Ok(out.stdout.contains("/snap/"))
}

async fn total_memory_mb(runner: &dyn Runner) -> Result<Option<u64>> {
    let Some(meminfo) = runner.read_file("/proc/meminfo").await? else {
        return Ok(None);
    };
    Ok(parse_meminfo_total_mb(&meminfo))
}

/// `MemTotal:       16311456 kB`
pub fn parse_meminfo_total_mb(meminfo: &str) -> Option<u64> {
    meminfo
        .lines()
        .find(|l| l.starts_with("MemTotal:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse::<u64>().ok())
        .map(|kb| kb / 1024)
}

async fn free_disk_mb(runner: &dyn Runner, path: &str) -> Result<Option<u64>> {
    // `-P` forces the POSIX format: without it, a long device name wraps onto the next
    // line and shifts every column.
    let out = runner
        .run(&["df".into(), "-Pm".into(), path.into()])
        .await?;
    if !out.ok() {
        return Ok(None);
    }
    Ok(parse_df_available_mb(&out.stdout))
}

pub fn parse_df_available_mb(df: &str) -> Option<u64> {
    df.lines()
        .nth(1)?
        .split_whitespace()
        .nth(3)?
        .parse::<u64>()
        .ok()
}

async fn clock_synced(runner: &dyn Runner) -> Result<Option<bool>> {
    // `timedatectl` on systemd, `chronyc` elsewhere. Neither is guaranteed.
    let out = runner.run(&["timedatectl".into(), "show".into()]).await;
    if let Ok(o) = out {
        if o.ok() {
            if let Some(v) = parse_timedatectl_synced(&o.stdout) {
                return Ok(Some(v));
            }
        }
    }

    let out = runner.run(&["chronyc".into(), "tracking".into()]).await;
    if let Ok(o) = out {
        if o.ok() {
            // `Leap status: Normal` signals a healthy clock.
            return Ok(Some(o.stdout.contains("Normal")));
        }
    }
    Ok(None)
}

pub fn parse_timedatectl_synced(out: &str) -> Option<bool> {
    out.lines()
        .find_map(|l| l.strip_prefix("NTPSynchronized="))
        .map(|v| v.trim() == "yes")
}

/// Whether `runner` acts as root: a TPM, `/run` and `/var/lib/hlb` refuse anyone else,
/// so a "no" read as anyone else says nothing.
pub async fn is_root(runner: &dyn Runner) -> Result<bool> {
    let out = runner.run(&["id".into(), "-u".into()]).await?;
    Ok(out.first_line().as_deref() == Some("0"))
}

async fn reboot_required(runner: &dyn Runner) -> Result<Option<bool>> {
    let out = runner
        .run(&[
            "sh".into(),
            "-c".into(),
            crate::updates::REBOOT_PROBE.into(),
        ])
        .await?;
    Ok(crate::updates::reboot_required(&out.stdout))
}

async fn cgroups_v2(runner: &dyn Runner) -> Result<Option<bool>> {
    // In v2 this file exists at the root of the unified cgroup mount.
    let out = runner
        .run(&[
            "sh".into(),
            "-c".into(),
            "test -f /sys/fs/cgroup/cgroup.controllers".into(),
        ])
        .await?;
    Ok(Some(out.ok()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Answers by the command line, exit 127 for anything it was not told about.
    struct Scripted(Vec<(&'static str, &'static str)>);

    #[async_trait::async_trait]
    impl Runner for Scripted {
        async fn run(&self, argv: &[String]) -> Result<crate::runner::Output> {
            let line = argv.join(" ");
            Ok(match self.0.iter().find(|(cmd, _)| line == *cmd) {
                Some((_, out)) => crate::runner::Output {
                    status: 0,
                    stdout: out.to_string(),
                    stderr: String::new(),
                },
                None => crate::runner::Output {
                    status: 127,
                    stdout: String::new(),
                    stderr: "not found".into(),
                },
            })
        }
        async fn read_file(&self, _: &str) -> Result<Option<String>> {
            Ok(None)
        }
        async fn write_file(&self, _: &str, _: &str) -> Result<()> {
            Ok(())
        }
        fn label(&self) -> String {
            "scripted".into()
        }
    }

    #[tokio::test]
    async fn a_running_timesyncd_satisfies_the_clock_without_chrony() {
        // Installing chrony next to it would start a second client on the same clock.
        let r = Scripted(vec![
            ("timedatectl show", "NTP=yes\nNTPSynchronized=no\n"),
            ("systemctl is-active systemd-timesyncd", "active\n"),
        ]);
        let d = Distro::parse("ID=arch\nPRETTY_NAME=x\n").expect("distro");
        let seen = dependencies(&r, &d).await.expect("observed");
        let ntp = seen.iter().find(|(n, _)| *n == "ntp").expect("ntp");
        assert_eq!(ntp.1.as_deref(), Some("via systemd-timesyncd"));
    }

    #[tokio::test]
    async fn no_client_at_all_leaves_the_clock_missing() {
        let r = Scripted(vec![("timedatectl show", "NTP=no\n")]);
        let d = Distro::parse("ID=arch\nPRETTY_NAME=x\n").expect("distro");
        let seen = dependencies(&r, &d).await.expect("observed");
        assert_eq!(seen.iter().find(|(n, _)| *n == "ntp").expect("ntp").1, None);
    }

    #[test]
    fn a_version_is_found_inside_a_sentence() {
        assert_eq!(
            extract_version("Docker version 27.3.1, build ce1223035a"),
            "27.3.1"
        );
        assert_eq!(
            extract_version("wireguard-tools v1.0.20210914"),
            "1.0.20210914"
        );
    }

    #[test]
    fn memory_is_read_from_meminfo() {
        let m = "MemTotal:       16311456 kB\nMemFree:         1234 kB\n";
        assert_eq!(parse_meminfo_total_mb(m), Some(15929));
    }

    #[test]
    fn a_malformed_meminfo_gives_none() {
        assert_eq!(parse_meminfo_total_mb(""), None);
        assert_eq!(parse_meminfo_total_mb("MemTotal: abc kB"), None);
        assert_eq!(parse_meminfo_total_mb("MemFree: 100 kB"), None);
    }

    #[test]
    fn disk_space_is_read_from_df() {
        let df = "Filesystem 1M-blocks Used Available Capacity Mounted on\n\
                  /dev/sda1      102400 20480     76800      21% /\n";
        assert_eq!(parse_df_available_mb(df), Some(76800));
    }

    #[test]
    fn a_df_without_data_gives_none() {
        assert_eq!(
            parse_df_available_mb("Filesystem 1M-blocks Used Available\n"),
            None
        );
        assert_eq!(parse_df_available_mb(""), None);
    }

    #[test]
    fn clock_sync_is_read_from_timedatectl() {
        let out = "Timezone=Europe/Paris\nNTPSynchronized=yes\nCanNTP=yes\n";
        assert_eq!(parse_timedatectl_synced(out), Some(true));

        let out = "Timezone=UTC\nNTPSynchronized=no\n";
        assert_eq!(parse_timedatectl_synced(out), Some(false));
    }

    #[test]
    fn a_timedatectl_without_the_field_gives_none() {
        // An older version may not expose this field: concluding nothing beats
        // assuming the clock is fine.
        assert_eq!(parse_timedatectl_synced("Timezone=UTC\n"), None);
    }

    #[tokio::test]
    async fn a_systemd_creds_missing_over_ssh_is_a_tpm_not_tried_never_absent() {
        // SSH answers a missing command with exit 127, where the local runner errs:
        // read as an empty `has-tpm2`, a machine with a TPM would be sent to its firmware.
        let r = Scripted(vec![("id -u", "0\n")]);
        let signals = protection(&r).await.expect("observed");
        assert_eq!(signals.tpm, crate::protection::Tpm::Untried);
        assert!(!tpm_driver(&r).await);
    }

    #[tokio::test]
    async fn observing_the_local_machine_does_not_panic() {
        // This test runs on macOS as well as Linux: /proc does not exist everywhere,
        // and observation must degrade cleanly rather than fail.
        let obs = observe(&crate::LocalRunner).await.expect("observation");
        // On macOS the os-release is absent, hence empty: that is a valid finding.
        assert!(obs.os_release.is_empty() || obs.os_release.contains("ID"));
    }

    #[tokio::test]
    async fn a_missing_binary_never_claims_presence() {
        // 🔴 A missing Docker must give None, never an invented version.
        struct Empty;
        #[async_trait::async_trait]
        impl Runner for Empty {
            async fn run(&self, _: &[String]) -> Result<crate::runner::Output> {
                Ok(crate::runner::Output {
                    status: 127,
                    stdout: String::new(),
                    stderr: "command not found".into(),
                })
            }
            async fn read_file(&self, _: &str) -> Result<Option<String>> {
                Ok(None)
            }
            async fn write_file(&self, _: &str, _: &str) -> Result<()> {
                Ok(())
            }
            fn label(&self) -> String {
                "empty".into()
            }
        }

        let obs = observe(&Empty).await.expect("observation");
        assert!(obs.docker_version.is_none());
        assert!(!obs.podman_present);
        assert!(!obs.is_root);
        assert!(obs.total_memory_mb.is_none());
    }
}
