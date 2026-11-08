//! NUT's `upsmon` on a node, a secondary of the house's UPS: what shuts the machine down
//! at low battery — by then Homelabus has stopped every app, so nothing is writing.
//!
//! 🔴 A NUT someone set up is never rewritten. The machine the UPS is plugged into runs
//! NUT's server and its own `upsmon` as the primary, which tells the secondaries to go
//! down and then cuts the power: a secondary's configuration written over it would leave
//! the UPS with nobody to cut it, and the house dark after the next outage.

use crate::distro::{Distro, Family};
use crate::provision::{Action, Phase, Provision, Step};

pub const NUT_CONF: &str = "/etc/nut/nut.conf";
pub const UPSMON_CONF: &str = "/etc/nut/upsmon.conf";
/// What upsmon runs at low battery: waits for the apps' containers, then powers off.
pub const SHUTDOWN_SCRIPT: &str = "/etc/nut/hlb-shutdown";

/// How long the machine waits for the apps' containers to end before it powers off anyway.
pub const CONTAINERS_WAIT_S: u32 = 60;

/// The first line of every file written here: what is rewritten, and what is a person's.
pub const MARK: &str = "# Written by Homelabus (hlb config ups): rewritten by it.";

/// The unit `nut-client` installs on Debian and Ubuntu.
pub const UNIT: &str = "nut-monitor";

/// What a node's `upsmon` attaches to, and as whom.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Monitor {
    /// `host` or `host:port`.
    pub server: String,
    pub ups: String,
    pub user: String,
    pub password: String,
}

/// What `nut.conf` says the machine is: `none` when there is no file.
pub fn mode(nut_conf: Option<&str>) -> String {
    nut_conf
        .into_iter()
        .flat_map(str::lines)
        .filter_map(|l| l.trim().strip_prefix("MODE="))
        .next_back()
        .map(|m| m.trim().trim_matches('"').to_string())
        .unwrap_or_else(|| "none".into())
}

/// Did a person write this `upsmon.conf`? Debian's own is all comments.
fn hand_written(upsmon_conf: Option<&str>) -> bool {
    upsmon_conf.is_some_and(|c| {
        !c.starts_with(MARK)
            && c.lines().any(|l| {
                let l = l.trim();
                !l.is_empty() && !l.starts_with('#')
            })
    })
}

/// Why this machine's NUT is not Homelabus's to write, if it is not.
pub fn refusal(
    distro: &Distro,
    nut_conf: Option<&str>,
    upsmon_conf: Option<&str>,
) -> Option<String> {
    if distro.family != Family::Debian {
        return Some(format!(
            "not set up on {} yet: install NUT's client and point its upsmon at the UPS \
             by hand",
            distro.id
        ));
    }
    let mode = mode(nut_conf);
    if mode == "standalone" || mode == "netserver" {
        return Some(format!(
            "NUT serves the UPS from this machine (MODE={mode}): its upsmon is the \
             primary, already set up, and never rewritten"
        ));
    }
    let ours = nut_conf.is_some_and(|c| c.starts_with(MARK));
    if (mode != "none" && !ours) || hand_written(upsmon_conf) {
        return Some(format!(
            "{UPSMON_CONF} was set up by hand (MODE={mode}): it is never rewritten — \
             remove it to let Homelabus write it"
        ));
    }
    None
}

/// 🔴 At a SUDDEN low battery (a worn battery says it within seconds of the cut) upsmon
/// reached its shutdown while Homelabus's waves still ran: the machines went down before
/// the databases' wave (lab, 2026-11-08), and systemd stopped those containers unordered.
/// Waits, bounded, until no task container runs here but Homelabus's own (`hlb-…`, which
/// stop last of all), then powers off. A Docker that does not answer lists nothing: the
/// machine goes down at once.
fn shutdown_script() -> String {
    const BODY: &str = r#"PATH=/usr/sbin:/usr/bin:/sbin:/bin
waited=0
while [ "$waited" -lt WAIT ]; do
	left=$(docker ps --filter label=com.docker.swarm.service.name \
		--format '{{.Label "com.docker.swarm.service.name"}}' 2>/dev/null | grep -v '^hlb-')
	[ -z "$left" ] && break
	sleep 2
	waited=$((waited + 2))
done
exec /sbin/shutdown -h +0
"#;
    format!(
        "#!/bin/sh\n{MARK}\n{}",
        BODY.replace("WAIT", &CONTAINERS_WAIT_S.to_string())
    )
}

/// The three files.
pub fn files(m: &Monitor) -> [(String, String, u32); 3] {
    let q = |w: &str| format!("\"{}\"", w.replace('\\', "\\\\").replace('"', "\\\""));
    [
        (NUT_CONF.into(), format!("{MARK}\nMODE=netclient\n"), 0o644),
        (
            UPSMON_CONF.into(),
            format!(
                "{MARK}\n\
                 # A secondary: it shuts this machine down when the UPS says its battery is\n\
                 # low, or when the UPS's primary orders every machine down.\n\
                 MONITOR {} 1 {} {} secondary\n\
                 MINSUPPLIES 1\n\
                 SHUTDOWNCMD \"{SHUTDOWN_SCRIPT}\"\n",
                q(&format!("{}@{}", m.ups, m.server)),
                q(&m.user),
                q(&m.password),
            ),
            // Read by upsmon's unprivileged half too, when it reloads.
            0o640,
        ),
        (SHUTDOWN_SCRIPT.into(), shutdown_script(), 0o755),
    ]
}

/// The steps that make the machine a secondary. The preview prints paths and modes,
/// never the password `upsmon.conf` holds.
pub fn plan(distro: &Distro, m: &Monitor) -> Provision {
    let pm = distro.package_manager();
    let mut steps = Vec::new();
    if let Some(refresh) = pm.refresh_command() {
        steps.push(Step {
            phase: Phase::Packages,
            what: "Refresh the package index".into(),
            action: Action::Run(refresh),
        });
    }
    steps.push(Step {
        phase: Phase::Packages,
        what: "Install NUT's client".into(),
        action: Action::Run(pm.install_command(&["nut-client"])),
    });
    for (path, content, mode) in files(m) {
        steps.push(Step {
            phase: Phase::Configuration,
            what: format!("Write {}", path.rsplit('/').next().unwrap_or(&path)),
            action: Action::Install {
                path,
                content,
                mode,
            },
        });
    }
    steps.push(Step {
        phase: Phase::Configuration,
        what: "Let upsmon's unprivileged half read it".into(),
        // `chgrp`, not `chown root:nut`: the file is root's already, and an `owner:group`
        // literal reads as an unpinned image to the scan over every source.
        action: Action::Run(vec!["chgrp".into(), "nut".into(), UPSMON_CONF.into()]),
    });
    steps.push(Step {
        phase: Phase::Services,
        what: "Start upsmon at every boot".into(),
        action: Action::Run(vec!["systemctl".into(), "enable".into(), UNIT.into()]),
    });
    steps.push(Step {
        phase: Phase::Services,
        what: "Start it now, on these files".into(),
        action: Action::Run(vec!["systemctl".into(), "restart".into(), UNIT.into()]),
    });
    Provision {
        steps,
        notes: Vec::new(),
    }
}

/// The steps that make it no secondary any more: only ever run where [`MARK`] is.
pub fn unplan() -> Provision {
    let step = |phase, what: &str, argv: &[&str]| Step {
        phase,
        what: what.into(),
        action: Action::Run(argv.iter().map(|a| a.to_string()).collect()),
    };
    Provision {
        steps: vec![
            step(
                Phase::Services,
                "Stop upsmon, and at boot",
                &["systemctl", "disable", "--now", UNIT],
            ),
            Step {
                phase: Phase::Configuration,
                what: "Say NUT is not used here".into(),
                action: Action::Install {
                    path: NUT_CONF.into(),
                    content: format!("{MARK}\nMODE=none\n"),
                    mode: 0o644,
                },
            },
            step(
                Phase::Configuration,
                "Remove the account upsmon signed in with",
                &["rm", "-f", UPSMON_CONF, SHUTDOWN_SCRIPT],
            ),
        ],
        notes: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn debian() -> Distro {
        Distro::parse("ID=debian\nVERSION_ID=\"12\"\nVERSION_CODENAME=bookworm\n").expect("parse")
    }

    fn monitor() -> Monitor {
        Monitor {
            server: "nut.lan:3493".into(),
            ups: "house".into(),
            user: "monitor".into(),
            password: "mon-pass.2".into(),
        }
    }

    /// Debian 12's `nut-client` 2.8.0, as installed: MODE=none, upsmon.conf all comments.
    const DEBIAN_NUT_CONF: &str = "# Network UPS Tools: example nut.conf\n#\nMODE=none\n";
    const DEBIAN_UPSMON: &str = "# Network UPS Tools: example upsmon configuration\n\
                                 #\n# MONITOR myups@localhost 1 upsmon pass primary\n";

    #[test]
    fn a_fresh_machine_or_one_written_here_is_written() {
        assert_eq!(refusal(&debian(), None, None), None);
        assert_eq!(
            refusal(&debian(), Some(DEBIAN_NUT_CONF), Some(DEBIAN_UPSMON)),
            None
        );
        let [(_, nut, _), (_, upsmon, _), _] = files(&monitor());
        assert_eq!(refusal(&debian(), Some(&nut), Some(&upsmon)), None);
    }

    #[test]
    fn the_machine_serving_the_ups_is_never_rewritten() {
        for mode in ["standalone", "netserver", "\"netserver\""] {
            let conf = format!("MODE={mode}\n");
            let why = refusal(&debian(), Some(&conf), None).expect(mode);
            assert!(why.contains("primary"), "{why}");
        }
        // A secondary set up by hand.
        let why = refusal(
            &debian(),
            Some("MODE=netclient\n"),
            Some("MONITOR ups@nas 1 u p secondary\n"),
        )
        .expect("by hand");
        assert!(why.contains("by hand"), "{why}");
        let alpine = Distro::parse("ID=alpine\nVERSION_ID=3.20.0\n").expect("parse");
        assert!(refusal(&alpine, None, None).is_some());
    }

    #[test]
    fn at_low_battery_the_machine_waits_for_the_apps_then_powers_off() {
        let [_, (_, upsmon, _), (path, script, mode)] = files(&monitor());
        assert!(upsmon.contains(&format!("SHUTDOWNCMD \"{SHUTDOWN_SCRIPT}\"")));
        assert_eq!((path.as_str(), mode), (SHUTDOWN_SCRIPT, 0o755));
        assert!(script.starts_with("#!/bin/sh\n"));
        assert!(
            script.contains(&format!("-lt {CONTAINERS_WAIT_S} ]")),
            "bounded"
        );
        assert!(
            script.contains("grep -v '^hlb-'"),
            "its own daemon stops last"
        );
        assert!(script.trim_end().ends_with("exec /sbin/shutdown -h +0"));
        let check = std::process::Command::new("sh")
            .args(["-n", "-c", &script])
            .output()
            .expect("sh");
        assert!(
            check.status.success(),
            "{}",
            String::from_utf8_lossy(&check.stderr)
        );
        // Taken away with upsmon.
        let removed = unplan()
            .steps
            .iter()
            .map(Step::describe)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(removed.contains(SHUTDOWN_SCRIPT), "{removed}");
    }

    #[test]
    fn upsmon_is_a_secondary_and_its_password_never_shown() {
        let [(nut_path, nut, nut_mode), (path, upsmon, mode), _] = files(&monitor());
        assert_eq!((nut_path.as_str(), nut_mode), (NUT_CONF, 0o644));
        assert!(nut.contains("\nMODE=netclient\n"));
        assert_eq!((path.as_str(), mode), (UPSMON_CONF, 0o640));
        assert!(
            upsmon.contains(r#"MONITOR "house@nut.lan:3493" 1 "monitor" "mon-pass.2" secondary"#)
        );
        // The preview never shows it.
        let shown: Vec<String> = plan(&debian(), &monitor())
            .steps
            .iter()
            .map(Step::describe)
            .collect();
        assert!(shown.iter().all(|s| !s.contains("mon-pass")), "{shown:?}");
        assert!(shown.iter().any(|s| s.contains("nut-client")));
    }
}
