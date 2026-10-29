//! Swarm's unlock key sealed to a manager, given back to Docker each time it starts.
//!
//! With autolock on, a manager keeps the Raft log — every app's secrets — encrypted on
//! its disk, and a restarted daemon stays locked until it is handed the key: a house
//! that reboots at night no longer comes back alone. Sealed by `systemd-creds` as the
//! vault's key is ([`crate::seal`]), the key opens only on its machine, and
//! `hlb-swarm-unlock.service` hands it to `docker swarm unlock` after every start of
//! Docker, a restart or a crash included.
//!
//! ## Why the key lives in memory for one command only
//!
//! The unit is a `oneshot` that does not remain active: its credential directory is
//! emptied as soon as the unlock returns. Remaining active would also leave it out of
//! the next start of Docker — a start job on an active unit runs nothing.

use crate::provision::{Action, Phase, Step};
use crate::seal::{self, Sealer};

pub const UNIT: &str = "hlb-swarm-unlock.service";
pub const UNIT_PATH: &str = "/etc/systemd/system/hlb-swarm-unlock.service";
/// The credential's name: decrypting it under another name is refused.
pub const NAME: &str = "swarm-unlock-key";
pub const CREDENTIAL: &str = "/var/lib/hlb/swarm-unlock-key.cred";
/// Where the key waits, in memory, for the one step that seals it. `/run` is a tmpfs.
pub const STAGED: &str = "/run/hlb-swarm-unlock-key";

// `$$` is systemd's escape for a `$` the shell is to see.
pub const UNIT_CONTENT: &str = "\
# Written by Homelabus (`hlb cluster autolock`): Swarm's unlock key, sealed to this
# machine, handed to Docker after each of its starts.
[Unit]
Description=Homelabus Swarm unlock, after each start of Docker
After=docker.service

[Service]
Type=oneshot
LoadCredentialEncrypted=swarm-unlock-key:/var/lib/hlb/swarm-unlock-key.cred
# An unlocked Swarm, or none, is left alone: `docker swarm unlock` would fail on it.
ExecCondition=/bin/sh -c 'test \"$$(docker info --format {{.Swarm.LocalNodeState}})\" = locked'
# On standard input: a command line is readable by every user of the machine.
ExecStart=/bin/sh -c 'exec docker swarm unlock < \"$${CREDENTIALS_DIRECTORY}/swarm-unlock-key\"'

[Install]
WantedBy=docker.service
";

/// The steps that seal the key waiting at [`STAGED`], then remove it. The caller puts
/// it there (`Runner::write_file`, through standard input) and removes it if a step
/// fails.
pub fn steps(sealer: Sealer) -> Vec<Step> {
    let mut steps = seal::encrypt(NAME, CREDENTIAL, STAGED, sealer);
    steps.push(Step {
        phase: Phase::Services,
        what: "forget the key outside its credential".to_string(),
        action: Action::Run(vec!["rm".into(), "-f".into(), STAGED.into()]),
    });
    steps.extend(seal::enable(UNIT, UNIT_PATH, UNIT_CONTENT));
    steps
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seal::Binding;

    #[test]
    fn the_unit_loads_the_credential_the_steps_write() {
        let wanted = format!("LoadCredentialEncrypted={NAME}:{CREDENTIAL}\n");
        assert!(UNIT_CONTENT.contains(&wanted), "{UNIT_CONTENT}");
        assert!(UNIT_CONTENT.contains(&format!("/{NAME}")), "{UNIT_CONTENT}");
        assert!(UNIT_PATH.ends_with(UNIT));
        let encrypt = steps(Sealer::HostAndTpm(Binding::Unbound))
            .into_iter()
            .find_map(|s| match s.action {
                Action::Run(a) if a.get(1).map(String::as_str) == Some("encrypt") => Some(a),
                _ => None,
            })
            .expect("an encrypt step");
        assert!(encrypt.contains(&format!("--name={NAME}")), "{encrypt:?}");
        assert!(encrypt.contains(&STAGED.to_string()), "{encrypt:?}");
    }

    #[test]
    fn the_unlock_runs_at_every_start_of_docker() {
        assert!(UNIT_CONTENT.contains("WantedBy=docker.service"));
        assert!(UNIT_CONTENT.contains("After=docker.service"));
        // Remaining active, the unit would be skipped by Docker's next start.
        assert!(!UNIT_CONTENT.contains("RemainAfterExit=yes"));
    }

    #[test]
    fn every_dollar_reaches_the_shell() {
        // A bare `$` is expanded by systemd itself, to nothing.
        for line in UNIT_CONTENT.lines().filter(|l| l.starts_with("Exec")) {
            let bare = line.replace("$$", "");
            assert!(!bare.contains('$'), "{line}");
        }
    }

    #[test]
    fn the_key_outside_its_credential_is_removed_once_sealed() {
        let steps = steps(Sealer::HostOnly);
        let at = |needle: &str| {
            steps
                .iter()
                .position(|s| matches!(&s.action, Action::Run(a) if a.iter().any(|x| x == needle)))
                .unwrap_or_else(|| panic!("no step with {needle}"))
        };
        assert!(at(CREDENTIAL) < at("rm"));
        assert!(STAGED.starts_with("/run/"), "never on a disk");
    }
}
