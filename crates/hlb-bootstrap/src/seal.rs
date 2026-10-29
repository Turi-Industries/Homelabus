//! The vault's master key sealed to this machine, and unsealed into memory at boot.
//!
//! `systemd-creds` encrypts the key with the machine's host key and, when it has one,
//! its TPM; `hlb-vault.service` decrypts it at boot into its credentials directory, a
//! `ramfs` only root reads, which lives exactly as long as the unit is active. The key's
//! old path becomes a link to it, so `hlb` and the controller's bind mount keep the
//! path they had.
//!
//! ## 🔴 What it protects, and what it does not
//!
//! With a TPM, a disk taken out of its machine, or a backup holding the credential,
//! opens nothing: the TPM stays behind. Without one, the host key sits on the same disk
//! as the credential, and only a credential copied alone opens nothing. A machine
//! carried away whole boots and unseals either way — that is disk encryption's to stop,
//! with a share held off the machine (Tang).
//!
//! ## Why no PCR is named, when systemd can do without
//!
//! `systemd-creds` binds to PCR 7 by default, the Secure Boot policy. A firmware or dbx
//! update changes it, and the key would stay sealed at the next boot — every secret and
//! the controller with it — while a signed live system booted on the stolen machine
//! measures the same PCR 7 anyway. `--tpm2-pcrs=` binds to the TPM alone. ⚠️ systemd
//! 252 (Debian 12) seals with no PCR and then cannot unseal it ("PCR bank invalid"), so
//! each binding is tried — sealed and unsealed, a value of no worth — and the first that
//! comes back is the one used: none, then PCR 7.
//!
//! ## 🔴 A TPM systemd cannot use
//!
//! systemd loads the TPM's libraries when it needs them, and Debian does not install
//! them: `has-tpm2` says `+driver` and every seal fails "TPM2 support not installed".
//! `tpm2-tools` pulls them in, under that name on every distribution.

use crate::provision::{Action, Phase, Step};

pub const UNIT: &str = "hlb-vault.service";
pub const UNIT_PATH: &str = "/etc/systemd/system/hlb-vault.service";
/// The credential's name: decrypting it under another name is refused, so it is part of
/// what it was sealed with.
pub const NAME: &str = "hlb-master-key";
pub const CREDENTIAL: &str = "/var/lib/hlb/hlb-master-key.cred";
/// Where the unit unseals the key, and where the key's old path then points.
pub const UNSEALED: &str = "/run/credentials/hlb-vault.service/hlb-master-key";

pub const UNIT_CONTENT: &str = "\
# Written by Homelabus (`hlb secrets-seal`): the vault's master key, unsealed into
# memory. Stopping this unit takes the key away from hlb and the controller.
[Unit]
Description=Homelabus vault master key, unsealed into memory
# A controller task started first would find no key to mount.
Before=docker.service

[Service]
Type=oneshot
# The credential lives exactly as long as the unit is active.
RemainAfterExit=yes
LoadCredentialEncrypted=hlb-master-key:/var/lib/hlb/hlb-master-key.cred
ExecStart=/bin/true

[Install]
WantedBy=multi-user.target
";

/// How the TPM binds the key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Binding {
    /// To the TPM alone.
    Unbound,
    /// To PCR 7 too: a Secure Boot or dbx update leaves it sealed until sealed again.
    Pcr7,
}

impl Binding {
    pub const ALL: [Self; 2] = [Self::Unbound, Self::Pcr7];

    fn pcrs(&self) -> &'static str {
        match self {
            Self::Unbound => "--tpm2-pcrs=",
            Self::Pcr7 => "--tpm2-pcrs=7",
        }
    }
}

/// What the key is sealed with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sealer {
    HostAndTpm(Binding),
    HostOnly,
}

/// What `systemd-creds has-tpm2` and the trials said.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Probe {
    Sealer(Sealer),
    /// A TPM is there, and systemd lacks its libraries.
    MissingLibraries,
    /// A TPM is there and every trial failed, for this last reason. Never quietly the
    /// host key alone: that opens with the disk, and the person believed in the TPM.
    Refuses(String),
}

/// A TPM's driver is loaded: worth trying. The `firmware` line is not read — it says
/// whether the firmware measured the boot, which no PCR here relies on (SeaBIOS says
/// `-firmware` over a TPM that seals fine).
pub fn has_driver(has_tpm2: &str) -> bool {
    has_tpm2.lines().any(|l| l.trim() == "+driver")
}

/// The decision, from the driver and each binding's trial in [`Binding::ALL`]'s order:
/// `Ok(())`, or the trial's error output.
pub fn decide(driver: bool, trials: &[(Binding, Result<(), String>)]) -> Probe {
    if !driver {
        return Probe::Sealer(Sealer::HostOnly);
    }
    if let Some((b, _)) = trials.iter().find(|(_, r)| r.is_ok()) {
        return Probe::Sealer(Sealer::HostAndTpm(*b));
    }
    if trials
        .iter()
        .any(|(_, r)| matches!(r, Err(e) if e.contains("TPM2 support not installed")))
    {
        return Probe::MissingLibraries;
    }
    let why = trials
        .last()
        .and_then(|(_, r)| r.as_ref().err())
        .map(|e| e.trim().to_string())
        .unwrap_or_default();
    Probe::Refuses(why)
}

/// What [`MissingLibraries`](Probe::MissingLibraries) installs.
pub const TPM_PACKAGE: &str = "tpm2-tools";

/// A value of no worth sealed and unsealed with `binding`, in memory: exits 0 only if
/// both work. Changes nothing on the machine.
pub fn trial(binding: Binding) -> Vec<String> {
    let script = format!(
        "f=$(mktemp -p /run) || exit 1; \
         printf probe | systemd-creds encrypt --name=hlb-probe --with-key=host+tpm2 {} - \"$f\" \
         && systemd-creds decrypt --name=hlb-probe \"$f\" - >/dev/null; \
         r=$?; rm -f \"$f\"; exit $r",
        binding.pcrs()
    );
    vec!["sh".into(), "-c".into(), script]
}

impl Sealer {
    fn with_key(&self) -> &'static str {
        match self {
            Self::HostAndTpm(_) => "host+tpm2",
            Self::HostOnly => "host",
        }
    }

    fn pcrs(&self) -> Option<&'static str> {
        match self {
            Self::HostAndTpm(b) => Some(b.pcrs()),
            Self::HostOnly => None,
        }
    }

    /// For the audit log.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::HostAndTpm(Binding::Unbound) => "host+tpm2",
            Self::HostAndTpm(Binding::Pcr7) => "host+tpm2, pcr 7",
            Self::HostOnly => "host",
        }
    }

    pub fn describe(&self) -> &'static str {
        match self {
            Self::HostAndTpm(Binding::Unbound) => {
                "this machine's TPM and host key: a disk taken out of it, or a backup of \
                 the credential, opens nothing"
            }
            Self::HostAndTpm(Binding::Pcr7) => {
                "this machine's TPM, bound to its Secure Boot policy (PCR 7), and its host \
                 key: a disk taken out of it opens nothing. This systemd cannot seal \
                 without a PCR, so a firmware or dbx update leaves the key sealed at the \
                 next boot: the kit's copy stands in until this command seals it again"
            }
            Self::HostOnly => {
                "this machine's host key alone — no TPM seals here. The host key sits on \
                 the same disk: a credential copied alone opens nothing, the disk itself does \
                 until it is encrypted"
            }
        }
    }
}

fn run(what: &str, argv: &[&str]) -> Step {
    Step {
        phase: Phase::Services,
        what: what.to_string(),
        action: Action::Run(argv.iter().map(|s| s.to_string()).collect()),
    }
}

/// The steps that encrypt the file at `source` into `credential`, under `name` — the
/// name a unit must load it by. Sealing again replaces the credential whole.
pub fn encrypt(name: &str, credential: &str, source: &str, sealer: Sealer) -> Vec<Step> {
    let staged = format!("{credential}.hlb-new");
    let with_key = format!("--with-key={}", sealer.with_key());
    let name = format!("--name={name}");
    let mut encrypt = vec!["systemd-creds", "encrypt", &name, &with_key];
    encrypt.extend(sealer.pcrs());
    encrypt.extend([source, &staged]);
    vec![
        run(
            "a directory only root enters",
            &["install", "-d", "-m", "0700", "/var/lib/hlb"],
        ),
        // The secret travels by its path, never by its value: a command line is readable
        // by every user of the machine.
        run("seal it", &encrypt),
        run(
            "put the credential in place",
            &["mv", "-f", &staged, credential],
        ),
    ]
}

/// The unit file at `path`, then systemd told about it and the unit enabled.
pub fn enable(unit: &str, path: &str, content: &str) -> Vec<Step> {
    vec![
        Step {
            phase: Phase::Configuration,
            what: "the unit that unseals it at boot".to_string(),
            action: Action::Install {
                path: path.to_string(),
                content: content.to_string(),
                mode: 0o644,
            },
        },
        run("read the unit", &["systemctl", "daemon-reload"]),
        run("unseal it at every boot", &["systemctl", "enable", unit]),
    ]
}

/// The steps that seal the key at `key` and unseal it now, as at every boot. Sealing
/// again — after a rekey — replaces the credential and restarts the unit.
pub fn steps(key: &str, sealer: Sealer) -> Vec<Step> {
    let mut steps = encrypt(NAME, CREDENTIAL, key, sealer);
    steps.extend(enable(UNIT, UNIT_PATH, UNIT_CONTENT));
    // `restart`, not `start`: sealed again, an active unit still holds the old key.
    steps.push(run("unseal it now", &["systemctl", "restart", UNIT]));
    steps
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_unit_unseals_the_credential_the_steps_write() {
        let wanted = format!("LoadCredentialEncrypted={NAME}:{CREDENTIAL}\n");
        assert!(UNIT_CONTENT.contains(&wanted), "{UNIT_CONTENT}");
        assert_eq!(
            UNSEALED,
            format!("/run/credentials/{UNIT}/{NAME}"),
            "systemd puts a credential at /run/credentials/<unit>/<name>"
        );
        assert!(UNIT_PATH.ends_with(UNIT));
    }

    #[test]
    fn the_unit_stays_active_or_the_key_vanishes() {
        // A oneshot's credentials are removed when it stops; without this, at once.
        assert!(UNIT_CONTENT.contains("RemainAfterExit=yes"));
        assert!(UNIT_CONTENT.contains("Before=docker.service"));
    }

    #[test]
    fn the_key_is_named_by_its_path_never_its_value() {
        let seal = steps("/root/hlb-master.key", Sealer::HostAndTpm(Binding::Unbound));
        let argv = seal
            .iter()
            .find_map(|s| match &s.action {
                Action::Run(a) if a.get(1).map(String::as_str) == Some("encrypt") => Some(a),
                _ => None,
            })
            .expect("an encrypt step");
        assert!(argv.contains(&"/root/hlb-master.key".to_string()));
        assert!(argv.contains(&format!("--name={NAME}")));
        assert!(argv.contains(&"--tpm2-pcrs=".to_string()), "{argv:?}");
    }

    const HAS_TPM2_SEABIOS: &str = "partial\n-firmware\n+driver\n+system\n+subsystem\n";
    const HAS_TPM2_NONE: &str = "partial\n-firmware\n-driver\n+system\n+subsystem\n";

    #[test]
    fn a_tpm_the_firmware_did_not_announce_is_still_tried() {
        // The lab's SeaBIOS: no firmware measurement, a TPM that seals fine.
        assert!(has_driver(HAS_TPM2_SEABIOS));
        assert!(!has_driver(HAS_TPM2_NONE));
        assert!(!has_driver("-driver\n"), "a minus is not a plus");
    }

    #[test]
    fn the_first_binding_that_comes_back_is_the_one_used() {
        let fail = |e: &str| Err(e.to_string());
        // systemd 252: sealed with no PCR, never unsealed.
        let debian12 = [
            (
                Binding::Unbound,
                fail("TPM2 PCR bank invalid or not supported"),
            ),
            (Binding::Pcr7, Ok(())),
        ];
        assert_eq!(
            decide(true, &debian12),
            Probe::Sealer(Sealer::HostAndTpm(Binding::Pcr7))
        );
        let newer = [(Binding::Unbound, Ok(())), (Binding::Pcr7, Ok(()))];
        assert_eq!(
            decide(true, &newer),
            Probe::Sealer(Sealer::HostAndTpm(Binding::Unbound))
        );
        let no_libraries = [
            (
                Binding::Unbound,
                fail("TPM2 support not installed: Operation not supported"),
            ),
            (
                Binding::Pcr7,
                fail("TPM2 support not installed: Operation not supported"),
            ),
        ];
        assert_eq!(decide(true, &no_libraries), Probe::MissingLibraries);
        let broken = [(Binding::Unbound, fail("x")), (Binding::Pcr7, fail("y\n"))];
        assert_eq!(decide(true, &broken), Probe::Refuses("y".into()));
        assert_eq!(decide(false, &newer), Probe::Sealer(Sealer::HostOnly));
    }

    #[test]
    fn the_seal_names_what_the_trial_proved() {
        let encrypt = |sealer| {
            steps("/k", sealer)
                .into_iter()
                .find_map(|s| match s.action {
                    Action::Run(a) if a.get(1).map(String::as_str) == Some("encrypt") => Some(a),
                    _ => None,
                })
                .expect("an encrypt step")
        };
        for b in Binding::ALL {
            let argv = encrypt(Sealer::HostAndTpm(b));
            assert!(argv.contains(&"--with-key=host+tpm2".to_string()));
            assert!(argv.contains(&b.pcrs().to_string()), "{argv:?}");
            let probe = trial(b).join(" ");
            assert!(
                probe.contains(b.pcrs()) && probe.contains("decrypt"),
                "{probe}"
            );
        }
        let host = encrypt(Sealer::HostOnly);
        assert!(host.contains(&"--with-key=host".to_string()));
        assert!(!host.iter().any(|a| a.starts_with("--tpm2")), "{host:?}");
    }

    #[test]
    fn the_credential_is_written_beside_then_moved() {
        let seal = steps("/k", Sealer::HostOnly);
        let at = |needle: &str| {
            seal.iter()
                .position(|s| matches!(&s.action, Action::Run(a) if a.iter().any(|x| x == needle)))
                .unwrap_or_else(|| panic!("no step with {needle}"))
        };
        // A credential cut in half by a full disk would be read at the next boot.
        assert!(at(&format!("{CREDENTIAL}.hlb-new")) < at(CREDENTIAL));
        assert!(at("daemon-reload") < at("restart"));
    }
}
