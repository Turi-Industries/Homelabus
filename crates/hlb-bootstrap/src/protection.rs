//! A machine's protection level, read from its firmware, its TPM and its systemd.
//!
//! What a stolen node gives up depends on what its hardware can bind a disk to, not on
//! the distribution's name — so the level is DETECTED, never declared, and never above
//! what was detected: a signal that cannot be read counts as absent.
//!
//! The level is what the machine can REACH. It holds nothing more than an unencrypted
//! machine until its disk is encrypted, which is why the root's encryption is read
//! beside it and said.
//!
//! ## Why the systemd version decides A, and not the tools
//!
//! A (`boot`) builds a signed kernel image with `ukify` and predicts the PCR 11 it
//! produces with `systemd-measure`, then binds Clevis to it AND a Tang. Measured
//! 2026-10-28: Debian 12 (systemd 252) has no `ukify`, not even in backports; Debian 13
//! (257) has it. A tool not installed yet is installed by the step that uses it, so
//! reading its presence would only say what is not done.

/// The first systemd with everything level A uses.
pub const SYSTEMD_FOR_A: u32 = 257;

/// The four levels, best first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    A,
    B,
    C,
    D,
}

impl Level {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::A => "A",
            Self::B => "B",
            Self::C => "C",
            Self::D => "D",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "A" => Some(Self::A),
            "B" => Some(Self::B),
            "C" => Some(Self::C),
            "D" => Some(Self::D),
            _ => None,
        }
    }

    /// The level in one sentence.
    pub fn describe(&self) -> &'static str {
        match self {
            Self::A => {
                "verified boot, disk bound to the network: a signed kernel, the disk \
                 opened by the TPM at that kernel's PCRs, in its initrd only, and by a \
                 Tang of the house"
            }
            Self::B => {
                "disk bound to the network, boot not verified: the TPM and a Tang of the \
                 house both open it; whoever has the machine inside the house gets a \
                 root shell from the boot menu"
            }
            Self::C => {
                "disk encrypted, the boot chain open: no TPM to bind it to — a Tang, a \
                 FIDO2 key or a passphrase opens it, and /boot can be changed unseen"
            }
            Self::D => {
                "encrypted at rest, the host trusted: a virtual machine, whose host reads \
                 its memory and its virtual TPM"
            }
        }
    }
}

/// What the machine's TPM was found to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tpm {
    /// Sealed and unsealed a throwaway value.
    Seals,
    /// No TPM 2.0 driver loaded.
    Absent,
    /// A TPM 1.2: nothing here seals with one.
    Version1,
    /// A TPM 2.0 whose libraries systemd lacks — `tpm2-tools` brings them.
    MissingLibraries,
    /// Answers `has-tpm2` and still seals nothing: `hlb secrets-seal` met one.
    Refuses,
    /// No `systemd-creds` to try it with.
    Untried,
    /// Not run as root: a TPM refuses everyone else, so a refusal would say nothing.
    NotRoot,
}

/// Whether it runs on a hypervisor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Virt {
    BareMetal,
    /// `systemd-detect-virt`'s answer: `kvm`, `vmware`, `lxc`…
    Virtual(String),
    /// `systemd-detect-virt` absent or failing.
    Unknown,
}

/// Everything read from the machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signals {
    pub uefi: bool,
    /// `None`: no `SecureBoot` variable to read — legacy BIOS, or a firmware without it.
    pub secure_boot: Option<bool>,
    /// `SetupMode`: on, the firmware holds no platform key — reset, its keys erased.
    pub setup_mode: Option<bool>,
    pub tpm: Tpm,
    pub virt: Virt,
    pub systemd: Option<u32>,
    /// The kernel modules DKMS builds (`zfs`): under Secure Boot each loads only signed.
    pub dkms: Vec<String>,
    /// `None`: the root's device could not be followed (ZFS root, an overlay).
    pub root_encrypted: Option<bool>,
    /// The platform key's certificate says it is a test key ("DO NOT TRUST - AMI Test
    /// PK"): shipped by the board's maker as is, its private half public (PKfail).
    pub test_platform_key: Option<String>,
}

/// The level and why it is not higher.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assessment {
    pub level: Level,
    /// What keeps the machine from the level above, one reason per line.
    pub held_back: Vec<String>,
    /// What stands in the way of the level itself, said before it bites.
    pub warnings: Vec<String>,
}

pub fn assess(s: &Signals) -> Assessment {
    let mut held_back = Vec::new();
    let mut warnings = Vec::new();

    let level = match &s.virt {
        Virt::Virtual(kind) => {
            held_back.push(format!(
                "a virtual machine ({kind}): its host reads its memory and its TPM's state"
            ));
            Level::D
        }
        Virt::Unknown => {
            held_back.push(
                "could not tell whether it is a virtual machine (`systemd-detect-virt`)"
                    .to_string(),
            );
            Level::D
        }
        Virt::BareMetal => match tpm_shortfall(&s.tpm) {
            Some(why) => {
                held_back.push(why);
                Level::C
            }
            None => {
                held_back.extend(boot_shortfall(s));
                if held_back.is_empty() {
                    Level::A
                } else {
                    Level::B
                }
            }
        },
    };

    if s.secure_boot == Some(true) && !s.dkms.is_empty() {
        warnings.push(format!(
            "Secure Boot is on and DKMS builds {}: a module loads only signed by a key \
             enrolled once at the console (MOK) — unsigned, a ZFS pool stays away",
            s.dkms.join(", ")
        ));
    }

    // Not a lower level: PCR 7 measures PK, KEK and db, so keys rewritten from the
    // running system leave the TPM opening nothing. What it costs is the prompt.
    if let Some(subject) = &s.test_platform_key {
        warnings.push(format!(
            "its Secure Boot platform key is a test key (\"{subject}\", PKfail): its \
             private half is public, so anyone with a root shell can rewrite the boot's \
             keys — a disk that asks for the kit's key after a reboot nobody explained \
             is that; a firmware update from the board's maker replaces it"
        ));
    }

    Assessment {
        level,
        held_back,
        warnings,
    }
}

/// What a joining machine is proposed as.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoleAdvice {
    Manager,
    Worker,
    /// The count asks for a manager and the machine would give every secret up: a
    /// person chooses, both costs said.
    Ask(String),
}

/// The role a machine joins as when none is imposed, from the managers' levels (`None`
/// where none was read) and its own.
///
/// 🔴 Two managers are WORSE than one: their quorum is 2, so losing either stops the
/// control plane, whereas a single manager lost stops only itself — so a second is
/// never proposed, and a third is. A manager holds the whole Raft log, every app's
/// secrets: a C or D machine is never proposed as one, and when the count asks for it
/// there is no default (decided 2026-10-28) — fragile control or exposed secrets.
pub fn advise_role(managers: &[Option<Level>], joining: Level) -> RoleAdvice {
    if managers.is_empty() {
        return RoleAdvice::Manager;
    }
    if managers.len() + 1 < 3 {
        return RoleAdvice::Worker;
    }
    if joining < Level::C {
        return RoleAdvice::Manager;
    }
    RoleAdvice::Ask(format!(
        "the cluster has {n} managers and asks for a third: with {n}, their quorum is \
         {n}, so losing either stops the control plane. But a manager holds every app's \
         secret (the Raft log), and this level-{l} machine gives them up when taken. \
         Choose: --role manager (secrets on this machine) or --role worker (the control \
         plane stays fragile until a machine at B or above joins)",
        n = managers.len(),
        l = joining.as_str()
    ))
}

/// Said when a machine becomes a manager weaker than it should be: below the best
/// manager's level, or one that gives the Raft log up when taken.
pub fn manager_warning(managers: &[Option<Level>], joining: Level) -> Option<String> {
    if joining >= Level::C {
        return Some(format!(
            "a manager holds every app's secret (the Raft log): taken, this level-{} \
             machine gives them up",
            joining.as_str()
        ));
    }
    let best = managers.iter().flatten().min()?;
    (joining > *best).then(|| {
        format!(
            "a manager at level {}, below the best manager's {}: the Raft log is only as \
             safe as its weakest copy",
            joining.as_str(),
            best.as_str()
        )
    })
}

/// Each manager weaker than it need be, said: one that gives the Raft log up when
/// taken, or one below a node that could carry it — `(hostname, is a manager, level)`.
pub fn weak_managers(nodes: &[(&str, bool, Option<Level>)]) -> Vec<String> {
    let best = nodes.iter().filter_map(|(_, _, l)| *l).min();
    nodes
        .iter()
        .filter_map(|(name, manager, level)| {
            let (true, Some(level), Some(best)) = (*manager, *level, best) else {
                return None;
            };
            if level >= Level::C {
                return manager_warning(&[], level).map(|w| format!("{name}: {w}"));
            }
            let better: Vec<&str> = nodes
                .iter()
                .filter(|(_, m, l)| !m && *l == Some(best))
                .map(|(n, _, _)| *n)
                .collect();
            (level > best && !better.is_empty()).then(|| {
                format!(
                    "{name}: a manager at level {}, where {} at {} would carry the Raft log \
                     better",
                    level.as_str(),
                    better.join(", "),
                    best.as_str()
                )
            })
        })
        .collect()
}

/// Said wherever Secure Boot is read off: a reset firmware is not a choice to respect.
pub const SETUP_MODE: &str = "Secure Boot is off: the firmware is in Setup Mode, its keys erased \
     (a reset, or a firmware update) — restore its factory keys in its setup";

/// What keeps a machine whose TPM seals from a verified boot.
fn boot_shortfall(s: &Signals) -> Vec<String> {
    let mut why = Vec::new();
    match (s.uefi, s.secure_boot) {
        (false, _) => why.push("a legacy BIOS: no Secure Boot".to_string()),
        (true, Some(true)) => {}
        (true, Some(false)) if s.setup_mode == Some(true) => why.push(SETUP_MODE.to_string()),
        (true, Some(false)) => why.push("Secure Boot is off".to_string()),
        (true, None) => why.push("the firmware has no Secure Boot variable to read".to_string()),
    }
    match s.systemd {
        Some(v) if v >= SYSTEMD_FOR_A => {}
        Some(v) => why.push(format!(
            "systemd {v}: no `ukify` to build a signed kernel image — systemd \
             {SYSTEMD_FOR_A} has it (Debian 13)"
        )),
        None => why.push("no systemd version read".to_string()),
    }
    why
}

/// Why the TPM binds nothing, or `None` when it seals.
fn tpm_shortfall(tpm: &Tpm) -> Option<String> {
    Some(match tpm {
        Tpm::Seals => return None,
        Tpm::Absent => "no TPM 2.0 — or one the firmware leaves off".to_string(),
        Tpm::Version1 => "a TPM 1.2: nothing seals with it".to_string(),
        Tpm::MissingLibraries => "a TPM 2.0 systemd cannot use yet: its libraries are missing \
                                  (`tpm2-tools`), so it is not proven to seal"
            .to_string(),
        Tpm::Refuses => "a TPM 2.0 that answers and seals nothing".to_string(),
        Tpm::Untried => {
            "no `systemd-creds` to prove the TPM seals (systemd 250 or later)".to_string()
        }
        Tpm::NotRoot => "not run as root: the TPM was not tried".to_string(),
    })
}

/// The TPM, from `has-tpm2`, the trials' verdict and `/sys/class/tpm/tpm0/tpm_version_major`.
pub fn tpm(
    root: bool,
    has_tpm2: Option<&str>,
    probe: Option<&crate::seal::Probe>,
    version_major: Option<&str>,
) -> Tpm {
    use crate::seal::{Probe, Sealer};
    let Some(has_tpm2) = has_tpm2 else {
        return Tpm::Untried;
    };
    if !crate::seal::has_driver(has_tpm2) {
        // `has-tpm2` speaks of TPM 2.0 alone: a 1.2 reads as no TPM at all.
        return if version_major.map(str::trim) == Some("1") {
            Tpm::Version1
        } else {
            Tpm::Absent
        };
    }
    if !root {
        return Tpm::NotRoot;
    }
    match probe {
        Some(Probe::Sealer(Sealer::HostAndTpm(_))) => Tpm::Seals,
        Some(Probe::MissingLibraries) => Tpm::MissingLibraries,
        Some(Probe::Sealer(Sealer::HostOnly) | Probe::Refuses(_)) | None => Tpm::Refuses,
    }
}

/// `systemctl --version`'s first line: `systemd 252 (252.39-1~deb12u1)`.
pub fn parse_systemd_version(out: &str) -> Option<u32> {
    let mut words = out.lines().next()?.split_whitespace();
    (words.next()? == "systemd").then_some(())?;
    words.next()?.parse().ok()
}

/// `od -An -tu1` of the `SecureBoot` variable — or `SetupMode`, shaped alike: four bytes
/// of attributes, then the value.
pub fn parse_secure_boot(od: &str) -> Option<bool> {
    let bytes: Vec<u8> = od
        .split_whitespace()
        .map(str::parse)
        .collect::<Result<_, _>>()
        .ok()?;
    match bytes.as_slice() {
        [_, _, _, _, 1] => Some(true),
        [_, _, _, _, 0] => Some(false),
        _ => None,
    }
}

/// `od -An -tx1 -v` of the `PK` variable: the subject naming it a test key, if its
/// certificate carries one.
///
/// Read in the DER as is: an X.509 name is a PrintableString or a UTF8String, its words
/// in clear, and its tag and length just before them — the next element follows at
/// once, so the length is where the subject ends. Binarly's two markers, from the keys
/// PKfail found on ~900 boards (2024).
pub fn parse_platform_key(od: &str) -> Option<String> {
    let bytes: Vec<u8> = od
        .split_whitespace()
        .map(|h| u8::from_str_radix(h, 16))
        .collect::<Result<_, _>>()
        .ok()?;
    ["DO NOT TRUST", "DO NOT SHIP"].iter().find_map(|marker| {
        let at = bytes
            .windows(marker.len())
            .position(|w| w == marker.as_bytes())?;
        // PrintableString (0x13) or UTF8String (0x0c), a short-form length.
        let whole = match bytes.get(at.checked_sub(2)?..at)? {
            [0x13 | 0x0c, len] if *len < 0x80 => bytes.get(at..at + usize::from(*len)),
            _ => None,
        };
        Some(String::from_utf8_lossy(whole.unwrap_or(marker.as_bytes())).into_owned())
    })
}

/// `systemd-detect-virt`'s output and exit status: `none` exits 1.
pub fn parse_virt(out: Option<(&str, bool)>) -> Virt {
    match out.map(|(o, ok)| (o.trim(), ok)) {
        Some(("none", _)) => Virt::BareMetal,
        Some((kind, true)) if !kind.is_empty() => Virt::Virtual(kind.to_string()),
        _ => Virt::Unknown,
    }
}

/// `dkms status`: `zfs/2.1.11, 6.1.0-26-amd64, x86_64: installed`, one line per module,
/// kernel and architecture. Each module once, sorted.
pub fn parse_dkms(out: &str) -> Vec<String> {
    let mut modules: Vec<String> = out
        .lines()
        .filter_map(|l| l.split(['/', ',']).next())
        .map(|m| m.trim().to_string())
        .filter(|m| !m.is_empty())
        .collect();
    modules.sort();
    modules.dedup();
    modules
}

/// `lsblk -nso TYPE` of the root's device: the device, then each one below it.
pub fn parse_root_types(out: &str) -> bool {
    out.lines().any(|l| l.trim() == "crypt")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seal::{Binding, Probe, Sealer};

    fn metal() -> Signals {
        Signals {
            uefi: true,
            secure_boot: Some(true),
            setup_mode: Some(false),
            tpm: Tpm::Seals,
            virt: Virt::BareMetal,
            systemd: Some(257),
            dkms: vec![],
            root_encrypted: Some(false),
            test_platform_key: None,
        }
    }

    #[test]
    fn uefi_secure_boot_a_sealing_tpm_and_systemd_257_reach_a() {
        let a = assess(&metal());
        assert_eq!(a.level, Level::A);
        assert!(a.held_back.is_empty());
    }

    #[test]
    fn debian_12_caps_a_node_at_b_and_says_why() {
        let a = assess(&Signals {
            systemd: Some(252),
            ..metal()
        });
        assert_eq!(a.level, Level::B);
        assert!(a.held_back[0].contains("systemd 252"), "{:?}", a.held_back);
        assert!(a.held_back[0].contains("Debian 13"));
    }

    #[test]
    fn a_boot_that_is_not_verified_is_b_whatever_the_reason() {
        for s in [
            Signals {
                secure_boot: Some(false),
                ..metal()
            },
            Signals {
                secure_boot: None,
                ..metal()
            },
            Signals {
                uefi: false,
                secure_boot: None,
                ..metal()
            },
            Signals {
                systemd: None,
                ..metal()
            },
        ] {
            let a = assess(&s);
            assert_eq!(a.level, Level::B, "{s:?}");
            assert_eq!(a.held_back.len(), 1, "{:?}", a.held_back);
        }
    }

    #[test]
    fn every_reason_keeping_it_from_a_is_said_not_only_the_first() {
        let a = assess(&Signals {
            secure_boot: Some(false),
            systemd: Some(252),
            ..metal()
        });
        assert_eq!(a.held_back.len(), 2, "{:?}", a.held_back);
    }

    #[test]
    fn a_firmware_that_lost_its_keys_is_said_so_not_only_secure_boot_off() {
        // Measured on enc3, its platform key deleted: SecureBoot 0, SetupMode 1.
        let a = assess(&Signals {
            secure_boot: Some(false),
            setup_mode: Some(true),
            ..metal()
        });
        assert_eq!(a.level, Level::B);
        assert_eq!(a.held_back, vec![SETUP_MODE.to_string()]);
    }

    #[test]
    fn a_tpm_that_does_not_seal_is_no_tpm() {
        // 🔴 `hlb secrets-seal` met a TPM answering every probe and sealing nothing: a
        // level resting on `+driver` alone would promise a binding that never comes.
        for tpm in [
            Tpm::Absent,
            Tpm::Version1,
            Tpm::MissingLibraries,
            Tpm::Refuses,
            Tpm::Untried,
            Tpm::NotRoot,
        ] {
            let a = assess(&Signals {
                tpm: tpm.clone(),
                ..metal()
            });
            assert_eq!(a.level, Level::C, "{tpm:?}");
        }
    }

    #[test]
    fn a_virtual_machine_is_d_however_well_its_host_dresses_it() {
        let a = assess(&Signals {
            virt: Virt::Virtual("kvm".into()),
            ..metal()
        });
        assert_eq!(a.level, Level::D);
        assert!(a.held_back[0].contains("kvm"));
    }

    #[test]
    fn a_machine_that_cannot_say_whether_it_is_virtual_is_d() {
        // Never above what was detected: bare metal is a claim, and nothing made it.
        let a = assess(&Signals {
            virt: Virt::Unknown,
            ..metal()
        });
        assert_eq!(a.level, Level::D);
    }

    #[test]
    fn dkms_under_secure_boot_is_warned_and_without_it_is_not() {
        let with = assess(&Signals {
            dkms: vec!["zfs".into()],
            ..metal()
        });
        assert!(with.warnings[0].contains("zfs"));
        let without = assess(&Signals {
            dkms: vec!["zfs".into()],
            secure_boot: Some(false),
            ..metal()
        });
        assert!(without.warnings.is_empty());
    }

    #[test]
    fn a_test_platform_key_is_warned_and_keeps_the_level() {
        // PCR 7 measures PK, KEK and db: the keys rewritten, the TPM opens nothing, so
        // the level holds — but the disk asking for the kit's key is then the attack.
        let a = assess(&Signals {
            test_platform_key: Some("DO NOT TRUST - AMI Test PK".into()),
            ..metal()
        });
        assert_eq!(a.level, Level::A);
        let w = a.warnings.join("\n");
        assert!(
            w.contains("DO NOT TRUST - AMI Test PK") && w.contains("PKfail"),
            "{w}"
        );
        assert!(w.contains("kit"), "says what the attack looks like: {w}");
        assert!(assess(&metal()).warnings.is_empty());
    }

    #[test]
    fn the_platform_keys_test_marker_is_read_from_its_certificate() {
        // `od -An -tx1 -v` of a PK variable as efivarfs gives it: attributes, then an
        // EFI_SIGNATURE_LIST holding an X.509 certificate made like AMI's leaked one.
        let ami = include_str!("../tests/data/pk-ami-test.od");
        assert_eq!(
            parse_platform_key(ami).as_deref(),
            Some("DO NOT TRUST - AMI Test PK")
        );
        // The same variable, its subject and issuer (self-signed) a manufacturer's own.
        let mut own: Vec<String> = ami.split_whitespace().map(String::from).collect();
        let marker: Vec<String> = b"DO NOT TRUST".iter().map(|b| format!("{b:02x}")).collect();
        let mut replaced = 0;
        while let Some(at) = own
            .windows(marker.len())
            .position(|w| w == marker.as_slice())
        {
            for (i, b) in b"GIGABYTE PK ".iter().enumerate() {
                own[at + i] = format!("{b:02x}");
            }
            replaced += 1;
        }
        assert_eq!(replaced, 2, "the fixture holds subject and issuer in clear");
        assert_eq!(parse_platform_key(&own.join(" ")), None);
        assert_eq!(parse_platform_key("not od"), None);
    }

    #[test]
    fn a_weak_machine_is_never_proposed_as_a_manager() {
        use RoleAdvice::*;
        // The count alone: the first manager, then workers, then the third manager.
        assert_eq!(
            advise_role(&[], Level::C),
            Manager,
            "the only manager there is"
        );
        assert_eq!(advise_role(&[Some(Level::A)], Level::A), Worker);
        assert_eq!(
            advise_role(&[Some(Level::A), Some(Level::B)], Level::B),
            Manager
        );
        // A third manager the count asks for, on a machine that gives the Raft log up
        // when taken: both costs, no default.
        for weak in [Level::C, Level::D] {
            match advise_role(&[Some(Level::A), Some(Level::A)], weak) {
                Ask(why) => {
                    assert!(why.contains("quorum") && why.contains("secret"), "{why}");
                    assert!(why.contains("--role manager") && why.contains("--role worker"));
                }
                other => panic!("{weak:?}: {other:?}"),
            }
        }
    }

    #[test]
    fn a_manager_below_the_best_is_warned() {
        let managers = [Some(Level::A), None];
        let w = manager_warning(&managers, Level::B).expect("below the best");
        assert!(w.contains("level B") && w.contains("A"), "{w}");
        assert!(manager_warning(&managers, Level::A).is_none());
        let w = manager_warning(&[], Level::D).expect("a weak manager, alone");
        assert!(w.contains("secret"), "{w}");
        // Nothing read is nothing to compare with.
        assert!(manager_warning(&[None], Level::B).is_none());
    }

    #[test]
    fn a_manager_a_better_node_could_replace_is_said() {
        let nodes = [
            ("deb1", true, Some(Level::B)),
            ("enc3", false, Some(Level::A)),
            ("vm1", true, Some(Level::D)),
            ("old", true, None),
        ];
        let said = weak_managers(&nodes);
        assert_eq!(said.len(), 2, "{said:#?}");
        assert!(
            said[0].starts_with("deb1") && said[0].contains("enc3"),
            "{}",
            said[0]
        );
        assert!(
            said[1].starts_with("vm1") && said[1].contains("secret"),
            "{}",
            said[1]
        );
        // The best there is: nothing to say.
        assert!(
            weak_managers(&[("deb1", true, Some(Level::B)), ("w", false, Some(Level::B))])
                .is_empty()
        );
    }

    #[test]
    fn the_levels_order_best_first_and_round_trip_through_the_label() {
        assert!(Level::A < Level::B && Level::B < Level::C && Level::C < Level::D);
        for l in [Level::A, Level::B, Level::C, Level::D] {
            assert_eq!(Level::parse(l.as_str()), Some(l));
        }
        assert_eq!(Level::parse("a"), None);
    }

    #[test]
    fn the_tpm_is_read_from_the_driver_then_the_trials() {
        let sealed = Probe::Sealer(Sealer::HostAndTpm(Binding::Pcr7));
        assert_eq!(
            tpm(true, Some("+driver\n"), Some(&sealed), None),
            Tpm::Seals
        );
        assert_eq!(
            tpm(
                true,
                Some("+driver\n"),
                Some(&Probe::MissingLibraries),
                None
            ),
            Tpm::MissingLibraries
        );
        assert_eq!(
            tpm(
                true,
                Some("+driver\n"),
                Some(&Probe::Sealer(Sealer::HostOnly)),
                None
            ),
            Tpm::Refuses
        );
        assert_eq!(
            tpm(true, Some("-driver\n"), None, Some("1\n")),
            Tpm::Version1
        );
        assert_eq!(tpm(true, Some("-driver\n"), None, None), Tpm::Absent);
        assert_eq!(tpm(true, None, None, Some("2")), Tpm::Untried);
        assert_eq!(tpm(false, Some("+driver\n"), None, None), Tpm::NotRoot);
        // `has-tpm2` reads the driver unprivileged: no TPM is said as no TPM.
        assert_eq!(tpm(false, Some("-driver\n"), None, None), Tpm::Absent);
    }

    #[test]
    fn systemd_s_version_is_its_second_word() {
        assert_eq!(
            parse_systemd_version("systemd 252 (252.39-1~deb12u1)\n+PAM +AUDIT"),
            Some(252)
        );
        assert_eq!(parse_systemd_version("systemd 257 (257.8-1)"), Some(257));
        assert_eq!(parse_systemd_version("bash: systemctl: not found"), None);
        assert_eq!(parse_systemd_version(""), None);
    }

    #[test]
    fn secure_boot_is_the_byte_after_the_attributes() {
        assert_eq!(parse_secure_boot("   6   0   0   0   1\n"), Some(true));
        assert_eq!(parse_secure_boot("   6   0   0   0   0\n"), Some(false));
        assert_eq!(parse_secure_boot(""), None);
        assert_eq!(parse_secure_boot("od: cannot open"), None);
    }

    #[test]
    fn detect_virt_says_none_on_bare_metal_with_a_failing_status() {
        assert_eq!(parse_virt(Some(("none\n", false))), Virt::BareMetal);
        assert_eq!(
            parse_virt(Some(("kvm\n", true))),
            Virt::Virtual("kvm".into())
        );
        assert_eq!(parse_virt(Some(("", false))), Virt::Unknown);
        assert_eq!(parse_virt(None), Virt::Unknown);
    }

    #[test]
    fn dkms_modules_are_named_once_each() {
        let out = "zfs/2.1.11, 6.1.0-26-amd64, x86_64: installed\n\
                   zfs/2.1.11, 6.1.0-25-amd64, x86_64: installed\n\
                   nvidia/535.54, 6.1.0-26-amd64, x86_64: installed\n";
        assert_eq!(parse_dkms(out), vec!["nvidia", "zfs"]);
        // DKMS 2's older shape puts a comma where 3 puts a slash.
        assert_eq!(
            parse_dkms("zfs, 2.0.3, 5.10.0-8-amd64, x86_64: installed"),
            vec!["zfs"]
        );
        assert!(parse_dkms("").is_empty());
    }

    #[test]
    fn the_root_is_encrypted_when_a_crypt_device_is_below_it() {
        assert!(parse_root_types("lvm\ncrypt\npart\ndisk\n"));
        assert!(!parse_root_types("part\ndisk\n"));
    }
}
