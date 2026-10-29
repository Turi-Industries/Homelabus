//! Level A: a verified boot, the disk sealed to it AND to a Tang of the house.
//!
//! shim boots a kernel image (UKI) signed by a key of the node's own — a MOK, enrolled
//! once at the console — and the disk's Clevis binding is the one `disk` writes with the
//! TPM half bound to PCR 7 and to the PCR 11 that image will produce, predicted by
//! `systemd-measure`. A kernel, an initrd or a command line nobody sealed opens nothing:
//! the boot waits for the kit's key, Tang answering or not.
//!
//! ## Why Clevis with predicted PCRs, and not systemd's signed policy
//!
//! A LUKS slot opens the disk alone, so the TPM and the Tang must sit in ONE slot, and
//! only Clevis has Tang; its `tpm2` pin binds PCR values as literals. Measured on the lab
//! (2026-10-29) against `systemd-cryptenroll` with a signed policy: that needs dracut,
//! which drops `dropbear-initramfs`, and either a PIN at every boot or Tang moved out of
//! the disk's way. The cost of this one: every initrd, kernel or command line is resealed
//! before the next reboot — [`TOOL`], run by [`HOOK`] after every `update-initramfs`.
//!
//! ## 🔴 The reseal cannot go through the binding it replaces
//!
//! The booted system's PCR 11 is past the initrd's ([`barrier`]), and the volume key is a
//! `logon` key root cannot read. A third slot opens the disk for the reseal: a key file
//! on the encrypted root ([`RESEAL_KEY`]), counted by `bind-disk` beside the binding and
//! the recovery key.
//!
//! ## 🔴 PCR 7 differs between GRUB's boot and the UKI's
//!
//! It records which certificate verified the second stage: Debian's for GRUB, the MOK
//! for the UKI. Read from a GRUB boot it binds a value the UKI never sees, so it is read
//! only from a UKI boot (`StubInfo` set) and kept ([`PCR7`]) for the reseals that run
//! from GRUB. Moving a node from B to A therefore costs ONE boot opened by the kit's key.
//!
//! ## 🔴 initramfs-tools leaves two holes, closed here
//!
//! The class of CVE-2026-32606: a root swapped in by whoever holds the machine, run while
//! the PCRs still read the initrd's. Nothing extends PCR 11 on leaving the initrd — the
//! [`barrier`] does, or panics —, and its `panic` drops to a root shell AFTER the disk is
//! open: `panic=10` on the signed command line reboots instead. Both measured on the lab.

use serde_json::{json, Value};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::disk::{Disk, Tang, STAGED_RECOVERY};
use crate::distro::PackageManager;
use crate::provision::{Action, Phase, Step};

/// What builds, signs and predicts the UKI, and boots it.
pub const PACKAGES: [&str; 9] = [
    "systemd-ukify",
    "systemd-boot-efi",
    "sbsigntool",
    "python3-pefile",
    "efibootmgr",
    "mokutil",
    "shim-signed",
    "tpm2-tools",
    "openssl",
];
/// Root's alone: the MOK's private key signs whatever this node will boot.
pub const DIR: &str = "/var/lib/hlb/boot";
pub const MOK_KEY: &str = "/var/lib/hlb/boot/mok.key";
pub const MOK_CERT: &str = "/var/lib/hlb/boot/mok.crt";
pub const MOK_DER: &str = "/var/lib/hlb/boot/mok.der";
pub const RESEAL_KEY: &str = "/var/lib/hlb/boot/reseal.key";
/// The binding's policy, its PCR digest left as [`DIGEST_PLACEHOLDER`]. Its presence is
/// what marks a node at level A for `bind-disk`.
pub const POLICY: &str = "/var/lib/hlb/boot/policy.json";
pub const CMDLINE: &str = "/var/lib/hlb/boot/cmdline";
/// PCR 7 as the last UKI boot read it.
pub const PCR7: &str = "/var/lib/hlb/boot/pcr7";
/// What the disk is sealed to now: PCR 7, PCR 11, the policy's hash.
pub const SEALED: &str = "/var/lib/hlb/boot/sealed";
/// Left by [`HOOK`] when a reseal failed: the next boot waits for the kit's key.
pub const RESEAL_FAILED: &str = "/var/lib/hlb/boot/reseal-failed";
pub const DIGEST_PLACEHOLDER: &str = "@PCR_DIGEST@";
pub const TOOL: &str = "/usr/local/sbin/hlb-uki";
pub const HOOK: &str = "/etc/initramfs/post-update.d/zz-hlb-uki";
pub const BARRIER: &str = "/etc/initramfs-tools/scripts/init-bottom/hlb-pcr-barrier";
pub const BARRIER_HOOK: &str = "/etc/initramfs-tools/hooks/hlb-pcr-barrier";
/// shim loads `grubx64.efi` from its own directory: the UKI is named so, beside a copy.
pub const ESP_DIR: &str = "/boot/efi/EFI/hlb";
pub const SHIM: &str = "/usr/lib/shim/shimx64.efi.signed";
pub const MOK_MANAGER: &str = "/usr/lib/shim/mmx64.efi.signed";
pub const ENTRY_LABEL: &str = "hlb-uki";
/// Set by systemd-stub: the running system was booted by a UKI.
pub const STUB_INFO: &str =
    "/sys/firmware/efi/efivars/StubInfo-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f";
/// The MOK's one-time enrolment password and its hash, in memory while `mokutil` reads.
pub const STAGED_MOK_PASSWORD: &str = "/run/hlb-mok-password";
pub const STAGED_MOK_HASH: &str = "/run/hlb-mok-hash";
/// What MokManager is told the password is: typed at a console whose keyboard may be
/// AZERTY while the firmware reads QWERTY — so no a, q, z, w, m, and no digit (shifted
/// on AZERTY). 21 letters, 16 of them: 70 bits, for a password used once, at the console.
const MOK_ALPHABET: &[u8] = b"bcdefghijklnoprstuvxy";
pub const MOK_PASSWORD_LEN: usize = 16;

/// Whether the node's boot key is known to shim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mok {
    NotEnrolled,
    /// Imported, waiting for a person at the console at the next boot.
    Pending,
    Enrolled,
}

/// `mokutil --test-key`'s verdict, from its words — its exit status says 1 for
/// "already enrolled" (measured, mokutil 0.7.2).
pub fn parse_mok(test_key: &str) -> Option<Mok> {
    if test_key.contains("is already enrolled") {
        Some(Mok::Enrolled)
    } else if test_key.contains("is already in the enrollment request") {
        Some(Mok::Pending)
    } else if test_key.contains("is not enrolled") {
        Some(Mok::NotEnrolled)
    } else {
        None
    }
}

/// Where a node stands on the way to level A, read from it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    /// No boot key shim knows: make one, ask shim to enrol it.
    Key,
    /// Enrolment asked, nobody at the console yet.
    Enrolment,
    /// Enrolled, booted by GRUB: install the UKI and its reseal, boot it once.
    Setup,
    /// Booted by the UKI: seal to the PCRs it produced, and boot it first.
    Seal,
}

/// `mok` is `None` while the node has no boot key.
pub fn stage(mok: Option<Mok>, uki_booted: bool) -> Stage {
    match mok {
        None | Some(Mok::NotEnrolled) => Stage::Key,
        Some(Mok::Pending) => Stage::Enrolment,
        Some(Mok::Enrolled) if uki_booted => Stage::Seal,
        Some(Mok::Enrolled) => Stage::Setup,
    }
}

/// A one-time enrolment password drawn from `random`, which must hold enough bytes:
/// each byte past the alphabet's last whole multiple is drawn again, so no letter is
/// likelier than another. `None` when `random` ran out.
pub fn enrolment_password(random: &[u8]) -> Option<String> {
    let n = MOK_ALPHABET.len();
    let limit = 256 - 256 % n;
    let password: String = random
        .iter()
        .filter(|b| usize::from(**b) < limit)
        .take(MOK_PASSWORD_LEN)
        .map(|b| char::from(MOK_ALPHABET[usize::from(*b) % n]))
        .collect();
    (password.len() == MOK_PASSWORD_LEN).then_some(password)
}

/// Why the disk cannot be sealed as level A, or `None`. Only what `bind-disk` leaves may
/// be there: its binding — to the TPM AND a Tang —, the recovery key, and the reseal key.
pub fn refusal(disk: &Disk) -> Option<String> {
    if let Some(b) = disk.bindings.iter().find(|b| b.tangs.is_none()) {
        return Some(format!(
            "slot {} holds a Clevis binding Homelabus did not make — run `hlb node \
             bind-disk` first, which says what to do with it",
            b.slot
        ));
    }
    if !disk.bindings.iter().any(|b| b.tangs.is_some()) {
        return Some(
            "the disk is not bound to its TPM AND a Tang yet: `hlb node bind-disk` first — \
             level A seals that binding to the boot"
                .into(),
        );
    }
    let known = disk.bindings.len() + 2;
    (disk.keyslots > known).then(|| {
        format!(
            "{} holds {} key slots, of which Homelabus knows at most {known}: a key it does \
             not know opens the disk alone, whatever the boot",
            disk.device, disk.keyslots
        )
    })
}

/// The command line the UKI carries, from the one GRUB booted with: what only a boot
/// loader passes goes, so does whatever opens a shell, and `panic=10` reboots where
/// initramfs-tools would drop to one — after the disk is open.
pub fn cmdline(booted: &str) -> String {
    const DROPPED: [&str; 14] = [
        "BOOT_IMAGE",
        "initrd",
        "panic",
        "break",
        "init",
        "rdinit",
        "single",
        "emergency",
        "rescue",
        "rd.break",
        "rd.shell",
        "rd.emergency",
        "systemd.unit",
        "systemd.debug_shell",
    ];
    let mut words: Vec<&str> = booted
        .split_whitespace()
        .filter(|w| !DROPPED.contains(&w.split('=').next().unwrap_or(w)))
        .collect();
    words.push("panic=10");
    words.join(" ")
}

/// Where Tang `i`'s advertisement is kept: a reseal then needs no Tang to answer.
pub fn adv_path(i: usize) -> String {
    format!("{DIR}/tang-{i}.jws")
}

/// The binding's policy: `disk::policy`'s nesting, its TPM half on PCR 7 and 11 at the
/// values [`TOOL`] writes in, each Tang pinned by its thumbprint AND read from its saved
/// advertisement — Clevis refuses one the pinned key did not sign.
pub fn policy(tangs: &[Tang]) -> String {
    let tang: Vec<Value> = tangs
        .iter()
        .enumerate()
        .map(|(i, t)| json!({ "url": t.url, "thp": t.thp, "adv": adv_path(i) }))
        .collect();
    json!({
        "t": 2,
        "pins": {
            "tpm2": { "pcr_bank": "sha256", "pcr_ids": "7,11", "pcr_digest": DIGEST_PLACEHOLDER },
            "sss": { "t": 1, "pins": { "tang": tang } },
        },
    })
    .to_string()
}

/// The Tangs' advertisements saved, then the policy naming them.
pub fn policy_steps(tangs: &[Tang]) -> Vec<Step> {
    let mut steps: Vec<Step> = tangs
        .iter()
        .enumerate()
        .map(|(i, t)| Step {
            phase: Phase::Configuration,
            what: format!("keep the advertisement of {}", t.url),
            action: Action::Run(argv(&[
                "sh",
                "-c",
                "curl -sf \"$1/adv\" -o \"$2.new\" && mv -f \"$2.new\" \"$2\"",
                "sh",
                &t.url,
                &adv_path(i),
            ])),
        })
        .collect();
    steps.push(install(
        "the binding's policy: PCR 7 and 11, AND a Tang",
        POLICY,
        &policy(tangs),
        0o600,
    ));
    steps
}

fn argv(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

fn run(phase: Phase, what: &str, v: &[&str]) -> Step {
    Step {
        phase,
        what: what.to_string(),
        action: Action::Run(argv(v)),
    }
}

fn install(what: &str, path: &str, content: &str, mode: u32) -> Step {
    Step {
        phase: Phase::Configuration,
        what: what.to_string(),
        action: Action::Install {
            path: path.to_string(),
            content: content.to_string(),
            mode,
        },
    }
}

fn private_dir() -> Step {
    run(
        Phase::Configuration,
        "its directory, root's alone",
        &["install", "-d", "-m", "700", DIR],
    )
}

/// Stage [`Stage::Key`]: a MOK made on the node, imported under the password staged at
/// [`STAGED_MOK_PASSWORD`], which the caller removes afterwards.
pub fn key_steps(node: &str) -> Vec<Step> {
    // The key last: present, the certificate is too.
    const MAKE: &str = "cd /var/lib/hlb/boot && [ -s mok.key ] || { \
openssl req -new -x509 -newkey rsa:2048 -nodes -days 36500 -subj \"/CN=Homelabus boot key of $1/\" \
-keyout mok.key.new -out mok.crt && mv -f mok.key.new mok.key; }";
    vec![
        run(
            Phase::Packages,
            "refresh the package index",
            &["apt-get", "update"],
        ),
        Step {
            phase: Phase::Packages,
            what: "the tools that sign, predict and boot".into(),
            action: Action::Run(PackageManager::Apt.install_command(&PACKAGES)),
        },
        private_dir(),
        run(
            Phase::Configuration,
            "its boot key (MOK), made here",
            &["sh", "-c", MAKE, "sh", node],
        ),
        run(
            Phase::Configuration,
            "the key as shim reads it",
            &[
                "openssl", "x509", "-in", MOK_CERT, "-outform", "DER", "-out", MOK_DER,
            ],
        ),
        run(
            Phase::Configuration,
            "the enrolment password, hashed",
            &[
                "sh",
                "-c",
                "umask 077; openssl passwd -6 -stdin < \"$1\" > \"$2\"",
                "sh",
                STAGED_MOK_PASSWORD,
                STAGED_MOK_HASH,
            ],
        ),
        run(
            Phase::Services,
            "ask shim to enrol it at the next boot",
            &[
                "mokutil",
                "--import",
                MOK_DER,
                "--hash-file",
                STAGED_MOK_HASH,
            ],
        ),
    ]
}

/// Stage [`Stage::Setup`]: everything that builds and reseals the UKI, the reseal key's
/// slot (through the kit's key staged at `STAGED_RECOVERY`), the first UKI, and the UKI
/// booted once at the next boot. `booted` is `/proc/cmdline`.
pub fn setup_steps(device: &str, tangs: &[Tang], booted: &str) -> Vec<Step> {
    const RESEAL_SLOT: &str = "umask 077; k=/var/lib/hlb/boot/reseal.key; \
[ -s \"$k\" ] || { head -c 64 /dev/urandom > \"$k.new\" && mv -f \"$k.new\" \"$k\"; }; \
cryptsetup open --test-passphrase --key-file \"$k\" \"$1\" 2>/dev/null || \
cryptsetup luksAddKey --key-file \"$2\" \"$1\" \"$k\"";
    const SHIM_COPY: &str = "mkdir -p \"$1\" && cp \"$2\" \"$1/shimx64.efi\" && \
cp \"$3\" \"$1/mmx64.efi\"";
    // 2: installed and not sealed, which is this stage's point when no PCR 7 is kept.
    const FIRST_UKI: &str = "/usr/local/sbin/hlb-uki; s=$?; [ $s -eq 0 ] || [ $s -eq 2 ]";
    let mut steps = vec![
        run(
            Phase::Packages,
            "refresh the package index",
            &["apt-get", "update"],
        ),
        Step {
            phase: Phase::Packages,
            what: "the tools that sign, predict and boot".into(),
            action: Action::Run(PackageManager::Apt.install_command(&PACKAGES)),
        },
        private_dir(),
        install("the UKI's command line", CMDLINE, &cmdline(booted), 0o600),
    ];
    steps.extend(policy_steps(tangs));
    steps.extend([
        run(
            Phase::Configuration,
            "a key the reseal opens the disk with, in a slot of its own",
            &["sh", "-c", RESEAL_SLOT, "sh", device, STAGED_RECOVERY],
        ),
        install(
            "the UKI built, signed and resealed",
            TOOL,
            &tool(device),
            0o755,
        ),
        install("resealed after every initrd", HOOK, HOOK_CONTENT, 0o755),
        install(
            "PCR 11 extended on leaving the initrd",
            BARRIER,
            &barrier(),
            0o755,
        ),
        install(
            "the barrier's tool, in the initrd",
            BARRIER_HOOK,
            BARRIER_HOOK_CONTENT,
            0o755,
        ),
        run(
            Phase::Configuration,
            "shim and MokManager, beside the UKI",
            &["sh", "-c", SHIM_COPY, "sh", ESP_DIR, SHIM, MOK_MANAGER],
        ),
        run(
            Phase::Configuration,
            "rebuild the initrd, with the barrier",
            &["update-initramfs", "-u"],
        ),
        run(
            Phase::Services,
            "build and install the UKI",
            &["sh", "-c", FIRST_UKI],
        ),
        run(
            Phase::Services,
            "boot it once, at the next boot",
            &[TOOL, "entry", "next"],
        ),
    ]);
    steps
}

/// Stage [`Stage::Seal`]: the tools refreshed, the disk sealed to the PCRs this boot
/// produced, the UKI first in the boot order.
pub fn seal_steps(device: &str) -> Vec<Step> {
    vec![
        install(
            "the UKI built, signed and resealed",
            TOOL,
            &tool(device),
            0o755,
        ),
        install("resealed after every initrd", HOOK, HOOK_CONTENT, 0o755),
        run(Phase::Services, "seal the disk to this boot", &[TOOL]),
        run(
            Phase::Services,
            "boot the UKI first, always",
            &[TOOL, "entry", "first"],
        ),
    ]
}

/// The string `systemd-pcrphase` extends PCR 11 with when the initrd hands over.
const LEAVE_INITRD: &str = "leave-initrd";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The `init-bottom` script that extends PCR 11 as systemd's initrd would, before the
/// root runs — or panics, which `panic=10` turns into a reboot. Its digests are written
/// in: the initrd has `sha256sum` and no `sha384sum` (the first try failed on it).
pub fn barrier() -> String {
    let w = LEAVE_INITRD.as_bytes();
    format!(
        "#!/bin/sh
# Written by Homelabus: a root started with the PCRs the disk was sealed to could unseal
# it again — one swapped in by whoever holds the machine included.
PREREQ=\"\"
prereqs() {{ echo \"$PREREQ\"; }}
case $1 in prereqs) prereqs; exit 0 ;; esac
. /scripts/functions
TPM2TOOLS_TCTI=device:/dev/tpmrm0 tpm2_pcrextend \\
  11:sha1={},sha256={},sha384={},sha512={} \\
  || panic \"PCR 11 barrier failed: refusing to start the root with the initrd's PCRs\"
",
        hex(&Sha1::digest(w)),
        hex(&Sha256::digest(w)),
        hex(&Sha384::digest(w)),
        hex(&Sha512::digest(w)),
    )
}

const BARRIER_HOOK_CONTENT: &str = "#!/bin/sh
# Written by Homelabus: the PCR barrier's tool, in the initrd.
PREREQ=\"\"
prereqs() { echo \"$PREREQ\"; }
case $1 in prereqs) prereqs; exit 0 ;; esac
. /usr/share/initramfs-tools/hook-functions
copy_exec /usr/bin/tpm2
ln -sf tpm2 \"$DESTDIR/usr/bin/tpm2_pcrextend\"
";

/// 🔴 Never fails: `update-initramfs` runs under dpkg, and a failed hook would leave a
/// kernel package half-configured. A failed reseal is loud instead — said on the
/// terminal, and left as [`RESEAL_FAILED`] for `verify-boot` to read.
const HOOK_CONTENT: &str = "#!/bin/sh
# Written by Homelabus: every new initrd is a new PCR 11 — resealed before the next boot,
# or that boot waits for the kit's recovery key.
newest=$(ls /boot/vmlinuz-* 2>/dev/null | sed 's|^/boot/vmlinuz-||' | sort -V | tail -n 1)
# Only the newest kernel is in the UKI; an older one's initrd changes nothing.
[ -n \"${1:-}\" ] && [ \"$1\" != \"$newest\" ] && exit 0
if ! /usr/local/sbin/hlb-uki >&2; then
  : > /var/lib/hlb/boot/reseal-failed
  echo \"hlb-uki: NOT RESEALED - the next boot runs the image of before, or waits for the kit's recovery key (ssh -p 2222).\" >&2
  echo \"hlb-uki: run /usr/local/sbin/hlb-uki by hand before rebooting.\" >&2
fi
exit 0
";

/// `hlb-uki`: builds the newest kernel's UKI, predicts its PCR 11, seals the disk to it
/// through [`RESEAL_KEY`], installs it, then removes the binding it replaced.
pub fn tool(device: &str) -> String {
    TOOL_TEMPLATE
        .replace("@DIR@", DIR)
        .replace("@DEVICE@", device)
        .replace("@ESP@", ESP_DIR)
        .replace("@LABEL@", ENTRY_LABEL)
        .replace("@STUB_INFO@", STUB_INFO)
        .replace("@REBIND@", crate::disk::REBIND.trim_end())
}

const TOOL_TEMPLATE: &str = r#"#!/bin/bash
# Written by Homelabus (`hlb node verify-boot`): the newest kernel's signed image (UKI),
# and the disk sealed to the PCRs it will boot with, AND a Tang.
#   hlb-uki: build, seal, install — nothing when already sealed to it.
#   hlb-uki entry next: boot the UKI once, at the next boot.
#   hlb-uki entry first: boot the UKI first, always.
# Exit 0: sealed. 2: installed but NOT sealed — no PCR 7 read from a UKI boot yet, so
# the next boot waits for the kit's key. 1: anything else.
set -euo pipefail
umask 077
dir=@DIR@
dev=@DEVICE@
esp=@ESP@
label=@LABEL@

entry_number() {
  efibootmgr | sed -n "s/^Boot\([0-9A-Fa-f]\{4\}\)[* ] $label\([[:space:]].*\)\{0,1\}\$/\1/p" | head -n 1
}

entry() {
  local n src disk part order
  n=$(entry_number)
  if [ -z "$n" ]; then
    src=$(findmnt -no SOURCE /boot/efi)
    disk=/dev/$(lsblk -no PKNAME "$src")
    part=$(cat "/sys/class/block/$(basename "$src")/partition")
    order=$(efibootmgr | sed -n 's/^BootOrder: //p')
    efibootmgr -q -c -d "$disk" -p "$part" -L "$label" -l '\EFI\hlb\shimx64.efi'
    # `-c` puts it first: the order of before stays until the UKI has opened the disk.
    if [ -n "$order" ]; then efibootmgr -q -o "$order"; fi
    n=$(entry_number)
  fi
  [ -n "$n" ] || { echo "hlb-uki: no boot entry $label" >&2; exit 1; }
  case $1 in
    # One-shot: a UKI that does not come up leaves the next reset to the order of before.
    next) efibootmgr -q -n "$n" ;;
    first)
      order=$(efibootmgr | sed -n 's/^BootOrder: //p')
      efibootmgr -q -o "$n$(printf ',%s' "$order" | sed "s/,$n//g; s/^,\$//")" ;;
    *) echo "hlb-uki entry next|first" >&2; exit 1 ;;
  esac
}

if [ "${1:-}" = entry ]; then
  entry "${2:-}"
  exit 0
fi

k=$(ls /boot/vmlinuz-* 2>/dev/null | sed 's|^/boot/vmlinuz-||' | sort -V | tail -n 1)
if [ -z "$k" ] || [ ! -f "/boot/initrd.img-$k" ]; then
  echo "hlb-uki: no kernel with its initrd in /boot" >&2
  exit 1
fi
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

ukify build --linux="/boot/vmlinuz-$k" --initrd="/boot/initrd.img-$k" \
  --cmdline="$(cat "$dir/cmdline")" --os-release=@/etc/os-release --uname="$k" \
  --secureboot-private-key="$dir/mok.key" --secureboot-certificate="$dir/mok.crt" \
  --output="$work/uki.efi" >/dev/null
sbverify --cert "$dir/mok.crt" "$work/uki.efi" >/dev/null 2>&1

python3 - "$work" <<'PY'
import sys, pefile
w = sys.argv[1]
for s in pefile.PE(w + "/uki.efi").sections:
    name = s.Name.rstrip(b"\0").decode()
    if name in (".linux", ".osrel", ".cmdline", ".initrd", ".ucode", ".splash", ".dtb",
                ".uname", ".sbat", ".pcrpkey"):
        # What the stub measures: the section's virtual size, not its padded raw data.
        open(w + "/" + name[1:], "wb").write(s.get_data()[: s.Misc_VirtualSize])
PY
args=()
for s in linux osrel cmdline initrd ucode splash dtb uname sbat pcrpkey; do
  if [ -f "$work/$s" ]; then args+=("--$s=$work/$s"); fi
done
# No phase: initramfs-tools extends none, so the initrd sees PCR 11 as the stub left it.
p11=$(/usr/lib/systemd/systemd-measure calculate "${args[@]}" --phase= --bank=sha256 \
  | sed -n 's/^11:sha256=//p')
if [ -z "$p11" ]; then
  echo "hlb-uki: systemd-measure predicted no PCR 11" >&2
  exit 1
fi

install_uki() {
  mkdir -p "$esp"
  cp "$work/uki.efi" "$esp/grubx64.efi.new"
  sync -f "$esp/grubx64.efi.new"
  mv -f "$esp/grubx64.efi.new" "$esp/grubx64.efi"
  sync -f "$esp/grubx64.efi"
}

p7=
if [ -e @STUB_INFO@ ]; then
  # Booted by the UKI: the PCR 7 its next boot sees too. GRUB's would never match.
  p7=$(tpm2_pcrread sha256:7 | sed -n 's/^ *7 *: *0x//p')
  if [ -z "$p7" ]; then
    echo "hlb-uki: PCR 7 cannot be read" >&2
    exit 1
  fi
  printf '%s\n' "$p7" > "$dir/pcr7.new"
  mv -f "$dir/pcr7.new" "$dir/pcr7"
elif [ -s "$dir/pcr7" ]; then
  p7=$(cat "$dir/pcr7")
fi
if [ -z "$p7" ]; then
  install_uki
  echo "hlb-uki: the UKI of $k is installed and NOT sealed: PCR 7 is read from a boot" >&2
  echo "hlb-uki: through it only. That boot waits for the kit's key (ssh -p 2222)." >&2
  exit 2
fi

want="$p7 $p11 $(sha256sum < "$dir/policy.json" | cut -d ' ' -f 1)"
if [ "$(cat "$dir/sealed" 2>/dev/null || true)" = "$want" ]; then
  rm -f "$dir/reseal-failed"
  echo "hlb-uki: $k is sealed already"
  exit 0
fi

digest=$(python3 -c 'import base64, sys
print(base64.urlsafe_b64encode(bytes.fromhex(sys.argv[1] + sys.argv[2])).decode().rstrip("="))' \
  "$p7" "$p11")
old=$(clevis luks list -d "$dev" | cut -d : -f 1 || true)
cat > "$work/rebind" <<'REBIND'
@REBIND@
REBIND
# The binding first, then the image it opens: a failed rebind leaves the image and the
# binding of before, which still open each other. Cut short between the two, the next
# boot waits for the kit's key — two bindings do not fit the header side by side.
sh "$work/rebind" "$dev" "$dir/reseal.key" \
  "$(sed "s/@PCR_DIGEST@/$digest/" "$dir/policy.json")" $old
install_uki
printf '%s\n' "$want" > "$dir/sealed.new"
mv -f "$dir/sealed.new" "$dir/sealed"
rm -f "$dir/reseal-failed"
echo "hlb-uki: $k sealed — PCR 7 and the predicted PCR 11, AND a Tang"
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disk::Binding;

    fn tangs() -> Vec<Tang> {
        vec![
            Tang {
                url: "http://10.77.0.11:7500".into(),
                thp: "thp-a".into(),
            },
            Tang {
                url: "http://10.77.0.12:7500".into(),
                thp: "thp-b".into(),
            },
        ]
    }

    fn bound(keyslots: usize) -> Disk {
        Disk {
            device: "/dev/disk/by-uuid/05388f4a".into(),
            keyslots,
            bindings: vec![Binding {
                slot: 1,
                tangs: Some(tangs()),
            }],
            verified: false,
        }
    }

    fn whats(steps: &[Step]) -> Vec<&str> {
        steps.iter().map(|s| s.what.as_str()).collect()
    }

    /// `sh -n`/`bash -n`: a script that does not parse fails at boot or under dpkg,
    /// where nobody reads it.
    fn parses(shell: &str, script: &str) {
        use std::io::Write;
        let mut child = std::process::Command::new(shell)
            .arg("-n")
            .stdin(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("a shell");
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(script.as_bytes())
            .expect("written");
        let out = child.wait_with_output().expect("ran");
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    #[test]
    fn the_generated_scripts_parse() {
        parses("bash", &tool("/dev/vda3"));
        parses("sh", HOOK_CONTENT);
        parses("sh", crate::disk::REBIND);
        parses("sh", &barrier());
        parses("sh", BARRIER_HOOK_CONTENT);
        for step in setup_steps("/dev/vda3", &tangs(), "root=/x ro")
            .iter()
            .chain(&key_steps("enc3"))
        {
            if let Action::Run(argv) = &step.action {
                if argv[0] == "sh" && argv[1] == "-c" {
                    parses("sh", &argv[2]);
                }
            }
        }
    }

    #[test]
    fn the_barrier_extends_what_systemd_s_initrd_would() {
        // The digests measured on enc3: PCR 11 after boot equalled the prediction of
        // `leave-initrd:sysinit:ready` exactly.
        let b = barrier();
        assert!(
            b.contains("sha256=3be261aff7db92bf507eae947f4003ffa2bcad0bffe3524601d62d0bc8be7135")
        );
        assert!(b.contains("sha1=865e1ff2cc5b8db815313b23fe3d8b561212f5d1"));
        assert!(b.contains("|| panic"), "{b}");
    }

    #[test]
    fn the_tool_names_this_disk_and_leaves_no_placeholder_but_the_digest() {
        let t = tool("/dev/disk/by-uuid/05388f4a");
        assert!(t.contains("dev=/dev/disk/by-uuid/05388f4a\n"));
        for p in [
            "@DIR@",
            "@DEVICE@",
            "@ESP@",
            "@LABEL@",
            "@STUB_INFO@",
            "@REBIND@",
        ] {
            assert!(!t.contains(p), "{p} left in");
        }
        // The one placeholder left is the policy's, which the tool fills itself.
        assert!(t.contains(&format!("s/{DIGEST_PLACEHOLDER}/$digest/")));
        assert!(t.contains(STUB_INFO) && t.contains(ESP_DIR));
    }

    #[test]
    fn the_policy_binds_pcr_7_and_11_and_pins_each_tang_with_its_saved_advertisement() {
        let p: Value = serde_json::from_str(&policy(&tangs())).expect("JSON");
        assert_eq!(p["t"], 2);
        assert_eq!(p["pins"]["tpm2"]["pcr_ids"], "7,11");
        assert_eq!(p["pins"]["tpm2"]["pcr_digest"], DIGEST_PLACEHOLDER);
        assert_eq!(p["pins"]["sss"]["t"], 1);
        let second = &p["pins"]["sss"]["pins"]["tang"][1];
        assert_eq!(second["thp"], "thp-b");
        assert_eq!(second["adv"], adv_path(1));
    }

    #[test]
    fn the_command_line_keeps_the_root_and_drops_every_shell() {
        assert_eq!(
            cmdline("BOOT_IMAGE=/vmlinuz-6.12.113+deb13-amd64 root=/dev/mapper/enc3--vg-root ro console=ttyS0,115200n8 quiet"),
            "root=/dev/mapper/enc3--vg-root ro console=ttyS0,115200n8 quiet panic=10"
        );
        assert_eq!(
            cmdline("root=/dev/x ro break=premount init=/bin/sh panic=0 rd.break single"),
            "root=/dev/x ro panic=10"
        );
    }

    #[test]
    fn the_stages_follow_the_key_then_the_boot() {
        assert_eq!(stage(None, false), Stage::Key);
        assert_eq!(stage(Some(Mok::NotEnrolled), false), Stage::Key);
        assert_eq!(stage(Some(Mok::Pending), false), Stage::Enrolment);
        assert_eq!(stage(Some(Mok::Enrolled), false), Stage::Setup);
        assert_eq!(stage(Some(Mok::Enrolled), true), Stage::Seal);
    }

    #[test]
    fn mokutil_is_read_by_its_words() {
        // Its three answers, measured on enc3.
        assert_eq!(
            parse_mok("/root/mok/mok.der is already enrolled\n"),
            Some(Mok::Enrolled)
        );
        assert_eq!(
            parse_mok("t.der is already in the enrollment request\n"),
            Some(Mok::Pending)
        );
        assert_eq!(parse_mok("t.der is not enrolled\n"), Some(Mok::NotEnrolled));
        assert_eq!(parse_mok("EFI variables are not supported"), None);
    }

    #[test]
    fn the_enrolment_password_types_the_same_on_azerty_and_qwerty() {
        let random: Vec<u8> = (0..=255).collect();
        let p = enrolment_password(&random).expect("enough bytes");
        assert_eq!(p.len(), MOK_PASSWORD_LEN);
        assert!(p
            .chars()
            .all(|c| !"aqzwm".contains(c) && c.is_ascii_lowercase()));
        // Past the last whole multiple of the alphabet a byte is drawn again.
        assert_eq!(enrolment_password(&[255; 64]), None);
        assert_eq!(enrolment_password(&[0; 15]), None);
    }

    #[test]
    fn a_disk_not_bound_or_with_a_slot_nobody_knows_is_refused() {
        assert_eq!(refusal(&bound(3)), None);
        assert!(refusal(&bound(4))
            .expect("refused")
            .contains("does not know"));
        let unbound = Disk {
            bindings: Vec::new(),
            ..bound(1)
        };
        assert!(refusal(&unbound).expect("refused").contains("bind-disk"));
        let foreign = Disk {
            bindings: vec![Binding {
                slot: 2,
                tangs: None,
            }],
            ..bound(2)
        };
        assert!(refusal(&foreign).expect("refused").contains("did not make"));
    }

    #[test]
    fn setup_installs_the_reseal_before_the_initrd_that_runs_it_then_boots_the_uki_once() {
        let steps = setup_steps("/dev/vda3", &tangs(), "root=/x ro");
        let w = whats(&steps);
        let pos = |s: &str| w.iter().position(|x| x.contains(s)).expect(s);
        assert!(pos("policy") < pos("rebuild the initrd"));
        assert!(pos("in a slot of its own") < pos("rebuild the initrd"));
        assert!(pos("resealed after every initrd") < pos("rebuild the initrd"));
        assert!(pos("barrier's tool") < pos("rebuild the initrd"));
        assert!(pos("rebuild the initrd") < pos("build and install"));
        assert!(
            pos("build and install") < pos("once, at the next boot"),
            "{w:?}"
        );
    }

    #[test]
    fn no_secret_reaches_a_command_line() {
        // The recovery key and the enrolment password go by their staged paths.
        for step in setup_steps("/dev/vda3", &tangs(), "root=/x")
            .iter()
            .chain(&key_steps("n"))
        {
            if let Action::Run(argv) = &step.action {
                let line = argv.join(" ");
                assert!(!line.contains("--generate-hash"), "{line}");
                assert!(
                    !line.contains("passwd") || line.contains("-stdin <"),
                    "{line}"
                );
            }
        }
    }
}
