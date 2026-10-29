//! A node's encrypted disk opened at boot by its TPM AND one of the house's Tangs.
//!
//! The installer encrypts the disk under a one-time passphrase (`preseed`); this binds
//! it with Clevis, enrols the kit's recovery key, then takes the passphrase out. After
//! it, two things open the disk: the binding, unattended, and the recovery key, typed.
//!
//! ## 🔴 Why a nested policy, never "two of three"
//!
//! `sss` `t=2` over the TPM and an inner `sss` `t=1` over the Tangs. Flat, two shares
//! of three, the two Tangs alone would open a disk taken out of its machine and plugged
//! in at home. Nested, the disk needs ITS TPM, and the machine needs the house: carried
//! away whole, it reaches no Tang. And no other slot may open it alone beside — a
//! TPM-only slot cancels the Tang — so a slot Homelabus does not know is a refusal.
//!
//! ## What was measured (Debian 13.7, Clevis 20, the lab)
//!
//! Debian's own initramfs-tools does it: `clevis-initramfs` brings DHCP up in the initrd
//! and the disk opens in ~5 s. Both Tangs down, it waits at the prompt and opens alone
//! 14 s after one comes back — Clevis retries in a loop, which is what lets a house cut
//! whole open in cascade once one node is opened by hand. The initrd has plain IP and no
//! mesh, so a Tang is reached at its node's address on the house's network.
//!
//! ## Why PCR 7 only
//!
//! The TPM itself is what B binds to; a firmware update moving PCR 0 or 2 would leave
//! the node at its prompt after a reboot nobody is watching.
//!
//! ## 🔴 A Tang is pinned by its thumbprint
//!
//! `clevis luks bind -y` trusts whatever answers the advertisement. Homelabus installs
//! the Tangs, so it reads their signing keys on their nodes and pins them (`thp`): a
//! wrong thumbprint is refused before anything is written (measured).

use base64::Engine as _;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::distro::PackageManager;
use crate::provision::{Action, Phase, Step};

/// What the bound node needs — `clevis-luks` pulls `clevis` in, `clevis-tpm2` the TPM's
/// libraries.
pub const PACKAGES: [&str; 3] = ["clevis-luks", "clevis-initramfs", "clevis-tpm2"];
pub const TANG_PACKAGE: &str = "tang";
/// Debian's `tangd.socket` listens on 80, which Caddy takes on the ingress node.
pub const TANG_PORT: u16 = 7500;
pub const TANG_KEYS: &str = "/var/lib/tang";
pub const TANG_DROPIN: &str = "/etc/systemd/system/tangd.socket.d/homelabus.conf";
// An empty `ListenStream=` resets the list; without it the socket listens on both.
pub const TANG_DROPIN_CONTENT: &str = "\
# Written by Homelabus: off port 80, which Caddy takes on the ingress node.
[Socket]
ListenStream=
ListenStream=7500
";
/// Owned by `_tang`, which serves them.
const TANG_KEYGEN: &str = "ls /var/lib/tang/*.jwk >/dev/null 2>&1 || \
runuser -u _tang -- /usr/libexec/tangd-keygen /var/lib/tang";
/// The keys, read back to pin them.
pub const TANG_READ_KEYS: &str = "cat /var/lib/tang/*.jwk";
/// Where the disk's current passphrase and the recovery key wait, in memory, for the
/// steps that read them by path. `/run` is a tmpfs; the caller removes both afterwards.
pub const STAGED_PASSPHRASE: &str = "/run/hlb-luks-passphrase";
pub const STAGED_RECOVERY: &str = "/run/hlb-luks-recovery";

/// Opens the disk with each Clevis binding in turn, as the initrd will: `$1` is the
/// device. The binding is proven before the passphrase goes.
const PROOF: &str = "for s in $(clevis luks list -d \"$1\" | cut -d: -f1); do \
clevis luks pass -d \"$1\" -s \"$s\" | cryptsetup open --test-passphrase --key-file - \"$1\" \
&& exit 0; done; exit 1";

/// A Tang, as a binding names it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Tang {
    pub url: String,
    pub thp: String,
}

/// The URL a Tang on `host` answers at.
pub fn tang_url(host: &str) -> String {
    if host.contains(':') {
        format!("http://[{host}]:{TANG_PORT}")
    } else {
        format!("http://{host}:{TANG_PORT}")
    }
}

/// The binding's policy: the TPM AND one of `tangs`.
pub fn policy(tangs: &[Tang]) -> String {
    let tang: Vec<Value> = tangs
        .iter()
        .map(|t| json!({ "url": t.url, "thp": t.thp }))
        .collect();
    json!({
        "t": 2,
        "pins": {
            "tpm2": { "pcr_bank": "sha256", "pcr_ids": "7" },
            "sss": { "t": 1, "pins": { "tang": tang } },
        },
    })
    .to_string()
}

/// A key's RFC 7638 thumbprint, SHA-256, as Tang names its key files and Clevis's `thp`
/// reads it. Tang's keys are elliptic: `None` for any other kind.
pub fn thumbprint(jwk: &Value) -> Option<String> {
    if jwk.get("kty")?.as_str()? != "EC" {
        return None;
    }
    // The required members only, in lexicographic order, no whitespace.
    let canonical = format!(
        r#"{{"crv":"{}","kty":"EC","x":"{}","y":"{}"}}"#,
        jwk.get("crv")?.as_str()?,
        jwk.get("x")?.as_str()?,
        jwk.get("y")?.as_str()?,
    );
    Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(canonical)))
}

/// The thumbprints of the signing keys among a Tang's key files, concatenated — the
/// keys an advertisement is signed with, which `thp` names.
pub fn signing_thumbprints(files: &str) -> Vec<String> {
    let keys: Vec<Value> = serde_json::Deserializer::from_str(files)
        .into_iter::<Value>()
        .filter_map(|k| k.ok())
        .collect();
    signing(&keys)
}

/// The thumbprints of the keys among `keys` that verify, sorted.
fn signing(keys: &[Value]) -> Vec<String> {
    let mut thps: Vec<String> = keys
        .iter()
        .filter(|k| {
            k.get("key_ops")
                .and_then(Value::as_array)
                .is_some_and(|ops| ops.iter().any(|o| o == "verify"))
        })
        .filter_map(thumbprint)
        .collect();
    thps.sort();
    thps
}

/// The encrypted device `/etc/crypttab` names. One, or a refusal: two encrypted volumes
/// are a layout the installer does not make, and binding one would leave the other at
/// its prompt.
pub fn device(crypttab: &str) -> Result<String, String> {
    let sources: Vec<&str> = crypttab
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| l.split_whitespace().nth(1))
        .collect();
    match sources.as_slice() {
        [] => Err("/etc/crypttab names no encrypted volume: this disk is not encrypted".into()),
        [one] => Ok(match one.strip_prefix("UUID=") {
            Some(uuid) => format!("/dev/disk/by-uuid/{uuid}"),
            None => (*one).to_string(),
        }),
        many => Err(format!(
            "/etc/crypttab names {} encrypted volumes ({}): Homelabus binds a disk the \
             installer laid out, one volume",
            many.len(),
            many.join(", ")
        )),
    }
}

/// A Clevis binding found on the disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    pub slot: u32,
    /// Its Tangs, each with the signing key it advertised when the disk was bound, when
    /// it is the TPM AND Tangs shape this module writes; `None` for any other — a TPM
    /// alone, a Tang alone, which open the disk without the other factor.
    pub tangs: Option<Vec<Tang>>,
}

/// The Clevis bindings in `cryptsetup luksDump --dump-json-metadata`, read from their
/// tokens. `clevis luks list` leaves each Tang's `thp` out (measured), so a Tang whose
/// keys were remade at the same address looked bound; the token keeps the advertisement
/// the disk was bound with. And it is read with Clevis not installed.
pub fn parse_bindings(dump: &str) -> Vec<Binding> {
    let Ok(v) = serde_json::from_str::<Value>(dump) else {
        return Vec::new();
    };
    let tokens = v.get("tokens").and_then(Value::as_object);
    let mut out: Vec<Binding> = tokens
        .into_iter()
        .flat_map(|t| t.values())
        .filter(|t| t.get("type").and_then(Value::as_str) == Some("clevis"))
        .flat_map(|t| {
            let tangs = t
                .pointer("/jwe/protected")
                .and_then(Value::as_str)
                .and_then(header)
                .and_then(|h| ours(&h));
            t.get("keyslots")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|s| s.as_str()?.parse().ok())
                .map(move |slot| Binding {
                    slot,
                    tangs: tangs.clone(),
                })
                .collect::<Vec<_>>()
        })
        .collect();
    out.sort_by_key(|b| b.slot);
    out
}

/// A JWE's protected header, decoded.
fn header(protected: &str) -> Option<Value> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(protected.trim_end_matches('='))
        .ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// The pin a header was made by, and that pin's part of it.
fn pin(h: &Value) -> Option<(&str, &Value)> {
    let c = h.get("clevis")?;
    let name = c.get("pin")?.as_str()?;
    Some((name, c.get(name)?))
}

/// An `sss` pin's threshold and the headers of its shares — each share a compact JWE.
fn shares(sss: &Value) -> Option<(u64, Vec<Value>)> {
    let jwes = sss
        .get("jwe")?
        .as_array()?
        .iter()
        .map(|j| header(j.as_str()?.split('.').next()?))
        .collect::<Option<Vec<_>>>()?;
    Some((sss.get("t")?.as_u64()?, jwes))
}

/// The Tangs of a binding shaped as [`policy`] writes it: `sss` t=2 over exactly the TPM
/// and an inner `sss` t=1 over Tangs only.
fn ours(h: &Value) -> Option<Vec<Tang>> {
    let ("sss", outer) = pin(h)? else {
        return None;
    };
    let (2, outer) = shares(outer)? else {
        return None;
    };
    let names: Vec<&str> = outer.iter().filter_map(|s| Some(pin(s)?.0)).collect();
    if outer.len() != 2 || !names.contains(&"tpm2") || !names.contains(&"sss") {
        return None;
    }
    let inner = outer.iter().find_map(|s| match pin(s)? {
        ("sss", c) => Some(c),
        _ => None,
    })?;
    let (1, inner) = shares(inner)? else {
        return None;
    };
    let mut tangs = inner
        .iter()
        .map(|s| {
            let ("tang", c) = pin(s)? else {
                return None;
            };
            let keys = c.pointer("/adv/keys")?.as_array()?;
            let [thp] = signing(keys).try_into().ok()?;
            Some(Tang {
                url: c.get("url")?.as_str()?.to_string(),
                thp,
            })
        })
        .collect::<Option<Vec<_>>>()?;
    tangs.sort();
    Some(tangs)
}

/// How many key slots `cryptsetup luksDump --dump-json-metadata` shows.
pub fn parse_keyslots(dump: &str) -> Option<usize> {
    let v: Value = serde_json::from_str(dump).ok()?;
    Some(v.get("keyslots")?.as_object()?.len())
}

/// What the disk holds, read without a secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Disk {
    pub device: String,
    pub keyslots: usize,
    pub bindings: Vec<Binding>,
}

/// Which of the two secrets open the disk — tried on the node, so known only when
/// applying.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Keys {
    pub passphrase: bool,
    pub recovery: bool,
}

/// The steps that bind `disk` to its TPM AND one of `tangs`, enrol the recovery key and
/// take the passphrase out. `keys` is `None` in a preview, which shows every step.
/// `Err` is a refusal, worded for a person.
pub fn plan(disk: &Disk, keys: Option<Keys>, tangs: &[Tang]) -> Result<Vec<Step>, String> {
    if tangs.is_empty() {
        return Err(
            "no Tang to bind to: the disk would open with its TPM alone, so a \
                    machine carried away whole would too"
                .into(),
        );
    }
    if let Some(b) = disk.bindings.iter().find(|b| b.tangs.is_none()) {
        return Err(format!(
            "slot {} holds a Clevis binding Homelabus did not make: it opens the disk \
             without the second factor. Remove it by hand (`clevis luks unbind -d {} -s {}`) \
             once the kit's recovery key is known to open the disk",
            b.slot, disk.device, b.slot
        ));
    }
    let mut wanted = tangs.to_vec();
    wanted.sort();
    let current = disk
        .bindings
        .iter()
        .any(|b| b.tangs.as_deref() == Some(wanted.as_slice()));
    // Every slot is a binding, the passphrase or the recovery key; until they are tried
    // both may still be there.
    let known = disk.bindings.len()
        + keys.map_or(2, |k| usize::from(k.passphrase) + usize::from(k.recovery));
    if disk.keyslots > known {
        return Err(format!(
            "{} holds {} key slots, of which Homelabus knows {known}: a key it does not \
             know opens the disk alone, beside the binding. Remove it by hand first",
            disk.device, disk.keyslots
        ));
    }
    if let Some(k) = keys {
        if !k.passphrase && !k.recovery {
            return Err(format!(
                "neither the install passphrase nor the kit's recovery key opens {}",
                disk.device
            ));
        }
    }

    let run = |phase, what: &str, argv: Vec<String>| Step {
        phase,
        what: what.to_string(),
        action: Action::Run(argv),
    };
    let s = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    let dev = disk.device.as_str();
    let mut steps = vec![
        run(
            Phase::Packages,
            "refresh the package index",
            s(&["apt-get", "update"]),
        ),
        run(
            Phase::Packages,
            "Clevis, its TPM pin and its initrd hook",
            PackageManager::Apt.install_command(&PACKAGES),
        ),
    ];
    if !keys.is_some_and(|k| k.recovery) {
        steps.push(run(
            Phase::Configuration,
            "enrol the kit's recovery key",
            s(&[
                "cryptsetup",
                "luksAddKey",
                "--key-file",
                STAGED_PASSPHRASE,
                dev,
                STAGED_RECOVERY,
            ]),
        ));
    }
    if !current {
        steps.push(run(
            Phase::Configuration,
            "bind the disk to this TPM AND one of the house's Tangs",
            s(&[
                "clevis",
                "luks",
                "bind",
                "-d",
                dev,
                "-k",
                STAGED_RECOVERY,
                "sss",
                &policy(tangs),
            ]),
        ));
    }
    // A binding to Tangs since replaced: the new one is in place before it goes.
    for b in disk
        .bindings
        .iter()
        .filter(|b| b.tangs.as_deref() != Some(wanted.as_slice()))
    {
        steps.push(run(
            Phase::Configuration,
            "remove the binding to the Tangs of before",
            s(&[
                "clevis",
                "luks",
                "unbind",
                "-f",
                "-d",
                dev,
                "-s",
                &b.slot.to_string(),
            ]),
        ));
    }
    steps.push(run(
        Phase::Configuration,
        "rebuild the initrd, which opens the disk",
        s(&["update-initramfs", "-u", "-k", "all"]),
    ));
    steps.push(run(
        Phase::Services,
        "open the disk through the binding, as at boot",
        s(&["sh", "-c", PROOF, "sh", dev]),
    ));
    if keys.is_none_or(|k| k.passphrase) {
        // Not `-q`: cryptsetup then refuses to remove a disk's last key.
        steps.push(run(
            Phase::Services,
            "take the install passphrase out",
            s(&["cryptsetup", "luksRemoveKey", dev, STAGED_PASSPHRASE]),
        ));
    }
    Ok(steps)
}

/// The steps that make a node one of the house's Tangs: on port [`TANG_PORT`], started
/// by systemd before Docker and anything of Homelabus, so it answers as soon as its own
/// disk is open.
pub fn tang_steps() -> Vec<Step> {
    let run = |phase, what: &str, argv: &[&str]| Step {
        phase,
        what: what.to_string(),
        action: Action::Run(argv.iter().map(|s| s.to_string()).collect()),
    };
    vec![
        // 🔴 Before the package: Debian's starts the socket on port 80 as it installs —
        // Caddy's, on the ingress node, at its next start.
        Step {
            phase: Phase::Configuration,
            what: "Tang's port".to_string(),
            action: Action::Install {
                path: TANG_DROPIN.to_string(),
                content: TANG_DROPIN_CONTENT.to_string(),
                mode: 0o644,
            },
        },
        run(
            Phase::Packages,
            "refresh the package index",
            &["apt-get", "update"],
        ),
        Step {
            phase: Phase::Packages,
            what: "Tang".to_string(),
            action: Action::Run(PackageManager::Apt.install_command(&[TANG_PACKAGE])),
        },
        // Tang makes them at its first request otherwise; they are read just after.
        run(
            Phase::Configuration,
            "Tang's keys",
            &["sh", "-c", TANG_KEYGEN],
        ),
        run(
            Phase::Services,
            "read the socket",
            &["systemctl", "daemon-reload"],
        ),
        run(
            Phase::Services,
            "answer from boot on",
            &["systemctl", "enable", "tangd.socket"],
        ),
        // `restart`: a socket installed before Homelabus keeps port 80 until then.
        run(
            Phase::Services,
            "answer now",
            &["systemctl", "restart", "tangd.socket"],
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEV: &str = "/dev/disk/by-uuid/832b31e0";

    /// A Tang at `host` whose signing key's `x` is `x` — the thumbprint computed, as a
    /// token's advertisement gives it back.
    fn tang(host: &str, x: &str) -> Tang {
        Tang {
            url: tang_url(host),
            thp: thumbprint(&signing_key(x)).expect("an EC key"),
        }
    }

    fn signing_key(x: &str) -> Value {
        json!({"kty": "EC", "crv": "P-521", "x": x, "y": "y", "key_ops": ["verify"]})
    }

    fn tangs() -> Vec<Tang> {
        vec![tang("10.77.0.11", "a"), tang("10.77.0.12", "b")]
    }

    fn b64(v: &Value) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v.to_string())
    }

    /// A share as `sss` holds it: a compact JWE, its header first.
    fn compact(h: Value) -> Value {
        Value::String(format!("{}..iv.ct.tag", b64(&h)))
    }

    // The shapes measured on enc1's token after `hlb node bind-disk` (Clevis 20).
    fn tang_share(host: &str, x: &str) -> Value {
        let derive =
            json!({"kty": "EC", "crv": "P-521", "x": "d", "y": "e", "key_ops": ["deriveKey"]});
        compact(
            json!({"alg": "ECDH-ES", "kid": "k", "clevis": {"pin": "tang",
            "tang": {"url": tang_url(host), "adv": {"keys": [signing_key(x), derive]}}}}),
        )
    }

    fn tpm_share() -> Value {
        compact(json!({"alg": "dir", "clevis": {"pin": "tpm2",
            "tpm2": {"hash": "sha256", "key": "ecc", "pcr_bank": "sha256", "pcr_ids": "7"}}}))
    }

    fn sss(t: u64, shares: Vec<Value>) -> Value {
        json!({"alg": "dir", "clevis": {"pin": "sss", "sss": {"t": t, "p": "p", "jwe": shares}}})
    }

    /// The metadata of a disk whose slot `slot` holds a binding of header `h`.
    fn dump(slot: &str, h: &Value) -> String {
        json!({"keyslots": {"1": {}, "2": {}}, "tokens": {"0": {"type": "clevis",
            "keyslots": [slot], "jwe": {"protected": b64(h), "ciphertext": "c"}}}})
        .to_string()
    }

    fn ours_on(hosts: &[(&str, &str)]) -> Value {
        let tangs = hosts.iter().map(|(h, x)| tang_share(h, x)).collect();
        sss(2, vec![tpm_share(), compact(sss(1, tangs))])
    }

    fn whats(steps: &[Step]) -> Vec<&str> {
        steps.iter().map(|s| s.what.as_str()).collect()
    }

    fn fresh() -> Disk {
        Disk {
            device: DEV.into(),
            keyslots: 1,
            bindings: Vec::new(),
        }
    }

    #[test]
    fn the_thumbprint_is_the_one_tang_names_its_key_file_by() {
        // The public half of a key `tangd-keygen` made on the lab, in the file it named
        // by this thumbprint — `jose jwk thp -a S256` agreeing.
        let key: Value = serde_json::from_str(
            r#"{"alg":"ES512","crv":"P-521","key_ops":["verify"],"kty":"EC",
            "x":"ARLA6rBUaz29RvweV9qmU_ZxqIpYzpJMnFTOBrlyZHWFglqCd6o2ZN_mPraPRmGl76hZ7DkZ9lz5gFEL_4NZ_4UG",
            "y":"AIe6umcodRPjeZQdyU0VDsdzRzaRLt_qh6cJhBzR1L_KA7fLy7GXIpIHF4fprF5fcOphWlVXwUmb-RUkvyLSo2nW"}"#,
        )
        .expect("a JWK");
        assert_eq!(
            thumbprint(&key).as_deref(),
            Some("vSveGTgrsIDWvKDYNif87C1uWXvT_Fa0v2hNGNANNnE")
        );
    }

    #[test]
    fn only_the_signing_keys_are_pinned() {
        let files = r#"{"kty":"EC","crv":"P-521","x":"a","y":"b","key_ops":["deriveKey"]}
{"kty":"EC","crv":"P-521","x":"c","y":"d","key_ops":["sign","verify"]}"#;
        let thps = signing_thumbprints(files);
        assert_eq!(thps.len(), 1, "{thps:?}");
        let signing: Value =
            serde_json::from_str(r#"{"kty":"EC","crv":"P-521","x":"c","y":"d"}"#).expect("JWK");
        assert_eq!(thumbprint(&signing), Some(thps[0].clone()));
    }

    #[test]
    fn the_policy_needs_the_tpm_and_one_tang() {
        let p: Value = serde_json::from_str(&policy(&tangs())).expect("JSON");
        assert_eq!(p["t"], 2);
        assert_eq!(p["pins"]["tpm2"]["pcr_ids"], "7");
        assert_eq!(p["pins"]["sss"]["t"], 1);
        assert_eq!(
            p["pins"]["sss"]["pins"]["tang"][1]["thp"],
            tangs()[1].thp.as_str()
        );
    }

    #[test]
    fn a_binding_is_read_back_from_its_token_with_its_tangs_keys() {
        let b = parse_bindings(&dump(
            "2",
            &ours_on(&[("10.77.0.12", "b"), ("10.77.0.11", "a")]),
        ));
        assert_eq!(
            b,
            vec![Binding {
                slot: 2,
                tangs: Some(tangs())
            }]
        );
    }

    #[test]
    fn a_binding_opening_with_one_factor_is_not_ours() {
        let tpm_alone = json!({"alg": "dir", "clevis": {"pin": "tpm2", "tpm2": {}}});
        let tang_alone = sss(1, vec![tang_share("10.77.0.11", "a")]);
        // The flat "two of three" this plan first said: the Tangs alone open it.
        let flat = sss(
            2,
            vec![
                tpm_share(),
                tang_share("10.77.0.11", "a"),
                tang_share("10.77.0.12", "b"),
            ],
        );
        // The outer threshold lowered to one: the TPM alone opens it.
        let either = sss(
            1,
            vec![
                tpm_share(),
                compact(sss(1, vec![tang_share("10.77.0.11", "a")])),
            ],
        );
        for h in [tpm_alone, tang_alone, flat, either] {
            assert_eq!(parse_bindings(&dump("1", &h))[0].tangs, None, "{h}");
        }
    }

    #[test]
    fn a_token_that_is_not_clevis_binds_nothing() {
        let d = r#"{"keyslots":{"1":{}},"tokens":{"0":{"type":"systemd-tpm2","keyslots":["1"]}}}"#;
        assert!(parse_bindings(d).is_empty());
    }

    #[test]
    fn a_tang_whose_keys_were_remade_is_bound_again() {
        let disk = Disk {
            device: DEV.into(),
            keyslots: 2,
            bindings: parse_bindings(&dump(
                "1",
                &ours_on(&[("10.77.0.11", "old"), ("10.77.0.12", "b")]),
            )),
        };
        let keys = Keys {
            passphrase: false,
            recovery: true,
        };
        let steps = plan(&disk, Some(keys), &tangs()).expect("a plan");
        let w = whats(&steps);
        assert!(w.iter().any(|x| x.contains("bind the disk")), "{w:?}");
        assert!(w.iter().any(|x| x.contains("of before")), "{w:?}");
    }

    #[test]
    fn crypttab_names_the_device_by_its_uuid() {
        let tab =
            "# <target> <source>\nvda5_crypt UUID=832b31e0 none luks,discard,x-initrd.attach\n";
        assert_eq!(device(tab).as_deref(), Ok(DEV));
        assert!(device("# nothing\n").is_err());
        assert!(device("a UUID=1 none luks\nb UUID=2 none luks\n").is_err());
    }

    #[test]
    fn keyslots_are_counted_from_the_metadata() {
        let dump = r#"{"keyslots":{"0":{"type":"luks2"},"1":{"type":"luks2"}},"tokens":{}}"#;
        assert_eq!(parse_keyslots(dump), Some(2));
    }

    #[test]
    fn a_fresh_disk_is_bound_proven_then_its_passphrase_goes() {
        let steps = plan(&fresh(), None, &tangs()).expect("a plan");
        let w = whats(&steps);
        let pos = |s: &str| w.iter().position(|x| x.contains(s)).expect(s);
        assert!(pos("recovery key") < pos("bind the disk"));
        assert!(pos("bind the disk") < pos("open the disk"));
        assert!(pos("rebuild the initrd") < pos("open the disk"));
        assert!(pos("open the disk") < pos("passphrase out"), "{w:?}");
    }

    #[test]
    fn no_secret_reaches_a_command_line() {
        // The secrets go by their staged paths; the policy carries thumbprints only.
        for step in plan(&fresh(), None, &tangs()).expect("a plan") {
            if let Action::Run(argv) = &step.action {
                assert!(!argv.iter().any(|a| a.contains("lab-enc1")), "{argv:?}");
            }
        }
    }

    #[test]
    fn a_disk_already_bound_is_left_as_it_is() {
        let disk = Disk {
            device: DEV.into(),
            keyslots: 2,
            bindings: vec![Binding {
                slot: 1,
                tangs: Some(tangs()),
            }],
        };
        let keys = Keys {
            passphrase: false,
            recovery: true,
        };
        let w = whats(&plan(&disk, Some(keys), &tangs()).expect("a plan")).join(" | ");
        assert!(!w.contains("bind the disk"), "{w}");
        assert!(!w.contains("recovery key"), "{w}");
        assert!(!w.contains("passphrase out"), "{w}");
    }

    #[test]
    fn a_binding_to_other_tangs_is_replaced_after_the_new_one() {
        let mut old = tangs();
        old.pop();
        let disk = Disk {
            device: DEV.into(),
            keyslots: 2,
            bindings: vec![Binding {
                slot: 1,
                tangs: Some(old),
            }],
        };
        let keys = Keys {
            passphrase: false,
            recovery: true,
        };
        let steps = plan(&disk, Some(keys), &tangs()).expect("a plan");
        let w = whats(&steps);
        let bind = w
            .iter()
            .position(|x| x.contains("bind the disk"))
            .expect("bind");
        let unbind = w
            .iter()
            .position(|x| x.contains("of before"))
            .expect("unbind");
        assert!(bind < unbind, "{w:?}");
    }

    #[test]
    fn a_slot_nobody_knows_is_refused() {
        let disk = Disk {
            keyslots: 3,
            ..fresh()
        };
        let keys = Keys {
            passphrase: true,
            recovery: true,
        };
        let e = plan(&disk, Some(keys), &tangs()).expect_err("refused");
        assert!(e.contains("does not know"), "{e}");
        // Untried, both secrets may be there: three slots refuse before them.
        assert!(plan(&disk, None, &tangs()).is_err());
    }

    #[test]
    fn a_binding_opening_with_one_factor_is_refused() {
        let disk = Disk {
            device: DEV.into(),
            keyslots: 2,
            bindings: vec![Binding {
                slot: 1,
                tangs: None,
            }],
        };
        let e = plan(&disk, None, &tangs()).expect_err("refused");
        assert!(e.contains("second factor"), "{e}");
    }

    #[test]
    fn no_tang_is_refused() {
        assert!(plan(&fresh(), None, &[]).is_err());
    }

    #[test]
    fn a_disk_neither_secret_opens_is_refused() {
        let keys = Keys {
            passphrase: false,
            recovery: false,
        };
        assert!(plan(&fresh(), Some(keys), &tangs()).is_err());
    }

    #[test]
    fn tang_is_off_port_80_before_its_package_starts_it() {
        let w = whats(&tang_steps()).join(" | ");
        let port = w.find("Tang's port").expect("the drop-in");
        assert!(port < w.find("| Tang |").expect("the package"), "{w}");
        assert!(TANG_KEYGEN.contains(TANG_KEYS) && TANG_READ_KEYS.contains(TANG_KEYS));
    }

    #[test]
    fn tang_leaves_port_80_to_caddy() {
        assert!(TANG_DROPIN_CONTENT.contains("ListenStream=\n"));
        assert!(TANG_DROPIN_CONTENT.contains(&format!("ListenStream={TANG_PORT}\n")));
        assert_eq!(tang_url("10.0.0.2"), "http://10.0.0.2:7500");
    }
}
