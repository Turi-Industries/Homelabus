//! Verifying downloaded binaries.
//!
//! ## 🔴 Why this is the system's most sensitive point
//!
//! An update replaces **the binary that holds every right**: it drives Docker, holds
//! the vault key, authenticates to the agents. An attacker who places their code here
//! has nothing left to bypass - they *are* Homelabus.
//!
//! None of the rest of the system's protections applies: the RBAC, the mTLS, the audit
//! log all live *inside* the binary being replaced.
//!
//! That is why `hlb self update` refused to download anything until now. This module is
//! what lifts that refusal.
//!
//! ## The trust model, stated plainly
//!
//! A **single public key**, compiled into the binary or supplied explicitly. No
//! certificate chain, no third-party authority, no TOFU.
//!
//! The choice is deliberately the simplest possible:
//!
//! - an X.509 chain would move trust to an authority, whose compromise or expiry would
//!   become one more failure mode;
//! - TOFU ("trust the first key you see") protects against *later* attacks, not the
//!   first - and the first update is precisely the one with nothing to compare against.
//!
//! ⚠️ An accepted consequence: **losing the private key means redistributing the public
//! key by hand on every machine.** That is the price of having no authority, and it is
//! low on a fleet of a few nodes.
//!
//! ## What a signature does NOT prove
//!
//! That a binary is signed says nothing about what it does. A signature proves
//! **origin**, not harmlessness: it guarantees the file comes from whoever holds the
//! key, and that it was not modified in transit. If the build machine is compromised,
//! it will sign malicious code and nothing here can see it.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

use crate::version::Version;

/// What accompanies a published binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    pub version: Version,
    /// The binary's SHA-256 fingerprint, in hexadecimal.
    pub sha256: String,
    /// The manifest's Ed25519 signature, in hexadecimal.
    pub signature: String,
}

/// Why a binary is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rejected {
    /// 🔴 No signature. An unsigned binary is not "less safe", it is unusable:
    /// nothing says where it came from.
    Unsigned,
    /// 🔴 Invalid signature: the file was modified, or comes from elsewhere.
    BadSignature,
    /// 🔴 The fingerprint does not match the downloaded file.
    ChecksumMismatch { expected: String, actual: String },
    /// The manifest announces a different version from the one requested.
    WrongVersion { expected: Version, found: Version },
    /// Unreadable public key.
    BadKey { detail: String },
}

impl Rejected {
    pub fn describe(&self) -> String {
        match self {
            Self::Unsigned => "🔴 UNSIGNED binary. This is not \"less safe\", it is \
                 unusable: nothing says where it came from. An update replaces the \
                 binary that holds the vault key and drives Docker."
                .to_string(),
            Self::BadSignature => "🔴 INVALID SIGNATURE. The file was modified after \
                 signing, or it does not come from who you think. Install nothing and \
                 check where this download came from."
                .to_string(),
            Self::ChecksumMismatch { expected, actual } => format!(
                "🔴 DIFFERENT FINGERPRINT. Expected {}..., got {}...\n\
                 The manifest is signed but does not describe this file: a truncated \
                 download, or the binary alone was substituted.",
                &expected[..8.min(expected.len())],
                &actual[..8.min(actual.len())]
            ),
            Self::WrongVersion { expected, found } => format!(
                "the manifest announces {found}, {expected} was requested. A manifest \
                 signed for ANOTHER version stays cryptographically valid - that is how \
                 an old vulnerable version gets replayed."
            ),
            Self::BadKey { detail } => format!("unreadable public key: {detail}"),
        }
    }
}

/// The signed content.
///
/// 🔴 The version is part of the signed message. Without it, a manifest signed for
/// 0.1.0 would stay valid for a claimed 0.9.0: an attacker would replay an old
/// vulnerable version, with an authentic signature.
pub fn signed_payload(version: Version, sha256: &str) -> String {
    format!("hlb-release\nversion={version}\nsha256={sha256}\n")
}

/// Loads a public key from its hexadecimal form.
pub fn parse_key(hex: &str) -> Result<VerifyingKey, Rejected> {
    let bytes = from_hex(hex.trim()).ok_or_else(|| Rejected::BadKey {
        detail: "invalid hexadecimal".into(),
    })?;

    let array: [u8; 32] = bytes.try_into().map_err(|_| Rejected::BadKey {
        detail: "an Ed25519 key is exactly 32 bytes".into(),
    })?;

    VerifyingKey::from_bytes(&array).map_err(|e| Rejected::BadKey {
        detail: e.to_string(),
    })
}

/// Checks a downloaded binary is the one a signed manifest announces.
///
/// The order of the checks matters: the **signature is verified before the
/// fingerprint**. Comparing the fingerprint first would trust a manifest we know
/// nothing about - an attacker would simply supply the fingerprint of their own
/// binary.
pub fn verify(
    key: &VerifyingKey,
    manifest: &Manifest,
    expected_version: Version,
    binary: &[u8],
) -> Result<(), Rejected> {
    if manifest.signature.trim().is_empty() {
        return Err(Rejected::Unsigned);
    }

    // 1. La signature, d'abord.
    let sig_octets = from_hex(&manifest.signature).ok_or(Rejected::BadSignature)?;
    let sig_tableau: [u8; 64] = sig_octets.try_into().map_err(|_| Rejected::BadSignature)?;
    let signature = Signature::from_bytes(&sig_tableau);

    let message = signed_payload(manifest.version, &manifest.sha256);
    key.verify(message.as_bytes(), &signature)
        .map_err(|_| Rejected::BadSignature)?;

    // 2. The version next: a manifest signed for ANOTHER version is
    //    cryptographically valid and nonetheless unacceptable.
    if manifest.version != expected_version {
        return Err(Rejected::WrongVersion {
            expected: expected_version,
            found: manifest.version,
        });
    }

    // 3. Finally, does the file match what the manifest describes?
    let reelle = sha256_hex(binary);
    if !constant_eq(&reelle, &manifest.sha256) {
        return Err(Rejected::ChecksumMismatch {
            expected: manifest.sha256.clone(),
            actual: reelle,
        });
    }

    Ok(())
}

/// Constant-time comparison.
fn constant_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes()
        .zip(b.bytes())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

fn from_hex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

/// A binary's fingerprint, in hexadecimal.
pub fn sha256_hex(data: &[u8]) -> String {
    hlb_types::token::sha256_hex(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn paire() -> (SigningKey, VerifyingKey) {
        // A fixed seed: a test must be reproducible.
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let vk = sk.verifying_key();
        (sk, vk)
    }

    fn manifeste_signe(sk: &SigningKey, version: Version, binary: &[u8]) -> Manifest {
        let sha = sha256_hex(binary);
        let sig = sk.sign(signed_payload(version, &sha).as_bytes());
        Manifest {
            version,
            sha256: sha,
            signature: sig.to_bytes().iter().map(|b| format!("{b:02x}")).collect(),
        }
    }

    #[test]
    fn a_correctly_signed_binary_passes() {
        let (sk, vk) = paire();
        let v = Version::new(0, 2, 0);
        let binary = b"le vrai binary";
        let m = manifeste_signe(&sk, v, binary);

        assert!(verify(&vk, &m, v, binary).is_ok());
    }

    #[test]
    fn an_unsigned_binary_is_refused() {
        // 🔴 Unsigned is not "less safe": it is unusable.
        let (sk, vk) = paire();
        let v = Version::new(0, 2, 0);
        let mut m = manifeste_signe(&sk, v, b"x");
        m.signature = String::new();

        let e = verify(&vk, &m, v, b"x").unwrap_err();
        assert_eq!(e, Rejected::Unsigned);
        assert!(e.describe().contains("vault key"), "{}", e.describe());
    }

    #[test]
    fn a_binary_from_another_key_is_refused() {
        // The basic case: an attacker signs with THEIR key.
        let (attaquant, _) = (SigningKey::from_bytes(&[9u8; 32]), ());
        let (_, notre_vk) = paire();
        let v = Version::new(0, 2, 0);
        let m = manifeste_signe(&attaquant, v, b"code malveillant");

        assert_eq!(
            verify(&notre_vk, &m, v, b"code malveillant").unwrap_err(),
            Rejected::BadSignature
        );
    }

    #[test]
    fn a_substituted_binary_is_caught() {
        // 🔴 The manifest is authentic, but the file was replaced. This is the attack
        // a signature alone, with no fingerprint, would not see.
        let (sk, vk) = paire();
        let v = Version::new(0, 2, 0);
        let m = manifeste_signe(&sk, v, b"le vrai binary");

        let e = verify(&vk, &m, v, b"ANOTHER binary").unwrap_err();
        assert!(matches!(e, Rejected::ChecksumMismatch { .. }), "{e:?}");
        assert!(e.describe().contains("substituted"), "{}", e.describe());
    }

    #[test]
    fn a_replayed_old_version_is_refused() {
        // 🔴 The replay attack: a manifest signed for 0.1.0 is cryptographically
        // PERFECT. Without the version check, an old vulnerable version would be
        // installed with an authentic signature.
        let (sk, vk) = paire();
        let ancienne = Version::new(0, 1, 0);
        let binary = b"vieux binary vulnerable";
        let m = manifeste_signe(&sk, ancienne, binary);

        let e = verify(&vk, &m, Version::new(0, 2, 0), binary).unwrap_err();
        assert!(matches!(e, Rejected::WrongVersion { .. }), "{e:?}");
        assert!(e.describe().contains("replayed"), "{}", e.describe());
    }

    #[test]
    fn the_version_is_part_of_what_is_signed() {
        // This is what makes a replay detectable: changing the version invalidates the
        // signature, so it cannot be "fixed" by an attacker.
        let a = signed_payload(Version::new(0, 1, 0), "abc");
        let b = signed_payload(Version::new(0, 2, 0), "abc");
        assert_ne!(a, b);
        assert!(a.contains("0.1.0"));
    }

    #[test]
    fn the_signature_is_checked_before_the_checksum() {
        // 🔴 The reverse would trust a manifest we know nothing about: the attacker
        // would simply supply the fingerprint of THEIR binary.
        let (attaquant, _) = (SigningKey::from_bytes(&[9u8; 32]), ());
        let (_, notre_vk) = paire();
        let v = Version::new(0, 2, 0);

        // Manifeste d'attaquant, DONT l'empreinte est juste pour son binary.
        let m = manifeste_signe(&attaquant, v, b"malveillant");
        let e = verify(&notre_vk, &m, v, b"malveillant").unwrap_err();

        // C'est la signature qui doit parler, pas l'empreinte (qui, elle, colle).
        assert_eq!(e, Rejected::BadSignature);
    }

    #[test]
    fn a_malformed_key_is_refused_clearly() {
        assert!(parse_key("pas de l'hexa").is_err());
        assert!(parse_key("aabb").is_err(), "trop courte");

        let e = parse_key("aabb").unwrap_err();
        assert!(e.describe().contains("32 bytes"), "{}", e.describe());
    }

    #[test]
    fn a_valid_key_round_trips() {
        let (_, vk) = paire();
        let hex: String = vk.to_bytes().iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(parse_key(&hex).expect("key").to_bytes(), vk.to_bytes());
    }

    #[test]
    fn a_truncated_signature_is_refused_not_panicking() {
        // A signature of the wrong length must not panic the binary that is updating
        // itself - the worst possible moment for a crash.
        let (sk, vk) = paire();
        let v = Version::new(0, 2, 0);
        let mut m = manifeste_signe(&sk, v, b"x");
        m.signature.truncate(20);

        assert_eq!(
            verify(&vk, &m, v, b"x").unwrap_err(),
            Rejected::BadSignature
        );
    }
}
