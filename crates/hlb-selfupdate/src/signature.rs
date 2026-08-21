//! Vérification des binaires téléchargés (§7bis).
//!
//! ## 🔴 Pourquoi c'est le point le plus sensible du système
//!
//! Une mise à jour remplace **le binaire qui a tous les droits** : il pilote Docker,
//! détient la clé du coffre, s'authentifie auprès des agents. Un attaquant qui place
//! son code ici n'a plus rien à contourner — il *est* Homelabus.
//!
//! Aucune des protections du reste du système ne s'applique : le RBAC, le mTLS, le
//! journal d'audit sont tous *dans* le binaire qu'on remplace.
//!
//! C'est pour ça que `hlb self update` refusait jusqu'ici de télécharger quoi que ce
//! soit. Ce module est ce qui lève ce refus.
//!
//! ## Le modèle de confiance, en clair
//!
//! Une **clé publique unique**, compilée dans le binaire ou fournie explicitement.
//! Pas de chaîne de certificats, pas d'autorité tierce, pas de TOFU.
//!
//! Ce choix est délibérément le plus simple possible :
//!
//! - une chaîne X.509 déplacerait la confiance vers une autorité, dont la
//!   compromission ou l'expiration deviendrait un mode de panne de plus ;
//! - le TOFU (« fais confiance à la première clé vue ») protège des attaques
//!   *ultérieures*, pas de la première — or la première mise à jour est justement
//!   celle où l'on n'a rien pour comparer.
//!
//! ⚠️ Conséquence assumée : **perdre la clé privée oblige à redistribuer la clé
//! publique à la main sur chaque machine.** C'est le prix de l'absence d'autorité, et
//! il est faible sur un parc de quelques nœuds.
//!
//! ## Ce que la signature ne prouve PAS
//!
//! Qu'un binaire est signé ne dit rien de ce qu'il fait. La signature prouve
//! l'**origine**, pas l'innocuité : elle garantit que le fichier vient bien de qui
//! détient la clé, et qu'il n'a pas été modifié en route. Si la machine de
//! construction est compromise, elle signera du code malveillant sans que rien ici ne
//! puisse le voir.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

use crate::version::Version;

/// Ce qui accompagne un binaire publié.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    pub version: Version,
    /// Empreinte SHA-256 du binaire, en hexadécimal.
    pub sha256: String,
    /// Signature Ed25519 du manifeste, en hexadécimal.
    pub signature: String,
}

/// Pourquoi un binaire est refusé.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rejected {
    /// 🔴 Signature absente. Un binaire non signé n'est pas « moins sûr », il est
    /// inutilisable : rien ne dit d'où il vient.
    Unsigned,
    /// 🔴 Signature invalide : le fichier a été modifié, ou vient d'ailleurs.
    BadSignature,
    /// 🔴 L'empreinte ne correspond pas au fichier téléchargé.
    ChecksumMismatch { expected: String, actual: String },
    /// Le manifeste annonce une autre version que celle demandée.
    WrongVersion { expected: Version, found: Version },
    /// Clé publique illisible.
    BadKey { detail: String },
}

impl Rejected {
    pub fn describe(&self) -> String {
        match self {
            Self::Unsigned => "🔴 binaire NON SIGNÉ. Ce n'est pas « moins sûr », c'est \
                 inutilisable : rien ne dit d'où il vient. Une mise à jour remplace le \
                 binaire qui détient la clé du coffre et pilote Docker."
                .to_string(),
            Self::BadSignature => "🔴 SIGNATURE INVALIDE. Le fichier a été modifié après \
                 signature, ou il ne vient pas de qui tu crois. N'installe rien et \
                 vérifie d'où vient ce téléchargement."
                .to_string(),
            Self::ChecksumMismatch { expected, actual } => format!(
                "🔴 EMPREINTE DIFFÉRENTE. Attendue {}…, obtenue {}…\n\
                 Le manifeste est signé mais ne décrit pas ce fichier : téléchargement \
                 tronqué, ou substitution du binaire seul.",
                &expected[..8.min(expected.len())],
                &actual[..8.min(actual.len())]
            ),
            Self::WrongVersion { expected, found } => format!(
                "le manifeste annonce {found}, on demandait {expected}. Un manifeste \
                 signé d'une AUTRE version reste valide cryptographiquement — c'est \
                 comme ça qu'on fait rejouer une vieille version vulnérable."
            ),
            Self::BadKey { detail } => format!("clé publique illisible : {detail}"),
        }
    }
}

/// Le contenu signé.
///
/// 🔴 La version fait partie du message signé. Sans elle, un manifeste signé pour la
/// 0.1.0 resterait valide pour une prétendue 0.9.0 : un attaquant rejouerait une
/// ancienne version vulnérable, avec une signature authentique.
pub fn signed_payload(version: Version, sha256: &str) -> String {
    format!("hlb-release\nversion={version}\nsha256={sha256}\n")
}

/// Charge une clé publique depuis son hexadécimal.
pub fn parse_key(hex: &str) -> Result<VerifyingKey, Rejected> {
    let octets = from_hex(hex.trim()).ok_or_else(|| Rejected::BadKey {
        detail: "hexadécimal invalide".into(),
    })?;

    let tableau: [u8; 32] = octets.try_into().map_err(|_| Rejected::BadKey {
        detail: "une clé Ed25519 fait exactement 32 octets".into(),
    })?;

    VerifyingKey::from_bytes(&tableau).map_err(|e| Rejected::BadKey {
        detail: e.to_string(),
    })
}

/// Vérifie qu'un binaire téléchargé est bien celui qu'annonce un manifeste signé.
///
/// L'ordre des contrôles n'est pas indifférent : on vérifie la **signature avant
/// l'empreinte**. Comparer d'abord l'empreinte ferait confiance à un manifeste dont
/// on ne sait rien — un attaquant fournirait simplement l'empreinte de son propre
/// binaire.
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

    // 2. La version, ensuite : un manifeste signé d'une AUTRE version est
    //    cryptographiquement valide et néanmoins inacceptable.
    if manifest.version != expected_version {
        return Err(Rejected::WrongVersion {
            expected: expected_version,
            found: manifest.version,
        });
    }

    // 3. Enfin, le fichier correspond-il à ce que le manifeste décrit ?
    let reelle = sha256_hex(binary);
    if !constant_eq(&reelle, &manifest.sha256) {
        return Err(Rejected::ChecksumMismatch {
            expected: manifest.sha256.clone(),
            actual: reelle,
        });
    }

    Ok(())
}

/// Comparaison à temps constant.
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
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

/// L'empreinte d'un binaire, en hexadécimal.
pub fn sha256_hex(data: &[u8]) -> String {
    hlb_types::token::sha256_hex(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn paire() -> (SigningKey, VerifyingKey) {
        // Graine fixe : un test doit être reproductible.
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let vk = sk.verifying_key();
        (sk, vk)
    }

    fn manifeste_signe(sk: &SigningKey, version: Version, binaire: &[u8]) -> Manifest {
        let sha = sha256_hex(binaire);
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
        let binaire = b"le vrai binaire";
        let m = manifeste_signe(&sk, v, binaire);

        assert!(verify(&vk, &m, v, binaire).is_ok());
    }

    #[test]
    fn an_unsigned_binary_is_refused() {
        // 🔴 Non signé n'est pas « moins sûr » : c'est inutilisable.
        let (sk, vk) = paire();
        let v = Version::new(0, 2, 0);
        let mut m = manifeste_signe(&sk, v, b"x");
        m.signature = String::new();

        let e = verify(&vk, &m, v, b"x").unwrap_err();
        assert_eq!(e, Rejected::Unsigned);
        assert!(e.describe().contains("clé du coffre"), "{}", e.describe());
    }

    #[test]
    fn a_binary_from_another_key_is_refused() {
        // Le cas de base : un attaquant signe avec SA clé.
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
        // 🔴 Le manifeste est authentique, mais le fichier a été remplacé. C'est
        // l'attaque qu'une signature seule, sans empreinte, ne verrait pas.
        let (sk, vk) = paire();
        let v = Version::new(0, 2, 0);
        let m = manifeste_signe(&sk, v, b"le vrai binaire");

        let e = verify(&vk, &m, v, b"un AUTRE binaire").unwrap_err();
        assert!(matches!(e, Rejected::ChecksumMismatch { .. }), "{e:?}");
        assert!(e.describe().contains("substitution"), "{}", e.describe());
    }

    #[test]
    fn a_replayed_old_version_is_refused() {
        // 🔴 L'attaque du rejeu : un manifeste signé pour la 0.1.0 est
        // cryptographiquement PARFAIT. Sans le contrôle de version, on installerait
        // une ancienne version vulnérable avec une signature authentique.
        let (sk, vk) = paire();
        let ancienne = Version::new(0, 1, 0);
        let binaire = b"vieux binaire vulnerable";
        let m = manifeste_signe(&sk, ancienne, binaire);

        let e = verify(&vk, &m, Version::new(0, 2, 0), binaire).unwrap_err();
        assert!(matches!(e, Rejected::WrongVersion { .. }), "{e:?}");
        assert!(e.describe().contains("rejouer"), "{}", e.describe());
    }

    #[test]
    fn the_version_is_part_of_what_is_signed() {
        // C'est ce qui rend le rejeu détectable : changer la version invalide la
        // signature, elle ne peut donc pas être « corrigée » par un attaquant.
        let a = signed_payload(Version::new(0, 1, 0), "abc");
        let b = signed_payload(Version::new(0, 2, 0), "abc");
        assert_ne!(a, b);
        assert!(a.contains("0.1.0"));
    }

    #[test]
    fn the_signature_is_checked_before_the_checksum() {
        // 🔴 L'inverse ferait confiance à un manifeste dont on ne sait rien :
        // l'attaquant fournirait simplement l'empreinte de SON binaire.
        let (attaquant, _) = (SigningKey::from_bytes(&[9u8; 32]), ());
        let (_, notre_vk) = paire();
        let v = Version::new(0, 2, 0);

        // Manifeste d'attaquant, DONT l'empreinte est juste pour son binaire.
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
        assert!(e.describe().contains("32 octets"), "{}", e.describe());
    }

    #[test]
    fn a_valid_key_round_trips() {
        let (_, vk) = paire();
        let hex: String = vk.to_bytes().iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(parse_key(&hex).expect("clé").to_bytes(), vk.to_bytes());
    }

    #[test]
    fn a_truncated_signature_is_refused_not_panicking() {
        // Une signature de mauvaise longueur ne doit pas faire paniquer le binaire
        // qui se met à jour — c'est le pire moment pour un plantage.
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
