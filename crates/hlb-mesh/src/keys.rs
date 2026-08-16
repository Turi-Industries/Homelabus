//! Génération des clés WireGuard.
//!
//! WireGuard utilise Curve25519. On génère les clés **en Rust** plutôt qu'en
//! appelant `wg genkey` : le binaire n'est pas garanti présent sur la machine qui
//! prépare la configuration (le controller peut tourner ailleurs que sur un nœud),
//! et une clé privée qui transite par la sortie standard d'un sous-processus est une
//! fuite de plus à surveiller.

use rand::RngCore;

use crate::{Error, Result};

/// Une paire de clés WireGuard, encodée en base64 comme l'attend `wg`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyPair {
    pub private: String,
    pub public: String,
}

impl KeyPair {
    pub fn generate() -> Self {
        let mut secret = [0u8; 32];
        rand::rng().fill_bytes(&mut secret);

        // Le « clamping » de Curve25519 : impose les bits requis par la courbe.
        // WireGuard le fait aussi de son côté, mais une clé non clampée serait
        // acceptée puis silencieusement modifiée — la clé publique dérivée ne
        // correspondrait alors plus.
        secret[0] &= 248;
        secret[31] &= 127;
        secret[31] |= 64;

        let public = x25519_dalek::x25519(secret, x25519_dalek::X25519_BASEPOINT_BYTES);

        Self {
            private: b64(&secret),
            public: b64(&public),
        }
    }

    /// Reconstruit la paire à partir d'une clé privée conservée au coffre.
    pub fn from_private(private_b64: &str) -> Result<Self> {
        let bytes = unb64(private_b64)
            .ok_or_else(|| Error::InvalidKey("base64 illisible".into()))?;

        let secret: [u8; 32] = bytes
            .try_into()
            .map_err(|_| Error::InvalidKey("longueur ≠ 32 octets".into()))?;

        let public = x25519_dalek::x25519(secret, x25519_dalek::X25519_BASEPOINT_BYTES);
        Ok(Self {
            private: private_b64.to_string(),
            public: b64(&public),
        })
    }
}

const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for c in data.chunks(3) {
        let b = [c[0], *c.get(1).unwrap_or(&0), *c.get(2).unwrap_or(&0)];
        let n = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
        out.push(TABLE[(n >> 18 & 63) as usize] as char);
        out.push(TABLE[(n >> 12 & 63) as usize] as char);
        out.push(if c.len() > 1 { TABLE[(n >> 6 & 63) as usize] as char } else { '=' });
        out.push(if c.len() > 2 { TABLE[(n & 63) as usize] as char } else { '=' });
    }
    out
}

fn unb64(s: &str) -> Option<Vec<u8>> {
    let mut idx = [255u8; 256];
    for (i, c) in TABLE.iter().enumerate() {
        idx[*c as usize] = i as u8;
    }

    let clean: Vec<u8> = s.bytes().filter(|b| *b != b'=' && !b.is_ascii_whitespace()).collect();
    let mut out = Vec::with_capacity(clean.len() * 3 / 4);

    for chunk in clean.chunks(4) {
        let mut n = 0u32;
        for (i, b) in chunk.iter().enumerate() {
            let v = idx[*b as usize];
            if v == 255 {
                return None;
            }
            n |= u32::from(v) << (18 - 6 * i);
        }
        let bytes = [(n >> 16) as u8, (n >> 8) as u8, n as u8];
        out.extend_from_slice(&bytes[..chunk.len() - 1]);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_generated_pair_has_the_expected_shape() {
        let k = KeyPair::generate();
        // 32 octets en base64 → 44 caractères avec le remplissage.
        assert_eq!(k.private.len(), 44, "{}", k.private);
        assert_eq!(k.public.len(), 44, "{}", k.public);
        assert!(k.private.ends_with('='));
        assert_ne!(k.private, k.public);
    }

    #[test]
    fn two_generations_differ() {
        assert_ne!(KeyPair::generate().private, KeyPair::generate().private);
    }

    #[test]
    fn the_public_key_is_derived_deterministically() {
        // 🔴 C'est ce qui permet de ne stocker QUE la clé privée au coffre : la
        // publique se recalcule, et ne peut donc pas désynchroniser.
        let k = KeyPair::generate();
        let relu = KeyPair::from_private(&k.private).expect("reconstruction");
        assert_eq!(relu.public, k.public);
        assert_eq!(relu.private, k.private);
    }

    #[test]
    fn clamping_is_applied() {
        // Sans clamping, WireGuard modifierait la clé en interne et la publique
        // dérivée ne correspondrait plus à celle qu'il utilise réellement.
        for _ in 0..20 {
            let k = KeyPair::generate();
            let b = unb64(&k.private).expect("décodable");
            assert_eq!(b[0] & 7, 0, "trois bits de poids faible non nuls");
            assert_eq!(b[31] & 128, 0, "bit de poids fort non nul");
            assert_eq!(b[31] & 64, 64, "bit 254 non posé");
        }
    }

    #[test]
    fn an_invalid_key_is_refused() {
        assert!(KeyPair::from_private("pas du base64 !").is_err());
        assert!(KeyPair::from_private("dHJvcCBjb3VydA==").is_err());
        assert!(KeyPair::from_private("").is_err());
    }

    #[test]
    fn base64_matches_known_vectors() {
        assert_eq!(b64(b"foobar"), "Zm9vYmFy");
        assert_eq!(b64(b"f"), "Zg==");
        assert_eq!(unb64("Zm9vYmFy"), Some(b"foobar".to_vec()));
        assert_eq!(unb64("Zg=="), Some(b"f".to_vec()));
    }

    #[test]
    fn base64_roundtrips_binary() {
        let mut data = [0u8; 32];
        rand::rng().fill_bytes(&mut data);
        assert_eq!(unb64(&b64(&data)), Some(data.to_vec()));
    }
}
