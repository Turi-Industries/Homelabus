//! API access tokens.
//!
//! ## What this is, and what it is not
//!
//! Roles can come from **PocketID groups** - a single source of truth for identities.
//! This module does not replace that; it provides the layer underneath.
//!
//! A bearer token stays necessary even with OIDC: it is what an OIDC flow ultimately
//! hands out, and it is what a script or a metrics collector needs, since neither can
//! open a browser to sign in.
//!
//! ## 🔴 The token is never stored in clear
//!
//! The `age` vault already encrypts what it holds, so storing the token as-is would
//! "work". But then anyone obtaining the master key **and** the database obtains
//! tokens that are **immediately usable**.
//!
//! So a **fingerprint** is stored instead. A vault leak reveals that a token exists,
//! not its value: it has to be regenerated, not panicked over. This is exactly the
//! reasoning behind a password file, and it holds here for the same reason.
//!
//! ⚠️ An accepted consequence: **a lost token is not recovered**, it is replaced.

use serde::{Deserialize, Serialize};

use crate::rbac::Role;

/// Length of the generated token, in bytes of entropy.
///
/// 32 bytes is 256 bits. Far beyond what brute force reaches, and a longer token costs
/// nothing.
pub const TOKEN_BYTES: usize = 32;

/// A token, as it is stored.
///
/// 🔴 There is **no field for the value**. As with [`crate::rbac::Role`], the guarantee
/// is structural: you cannot leak what you cannot represent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredToken {
    /// A readable name, so you know which one to revoke.
    pub name: String,
    pub role: Role,
    /// Hexadecimal fingerprint of the value.
    pub fingerprint: String,
}

impl StoredToken {
    /// Does the supplied token match?
    ///
    /// 🔴 **Constant-time** comparison. A `==` on strings stops at the first differing
    /// byte: the response time reveals how many characters are correct, and the token
    /// can be guessed byte by byte. The cost here is nil; the cost of not protecting
    /// against it is not.
    pub fn matches(&self, presented: &str) -> bool {
        constant_eq(&fingerprint(presented), &self.fingerprint)
    }
}

/// A token's fingerprint.
///
/// ## Why SHA-256 and not a password hash
///
/// A `bcrypt`/`argon2` exists to slow down brute force **against a secret a human
/// chose**, and therefore of low entropy. Here the token is 256 randomly generated
/// bits: there is nothing to slow down, the space is already out of reach.
///
/// And a slow hash would be a defect: it runs on **every API request**, including
/// those of the metrics collector that comes round every fifteen seconds.
pub fn fingerprint_of(token: &str) -> String {
    fingerprint(token)
}

/// The SHA-256 fingerprint of a binary or a file, in hexadecimal.
///
/// Same implementation as for tokens, checked against the NIST vectors: a second
/// SHA-256 in the project would be a second place to get it wrong.
pub fn sha256_hex(data: &[u8]) -> String {
    sha256(data).iter().map(|b| format!("{b:02x}")).collect()
}

/// The raw SHA-256 fingerprint.
///
/// Exposed for PKCE: OAuth 2.1's `S256` challenge is computed as base64url over the
/// bytes, not over their hexadecimal representation - hashing the hex text would
/// produce a challenge the authorisation server rejects.
pub fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    sha256(data)
}

/// base64url encoding **without padding** (RFC 4648 §5).
///
/// Written by hand rather than pulled in as a dependency, like the token base32: it is
/// twenty lines, and one fewer dependency in the supply chain of a crate that handles
/// secrets.
///
/// ⚠️ The **URL** alphabet (`-` and `_`), not the standard one: `+` and `/` would be
/// re-encoded by the browser inside a query parameter, and the PKCE challenge would no
/// longer match the verifier - with an error about an invalid code that points at
/// nothing.
pub fn base64url(data: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for bloc in data.chunks(3) {
        let b = [
            bloc[0],
            *bloc.get(1).unwrap_or(&0),
            *bloc.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        // 4 characters per 3 bytes, minus those the last incomplete block lacks.
        let utiles = bloc.len() + 1;
        for i in 0..utiles {
            let idx = ((n >> (18 - 6 * i)) & 0x3F) as usize;
            out.push(A[idx] as char);
        }
    }
    out
}

/// base64url decoding without padding, tolerant of `=` padding.
///
/// Used to read an `id_token` payload - see the security note in
/// `hlb_identity::oidc`, which explains why it is read without verifying its
/// signature.
pub fn base64url_decode(s: &str) -> Option<Vec<u8>> {
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    for c in s.bytes() {
        if c == b'=' {
            break;
        }
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xFF) as u8);
        }
    }
    Some(out)
}

fn fingerprint(token: &str) -> String {
    // SHA-256 implemented directly: no new dependency for thirty lines, and the
    // algorithm has been frozen for twenty years.
    let d = sha256(token.as_bytes());
    d.iter().map(|b| format!("{b:02x}")).collect()
}

/// A fresh token: the value (handed out ONCE) and its stored form.
pub fn generate(name: &str, role: Role, random: [u8; TOKEN_BYTES]) -> (String, StoredToken) {
    // Base32 without padding: readable, selectable with a double-click, and free of
    // characters the shell interprets - unlike base64, whose "/" and "+" break
    // copy-paste into a URL or a unit file.
    let valeur = base32(&random);
    let stored = StoredToken {
        name: name.to_string(),
        role,
        fingerprint: fingerprint(&valeur),
    };
    (valeur, stored)
}

/// Constant-time comparison.
pub fn constant_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes()
        .zip(b.bytes())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

/// Encodage base32 (RFC 4648, sans remplissage).
pub fn base32(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    let mut tampon: u32 = 0;
    let mut bits = 0;

    for &b in data {
        tampon = (tampon << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((tampon >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((tampon << (5 - bits)) & 0x1f) as usize] as char);
    }
    out
}

/// SHA-256.
fn sha256(message: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    let mut m = message.to_vec();
    let bits = (message.len() as u64) * 8;
    m.push(0x80);
    while m.len() % 64 != 56 {
        m.push(0);
    }
    m.extend_from_slice(&bits.to_be_bytes());

    for bloc in m.chunks(64) {
        let mut w = [0u32; 64];
        for (i, c) in bloc.chunks(4).enumerate() {
            w[i] = u32::from_be_bytes([c[0], c[1], c[2], c[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let (mut a, mut b, mut c, mut d) = (h[0], h[1], h[2], h[3]);
        let (mut e, mut f, mut g, mut hh) = (h[4], h[5], h[6], h[7]);

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        for (i, v) in [a, b, c, d, e, f, g, hh].iter().enumerate() {
            h[i] = h[i].wrapping_add(*v);
        }
    }

    let mut out = [0u8; 32];
    for (i, v) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&v.to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alea(n: u8) -> [u8; TOKEN_BYTES] {
        let mut v = [0u8; TOKEN_BYTES];
        for (i, b) in v.iter_mut().enumerate() {
            *b = n.wrapping_add(i as u8);
        }
        v
    }

    #[test]
    fn base64url_matches_the_reference_vectors() {
        // RFC 4648 §10, transposed to the URL alphabet and without padding.
        assert_eq!(base64url(b""), "");
        assert_eq!(base64url(b"f"), "Zg");
        assert_eq!(base64url(b"fo"), "Zm8");
        assert_eq!(base64url(b"foo"), "Zm9v");
        assert_eq!(base64url(b"foob"), "Zm9vYg");
        assert_eq!(base64url(b"fooba"), "Zm9vYmE");
        assert_eq!(base64url(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn base64url_never_emits_characters_a_url_would_reencode() {
        // 🔴 `+` and `/` would be re-encoded inside a query parameter, and the PKCE
        // challenge would no longer match the verifier.
        let tout = base64url(&(0u8..=255).collect::<Vec<u8>>());
        assert!(!tout.contains('+'), "{tout}");
        assert!(!tout.contains('/'), "{tout}");
        assert!(!tout.contains('='), "pas de remplissage : {tout}");
    }

    #[test]
    fn base64url_survives_a_round_trip() {
        for n in 0..40usize {
            let brut: Vec<u8> = (0..n).map(|i| (i * 37 % 251) as u8).collect();
            let code = base64url(&brut);
            assert_eq!(
                base64url_decode(&code).as_deref(),
                Some(brut.as_slice()),
                "{n} octets"
            );
        }
    }

    #[test]
    fn base64url_decoding_refuses_a_foreign_alphabet() {
        // A payload that is not base64url is not "nearly right": reading half of it
        // would give truncated JSON, and therefore a misleading error.
        assert_eq!(base64url_decode("abc+def"), None);
        assert_eq!(base64url_decode("abc/def"), None);
    }

    #[test]
    fn the_pkce_challenge_hashes_bytes_not_hex() {
        // Hashing the hexadecimal representation would produce a challenge the
        // authorisation server rejects, with an error about an invalid code.
        let verifier = "verifier".as_bytes();
        assert_eq!(sha256_bytes(verifier).len(), 32);
        assert_ne!(
            base64url(&sha256_bytes(verifier)),
            base64url(sha256_hex(verifier).as_bytes())
        );
    }

    #[test]
    fn sha256_matches_the_reference_vectors() {
        // 🔴 A hand-written cryptographic implementation MUST be checked against the
        // official vectors. A one-bit mistake would give a hash perfectly consistent
        // with itself, and therefore tokens that "work" - until the day you compare
        // with another tool.
        let vide: String = sha256(b"").iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            vide,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );

        let abc: String = sha256(b"abc").iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            abc,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );

        // Un message de plus d'un bloc, pour exercer le remplissage.
        let long: String = sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(
            long,
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn the_stored_form_has_no_field_for_the_value() {
        // 🔴 The guarantee is structural: you cannot leak what you cannot
        // represent.
        let (_, s) = generate("ui", Role::Viewer, alea(1));
        let j = serde_json::to_string(&s).expect("serialisable");
        assert!(!j.contains("value"), "{j}");
        assert!(!j.contains("token\":"), "{j}");
        assert!(j.contains("fingerprint"));
    }

    #[test]
    fn a_vault_dump_does_not_yield_usable_tokens() {
        // The point of hashing: a leak reveals a token EXISTS, not its value.
        let (valeur, s) = generate("ui", Role::Viewer, alea(7));
        assert!(!s.fingerprint.contains(&valeur));
        assert_ne!(s.fingerprint, valeur);
        // Et l'empreinte ne permet pas de reconstruire la valeur.
        assert!(!s.matches(&s.fingerprint));
    }

    #[test]
    fn a_token_matches_only_itself() {
        let (valeur, s) = generate("ui", Role::Viewer, alea(3));
        assert!(s.matches(&valeur));
        assert!(!s.matches(&format!("{valeur}x")));
        assert!(!s.matches(""));
        assert!(!s.matches("NIMPORTEQUOI"));
    }

    #[test]
    fn two_tokens_are_never_identical() {
        let (a, _) = generate("a", Role::Viewer, alea(1));
        let (b, _) = generate("b", Role::Viewer, alea(2));
        assert_ne!(a, b);
    }

    #[test]
    fn the_token_survives_a_copy_paste() {
        // ⚠️ Base32: no "/" or "+" as in base64, which break copy-paste into a URL or
        // a systemd unit file.
        let (v, _) = generate("x", Role::Admin, alea(9));
        assert!(v
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()));
        assert!(!v.contains('/') && !v.contains('+') && !v.contains('='));
        // 32 bytes gives at least 51 base32 characters.
        assert!(v.len() >= 51, "{} characters", v.len());
    }

    #[test]
    fn comparison_does_not_leak_by_timing() {
        // A `==` stops at the first differing byte: the response time would say how
        // many characters are right, and the token could be guessed byte by byte.
        assert!(constant_eq("abc", "abc"));
        assert!(!constant_eq("abc", "abd"));
        assert!(!constant_eq("abc", "abcd"));
        assert!(constant_eq("", ""));
    }

    #[test]
    fn the_role_is_carried_by_the_token() {
        // This is what will decide what the request is allowed to do.
        let (_, s) = generate("ops", Role::Operator, alea(5));
        assert_eq!(s.role, Role::Operator);
        assert!(s.role.allows(crate::rbac::Action::Operate));
        assert!(!s.role.allows(crate::rbac::Action::Destroy));
    }
}
