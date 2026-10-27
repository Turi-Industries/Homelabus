//! Bitwarden's client cryptography — what an official client does before the server
//! sees anything, read in `bitwarden/sdk-internal` and checked against Vaultwarden
//! 1.37.1 and the official CLI.
//!
//! The server stores what it is handed and decrypts nothing: a member's vault is
//! encrypted under a key only their master password unwraps, an organisation's items
//! under the organisation's key, which reaches each member encrypted for their RSA key
//! once an owner confirms them.
//!
//! - master key: PBKDF2-SHA256 (salt: the address, lower-cased) or Argon2id (salt: its
//!   SHA-256), 32 bytes. What the server checks is one more PBKDF2 round of it over the
//!   password — never the key itself.
//! - stretched: HKDF-Expand of the master key into an encryption and a MAC key.
//! - an `EncString` of type 2 is `2.iv|data|mac`, AES-256-CBC then HMAC-SHA256 over
//!   `iv || data`; type 4 is RSA-OAEP with SHA-1, type 3 with SHA-256.

use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use hmac::{Hmac, Mac};
use rand::RngCore;
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256};

use crate::{Error, Result};

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

/// How a master key is derived — the account's own setting, which the server hands
/// back at sign-in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kdf {
    Pbkdf2 {
        iterations: u32,
    },
    Argon2id {
        iterations: u32,
        memory_mib: u32,
        parallelism: u32,
    },
}

impl Kdf {
    /// From the server's numbers: `0` PBKDF2, `1` Argon2id.
    pub fn from_server(
        kind: i64,
        iterations: i64,
        memory: Option<i64>,
        parallelism: Option<i64>,
    ) -> Result<Self> {
        let n = |v: i64, what: &str| {
            u32::try_from(v).map_err(|_| Error::Crypto(format!("{what} out of range: {v}")))
        };
        match kind {
            0 => Ok(Self::Pbkdf2 {
                iterations: n(iterations, "iterations")?,
            }),
            1 => Ok(Self::Argon2id {
                iterations: n(iterations, "iterations")?,
                memory_mib: n(memory.unwrap_or(64), "memory")?,
                parallelism: n(parallelism.unwrap_or(4), "parallelism")?,
            }),
            other => Err(Error::Crypto(format!("unknown key derivation {other}"))),
        }
    }
}

/// The 32-byte key a master password derives.
pub struct MasterKey([u8; 32]);

impl MasterKey {
    pub fn derive(password: &str, email: &str, kdf: Kdf) -> Result<Self> {
        let salt = email.trim().to_lowercase();
        let mut key = [0u8; 32];
        match kdf {
            Kdf::Pbkdf2 { iterations } => {
                pbkdf2::pbkdf2_hmac::<Sha256>(
                    password.as_bytes(),
                    salt.as_bytes(),
                    iterations,
                    &mut key,
                );
            }
            Kdf::Argon2id {
                iterations,
                memory_mib,
                parallelism,
            } => {
                let params = argon2::Params::new(
                    memory_mib.saturating_mul(1024),
                    iterations,
                    parallelism,
                    Some(32),
                )
                .map_err(|e| Error::Crypto(format!("Argon2 parameters: {e}")))?;
                argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
                    .hash_password_into(
                        password.as_bytes(),
                        &Sha256::digest(salt.as_bytes()),
                        &mut key,
                    )
                    .map_err(|e| Error::Crypto(format!("Argon2: {e}")))?;
            }
        }
        Ok(Self(key))
    }

    /// What the server is shown instead of the password: one PBKDF2 round of the key,
    /// salted with the password.
    pub fn password_hash(&self, password: &str) -> String {
        let mut out = [0u8; 32];
        pbkdf2::pbkdf2_hmac::<Sha256>(&self.0, password.as_bytes(), 1, &mut out);
        B64.encode(out)
    }

    /// The key the account's own key is encrypted under.
    pub fn stretch(&self) -> Result<SymmetricKey> {
        let hk = hkdf::Hkdf::<Sha256>::from_prk(&self.0)
            .map_err(|e| Error::Crypto(format!("HKDF: {e}")))?;
        let mut enc = [0u8; 32];
        let mut mac = [0u8; 32];
        hk.expand(b"enc", &mut enc)
            .and_then(|()| hk.expand(b"mac", &mut mac))
            .map_err(|e| Error::Crypto(format!("HKDF: {e}")))?;
        Ok(SymmetricKey { enc, mac })
    }
}

/// An AES-256 key and its HMAC key: an account's key, an organisation's.
#[derive(Clone, PartialEq, Eq)]
pub struct SymmetricKey {
    enc: [u8; 32],
    mac: [u8; 32],
}

/// Redacted, like the vault's: a `{:?}` must never print a key.
impl std::fmt::Debug for SymmetricKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SymmetricKey(<redacted>)")
    }
}

impl SymmetricKey {
    pub fn generate() -> Self {
        let mut b = [0u8; 64];
        rand::rngs::OsRng.fill_bytes(&mut b);
        Self::from_bytes(&b).unwrap_or_else(|_| unreachable!("64 bytes"))
    }

    /// From the 64 bytes an `EncString` decrypts to.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() != 64 {
            return Err(Error::Crypto(format!(
                "a key is 64 bytes, this one {} — an account made before 2020 (a key without \
                 a MAC) is not read: change its master password once in the web vault",
                b.len()
            )));
        }
        let mut enc = [0u8; 32];
        let mut mac = [0u8; 32];
        enc.copy_from_slice(&b[..32]);
        mac.copy_from_slice(&b[32..]);
        Ok(Self { enc, mac })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        [self.enc.as_slice(), self.mac.as_slice()].concat()
    }

    /// An `EncString` of type 2.
    pub fn encrypt(&self, plain: &[u8]) -> String {
        let mut iv = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut iv);
        let data =
            Aes256CbcEnc::new(&self.enc.into(), &iv.into()).encrypt_padded_vec_mut::<Pkcs7>(plain);
        let mac = self.mac_of(&iv, &data);
        format!(
            "2.{}|{}|{}",
            B64.encode(iv),
            B64.encode(&data),
            B64.encode(mac)
        )
    }

    pub fn encrypt_str(&self, plain: &str) -> String {
        self.encrypt(plain.as_bytes())
    }

    /// The bytes of an `EncString` of type 2, its MAC checked first: a value someone
    /// altered on the server is refused, never decrypted into garbage.
    pub fn decrypt(&self, enc: &str) -> Result<Vec<u8>> {
        let (kind, body) = enc
            .split_once('.')
            .ok_or_else(|| Error::Crypto("not an encrypted value".into()))?;
        if kind != "2" {
            return Err(Error::Crypto(format!(
                "encrypted value of type {kind}: only type 2 (AES-256 with a MAC) is read"
            )));
        }
        let parts: Vec<&str> = body.split('|').collect();
        let [iv, data, mac] = parts.as_slice() else {
            return Err(Error::Crypto("an encrypted value has three parts".into()));
        };
        let b = |s: &str| {
            B64.decode(s)
                .map_err(|e| Error::Crypto(format!("encrypted value: {e}")))
        };
        let (iv, data, mac) = (b(iv)?, b(data)?, b(mac)?);
        let mut check = <Hmac<Sha256> as Mac>::new_from_slice(&self.mac)
            .map_err(|e| Error::Crypto(e.to_string()))?;
        check.update(&iv);
        check.update(&data);
        check
            .verify_slice(&mac)
            .map_err(|_| Error::Crypto("MAC mismatch: the wrong key, or a value altered".into()))?;
        let iv: [u8; 16] = iv
            .try_into()
            .map_err(|_| Error::Crypto("an IV is 16 bytes".into()))?;
        Aes256CbcDec::new(&self.enc.into(), &iv.into())
            .decrypt_padded_vec_mut::<Pkcs7>(&data)
            .map_err(|_| Error::Crypto("bad padding".into()))
    }

    pub fn decrypt_str(&self, enc: &str) -> Result<String> {
        String::from_utf8(self.decrypt(enc)?)
            .map_err(|_| Error::Crypto("a decrypted text is not UTF-8".into()))
    }

    fn mac_of(&self, iv: &[u8], data: &[u8]) -> Vec<u8> {
        let mut m = <Hmac<Sha256> as Mac>::new_from_slice(&self.mac)
            .unwrap_or_else(|_| unreachable!("HMAC takes a key of any length"));
        m.update(iv);
        m.update(data);
        m.finalize().into_bytes().to_vec()
    }
}

/// An account's RSA key pair: an organisation's key reaches the member through it.
pub struct KeyPair {
    private: RsaPrivateKey,
}

impl KeyPair {
    /// A new pair, 2048 bits as the clients make them.
    pub fn generate() -> Result<Self> {
        RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048)
            .map(|private| Self { private })
            .map_err(|e| Error::Crypto(format!("RSA: {e}")))
    }

    /// The account's private key, as the server keeps it: PKCS#8, encrypted under the
    /// account's key.
    pub fn unwrap(encrypted: &str, key: &SymmetricKey) -> Result<Self> {
        let der = key.decrypt(encrypted)?;
        RsaPrivateKey::from_pkcs8_der(&der)
            .map(|private| Self { private })
            .map_err(|e| Error::Crypto(format!("private key: {e}")))
    }

    pub fn wrap(&self, key: &SymmetricKey) -> Result<String> {
        let der = self
            .private
            .to_pkcs8_der()
            .map_err(|e| Error::Crypto(format!("private key: {e}")))?;
        Ok(key.encrypt(der.as_bytes()))
    }

    /// The public half, as the server keeps it: SPKI DER, in base64.
    pub fn public(&self) -> Result<String> {
        RsaPublicKey::from(&self.private)
            .to_public_key_der()
            .map(|d| B64.encode(d.as_bytes()))
            .map_err(|e| Error::Crypto(format!("public key: {e}")))
    }

    /// A key encrypted for this account: an organisation's, once an owner confirmed it.
    pub fn open(&self, enc: &str) -> Result<SymmetricKey> {
        let (kind, body) = enc
            .split_once('.')
            .ok_or_else(|| Error::Crypto("not an encrypted key".into()))?;
        let data = B64
            .decode(body)
            .map_err(|e| Error::Crypto(format!("encrypted key: {e}")))?;
        let plain = match kind {
            "4" => self.private.decrypt(Oaep::new::<sha1::Sha1>(), &data),
            "3" => self.private.decrypt(Oaep::new::<Sha256>(), &data),
            other => {
                return Err(Error::Crypto(format!(
                    "an organisation key of type {other}: types 3 and 4 (RSA-OAEP) are read"
                )))
            }
        }
        .map_err(|_| {
            Error::Crypto("the organisation key does not open with this account's".into())
        })?;
        SymmetricKey::from_bytes(&plain)
    }
}

/// A key encrypted for someone's public key — what an owner's client does when it
/// confirms a member. Type 4, as the clients write it.
pub fn seal(public_b64: &str, key: &SymmetricKey) -> Result<String> {
    let der = B64
        .decode(public_b64)
        .map_err(|e| Error::Crypto(format!("public key: {e}")))?;
    let public = RsaPublicKey::from_public_key_der(&der)
        .map_err(|e| Error::Crypto(format!("public key: {e}")))?;
    let data = public
        .encrypt(
            &mut rand::rngs::OsRng,
            Oaep::new::<sha1::Sha1>(),
            &key.to_bytes(),
        )
        .map_err(|e| Error::Crypto(format!("RSA: {e}")))?;
    Ok(format!("4.{}", B64.encode(data)))
}

/// A time-based one-time code (RFC 6238: SHA-1, six digits, thirty seconds), from a
/// base32 secret — the second factor the emergency vault's account holds.
pub fn totp(secret_b32: &str, unix: u64) -> Result<String> {
    let key = base32_decode(secret_b32)
        .ok_or_else(|| Error::Crypto("the TOTP secret is not base32".into()))?;
    let counter = (unix / 30).to_be_bytes();
    let mut m = <Hmac<sha1::Sha1> as Mac>::new_from_slice(&key)
        .map_err(|e| Error::Crypto(e.to_string()))?;
    m.update(&counter);
    let h = m.finalize().into_bytes();
    let at = usize::from(h[19] & 0x0f);
    let code = u32::from_be_bytes([h[at] & 0x7f, h[at + 1], h[at + 2], h[at + 3]]) % 1_000_000;
    Ok(format!("{code:06}"))
}

/// A new TOTP secret: twenty random bytes, the length Vaultwarden requires.
pub fn totp_secret() -> String {
    let mut b = [0u8; 20];
    rand::rngs::OsRng.fill_bytes(&mut b);
    base32_encode(&b)
}

const B32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

fn base32_encode(data: &[u8]) -> String {
    let mut out = String::new();
    let (mut buf, mut bits) = (0u32, 0u32);
    for &b in data {
        buf = (buf << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(B32[((buf >> bits) & 31) as usize]));
        }
    }
    if bits > 0 {
        out.push(char::from(B32[((buf << (5 - bits)) & 31) as usize]));
    }
    out
}

fn base32_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let (mut buf, mut bits) = (0u32, 0u32);
    for c in s.trim_end_matches('=').bytes() {
        let v = B32.iter().position(|&x| x == c.to_ascii_uppercase())? as u32;
        buf = (buf << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xff) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_value_round_trips_and_an_altered_one_is_refused() {
        let k = SymmetricKey::generate();
        let e = k.encrypt_str("hunter2 — é");
        assert!(e.starts_with("2."), "{e}");
        assert_eq!(k.decrypt_str(&e).expect("decrypted"), "hunter2 — é");
        let other = SymmetricKey::generate();
        assert!(other.decrypt_str(&e).is_err(), "another key's MAC fails");
        // One bit of the data changed: the MAC catches it before AES does.
        let parts: Vec<&str> = e[2..].split('|').collect();
        let mut data = B64.decode(parts[1]).expect("b64");
        data[0] ^= 1;
        let altered = format!("2.{}|{}|{}", parts[0], B64.encode(data), parts[2]);
        assert!(k
            .decrypt(&altered)
            .expect_err("refused")
            .to_string()
            .contains("MAC"));
    }

    #[test]
    fn the_master_key_is_the_documented_derivation() {
        // Computed apart, with Python's hashlib, from the derivation as Bitwarden
        // documents it: the address trimmed and lower-cased, 600 000 rounds, then one
        // round over the password for the hash, HKDF-Expand for the stretched key. That
        // the server accepts the hash is `tests/live_emergency.rs`'s to prove.
        let k = MasterKey::derive(
            "asdfasdf",
            "Test@Example.com ",
            Kdf::Pbkdf2 {
                iterations: 600_000,
            },
        )
        .expect("derived");
        assert_eq!(
            B64.encode(k.0),
            "Acu/x2BCCyj5TSNPP/UDst2yTzwdgjmThgxnc+whLlk="
        );
        assert_eq!(
            k.password_hash("asdfasdf"),
            "pYxuu49a01CyyBBY0rubjt7fMHpDRJFDAIT9UpBigzQ="
        );
        assert_eq!(
            B64.encode(k.stretch().expect("stretched").to_bytes()),
            "tmrHhcFyLx95RWkWdebvdZugJVqky1PBT3lmiKLElvG2EnC8TBlAixh3NyJu8X0TSUeeNLwHbkf2IiyiE6Raxg=="
        );
    }

    #[test]
    fn an_organisation_key_sealed_for_an_account_opens_with_it_only() {
        let pair = KeyPair::generate().expect("pair");
        let org = SymmetricKey::generate();
        let sealed = seal(&pair.public().expect("public"), &org).expect("sealed");
        assert!(sealed.starts_with("4."));
        assert_eq!(pair.open(&sealed).expect("opened"), org);
        let user = SymmetricKey::generate();
        let wrapped = pair.wrap(&user).expect("wrapped");
        let back = KeyPair::unwrap(&wrapped, &user).expect("unwrapped");
        assert_eq!(back.open(&sealed).expect("opened"), org);
        assert!(KeyPair::generate().expect("pair").open(&sealed).is_err());
    }

    #[test]
    fn a_totp_code_is_rfc_6238s() {
        // RFC 6238, appendix B: the SHA-1 secret "12345678901234567890", eight digits
        // there, the last six here.
        let secret = base32_encode(b"12345678901234567890");
        assert_eq!(secret, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
        assert_eq!(totp(&secret, 59).expect("code"), "287082");
        assert_eq!(totp(&secret, 1_111_111_109).expect("code"), "081804");
        assert_eq!(totp_secret().len(), 32, "twenty bytes");
    }
}
