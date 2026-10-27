//! The nodes' key: ed25519, generated in memory and written in OpenSSH's own format.
//!
//! 🔴 Never a file. `ssh-keygen` writes the private half to disk before anything can
//! read it, and the controller's image has no `ssh-keygen` besides: the pair is drawn
//! here, kept encrypted in the vault, and handed to Termix and the emergency vault as
//! text. What the nodes receive is the PUBLIC line only.
//!
//! The format is `openssh-key-v1`, unencrypted — the vault is what encrypts it — as
//! `ssh-keygen -N ''` writes it (PROTOCOL.key in OpenSSH's sources): Termix's `ssh2`
//! and `ssh-keygen -y` both read it back, which the tests hold.

use base64::Engine as _;
use rand::RngCore as _;
use sha2::Digest as _;

use crate::{Error, Result};

const MAGIC: &[u8] = b"openssh-key-v1\0";
const KEY_TYPE: &str = "ssh-ed25519";
const BEGIN: &str = "-----BEGIN OPENSSH PRIVATE KEY-----";
const END: &str = "-----END OPENSSH PRIVATE KEY-----";

/// An ed25519 pair. Its `Debug` never shows the private half.
#[derive(Clone, PartialEq, Eq)]
pub struct NodeKey {
    seed: [u8; 32],
    public: [u8; 32],
    comment: String,
}

impl std::fmt::Debug for NodeKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeKey")
            .field("public", &self.public_body())
            .field("comment", &self.comment)
            .finish_non_exhaustive()
    }
}

impl NodeKey {
    pub fn generate(comment: &str) -> Self {
        let mut seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        Self::from_seed(seed, comment)
    }

    fn from_seed(seed: [u8; 32], comment: &str) -> Self {
        let public = ed25519_dalek::SigningKey::from_bytes(&seed)
            .verifying_key()
            .to_bytes();
        Self {
            seed,
            public,
            comment: comment.to_string(),
        }
    }

    /// The public key's wire blob: the type, then the 32 bytes, each length-prefixed.
    fn blob(&self) -> Vec<u8> {
        let mut b = Vec::new();
        put_string(&mut b, KEY_TYPE.as_bytes());
        put_string(&mut b, &self.public);
        b
    }

    /// `ssh-ed25519 AAAA…`, without the comment — what Termix answers for a credential,
    /// and what two keys are compared by.
    pub fn public_body(&self) -> String {
        format!("{KEY_TYPE} {}", b64(&self.blob()))
    }

    /// The `authorized_keys` key, comment included.
    pub fn public_line(&self) -> String {
        format!("{} {}", self.public_body(), self.comment)
    }

    /// As `ssh-keygen -l` prints it, so a person can compare the two.
    pub fn fingerprint(&self) -> String {
        let digest = sha2::Sha256::digest(self.blob());
        format!(
            "SHA256:{}",
            base64::engine::general_purpose::STANDARD_NO_PAD.encode(digest)
        )
    }

    /// The private key as `ssh-keygen -N ''` writes it.
    pub fn openssh_private(&self) -> String {
        let mut private = Vec::new();
        // Two equal words: a reader that decrypted with the wrong passphrase finds
        // them different. Unencrypted, they only have to match.
        let check = rand::rngs::OsRng.next_u32().to_be_bytes();
        private.extend_from_slice(&check);
        private.extend_from_slice(&check);
        put_string(&mut private, KEY_TYPE.as_bytes());
        put_string(&mut private, &self.public);
        let mut secret = self.seed.to_vec();
        secret.extend_from_slice(&self.public);
        put_string(&mut private, &secret);
        put_string(&mut private, self.comment.as_bytes());
        // Padded to the cipher's block, 8 for "none", with 1, 2, 3… — a reader checks
        // the padding's bytes, not only its length.
        let mut pad = 1u8;
        while private.len() % 8 != 0 {
            private.push(pad);
            pad += 1;
        }

        let mut whole = MAGIC.to_vec();
        put_string(&mut whole, b"none");
        put_string(&mut whole, b"none");
        put_string(&mut whole, b"");
        whole.extend_from_slice(&1u32.to_be_bytes());
        put_string(&mut whole, &self.blob());
        put_string(&mut whole, &private);

        let text = b64(&whole);
        let mut out = String::from(BEGIN);
        out.push('\n');
        // 70 columns, as OpenSSH wraps it: some readers refuse a single long line.
        for chunk in text.as_bytes().chunks(70) {
            out.push_str(&String::from_utf8_lossy(chunk));
            out.push('\n');
        }
        out.push_str(END);
        out.push('\n');
        out
    }

    /// Reads back what [`Self::openssh_private`] wrote — or `ssh-keygen` did, for an
    /// unencrypted ed25519 key.
    pub fn from_openssh(text: &str) -> Result<Self> {
        let bad = |why: &str| Error::Key(why.to_string());
        let body: String = text
            .lines()
            .map(str::trim)
            .skip_while(|l| *l != BEGIN)
            .skip(1)
            .take_while(|l| *l != END)
            .collect();
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(body.as_bytes())
            .map_err(|_| bad("not an OpenSSH private key"))?;
        let rest = bytes
            .strip_prefix(MAGIC)
            .ok_or_else(|| bad("not an OpenSSH private key"))?;
        let mut r = Reader(rest);
        if r.string()? != b"none" || r.string()? != b"none" {
            return Err(bad("an encrypted key: the vault holds it unencrypted"));
        }
        r.string()?;
        if r.u32()? != 1 {
            return Err(bad("more than one key"));
        }
        r.string()?;
        let mut p = Reader(r.string()?);
        if p.u32()? != p.u32()? {
            return Err(bad("its check words differ"));
        }
        if p.string()? != KEY_TYPE.as_bytes() {
            return Err(bad("not an ed25519 key"));
        }
        let public: [u8; 32] = p
            .string()?
            .try_into()
            .map_err(|_| bad("a public half of the wrong length"))?;
        let secret = p.string()?;
        let seed: [u8; 32] = secret
            .get(..32)
            .and_then(|s| s.try_into().ok())
            .ok_or_else(|| bad("a private half of the wrong length"))?;
        let comment = String::from_utf8_lossy(p.string()?).into_owned();
        let key = Self::from_seed(seed, &comment);
        if key.public != public {
            return Err(bad("its two halves do not match"));
        }
        Ok(key)
    }
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn put_string(out: &mut Vec<u8>, s: &[u8]) {
    out.extend_from_slice(&u32::try_from(s.len()).unwrap_or(u32::MAX).to_be_bytes());
    out.extend_from_slice(s);
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.0.len() < n {
            return Err(Error::Key("a truncated key".into()));
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Ok(head)
    }

    fn u32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn string(&mut self) -> Result<&'a [u8]> {
        let n = self.u32()? as usize;
        self.take(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_reads_back_whole() {
        let k = NodeKey::generate("homelabus-termix");
        let back = NodeKey::from_openssh(&k.openssh_private()).expect("read back");
        assert_eq!(back, k);
        assert_eq!(back.comment, "homelabus-termix");
    }

    #[test]
    fn the_private_half_never_shows_in_debug() {
        let k = NodeKey::generate("c");
        let pem = k.openssh_private();
        let body: String = pem
            .lines()
            .nth(2)
            .expect("a line")
            .chars()
            .take(20)
            .collect();
        assert!(!format!("{k:?}").contains(&body));
    }

    #[test]
    fn its_lines_are_wrapped_as_openssh_wraps_them() {
        let pem = NodeKey::generate("c").openssh_private();
        let lines: Vec<&str> = pem.lines().collect();
        assert_eq!(lines.first(), Some(&BEGIN));
        assert_eq!(lines.last(), Some(&END));
        assert!(lines[1..lines.len() - 1].iter().all(|l| l.len() <= 70));
        assert!(
            pem.ends_with('\n'),
            "ssh refuses a key with no final newline"
        );
    }

    #[test]
    fn a_key_whose_halves_differ_is_refused() {
        let k = NodeKey::generate("c");
        let other = NodeKey::generate("c");
        let forged = NodeKey {
            public: other.public,
            ..k
        };
        assert!(NodeKey::from_openssh(&forged.openssh_private()).is_err());
    }

    #[test]
    fn garbage_is_refused_not_panicked_on() {
        for t in ["", "hello", &format!("{BEGIN}\nAAAA\n{END}\n")] {
            assert!(NodeKey::from_openssh(t).is_err(), "{t:?}");
        }
    }
}
