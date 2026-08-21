//! The secret vault.
//!
//! Two principles govern this module:
//!
//! 1. **No password is ever typed by a human.** They are randomly generated, stored
//!    encrypted, and injected into services. Nobody needs to know them, so nobody
//!    reuses them elsewhere.
//!
//! 2. **The master key is the only secret whose loss is final.** Without it no backup
//!    can be decrypted. It must exist as two offline copies.
//!
//! Encryption at rest uses `age` (X25519 + ChaCha20-Poly1305). The key file is
//! protected by POSIX permissions; the real defence against a stolen machine is disk
//! encryption (LUKS), not this file.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use age::secrecy::ExposeSecret;
use age::x25519::{Identity, Recipient};
use rand::Rng;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("reading/writing {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error(
        "master key missing: {0}\n  -> `hlb secrets init` creates one, \
             but anything already encrypted would then be unrecoverable"
    )]
    MissingKey(PathBuf),

    #[error("master key is unreadable: {0}")]
    MalformedKey(String),

    #[error("encryption: {0}")]
    Encrypt(String),

    #[error("cannot decrypt - wrong master key? ({0})")]
    Decrypt(String),

    #[error("secret \"{0}\" is not valid UTF-8")]
    NotUtf8(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// The vault: an `age` identity held in memory.
pub struct Vault {
    identity: Identity,
    recipient: Recipient,
}

/// `Debug` is redacted, deliberately.
///
/// A `#[derive(Debug)]` would leak the master key into the first `dbg!`, the first
/// trace or the first panic message. Only the **public** key is shown: that one is
/// safe to share.
impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault")
            .field("public_key", &self.recipient.to_string())
            .field("identity", &"<redacted>")
            .finish()
    }
}

impl Vault {
    /// Creates a new master key and writes it to disk as 0600.
    ///
    /// Refuses to overwrite an existing key: doing so would make everything already
    /// encrypted unrecoverable, backups included.
    pub fn init(key_path: impl AsRef<Path>) -> Result<Self> {
        let path = key_path.as_ref();

        if path.exists() {
            return Err(Error::Io {
                path: path.to_path_buf(),
                source: std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    "a master key already exists - overwriting it would make every \
                     existing secret and backup unrecoverable",
                ),
            });
        }

        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|source| Error::Io {
                path: dir.to_path_buf(),
                source,
            })?;
        }

        let identity = Identity::generate();
        write_private(path, identity.to_string().expose_secret())?;

        let recipient = identity.to_public();
        Ok(Self {
            identity,
            recipient,
        })
    }

    /// Loads an existing master key.
    pub fn open(key_path: impl AsRef<Path>) -> Result<Self> {
        let path = key_path.as_ref();
        if !path.exists() {
            return Err(Error::MissingKey(path.to_path_buf()));
        }

        let raw = std::fs::read_to_string(path).map_err(|source| Error::Io {
            path: path.to_path_buf(),
            source,
        })?;

        // Comments are skipped: `age` key files often carry them.
        let line = raw
            .lines()
            .map(str::trim)
            .find(|l| !l.is_empty() && !l.starts_with('#'))
            .ok_or_else(|| Error::MalformedKey("empty file".into()))?;

        let identity: Identity = line
            .parse()
            .map_err(|e: &str| Error::MalformedKey(e.to_string()))?;

        let recipient = identity.to_public();
        Ok(Self {
            identity,
            recipient,
        })
    }

    /// Opens the key if it exists, creates it otherwise.
    pub fn open_or_init(key_path: impl AsRef<Path>) -> Result<Self> {
        let path = key_path.as_ref();
        if path.exists() {
            Self::open(path)
        } else {
            Self::init(path)
        }
    }

    pub fn encrypt(&self, plaintext: &str) -> Result<Vec<u8>> {
        let encryptor = age::Encryptor::with_recipients([&self.recipient as _].into_iter())
            .map_err(|e| Error::Encrypt(e.to_string()))?;

        let mut out = Vec::new();
        let mut writer = encryptor
            .wrap_output(&mut out)
            .map_err(|e| Error::Encrypt(e.to_string()))?;
        writer
            .write_all(plaintext.as_bytes())
            .map_err(|e| Error::Encrypt(e.to_string()))?;
        writer.finish().map_err(|e| Error::Encrypt(e.to_string()))?;

        Ok(out)
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<String> {
        let decryptor =
            age::Decryptor::new(ciphertext).map_err(|e| Error::Decrypt(e.to_string()))?;

        let mut reader = decryptor
            .decrypt(std::iter::once(&self.identity as &dyn age::Identity))
            .map_err(|e| Error::Decrypt(e.to_string()))?;

        let mut buf = Vec::new();
        reader
            .read_to_end(&mut buf)
            .map_err(|e| Error::Decrypt(e.to_string()))?;

        String::from_utf8(buf).map_err(|_| Error::NotUtf8("<secret>".into()))
    }

    /// The public key: safe to display and to back up.
    pub fn public_key(&self) -> String {
        self.recipient.to_string()
    }
}

/// Alphabet deliberately free of special characters.
///
/// These passwords end up in connection URLs (`postgres://user:pass@...`), config
/// files and environment variables. An `@`, a `:` or a `/` breaks parsing there in
/// subtle ways. Length more than compensates: 32 characters over this alphabet is
/// about 190 bits of entropy.
const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

pub const DEFAULT_PASSWORD_LEN: usize = 32;

/// Generates a password using the system's cryptographic generator.
pub fn generate_password(len: usize) -> String {
    let mut rng = rand::rng();
    (0..len)
        .map(|_| ALPHABET[rng.random_range(0..ALPHABET.len())] as char)
        .collect()
}

/// Fills a buffer using the system's cryptographic generator.
///
/// 🔴 `rand::rng()` rather than a clock-seeded generator: a predictable access token
/// would be the shortest link in the whole chain, and the mistake would never show -
/// the values look random either way.
pub fn fill_random(buf: &mut [u8]) {
    use rand::RngCore as _;
    rand::rng().fill_bytes(buf);
}

fn write_private(path: &Path, contents: &str) -> Result<()> {
    let body = format!(
        "# Homelabus master key - DO NOT SHARE, DO NOT COMMIT.\n\
         # Losing it makes EVERY secret and EVERY backup unrecoverable.\n\
         # Keep two offline copies.\n\
         {contents}\n"
    );

    std::fs::write(path, body).map_err(|source| Error::Io {
        path: path.to_path_buf(),
        source,
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(
            |source| Error::Io {
                path: path.to_path_buf(),
                source,
            },
        )?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> tempfile::TempDir {
        tempfile::tempdir().expect("temp dir")
    }

    #[test]
    fn roundtrip() {
        let d = tmp();
        let v = Vault::init(d.path().join("master.key")).expect("init");
        let secret = "a-very-secret-password";
        let ct = v.encrypt(secret).expect("encryption");

        assert!(!ct.is_empty());
        assert!(
            !ct.windows(secret.len()).any(|w| w == secret.as_bytes()),
            "plaintext must not appear in the ciphertext"
        );
        assert_eq!(v.decrypt(&ct).expect("decryption"), secret);
    }

    #[test]
    fn key_survives_a_reopen() {
        let d = tmp();
        let path = d.path().join("master.key");

        let ct = Vault::init(&path)
            .expect("init")
            .encrypt("value")
            .expect("encryption");
        let reopened = Vault::open(&path).expect("reopen");

        assert_eq!(reopened.decrypt(&ct).expect("decryption"), "value");
    }

    #[test]
    fn another_key_cannot_decrypt() {
        let d = tmp();
        let a = Vault::init(d.path().join("a.key")).expect("init a");
        let b = Vault::init(d.path().join("b.key")).expect("init b");

        let ct = a.encrypt("secret").expect("encryption");
        let err = b.decrypt(&ct).unwrap_err();
        assert!(matches!(err, Error::Decrypt(_)), "{err}");
    }

    #[test]
    fn init_refuses_to_overwrite() {
        // Overwriting a master key would make the backups unrecoverable.
        let d = tmp();
        let path = d.path().join("master.key");
        Vault::init(&path).expect("first init");

        let err = Vault::init(&path).unwrap_err();
        assert!(err.to_string().contains("already exists"), "{err}");
    }

    #[test]
    fn open_reports_a_missing_key_clearly() {
        let d = tmp();
        let err = Vault::open(d.path().join("missing.key")).unwrap_err();
        assert!(matches!(err, Error::MissingKey(_)), "{err}");
    }

    #[test]
    fn open_or_init_is_idempotent() {
        let d = tmp();
        let path = d.path().join("master.key");

        let first = Vault::open_or_init(&path).expect("creation").public_key();
        let second = Vault::open_or_init(&path).expect("reopen").public_key();

        assert_eq!(first, second, "the key must not be regenerated");
    }

    #[cfg(unix)]
    #[test]
    fn key_file_is_not_world_readable() {
        use std::os::unix::fs::PermissionsExt;
        let d = tmp();
        let path = d.path().join("master.key");
        Vault::init(&path).expect("init");

        let mode = std::fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0, "no access for group or others");
    }

    #[test]
    fn debug_never_leaks_the_private_key() {
        let d = tmp();
        let path = d.path().join("master.key");
        let v = Vault::init(&path).expect("init");

        let private = std::fs::read_to_string(&path)
            .expect("read")
            .lines()
            .find(|l| l.starts_with("AGE-SECRET-KEY"))
            .expect("private key present")
            .to_string();

        let debug = format!("{v:?}");
        assert!(!debug.contains(&private), "the private key leaked: {debug}");
        assert!(debug.contains("<redacted>"));
        assert!(debug.contains(&v.public_key()));
    }

    #[test]
    fn passwords_are_url_safe() {
        // These end up in connection URLs, where an `@` or a `/` would break parsing.
        for _ in 0..100 {
            let p = generate_password(DEFAULT_PASSWORD_LEN);
            assert_eq!(p.len(), DEFAULT_PASSWORD_LEN);
            assert!(
                p.chars().all(|c| c.is_ascii_alphanumeric()),
                "unexpected character in {p}"
            );
        }
    }

    #[test]
    fn passwords_are_not_repeated() {
        let a = generate_password(DEFAULT_PASSWORD_LEN);
        let b = generate_password(DEFAULT_PASSWORD_LEN);
        assert_ne!(a, b);
    }

    #[test]
    fn public_key_is_stable_and_shareable() {
        let d = tmp();
        let v = Vault::init(d.path().join("master.key")).expect("init");
        let pk = v.public_key();
        assert!(pk.starts_with("age1"), "unexpected public key: {pk}");
        assert_eq!(pk, v.public_key());
    }
}
