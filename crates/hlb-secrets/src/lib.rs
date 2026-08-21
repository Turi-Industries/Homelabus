//! Le coffre de secrets (§9 et §9quater du plan).
//!
//! Deux principes qui gouvernent tout ce module :
//!
//! 1. **Aucun mot de passe n'est jamais saisi par un humain.** Ils sont générés
//!    aléatoirement, stockés chiffrés, et injectés dans les services. Personne n'a
//!    besoin de les connaître, donc personne ne les réutilise ailleurs.
//!
//! 2. **La clé maîtresse est le seul secret dont la perte est définitive.** Sans elle,
//!    aucune sauvegarde n'est déchiffrable. Elle doit exister en deux copies hors
//!    ligne (§9quater).
//!
//! Le chiffrement au repos repose sur `age` (X25519 + ChaCha20-Poly1305). Le fichier
//! de clé est protégé par les permissions POSIX ; la vraie défense contre le vol de
//! machine est le chiffrement du disque (LUKS), pas ce fichier — voir §9quater pour
//! le raisonnement.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use age::secrecy::ExposeSecret;
use age::x25519::{Identity, Recipient};
use rand::Rng;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("lecture/écriture de {path} : {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error(
        "clé maîtresse absente : {0}\n  → `hlb secrets init` la crée, \
             mais toute donnée déjà chiffrée serait alors irrécupérable"
    )]
    MissingKey(PathBuf),

    #[error("clé maîtresse illisible : {0}")]
    MalformedKey(String),

    #[error("chiffrement : {0}")]
    Encrypt(String),

    #[error("déchiffrement impossible — mauvaise clé maîtresse ? ({0})")]
    Decrypt(String),

    #[error("le secret « {0} » n'est pas de l'UTF-8 valide")]
    NotUtf8(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Le coffre : une identité `age` chargée en mémoire.
pub struct Vault {
    identity: Identity,
    recipient: Recipient,
}

/// `Debug` rédigé, à dessein.
///
/// Un `#[derive(Debug)]` ferait fuiter la clé maîtresse dans le premier `dbg!`, la
/// première trace ou le premier message de panique venu. Seule la clé **publique**
/// est affichée : elle est sûre à partager.
impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault")
            .field("public_key", &self.recipient.to_string())
            .field("identity", &"<rédigé>")
            .finish()
    }
}

impl Vault {
    /// Crée une nouvelle clé maîtresse et l'écrit sur disque en 0600.
    ///
    /// Refuse d'écraser une clé existante : le faire rendrait irrécupérable tout ce
    /// qui a déjà été chiffré, y compris les sauvegardes.
    pub fn init(key_path: impl AsRef<Path>) -> Result<Self> {
        let path = key_path.as_ref();

        if path.exists() {
            return Err(Error::Io {
                path: path.to_path_buf(),
                source: std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    "une clé maîtresse existe déjà — l'écraser rendrait tous les \
                     secrets et sauvegardes existants irrécupérables",
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

    /// Charge une clé maîtresse existante.
    pub fn open(key_path: impl AsRef<Path>) -> Result<Self> {
        let path = key_path.as_ref();
        if !path.exists() {
            return Err(Error::MissingKey(path.to_path_buf()));
        }

        let raw = std::fs::read_to_string(path).map_err(|source| Error::Io {
            path: path.to_path_buf(),
            source,
        })?;

        // On ignore les commentaires : les fichiers `age` en contiennent souvent.
        let line = raw
            .lines()
            .map(str::trim)
            .find(|l| !l.is_empty() && !l.starts_with('#'))
            .ok_or_else(|| Error::MalformedKey("fichier vide".into()))?;

        let identity: Identity = line
            .parse()
            .map_err(|e: &str| Error::MalformedKey(e.to_string()))?;

        let recipient = identity.to_public();
        Ok(Self {
            identity,
            recipient,
        })
    }

    /// Ouvre la clé si elle existe, la crée sinon.
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

    /// La clé publique, sûre à afficher et à sauvegarder.
    pub fn public_key(&self) -> String {
        self.recipient.to_string()
    }
}

/// Alphabet volontairement sans caractères spéciaux.
///
/// Ces mots de passe finissent dans des URL de connexion (`postgres://user:pass@…`),
/// des fichiers de configuration et des variables d'environnement. Un `@`, un `:` ou
/// un `/` y casse le parsing de façon subtile. La longueur compense largement :
/// 32 caractères sur cet alphabet valent ~190 bits d'entropie.
const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

pub const DEFAULT_PASSWORD_LEN: usize = 32;

/// Génère un mot de passe avec le générateur cryptographique du système.
pub fn generate_password(len: usize) -> String {
    let mut rng = rand::rng();
    (0..len)
        .map(|_| ALPHABET[rng.random_range(0..ALPHABET.len())] as char)
        .collect()
}

/// Remplit un tampon avec le générateur cryptographique du système.
///
/// 🔴 `rand::rng()` et non un générateur ensemencé sur l'horloge : un jeton d'accès
/// prédictible serait le maillon le plus court de toute la chaîne, et l'erreur ne se
/// verrait jamais — les valeurs paraissent aléatoires dans les deux cas.
pub fn fill_random(buf: &mut [u8]) {
    use rand::RngCore as _;
    rand::rng().fill_bytes(buf);
}

fn write_private(path: &Path, contents: &str) -> Result<()> {
    let body = format!(
        "# Clé maîtresse Homelabus — NE PAS PARTAGER, NE PAS COMMITER.\n\
         # Sa perte rend TOUS les secrets et TOUTES les sauvegardes irrécupérables.\n\
         # Garde deux copies hors ligne (§9quater du plan).\n\
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
        tempfile::tempdir().expect("dossier temporaire")
    }

    #[test]
    fn roundtrip() {
        let d = tmp();
        let v = Vault::init(d.path().join("master.key")).expect("init");
        let secret = "mot-de-passe-très-secret";
        let ct = v.encrypt(secret).expect("chiffrement");

        assert!(!ct.is_empty());
        assert!(
            !ct.windows(secret.len()).any(|w| w == secret.as_bytes()),
            "le clair ne doit pas apparaître dans le chiffré"
        );
        assert_eq!(v.decrypt(&ct).expect("déchiffrement"), secret);
    }

    #[test]
    fn key_survives_a_reopen() {
        let d = tmp();
        let path = d.path().join("master.key");

        let ct = Vault::init(&path)
            .expect("init")
            .encrypt("valeur")
            .expect("chiffrement");
        let reopened = Vault::open(&path).expect("réouverture");

        assert_eq!(reopened.decrypt(&ct).expect("déchiffrement"), "valeur");
    }

    #[test]
    fn another_key_cannot_decrypt() {
        let d = tmp();
        let a = Vault::init(d.path().join("a.key")).expect("init a");
        let b = Vault::init(d.path().join("b.key")).expect("init b");

        let ct = a.encrypt("secret").expect("chiffrement");
        let err = b.decrypt(&ct).unwrap_err();
        assert!(matches!(err, Error::Decrypt(_)), "{err}");
    }

    #[test]
    fn init_refuses_to_overwrite() {
        // Écraser une clé maîtresse rendrait les sauvegardes irrécupérables.
        let d = tmp();
        let path = d.path().join("master.key");
        Vault::init(&path).expect("première init");

        let err = Vault::init(&path).unwrap_err();
        assert!(err.to_string().contains("existe déjà"), "{err}");
    }

    #[test]
    fn open_reports_a_missing_key_clearly() {
        let d = tmp();
        let err = Vault::open(d.path().join("absente.key")).unwrap_err();
        assert!(matches!(err, Error::MissingKey(_)), "{err}");
    }

    #[test]
    fn open_or_init_is_idempotent() {
        let d = tmp();
        let path = d.path().join("master.key");

        let first = Vault::open_or_init(&path).expect("création").public_key();
        let second = Vault::open_or_init(&path)
            .expect("réouverture")
            .public_key();

        assert_eq!(first, second, "la clé ne doit pas être régénérée");
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
        assert_eq!(mode & 0o077, 0, "aucun accès pour le groupe ni les autres");
    }

    #[test]
    fn debug_never_leaks_the_private_key() {
        let d = tmp();
        let path = d.path().join("master.key");
        let v = Vault::init(&path).expect("init");

        let private = std::fs::read_to_string(&path)
            .expect("lecture")
            .lines()
            .find(|l| l.starts_with("AGE-SECRET-KEY"))
            .expect("clé privée présente")
            .to_string();

        let debug = format!("{v:?}");
        assert!(!debug.contains(&private), "la clé privée a fuité : {debug}");
        assert!(debug.contains("<rédigé>"));
        assert!(debug.contains(&v.public_key()));
    }

    #[test]
    fn passwords_are_url_safe() {
        // Ces mots de passe finissent dans des URL de connexion : un `@` ou un `/`
        // y casserait le parsing.
        for _ in 0..100 {
            let p = generate_password(DEFAULT_PASSWORD_LEN);
            assert_eq!(p.len(), DEFAULT_PASSWORD_LEN);
            assert!(
                p.chars().all(|c| c.is_ascii_alphanumeric()),
                "caractère inattendu dans {p}"
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
        assert!(pk.starts_with("age1"), "clé publique inattendue : {pk}");
        assert_eq!(pk, v.public_key());
    }
}
