//! The internal certificate authority for agent ↔ controller mTLS.
//!
//! ## What this replaces
//!
//! The agent's API was plain HTTP, protected only by the Swarm overlay's encryption.
//! That assumes **everything on the overlay is trusted** - and any compromised
//! container is on it too. An infected Gitea could query every agent in the fleet and
//! map the cluster's disks.
//!
//! mTLS settles both directions at once:
//!
//! - the agent accepts only clients presenting a certificate signed by our CA;
//! - the controller checks it is talking to an agent, not to an impostor that took its
//!   place in the overlay's DNS.
//!
//! ## 🔴 Why `openssl` rather than a Rust library
//!
//! Same reasoning as for `ssh-keygen`: X.509 is a format where an encoding mistake
//! produces a certificate the tools accept and the TLS stack rejects - or worse, the
//! reverse. `openssl` is present on every machine running a server, and delegating to
//! it avoids adding a dependency whose output would be poorly audited.
//!
//! ## What is NOT handled here, and why that is said
//!
//! There is **no revocation** (no CRL, no OCSP). On a fleet of a few machines, a CRL
//! that has to be distributed and refreshed adds a mechanism that fails silently;
//! **short** certificates that get renewed are preferred. Removing a node from the
//! fleet means revoking its SSH access and taking it out of the Swarm, not hoping a
//! revocation list reached everywhere.

use std::path::Path;

use crate::Error;

type Result<T> = std::result::Result<T, Error>;

/// The CA's lifetime, in days.
///
/// **Deliberately** long: replacing it means redeploying every certificate in the fleet
/// at once. A CA expiring after a year turns a silent failure into a total one, one
/// morning, with nobody having changed anything.
pub const CA_DAYS: u32 = 3650;

/// The lifetime of leaf certificates.
///
/// **Deliberately** short: this is what replaces revocation. A stolen certificate stops
/// being useful on its own, and automatic renewal is exercised often enough that we
/// know it works - instead of finding out on the day it has been broken for six
/// months.
pub const LEAF_DAYS: u32 = 90;

/// A certificate + private key pair, in PEM format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertPair {
    pub cert_pem: String,
    pub key_pem: String,
}

impl CertPair {
    /// Does the certificate really keep its private key separate?
    ///
    /// 🔴 A guard against the most expensive mistake in this area: pasting the private
    /// key into the certificate file, which is handed to everyone.
    pub fn looks_valid(&self) -> bool {
        self.cert_pem.contains("BEGIN CERTIFICATE")
            && !self.cert_pem.contains("PRIVATE KEY")
            && self.key_pem.contains("PRIVATE KEY")
    }
}

/// The role the certificate authorises.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    /// The agent, presenting its certificate to clients.
    Server,
    /// The controller, proving its identity to the agent.
    Client,
}

impl Purpose {
    /// The matching extended key usage extension.
    ///
    /// ⚠️ It is not decorative: a TLS stack refuses a server certificate presented as a
    /// client one, and the reverse. A certificate with no `extendedKeyUsage` passes
    /// with some clients and not others - so it works in testing and fails in
    /// production.
    fn ext_key_usage(&self) -> &'static str {
        match self {
            Self::Server => "serverAuth",
            Self::Client => "clientAuth",
        }
    }
}

/// Generates the cluster's certificate authority.
pub async fn generate_ca(common_name: &str) -> Result<CertPair> {
    let dir = tempdir()?;
    let key = dir.path().join("ca.key");
    let crt = dir.path().join("ca.crt");

    openssl(&[
        "req",
        "-x509",
        "-newkey",
        "ed25519",
        // No passphrase: the key is protected by the vault, and an interactive prompt
        // would block every automation.
        "-nodes",
        "-keyout",
        &key.to_string_lossy(),
        "-out",
        &crt.to_string_lossy(),
        "-days",
        &CA_DAYS.to_string(),
        "-subj",
        &format!("/CN={common_name}"),
        // `critical`: a client that does not understand this extension must REFUSE,
        // not ignore it. Without that, a leaf certificate could sign others.
        "-addext",
        "basicConstraints=critical,CA:TRUE,pathlen:0",
        "-addext",
        "keyUsage=critical,keyCertSign,cRLSign",
    ])
    .await?;

    lire_paire(&crt, &key).await
}

/// Issues a certificate signed by the CA.
///
/// `names` lists the names the bearer will be reached under. For an agent, that is its
/// hostname **and** the overlay's DNS entry.
pub async fn issue(
    ca: &CertPair,
    common_name: &str,
    names: &[String],
    purpose: Purpose,
) -> Result<CertPair> {
    let dir = tempdir()?;
    let ca_crt = dir.path().join("ca.crt");
    let ca_key = dir.path().join("ca.key");
    let key = dir.path().join("leaf.key");
    let csr = dir.path().join("leaf.csr");
    let crt = dir.path().join("leaf.crt");
    let ext = dir.path().join("leaf.ext");

    ecrire(&ca_crt, &ca.cert_pem).await?;
    ecrire(&ca_key, &ca.key_pem).await?;
    ecrire(&ext, &extensions(names, purpose)).await?;

    openssl(&[
        "req",
        "-new",
        "-newkey",
        "ed25519",
        "-nodes",
        "-keyout",
        &key.to_string_lossy(),
        "-out",
        &csr.to_string_lossy(),
        "-subj",
        &format!("/CN={common_name}"),
    ])
    .await?;

    openssl(&[
        "x509",
        "-req",
        "-in",
        &csr.to_string_lossy(),
        "-CA",
        &ca_crt.to_string_lossy(),
        "-CAkey",
        &ca_key.to_string_lossy(),
        "-CAcreateserial",
        "-out",
        &crt.to_string_lossy(),
        "-days",
        &LEAF_DAYS.to_string(),
        "-extfile",
        &ext.to_string_lossy(),
    ])
    .await?;

    lire_paire(&crt, &key).await
}

/// The extensions file passed to the signing step.
///
/// 🔴 **`subjectAltName` is mandatory, `CN` is not.** Every modern TLS stack has
/// ignored the Common Name for years: a certificate with no SAN is rejected with a
/// message about a hostname, which sends you hunting for a DNS problem for hours.
pub fn extensions(names: &[String], purpose: Purpose) -> String {
    let san: Vec<String> = names
        .iter()
        .enumerate()
        .map(|(i, n)| {
            // An IP must be declared as `IP:`, not `DNS:`: declared as DNS it never
            // matches, and the error does not say why.
            if n.parse::<std::net::IpAddr>().is_ok() {
                format!("IP.{} = {n}", i + 1)
            } else {
                format!("DNS.{} = {n}", i + 1)
            }
        })
        .collect();

    format!(
        "basicConstraints = critical,CA:FALSE\n\
         keyUsage = critical,digitalSignature,keyEncipherment\n\
         extendedKeyUsage = {}\n\
         subjectAltName = @noms\n\
         \n\
         [noms]\n\
         {}\n",
        purpose.ext_key_usage(),
        san.join("\n")
    )
}

/// The names an agent must be reachable under.
///
/// ⚠️ The `tasks.<service>` entry is essential: it is how the controller queries
/// **each** task rather than the VIP. A certificate lacking it fails every connection
/// with a name error, even though the hostname is correct.
pub fn agent_names(hostname: &str, service: &str) -> Vec<String> {
    let mut v = vec![
        hostname.to_string(),
        service.to_string(),
        format!("tasks.{service}"),
        // The controller sometimes connects to the resolved address rather than the name.
        "localhost".to_string(),
    ];
    v.dedup();
    v
}

async fn openssl(args: &[&str]) -> Result<String> {
    let out = tokio::process::Command::new("openssl")
        .args(args)
        .output()
        .await
        .map_err(|e| Error::Pki(format!("openssl introuvable : {e}")))?;

    if !out.status.success() {
        return Err(Error::Pki(format!(
            "openssl {} : {}",
            args.first().unwrap_or(&""),
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

fn tempdir() -> Result<tempfile::TempDir> {
    tempfile::tempdir().map_err(|e| Error::Pki(format!("temporary directory: {e}")))
}

async fn ecrire(p: &Path, contenu: &str) -> Result<()> {
    tokio::fs::write(p, contenu)
        .await
        .map_err(|e| Error::Pki(format!("writing {}: {e}", p.display())))
}

async fn lire_paire(crt: &Path, key: &Path) -> Result<CertPair> {
    let cert_pem = tokio::fs::read_to_string(crt)
        .await
        .map_err(|e| Error::Pki(format!("lecture du certificat : {e}")))?;
    let key_pem = tokio::fs::read_to_string(key)
        .await
        .map_err(|e| Error::Pki(format!("reading the key: {e}")))?;

    let p = CertPair { cert_pem, key_pem };
    if !p.looks_valid() {
        return Err(Error::Pki(
            "openssl produced an unexpected pair - private key inside the certificate?".into(),
        ));
    }
    Ok(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_server_and_a_client_are_not_interchangeable() {
        // ⚠️ A TLS stack refuses a server certificate presented as a client one.
        // Without extendedKeyUsage it works with some clients and not others - so in
        // testing and not in production.
        let s = extensions(&["agent".into()], Purpose::Server);
        let c = extensions(&["controller".into()], Purpose::Client);

        assert!(s.contains("extendedKeyUsage = serverAuth"), "{s}");
        assert!(c.contains("extendedKeyUsage = clientAuth"), "{c}");
        assert_ne!(s, c);
    }

    #[test]
    fn a_leaf_can_never_sign_other_certificates() {
        // 🔴 `CA:FALSE` en critique : un certificat de feuille qui pourrait signer
        // transformerait la compromission d'un seul agent en compromission du parc.
        let e = extensions(&["x".into()], Purpose::Server);
        assert!(e.contains("basicConstraints = critical,CA:FALSE"), "{e}");
    }

    #[test]
    fn names_are_declared_as_subject_alt_names() {
        // 🔴 The CN is ignored by every modern TLS stack. A certificate with no SAN
        // fails on a hostname error, which sends you hunting for a DNS problem for
        // hours.
        let e = extensions(&["node1".into(), "tasks.hlb-agent".into()], Purpose::Server);
        assert!(e.contains("subjectAltName = @noms"), "{e}");
        assert!(e.contains("DNS.1 = node1"), "{e}");
        assert!(e.contains("DNS.2 = tasks.hlb-agent"), "{e}");
    }

    #[test]
    fn an_ip_is_declared_as_an_ip_not_a_dns_name() {
        // An IP declared as DNS never matches, and the error message does not say
        // why.
        let e = extensions(&["10.42.0.2".into(), "node1".into()], Purpose::Server);
        assert!(e.contains("IP.1 = 10.42.0.2"), "{e}");
        assert!(e.contains("DNS.2 = node1"), "{e}");
        assert!(!e.contains("DNS.1 = 10.42.0.2"), "{e}");
    }

    #[test]
    fn an_agent_is_reachable_by_its_overlay_name() {
        // ⚠️ `tasks.<service>` is the name by which the controller reaches EVERY task.
        // Without it on the certificate, every connection fails.
        let n = agent_names("node1", "hlb-agent");
        assert!(n.contains(&"tasks.hlb-agent".to_string()), "{n:?}");
        assert!(n.contains(&"node1".to_string()));
        assert!(n.contains(&"hlb-agent".to_string()));
    }

    #[test]
    fn a_private_key_inside_a_certificate_is_refused() {
        // 🔴 The most expensive mistake in this area: the certificate is handed to
        // everyone, so the private key must never be in it.
        let mauvais = CertPair {
            cert_pem: "-----BEGIN CERTIFICATE-----\nx\n-----BEGIN PRIVATE KEY-----".into(),
            key_pem: "-----BEGIN PRIVATE KEY-----".into(),
        };
        assert!(!mauvais.looks_valid());

        let bon = CertPair {
            cert_pem: "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----".into(),
            key_pem: "-----BEGIN PRIVATE KEY-----\ny\n-----END PRIVATE KEY-----".into(),
        };
        assert!(bon.looks_valid());
    }

    #[test]
    fn leaves_expire_long_before_the_authority() {
        // The short lifetime REPLACES revocation: a stolen certificate stops being
        // useful on its own. The CA must survive - replacing it means redeploying the
        // whole fleet the same day.
        // `const`: the constraint is checked at COMPILE time, so changing a constant
        // without thinking does not even compile.
        const _: () = assert!(LEAF_DAYS * 10 < CA_DAYS);
        const _: () = assert!(
            LEAF_DAYS >= 30,
            "trop court : le renouvellement deviendrait un fardeau"
        );
    }
}
