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
//! **short** certificates that get renewed are preferred — see [`LEAF_DAYS`] for who
//! renews them. Removing a node from the
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
/// being useful on its own, and renewal is exercised often enough that we know it works
/// - instead of finding out on the day it has been broken for six months.
///
/// 🔴 Nothing renewed them until 2026-10-21: on day 91 every agent refused the
/// controller and the whole fleet read "unreachable". The controller renews both
/// leaves [`RENEW_BEFORE_DAYS`] before they end (`hlb_engine::pki`), `hlb pki renew
/// --apply` does it by hand, and one left to end is in the inbox.
pub const LEAF_DAYS: u32 = 90;

/// How long before its end a leaf is issued again.
pub const RENEW_BEFORE_DAYS: u32 = 30;

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

    read_pair(&crt, &key).await
}

/// Generates the root the ingress signs its own certificates under, when no public
/// name reaches the house (`hlb config exposure --internal`).
///
/// ⚠️ Not the cluster's CA: that one is ed25519 with `pathlen:0`. Browsers refuse
/// ed25519 in a TLS chain, and Caddy signs an intermediate under this root, then the
/// sites' certificates under that — a root that may sign no CA would break the chain.
pub async fn generate_web_root(common_name: &str) -> Result<CertPair> {
    let dir = tempdir()?;
    let key = dir.path().join("root.key");
    let crt = dir.path().join("root.crt");
    openssl(&[
        "req",
        "-x509",
        "-newkey",
        "ec",
        "-pkeyopt",
        "ec_paramgen_curve:P-256",
        "-nodes",
        "-keyout",
        &key.to_string_lossy(),
        "-out",
        &crt.to_string_lossy(),
        "-days",
        &CA_DAYS.to_string(),
        "-subj",
        &format!("/CN={common_name}"),
        "-addext",
        "basicConstraints=critical,CA:TRUE,pathlen:1",
        "-addext",
        "keyUsage=critical,keyCertSign,cRLSign",
    ])
    .await?;
    read_pair(&crt, &key).await
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
    issue_with(ca, common_name, names, purpose, &["ed25519"], LEAF_DAYS).await
}

/// A server certificate under [`generate_web_root`]'s root, for a platform service
/// apps reach by its overlay name over TLS — Stalwart's submission port.
///
/// ECDSA P-256, as the root: every TLS stack an app may carry takes it, where ed25519
/// leaves out TLS 1.2. And as long as the root: the name is the overlay's alone, no
/// public authority will ever sign it, and the key lives in the service's own
/// database — a leaf expiring there would stop every app's mail on the same morning.
pub async fn issue_platform_server(root: &CertPair, name: &str) -> Result<CertPair> {
    issue_with(
        root,
        name,
        &[name.to_string()],
        Purpose::Server,
        &["ec", "-pkeyopt", "ec_paramgen_curve:P-256"],
        CA_DAYS,
    )
    .await
}

async fn issue_with(
    ca: &CertPair,
    common_name: &str,
    names: &[String],
    purpose: Purpose,
    key: &[&str],
    days: u32,
) -> Result<CertPair> {
    let dir = tempdir()?;
    let ca_crt = dir.path().join("ca.crt");
    let ca_key = dir.path().join("ca.key");
    let key_out = dir.path().join("leaf.key");
    let csr = dir.path().join("leaf.csr");
    let crt = dir.path().join("leaf.crt");
    let ext = dir.path().join("leaf.ext");

    write(&ca_crt, &ca.cert_pem).await?;
    write(&ca_key, &ca.key_pem).await?;
    write(&ext, &extensions(names, purpose)).await?;

    let key_path = key_out.to_string_lossy();
    let csr_path = csr.to_string_lossy();
    let subject = format!("/CN={common_name}");
    let mut req = vec!["req", "-new", "-newkey"];
    req.extend_from_slice(key);
    req.extend_from_slice(&[
        "-nodes", "-keyout", &key_path, "-out", &csr_path, "-subj", &subject,
    ]);
    openssl(&req).await?;

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
        &days.to_string(),
        "-extfile",
        &ext.to_string_lossy(),
    ])
    .await?;

    read_pair(&crt, &key_out).await
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
         subjectAltName = @names\n\
         \n\
         [names]\n\
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

/// When a certificate ends, in seconds since the epoch: its `notAfter`, read from the
/// DER itself.
///
/// Read here rather than through `openssl`: what it must read is only the one field of
/// a structure the TLS stack has already accepted, and a process per leaf for it every
/// night would buy nothing.
pub fn not_after(cert_pem: &str) -> Result<i64> {
    let bad = |what: &str| Error::Pki(format!("certificate unreadable: {what}"));
    let der = rustls_pemfile::certs(&mut std::io::Cursor::new(cert_pem.as_bytes()))
        .next()
        .ok_or_else(|| bad("no certificate in the PEM"))?
        .map_err(|e| bad(&e.to_string()))?;

    // Certificate ::= SEQUENCE { tbsCertificate SEQUENCE { [0] version OPTIONAL,
    // serialNumber, signature, issuer, validity SEQUENCE { notBefore, notAfter } … } … }
    let (_, cert, _) = der_take(&der).ok_or_else(|| bad("not a DER sequence"))?;
    let (_, tbs, _) = der_take(cert).ok_or_else(|| bad("no tbsCertificate"))?;
    let mut rest = tbs;
    if rest.first() == Some(&0xA0) {
        rest = der_take(rest).ok_or_else(|| bad("version"))?.2;
    }
    for field in ["serial number", "signature", "issuer"] {
        rest = der_take(rest).ok_or_else(|| bad(field))?.2;
    }
    let (_, validity, _) = der_take(rest).ok_or_else(|| bad("validity"))?;
    let after = der_take(validity).ok_or_else(|| bad("notBefore"))?.2;
    let (tag, time, _) = der_take(after).ok_or_else(|| bad("notAfter"))?;
    let text = std::str::from_utf8(time).map_err(|_| bad("notAfter is not text"))?;
    asn1_time(tag, text).ok_or_else(|| bad(&format!("notAfter \"{text}\"")))
}

/// One DER element: its tag, its content, and what follows it.
fn der_take(data: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = data.split_first()?;
    let (&first, mut rest) = rest.split_first()?;
    let len = if first < 0x80 {
        usize::from(first)
    } else {
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 4 || rest.len() < n {
            return None;
        }
        let (bytes, after) = rest.split_at(n);
        rest = after;
        bytes.iter().fold(0usize, |l, b| (l << 8) | usize::from(*b))
    };
    if rest.len() < len {
        return None;
    }
    let (content, after) = rest.split_at(len);
    Some((tag, content, after))
}

/// A UTCTime (`YYMMDDHHMMSSZ`, tag 0x17) or GeneralizedTime (`YYYYMMDDHHMMSSZ`, 0x18).
fn asn1_time(tag: u8, text: &str) -> Option<i64> {
    let digits = text.strip_suffix('Z')?;
    let (year, rest) = match (tag, digits.len()) {
        // RFC 5280: a two-digit year from 50 is 19xx.
        (0x17, 12) => {
            let yy: i64 = digits.get(..2)?.parse().ok()?;
            (
                if yy >= 50 { 1900 + yy } else { 2000 + yy },
                digits.get(2..)?,
            )
        }
        (0x18, 14) => (digits.get(..4)?.parse().ok()?, digits.get(4..)?),
        _ => return None,
    };
    let field = |i: usize| -> Option<i64> { rest.get(i..i + 2)?.parse().ok() };
    let (month, day) = (field(0)?, field(2)?);
    let (hour, minute, second) = (field(4)?, field(6)?, field(8)?);
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    // Days since the epoch of a civil date (Howard Hinnant's algorithm).
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + hour * 3_600 + minute * 60 + second)
}

async fn openssl(args: &[&str]) -> Result<String> {
    let out = tokio::process::Command::new("openssl")
        .args(args)
        .output()
        .await
        .map_err(|e| Error::Pki(format!("openssl not found: {e}")))?;

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

async fn write(p: &Path, content: &str) -> Result<()> {
    tokio::fs::write(p, content)
        .await
        .map_err(|e| Error::Pki(format!("writing {}: {e}", p.display())))
}

async fn read_pair(crt: &Path, key: &Path) -> Result<CertPair> {
    let cert_pem = tokio::fs::read_to_string(crt)
        .await
        .map_err(|e| Error::Pki(format!("reading the certificate: {e}")))?;
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
        // 🔴 `CA:FALSE` marked critical: a leaf certificate able to sign would turn
        // the compromise of a single agent into the compromise of the whole fleet.
        let e = extensions(&["x".into()], Purpose::Server);
        assert!(e.contains("basicConstraints = critical,CA:FALSE"), "{e}");
    }

    #[test]
    fn names_are_declared_as_subject_alt_names() {
        // 🔴 The CN is ignored by every modern TLS stack. A certificate with no SAN
        // fails on a hostname error, which sends you hunting for a DNS problem for
        // hours.
        let e = extensions(&["node1".into(), "tasks.hlb-agent".into()], Purpose::Server);
        assert!(e.contains("subjectAltName = @names"), "{e}");
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
        let bad = CertPair {
            cert_pem: "-----BEGIN CERTIFICATE-----\nx\n-----BEGIN PRIVATE KEY-----".into(),
            key_pem: "-----BEGIN PRIVATE KEY-----".into(),
        };
        assert!(!bad.looks_valid());

        let good = CertPair {
            cert_pem: "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----".into(),
            key_pem: "-----BEGIN PRIVATE KEY-----\ny\n-----END PRIVATE KEY-----".into(),
        };
        assert!(good.looks_valid());
    }

    /// Run through the real `openssl`: what an app's TLS stack checks is the chain and
    /// the name, and both are only proven by a verifier.
    #[tokio::test]
    async fn a_platform_server_certificate_verifies_under_the_root_for_its_name_only() {
        let root = generate_web_root("Homelabus test").await.expect("root");
        let leaf = issue_platform_server(&root, "stalwart")
            .await
            .expect("leaf");
        assert!(leaf.looks_valid());
        let dir = tempdir().expect("tmp");
        let (r, l) = (dir.path().join("root.crt"), dir.path().join("leaf.crt"));
        write(&r, &root.cert_pem).await.expect("write");
        write(&l, &leaf.cert_pem).await.expect("write");
        let (r, l) = (r.to_string_lossy(), l.to_string_lossy());
        let verify = |name: &'static str| {
            let (r, l) = (r.to_string(), l.to_string());
            async move {
                openssl(&["verify", "-CAfile", &r, "-verify_hostname", name, &l])
                    .await
                    .is_ok()
            }
        };
        assert!(verify("stalwart").await, "the name it is issued for");
        assert!(!verify("postgres").await, "and no other");
        let text = openssl(&["x509", "-in", &l, "-noout", "-text"])
            .await
            .expect("x509");
        assert!(text.contains("ecdsa-with-SHA256"), "{text}");
        assert!(text.contains("TLS Web Server Authentication"), "{text}");
    }

    #[tokio::test]
    async fn a_leaf_says_when_it_ends_as_openssl_wrote_it() {
        let ca = generate_ca("Homelabus test").await.expect("CA");
        let leaf = issue(&ca, "controller", &["controller".into()], Purpose::Client)
            .await
            .expect("leaf");
        let dir = tempdir().expect("tmp");
        let path = dir.path().join("leaf.crt");
        write(&path, &leaf.cert_pem).await.expect("write");
        // openssl's own reading, as seconds: `-checkend` answers whether it ends within.
        let ends_within = |s: i64| {
            let path = path.to_string_lossy().to_string();
            async move {
                openssl(&["x509", "-in", &path, "-noout", "-checkend", &s.to_string()])
                    .await
                    .is_err()
            }
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_secs() as i64;
        let end = not_after(&leaf.cert_pem).expect("notAfter");
        assert!(!ends_within(end - now - 60).await, "read too late: {end}");
        assert!(ends_within(end - now + 60).await, "read too early: {end}");
        assert!((end - now - i64::from(LEAF_DAYS) * 86_400).abs() < 300);
    }

    #[test]
    fn both_asn1_times_read_alike() {
        assert_eq!(asn1_time(0x17, "700101000000Z"), Some(0));
        assert_eq!(asn1_time(0x17, "270119120000Z"), Some(1_800_360_000));
        assert_eq!(asn1_time(0x18, "20270119120000Z"), Some(1_800_360_000));
        assert_eq!(asn1_time(0x18, "20000229000000Z"), Some(951_782_400));
        assert_eq!(asn1_time(0x17, "271319120000Z"), None);
        assert_eq!(asn1_time(0x17, "2701191200Z"), None);
        assert!(not_after("not a certificate").is_err());
    }

    #[test]
    fn leaves_expire_long_before_the_authority() {
        // The short lifetime REPLACES revocation: a stolen certificate stops being
        // useful on its own. The CA must survive - replacing it means redeploying the
        // whole fleet the same day.
        // `const`: the constraint is checked at COMPILE time, so changing a constant
        // without thinking does not even compile.
        const _: () = assert!(LEAF_DAYS * 10 < CA_DAYS);
        const _: () = assert!(LEAF_DAYS >= 30, "too short: renewal would become a burden");
        // Renewed early enough to retry for weeks, late enough to renew at all.
        const _: () = assert!(RENEW_BEFORE_DAYS * 2 < LEAF_DAYS && RENEW_BEFORE_DAYS >= 14);
    }
}
