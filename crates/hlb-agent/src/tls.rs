//! mTLS transport for the agent's API.
//!
//! ## What "mutual" changes
//!
//! In ordinary TLS only the server proves its identity: anyone can connect. That is
//! enough for a website, not for an API exposing the disk state of a whole fleet.
//!
//! In **mTLS** the client must also present a certificate signed by our CA. A
//! compromised container on the overlay can therefore no longer query the agents: it
//! has no certificate, and it cannot forge one - the CA never leaves the vault.
//!
//! ## 🔴 The trap: requiring without verifying
//!
//! `rustls` distinguishes three postures, and two of them protect nothing:
//!
//! | Configuration | What it does |
//! |---|---|
//! | `with_no_client_auth()` | anyone gets in |
//! | a verifier that accepts everything | the client presents a certificate, we do not read it |
//! | `WebPkiClientVerifier` over our CA | **only our certificates pass** |
//!
//! The second is the most dangerous: the client does present a certificate, the
//! handshake succeeds, everything looks secure - and a self-signed certificate passes.
//! Only the third is used, and a test checks it by attempting a connection with a
//! certificate from another authority.

use std::sync::Arc;

use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::{ClientConfig, RootCertStore, ServerConfig};

use crate::pki::CertPair;
use crate::Error;

type Result<T> = std::result::Result<T, Error>;

/// Installs the cryptographic provider.
///
/// ⚠️ Without this, the first TLS configuration build **panics** with a message about a
/// "process-level CryptoProvider". It is idempotent: later calls do nothing.
pub fn install_crypto_provider() {
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
}

fn parse_certs(pem: &str) -> Result<Vec<CertificateDer<'static>>> {
    let mut c = std::io::Cursor::new(pem.as_bytes());
    let v: std::result::Result<Vec<_>, _> = rustls_pemfile::certs(&mut c).collect();
    let v = v.map_err(|e| Error::Pki(format!("certificat illisible : {e}")))?;

    if v.is_empty() {
        // An empty PEM would produce a "valid" TLS configuration refusing every
        // connection with an incomprehensible handshake error.
        return Err(Error::Pki("aucun certificat dans le PEM fourni".into()));
    }
    Ok(v)
}

fn parse_key(pem: &str) -> Result<PrivateKeyDer<'static>> {
    let mut c = std::io::Cursor::new(pem.as_bytes());
    rustls_pemfile::private_key(&mut c)
        .map_err(|e| Error::Pki(format!("unreadable private key: {e}")))?
        .ok_or_else(|| Error::Pki("no private key in the supplied PEM".into()))
}

fn root_store(ca_pem: &str) -> Result<RootCertStore> {
    let mut store = RootCertStore::empty();
    for c in parse_certs(ca_pem)? {
        store
            .add(c)
            .map_err(|e| Error::Pki(format!("CA refused: {e}")))?;
    }
    Ok(store)
}

/// La configuration serveur de l'agent : **exige** un certificat client valide.
pub fn server_config(agent: &CertPair, ca_pem: &str) -> Result<Arc<ServerConfig>> {
    install_crypto_provider();

    let verifier =
        tokio_rustls::rustls::server::WebPkiClientVerifier::builder(Arc::new(root_store(ca_pem)?))
            // 🔴 `build()` and NOT `allow_unauthenticated()`: the latter lets clients
            // through without a certificate, which cancels the whole point of mTLS while
            // looking like a secure configuration.
            .build()
            .map_err(|e| Error::Pki(format!("client verifier: {e}")))?;

    let cfg = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(parse_certs(&agent.cert_pem)?, parse_key(&agent.key_pem)?)
        .map_err(|e| Error::Pki(format!("configuration serveur : {e}")))?;

    Ok(Arc::new(cfg))
}

/// The controller's client configuration: presents its certificate and verifies the agent.
pub fn client_config(controller: &CertPair, ca_pem: &str) -> Result<Arc<ClientConfig>> {
    install_crypto_provider();

    let cfg = ClientConfig::builder()
        .with_root_certificates(root_store(ca_pem)?)
        .with_client_auth_cert(
            parse_certs(&controller.cert_pem)?,
            parse_key(&controller.key_pem)?,
        )
        .map_err(|e| Error::Pki(format!("configuration client : {e}")))?;

    Ok(Arc::new(cfg))
}

/// A TCP listener wrapping each connection in TLS.
///
/// Implements `axum::serve::Listener`, which allows serving the same application as in
/// plaintext without modifying it.
pub struct TlsListener {
    inner: tokio::net::TcpListener,
    acceptor: tokio_rustls::TlsAcceptor,
}

impl TlsListener {
    pub fn new(inner: tokio::net::TcpListener, config: Arc<ServerConfig>) -> Self {
        Self {
            inner,
            acceptor: tokio_rustls::TlsAcceptor::from(config),
        }
    }
}

impl axum::serve::Listener for TlsListener {
    type Io = tokio_rustls::server::TlsStream<tokio::net::TcpStream>;
    type Addr = std::net::SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let Ok((flux, adresse)) = self.inner.accept().await else {
                // An `accept` error is transient (exhausted descriptors, a connection
                // abandoned before the handshake). Returning would stop the whole
                // server over a passing incident.
                continue;
            };

            match self.acceptor.accept(flux).await {
                Ok(tls) => return (tls, adresse),
                Err(e) => {
                    // 🔴 The nominal refusal case: a client with no valid certificate.
                    // That is mTLS doing its job, NOT a failure - hence `debug` and not
                    // `error`, or the logs would fill on every port scan.
                    tracing::debug!(%adresse, "TLS handshake refused: {e}");
                    continue;
                }
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        self.inner.local_addr()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pem_bidon() -> CertPair {
        CertPair {
            cert_pem: "-----BEGIN CERTIFICATE-----\nnimportequoi\n-----END CERTIFICATE-----\n"
                .into(),
            key_pem: "-----BEGIN PRIVATE KEY-----\nnimportequoi\n-----END PRIVATE KEY-----\n"
                .into(),
        }
    }

    #[test]
    fn installing_the_provider_twice_is_harmless() {
        // ⚠️ Without installation, the first build PANICS. And it can be called from
        // several entry points.
        install_crypto_provider();
        install_crypto_provider();
    }

    #[test]
    fn an_empty_pem_is_refused_up_front() {
        // 🔴 An empty PEM would give a "valid" TLS configuration refusing every
        // connection with an incomprehensible handshake error.
        let e = parse_certs("").unwrap_err().to_string();
        assert!(e.contains("aucun certificat"), "{e}");

        let e = parse_key("").unwrap_err().to_string();
        assert!(e.contains("no private key"), "{e}");
    }

    #[test]
    fn a_certificate_without_a_key_is_refused() {
        let mut p = pem_bidon();
        p.key_pem = String::new();
        assert!(server_config(&p, &pem_bidon().cert_pem).is_err());
    }

    #[test]
    fn an_unparsable_ca_is_refused() {
        // An unreadable CA must fail AT BUILD TIME, not produce a server that silently
        // refuses everyone.
        assert!(server_config(&pem_bidon(), "pas du PEM du tout").is_err());
    }
}
