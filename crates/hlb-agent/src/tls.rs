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
//! | a check that accepts everything | the client presents a certificate, we do not read it |
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
        return Err(Error::Pki("no certificate in the supplied PEM".into()));
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

/// The agent's server configuration: **requires** a valid client certificate.
pub fn server_config(agent: &CertPair, ca_pem: &str) -> Result<Arc<ServerConfig>> {
    install_crypto_provider();

    let check =
        tokio_rustls::rustls::server::WebPkiClientVerifier::builder(Arc::new(root_store(ca_pem)?))
            // 🔴 `build()` and NOT `allow_unauthenticated()`: the latter lets clients
            // through without a certificate, which cancels the whole point of mTLS while
            // looking like a secure configuration.
            .build()
            .map_err(|e| Error::Pki(format!("client check: {e}")))?;

    let cfg = ServerConfig::builder()
        .with_client_cert_verifier(check)
        .with_single_cert(parse_certs(&agent.cert_pem)?, parse_key(&agent.key_pem)?)
        .map_err(|e| Error::Pki(format!("server configuration: {e}")))?;

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

/// How long a client has to complete its handshake.
///
/// A peer that opens a connection and says nothing — a scan, a half-open socket left by
/// a partition — is dropped after this, never waited for.
pub const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// A TCP listener wrapping each connection in TLS.
///
/// Implements `axum::serve::Listener`, which allows serving the same application as in
/// plaintext without modifying it.
///
/// 🔴 axum calls `accept` again only once it returns: a handshake awaited there held
/// every later client behind one silent connection, and the controller read the whole
/// node as unreachable. Each handshake runs in a task of its own, bounded by
/// [`HANDSHAKE_TIMEOUT`], and only finished ones come back through a channel.
pub struct TlsListener {
    accepted: tokio::sync::mpsc::Receiver<(
        tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
        std::net::SocketAddr,
    )>,
    address: std::io::Result<std::net::SocketAddr>,
}

impl TlsListener {
    /// Must be called within a Tokio runtime: the accept loop is spawned here.
    pub fn new(inner: tokio::net::TcpListener, config: Arc<ServerConfig>) -> Self {
        Self::with_timeout(inner, config, HANDSHAKE_TIMEOUT)
    }

    pub fn with_timeout(
        inner: tokio::net::TcpListener,
        config: Arc<ServerConfig>,
        timeout: std::time::Duration,
    ) -> Self {
        let address = inner.local_addr();
        let acceptor = tokio_rustls::TlsAcceptor::from(config);
        let (tx, accepted) = tokio::sync::mpsc::channel(64);
        tokio::spawn(async move {
            loop {
                let (stream, address) = tokio::select! {
                    // The server is gone: nothing will take what this accepts.
                    () = tx.closed() => return,
                    r = inner.accept() => match r {
                        Ok(pair) => pair,
                        // An `accept` error is transient (exhausted descriptors, a
                        // connection abandoned before the handshake). Returning would
                        // stop the whole server over a passing incident.
                        Err(_) => continue,
                    },
                };
                let (acceptor, tx) = (acceptor.clone(), tx.clone());
                tokio::spawn(async move {
                    match tokio::time::timeout(timeout, acceptor.accept(stream)).await {
                        Ok(Ok(tls)) => {
                            let _ = tx.send((tls, address)).await;
                        }
                        // 🔴 The nominal refusal case: a client with no valid
                        // certificate. That is mTLS doing its job, NOT a failure -
                        // hence `debug` and not `error`, or the logs would fill on
                        // every port scan.
                        Ok(Err(e)) => tracing::debug!(%address, "TLS handshake refused: {e}"),
                        Err(_) => tracing::debug!(%address, "TLS handshake timed out"),
                    }
                });
            }
        });
        Self { accepted, address }
    }
}

impl axum::serve::Listener for TlsListener {
    type Io = tokio_rustls::server::TlsStream<tokio::net::TcpStream>;
    type Addr = std::net::SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        match self.accepted.recv().await {
            Some(pair) => pair,
            // The accept loop holds a sender for as long as this receiver lives, so
            // this is never reached; serving nothing beats a panic if it is.
            None => std::future::pending().await,
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        match &self.address {
            Ok(a) => Ok(*a),
            Err(e) => Err(std::io::Error::new(e.kind(), e.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_pem() -> CertPair {
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
        assert!(e.contains("no certificate"), "{e}");

        let e = parse_key("").unwrap_err().to_string();
        assert!(e.contains("no private key"), "{e}");
    }

    #[test]
    fn a_certificate_without_a_key_is_refused() {
        let mut p = fake_pem();
        p.key_pem = String::new();
        assert!(server_config(&p, &fake_pem().cert_pem).is_err());
    }

    #[test]
    fn an_unparsable_ca_is_refused() {
        // An unreadable CA must fail AT BUILD TIME, not produce a server that silently
        // refuses everyone.
        assert!(server_config(&fake_pem(), "not PEM at all").is_err());
    }
}
