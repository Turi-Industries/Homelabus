//! Transport mTLS pour l'API de l'agent (§2).
//!
//! ## Ce que « mutuel » change
//!
//! En TLS ordinaire, seul le serveur prouve son identité : n'importe qui peut se
//! connecter. C'est suffisant pour un site web, pas pour une API qui expose l'état
//! des disques de tout un parc.
//!
//! En **mTLS**, le client doit lui aussi présenter un certificat signé par notre CA.
//! Un conteneur compromis sur l'overlay ne peut donc plus interroger les agents : il
//! n'a pas de certificat, et il ne peut pas s'en fabriquer un — la CA ne quitte jamais
//! le coffre.
//!
//! ## 🔴 Le piège : exiger sans vérifier
//!
//! `rustls` distingue trois postures, et deux d'entre elles ne protègent rien :
//!
//! | Configuration | Ce que ça fait |
//! |---|---|
//! | `with_no_client_auth()` | n'importe qui entre |
//! | vérificateur qui accepte tout | le client présente un certificat, on ne le lit pas |
//! | `WebPkiClientVerifier` sur notre CA | **seuls nos certificats passent** |
//!
//! La deuxième est la plus dangereuse : le client présente bien un certificat, la
//! poignée de main réussit, tout paraît sécurisé — et un certificat auto-signé passe.
//! On n'utilise donc que la troisième, et un test le vérifie en tentant une connexion
//! avec un certificat d'une autre autorité.

use std::sync::Arc;

use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::{ClientConfig, RootCertStore, ServerConfig};

use crate::pki::CertPair;
use crate::Error;

type Result<T> = std::result::Result<T, Error>;

/// Installe le fournisseur cryptographique.
///
/// ⚠️ Sans ça, la première construction de configuration TLS **panique** avec un
/// message sur un « process-level CryptoProvider ». C'est idempotent : les appels
/// suivants ne font rien.
pub fn install_crypto_provider() {
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
}

fn parse_certs(pem: &str) -> Result<Vec<CertificateDer<'static>>> {
    let mut c = std::io::Cursor::new(pem.as_bytes());
    let v: std::result::Result<Vec<_>, _> = rustls_pemfile::certs(&mut c).collect();
    let v = v.map_err(|e| Error::Pki(format!("certificat illisible : {e}")))?;

    if v.is_empty() {
        // Un PEM vide produirait une configuration TLS « valide » qui refuse toutes
        // les connexions avec une erreur de poignée de main incompréhensible.
        return Err(Error::Pki("aucun certificat dans le PEM fourni".into()));
    }
    Ok(v)
}

fn parse_key(pem: &str) -> Result<PrivateKeyDer<'static>> {
    let mut c = std::io::Cursor::new(pem.as_bytes());
    rustls_pemfile::private_key(&mut c)
        .map_err(|e| Error::Pki(format!("clé privée illisible : {e}")))?
        .ok_or_else(|| Error::Pki("aucune clé privée dans le PEM fourni".into()))
}

fn root_store(ca_pem: &str) -> Result<RootCertStore> {
    let mut store = RootCertStore::empty();
    for c in parse_certs(ca_pem)? {
        store
            .add(c)
            .map_err(|e| Error::Pki(format!("CA refusée : {e}")))?;
    }
    Ok(store)
}

/// La configuration serveur de l'agent : **exige** un certificat client valide.
pub fn server_config(agent: &CertPair, ca_pem: &str) -> Result<Arc<ServerConfig>> {
    install_crypto_provider();

    let verifier = tokio_rustls::rustls::server::WebPkiClientVerifier::builder(
        Arc::new(root_store(ca_pem)?),
    )
    // 🔴 `build()` et NON `allow_unauthenticated()` : ce dernier laisse passer les
    // clients sans certificat, ce qui annule tout l'intérêt du mTLS tout en donnant
    // l'apparence d'une configuration sécurisée.
    .build()
    .map_err(|e| Error::Pki(format!("vérificateur client : {e}")))?;

    let cfg = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(parse_certs(&agent.cert_pem)?, parse_key(&agent.key_pem)?)
        .map_err(|e| Error::Pki(format!("configuration serveur : {e}")))?;

    Ok(Arc::new(cfg))
}

/// La configuration client du controller : présente son certificat et vérifie l'agent.
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

/// Un écouteur TCP qui enveloppe chaque connexion dans TLS.
///
/// Implémente `axum::serve::Listener`, ce qui permet de servir la même application
/// qu'en clair sans la modifier.
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
                // Une erreur d'`accept` est transitoire (descripteurs épuisés,
                // connexion abandonnée avant la poignée de main). Rendre la main
                // arrêterait tout le serveur pour un incident passager.
                continue;
            };

            match self.acceptor.accept(flux).await {
                Ok(tls) => return (tls, adresse),
                Err(e) => {
                    // 🔴 Le cas nominal du refus : un client sans certificat valide.
                    // C'est le mTLS qui fait son travail, PAS une panne — d'où
                    // `debug` et non `error`, sinon les journaux se rempliraient à
                    // chaque scan de port.
                    tracing::debug!(%adresse, "poignée de main TLS refusée : {e}");
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
        // ⚠️ Sans installation, la première construction PANIQUE. Et elle peut être
        // appelée depuis plusieurs points d'entrée.
        install_crypto_provider();
        install_crypto_provider();
    }

    #[test]
    fn an_empty_pem_is_refused_up_front() {
        // 🔴 Un PEM vide donnerait une configuration TLS « valide » qui refuse toutes
        // les connexions avec une erreur de poignée de main incompréhensible.
        let e = parse_certs("").unwrap_err().to_string();
        assert!(e.contains("aucun certificat"), "{e}");

        let e = parse_key("").unwrap_err().to_string();
        assert!(e.contains("aucune clé"), "{e}");
    }

    #[test]
    fn a_certificate_without_a_key_is_refused() {
        let mut p = pem_bidon();
        p.key_pem = String::new();
        assert!(server_config(&p, &pem_bidon().cert_pem).is_err());
    }

    #[test]
    fn an_unparsable_ca_is_refused() {
        // Une CA illisible doit échouer À LA CONSTRUCTION, pas produire un serveur
        // qui refuse silencieusement tout le monde.
        assert!(server_config(&pem_bidon(), "pas du PEM du tout").is_err());
    }
}
