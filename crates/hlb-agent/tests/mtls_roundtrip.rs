//! Le mTLS refuse-t-il réellement les intrus ? (§2)
//!
//! 🔴 Une configuration mTLS mal faite donne exactement les mêmes apparences qu'une
//! bonne : la poignée de main réussit, les journaux sont propres, et un certificat
//! auto-signé passe. Le seul test qui prouve quelque chose est une **connexion réelle
//! refusée**.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::Arc;

use hlb_agent::pki::{self, Purpose};
use hlb_agent::tls;
use tokio_rustls::rustls::pki_types::ServerName;

/// Démarre un serveur mTLS minimal et renvoie son adresse.
async fn serveur(
    config: Arc<tokio_rustls::rustls::ServerConfig>,
) -> std::net::SocketAddr {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = l.local_addr().expect("adresse");
    let acceptor = tokio_rustls::TlsAcceptor::from(config);

    tokio::spawn(async move {
        loop {
            let Ok((flux, _)) = l.accept().await else { continue };
            let a = acceptor.clone();
            tokio::spawn(async move {
                // Le résultat importe peu côté serveur : c'est le client qui doit
                // constater le refus.
                if let Ok(mut tls) = a.accept(flux).await {
                    use tokio::io::AsyncWriteExt;
                    let _ = tls.write_all(b"ok").await;
                    let _ = tls.shutdown().await;
                }
            });
        }
    });
    addr
}

/// Tente une poignée de main complète et dit si elle a abouti.
async fn se_connecte(
    addr: std::net::SocketAddr,
    config: Arc<tokio_rustls::rustls::ClientConfig>,
    nom: &str,
) -> Result<(), String> {
    let flux = tokio::net::TcpStream::connect(addr)
        .await
        .map_err(|e| e.to_string())?;

    let connector = tokio_rustls::TlsConnector::from(config);
    let sni = ServerName::try_from(nom.to_string()).map_err(|e| e.to_string())?;

    let mut tls = connector
        .connect(sni, flux)
        .await
        .map_err(|e| format!("poignée de main : {e}"))?;

    // 🔴 Lire vraiment : rustls termine la poignée de main paresseusement, et une
    // connexion « réussie » sans lecture ne prouve rien.
    use tokio::io::AsyncReadExt;
    let mut buf = [0u8; 2];
    tls.read_exact(&mut buf).await.map_err(|e| e.to_string())?;
    assert_eq!(&buf, b"ok");
    Ok(())
}

struct Parc {
    ca: pki::CertPair,
    agent: pki::CertPair,
    controller: pki::CertPair,
}

async fn parc() -> Parc {
    let ca = pki::generate_ca("Homelabus CA").await.expect("CA");
    let agent = pki::issue(&ca, "agent", &["localhost".into()], Purpose::Server)
        .await
        .expect("agent");
    let controller = pki::issue(&ca, "controller", &["controller".into()], Purpose::Client)
        .await
        .expect("controller");
    Parc { ca, agent, controller }
}

#[tokio::test]
async fn the_controller_gets_in() {
    let p = parc().await;
    let addr = serveur(tls::server_config(&p.agent, &p.ca.cert_pem).expect("serveur")).await;
    let client = tls::client_config(&p.controller, &p.ca.cert_pem).expect("client");

    se_connecte(addr, client, "localhost")
        .await
        .expect("le controller légitime doit entrer");
}

#[tokio::test]
async fn a_client_without_any_certificate_is_refused() {
    // 🔴 Le cas qui justifie tout ce module : un conteneur compromis sur l'overlay
    // n'a pas de certificat. Il ne doit pas pouvoir cartographier les disques.
    let p = parc().await;
    let addr = serveur(tls::server_config(&p.agent, &p.ca.cert_pem).expect("serveur")).await;

    tls::install_crypto_provider();
    let mut store = tokio_rustls::rustls::RootCertStore::empty();
    for c in rustls_pemfile::certs(&mut std::io::Cursor::new(p.ca.cert_pem.as_bytes())) {
        store.add(c.expect("certificat")).expect("ajout");
    }
    // Il fait confiance à notre CA, mais ne présente RIEN.
    let anonyme = Arc::new(
        tokio_rustls::rustls::ClientConfig::builder()
            .with_root_certificates(store)
            .with_no_client_auth(),
    );

    let r = se_connecte(addr, anonyme, "localhost").await;
    assert!(r.is_err(), "un client sans certificat doit être REFUSÉ");
}

#[tokio::test]
async fn a_certificate_from_another_authority_is_refused() {
    // Forger son propre certificat ne doit servir à rien : c'est la signature par
    // NOTRE CA qui compte, pas la présence d'un certificat.
    let p = parc().await;
    let addr = serveur(tls::server_config(&p.agent, &p.ca.cert_pem).expect("serveur")).await;

    let autre_ca = pki::generate_ca("CA de l'attaquant").await.expect("CA");
    let intrus = pki::issue(&autre_ca, "intrus", &["intrus".into()], Purpose::Client)
        .await
        .expect("intrus");

    // L'intrus fait confiance à NOTRE CA pour vérifier le serveur, et présente son
    // propre certificat : c'est exactement ce que ferait un attaquant.
    let config = tls::client_config(&intrus, &p.ca.cert_pem).expect("client");

    let r = se_connecte(addr, config, "localhost").await;
    assert!(r.is_err(), "un certificat d'une autre CA doit être REFUSÉ");
}

#[tokio::test]
async fn the_controller_refuses_an_impostor_agent() {
    // L'autre sens : quelqu'un qui prendrait la place de l'agent dans le DNS de
    // l'overlay ne doit pas pouvoir recevoir les requêtes du controller.
    let p = parc().await;
    let autre_ca = pki::generate_ca("CA de l'attaquant").await.expect("CA");
    let faux_agent = pki::issue(&autre_ca, "agent", &["localhost".into()], Purpose::Server)
        .await
        .expect("faux agent");

    // Le faux agent accepte tout le monde : c'est le CONTROLLER qui doit refuser.
    let addr = serveur(
        tls::server_config(&faux_agent, &autre_ca.cert_pem).expect("serveur"),
    )
    .await;

    let client = tls::client_config(&p.controller, &p.ca.cert_pem).expect("client");
    let r = se_connecte(addr, client, "localhost").await;
    assert!(r.is_err(), "le controller doit REFUSER un agent qu'il ne reconnaît pas");
}
