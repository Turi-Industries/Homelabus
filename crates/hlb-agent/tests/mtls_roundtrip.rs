//! Does mTLS actually refuse intruders?
//!
//! 🔴 A badly configured mTLS setup looks exactly like a good one: the handshake
//! succeeds, the logs are clean, and a self-signed certificate goes through. The only
//! test that proves anything is a **real connection being refused**.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::Arc;

use hlb_agent::pki::{self, Purpose};
use hlb_agent::tls;
use tokio_rustls::rustls::pki_types::ServerName;

/// Starts a minimal mTLS server and returns its address.
async fn server(config: Arc<tokio_rustls::rustls::ServerConfig>) -> std::net::SocketAddr {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = l.local_addr().expect("address");
    let acceptor = tokio_rustls::TlsAcceptor::from(config);

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = l.accept().await else {
                continue;
            };
            let a = acceptor.clone();
            tokio::spawn(async move {
                // The result matters little server-side: it is the client that must
                // observe the refusal.
                if let Ok(mut tls) = a.accept(stream).await {
                    use tokio::io::AsyncWriteExt;
                    let _ = tls.write_all(b"ok").await;
                    let _ = tls.shutdown().await;
                }
            });
        }
    });
    addr
}

/// Attempts a full handshake and says whether it succeeded.
async fn connects(
    addr: std::net::SocketAddr,
    config: Arc<tokio_rustls::rustls::ClientConfig>,
    name: &str,
) -> Result<(), String> {
    let stream = tokio::net::TcpStream::connect(addr)
        .await
        .map_err(|e| e.to_string())?;

    let connector = tokio_rustls::TlsConnector::from(config);
    let sni = ServerName::try_from(name.to_string()).map_err(|e| e.to_string())?;

    let mut tls = connector
        .connect(sni, stream)
        .await
        .map_err(|e| format!("handshake: {e}"))?;

    // 🔴 Actually read: rustls completes the handshake lazily, and a "successful"
    // connection with no read proves nothing.
    use tokio::io::AsyncReadExt;
    let mut buf = [0u8; 2];
    tls.read_exact(&mut buf).await.map_err(|e| e.to_string())?;
    assert_eq!(&buf, b"ok");
    Ok(())
}

struct Fleet {
    ca: pki::CertPair,
    agent: pki::CertPair,
    controller: pki::CertPair,
}

async fn fleet() -> Fleet {
    let ca = pki::generate_ca("Homelabus CA").await.expect("CA");
    let agent = pki::issue(&ca, "agent", &["localhost".into()], Purpose::Server)
        .await
        .expect("agent");
    let controller = pki::issue(&ca, "controller", &["controller".into()], Purpose::Client)
        .await
        .expect("controller");
    Fleet {
        ca,
        agent,
        controller,
    }
}

#[tokio::test]
async fn the_controller_gets_in() {
    let p = fleet().await;
    let addr = server(tls::server_config(&p.agent, &p.ca.cert_pem).expect("server")).await;
    let client = tls::client_config(&p.controller, &p.ca.cert_pem).expect("client");

    connects(addr, client, "localhost")
        .await
        .expect("the legitimate controller must get in");
}

#[tokio::test]
async fn a_client_without_any_certificate_is_refused() {
    // 🔴 The case that justifies this whole module: a compromised container on the
    // overlay has no certificate. It must not be able to map the disks.
    let p = fleet().await;
    let addr = server(tls::server_config(&p.agent, &p.ca.cert_pem).expect("server")).await;

    tls::install_crypto_provider();
    let mut store = tokio_rustls::rustls::RootCertStore::empty();
    for c in rustls_pemfile::certs(&mut std::io::Cursor::new(p.ca.cert_pem.as_bytes())) {
        store.add(c.expect("certificat")).expect("ajout");
    }
    // It trusts our CA, but presents NOTHING.
    let anonymous = Arc::new(
        tokio_rustls::rustls::ClientConfig::builder()
            .with_root_certificates(store)
            .with_no_client_auth(),
    );

    let r = connects(addr, anonymous, "localhost").await;
    assert!(r.is_err(), "a client with no certificate must be REFUSED");
}

#[tokio::test]
async fn a_certificate_from_another_authority_is_refused() {
    // Forging your own certificate must achieve nothing: what counts is the signature
    // by OUR CA, not the presence of a certificate.
    let p = fleet().await;
    let addr = server(tls::server_config(&p.agent, &p.ca.cert_pem).expect("server")).await;

    let other_ca = pki::generate_ca("attacker CA").await.expect("CA");
    let intruder = pki::issue(&other_ca, "intrus", &["intrus".into()], Purpose::Client)
        .await
        .expect("intrus");

    // The intruder trusts OUR CA to verify the server, and presents its own
    // certificate: exactly what an attacker would do.
    let config = tls::client_config(&intruder, &p.ca.cert_pem).expect("client");

    let r = connects(addr, config, "localhost").await;
    assert!(r.is_err(), "a certificate from another CA must be REFUSED");
}

#[tokio::test]
async fn the_controller_refuses_an_impostor_agent() {
    // The other direction: someone taking the agent's place in the overlay DNS must
    // not be able to receive the controller's requests.
    let p = fleet().await;
    let other_ca = pki::generate_ca("attacker CA").await.expect("CA");
    let fake_agent = pki::issue(&other_ca, "agent", &["localhost".into()], Purpose::Server)
        .await
        .expect("fake agent");

    // The fake agent accepts everyone: it is the CONTROLLER that must refuse.
    let addr = server(tls::server_config(&fake_agent, &other_ca.cert_pem).expect("server")).await;

    let client = tls::client_config(&p.controller, &p.ca.cert_pem).expect("client");
    let r = connects(addr, client, "localhost").await;
    assert!(
        r.is_err(),
        "the controller must REFUSE an agent it does not recognise"
    );
}

/// The agent's own listener, serving `ok` to every connection it hands out.
async fn agent_listener(config: Arc<tokio_rustls::rustls::ServerConfig>) -> std::net::SocketAddr {
    use axum::serve::Listener;
    let l = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let mut tls = tls::TlsListener::new(l, config);
    let addr = tls.local_addr().expect("address");
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = tls.accept().await;
            tokio::spawn(async move {
                use tokio::io::AsyncWriteExt;
                let _ = stream.write_all(b"ok").await;
                let _ = stream.shutdown().await;
            });
        }
    });
    addr
}

#[tokio::test]
async fn a_silent_connection_does_not_hold_the_next_client() {
    // 🔴 A peer that connects and never speaks — a scan, a socket half-open after a
    // partition — held every later handshake behind it: the controller read the node
    // as unreachable for as long as the silent one stayed.
    let p = fleet().await;
    let addr = agent_listener(tls::server_config(&p.agent, &p.ca.cert_pem).expect("server")).await;
    let _silent = tokio::net::TcpStream::connect(addr)
        .await
        .expect("silent peer");

    let client = tls::client_config(&p.controller, &p.ca.cert_pem).expect("client");
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        connects(addr, client, "localhost"),
    )
    .await
    .expect("the controller waited behind a silent connection")
    .expect("the legitimate controller must get in");
}

#[tokio::test]
async fn a_handshake_that_never_comes_is_dropped() {
    let p = fleet().await;
    let l = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = l.local_addr().expect("address");
    let _tls = tls::TlsListener::with_timeout(
        l,
        tls::server_config(&p.agent, &p.ca.cert_pem).expect("server"),
        std::time::Duration::from_millis(200),
    );
    let mut silent = tokio::net::TcpStream::connect(addr)
        .await
        .expect("silent peer");
    use tokio::io::AsyncReadExt;
    let mut buf = [0u8; 1];
    let read = tokio::time::timeout(std::time::Duration::from_secs(5), silent.read(&mut buf))
        .await
        .expect("the silent peer was kept past its timeout");
    assert!(
        matches!(read, Ok(0) | Err(_)),
        "closed, not answered: {read:?}"
    );
}
