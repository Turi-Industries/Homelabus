//! What the guide verifier takes for "done", against real servers.
//!
//! 🔴 An `after-guide` route opens on what it says: a verifier taking any certificate,
//! or following a portal to its sign-in page, opened routes nothing had earned.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::Arc;

use hlb_guide::{Outcome, Verifier};
use hlb_types::{GuideStep, JsonValue, Verify};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn step(verify: Verify) -> GuideStep {
    GuideStep {
        id: "first-account".into(),
        title: "Create the administrator account".into(),
        phase: Default::default(),
        severity: Default::default(),
        body: String::new(),
        after: Vec::new(),
        automate: Vec::new(),
        verify,
        deeplink: None,
        recheck: None,
    }
}

fn http(url: String, json: Option<(&str, &str)>) -> Verify {
    Verify::Http {
        url,
        expect_status: vec![200],
        expect_json: json.map(|(pointer, equals)| JsonValue {
            pointer: pointer.into(),
            equals: equals.into(),
        }),
    }
}

/// Answers every request on one stream with `answer(path)`.
async fn respond<S>(mut stream: S, answer: Arc<dyn Fn(&str) -> String + Send + Sync>)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 8192];
    let mut read = 0;
    while !buf[..read].windows(4).any(|w| w == b"\r\n\r\n") {
        match stream.read(&mut buf[read..]).await {
            Ok(0) | Err(_) => return,
            Ok(n) => read += n,
        }
    }
    let head = String::from_utf8_lossy(&buf[..read]);
    let path = head.split_whitespace().nth(1).unwrap_or("/").to_string();
    let _ = stream.write_all(answer(&path).as_bytes()).await;
    let _ = stream.shutdown().await;
}

fn answer(status: &str, headers: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status}\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

/// A plain HTTP server; its base URL.
async fn plain(answer: impl Fn(&str) -> String + Send + Sync + 'static) -> String {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = l.local_addr().expect("address");
    let answer: Arc<dyn Fn(&str) -> String + Send + Sync> = Arc::new(answer);
    tokio::spawn(async move {
        while let Ok((s, _)) = l.accept().await {
            tokio::spawn(respond(s, answer.clone()));
        }
    });
    format!("http://{addr}")
}

#[tokio::test]
async fn a_redirect_is_judged_as_it_answers_never_followed() {
    // n8n behind the portal: its `/healthz` answered 302 to the sign-in page, which
    // answered 200 — "verified" while n8n itself was down.
    let base = plain(|path| match path {
        "/healthz" => answer("302 Found", "Location: /oauth2/sign_in\r\n", ""),
        _ => answer("200 OK", "", "sign in"),
    })
    .await;
    let o = Verifier::default()
        .check(&step(http(format!("{base}/healthz"), None)), &[])
        .await;
    assert!(
        matches!(&o, Outcome::Failed { detail } if detail.contains("302")),
        "{}",
        o.describe()
    );
}

#[tokio::test]
async fn an_answer_is_verified_by_the_value_it_says_not_by_its_status() {
    let base = plain(|path| match path {
        "/api/server/config" => answer(
            "200 OK",
            "Content-Type: application/json\r\n",
            r#"{"isInitialized":false,"isOnboarded":false}"#,
        ),
        "/done" => answer(
            "200 OK",
            "Content-Type: application/json\r\n",
            r#"{"isInitialized":true}"#,
        ),
        _ => answer(
            "200 OK",
            "Content-Type: text/html\r\n",
            "<html>starting</html>",
        ),
    })
    .await;
    let check = |path: &str| {
        let s = step(http(
            format!("{base}{path}"),
            Some(("/isInitialized", "true")),
        ));
        async move { Verifier::default().check(&s, &[]).await }
    };
    let open = check("/api/server/config").await;
    assert!(
        matches!(&open, Outcome::Failed { detail } if detail.contains("false")),
        "{}",
        open.describe()
    );
    assert!(check("/done").await.is_verified());
    // A page where a document was expected says nothing, and is never "done".
    let page = check("/starting").await;
    assert!(
        matches!(&page, Outcome::Failed { detail } if detail.contains("no JSON")),
        "{}",
        page.describe()
    );
}

/// An HTTPS server for `localhost` under `root`; its base URL.
async fn tls(leaf: &hlb_agent::pki::CertPair) -> String {
    hlb_agent::tls::install_crypto_provider();
    let certs: Vec<_> = rustls_pemfile::certs(&mut leaf.cert_pem.as_bytes())
        .collect::<Result<_, _>>()
        .expect("certificate");
    let key = rustls_pemfile::private_key(&mut leaf.key_pem.as_bytes())
        .expect("key")
        .expect("a key");
    let config = tokio_rustls::rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("server configuration");
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let l = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = l.local_addr().expect("address").port();
    let ok: Arc<dyn Fn(&str) -> String + Send + Sync> =
        Arc::new(|_: &str| answer("200 OK", "", "ok"));
    tokio::spawn(async move {
        while let Ok((s, _)) = l.accept().await {
            let (a, ok) = (acceptor.clone(), ok.clone());
            tokio::spawn(async move {
                if let Ok(s) = a.accept(s).await {
                    respond(s, ok).await;
                }
            });
        }
    });
    format!("https://localhost:{port}")
}

#[tokio::test]
async fn a_certificate_is_trusted_only_under_a_public_root_or_the_installations() {
    let root = hlb_agent::pki::generate_web_root("Homelabus")
        .await
        .expect("root (openssl)");
    let leaf = hlb_agent::pki::issue_platform_server(&root, "localhost")
        .await
        .expect("leaf");
    let base = tls(&leaf).await;
    let s = step(Verify::Http {
        url: format!("{base}/health"),
        expect_status: vec![200],
        expect_json: None,
    });
    let timeout = std::time::Duration::from_secs(5);

    // Whoever answers for the name with a certificate nobody trusts proves nothing.
    let stranger = Verifier::new(timeout).check(&s, &[]).await;
    assert!(
        matches!(&stranger, Outcome::Failed { detail } if detail.contains("unreachable")),
        "{}",
        stranger.describe()
    );
    let other = hlb_agent::pki::generate_web_root("Elsewhere")
        .await
        .expect("root");
    let o = Verifier::trusting(timeout, Some(&other.cert_pem))
        .check(&s, &[])
        .await;
    assert!(!o.is_verified(), "{}", o.describe());

    let o = Verifier::trusting(timeout, Some(&root.cert_pem))
        .check(&s, &[])
        .await;
    assert!(o.is_verified(), "{}", o.describe());
}
