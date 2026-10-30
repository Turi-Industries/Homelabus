//! The controller reaches an agent over mTLS at its task's IP.
//!
//! 🔴 Swarm hands the controller one IP per task; the certificate names hosts. Polling
//! `https://10.0.1.7` verified the IP against a certificate that cannot name it, and
//! every agent read as unreachable the day mTLS was switched on. Needs `openssl`.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::time::Duration;

use hlb_agent::pki::{self, Purpose};
use hlb_privd::fleet::{AgentPoller, AgentStatus};

#[tokio::test]
async fn an_agent_is_polled_by_ip_and_verified_by_name() {
    let ca = pki::generate_ca("test CA").await.expect("CA");
    let agent = pki::issue(
        &ca,
        "node1",
        &pki::agent_names("node1", "hlb-agent"),
        Purpose::Server,
    )
    .await
    .expect("agent certificate");
    let client = pki::issue(&ca, "controller", &["controller".into()], Purpose::Client)
        .await
        .expect("controller certificate");

    let config = hlb_agent::tls::server_config(&agent, &ca.cert_pem).expect("server config");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let app = axum::Router::new().route(
        "/api/report",
        axum::routing::get(|| async {
            axum::Json(hlb_agent::NodeReport {
                hostname: "node1".into(),
                ..Default::default()
            })
        }),
    );
    tokio::spawn(async move {
        let _ = axum::serve(hlb_agent::tls::TlsListener::new(listener, config), app).await;
    });

    let poller = AgentPoller::with_mtls(
        port,
        Duration::from_secs(5),
        &format!("{}{}", client.cert_pem, client.key_pem),
        &ca.cert_pem,
        "tasks.hlb-agent",
    )
    .expect("poller");

    match poller.poll("127.0.0.1").await {
        AgentStatus::Reporting(r) => assert_eq!(r.hostname, "node1"),
        other => panic!("not reached: {other:?}"),
    }

    // And a name the certificate does not carry is still refused.
    let wrong = AgentPoller::with_mtls(
        port,
        Duration::from_secs(5),
        &format!("{}{}", client.cert_pem, client.key_pem),
        &ca.cert_pem,
        "tasks.someone-else",
    )
    .expect("poller");
    assert!(matches!(
        wrong.poll("127.0.0.1").await,
        AgentStatus::Unreachable { .. }
    ));
}
