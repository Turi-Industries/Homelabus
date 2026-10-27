//! The full controller → agent path, against a real binary.
//!
//! This test was born of an accident: an agent started by hand was lingering on port
//! 8421, and a test meant to check a connection failure received a real answer. Rather
//! than simply fix the test, we may as well deliberately check what the accident had
//! proved.
//!
//! ```sh
//! cargo test -p hlb-controller --test agent_roundtrip -- --ignored --nocapture
//! ```

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::time::Duration;

/// An agent that stops on its own, even if the test panics.
///
/// Without this guard, a failing test leaves an orphan agent on the port — and the next
/// test receives its answer. That is exactly the trap that made me write this file: a
/// forgotten agent made a test meant to check an absence pass.
struct AgentGuard(Option<std::process::Child>);

impl AgentGuard {
    fn stop(&mut self) {
        if let Some(mut c) = self.0.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

impl Drop for AgentGuard {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Starts the repository's compiled agent and waits for it to answer.
async fn start_agent(port: u16) -> AgentGuard {
    let bin = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/hlb-agent");
    assert!(
        bin.exists(),
        "binary missing: run `cargo build` first ({})",
        bin.display()
    );

    let child = std::process::Command::new(&bin)
        .args(["--listen", &format!("127.0.0.1:{port}"), "--watch", "/"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("agent start");

    let mut guard = AgentGuard(Some(child));
    for _ in 0..50 {
        if tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_ok()
        {
            return guard;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    guard.stop();
    panic!("the agent did not start in time");
}

#[tokio::test]
#[ignore = "starts a real agent"]
async fn the_controller_reads_a_real_agent_report() {
    let port = 18421;
    let _agent = start_agent(port).await;

    let poller = hlb_controller::AgentPoller::new(port, Duration::from_secs(5));
    let status = poller.poll("127.0.0.1").await;

    let report = status
        .report()
        .unwrap_or_else(|| panic!("agent unreachable : {}", status.describe()));

    // The agent must report at least one real filesystem.
    assert!(!report.disks.is_empty(), "no disk reported");
    assert!(report.disks[0].total_mb > 0);
    assert!(!report.agent_version.is_empty());

    // And the usage must be plausible: neither 0 %, nor above 100 %.
    let p = report.disks[0].used_percent();
    assert!(p > 0.0 && p <= 100.0, "occupation aberrante : {p:.1} %");

    println!(
        "✓ report received: {} — {:.1} % used, agent {}",
        report.hostname, p, report.agent_version
    );
}

#[tokio::test]
#[ignore = "starts a real agent"]
async fn a_stopped_agent_becomes_unreachable() {
    // 🔴 What matters: after the stop we must say "unreachable" and above all NOT keep
    // serving the last known report as though it were fresh.
    let port = 18422;
    let mut agent = start_agent(port).await;
    let poller = hlb_controller::AgentPoller::new(port, Duration::from_secs(5));

    assert!(poller.poll("127.0.0.1").await.report().is_some());

    agent.stop();
    tokio::time::sleep(Duration::from_millis(300)).await;

    let status = poller.poll("127.0.0.1").await;
    assert!(
        status.report().is_none(),
        "the stopped agent still answers?"
    );
    assert!(!status.allows_deploy(&hlb_agent::Thresholds::default()));
    println!("✓ agent stopped -> {}", status.describe());
}

/// Does the controller really speak mTLS to a real agent?
///
/// 🔴 The test that counts: both binaries, a real handshake, and an anonymous client
/// refused. A badly done mTLS configuration looks exactly like a good one — only a
/// connection genuinely refused proves
/// anything.
#[tokio::test]
#[ignore = "starts a real agent"]
async fn the_controller_polls_a_real_agent_over_mtls() {
    use hlb_agent::pki::{self, Purpose};

    let d = tempfile::tempdir().expect("temp directory");
    let ca = pki::generate_ca("test CA").await.expect("CA");
    let agent = pki::issue(
        &ca,
        "localhost",
        &["localhost".into(), "127.0.0.1".into()],
        Purpose::Server,
    )
    .await
    .expect("certificat agent");
    let controller = pki::issue(&ca, "controller", &["controller".into()], Purpose::Client)
        .await
        .expect("certificat controller");

    let write = |name: &str, c: &str| {
        let p = d.path().join(name);
        std::fs::write(&p, c).expect("write");
        p
    };
    let p_ca = write("ca.crt", &ca.cert_pem);
    let p_crt = write("agent.crt", &agent.cert_pem);
    let p_key = write("agent.key", &agent.key_pem);

    let bin = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/hlb-agent");
    let port = 8497u16;

    let child = std::process::Command::new(&bin)
        .args([
            "--listen",
            &format!("127.0.0.1:{port}"),
            "--watch",
            "/",
            "--cert",
            &p_crt.to_string_lossy(),
            "--key",
            &p_key.to_string_lossy(),
            "--ca",
            &p_ca.to_string_lossy(),
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("agent start");

    let mut guard = AgentGuard(Some(child));
    for _ in 0..50 {
        if tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_ok()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // 1. The legitimate controller does get a report.
    let poller = hlb_controller::AgentPoller::with_mtls(
        port,
        Duration::from_secs(5),
        &format!("{}{}", controller.cert_pem, controller.key_pem),
        &ca.cert_pem,
        "tasks.hlb-agent",
    )
    .expect("poller mTLS");

    assert!(poller.is_secure(), "the poller must be on https");

    let s = poller.poll("localhost").await;
    let report = s.report().unwrap_or_else(|| {
        panic!(
            "the legitimate controller must get a report: {}",
            s.describe()
        )
    });
    assert!(
        !report.disks.is_empty(),
        "a report with no disk is not normal"
    );

    // 2. 🔴 A poller WITHOUT a certificate must be refused. That is the compromised
    //    container on the overlay: it sees the agent, it must get nothing from it.
    let anonymous = hlb_controller::AgentPoller::new(port, Duration::from_secs(5));
    let s = anonymous.poll("localhost").await;
    assert!(
        s.report().is_none(),
        "🔴 a client with no certificate got a report — mTLS protects nothing"
    );

    // 3. A certificate from another authority is no better.
    let other = pki::generate_ca("Attacker CA").await.expect("CA");
    let intruder = pki::issue(&other, "intrus", &["intrus".into()], Purpose::Client)
        .await
        .expect("intrus");
    let fake = hlb_controller::AgentPoller::with_mtls(
        port,
        Duration::from_secs(5),
        &format!("{}{}", intruder.cert_pem, intruder.key_pem),
        &ca.cert_pem,
        "tasks.hlb-agent",
    )
    .expect("poller");
    assert!(
        fake.poll("localhost").await.report().is_none(),
        "🔴 a certificate from another CA was accepted"
    );

    guard.stop();
}
