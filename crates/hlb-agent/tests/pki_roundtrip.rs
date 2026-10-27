//! Does the PKI produce certificates a TLS stack really accepts?
//!
//! 🔴 A malformed X.509 certificate is often accepted by the tools that write it and
//! refused by the ones that read it. Checking that `openssl` returned 0 proves nothing:
//! these tests **validate the chain** and check the extensions one by one, because that
//! is where production failures hide.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use hlb_agent::pki::{self, Purpose};

/// Runs `openssl` and returns its combined output.
fn openssl(args: &[&str]) -> (bool, String) {
    let out = std::process::Command::new("openssl")
        .args(args)
        .output()
        .expect("openssl present");
    (
        out.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

fn write(dir: &std::path::Path, name: &str, content: &str) -> String {
    let p = dir.join(name);
    std::fs::write(&p, content).expect("write");
    p.to_string_lossy().to_string()
}

#[tokio::test]
async fn the_chain_actually_validates() {
    let ca = pki::generate_ca("Homelabus test CA").await.expect("CA");
    let agent = pki::issue(
        &ca,
        "node1",
        &pki::agent_names("node1", "hlb-agent"),
        Purpose::Server,
    )
    .await
    .expect("certificat agent");

    let d = tempfile::tempdir().expect("temp directory");
    let ca_p = write(d.path(), "ca.crt", &ca.cert_pem);
    let ag_p = write(d.path(), "agent.crt", &agent.cert_pem);

    // 🔴 The proof that counts: the chain verifies, with the server usage required.
    let (ok, output) = openssl(&["verify", "-CAfile", &ca_p, "-purpose", "sslserver", &ag_p]);
    assert!(ok, "invalid chain:\n{output}");
}

#[tokio::test]
async fn a_client_certificate_is_refused_as_a_server() {
    // ⚠️ Without `extendedKeyUsage` this would pass — and break on the first strict
    // client, in production, a month later.
    let ca = pki::generate_ca("CA").await.expect("CA");
    let client = pki::issue(&ca, "controller", &["controller".into()], Purpose::Client)
        .await
        .expect("certificat client");

    let d = tempfile::tempdir().expect("temp directory");
    let ca_p = write(d.path(), "ca.crt", &ca.cert_pem);
    let cl_p = write(d.path(), "client.crt", &client.cert_pem);

    let (ok_client, _) = openssl(&["verify", "-CAfile", &ca_p, "-purpose", "sslclient", &cl_p]);
    assert!(
        ok_client,
        "the client certificate must validate as a client"
    );

    let (ok_server, output) =
        openssl(&["verify", "-CAfile", &ca_p, "-purpose", "sslserver", &cl_p]);
    assert!(
        !ok_server,
        "a client certificate must NOT validate as a server:\n{output}"
    );
}

#[tokio::test]
async fn the_overlay_name_is_really_in_the_certificate() {
    // Without `tasks.<service>` in the SAN, the controller can reach NO agent, with an
    // error about a hostname that sends you hunting a DNS problem.
    let ca = pki::generate_ca("CA").await.expect("CA");
    let agent = pki::issue(
        &ca,
        "node1",
        &pki::agent_names("node1", "hlb-agent"),
        Purpose::Server,
    )
    .await
    .expect("certificat");

    let d = tempfile::tempdir().expect("temp directory");
    let p = write(d.path(), "agent.crt", &agent.cert_pem);

    let (_, text) = openssl(&["x509", "-in", &p, "-noout", "-text"]);
    assert!(text.contains("DNS:tasks.hlb-agent"), "{text}");
    assert!(text.contains("DNS:node1"), "{text}");
}

#[tokio::test]
async fn a_leaf_cannot_sign_anything() {
    // 🔴 If a leaf could sign, compromising a single agent would compromise the whole
    // fleet.
    let ca = pki::generate_ca("CA").await.expect("CA");
    let agent = pki::issue(&ca, "node1", &["node1".into()], Purpose::Server)
        .await
        .expect("certificat");

    let d = tempfile::tempdir().expect("temp directory");
    let p = write(d.path(), "agent.crt", &agent.cert_pem);

    let (_, text) = openssl(&["x509", "-in", &p, "-noout", "-text"]);
    assert!(text.contains("CA:FALSE"), "{text}");
}

#[tokio::test]
async fn a_certificate_from_another_authority_is_rejected() {
    // Verification must REFUSE what comes from elsewhere, or the mTLS proves nothing:
    // anyone could forge their own certificate.
    let ca_a = pki::generate_ca("CA-A").await.expect("CA A");
    let ca_b = pki::generate_ca("CA-B").await.expect("CA B");
    let intruder = pki::issue(&ca_b, "intrus", &["intrus".into()], Purpose::Client)
        .await
        .expect("certificat");

    let d = tempfile::tempdir().expect("temp directory");
    let a_p = write(d.path(), "ca-a.crt", &ca_a.cert_pem);
    let i_p = write(d.path(), "intrus.crt", &intruder.cert_pem);

    let (ok, output) = openssl(&["verify", "-CAfile", &a_p, &i_p]);
    assert!(
        !ok,
        "a certificate from another CA must be REFUSED:\n{output}"
    );
}

#[tokio::test]
async fn two_authorities_are_never_identical() {
    let a = pki::generate_ca("CA").await.expect("A");
    let b = pki::generate_ca("CA").await.expect("B");
    assert_ne!(a.cert_pem, b.cert_pem);
    assert_ne!(a.key_pem, b.key_pem);
}
