//! La PKI produit-elle des certificats qu'une pile TLS accepte réellement ? (§2)
//!
//! 🔴 Un certificat X.509 mal formé est souvent accepté par les outils qui l'écrivent
//! et refusé par ceux qui le lisent. Vérifier que `openssl` a répondu 0 ne prouve
//! rien : ces tests font **valider la chaîne** et contrôlent les extensions une par
//! une, parce que c'est là que se cachent les échecs de production.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use hlb_agent::pki::{self, Purpose};

/// Lance `openssl` et renvoie sa sortie combinée.
fn openssl(args: &[&str]) -> (bool, String) {
    let out = std::process::Command::new("openssl")
        .args(args)
        .output()
        .expect("openssl présent");
    (
        out.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

fn ecrire(dir: &std::path::Path, nom: &str, contenu: &str) -> String {
    let p = dir.join(nom);
    std::fs::write(&p, contenu).expect("écriture");
    p.to_string_lossy().to_string()
}

#[tokio::test]
async fn the_chain_actually_validates() {
    let ca = pki::generate_ca("Homelabus CA de test").await.expect("CA");
    let agent = pki::issue(
        &ca,
        "node1",
        &pki::agent_names("node1", "hlb-agent"),
        Purpose::Server,
    )
    .await
    .expect("certificat agent");

    let d = tempfile::tempdir().expect("répertoire");
    let ca_p = ecrire(d.path(), "ca.crt", &ca.cert_pem);
    let ag_p = ecrire(d.path(), "agent.crt", &agent.cert_pem);

    // 🔴 La preuve qui compte : la chaîne se vérifie, avec l'usage serveur exigé.
    let (ok, sortie) = openssl(&["verify", "-CAfile", &ca_p, "-purpose", "sslserver", &ag_p]);
    assert!(ok, "chaîne invalide :\n{sortie}");
}

#[tokio::test]
async fn a_client_certificate_is_refused_as_a_server() {
    // ⚠️ Sans `extendedKeyUsage`, ça passerait — et ça casserait chez le premier
    // client strict, en production, un mois plus tard.
    let ca = pki::generate_ca("CA").await.expect("CA");
    let client = pki::issue(&ca, "controller", &["controller".into()], Purpose::Client)
        .await
        .expect("certificat client");

    let d = tempfile::tempdir().expect("répertoire");
    let ca_p = ecrire(d.path(), "ca.crt", &ca.cert_pem);
    let cl_p = ecrire(d.path(), "client.crt", &client.cert_pem);

    let (ok_client, _) = openssl(&["verify", "-CAfile", &ca_p, "-purpose", "sslclient", &cl_p]);
    assert!(ok_client, "le certificat client doit valider comme client");

    let (ok_serveur, sortie) =
        openssl(&["verify", "-CAfile", &ca_p, "-purpose", "sslserver", &cl_p]);
    assert!(
        !ok_serveur,
        "un certificat client ne doit PAS valider comme serveur :\n{sortie}"
    );
}

#[tokio::test]
async fn the_overlay_name_is_really_in_the_certificate() {
    // Sans `tasks.<service>` au SAN, le controller ne peut joindre AUCUN agent, avec
    // une erreur qui parle de nom d'hôte et envoie chercher un problème de DNS.
    let ca = pki::generate_ca("CA").await.expect("CA");
    let agent = pki::issue(
        &ca,
        "node1",
        &pki::agent_names("node1", "hlb-agent"),
        Purpose::Server,
    )
    .await
    .expect("certificat");

    let d = tempfile::tempdir().expect("répertoire");
    let p = ecrire(d.path(), "agent.crt", &agent.cert_pem);

    let (_, texte) = openssl(&["x509", "-in", &p, "-noout", "-text"]);
    assert!(texte.contains("DNS:tasks.hlb-agent"), "{texte}");
    assert!(texte.contains("DNS:node1"), "{texte}");
}

#[tokio::test]
async fn a_leaf_cannot_sign_anything() {
    // 🔴 Si une feuille pouvait signer, compromettre un seul agent compromettrait
    // tout le parc.
    let ca = pki::generate_ca("CA").await.expect("CA");
    let agent = pki::issue(&ca, "node1", &["node1".into()], Purpose::Server)
        .await
        .expect("certificat");

    let d = tempfile::tempdir().expect("répertoire");
    let p = ecrire(d.path(), "agent.crt", &agent.cert_pem);

    let (_, texte) = openssl(&["x509", "-in", &p, "-noout", "-text"]);
    assert!(texte.contains("CA:FALSE"), "{texte}");
}

#[tokio::test]
async fn a_certificate_from_another_authority_is_rejected() {
    // La vérification doit REFUSER ce qui vient d'ailleurs, sinon le mTLS ne prouve
    // rien : n'importe qui pourrait forger son propre certificat.
    let ca_a = pki::generate_ca("CA-A").await.expect("CA A");
    let ca_b = pki::generate_ca("CA-B").await.expect("CA B");
    let intrus = pki::issue(&ca_b, "intrus", &["intrus".into()], Purpose::Client)
        .await
        .expect("certificat");

    let d = tempfile::tempdir().expect("répertoire");
    let a_p = ecrire(d.path(), "ca-a.crt", &ca_a.cert_pem);
    let i_p = ecrire(d.path(), "intrus.crt", &intrus.cert_pem);

    let (ok, sortie) = openssl(&["verify", "-CAfile", &a_p, &i_p]);
    assert!(
        !ok,
        "un certificat d'une autre CA doit être REFUSÉ :\n{sortie}"
    );
}

#[tokio::test]
async fn two_authorities_are_never_identical() {
    let a = pki::generate_ca("CA").await.expect("A");
    let b = pki::generate_ca("CA").await.expect("B");
    assert_ne!(a.cert_pem, b.cert_pem);
    assert_ne!(a.key_pem, b.key_pem);
}
