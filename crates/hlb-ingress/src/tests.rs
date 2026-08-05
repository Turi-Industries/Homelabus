//! Tests de la traduction manifest → routes.

use super::*;

const GITEA: &str = r#"
apiVersion: hlb/v1
kind: App
metadata: { name: gitea }
spec:
  image: { repo: gitea/gitea, tag: "1.24" }
  requires:
    - kind: sso
      mode: native
      redirectPaths: ["/user/oauth2/PocketID/callback"]
  ingress:
    - host: "{{ domain }}"
      port: 3000
      chain: [caddy-front, caddy-back]
      expose: after-guide
"#;

fn manifest(y: &str) -> Manifest {
    serde_yaml_ng::from_str(y).expect("manifest de test")
}

#[test]
fn the_domain_template_is_resolved() {
    let r = routes_from_manifest(&manifest(GITEA), Some("git.example.fr"), false);
    assert_eq!(r[0].host, "git.example.fr");
    assert_eq!(r[0].service, "gitea");
    assert_eq!(r[0].port, 3000);
}

#[test]
fn after_guide_stays_internal_until_the_guide_is_done() {
    // §4.6bis — c'est ce qui ferme la fenêtre « premier inscrit = admin ».
    let before = routes_from_manifest(&manifest(GITEA), Some("git.example.fr"), false);
    assert!(!before[0].public, "la route doit rester interne");

    let after = routes_from_manifest(&manifest(GITEA), Some("git.example.fr"), true);
    assert!(after[0].public, "une fois le guide traité, la route s'ouvre");
}

#[test]
fn sso_paths_are_collected_for_the_anubis_bypass() {
    let r = routes_from_manifest(&manifest(GITEA), Some("git.example.fr"), true);
    assert_eq!(r[0].sso_paths, vec!["/user/oauth2/PocketID/callback"]);
}

#[test]
fn anubis_is_deduced_from_the_chain() {
    let without = routes_from_manifest(&manifest(GITEA), Some("x.fr"), true);
    assert!(!without[0].through_anubis);

    let with = routes_from_manifest(
        &manifest(&GITEA.replace("[caddy-front, caddy-back]", "[caddy-front, anubis, caddy-back]")),
        Some("x.fr"),
        true,
    );
    assert!(with[0].through_anubis);
}

#[test]
fn a_private_manifest_never_becomes_public() {
    let y = GITEA.replace("expose: after-guide", "expose: private");
    let r = routes_from_manifest(&manifest(&y), Some("x.fr"), true);
    assert!(!r[0].public, "private reste private, guide traité ou non");
}
