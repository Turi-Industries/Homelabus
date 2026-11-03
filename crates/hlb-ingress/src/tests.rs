//! Tests for the manifest → routes translation.

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
    serde_yaml_ng::from_str(y).expect("test manifest")
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
    // This is what closes the "first to sign up becomes admin" window.
    let before = routes_from_manifest(&manifest(GITEA), Some("git.example.fr"), false);
    assert!(!before[0].public, "the route must stay internal");

    let after = routes_from_manifest(&manifest(GITEA), Some("git.example.fr"), true);
    assert!(
        after[0].public,
        "once the guide is handled, the route opens"
    );
}

#[test]
fn a_private_manifest_never_becomes_public() {
    let y = GITEA.replace("expose: after-guide", "expose: private");
    let r = routes_from_manifest(&manifest(&y), Some("x.fr"), true);
    assert!(!r[0].public, "private stays private, guide handled or not");
}
