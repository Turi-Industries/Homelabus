//! Checks Caddy actually accepts the generated configuration.
//!
//! Generating text that *looks like* a Caddyfile proves nothing. This test submits it
//! to the real Caddy binary — the image the catalog's `caddy` runs, with its DNS and
//! CrowdSec modules, so the `dns` and `crowdsec` directives are checked too: a standard
//! image refuses both, and the test used to cut the `dns` line out to pass.
//!
//! ```sh
//! docker build --target caddy -t hlb-caddy:dev .
//! export DOCKER_HOST=$(docker context inspect -f '{{.Endpoints.docker.Host}}')
//! cargo test -p hlb-ingress -- --ignored --nocapture
//! ```

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::io::Write;
use std::process::Command;

use hlb_ingress::caddyfile::{ForwardAuth, Tls, Wildcard};
use hlb_ingress::{render, CompanionPath, Config, CrowdSec, Route};

fn image() -> String {
    std::env::var("HLB_CADDY_IMAGE").unwrap_or_else(|_| "hlb-caddy:dev".into())
}

/// Submits a Caddyfile to `caddy validate` in a throwaway container.
///
/// The config goes through **stdin**, not a mount: on macOS the host's temp directory
/// is not shared into the Docker VM, and the bind mount fails.
fn caddy_validate(caddyfile: &str, label: &str) {
    let mut child = Command::new("docker")
        .args([
            "run",
            "--rm",
            "-i",
            "--entrypoint",
            "sh",
            &image(),
            "-c",
            "cat > /tmp/Caddyfile && caddy validate --config /tmp/Caddyfile --adapter caddyfile",
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("docker must be reachable (DOCKER_HOST?)");

    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(caddyfile.as_bytes())
        .expect("sending the config");

    let out = child.wait_with_output().expect("waiting for caddy");
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(
        out.status.success(),
        "Caddy refused the \"{label}\" Caddyfile:\n\
         ───── caddy's output ─────\n{stderr}\n\
         ───── generated config ─────\n{caddyfile}"
    );

    println!("✓ {label} accepted by Caddy");
}

fn routes() -> Vec<Route> {
    vec![
        // Gitea: public.
        Route {
            host: "git.example.fr".into(),
            service: "gitea".into(),
            port: 3000,
            public: true,
            needs_forward_auth: false,
            allowed_groups: Vec::new(),
            paths: Vec::new(),
            // `rate_limit` and its global `order` are in every configuration below.
            auth_routes: vec![
                hlb_types::AuthRoute {
                    paths: vec!["/user/login".into(), "/user/two_factor*".into()],
                    fails_with: None,
                },
                hlb_types::AuthRoute {
                    paths: vec!["/api/v1/token".into()],
                    fails_with: Some(401),
                },
            ],
            open_paths: Vec::new(),
        },
        // Vikunja: public.
        Route {
            host: "tasks.example.fr".into(),
            service: "vikunja".into(),
            port: 3456,
            public: true,
            needs_forward_auth: false,
            allowed_groups: Vec::new(),
            paths: Vec::new(),
            auth_routes: Vec::new(),
            open_paths: Vec::new(),
        },
        // Vaultwarden: private, reachable from private addresses only.
        Route {
            host: "vault.example.fr".into(),
            service: "vaultwarden".into(),
            port: 80,
            public: false,
            needs_forward_auth: false,
            allowed_groups: Vec::new(),
            paths: Vec::new(),
            auth_routes: Vec::new(),
            open_paths: Vec::new(),
        },
        // An old app behind the portal, private too.
        Route {
            host: "old.example.fr".into(),
            service: "old-app".into(),
            port: 80,
            public: false,
            needs_forward_auth: true,
            allowed_groups: vec!["hlb-family".into(), "hlb-admin".into()],
            paths: Vec::new(),
            auth_routes: Vec::new(),
            // A webhook path opened to anyone, past the portal and the private ranges.
            open_paths: vec!["/webhook/*".into()],
        },
        // Behind the portal, and no role let in: answered 403 before the portal.
        Route {
            host: "closed.example.fr".into(),
            service: "n8n".into(),
            port: 5678,
            public: true,
            needs_forward_auth: true,
            allowed_groups: Vec::new(),
            paths: Vec::new(),
            auth_routes: Vec::new(),
            open_paths: Vec::new(),
        },
        // A path a companion answers, on a private route.
        Route {
            host: "files.example.fr".into(),
            service: "seafile".into(),
            port: 80,
            public: false,
            needs_forward_auth: false,
            allowed_groups: Vec::new(),
            paths: vec![CompanionPath::stripped(
                "/notification",
                "seafile-notification:8083",
            )],
            auth_routes: Vec::new(),
            open_paths: Vec::new(),
        },
        Route {
            host: "ws.example.fr".into(),
            service: "chat".into(),
            port: 80,
            public: true,
            needs_forward_auth: false,
            allowed_groups: Vec::new(),
            paths: vec![
                CompanionPath::stripped("/socket", "chat-socket:9000"),
                // Handed on whole: Fluxer's api answers its discovery under its name.
                CompanionPath {
                    prefix: "/.well-known/fluxer".into(),
                    upstream: "chat-api:8080".into(),
                    keep_prefix: true,
                },
            ],
            auth_routes: Vec::new(),
            open_paths: Vec::new(),
        },
        // A name outside the wildcard's domain.
        Route::new("photos.other.org", "immich", 2283),
    ]
}

/// Everything at once: bouncer, portal, private routes.
fn full(tls: Tls) -> Config {
    Config {
        crowdsec: Some(CrowdSec {
            api_url: "http://crowdsec:8080".into(),
            api_key: "0123456789abcdef0123456789abcdef".into(),
        }),
        forward_auth: Some(ForwardAuth::default()),
        tls,
        site: None,
    }
}

#[test]
#[ignore = "needs Docker and the hlb-caddy image"]
fn an_empty_installation_still_produces_a_valid_config() {
    // The first-boot case: no app installed.
    caddy_validate(&render(&[], &Config::default()), "empty");
}

#[test]
#[ignore = "needs Docker and the hlb-caddy image"]
fn an_internal_authority_config_is_accepted() {
    caddy_validate(
        &render(&routes(), &full(Tls::Internal { own_root: false })),
        "internal",
    );
}

#[test]
#[ignore = "needs Docker and the hlb-caddy image"]
fn per_name_certificates_are_accepted() {
    let tls = Tls::Acme {
        email: "admin@example.fr".into(),
        wildcard: None,
        staging: true,
        ca: None,
        ca_root: false,
    };
    caddy_validate(&render(&routes(), &full(tls)), "per name, staging");
}

/// The site's own Caddy, as the lifeboat renders it: the relay's listener alone, the
/// redirect of its own, certificates per name over HTTP-01.
#[test]
#[ignore = "needs Docker and the hlb-caddy image"]
fn the_site_s_caddy_is_accepted() {
    let tls = Tls::Acme {
        email: "admin@example.fr".into(),
        wildcard: None,
        staging: true,
        ca: None,
        ca_root: false,
    };
    let mut routes = routes();
    for r in &mut routes {
        r.public = true;
        r.needs_forward_auth = false;
    }
    let cfg = Config {
        tls,
        site: Some("10.0.9.0/24".into()),
        ..Config::default()
    };
    caddy_validate(&render(&routes, &cfg), "the site's");
}

/// 🔴 The one that matters most: every route shares the wildcard's site block, so its
/// matchers must not collide, and `handle` must carry the portal's nested `handle`,
/// `forward_auth` and `handle_response` — whose evaluation order is not the order they
/// are written in.
#[test]
#[ignore = "needs Docker and the hlb-caddy image"]
fn every_provider_s_wildcard_is_accepted() {
    for p in hlb_ingress::dns::PROVIDERS {
        let tls = Tls::Acme {
            email: "admin@example.fr".into(),
            wildcard: Some(Wildcard {
                provider: p,
                // Shaped like real ones: Cloudflare's module refuses a token that is
                // not 40 characters at load time, before anything is requested.
                credentials: p
                    .fields
                    .iter()
                    .map(|f| f.default.map_or_else(|| "a".repeat(40), str::to_string))
                    .collect(),
                base_domain: "example.fr".into(),
            }),
            staging: false,
            ca: None,
            ca_root: false,
        };
        caddy_validate(
            &render(&routes(), &full(tls)),
            &format!("wildcard {}", p.name),
        );
    }
}

/// Every manifest of the catalog, the way it is published: its sign-in routes, its
/// companions' paths, its chain. Routes written for the test prove the shapes; these
/// prove what an installation will actually be handed.
#[test]
#[ignore = "needs Docker and the hlb-caddy image"]
fn the_catalog_s_own_routes_are_accepted() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../catalog");
    let mut manifests = Vec::new();
    for dir in [root.join("apps"), root.join("_platform")] {
        for e in std::fs::read_dir(&dir).expect("the catalog") {
            let path = e.expect("an entry").path().join("manifest.yaml");
            if let Ok(text) = std::fs::read_to_string(&path) {
                let m: hlb_types::Manifest = serde_yaml_ng::from_str(&text).expect("a manifest");
                manifests.push(m);
            }
        }
    }
    let mut routes: Vec<Route> = manifests
        .iter()
        .flat_map(|m| {
            let name = m.metadata.name.clone();
            hlb_ingress::routes_from_manifest(m, Some(&format!("{name}.example.fr")), true)
        })
        .collect();
    for r in &mut routes {
        // The portal's groups come from the roles at publication; one stands for them.
        r.allowed_groups = vec!["hlb-admin".into()];
    }
    assert!(routes.len() >= 15, "only {} routes read", routes.len());
    assert!(
        routes.iter().filter(|r| !r.auth_routes.is_empty()).count() >= 8,
        "the catalog's sign-in routes were not read"
    );
    caddy_validate(
        &render(&routes, &full(Tls::Internal { own_root: false })),
        "the catalog",
    );
}
