//! Checks Caddy actually accepts the generated configuration.
//!
//! Generating text that *looks like* a Caddyfile proves nothing. This test submits it
//! to the real Caddy binary - the only way to catch a misplaced directive, an invalid
//! matcher, or a syntax that changed between versions.
//!
//! ```sh
//! export DOCKER_HOST=$(docker context inspect -f '{{.Endpoints.docker.Host}}')
//! cargo test -p hlb-ingress -- --ignored --nocapture
//! ```

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::io::Write;
use std::process::Command;

use hlb_ingress::{render_backend, render_frontend, Config, Route};

const CADDY_IMAGE: &str = "caddy:2-alpine";

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
            CADDY_IMAGE,
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
        .expect("envoi de la config");

    let out = child.wait_with_output().expect("attente de caddy");

    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(
        out.status.success(),
        "Caddy refused the \"{label}\" Caddyfile:\n\
         ───── sortie de caddy ─────\n{stderr}\n\
         ───── generated config ─────\n{caddyfile}"
    );

    println!("✓ {label} accepted by Caddy");
}

fn routes() -> Vec<Route> {
    vec![
        // Gitea : pas d'Anubis (casserait `git clone`), public.
        Route {
            host: "git.example.fr".into(),
            service: "gitea".into(),
            port: 3000,
            through_anubis: false,
            public: true,
            sso_paths: vec!["/user/oauth2/PocketID/callback".into()],
            needs_forward_auth: false,
        },
        // Vikunja: behind Anubis, with the OIDC callback excluded.
        Route {
            host: "tasks.example.fr".into(),
            service: "vikunja".into(),
            port: 3456,
            through_anubis: true,
            public: true,
            sso_paths: vec!["/auth/openid/pocketid".into()],
            needs_forward_auth: false,
        },
        // Vaultwarden: private, reachable from the VPN only.
        Route {
            host: "vault.example.fr".into(),
            service: "vaultwarden".into(),
            port: 80,
            through_anubis: false,
            public: false,
            sso_paths: vec!["/identity/connect/oidc-signin".into()],
            needs_forward_auth: false,
        },
    ]
}

#[test]
#[ignore = "needs Docker"]
fn frontend_config_is_accepted_by_caddy() {
    caddy_validate(&render_frontend(&routes(), &Config::default()), "frontend");
}

#[test]
#[ignore = "needs Docker"]
fn backend_config_is_accepted_by_caddy() {
    caddy_validate(&render_backend(&routes(), &Config::default()), "backend");
}

#[test]
#[ignore = "needs Docker"]
fn an_empty_catalog_still_produces_valid_configs() {
    // The first-boot case: no app installed.
    let cfg = Config::default();
    caddy_validate(&render_frontend(&[], &cfg), "frontend vide");
    caddy_validate(&render_backend(&[], &cfg), "backend vide");
}

#[test]
#[ignore = "needs Docker"]
fn hosts_with_dashes_produce_valid_matchers() {
    // Les noms de matcher Caddy n'acceptent ni points ni tirets.
    let r = Route {
        host: "mon-app.sous-domaine.example.fr".into(),
        service: "mon-app".into(),
        port: 8080,
        through_anubis: true,
        public: true,
        sso_paths: vec!["/oidc/callback".into()],
        needs_forward_auth: false,
    };
    caddy_validate(
        &render_frontend(std::slice::from_ref(&r), &Config::default()),
        "host with hyphens",
    );
    caddy_validate(
        &render_backend(&[r], &Config::default()),
        "backend avec tirets",
    );
}

/// Does forward-auth produce a configuration Caddy accepts?
///
/// 🔴 This test matters more than the others: the forward-auth block mixes
/// `request_header`, `handle`, `forward_auth` and `handle_response`, whose evaluation
/// order in Caddy is not the order they are written in. A mistake here would give a
/// Caddy that refuses to start - or worse, one that starts and authenticates nothing.
#[test]
#[ignore = "needs Docker"]
fn forward_auth_config_is_accepted_by_caddy() {
    let mut r = Route::new("vieux.example.fr", "vieux-truc", 80);
    r.public = true;
    r.needs_forward_auth = true;

    let cfg = Config {
        forward_auth: Some(hlb_ingress::caddyfile::ForwardAuth::default()),
        ..Config::default()
    };

    let out = render_frontend(&[r], &cfg);
    caddy_validate(&out, "frontend avec portail");
}

/// Un mélange réaliste : une app à SSO natif et une app derrière portail.
#[test]
#[ignore = "needs Docker"]
fn a_mixed_frontend_is_accepted_by_caddy() {
    let mut native = Route::new("git.example.fr", "gitea", 3000);
    native.public = true;
    native.sso_paths = vec!["/user/oauth2/PocketID/callback".into()];

    let mut portail = Route::new("vieux.example.fr", "vieux-truc", 80);
    portail.public = true;
    portail.needs_forward_auth = true;
    portail.through_anubis = true;

    let cfg = Config {
        forward_auth: Some(hlb_ingress::caddyfile::ForwardAuth::default()),
        ..Config::default()
    };

    caddy_validate(&render_frontend(&[native, portail], &cfg), "frontend mixte");
}

/// Is the ACME wildcard block syntactically valid?
///
/// ⚠️ `caddy validate` can NOT check the `dns` directive: it comes from a module absent
/// from the standard image. So the structure is validated without it - a partial check,
/// and said rather than left implied.
#[test]
#[ignore = "needs Docker"]
fn the_wildcard_site_block_is_structurally_valid() {
    use hlb_ingress::caddyfile::Acme;

    // With no token and no provider, a bare `tls` is accepted by a standard Caddy:
    // that validates the block's structure (names, nesting, respond) without needing
    // the module.
    let a = Acme {
        provider: "internal".into(),
        api_token: String::new(),
        base_domain: "example.fr".into(),
        staging: false,
    };

    // The `dns` line is REPLACED by a standard sub-directive rather than removed: an
    // empty `tls { }` block is refused by Caddy, and the test would fail on its own
    // scaffolding instead of checking the generator.
    let out = render_frontend(
        &[],
        &Config {
            acme: Some(a),
            ..Config::default()
        },
    )
    .lines()
    .map(|l| {
        if l.trim_start().starts_with("dns ") {
            "\t\tprotocols tls1.2 tls1.3"
        } else {
            l
        }
    })
    .collect::<Vec<_>>()
    .join("\n");

    caddy_validate(&out, "bloc wildcard");
}
