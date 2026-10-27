//! A path a manifest opens to anyone, tried on the real Caddy: it reaches the app with
//! no session, while the rest of the host still goes through the portal.
//!
//! ```sh
//! docker build --target caddy -t hlb-caddy:dev .
//! cargo test -p hlb-ingress --test open_paths -- --ignored --nocapture
//! ```

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::process::Command;

use hlb_ingress::caddyfile::{ForwardAuth, Tls};
use hlb_ingress::{render, Config, Route};

fn image() -> String {
    std::env::var("HLB_CADDY_IMAGE").unwrap_or_else(|_| "hlb-caddy:dev".into())
}

fn docker(args: &[&str]) -> String {
    let out = Command::new("docker").args(args).output().expect("docker");
    assert!(
        out.status.success(),
        "docker {}: {}",
        args.join(" "),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

struct Stand {
    network: String,
    containers: Vec<String>,
}

impl Drop for Stand {
    fn drop(&mut self) {
        for c in &self.containers {
            let _ = Command::new("docker").args(["rm", "-f", c]).output();
        }
        let _ = Command::new("docker")
            .args(["network", "rm", &self.network])
            .output();
    }
}

/// The status Caddy answered `GET path`.
fn status(port: &str, path: &str) -> u16 {
    let resolve = format!("n8n.example.fr:{port}:127.0.0.1");
    let out = Command::new("curl")
        .args([
            "-sk",
            // curl squashes `%2e%2e` segments itself and would send `/webhook/a`.
            "--path-as-is",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            "--resolve",
            &resolve,
        ])
        .arg(format!("https://n8n.example.fr:{port}{path}"))
        .output()
        .expect("curl");
    String::from_utf8_lossy(&out.stdout)
        .parse()
        .unwrap_or_default()
}

#[test]
#[ignore = "needs Docker, curl and the hlb-caddy image"]
fn an_open_path_reaches_the_app_and_the_rest_asks_the_portal() {
    let tag = std::process::id().to_string();
    let mut stand = Stand {
        network: format!("hlb-open-{tag}"),
        containers: Vec::new(),
    };
    docker(&["network", "create", &stand.network]);
    // The app answers 200 to everything; the portal knows nobody.
    for (name, alias, code) in [("app", "n8n", "200"), ("portal", "oauth2-proxy", "401")] {
        let c = format!("hlb-open-{name}-{tag}");
        docker(&[
            "run",
            "-d",
            "--name",
            &c,
            "--network",
            &stand.network,
            "--network-alias",
            alias,
            &image(),
            "caddy",
            "respond",
            "--listen",
            if name == "app" { ":5678" } else { ":4180" },
            "--status",
            code,
            "--body",
            name,
        ]);
        stand.containers.push(c);
    }

    let mut route = Route::new("n8n.example.fr", "n8n", 5678);
    route.needs_forward_auth = true;
    route.allowed_groups = vec!["hlb-admin".into()];
    route.open_paths = vec!["/webhook/*".into()];
    let caddyfile = render(
        &[route],
        &Config {
            tls: Tls::Internal { own_root: false },
            forward_auth: Some(ForwardAuth::default()),
            ..Config::default()
        },
    );
    let ingress = format!("hlb-open-caddy-{tag}");
    let env = format!("CADDYFILE={caddyfile}");
    docker(&[
        "run",
        "-d",
        "--name",
        &ingress,
        "--network",
        &stand.network,
        "-p",
        "127.0.0.1::443",
        "-e",
        &env,
        "--entrypoint",
        "sh",
        &image(),
        "-c",
        "printf '%s' \"$CADDYFILE\" > /tmp/Caddyfile && \
         exec caddy run --config /tmp/Caddyfile --adapter caddyfile",
    ]);
    stand.containers.push(ingress.clone());
    let port = docker(&["port", &ingress, "443/tcp"])
        .rsplit(':')
        .next()
        .expect("a port")
        .to_string();
    let mut up = false;
    for _ in 0..60 {
        if status(&port, "/webhook/up") == 200 {
            up = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    assert!(up, "{caddyfile}\n{}", docker(&["logs", &ingress]));

    assert_eq!(
        status(&port, "/webhook/7c1e-order"),
        200,
        "opened: no session asked"
    );
    // The rest, the editor's test webhooks included, still asks the portal.
    assert_eq!(status(&port, "/workflows"), 302);
    assert_eq!(status(&port, "/webhook-test/7c1e"), 302);
    assert_eq!(status(&port, "/"), 302);
    // Cleaned, these are `/webhook/a`; the app would receive them raw.
    assert_eq!(status(&port, "/rest/x/..%2F..%2Fwebhook/a"), 302);
    assert_eq!(status(&port, "/rest/x/%2e%2e/%2e%2e/webhook/a"), 302);
    println!("✓ /webhook/* past the portal, the rest sent to sign in");
}
