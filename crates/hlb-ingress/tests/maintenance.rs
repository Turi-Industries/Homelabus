//! What a visitor reads while an app is not there, on the real Caddy: the maintenance
//! page, said as a 503 a client can read, with nothing of the overlay in it — and an
//! app's own 5xx passed through as the app said it.
//!
//! ```sh
//! docker build --target caddy -t hlb-caddy:dev .
//! cargo test -p hlb-ingress --test maintenance -- --ignored --nocapture
//! ```

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::process::Command;

use hlb_ingress::caddyfile::{ForwardAuth, Tls, MAINTENANCE_RETRY_SECS};
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

/// The status, the headers (lower-cased) and the body Caddy answered `GET /` at `host`.
fn get(port: &str, host: &str) -> (u16, String, String) {
    let resolve = format!("{host}:{port}:127.0.0.1");
    let out = Command::new("curl")
        .args(["-sk", "-D", "-", "--resolve", &resolve])
        .arg(format!("https://{host}:{port}/"))
        .output()
        .expect("curl");
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or_default();
    (status, head.to_lowercase(), body.to_string())
}

#[test]
#[ignore = "needs Docker, curl and the hlb-caddy image"]
fn an_app_not_there_is_the_maintenance_page_and_an_apps_own_error_is_its_own() {
    let tag = std::process::id().to_string();
    let mut stand = Stand {
        network: format!("hlb-maint-{tag}"),
        containers: Vec::new(),
    };
    docker(&["network", "create", &stand.network]);
    // An app that is there and answers 502 itself, saying why.
    let own = format!("hlb-maint-own-{tag}");
    docker(&[
        "run",
        "-d",
        "--name",
        &own,
        "--network",
        &stand.network,
        "--network-alias",
        "gitea",
        &image(),
        "caddy",
        "respond",
        "--listen",
        ":3000",
        "--status",
        "502",
        "--body",
        "the app's own words",
    ]);
    stand.containers.push(own);

    let mut public = Route::new("git.example.fr", "gitea", 3000);
    public.public = true;
    // Nothing named `vikunja` runs: a stop-first update's gap, or a node gone.
    let mut absent = Route::new("tasks.example.fr", "vikunja", 3456);
    absent.public = true;
    // Behind a portal nobody runs: every private app, while oauth2-proxy is down.
    let mut gated = Route::new("n8n.example.fr", "n8n", 5678);
    gated.needs_forward_auth = true;
    gated.allowed_groups = vec!["hlb-admin".into()];
    let caddyfile = render(
        &[public, absent, gated],
        &Config {
            tls: Tls::Internal { own_root: false },
            forward_auth: Some(ForwardAuth::default()),
            ..Config::default()
        },
    );
    let ingress = format!("hlb-maint-caddy-{tag}");
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
        if get(&port, "git.example.fr").0 == 502 {
            up = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    assert!(up, "{caddyfile}\n{}", docker(&["logs", &ingress]));

    let (status, _, body) = get(&port, "git.example.fr");
    assert_eq!(status, 502);
    assert_eq!(body, "the app's own words", "an app's own error is its own");

    for host in ["tasks.example.fr", "n8n.example.fr"] {
        let (status, head, body) = get(&port, host);
        assert_eq!(status, 503, "{host}: {head}{body}");
        assert!(
            body.contains("<title>Back in a moment</title>"),
            "{host}: {body}"
        );
        assert!(
            head.contains(&format!("retry-after: {MAINTENANCE_RETRY_SECS}\r\n")),
            "{host}: {head}"
        );
        assert!(head.contains("cache-control: no-store"), "{host}: {head}");
        assert!(head.contains("content-type: text/html"), "{host}: {head}");
        // The site's own headers are set before the proxy fails, and stay.
        assert!(head.contains("strict-transport-security"), "{host}: {head}");
        assert!(!head.contains("\r\nserver:"), "{host}: {head}");
        // Nothing of what Caddy knows of the failure: the overlay's names, its resolver.
        for leak in ["vikunja", "oauth2-proxy", "lookup", "dial", "127.0.0.11"] {
            assert!(!body.contains(leak), "{host} says {leak}: {body}");
        }
    }
    println!("✓ absent app and absent portal: the page, 503; the app's own 502 its own");
}
