//! The limits the Caddyfile writes, tried on the real Caddy they are written for.
//!
//! `caddy validate` accepts a `rate_limit` that never runs: a sibling installation's
//! limits sat behind the `handle` its sites sent their traffic through, and none had
//! fired since they were written — a limit lowered to 3 let 4 requests in 4 through.
//! Only sending the requests says whether one fires. (That trap needs a `handle` around
//! the proxy, which this Caddyfile does not write: the global order is still `before
//! basic_auth`, so that one written tomorrow does not bring it back.) And the path the
//! limit matches must be the one the app routes — the DECODED one: `%74oken` is
//! `token` to Vaultwarden.
//!
//! ```sh
//! docker build --target caddy -t hlb-caddy:dev .
//! cargo test -p hlb-ingress --test rate_limit_fires -- --ignored --nocapture
//! ```

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::process::Command;

use hlb_ingress::caddyfile::{Tls, AUTH_EVENTS_PER_MINUTE};
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

/// Removes what the test started, whatever happens to it.
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

/// `method path`, with extra headers: the status Caddy answered.
fn status(port: &str, method: &str, path: &str, headers: &[&str]) -> u16 {
    let url = format!("https://vault.example.fr:{port}{path}");
    let resolve = format!("vault.example.fr:{port}:127.0.0.1");
    let mut args = vec![
        "-sk",
        // Sent as written: curl would otherwise merge `//` and decode nothing, and the
        // test would try the clean path twice.
        "--path-as-is",
        "-o",
        "/dev/null",
        "-w",
        "%{http_code}",
        "--resolve",
        &resolve,
        "-X",
        method,
    ];
    for h in headers {
        args.extend(["-H", h]);
    }
    args.push(&url);
    let out = Command::new("curl").args(&args).output().expect("curl");
    String::from_utf8_lossy(&out.stdout)
        .parse()
        .unwrap_or_default()
}

#[test]
#[ignore = "needs Docker, curl and the hlb-caddy image"]
fn a_sign_in_route_is_limited_on_the_path_the_app_routes() {
    let tag = std::process::id().to_string();
    let mut stand = Stand {
        network: format!("hlb-rl-{tag}"),
        containers: Vec::new(),
    };
    docker(&["network", "create", &stand.network]);

    // The app: Caddy again, answering 200 to everything — whatever reaches it.
    let app = format!("hlb-rl-app-{tag}");
    docker(&[
        "run",
        "-d",
        "--name",
        &app,
        "--network",
        &stand.network,
        "--network-alias",
        "vaultwarden",
        &image(),
        "caddy",
        "respond",
        "--listen",
        ":80",
        "--body",
        "app",
    ]);
    stand.containers.push(app);

    let mut route = Route::new("vault.example.fr", "vaultwarden", 80);
    route.public = true;
    route.auth_routes = vec![hlb_types::AuthRoute {
        paths: vec!["/identity/connect/token".into()],
        fails_with: Some(400),
    }];
    let caddyfile = render(
        &[route],
        &Config {
            tls: Tls::Internal { own_root: false },
            ..Config::default()
        },
    );

    let ingress = format!("hlb-rl-caddy-{tag}");
    // By the environment: `docker run -d` attaches no standard input to pipe it into.
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

    // Caddy issues its certificate at start: wait until a request is answered.
    let mut up = false;
    for _ in 0..60 {
        if status(&port, "GET", "/", &[]) == 200 {
            up = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    assert!(up, "{}", docker(&["logs", &ingress]));

    // Other paths are not counted, however many.
    for _ in 0..(AUTH_EVENTS_PER_MINUTE + 5) {
        assert_eq!(status(&port, "POST", "/api/sync", &[]), 200);
    }

    // The sign-in: the limit's worth reaches the app, then 429.
    let token = "/identity/connect/token";
    for i in 0..AUTH_EVENTS_PER_MINUTE {
        assert_eq!(status(&port, "POST", token, &[]), 200, "try {}", i + 1);
    }
    assert_eq!(
        status(&port, "POST", token, &[]),
        429,
        "the limit never fired"
    );
    // 🔴 The same route, spelled the ways the app still routes it.
    assert_eq!(status(&port, "POST", "/identity/connect/%74oken", &[]), 429);
    assert_eq!(status(&port, "POST", "//identity/connect/token", &[]), 429);
    // Jellyfin's routes ignore case, and Caddy's `path` must too.
    assert_eq!(status(&port, "POST", "/Identity/Connect/TOKEN", &[]), 429);

    // A probe never reaches the app.
    assert_eq!(status(&port, "GET", "/.env", &[]), 404);
    assert_eq!(status(&port, "GET", "/wp-login.php", &[]), 404);

    // A write another site's page sent is refused; one from an extension is not.
    let cross = "Sec-Fetch-Site: cross-site";
    assert_eq!(
        status(
            &port,
            "POST",
            "/api/ciphers",
            &[cross, "Origin: https://evil.example"]
        ),
        403
    );
    assert_eq!(
        status(
            &port,
            "POST",
            "/api/ciphers",
            &[cross, "Origin: chrome-extension://abc"]
        ),
        200
    );
    assert_eq!(
        status(
            &port,
            "POST",
            "/api/ciphers",
            &["Sec-Fetch-Site: same-origin"]
        ),
        200
    );
}
