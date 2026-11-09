//! A private route reached through the front door, on the real Caddy and the real
//! HAProxy: refused, whatever address the visitor has — while the same route still
//! answers someone at home on 443.
//!
//! The visitor sits on a private network the door also reaches, so the PROXY header
//! HAProxy writes carries a private source, as a hostile VPS's would, and the
//! destination HAProxy saw — not the relay port. The lab's Vaultwarden answered such a
//! visitor 200 while Caddy told the relay apart by `{http.request.local.port}`, which
//! the header writes.
//!
//! ```sh
//! docker build --target caddy -t hlb-caddy:dev .
//! cargo test -p hlb-ingress --test relay_is_a_stranger -- --ignored --nocapture
//! ```

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::process::Command;

use hlb_ingress::caddyfile::{Tls, RELAY_HTTPS_PORT};
use hlb_ingress::{render, Config, Route};

/// A client image with curl, pinned.
const CURL: &str =
    "curlimages/curl:8.11.1@sha256:c1fe1679c34d9784c1b0d1e5f62ac0a79fca01fb6377cdd33e90473c6f9f9a69";

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
    networks: Vec<String>,
    containers: Vec<String>,
}

impl Drop for Stand {
    fn drop(&mut self) {
        for c in &self.containers {
            let _ = Command::new("docker").args(["rm", "-f", c]).output();
        }
        for n in &self.networks {
            let _ = Command::new("docker").args(["network", "rm", n]).output();
        }
    }
}

/// The status a client on `network` at `ip` got from `https://git.example.fr` at `to`.
fn status(network: &str, ip: &str, to: &str) -> String {
    let (ip_to, port) = to.split_once(':').expect("address:port");
    let resolve = format!("git.example.fr:{port}:{ip_to}");
    let out = Command::new("docker")
        .args([
            "run",
            "--rm",
            "--network",
            network,
            "--ip",
            ip,
            CURL,
            "-sk",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            "--resolve",
            &resolve,
        ])
        .arg(format!("https://git.example.fr:{port}/"))
        .output()
        .expect("curl");
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

#[test]
#[ignore = "needs Docker, curl and the hlb-caddy image"]
fn a_private_route_refuses_whatever_the_front_door_relays() {
    let tag = std::process::id().to_string();
    // The site link; a private network the door also reaches, where the visitor is;
    // the house's own network, where someone at home reaches Caddy's 443.
    let site = format!("hlb-relay-site-{tag}");
    let lan = format!("hlb-relay-lan-{tag}");
    let home = format!("hlb-relay-home-{tag}");
    let mut stand = Stand {
        networks: Vec::new(),
        containers: Vec::new(),
    };
    docker(&["network", "create", "--subnet", "10.43.0.0/24", &site]);
    stand.networks.push(site.clone());
    docker(&["network", "create", "--subnet", "192.168.77.0/24", &lan]);
    stand.networks.push(lan.clone());
    docker(&["network", "create", "--subnet", "192.168.78.0/24", &home]);
    stand.networks.push(home.clone());

    let app = format!("hlb-relay-app-{tag}");
    docker(&[
        "run",
        "-d",
        "--name",
        &app,
        "--network",
        &site,
        "--network-alias",
        "gitea",
        &image(),
        "caddy",
        "respond",
        "--listen",
        ":3000",
        "--status",
        "200",
        "--body",
        "app",
    ]);
    stand.containers.push(app);

    let mut route = Route::new("git.example.fr", "gitea", 3000);
    route.public = false;
    let caddyfile = render(
        &[route],
        &Config {
            tls: Tls::Internal { own_root: false },
            ..Config::default()
        },
    );
    let caddy = format!("hlb-relay-caddy-{tag}");
    let env = format!("CADDYFILE={caddyfile}");
    docker(&[
        "run",
        "-d",
        "--name",
        &caddy,
        "--network",
        &site,
        "--ip",
        "10.43.0.20",
        "-e",
        &env,
        "--entrypoint",
        "sh",
        &image(),
        "-c",
        "printf '%s' \"$CADDYFILE\" > /tmp/Caddyfile && \
         exec caddy run --config /tmp/Caddyfile --adapter caddyfile",
    ]);
    stand.containers.push(caddy.clone());
    docker(&["network", "connect", "--ip", "192.168.78.20", &home, &caddy]);

    // As the site's door relays 443: the visitor's connection, a PROXY v2 header first.
    let haproxy_cfg = format!(
        "defaults\n\tmode tcp\n\ttimeout connect 5s\n\ttimeout client 30s\n\ttimeout server 30s\n\
         frontend https\n\tbind :8443\n\tdefault_backend house\n\
         backend house\n\tserver caddy 10.43.0.20:{RELAY_HTTPS_PORT} send-proxy-v2\n"
    );
    let door = format!("hlb-relay-door-{tag}");
    let env = format!("CFG={haproxy_cfg}");
    docker(&[
        "create",
        "--name",
        &door,
        "--network",
        &site,
        "--ip",
        "10.43.0.10",
        "-e",
        &env,
        "--entrypoint",
        "sh",
        hlb_ingress::front_door::IMAGE,
        "-c",
        "printf '%s' \"$CFG\" > /tmp/haproxy.cfg && exec haproxy -f /tmp/haproxy.cfg",
    ]);
    stand.containers.push(door.clone());
    docker(&["network", "connect", "--ip", "192.168.77.10", &lan, &door]);
    docker(&["start", &door]);

    let mut last = String::new();
    for _ in 0..60 {
        last = status(&home, "192.168.78.5", "192.168.78.20:443");
        if last == "200" {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    assert_eq!(last, "200", "at home:\n{}", docker(&["logs", &caddy]));

    assert_eq!(
        status(&lan, "192.168.77.5", "192.168.77.10:8443"),
        "403",
        "a visitor the door relays is a stranger, private address or not:\n{}",
        docker(&["logs", &caddy])
    );
    println!("✓ at home 200, through the front door 403");
}
