//! A promoted front door, on the real HAProxy and the real Caddy: the lifeboat's name
//! answered by the site's own Caddy, every other name still relayed home, and plain
//! HTTP redirected to the door's 443 — never to the relay listener's port.
//!
//! The site's Caddy is found by its name on the lifeboat's network, through Docker's
//! resolver, as the door finds it on the site's overlay.
//!
//! ```sh
//! docker build --target caddy -t hlb-caddy:dev .
//! cargo test -p hlb-ingress --test promoted_door -- --ignored --nocapture
//! ```

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::net::Ipv4Addr;
use std::process::Command;

use hlb_ingress::caddyfile::Tls;
use hlb_ingress::front_door::{self, Backend, SITE_CADDY};
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

/// An app answering `body` on `port`, by `alias` on `network`.
fn app(stand: &mut Stand, name: &str, network: &str, alias: &str, port: &str, body: &str) {
    docker(&[
        "run",
        "-d",
        "--name",
        name,
        "--network",
        network,
        "--network-alias",
        alias,
        &image(),
        "caddy",
        "respond",
        "--listen",
        &format!(":{port}"),
        "--status",
        "200",
        "--body",
        body,
    ]);
    stand.containers.push(name.to_string());
}

/// A Caddy running `caddyfile`, on `network` at `ip`, answering to `alias` too.
fn caddy(stand: &mut Stand, name: &str, network: &str, ip: &str, alias: &str, caddyfile: &str) {
    let env = format!("CADDYFILE={caddyfile}");
    docker(&[
        "run",
        "-d",
        "--name",
        name,
        "--network",
        network,
        "--ip",
        ip,
        "--network-alias",
        alias,
        "-e",
        &env,
        "--entrypoint",
        "sh",
        &image(),
        "-c",
        "printf '%s' \"$CADDYFILE\" > /tmp/Caddyfile && \
         exec caddy run --config /tmp/Caddyfile --adapter caddyfile",
    ]);
    stand.containers.push(name.to_string());
}

/// `curl` from the internet's network: `-w` written after the body.
fn curl(network: &str, url: &str, resolve: &str, w: &str) -> String {
    let out = Command::new("docker")
        .args([
            "run",
            "--rm",
            "--network",
            network,
            CURL,
            "-sk",
            "--max-time",
            "10",
            "--resolve",
            resolve,
            "-w",
            w,
            url,
        ])
        .output()
        .expect("curl");
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

#[test]
#[ignore = "needs Docker, curl and the hlb-caddy image"]
fn a_promoted_door_serves_the_lifeboat_from_the_site_and_the_rest_from_home() {
    let tag = std::process::id().to_string();
    let site = format!("hlb-pd-site-{tag}");
    let lifeboat = format!("hlb-pd-lifeboat-{tag}");
    let internet = format!("hlb-pd-internet-{tag}");
    let mut stand = Stand {
        networks: Vec::new(),
        containers: Vec::new(),
    };
    for (net, subnet) in [
        (&site, "10.43.0.0/24"),
        (&lifeboat, "10.0.9.0/24"),
        (&internet, "192.168.79.0/24"),
    ] {
        docker(&["network", "create", "--subnet", subnet, net]);
        stand.networks.push(net.clone());
    }

    // The house: its Caddy on the site link, an app behind it.
    app(
        &mut stand,
        &format!("hlb-pd-home-app-{tag}"),
        &site,
        "gitea",
        "3000",
        "home",
    );
    let mut home_route = Route::new("git.example.fr", "gitea", 3000);
    home_route.public = true;
    let house = render(
        &[home_route],
        &Config {
            tls: Tls::Internal { own_root: false },
            ..Config::default()
        },
    );
    caddy(
        &mut stand,
        &format!("hlb-pd-house-{tag}"),
        &site,
        "10.43.0.20",
        "house",
        &house,
    );

    // The lifeboat: the site's own Caddy and the app it rebuilt, on its overlay.
    app(
        &mut stand,
        &format!("hlb-pd-vault-{tag}"),
        &lifeboat,
        "vaultwarden",
        "8080",
        "lifeboat",
    );
    let mut vault = Route::new("vault.example.fr", "vaultwarden", 8080);
    vault.public = true;
    let on_site = render(
        &[vault],
        &Config {
            tls: Tls::Internal { own_root: false },
            site: Some("10.0.9.0/24".into()),
            ..Config::default()
        },
    );
    let site_caddy = format!("hlb-pd-site-caddy-{tag}");
    caddy(
        &mut stand,
        &site_caddy,
        &lifeboat,
        "10.0.9.20",
        SITE_CADDY,
        &on_site,
    );

    let cfg = front_door::render_promoted(
        &[Backend {
            name: "deb1".into(),
            address: Ipv4Addr::new(10, 43, 0, 20),
        }],
        &["vault.example.fr".into()],
        &[],
    );
    let door = format!("hlb-pd-door-{tag}");
    let env = format!("CFG={cfg}");
    docker(&[
        "create",
        "--name",
        &door,
        "--network",
        &internet,
        "--ip",
        "192.168.79.10",
        "-e",
        &env,
        "--entrypoint",
        "sh",
        front_door::IMAGE,
        "-c",
        "printf '%s' \"$CFG\" > /tmp/haproxy.cfg && exec haproxy -f /tmp/haproxy.cfg",
    ]);
    stand.containers.push(door.clone());
    docker(&["network", "connect", "--ip", "10.43.0.10", &site, &door]);
    docker(&["network", "connect", &lifeboat, &door]);
    docker(&["start", &door]);

    let at = |name: &str, port: u16| format!("{name}:{port}:192.168.79.10");
    let mut last = String::new();
    for _ in 0..60 {
        last = curl(
            &internet,
            "https://vault.example.fr/",
            &at("vault.example.fr", 443),
            " %{http_code}",
        );
        if last == "lifeboat 200" {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    assert_eq!(
        last,
        "lifeboat 200",
        "the lifeboat through the door:\n{}\n{}",
        docker(&["logs", &door]),
        docker(&["logs", &site_caddy])
    );

    let mut home = String::new();
    for _ in 0..30 {
        home = curl(
            &internet,
            "https://git.example.fr/",
            &at("git.example.fr", 443),
            " %{http_code}",
        );
        if home == "home 200" {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    assert_eq!(home, "home 200", "every other name still goes home");

    let redirect = curl(
        &internet,
        "http://vault.example.fr/sync?x=1",
        &at("vault.example.fr", 80),
        "%{http_code} %{redirect_url}",
    );
    assert_eq!(
        redirect, "308 https://vault.example.fr/sync?x=1",
        "to the door's 443, never the relay's port"
    );
    println!("✓ the lifeboat from the site, the rest from home, HTTP to 443");
}
