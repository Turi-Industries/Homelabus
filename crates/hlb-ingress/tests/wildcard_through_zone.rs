//! The wildcard obtained through the house's own zone, once the registrar delegates to
//! it: the real Caddy writes its challenge into the real Knot over RFC 2136, with the
//! update key alone, and an ACME authority asking that Knot validates it.
//!
//! Pebble stands for Let's Encrypt, its resolver the house's Knot — as the internet's
//! is the site's, which serves what the house signs.
//!
//! ```sh
//! docker build --target caddy -t hlb-caddy:dev .
//! cargo test -p hlb-ingress --test wildcard_through_zone -- --ignored --nocapture
//! ```

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::process::Command;
use std::time::{Duration, Instant};

use hlb_ingress::caddyfile::{Tls, Wildcard};
use hlb_ingress::zone::{self, Delegated, UpdateKey, Zone};
use hlb_ingress::{Config, Route};

fn docker(args: &[&str]) -> (bool, String) {
    let out = Command::new("docker").args(args).output().expect("docker");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.success(), text)
}

fn ok(args: &[&str]) -> String {
    let (ok, out) = docker(args);
    assert!(ok, "docker {args:?}: {out}");
    out.trim().to_string()
}

/// Every container and volume of the stand, and its network, gone with it.
struct Stand {
    id: String,
    dir: tempfile::TempDir,
    started: Vec<String>,
}

impl Drop for Stand {
    fn drop(&mut self) {
        for c in &self.started {
            docker(&["rm", "-f", c]);
            docker(&["volume", "rm", "-f", c]);
        }
        docker(&["network", "rm", &self.id]);
    }
}

const SUBNET: &str = "10.198.7";
const PEBBLE_DIR: &str = "https://pebble:14000/dir";

impl Stand {
    fn name(&self, role: &str) -> String {
        format!("{}-{role}", self.id)
    }

    fn at(host: u8) -> String {
        format!("{SUBNET}.{host}")
    }
}

fn knot_image() -> String {
    let manifest = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../catalog/_platform/knot/manifest.yaml"),
    )
    .expect("the catalog's Knot");
    assert!(
        manifest.contains(zone::SITE_IMAGE.split('@').nth(1).unwrap()),
        "the house runs the site's Knot"
    );
    zone::SITE_IMAGE.to_string()
}

#[test]
#[ignore = "needs Docker and the hlb-caddy image"]
fn the_wildcard_is_validated_through_the_houses_zone() {
    let id = format!("hlb-zone-acme-{}", std::process::id());
    let mut stand = Stand {
        id: id.clone(),
        dir: tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap(),
        started: Vec::new(),
    };
    ok(&[
        "network",
        "create",
        "--subnet",
        &format!("{SUBNET}.0/24"),
        &id,
    ]);

    // The house's Knot, answering to `knot` on its network as on the overlay.
    let knot = stand.name("knot");
    let knot_ip = Stand::at(20);
    std::fs::write(stand.dir.path().join("knot.conf"), zone::BASE_CONF).unwrap();
    let conf = format!(
        "{}/knot.conf:/etc/knot/knot.conf:ro",
        stand.dir.path().display()
    );
    let storage = format!("{knot}:{}", zone::STORAGE);
    stand.started.push(knot.clone());
    ok(&[
        "run",
        "-d",
        "--name",
        &knot,
        "--network",
        &id,
        "--ip",
        &knot_ip,
        "--network-alias",
        zone::SERVICE,
        "--user",
        "53:53",
        "--read-only",
        "--tmpfs",
        "/tmp:mode=1777",
        "--cap-drop",
        "ALL",
        "-v",
        &storage,
        "-v",
        &conf,
        &knot_image(),
        "sh",
        "-c",
        "mkdir -p /storage/run /storage/hlb && exec knotd -c /etc/knot/knot.conf",
    ]);
    let deadline = Instant::now() + Duration::from_secs(20);
    while !docker(&["exec", &knot, "knotc", "-s", zone::SOCKET, "status"]).0 {
        assert!(Instant::now() < deadline, "{}", docker(&["logs", &knot]).1);
        std::thread::sleep(Duration::from_millis(300));
    }

    let key = UpdateKey("6Dq1Ixb3Tn8bJjXyOJKiwq/0aP5Dq8XJm3AOlSxPKkk=".into());
    let z = Zone {
        apex: "lab.test".into(),
        addresses: vec!["10.99.0.40".parse().unwrap()],
        names: vec!["vault.home.lab.test".into()],
        extra: String::new(),
        transfer: None,
        mail: Vec::new(),
        caa: None,
        delegated: Some(Delegated {
            key: key.clone(),
            challenge: Some("home.lab.test".into()),
        }),
    };
    let r = zone::render(&z);
    let staged = stand.dir.path().join("staged");
    std::fs::create_dir_all(&staged).unwrap();
    for (path, content) in r.staged() {
        let file = staged.join(std::path::Path::new(path).file_name().unwrap());
        let _ = std::fs::remove_file(&file);
        std::fs::write(&file, content).unwrap();
        // As Swarm mounts a job's files: read-only, to their owner too.
        std::fs::set_permissions(&file, std::os::unix::fs::PermissionsExt::from_mode(0o444))
            .unwrap();
    }
    let staged = format!("{}:/run/hlb:ro", staged.display());
    ok(&[
        "run",
        "--rm",
        "--network",
        "none",
        "--user",
        "53:53",
        "--read-only",
        "--tmpfs",
        "/tmp:mode=1777",
        "--cap-drop",
        "ALL",
        "-v",
        &storage,
        "-v",
        &staged,
        &knot_image(),
        "sh",
        "-c",
        &zone::writer_script(&z.apex, &r.children),
    ]);

    // Pebble, asking the house's Knot for every name.
    let pebble = stand.name("pebble");
    stand.started.push(pebble.clone());
    ok(&[
        "create",
        "--name",
        &pebble,
        "--network",
        &id,
        "--network-alias",
        "pebble",
        "-e",
        "PEBBLE_VA_NOSLEEP=1",
        "-e",
        "PEBBLE_WFE_NONCEREJECT=0",
        "ghcr.io/letsencrypt/pebble:2.8.0",
        "-config",
        "/cfg.json",
        "-dnsserver",
        &format!("{knot_ip}:{}", zone::PORT),
    ]);
    let cfg = stand.dir.path().join("pebble.json");
    std::fs::write(
        &cfg,
        r#"{"pebble":{"listenAddress":"0.0.0.0:14000","managementListenAddress":"0.0.0.0:15000",
            "certificate":"test/certs/localhost/cert.pem","privateKey":"test/certs/localhost/key.pem",
            "httpPort":80,"tlsPort":5001,"ocspResponderURL":"","externalAccountBindingRequired":false}}"#,
    )
    .unwrap();
    ok(&["cp", cfg.to_str().unwrap(), &format!("{pebble}:/cfg.json")]);
    let root = stand.dir.path().join("pebble-root.pem");
    ok(&[
        "cp",
        &format!("{pebble}:/test/certs/pebble.minica.pem"),
        root.to_str().unwrap(),
    ]);
    ok(&["start", &pebble]);
    let root = std::fs::read_to_string(root).unwrap();

    // The house's Caddy, its wildcard written as `hlb_engine::ingress::config` writes a
    // delegated one.
    let caddyfile = hlb_ingress::render(
        &[Route::new("vault.home.lab.test", "vaultwarden", 80)],
        &Config {
            tls: Tls::Acme {
                email: "admin@lab.test".into(),
                wildcard: Some(Wildcard {
                    provider: hlb_ingress::dns::provider("rfc2136").expect("built"),
                    credentials: vec![
                        zone::UPDATE_KEY_ID.into(),
                        zone::UPDATE_ALGORITHM.into(),
                        key.0.clone(),
                        format!("{}:{}", zone::SERVICE, zone::PORT),
                    ],
                    base_domain: "home.lab.test".into(),
                    resolvers: vec![format!("{knot_ip}:{}", zone::PORT)],
                }),
                staging: false,
                ca: Some(PEBBLE_DIR.into()),
                ca_root: true,
            },
            ..Config::default()
        },
    );
    let caddy = stand.name("caddy");
    stand.started.push(caddy.clone());
    let image = std::env::var("HLB_CADDY_IMAGE").unwrap_or_else(|_| "hlb-caddy:dev".into());
    ok(&[
        "run",
        "-d",
        "--name",
        &caddy,
        "--network",
        &id,
        "--ip",
        &Stand::at(80),
        "-e",
        &format!("CADDYFILE={caddyfile}"),
        "-e",
        &format!("ACME_ROOT={root}"),
        "--entrypoint",
        "sh",
        &image,
        "-c",
        &format!(
            "mkdir -p $(dirname {at}) && printf '%s' \"$ACME_ROOT\" > {at} && \
             printf '%s' \"$CADDYFILE\" > /tmp/Caddyfile && \
             exec caddy run --config /tmp/Caddyfile --adapter caddyfile",
            at = hlb_ingress::caddyfile::ACME_ROOT
        ),
    ]);

    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        let logs = docker(&["logs", &caddy]).1;
        if logs.contains("certificate obtained successfully")
            && logs.contains("\"identifier\":\"*.home.lab.test\"")
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "no wildcard through the zone:\n{logs}\n--- knot:\n{}",
            docker(&["logs", &knot]).1
        );
        std::thread::sleep(Duration::from_secs(1));
    }
    // Written with the update key into the zone below, never the house's.
    let knot_logs = docker(&["logs", &knot]).1;
    assert!(
        knot_logs.contains("[_acme-challenge.home.lab.test.] DDNS"),
        "{knot_logs}"
    );
    assert!(!knot_logs.contains("[lab.test.] DDNS"), "{knot_logs}");
}
