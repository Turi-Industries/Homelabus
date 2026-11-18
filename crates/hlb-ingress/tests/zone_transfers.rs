//! The site's secondary on the real Knot: it transfers the house's signed zone with the
//! shared key, is told of each new serial, keeps serving with the house gone, and a
//! Knot presenting another key gets nothing.
//!
//! Two containers on a network of fixed addresses stand for the two ends of the site
//! link; each runs as the house and the site run it — Knot's user, a read-only root,
//! no capability.
//!
//! ```sh
//! cargo test -p hlb-ingress --test zone_transfers -- --ignored --nocapture
//! ```

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::net::Ipv4Addr;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use hlb_ingress::zone::{self, Transfer, TransferKey, Zone};

fn docker(args: &[&str]) -> (bool, String) {
    let out = Command::new("docker").args(args).output().expect("docker");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.success(), text)
}

fn key() -> TransferKey {
    TransferKey("dGVzdC10cmFuc2Zlci1rZXktdGhpcnR5LXR3by1ieXQ=".into())
}

struct Net {
    id: String,
    /// The third octet of `10.197.x.0/24`: two tests of one run apart.
    octet: u8,
    dir: tempfile::TempDir,
    started: Vec<String>,
}

impl Drop for Net {
    fn drop(&mut self) {
        for c in &self.started {
            docker(&["rm", "-f", c]);
            docker(&["volume", "rm", "-f", c]);
        }
        docker(&["network", "rm", &self.id]);
    }
}

impl Net {
    fn up(tag: &str, octet: u8) -> Self {
        let id = format!("hlb-zone-xfr-{}-{tag}", std::process::id());
        let subnet = format!("10.197.{octet}.0/24");
        let (ok, out) = docker(&["network", "create", "--subnet", &subnet, &id]);
        assert!(ok, "{out}");
        Net {
            id,
            octet,
            dir: tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap(),
            started: Vec::new(),
        }
    }

    fn name(&self, role: &str) -> String {
        format!("{}-{role}", self.id)
    }

    fn at(&self, host: u8) -> Ipv4Addr {
        Ipv4Addr::new(10, 197, self.octet, host)
    }

    /// A Knot at `ip` on `conf`, its volume its own.
    fn knot(&mut self, role: &str, ip: Ipv4Addr, conf: &str) -> String {
        let name = self.name(role);
        let dir = self.dir.path().join(role);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("knot.conf"), conf).unwrap();
        let mount = format!("{}:/etc/knot:ro", dir.display());
        let storage = format!("{name}:{}", zone::STORAGE);
        let ip = ip.to_string();
        let (ok, out) = docker(&[
            "run",
            "-d",
            "--name",
            &name,
            "--network",
            &self.id,
            "--ip",
            &ip,
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
            &mount,
            zone::SITE_IMAGE,
            "sh",
            "-c",
            "mkdir -p /storage/run /storage/hlb && exec knotd -c /etc/knot/knot.conf",
        ]);
        assert!(ok, "{out}");
        self.started.push(name.clone());
        let deadline = Instant::now() + Duration::from_secs(20);
        while !exec(&name, &["knotc", "-s", zone::SOCKET, "status"]).0 {
            assert!(Instant::now() < deadline, "{}", docker(&["logs", &name]).1);
            std::thread::sleep(Duration::from_millis(300));
        }
        name
    }

    /// The house's writer, as the job runs it, into the house's volume.
    fn write(&self, house: &str, z: &Zone) {
        let r = zone::render(z);
        let staged = self.dir.path().join("staged");
        std::fs::create_dir_all(&staged).unwrap();
        std::fs::write(staged.join("zone"), &r.zone).unwrap();
        std::fs::write(staged.join("zone.conf"), &r.conf).unwrap();
        std::fs::write(staged.join("check.conf"), zone::check_conf()).unwrap();
        let staged = format!("{}:/run/hlb:ro", staged.display());
        let storage = format!("{house}:{}", zone::STORAGE);
        let (ok, out) = docker(&[
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
            zone::SITE_IMAGE,
            "sh",
            "-c",
            &zone::writer_script(&z.apex),
        ]);
        assert!(ok, "{out}");
    }
}

fn exec(container: &str, args: &[&str]) -> (bool, String) {
    let mut all = vec!["exec", container];
    all.extend_from_slice(args);
    docker(&all)
}

fn dig(container: &str, name: &str, kind: &str) -> String {
    let port = zone::PORT.to_string();
    exec(
        container,
        &[
            "kdig",
            "@127.0.0.1",
            "-p",
            &port,
            "+dnssec",
            "+norec",
            name,
            kind,
        ],
    )
    .1
}

fn serial(container: &str) -> Option<u32> {
    let port = zone::PORT.to_string();
    let out = exec(
        container,
        &[
            "kdig",
            "@127.0.0.1",
            "-p",
            &port,
            "+norec",
            "lab.test",
            "SOA",
        ],
    )
    .1;
    out.lines()
        .find(|l| l.contains("\tSOA\t"))
        .and_then(zone::soa_serial)
}

fn until(what: &str, container: &str, within: Duration, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + within;
    while !done() {
        assert!(
            Instant::now() < deadline,
            "{what}: {}",
            docker(&["logs", container]).1
        );
        std::thread::sleep(Duration::from_millis(500));
    }
}

fn the_zone(site: Ipv4Addr) -> Zone {
    Zone {
        apex: "lab.test".into(),
        addresses: vec!["10.99.0.40".parse().unwrap()],
        names: vec!["vault.lab.test".into()],
        extra: String::new(),
        transfer: Some(Transfer {
            key: key(),
            site,
            // Two containers: the site's Knot answers on its own port, no publication.
            port: zone::PORT,
        }),
        mail: Vec::new(),
        caa: None,
    }
}

#[test]
#[ignore = "needs Docker"]
fn the_site_transfers_the_signed_zone_follows_it_and_serves_it_alone() {
    let mut net = Net::up("follows", 1);
    let (house_at, site_at) = (net.at(20), net.at(10));
    let house = net.knot("house", house_at, zone::BASE_CONF);
    net.write(&house, &the_zone(site_at));
    let conf = zone::site_conf("lab.test", &[house_at], &key());
    let site = net.knot("site", site_at, &conf);

    until(
        "the site never transferred the zone",
        &site,
        Duration::from_secs(30),
        || dig(&site, "vault.lab.test", "A").contains("RRSIG"),
    );
    let answer = dig(&site, "vault.lab.test", "A");
    assert!(
        answer.contains("10.99.0.40") && answer.contains(" aa"),
        "{answer}"
    );
    assert_eq!(serial(&site), serial(&house));

    // A new name at home reaches the site by NOTIFY, long before the SOA's refresh.
    let mut more = the_zone(site_at);
    more.names.push("photos.lab.test".into());
    net.write(&house, &more);
    until(
        "the site was not told of the new serial",
        &site,
        Duration::from_secs(20),
        || dig(&site, "photos.lab.test", "A").contains("RRSIG"),
    );
    assert_eq!(serial(&site), serial(&house));

    // The house gone, and the site restarted: its journal still holds the zone.
    docker(&["stop", &house]);
    docker(&["restart", &site]);
    until(
        "the site lost the zone with the house",
        &site,
        Duration::from_secs(20),
        || dig(&site, "photos.lab.test", "A").contains("RRSIG"),
    );
}

#[test]
#[ignore = "needs Docker"]
fn a_knot_without_the_key_is_handed_nothing() {
    let mut net = Net::up("stranger", 2);
    let (house_at, stranger_at) = (net.at(20), net.at(30));
    let house = net.knot("house", house_at, zone::BASE_CONF);
    // The stranger stands where the site would: only the key tells them apart.
    net.write(&house, &the_zone(stranger_at));
    let other = TransferKey("b3RoZXItdHJhbnNmZXIta2V5LXRoaXJ0eS10d28tYnk=".into());
    let conf = zone::site_conf("lab.test", &[house_at], &other);
    let stranger = net.knot("stranger", stranger_at, &conf);
    std::thread::sleep(Duration::from_secs(5));
    let answer = dig(&stranger, "vault.lab.test", "A");
    assert!(!answer.contains("10.99.0.40"), "{answer}");
    let logs = docker(&["logs", &stranger]).1;
    assert!(
        logs.contains("refresh, failed (no usable master)"),
        "{logs}"
    );
}

/// Both ends run one Knot: the site's pin is the catalog's.
#[test]
fn the_site_runs_the_catalogs_knot() {
    let manifest = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../catalog/_platform/knot/manifest.yaml"),
    )
    .expect("the catalog's Knot");
    let line = manifest
        .lines()
        .find(|l| l.trim_start().starts_with("image:"))
        .expect("an image line");
    let (repo_tag, digest) = zone::SITE_IMAGE.split_once('@').unwrap();
    let (repo, tag) = repo_tag.split_once(':').unwrap();
    for part in [repo, tag, digest] {
        assert!(line.contains(part), "{part} not in the catalog's {line}");
    }
}
