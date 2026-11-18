//! The house's zone on the real Knot: what `hlb` renders is checked, put in place,
//! signed, and served; a zone Knot refuses leaves the one served as it was.
//!
//! The writer runs as the job does — Knot's image, its user, the volume, the staged
//! files — beside a Knot started on the manifest's own configuration.
//!
//! ```sh
//! cargo test -p hlb-ingress --test zone_signs -- --ignored --nocapture
//! ```

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use hlb_ingress::zone::{self, Zone};

/// The catalog's image, read from its manifest: the one the house runs.
fn image() -> String {
    let manifest = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../catalog/_platform/knot/manifest.yaml"),
    )
    .expect("the catalog's Knot");
    let line = manifest
        .lines()
        .find(|l| l.trim_start().starts_with("image:"))
        .expect("an image line");
    let field = |k: &str| {
        let at = line.find(&format!("{k}: ")).expect(k) + k.len() + 2;
        line[at..]
            .split([',', '}'])
            .next()
            .unwrap()
            .trim()
            .trim_matches('"')
            .to_string()
    };
    format!("{}:{}@{}", field("repo"), field("tag"), field("digest"))
}

fn docker(args: &[&str]) -> (bool, String) {
    let out = Command::new("docker").args(args).output().expect("docker");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.success(), text)
}

struct Lab {
    dir: tempfile::TempDir,
    volume: String,
    server: String,
}

impl Drop for Lab {
    fn drop(&mut self) {
        docker(&["rm", "-f", &self.server]);
        docker(&["volume", "rm", "-f", &self.volume]);
    }
}

impl Lab {
    /// `tag` keeps two tests of one run apart.
    fn up(tag: &str) -> Self {
        let id = format!("{}-{tag}", std::process::id());
        let dir = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
        std::fs::write(dir.path().join("knot.conf"), zone::BASE_CONF).unwrap();
        let lab = Lab {
            dir,
            volume: format!("hlb-zone-test-{id}"),
            server: format!("hlb-zone-test-{id}"),
        };
        let conf = format!(
            "{}/knot.conf:/etc/knot/knot.conf:ro",
            lab.dir.path().display()
        );
        let storage = format!("{}:{}", lab.volume, zone::STORAGE);
        // As the manifest runs it: Knot's user, a read-only root, no capability.
        let (ok, out) = docker(&[
            "run",
            "-d",
            "--name",
            &lab.server,
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
            &image(),
            "sh",
            "-c",
            "mkdir -p /storage/run /storage/hlb && exec knotd -c /etc/knot/knot.conf",
        ]);
        assert!(ok, "{out}");
        let deadline = Instant::now() + Duration::from_secs(20);
        while !lab.exec(&["knotc", "-s", zone::SOCKET, "status"]).0 {
            assert!(
                Instant::now() < deadline,
                "Knot never started: {}",
                docker(&["logs", &lab.server]).1
            );
            std::thread::sleep(Duration::from_millis(300));
        }
        lab
    }

    fn exec(&self, args: &[&str]) -> (bool, String) {
        let mut all = vec!["exec", self.server.as_str()];
        all.extend_from_slice(args);
        docker(&all)
    }

    /// The writer, as the job runs it.
    fn write(&self, z: &Zone) -> (bool, String) {
        let r = zone::render(z);
        let staged = self.dir.path().join("staged");
        std::fs::create_dir_all(&staged).unwrap();
        std::fs::write(staged.join("zone"), &r.zone).unwrap();
        std::fs::write(staged.join("zone.conf"), &r.conf).unwrap();
        std::fs::write(staged.join("check.conf"), zone::check_conf()).unwrap();
        let staged = format!("{}:/run/hlb:ro", staged.display());
        let storage = format!("{}:{}", self.volume, zone::STORAGE);
        docker(&[
            "run",
            "--rm",
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
            &image(),
            "sh",
            "-c",
            &zone::writer_script(&z.apex),
        ])
    }

    fn dig(&self, name: &str, kind: &str) -> String {
        let port = zone::PORT.to_string();
        self.exec(&["kdig", "@127.0.0.1", "-p", &port, "+dnssec", name, kind])
            .1
    }
}

fn the_zone() -> Zone {
    Zone {
        apex: "lab.test".into(),
        addresses: vec!["10.99.0.40".parse().unwrap()],
        names: vec!["vault.lab.test".into(), "id.lab.test".into()],
        extra: "@ TXT \"kept\"\n".into(),
    }
}

#[test]
#[ignore = "needs Docker"]
fn the_house_zone_is_signed_and_a_refused_one_changes_nothing() {
    let lab = Lab::up("signs");

    let (ok, out) = lab.write(&the_zone());
    assert!(ok, "{out}");
    assert!(
        out.contains("SOA ns1.lab.test. hostmaster.lab.test."),
        "{out}"
    );

    let answer = lab.dig("vault.lab.test", "A");
    assert!(answer.contains("10.99.0.40"), "{answer}");
    assert!(answer.contains("RRSIG\tA 13 3 300"), "{answer}");
    let txt = lab.dig("lab.test", "TXT");
    assert!(txt.contains("\"kept\""), "{txt}");
    let key = lab
        .exec(&["keymgr", "-c", "/etc/knot/knot.conf", "lab.test", "ds"])
        .1;
    assert!(
        key.contains("lab.test. DS ") && key.contains(" 13 2 "),
        "{key}"
    );

    // A CNAME beside the addresses of a published name: Knot refuses the zone, and
    // nothing of it reaches what is served.
    let mut bad = the_zone();
    bad.names.push("new.lab.test".into());
    bad.extra = "vault CNAME elsewhere.example.\n".into();
    let (ok, out) = lab.write(&bad);
    assert!(!ok, "a refused zone was written: {out}");
    assert!(!lab.dig("new.lab.test", "A").contains("10.99.0.40"));
    assert!(lab.dig("lab.test", "TXT").contains("\"kept\""));

    // A new name reaches what is served at the next publication.
    let mut more = the_zone();
    more.names.push("photos.lab.test".into());
    let (ok, out) = lab.write(&more);
    assert!(ok, "{out}");
    let answer = lab.dig("photos.lab.test", "A");
    assert!(
        answer.contains("10.99.0.40") && answer.contains("RRSIG"),
        "{answer}"
    );
}

#[test]
#[ignore = "needs Docker"]
fn a_knot_not_running_reads_the_zone_when_it_starts() {
    let lab = Lab::up("starts");
    docker(&["stop", &lab.server]);
    let (ok, out) = lab.write(&the_zone());
    assert!(ok, "{out}");
    assert!(out.contains("reads the zone when it starts"), "{out}");
    docker(&["start", &lab.server]);
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if lab.dig("vault.lab.test", "A").contains("RRSIG") {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "{}",
            docker(&["logs", &lab.server]).1
        );
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// The manifest mounts Knot's configuration; the writer writes where it includes.
#[test]
fn the_manifest_runs_knot_on_the_configuration_the_writer_writes_for() {
    let manifest = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../catalog/_platform/knot/manifest.yaml"),
    )
    .expect("the catalog's Knot");
    let block: String = manifest
        .lines()
        .skip_while(|l| !l.trim_start().starts_with("content: |"))
        .skip(1)
        .take_while(|l| l.is_empty() || l.starts_with("        "))
        .map(|l| format!("{}\n", l.get(8..).unwrap_or("")))
        .collect();
    assert_eq!(block, zone::BASE_CONF);
    assert!(manifest.contains(&format!("publishedPorts: [{0}, \"{0}/udp\"]", zone::PORT)));
    assert!(manifest.contains(&format!("\"{}\", \"status\"", zone::SOCKET)));
    assert!(manifest.contains(&format!("name: {}\n", zone::SERVICE)));
}
