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
            &zone::writer_script(&z.apex, &zone::render(z).children),
        ])
    }

    /// `knsupdate` inside Knot's container, signed with `key` when given; the answer
    /// and whether it was taken.
    fn update(
        &self,
        key: Option<&zone::UpdateKey>,
        origin: &str,
        lines: &[&str],
    ) -> (bool, String) {
        let mut args = vec!["exec".to_string(), "-i".into(), self.server.clone()];
        args.push("knsupdate".into());
        if let Some(k) = key {
            args.push("-y".into());
            args.push(format!(
                "{}:{}:{}",
                zone::UPDATE_ALGORITHM,
                zone::UPDATE_KEY_ID,
                k.0
            ));
        }
        let script = format!(
            "server 127.0.0.1 {}\nzone {origin}.\n{}\nsend\nanswer\n",
            zone::PORT,
            lines.join("\n")
        );
        let mut child = Command::new("docker")
            .args(&args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("docker");
        std::io::Write::write_all(&mut child.stdin.take().unwrap(), script.as_bytes()).unwrap();
        let out = child.wait_with_output().unwrap();
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        (
            out.status.success() && !text.contains("update failed"),
            text,
        )
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
        transfer: None,
        mail: Vec::new(),
        caa: None,
        delegated: None,
    }
}

/// A record as Stalwart writes it, its data the zone line's after the type.
fn stalwart(line: &str) -> zone::Record {
    let mut words = line.split_whitespace();
    let name = words.next().unwrap().trim_end_matches('.').to_string();
    let kind = words.nth(1).unwrap().to_string();
    let data = line.split_once(&format!(" IN {kind} ")).unwrap().1;
    let value = if kind == "TXT" {
        data.split('"').skip(1).step_by(2).collect()
    } else {
        data.to_string()
    };
    zone::Record {
        name,
        kind,
        value,
        line: line.to_string(),
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

/// Stalwart's own lines — an RSA key across lines in `( … )`, absolute names — and the
/// house's CAA pins, as Knot reads them.
#[test]
#[ignore = "needs Docker"]
fn the_houses_mail_and_its_caa_are_signed_with_the_rest() {
    let lab = Lab::up("mail");
    let mut z = the_zone();
    z.mail = [
        "v1-rsa-20261019._domainkey.lab.test. IN TXT (\n    \"v=DKIM1; k=rsa; h=sha256; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApjfTAXunf\"\n    \"ZJ+iTnTjRq7hKHVGM1RiiMBtBdRNZC2NlPeycSEV+/5EI//2/AMhIn/rCQZtYEq58d2a9+KHuIDAQAB\"\n)",
        "mail.lab.test. IN TXT \"v=spf1 a -all\"",
        "lab.test. IN TXT \"v=spf1 mx -all\"",
        "lab.test. IN MX 10 mail.lab.test.",
        "_dmarc.lab.test. IN TXT \"v=DMARC1; p=reject; rua=mailto:postmaster@lab.test\"",
        "_imaps._tcp.lab.test. IN SRV 0 1 993 mail.lab.test.",
    ]
    .map(stalwart)
    .to_vec();
    z.caa = Some(zone::Caa {
        at: "lab.test".into(),
        records: vec![
            "0 issue \"letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/1\""
                .into(),
        ],
    });
    let (ok, out) = lab.write(&z);
    assert!(ok, "{out}");

    let dkim = lab.dig("v1-rsa-20261019._domainkey.lab.test", "TXT");
    assert!(
        dkim.contains("ZJ+iTnTjRq7hKHVGM1Ri") && dkim.contains("RRSIG"),
        "{dkim}"
    );
    let mx = lab.dig("lab.test", "MX");
    assert!(
        mx.contains("10 mail.lab.test.") && mx.contains("RRSIG"),
        "{mx}"
    );
    let txt = lab.dig("lab.test", "TXT");
    assert!(
        txt.contains("v=spf1 mx -all") && txt.contains("\"kept\""),
        "{txt}"
    );
    let srv = lab.dig("_imaps._tcp.lab.test", "SRV");
    assert!(srv.contains("0 1 993 mail.lab.test."), "{srv}");
    let caa = lab.dig("lab.test", "CAA");
    assert!(
        caa.contains("issue \"letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/1\"")
            && caa.contains("RRSIG\tCAA"),
        "{caa}"
    );
}

/// An RSA-2048 DKIM key as Stalwart publishes it: one string past 255 bytes.
const DKIM_P: &str = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u+qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyehkd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdx/Py+ZtHrvO4xqLPxPKp3emH0mlVdUOJqjCDHCtLdMB8WiP2fn1cvpYM4Vgr2E8zRvIbQ4HJqo8M0Ft5V1rlTmeLGkEUv4ZvXXVR6LH1aNC4wO8M18Vwdh/RgB37ty5MbnTd5PRWGQIDAQAB";

/// Once delegated, the challenge and the DKIM keys are zones of their own: the update
/// key writes a TXT where its client writes and nowhere else, what it wrote outlives a
/// republication and a restart, and the house's zone holds each one's DS.
#[test]
#[ignore = "needs Docker"]
fn the_zones_below_are_written_by_their_key_alone_and_outlive_a_publication() {
    let lab = Lab::up("children");
    let key = zone::UpdateKey("6Dq1Ixb3Tn8bJjXyOJKiwq/0aP5Dq8XJm3AOlSxPKkk=".into());
    let mut z = the_zone();
    z.delegated = Some(zone::Delegated {
        key: key.clone(),
        challenge: Some("lab.test".into()),
    });
    z.mail = vec![stalwart(&format!(
        "v1-rsa-20261019._domainkey.lab.test. IN TXT \"v=DKIM1; k=rsa; h=sha256; p={DKIM_P}\""
    ))];
    let (ok, out) = lab.write(&z);
    assert!(ok, "{out}");

    // The DKIM key the house knew is served from its own zone, signed there, whole.
    let dkim = lab.dig("v1-rsa-20261019._domainkey.lab.test", "TXT");
    let joined: String = dkim
        .lines()
        .filter(|l| l.contains("\tTXT\t"))
        .flat_map(|l| {
            l.split('"')
                .skip(1)
                .step_by(2)
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .collect();
    assert!(joined.ends_with(&format!("p={DKIM_P}")), "{dkim}");
    assert!(dkim.contains("RRSIG\tTXT"), "{dkim}");

    // The house's zone delegates each, and its DS is the child's own CDS.
    for child in ["_acme-challenge.lab.test", "_domainkey.lab.test"] {
        let cds = lab
            .exec(&["knotc", "-s", zone::SOCKET, "zone-read", child, "@", "CDS"])
            .1;
        let digest = cds.split_whitespace().last().expect("a CDS").to_string();
        let ds = lab.dig(child, "DS");
        assert!(
            ds.contains(&digest) && ds.contains("RRSIG\tDS"),
            "{cds}\n{ds}"
        );
    }

    let challenge = "_acme-challenge.lab.test";
    let (ok, out) = lab.update(
        Some(&key),
        challenge,
        &[&format!("update add {challenge}. 60 TXT \"token-1\"")],
    );
    assert!(ok, "{out}");
    let (ok, out) = lab.update(
        Some(&key),
        "_domainkey.lab.test",
        &["update add v2-ed-20261118._domainkey.lab.test. 3600 TXT \"v=DKIM1; k=ed25519; p=abc\""],
    );
    assert!(ok, "{out}");

    // Refused: no key, an address, a TXT where Caddy never writes, the house's zone.
    for (key, zone_name, line) in [
        (
            None,
            challenge,
            format!("update add {challenge}. 60 TXT \"forged\""),
        ),
        (
            Some(&key),
            challenge,
            format!("update add {challenge}. 60 A 192.0.2.1"),
        ),
        (
            Some(&key),
            challenge,
            format!("update add x.{challenge}. 60 TXT \"forged\""),
        ),
        (
            Some(&key),
            "lab.test",
            "update add vault.lab.test. 60 TXT \"forged\"".to_string(),
        ),
    ] {
        let (ok, out) = lab.update(key, zone_name, &[&line]);
        assert!(
            !ok && out.contains("status: NOTAUTH"),
            "taken: {line}\n{out}"
        );
    }
    assert!(!lab.dig(challenge, "TXT").contains("forged"));
    assert!(!lab.dig(challenge, "A").contains("192.0.2.1"));

    let written = |lab: &Lab| {
        lab.dig(challenge, "TXT").contains("\"token-1\"")
            && lab
                .dig("v2-ed-20261118._domainkey.lab.test", "TXT")
                .contains("k=ed25519")
    };
    assert!(written(&lab));

    // The next publication, and a restart, keep what was written.
    let mut more = z.clone();
    more.names.push("photos.lab.test".into());
    let (ok, out) = lab.write(&more);
    assert!(ok, "{out}");
    assert!(lab.dig("photos.lab.test", "A").contains("10.99.0.40"));
    assert!(written(&lab), "a publication lost the updates");
    let (ok, out) = docker(&["restart", &lab.server]);
    assert!(ok, "{out}");
    let deadline = Instant::now() + Duration::from_secs(20);
    while !lab.dig("vault.lab.test", "A").contains("RRSIG") {
        assert!(
            Instant::now() < deadline,
            "{}",
            docker(&["logs", &lab.server]).1
        );
        std::thread::sleep(Duration::from_millis(300));
    }
    assert!(written(&lab), "a restart lost the updates");
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
