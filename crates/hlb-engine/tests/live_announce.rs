//! An alert's "Announce" button, end to end on the real images: Gatus raises the
//! alert through the site's ntfy, the button is pressed as the phone presses it — the
//! request the alert itself describes —, the announcer puts the house's words on the
//! page, the owner replaces and follows them through the site's command, and the
//! alert's resolution archives that one entry.
//!
//! The files are the ones `hlb site sync` writes: ntfy's `server.yml`, the page, the
//! announcer's script, client and table, the owner's command. Only the probe's pace is
//! shortened.
//!
//! ```sh
//! cargo test -p hlb-engine --test live_announce -- --ignored --nocapture
//! ```

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use std::time::{Duration, Instant};

use hlb_engine::site_watch;
use hlb_ingress::status_page::{self, Page};

/// A client image with curl, pinned.
const CURL: &str =
    "curlimages/curl:8.11.1@sha256:c1fe1679c34d9784c1b0d1e5f62ac0a79fca01fb6377cdd33e90473c6f9f9a69";

const NETWORK: &str = "hlb-announce-test";
const SUBNET: &str = "172.31.252.0/24";
/// Where "the house" answers once it comes back: nothing listens there at first.
const HOUSE: &str = "172.31.252.20";

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
    containers: Vec<String>,
}

impl Drop for Stand {
    fn drop(&mut self) {
        for c in &self.containers {
            let _ = Command::new("docker").args(["rm", "-f", c]).output();
        }
        let _ = Command::new("docker")
            .args(["network", "rm", NETWORK])
            .output();
    }
}

fn within<T>(secs: u64, what: &str, mut f: impl FnMut() -> Option<T>) -> T {
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        if let Some(v) = f() {
            return v;
        }
        assert!(Instant::now() < deadline, "{what} after {secs} s");
        std::thread::sleep(Duration::from_secs(1));
    }
}

/// curl on the test's network; its body, and the status code on the last line.
fn curl(args: &[&str]) -> (String, String) {
    let mut all = vec![
        "run",
        "--rm",
        "--network",
        NETWORK,
        CURL,
        "-s",
        "-w",
        "\n%{http_code}",
    ];
    all.extend_from_slice(args);
    let out = Command::new("docker").args(&all).output().expect("curl");
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    let (body, code) = text.rsplit_once('\n').unwrap_or(("", &text));
    (body.to_string(), code.to_string())
}

fn write(path: &std::path::Path, content: &str, mode: u32) {
    std::fs::write(path, content).expect("write");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("chmod");
}

fn mkdir(path: &std::path::Path, mode: u32) {
    std::fs::create_dir_all(path).expect("mkdir");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("chmod");
}

#[test]
#[ignore = "needs Docker"]
fn a_pressed_button_puts_the_house_s_words_on_the_page_until_it_is_over() {
    let mut stand = Stand {
        containers: Vec::new(),
    };
    let _ = Command::new("docker")
        .args(["network", "rm", NETWORK])
        .output();
    docker(&["network", "create", "--subnet", SUBNET, NETWORK]);

    let tokens = site_watch::Tokens {
        gatus: site_watch::draw_token(),
        ack: site_watch::draw_token(),
        announcer: site_watch::draw_token(),
    };
    let page = Page {
        probes: Vec::new(),
        house: Some(HOUSE.parse().expect("address")),
        token: tokens.gatus.clone(),
        url: "https://status.example.test".into(),
        push_token: "push-0123456789abcdef".into(),
        alerts_url: "https://alerts.example.test".into(),
        ack_token: tokens.ack.clone(),
    };

    // Containers run as root with no capability: root's files on the VPS, opened to
    // all here, where the test's user owns them.
    let tmp = tempfile::tempdir().expect("tmp");
    let root = tmp.path();
    let (etc, hlb, config) = (root.join("ntfy"), root.join("hlb"), root.join("config"));
    let announced = config.join(site_watch::ANNOUNCED);
    for d in [&etc, &hlb, &config, &config.join(site_watch::LIVE)] {
        mkdir(d, 0o755);
    }
    mkdir(&announced, 0o777);
    write(
        &etc.join("server.yml"),
        &site_watch::ntfy_config("alerts.example.test", "reader-pw", &tokens),
        0o644,
    );
    write(&hlb.join("announce.sh"), &site_watch::announce_sh(), 0o644);
    write(
        &hlb.join("client.yml"),
        &site_watch::announcer_client(&tokens.announcer),
        0o644,
    );
    write(&hlb.join("texts"), &status_page::texts(&page, &[]), 0o644);
    // One probe every five seconds, one miss an outage: the alert within the test.
    let gatus_yaml = status_page::render(&page, &[])
        .replace("interval: 1m", "interval: 5s")
        .replace("failure-threshold: 3", "failure-threshold: 1")
        .replace("success-threshold: 2", "success-threshold: 1");
    write(&config.join(site_watch::GATUS_LIVE), &gatus_yaml, 0o644);

    let ntfy = status_page::NTFY;
    docker(&[
        "run",
        "-d",
        "--name",
        ntfy,
        "--network",
        NETWORK,
        "--tmpfs",
        "/var/cache/ntfy",
        "-v",
        &format!("{}:/etc/ntfy:ro", etc.display()),
        site_watch::NTFY_IMAGE,
        "serve",
    ]);
    stand.containers.push(ntfy.into());
    within(30, "ntfy is not up", || {
        let (body, _) = curl(&[&format!("http://{ntfy}/v1/health")]);
        body.contains("true").then_some(())
    });

    let announcer = site_watch::ANNOUNCER_SERVICE;
    docker(&[
        "run",
        "-d",
        "--name",
        announcer,
        "--network",
        NETWORK,
        "--read-only",
        "--cap-drop",
        "ALL",
        // What the owner's command finds the running task by, as Swarm labels it.
        "--label",
        &format!("com.docker.swarm.service.name={announcer}"),
        "-v",
        &format!("{}:/hlb:ro", hlb.display()),
        "-v",
        &format!("{}:/announced", announced.display()),
        "--entrypoint",
        "sh",
        site_watch::NTFY_IMAGE,
        "/hlb/announce.sh",
    ]);
    stand.containers.push(announcer.into());
    // Subscribed before the alert: ntfy hands a subscription what comes after it.
    std::thread::sleep(Duration::from_secs(3));

    let gatus = status_page::SERVICE;
    docker(&[
        "run",
        "-d",
        "--name",
        gatus,
        "--network",
        NETWORK,
        "--read-only",
        "--tmpfs",
        "/data",
        "--cap-drop",
        "ALL",
        "-v",
        &format!("{}:{}:ro", config.display(), site_watch::MOUNTED_AT),
        "-e",
        &format!(
            "GATUS_CONFIG_PATH={}/{}",
            site_watch::MOUNTED_AT,
            site_watch::LIVE
        ),
        status_page::IMAGE,
    ]);
    stand.containers.push(gatus.into());

    // The alert, as the phone receives it.
    let auth = format!("Authorization: Bearer {}", tokens.announcer);
    let alert = within(60, "no alert reached ntfy", || {
        let (body, _) = curl(&[
            "-H",
            &auth,
            &format!("http://{ntfy}/{}/json?poll=1", status_page::TOPIC),
        ]);
        body.lines()
            .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            .find(|m| m["actions"].is_array())
    });
    assert_eq!(
        alert["title"], "Down: Reached over the site link",
        "{alert}"
    );

    // The button reads nothing.
    let button = &alert["actions"][0];
    let bearer = button["headers"]["Authorization"].as_str().expect("header");
    let (_, code) = curl(&[
        "-H",
        &format!("Authorization: {bearer}"),
        &format!("http://{ntfy}/{}/json?poll=1", status_page::TOPIC),
    ]);
    assert_eq!(code, "403", "the button's token reads the alerts");

    // Pressed: the request the alert describes, sent to the site's ntfy on the overlay
    // rather than through the edge.
    let url = button["url"]
        .as_str()
        .expect("url")
        .replace(&page.alerts_url, &format!("http://{ntfy}"));
    let (_, code) = curl(&[
        "-X",
        button["method"].as_str().expect("method"),
        "-H",
        &format!("Authorization: {bearer}"),
        "-d",
        button["body"].as_str().expect("body"),
        &url,
    ]);
    assert_eq!(code, "200", "the button was refused");

    let shown = |archived: bool| {
        let (body, _) = curl(&[&format!(
            "http://{gatus}:{}/api/v1/config",
            status_page::PORT
        )]);
        let v: serde_json::Value = serde_json::from_str(&body).ok()?;
        let list = v["announcements"].as_array()?.clone();
        let done = list
            .iter()
            .any(|a| a["archived"].as_bool().unwrap_or(false) == archived);
        done.then_some(list)
    };
    let list = within(90, "the announcement is not on the page", || shown(false));
    assert_eq!(list.len(), 1, "{list:?}");
    assert_eq!(list[0]["type"], "outage");
    assert_eq!(
        list[0]["message"],
        "The house cannot be reached: every service may be unavailable. We know, and we \
         are on it."
    );

    // The owner's words, by the command the site keeps for them — the way a phone
    // over SSH reaches the running announcer.
    let command = site_watch::announce_command();
    let owner = |args: &[&str]| {
        let out = Command::new("sh")
            .args(["-c", &command, "hlb-site-announce"])
            .args(args)
            .output()
            .expect("sh");
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).to_string(),
            String::from_utf8_lossy(&out.stderr).to_string(),
        )
    };
    let (ok, listed, err) = owner(&[]);
    assert!(ok, "{err}");
    let id = listed
        .lines()
        .find(|l| l.contains("\tannounced\t"))
        .and_then(|l| l.split('\t').next())
        .expect("an announced notice")
        .to_string();
    let words = "Power cut in the street: back with \"the grid\", $0 lost.";
    let (ok, _, err) = owner(&[&id, "replace", words]);
    assert!(ok, "{err}");
    let (ok, _, err) = owner(&[&id, "follow", "The grid is back, starting."]);
    assert!(ok, "{err}");
    let (ok, _, err) = owner(&[&id, "follow", "two\nlines"]);
    assert!(!ok && err.contains("line break"), "{err}");
    let said = format!("{words} [");
    let list = within(60, "the owner's words are not on the page", || {
        shown(false).filter(|l| {
            l.len() == 1
                && l[0]["message"].as_str().is_some_and(|m| {
                    m.starts_with(&said) && m.ends_with("UTC] The grid is back, starting.")
                })
        })
    });
    let since = list[0]["timestamp"].clone();

    // The house answers again: the alert resolves, and the page archives what it said.
    docker(&[
        "run",
        "-d",
        "--name",
        "hlb-announce-house",
        "--network",
        NETWORK,
        "--ip",
        HOUSE,
        site_watch::NTFY_IMAGE,
        "serve",
    ]);
    stand.containers.push("hlb-announce-house".into());
    let list = within(120, "the announcement is not archived", || {
        shown(true).filter(|l| l.iter().all(|a| a["archived"] == true))
    });
    // One incident, one entry: its time kept, the owner's words, then the house's.
    assert_eq!(list.len(), 1, "{list:?}");
    assert_eq!(list[0]["timestamp"], since);
    assert_eq!(list[0]["type"], "outage");
    let message = list[0]["message"].as_str().expect("message");
    assert!(message.starts_with(&said), "{message}");
    assert!(
        message.ends_with("UTC] The house can be reached again."),
        "{message}"
    );
    let (ok, _, err) = owner(&[&id, "follow", "Late."]);
    assert!(!ok && err.contains("not on the page"), "{err}");

    // What the house reads of the page, as `hlb-privd` mirrors it into the portal:
    // Gatus's own answer, the owner's words first and each addition a follow-up.
    let (body, _) = curl(&[&format!(
        "http://{gatus}:{}/api/v1/config",
        status_page::PORT
    )]);
    let config: site_watch::PageConfig = serde_json::from_str(&body).expect("Gatus's config");
    assert_eq!(config.announcements.len(), 1, "{body}");
    let m = site_watch::mirror(&config.announcements[0], None).expect("mirrored");
    assert!(m.archived);
    assert_eq!(m.timestamp, since.as_str().expect("timestamp"));
    assert_eq!(m.first.body, words);
    assert_eq!(m.first.level, hlb_api::AnnouncementLevel::Incident);
    assert_eq!(m.follow_ups.len(), 2, "{:?}", m.follow_ups);
    assert!(m.follow_ups[1].ends_with("UTC] The house can be reached again."));
}
