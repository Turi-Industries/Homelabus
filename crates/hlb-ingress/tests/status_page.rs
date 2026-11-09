//! The status page's configuration, on the real Gatus against a real Caddy: a public
//! app judged by its answer, a private one by its refusal — and a private app answering
//! strangers judged DOWN, since that is a door left open.
//!
//! Gatus reaches each name at the address it is given (`--add-host`, as the site's
//! service is given the door's), trusting the authority it is told to, as the site's
//! trusts a private ACME directory's root.
//!
//! ```sh
//! docker build --target caddy -t hlb-caddy:dev .
//! cargo test -p hlb-ingress --test status_page -- --ignored --nocapture
//! ```

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::net::Ipv4Addr;
use std::process::Command;
use std::time::{Duration, Instant};

use hlb_ingress::status_page::{self, Page, Probe};

/// A client image with curl, pinned.
const CURL: &str =
    "curlimages/curl:8.11.1@sha256:c1fe1679c34d9784c1b0d1e5f62ac0a79fca01fb6377cdd33e90473c6f9f9a69";

const NETWORK: &str = "hlb-status-page-test";
const CADDY_IP: &str = "172.31.251.10";

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

/// Polls `f` until it answers, or fails the test after `secs`.
fn within<T>(secs: u64, what: &str, mut f: impl FnMut() -> Option<T>) -> T {
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        if let Some(v) = f() {
            return v;
        }
        assert!(Instant::now() < deadline, "{what} after {secs} s");
        std::thread::sleep(Duration::from_millis(500));
    }
}

#[test]
#[ignore = "needs Docker and the hlb-caddy image"]
fn gatus_judges_a_public_app_by_its_answer_and_a_private_one_by_its_refusal() {
    let mut stand = Stand {
        containers: Vec::new(),
    };
    let _ = Command::new("docker")
        .args(["network", "rm", NETWORK])
        .output();
    docker(&["network", "create", "--subnet", "172.31.251.0/24", NETWORK]);

    // The house's Caddy, as a visitor reaches it: Jellyfin answers, Vaultwarden refuses
    // strangers, and a private app left open answers them.
    let caddyfile = "{\n\tlocal_certs\n\tskip_install_trust\n}\n\
                     films.example.test {\n\trespond \"films\" 200\n}\n\
                     vault.example.test {\n\trespond 403\n}\n\
                     leak.example.test {\n\trespond \"open\" 200\n}\n";
    let caddy = "hlb-status-page-caddy";
    let env = format!("CADDYFILE={caddyfile}");
    docker(&[
        "run",
        "-d",
        "--name",
        caddy,
        "--network",
        NETWORK,
        "--ip",
        CADDY_IP,
        "-e",
        &env,
        "--entrypoint",
        "sh",
        &image(),
        "-c",
        "printf '%s' \"$CADDYFILE\" > /tmp/Caddyfile && \
         exec caddy run --config /tmp/Caddyfile --adapter caddyfile",
    ]);
    stand.containers.push(caddy.into());
    let root = within(30, "Caddy made no root", || {
        let out = Command::new("docker")
            .args([
                "exec",
                caddy,
                "cat",
                "/data/caddy/pki/authorities/local/root.crt",
            ])
            .output()
            .ok()?;
        out.status
            .success()
            .then(|| String::from_utf8_lossy(&out.stdout).to_string())
    });

    let probe = |title: &str, host: &str, public| Probe {
        title: title.into(),
        host: host.into(),
        public,
    };
    let page = Page {
        probes: vec![
            probe("Jellyfin", "films.example.test", true),
            probe("Vaultwarden", "vault.example.test", false),
            probe("Leaky", "leak.example.test", false),
        ],
        house: Some(CADDY_IP.parse::<Ipv4Addr>().expect("address")),
        token: "tk_0123456789abcdefghijklmnopqrs".into(),
        url: "https://status.example.test".into(),
        push_token: "push-0123456789abcdef".into(),
    };
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        dir.path().join("gatus.yaml"),
        status_page::render(&page, &[]),
    )
    .expect("write");
    std::fs::write(dir.path().join("root.pem"), root).expect("write");
    let mount = format!(
        "type=bind,src={},dst=/config,readonly",
        dir.path().display()
    );

    let gatus = "hlb-status-page-gatus";
    let mut run = vec![
        "run".to_string(),
        "-d".into(),
        "--name".into(),
        gatus.into(),
        "--network".into(),
        NETWORK.into(),
        "--read-only".into(),
        "--tmpfs".into(),
        "/data".into(),
        "--cap-drop".into(),
        "ALL".into(),
        "--mount".into(),
        mount,
        "-e".into(),
        "GATUS_CONFIG_PATH=/config/gatus.yaml".into(),
        "-e".into(),
        "SSL_CERT_FILE=/config/root.pem".into(),
    ];
    for p in &page.probes {
        run.push("--add-host".into());
        run.push(format!("{}:{CADDY_IP}", p.host));
    }
    run.push(status_page::IMAGE.into());
    docker(&run.iter().map(String::as_str).collect::<Vec<_>>());
    stand.containers.push(gatus.into());

    // Each endpoint is probed once at start: read until all four have a result.
    let statuses = within(60, "Gatus has not probed every endpoint", || {
        let out = Command::new("docker")
            .args([
                "run",
                "--rm",
                "--network",
                NETWORK,
                CURL,
                "-sf",
                "--max-time",
                "5",
                &format!(
                    "http://{gatus}:{}/api/v1/endpoints/statuses",
                    status_page::PORT
                ),
            ])
            .output()
            .ok()?;
        let v: serde_yaml_ng::Value =
            serde_yaml_ng::from_str(&String::from_utf8_lossy(&out.stdout)).ok()?;
        let all = v.as_sequence()?.clone();
        let probed = all
            .iter()
            .filter(|e| e["results"].as_sequence().is_some_and(|r| !r.is_empty()))
            .count();
        (probed == 4).then_some(all)
    });
    let success = |name: &str| {
        let e = statuses
            .iter()
            .find(|e| e["name"].as_str() == Some(name))
            .unwrap_or_else(|| panic!("no endpoint {name}: {statuses:?}"));
        e["results"][0]["success"].as_bool().expect("success")
    };
    assert!(success("Jellyfin"), "{statuses:?}");
    assert!(
        success("Vaultwarden"),
        "refused strangers: up — {statuses:?}"
    );
    assert!(
        !success("Leaky"),
        "a private app open to strangers: down — {statuses:?}"
    );
    assert!(success("Reached over the site link"), "{statuses:?}");
    // The public page names nothing of where: no host, no address in what it serves.
    let served = format!("{statuses:?}");
    for leak in ["example.test", CADDY_IP] {
        assert!(
            !served.contains(leak),
            "{leak} on the public page: {served}"
        );
    }

    // The house's heartbeats, pushed where `push_path` says, with the page's token.
    let push = |path: &str, token: &str| {
        let url = format!("http://{gatus}:{}{path}", status_page::PORT);
        let auth = format!("Authorization: Bearer {token}");
        let out = Command::new("docker")
            .args([
                "run",
                "--rm",
                "--network",
                NETWORK,
                CURL,
                "-s",
                "-o",
                "/dev/null",
                "-w",
                "%{http_code}",
                "-X",
                "POST",
                "-H",
                &auth,
                &url,
            ])
            .output()
            .expect("curl");
        String::from_utf8_lossy(&out.stdout).to_string()
    };
    let controller = status_page::push_path(&status_page::CONTROLLER);
    assert_eq!(push(&format!("{controller}?success=true"), "nope"), "401");
    assert_eq!(
        push(&format!("{controller}?success=true"), &page.push_token),
        "200"
    );
    let backups = status_page::push_path(&status_page::BACKUPS);
    assert_eq!(
        push(
            &format!("{backups}?success=false&error=gitea"),
            &page.push_token
        ),
        "200",
        "a key Gatus does not hold is a 404: {backups}"
    );
    let result = |beat: &status_page::Heartbeat| {
        let key = status_page::key(status_page::HOUSE, beat.name);
        let out = Command::new("docker")
            .args([
                "run",
                "--rm",
                "--network",
                NETWORK,
                CURL,
                "-sf",
                &format!(
                    "http://{gatus}:{}/api/v1/endpoints/{key}/statuses",
                    status_page::PORT
                ),
            ])
            .output()
            .expect("curl");
        let v: serde_yaml_ng::Value =
            serde_yaml_ng::from_str(&String::from_utf8_lossy(&out.stdout)).expect("JSON");
        v["results"][0]["success"].as_bool()
    };
    assert_eq!(result(&status_page::CONTROLLER), Some(true));
    assert_eq!(result(&status_page::BACKUPS), Some(false));
}
