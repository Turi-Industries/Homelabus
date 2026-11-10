//! Two replicas of the portal, on the real PocketID and oauth2-proxy the catalog names: a
//! sign-in begun on one and finished on the other, its session accepted by both.
//!
//! Swarm's virtual IP sends each request to either replica, so a person's sign-in is
//! begun by one (the CSRF cookie) and finished by whichever the callback reaches. Both
//! cookies are sealed with `cookie-secret`; a replica with another secret refuses both —
//! which this test also shows, or the first half would prove nothing.
//!
//! ```sh
//! cargo test -p hlb-identity --test live_portal_replicas -- --ignored --nocapture
//! ```

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::process::Command;

use hlb_identity::PocketId;
use hlb_types::manifest::Manifest;
use reqwest::header::{HeaderMap, COOKIE, LOCATION, SET_COOKIE};

const API_KEY: &str = "plaintext-test-key-0123456789";
/// PocketID's name on the network: WebAuthn refuses a relying party without a dot.
const ISSUER_HOST: &str = "id.example.fr";
const APP: &str = "app.example.fr";
const SHARED: &str = "0123456789abcdef0123456789abcdef";
const OTHER: &str = "fedcba9876543210fedcba9876543210";

fn manifest(name: &str) -> Manifest {
    let path = format!(
        "{}/../../catalog/_platform/{name}/manifest.yaml",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_yaml_ng::from_str(&std::fs::read_to_string(path).expect("manifest")).expect("parsed")
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

impl Stand {
    /// Runs `args` on the network, published on a loopback port; its URL.
    fn run(&mut self, name: &str, port: u16, args: &[String]) -> String {
        let mut all = vec![
            "run".to_string(),
            "-d".into(),
            "--name".into(),
            name.into(),
            "--network".into(),
            self.network.clone(),
            "-p".into(),
            format!("127.0.0.1::{port}"),
        ];
        all.extend(args.iter().cloned());
        let all: Vec<&str> = all.iter().map(String::as_str).collect();
        docker(&all);
        self.containers.push(name.to_string());
        let published = docker(&["port", name, &format!("{port}/tcp")]);
        format!("http://{}", published.lines().next().expect("a port"))
    }
}

/// `name=value` of the cookie `name` among the answer's `Set-Cookie`s.
fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .filter_map(|v| v.split(';').next())
        .find(|c| c.starts_with(&format!("{name}=")))
        .map(str::to_string)
}

fn location(headers: &HeaderMap) -> String {
    headers
        .get(LOCATION)
        .and_then(|v| v.to_str().ok())
        .expect("a redirect")
        .to_string()
}

fn query(url: &str) -> &str {
    url.split_once('?').map(|(_, q)| q).expect("a query")
}

/// As Caddy reaches the portal: the app's name, over HTTPS.
fn as_caddy(r: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
    r.header("Host", APP)
        .header("X-Forwarded-Host", APP)
        .header("X-Forwarded-Proto", "https")
}

/// Signs `session` in through the portal: begun at `start`, finished at `finish`. The
/// session cookie, or the status `finish` refused the callback with.
async fn sign_in(
    http: &reqwest::Client,
    pocket_id: &str,
    session: &str,
    start: &str,
    finish: &str,
) -> Result<String, u16> {
    let begun = as_caddy(http.get(format!("{start}/oauth2/start?rd=%2F")))
        .send()
        .await
        .expect("start");
    let csrf = cookie(begun.headers(), "_oauth2_proxy_csrf").expect("a CSRF cookie");
    let authorize = location(begun.headers());

    // PocketID 2.19: `/authorize` opens an interaction, consent completes it, and the
    // same `/authorize` then redirects with the code. Consented once, it redirects at once.
    let mut next = location(
        http.get(format!("{pocket_id}/authorize?{}", query(&authorize)))
            .header(COOKIE, session)
            .send()
            .await
            .expect("authorize")
            .headers(),
    );
    if let Some((_, interaction)) = next.split_once("interaction=") {
        http.post(format!(
            "{pocket_id}/api/oidc/interactions/{interaction}/complete"
        ))
        .header(COOKIE, session)
        .json(&serde_json::json!({
            "step": "consent", "scopes": ["openid", "email", "profile", "groups"],
        }))
        .send()
        .await
        .expect("consent")
        .error_for_status()
        .expect("consented");
        next = location(
            http.get(format!("{pocket_id}/authorize?interaction={interaction}"))
                .header(COOKIE, session)
                .send()
                .await
                .expect("authorize")
                .headers(),
        );
    }
    assert!(
        next.starts_with(&format!("https://{APP}/oauth2/callback?")),
        "{next}"
    );

    let back = as_caddy(http.get(format!("{finish}/oauth2/callback?{}", query(&next))))
        .header(COOKIE, csrf)
        .send()
        .await
        .expect("callback");
    cookie(back.headers(), "_oauth2_proxy").ok_or(back.status().as_u16())
}

async fn auth(http: &reqwest::Client, portal: &str, session: &str) -> u16 {
    as_caddy(http.get(format!("{portal}/oauth2/auth")))
        .header(COOKIE, session)
        .send()
        .await
        .expect("auth")
        .status()
        .as_u16()
}

#[tokio::test]
#[ignore = "needs Docker"]
async fn a_sign_in_begun_on_one_portal_replica_is_finished_and_kept_by_the_other() {
    let tag = std::process::id().to_string();
    let mut stand = Stand {
        network: format!("hlb-portal-{tag}"),
        containers: Vec::new(),
    };
    docker(&["network", "create", &stand.network]);

    let pid = manifest("pocket-id");
    let issuer = format!("http://{ISSUER_HOST}:1411");
    let pocket_id = stand.run(
        &format!("hlb-portal-pid-{tag}"),
        1411,
        &[
            "--network-alias".into(),
            ISSUER_HOST.into(),
            "-e".into(),
            format!("APP_URL={issuer}"),
            "-e".into(),
            "ENCRYPTION_KEY=test-encryption-key-0123456789".into(),
            "-e".into(),
            format!("STATIC_API_KEY={API_KEY}"),
            pid.spec.image.reference(),
        ],
    );
    let mut ready = false;
    for _ in 0..60 {
        if reqwest::get(format!("{pocket_id}/healthz"))
            .await
            .is_ok_and(|r| r.status().as_u16() == 204)
        {
            ready = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    assert!(ready, "PocketID did not start");

    let p = PocketId::new(&pocket_id, API_KEY);
    let client = p
        .create(
            "oauth2-proxy",
            &[format!("https://{APP}/oauth2/callback")],
            false,
        )
        .await
        .expect("client");
    let client_secret = p.regenerate_secret(&client.id).await.expect("secret");
    let person = p
        .create_user("sacha", Some("sacha@example.org"), "Sacha", &[])
        .await
        .expect("person");
    let token = p.one_time_token(&person.id, "1h").await.expect("token");
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("client");
    let signed_in = http
        .post(format!("{pocket_id}/api/one-time-access-token/{token}"))
        .send()
        .await
        .expect("exchange");
    let session = cookie(signed_in.headers(), "access_token").expect("a PocketID session");

    // The portal as the catalog runs it, its two files given as the variables they
    // stand for: the image is distroless, with no shell to write them.
    let portal = manifest("oauth2-proxy");
    let mut env = Vec::new();
    for (k, v) in &portal.spec.env {
        let v = match k.as_str() {
            "OAUTH2_PROXY_OIDC_ISSUER_URL" => issuer.clone(),
            "OAUTH2_PROXY_CLIENT_ID" => client.id.clone(),
            "OAUTH2_PROXY_CLIENT_SECRET_FILE" | "OAUTH2_PROXY_COOKIE_SECRET_FILE" => continue,
            _ => {
                assert!(!v.contains("{{"), "{k} is not filled here: {v}");
                v.clone()
            }
        };
        env.push(format!("{k}={v}"));
    }
    env.push(format!("OAUTH2_PROXY_CLIENT_SECRET={client_secret}"));
    let mut replicas = Vec::new();
    for (name, secret) in [("a", SHARED), ("b", SHARED), ("other", OTHER)] {
        let mut args = Vec::new();
        for e in env
            .iter()
            .cloned()
            .chain([format!("OAUTH2_PROXY_COOKIE_SECRET={secret}")])
        {
            args.extend(["-e".to_string(), e]);
        }
        args.push(portal.spec.image.reference());
        replicas.push(stand.run(&format!("hlb-portal-{name}-{tag}"), 4180, &args));
    }
    let (a, b, other) = (&replicas[0], &replicas[1], &replicas[2]);
    for r in &replicas {
        let mut up = false;
        for _ in 0..30 {
            if http.get(format!("{r}/ping")).send().await.is_ok() {
                up = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
        assert!(up, "{r} did not start");
    }

    let kept = sign_in(&http, &pocket_id, &session, a, b)
        .await
        .expect("begun on one replica, finished on the other");
    assert_eq!(
        auth(&http, a, &kept).await,
        202,
        "the replica that began it"
    );
    assert_eq!(
        auth(&http, b, &kept).await,
        202,
        "the replica that finished it"
    );
    // Without the shared secret, neither half holds: what the test above rests on.
    assert_eq!(auth(&http, other, &kept).await, 401);
    assert_eq!(
        sign_in(&http, &pocket_id, &session, a, other).await,
        Err(403),
        "another secret refuses the CSRF cookie"
    );
    println!("✓ one sign-in across two replicas sharing cookie-secret; another secret refuses it");
}
