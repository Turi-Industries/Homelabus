//! Against a real Stalwart 0.16 — what `hlb-mail` was written from source and never
//! run against until 2026-10-14.
//!
//! The container boots from the same one-line `config.json` the catalog delivers, with
//! its administrator from `STALWART_RECOVERY_ADMIN`: no setup page, no bootstrap mode.
//!
//! ```sh
//! cargo test -p hlb-mail --test live_stalwart -- --ignored --test-threads=1 --nocapture
//! ```
//!
//! `HLB_STALWART_IMAGE` runs it against another release: both majors are driven while
//! installed servers stay on the one they were installed with.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use hlb_mail::{Auth, Stalwart};

const CONTAINER: &str = "hlb-test-stalwart";
const PORT: u16 = 18081;
/// SMTP, where the banner and `EHLO` say Stalwart's name.
const SMTP_PORT: u16 = 18025;
const ADMIN_PASSWORD: &str = "a-test-admin-password-long-enough";

fn image() -> String {
    std::env::var("HLB_STALWART_IMAGE").unwrap_or_else(|_| "stalwartlabs/stalwart:v0.16".into())
}

fn docker(args: &[&str]) -> std::process::Output {
    std::process::Command::new("docker")
        .args(args)
        .output()
        .expect("docker reachable")
}

fn start() -> Stalwart {
    let _ = docker(&["rm", "-f", CONTAINER]);
    let out = docker(&[
        "create",
        "--name",
        CONTAINER,
        "-p",
        &format!("127.0.0.1:{PORT}:8080"),
        "-p",
        &format!("127.0.0.1:{SMTP_PORT}:25"),
        "-e",
        &format!("STALWART_RECOVERY_ADMIN=admin:{ADMIN_PASSWORD}"),
        &image(),
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    // Copied in rather than bind-mounted: a host path is not visible to Docker on
    // macOS, and `docker cp` works the same everywhere.
    let dir = tempfile::tempdir().expect("tmp");
    let config = dir.path().join("config.json");
    std::fs::write(
        &config,
        r#"{"@type":"RocksDb","path":"/var/lib/stalwart/"}"#,
    )
    .expect("write");
    let cp = docker(&[
        "cp",
        config.to_str().expect("path"),
        &format!("{CONTAINER}:/etc/stalwart/config.json"),
    ]);
    assert!(
        cp.status.success(),
        "{}",
        String::from_utf8_lossy(&cp.stderr)
    );
    assert!(docker(&["start", CONTAINER]).status.success());

    let url = format!("http://127.0.0.1:{PORT}");
    for _ in 0..60 {
        let up = std::process::Command::new("curl")
            .args(["-s", "-o", "/dev/null", "-w", "%{http_code}", "-L"])
            .args(["-u", &format!("admin:{ADMIN_PASSWORD}")])
            .arg(format!("{url}/.well-known/jmap"))
            .output()
            .expect("curl");
        if String::from_utf8_lossy(&up.stdout) == "200" {
            return Stalwart::new(
                url,
                Auth::Basic {
                    user: "admin".into(),
                    password: ADMIN_PASSWORD.into(),
                },
            );
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    panic!(
        "Stalwart did not come up: {}",
        String::from_utf8_lossy(&docker(&["logs", CONTAINER]).stderr)
    );
}

fn stop() {
    let _ = docker(&["rm", "-f", CONTAINER]);
}

#[tokio::test]
#[ignore = "needs Docker"]
async fn a_mailbox_is_provisioned_end_to_end() {
    let s = start();
    s.ping().await.expect("the admin is accepted");
    // Every renamed field is written by what this says: read wrong, nothing is created.
    let expected = if image().contains(":v0.16") {
        hlb_mail::Generation::V016
    } else {
        hlb_mail::Generation::V1
    };
    assert_eq!(
        s.generation().await.expect("session"),
        expected,
        "{}",
        image()
    );

    // A fresh server hosts no domain: the first mailbox creates it.
    let first = s
        .ensure_account("gitea@example.org", "an-app-password-123456", &[])
        .await
        .expect("account");
    assert!(first.created);
    let again = s
        .ensure_account("gitea@example.org", "ANOTHER-password-999", &[])
        .await
        .expect("account again");
    assert!(
        !again.created,
        "an existing account is kept, password untouched"
    );
    assert_eq!(again.account_id, first.account_id);
    let d1 = s
        .domain_id("example.org")
        .await
        .expect("domain created with it");
    assert_eq!(s.ensure_domain("example.org").await.expect("again"), d1);
    println!("✓ domain {d1} created with the first mailbox, once");
    println!("✓ account {} (kept on rerun)", first.account_id);

    assert!(s
        .add_alias("gitea@example.org", "noreply")
        .await
        .expect("alias"));
    assert!(!s
        .add_alias("gitea@example.org", "noreply")
        .await
        .expect("alias twice"));
    let aliases = s.aliases_of(&first.account_id).await.expect("aliases");
    assert!(
        aliases.iter().any(|a| a.starts_with("noreply")),
        "{aliases:?}"
    );
    assert!(s
        .remove_alias("gitea@example.org", "noreply")
        .await
        .expect("remove"));
    assert!(!s
        .aliases_of(&first.account_id)
        .await
        .expect("aliases")
        .iter()
        .any(|a| a.starts_with("noreply")));
    println!("✓ alias added once, read back, removed");

    let blob = s
        .upload_blob(&first.account_id, "require \"fileinto\";\n")
        .await
        .expect("upload");
    let back = s
        .download_blob(&first.account_id, &blob)
        .await
        .expect("download");
    assert_eq!(back, "require \"fileinto\";\n");
    println!("✓ blob round trip");

    // The production renderer: it puts the `require` first, where Sieve wants it.
    let rules = [hlb_users::sieve::Rule::new("shop-x1", "Shops")];
    let script = s
        .apply_sieve("gitea@example.org", &|existing| {
            hlb_users::sieve::merge(existing, &rules)
        })
        .await
        .expect("sieve");
    let (_, blob) = s
        .active_sieve_script(&first.account_id)
        .await
        .expect("read sieve")
        .expect("an ACTIVE script — `onSuccessActivateScript` took");
    let active = s
        .download_blob(&first.account_id, &blob)
        .await
        .expect("script content");
    assert_eq!(active, script);
    // A second run replaces Homelabus's block and keeps the rest: one block, not two.
    let again = s
        .apply_sieve("gitea@example.org", &|existing| {
            hlb_users::sieve::merge(existing, &rules)
        })
        .await
        .expect("sieve again");
    assert_eq!(again.matches("require [").count(), 1, "{again}");
    println!("✓ sieve script written and active");

    stop();
}

#[tokio::test]
#[ignore = "needs Docker"]
async fn an_account_is_deleted_by_its_address_and_a_wrong_password_opens_nothing() {
    let s = start();
    s.ensure_account("gitea@example.org", "an-app-password-123456", &[])
        .await
        .expect("account");
    s.ensure_account("other@example.org", "another-password-123456", &[])
        .await
        .expect("account");

    assert!(s
        .accepts("gitea@example.org", "an-app-password-123456")
        .await
        .expect("asked"));
    assert!(!s
        .accepts("gitea@example.org", "not-its-password-123456")
        .await
        .expect("asked"));

    assert!(s.destroy_account("gitea@example.org").await.expect("gone"));
    assert!(!s.destroy_account("gitea@example.org").await.expect("none"));
    assert!(!s.destroy_account("gitea@nowhere.test").await.expect("none"));
    let domain = s.domain_id("example.org").await.expect("domain");
    assert_eq!(s.find_account("gitea", &domain).await.expect("query"), None);
    assert!(s
        .find_account("other", &domain)
        .await
        .expect("query")
        .is_some());
    stop();
}

#[tokio::test]
#[ignore = "needs Docker"]
async fn postmaster_and_abuse_reach_whoever_opens_the_shared_mailbox() {
    let s = start();
    let alice = s
        .ensure_account("alice@example.org", "alice-password-0123456789", &[])
        .await
        .expect("alice");
    let pm = s
        .ensure_shared_mailbox("postmaster", "example.org", &["abuse"])
        .await
        .expect("postmaster");
    assert_eq!(
        s.ensure_shared_mailbox("postmaster", "example.org", &["abuse"])
            .await
            .expect("again"),
        pm,
        "made once"
    );
    assert_eq!(
        s.shared_mailbox("postmaster", "example.org")
            .await
            .expect("read"),
        Some(pm.clone())
    );
    // A personal account of that name is never turned into the shared one.
    let err = s
        .ensure_shared_mailbox("alice", "example.org", &[])
        .await
        .expect_err("a person's mailbox");
    assert!(err.to_string().contains("personal account"), "{err}");

    assert!(s.members_of(&pm).await.expect("members").is_empty());
    s.set_member(&alice.account_id, &pm, true)
        .await
        .expect("join");
    assert_eq!(
        s.members_of(&pm).await.expect("members"),
        vec![alice.account_id.clone()]
    );

    // From outside, on 25: both addresses land in the shared mailbox.
    for rcpt in ["postmaster@example.org", "abuse@example.org"] {
        let (rc, out) = curl_on(
            &format!("container:{CONTAINER}"),
            "",
            &[
                "--mail-from",
                "someone@outside.example.net",
                "--mail-rcpt",
                rcpt,
                "-T",
                "-",
                // The path is the EHLO name: curl otherwise greets as the bare IP,
                // which Stalwart answers 550.
                "smtp://127.0.0.1:25/outside.example.net",
            ],
        );
        assert_eq!(rc, 0, "{rcpt}: {out}");
    }
    let read = || async {
        let body = serde_json::json!({
            "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
            "methodCalls": [["Email/query", { "accountId": pm }, "0"]],
        });
        let r: serde_json::Value = reqwest::Client::new()
            .post(format!("http://127.0.0.1:{PORT}/jmap/"))
            .basic_auth("alice@example.org", Some("alice-password-0123456789"))
            .json(&body)
            .send()
            .await
            .expect("jmap")
            .json()
            .await
            .expect("json");
        r["methodResponses"][0][1]["ids"]
            .as_array()
            .map_or(0, Vec::len)
    };
    let mut seen = 0;
    for _ in 0..20 {
        seen = read().await;
        if seen == 2 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    assert_eq!(seen, 2, "a member reads both in the shared mailbox");

    s.set_member(&alice.account_id, &pm, false)
        .await
        .expect("leave");
    assert!(s.members_of(&pm).await.expect("members").is_empty());
    println!("✓ postmaster@ and abuse@ delivered to the shared mailbox its member opens");
    stop();
}

#[tokio::test]
#[ignore = "needs Docker"]
async fn the_platform_network_is_never_banned_and_a_ban_lasts_a_day() {
    let s = start();
    s.ensure_account("alice@example.org", "alice-password-0123456789", &[])
        .await
        .expect("alice");
    let net = "hlb-test-stalwart-ban";
    let _ = docker(&["network", "rm", net]);
    assert!(docker(&["network", "create", net]).status.success());
    assert!(docker(&["network", "connect", net, CONTAINER])
        .status
        .success());
    let subnet = String::from_utf8_lossy(
        &docker(&[
            "network",
            "inspect",
            "-f",
            "{{range .IPAM.Config}}{{.Subnet}}{{end}}",
            net,
        ])
        .stdout,
    )
    .trim()
    .to_string();
    // `n` wrong passwords then the right one, from `net`: did the right one get in?
    let attempts = |n: u32| {
        let script = format!(
            "for i in $(seq 1 {n}); do curl -sk --max-time 5 -u alice@example.org:wrong$i \
             imaps://{CONTAINER}:993/ >/dev/null 2>&1; done; \
             curl -sk --max-time 5 -u alice@example.org:alice-password-0123456789 \
             imaps://{CONTAINER}:993/ >/dev/null"
        );
        docker(&[
            "run",
            "--rm",
            "--network",
            net,
            "--entrypoint",
            "sh",
            "curlimages/curl:8.11.1",
            "-c",
            &script,
        ])
        .status
        .success()
    };
    assert_eq!(s.auth_ban_period().await.expect("read"), None, "for ever");
    assert!(
        !attempts(101),
        "banned after a hundred failures, right password included"
    );

    assert!(s.trust_network(&subnet, "test").await.expect("trust"));
    assert!(
        !s.trust_network(&subnet, "test").await.expect("again"),
        "once"
    );
    assert!(attempts(0), "the ban already there is lifted");
    assert!(attempts(120), "and none comes back");

    s.set_auth_ban_period(86_400_000).await.expect("set");
    assert_eq!(s.auth_ban_period().await.expect("read"), Some(86_400_000));
    println!("✓ {subnet} never banned, a ban already on it lifted, a ban a day long");
    stop();
    let _ = docker(&["network", "rm", net]);
}

/// The banner and the `EHLO` reply, as a sending server reads them.
fn smtp_greeting() -> String {
    use std::io::{BufRead, BufReader, Write};
    let stream = std::net::TcpStream::connect(("127.0.0.1", SMTP_PORT)).expect("SMTP is published");
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .expect("timeout");
    let mut reader = BufReader::new(stream.try_clone().expect("clone"));
    let mut out = String::new();
    reader.read_line(&mut out).expect("banner");
    (&stream)
        .write_all(b"EHLO probe.example\r\n")
        .expect("EHLO");
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).expect("EHLO reply");
        out.push_str(&line);
        // The last line of a multi-line reply has a space after its code.
        if line.len() < 4 || line.as_bytes()[3] == b' ' {
            break;
        }
    }
    let _ = (&stream).write_all(b"QUIT\r\n");
    out
}

#[tokio::test]
#[ignore = "needs Docker"]
async fn stalwart_answers_as_the_name_it_is_given() {
    let s = start();
    let before = smtp_greeting();
    assert!(
        !before.contains("mail.example.org"),
        "a fresh Stalwart says its container's name: {before}"
    );
    let id = s.ensure_domain("example.org").await.expect("domain");
    s.set_identity("mail.example.org", &id)
        .await
        .expect("named");
    let after = smtp_greeting();
    assert!(
        after.starts_with("220 mail.example.org "),
        "the banner: {after}"
    );
    assert!(
        after.contains("250-mail.example.org ") || after.contains("250 mail.example.org "),
        "EHLO: {after}"
    );
    let read = s.identity().await.expect("read back");
    assert_eq!(read.hostname, "mail.example.org");
    assert_eq!(read.default_domain_id, id);
    println!("✓ was {}", before.lines().next().unwrap_or(""));
    println!("✓ now {}", after.lines().next().unwrap_or(""));
    stop();
}

/// curl on `network`, trusting `root`: its exit code and what it said.
fn curl_on(network: &str, root: &str, args: &[&str]) -> (i32, String) {
    let mut cmd = vec![
        "run",
        "--rm",
        "--network",
        network,
        "-e",
        "ROOT",
        "--entrypoint",
        "sh",
        "curlimages/curl:8.11.1",
        "-c",
        r#"printf '%s' "$ROOT" > /tmp/root.pem; printf 'Subject: hlb probe\r\n\r\nprobe\r\n' | curl -sS --max-time 20 --cacert /tmp/root.pem "$@""#,
        "curl",
    ];
    cmd.extend_from_slice(args);
    let out = std::process::Command::new("docker")
        .env("ROOT", root)
        .args(&cmd)
        .output()
        .expect("docker reachable");
    (
        out.status.code().unwrap_or(-1),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

/// What `kind: smtp` relies on, on a real 0.16 — each line was found by hand on
/// 2026-10-18, and a Stalwart update that changes one breaks every app's mail.
#[tokio::test]
#[ignore = "needs Docker"]
async fn an_app_account_sends_on_submission_as_itself_only() {
    const NAME: &str = "hlb-test-stalwart-smtp";
    const NET: &str = "hlb-test-mail";
    const API: u16 = 18082;
    let _ = docker(&["rm", "-f", NAME]);
    let _ = docker(&["network", "rm", NET]);
    assert!(docker(&["network", "create", NET]).status.success());
    let created = docker(&[
        "create",
        "--name",
        NAME,
        "--network",
        NET,
        "--network-alias",
        "stalwart",
        "-p",
        &format!("127.0.0.1:{API}:8080"),
        "-e",
        &format!("STALWART_RECOVERY_ADMIN=admin:{ADMIN_PASSWORD}"),
        &image(),
    ]);
    assert!(created.status.success(), "{created:?}");
    let dir = tempfile::tempdir().expect("tmp");
    let config = dir.path().join("config.json");
    std::fs::write(
        &config,
        r#"{"@type":"RocksDb","path":"/var/lib/stalwart/"}"#,
    )
    .expect("write");
    assert!(docker(&[
        "cp",
        config.to_str().expect("path"),
        &format!("{NAME}:/etc/stalwart/config.json")
    ])
    .status
    .success());
    let up = || async {
        let s = Stalwart::new(
            format!("http://127.0.0.1:{API}"),
            Auth::Basic {
                user: "admin".into(),
                password: ADMIN_PASSWORD.into(),
            },
        );
        for _ in 0..60 {
            if s.ping().await.is_ok() {
                return s;
            }
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
        panic!("Stalwart did not answer");
    };
    assert!(docker(&["start", NAME]).status.success());
    let s = up().await;

    // A fresh server does not listen on 587, and serves a certificate naming nothing.
    assert!(!s.has_submission().await.expect("listeners"));
    let root = hlb_agent::pki::generate_web_root("Homelabus test")
        .await
        .expect("root");
    let leaf = hlb_agent::pki::issue_platform_server(&root, "stalwart")
        .await
        .expect("leaf");
    s.add_certificate(&leaf.cert_pem, &leaf.key_pem)
        .await
        .expect("certificate");
    assert!(s
        .certificates()
        .await
        .expect("certificates")
        .iter()
        .any(|c| c.names.iter().any(|n| n == "stalwart")));
    // Stored at once, bound at the next start only.
    s.add_submission().await.expect("listener");
    assert!(s.has_submission().await.expect("listeners"));
    assert!(docker(&["restart", NAME]).status.success());
    let s = up().await;

    s.ensure_account("vikunja@example.org", "vikunja-password-0123456789", &[])
        .await
        .expect("sender");
    s.ensure_account("alice@example.org", "alice-password-0123456789", &[])
        .await
        .expect("recipient");
    let url = "smtp://stalwart:587";
    let auth = |user: &str| format!("{user}:vikunja-password-0123456789");
    // The login is the address: the name is refused.
    let (rc, out) = curl_on(
        NET,
        &root.cert_pem,
        &["--ssl-reqd", "-u", &auth("vikunja"), "-X", "NOOP", url],
    );
    assert_eq!(rc, 67, "{out}");
    let (rc, out) = curl_on(
        NET,
        &root.cert_pem,
        &[
            "--ssl-reqd",
            "-u",
            &auth("vikunja@example.org"),
            "-X",
            "NOOP",
            url,
        ],
    );
    assert_eq!(rc, 0, "{out}");
    // As itself, delivered; as anyone else, refused at MAIL FROM (curl 55).
    let send = |from: &str| {
        curl_on(
            NET,
            &root.cert_pem,
            &[
                "--ssl-reqd",
                "-u",
                &auth("vikunja@example.org"),
                "--mail-from",
                from,
                "--mail-rcpt",
                "alice@example.org",
                "-T",
                "-",
                url,
            ],
        )
    };
    let (rc, out) = send("vikunja@example.org");
    assert_eq!(rc, 0, "{out}");
    let (rc, out) = send("postmaster@example.org");
    assert_eq!(rc, 55, "an account sends as itself only: {out}");
    // And it arrived — read back over IMAPS, under the same certificate.
    let (rc, out) = curl_on(
        NET,
        &root.cert_pem,
        &[
            "-u",
            "alice@example.org:alice-password-0123456789",
            "imaps://stalwart:993/INBOX?SUBJECT%20%22hlb%20probe%22",
        ],
    );
    assert_eq!(rc, 0, "{out}");
    assert!(out.trim() != "* SEARCH", "nothing arrived: {out}");
    println!(
        "✓ 587 opened, certificate served for `stalwart`, sent as itself, refused as another: {}",
        out.trim()
    );

    let _ = docker(&["rm", "-f", NAME]);
    let _ = docker(&["network", "rm", NET]);
}

/// What a phone gets in place of the mailbox's password, which nobody is ever shown:
/// one password per device, made by the administrator FOR the account, opening its
/// mail, calendars and contacts — and nothing once revoked.
#[tokio::test]
#[ignore = "needs Docker"]
async fn a_device_password_opens_calendars_and_contacts_until_revoked() {
    let s = start();
    let account = s
        .ensure_account("lena@example.org", "the-mailbox-password-nobody-sees", &[])
        .await
        .expect("account");
    if s.generation().await.expect("session") == hlb_mail::Generation::V016 {
        // 0.16 keeps app passwords elsewhere: refused by name, never half-made.
        let refused = s.create_app_password(&account.account_id, "phone").await;
        assert!(
            matches!(refused, Err(hlb_mail::Error::NeedsV1(_))),
            "{refused:?}"
        );
        println!("✓ 0.16: refused by name");
        stop();
        return;
    }
    let made = s
        .create_app_password(&account.account_id, "Lena's phone")
        .await
        .expect("made");
    assert!(!made.secret.is_empty());
    assert!(
        !format!("{made:?}").contains(&made.secret),
        "a Debug print leaks the secret"
    );
    let listed = s.app_passwords(&account.account_id).await.expect("listed");
    assert_eq!(listed.len(), 1, "{listed:?}");
    assert_eq!(listed[0].id, made.id);
    assert_eq!(listed[0].description, "Lena's phone");
    assert!(listed[0].created_at.is_some(), "{listed:?}");
    println!("✓ made for the account by the administrator, listed by its name");

    let url = format!("http://127.0.0.1:{PORT}");
    let status = |path: &'static str, secret: String| {
        let url = url.clone();
        async move {
            reqwest::Client::new()
                .request(
                    reqwest::Method::from_bytes(b"PROPFIND").expect("method"),
                    format!("{url}{path}"),
                )
                .header("Depth", "0")
                .basic_auth("lena@example.org", Some(secret))
                .send()
                .await
                .expect("reached")
                .status()
                .as_u16()
        }
    };
    assert_eq!(status("/dav/cal/", made.secret.clone()).await, 207);
    assert_eq!(status("/dav/card/", made.secret.clone()).await, 207);
    println!("✓ CalDAV and CardDAV open with it");

    assert!(s
        .revoke_app_password(&account.account_id, &made.id)
        .await
        .expect("revoked"));
    assert!(!s
        .revoke_app_password(&account.account_id, &made.id)
        .await
        .expect("revoked twice"));
    assert_eq!(status("/dav/cal/", made.secret.clone()).await, 401);
    assert!(s
        .app_passwords(&account.account_id)
        .await
        .expect("listed")
        .is_empty());
    println!("✓ revoked: refused at once, gone from the list");
    stop();
}

/// One JMAP request as the administrator, its answers' arguments in order.
async fn jmap(calls: serde_json::Value) -> Vec<serde_json::Value> {
    let v: serde_json::Value = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{PORT}/jmap/"))
        .basic_auth("admin", Some(ADMIN_PASSWORD))
        .json(&serde_json::json!({
            "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
            "methodCalls": calls,
        }))
        .send()
        .await
        .expect("jmap")
        .json()
        .await
        .expect("json");
    v["methodResponses"]
        .as_array()
        .expect("answers")
        .iter()
        .map(|r| r[1].clone())
        .collect()
}

#[tokio::test]
#[ignore = "needs Docker"]
async fn the_house_sends_a_file_and_keeps_no_copy() {
    // The family's sealed kit leaves this way: written into the house's own account by
    // the administrator, submitted, and destroyed there — a Sent folder holding the
    // kit would be one more place to read it from.
    let s = start();
    let sender = s
        .ensure_account("noreply@example.org", "a-sender-password-123456", &[])
        .await
        .expect("sender");
    let relative = s
        .ensure_account("camille@example.org", "a-relative-password-12345", &[])
        .await
        .expect("relative");
    let postmaster = s
        .ensure_shared_mailbox("postmaster", "example.org", &[])
        .await
        .expect("postmaster");
    let kit = b"-----BEGIN AGE ENCRYPTED FILE-----\nYWdlLWVuY3J5cHRpb24=\n-----END AGE ENCRYPTED FILE-----\n";
    s.send(&hlb_mail::Outgoing {
        from: "noreply@example.org",
        from_name: "Homelabus",
        reply_to: Some("postmaster@example.org"),
        to: "camille@example.org",
        subject: "The house's emergency kit",
        text: "Keep this message.",
        attachment: Some(hlb_mail::Attachment {
            name: "kit.age",
            mime: "application/octet-stream",
            bytes: kit,
        }),
    })
    .await
    .expect("submitted");

    let mut got = None;
    for _ in 0..30 {
        let a = jmap(serde_json::json!([
            ["Email/query", { "accountId": relative.account_id }, "0"],
            ["Email/get", { "accountId": relative.account_id,
                "#ids": { "resultOf": "0", "name": "Email/query", "path": "/ids" },
                "properties": ["subject", "from", "replyTo", "attachments"] }, "1"],
        ]))
        .await;
        if let Some(m) = a[1]["list"].as_array().and_then(|l| l.first()) {
            got = Some(m.clone());
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    let m = got.expect("delivered");
    assert_eq!(m["subject"], "The house's emergency kit");
    assert_eq!(m["replyTo"][0]["email"], "postmaster@example.org");
    let blob = m["attachments"][0]["blobId"].as_str().expect("attached");
    let bytes = reqwest::Client::new()
        .get(format!(
            "http://127.0.0.1:{PORT}/jmap/download/{}/{blob}/kit.age",
            relative.account_id
        ))
        .basic_auth("admin", Some(ADMIN_PASSWORD))
        .send()
        .await
        .expect("download")
        .bytes()
        .await
        .expect("bytes");
    assert_eq!(&bytes[..], &kit[..], "the file arrives as it left");

    let left = jmap(serde_json::json!([[
        "Email/query", { "accountId": sender.account_id }, "0"
    ]]))
    .await;
    assert_eq!(left[0]["ids"], serde_json::json!([]), "no copy kept");

    // 🔴 A relative's server refusing the kit answers the envelope's sender, which is
    // the sending account: the refusal sat in `noreply@` and nobody learnt that a
    // relative held no kit (lab, 2026-11-01). It reaches the administrators' box.
    s.forward_everything("noreply@example.org", "postmaster@example.org")
        .await
        .expect("forwarded");
    s.send(&hlb_mail::Outgoing {
        from: "noreply@example.org",
        from_name: "Homelabus",
        reply_to: Some("postmaster@example.org"),
        // Its null MX refuses everything, at once — and sends nothing anywhere.
        to: "nobody@example.net",
        subject: "The house's emergency kit",
        text: "Keep this message.",
        attachment: None,
    })
    .await
    .expect("submitted");
    let mut bounced = None;
    for _ in 0..30 {
        let a = jmap(serde_json::json!([
            ["Email/query", { "accountId": postmaster }, "0"],
            ["Email/get", { "accountId": postmaster,
                "#ids": { "resultOf": "0", "name": "Email/query", "path": "/ids" },
                "properties": ["subject", "preview"] }, "1"],
        ]))
        .await;
        if let Some(m) = a[1]["list"].as_array().and_then(|l| l.first()) {
            bounced = Some(m.clone());
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    let b = bounced.expect("the refusal reaches postmaster@");
    assert!(
        b.to_string().contains("nobody@example.net"),
        "it names the relative not reached: {b}"
    );
    let left = jmap(serde_json::json!([[
        "Email/query", { "accountId": sender.account_id }, "0"
    ]]))
    .await;
    assert_eq!(
        left[0]["ids"],
        serde_json::json!([]),
        "nothing waits in noreply@"
    );

    // An address the house holds no account for sends nothing.
    let refused = s
        .send(&hlb_mail::Outgoing {
            from: "nobody@example.org",
            from_name: "x",
            reply_to: None,
            to: "camille@example.org",
            subject: "x",
            text: "x",
            attachment: None,
        })
        .await;
    assert!(refused.is_err());
    stop();
}
