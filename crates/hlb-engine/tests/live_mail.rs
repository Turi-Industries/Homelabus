//! What Stalwart needs for mail to leave the house, against a real Stalwart 0.16.
//!
//! The container boots from the catalog's one-line `config.json`, its administrator
//! from `STALWART_RECOVERY_ADMIN`, as `hlb install stalwart` deploys it.
//!
//! ```sh
//! docker build --target caddy -t hlb-caddy:dev .   # the certificate test goes through it
//! cargo test -p hlb-engine --test live_mail -- --ignored --test-threads=1 --nocapture
//! ```
//!
//! The certificate tests stand Pebble (`ghcr.io/letsencrypt/pebble:2.8.0`) for Let's
//! Encrypt: HTTP-01 on a network of their own (`10.232.0.0/24`), Pebble's resolver
//! answering Caddy's address for every name; DNS-01 on the default bridge, Pebble asking
//! the BIND standing for the provider. Over DNS-01 Stalwart first waits a minute for the
//! TXT it cannot see through its own resolver.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use hlb_mail::{Auth, Generation, Stalwart};
use hlb_state::{Certificates, Exposure, State};

const CONTAINER: &str = "hlb-test-mail";
const PORT: u16 = 18082;
const ADMIN_PASSWORD: &str = "a-test-admin-password-long-enough";

fn docker(args: &[&str]) -> std::process::Output {
    std::process::Command::new("docker")
        .args(args)
        .output()
        .expect("docker reachable")
}

fn catalog(path: &str) -> hlb_types::Manifest {
    let p = format!(
        "{}/../../catalog/{path}/manifest.yaml",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_yaml_ng::from_str(&std::fs::read_to_string(p).expect("manifest")).expect("parsed")
}

/// The catalog's Stalwart, on its pinned image.
fn start() -> Stalwart {
    start_with(&[], &[])
}

/// The same, with more `docker create` arguments and files copied in before it starts.
fn start_with(extra: &[&str], files: &[(&std::path::Path, &str)]) -> Stalwart {
    let _ = docker(&["rm", "-f", CONTAINER]);
    let m = catalog("_platform/stalwart");
    // `HLB_STALWART_IMAGE` tries another release before the catalog moves to it.
    let image = std::env::var("HLB_STALWART_IMAGE").unwrap_or_else(|_| {
        format!(
            "{}:{}@{}",
            m.spec.image.repo,
            m.spec.image.tag,
            m.spec.image.digest.as_deref().expect("pinned")
        )
    });
    let out = docker(
        &[
            "create",
            "--name",
            CONTAINER,
            "-p",
            &format!("127.0.0.1:{PORT}:8080"),
            "-e",
            &format!("STALWART_RECOVERY_ADMIN=admin:{ADMIN_PASSWORD}"),
        ]
        .into_iter()
        .chain(extra.iter().copied())
        .chain([image.as_str()])
        .collect::<Vec<_>>(),
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let dir = tempfile::tempdir().expect("tmp");
    let config = dir.path().join("config.json");
    let file = m
        .spec
        .files
        .iter()
        .find(|f| f.path == "/etc/stalwart/config.json")
        .expect("the catalog delivers its config.json");
    std::fs::write(&config, &file.content).expect("write");
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
    for (from, to) in files {
        let cp = docker(&[
            "cp",
            from.to_str().expect("path"),
            &format!("{CONTAINER}:{to}"),
        ]);
        assert!(
            cp.status.success(),
            "{}",
            String::from_utf8_lossy(&cp.stderr)
        );
    }
    assert!(docker(&["start", CONTAINER]).status.success());

    let url = format!("http://127.0.0.1:{PORT}");
    let s = Stalwart::new(
        url.clone(),
        Auth::Basic {
            user: "admin".into(),
            password: ADMIN_PASSWORD.into(),
        },
    );
    for _ in 0..60 {
        let up = std::process::Command::new("curl")
            .args(["-s", "-o", "/dev/null", "-w", "%{http_code}", "-L"])
            .args(["-u", &format!("admin:{ADMIN_PASSWORD}")])
            .arg(format!("{url}/.well-known/jmap"))
            .output()
            .expect("curl");
        if String::from_utf8_lossy(&up.stdout) == "200" {
            return s;
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

async fn exposed(domain: &str) -> State {
    let state = State::in_memory().await.expect("state");
    state
        .set_exposure(&Exposure {
            domain: domain.into(),
            certificates: Certificates::Internal,
            acme_email: None,
            dns_provider: None,
            staging: false,
            controller_host: None,
            acme_ca: None,
            acme_ca_root: None,
        })
        .await
        .expect("exposure");
    state
}

#[tokio::test]
#[ignore = "needs Docker"]
async fn stalwart_is_named_by_its_route_and_follows_it() {
    let s = start();
    let state = exposed("example.org").await;
    let stalwart = catalog("_platform/stalwart");

    // No route yet: no name of it is in any DNS, so none is written.
    let none = hlb_engine::submission::name_server(&state, &s, true)
        .await
        .expect("read");
    assert!(none.is_empty(), "{none:?}");

    state
        .upsert_app("stalwart", &stalwart, Some("mail.example.org"))
        .await
        .expect("installed");
    let preview = hlb_engine::submission::name_server(&state, &s, false)
        .await
        .expect("preview");
    assert_eq!(preview.len(), 1, "{preview:?}");
    assert!(
        s.identity().await.expect("read").hostname.is_empty(),
        "a preview writes nothing"
    );

    hlb_engine::submission::name_server(&state, &s, true)
        .await
        .expect("named");
    let id = s.identity().await.expect("read");
    assert_eq!(id.hostname, "mail.example.org");
    assert_eq!(
        id.default_domain_id,
        s.domain_id("example.org")
            .await
            .expect("made with the name")
    );
    let again = hlb_engine::submission::name_server(&state, &s, true)
        .await
        .expect("again");
    assert!(again.is_empty(), "named once: {again:?}");

    // The route moves: the next pass follows it.
    state
        .upsert_app("stalwart", &stalwart, Some("smtp.example.org"))
        .await
        .expect("moved");
    hlb_engine::submission::name_server(&state, &s, true)
        .await
        .expect("renamed");
    assert_eq!(
        s.identity().await.expect("read").hostname,
        "smtp.example.org"
    );
    println!("✓ named by its route, once, and again when the route moved");
    stop();
}

/// An SMTP client greeting Stalwart's port 25 with a bare name, which it refuses — an
/// event at `info` — and the container's logs from then on.
fn knock_and_read_logs() -> String {
    let ip = String::from_utf8_lossy(
        &docker(&[
            "inspect",
            "-f",
            "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
            CONTAINER,
        ])
        .stdout,
    )
    .trim()
    .to_string();
    let _ = docker(&[
        "run",
        "--rm",
        "curlimages/curl:8.11.1",
        "-sS",
        "--max-time",
        "10",
        &format!("smtp://{ip}:25"),
        "-X",
        "NOOP",
    ]);
    std::thread::sleep(std::time::Duration::from_secs(1));
    let out = docker(&["logs", CONTAINER]);
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

#[tokio::test]
#[ignore = "needs Docker"]
async fn stalwart_s_traces_reach_its_logs() {
    let s = start();
    assert!(
        !knock_and_read_logs().contains("(smtp."),
        "the image's own tracer writes where nothing reads"
    );

    let preview = hlb_engine::submission::trace(&s, false)
        .await
        .expect("preview");
    assert_eq!(preview.len(), 1, "{preview:?}");
    assert!(
        !s.traces_to_stdout().await.expect("read"),
        "a preview writes nothing"
    );
    hlb_engine::submission::trace(&s, true)
        .await
        .expect("traced");
    let logs = knock_and_read_logs();
    assert!(
        logs.contains("(smtp.invalid-ehlo)"),
        "the refused greeting, with no restart: {logs}"
    );
    let again = hlb_engine::submission::trace(&s, true)
        .await
        .expect("again");
    assert!(again.is_empty(), "added once: {again:?}");
    println!("✓ the refused greeting in `docker logs`, at the next ReloadSettings");
    stop();
}

/// A resolver answering from a table: the internet as the test publishes it.
struct Published(Vec<(String, String, String)>);

#[async_trait::async_trait]
impl hlb_engine::mail_dns::Lookup for Published {
    async fn lookup(&self, name: &str, kind: &str) -> Result<Vec<String>, String> {
        Ok(self
            .0
            .iter()
            .filter(|(n, k, _)| n == name && k == kind)
            .map(|(_, _, d)| d.clone())
            .collect())
    }
}

#[tokio::test]
#[ignore = "needs Docker"]
async fn every_record_stalwart_computes_is_judged_against_what_is_published() {
    use hlb_api::mail_dns::{Purpose, RecordState};
    let s = start();
    let id = s.ensure_domain("example.org").await.expect("domain");
    s.set_identity("mail.example.org", &id)
        .await
        .expect("named");

    // Both keys are made after the domain, the RSA one last: under load the zone was
    // read before it existed, and nothing was there to judge.
    let mut zone = Vec::new();
    for _ in 0..30 {
        zone = hlb_api::mail_dns::parse_zone(&s.zones().await.expect("zones")[0].1);
        if zone.iter().any(|r| r.name.contains("-rsa-")) {
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }

    // What a person published from `hlb mail dns`, half done: the Ed25519 key, the
    // MX, an SPF written their own way — not the RSA key, no DMARC.
    let ed25519 = zone
        .iter()
        .find(|r| r.name.contains("-ed25519-"))
        .expect("an Ed25519 selector");
    let dns = Published(vec![
        (
            ed25519.name.clone(),
            "TXT".into(),
            format!("\"{}\"", ed25519.value),
        ),
        (
            "example.org".into(),
            "MX".into(),
            "10 mail.example.org.".into(),
        ),
        (
            "example.org".into(),
            "TXT".into(),
            "\"v=spf1 mx ~all\"".into(),
        ),
    ]);
    // The ports the catalog publishes, and its route's.
    let read = hlb_engine::mail_dns::read(&s, &dns, None, &[25, 465, 993, 4190, 443], 7)
        .await
        .expect("read");
    // A whole name, or a part of one: `example.org` is in Stalwart's own name too.
    let state = |p: Purpose, part: &str| {
        read.records
            .iter()
            .filter(|r| r.purpose == p)
            .find(|r| r.name == part)
            .or_else(|| {
                read.records
                    .iter()
                    .find(|r| r.purpose == p && r.name.contains(part))
            })
            .map(|r| r.state)
            .expect("judged")
    };
    assert_eq!(state(Purpose::Dkim, "-ed25519-"), RecordState::Published);
    assert_eq!(state(Purpose::Dkim, "-rsa-"), RecordState::Missing);
    assert_eq!(state(Purpose::Mx, "example.org"), RecordState::Published);
    assert_eq!(state(Purpose::Spf, "example.org"), RecordState::Published);
    assert_eq!(state(Purpose::Dmarc, "_dmarc"), RecordState::Missing);
    assert_eq!(
        state(Purpose::Spf, "mail.example.org"),
        RecordState::Missing,
        "the name it greets with is judged too"
    );
    assert_eq!(read.records.len(), 6, "{:#?}", read.records);
    assert!(
        read.optional.iter().any(
            |(_, l)| l.starts_with("_imaps._tcp.example.org. IN SRV 0 1 993 mail.example.org.")
        ),
        "the rest is printed, under Stalwart's name: {:#?}",
        read.optional
    );
    assert!(
        !read
            .optional
            .iter()
            .any(|(_, l)| l.contains("IN CNAME") || l.starts_with("_pop3s.")),
        "nothing the house does not route or forward: {:#?}",
        read.optional
    );
    assert!(read.unserved > 0, "said as left out");
    let rsa = read
        .records
        .iter()
        .find(|r| r.name.contains("-rsa-"))
        .expect("rsa");
    assert!(
        rsa.expected.contains("IN TXT (") && rsa.expected.contains("v=DKIM1; k=rsa"),
        "the line to paste, as Stalwart wrote it: {}",
        rsa.expected
    );
    println!(
        "✓ {} records judged, {} printed",
        read.records.len(),
        read.optional.len()
    );
    stop();
}

#[tokio::test]
#[ignore = "needs Docker and the internet"]
async fn blocklists_refusing_a_public_resolver_are_named() {
    // 1.1.1.1 as the node's resolver, the commonest a house has: Spamhaus answers it
    // `127.255.255.254`, a refusal, which the spam filter reads as no listing.
    let s = start_with(&["--dns", "1.1.1.1"], &[]);
    // The spam rules, and their lists, are downloaded after the start.
    let mut refused = Vec::new();
    for _ in 0..60 {
        refused = s.refused_blocklists().await.expect("probe");
        if !refused.is_empty() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    assert!(
        refused
            .iter()
            .any(|t| t == "RBL_SPAMHAUS_BLOCKED_OPENRESOLVER"),
        "{refused:?}"
    );
    println!("✓ refused through 1.1.1.1: {}", refused.join(", "));
    stop();
}

#[tokio::test]
#[ignore = "needs Docker and the internet"]
async fn through_its_own_resolver_every_blocklist_answers() {
    const NET: &str = "hlb-test-resolver";
    const RESOLVER: &str = "hlb-test-unbound";
    let _ = docker(&["rm", "-f", RESOLVER]);
    let _ = docker(&["network", "rm", NET]);
    assert!(docker(&["network", "create", NET]).status.success());
    // The companion as the catalog deploys it: its image, its capabilities.
    let m = catalog("_platform/stalwart");
    let c = m
        .spec
        .companions
        .iter()
        .find(|c| c.name == hlb_engine::submission::RESOLVER)
        .expect("the resolver companion");
    let image = format!(
        "{}:{}@{}",
        c.image.repo,
        c.image.tag,
        c.image.digest.as_deref().expect("pinned")
    );
    let mut run = vec![
        "run",
        "-d",
        "--name",
        RESOLVER,
        "--network",
        NET,
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
    ];
    for cap in &c.security.cap_add {
        run.extend(["--cap-add", cap.as_str()]);
    }
    run.push(&image);
    let out = docker(&run);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let address = String::from_utf8_lossy(
        &docker(&[
            "inspect",
            RESOLVER,
            "--format",
            "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
        ])
        .stdout,
    )
    .trim()
    .to_string();

    let s = start_with(&["--network", NET, "--dns", "1.1.1.1"], &[]);
    let mut refused = Vec::new();
    for _ in 0..60 {
        refused = s.refused_blocklists().await.expect("probe");
        if !refused.is_empty() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    assert!(!refused.is_empty(), "refused through 1.1.1.1 first");

    s.resolve_through(&address).await.expect("resolver set");
    assert_eq!(
        s.resolver_servers().await.expect("read"),
        [format!("tcp {address}:53"), format!("udp {address}:53")]
    );
    // A new probe asks new names: no refusal cached before the switch is read again.
    let refused = s.refused_blocklists().await.expect("probe");
    assert!(refused.is_empty(), "through Unbound: {refused:?}");
    println!("✓ every blocklist answered through {address}, without a restart");
    stop();
    let _ = docker(&["rm", "-f", RESOLVER]);
    let _ = docker(&["network", "rm", NET]);
}

#[tokio::test]
#[ignore = "needs the internet"]
async fn the_public_resolvers_answer_as_the_judging_reads() {
    for r in hlb_mail::public_dns::RESOLVERS {
        let dns = hlb_mail::public_dns::PublicDns::new(vec![r.to_string()]);
        let mx = dns.lookup("gmail.com", "MX").await.expect("MX");
        assert!(
            mx.iter()
                .any(|m| m.ends_with("gmail-smtp-in.l.google.com.")),
            "{r}: {mx:?}"
        );
        let txt: Vec<String> = dns
            .lookup("gmail.com", "TXT")
            .await
            .expect("TXT")
            .iter()
            .map(|d| hlb_api::mail_dns::txt_value(d))
            .collect();
        assert!(txt.iter().any(|t| t.starts_with("v=spf1 ")), "{r}: {txt:?}");
        let none = dns
            .lookup("no-such-name.homelabus.invalid", "TXT")
            .await
            .expect("an answer");
        assert!(none.is_empty(), "{r}: {none:?}");
        println!("✓ {r}");
    }
}

const BIND: &str = "hlb-test-mail-bind";
/// A TSIG key for the test zone, base64 as BIND and Stalwart both read it.
const TSIG: &str = "c3RhbmRpbmctZm9yLWEtcHJvdmlkZXItaW4tYS10ZXN0LTAxMjM0NTY3ODk=";

/// A BIND accepting signed updates for `example.org`: a DNS provider's API, as far as
/// Stalwart's publishing goes. Its address on the default bridge, which Stalwart
/// reaches.
fn bind() -> String {
    let _ = docker(&["rm", "-f", BIND]);
    let out = docker(&[
        "create",
        "--name",
        BIND,
        "internetsystemsconsortium/bind9:9.20",
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let dir = tempfile::tempdir().expect("tmp");
    let conf = dir.path().join("named.conf");
    std::fs::write(
        &conf,
        format!(
            r#"key "hlb" {{ algorithm hmac-sha256; secret "{TSIG}"; }};
options {{ directory "/var/cache/bind"; listen-on {{ any; }}; allow-query {{ any; }};
          recursion no; dnssec-validation no; }};
zone "example.org" {{ type primary; file "/var/lib/bind/example.org.zone";
                      allow-update {{ key "hlb"; }}; }};
"#
        ),
    )
    .expect("conf");
    let zone = dir.path().join("example.org.zone");
    std::fs::write(
        &zone,
        "$TTL 300\n@ IN SOA ns.example.org. admin.example.org. 1 3600 600 86400 300\n\
         @ IN NS ns.example.org.\nns IN A 127.0.0.1\n",
    )
    .expect("zone");
    for (from, to) in [
        (&conf, "/etc/bind/named.conf"),
        (&zone, "/var/lib/bind/example.org.zone"),
    ] {
        let cp = docker(&["cp", from.to_str().expect("path"), &format!("{BIND}:{to}")]);
        assert!(
            cp.status.success(),
            "{}",
            String::from_utf8_lossy(&cp.stderr)
        );
    }
    assert!(docker(&["start", BIND]).status.success());
    let ip = String::from_utf8_lossy(
        &docker(&[
            "inspect",
            "-f",
            "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
            BIND,
        ])
        .stdout,
    )
    .trim()
    .to_string();
    for _ in 0..30 {
        if !dig("ns.example.org", "A").is_empty() {
            return ip;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    panic!(
        "BIND did not come up: {}",
        String::from_utf8_lossy(&docker(&["logs", BIND]).stderr)
    );
}

/// What BIND answers, its TXT strings as `dig +short` prints them.
fn dig(name: &str, kind: &str) -> Vec<String> {
    let out = docker(&["exec", BIND, "dig", "@127.0.0.1", "+short", kind, name]);
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::to_string)
        .filter(|l| !l.is_empty())
        .collect()
}

/// BIND, standing for the provider, as the judging reads a resolver.
struct Bind;

#[async_trait::async_trait]
impl hlb_engine::mail_dns::Lookup for Bind {
    async fn lookup(&self, name: &str, kind: &str) -> Result<Vec<String>, String> {
        Ok(dig(name, kind))
    }
}

#[tokio::test]
#[ignore = "needs Docker"]
async fn stalwart_publishes_its_active_keys_through_a_provider_and_again_when_asked() {
    use hlb_api::mail_dns::{Purpose, RecordState};
    let s = start();
    let ip = bind();
    let domain = s.ensure_domain("example.org").await.expect("domain");
    let server = s
        .create_dns_server(serde_json::json!({
            "@type": "Tsig",
            "host": ip,
            "port": 53,
            "keyName": "hlb",
            "key": { "@type": "Value", "secret": TSIG },
            // 🔴 Over UDP the RSA key's update — past 512 bytes signed — never reached
            // BIND, and Stalwart counted the task done: only the reading saw it.
            "protocol": "tcp",
            "tsigAlgorithm": "hmac-sha256",
            "description": "test",
        }))
        .await
        .expect("server");
    hlb_engine::mail_dns::switch(&s, &domain, &server, &["dkim".to_string()])
        .await
        .expect("switched");

    let dkim = |read: &hlb_engine::mail_dns::Reading| {
        read.records
            .iter()
            .filter(|r| r.purpose == Purpose::Dkim)
            .map(|r| (r.name.clone(), r.state))
            .collect::<Vec<_>>()
    };
    let mut published = Vec::new();
    for _ in 0..30 {
        let read = hlb_engine::mail_dns::read(&s, &Bind, None, &[], 1)
            .await
            .expect("read");
        published = dkim(&read);
        if published.len() == 2
            && published
                .iter()
                .all(|(_, st)| *st == RecordState::Published)
        {
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    assert!(
        published.len() == 2
            && published
                .iter()
                .all(|(_, st)| *st == RecordState::Published),
        "the keys already active are published at the switch: {published:?} — tasks {:?}",
        s.dns_tasks(&domain).await
    );
    println!("✓ both active keys published at the switch: {published:?}");
    // Switched the moment the domain exists, as here: 1.0 scheduled no rotation at all.
    let keys = s.dkim_keys(&domain).await.expect("keys");
    assert!(
        !keys.is_empty()
            && keys
                .iter()
                .filter(|k| k.stage == "active")
                .all(|k| k.next_transition.is_some()),
        "every active key's rotation scheduled: {keys:?}"
    );
    println!("✓ and their rotation scheduled: {keys:?}");

    // Gone from the zone — a provider's failure, a person's mistake: asked again, back.
    let (gone, _) = &published[0];
    let delete = format!("server 127.0.0.1\nzone example.org\nupdate delete {gone}. TXT\nsend\n");
    let mut nsupdate = std::process::Command::new("docker")
        .args([
            "exec",
            "-i",
            BIND,
            "nsupdate",
            "-y",
            &format!("hmac-sha256:hlb:{TSIG}"),
        ])
        .stdin(std::process::Stdio::piped())
        .spawn()
        .expect("nsupdate");
    std::io::Write::write_all(nsupdate.stdin.as_mut().expect("stdin"), delete.as_bytes())
        .expect("write");
    assert!(nsupdate.wait().expect("ran").success());
    assert!(dig(gone, "TXT").is_empty(), "deleted");

    s.publish_again(&domain, &["dkim".to_string()])
        .await
        .expect("asked again");
    let mut back = false;
    for _ in 0..30 {
        if !dig(gone, "TXT").is_empty() {
            back = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    assert!(
        back,
        "{gone} published again — tasks {:?}",
        s.dns_tasks(&domain).await
    );
    println!("✓ {gone} published again when asked");
    let _ = docker(&["rm", "-f", BIND]);
    stop();
}

#[tokio::test]
#[ignore = "needs Docker"]
async fn stalwart_takes_the_dns_server_of_every_provider_homelabus_maps() {
    let s = start();
    for p in hlb_ingress::dns::PROVIDERS {
        let values: Vec<String> = p
            .fields
            .iter()
            .map(|f| {
                f.default
                    .map_or_else(|| format!("test-{}", f.name), str::to_string)
            })
            .collect();
        let Ok(mut body) = hlb_engine::mail_dns::stalwart_dns_server(
            p.name,
            &values,
            s.generation().await.expect("generation"),
        ) else {
            continue;
        };
        body["description"] = p.name.into();
        let id = s.create_dns_server(body).await.unwrap_or_else(|e| {
            panic!(
                "{}: Stalwart refuses the server Homelabus writes: {e}",
                p.name
            )
        });
        println!("✓ {} accepted ({id})", p.name);
    }
    stop();
}

#[tokio::test]
#[ignore = "needs Docker and the internet"]
async fn dkim_goes_through_the_exposures_provider_once_and_follows_its_credential() {
    use hlb_api::mail_dns::{MailRecord, Purpose, RecordState};
    let s = start();
    let state = State::in_memory().await.expect("state");
    state
        .set_exposure(&Exposure {
            domain: "example.org".into(),
            certificates: Certificates::Acme,
            acme_email: Some("admin@example.org".into()),
            dns_provider: Some("cloudflare".into()),
            staging: true,
            controller_host: None,
            acme_ca: None,
            acme_ca_root: None,
        })
        .await
        .expect("exposure");
    let dir = tempfile::tempdir().expect("tmp");
    let vault = hlb_secrets::Vault::init(dir.path().join("k.key")).expect("vault");
    let token = |t: &str| vault.encrypt(t).expect("enc");
    state
        .store_secret_if_absent("dns-cloudflare-api-token", &token("first-token"), "dns")
        .await
        .expect("token");
    let mine = s.ensure_domain("example.org").await.expect("domain");
    // A domain under the exposure that a person publishes through a server of their own.
    let theirs = s.ensure_domain("lab.example.org").await.expect("theirs");
    let their_server = s
        .create_dns_server(serde_json::json!({
            "@type": "DeSEC",
            "secret": { "@type": "Value", "secret": "theirs" },
            "description": "set up by hand",
        }))
        .await
        .expect("their server");
    s.publish_through(&theirs, &their_server, &["dkim".to_string()])
        .await
        .expect("theirs");

    let preview = hlb_engine::mail_dns::publish_dkim(&state, &vault, &s, false)
        .await
        .expect("preview");
    assert_eq!(
        preview,
        [
            "DKIM published through cloudflare",
            "example.org: DKIM published and rotated by Stalwart"
        ]
    );
    assert_eq!(
        s.dns_servers().await.expect("read").len(),
        1,
        "a preview writes nothing"
    );

    hlb_engine::mail_dns::publish_dkim(&state, &vault, &s, true)
        .await
        .expect("applied");
    let servers = s.dns_servers().await.expect("read");
    let ours = servers
        .iter()
        .find(|x| x.description.starts_with("Homelabus: cloudflare "))
        .expect("ours, by its description");
    assert_eq!(ours.kind, "Cloudflare");
    let by = |id: &str| {
        let s = &s;
        let id = id.to_string();
        async move {
            s.domains_dns()
                .await
                .expect("read")
                .into_iter()
                .find(|d| d.id == id)
                .and_then(|d| d.published_by)
        }
    };
    assert_eq!(
        by(&mine).await,
        Some((ours.id.clone(), vec!["dkim".to_string()]))
    );
    assert_eq!(
        by(&theirs).await,
        Some((their_server.clone(), vec!["dkim".to_string()])),
        "a domain published through a server of a person's own stays theirs"
    );
    let again = hlb_engine::mail_dns::publish_dkim(&state, &vault, &s, true)
        .await
        .expect("again");
    assert!(again.is_empty(), "once: {again:?}");

    // The credential rotated in the vault: the same server, written again.
    state
        .rotate_secret("dns-cloudflare-api-token", &token("second-token"))
        .await
        .expect("rotated");
    let rotated = hlb_engine::mail_dns::publish_dkim(&state, &vault, &s, true)
        .await
        .expect("rotated");
    assert_eq!(
        rotated,
        ["DKIM published with the cloudflare credential the vault holds now"]
    );
    let now = s.dns_servers().await.expect("read");
    let updated = now
        .iter()
        .find(|x| x.id == ours.id)
        .expect("the same server");
    assert_ne!(
        updated.description, ours.description,
        "its fingerprint followed"
    );

    // A key the night found missing — Cloudflare refused the fake token. 0.16 retries
    // no task, so it is asked for again, its failed one replaced; 1.0 retries it itself
    // (`Retry`, then `Stalled` past `x:TaskManager.alertAfter`), and a second task
    // would only duplicate it.
    let generation = s.generation().await.expect("generation");
    state
        .record_mail_records(&[MailRecord {
            domain: "example.org".into(),
            name: "v1-rsa-1._domainkey.example.org".into(),
            purpose: Purpose::Dkim,
            expected: String::new(),
            state: RecordState::Missing,
            observed: "nothing".into(),
            checked_at: 1,
        }])
        .await
        .expect("reading");
    let settled = match generation {
        Generation::V016 => "Failed",
        Generation::V1 => "Retry",
    };
    for _ in 0..30 {
        if s.dns_tasks(&mine)
            .await
            .expect("tasks")
            .iter()
            .all(|t| t.state == settled)
        {
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    let before = s.dns_tasks(&mine).await.expect("tasks");
    let retried = hlb_engine::mail_dns::publish_dkim(&state, &vault, &s, true)
        .await
        .expect("retried");
    let tasks = s.dns_tasks(&mine).await.expect("tasks");
    match generation {
        Generation::V016 => {
            assert_eq!(retried, ["example.org: its DKIM keys published again"]);
            assert!(
                tasks.iter().filter(|t| t.state == "Failed").count() <= 1,
                "the failed ones before it removed: {tasks:?}"
            );
        }
        Generation::V1 => {
            assert!(
                before.iter().any(|t| t.state == "Retry"),
                "1.0 retries a refused publication: {before:?}"
            );
            assert!(retried.is_empty(), "left to Stalwart: {retried:?}");
            assert_eq!(tasks.len(), before.len(), "no second task: {tasks:?}");
        }
    }

    // The reading says why the key is missing: Cloudflare's refusal, as Stalwart's
    // task holds it — on 0.16 once the task asked again has failed in its turn.
    struct Nowhere;
    #[async_trait::async_trait]
    impl hlb_engine::mail_dns::Lookup for Nowhere {
        async fn lookup(&self, _: &str, _: &str) -> Result<Vec<String>, String> {
            Ok(Vec::new())
        }
    }
    let mut said = Vec::new();
    for _ in 0..30 {
        said = hlb_engine::mail_dns::read(&s, &Nowhere, None, &[], 1)
            .await
            .expect("read")
            .records
            .into_iter()
            .filter(|r| r.domain == "example.org" && r.purpose == Purpose::Dkim)
            .map(|r| r.observed)
            .collect();
        if !said.is_empty() && said.iter().all(|o| o.contains("Stalwart")) {
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    let why = match generation {
        Generation::V016 => "Stalwart's publishing failed: ",
        Generation::V1 => "Stalwart retries its publishing: ",
    };
    assert!(
        !said.is_empty() && said.iter().all(|o| o.contains(why)),
        "the reason beside the missing key: {said:?}"
    );
    println!("✓ through the exposure's provider, once; its credential followed; retried; said why: {said:?}");
    stop();
}

const RELAY: &str = "hlb-test-mail-relay";
const RELAY_UI: u16 = 18826;
const RELAY_USER: &str = "relayuser";
const RELAY_PASSWORD: &str = "relay-pass-123";

/// A relay standing for a provider's: Mailpit, AUTH required, STARTTLS under a test
/// root when `cert` is given, none otherwise. Its address.
fn relay(cert: Option<(&std::path::Path, &std::path::Path)>) -> String {
    let _ = docker(&["rm", "-f", RELAY]);
    let mut args = vec![
        "create".to_string(),
        "--name".into(),
        RELAY.into(),
        "-p".into(),
        format!("127.0.0.1:{RELAY_UI}:8025"),
        "-e".into(),
        format!("MP_SMTP_AUTH={RELAY_USER}:{RELAY_PASSWORD}"),
    ];
    if cert.is_some() {
        for e in [
            "MP_SMTP_TLS_CERT=/tmp/cert.pem",
            "MP_SMTP_TLS_KEY=/tmp/key.pem",
            "MP_SMTP_REQUIRE_STARTTLS=true",
        ] {
            args.extend(["-e".into(), e.into()]);
        }
    } else {
        // Mailpit refuses AUTH in the clear unless told: this one takes it — what a
        // relay stripped of its STARTTLS looks like to the sender.
        args.extend(["-e".into(), "MP_SMTP_AUTH_ALLOW_INSECURE=true".into()]);
    }
    args.push("axllent/mailpit:v1.27".into());
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let out = docker(&refs);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    if let Some((c, k)) = cert {
        for (from, to) in [(c, "/tmp/cert.pem"), (k, "/tmp/key.pem")] {
            let cp = docker(&["cp", from.to_str().expect("path"), &format!("{RELAY}:{to}")]);
            assert!(
                cp.status.success(),
                "{}",
                String::from_utf8_lossy(&cp.stderr)
            );
        }
    }
    assert!(docker(&["start", RELAY]).status.success());
    std::thread::sleep(std::time::Duration::from_secs(2));
    String::from_utf8_lossy(
        &docker(&[
            "inspect",
            "-f",
            "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
            RELAY,
        ])
        .stdout,
    )
    .trim()
    .to_string()
}

/// The subjects the relay received.
fn relayed() -> Vec<String> {
    let out = std::process::Command::new("curl")
        .args([
            "-s",
            &format!("http://127.0.0.1:{RELAY_UI}/api/v1/messages"),
        ])
        .output()
        .expect("curl");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap_or_default();
    v["messages"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|m| m["Subject"].as_str().map(str::to_string))
        .collect()
}

/// A test root, and a certificate for `relay.test` under it.
fn test_root(
    dir: &std::path::Path,
) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
    let p = |f: &str| dir.join(f);
    let run = |args: &[&str]| {
        let out = std::process::Command::new("openssl")
            .args(args)
            .output()
            .expect("openssl");
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    };
    std::fs::write(p("ext"), "subjectAltName=DNS:relay.test\n").expect("ext");
    run(&[
        "req",
        "-x509",
        "-newkey",
        "ec",
        "-pkeyopt",
        "ec_paramgen_curve:P-256",
        "-nodes",
        "-keyout",
        p("ca.key").to_str().unwrap(),
        "-out",
        p("ca.pem").to_str().unwrap(),
        "-days",
        "2",
        "-subj",
        "/CN=hlb test root",
    ]);
    run(&[
        "req",
        "-newkey",
        "ec",
        "-pkeyopt",
        "ec_paramgen_curve:P-256",
        "-nodes",
        "-keyout",
        p("key.pem").to_str().unwrap(),
        "-out",
        p("csr").to_str().unwrap(),
        "-subj",
        "/CN=relay.test",
    ]);
    run(&[
        "x509",
        "-req",
        "-in",
        p("csr").to_str().unwrap(),
        "-CA",
        p("ca.pem").to_str().unwrap(),
        "-CAkey",
        p("ca.key").to_str().unwrap(),
        "-CAcreateserial",
        "-days",
        "2",
        "-extfile",
        p("ext").to_str().unwrap(),
        "-out",
        p("cert.pem").to_str().unwrap(),
    ]);
    (p("ca.pem"), p("cert.pem"), p("key.pem"))
}

/// Sends as `alice@example.org` through Stalwart's SMTPS, to a domain with a null MX:
/// were the relay not taken, nothing would leave for the internet.
fn send(subject: &str) {
    let ip = String::from_utf8_lossy(
        &docker(&[
            "inspect",
            "-f",
            "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
            CONTAINER,
        ])
        .stdout,
    )
    .trim()
    .to_string();
    let script = format!(
        "printf 'From: alice@example.org\\r\\nTo: bob@example.net\\r\\nSubject: {subject}\\r\\n\\r\\nhi\\r\\n' \
         | curl -sS -k smtps://{ip}:465 --user alice@example.org:alice-password-0123456789 \
           --mail-from alice@example.org --mail-rcpt bob@example.net -T -"
    );
    let out = docker(&[
        "run",
        "--rm",
        "--entrypoint",
        "sh",
        "curlimages/curl:8.11.1",
        "-c",
        &script,
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Every message of a mailbox's INBOX, as text, read over IMAPS.
fn inbox_text(user: &str, password: &str) -> String {
    let ip = String::from_utf8_lossy(
        &docker(&[
            "inspect",
            "-f",
            "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
            CONTAINER,
        ])
        .stdout,
    )
    .trim()
    .to_string();
    let script = format!(
        "for uid in $(curl -sS -k imaps://{ip}:993/INBOX --user '{user}:{password}' -X 'UID SEARCH ALL' \
           | tr -cd '0-9 \n' | tr ' ' '\n'); do \
           curl -sS -k \"imaps://{ip}:993/INBOX;UID=$uid\" --user '{user}:{password}'; done"
    );
    let out = docker(&[
        "run",
        "--rm",
        "--entrypoint",
        "sh",
        "curlimages/curl:8.11.1",
        "-c",
        &script,
    ]);
    // Quoted-printable folds long lines: unfolded, a sentence reads whole.
    String::from_utf8_lossy(&out.stdout)
        .replace("=\r\n", "")
        .replace("=\n", "")
}

/// Runs the trial job's own script in a plain container, its files written in — with
/// `bundle` in place of the image's public roots, or beside them when `None`.
fn trial(job: &hlb_orchestrator::ServiceSpec, ip: &str, bundle: Option<&std::path::Path>) -> bool {
    let dir = tempfile::tempdir().expect("tmp");
    let mut args = vec![
        "run".to_string(),
        "--rm".into(),
        "--add-host".into(),
        format!("relay.test:{ip}"),
    ];
    if let Some(root) = bundle {
        args.extend([
            "-e".into(),
            "CURL_CA_BUNDLE=/run/root.pem".into(),
            "-v".into(),
            format!("{}:/run/root.pem:ro", root.display()),
        ]);
    }
    for (i, (path, content)) in job.files.iter().enumerate() {
        let f = dir.path().join(format!("f{i}"));
        std::fs::write(&f, content).expect("file");
        args.extend(["-v".into(), format!("{}:{path}:ro", f.display())]);
    }
    args.extend([
        "--entrypoint".into(),
        job.command[0].clone(),
        job.image.split('@').next().unwrap().into(),
    ]);
    args.extend(job.command[1..].iter().cloned());
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let out = docker(&refs);
    println!("  trial: {}", String::from_utf8_lossy(&out.stdout).trim());
    out.status.success()
}

#[tokio::test]
#[ignore = "needs Docker"]
async fn remote_mail_leaves_through_the_relay_and_its_password_never_in_the_clear() {
    use hlb_engine::mail_relay::{self, Relay};
    let dir = tempfile::tempdir().expect("tmp");
    let (root, cert, key) = test_root(dir.path());
    let relay_ip = relay(Some((&cert, &key)));
    // Stalwart trusts the system's roots; here the test's, as a provider's public one.
    let s = start_with(
        &[
            "--add-host",
            &format!("relay.test:{relay_ip}"),
            "-e",
            "SSL_CERT_FILE=/etc/stalwart/test-root.pem",
        ],
        &[(&root, "/etc/stalwart/test-root.pem")],
    );
    let id = s.ensure_domain("example.org").await.expect("domain");
    s.set_identity("mail.example.org", &id)
        .await
        .expect("named");
    s.ensure_account("alice@example.org", "alice-password-0123456789", &[])
        .await
        .expect("alice");
    let before = s.outbound_strategy().await.expect("read");

    let the_relay = Relay {
        host: "relay.test".into(),
        port: 1025,
        implicit_tls: false,
        user: RELAY_USER.into(),
    };
    assert!(trial(
        &mail_relay::trial_job(&the_relay, RELAY_PASSWORD, "bridge", &[]),
        &relay_ip,
        Some(&root)
    ));
    assert!(
        !trial(
            &mail_relay::trial_job(&the_relay, "wrong", "bridge", &[]),
            &relay_ip,
            Some(&root)
        ),
        "a wrong password is refused before anything is written"
    );
    // A root Stalwart is handed — a private ACME authority's — is the trial's too,
    // beside the image's public ones: without it, a relay Stalwart takes was refused.
    let private = std::fs::read_to_string(&root).expect("root");
    assert!(
        !trial(
            &mail_relay::trial_job(&the_relay, RELAY_PASSWORD, "bridge", &[]),
            &relay_ip,
            None
        ),
        "the public roots alone do not know the test's"
    );
    assert!(
        trial(
            &mail_relay::trial_job(&the_relay, RELAY_PASSWORD, "bridge", &[private]),
            &relay_ip,
            None
        ),
        "the root Stalwart trusts, beside the image's"
    );

    mail_relay::apply(&s, &the_relay, RELAY_PASSWORD)
        .await
        .expect("relay");
    assert_eq!(
        mail_relay::current(&s).await.expect("read"),
        Some(the_relay.clone())
    );
    send("through the relay");
    let mut got = Vec::new();
    for _ in 0..20 {
        got = relayed();
        if !got.is_empty() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    assert_eq!(
        got,
        ["through the relay"],
        "over STARTTLS, its certificate verified"
    );
    println!("✓ relayed over STARTTLS: {got:?}");

    // The same relay with no TLS — a line stripping STARTTLS: nothing is sent, the
    // password stays home, and the message waits in the queue.
    let plain_ip = relay(None);
    let _ = docker(&[
        "exec",
        CONTAINER,
        "sh",
        "-c",
        &format!("echo '{plain_ip} relay.test' >> /etc/hosts"),
    ]);
    s.reload_settings().await.expect("reload");
    send("in the clear");
    // Why, from Stalwart itself: the bounce alice gets says the relay was refused for
    // offering no STARTTLS — not merely unreachable, which would prove nothing.
    let mut bounce = String::new();
    for _ in 0..20 {
        bounce = inbox_text("alice@example.org", "alice-password-0123456789");
        if bounce.contains("STARTTLS not advertised") {
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    assert!(
        bounce.contains("STARTTLS not advertised"),
        "the relay offering no TLS was refused for it: {bounce}"
    );
    assert!(relayed().is_empty(), "and handed nothing");
    println!("✓ a relay offering no TLS was handed nothing: STARTTLS not advertised");

    assert!(mail_relay::remove(&s).await.expect("removed"));
    assert_eq!(
        s.outbound_strategy().await.expect("read"),
        before,
        "Stalwart's own, back"
    );
    assert_eq!(mail_relay::current(&s).await.expect("read"), None);
    let _ = docker(&["rm", "-f", RELAY]);
    stop();
}

/// Sends as alice through Stalwart's SMTPS to every `to`, one message.
fn send_to(subject: &str, to: &[&str]) {
    let ip = String::from_utf8_lossy(
        &docker(&[
            "inspect",
            "-f",
            "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
            CONTAINER,
        ])
        .stdout,
    )
    .trim()
    .to_string();
    let rcpts: String = to.iter().map(|r| format!(" --mail-rcpt {r}")).collect();
    let script = format!(
        "printf 'From: alice@example.org\\r\\nTo: {}\\r\\nSubject: {subject}\\r\\n\\r\\nhi\\r\\n' \
         | curl -sS -k smtps://{ip}:465 --user alice@example.org:alice-password-0123456789 \
           --mail-from alice@example.org{rcpts} -T -",
        to.join(", ")
    );
    let out = docker(&[
        "run",
        "--rm",
        "--entrypoint",
        "sh",
        "curlimages/curl:8.11.1",
        "-c",
        &script,
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[tokio::test]
#[ignore = "needs Docker"]
async fn a_message_that_cannot_leave_is_read_with_what_its_last_attempt_was_told() {
    use hlb_engine::mail_relay::{self, Relay};
    // A relay nobody listens on: every remote domain's attempt is refused, as where
    // a line closes the port.
    let s = start_with(&["--add-host", "relay.test:127.0.0.1"], &[]);
    let id = s.ensure_domain("example.org").await.expect("domain");
    s.set_identity("mail.example.org", &id)
        .await
        .expect("named");
    s.ensure_account("alice@example.org", "alice-password-0123456789", &[])
        .await
        .expect("alice");
    assert!(
        hlb_engine::mail_queue::read(&s, 0)
            .await
            .expect("read")
            .0
            .is_empty(),
        "a fresh Stalwart's queue is empty"
    );
    let relay = Relay {
        host: "relay.test".into(),
        port: 1025,
        implicit_tls: false,
        user: "house@example.org".into(),
    };
    mail_relay::apply(&s, &relay, "unused")
        .await
        .expect("relay");
    let sent = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs() as i64;
    send_to("stuck", &["bob@example.net", "alice@example.org"]);

    let mut waiting = Vec::new();
    for _ in 0..30 {
        waiting = hlb_engine::mail_queue::read(&s, sent)
            .await
            .expect("read")
            .0;
        if waiting.iter().any(|w| w.error.is_some()) {
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    assert_eq!(
        waiting
            .iter()
            .map(|w| w.recipient.as_str())
            .collect::<Vec<_>>(),
        ["bob@example.net"],
        "alice, delivered in the house, is not waiting: {waiting:?}"
    );
    let w = &waiting[0];
    let error = w.error.as_deref().unwrap_or_default();
    assert!(
        error.starts_with("relay.test:") && error.contains("Connection refused"),
        "the last attempt's own words, and who said them: {error}"
    );
    assert!(w.attempts >= 1);
    assert!((w.since - sent).abs() < 60, "taken now: {}", w.since);
    assert_eq!(
        w.expires_at.map(|t| t - w.since),
        Some(3 * 86_400),
        "Stalwart's default: three days before the bounce"
    );
    assert!(!w.late(sent + 60));
    assert!(w.late(sent + 2 * 3_600), "late past the hour");

    // Recorded, and replaced whole once the queue is empty again.
    let state = State::in_memory().await.expect("state");
    state.record_mail_queue(&waiting).await.expect("record");
    assert_eq!(state.mail_queue().await.expect("read"), waiting);
    let raw = s.queue().await.expect("raw").0;
    assert_eq!(raw.len(), 1);
    println!("✓ waiting: {} — {}", w.recipient, error);
    stop();
}

const ACME_NET: &str = "hlb-test-acme";
const ACME_DNS: &str = "hlb-test-acme-dns";
const PEBBLE: &str = "hlb-test-acme-pebble";
const CADDY: &str = "hlb-test-acme-caddy";
/// Stalwart's address on the stand: what the ACME server's resolver answers for none.
const STALWART_IP: &str = "10.232.0.10";
/// Caddy's: every name resolves there, as `mail.example.org` does to the house.
const CADDY_IP: &str = "10.232.0.80";
const PEBBLE_DIR: &str = "https://pebble:14000/dir";

/// An ACME authority standing for Let's Encrypt — Pebble, validating on port 80 of
/// whatever its resolver names — and the house's Caddy in front of Stalwart, as the
/// catalog routes it. Pebble's root, to trust its directory.
fn acme_stand(dir: &std::path::Path) -> String {
    // Stalwart too: a run that panicked left it on the network.
    for c in [CADDY, PEBBLE, ACME_DNS, CONTAINER] {
        let _ = docker(&["rm", "-f", c]);
    }
    let _ = docker(&["network", "rm", ACME_NET]);
    let ok = |out: std::process::Output| {
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    };
    ok(docker(&[
        "network",
        "create",
        "--subnet",
        "10.232.0.0/24",
        ACME_NET,
    ]));
    ok(docker(&[
        "run",
        "-d",
        "--name",
        ACME_DNS,
        "--network",
        ACME_NET,
        "--ip",
        "10.232.0.53",
        "ghcr.io/letsencrypt/pebble-challtestsrv:2.8.0",
        "-defaultIPv4",
        CADDY_IP,
        "-defaultIPv6",
        "",
        "-dns01",
        ":8053",
        "-http01",
        "",
        "-https01",
        "",
        "-tlsalpn01",
        "",
        "-doh",
        "",
    ]));
    ok(docker(&[
        "create",
        "--name",
        PEBBLE,
        "--network",
        ACME_NET,
        "--network-alias",
        "pebble",
        "-e",
        "PEBBLE_VA_NOSLEEP=1",
        // Pebble refuses 5 % of nonces by default, on purpose: an order of ten requests
        // then fails four times in ten, and Stalwart retries it within its task after
        // 32, 64 and 128 s — past the wait below, its task still "Pending".
        "-e",
        "PEBBLE_WFE_NONCEREJECT=0",
        "ghcr.io/letsencrypt/pebble:2.8.0",
        "-config",
        "/cfg.json",
        "-dnsserver",
        "10.232.0.53:8053",
    ]));
    let cfg = dir.join("pebble.json");
    std::fs::write(
        &cfg,
        r#"{"pebble":{"listenAddress":"0.0.0.0:14000","managementListenAddress":"0.0.0.0:15000",
            "certificate":"test/certs/localhost/cert.pem","privateKey":"test/certs/localhost/key.pem",
            "httpPort":80,"tlsPort":5001,"ocspResponderURL":"","externalAccountBindingRequired":false}}"#,
    )
    .expect("config");
    ok(docker(&[
        "cp",
        cfg.to_str().unwrap(),
        &format!("{PEBBLE}:/cfg.json"),
    ]));
    let root = dir.join("pebble-root.pem");
    ok(docker(&[
        "cp",
        &format!("{PEBBLE}:/test/certs/pebble.minica.pem"),
        root.to_str().unwrap(),
    ]));
    ok(docker(&["start", PEBBLE]));
    let root = std::fs::read_to_string(root).expect("root");

    let route = hlb_ingress::Route::new("mail.example.org", "stalwart", 8080);
    let caddyfile = hlb_ingress::render(
        &[route],
        &hlb_ingress::Config {
            tls: hlb_ingress::caddyfile::Tls::Acme {
                email: "admin@example.org".into(),
                wildcard: None,
                staging: false,
                ca: Some(PEBBLE_DIR.into()),
                ca_root: true,
            },
            ..hlb_ingress::Config::default()
        },
    );
    let image = std::env::var("HLB_CADDY_IMAGE").unwrap_or_else(|_| "hlb-caddy:dev".into());
    ok(docker(&[
        "run",
        "-d",
        "--name",
        CADDY,
        "--network",
        ACME_NET,
        "--ip",
        CADDY_IP,
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
    ]));
    root
}

fn acme_stand_down() {
    for c in [CADDY, PEBBLE, ACME_DNS] {
        let _ = docker(&["rm", "-f", c]);
    }
}

/// The issuer and names of the certificate Stalwart presents on `port` to a client
/// asking for `name`.
fn presented(port: u16, name: &str) -> String {
    presented_at(ACME_NET, STALWART_IP, port, name)
}

fn presented_at(network: &str, ip: &str, port: u16, name: &str) -> String {
    let out = docker(&[
        "run",
        "--rm",
        "--network",
        network,
        "--entrypoint",
        "sh",
        "alpine/openssl:3.3.2",
        "-c",
        &format!(
            "echo | openssl s_client -connect {ip}:{port} -servername {name} 2>/dev/null \
             | openssl x509 -noout -issuer -ext subjectAltName"
        ),
    ]);
    String::from_utf8_lossy(&out.stdout).replace('\n', " ")
}

#[tokio::test]
#[ignore = "needs Docker and the hlb-caddy image"]
async fn people_s_clients_meet_a_certificate_for_stalwart_s_public_name() {
    let dir = tempfile::tempdir().expect("tmp");
    let root = acme_stand(dir.path());
    // Stalwart trusts the private directory the way the executor hands it a root:
    // added to the image's own, by `trust::mount`.
    let trust = hlb_engine::trust::mount(std::slice::from_ref(&root)).expect("a mount");
    let files_dir = dir.path().join("hlb");
    for (path, content) in &trust.files {
        let rel = path.strip_prefix("/run/hlb/").expect("under /run/hlb");
        let f = files_dir.join(rel);
        std::fs::create_dir_all(f.parent().unwrap()).expect("dir");
        std::fs::write(f, content).expect("file");
    }
    let env: Vec<String> = trust.env.iter().map(|(k, v)| format!("{k}={v}")).collect();
    let mut extra = vec![
        "--network",
        ACME_NET,
        "--ip",
        STALWART_IP,
        "--network-alias",
        "stalwart",
    ];
    for e in &env {
        extra.extend(["-e", e.as_str()]);
    }
    let s = start_with(&extra, &[(&files_dir, "/run/hlb")]);

    // Caddy holds its own certificate first, as an installation's ingress does.
    let mut caddy_ready = false;
    for _ in 0..60 {
        let logs = docker(&["logs", CADDY]);
        if String::from_utf8_lossy(&logs.stderr).contains("certificate obtained successfully") {
            caddy_ready = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    assert!(caddy_ready, "Caddy got no certificate from Pebble");

    let state = State::in_memory().await.expect("state");
    let acme = Exposure {
        domain: "example.org".into(),
        certificates: Certificates::Acme,
        acme_email: Some("admin@example.org".into()),
        dns_provider: None,
        staging: false,
        controller_host: None,
        acme_ca: Some(PEBBLE_DIR.into()),
        acme_ca_root: Some(root.clone()),
    };
    state.set_exposure(&acme).await.expect("exposure");
    state
        .upsert_app(
            "stalwart",
            &catalog("_platform/stalwart"),
            Some("mail.example.org"),
        )
        .await
        .expect("app");
    let vault = hlb_secrets::Vault::init(dir.path().join("k.key")).expect("vault");
    // What the apps meet, under Homelabus's root: it must stay theirs.
    let ours = hlb_engine::submission::root(&state, &vault, "example.org")
        .await
        .expect("root");
    let overlay = hlb_agent::pki::issue_platform_server(&ours, "stalwart")
        .await
        .expect("leaf");
    s.add_certificate(&overlay.cert_pem, &overlay.key_pem)
        .await
        .expect("overlay");

    let preview = hlb_engine::mail_tls::certify(&state, &vault, &s, false)
        .await
        .expect("preview");
    assert_eq!(
        preview,
        ["mail.example.org's certificate requested from https://pebble:14000/dir over HTTP-01"]
    );
    assert!(
        s.acme_providers().await.expect("read").is_empty(),
        "a preview opens no account"
    );
    assert_eq!(
        hlb_engine::mail_tls::certify(&state, &vault, &s, true)
            .await
            .expect("certify"),
        preview
    );
    let mut issued = false;
    for _ in 0..90 {
        let certs = s.certificates().await.expect("read");
        if hlb_engine::submission::holds(&certs, "mail.example.org", chrono::Utc::now()) {
            issued = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    assert!(
        issued,
        "no certificate through Caddy's route: {:?}",
        s.acme_tasks(&s.domain_id("example.org").await.expect("id"))
            .await
    );
    for port in [993, 465] {
        let got = presented(port, "mail.example.org");
        assert!(
            got.contains("Pebble Intermediate") && got.contains("DNS:mail.example.org"),
            "{port}: {got}"
        );
    }
    let apps = presented(465, "stalwart");
    assert!(
        apps.contains("Homelabus example.org") && apps.contains("DNS:stalwart"),
        "the apps' certificate is still theirs: {apps}"
    );
    println!("✓ ACME, HTTP-01 through Caddy: 993 and 465 present mail.example.org under Pebble");
    assert!(
        hlb_engine::mail_tls::certify(&state, &vault, &s, true)
            .await
            .expect("again")
            .is_empty(),
        "nothing to do twice"
    );

    // Internal: a leaf under Homelabus's root, the account closed.
    let internal = Exposure {
        certificates: Certificates::Internal,
        ..acme.clone()
    };
    state.set_exposure(&internal).await.expect("exposure");
    assert_eq!(
        hlb_engine::mail_tls::certify(&state, &vault, &s, true)
            .await
            .expect("internal"),
        [
            "mail.example.org's certificate no longer requested from an ACME directory",
            "a certificate for mail.example.org under Homelabus's root",
        ]
    );
    assert!(s.acme_providers().await.expect("read").is_empty());
    assert_eq!(state.mail_acme_provider().await.expect("read"), None);
    let got = presented(993, "mail.example.org");
    assert!(
        got.contains("Homelabus example.org") && got.contains("DNS:mail.example.org"),
        "{got}"
    );
    println!("✓ internal: 993 presents mail.example.org under Homelabus's root");

    // And back: the ten-year leaf would hide every certificate ACME brings.
    state.set_exposure(&acme).await.expect("exposure");
    hlb_engine::mail_tls::certify(&state, &vault, &s, true)
        .await
        .expect("acme again");
    let mut back = String::new();
    for _ in 0..90 {
        let _ = hlb_engine::mail_tls::certify(&state, &vault, &s, true).await;
        back = presented(993, "mail.example.org");
        if back.contains("Pebble Intermediate") {
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(2));
    }
    assert!(back.contains("Pebble Intermediate"), "{back}");
    assert_eq!(state.mail_public_certificate().await.expect("read"), None);
    println!("✓ back to ACME: the internal leaf taken back, Pebble's served");
    stop();
    acme_stand_down();
    let _ = docker(&["network", "rm", ACME_NET]);
}

#[tokio::test]
#[ignore = "needs Docker"]
async fn a_domain_its_provider_publishes_is_certified_over_dns_01_with_no_port_open() {
    let dir = tempfile::tempdir().expect("tmp");
    let bind_ip = bind();
    // Pebble asks BIND, the provider's zone, for the challenge's TXT — and reaches no
    // port of Stalwart's: none is published to it.
    let _ = docker(&["rm", "-f", PEBBLE]);

    let out = docker(&[
        "run",
        "-d",
        "--name",
        PEBBLE,
        "-e",
        "PEBBLE_VA_NOSLEEP=1",
        // Pebble refuses 5 % of nonces by default, on purpose: an order of ten requests
        // then fails four times in ten, and Stalwart retries it within its task after
        // 32, 64 and 128 s — past the wait below, its task still "Pending".
        "-e",
        "PEBBLE_WFE_NONCEREJECT=0",
        "ghcr.io/letsencrypt/pebble:2.8.0",
        "-dnsserver",
        &format!("{bind_ip}:53"),
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let pebble_ip = String::from_utf8_lossy(
        &docker(&[
            "inspect",
            "-f",
            "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
            PEBBLE,
        ])
        .stdout,
    )
    .trim()
    .to_string();
    let root_file = dir.path().join("pebble-root.pem");
    assert!(docker(&[
        "cp",
        &format!("{PEBBLE}:/test/certs/pebble.minica.pem"),
        root_file.to_str().unwrap(),
    ])
    .status
    .success());
    let root = std::fs::read_to_string(&root_file).expect("root");
    let trust = hlb_engine::trust::mount(std::slice::from_ref(&root)).expect("a mount");
    let files_dir = dir.path().join("hlb");
    for (path, content) in &trust.files {
        let f = files_dir.join(path.strip_prefix("/run/hlb/").expect("under /run/hlb"));
        std::fs::create_dir_all(f.parent().unwrap()).expect("dir");
        std::fs::write(f, content).expect("file");
    }
    let env: Vec<String> = trust.env.iter().map(|(k, v)| format!("{k}={v}")).collect();
    let host = format!("pebble:{pebble_ip}");
    let mut extra = vec!["--add-host", host.as_str()];
    for e in &env {
        extra.extend(["-e", e.as_str()]);
    }
    // Its traces where an installation has them: a failure here says why.
    let s = start_with(&extra, &[(&files_dir, "/run/hlb")]);
    s.trace_to_stdout()
        .await
        .expect("a tracer to standard output");

    // The domain's records published through a DnsServer, as phase 3 leaves them.
    let domain = s.ensure_domain("example.org").await.expect("domain");
    let server = s
        .create_dns_server(serde_json::json!({
            "@type": "Tsig",
            "host": bind_ip,
            "port": 53,
            "keyName": "hlb",
            "key": { "@type": "Value", "secret": TSIG },
            "protocol": "tcp",
            "tsigAlgorithm": "hmac-sha256",
            "description": "test",
        }))
        .await
        .expect("server");
    hlb_engine::mail_dns::switch(&s, &domain, &server, &["dkim".to_string()])
        .await
        .expect("switched");

    let state = State::in_memory().await.expect("state");
    state
        .set_exposure(&Exposure {
            domain: "example.org".into(),
            certificates: Certificates::Acme,
            acme_email: Some("admin@example.org".into()),
            dns_provider: None,
            staging: false,
            controller_host: None,
            acme_ca: Some("https://pebble:14000/dir".into()),
            acme_ca_root: Some(root),
        })
        .await
        .expect("exposure");
    state
        .upsert_app(
            "stalwart",
            &catalog("_platform/stalwart"),
            Some("mail.example.org"),
        )
        .await
        .expect("app");
    let vault = hlb_secrets::Vault::init(dir.path().join("k.key")).expect("vault");
    assert_eq!(
        hlb_engine::mail_tls::certify(&state, &vault, &s, true)
            .await
            .expect("certify"),
        ["mail.example.org's certificate requested from https://pebble:14000/dir over DNS-01"]
    );
    let mut issued = false;
    // Stalwart waits to see the challenge's TXT through its own resolver before it
    // answers (`propagationTimeout`); this one asks the real example.org, sees nothing,
    // and goes on once the wait is over — a minute at least.
    for _ in 0..240 {
        let certs = s.certificates().await.expect("read");
        if hlb_engine::submission::holds(&certs, "mail.example.org", chrono::Utc::now()) {
            issued = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    assert!(
        issued,
        "no certificate over DNS-01: {:?}\n{}",
        s.acme_tasks(&domain).await,
        String::from_utf8_lossy(&docker(&["logs", CONTAINER]).stderr)
            .lines()
            .filter(|l| l.contains("acme") || l.contains("ERROR") || l.contains("WARN"))
            .collect::<Vec<_>>()
            .join("\n")
    );
    let ip = String::from_utf8_lossy(
        &docker(&[
            "inspect",
            "-f",
            "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
            CONTAINER,
        ])
        .stdout,
    )
    .trim()
    .to_string();
    let got = presented_at("bridge", &ip, 993, "mail.example.org");
    assert!(
        got.contains("Pebble Intermediate") && got.contains("DNS:mail.example.org"),
        "{got}"
    );
    println!("✓ DNS-01 through the provider's zone: 993 presents mail.example.org under Pebble");
    for c in [PEBBLE, BIND] {
        let _ = docker(&["rm", "-f", c]);
    }
    stop();
}
