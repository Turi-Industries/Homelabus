//! Outgoing mail: the account an app sends as, and what Stalwart needs for any app to
//! send at all.
//!
//! 🔴 Until 2026-10-18 `kind: smtp` generated a password and nothing else: no account
//! in Stalwart held it, port 587 was handed out and Stalwart does not open it, and the
//! login handed out was the app's name where Stalwart takes an address. No app could
//! send, and nothing said so. Measured on 0.16.26:
//!
//! | | |
//! |---|---|
//! | Listening on a fresh install | 25, 465, 993, 995, 4190, 443, 8080 — not 587 |
//! | A listener added over JMAP | bound at the next restart only |
//! | A certificate added over JMAP | served by SNI at once, after `ReloadTlsCertificates` |
//! | Its own certificate | `CN=rcgen self signed cert`, no name: every app refuses it |
//! | `AUTH PLAIN` / `LOGIN` | offered over TLS only, and to the full address only |
//! | `MAIL FROM` another address | `501`: an account sends as itself (`mustMatchSender`) |
//!
//! Hence: a submission listener, once; a certificate for Stalwart's overlay name under
//! Homelabus's own root, which every app sending mail is handed (`crate::trust`); and an
//! account per app, TRIED from the overlay before the action is done — a password
//! nobody tried is only noticed at the first mail that does not leave.

use hlb_orchestrator::ServiceSpec;

/// Stalwart's name on the overlay, which its certificate is issued for.
pub fn host() -> &'static str {
    hlb_types::Capability::Smtp {
        sender: hlb_types::SmtpSender::App,
    }
    .platform_service()
    .unwrap_or("stalwart")
}

/// curl, which speaks SMTP with STARTTLS and a netrc file — by digest: this image is
/// handed an app's password.
pub const TRIAL_IMAGE: &str =
    "curlimages/curl:8.11.1@sha256:c1fe1679c34d9784c1b0d1e5f62ac0a79fca01fb6377cdd33e90473c6f9f9a69";

/// How long a trial may take: a few round trips, or something is wrong.
const TRIAL_TIMEOUT_S: u64 = 120;

/// Where an app's sending address is kept, beside its password. Not a secret, read
/// like one: `{{ smtp.user }}` and `{{ smtp.from }}` must name the account that was
/// tried, never one recomputed from a domain that may have changed since.
pub fn address_secret(app: &str) -> String {
    format!("{app}-smtp-address")
}

/// Does Stalwart need a certificate for [`host`]? None names it, or every one that
/// does ends within a year — renewed at an install, then, never on the morning it
/// lapses.
pub fn needs_certificate(
    certs: &[hlb_mail::Certificate],
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    !holds(certs, host(), now + chrono::Duration::days(365))
}

/// Does one of `certs` name `name` beyond `until`?
pub fn holds(
    certs: &[hlb_mail::Certificate],
    name: &str,
    until: chrono::DateTime<chrono::Utc>,
) -> bool {
    certs.iter().any(|c| {
        c.names.iter().any(|n| n.eq_ignore_ascii_case(name))
            && chrono::DateTime::parse_from_rfc3339(&c.not_valid_after).is_ok_and(|end| end > until)
    })
}

/// The job trying `address` on the submission port, from the overlay the apps send
/// from — their network, their name for Stalwart, the root they are given.
///
/// It must authenticate, and it must be REFUSED as another sender: an account that may
/// send as anyone would let a compromised app write as the administrator. The password
/// reaches it in a file, never in its command line or environment.
pub fn trial_job(
    app: &str,
    address: &str,
    password: &str,
    root_pem: &str,
    network: &str,
) -> ServiceSpec {
    const ROOT: &str = "/run/hlb/root.pem";
    const NETRC: &str = "/run/hlb/netrc";
    let domain = address.rsplit_once('@').map_or("", |(_, d)| d);
    // curl's exit code for a refused `MAIL FROM`; any other failure says nothing about
    // who may send.
    let script = format!(
        r#"set -u
url="smtp://{host}:{port}"
opts="-sS --max-time 30 --ssl-reqd --cacert {ROOT} --netrc-file {NETRC}"
curl $opts -X NOOP "$url" || {{ echo "hlb: $HLB_ADDRESS was refused on $url"; exit 1; }}
printf 'Subject: hlb\r\n\r\nrefused\r\n' | curl $opts --mail-from "$HLB_OTHER" --mail-rcpt "$HLB_ADDRESS" -T - "$url"
rc=$?
[ "$rc" -eq 55 ] || {{ echo "hlb: $HLB_ADDRESS sending as $HLB_OTHER ended with curl $rc, not the refusal (55)"; exit 2; }}
echo "hlb: $HLB_ADDRESS accepted, and refused as $HLB_OTHER""#,
        host = host(),
        port = hlb_mail::SUBMISSION_PORT,
    );
    let mut job = ServiceSpec::new(format!("hlb-smtp-trial-{app}"), TRIAL_IMAGE)
        .job()
        .network(network)
        .file(ROOT, root_pem)
        .file(
            NETRC,
            format!("machine {} login {address} password {password}\n", host()),
        )
        .env(vec![
            ("HLB_ADDRESS".to_string(), address.to_string()),
            ("HLB_OTHER".to_string(), format!("postmaster@{domain}")),
        ])
        .command(["sh", "-c", &script]);
    // Nothing written: the message comes on stdin.
    job.hardening.read_only_rootfs = true;
    job
}

/// The roots Stalwart trusts beside its image's public ones, and so whatever tries a
/// connection on its behalf.
///
/// It requests its public name's certificate itself, and under a private ACME
/// authority refused the directory's own certificate: the account could not even be
/// opened.
pub async fn trusted_roots(state: &hlb_state::State) -> crate::Result<Vec<String>> {
    Ok(match state.exposure().await? {
        Some(e) if e.certificates == hlb_state::Certificates::Acme => {
            e.acme_ca_root.into_iter().collect()
        }
        _ => Vec::new(),
    })
}

/// Homelabus's own root, made now if `hlb config exposure --internal` has not made it:
/// Stalwart's certificate is signed under it whatever the exposure, Let's Encrypt
/// included — no public authority signs a name only the overlay has.
pub async fn root(
    state: &hlb_state::State,
    vault: &hlb_secrets::Vault,
    domain: &str,
) -> crate::Result<hlb_agent::pki::CertPair> {
    if crate::ingress::root(state, vault).await?.is_none() {
        let r = hlb_agent::pki::generate_web_root(&format!("Homelabus {domain}"))
            .await
            .map_err(|e| crate::Error::Submission(format!("Homelabus's root: {e}")))?;
        let j = serde_json::json!({ "cert": r.cert_pem, "key": r.key_pem });
        state
            .store_secret_if_absent(
                crate::ingress::ROOT_SECRET,
                &vault.encrypt(&j.to_string())?,
                "internal authority's root",
            )
            .await?;
    }
    // Read back: another command may have stored its own first, and that one is kept.
    let (cert_pem, key_pem) = crate::ingress::root(state, vault)
        .await?
        .ok_or_else(|| crate::Error::Submission("Homelabus's root was not stored".into()))?;
    Ok(hlb_agent::pki::CertPair { cert_pem, key_pem })
}

/// How long a ban for failed sign-ins lasts, where Stalwart had it last for ever: a
/// phone left with an old password, retrying every few minutes, is banned by the
/// evening and would never be let in again.
pub const AUTH_BAN_MS: u64 = 86_400_000;

/// Stalwart never bans the platform network's addresses, and a ban lasts a day.
///
/// 🔴 Every webmail and every app sign in from their container's one address: banned
/// for ever after 100 failures (Stalwart 0.16.26's default), one person guessing
/// through Roundcube shut every household member out of it. Their own limits stand
/// in front — Roundcube locks an account after three failures a minute — and a
/// client from outside is still banned, for a day. `Ok(what changed)` — or, `apply`
/// false, what would.
pub async fn protect_platform<O: hlb_orchestrator::Orchestrator + ?Sized>(
    orch: &O,
    mail: &hlb_mail::Stalwart,
    apply: bool,
) -> crate::Result<Vec<String>> {
    let mut changed = Vec::new();
    let subnets = orch
        .network_subnets(hlb_orchestrator::PLATFORM_NETWORK)
        .await?;
    if subnets.is_empty() {
        return Err(crate::Error::Submission(format!(
            "{} gives no subnet: Stalwart cannot be told never to ban the apps",
            hlb_orchestrator::PLATFORM_NETWORK
        )));
    }
    for s in &subnets {
        if !apply {
            if !mail.trusts(s).await? {
                changed.push(format!("never banned: {s}"));
            }
            continue;
        }
        if mail
            .trust_network(
                s,
                "Homelabus's platform network: webmails and apps sign in for many people \
                 from one address",
            )
            .await?
        {
            changed.push(format!("never banned: {s}"));
        }
    }
    if mail.auth_ban_period().await?.is_none() {
        if apply {
            mail.set_auth_ban_period(AUTH_BAN_MS).await?;
        }
        changed.push("a ban for failed sign-ins lasts a day, not for ever".into());
    }
    Ok(changed)
}

/// Stalwart's traces go to its standard output, read by `docker service logs`.
/// `Ok(what changed)` — or, `apply` false, what would.
///
/// 🔴 Its image's tracer writes to a directory the image lacks, and drops everything: a
/// delivery refused, an ACME order failed, said nowhere. Read every night as well as at
/// install, so a tracer someone removed comes back.
pub async fn trace(mail: &hlb_mail::Stalwart, apply: bool) -> crate::Result<Vec<String>> {
    if mail.traces_to_stdout().await? {
        return Ok(Vec::new());
    }
    if apply {
        mail.trace_to_stdout().await?;
    }
    Ok(vec![format!(
        "its traces in its logs: docker service logs {}",
        host()
    )])
}

/// Stalwart's own recursive resolver: a companion of its manifest, by this name.
pub const RESOLVER: &str = "resolver";

/// Stalwart resolves through its own resolver — the Unbound companion beside it, asked
/// by nobody else. `Ok(what changed)` — or, `apply` false, what would.
///
/// 🔴 Its default is the system's resolver, the node's: a public one in most houses
/// (1.1.1.1 on the maintainer's machine), which Spamhaus, URIBL and the others refuse —
/// they answer a refusal, scored zero, and check nothing. A router forwarding to its
/// ISP was refused by URIBL still. Through Unbound recursing on its own, every list
/// answered (0.16.26, measured 2026-10-20). Stalwart takes an address, not a name: the
/// companion's virtual IP, kept by Swarm while the service lives and read again every
/// night.
pub async fn own_resolver<O: hlb_orchestrator::Orchestrator + ?Sized>(
    orch: &O,
    mail: &hlb_mail::Stalwart,
    apply: bool,
) -> crate::Result<Vec<String>> {
    let service = format!("{}-{RESOLVER}", host());
    let Some(address) = orch
        .service_address(&service, hlb_orchestrator::PLATFORM_NETWORK)
        .await?
    else {
        return Err(crate::Error::Submission(format!(
            "{service} is not deployed, and the spam filter's blocklists refuse a public \
             resolver: hlb upgrade {} --apply",
            host()
        )));
    };
    let wanted = [format!("tcp {address}:53"), format!("udp {address}:53")];
    if mail.resolver_servers().await? == wanted {
        return Ok(Vec::new());
    }
    if apply {
        mail.resolve_through(&address).await?;
    }
    Ok(vec![format!(
        "resolves through its own resolver, {service} ({address})"
    )])
}

/// Stalwart answers as its public name — its route's host — with the mail domain as its
/// default. `Ok(what changed)` — or, `apply` false, what would; nothing while Stalwart
/// has no route or there is no exposure, since then no name of it is in any DNS.
///
/// 🔴 Unset, it says the container's name, the task's id on Swarm: `220 7f3a9c0e21b4`,
/// `EHLO 7f3a9c0e21b4`, and every MX and SRV record it computes pointing there. A
/// receiver reads `EHLO` against the sender's reverse DNS. Read every night as well as
/// at install, so a route moved to another name is followed.
pub async fn name_server(
    state: &hlb_state::State,
    mail: &hlb_mail::Stalwart,
    apply: bool,
) -> crate::Result<Vec<String>> {
    let (Some(name), Some(exposure)) = (state.app_domain(host()).await?, state.exposure().await?)
    else {
        return Ok(Vec::new());
    };
    let now = mail.identity().await?;
    let domain_id = match mail.domain_id(&exposure.domain).await {
        Ok(id) => Some(id),
        Err(hlb_mail::Error::UnknownDomain(_)) => None,
        Err(e) => return Err(e.into()),
    };
    if now.hostname == name && domain_id.as_deref() == Some(now.default_domain_id.as_str()) {
        return Ok(Vec::new());
    }
    if apply {
        let id = match domain_id {
            Some(id) => id,
            None => mail.ensure_domain(&exposure.domain).await?,
        };
        mail.set_identity(&name, &id).await?;
    }
    Ok(vec![format!(
        "answers as {name}, {} by default",
        exposure.domain
    )])
}

/// Restarts Stalwart so it binds a listener just added, and waits until it answers
/// again — which is when an account can be made.
pub async fn restart<O: hlb_orchestrator::Orchestrator + ?Sized>(
    orch: &O,
    mail: &hlb_mail::Stalwart,
    service: &str,
) -> crate::Result<()> {
    let replicas = orch.status(service).await?.desired_replicas.max(1);
    orch.scale(service, 0).await?;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(120);
    // Scaled to zero is asked, not done: its RocksDB is held until the task exits.
    while orch.status(service).await?.running_replicas > 0 {
        if tokio::time::Instant::now() > deadline {
            return Err(crate::Error::Submission(format!(
                "{service} did not stop within 120 s; it is left at 0 replicas"
            )));
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
    orch.scale(service, replicas).await?;
    orch.wait_healthy(service, 180).await?;
    for _ in 0..30 {
        if mail.ping().await.is_ok() {
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
    Err(crate::Error::Submission(format!(
        "{service} restarted and its API did not answer within a minute"
    )))
}

/// Runs [`trial_job`]. What curl said, when it was not the expected.
pub async fn try_account<O: hlb_orchestrator::Orchestrator + ?Sized>(
    orch: &O,
    job: &ServiceSpec,
) -> std::result::Result<(), String> {
    match orch.run_job(job, TRIAL_TIMEOUT_S).await {
        Ok(o) if o.succeeded => Ok(()),
        Ok(o) => Err(o.output.join("\n")),
        Err(e) => Err(format!("the trial could not run: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_resolver_stalwart_is_pointed_at_is_a_companion_of_its_manifest() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../catalog/_platform/stalwart/manifest.yaml"
        );
        let m: hlb_types::Manifest =
            serde_yaml_ng::from_str(&std::fs::read_to_string(path).expect("manifest"))
                .expect("parsed");
        assert_eq!(m.metadata.name, host());
        let resolver = m
            .spec
            .companions
            .iter()
            .find(|c| c.name == RESOLVER)
            .expect("Stalwart's manifest deploys its resolver");
        assert!(
            resolver.healthcheck.is_some(),
            "waited for before Stalwart starts"
        );
    }

    fn cert(names: &[&str], end: &str) -> hlb_mail::Certificate {
        hlb_mail::Certificate {
            id: "c".into(),
            names: names.iter().map(|n| n.to_string()).collect(),
            not_valid_after: end.into(),
            pem: String::new(),
        }
    }

    #[test]
    fn the_overlay_name_is_the_mail_servers() {
        assert_eq!(host(), "stalwart");
    }

    #[test]
    fn a_certificate_is_issued_when_none_names_stalwart_for_another_year() {
        let now = chrono::DateTime::parse_from_rfc3339("2026-10-18T12:00:00Z")
            .expect("date")
            .with_timezone(&chrono::Utc);
        assert!(needs_certificate(&[], now), "a fresh Stalwart has none");
        // Its own, self-signed, names nothing an app asks for.
        assert!(needs_certificate(
            &[cert(&["rcgen self signed cert"], "4096-01-01T00:00:00Z")],
            now
        ));
        assert!(
            needs_certificate(&[cert(&["stalwart"], "2027-03-01T00:00:00Z")], now),
            "within a year: renewed now"
        );
        assert!(!needs_certificate(
            &[cert(&["stalwart"], "2036-10-15T00:00:00Z")],
            now
        ));
    }

    #[test]
    fn the_trial_is_handed_the_password_in_a_file_only() {
        let j = trial_job(
            "vikunja",
            "vikunja@home.example",
            "s3cretPassw0rd",
            "ROOT",
            "hlb_platform",
        );
        assert!(j.image.contains("@sha256:"), "{}", j.image);
        assert_eq!(j.networks, vec!["hlb_platform".to_string()]);
        let netrc = j
            .files
            .iter()
            .find(|(p, _)| p.ends_with("netrc"))
            .map(|(_, c)| c.as_str())
            .expect("a netrc");
        assert_eq!(
            netrc,
            "machine stalwart login vikunja@home.example password s3cretPassw0rd\n"
        );
        assert!(j
            .files
            .contains(&("/run/hlb/root.pem".into(), "ROOT".into())));
        // 🔴 Nowhere `docker service inspect` or `ps` would print it.
        assert!(!j.command.join(" ").contains("s3cretPassw0rd"));
        assert!(!j.env.iter().any(|(_, v)| v.contains("s3cretPassw0rd")));
        // Tried as itself, and as another address, which must be refused.
        assert!(j
            .env
            .contains(&("HLB_OTHER".into(), "postmaster@home.example".into())));
        let script = j.command.join(" ");
        assert!(script.contains("smtp://stalwart:587"), "{script}");
        assert!(
            script.contains("--ssl-reqd") && script.contains("--cacert"),
            "{script}"
        );
        assert!(script.contains(r#""$rc" -eq 55"#), "{script}");
    }
}
