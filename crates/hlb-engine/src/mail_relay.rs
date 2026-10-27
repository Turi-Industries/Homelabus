//! Sending out through a relay, where the house's line closes port 25.
//!
//! Most residential lines block outbound 25, and many receivers refuse a residential
//! address anyway: Stalwart's `mx` route then queues every message for days, and the
//! sender learns of it from a bounce. A relay is a provider's submission service —
//! address, port, account — written into Stalwart as a route every remote domain
//! takes. Its password is the vault's; Stalwart holds the copy it sends with.
//!
//! 🔴 Stalwart's defaults would hand the relay's password to anyone in the way: its
//! `default` TLS strategy takes STARTTLS when offered (`startTls: optional`), and the
//! outbound strategy retries a TLS failure with `invalid-tls`, which accepts any
//! certificate. The relay gets a TLS strategy of its own — TLS required, the
//! certificate verified, no fallback.

use hlb_orchestrator::ServiceSpec;

/// Where a copy of the relay's password used to be written. Stalwart holds the one it
/// signs in with, and nothing ever read this one back: a credential kept for nobody is
/// one more to leak and to rotate. Forgotten when the relay is set or removed.
pub const FORMER_PASSWORD_SECRET: &str = "mail-relay-password";
/// The route's name, which the outbound strategy names.
pub const ROUTE: &str = "relay";
/// The TLS strategy's name.
pub const TLS: &str = "relay-tls";

/// A provider's submission service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Relay {
    pub host: String,
    pub port: u16,
    /// TLS from the first byte (465); STARTTLS otherwise, required.
    pub implicit_tls: bool,
    pub user: String,
}

/// Stalwart's own outbound expressions, as 0.16.26 ships them: what a removed relay
/// gives back.
fn stalwart_defaults() -> (serde_json::Value, serde_json::Value) {
    (
        serde_json::json!({
            "match": { "0": { "if": "is_local_domain(rcpt_domain)", "then": "'local'" } },
            "else": "'mx'",
        }),
        serde_json::json!({
            "match": { "0": { "if": "retry_num > 0 && last_error == 'tls'", "then": "'invalid-tls'" } },
            "else": "'default'",
        }),
    )
}

/// Every remote domain through the relay, with its TLS strategy and no other.
fn through_relay() -> (serde_json::Value, serde_json::Value) {
    (
        serde_json::json!({
            "match": { "0": { "if": "is_local_domain(rcpt_domain)", "then": "'local'" } },
            "else": format!("'{ROUTE}'"),
        }),
        serde_json::json!({ "match": {}, "else": format!("'{TLS}'") }),
    )
}

/// The relay Stalwart sends through now, read from its route.
pub async fn current(mail: &hlb_mail::Stalwart) -> crate::Result<Option<Relay>> {
    let Some(r) = mail.named("MtaRoute", ROUTE).await? else {
        return Ok(None);
    };
    let (route, _) = mail.outbound_strategy().await?;
    if route.get("else").and_then(|v| v.as_str()) != Some(&format!("'{ROUTE}'")) {
        return Ok(None);
    }
    let text = |k: &str| r.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
    Ok(Some(Relay {
        host: text("address"),
        port: r.get("port").and_then(|v| v.as_u64()).unwrap_or(0) as u16,
        implicit_tls: r
            .get("implicitTls")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        user: text("authUsername"),
    }))
}

/// Sends every remote domain through `relay`, effective at once.
pub async fn apply(mail: &hlb_mail::Stalwart, relay: &Relay, password: &str) -> crate::Result<()> {
    mail.put_named(
        "MtaTlsStrategy",
        TLS,
        serde_json::json!({
            "description": "Homelabus: the relay's — TLS required, its certificate verified",
            "allowInvalidCerts": false,
            "startTls": "require",
            // The recipient's MTA-STS and DANE name its own MX, never the relay: kept,
            // a domain enforcing either would refuse every message handed over.
            "mtaSts": "disable",
            "dane": "disable",
        }),
    )
    .await?;
    mail.put_named(
        "MtaRoute",
        ROUTE,
        serde_json::json!({
            "@type": "Relay",
            "description": "Homelabus: every remote domain, through the relay",
            "address": relay.host,
            "port": relay.port,
            "protocol": "smtp",
            "implicitTls": relay.implicit_tls,
            "allowInvalidCerts": false,
            "authUsername": relay.user,
            "authSecret": { "@type": "Value", "secret": password },
        }),
    )
    .await?;
    let (route, tls) = through_relay();
    mail.set_outbound_strategy(route, tls).await?;
    Ok(())
}

/// Sends remote domains by their MX again. `false` when no relay was set.
pub async fn remove(mail: &hlb_mail::Stalwart) -> crate::Result<bool> {
    let was = current(mail).await?.is_some();
    let (route, tls) = stalwart_defaults();
    mail.set_outbound_strategy(route, tls).await?;
    // The route and its strategy after the strategy that names them: removed first,
    // a message leaving between the two calls would name a route that is gone.
    mail.destroy_named("MtaRoute", ROUTE).await?;
    mail.destroy_named("MtaTlsStrategy", TLS).await?;
    mail.reload_settings().await?;
    Ok(was)
}

/// The job trying the relay's account before anything is written: TLS as Stalwart will
/// require it, the certificate verified against what Stalwart trusts — the image's
/// public roots and `roots` ([`crate::submission::trusted_roots`]) —, AUTH. The
/// password reaches it in a file, never in its command line or environment.
///
/// 🔴 Verified against the public roots alone, a relay under the private ACME
/// authority Stalwart is handed was refused by the trial and would have been taken by
/// Stalwart (found on the lab, 2026-10-20).
pub fn trial_job(relay: &Relay, password: &str, network: &str, roots: &[String]) -> ServiceSpec {
    const NETRC: &str = "/run/hlb/netrc";
    let (scheme, tls) = if relay.implicit_tls {
        ("smtps", "")
    } else {
        ("smtp", "--ssl-reqd")
    };
    let mount = crate::trust::mount(roots);
    // Beside the image's bundle, not in place of it: OpenSSL reads both.
    let capath = if mount.is_some() {
        format!(" --capath {}", crate::trust::DIR)
    } else {
        String::new()
    };
    let script = format!(
        r#"set -u
url="{scheme}://{host}:{port}"
curl -sS --max-time 30 {tls}{capath} --netrc-file {NETRC} -X NOOP "$url" \
  || {{ echo "hlb: the relay refused {user} on $url, or offered no TLS it could verify"; exit 1; }}
echo "hlb: the relay took {user} on $url""#,
        host = relay.host,
        port = relay.port,
        user = relay.user,
    );
    let mut job = ServiceSpec::new("hlb-relay-trial", crate::submission::TRIAL_IMAGE)
        .job()
        .network(network)
        .file(
            NETRC,
            format!(
                "machine {} login {} password {password}\n",
                relay.host, relay.user
            ),
        )
        .command(["sh", "-c", &script]);
    for (path, content) in mount.map(|m| m.files).unwrap_or_default() {
        job = job.file(path, content);
    }
    job.hardening.read_only_rootfs = true;
    job
}

/// The job telling whether Stalwart's node reaches the internet on port 25 — whether
/// a relay is needed. Run on that node, where its data pins it: the line of another
/// machine says nothing. Gmail's first MX stands for every receiver: a line that blocks
/// 25 blocks it for all of them.
pub fn port25_job(network: &str) -> ServiceSpec {
    // A connection, no SMTP: nothing is said to the receiver.
    let script = r#"if nc -z -w 10 gmail-smtp-in.l.google.com 25 2>/dev/null; then
  echo "hlb: port 25 reaches the internet"; exit 0
fi
echo "hlb: port 25 does not reach the internet"; exit 3"#;
    let mut job = ServiceSpec::new("hlb-port25-probe", crate::submission::TRIAL_IMAGE)
        .job()
        .constraint(format!(
            "node.labels.{}==true",
            hlb_types::manifest::data_label(crate::submission::host())
        ))
        .network(network)
        .command(["sh", "-c", script]);
    job.hardening.read_only_rootfs = true;
    job
}
