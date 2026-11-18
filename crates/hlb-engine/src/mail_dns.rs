//! The DNS records the house's mail needs, read from a public resolver against the
//! zones Stalwart computed — the same pass for `hlb mail dns` and the controller's night.

use async_trait::async_trait;
use hlb_api::mail_dns::{self, MailRecord, Purpose, RecordState};

/// Where records are resolved. A trait so the judging is tried without the internet.
#[async_trait]
pub trait Lookup: Send + Sync {
    /// The data of every `kind` record at `name`; `Err` when nothing could say.
    async fn lookup(&self, name: &str, kind: &str) -> Result<Vec<String>, String>;
}

#[async_trait]
impl Lookup for hlb_mail::public_dns::PublicDns {
    async fn lookup(&self, name: &str, kind: &str) -> Result<Vec<String>, String> {
        hlb_mail::public_dns::PublicDns::lookup(self, name, kind).await
    }
}

/// One pass.
#[derive(Debug)]
pub struct Reading {
    /// The records judged, every domain Stalwart hosts.
    pub records: Vec<MailRecord>,
    /// The other lines of each zone the house serves — SRV records, TLS reports —
    /// printed, not judged.
    pub optional: Vec<(String, String)>,
    /// How many lines of the zones were left out: what does harm or nothing published
    /// by hand ([`mail_dns::served`]).
    pub unserved: usize,
    /// The spam filter's blocklists refusing Stalwart's resolver, by tag; `Err` when
    /// Stalwart could not be asked — not "none refuse".
    pub refused_blocklists: Result<Vec<String>, String>,
}

impl Default for Reading {
    fn default() -> Self {
        Self {
            records: Vec::new(),
            optional: Vec::new(),
            unserved: 0,
            refused_blocklists: Ok(Vec::new()),
        }
    }
}

/// The ports reaching Stalwart from outside: those its manifest publishes, and 443
/// when it has a route.
pub async fn served_ports(state: &hlb_state::State) -> crate::Result<Vec<u16>> {
    let host = crate::submission::host();
    let mut ports: Vec<u16> = match state.app_manifest(host).await {
        // A mail port is TCP; the lines offered are chosen by its number.
        Ok(m) => m
            .spec
            .security
            .published_ports
            .iter()
            .filter(|p| p.protocol == hlb_types::manifest::Protocol::Tcp)
            .map(|p| p.port)
            .collect(),
        Err(hlb_state::Error::UnknownApp(_)) => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };
    if state.app_domain(host).await?.is_some() {
        ports.push(443);
    }
    Ok(ports)
}

/// `relay_spf` is the term of the relay mail leaves through, which the domain's SPF
/// must name too: Stalwart's own zone knows nothing of it. `ports`, from
/// [`served_ports`], decide which of the other lines are offered.
pub async fn read(
    mail: &hlb_mail::Stalwart,
    dns: &dyn Lookup,
    relay_spf: Option<&str>,
    ports: &[u16],
    now: i64,
) -> crate::Result<Reading> {
    let mut out = Reading {
        // Read with the records: a house whose mail looks right to the internet can
        // still take every spammer's message in, its blocklists answering nothing.
        refused_blocklists: mail.refused_blocklists().await.map_err(|e| e.to_string()),
        ..Reading::default()
    };
    // Read only to say why a key is missing: a reading never fails for it.
    let publishing = mail.domains_dns().await.unwrap_or_default();
    for (domain, zone) in mail.zones().await? {
        // 🔴 The resolver says only "missing"; why is in Stalwart's task — a refused
        // credential, `Failed` on 0.16, retried for ever on 1.0 (`Retry`, `Stalled`).
        let failure = match publishing
            .iter()
            .find(|d| d.name == domain && d.published_by.is_some())
        {
            Some(d) => publishing_failure(&mail.dns_tasks(&d.id).await.unwrap_or_default()),
            None => None,
        };
        let zone = mail_dns::parse_zone(&zone);
        let needed = mail_dns::needed(&domain, &zone);
        for r in &zone {
            if needed.iter().any(|(_, n)| n == r) {
                continue;
            }
            if mail_dns::served(r, ports) {
                out.optional.push((domain.clone(), r.line.clone()));
            } else {
                out.unserved += 1;
            }
        }
        for (purpose, expected) in expected(&domain, needed, relay_spf) {
            let answer = dns
                .lookup(&expected.name, purpose.record_type())
                .await
                .map(|found| match purpose {
                    Purpose::Mx => found,
                    _ => found.iter().map(|d| mail_dns::txt_value(d)).collect(),
                });
            let (state, mut observed) = mail_dns::judge(purpose, &expected, &answer);
            if let (Purpose::Dkim, RecordState::Missing | RecordState::Differs, Some(why)) =
                (purpose, state, &failure)
            {
                observed = format!("{observed} — {why}");
            }
            out.records.push(MailRecord {
                domain: domain.clone(),
                name: expected.name,
                purpose,
                expected: expected.line,
                state,
                observed,
                checked_at: now,
            });
        }
    }
    Ok(out)
}

/// The lines the house's own zone carries for its mail: every record judged, as it
/// must read, and the others offered — Stalwart's zones read alone, no resolver asked.
/// Read before the records are judged, so a key Stalwart made today is served by the
/// time the internet is asked for it.
pub async fn zone_lines(
    mail: &hlb_mail::Stalwart,
    relay_spf: Option<&str>,
    ports: &[u16],
) -> crate::Result<String> {
    let mut out = Vec::new();
    for (domain, zone) in mail.zones().await? {
        out.extend(lines_of(&domain, &zone, relay_spf, ports));
    }
    Ok(out.join("\n"))
}

fn lines_of(domain: &str, zone: &str, relay_spf: Option<&str>, ports: &[u16]) -> Vec<String> {
    let zone = mail_dns::parse_zone(zone);
    let needed = mail_dns::needed(domain, &zone);
    let offered: Vec<String> = zone
        .iter()
        .filter(|r| !needed.iter().any(|(_, n)| n == *r) && mail_dns::served(r, ports))
        .map(|r| r.line.clone())
        .collect();
    expected(domain, needed, relay_spf)
        .into_iter()
        .map(|(_, r)| r.line)
        .chain(offered)
        .collect()
}

/// Why Stalwart's publishing did not land, from its latest task that says: a task done
/// is removed, so what is left is pending or has failed.
fn publishing_failure(tasks: &[hlb_mail::DnsTask]) -> Option<String> {
    let task = tasks.iter().find(|t| t.failure.is_some())?;
    // One failure per record, joined, each with the provider's whole answer: the first
    // says it, and a notification line stays readable.
    let all = task.failure.as_deref()?;
    let first = all.split("; ").next().unwrap_or(all);
    let mut why: String = first.chars().take(300).collect();
    if why.len() < first.len() {
        why.push('…');
    }
    Some(match task.state.as_str() {
        "Failed" => format!("Stalwart's publishing failed: {why}"),
        _ => format!("Stalwart retries its publishing: {why}"),
    })
}

/// What each judged record must hold: Stalwart's line, the relay's term added to the
/// domain's SPF — not to the one for Stalwart's own name, which only ever greets the
/// relay.
fn expected(
    domain: &str,
    needed: Vec<(Purpose, mail_dns::ZoneRecord)>,
    relay_spf: Option<&str>,
) -> Vec<(Purpose, mail_dns::ZoneRecord)> {
    needed
        .into_iter()
        .map(|(purpose, r)| match (purpose, relay_spf) {
            (Purpose::Spf, Some(term)) if r.name == domain => (purpose, with_spf_term(r, term)),
            _ => (purpose, r),
        })
        .collect()
}

/// An SPF record with `term` before its `all`, the line to paste written again.
fn with_spf_term(mut r: mail_dns::ZoneRecord, term: &str) -> mail_dns::ZoneRecord {
    let mut terms: Vec<&str> = r.value.split_whitespace().collect();
    if terms.iter().any(|t| t.eq_ignore_ascii_case(term)) {
        return r;
    }
    let at = terms
        .iter()
        .position(|t| {
            t.trim_start_matches(['-', '~', '?', '+'])
                .eq_ignore_ascii_case("all")
        })
        .unwrap_or(terms.len());
    terms.insert(at, term);
    let value = terms.join(" ");
    r.line = format!("{}. IN TXT \"{value}\"", r.name);
    r.value = value;
    r
}

/// Who Homelabus's DNS servers in Stalwart are: their description starts with this,
/// then the provider and a fingerprint of the credential — Stalwart reads a secret back
/// as `****`, so a credential rotated in the vault is seen by the fingerprint.
const OURS: &str = "Homelabus:";

/// Stalwart's DNS server for one of the ingress's providers, its credentials in the
/// provider's field order — or why it cannot publish DKIM.
///
/// Each shape read from Stalwart's registry schema at v0.16.26, and each kind from
/// `dns-update` 0.5.9, which speaks to the provider: Gandi and Hetzner by a Bearer
/// token — Hetzner's Cloud API, as the ingress's v2 module —, deSEC by `Token`.
pub fn stalwart_dns_server(
    provider: &str,
    values: &[String],
    generation: hlb_mail::Generation,
) -> Result<serde_json::Value, &'static str> {
    let secret = |i: usize| serde_json::json!({ "@type": "Value", "secret": values.get(i).cloned().unwrap_or_default() });
    let one = |kind: &str| serde_json::json!({ "@type": kind, "secret": secret(0) });
    Ok(match provider {
        "cloudflare" => one("Cloudflare"),
        "desec" => one("DeSEC"),
        "gandi" => one("GandiV5"),
        "hetzner" => one("Hetzner"),
        "ovh" => serde_json::json!({
            "@type": "Ovh",
            // The ingress's field is the endpoint's name, which Stalwart spells alike.
            "ovhEndpoint": values.first().cloned().unwrap_or_default(),
            "applicationKey": values.get(1).cloned().unwrap_or_default(),
            "applicationSecret": secret(2),
            "consumerKey": secret(3),
        }),
        // 1.0 renamed both (`apiKeyId`, `secret`), and refuses the old names.
        "porkbun" => {
            let (key, secret_key) = generation.porkbun_keys();
            serde_json::json!({
                "@type": "Porkbun",
                key: values.first().cloned().unwrap_or_default(),
                secret_key: secret(1),
            })
        }
        // A server of the person's own taking dynamic updates, in Caddy's field order:
        // key name, algorithm, key, `host:port`.
        "rfc2136" => {
            let server = values.get(3).map(String::as_str).unwrap_or_default();
            // Stalwart's `host` is an address: a name would be refused at creation.
            let at: std::net::SocketAddr = match server.parse() {
                Ok(a) => a,
                Err(_) => match server.parse::<std::net::IpAddr>() {
                    Ok(ip) => (ip, 53).into(),
                    Err(_) => {
                        return Err("Stalwart reaches an RFC 2136 server by its IP address, \
                                    and the exposure names it otherwise")
                    }
                },
            };
            serde_json::json!({
                "@type": "Tsig",
                "host": at.ip().to_string(),
                "port": at.port(),
                "keyName": values.first().cloned().unwrap_or_default(),
                "key": secret(2),
                "protocol": "tcp",
                "tsigAlgorithm": values.get(1).cloned().unwrap_or_default(),
            })
        }
        // 🔴 DuckDNS keeps ONE TXT a name, on the name itself: a DKIM key published
        // through it would overwrite the certificate challenge's, and a duckdns.org
        // name has no MX of its own to receive mail by anyway.
        "duckdns" => {
            return Err("DuckDNS keeps one TXT a name, which the certificate's challenge holds")
        }
        _ => return Err("Homelabus does not know how Stalwart publishes through it"),
    })
}

/// Publishes a domain's `records` through `server`, its DKIM keys rotated by Stalwart
/// from then on; `origin`, the zone the updates go to when not the domain's own.
///
/// 🔴 Switched on, Stalwart publishes and schedules the rotation in two tasks at once,
/// and the rotation rewrites each key while the publishing reads them: a key read
/// mid-rewrite is skipped without a word (0.16.26 — the RSA key, one switch in two on a
/// real RFC 2136 server; six in six on 0.16.27 and 1.0.0 switched as the domain is
/// made). So once every active key carries its next rotation, the publishing is asked
/// for again, alone.
pub async fn switch(
    mail: &hlb_mail::Stalwart,
    domain_id: &str,
    server: &str,
    records: &[String],
    origin: Option<&str>,
) -> crate::Result<()> {
    let dkim = records.iter().any(|r| r == "dkim");
    // 🔴 Switched while its first keys are being made — its `DkimManagement` task still
    // pending — 1.0 schedules no rotation, ever, and says nothing (0.16 does). Waited
    // until they are: no task left, or keys already rotated by schedule.
    for _ in 0..if dkim { 30 } else { 0 } {
        let keys = mail.dkim_keys(domain_id).await?;
        let scheduled = keys
            .iter()
            .filter(|k| k.stage == "active")
            .all(|k| k.next_transition.is_some());
        if !keys.is_empty() && (scheduled || mail.dkim_tasks(domain_id).await?.is_empty()) {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    mail.publish_through(domain_id, server, records, origin)
        .await?;
    if !dkim {
        return Ok(());
    }
    for _ in 0..30 {
        let keys = mail.dkim_keys(domain_id).await?;
        if keys
            .iter()
            .filter(|k| k.stage == "active")
            .all(|k| k.next_transition.is_some())
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    mail.publish_again(domain_id, &["dkim".to_string()]).await?;
    Ok(())
}

/// The DNS server Stalwart publishes through, as Homelabus wants it.
struct Through {
    /// How it is named in what changed: the provider, or the house's zone.
    label: String,
    body: serde_json::Value,
    /// `Homelabus: <provider> <fingerprint>`.
    description: String,
    /// The domains it publishes, each with the zone its updates go to — `None`: every
    /// domain under the exposure, each at its own zone.
    origins: Option<Vec<(String, String)>>,
}

/// Stalwart's server for the house's zone: Knot's update port, signed with the update key.
fn zone_server(knot: std::net::IpAddr, key: &hlb_ingress::zone::UpdateKey) -> serde_json::Value {
    use hlb_ingress::zone;
    serde_json::json!({
        "@type": "Tsig",
        "host": knot.to_string(),
        "port": zone::PORT,
        "keyName": zone::UPDATE_KEY_ID,
        "key": { "@type": "Value", "secret": key.0 },
        // 🔴 Over UDP the RSA key's signed update, past 512 bytes, never reached the
        // server and the task counted as done (0.16.26).
        "protocol": "tcp",
        "tsigAlgorithm": zone::UPDATE_ALGORITHM,
    })
}

/// Where Stalwart publishes, or `None` where the records are a person's to publish.
///
/// 🔴 Once the registrar delegates to the house's zone, the exposure's provider no longer
/// serves the domain: the keys go into the zone's `_domainkey.<domain>` children, signed
/// with the update key — the only names that key may write. A domain whose child the
/// zone does not render (outside the apex, or under the owner's own lines) is not
/// Stalwart's to publish.
async fn through(
    state: &hlb_state::State,
    vault: &hlb_secrets::Vault,
    mail: &hlb_mail::Stalwart,
    knot: Option<std::net::IpAddr>,
    exposure: &hlb_state::Exposure,
) -> crate::Result<Option<Through>> {
    if let Some(delegation) = crate::zone::delegation(state, Some(vault)).await? {
        match mail.generation().await? {
            hlb_mail::Generation::V1 => {}
            hlb_mail::Generation::V016 => {
                return Err(hlb_mail::Error::NeedsV1(
                    "publishing DKIM into the house's delegated zone".into(),
                )
                .into())
            }
        }
        let knot = knot.ok_or_else(|| {
            crate::Error::Exposure(
                "the zone is delegated and Knot is not running: Stalwart has nowhere to \
                 publish its DKIM keys — hlb install knot --apply"
                    .into(),
            )
        })?;
        let Some(config) = state.zone().await? else {
            return Ok(None);
        };
        let wanted = crate::zone::wanted(state, &config, Some(vault)).await?;
        let origins = hlb_ingress::zone::render(&wanted)
            .children
            .into_iter()
            .filter(|c| c.kind == hlb_ingress::zone::ChildKind::Dkim)
            .filter_map(|c| {
                let domain = c.name.strip_prefix("_domainkey.")?.to_string();
                Some((domain, c.name))
            })
            .collect();
        let print =
            &hlb_types::token::sha256_hex(format!("{knot}\n{}", delegation.key.0).as_bytes())[..12];
        return Ok(Some(Through {
            label: "the house's zone".into(),
            body: zone_server(knot, &delegation.key),
            description: format!("{OURS} zone {print}"),
            origins: Some(origins),
        }));
    }
    let Some(name) = exposure.dns_provider.as_deref() else {
        return Ok(None);
    };
    let Some(provider) = hlb_ingress::dns::provider(name) else {
        return Ok(None);
    };
    let values = crate::ingress::dns_credentials(state, Some(vault), provider).await?;
    let body = match stalwart_dns_server(name, &values, mail.generation().await?) {
        Ok(b) => b,
        Err(why) => {
            tracing::info!(provider = name, "DKIM is published by hand: {why}");
            return Ok(None);
        }
    };
    let print = &hlb_types::token::sha256_hex(values.join("\n").as_bytes())[..12];
    Ok(Some(Through {
        label: name.to_string(),
        body,
        description: format!("{OURS} {name} {print}"),
        origins: None,
    }))
}

/// Stalwart publishes and rotates the DKIM keys of the mail domains through the DNS
/// provider the exposure uses — the credential `hlb config exposure` already keeps — or,
/// once the registrar delegates to it, into the house's own zone, on Knot at `knot`.
/// `Ok(what changed)` — or, `apply` false, what would; nothing without either, where
/// the records are a person's to publish (`hlb mail dns`).
///
/// DKIM only: the selectors are Stalwart's own names, so publishing them overwrites
/// nothing. MX, SPF and DMARC are the domain's — another provider may hold its mail or
/// its web — and stay printed.
///
/// 🔴 A publishing task that failed is not retried by Stalwart 0.16: a key the last
/// reading found missing, on a domain published through Homelabus, is asked for again
/// here — unless a task is still pending, which on 1.0 includes one Stalwart retries
/// itself (`Retry`, `Stalled`).
pub async fn publish_dkim(
    state: &hlb_state::State,
    vault: &hlb_secrets::Vault,
    mail: &hlb_mail::Stalwart,
    knot: Option<std::net::IpAddr>,
    apply: bool,
) -> crate::Result<Vec<String>> {
    let Some(exposure) = state.exposure().await? else {
        return Ok(Vec::new());
    };
    let Some(Through {
        label,
        body,
        description,
        origins,
    }) = through(state, vault, mail, knot, &exposure).await?
    else {
        return Ok(Vec::new());
    };
    let kind = body
        .get("@type")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let mut changed = Vec::new();
    let servers = mail.dns_servers().await?;
    let ours = servers.iter().find(|s| s.description.starts_with(OURS));
    let domains = mail.domains_dns().await?;
    let server_id = match ours {
        Some(s) if s.kind == kind && s.description == description => Some(s.id.clone()),
        Some(s) if s.kind == kind => {
            changed.push(if origins.is_some() {
                format!("DKIM published into {label} with the address and key it has now")
            } else {
                format!("DKIM published with the {label} credential the vault holds now")
            });
            if apply {
                let mut b = body.clone();
                b["description"] = description.clone().into();
                mail.update_dns_server(&s.id, b).await?;
            }
            Some(s.id.clone())
        }
        // Another provider: the domains it publishes go back to manual first — a server
        // a domain names cannot be removed.
        Some(s) => {
            changed.push(format!(
                "DKIM published through {label}, no longer {}",
                s.kind
            ));
            if apply {
                for d in domains.iter().filter(|d| {
                    d.published_by
                        .as_ref()
                        .is_some_and(|(server, _)| *server == s.id)
                }) {
                    mail.set_manual_dns(&d.id).await?;
                }
                mail.destroy_dns_server(&s.id).await?;
            }
            None
        }
        None => None,
    };
    let server_id = match server_id {
        Some(id) => Some(id),
        None => {
            if ours.is_none() {
                changed.push(format!("DKIM published through {label}"));
            }
            if apply {
                let mut b = body;
                b["description"] = description.into();
                Some(mail.create_dns_server(b).await?)
            } else {
                None
            }
        }
    };

    let last = state.mail_records().await?;
    let ours_now = server_id.as_deref();
    let ours_before = ours.map(|o| o.id.as_str());
    // Read again once the server changed: a domain the step above set back to manual
    // must not be taken for one the new server already publishes.
    let domains = if apply {
        mail.domains_dns().await?
    } else {
        domains
    };
    for d in &domains {
        let by = d.published_by.as_ref();
        let by_us = by
            .is_some_and(|(s, _)| Some(s.as_str()) == ours_now || Some(s.as_str()) == ours_before);
        // Someone set this domain up through a server of their own: theirs.
        if by.is_some() && !by_us {
            continue;
        }
        let origin = match &origins {
            None if d.name == exposure.domain
                || d.name.ends_with(&format!(".{}", exposure.domain)) =>
            {
                None
            }
            None => continue,
            Some(o) => match o.iter().find(|(domain, _)| *domain == d.name) {
                Some((_, zone)) => Some(zone.as_str()),
                // 🔴 Published by us with no child of its own to go to: every update
                // would be refused. Back to the records the house's zone holds.
                None if by_us => {
                    changed.push(format!(
                        "{}: DKIM no longer published by Stalwart — the house's zone \
                         delegates no _domainkey below it",
                        d.name
                    ));
                    if apply {
                        mail.set_manual_dns(&d.id).await?;
                    }
                    continue;
                }
                None => continue,
            },
        };
        let publishes_dkim = by.is_some_and(|(s, records)| {
            Some(s.as_str()) == ours_now && records.iter().any(|r| r == "dkim")
        }) && d.origin.as_deref() == origin;
        if !publishes_dkim {
            changed.push(match origin {
                Some(zone) => format!(
                    "{}: DKIM published into {zone} and rotated by Stalwart",
                    d.name
                ),
                None => format!("{}: DKIM published and rotated by Stalwart", d.name),
            });
            if let (true, Some(server)) = (apply, ours_now) {
                // Below `_domainkey.` the key may write DKIM alone: whatever else the
                // domain published goes back to the person.
                let records: Vec<String> = if origin.is_some() {
                    vec!["dkim".into()]
                } else {
                    let mut r: Vec<String> = by.map(|(_, r)| r.clone()).unwrap_or_default();
                    r.push("dkim".into());
                    r.sort();
                    r.dedup();
                    r
                };
                switch(mail, &d.id, server, &records, origin).await?;
            }
            continue;
        }
        let missing = last.iter().any(|r| {
            r.domain == d.name
                && r.purpose == hlb_api::mail_dns::Purpose::Dkim
                && matches!(
                    r.state,
                    hlb_api::mail_dns::RecordState::Missing
                        | hlb_api::mail_dns::RecordState::Differs
                )
        });
        let pending = mail
            .dns_tasks(&d.id)
            .await?
            .iter()
            .any(|t| t.state != "Failed");
        if missing && !pending {
            changed.push(format!("{}: its DKIM keys published again", d.name));
            if apply {
                mail.publish_again(&d.id, &["dkim".to_string()]).await?;
            }
        }
    }
    Ok(changed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_zone_carries_what_is_judged_as_it_must_read_and_what_is_offered() {
        let zone =
            "v1-ed25519-20261019._domainkey.example.org. IN TXT \"v=DKIM1; k=ed25519; p=AB\"\n\
                    mail.example.org. IN TXT \"v=spf1 a -all\"\n\
                    example.org. IN TXT \"v=spf1 mx -all\"\n\
                    example.org. IN MX 10 mail.example.org.\n\
                    _imaps._tcp.example.org. IN SRV 0 1 993 mail.example.org.\n\
                    _pop3s._tcp.example.org. IN SRV 0 1 995 mail.example.org.\n\
                    mta-sts.example.org. IN CNAME mail.example.org.\n";
        let lines = lines_of("example.org", zone, Some("include:relay.example"), &[993]);
        assert_eq!(
            lines,
            [
                "v1-ed25519-20261019._domainkey.example.org. IN TXT \"v=DKIM1; k=ed25519; p=AB\"",
                "mail.example.org. IN TXT \"v=spf1 a -all\"",
                "example.org. IN TXT \"v=spf1 mx include:relay.example -all\"",
                "example.org. IN MX 10 mail.example.org.",
                "_imaps._tcp.example.org. IN SRV 0 1 993 mail.example.org.",
            ]
        );
    }

    #[test]
    fn a_key_missing_says_why_stalwart_did_not_publish_it() {
        let task = |state: &str, failure: Option<&str>| hlb_mail::DnsTask {
            id: state.into(),
            state: state.into(),
            created_at: String::new(),
            failure: failure.map(str::to_string),
        };
        assert_eq!(publishing_failure(&[]), None);
        assert_eq!(publishing_failure(&[task("Pending", None)]), None);
        assert_eq!(
            publishing_failure(&[task("Failed", Some("401 invalid token"))]).as_deref(),
            Some("Stalwart's publishing failed: 401 invalid token"),
            "0.16"
        );
        assert_eq!(
            publishing_failure(&[
                task("Pending", None),
                task("Stalled", Some("401 invalid token"))
            ])
            .as_deref(),
            Some("Stalwart retries its publishing: 401 invalid token"),
            "1.0: the latest task that says"
        );
        let long = format!("{}; the next key, refused alike", "x".repeat(400));
        let said = publishing_failure(&[task("Retry", Some(&long))]).expect("said");
        assert!(said.ends_with('…') && !said.contains("next key"), "{said}");
    }

    #[test]
    fn a_relays_term_goes_before_all_once() {
        let spf = mail_dns::ZoneRecord {
            name: "example.org".into(),
            kind: "TXT".into(),
            value: "v=spf1 mx -all".into(),
            line: "example.org. IN TXT \"v=spf1 mx -all\"".into(),
        };
        let with = with_spf_term(spf.clone(), "include:spf.relay.net");
        assert_eq!(with.value, "v=spf1 mx include:spf.relay.net -all");
        assert_eq!(
            with.line,
            "example.org. IN TXT \"v=spf1 mx include:spf.relay.net -all\""
        );
        assert_eq!(with_spf_term(with.clone(), "INCLUDE:spf.relay.net"), with);
    }

    #[tokio::test]
    async fn the_ports_offered_are_the_manifests_and_its_routes() {
        let state = hlb_state::State::in_memory().await.expect("state");
        assert!(served_ports(&state).await.expect("read").is_empty());
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../catalog/_platform/stalwart/manifest.yaml"
        );
        let m: hlb_types::Manifest =
            serde_yaml_ng::from_str(&std::fs::read_to_string(path).expect("manifest"))
                .expect("parsed");
        state
            .upsert_app("stalwart", &m, None)
            .await
            .expect("installed");
        let published: Vec<u16> = m
            .spec
            .security
            .published_ports
            .iter()
            .map(|p| p.port)
            .collect();
        assert!(published.contains(&25), "{published:?}");
        assert_eq!(served_ports(&state).await.expect("read"), published);
        state
            .upsert_app("stalwart", &m, Some("mail.example.org"))
            .await
            .expect("routed");
        let mut routed = published;
        routed.push(443);
        assert_eq!(served_ports(&state).await.expect("read"), routed);
    }

    #[test]
    fn the_relays_term_is_asked_of_the_domain_not_of_stalwarts_name() {
        let zone = mail_dns::parse_zone(
            "mail.example.org. IN TXT \"v=spf1 a -all\"\n\
             example.org. IN TXT \"v=spf1 mx -all\"\n",
        );
        let needed = mail_dns::needed("example.org", &zone);
        let got: Vec<(String, String)> =
            expected("example.org", needed, Some("include:spf.relay.net"))
                .into_iter()
                .map(|(_, r)| (r.name, r.value))
                .collect();
        assert_eq!(
            got,
            [
                ("mail.example.org".into(), "v=spf1 a -all".into()),
                (
                    "example.org".into(),
                    "v=spf1 mx include:spf.relay.net -all".into()
                ),
            ]
        );
    }

    #[test]
    fn every_provider_the_ingress_offers_publishes_dkim_or_says_why_not() {
        for (p, g) in hlb_ingress::dns::PROVIDERS.iter().flat_map(|p| {
            [
                (p, hlb_mail::Generation::V016),
                (p, hlb_mail::Generation::V1),
            ]
        }) {
            // An RFC 2136 server is reached by address, which Stalwart takes apart.
            let values: Vec<String> = p
                .fields
                .iter()
                .map(|f| match (p.name, f.name) {
                    ("rfc2136", "server") => "192.0.2.53:5353".into(),
                    _ => format!("v-{}-v", f.name),
                })
                .collect();
            match stalwart_dns_server(p.name, &values, g) {
                Ok(body) => {
                    assert!(body.get("@type").is_some(), "{}: {body}", p.name);
                    // Every credential reaches Stalwart, none twice and none lost.
                    let text = body.to_string();
                    if p.name == "rfc2136" {
                        assert_eq!(
                            (body["host"].as_str(), body["port"].as_u64()),
                            (Some("192.0.2.53"), Some(5353))
                        );
                    }
                    for v in values.iter().filter(|v| v.starts_with("v-")) {
                        assert_eq!(
                            text.matches(v.as_str()).count(),
                            1,
                            "{}: {v} in {text}",
                            p.name
                        );
                    }
                }
                Err(why) => assert_eq!(p.name, "duckdns", "{}: {why}", p.name),
            }
        }
    }
}
