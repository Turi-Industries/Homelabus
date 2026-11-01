//! The house's domain, read from the internet — the same pass for `hlb domain` and the
//! daemon's night. What is compared and advised is `hlb_api::domain`'s.

use async_trait::async_trait;
use hlb_api::domain::{Account, DnsSide, Governing, Issuance, Reading, Registry, Whois};
use hlb_state::{Certificates, State};

/// IANA's list of the RDAP server of each TLD.
pub const RDAP_BOOTSTRAP: &str = "https://data.iana.org/rdap/dns.json";

/// IANA's WHOIS: asked a TLD, it names the registry's WHOIS host.
pub const IANA_WHOIS: &str = "whois.iana.org";

/// Where a reading comes from. A trait so a reading is tried without the internet.
#[async_trait]
pub trait Internet: Send + Sync {
    /// Every `kind` record at `name`, and whether the resolver validated them.
    async fn query(&self, name: &str, kind: &str) -> Result<(Vec<String>, bool), String>;
    /// A JSON document; `Ok(None)` for a 404, which RDAP answers for a name it does not
    /// hold.
    async fn json(&self, url: &str) -> Result<Option<serde_json::Value>, String>;
    /// One WHOIS question (RFC 3912) to `server`'s port 43: the answer as written.
    async fn whois(&self, server: &str, query: &str) -> Result<String, String>;
}

/// The public resolvers `hlb mail dns` asks, and HTTPS.
pub struct Public {
    dns: hlb_mail::public_dns::PublicDns,
    http: reqwest::Client,
}

impl Default for Public {
    fn default() -> Self {
        Self {
            dns: hlb_mail::public_dns::PublicDns::default(),
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(20))
                .build()
                .unwrap_or_default(),
        }
    }
}

#[async_trait]
impl Internet for Public {
    async fn query(&self, name: &str, kind: &str) -> Result<(Vec<String>, bool), String> {
        self.dns.query(name, kind).await
    }

    async fn json(&self, url: &str) -> Result<Option<serde_json::Value>, String> {
        let resp = self
            .http
            .get(url)
            // RDAP's own type; most servers answer `application/json` to it too.
            .header("accept", "application/rdap+json, application/json")
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let mut resp = resp.error_for_status().map_err(|e| e.to_string())?;
        // IANA's bootstrap is ~40 KB, an RDAP answer a few: four megabytes is neither.
        const MAX: usize = 4 * 1024 * 1024;
        let mut body = Vec::new();
        while let Some(chunk) = resp.chunk().await.map_err(|e| e.to_string())? {
            if body.len() + chunk.len() > MAX {
                return Err(format!("an answer larger than {MAX} bytes, not read"));
            }
            body.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&body)
            .map(Some)
            .map_err(|e| e.to_string())
    }

    async fn whois(&self, server: &str, query: &str) -> Result<String, String> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        // A record is a few kilobytes; whatever runs past this is not one.
        const MAX: u64 = 1024 * 1024;
        let ask = async {
            let mut s = tokio::net::TcpStream::connect((server, 43))
                .await
                .map_err(|e| e.to_string())?;
            s.write_all(format!("{query}\r\n").as_bytes())
                .await
                .map_err(|e| e.to_string())?;
            let mut body = Vec::new();
            s.take(MAX + 1)
                .read_to_end(&mut body)
                .await
                .map_err(|e| e.to_string())?;
            if body.len() as u64 > MAX {
                return Err(format!("an answer larger than {MAX} bytes, not read"));
            }
            Ok(String::from_utf8_lossy(&body).into_owned())
        };
        // The server ends its answer by closing: one that never does is no answer.
        tokio::time::timeout(std::time::Duration::from_secs(20), ask)
            .await
            .map_err(|_| "no answer within 20 s".to_string())?
    }
}

/// The zone holding `domain`: the first name holding NS, walking up. The TLD is never
/// the answer — it holds NS too, and is nobody's zone to watch.
pub async fn zone_of(net: &dyn Internet, domain: &str) -> Result<String, String> {
    let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    let labels: Vec<&str> = domain.split('.').collect();
    for start in 0..labels.len().saturating_sub(1) {
        let name = labels[start..].join(".");
        let (ns, _) = net.query(&name, "NS").await?;
        if !ns.is_empty() {
            return Ok(name);
        }
    }
    Err(format!("no name from {domain} up holds NS records"))
}

/// One reading of the zone holding `domain`.
pub async fn read(net: &dyn Internet, domain: &str, now: i64) -> Reading {
    let zone = match zone_of(net, domain).await {
        Ok(z) => z,
        Err(e) => {
            return Reading {
                zone: domain.trim_end_matches('.').to_ascii_lowercase(),
                read_at: now,
                dns: Err(e.clone()),
                registry: Registry::NotRead { why: e },
                caa_governing: None,
                accounts: Vec::new(),
            };
        }
    };
    Reading {
        dns: dns_side(net, &zone).await,
        registry: registry(net, &zone).await,
        caa_governing: governing(net, domain, &zone).await.ok(),
        zone,
        read_at: now,
        accounts: Vec::new(),
    }
}

/// The CAA set an authority checks for the exposure's names: the first non-empty one
/// climbing from its domain up to the zone. Above the zone is another owner's.
async fn governing(net: &dyn Internet, domain: &str, zone: &str) -> Result<Governing, String> {
    let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    let mut name = domain.as_str();
    loop {
        let (records, _) = net.query(name, "CAA").await?;
        if !records.is_empty() {
            return Ok(Governing {
                at: Some(name.to_string()),
                records,
            });
        }
        if name == zone {
            return Ok(Governing {
                at: None,
                records: Vec::new(),
            });
        }
        match name.split_once('.') {
            Some((_, parent)) => name = parent,
            None => return Err(format!("{domain} is not under {zone}")),
        }
    }
}

/// Let's Encrypt's CAA domain.
const LETS_ENCRYPT_CAA: &str = "letsencrypt.org";

/// The house's ACME accounts at Let's Encrypt's production, and why one was not
/// read. None under staging or a private directory: their accounts pin nothing a
/// public authority checks. Caddy's is read from its storage in its container,
/// Stalwart's over JMAP.
pub async fn accounts(
    state: &State,
    orch: Option<&dyn hlb_orchestrator::Orchestrator>,
    mail: Option<&hlb_mail::Stalwart>,
) -> (Vec<Account>, Vec<String>) {
    let (mut found, mut unread) = (Vec::new(), Vec::new());
    let exposure = match state.exposure().await {
        Ok(Some(e)) => e,
        Ok(None) => return (found, unread),
        Err(e) => return (found, vec![format!("the exposure not read: {e}")]),
    };
    if exposure.certificates == Certificates::Internal
        || exposure.acme_ca.is_some()
        || exposure.staging
    {
        return (found, unread);
    }
    let directory = crate::mail_tls::LETS_ENCRYPT;
    match (orch, exposure.acme_email.as_deref()) {
        (Some(orch), Some(email)) => {
            let path = caddy_account_path(directory, email);
            match orch
                .exec_in_service(
                    hlb_types::manifest::INGRESS_SERVICE,
                    &["cat".to_string(), path.clone()],
                )
                .await
            {
                Ok(out) if out.ok() => match account_location(&out.stdout) {
                    Some(uri) => found.push(Account {
                        who: "Caddy".into(),
                        issuer: LETS_ENCRYPT_CAA.into(),
                        uri,
                        // Its wildcard is requested over DNS-01, through the provider.
                        wildcard: exposure.dns_provider.is_some(),
                    }),
                    None => unread.push(format!("Caddy's account: {path} names no location")),
                },
                Ok(out) => unread.push(format!(
                    "Caddy's account: {path} not read ({}) — no certificate requested yet?",
                    out.stderr.trim()
                )),
                Err(e) => unread.push(format!("Caddy's account not read: {e}")),
            }
        }
        (None, _) => unread.push("Caddy's account not read: no orchestrator".into()),
        (_, None) => unread.push("Caddy's account not read: no ACME address".into()),
    }
    let ours = match state.mail_acme_provider().await {
        Ok(id) => id,
        Err(e) => {
            unread.push(format!("Stalwart's account not read: {e}"));
            None
        }
    };
    match (ours, mail) {
        // Stalwart asks no authority: nothing of its to pin.
        (None, _) => {}
        (Some(_), None) => unread.push("Stalwart's account not read: no Stalwart".into()),
        (Some(id), Some(mail)) => match mail.acme_providers().await {
            Ok(providers) => match providers.into_iter().find(|p| p.id == id) {
                Some(p) if p.directory != directory => {}
                Some(p) => match p.account_uri {
                    Some(uri) => found.push(Account {
                        who: "Stalwart".into(),
                        issuer: LETS_ENCRYPT_CAA.into(),
                        uri,
                        wildcard: false,
                    }),
                    None => unread.push("Stalwart's account has no URI yet".into()),
                },
                None => unread.push(format!("Stalwart holds no ACME account {id}")),
            },
            Err(e) => unread.push(format!("Stalwart's account not read: {e}")),
        },
    }
    (found, unread)
}

/// Where Caddy keeps its account for `directory` and `email`, under the image's
/// `XDG_DATA_HOME`: certmagic 0.25's `storageKeyUserReg`.
fn caddy_account_path(directory: &str, email: &str) -> String {
    let email = email.to_lowercase();
    let local = match email.split_once('@') {
        Some(("", rest)) => rest,
        Some((l, _)) => l,
        None => email.as_str(),
    };
    format!(
        "/data/caddy/acme/{}/users/{}/{}.json",
        certmagic_safe(&issuer_key(directory)),
        certmagic_safe(&email),
        certmagic_safe(local)
    )
}

/// certmagic's `ACMEIssuer.issuerKey`: the host, and the path as one component.
fn issuer_key(directory: &str) -> String {
    let Ok(url) = reqwest::Url::parse(directory) else {
        return directory.to_string();
    };
    let mut key = url.host_str().unwrap_or_default().to_string();
    if let Some(port) = url.port() {
        key += &format!(":{port}");
    }
    let path = url.path().replace(['/', '\\'], "-");
    let path = path.trim_matches('-');
    if !path.is_empty() {
        key += "-";
        key += path;
    }
    key
}

/// certmagic's `KeyBuilder.Safe`: lower case, a few characters spelled out, then
/// anything but `[\w@.-]` dropped.
fn certmagic_safe(s: &str) -> String {
    let mut s = s.trim().to_lowercase();
    for (from, to) in [
        (" ", "_"),
        ("+", "_plus_"),
        ("*", "wildcard_"),
        (":", "-"),
        ("..", ""),
    ] {
        s = s.replace(from, to);
    }
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '@' | '.' | '-'))
        .collect()
}

/// The account's URL in Caddy's file: its `location`.
fn account_location(file: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(file)
        .ok()?
        .get("location")?
        .as_str()
        .filter(|l| !l.is_empty())
        .map(str::to_string)
}

/// Cert Spotter's view of the Certificate Transparency logs, open without a key.
pub const CERT_SPOTTER: &str = "https://api.certspotter.com/v1/issuances";

/// Pages one reading asks at most: a reader without a key has ten requests a window,
/// and what is left is read the next night, from the last issuance judged.
const PAGES: usize = 5;

/// The issuances for `domain` and its subdomains after `after`, oldest first — every
/// unexpired one when `after` is `None`.
pub async fn issuances(
    net: &dyn Internet,
    domain: &str,
    after: Option<&str>,
) -> Result<Vec<Issuance>, String> {
    let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    let mut after = after.map(str::to_string);
    let mut out = Vec::new();
    for _ in 0..PAGES {
        let mut query = vec![
            ("domain", domain.clone()),
            ("include_subdomains", "true".into()),
            ("expand", "dns_names".into()),
            ("expand", "issuer".into()),
        ];
        if let Some(a) = &after {
            query.push(("after", a.clone()));
        }
        let url =
            reqwest::Url::parse_with_params(CERT_SPOTTER, &query).map_err(|e| e.to_string())?;
        let page = match net.json(url.as_str()).await {
            Ok(Some(body)) => hlb_api::domain::parse_issuances(&body)?,
            Ok(None) => return Err(format!("{CERT_SPOTTER} answered 404")),
            Err(e) => return Err(format!("Cert Spotter not read: {e}")),
        };
        // Its `Link` names a next page even after the last: an empty one is the end.
        let Some(last) = page.last() else { break };
        after = Some(last.id.clone());
        out.extend(page);
    }
    Ok(out)
}

/// What the house holds: the keys of its certificates and the names it serves.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Held {
    pub keys: Vec<String>,
    pub names: Vec<String>,
}

/// The keys of the certificates Caddy and Stalwart hold, and the names the house
/// serves. `Err` when one that requests certificates could not be read: judged
/// without its keys, each of its own certificates would read as a stranger's.
pub async fn held(
    state: &State,
    orch: Option<&dyn hlb_orchestrator::Orchestrator>,
    mail: Option<&hlb_mail::Stalwart>,
) -> Result<Held, String> {
    let exposure = state
        .exposure()
        .await
        .map_err(|e| e.to_string())?
        .ok_or("no exposure")?;
    let mut held = Held::default();
    held.names.push(exposure.domain.clone());
    held.names.push(exposure.controller_host());
    if exposure.dns_provider.is_some() {
        held.names.push(format!("*.{}", exposure.domain));
    }
    for (app, _) in state.installed_apps().await.map_err(|e| e.to_string())? {
        if let Some(d) = state.app_domain(&app).await.map_err(|e| e.to_string())? {
            held.names.push(d);
        }
    }
    let orch = orch.ok_or("Caddy's certificates not read: no orchestrator")?;
    let out = orch
        .exec_in_service(
            hlb_types::manifest::INGRESS_SERVICE,
            &[
                "find",
                CADDY_CERTIFICATES,
                "-name",
                "*.crt",
                "-exec",
                "cat",
                "{}",
                "+",
            ]
            .map(String::from),
        )
        .await
        .map_err(|e| format!("Caddy's certificates not read: {e}"))?;
    if !out.ok() {
        return Err(format!(
            "Caddy's certificates not read ({}) — none requested yet?",
            out.stderr.trim()
        ));
    }
    held.keys.extend(key_fingerprints(&out.stdout));
    if state
        .mail_acme_provider()
        .await
        .map_err(|e| e.to_string())?
        .is_some()
    {
        let mail = mail.ok_or("Stalwart's certificates not read: no Stalwart")?;
        for c in mail
            .certificates()
            .await
            .map_err(|e| format!("Stalwart's certificates not read: {e}"))?
        {
            held.keys.extend(key_fingerprints(&c.pem));
            held.names.extend(c.names);
        }
    }
    held.keys.sort();
    held.keys.dedup();
    Ok(held)
}

/// The issuances for the exposure's names after `after`, judged against what the house
/// holds — read after the logs, so a certificate issued between the two is held by
/// then.
pub async fn transparency(
    state: &State,
    net: &dyn Internet,
    orch: Option<&dyn hlb_orchestrator::Orchestrator>,
    mail: Option<&hlb_mail::Stalwart>,
    domain: &str,
    after: Option<&str>,
) -> Result<(Vec<Issuance>, hlb_api::domain::Judged), String> {
    let found = issuances(net, domain, after).await?;
    let held = held(state, orch, mail).await?;
    let judged = hlb_api::domain::judge_issuances(&found, &held.keys, &held.names);
    Ok((found, judged))
}

/// Where Caddy keeps its certificates, one directory per authority and name.
const CADDY_CERTIFICATES: &str = "/data/caddy/certificates";

/// The SHA-256 of each certificate's key in `pem`, hex: Cert Spotter's `pubkey_sha256`.
pub fn key_fingerprints(pem: &str) -> Vec<String> {
    use sha2::{Digest, Sha256};
    rustls_pemfile::certs(&mut pem.as_bytes())
        .filter_map(|der| crate::trust::spki(der.ok()?.as_ref()))
        .map(|spki| {
            Sha256::digest(&spki)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect()
        })
        .collect()
}

async fn dns_side(net: &dyn Internet, zone: &str) -> Result<DnsSide, String> {
    // The NS answer's `AD` is the zone's own chain; a DS's is its parent's.
    let (ns, validated) = net.query(zone, "NS").await?;
    let (ds, _) = net.query(zone, "DS").await?;
    let (caa, _) = net.query(zone, "CAA").await?;
    Ok(DnsSide::new(ns, ds, validated, caa))
}

/// The registry's record of the registered name: the zone itself, or the first parent
/// the registry holds — a delegated `lab.example.org` is registered as `example.org`.
async fn registry(net: &dyn Internet, zone: &str) -> Registry {
    let not_read = |why: String| Registry::NotRead { why };
    let Some(tld) = zone.rsplit('.').next().filter(|t| *t != zone) else {
        return not_read(format!("{zone} is not a registered name"));
    };
    let bootstrap = match net.json(RDAP_BOOTSTRAP).await {
        Ok(Some(b)) => b,
        Ok(None) => return not_read(format!("{RDAP_BOOTSTRAP} answered 404")),
        Err(e) => return not_read(format!("IANA's RDAP list not read: {e}")),
    };
    let Some(base) = hlb_api::domain::rdap_base(&bootstrap, tld) else {
        return whois(net, zone, tld).await;
    };
    let base = format!("{}/", base.trim_end_matches('/'));
    let labels: Vec<&str> = zone.split('.').collect();
    for start in 0..labels.len().saturating_sub(1) {
        let name = labels[start..].join(".");
        let url = format!("{base}domain/{name}");
        match net.json(&url).await {
            Ok(Some(body)) => {
                let (mut record, expiry) = hlb_api::domain::parse_rdap(&base, &body);
                record.expires = expiry
                    .and_then(|d| chrono::DateTime::parse_from_rfc3339(&d).ok())
                    .map(|d| d.timestamp());
                return Registry::Read(record);
            }
            Ok(None) => continue,
            Err(e) => return not_read(format!("{url}: {e}")),
        }
    }
    not_read(format!("{base} holds no name of {zone}"))
}

/// The registry's WHOIS, for a TLD with no RDAP: the host IANA names, asked for the
/// zone and then each parent, as RDAP is.
async fn whois(net: &dyn Internet, zone: &str, tld: &str) -> Registry {
    let not_read = |why: String| Registry::NotRead { why };
    let server = match net.whois(IANA_WHOIS, tld).await {
        Ok(iana) => match hlb_api::domain::whois_server(&iana) {
            Some(s) => s,
            None => return not_read(format!("no RDAP for .{tld}, and IANA names no WHOIS")),
        },
        Err(e) => return not_read(format!("no RDAP for .{tld}, and {IANA_WHOIS}: {e}")),
    };
    let labels: Vec<&str> = zone.split('.').collect();
    let mut why = None;
    for start in 0..labels.len().saturating_sub(1) {
        let name = labels[start..].join(".");
        let text = match net
            .whois(&server, &hlb_api::domain::whois_query(&server, &name))
            .await
        {
            Ok(t) => t,
            Err(e) => return not_read(format!("{server}: {e}")),
        };
        match hlb_api::domain::parse_whois(&server, &text) {
            Whois::Held(mut record, expiry) => {
                record.expires = expiry
                    .and_then(|d| chrono::DateTime::parse_from_rfc3339(&d).ok())
                    .map(|d| d.timestamp());
                return Registry::Read(record);
            }
            Whois::NotHeld => {}
            // EURid answers a name below a registered one so: its parent may be held.
            Whois::Unread(first) => why = Some(format!("{server} answered: {first}")),
        }
    }
    not_read(why.unwrap_or_else(|| format!("{server} holds no name of {zone}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// The internet, as a table. A name absent answers nothing; `fails` makes every
    /// DNS question fail.
    #[derive(Default)]
    struct Table {
        dns: HashMap<(String, String), (Vec<String>, bool)>,
        http: HashMap<String, serde_json::Value>,
        whois: HashMap<(String, String), String>,
        fails: bool,
    }

    impl Table {
        fn record(mut self, name: &str, kind: &str, data: &[&str], ad: bool) -> Self {
            self.dns.insert(
                (name.into(), kind.into()),
                (data.iter().map(|d| d.to_string()).collect(), ad),
            );
            self
        }

        fn page(mut self, url: &str, body: serde_json::Value) -> Self {
            self.http.insert(url.into(), body);
            self
        }

        fn whois(mut self, server: &str, query: &str, answer: &str) -> Self {
            self.whois
                .insert((server.into(), query.into()), answer.into());
            self
        }
    }

    #[async_trait]
    impl Internet for Table {
        async fn query(&self, name: &str, kind: &str) -> Result<(Vec<String>, bool), String> {
            if self.fails {
                return Err("every resolver timed out".into());
            }
            Ok(self
                .dns
                .get(&(name.into(), kind.into()))
                .cloned()
                .unwrap_or_default())
        }

        async fn json(&self, url: &str) -> Result<Option<serde_json::Value>, String> {
            Ok(self.http.get(url).cloned())
        }

        async fn whois(&self, server: &str, query: &str) -> Result<String, String> {
            self.whois
                .get(&(server.into(), query.into()))
                .cloned()
                .ok_or_else(|| format!("connection refused by {server}"))
        }
    }

    fn bootstrap() -> serde_json::Value {
        serde_json::json!({ "services": [[["org"], ["https://rdap.example.org/rdap"]]] })
    }

    #[tokio::test]
    async fn a_subdomain_is_watched_as_its_zone_and_registered_as_its_parent() {
        let net = Table::default()
            .record("lab.home.org", "NS", &["ns1.desec.io."], true)
            .record("lab.home.org", "DS", &["1 13 2 AB"], true)
            .page(RDAP_BOOTSTRAP, bootstrap())
            .page(
                "https://rdap.example.org/rdap/domain/home.org",
                serde_json::json!({
                    "status": ["client transfer prohibited"],
                    "events": [{ "eventAction": "expiration", "eventDate": "2030-01-01T00:00:00Z" }],
                }),
            );
        let r = read(&net, "apps.lab.home.org", 0).await;
        assert_eq!(r.zone, "lab.home.org");
        let dns = r.dns.expect("read");
        assert_eq!(dns.ns, ["ns1.desec.io"]);
        assert_eq!(dns.ds, ["1 13 2 ab"]);
        assert!(dns.validated);
        let Registry::Read(reg) = r.registry else {
            panic!("the registry was not read: {:?}", r.registry)
        };
        assert_eq!(
            reg.statuses,
            Some(vec!["client transfer prohibited".to_string()])
        );
        assert_eq!(reg.expires, Some(1_893_456_000));
    }

    /// The registries' real answers, kept by `hlb-api`.
    fn kept(name: &str) -> &'static str {
        match name {
            "iana-eu" => include_str!("../../hlb-api/tests/whois/iana-eu.txt"),
            "eu" => include_str!("../../hlb-api/tests/whois/eu.txt"),
            "eu-subdomain" => include_str!("../../hlb-api/tests/whois/eu-subdomain.txt"),
            "ch" => include_str!("../../hlb-api/tests/whois/ch.txt"),
            other => panic!("no answer kept for {other}"),
        }
    }

    #[tokio::test]
    async fn a_tld_without_rdap_is_read_from_the_whois_iana_names_as_its_parent() {
        let net = Table::default()
            .record("lab.europa.eu", "NS", &["ns1.example."], false)
            .page(RDAP_BOOTSTRAP, bootstrap())
            .whois(IANA_WHOIS, "eu", kept("iana-eu"))
            .whois("whois.eu", "lab.europa.eu", kept("eu-subdomain"))
            .whois("whois.eu", "europa.eu", kept("eu"));
        let r = read(&net, "lab.europa.eu", 0).await;
        assert!(r.dns.is_ok());
        let Registry::Read(reg) = r.registry else {
            panic!("the WHOIS was not read: {:?}", r.registry)
        };
        assert_eq!(reg.source, "whois.eu");
        assert_eq!(reg.registrar.as_deref(), Some("ClearMedia NV"));
        assert_eq!(reg.statuses, None);
    }

    #[tokio::test]
    async fn a_whois_refusing_or_silent_is_said_not_read_with_its_reason() {
        let iana_ch =
            "refer:        whois.nic.ch\n\ndomain:       CH\nwhois:        whois.nic.ch\n";
        let refused = Table::default()
            .record("home.ch", "NS", &["ns1.example."], false)
            .page(RDAP_BOOTSTRAP, bootstrap())
            .whois(IANA_WHOIS, "ch", iana_ch)
            .whois("whois.nic.ch", "home.ch", kept("ch"));
        let Registry::NotRead { why } = read(&refused, "home.ch", 0).await.registry else {
            panic!("read a registry that refused")
        };
        assert!(
            why.contains("whois.nic.ch answered: Requests of this client are not permitted"),
            "{why}"
        );
        let silent = Table::default()
            .record("home.eu", "NS", &["ns1.example."], false)
            .page(RDAP_BOOTSTRAP, bootstrap());
        let Registry::NotRead { why } = read(&silent, "home.eu", 0).await.registry else {
            panic!("read a registry nobody answered for")
        };
        assert!(why.contains("no RDAP for .eu, and whois.iana.org"), "{why}");
    }

    #[tokio::test]
    async fn resolvers_down_make_a_reading_that_compares_nothing() {
        let net = Table {
            fails: true,
            ..Table::default()
        };
        let r = read(&net, "home.org", 0).await;
        assert!(r.dns.is_err());
        assert!(matches!(r.registry, Registry::NotRead { .. }));
        let baseline = read(
            &Table::default().record("home.org", "NS", &["ns1.example."], true),
            "home.org",
            0,
        )
        .await;
        assert!(hlb_api::domain::drifts(&baseline, &r).is_empty());
    }

    #[test]
    fn caddy_s_account_is_where_certmagic_keeps_it() {
        // Measured on hlb-caddy:dev against Pebble, 2026-10-30.
        assert_eq!(
            caddy_account_path("https://pebble:14000/dir", "admin@example.org"),
            "/data/caddy/acme/pebble-14000-dir/users/admin@example.org/admin.json"
        );
        assert_eq!(
            caddy_account_path(crate::mail_tls::LETS_ENCRYPT, "Me+acme@Home.example"),
            "/data/caddy/acme/acme-v02.api.letsencrypt.org-directory/users/\
             me_plus_acme@home.example/me_plus_acme.json"
        );
        assert_eq!(
            account_location(r#"{"status":"valid","location":"https://acme/acct/1"}"#).as_deref(),
            Some("https://acme/acct/1")
        );
    }

    #[tokio::test]
    async fn the_caa_governing_a_subdomain_is_the_nearest_set_up_to_the_zone() {
        let net = Table::default()
            .record("home.org", "NS", &["ns1.example."], true)
            .record("home.org", "CAA", &["0 issue \"letsencrypt.org\""], true);
        let r = read(&net, "lab.home.org", 0).await;
        assert_eq!(
            r.caa_governing,
            Some(Governing {
                at: Some("home.org".into()),
                records: vec!["0 issue \"letsencrypt.org\"".into()],
            })
        );
        let net = net.record("lab.home.org", "CAA", &["0 issue \";\""], true);
        let r = read(&net, "lab.home.org", 0).await;
        assert_eq!(
            r.caa_governing.and_then(|g| g.at).as_deref(),
            Some("lab.home.org")
        );
        let r = read(
            &Table::default().record("home.org", "NS", &["ns1.example."], true),
            "home.org",
            0,
        )
        .await;
        assert_eq!(
            r.caa_governing,
            Some(Governing {
                at: None,
                records: vec![]
            })
        );
    }

    /// desec.io's certificate as it served it on 2026-10-31: RSA, Let's Encrypt's R13.
    const DESEC_IO: &str = "\
-----BEGIN CERTIFICATE-----\n\
MIIFBzCCA++gAwIBAgISBZszSh+DlpqYwIXLQGGI3zf7MA0GCSqGSIb3DQEBCwUA\n\
MDMxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MQwwCgYDVQQD\n\
EwNZUjIwHhcNMjYxMDEyMTQzNTM2WhcNMjcwMTEwMTQzNTM1WjATMREwDwYDVQQD\n\
EwhkZXNlYy5pbzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJD4Qi84\n\
nMtwVL2D7hAOfW1LH3zSoml7sIKXj2bVzetPKBUtN/vxAbOqGJS+mCqEeztvcPSP\n\
UDtnoiY/LzIPeV9lDbw8bsRYFpoc/z9ZFbFw8Q4bVlDaLsWSrQkhE50zMQLL5xAc\n\
/njeUD8f9BkSvPa6rapfKIXfyZY/ew4sFc6dr734Ld2Ma9RCahn0LFodNLSawOYy\n\
92eEz8sFsNfWfmE9A373p2WJSCrZmJJG2n2t4QgQViEZJfl0gt1/cD8lh46BTvGb\n\
9WdTYkg1gl2eInb25iz3C7Ynvh4jhwtJogvAA03fp7krt7r+jdTIjdJ1L9g2VZIC\n\
A+5v9H8NIeya3U0CAwEAAaOCAjMwggIvMA4GA1UdDwEB/wQEAwIFoDATBgNVHSUE\n\
DDAKBggrBgEFBQcDATAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBTBilpa3xrwdSAk\n\
p4lJkVrX6bKRwDAfBgNVHSMEGDAWgBRAFS0mee0yIJ7fmnId1jIfgQyBDDAzBggr\n\
BgEFBQcBAQQnMCUwIwYIKwYBBQUHMAKGF2h0dHA6Ly95cjIuaS5sZW5jci5vcmcv\n\
MC8GA1UdEQQoMCaCCGRlc2VjLmlvggxnZXQuZGVzZWMuaW+CDHd3dy5kZXNlYy5p\n\
bzATBgNVHSAEDDAKMAgGBmeBDAECATAvBgNVHR8EKDAmMCSgIqAghh5odHRwOi8v\n\
eXIyLmMubGVuY3Iub3JnLzEyNC5jcmwwggEMBgorBgEEAdZ5AgQCBIH9BIH6APgA\n\
dgBGojlnxg22RofGbz35mZR2k6amESCEV9VV5+PQodm2RgAAAaEwv+rBAAAEAwBH\n\
MEUCIQDLY8q7isimKvF6diBm322a4KjycaFpU80mVMEV5EnhzgIgPaUELnfIyyBY\n\
f6tDbR0ElXKAX53vnfRM27vRK8PAIqcAfgAai51rjdeR0c0FSe22A1XWBrZPrTDb\n\
cf54jw/HyPvEsQAAAaEwv+/bAAgAAAUAB69QxQQDAEcwRQIhAOGtPBUwA0R44lID\n\
bYmezadj3eqVqGK7294VheW4HwunAiAIE/ixAvjdWMefCF5aR2DxU18a0SwU05xy\n\
WqqBfdsmcTANBgkqhkiG9w0BAQsFAAOCAQEATlohbwQe40SnWugBJqRj5Xa4yM1X\n\
PVjEfbqnQBy7s6wvzX5+nygxdcp/XKnN41A+1qqQ8JosaNl6x20MXo2b90QtwaYO\n\
WOsDKMtfNa6sZBKyT76bd9S/iJMB3z9NneoESiD651cIn4ocnSR5GrrVeWkfFGao\n\
9VZiej4i8YFERZsqYcyEZE9lRYSQJHDOxjL/wLZCtvZvo1xIKzEvtpRxxQPV/zaL\n\
8WEeqrtB6XzhoIfGOLY3A5ycksdisr3jRMnjK679/fM+3oj/P+rwQjoAJiwJ5uzB\n\
MBPZZDJCahB6Q40ZVtZoCfdVPcnif4cDklNhQGzIVxZ04bOJtisOneggmQ==\n\
-----END CERTIFICATE-----\n";

    /// An ECDSA P-256 certificate, as Caddy requests by default: `openssl req -x509
    /// -newkey ec`, its key thrown away.
    const P256: &str = "\
-----BEGIN CERTIFICATE-----\n\
MIIBpzCCAU6gAwIBAgIUIPghBth2VYz3tN7ELcqoxDGc7k4wCgYIKoZIzj0EAwIw\n\
GzEZMBcGA1UEAwwQbWFpbC5leGFtcGxlLm9yZzAeFw0yNjEwMzExMDIwMjZaFw0y\n\
NjExMzAxMDIwMjZaMBsxGTAXBgNVBAMMEG1haWwuZXhhbXBsZS5vcmcwWTATBgcq\n\
hkjOPQIBBggqhkjOPQMBBwNCAATUJU31HJcYFQpD/h94NbPr8TqJf31Gdc1D5iDO\n\
WS+WCXjJxZ2Mko1HIiplVXzPLMIh5fylQAGiICyrPhI7Gb2Co3AwbjAdBgNVHQ4E\n\
FgQUGRFw1T+DoK8DedikyQKxNTr3dnMwHwYDVR0jBBgwFoAUGRFw1T+DoK8Dedik\n\
yQKxNTr3dnMwDwYDVR0TAQH/BAUwAwEB/zAbBgNVHREEFDASghBtYWlsLmV4YW1w\n\
bGUub3JnMAoGCCqGSM49BAMCA0cAMEQCICGj+7EU096h3KaTnDFXuOUYOe0E9v26\n\
pLQeT5/2gKrVAiAexS7iBVbNjglbexsQY/6OsKFciWjxwfS7rH07DCmelA==\n\
-----END CERTIFICATE-----\n";

    #[test]
    fn a_key_is_fingerprinted_as_cert_spotter_does() {
        // Cert Spotter's `pubkey_sha256` for desec.io's issuance 17742810616, and
        // `openssl pkey -pubin -outform DER | sha256sum` for the other.
        assert_eq!(
            key_fingerprints(DESEC_IO),
            ["16e73877ff5b51995c9ea55daffb9ab38c8c8514c10b39688db52ff54773573a"]
        );
        assert_eq!(
            key_fingerprints(&format!("{P256}{DESEC_IO}"))[0],
            "7eaa7101afb25e35da7295cf17d82a8842782e86f6ff11e45f108f224538e1c9"
        );
        assert!(key_fingerprints("not a certificate").is_empty());
    }

    fn issuance(id: &str) -> serde_json::Value {
        serde_json::json!({
            "id": id,
            "dns_names": ["home.org"],
            "pubkey_sha256": "aa",
            "issuer": { "friendly_name": "Let's Encrypt" },
            "not_before": "2026-10-12T14:35:36Z",
        })
    }

    #[tokio::test]
    async fn issuances_are_read_page_after_page_until_one_is_empty() {
        let first = "https://api.certspotter.com/v1/issuances?domain=home.org\
                     &include_subdomains=true&expand=dns_names&expand=issuer";
        let net = Table::default()
            .page(first, serde_json::json!([issuance("1"), issuance("2")]))
            .page(
                &format!("{first}&after=2"),
                serde_json::json!([issuance("3")]),
            )
            .page(&format!("{first}&after=3"), serde_json::json!([]));
        let ids = |v: Vec<Issuance>| v.into_iter().map(|i| i.id).collect::<Vec<_>>();
        assert_eq!(
            ids(issuances(&net, "Home.org.", None).await.expect("read")),
            ["1", "2", "3"]
        );
        assert_eq!(
            ids(issuances(&net, "home.org", Some("2")).await.expect("read")),
            ["3"]
        );
        // A page missing is not the end of the list.
        let e = issuances(&net, "home.org", Some("9"))
            .await
            .expect_err("not read");
        assert!(e.contains("404"), "{e}");
    }

    async fn exposed(wildcard: bool) -> State {
        let state = State::in_memory().await.expect("state");
        state
            .set_exposure(&hlb_state::Exposure {
                domain: "home.org".into(),
                certificates: Certificates::Acme,
                acme_email: Some("me@home.org".into()),
                dns_provider: wildcard.then(|| "desec".into()),
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
    async fn the_house_holds_caddy_s_keys_and_serves_its_names_and_its_wildcard() {
        let state = exposed(true).await;
        let caddy = crate::tests::Fake::exec_answering(&format!("{P256}{DESEC_IO}"), false);
        let held = held(&state, Some(&caddy), None).await.expect("read");
        assert_eq!(held.keys.len(), 2);
        assert!(held.keys.contains(&key_fingerprints(DESEC_IO)[0]));
        assert_eq!(held.names, ["home.org", "hlb.home.org", "*.home.org"]);
        let (service, cmd) = &caddy.execs()[0];
        assert_eq!(service, hlb_types::manifest::INGRESS_SERVICE);
        assert_eq!(
            cmd[..2],
            ["find", "/data/caddy/certificates"].map(String::from)
        );
    }

    #[tokio::test]
    async fn keys_not_read_judge_nothing() {
        let state = exposed(false).await;
        let e = held(
            &state,
            Some(&crate::tests::Fake::exec_answering("", true)),
            None,
        )
        .await
        .expect_err("Caddy failed");
        assert!(e.starts_with("Caddy's certificates not read"), "{e}");
        assert!(held(&state, None, None).await.is_err());
        // Stalwart asks an authority: without it, its own certificate reads as a
        // stranger's.
        state
            .set_mail_acme_provider(Some("p1"))
            .await
            .expect("provider");
        let caddy = crate::tests::Fake::exec_answering(DESEC_IO, false);
        let e = held(&state, Some(&caddy), None)
            .await
            .expect_err("no Stalwart");
        assert!(e.contains("no Stalwart"), "{e}");
    }
}
