//! The house's domain, read from the internet — the same pass for `hlb domain` and the
//! daemon's night. What is compared and advised is `hlb_api::domain`'s.

use async_trait::async_trait;
use hlb_api::domain::{DnsSide, Reading, Registry};

/// IANA's list of the RDAP server of each TLD.
pub const RDAP_BOOTSTRAP: &str = "https://data.iana.org/rdap/dns.json";

/// Where a reading comes from. A trait so a reading is tried without the internet.
#[async_trait]
pub trait Internet: Send + Sync {
    /// Every `kind` record at `name`, and whether the resolver validated them.
    async fn query(&self, name: &str, kind: &str) -> Result<(Vec<String>, bool), String>;
    /// A JSON document; `Ok(None)` for a 404, which RDAP answers for a name it does not
    /// hold.
    async fn json(&self, url: &str) -> Result<Option<serde_json::Value>, String>;
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
            };
        }
    };
    Reading {
        dns: dns_side(net, &zone).await,
        registry: registry(net, &zone).await,
        zone,
        read_at: now,
    }
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
        return not_read(format!(
            "no RDAP for .{tld}: its registry publishes none, and its WHOIS is not read"
        ));
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
        assert_eq!(reg.statuses, ["client transfer prohibited"]);
        assert_eq!(reg.expires, Some(1_893_456_000));
    }

    #[tokio::test]
    async fn a_tld_without_rdap_is_said_not_read_and_its_dns_still_is() {
        let net = Table::default()
            .record("home.eu", "NS", &["ns1.example."], false)
            .page(RDAP_BOOTSTRAP, bootstrap());
        let r = read(&net, "home.eu", 0).await;
        assert!(r.dns.is_ok());
        let Registry::NotRead { why } = r.registry else {
            panic!("read a registry that has no RDAP")
        };
        assert!(why.contains("no RDAP for .eu"), "{why}");
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
}
