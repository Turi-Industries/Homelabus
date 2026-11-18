//! The house's domain, read every night and compared with the baseline `hlb domain
//! accept` recorded.

use hlb_api::domain::{Account, Drift, Issuance, Unmet};
use hlb_state::{Certificates, State};

/// What a night's reading found.
#[derive(Debug, Default)]
pub struct Found {
    /// What moved since the baseline; nothing before one was accepted.
    pub drifts: Vec<Drift>,
    /// The house's ACME accounts the CAA refuses, baseline or not: their
    /// certificates stop renewing.
    pub refused: Vec<Account>,
    /// Certificates for the house's names under a key it does not hold, found this
    /// night or before and not accepted since.
    pub foreign: Vec<Issuance>,
    /// The CAA pins the house's zone carries moved: it is published again.
    pub pins_moved: bool,
    /// Where the parent is not what the house's delegated zone needs, baseline or not.
    pub unmet: Vec<Unmet>,
}

/// Reads the exposure's domain and records the reading. Nothing without an exposure
/// or under the house's own root: there is nothing public to watch.
pub async fn read_and_record(
    state: &State,
    net: &dyn hlb_engine::domain::Internet,
    orch: Option<&dyn hlb_orchestrator::Orchestrator>,
    mail: Option<&hlb_mail::Stalwart>,
    now: i64,
) -> Result<Found, String> {
    let Some(exposure) = state.exposure().await.map_err(|e| e.to_string())? else {
        return Ok(Found::default());
    };
    if exposure.certificates == Certificates::Internal {
        return Ok(Found::default());
    }
    let mut reading = hlb_engine::domain::read(net, &exposure.domain, now).await;
    let (accounts, unread) = hlb_engine::domain::accounts(state, orch, mail).await;
    for u in &unread {
        tracing::warn!("{u}");
    }
    let pins_moved = hlb_engine::zone::keep_pins(state, &accounts, &unread)
        .await
        .map_err(|e| e.to_string())?;
    reading.accounts = accounts;
    state
        .record_domain_reading(&reading)
        .await
        .map_err(|e| e.to_string())?;
    let refused = hlb_api::domain::refused(&reading)
        .into_iter()
        .cloned()
        .collect();
    let unmet = match (
        hlb_engine::zone::delegation_needed(state)
            .await
            .map_err(|e| e.to_string())?,
        &reading.dns,
    ) {
        (Some(needs), Ok(dns)) => hlb_api::domain::unmet(&needs, dns),
        _ => Vec::new(),
    };
    let baseline = state.domain_baseline().await.map_err(|e| e.to_string())?;
    let drifts = match baseline.filter(|b| b.zone == reading.zone) {
        Some(b) => hlb_api::domain::drifts(&b, &reading),
        None => {
            tracing::info!(
                zone = %reading.zone,
                "the domain is not watched: `hlb domain accept --apply` sets its baseline"
            );
            Vec::new()
        }
    };
    // Apart from the drifts: a watch that cannot be read must not silence them.
    let foreign = watch_logs(state, net, orch, mail, &exposure.domain)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!("the certificates issued were not judged: {e}");
            Vec::new()
        });
    Ok(Found {
        drifts,
        refused,
        foreign,
        pins_moved,
        unmet,
    })
}

/// Judges what the logs hold since the last night, and keeps what was foreign until
/// `hlb domain accept` takes it.
async fn watch_logs(
    state: &State,
    net: &dyn hlb_engine::domain::Internet,
    orch: Option<&dyn hlb_orchestrator::Orchestrator>,
    mail: Option<&hlb_mail::Stalwart>,
    domain: &str,
) -> Result<Vec<Issuance>, String> {
    let mut watch = state
        .domain_transparency()
        .await
        .map_err(|e| e.to_string())?;
    let Some(after) = watch.after.clone() else {
        tracing::info!(
            "the certificates are not watched: `hlb domain accept --apply` takes those \
             already issued as the baseline"
        );
        return Ok(Vec::new());
    };
    match hlb_engine::domain::transparency(state, net, orch, mail, domain, Some(&after)).await {
        Ok((found, judged)) => {
            for i in &judged.elsewhere {
                tracing::info!(
                    "a certificate for names the house does not serve: {}",
                    hlb_api::domain::issuance_line(i)
                );
            }
            watch.advance(&found, judged.foreign);
            state
                .set_domain_transparency(&watch)
                .await
                .map_err(|e| e.to_string())?;
        }
        // Not read is not judged: the cursor stays, the next night reads from it.
        Err(e) => tracing::warn!("the certificates issued were not judged: {e}"),
    }
    Ok(watch.foreign)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use async_trait::async_trait;
    use hlb_api::domain::Moved;
    use hlb_state::{State, ZoneConfig};

    use super::read_and_record;

    /// The DNS only: every registry is unreachable, which compares nothing.
    struct Dns(HashMap<(&'static str, &'static str), Vec<String>>);

    #[async_trait]
    impl hlb_engine::domain::Internet for Dns {
        async fn query(&self, name: &str, kind: &str) -> Result<(Vec<String>, bool), String> {
            let found = self
                .0
                .iter()
                .find(|((n, k), _)| *n == name && *k == kind)
                .map(|(_, v)| v.clone())
                .unwrap_or_default();
            Ok((found, true))
        }
        async fn json(&self, _: &str) -> Result<Option<serde_json::Value>, String> {
            Err("offline".into())
        }
        async fn whois(&self, _: &str, _: &str) -> Result<String, String> {
            Err("offline".into())
        }
    }

    async fn house(delegated: bool) -> State {
        let s = State::in_memory().await.expect("state");
        s.set_exposure(&hlb_state::Exposure {
            domain: "home.example.org".into(),
            certificates: hlb_state::Certificates::Acme,
            acme_email: Some("me@example.org".into()),
            dns_provider: None,
            staging: false,
            controller_host: None,
            acme_ca: None,
            acme_ca_root: None,
        })
        .await
        .expect("exposure");
        s.set_zone(&ZoneConfig {
            apex: "example.org".into(),
            addresses: vec!["203.0.113.4".into()],
            extra: String::new(),
            delegated,
        })
        .await
        .expect("zone");
        s.keep_zone_parent(&["4242 13 2 ABCD".into()], &["257 3 13 key".into()])
            .await
            .expect("parent");
        s
    }

    fn internet(ns: &[&str], ds: &[&str]) -> Dns {
        let v = |s: &[&str]| s.iter().map(|x| x.to_string()).collect();
        Dns(HashMap::from([
            (("example.org", "NS"), v(ns)),
            (("example.org", "DS"), v(ds)),
        ]))
    }

    #[tokio::test]
    async fn a_delegated_zone_the_registrar_still_points_elsewhere_is_said() {
        let s = house(true).await;
        let net = internet(&["ns1.provider.example"], &[]);
        let found = read_and_record(&s, &net, None, None, 0)
            .await
            .expect("read");
        let what: Vec<Moved> = found.unmet.iter().map(|u| u.what).collect();
        assert_eq!(what, [Moved::Ns, Moved::Ds]);
        // Before the switch the provider's zone is the one asked, rightly.
        let s = house(false).await;
        let found = read_and_record(&s, &net, None, None, 0)
            .await
            .expect("read");
        assert!(found.unmet.is_empty(), "{:?}", found.unmet);
    }

    #[tokio::test]
    async fn a_registrar_holding_the_zones_servers_and_ds_meets_it() {
        let s = house(true).await;
        let net = internet(
            &["ns1.example.org.", "ns2.example.org."],
            &["4242 13 2 abcd"],
        );
        let found = read_and_record(&s, &net, None, None, 0)
            .await
            .expect("read");
        assert!(found.unmet.is_empty(), "{:?}", found.unmet);
    }
}
