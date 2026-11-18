//! The house's own zone, published to its Knot: `hlb zone set`, and every publication of
//! the routes after it — a name Caddy serves is a name the zone holds.
//!
//! What is written is [`hlb_ingress::zone`]'s; here it is placed. A one-off job on
//! Knot's node, from Knot's own image, checks both files with Knot's tools, puts them in
//! the volume, reloads Knot over its socket and waits for the zone to be signed.

use std::net::IpAddr;

use hlb_ingress::zone::{self, Delegated, Transfer, TransferKey, UpdateKey, Zone};
use hlb_orchestrator::{Orchestrator, ServiceSpec};
use hlb_secrets::Vault;
use hlb_state::{State, ZoneConfig};
use hlb_types::manifest::Tmpfs;

/// The TSIG key both Knots share, in the vault. A stored name.
pub const TRANSFER_SECRET: &str = "zone-transfer-key";

/// The TSIG key Caddy and Stalwart sign their updates with, in the vault. A stored name.
pub const UPDATE_SECRET: &str = "zone-update-key";

/// The key, drawn once and kept: both ends hold it, and a new one would stop every
/// transfer until the site has it too.
pub async fn transfer_key(state: &State, vault: &Vault) -> crate::Result<TransferKey> {
    Ok(TransferKey(
        draw_once(
            state,
            vault,
            TRANSFER_SECRET,
            "the TSIG key the house's and the site's Knot share",
        )
        .await?,
    ))
}

/// The update key, drawn once and kept: Caddy's and Stalwart's configurations hold it,
/// and one drawn again would refuse their next write until both were redeployed.
pub async fn update_key(state: &State, vault: &Vault) -> crate::Result<UpdateKey> {
    Ok(UpdateKey(
        draw_once(
            state,
            vault,
            UPDATE_SECRET,
            "the TSIG key Caddy and Stalwart write into the house's zone with",
        )
        .await?,
    ))
}

async fn draw_once(
    state: &State,
    vault: &Vault,
    name: &str,
    purpose: &str,
) -> crate::Result<String> {
    let mut raw = [0u8; 32];
    hlb_secrets::fill_random(&mut raw);
    let drawn = hlb_types::token::base64_standard(&raw);
    state
        .store_secret_if_absent(name, &vault.encrypt(&drawn)?, purpose)
        .await?;
    stored(state, Some(vault), name)
        .await?
        .ok_or_else(|| crate::Error::Exposure(format!("the zone's {name} vanished")))
}

/// A key of the zone's, if drawn. 🔴 One there and no vault to read it with is an
/// error, never a zone rendered without it: that zone would take the site's access
/// away, or refuse every update Caddy and Stalwart sign.
async fn stored(state: &State, vault: Option<&Vault>, name: &str) -> crate::Result<Option<String>> {
    let Some(ct) = state.secret(name).await? else {
        return Ok(None);
    };
    let vault = vault.ok_or_else(|| {
        crate::Error::Exposure(format!(
            "the zone's {name} is in the vault, which this publication was not given: \
             the zone served is unchanged"
        ))
    })?;
    Ok(Some(vault.decrypt(&ct)?))
}

/// The one-off service that writes the zone on Knot's node.
const WRITER: &str = "hlb-zone-writer";

/// Knot's volume, as its manifest's storage names it.
const VOLUME: &str = "knot-data";

/// What a publication came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Followed {
    /// The house serves no zone of its own: `hlb zone set` was never run.
    Off,
    /// A zone is declared and Knot is not deployed: its deployment publishes it.
    NoServer,
    /// Knot serves it. `soa`: the record it answers, its serial Knot's own; `outside`:
    /// published names no record of this zone can hold.
    Published { soa: String, outside: Vec<String> },
}

/// The zone as the house wants it now: the declaration, every name Caddy serves, and the
/// site's secondary once it has a key.
pub async fn wanted(
    state: &State,
    config: &ZoneConfig,
    vault: Option<&Vault>,
) -> crate::Result<Zone> {
    let mut addresses = Vec::new();
    for a in &config.addresses {
        let ip: IpAddr = a.parse().map_err(|_| {
            crate::Error::Exposure(format!(
                "the zone's address {a} is not an IP address — hlb zone set --address"
            ))
        })?;
        addresses.push(ip);
    }
    let names = state
        .published_ingress()
        .await?
        .into_iter()
        .map(|(host, _, _)| host)
        .collect();
    let transfer = stored(state, vault, TRANSFER_SECRET)
        .await?
        .map(|key| Transfer {
            key: TransferKey(key),
            site: hlb_mesh::site::HUB,
            port: zone::SITE_PORT,
        });
    let mail = hlb_api::mail_dns::parse_zone(&state.zone_mail().await?)
        .into_iter()
        .map(|r| zone::Record {
            name: r.name,
            kind: r.kind,
            value: r.value,
            line: r.line,
        })
        .collect();
    let delegated = if config.delegated {
        Some(Delegated {
            key: delegated_key(state, vault).await?,
            challenge: challenge(state).await?,
        })
    } else {
        None
    };
    Ok(Zone {
        apex: config.apex.clone(),
        addresses,
        names,
        extra: config.extra.clone(),
        transfer,
        mail,
        caa: caa(state).await?,
        delegated,
    })
}

async fn delegated_key(state: &State, vault: Option<&Vault>) -> crate::Result<UpdateKey> {
    stored(state, vault, UPDATE_SECRET)
        .await?
        .map(UpdateKey)
        .ok_or_else(|| {
            crate::Error::Exposure(
                "the zone is delegated and its update key was never drawn: hlb zone switch --apply"
                    .into(),
            )
        })
}

/// How Caddy writes its challenges into the delegated zone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delegation {
    pub key: UpdateKey,
    /// Where it asks whether the challenge is in place: the zone's server as the
    /// internet reaches it. One address — certmagic fails on any resolver given that
    /// does not answer, and the house may not reach the site over IPv6 —, IPv4 first.
    pub resolver: Option<IpAddr>,
}

/// The delegation Caddy writes through; `None` while the registrar points at the
/// provider.
pub async fn delegation(state: &State, vault: Option<&Vault>) -> crate::Result<Option<Delegation>> {
    let Some(config) = state.zone().await? else {
        return Ok(None);
    };
    if !config.delegated {
        return Ok(None);
    }
    let mut addresses: Vec<IpAddr> = config
        .addresses
        .iter()
        .filter_map(|a| a.parse().ok())
        .collect();
    addresses.sort_by_key(|a| !a.is_ipv4());
    Ok(Some(Delegation {
        key: delegated_key(state, vault).await?,
        resolver: addresses.first().copied(),
    }))
}

/// The domain whose wildcard Caddy asks an ACME authority for, through the zone: none
/// under the house's own root, which challenges nothing.
async fn challenge(state: &State) -> crate::Result<Option<String>> {
    Ok(state
        .exposure()
        .await?
        .filter(|e| e.certificates == hlb_state::Certificates::Acme)
        .map(|e| e.domain))
}

/// Who may issue for the house's names: under its own root, no public authority at
/// all; under Let's Encrypt's production, its accounts as last read whole. A staging or
/// private authority pins nothing — staging checks the CAA a pin would refuse it by.
async fn caa(state: &State) -> crate::Result<Option<zone::Caa>> {
    let Some(exposure) = state.exposure().await? else {
        return Ok(None);
    };
    let records = if exposure.certificates == hlb_state::Certificates::Internal {
        vec!["0 issue \";\"".to_string()]
    } else if exposure.acme_ca.is_some() || exposure.staging {
        return Ok(None);
    } else {
        state.zone_caa().await?
    };
    Ok((!records.is_empty()).then_some(zone::Caa {
        at: exposure.domain,
        records,
    }))
}

/// Keeps the pins of a reading of the house's ACME accounts — only one that read every
/// account: 🔴 a night Caddy's could not be read would pin Stalwart's alone, and every
/// renewal of Caddy's would be refused by the house's own zone. `true` when they moved.
pub async fn keep_pins(
    state: &State,
    accounts: &[hlb_api::domain::Account],
    unread: &[String],
) -> crate::Result<bool> {
    if !unread.is_empty() || accounts.is_empty() {
        return Ok(false);
    }
    let mut pins: Vec<String> = accounts.iter().map(hlb_api::domain::pin).collect();
    pins.sort();
    pins.dedup();
    Ok(state.keep_zone_caa(&pins).await?)
}

/// Publishes the zone on the running Knot.
pub async fn publish<O: Orchestrator + ?Sized>(
    orch: &O,
    state: &State,
    vault: Option<&Vault>,
) -> crate::Result<Followed> {
    let Some(config) = state.zone().await? else {
        return Ok(Followed::Off);
    };
    let running = match orch.status(zone::SERVICE).await {
        Ok(s) => s,
        Err(hlb_orchestrator::Error::NotFound(_)) => return Ok(Followed::NoServer),
        Err(e) => return Err(e.into()),
    };
    let rendered = zone::render(&wanted(state, &config, vault).await?);
    let out = orch
        .run_job(&writer(&running.image, &config.apex, &rendered), 180)
        .await?;
    if !out.succeeded {
        return Err(crate::Error::Exposure(format!(
            "Knot refused the zone — the one it serves is unchanged: {}",
            out.output.join(" | ")
        )));
    }
    Ok(Followed::Published {
        soa: out.output.last().cloned().unwrap_or_default(),
        outside: rendered.outside,
    })
}

/// The writer's job: Knot's image and user, on its node, its volume mounted.
pub fn writer(image: &str, apex: &str, rendered: &zone::Rendered) -> ServiceSpec {
    let mut job = ServiceSpec::new(WRITER, image)
        .job()
        .constraint(format!(
            "node.labels.{}==true",
            hlb_types::manifest::data_label(zone::SERVICE)
        ))
        .mount(VOLUME, zone::STORAGE);
    for (path, content) in rendered.staged() {
        job = job.file(path, content);
    }
    let mut job = job.command([
        "sh".to_string(),
        "-c".to_string(),
        zone::writer_script(apex, &rendered.children),
    ]);
    // Knot's own user, so what it writes in the volume stays Knot's; `conf-check`
    // compiles the configuration under /tmp.
    job.hardening.user = Some("53:53".into());
    job.hardening.tmpfs = vec![Tmpfs::from("/tmp")];
    job
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> ZoneConfig {
        ZoneConfig {
            apex: "example.org".into(),
            addresses: vec!["203.0.113.4".into()],
            extra: String::new(),
            delegated: false,
        }
    }

    #[tokio::test]
    async fn the_zone_holds_every_name_caddy_serves() {
        let s = State::in_memory().await.expect("state");
        s.record_ingress(&[
            ("vault.example.org".into(), "vaultwarden".into(), false),
            ("id.example.org".into(), "pocket-id".into(), true),
        ])
        .await
        .expect("routes");
        let z = wanted(&s, &config(), None).await.expect("wanted");
        assert_eq!(z.names, ["id.example.org", "vault.example.org"]);
        assert_eq!(z.addresses, ["203.0.113.4".parse::<IpAddr>().unwrap()]);
    }

    fn exposure(certificates: hlb_state::Certificates) -> hlb_state::Exposure {
        hlb_state::Exposure {
            domain: "home.example.org".into(),
            certificates,
            acme_email: Some("admin@example.org".into()),
            dns_provider: None,
            staging: false,
            controller_host: None,
            acme_ca: None,
            acme_ca_root: None,
        }
    }

    fn account(who: &str, n: u32) -> hlb_api::domain::Account {
        hlb_api::domain::Account {
            who: who.into(),
            issuer: "letsencrypt.org".into(),
            uri: format!("https://acme-v02.api.letsencrypt.org/acme/acct/{n}"),
            wildcard: false,
            validations: Vec::new(),
        }
    }

    #[tokio::test]
    async fn stalwarts_lines_kept_are_the_zones() {
        let s = State::in_memory().await.expect("state");
        s.keep_zone_mail(
            "example.org. IN MX 10 mail.example.org.\n\
             k._domainkey.example.org. IN TXT (\n    \"v=DKIM1; p=AB\"\n    \"CD\"\n)",
        )
        .await
        .expect("keep");
        let z = wanted(&s, &config(), None).await.expect("wanted");
        assert_eq!(z.mail.len(), 2, "{:?}", z.mail);
        assert_eq!(
            (z.mail[1].name.as_str(), z.mail[1].value.as_str()),
            ("k._domainkey.example.org", "v=DKIM1; p=ABCD")
        );
    }

    #[tokio::test]
    async fn only_the_houses_accounts_may_issue_and_none_under_its_own_root() {
        let s = State::in_memory().await.expect("state");
        assert_eq!(caa(&s).await.expect("caa"), None, "no exposure");

        s.set_exposure(&exposure(hlb_state::Certificates::Internal))
            .await
            .expect("exposure");
        let c = caa(&s).await.expect("caa").expect("internal");
        assert_eq!(
            (c.at.as_str(), c.records),
            ("home.example.org", vec!["0 issue \";\"".to_string()])
        );

        s.set_exposure(&exposure(hlb_state::Certificates::Acme))
            .await
            .expect("exposure");
        assert_eq!(caa(&s).await.expect("caa"), None, "no account read yet");
        let both = [account("Caddy", 1), account("Stalwart", 2)];
        assert!(keep_pins(&s, &both, &[]).await.expect("pins"));
        assert!(!keep_pins(&s, &both, &[]).await.expect("again"));
        // A night that read Stalwart's alone pins nothing: Caddy's stays allowed.
        assert!(
            !keep_pins(&s, &both[1..], &["Caddy's account not read".into()])
                .await
                .expect("partial")
        );
        let c = caa(&s).await.expect("caa").expect("acme");
        assert_eq!(
            c.records,
            [
                "0 issue \"letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/1\"",
                "0 issue \"letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/2\"",
            ]
        );

        let mut staging = exposure(hlb_state::Certificates::Acme);
        staging.staging = true;
        s.set_exposure(&staging).await.expect("exposure");
        assert_eq!(
            caa(&s).await.expect("caa"),
            None,
            "staging checks the CAA too"
        );
    }

    #[tokio::test]
    async fn an_address_that_is_none_is_refused_before_anything_is_written() {
        let s = State::in_memory().await.expect("state");
        let mut c = config();
        c.addresses = vec!["vps.example.net".into()];
        let err = wanted(&s, &c, None).await.unwrap_err().to_string();
        assert!(err.contains("vps.example.net"), "{err}");
    }

    #[tokio::test]
    async fn the_site_is_handed_the_zone_once_it_has_a_key_and_never_loses_it() {
        let s = State::in_memory().await.expect("state");
        let vault = Vault::ephemeral();
        let z = wanted(&s, &config(), Some(&vault)).await.expect("wanted");
        assert_eq!(z.transfer, None, "no key drawn: no site to hand it to");

        let key = transfer_key(&s, &vault).await.expect("key");
        assert_eq!(
            transfer_key(&s, &vault).await.expect("again"),
            key,
            "drawn once"
        );
        let z = wanted(&s, &config(), Some(&vault)).await.expect("wanted");
        let t = z.transfer.expect("the site");
        assert_eq!((t.key, t.site, t.port), (key, hlb_mesh::site::HUB, 53));

        let err = wanted(&s, &config(), None).await.unwrap_err().to_string();
        assert!(err.contains("unchanged"), "{err}");
    }

    #[tokio::test]
    async fn a_delegated_zone_is_written_with_the_key_drawn_once() {
        let s = State::in_memory().await.expect("state");
        let vault = Vault::ephemeral();
        let mut c = config();
        c.delegated = true;
        let err = wanted(&s, &c, Some(&vault)).await.unwrap_err().to_string();
        assert!(err.contains("hlb zone switch"), "no key, no zone: {err}");

        let key = update_key(&s, &vault).await.expect("key");
        assert_eq!(
            update_key(&s, &vault).await.expect("again"),
            key,
            "drawn once"
        );
        assert_ne!(
            key.0,
            transfer_key(&s, &vault).await.expect("transfer").0,
            "the site never holds the key that writes the challenges"
        );
        let d = wanted(&s, &c, Some(&vault))
            .await
            .expect("wanted")
            .delegated
            .expect("delegated");
        assert_eq!(
            (d.key, d.challenge),
            (key.clone(), None),
            "no exposure: no challenge"
        );

        s.set_exposure(&exposure(hlb_state::Certificates::Acme))
            .await
            .expect("exposure");
        let d = wanted(&s, &c, Some(&vault))
            .await
            .expect("wanted")
            .delegated;
        assert_eq!(
            d.and_then(|d| d.challenge).as_deref(),
            Some("home.example.org")
        );
        s.set_exposure(&exposure(hlb_state::Certificates::Internal))
            .await
            .expect("exposure");
        let d = wanted(&s, &c, Some(&vault))
            .await
            .expect("wanted")
            .delegated;
        assert_eq!(
            d.and_then(|d| d.challenge),
            None,
            "its own root asks no challenge"
        );

        assert!(wanted(&s, &c, None).await.is_err(), "the key, or nothing");
        c.delegated = false;
        assert_eq!(
            wanted(&s, &c, Some(&vault)).await.expect("back").delegated,
            None
        );
    }

    #[tokio::test]
    async fn once_delegated_caddy_writes_its_challenge_into_the_zone() {
        let s = State::in_memory().await.expect("state");
        let vault = Vault::ephemeral();
        let mut e = exposure(hlb_state::Certificates::Acme);
        e.dns_provider = Some("hetzner".into());
        s.set_exposure(&e).await.expect("exposure");
        let mut c = config();
        c.delegated = true;
        s.set_zone(&c).await.expect("zone");
        let key = update_key(&s, &vault).await.expect("key");

        // No provider token in the vault: the delegation needs none.
        let cfg = crate::ingress::config(&s, Some(&vault), Some(&e), &[], false)
            .await
            .expect("config");
        let hlb_ingress::Tls::Acme {
            wildcard: Some(w), ..
        } = &cfg.tls
        else {
            panic!("no wildcard: {:?}", cfg.tls);
        };
        assert_eq!(w.provider.name, "rfc2136");
        assert_eq!(
            w.credentials,
            [
                "hlb-update".to_string(),
                "hmac-sha256".into(),
                key.0.clone(),
                "knot:10053".into()
            ]
        );
        assert_eq!(w.resolvers, ["203.0.113.4"]);
        assert_eq!(w.base_domain, "home.example.org");
        let shown = hlb_ingress::render(&[], &cfg.redacted());
        assert!(!shown.contains(&key.0), "a preview never prints the key");

        c.delegated = false;
        s.set_zone(&c).await.expect("zone");
        let err = crate::ingress::config(&s, Some(&vault), Some(&e), &[], false)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("dns-hetzner-api-token"),
            "the provider's again: {err}"
        );
    }

    #[test]
    fn the_writer_runs_on_knots_node_as_knot() {
        let r = zone::render(&Zone {
            apex: "example.org".into(),
            addresses: vec![],
            names: vec![],
            extra: String::new(),
            transfer: None,
            mail: Vec::new(),
            caa: None,
            delegated: None,
        });
        let job = writer("cznic/knot:v3.6.2", "example.org", &r);
        assert!(job.constraints.contains(&format!(
            "node.labels.{}==true",
            hlb_types::manifest::data_label("knot")
        )));
        assert_eq!(job.mounts, [(VOLUME.to_string(), "/storage".to_string())]);
        assert_eq!(job.hardening.user.as_deref(), Some("53:53"));
        assert!(job.hardening.read_only_rootfs);
        assert_eq!(job.files.len(), 3);
    }

    #[test]
    fn the_volume_is_the_one_the_manifest_declares() {
        let catalog =
            hlb_catalog::Catalog::load(concat!(env!("CARGO_MANIFEST_DIR"), "/../../catalog"))
                .expect("catalog");
        let knot = catalog.get(zone::SERVICE).expect("knot");
        let storage: Vec<String> = knot
            .manifest
            .spec
            .requires
            .iter()
            .filter_map(|c| match c {
                hlb_types::Capability::Storage { name, .. } => {
                    Some(format!("{}-{name}", zone::SERVICE))
                }
                _ => None,
            })
            .collect();
        assert_eq!(storage, [VOLUME]);
    }
}
