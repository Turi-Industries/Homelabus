//! The house's own zone, published to its Knot: `hlb zone set`, and every publication of
//! the routes after it — a name Caddy serves is a name the zone holds.
//!
//! What is written is [`hlb_ingress::zone`]'s; here it is placed. A one-off job on
//! Knot's node, from Knot's own image, checks both files with Knot's tools, puts them in
//! the volume, reloads Knot over its socket and waits for the zone to be signed.

use std::net::IpAddr;

use hlb_ingress::zone::{self, Transfer, TransferKey, Zone};
use hlb_orchestrator::{Orchestrator, ServiceSpec};
use hlb_secrets::Vault;
use hlb_state::{State, ZoneConfig};
use hlb_types::manifest::Tmpfs;

/// The TSIG key both Knots share, in the vault. A stored name.
pub const TRANSFER_SECRET: &str = "zone-transfer-key";

/// The key, drawn once and kept: both ends hold it, and a new one would stop every
/// transfer until the site has it too.
pub async fn transfer_key(state: &State, vault: &Vault) -> crate::Result<TransferKey> {
    let mut raw = [0u8; 32];
    hlb_secrets::fill_random(&mut raw);
    let drawn = hlb_types::token::base64_standard(&raw);
    state
        .store_secret_if_absent(
            TRANSFER_SECRET,
            &vault.encrypt(&drawn)?,
            "the TSIG key the house's and the site's Knot share",
        )
        .await?;
    stored_key(state, Some(vault))
        .await?
        .ok_or_else(|| crate::Error::Exposure("the zone's transfer key vanished".into()))
}

/// The key the site was given, if any. 🔴 One there and no vault to read it with is an
/// error, never a zone rendered without it: that zone would take the site's access away.
async fn stored_key(state: &State, vault: Option<&Vault>) -> crate::Result<Option<TransferKey>> {
    let Some(ct) = state.secret(TRANSFER_SECRET).await? else {
        return Ok(None);
    };
    let vault = vault.ok_or_else(|| {
        crate::Error::Exposure(
            "the zone's transfer key is in the vault, which this publication was not given: \
             the zone served is unchanged"
                .into(),
        )
    })?;
    Ok(Some(TransferKey(vault.decrypt(&ct)?)))
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
    let transfer = stored_key(state, vault).await?.map(|key| Transfer {
        key,
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
    Ok(Zone {
        apex: config.apex.clone(),
        addresses,
        names,
        extra: config.extra.clone(),
        transfer,
        mail,
        caa: caa(state).await?,
        // Declared by the switch at the registrar, the next step.
        delegated: None,
    })
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
        .mount(VOLUME, zone::STORAGE)
        .file(zone::STAGED_ZONE, rendered.zone.as_str())
        .file(zone::STAGED_CONF, rendered.conf.as_str())
        .file(zone::STAGED_CHECK, zone::check_conf())
        .command([
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
