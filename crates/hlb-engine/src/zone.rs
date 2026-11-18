//! The house's own zone, published to its Knot: `hlb zone set`, and every publication of
//! the routes after it — a name Caddy serves is a name the zone holds.
//!
//! What is written is [`hlb_ingress::zone`]'s; here it is placed. A one-off job on
//! Knot's node, from Knot's own image, checks both files with Knot's tools, puts them in
//! the volume, reloads Knot over its socket and waits for the zone to be signed.

use std::net::IpAddr;

use hlb_ingress::zone::{self, Zone};
use hlb_orchestrator::{Orchestrator, ServiceSpec};
use hlb_state::{State, ZoneConfig};
use hlb_types::manifest::Tmpfs;

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

/// The zone as the house wants it now: the declaration, and every name Caddy serves.
pub async fn wanted(state: &State, config: &ZoneConfig) -> crate::Result<Zone> {
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
    Ok(Zone {
        apex: config.apex.clone(),
        addresses,
        names,
        extra: config.extra.clone(),
    })
}

/// Publishes the zone on the running Knot.
pub async fn publish<O: Orchestrator + ?Sized>(orch: &O, state: &State) -> crate::Result<Followed> {
    let Some(config) = state.zone().await? else {
        return Ok(Followed::Off);
    };
    let running = match orch.status(zone::SERVICE).await {
        Ok(s) => s,
        Err(hlb_orchestrator::Error::NotFound(_)) => return Ok(Followed::NoServer),
        Err(e) => return Err(e.into()),
    };
    let rendered = zone::render(&wanted(state, &config).await?);
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
            zone::writer_script(apex),
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
        let z = wanted(&s, &config()).await.expect("wanted");
        assert_eq!(z.names, ["id.example.org", "vault.example.org"]);
        assert_eq!(z.addresses, ["203.0.113.4".parse::<IpAddr>().unwrap()]);
    }

    #[tokio::test]
    async fn an_address_that_is_none_is_refused_before_anything_is_written() {
        let s = State::in_memory().await.expect("state");
        let mut c = config();
        c.addresses = vec!["vps.example.net".into()];
        let err = wanted(&s, &c).await.unwrap_err().to_string();
        assert!(err.contains("vps.example.net"), "{err}");
    }

    #[test]
    fn the_writer_runs_on_knots_node_as_knot() {
        let r = zone::render(&Zone {
            apex: "example.org".into(),
            addresses: vec![],
            names: vec![],
            extra: String::new(),
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
