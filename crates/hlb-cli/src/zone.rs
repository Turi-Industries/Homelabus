//! `hlb zone`: the house's own zone, signed by its Knot and served by the site's alone
//! (`hlb_ingress::zone` says why the house's is hidden).
//!
//! A module of its own, which needs the site: without a VPS no server would answer
//! the internet, so the preview refuses it, as it refuses an app whose service is
//! missing.

use std::process::ExitCode;

use hlb_engine::zone::Followed;
use hlb_orchestrator::{Orchestrator, SwarmOrchestrator};
use hlb_state::ZoneConfig;

use crate::{open_state, open_vault, Cli, ZoneCmd, ACTOR_ROLE};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub async fn run(cli: &Cli, cmd: &ZoneCmd) -> Result<ExitCode> {
    match cmd {
        ZoneCmd::Show => show(cli).await,
        ZoneCmd::Set {
            apex,
            address,
            extra,
            apply,
        } => set(cli, apex, address, extra.as_deref(), *apply).await,
    }
}

async fn show(cli: &Cli) -> Result<ExitCode> {
    let state = open_state(cli).await?;
    let Some(config) = state.zone().await? else {
        println!("The house serves no zone of its own: its names are the DNS provider's.");
        println!("  hlb zone set --apex <registered name>   signs it at home, served by the site");
        return Ok(ExitCode::SUCCESS);
    };
    let vault = open_vault(cli)?;
    let wanted = hlb_engine::zone::wanted(&state, &config, Some(&vault)).await?;
    let rendered = hlb_ingress::zone::render(&wanted);
    println!("{}", rendered.zone);
    say_outside(&rendered.outside);
    let orch = SwarmOrchestrator::connect().await?;
    match orch.status(hlb_ingress::zone::SERVICE).await {
        Ok(s) if s.is_converged() => println!("✓ Knot runs ({})", s.replicas_text()),
        Ok(s) => println!("⚠️  Knot is not up ({})", s.replicas_text()),
        Err(hlb_orchestrator::Error::NotFound(_)) => {
            println!(
                "🔴 Knot is not deployed: hlb zone set --apex {} --apply",
                config.apex
            )
        }
        Err(e) => return Err(e.into()),
    }
    Ok(ExitCode::SUCCESS)
}

/// The zone declared, or why it cannot be: its apex holds the exposure's domain, and
/// its addresses are the site's — given, or the site's endpoint when that is one.
fn settle(
    apex: &str,
    domain: &str,
    endpoint: &str,
    addresses: &[String],
) -> std::result::Result<(String, Vec<String>), String> {
    let apex = hlb_ingress::zone::normalize(apex).ok_or(format!("{apex} is no domain name"))?;
    if domain != apex && !domain.ends_with(&format!(".{apex}")) {
        return Err(format!(
            "{domain}, where the house publishes its names, is not in {apex}: \
             the zone must be the registered name holding it"
        ));
    }
    let addresses = if addresses.is_empty() {
        match endpoint.parse::<std::net::IpAddr>() {
            Ok(ip) => vec![ip.to_string()],
            Err(_) => {
                return Err(format!(
                    "the site is reached at {endpoint}, a name: give its public addresses, \
                     --address <IPv4> --address <IPv6>"
                ));
            }
        }
    } else {
        let mut out = Vec::new();
        for a in addresses {
            let ip: std::net::IpAddr = a.parse().map_err(|_| format!("{a} is no IP address"))?;
            out.push(ip.to_string());
        }
        out
    };
    Ok((apex, addresses))
}

async fn set(
    cli: &Cli,
    apex: &str,
    addresses: &[String],
    extra: Option<&std::path::Path>,
    apply: bool,
) -> Result<ExitCode> {
    let state = open_state(cli).await?;
    let vault = open_vault(cli)?;
    let Some(exposure) = state.exposure().await? else {
        eprintln!("🔴 No domain yet: hlb config exposure --domain <domain> --apply");
        return Ok(ExitCode::FAILURE);
    };
    let Some(site) = crate::site::load(&state, &vault).await? else {
        eprintln!(
            "🔴 No site: the house's Knot answers the site's alone, and the site's is the only \
             server the internet asks. hlb site add <host> --apply"
        );
        return Ok(ExitCode::FAILURE);
    };
    let (apex, addresses) = match settle(apex, &exposure.domain, &site.endpoint, addresses) {
        Ok(d) => d,
        Err(why) => {
            eprintln!("🔴 {why}");
            return Ok(ExitCode::FAILURE);
        }
    };
    let extra = match extra {
        Some(path) => std::fs::read_to_string(path)?,
        None => state.zone().await?.map(|z| z.extra).unwrap_or_default(),
    };
    let config = ZoneConfig {
        apex,
        addresses,
        extra,
    };

    let rendered =
        hlb_ingress::zone::render(&hlb_engine::zone::wanted(&state, &config, Some(&vault)).await?);
    println!("{}", rendered.zone);
    say_outside(&rendered.outside);
    let orch = SwarmOrchestrator::connect().await?;
    let deployed = match orch.status(hlb_ingress::zone::SERVICE).await {
        Ok(_) => true,
        Err(hlb_orchestrator::Error::NotFound(_)) => false,
        Err(e) => return Err(e.into()),
    };
    if !apply {
        if !deployed {
            println!("Knot would be installed, and sign this zone with a key of its own.");
        }
        println!("Knot checks the zone before serving it. Rerun with --apply.");
        return Ok(ExitCode::SUCCESS);
    }

    state.set_zone(&config).await?;
    state
        .audit(
            "cli",
            ACTOR_ROLE,
            "zone-set",
            &config.apex,
            "ok",
            Some(&config.addresses.join(" ")),
        )
        .await?;
    let code = if !deployed {
        // Its deployment publishes the zone once it answers.
        crate::install(cli, hlb_ingress::zone::SERVICE, None, None, true).await?
    } else {
        match hlb_engine::zone::publish(&orch, &state, Some(&vault)).await {
            Ok(f) => {
                say(&Ok(f));
                ExitCode::SUCCESS
            }
            Err(e) => {
                say(&Err(e.to_string()));
                ExitCode::FAILURE
            }
        }
    };
    // The site's name server, its key and the link's firewall go together, and the
    // site sync puts all three in place.
    if code == ExitCode::SUCCESS
        && state
            .secret(hlb_engine::zone::TRANSFER_SECRET)
            .await?
            .is_none()
    {
        println!("The internet asks the site, which serves the zone from: hlb site sync --apply");
    }
    Ok(code)
}

fn say_outside(outside: &[String]) {
    if !outside.is_empty() {
        println!(
            "⚠️  Served by Caddy, outside the zone — their records stay where they are: {}",
            outside.join(", ")
        );
    }
}

/// What a publication of the routes did to the zone, said after them.
pub fn say(zone: &std::result::Result<Followed, String>) {
    match zone {
        Ok(Followed::Off) => {}
        Ok(Followed::NoServer) => {
            println!("⚠️  Knot is not deployed: the zone waits for it — hlb zone set --apply")
        }
        Ok(Followed::Published { soa, outside }) => {
            println!("✓ zone signed and served to the site: {}", soa.trim());
            say_outside(outside);
        }
        Err(e) => eprintln!("🔴 the zone did not follow: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::settle;

    #[test]
    fn the_zone_holds_the_exposures_domain() {
        let ok = settle("Example.org.", "home.example.org", "203.0.113.4", &[]).expect("ok");
        assert_eq!(
            ok,
            ("example.org".to_string(), vec!["203.0.113.4".to_string()])
        );
        assert!(settle("example.org", "example.org", "203.0.113.4", &[]).is_ok());
        let err = settle("other.org", "home.example.org", "203.0.113.4", &[]).unwrap_err();
        assert!(err.contains("not in other.org"), "{err}");
        // A suffix is not a parent.
        assert!(settle("ample.org", "example.org", "203.0.113.4", &[]).is_err());
    }

    #[test]
    fn a_site_reached_by_name_must_be_given_its_addresses() {
        let err = settle("example.org", "example.org", "vps.example.net", &[]).unwrap_err();
        assert!(err.contains("--address"), "{err}");
        let given = ["2001:db8::4".to_string(), "203.0.113.4".to_string()];
        let (_, a) = settle("example.org", "example.org", "vps.example.net", &given).expect("ok");
        assert_eq!(a, given);
        assert!(settle("example.org", "example.org", "x", &["nope".into()]).is_err());
    }
}
