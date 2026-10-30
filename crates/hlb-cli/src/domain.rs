//! `hlb domain`: the house's domain read as the internet and its registry see it, and
//! compared with the reading accepted as its baseline (`hlb_api::domain`).

use std::process::ExitCode;

use hlb_api::domain::{self, Reading, Registry};
use hlb_state::Certificates;

use crate::{open_state, Cli, DomainCmd, ACTOR_ROLE};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub async fn run(cli: &Cli, cmd: &DomainCmd) -> Result<ExitCode> {
    let state = open_state(cli).await?;
    let Some(exposure) = state.exposure().await? else {
        eprintln!("No domain yet: `hlb config exposure --domain …` names it.");
        return Ok(ExitCode::FAILURE);
    };
    if exposure.certificates == Certificates::Internal {
        eprintln!(
            "{} is served under the house's own root: no registry holds it, nothing to watch.",
            exposure.domain
        );
        return Ok(ExitCode::FAILURE);
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    let reading = hlb_engine::domain::read(
        &hlb_engine::domain::Public::default(),
        &exposure.domain,
        now,
    )
    .await;
    let baseline = state
        .domain_baseline()
        .await?
        .filter(|b| b.zone == reading.zone);
    print(&reading, now);

    match cmd {
        DomainCmd::Watch => {
            state.record_domain_reading(&reading).await?;
            let Some(baseline) = baseline else {
                println!(
                    "\nNot watched yet: nothing to compare with. Read the above, then \
                     `hlb domain accept --apply` makes it the baseline."
                );
                return Ok(ExitCode::FAILURE);
            };
            let drifts = domain::drifts(&baseline, &reading);
            if drifts.is_empty() {
                println!(
                    "\nAs accepted on {}.",
                    day(baseline.read_at).unwrap_or_default()
                );
                return Ok(ExitCode::SUCCESS);
            }
            println!(
                "\nMoved since the baseline of {} — if nobody here did this, call the \
                 registrar now:",
                day(baseline.read_at).unwrap_or_default()
            );
            for d in &drifts {
                println!("  🔴 {}: was {}, now {}", d.what.label(), d.was, d.now);
            }
            Ok(ExitCode::FAILURE)
        }
        DomainCmd::Accept { apply } => {
            if reading.dns.is_err() {
                eprintln!("\nRefused: a baseline the resolvers could not read compares nothing.");
                return Ok(ExitCode::FAILURE);
            }
            match &baseline {
                None => println!("\nThis becomes the baseline every night compares with."),
                Some(b) => {
                    let drifts = domain::drifts(b, &reading);
                    if drifts.is_empty() {
                        println!("\nThe same as the baseline: accepting it changes nothing.");
                    } else {
                        println!(
                            "\nReplaces the baseline of {}:",
                            day(b.read_at).unwrap_or_default()
                        );
                        for d in &drifts {
                            println!("  {}: was {}, now {}", d.what.label(), d.was, d.now);
                        }
                    }
                }
            }
            if !apply {
                println!("\nPreview: nothing recorded. --apply accepts it.");
                return Ok(ExitCode::SUCCESS);
            }
            state.set_domain_baseline(&reading).await?;
            state.record_domain_reading(&reading).await?;
            state
                .audit(
                    "cli",
                    ACTOR_ROLE,
                    "domain-accept",
                    &reading.zone,
                    "ok",
                    None,
                )
                .await?;
            println!("Accepted.");
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn print(r: &Reading, now: i64) {
    println!("{} — as the internet and its registry see it", r.zone);
    let line = |label: &str, v: &[String]| {
        println!(
            "  {label:<13} {}",
            if v.is_empty() {
                "none".into()
            } else {
                v.join(", ")
            }
        );
    };
    match &r.dns {
        Ok(dns) => {
            line("name servers", &dns.ns);
            line("DS", &dns.ds);
            println!(
                "  {:<13} {}",
                "DNSSEC",
                match (dns.ds.is_empty(), dns.validated) {
                    (true, _) => "not signed",
                    (false, true) => "validates",
                    (false, false) => "🔴 signed, and does not validate",
                }
            );
            line("CAA", &dns.caa);
        }
        Err(e) => println!("  ? DNS not read: {e}"),
    }
    match &r.registry {
        Registry::Read(reg) => {
            println!("  {:<13} {}", "registry", reg.source);
            println!(
                "  {:<13} {}",
                "registrar",
                reg.registrar.as_deref().unwrap_or("not named")
            );
            line("statuses", &reg.statuses);
            line("delegation", &reg.nameservers);
            if let Some(e) = reg.expires.and_then(day) {
                println!("  {:<13} {e}", "expires");
            }
        }
        Registry::NotRead { why } => println!("  ? registry not read: {why}"),
    }
    for a in domain::advice(r, now) {
        println!("  • {a}");
    }
}

fn day(epoch: i64) -> Option<String> {
    chrono::DateTime::from_timestamp(epoch, 0).map(|d| d.format("%Y-%m-%d").to_string())
}
