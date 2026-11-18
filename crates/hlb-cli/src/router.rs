//! `hlb router`: the house's router, OPNsense (`hlb_engine::router`).

use std::net::Ipv4Addr;
use std::process::ExitCode;

use hlb_engine::roles::Outcome;
use hlb_engine::router::{house_names, Report, Router};
use hlb_orchestrator::SwarmOrchestrator;
use hlb_router::client::Credentials;

use crate::{open_state, open_vault, Cli, RouterCmd, ACTOR_ROLE};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// The key and the secret, as the file OPNsense downloads holds them (`key=…`,
/// `secret=…`) or as two bare lines, key first.
fn credentials(text: &str) -> Option<Credentials> {
    let lines: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    let field = |name: &str| {
        lines
            .iter()
            .find_map(|l| l.strip_prefix(name).and_then(|v| v.strip_prefix('=')))
            .map(str::to_string)
    };
    let (key, secret) = match (field("key"), field("secret")) {
        (Some(k), Some(s)) => (k, s),
        _ => match lines.as_slice() {
            [k, s] => (k.to_string(), s.to_string()),
            _ => return None,
        },
    };
    (!key.is_empty() && !secret.is_empty()).then_some(Credentials { key, secret })
}

pub async fn run(cli: &Cli, cmd: &RouterCmd) -> Result<ExitCode> {
    let state = open_state(cli).await?;
    let vault = open_vault(cli)?;
    let router = Router {
        state: &state,
        vault: &vault,
    };
    let (report, apply, action) = match cmd {
        RouterCmd::Connect {
            url,
            fingerprint: None,
            ..
        } => {
            // Nothing is sent to a router not yet compared with its console: the
            // handshake is read, then refused.
            let presented = hlb_router::tls::peek(url).await?;
            println!("{url} presents a certificate whose SHA-256 is\n\n  {presented}\n");
            println!(
                "Compare it with the router's console (`HTTPS: SHA256 …`, under its \
                 addresses). If it reads the same, re-run with\n  --fingerprint {}",
                presented.hex()
            );
            return Ok(ExitCode::SUCCESS);
        }
        RouterCmd::Connect {
            url,
            fingerprint: Some(fingerprint),
            caddy: Some(caddy),
            apply,
        } => {
            // 🔴 Read on standard input, never as arguments: a secret on a command line
            // stays in the shell's history and in every `ps` while it runs.
            eprintln!(
                "The router administrator's API key and secret — the file it downloaded, \
                 or the key then the secret (standard input, Ctrl-D to finish):"
            );
            let mut text = String::new();
            std::io::Read::read_to_string(&mut std::io::stdin(), &mut text)?;
            let Some(given) = credentials(&text) else {
                eprintln!("No key and secret read — nothing was done.");
                return Ok(ExitCode::FAILURE);
            };
            let report = router
                .connect(url, fingerprint, given, *caddy, *apply)
                .await?;
            (report, *apply, "router-connect")
        }
        RouterCmd::Connect { caddy: None, .. } => {
            // clap requires it beside --fingerprint; said all the same.
            eprintln!("--caddy <address>: Caddy's address on the router's network.");
            return Ok(ExitCode::FAILURE);
        }
        RouterCmd::Show => {
            let orch = SwarmOrchestrator::connect().await?;
            let names = house_names(&orch, &state).await?;
            let (config, report) = router.show(&names).await?;
            if let Some(c) = &config {
                println!("Router  {}", c.url);
                if let Some(pin) = hlb_router::Fingerprint::parse(&c.fingerprint) {
                    println!("  certificate  SHA256 {pin}");
                }
                println!("  Caddy        {}, inside the house", c.caddy);
            }
            (report, false, "router-show")
        }
        RouterCmd::Sync { apply } => {
            let orch = SwarmOrchestrator::connect().await?;
            let names = house_names(&orch, &state).await?;
            (router.sync(&names, *apply).await?, *apply, "router-sync")
        }
    };
    print(&report);
    let failed = report.failed();
    if apply {
        state
            .audit(
                "cli",
                ACTOR_ROLE,
                action,
                hlb_engine::router::ACCOUNT,
                if failed { "failed" } else { "ok" },
                None,
            )
            .await?;
    } else if report.stopped.is_none() && report.lines.iter().any(|l| l.outcome == Outcome::ToDo) {
        println!("\nRe-run with --apply to make it so.");
    }
    Ok(if failed || report.stopped.is_some() {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    })
}

fn print(r: &Report) {
    if let Some(s) = &r.system {
        println!("{} — {}\n", s.version, s.name);
    }
    for l in &r.lines {
        let (mark, why) = match &l.outcome {
            Outcome::ToDo => ("·", None),
            Outcome::Done => ("✓", None),
            Outcome::Waiting(w) => ("…", Some(w)),
            Outcome::NotConfigured(w) => ("⚠️", Some(w)),
            Outcome::Failed(w) => ("🔴", Some(w)),
        };
        println!("{mark} {}: {}", l.subject, l.change);
        if let Some(w) = why {
            println!("    {w}");
        }
    }
    if r.unchanged > 0 {
        println!(
            "\n{} already answered inside the house.",
            hlb_api::plural(r.unchanged as u64, "name", "names")
        );
    }
    for n in &r.notes {
        println!("⚠️  {n}");
    }
    if let Some(why) = &r.stopped {
        println!("\n{why}");
    }
}

/// Parsed by clap: an address, never a name to resolve.
pub fn caddy_address(s: &str) -> std::result::Result<Ipv4Addr, String> {
    s.parse()
        .map_err(|_| format!("{s}: Caddy's IPv4 address on the router's network"))
}

#[cfg(test)]
mod tests {
    use super::credentials;

    #[test]
    fn the_file_opnsense_downloads_is_read_as_is() {
        let c = credentials("key=AbC+/1==\nsecret=s3cr=et\n").expect("the file");
        assert_eq!((c.key.as_str(), c.secret.as_str()), ("AbC+/1==", "s3cr=et"));
    }

    #[test]
    fn two_bare_lines_are_the_key_then_the_secret() {
        let c = credentials("  AbC\n\nsecret-ish\n").expect("two lines");
        assert_eq!((c.key.as_str(), c.secret.as_str()), ("AbC", "secret-ish"));
    }

    #[test]
    fn anything_else_reads_as_nothing() {
        assert!(credentials("").is_none());
        assert!(credentials("only one line").is_none());
        assert!(credentials("key=\nsecret=x").is_none());
    }
}
