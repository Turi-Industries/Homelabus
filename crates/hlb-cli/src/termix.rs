//! `hlb termix`: the nodes, kept in Termix (`hlb_engine::termix`).

use std::process::ExitCode;

use hlb_engine::roles::Outcome;
use hlb_engine::termix::{NodeAccess, Report};
use hlb_orchestrator::{Orchestrator, SwarmOrchestrator};

use crate::{open_state, open_vault, relay, Cli, TermixCmd, ACTOR_ROLE};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub async fn run(cli: &Cli, cmd: &TermixCmd) -> Result<ExitCode> {
    let state = open_state(cli).await?;
    let vault = open_vault(cli)?;
    let orch = SwarmOrchestrator::connect().await?;
    let network = cli.platform_network.clone();
    let reach = move |u: &str| relay::reach(u, &network);
    let access = NodeAccess {
        state: &state,
        vault: &vault,
        orchestrator: &orch as &dyn Orchestrator,
        reach: &reach,
    };
    let (reports, apply, action) = match cmd {
        TermixCmd::Connect { apply } => {
            // 🔴 Read on standard input, never as an argument: a key on a command line
            // stays in the shell's history and in every `ps` while it runs.
            eprintln!("A Termix administrator's API key (standard input, Ctrl-D to finish):");
            let mut token = String::new();
            std::io::Read::read_to_string(&mut std::io::stdin(), &mut token)?;
            let token = token.trim();
            if token.is_empty() {
                eprintln!("No key given — nothing was done.");
                return Ok(ExitCode::FAILURE);
            }
            let connected = access.connect(token, *apply).await?;
            let mut reports = vec![connected];
            if *apply && reports[0].stopped.is_none() && !reports[0].failed() {
                reports.push(access.run(true).await?);
            }
            (reports, *apply, "termix-connect")
        }
        TermixCmd::Sync { apply } => (vec![access.run(*apply).await?], *apply, "termix-sync"),
        TermixCmd::Rotate { apply } => {
            (vec![access.rotate(*apply).await?], *apply, "termix-rotate")
        }
    };
    let mut failed = false;
    for r in &reports {
        print(r);
        failed |= r.failed();
    }
    let last = reports.last();
    if apply {
        let app = last.and_then(|r| r.app.clone()).unwrap_or_default();
        state
            .audit(
                "cli",
                ACTOR_ROLE,
                action,
                &app,
                if failed { "failed" } else { "ok" },
                None,
            )
            .await?;
    } else if last
        .is_some_and(|r| r.stopped.is_none() && r.lines.iter().any(|l| l.outcome == Outcome::ToDo))
    {
        println!("\nRe-run with --apply to make it so.");
    }
    Ok(if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    })
}

fn print(r: &Report) {
    if let Some(app) = &r.app {
        println!("The nodes, in {app}\n");
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
            "\n{} already as {} should be.",
            hlb_api::plural(r.unchanged as u64, "thing", "things"),
            if r.unchanged == 1 { "it" } else { "they" }
        );
    }
    if !r.host_keys.is_empty() {
        println!(
            "\nEach node's host key — Termix asks to accept it at a first connection; it \
             must read the same:"
        );
        for (node, key) in &r.host_keys {
            println!("  {node}  {key}");
        }
    }
    for n in &r.notes {
        println!("⚠️  {n}");
    }
    if let Some(why) = &r.stopped {
        println!("\n{why}");
    }
}
