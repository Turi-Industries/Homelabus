//! `hlb config ups`'s second half: NUT's `upsmon` on every node, a secondary of the
//! house's UPS, which shuts the machine down at low battery — by then the power loop
//! has stopped every app (`hlb_bootstrap::nut`).
//!
//! The account it signs in with is the house's NUT's, made by a person in its
//! `upsd.users`: it is proved against the server before a node is touched, and kept in
//! the vault so a node added later is set up without asking again.

use std::process::ExitCode;

use hlb_bootstrap::nut::{self, Monitor};
use hlb_bootstrap::provision::{self, Provision};
use hlb_bootstrap::{Distro, Runner};
use hlb_engine::power;
use hlb_orchestrator::{Orchestrator, SwarmOrchestrator};
use hlb_secrets::Vault;
use hlb_state::{State, UpsPolicy};

use crate::{open_vault, Cli, ACTOR_ROLE};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// The vault's entry: `{"user", "password"}`. A stored name.
pub const SECRET: &str = "ups-shutdown";

/// What to do with the nodes' `upsmon`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shutdown<'a> {
    /// Sign in as this account (its password on standard input), on every node.
    Set(&'a str),
    /// Again, with the vault's account: a node added since, a server changed.
    Again,
    /// Undo it where Homelabus wrote it.
    Remove,
}

/// The vault's account: user, then password.
async fn account(state: &State, vault: &Vault) -> Result<Option<(String, String)>> {
    let Some(ct) = state.secret(SECRET).await? else {
        return Ok(None);
    };
    let v: serde_json::Value = serde_json::from_str(&vault.decrypt(&ct)?)?;
    let field = |k: &str| v[k].as_str().map(String::from);
    match (field("user"), field("password")) {
        (Some(u), Some(p)) => Ok(Some((u, p))),
        _ => Err(format!("the vault's {SECRET} holds no user and password").into()),
    }
}

/// Whether the nodes are set up to shut down, said in a line — and who NUT sees signed
/// in, which is the proof.
pub async fn describe(state: &State, policy: &UpsPolicy) -> Result<String> {
    if state.secret(SECRET).await?.is_none() {
        return Ok("  No machine shuts down at low battery through Homelabus \
                   (--shutdown-user sets NUT's upsmon on every node)."
            .into());
    }
    let Some(server) = &policy.server else {
        return Ok("  The nodes' upsmon is set, and no UPS is read.".into());
    };
    Ok(match power::clients(server, &policy.ups).await {
        Ok(c) if c.is_empty() => "⚠️ The nodes' upsmon is set, and NUT lists no machine \
                                  signed in: none would shut down."
            .into(),
        Ok(c) => format!(
            "  Shut down at low battery by NUT's upsmon; signed in: {}.",
            c.join(", ")
        ),
        Err(e) => format!("⚠️ Who is signed in to the UPS was not read: {e}."),
    })
}

/// Sets up, again, or removes each node's `upsmon`.
pub async fn run(
    cli: &Cli,
    state: &State,
    policy: &UpsPolicy,
    what: Shutdown<'_>,
    only: Option<&str>,
    apply: bool,
) -> Result<ExitCode> {
    let vault = open_vault(cli)?;
    let monitor = match what {
        Shutdown::Remove => None,
        Shutdown::Set(user) => {
            println!("Password of {user} in the NUT server's upsd.users (standard input):");
            let mut password = String::new();
            std::io::stdin().read_line(&mut password)?;
            Some((
                user.to_string(),
                password.trim_end_matches(['\r', '\n']).to_string(),
            ))
        }
        Shutdown::Again => match account(state, &vault).await? {
            Some(a) => Some(a),
            None => {
                eprintln!("🔴 No NUT account is kept: --shutdown-user <name> sets one.");
                return Ok(ExitCode::FAILURE);
            }
        },
    };
    let monitor = match monitor {
        None => None,
        Some((user, password)) => {
            let Some(server) = policy.server.clone() else {
                eprintln!("🔴 No UPS is read: --server first, the nodes sign in to it.");
                return Ok(ExitCode::FAILURE);
            };
            // 🔴 Proved before a node is touched: a wrong account written on every node
            // is a house where no machine shuts down, and nothing says so.
            if let Err(e) = power::check_login(&server, &policy.ups, &user, &password).await {
                eprintln!("🔴 {e}.");
                return Ok(ExitCode::FAILURE);
            }
            println!("✓ NUT lets {user} sign in to {} on {server}.", policy.ups);
            Some(Monitor {
                server,
                ups: policy.ups.clone(),
                user,
                password,
            })
        }
    };

    let orch = SwarmOrchestrator::connect().await?;
    let all: Vec<_> = orch
        .nodes()
        .await?
        .into_iter()
        .filter(|n| only.is_none_or(|o| o == n.hostname))
        .collect();
    let mut refused = 0;
    let mut nodes = Vec::new();
    for n in all {
        // 🔴 One machine off must not keep the others from shutting down at low battery:
        // reaching it failed the whole command (the lab's powered-off VMs, 2026-11-08).
        if n.status == "ready" {
            nodes.push(n.hostname);
        } else {
            println!(
                "\n{}: 🔴 {} — `hlb config ups --shutdown --node {}` once it is back.",
                n.hostname, n.status, n.hostname
            );
            refused += 1;
        }
    }
    if nodes.is_empty() && refused == 0 {
        eprintln!(
            "🔴 No node {} in the cluster — see `hlb cluster status`.",
            only.unwrap_or("at all")
        );
        return Ok(ExitCode::FAILURE);
    }
    let dir = tempfile::tempdir()?;
    let mut planned = Vec::new();
    for host in &nodes {
        let Some(runner) =
            crate::reach_node(state, &vault, host, None, None, None, dir.path()).await?
        else {
            println!(
                "\n{host}: 🔴 no SSH address recorded — `hlb config ups --node {host}` from it."
            );
            refused += 1;
            continue;
        };
        let plan = match node_plan(runner.as_ref(), monitor.as_ref()).await {
            Ok(plan) => plan,
            Err(e) => Err(format!("not reached: {e}")),
        };
        match plan {
            Ok(p) if p.is_empty() => println!("\n{host}: nothing of Homelabus's here."),
            Ok(p) => {
                println!("\n{host}:");
                for s in &p.steps {
                    println!("  · {}", s.describe());
                }
                planned.push((host.clone(), runner, p));
            }
            Err(why) => {
                println!("\n{host}: ⚠️ left alone — {why}.");
                refused += 1;
            }
        }
    }
    if !apply {
        println!("\nRerun with --apply.");
        return Ok(ExitCode::SUCCESS);
    }

    if let Some(m) = &monitor {
        let ct = vault
            .encrypt(&serde_json::json!({ "user": m.user, "password": m.password }).to_string())?;
        let purpose = "the NUT account every node's upsmon signs in with";
        if !state.store_secret_if_absent(SECRET, &ct, purpose).await? {
            state.rotate_secret(SECRET, &ct).await?;
        }
    }
    let mut failed = 0;
    for (host, runner, p) in &planned {
        let done = match provision::execute(runner.as_ref(), p, |_| {}).await {
            Ok(()) if monitor.is_some() => running(runner.as_ref()).await,
            Ok(()) => Ok(()),
            Err(e) => Err(e.to_string()),
        };
        let (outcome, detail) = match &done {
            Ok(()) if monitor.is_some() => ("ok", "upsmon runs, a secondary of the UPS"),
            Ok(()) => ("ok", "upsmon removed"),
            Err(e) => ("failed", e.as_str()),
        };
        state
            .audit(
                "cli",
                ACTOR_ROLE,
                "config-ups-shutdown",
                host,
                outcome,
                Some(detail),
            )
            .await?;
        match done {
            Ok(()) => println!("✓ {host}: {detail}."),
            Err(e) => {
                eprintln!("🔴 {host}: {e}");
                failed += 1;
            }
        }
    }
    // A node left alone keeps its upsmon, and the account it signs in with.
    if what == Shutdown::Remove && only.is_none() && failed + refused == 0 {
        state.forget_secret(SECRET).await?;
    }
    if monitor.is_some() {
        // upsmon signs in within its first poll.
        tokio::time::sleep(std::time::Duration::from_secs(6)).await;
        println!("{}", describe(state, policy).await?);
    }
    Ok(if failed + refused == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

/// What to run on one node, or why it is left alone. `monitor` `None`: the removal,
/// only where Homelabus wrote.
async fn node_plan(
    runner: &dyn Runner,
    monitor: Option<&Monitor>,
) -> Result<std::result::Result<Provision, String>> {
    let nut_conf = runner.read_file(nut::NUT_CONF).await?;
    let upsmon_conf = runner.read_file(nut::UPSMON_CONF).await?;
    let Some(m) = monitor else {
        let ours = [&nut_conf, &upsmon_conf]
            .iter()
            .any(|c| c.as_deref().is_some_and(|c| c.starts_with(nut::MARK)));
        let written = upsmon_conf.is_some() || nut::mode(nut_conf.as_deref()) != "none";
        return Ok(Ok(if ours && written {
            nut::unplan()
        } else {
            Provision::default()
        }));
    };
    let Some(distro) = runner
        .read_file("/etc/os-release")
        .await?
        .as_deref()
        .and_then(Distro::parse)
    else {
        return Ok(Err("its distribution was not recognised".into()));
    };
    Ok(
        match nut::refusal(&distro, nut_conf.as_deref(), upsmon_conf.as_deref()) {
            Some(why) => Err(why),
            None => Ok(nut::plan(&distro, m)),
        },
    )
}

/// `upsmon` runs once started: a file it refuses stops it at once.
async fn running(runner: &dyn Runner) -> std::result::Result<(), String> {
    let out = runner
        .run(&["systemctl".into(), "is-active".into(), nut::UNIT.into()])
        .await
        .map_err(|e| e.to_string())?;
    if out.stdout.trim() == "active" {
        Ok(())
    } else {
        Err(format!(
            "{} is {} — `journalctl -u {}` says why",
            nut::UNIT,
            out.stdout.trim(),
            nut::UNIT
        ))
    }
}
