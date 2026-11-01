//! `hlb user device`: a person's devices, one password each for their mailbox — mail,
//! calendars and contacts on a phone, which cannot sign in with a passkey.
//!
//! The rules are `hlb_engine::devices`, which the privileged daemon answers the
//! interface with: this is the same plan, said in a terminal. Run as root, it takes no
//! passkey — the interface asks for one because its session could be someone else's.

use std::process::ExitCode;

use hlb_api::{ActionResult, StepState};
use hlb_mail::Stalwart;
use hlb_state::State;

use crate::{DeviceCmd, ACTOR_ROLE};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub async fn run(state: &State, mail: Option<&Stalwart>, cmd: &DeviceCmd) -> Result<ExitCode> {
    match cmd {
        DeviceCmd::List { name } => {
            let asked = hlb_api::intent::Devices {
                account: name.clone(),
            };
            let devices = match hlb_engine::devices::devices(state, mail, asked).await {
                Ok(d) => d,
                Err(why) => {
                    // Never "no device": a list nobody read may hide a password still open.
                    eprintln!("🔴 {name}'s devices could not be read — {why}");
                    return Ok(ExitCode::FAILURE);
                }
            };
            if devices.is_empty() {
                println!("No device of {name} has a password.");
                return Ok(ExitCode::SUCCESS);
            }
            println!("{:<10} {:<28} {:<22} NAME", "ID", "MAILBOX", "MADE");
            for d in &devices {
                println!(
                    "{:<10} {:<28} {:<22} {}",
                    d.id,
                    d.mailbox,
                    d.created_at.as_deref().unwrap_or("-"),
                    d.name
                );
            }
            println!("\nRevoke:  hlb user device revoke {name} <MAILBOX> <ID> --apply");
            Ok(ExitCode::SUCCESS)
        }
        DeviceCmd::Add {
            name,
            device,
            mailbox,
            apply,
        } => {
            let asked = hlb_api::intent::AddDevice {
                account: Some(name.clone()),
                name: device.clone(),
                mailbox: mailbox.clone(),
                apply: *apply,
            };
            let made = hlb_engine::devices::add_device(state, mail, asked).await;
            say(&made.result);
            // The result alone: `setup` carries the password, which no log holds.
            audit(state, "device-add", name, &made.result).await?;
            if let Some(s) = &made.setup {
                println!("\nShown once — set the device up now:");
                println!("  server    {}", s.server);
                println!("  user      {}", s.user);
                println!("  password  {}", s.password);
                println!(
                    "\nCalendars and contacts: https://{} (CalDAV, CardDAV). Mail: IMAP on \
                     port 993, SMTP on 465, both TLS.",
                    s.server
                );
            }
            Ok(exit(&made.result))
        }
        DeviceCmd::Revoke {
            name,
            mailbox,
            id,
            apply,
        } => {
            let asked = hlb_api::intent::RevokeDevice {
                account: Some(name.clone()),
                mailbox: mailbox.clone(),
                id: id.clone(),
                apply: *apply,
            };
            let r = match hlb_engine::devices::revoke_device(state, mail, asked).await {
                hlb_api::intent::Acted::Planned(r) => r,
                hlb_api::intent::Acted::Unplannable(why) => {
                    eprintln!("🔴 {why}");
                    return Ok(ExitCode::FAILURE);
                }
            };
            say(&r);
            audit(state, "device-revoke", name, &r).await?;
            Ok(exit(&r))
        }
    }
}

/// The plan, its refusals and how it went, as the interface's panel shows them.
fn say(r: &ActionResult) {
    if !r.applied && r.blockers.is_empty() {
        println!("Preview — {}", r.summary);
    }
    for s in &r.steps {
        let mark = match s.state {
            StepState::Planned => "·",
            StepState::Done => "✓",
            StepState::Failed => "✗",
            StepState::Unimplemented => "⚠️",
        };
        println!("{mark} {}", s.description);
        if let Some(e) = &s.error {
            println!("    {e}");
        }
    }
    for b in &r.blockers {
        eprintln!("🔴 {b}");
    }
    for w in &r.warnings {
        println!("⚠️ {w}");
    }
    if !r.applied && r.blockers.is_empty() {
        println!("\nRe-run with --apply to apply it.");
    }
}

/// A preview is logged too, as `preview`: knowing someone looked is information.
async fn audit(state: &State, action: &str, name: &str, r: &ActionResult) -> Result<()> {
    let outcome = if !r.applied {
        "preview"
    } else if r.succeeded() {
        "ok"
    } else {
        "failed"
    };
    state
        .audit("cli", ACTOR_ROLE, action, name, outcome, Some(&r.verdict()))
        .await?;
    Ok(())
}

fn exit(r: &ActionResult) -> ExitCode {
    if r.blockers.is_empty() && (!r.applied || r.succeeded()) {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
