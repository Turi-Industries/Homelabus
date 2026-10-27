//! `hlb emergency`: the emergency vault (`hlb_engine::emergency`) and the printed kit
//! (`hlb_backup_run::kit`).

use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use hlb_api::breakglass::EMERGENCY_KIT;
use hlb_bitwarden::emergency::Verdict;
use hlb_engine::emergency::{EmergencyVault, Report};
use hlb_engine::roles::Outcome;

use crate::{open_state, open_vault, relay, Cli, EmergencyCmd, ACTOR_ROLE};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub async fn run(cli: &Cli, cmd: &EmergencyCmd) -> Result<ExitCode> {
    match cmd {
        EmergencyCmd::Vault { address, apply } => vault(cli, address.as_deref(), *apply).await,
        EmergencyCmd::Kit { out } => kit(cli, out.as_deref()).await,
    }
}

async fn vault(cli: &Cli, address: Option<&str>, apply: bool) -> Result<ExitCode> {
    let state = open_state(cli).await?;
    let vault = open_vault(cli)?;
    let network = cli.platform_network.clone();
    let reach = move |u: &str| relay::reach(u, &network);
    let r = EmergencyVault {
        state: &state,
        vault: &vault,
        reach: &reach,
        now: crate::now(),
    }
    .run(address, apply)
    .await?;
    print(&r, apply);
    let wrong = r
        .checks
        .iter()
        .any(|c| matches!(c.verdict, Verdict::Wrong(_)));
    // What reaches the vault — an account made, a deposit — is a person's decision.
    let done = r
        .lines
        .iter()
        .filter(|l| l.outcome == Outcome::Done)
        .count();
    if apply && (done > 0 || r.failed()) {
        state
            .audit(
                "cli",
                ACTOR_ROLE,
                "emergency-vault",
                r.app.as_deref().unwrap_or_default(),
                if r.failed() || wrong { "failed" } else { "ok" },
                Some(&hlb_api::plural(done as u64, "change", "changes")),
            )
            .await?;
    }
    Ok(if r.failed() || wrong {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    })
}

fn print(r: &Report, apply: bool) {
    if let Some(app) = &r.app {
        println!("The emergency vault, in {app}\n");
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
    if !r.checks.is_empty() {
        println!("\nWhat the account was given:");
    }
    for c in &r.checks {
        match &c.verdict {
            Verdict::Holds => println!("  ✓ {}", c.what),
            Verdict::Missing(how) => println!("  · {}\n      {how}", c.what),
            Verdict::Wrong(why) => println!("  🔴 {}\n      {why}", c.what),
        }
    }
    if r.unchanged > 0 {
        println!(
            "\n{} already as {} should be.",
            hlb_api::plural(r.unchanged as u64, "recovery sign-in", "recovery sign-ins"),
            if r.unchanged == 1 { "it" } else { "they" }
        );
    }
    for n in &r.notes {
        println!("⚠️  {n}");
    }
    if let Some(why) = &r.stopped {
        println!("\n{why}");
    } else if !apply && r.lines.iter().any(|l| l.outcome == Outcome::ToDo) {
        println!("\nRe-run with --apply to make it so.");
    }
}

async fn kit(cli: &Cli, out: Option<&Path>) -> Result<ExitCode> {
    let state = open_state(cli).await?;
    let vault = open_vault(cli)?;
    if let Some(path) = out {
        if path.exists() {
            eprintln!(
                "🔴 {} exists: a kit is never written over a file — a former kit there \
                 would be lost without anyone deciding it.",
                path.display()
            );
            return Ok(ExitCode::FAILURE);
        }
    }
    let kit = hlb_backup_run::kit::read(&state, &vault).await?;
    let printed = chrono::Utc::now().format("%Y-%m-%d %H:%M UTC").to_string();
    let sheet = hlb_backup_run::kit::render(&kit, &state.brand().await?.name, &printed);
    hand_over(&state, &kit.fingerprint, &sheet, out).await?;
    if let Some(path) = out {
        println!(
            "The kit is in {} (fingerprint {}): print it, keep the sheet away from \
             the cluster, and delete the file.",
            path.display(),
            kit.fingerprint
        );
    }
    Ok(ExitCode::SUCCESS)
}

/// Shows or writes the kit, recorded before and counted after.
async fn hand_over(
    state: &hlb_state::State,
    fingerprint: &str,
    sheet: &str,
    out: Option<&Path>,
) -> Result<()> {
    // Recorded BEFORE it is shown, like `secret-get`: a reading that leaves no trace is
    // the one an intruder with a shell would make. The fingerprint, never a value.
    state
        .audit("cli", ACTOR_ROLE, "emergency-kit", fingerprint, "ok", None)
        .await?;
    match out {
        None => print!("{sheet}"),
        Some(path) => write_private(path, sheet)?,
    }
    // 🔴 Counted only once it exists: attested before the write, a full disk or a
    // missing directory left the safeguard green over a kit nobody holds.
    state
        .attest_breakglass(EMERGENCY_KIT, "hlb emergency kit", Some(fingerprint))
        .await?;
    Ok(())
}

/// A file only its owner reads, created — never truncated.
fn write_private(path: &Path, content: &str) -> std::io::Result<()> {
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o.open(path)?.write_all(content.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_kit_that_could_not_be_written_is_not_counted() {
        // 🔴 Found by review: the kit was attested, then written — a write that failed
        // left the safeguard counting a kit that exists nowhere.
        let state = hlb_state::State::in_memory().await.expect("state");
        let nowhere = std::env::temp_dir()
            .join(format!("hlb-no-such-dir-{}", std::process::id()))
            .join("kit.txt");
        let r = hand_over(&state, "abc", "sheet", Some(&nowhere)).await;
        assert!(r.is_err());
        assert_eq!(
            state.breakglass_note(EMERGENCY_KIT).await.expect("read"),
            None
        );
        // The attempt is in the log all the same.
        assert_eq!(state.audit_trail(10).await.expect("log").len(), 1);

        let dir = std::env::temp_dir().join(format!("hlb-kit-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("kit.txt");
        let _ = std::fs::remove_file(&path);
        hand_over(&state, "abc", "sheet", Some(&path))
            .await
            .expect("written");
        assert_eq!(
            state
                .breakglass_note(EMERGENCY_KIT)
                .await
                .expect("read")
                .as_deref(),
            Some("abc")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
