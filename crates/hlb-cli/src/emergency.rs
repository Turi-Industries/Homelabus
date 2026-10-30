//! `hlb emergency`: the emergency vault (`hlb_engine::emergency`), the printed kit
//! (`hlb_backup_run::kit`) and its split among relatives (`hlb_secrets::split`).

use std::io::{BufRead, Write};
use std::path::Path;
use std::process::ExitCode;

use hlb_api::breakglass::{EMERGENCY_KIT, FAMILY_KIT, FAMILY_REHEARSAL};
use hlb_bitwarden::emergency::Verdict;
use hlb_engine::emergency::{EmergencyVault, Report};
use hlb_engine::roles::Outcome;

use crate::{open_state, open_vault, relay, Cli, EmergencyCmd, ACTOR_ROLE};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub async fn run(cli: &Cli, cmd: &EmergencyCmd) -> Result<ExitCode> {
    match cmd {
        EmergencyCmd::Vault { address, apply } => vault(cli, address.as_deref(), *apply).await,
        EmergencyCmd::Kit { out, sealed } => kit(cli, out.as_deref(), *sealed).await,
        EmergencyCmd::Split {
            threshold,
            shares,
            out,
            replace,
        } => split(cli, *threshold, *shares, out, *replace).await,
        EmergencyCmd::Combine { kit, out } => combine(kit.as_deref(), out.as_deref()),
        EmergencyCmd::Rehearsed { code } => rehearsed(cli, code).await,
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

async fn kit(cli: &Cli, out: Option<&Path>, sealed: bool) -> Result<ExitCode> {
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
    let split = match (sealed, hlb_backup_run::kit::split(&state, &vault).await?) {
        (false, _) => None,
        (true, Some(split)) => Some(split),
        (true, None) => {
            eprintln!(
                "🔴 No split to seal the kit to: `hlb emergency split --out <dir>` makes \
                 one, a share for each relative."
            );
            return Ok(ExitCode::FAILURE);
        }
    };
    let kit = hlb_backup_run::kit::read(&state, &vault).await?;
    let printed = chrono::Utc::now().format("%Y-%m-%d %H:%M UTC").to_string();
    let mut sheet = hlb_backup_run::kit::render(&kit, &state.brand().await?.name, &printed);
    if let Some(split) = &split {
        let code = hlb_backup_run::kit::rehearsal_code(&state, &vault).await?;
        let sealed = hlb_backup_run::kit::render_sealed(&sheet, &code);
        sheet = hlb_secrets::split::seal(&sealed, &split.recipient)?;
    }
    hand_over(&state, &kit.fingerprint, &sheet, out).await?;
    if split.is_some() {
        state
            .attest_breakglass(
                FAMILY_KIT,
                "hlb emergency kit --sealed",
                Some(&kit.fingerprint),
            )
            .await?;
    }
    match (out, &split) {
        (Some(path), None) => println!(
            "The kit is in {} (fingerprint {}): print it, keep the sheet away from \
             the cluster, and delete the file.",
            path.display(),
            kit.fingerprint
        ),
        (Some(path), Some(split)) => println!(
            "The kit is in {}, sealed to split {} (fingerprint {}): send it to each \
             holder of a share, in place of the one they have. Their shares stay as \
             they are.",
            path.display(),
            split.id(),
            kit.fingerprint
        ),
        (None, _) => {}
    }
    Ok(ExitCode::SUCCESS)
}

async fn split(cli: &Cli, threshold: u8, count: u8, out: &Path, replace: bool) -> Result<ExitCode> {
    let state = open_state(cli).await?;
    let vault = open_vault(cli)?;
    if let Some(old) = hlb_backup_run::kit::split(&state, &vault).await? {
        if !replace {
            eprintln!(
                "🔴 Split {} ({} of {}) exists, its shares with your relatives. \
                 --replace makes a new one: the old shares still open every kit already \
                 sealed to them — paper cannot be revoked — and no kit sealed from now on.",
                old.id(),
                old.threshold,
                old.count
            );
            return Ok(ExitCode::FAILURE);
        }
    }
    if out.exists() {
        eprintln!(
            "🔴 {} exists: the shares go into a new directory, never among other files.",
            out.display()
        );
        return Ok(ExitCode::FAILURE);
    }
    let made = hlb_secrets::split::split(threshold, count)?;
    let record = hlb_backup_run::kit::SplitRecord {
        recipient: made.recipient.clone(),
        threshold,
        count,
    };
    let installation = state.brand().await?.name;
    let kit = hlb_backup_run::kit::read(&state, &vault).await?;
    let printed = chrono::Utc::now().format("%Y-%m-%d %H:%M UTC").to_string();
    let sheet = hlb_backup_run::kit::render(&kit, &installation, &printed);
    let code = hlb_secrets::split::draw_code();
    let sealed = hlb_backup_run::kit::render_sealed(&sheet, &code);
    let sealed = hlb_secrets::split::seal(&sealed, &made.recipient)?;
    // Recorded before anything is written, as the kit is.
    state
        .audit(
            "cli",
            ACTOR_ROLE,
            "emergency-split",
            &record.id(),
            "ok",
            Some(&format!("{threshold} of {count}")),
        )
        .await?;
    let mut dir = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        dir.mode(0o700);
    }
    dir.create(out)?;
    for share in &made.shares {
        let sheet = hlb_backup_run::kit::render_share(share, &installation, &printed);
        write_private(&out.join(format!("share-{}.txt", share.index())), &sheet)?;
    }
    write_private(&out.join("kit.age"), &sealed)?;
    // 🔴 Recorded once every sheet exists: recorded first, a write that failed would
    // leave the kit sealed from then on to shares nobody holds.
    hlb_backup_run::kit::record_split(&state, &vault, &record).await?;
    hlb_backup_run::kit::set_rehearsal_code(&state, &vault, &code).await?;
    // New shares were never rehearsed, whatever the old ones were.
    state.forget_breakglass(FAMILY_REHEARSAL).await?;
    // The sealed kit holds today's material, and opens without the owner.
    for id in [EMERGENCY_KIT, FAMILY_KIT] {
        state
            .attest_breakglass(id, "hlb emergency split", Some(&kit.fingerprint))
            .await?;
    }
    println!(
        "Split {}: any {threshold} of {count} shares open the kit. In {}:",
        record.id(),
        out.display()
    );
    let shares = format!("share-1.txt … share-{count}.txt");
    println!("  {shares:<28} one printed sheet per relative");
    println!(
        "  {:<28} the sealed kit, sent to every one of them",
        "kit.age"
    );
    println!("Then delete the directory. After any change to the kit, send them");
    println!("`hlb emergency kit --sealed --out kit.age`; their shares stay as they are.");
    Ok(ExitCode::SUCCESS)
}

async fn rehearsed(cli: &Cli, code: &str) -> Result<ExitCode> {
    let state = open_state(cli).await?;
    let vault = open_vault(cli)?;
    let Some(split) = hlb_backup_run::kit::split(&state, &vault).await? else {
        eprintln!(
            "🔴 No split: there is no family to have rehearsed. `hlb emergency split` first."
        );
        return Ok(ExitCode::FAILURE);
    };
    let proved = hlb_backup_run::kit::redeem_rehearsal(&state, &vault, code).await?;
    // Recorded either way: a wrong code is someone trying to paint the safeguard green.
    state
        .audit(
            "cli",
            ACTOR_ROLE,
            "emergency-rehearsed",
            &split.id(),
            if proved { "ok" } else { "failed" },
            None,
        )
        .await?;
    if !proved {
        eprintln!(
            "🔴 Not the rehearsal code waiting for split {}: mistyped, given already, or \
             read off a kit sealed to an earlier split. Send the family `hlb emergency kit \
             --sealed` again and read the code at the end of the kit they open.",
            split.id()
        );
        return Ok(ExitCode::FAILURE);
    }
    state
        .attest_breakglass(
            FAMILY_REHEARSAL,
            "hlb emergency rehearsed",
            Some(&split.id()),
        )
        .await?;
    println!(
        "Recorded: the family opened the kit of split {} without you. The code is burned; \
         the next kit you seal carries a new one, for next year.",
        split.id()
    );
    Ok(ExitCode::SUCCESS)
}

/// Needs no state and no vault: run by relatives, on whatever machine they have.
fn combine(kit: Option<&Path>, out: Option<&Path>) -> Result<ExitCode> {
    if let Some(path) = out {
        if path.exists() {
            eprintln!(
                "🔴 {} exists: the kit is never written over a file.",
                path.display()
            );
            return Ok(ExitCode::FAILURE);
        }
    }
    // Read before the shares are typed: a wrong path is said before anyone types 78
    // letters three times.
    let sealed = kit.map(std::fs::read_to_string).transpose()?;
    eprintln!("Type each share as printed, then an empty line after the last:");
    let mut lines = Vec::new();
    for line in std::io::stdin().lock().lines() {
        let line = line?;
        match (line.trim().is_empty(), lines.is_empty()) {
            (true, true) => continue,
            (true, false) => break,
            (false, _) => lines.push(line),
        }
    }
    let shares = hlb_secrets::split::gather(&lines);
    let key = match hlb_secrets::split::combine(&shares) {
        Ok(key) => key,
        Err(e) => {
            eprintln!("🔴 {e}");
            return Ok(ExitCode::FAILURE);
        }
    };
    let Some(sealed) = sealed else {
        println!(
            "These {} shares open split {}.",
            shares.len(),
            key.split_id()
        );
        return Ok(ExitCode::SUCCESS);
    };
    let plain = match key.open(&sealed) {
        Ok(plain) => plain,
        Err(e) => {
            eprintln!("🔴 {e} — is it the kit sealed to split {}?", key.split_id());
            return Ok(ExitCode::FAILURE);
        }
    };
    match out {
        None => print!("{plain}"),
        Some(path) => {
            write_private(path, &plain)?;
            println!(
                "The kit is in {}, readable by you only: the sheet says what to do.",
                path.display()
            );
        }
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
