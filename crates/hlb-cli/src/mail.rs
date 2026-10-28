//! `hlb mail`: what the house's mail needs outside it (`hlb_engine::mail_dns`).

use std::process::ExitCode;

use hlb_api::mail_dns::RecordState;

use hlb_engine::mail_relay::{self, Relay};
use hlb_orchestrator::{Orchestrator, SwarmOrchestrator};

use crate::{open_state, relay, Cli, MailCmd, RelayCmd, ACTOR_ROLE};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub async fn run(cli: &Cli, cmd: &MailCmd) -> Result<ExitCode> {
    let state = open_state(cli).await?;
    let (Some(url), Some(user), Some(password)) = (
        &cli.stalwart_url,
        &cli.stalwart_admin,
        &cli.stalwart_password,
    ) else {
        eprintln!("No Stalwart: `hlb install stalwart --apply` first.");
        return Ok(ExitCode::FAILURE);
    };
    let mail = hlb_mail::Stalwart::new(
        relay::reach(url, &cli.platform_network),
        hlb_mail::Auth::Basic {
            user: user.clone(),
            password: password.clone(),
        },
    );
    match cmd {
        MailCmd::Dns { domain } => dns(&state, &mail, domain.as_deref()).await,
        MailCmd::Relay { action } => relay_cmd(cli, &state, &mail, action.as_ref()).await,
        MailCmd::Queue => queue(&state, &mail).await,
        MailCmd::Migrate { apply } => migrate(cli, &state, *apply).await,
    }
}

async fn relay_cmd(
    cli: &Cli,
    state: &hlb_state::State,
    mail: &hlb_mail::Stalwart,
    action: Option<&RelayCmd>,
) -> Result<ExitCode> {
    match action {
        None => {
            match mail_relay::current(mail).await? {
                Some(r) => println!(
                    "Remote mail leaves through {}:{} ({}), as {}.",
                    r.host,
                    r.port,
                    if r.implicit_tls {
                        "TLS"
                    } else {
                        "STARTTLS, required"
                    },
                    r.user
                ),
                None => println!("Remote mail leaves by each domain's MX, from Stalwart's node."),
            }
            if let Some(t) = state.mail_relay_spf().await? {
                println!("The domain's SPF must name {t}: `hlb mail dns` reads it.");
            }
            match SwarmOrchestrator::connect().await {
                Ok(orch) => {
                    let job = mail_relay::port25_job(&cli.platform_network);
                    match orch.run_job(&job, 60).await {
                        Ok(o) if o.succeeded => {
                            println!("✓ Stalwart's node reaches port 25 of the internet.")
                        }
                        Ok(_) => println!(
                            "🔴 Stalwart's node does not reach port 25 of the internet: without a \
                             relay, mail to other domains waits in the queue and bounces in days.\n   \
                             hlb mail relay set --host <provider> --user <account> --apply"
                        ),
                        Err(e) => println!("? Port 25 not tried: {e}"),
                    }
                }
                Err(e) => println!("? Port 25 not tried — no Swarm here: {e}"),
            }
            Ok(ExitCode::SUCCESS)
        }
        Some(RelayCmd::Remove { apply }) => {
            let Some(r) = mail_relay::current(mail).await? else {
                println!("No relay: remote mail already leaves by each domain's MX.");
                return Ok(ExitCode::SUCCESS);
            };
            if !apply {
                println!(
                    "Would send remote mail by each domain's MX again, no longer through {}.",
                    r.host
                );
                println!("\nRe-run with --apply to make it so.");
                return Ok(ExitCode::SUCCESS);
            }
            mail_relay::remove(mail).await?;
            state
                .forget_secret(mail_relay::FORMER_PASSWORD_SECRET)
                .await?;
            state.set_mail_relay_spf(None).await?;
            state
                .audit("cli", ACTOR_ROLE, "mail-relay-remove", &r.host, "ok", None)
                .await?;
            println!("✓ Remote mail leaves by each domain's MX again.");
            Ok(ExitCode::SUCCESS)
        }
        Some(RelayCmd::Set {
            host,
            port,
            implicit_tls,
            user,
            spf,
            apply,
        }) => {
            let r = Relay {
                host: host.clone(),
                port: *port,
                implicit_tls: *implicit_tls,
                user: user.clone(),
            };
            println!(
                "Every remote domain through {}:{} ({}), as {}; TLS required and its \
                 certificate verified, no fallback.",
                r.host,
                r.port,
                if r.implicit_tls { "TLS" } else { "STARTTLS" },
                r.user
            );
            if let Some(t) = spf {
                println!("The domain's SPF must then name {t}.");
            }
            if !apply {
                println!(
                    "\nRe-run with --apply: the account's password is read on standard input, \
                     tried on the relay, then written."
                );
                return Ok(ExitCode::SUCCESS);
            }
            // 🔴 Read on standard input, never as an argument: a password on a command
            // line stays in the shell's history and in every `ps` while it runs.
            eprintln!("The relay account's password (standard input, Ctrl-D to finish):");
            let mut password = String::new();
            std::io::Read::read_to_string(&mut std::io::stdin(), &mut password)?;
            let password = password.trim();
            if password.is_empty() {
                eprintln!("No password given — nothing was done.");
                return Ok(ExitCode::FAILURE);
            }
            let orch = SwarmOrchestrator::connect().await?;
            let roots = hlb_engine::submission::trusted_roots(state).await?;
            let job = mail_relay::trial_job(&r, password, &cli.platform_network, &roots);
            if let Err(why) = hlb_engine::submission::try_account(&orch, &job).await {
                eprintln!("🔴 The relay did not take the account — nothing was written:\n{why}");
                return Ok(ExitCode::FAILURE);
            }
            // Stalwart keeps the password it signs in with; no copy goes to the vault,
            // where nothing would read it.
            mail_relay::apply(mail, &r, password).await?;
            state
                .forget_secret(mail_relay::FORMER_PASSWORD_SECRET)
                .await?;
            state.set_mail_relay_spf(spf.as_deref()).await?;
            state
                .audit("cli", ACTOR_ROLE, "mail-relay-set", &r.host, "ok", None)
                .await?;
            println!("✓ Remote mail leaves through {} now.", r.host);
            if spf.is_some() {
                println!("  `hlb mail dns` says whether the domain's SPF names it.");
            }
            Ok(ExitCode::SUCCESS)
        }
    }
}

async fn dns(
    state: &hlb_state::State,
    mail: &hlb_mail::Stalwart,
    only: Option<&str>,
) -> Result<ExitCode> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    let dns = hlb_mail::public_dns::PublicDns::default();
    let ports = hlb_engine::mail_dns::served_ports(state).await?;
    let reading = hlb_engine::mail_dns::read(
        mail,
        &dns,
        state.mail_relay_spf().await?.as_deref(),
        &ports,
        now,
    )
    .await?;
    // Recorded whole, every domain: the inbox reads what was found now.
    state.record_mail_records(&reading.records).await?;
    if let Ok(tags) = &reading.refused_blocklists {
        state.record_refused_blocklists(tags).await?;
    }

    let mut domains: Vec<&str> = reading.records.iter().map(|r| r.domain.as_str()).collect();
    domains.dedup();
    if let Some(d) = only {
        if !domains.contains(&d) {
            eprintln!(
                "Stalwart hosts no domain {d}: it hosts {}.",
                domains.join(", ")
            );
            return Ok(ExitCode::FAILURE);
        }
        domains.retain(|x| *x == d);
    }
    if domains.is_empty() {
        eprintln!("Stalwart hosts no domain yet: the first mailbox makes one.");
        return Ok(ExitCode::FAILURE);
    }
    let publishing = mail.domains_dns().await?;
    let servers = mail.dns_servers().await?;
    let generation = mail.generation().await?;
    let provider = state.exposure().await?.and_then(|e| e.dns_provider);
    let mut wrong = Vec::new();
    for d in &domains {
        println!("{d} — as the internet resolves it");
        let by = publishing
            .iter()
            .find(|p| p.name == *d)
            .and_then(|p| p.published_by.as_ref())
            .filter(|(_, records)| records.iter().any(|r| r == "dkim"))
            .and_then(|(id, _)| servers.iter().find(|s| s.id == *id));
        match (by, provider.as_deref()) {
            (Some(s), _) => println!(
                "  DKIM published and rotated by Stalwart, through {}",
                s.kind
            ),
            (None, Some(p)) => {
                match hlb_engine::mail_dns::stalwart_dns_server(p, &[], generation) {
                    Ok(_) => println!(
                        "  DKIM by hand until the next role pass publishes it through {p}: \
                     hlb role sync --apply"
                    ),
                    Err(why) => println!("  DKIM by hand: {why}"),
                }
            }
            (None, None) => println!(
                "  DKIM by hand: the exposure names no DNS provider Stalwart could publish \
                 through, and keys are never rotated"
            ),
        }
        for r in reading.records.iter().filter(|r| r.domain == *d) {
            let mark = match r.state {
                RecordState::Published => "✓",
                RecordState::Missing | RecordState::Differs => {
                    wrong.push(r);
                    "🔴"
                }
                RecordState::Unreadable => "?",
            };
            println!(
                "  {mark} {:<5} {}  ({}: {})",
                r.purpose.as_str(),
                r.name,
                r.state.as_str(),
                r.observed
            );
        }
        let optional: Vec<&String> = reading
            .optional
            .iter()
            .filter(|(od, _)| od == d)
            .map(|(_, l)| l)
            .collect();
        if !optional.is_empty() {
            println!("\n  Also useful, not read — mail clients' discovery, TLS reports:");
            for l in optional {
                println!("    {l}");
            }
        }
        println!();
    }
    if reading.unserved > 0 {
        println!(
            "  {} more of Stalwart's lines left out: names the ingress does not route, \
             ports nothing forwards, and what Stalwart keeps in step only when it \
             publishes itself — a TLSA pinning today's key, a CAA binding every name to \
             its ACME account.\n",
            reading.unserved
        );
    }
    // Port 25 is verified by some senders — Stalwart's own defaults —, which then retry
    // minutes later accepting any certificate: no mail is lost, each waits.
    if let Some(e) = state.exposure().await? {
        if e.certificates == hlb_state::Certificates::Internal {
            println!(
                "⚠️ Port 25 presents a certificate under Homelabus's own root, which no \
                 sender trusts: one that verifies retries minutes later without verifying. \
                 A certificate the internet trusts needs an ACME exposure.\n"
            );
        }
    }
    // Not a record and not a failure: mail flows, its spam filter is only blinder.
    match &reading.refused_blocklists {
        Ok(tags) if tags.is_empty() => {
            println!("✓ The spam filter's blocklists answer Stalwart's resolver.\n")
        }
        Ok(tags) => println!(
            "⚠️ The spam filter's blocklists refuse the resolver Stalwart asks through, so \
             they check nothing: {}.\n   They refuse public resolvers (1.1.1.1, 8.8.8.8, \
             9.9.9.9) and busy ones — an ISP's too, for some. Stalwart's own resolver \
             answers them: hlb upgrade stalwart --apply deploys it, hlb role sync --apply \
             points Stalwart at it.\n",
            tags.join(", ")
        ),
        Err(why) => println!("? The spam filter's blocklists could not be probed: {why}\n"),
    }
    if wrong.is_empty() {
        println!("✓ Every record the house's mail needs is published.");
        return Ok(ExitCode::SUCCESS);
    }
    // The lines to add, as Stalwart computed them, ready to paste into a zone.
    eprintln!("🔴 To add at the DNS provider, or to correct:\n");
    for r in &wrong {
        eprintln!("{}", r.expected);
    }
    eprintln!(
        "\n⚠️ An SPF or a DMARC already there is the domain's: merge Stalwart's terms into \
         it rather than adding a second one — receivers treat two as none."
    );
    Ok(ExitCode::FAILURE)
}

async fn queue(state: &hlb_state::State, mail: &hlb_mail::Stalwart) -> Result<ExitCode> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    let (waiting, cut) = hlb_engine::mail_queue::read(mail, now).await?;
    // Recorded whole: the inbox reads what was found now.
    state.record_mail_queue(&waiting).await?;
    if waiting.is_empty() {
        println!("✓ Stalwart's queue is empty: every message was handed over.");
        return Ok(ExitCode::SUCCESS);
    }
    let date = |t: i64| {
        chrono::DateTime::from_timestamp(t, 0).map_or_else(
            || "?".into(),
            |d| d.format("%Y-%m-%d %H:%M UTC").to_string(),
        )
    };
    for w in &waiting {
        let minutes = (now - w.since).max(0) / 60;
        let waited = if minutes < 120 {
            format!("{minutes} min")
        } else {
            format!("{} h", minutes / 60)
        };
        println!(
            "{} {}  waiting {waited}, {} attempt{}, next {}",
            if w.late(now) { "🔴" } else { "·" },
            w.recipient,
            w.attempts,
            if w.attempts == 1 { "" } else { "s" },
            date(w.next_retry),
        );
        println!(
            "    last told: {}",
            w.error.as_deref().unwrap_or("nothing yet — not tried")
        );
        if let Some(t) = w.expires_at {
            println!("    bounced to its sender at {}", date(t));
        }
    }
    if cut {
        println!("\n⚠️ Stalwart answered part of its queue: more messages wait than are listed.");
    }
    if !waiting.iter().any(|w| w.late(now)) {
        return Ok(ExitCode::SUCCESS);
    }
    eprintln!(
        "\n🔴 Mail has waited over an hour. A refused connection to every domain is a line \
         closing port 25: `hlb mail relay` tries it, and sends through a provider instead."
    );
    Ok(ExitCode::FAILURE)
}

/// A whole first copy of a large store takes hours; the final pass only what changed
/// since, plus a comparison of every account.
const COPY_TIMEOUT_S: u64 = 6 * 3600;
const FINAL_TIMEOUT_S: u64 = 6 * 3600;

async fn migrate(cli: &Cli, state: &hlb_state::State, apply: bool) -> Result<ExitCode> {
    use hlb_engine::stalwart_migrate::{self as sm, Pass};
    let app = hlb_engine::submission::host();
    let catalog = hlb_catalog::Catalog::load(&cli.catalog)?;
    let entry = catalog.get(app)?;
    let frozen = state.app_manifest(app).await?;
    let [from, to, progress] = sm::volumes(app);
    let (was, will) = (&frozen.spec.image, &entry.manifest.spec.image);
    println!(
        "Stalwart {}:{} → {}:{}\n",
        was.repo, was.tag, will.repo, will.tag
    );
    let blockers = sm::blockers(&frozen, &entry.manifest);
    if !blockers.is_empty() {
        for b in &blockers {
            eprintln!("🔴 {b}");
        }
        eprintln!("   Nothing was changed.");
        return Ok(ExitCode::FAILURE);
    }
    println!(
        "  1. {from} copied into the new volume {to} while 0.16 serves (progress in {progress})"
    );
    println!(
        "  2. Stalwart stopped — senders keep their mail and retry — the last changes copied,"
    );
    println!("     the queue handed over, every account compared");
    println!("  3. the catalog's manifest frozen: 1.0 on {to}");
    println!("  {from} is opened read-only and kept: before 1.0 has served anyone, going back is");
    println!(
        "  starting 0.16 on it again. Users sign in to OAuth clients again; search is rebuilt."
    );

    let mut next = hlb_engine::upgrade::next(&frozen, &entry.manifest);
    next.spec.image = entry.manifest.spec.image.clone();
    let refused = hlb_engine::upgrade::refusals(&sm::after_copy(&frozen), &next);
    let again = "hlb mail migrate --apply";
    if !apply {
        return crate::switch_manifest(
            cli,
            state,
            app,
            &entry.guide,
            &frozen,
            &next,
            refused,
            None,
            false,
            "migrate",
            again,
        )
        .await;
    }
    if !refused.is_empty() {
        for r in &refused {
            eprintln!("🔴 {r}");
        }
        eprintln!("   Nothing was changed.");
        return Ok(ExitCode::FAILURE);
    }

    let orch = SwarmOrchestrator::connect().await?;
    println!("\n1/3 Copying while 0.16 serves…");
    if !pass_ok(sm::run(&orch, app, Pass::Copy, COPY_TIMEOUT_S).await?) {
        eprintln!("   Nothing was changed: 0.16 serves from {from}. `{again}` copies again.");
        return Ok(ExitCode::FAILURE);
    }

    let replicas = orch.status(app).await?.desired_replicas.max(1);
    let decided = state.app_replicas(app).await?;
    println!("2/3 Stopping Stalwart for the last changes…");
    orch.scale(app, 0).await?;
    // Kept in the state: in Swarm alone, reconciliation starts it again within a minute,
    // and the final pass stops on counters that moved.
    crate::remember_replicas(cli, app, 0).await?;
    for _ in 0..120 {
        if orch.status(app).await?.running_replicas == 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    let restart = || async {
        state.set_app_replicas(app, decided).await?;
        orch.scale(app, replicas).await?;
        Ok::<_, Box<dyn std::error::Error>>(())
    };
    if !pass_ok(sm::run(&orch, app, Pass::Final, FINAL_TIMEOUT_S).await?) {
        restart().await?;
        eprintln!("   0.16 serves again from {from}, as it was. `{again}` resumes the copy.");
        return Ok(ExitCode::FAILURE);
    }

    println!("3/3 Starting 1.0 on {to}…");
    state.set_app_replicas(app, decided).await?;
    let run = crate::switch_manifest(
        cli,
        state,
        app,
        &entry.guide,
        &frozen,
        &next,
        Vec::new(),
        None,
        true,
        "migrate",
        again,
    )
    .await?;
    state
        .audit(
            "cli",
            ACTOR_ROLE,
            "mail-migrate",
            app,
            if run == ExitCode::SUCCESS {
                "ok"
            } else {
                "failed"
            },
            Some(&format!("{from} → {to}")),
        )
        .await?;
    // Put back by the switch, nothing redeployed: 0.16 is still the one to run.
    if state.app_manifest(app).await?.spec.image == frozen.spec.image {
        restart().await?;
        eprintln!("   0.16 serves again from {from}.");
        return Ok(ExitCode::FAILURE);
    }
    // A client of its own: the generation is read once per client.
    if let (Some(url), Some(user), Some(password)) = (
        &cli.stalwart_url,
        &cli.stalwart_admin,
        &cli.stalwart_password,
    ) {
        let fresh = hlb_mail::Stalwart::new(
            relay::reach(url, &cli.platform_network),
            hlb_mail::Auth::Basic {
                user: user.clone(),
                password: password.clone(),
            },
        );
        match fresh.generation().await {
            Ok(hlb_mail::Generation::V1) => println!("✓ Stalwart answers as 1.0, from {to}."),
            Ok(hlb_mail::Generation::V016) => {
                eprintln!("🔴 Stalwart still answers as 0.16: its service did not switch.");
                return Ok(ExitCode::FAILURE);
            }
            Err(e) => eprintln!("? Stalwart not asked: {e}"),
        }
    }
    println!(
        "  {from} is kept. Remove it once 1.0 is trusted: `docker volume rm {from}` on its node."
    );
    Ok(run)
}

/// Says how a pass ended; true when it did.
fn pass_ok(outcome: hlb_engine::stalwart_migrate::Outcome) -> bool {
    use hlb_engine::stalwart_migrate::Outcome;
    match outcome {
        Outcome::Done(lines) => {
            if let Some(summary) = lines
                .iter()
                .rev()
                .find(|l| l.starts_with("verify:") || l.starts_with("run "))
            {
                println!("   {summary}");
            }
            true
        }
        Outcome::Questions(q) => {
            eprintln!(
                "🔴 The store asks what Homelabus does not answer for it — a person decides:"
            );
            for line in q {
                eprintln!("   {line}");
            }
            false
        }
        Outcome::Failed(lines) => {
            eprintln!("🔴 The pass failed:");
            for line in lines.iter().rev().take(15).rev() {
                eprintln!("   {line}");
            }
            false
        }
    }
}
