//! `hlb site guard`: a house cut from its site stops its vital apps, and starts them
//! again once the link is back and the site was not promoted meanwhile.
//!
//! Run every 30 s by a systemd timer on the node holding the state and the vault (the
//! decision itself is `hlb_engine::site_guard`). Not by the controller: a watcher must
//! not depend on what it guards, and `hlb-privd` holds neither SSH nor `wg`.

use std::process::ExitCode;

use hlb_backup_run::restore;
use hlb_bootstrap::{LocalRunner, Runner};
use hlb_engine::site_guard::{self, Act, Held, Link};
use hlb_mesh::site;
use hlb_secrets::Vault;
use hlb_state::State;

use crate::{open_state, open_vault, Cli, ACTOR_ROLE};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// The seconds past a stale handshake before the house stops, as the owner set them.
pub async fn stop_after(state: &State) -> Result<u64> {
    Ok(state
        .site_link_stop_after()
        .await?
        .unwrap_or(site_guard::DEFAULT_STOP_AFTER_SECS))
}

/// This node's end of the link.
async fn local_link() -> Link {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default();
    let argv = [
        "wg".to_string(),
        "show".into(),
        site::INTERFACE.into(),
        "latest-handshakes".into(),
    ];
    let out = match LocalRunner.run(&argv).await {
        Ok(o) if o.ok() => Ok(o.stdout),
        Ok(o) => Err(o.stderr.trim().to_string()),
        Err(e) => Err(e.to_string()),
    };
    site_guard::reading(out.as_deref().map_err(Clone::clone), now)
}

fn says(link: &Link) -> String {
    match link {
        Link::Never => "no handshake since the link came up".into(),
        Link::Unread(e) => format!("the link cannot be read ({e})"),
        Link::Age(a) => format!("last handshake {a} s ago"),
    }
}

/// The carried services the guard holds, `(service, 0)`: [`restore::start`] gives each
/// the replicas its hold recorded.
async fn ours(state: &State) -> Result<Vec<(String, u64)>> {
    Ok(state
        .service_holds()
        .await?
        .into_iter()
        .filter(|h| h.why == site_guard::LINK_HOLD)
        .map(|h| (h.service, 0))
        .collect())
}

pub async fn run(cli: &Cli, apply: bool) -> Result<ExitCode> {
    let state = open_state(cli).await?;
    let vault = open_vault(cli)?;
    let Some(s) = super::load(&state, &vault).await? else {
        println!("The house has no site: nothing to guard.");
        return Ok(ExitCode::SUCCESS);
    };
    let delay = stop_after(&state).await?;
    let link = local_link().await;
    // No lifeboat, no promotion: stopping the house would leave nobody serving.
    if super::lifeboat::left_on_site(&state, &vault)
        .await?
        .is_empty()
    {
        println!(
            "{}: the lifeboat never ran on {}, so it serves nothing: nothing to guard.",
            says(&link),
            s.name
        );
        return Ok(ExitCode::SUCCESS);
    }
    let o = hlb_orchestrator::SwarmOrchestrator::connect().await?;
    let carried = super::promote::house_services(&o, &state, &vault).await?;
    if carried.is_empty() {
        println!("{}: no vital app at home to guard.", says(&link));
        return Ok(ExitCode::SUCCESS);
    }
    let names: Vec<String> = carried.iter().map(|(s, _)| s.clone()).collect();
    let holds: Vec<(String, String)> = state
        .service_holds()
        .await?
        .into_iter()
        .map(|h| (h.service, h.why))
        .collect();
    let held = site_guard::held(&holds, &names);
    let stops_at = site_guard::stops_at(delay);
    match (site_guard::decide(&link, delay, &held), &held) {
        (Act::Nothing, Held::Other(why)) => {
            println!(
                "{}; held stopped for \"{why}\": not the guard's.",
                says(&link)
            );
            Ok(ExitCode::SUCCESS)
        }
        (Act::Nothing, Held::ByGuard) => {
            println!(
                "{}: {} stay stopped until it handshakes afresh.",
                says(&link),
                names.join(", ")
            );
            Ok(ExitCode::SUCCESS)
        }
        (Act::Nothing, Held::Not) => {
            println!(
                "{}: {} serve; stopped once it is {stops_at} s old.",
                says(&link),
                names.join(", ")
            );
            Ok(ExitCode::SUCCESS)
        }
        (Act::Stop, _) if !apply => {
            println!(
                "{}: would stop {}, held until the link is back.",
                says(&link),
                names.join(", ")
            );
            Ok(ExitCode::SUCCESS)
        }
        (Act::Stop, _) => {
            let r = restore::stop_held(
                &o,
                &state,
                &carried,
                site_guard::LINK_HOLD,
                site_guard::LINK_HOLD_SECS,
            )
            .await;
            let detail = format!("{}; {}", says(&link), names.join(", "));
            let (outcome, code) = match &r {
                Ok(()) => {
                    println!(
                        "✓ {}: {} stopped, so a promoted {} is the only side written.",
                        says(&link),
                        names.join(", "),
                        s.name
                    );
                    ("ok", ExitCode::SUCCESS)
                }
                Err(e) => {
                    eprintln!("🔴 {}: stopping {}: {e}", says(&link), names.join(", "));
                    ("failed", ExitCode::FAILURE)
                }
            };
            state
                .audit(
                    "cli",
                    ACTOR_ROLE,
                    "site-guard-stop",
                    &s.name,
                    outcome,
                    Some(&detail),
                )
                .await?;
            Ok(code)
        }
        (Act::AskSite, _) => ask_site(&state, &vault, &o, &s, &link, apply).await,
    }
}

/// The link is back: started again unless the site serves them now.
async fn ask_site(
    state: &State,
    vault: &Vault,
    o: &hlb_orchestrator::SwarmOrchestrator,
    s: &site::Site,
    link: &Link,
    apply: bool,
) -> Result<ExitCode> {
    let held = ours(state).await?;
    let names: Vec<String> = held.iter().map(|(s, _)| s.clone()).collect();
    let promoted = match super::reach(state, vault, s).await {
        Ok((_key_dir, site)) => super::promote::since(site.as_ref())
            .await
            .map_err(|e| e.to_string()),
        Err(e) => Err(e.to_string()),
    };
    if !site_guard::start_again(&promoted) {
        match promoted {
            Ok(Some(since)) => println!(
                "{}: {} promoted since {since}, so {} stay stopped until `hlb site return`.",
                says(link),
                s.name,
                names.join(", ")
            ),
            Err(e) => eprintln!(
                "⚠️  {}, but {} does not say whether it was promoted ({e}): {} stay stopped.",
                says(link),
                s.name,
                names.join(", ")
            ),
            Ok(None) => {}
        }
        return Ok(ExitCode::SUCCESS);
    }
    if !apply {
        println!(
            "{}, {} not promoted: would start {} again.",
            says(link),
            s.name,
            names.join(", ")
        );
        return Ok(ExitCode::SUCCESS);
    }
    let r = restore::start(o, state, &held).await;
    let (outcome, code) = match &r {
        Ok(()) => {
            println!(
                "✓ {}, {} not promoted: {} started again.",
                says(link),
                s.name,
                names.join(", ")
            );
            ("ok", ExitCode::SUCCESS)
        }
        Err(e) => {
            eprintln!("🔴 starting {} again: {e}", names.join(", "));
            ("failed", ExitCode::FAILURE)
        }
    };
    state
        .audit(
            "cli",
            ACTOR_ROLE,
            "site-guard-start",
            &s.name,
            outcome,
            Some(&names.join(", ")),
        )
        .await?;
    Ok(code)
}

/// Where the guard's units are written, on the node holding the state.
fn unit_path(ext: &str) -> String {
    format!("/etc/systemd/system/{}.{ext}", site_guard::UNIT)
}

/// The guard's service and timer, running `exe site guard --apply` with these paths.
///
/// The vault's unit is wanted, not required: an unsealed house has none.
fn units(exe: &str, env: &[(&str, String)]) -> (String, String) {
    let env: String = env
        .iter()
        .map(|(k, v)| format!("Environment=\"{k}={v}\"\n"))
        .collect();
    let every = site_guard::GUARD_EVERY_SECS;
    let service = format!(
        "# Written by Homelabus (`hlb site sync`): the vital apps stopped while the link\n\
         # to the site is down, so a promoted site is the only side written.\n\
         [Unit]\n\
         Description=Homelabus: vital apps stopped while the site link is down\n\
         Wants=hlb-vault.service docker.service\n\
         After=hlb-vault.service docker.service\n\
         \n\
         [Service]\n\
         Type=oneshot\n\
         {env}ExecStart={exe} site guard --apply\n"
    );
    let timer = format!(
        "# Written by Homelabus (`hlb site sync`).\n\
         [Unit]\n\
         Description=Homelabus: the site link's guard, every {every} s\n\
         \n\
         [Timer]\n\
         OnBootSec={every}s\n\
         OnUnitActiveSec={every}s\n\
         AccuracySec=1s\n\
         \n\
         [Install]\n\
         WantedBy=timers.target\n"
    );
    (service, timer)
}

/// Puts the guard on this node, the one `hlb` runs on with the state and the vault —
/// the paths this run was given, made absolute.
pub async fn install(cli: &Cli) -> std::result::Result<(), String> {
    let abs = |p: &std::path::Path| {
        std::path::absolute(p)
            .map(|p| p.display().to_string())
            .map_err(|e| format!("{}: {e}", p.display()))
    };
    let exe = std::env::current_exe().map_err(|e| format!("this hlb's path: {e}"))?;
    let paths = [
        ("HLB_STATE", abs(&cli.state)?),
        ("HLB_MASTER_KEY", abs(&cli.master_key)?),
        ("HLB_CATALOG", abs(&cli.catalog)?),
    ];
    if let Some((k, v)) = paths
        .iter()
        .find(|(_, v)| v.contains(['"', '\\', '\n', '%']))
    {
        return Err(format!("{k} {v}: a path systemd would read otherwise"));
    }
    let exe = abs(&exe)?;
    if exe.contains(char::is_whitespace) {
        return Err(format!(
            "{exe}: a path with a space, which ExecStart splits"
        ));
    }
    let (service, timer) = units(&exe, &paths);
    let local = LocalRunner;
    hlb_bootstrap::provision::install_file(&local, &unit_path("service"), &service, 0o644)
        .await
        .map_err(|e| e.to_string())?;
    hlb_bootstrap::provision::install_file(&local, &unit_path("timer"), &timer, 0o644)
        .await
        .map_err(|e| e.to_string())?;
    let timer_unit = format!("{}.timer", site_guard::UNIT);
    for argv in [
        vec!["systemctl", "daemon-reload"],
        vec!["systemctl", "enable", "--now", timer_unit.as_str()],
    ] {
        let argv: Vec<String> = argv.into_iter().map(String::from).collect();
        let out = local.run(&argv).await.map_err(|e| e.to_string())?;
        if !out.ok() {
            return Err(format!("{}: {}", argv.join(" "), out.stderr.trim()));
        }
    }
    Ok(())
}

/// Whether this node's guard timer runs.
pub async fn active() -> bool {
    let argv = [
        "systemctl".to_string(),
        "is-active".into(),
        "--quiet".into(),
        format!("{}.timer", site_guard::UNIT),
    ];
    matches!(LocalRunner.run(&argv).await, Ok(o) if o.ok())
}

/// The site's wait, as the site reads it: seconds.
pub async fn site_wait(site: &dyn Runner) -> std::result::Result<Option<u64>, String> {
    Ok(site
        .read_file(site_guard::WAIT_FILE)
        .await
        .map_err(|e| e.to_string())?
        .and_then(|v| v.trim().parse().ok()))
}

/// Tells the site how long its promotion waits for a house stopping after `stop_after`.
pub async fn push_wait(site: &dyn Runner, stop_after: u64) -> std::result::Result<u64, String> {
    let wait = site_guard::promotion_waits(stop_after);
    hlb_bootstrap::provision::install_file(
        site,
        site_guard::WAIT_FILE,
        &format!("{wait}\n"),
        0o644,
    )
    .await
    .map_err(|e| e.to_string())?;
    Ok(wait)
}

/// The site told its wait, when there is one.
async fn tell(hub: Option<&dyn Runner>, new: u64) -> std::result::Result<Option<u64>, String> {
    match hub {
        Some(h) => push_wait(h, new).await.map(Some),
        None => Ok(None),
    }
}

/// `hlb config site-link`: the delay past a stale handshake before the house stops.
///
/// 🔴 The site must never wait less than the house takes to stop: a longer delay is told
/// to the site FIRST, then saved; a shorter one saved, then told — in between, the site
/// waits longer than it needs, never shorter.
pub async fn config(cli: &Cli, asked: Option<&str>, apply: bool) -> Result<ExitCode> {
    let state = open_state(cli).await?;
    let old = stop_after(&state).await?;
    let Some(asked) = asked else {
        println!(
            "The vital apps stop once the site link has been down {} s: WireGuard's {} s, \
             then {old} s.",
            site_guard::stops_at(old),
            site_guard::STALE_AFTER_SECS
        );
        println!(
            "The site's promotion waits {} s without a handshake from the house.",
            site_guard::promotion_waits(old)
        );
        return Ok(ExitCode::SUCCESS);
    };
    let new = u64::try_from(crate::parse_duration(asked)?)?;
    if !apply {
        println!(
            "Would stop the vital apps once the link has been down {} s (now {}), the \
             site's promotion waiting {} s.  Rerun with --apply.",
            site_guard::stops_at(new),
            site_guard::stops_at(old),
            site_guard::promotion_waits(new)
        );
        return Ok(ExitCode::SUCCESS);
    }
    let vault = open_vault(cli)?;
    let site = super::load(&state, &vault).await?;
    let reached = match &site {
        Some(s) => Some(super::reach(&state, &vault, s).await?),
        None => None,
    };
    let hub = reached.as_ref().map(|(_, r)| r.as_ref());
    let told = if new > old {
        match tell(hub, new).await {
            Ok(t) => {
                state.set_site_link_stop_after(Some(new)).await?;
                Ok(t)
            }
            Err(e) => {
                eprintln!(
                    "🔴 the site was not told ({e}): nothing changed — a house stopping \
                     later than its site waits would be written beside it."
                );
                state
                    .audit(
                        "cli",
                        ACTOR_ROLE,
                        "config-site-link",
                        asked,
                        "failed",
                        Some(&e),
                    )
                    .await?;
                return Ok(ExitCode::FAILURE);
            }
        }
    } else {
        state.set_site_link_stop_after(Some(new)).await?;
        tell(hub, new).await
    };
    let (outcome, code) = match &told {
        Ok(_) => ("ok", ExitCode::SUCCESS),
        Err(_) => ("partial", ExitCode::FAILURE),
    };
    state
        .audit("cli", ACTOR_ROLE, "config-site-link", asked, outcome, None)
        .await?;
    println!(
        "✓ The vital apps stop once the site link has been down {} s.",
        site_guard::stops_at(new)
    );
    match told {
        Ok(Some(wait)) => println!("✓ The site's promotion waits {wait} s."),
        Ok(None) => println!("  The house has no site yet: `hlb site add` tells it."),
        Err(e) => eprintln!(
            "⚠️  The site was not told ({e}): it waits longer than it needs until \
             `hlb site sync --apply`."
        ),
    }
    Ok(code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_guard_runs_with_this_runs_paths_every_period() {
        let (service, timer) = units(
            "/usr/local/bin/hlb",
            &[("HLB_STATE", "/var/lib/homelabus/hlb.db".into())],
        );
        assert!(service.contains("Environment=\"HLB_STATE=/var/lib/homelabus/hlb.db\"\n"));
        assert!(service.contains("ExecStart=/usr/local/bin/hlb site guard --apply\n"));
        assert!(service.contains("After=hlb-vault.service docker.service\n"));
        let every = site_guard::GUARD_EVERY_SECS;
        assert!(timer.contains(&format!("OnUnitActiveSec={every}s\n")));
        assert!(timer.contains(&format!("OnBootSec={every}s\n")));
    }
}
