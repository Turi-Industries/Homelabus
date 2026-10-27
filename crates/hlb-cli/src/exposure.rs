//! `hlb config exposure`: how the installation is reached from outside.
//!
//! One command answers what putting apps online needs — the domain, where certificates
//! come from and with which credentials, the name the interface answers at, the machine
//! the router forwards to — and says, before anything is written, what is still missing
//! on the other side: the DNS record and the router.

use std::process::ExitCode;

use hlb_orchestrator::{Orchestrator, SwarmOrchestrator};
use hlb_state::{Certificates, Exposure};
use hlb_types::manifest::{INGRESS_NODE_LABEL, INGRESS_SERVICE};

/// What `hlb config exposure` was asked.
pub struct Request<'a> {
    pub domain: Option<&'a str>,
    pub email: Option<&'a str>,
    pub dns: Option<&'a str>,
    pub internal: bool,
    pub staging: bool,
    pub production: bool,
    pub interface: Option<&'a str>,
    pub node: Option<&'a str>,
    /// A private ACME directory; `none` goes back to Let's Encrypt.
    pub acme_ca: Option<&'a str>,
    /// Its root, PEM — read from the file named on the command line.
    pub acme_ca_root: Option<String>,
    /// Print the internal authority's root, to install on devices.
    pub root: bool,
    pub apply: bool,
}

impl Request<'_> {
    fn changes_nothing(&self) -> bool {
        self.domain.is_none()
            && self.email.is_none()
            && self.dns.is_none()
            && !self.internal
            && !self.staging
            && !self.production
            && self.interface.is_none()
            && self.node.is_none()
            && self.acme_ca.is_none()
            && self.acme_ca_root.is_none()
    }
}

/// One validator for every way a domain comes in: an install's, the exposure's.
use hlb_types::domain::is_domain as valid_domain;

/// The settings `request` makes from `current`, or why it cannot.
fn merge(current: Option<&Exposure>, r: &Request) -> Result<Exposure, Vec<String>> {
    let mut blockers = Vec::new();
    let domain = match (r.domain, current) {
        (Some(d), _) => d.trim_end_matches('.').to_ascii_lowercase(),
        (None, Some(c)) => c.domain.clone(),
        (None, None) => {
            blockers.push("no domain yet: --domain <domain>, e.g. --domain example.org".into());
            String::new()
        }
    };
    if !domain.is_empty() && !valid_domain(&domain) {
        blockers.push(format!(
            "\"{domain}\" is not a domain name — lowercase labels separated by dots, \
             without \"*.\" or a scheme"
        ));
    }

    let asks_acme = r.email.is_some()
        || r.dns.is_some()
        || r.staging
        || r.production
        || r.acme_ca.is_some()
        || r.acme_ca_root.is_some();
    let certificates = if r.internal {
        Certificates::Internal
    } else if asks_acme {
        Certificates::Acme
    } else {
        current.map_or(Certificates::Acme, |c| c.certificates)
    };
    let keep = |f: fn(&Exposure) -> Option<String>| current.and_then(f);
    let acme_email = match r.email {
        Some(e) => Some(e.to_string()),
        None => keep(|c| c.acme_email.clone()),
    };
    let dns_provider = match r.dns {
        Some("none") => None,
        Some(p) => Some(p.to_string()),
        None => keep(|c| c.dns_provider.clone()),
    };
    let staging = if r.staging {
        true
    } else if r.production {
        false
    } else {
        current.is_some_and(|c| c.staging)
    };

    let acme_ca = match r.acme_ca {
        Some("none") => None,
        Some(u) => Some(u.trim_end_matches('/').to_string()),
        None => keep(|c| c.acme_ca.clone()),
    };
    let acme_ca_root = match &r.acme_ca_root {
        Some(pem) => Some(pem.trim().to_string()),
        None if r.acme_ca == Some("none") => None,
        None => keep(|c| c.acme_ca_root.clone()),
    };
    if let Some(u) = &acme_ca {
        if !u.starts_with("https://") {
            blockers.push(format!(
                "\"{u}\" is not an ACME directory — ACME is spoken over https only"
            ));
        }
    }
    if let Some(pem) = &acme_ca_root {
        if !pem.starts_with("-----BEGIN CERTIFICATE-----") {
            blockers.push("--acme-ca-root is not a PEM certificate".into());
        }
    }

    if certificates == Certificates::Acme {
        match &acme_email {
            Some(e) if e.contains('@') => {}
            Some(e) => blockers.push(format!("\"{e}\" is not a mail address")),
            None => blockers.push(
                "an ACME authority needs an address for expiry notices: --email <address> \
                 (or --internal, for an installation no public name reaches)"
                    .into(),
            ),
        }
        if let Some(p) = &dns_provider {
            if hlb_ingress::dns::provider(p).is_none() {
                blockers.push(format!(
                    "\"{p}\" is not a DNS provider the ingress is built with — one of {}, \
                     or \"none\" for one certificate per name",
                    hlb_ingress::dns::names().join(", ")
                ));
            }
        }
    }
    let controller_host = match r.interface {
        Some(h) => Some(h.to_ascii_lowercase()),
        None => keep(|c| c.controller_host.clone()),
    };
    if let Some(h) = &controller_host {
        if !valid_domain(h) {
            blockers.push(format!("\"{h}\" is not a host name"));
        }
    }

    if !blockers.is_empty() {
        return Err(blockers);
    }
    Ok(Exposure {
        domain,
        // The internal authority keeps no ACME setting: one left behind would read as
        // in use.
        acme_email: (certificates == Certificates::Acme)
            .then_some(acme_email)
            .flatten(),
        dns_provider: (certificates == Certificates::Acme)
            .then_some(dns_provider)
            .flatten(),
        staging: certificates == Certificates::Acme && staging,
        acme_ca: (certificates == Certificates::Acme)
            .then_some(acme_ca)
            .flatten(),
        acme_ca_root: (certificates == Certificates::Acme)
            .then_some(acme_ca_root)
            .flatten(),
        certificates,
        controller_host,
    })
}

/// `(secret name, present)` for each credential the provider needs and has no default.
async fn credentials(
    state: &hlb_state::State,
    e: &Exposure,
) -> Result<Vec<(String, bool)>, hlb_state::Error> {
    let mut out = Vec::new();
    if let Some(p) = e
        .dns_provider
        .as_deref()
        .and_then(hlb_ingress::dns::provider)
    {
        for f in p.fields {
            let name = p.secret_name(f);
            let present = state.secret(&name).await?.is_some();
            if !present && f.default.is_some() {
                continue;
            }
            out.push((name, present));
        }
    }
    Ok(out)
}

fn describe(e: &Exposure, node: Option<&str>) {
    println!(
        "  domain        {} — an app is published at <name>.{}",
        e.domain, e.domain
    );
    match e.certificates {
        Certificates::Internal => println!(
            "  certificates  Homelabus's own authority — no public name needed; a device \
             trusts it once its root is installed (hlb config exposure --root)"
        ),
        Certificates::Acme => {
            let how = match &e.dns_provider {
                Some(p) => format!("one wildcard, *.{} and {}, through {p}", e.domain, e.domain),
                None => "one per name, over HTTP-01".into(),
            };
            let who = match &e.acme_ca {
                Some(ca) => format!("the authority at {ca}"),
                None => "Let's Encrypt".into(),
            };
            let env = if e.staging {
                "  🔴 STAGING: no browser trusts them"
            } else {
                ""
            };
            println!(
                "  certificates  {who}, {how} — notices to {}{env}",
                e.acme_email.as_deref().unwrap_or("?")
            );
        }
    }
    println!("  interface     https://{}", e.controller_host());
    println!(
        "  ingress node  {}",
        node.unwrap_or("none yet — --node <hostname>")
    );
}

/// The machine carrying `hlb.ingress=true`, if one does.
fn ingress_node(nodes: &[hlb_orchestrator::NodeInfo]) -> Option<&hlb_orchestrator::NodeInfo> {
    nodes.iter().find(|n| n.ingress)
}

pub async fn run(cli: &crate::Cli, r: Request<'_>) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let state = crate::open_state(cli).await?;
    let current = state.exposure().await?;
    // Optional: the settings can be written before the cluster exists, and read where
    // no Docker answers.
    let orch = SwarmOrchestrator::connect().ok();
    let nodes = match &orch {
        Some(o) => o.nodes().await.unwrap_or_default(),
        None => Vec::new(),
    };
    let ingress = ingress_node(&nodes).map(|n| n.hostname.clone());

    if r.root {
        let vault = crate::open_vault(cli)?;
        let Some((cert, _)) = hlb_engine::ingress::root(&state, &vault).await? else {
            eprintln!("No internal authority yet: hlb config exposure --internal --apply");
            return Ok(ExitCode::FAILURE);
        };
        // The certificate only, never the key: this is what a phone or a laptop
        // installs to trust the names the house serves.
        print!("{cert}");
        return Ok(ExitCode::SUCCESS);
    }

    if r.changes_nothing() {
        let Some(e) = &current else {
            println!("Nothing is published: no domain configured.\n");
            println!("  hlb config exposure --domain example.org --email you@example.org \\");
            println!("      --dns <provider> --node <hostname> --apply");
            println!(
                "\n  DNS providers built into the ingress: {}",
                hlb_ingress::dns::names().join(", ")
            );
            return Ok(ExitCode::SUCCESS);
        };
        println!("Exposure\n");
        describe(e, ingress.as_deref());
        report_credentials(&state, e).await?;
        return Ok(ExitCode::SUCCESS);
    }

    let next = match merge(current.as_ref(), &r) {
        Ok(e) => e,
        Err(blockers) => {
            for b in blockers {
                eprintln!("🔴 {b}");
            }
            eprintln!("   Nothing was changed.");
            return Ok(ExitCode::FAILURE);
        }
    };

    let mut blockers = Vec::new();
    let target = match r.node {
        None => None,
        Some(h) => match nodes.iter().find(|n| n.hostname == h) {
            Some(n) => Some(n.clone()),
            None if orch.is_none() => {
                blockers.push("Docker does not answer: the node cannot be labelled".into());
                None
            }
            None => {
                blockers.push(format!(
                    "no node \"{h}\" in the cluster — {}",
                    nodes
                        .iter()
                        .map(|n| n.hostname.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
                None
            }
        },
    };
    // Caddy keeps its certificates on its node, and is pinned there by them: moving it
    // releases that pin, and its next deployment requests them again on the new one.
    let caddy_runs = match &orch {
        Some(o) => o.status(INGRESS_SERVICE).await.is_ok(),
        None => false,
    };
    let moving = match (&target, &ingress) {
        (Some(t), Some(old)) => caddy_runs && &t.hostname != old,
        _ => false,
    };
    // What reads one of Caddy's volumes moves with it — CrowdSec, its log: left behind,
    // it would be pinned to its own data on the old node and to Caddy's on the new one,
    // and placed on neither.
    let followers = if moving {
        readers_of_ingress(&state).await?
    } else {
        Vec::new()
    };
    let missing: Vec<String> = credentials(&state, &next)
        .await?
        .into_iter()
        .filter(|(_, present)| !present)
        .map(|(n, _)| n)
        .collect();
    for m in &missing {
        blockers.push(format!(
            "{m} is not in the vault: printf '%s' '<value>' | hlb secret-set {m} --purpose dns"
        ));
    }

    println!(
        "{} exposure\n",
        if current.is_some() {
            "Changing the"
        } else {
            "New"
        }
    );
    describe(
        &next,
        target
            .as_ref()
            .map(|n| n.hostname.as_str())
            .or(ingress.as_deref()),
    );
    println!("\nWhat the internet needs, which Homelabus cannot do for you:");
    match (next.certificates, &next.dns_provider) {
        (Certificates::Internal, _) => {
            println!("  a DNS record  each name → the ingress node's address, on your network")
        }
        (Certificates::Acme, Some(_)) => println!(
            "  a DNS record  *.{} and {} → the house's public address",
            next.domain, next.domain
        ),
        (Certificates::Acme, None) => println!(
            "  a DNS record  per app, BEFORE it is installed: the authority checks each name"
        ),
    }
    if moving {
        println!(
            "  🟠 Caddy moves to {} — a few seconds without routes, and its certificates \
             are requested again there",
            target.as_ref().map(|t| t.hostname.as_str()).unwrap_or("?")
        );
        for f in &followers {
            println!("     {f} moves with it, starting over on what it kept there");
        }
    }
    // An app is handed the root when it is deployed: without this, it kept trusting
    // the old one — or none — until something happened to deploy it again.
    let new_root = current
        .as_ref()
        .map(|c| (c.certificates, c.acme_ca_root.as_deref()))
        != Some((next.certificates, next.acme_ca_root.as_deref()));
    let trusting = if new_root {
        trusting_apps(&state).await?
    } else {
        Vec::new()
    };
    if !trusting.is_empty() {
        println!(
            "  🟠 {} deployed again, to trust the certificates' new root",
            trusting.join(", ")
        );
    }
    if next.certificates == Certificates::Acme {
        println!("  the router    TCP 80 and 443 forwarded to the ingress node");
        // Let's Encrypt's quota only: a private authority has its own rules.
        if !next.staging
            && next.acme_ca.is_none()
            && current
                .as_ref()
                .is_none_or(|c| c.certificates != Certificates::Acme)
        {
            println!(
                "  ⚠️  First time: --staging checks it all without spending Let's Encrypt's \
                 quota, which a loop of failures exhausts for a week."
            );
        }
    }

    if !blockers.is_empty() {
        println!();
        for b in &blockers {
            eprintln!("🔴 {b}");
        }
        eprintln!("   Nothing was changed.");
        return Ok(ExitCode::FAILURE);
    }
    if !r.apply {
        println!("\nRe-run with --apply.");
        return Ok(ExitCode::SUCCESS);
    }

    let vault = crate::open_vault(cli).ok();
    let root_before = hlb_engine::ingress::trusted_root(&state, vault.as_ref()).await;
    state.set_exposure(&next).await?;
    // The internal authority signs under a root Homelabus holds, generated once: the
    // controller is given it to verify PocketID, and the devices by `--root`.
    if next.certificates == Certificates::Internal {
        let vault = crate::open_vault(cli)?;
        if hlb_engine::ingress::root(&state, &vault).await?.is_none() {
            let r =
                hlb_agent::pki::generate_web_root(&format!("Homelabus {}", next.domain)).await?;
            let j = serde_json::json!({ "cert": r.cert_pem, "key": r.key_pem });
            state
                .store_secret_if_absent(
                    hlb_engine::ingress::ROOT_SECRET,
                    &vault.encrypt(&j.to_string())?,
                    "internal authority's root",
                )
                .await?;
            println!("✓ Internal authority's root generated: hlb config exposure --root");
        }
    }
    // The labels as they were, put back if Caddy cannot start where it moves.
    let mut moves: Vec<Relabel> = Vec::new();
    if let Some(t) = &target {
        // One machine carries it: two would leave Swarm free to place Caddy on the one
        // the router does not forward to.
        for n in nodes.iter().filter(|n| n.ingress && n.id != t.id) {
            moves.push(Relabel::new(&n.id, INGRESS_NODE_LABEL, "false", "true"));
        }
        let was = if t.ingress { "true" } else { "false" };
        moves.push(Relabel::new(&t.id, INGRESS_NODE_LABEL, "true", was));
        // The data pin is released, never left: kept, it would hold Caddy on the old
        // machine against the label naming the new one, and place it nowhere.
        if moving {
            for service in
                std::iter::once(INGRESS_SERVICE).chain(followers.iter().map(String::as_str))
            {
                let pin = hlb_orchestrator::cluster::data_label(service);
                for n in nodes.iter().filter(|n| n.data.iter().any(|d| d == service)) {
                    moves.push(Relabel::new(&n.id, &pin, "false", "true"));
                }
            }
        }
    }
    if let Some(o) = &orch {
        relabel(&moves, |node, label, value| async move {
            o.label_node(&node, &label, value).await
        })
        .await?;
    }
    state
        .audit(
            "cli",
            crate::ACTOR_ROLE,
            "exposure-set",
            &next.domain,
            "ok",
            Some(next.certificates.as_str()),
        )
        .await?;
    println!("\n✓ Recorded.");

    let mut code = ExitCode::SUCCESS;
    if moving {
        // 🔴 The labels moved before Caddy did, and moving them is what stops the Caddy
        // running: its node no longer meets its constraints. When the new one could not
        // start — a Caddyfile its image refused, on the lab — nothing served at all,
        // under "the configuration it serves is unchanged". Put back, Swarm starts the
        // old Caddy where its certificates are.
        // An error is a Caddy that did not start just as much: `?` here left the labels
        // naming a node nothing runs on.
        let started = match crate::redeploy(cli, &state, INGRESS_SERVICE).await {
            Ok(started) => started,
            Err(e) => {
                eprintln!("🔴 {e}");
                false
            }
        };
        if !started {
            if let Some(o) = &orch {
                let set = |node: String, label: String, value| async move {
                    o.label_node(&node, &label, value).await
                };
                for command in put_back(&moves, set).await {
                    eprintln!("⚠️  not put back — run it by hand: {command}");
                }
            }
            eprintln!(
                "\n🔴 Caddy could not start on {}: the labels are back on {}, where Swarm \
                 starts the Caddy that ran there. Fix the cause above, then run this again.",
                target.as_ref().map(|t| t.hostname.as_str()).unwrap_or("?"),
                ingress.as_deref().unwrap_or("its old node")
            );
            return Ok(ExitCode::FAILURE);
        }
        for f in &followers {
            if !crate::redeploy(cli, &state, f).await? {
                code = ExitCode::FAILURE;
            }
        }
    } else if let (Some(o), true) = (&orch, caddy_runs) {
        // Already running: the change reaches it now, rather than with the next install.
        let vault = crate::open_vault(cli)?;
        if let hlb_engine::ingress::Published::Done { routes, .. } =
            hlb_engine::ingress::publish(o, &state, Some(&vault)).await?
        {
            println!(
                "✓ Caddy serves {}",
                hlb_api::plural(routes.len() as u64, "route", "routes")
            );
        }
    } else {
        println!("  Next: hlb install caddy --apply");
    }

    // Read again rather than predicted: the internal root may have just been made.
    let vault = crate::open_vault(cli).ok();
    if hlb_engine::ingress::trusted_root(&state, vault.as_ref()).await != root_before {
        for app in &trusting {
            if !crate::redeploy(cli, &state, app).await? {
                code = ExitCode::FAILURE;
            }
        }
    }
    Ok(code)
}

/// A node label to set, and the value it had.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Relabel {
    node: String,
    label: String,
    to: &'static str,
    was: &'static str,
}

impl Relabel {
    fn new(node: &str, label: &str, to: &'static str, was: &'static str) -> Self {
        Self {
            node: node.to_string(),
            label: label.to_string(),
            to,
            was,
        }
    }
}

/// Sets each label in order. 🔴 One failing midway puts back those already set before
/// the error is returned: left half moved, Caddy's constraints matched no node, or two.
async fn relabel<F, Fut, E>(moves: &[Relabel], mut set: F) -> Result<(), E>
where
    F: FnMut(String, String, &'static str) -> Fut,
    Fut: std::future::Future<Output = Result<(), E>>,
{
    for (i, m) in moves.iter().enumerate() {
        if let Err(e) = set(m.node.clone(), m.label.clone(), m.to).await {
            for command in put_back(&moves[..i], &mut set).await {
                eprintln!("⚠️  not put back — run it by hand: {command}");
            }
            return Err(e);
        }
    }
    Ok(())
}

/// Puts every label back as it was, the last set first, and answers the command for
/// each one that could not be — every one is tried, a failure stops none of the rest.
async fn put_back<F, Fut, E>(moves: &[Relabel], mut set: F) -> Vec<String>
where
    F: FnMut(String, String, &'static str) -> Fut,
    Fut: std::future::Future<Output = Result<(), E>>,
{
    let mut failed = Vec::new();
    for m in moves.iter().rev().filter(|m| m.to != m.was) {
        if set(m.node.clone(), m.label.clone(), m.was).await.is_err() {
            failed.push(format!(
                "docker node update --label-add {}={} {}",
                m.label, m.was, m.node
            ));
        }
    }
    failed
}

/// The installed apps handed the exposure's root when deployed: those verifying
/// PocketID's certificate themselves, and Stalwart, which asks the ACME authority for
/// its public name's certificate itself: under a private one whose root it was not
/// handed, it refuses the directory's certificate and cannot open its account.
async fn trusting_apps(
    state: &hlb_state::State,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut out = Vec::new();
    for (name, _) in state.installed_apps().await? {
        if name == hlb_engine::submission::host()
            || hlb_engine::trust::verifies_issuer(&state.app_manifest(&name).await?)
        {
            out.push(name);
        }
    }
    Ok(out)
}

/// The installed apps that read one of the ingress's volumes.
async fn readers_of_ingress(
    state: &hlb_state::State,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut out = Vec::new();
    for (name, _) in state.installed_apps().await? {
        let m = state.app_manifest(&name).await?;
        let reads = m.spec.requires.iter().any(|c| {
            matches!(c, hlb_types::Capability::Storage { owner: Some(o), .. } if o == INGRESS_SERVICE)
        });
        if reads {
            out.push(name);
        }
    }
    Ok(out)
}

/// Republishes the routes after something they depend on changed — a step handled,
/// which opens an `after-guide` route. Said, never fatal: the change itself is done.
pub async fn republish(cli: &crate::Cli, state: &hlb_state::State) {
    let Ok(orch) = SwarmOrchestrator::connect() else {
        return;
    };
    let vault = crate::open_vault(cli).ok();
    match hlb_engine::ingress::publish(&orch, state, vault.as_ref()).await {
        Ok(hlb_engine::ingress::Published::Done { routes, .. }) => println!(
            "✓ routes republished ({})",
            hlb_api::plural(routes.len() as u64, "route", "routes")
        ),
        Ok(_) => {}
        Err(e) => eprintln!("⚠️  the routes could not be republished: {e} — hlb ingress --apply"),
    }
}

async fn report_credentials(
    state: &hlb_state::State,
    e: &Exposure,
) -> Result<(), Box<dyn std::error::Error>> {
    let creds = credentials(state, e).await?;
    if creds.is_empty() {
        return Ok(());
    }
    println!("\n  DNS credentials, in the vault:");
    for (name, present) in creds {
        if present {
            println!("    ✓ {name}");
        } else {
            println!("    🔴 {name}   printf '%s' '<value>' | hlb secret-set {name} --purpose dns");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    type Log = std::sync::Arc<std::sync::Mutex<Vec<String>>>;

    /// Records every label set into `log`, and fails the call numbered `fail_at`.
    fn recorder(
        log: &Log,
        fail_at: Option<usize>,
    ) -> impl FnMut(String, String, &'static str) -> std::future::Ready<Result<(), String>> {
        let seen = log.clone();
        let mut calls = 0;
        move |node: String, label: String, value: &'static str| {
            calls += 1;
            let failed = fail_at == Some(calls);
            if !failed {
                seen.lock()
                    .expect("log")
                    .push(format!("{node} {label}={value}"));
            }
            std::future::ready(if failed {
                Err("refused".to_string())
            } else {
                Ok(())
            })
        }
    }

    fn moves() -> Vec<Relabel> {
        vec![
            Relabel::new("old", INGRESS_NODE_LABEL, "false", "true"),
            Relabel::new("new", INGRESS_NODE_LABEL, "true", "false"),
            Relabel::new("old", "hlb.data.caddy", "false", "true"),
        ]
    }

    #[tokio::test]
    async fn a_label_refused_midway_puts_back_the_ones_already_moved() {
        let log = Log::default();
        let r = relabel(&moves(), recorder(&log, Some(2))).await;
        assert!(r.is_err());
        let ingress = format!("old {INGRESS_NODE_LABEL}");
        assert_eq!(
            *log.lock().expect("log"),
            [format!("{ingress}=false"), format!("{ingress}=true")],
            "the old node keeps the ingress"
        );
    }

    #[tokio::test]
    async fn putting_back_tries_every_label_whatever_one_refuses() {
        let log = Log::default();
        let failed = put_back(&moves(), recorder(&log, Some(1))).await;
        assert_eq!(
            failed,
            ["docker node update --label-add hlb.data.caddy=true old"]
        );
        assert_eq!(
            log.lock().expect("log").len(),
            2,
            "the two others were put back"
        );
    }

    fn ask() -> Request<'static> {
        Request {
            domain: None,
            email: None,
            dns: None,
            internal: false,
            staging: false,
            production: false,
            interface: None,
            node: None,
            acme_ca: None,
            acme_ca_root: None,
            root: false,
            apply: false,
        }
    }

    #[test]
    fn a_first_exposure_needs_a_domain_and_an_acme_address() {
        let err = merge(None, &ask()).unwrap_err().join("\n");
        assert!(err.contains("--domain"), "{err}");
        let err = merge(
            None,
            &Request {
                domain: Some("example.org"),
                ..ask()
            },
        )
        .unwrap_err()
        .join("\n");
        assert!(err.contains("--email"), "{err}");
    }

    #[test]
    fn an_internal_authority_keeps_no_acme_setting() {
        let acme = merge(
            None,
            &Request {
                domain: Some("Example.org."),
                email: Some("a@example.org"),
                dns: Some("ovh"),
                staging: true,
                ..ask()
            },
        )
        .expect("valid");
        assert_eq!(acme.domain, "example.org");
        let internal = merge(
            Some(&acme),
            &Request {
                internal: true,
                ..ask()
            },
        )
        .expect("valid");
        assert_eq!(internal.certificates, Certificates::Internal);
        assert_eq!(internal.dns_provider, None);
        assert!(!internal.staging);
        assert_eq!(internal.domain, "example.org", "the rest is kept");
    }

    #[test]
    fn a_provider_the_image_lacks_is_refused_before_anything_is_written() {
        let err = merge(
            None,
            &Request {
                domain: Some("example.org"),
                email: Some("a@example.org"),
                dns: Some("route53"),
                ..ask()
            },
        )
        .unwrap_err()
        .join("\n");
        assert!(err.contains("\"route53\""), "{err}");
        assert!(
            err.contains("ovh"),
            "the providers that exist are named: {err}"
        );
    }

    #[test]
    fn a_private_authority_is_https_with_a_pem_root() {
        let base = || Request {
            domain: Some("lab.home"),
            email: Some("a@lab.home"),
            ..ask()
        };
        let ok = merge(
            None,
            &Request {
                acme_ca: Some("https://ca.lab.home:9000/acme/acme/directory/"),
                acme_ca_root: Some("-----BEGIN CERTIFICATE-----\nMII…".into()),
                ..base()
            },
        )
        .expect("valid");
        assert_eq!(
            ok.acme_ca.as_deref(),
            Some("https://ca.lab.home:9000/acme/acme/directory")
        );
        assert!(merge(
            None,
            &Request {
                acme_ca: Some("http://ca"),
                ..base()
            }
        )
        .is_err());
        assert!(merge(
            None,
            &Request {
                acme_ca_root: Some("hello".into()),
                ..base()
            }
        )
        .is_err());
        let back = merge(
            Some(&ok),
            &Request {
                acme_ca: Some("none"),
                ..ask()
            },
        )
        .expect("valid");
        assert_eq!(
            (back.acme_ca, back.acme_ca_root),
            (None, None),
            "back to Let's Encrypt"
        );
    }

    #[test]
    fn a_wildcard_or_a_url_is_not_a_domain() {
        assert!(valid_domain("example.org"));
        assert!(valid_domain("home.example.org"));
        assert!(!valid_domain("*.example.org"));
        assert!(!valid_domain("https://example.org"));
        assert!(!valid_domain("localhost"));
        assert!(!valid_domain("-bad.example.org"));
    }

    #[tokio::test]
    async fn stalwart_is_deployed_again_with_the_apps_trusting_the_root() {
        let state = hlb_state::State::in_memory().await.expect("state");
        let catalog = hlb_catalog::Catalog::load(std::path::Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../catalog"
        )))
        .expect("catalog");
        for app in ["stalwart", "gitea", "postgres"] {
            let m = &catalog.get(app).expect("in the catalog").manifest;
            state.upsert_app(app, m, None).await.expect("installed");
        }
        let mut trusting = trusting_apps(&state).await.expect("read");
        trusting.sort();
        assert_eq!(trusting, ["gitea", "stalwart"]);
    }
}
