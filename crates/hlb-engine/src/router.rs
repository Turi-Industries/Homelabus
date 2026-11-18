//! The house's router, from the installation's side: its API key in the vault, where
//! it is in the state, and the names it answers inside the house. `hlb router` runs it.
//!
//! 🔴 Preview by default: nothing is made, kept or deleted on the router unless `apply`.
//!
//! What `connect` makes true, in this order — each step only once the one before held:
//!
//! 1. The certificate the router presents is the one a person read on its console.
//! 2. The key given acts as an administrator, and Caddy's address is on one of the
//!    router's networks.
//! 3. An account of Homelabus's own (`homelabus`, in `admins`) and a key of its own,
//!    kept in the vault — and proved, by a call made with it.
//! 4. Only then is the key given deleted, and any key of Homelabus's from before.
//!
//! What `sync` makes true: every name Caddy serves answered with Caddy's address inside
//! the house, and every port an installed manifest publishes for the internet forwarded
//! to the node its service runs on — at that node's declared address on the house's
//! network (`hlb router address`), Caddy's node falling back to the address `connect`
//! was given.

use std::collections::HashMap;
use std::net::Ipv4Addr;

use hlb_orchestrator::Orchestrator;
use hlb_router::client::{Credentials, Network, OutboundMode, System};
use hlb_router::forwards::{self, Edit, Key, Protocol, Wanted};
use hlb_router::names::{self, Change};
use hlb_router::{Fingerprint, Opnsense};
use hlb_secrets::Vault;
use hlb_state::{RouterConfig, RouterSync, State};
use hlb_types::manifest::Reach;

use crate::roles::{Line, Outcome};

/// The router account Homelabus works as.
pub const ACCOUNT: &str = "homelabus";
const COMMENT: &str = "Homelabus: its API key is in the house's vault";
/// The vault's names and purpose. ⚠️ Stored values.
const KEY: &str = "router-api-key";
const SECRET: &str = "router-api-secret";
const PURPOSE: &str = "router";

/// What a run found, and did.
#[derive(Debug, Default)]
pub struct Report {
    pub system: Option<System>,
    pub lines: Vec<Line>,
    /// Names already answered as they should be.
    pub unchanged: usize,
    /// Ports already forwarded as they should be.
    pub forwards_unchanged: usize,
    pub notes: Vec<String>,
    /// Why the run went no further, and what a person does about it.
    pub stopped: Option<String>,
}

impl Report {
    pub fn failed(&self) -> bool {
        self.lines
            .iter()
            .any(|l| matches!(l.outcome, Outcome::Failed(_)))
    }

    /// What did not hold, one line each. A run that stopped short is a failure: a router
    /// is connected, so a missing key or Caddy moved off its networks leaves every new
    /// name unanswered.
    pub fn failures(&self) -> Option<String> {
        let mut lines: Vec<String> = self
            .lines
            .iter()
            .filter_map(|l| match &l.outcome {
                Outcome::Failed(e) | Outcome::NotConfigured(e) => {
                    Some(format!("{} — {}: {e}", l.subject, l.change))
                }
                _ => None,
            })
            .collect();
        lines.extend(self.stopped.clone());
        (!lines.is_empty()).then(|| lines.join("\n"))
    }

    fn push(&mut self, subject: &str, change: impl Into<String>, outcome: Outcome) {
        self.lines.push(Line {
            subject: subject.to_string(),
            change: change.into(),
            outcome,
        });
    }

    fn stop(mut self, why: impl Into<String>) -> Self {
        self.stopped = Some(why.into());
        self
    }
}

/// What an administrator does, once, for Homelabus to work on the router.
pub fn connect_steps(url: &str) -> String {
    format!(
        "Homelabus works on the router as an account of its own, which an administrator \
         lets in once:\n\
         \x20 1. Sign in to {url} as an administrator (root).\n\
         \x20 2. System → Access → Users → root → API keys → + : a file with a key and a \
         secret downloads.\n\
         \x20 3. `hlb router connect --url {url}` prints the certificate it presents: \
         compare it with the router's console (`HTTPS: SHA256 …`).\n\
         \x20 4. `hlb router connect --url {url} --fingerprint <sha256> --caddy <address> \
         --apply`, the file on standard input — Caddy's address on the router's network: Homelabus \
         makes its own account and key with the file, then deletes its key."
    )
}

/// Everything a run reaches.
pub struct Router<'a> {
    pub state: &'a State,
    pub vault: &'a Vault,
}

/// Every name Caddy serves: what the router answers inside the house.
pub async fn house_names<O: Orchestrator + ?Sized>(
    orch: &O,
    state: &State,
) -> crate::Result<Vec<String>> {
    let exposure = state.exposure().await?;
    let routes = crate::ingress::routes(orch, state, exposure.as_ref()).await?;
    let mut names: Vec<String> = routes.into_iter().map(|r| r.host).collect();
    names.sort();
    names.dedup();
    Ok(names)
}

/// What the router forwards for the house: read from the installed manifests, and from
/// where Swarm runs each service now.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct HouseForwards {
    pub wanted: Vec<Wanted>,
    /// The ports of services whose forwards stay as they are: running nowhere now (a
    /// restart would find its port closed until the next sync), or on a node whose
    /// address is not declared.
    pub held: Vec<Key>,
    /// `(service, node)`: running where no address is declared.
    pub unaddressed: Vec<(String, String)>,
    /// `(service, port, app)`: the internet's as frozen, the site's in today's catalog.
    pub withheld: Vec<(String, Key, String)>,
}

fn protocol(p: hlb_types::manifest::Protocol) -> Protocol {
    match p {
        hlb_types::manifest::Protocol::Tcp => Protocol::Tcp,
        hlb_types::manifest::Protocol::Udp => Protocol::Udp,
    }
}

/// Every port the house's installed services publish for the internet, and where it
/// goes. With a site, the front door's ports are the VPS's: forwarded home too, they
/// would be a second door, around the site's.
///
/// 🔴 A port today's `catalog` says is the site's is never forwarded, whatever the
/// manifest frozen at install says: one frozen before ports said who they were for
/// reads every port as the internet's — Caddy's relay listener and Knot's hidden
/// primary among them, found on the lab. Said, with the upgrade that clears it.
pub async fn house_forwards<O: Orchestrator + ?Sized>(
    orch: &O,
    state: &State,
    catalog: &hlb_catalog::Catalog,
    caddy: Option<Ipv4Addr>,
) -> crate::Result<HouseForwards> {
    use hlb_ingress::front_door::{HTTPS_PORT, HTTP_PORT};
    let site = state.secret(crate::site_guard::TOPOLOGY).await?.is_some();
    let declared: HashMap<String, Ipv4Addr> = state
        .router_addresses()
        .await?
        .into_iter()
        .filter_map(|(node, a)| Some((node, a.parse().ok()?)))
        .collect();
    let nodes = orch.nodes().await?;
    let mut out = HouseForwards::default();
    for (app, _) in state.installed_apps().await? {
        let m = match state.app_manifest(&app).await {
            Ok(m) => m,
            Err(hlb_state::Error::UnknownApp(_)) => continue,
            Err(e) => return Err(e.into()),
        };
        let today = catalog.get(&app).ok().map(|e| &e.manifest);
        let mut services = vec![(
            app.clone(),
            &m.spec.security.published_ports,
            today.map(|t| &t.spec.security.published_ports),
        )];
        for c in &m.spec.companions {
            let now = today.and_then(|t| t.spec.companions.iter().find(|n| n.name == c.name));
            services.push((
                format!("{app}-{}", c.name),
                &c.security.published_ports,
                now.map(|n| &n.security.published_ports),
            ));
        }
        for (service, ports, now) in services {
            let sites: Vec<Key> = now
                .into_iter()
                .flatten()
                .filter(|p| p.reach == Reach::Site)
                .map(|p| (protocol(p.protocol), p.port))
                .collect();
            let mut keys: Vec<Key> = Vec::new();
            for p in ports.iter().filter(|p| p.reach == Reach::Internet) {
                let key = (protocol(p.protocol), p.port);
                if site && key.0 == Protocol::Tcp && [HTTP_PORT, HTTPS_PORT].contains(&key.1) {
                    continue;
                }
                if sites.contains(&key) {
                    out.withheld.push((service.clone(), key, app.clone()));
                    continue;
                }
                keys.push(key);
            }
            if keys.is_empty() {
                continue;
            }
            let tasks = orch.tasks(Some(&service)).await?;
            // Several replicas each publish the port on their node: one forward, to the
            // first by name, so the same Swarm forwards the same way every night.
            let node = tasks
                .iter()
                .filter(|t| t.is_alive())
                .filter_map(|t| t.node_id.as_deref())
                .filter_map(|id| nodes.iter().find(|n| n.id == id))
                .min_by(|a, b| a.hostname.cmp(&b.hostname));
            let Some(node) = node else {
                out.held.extend(keys);
                continue;
            };
            let target =
                declared
                    .get(&node.hostname)
                    .copied()
                    .or(if node.ingress { caddy } else { None });
            let Some(target) = target else {
                out.held.extend(keys);
                out.unaddressed.push((service, node.hostname.clone()));
                continue;
            };
            out.wanted
                .extend(keys.into_iter().map(|(protocol, port)| Wanted {
                    protocol,
                    port,
                    target,
                    service: service.clone(),
                }));
        }
    }
    Ok(out)
}

/// The router's own port, when its interface could be what the WAN's forward of that
/// port takes: reached at an address on no network but the WAN's, or by a name.
fn guarded(url: &str, networks: &[Network]) -> Option<Key> {
    let authority = url
        .trim_start_matches("https://")
        .split('/')
        .next()
        .unwrap_or_default();
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h, p.parse().unwrap_or(443)),
        None => (authority, 443),
    };
    let inside = host
        .parse::<Ipv4Addr>()
        .ok()
        .and_then(|ip| names::network_of(ip, networks))
        .is_some_and(|(network, _)| network != forwards::WAN);
    (!inside).then_some((Protocol::Tcp, port))
}

fn parse_pin(text: &str) -> crate::Result<Fingerprint> {
    Fingerprint::parse(text).ok_or_else(|| {
        crate::Error::RouterConfig(format!(
            "the router's fingerprint is not a SHA-256 ({text}): 64 hexadecimal digits, as \
             its console prints them"
        ))
    })
}

impl Router<'_> {
    async fn secret(&self, name: &str) -> crate::Result<Option<String>> {
        match self.state.secret(name).await? {
            Some(ct) => Ok(Some(self.vault.decrypt(&ct)?)),
            None => Ok(None),
        }
    }

    async fn keep(&self, name: &str, value: &str) -> crate::Result<()> {
        let ct = self.vault.encrypt(value)?;
        if !self
            .state
            .store_secret_if_absent(name, &ct, PURPOSE)
            .await?
        {
            self.state.rotate_secret(name, &ct).await?;
        }
        Ok(())
    }

    /// The router as connected, through its pinned certificate and Homelabus's key.
    async fn client(&self) -> crate::Result<Result<(RouterConfig, Opnsense), String>> {
        let Some(config) = self.state.router().await? else {
            return Ok(Err(
                "no router connected — `hlb router connect --url <url>` first".into(),
            ));
        };
        let (Some(key), Some(secret)) = (self.secret(KEY).await?, self.secret(SECRET).await?)
        else {
            return Ok(Err(format!(
                "the router's API key is not in the vault.\n{}",
                connect_steps(&config.url)
            )));
        };
        let pin = parse_pin(&config.fingerprint)?;
        let client = Opnsense::new(&config.url, pin, Credentials { key, secret })?;
        Ok(Ok((config, client)))
    }

    /// Turns an administrator's key into Homelabus's own account and key, then
    /// deletes the administrator's. `given` is read from them, never from a command
    /// line.
    pub async fn connect(
        &self,
        url: &str,
        fingerprint: &str,
        given: Credentials,
        caddy: Ipv4Addr,
        apply: bool,
    ) -> crate::Result<Report> {
        let mut r = Report::default();
        let url = url.trim_end_matches('/');
        if !url.starts_with("https://") {
            return Ok(r.stop(format!(
                "{url}: the router's API is reached over https only — its key would \
                 cross the network in clear"
            )));
        }
        let pin = parse_pin(fingerprint)?;
        let router = Opnsense::new(url, pin, given.clone())?;
        let system = match router.system().await {
            Ok(s) => s,
            Err(hlb_router::Error::Unauthorized) => {
                return Ok(r.stop(format!(
                    "the router refused that key.\n{}",
                    connect_steps(url)
                )));
            }
            Err(hlb_router::Error::Http { .. }) => {
                // A certificate other than the pin fails the handshake: say what it is.
                let presented = hlb_router::tls::peek(url).await.ok();
                return Ok(r.stop(match presented {
                    Some(p) if p != pin => format!(
                        "{url} presents another certificate than the one given:\n  \
                         given      {pin}\n  presented  {p}\nCompare with the router's \
                         console (`HTTPS: SHA256 …`): if it says the second, give that one; \
                         if not, something else answers at that address."
                    ),
                    _ => format!("{url} does not answer as an OPNsense router does"),
                }));
            }
            Err(e) => return Err(e.into()),
        };
        r.system = Some(system);

        let keys = router.api_keys().await?;
        let users = router.users().await?;
        let Some(holder) = keys
            .iter()
            .find(|k| k.key == given.key)
            .map(|k| k.username.clone())
        else {
            return Ok(r.stop(
                "the router does not list the key it accepted: give a key of an \
                              administrator's",
            ));
        };
        if !users.iter().any(|u| u.name == holder && u.is_admin) {
            return Ok(r.stop(format!(
                "that key acts as {holder}, who does not hold every privilege: only an \
                 administrator's key can make Homelabus's account"
            )));
        }
        let networks = router.networks().await?;
        let Some((network, own)) = names::network_of(caddy, &networks) else {
            let known: Vec<String> = networks
                .iter()
                .filter(|n| !n.addr4.is_empty())
                .map(|n| format!("{} {}", n.identifier, n.addr4))
                .collect();
            return Ok(r.stop(format!(
                "Caddy's address {caddy} is on none of the router's networks ({}): the \
                 names would resolve to an address the house cannot reach. Give the \
                 ingress node's address on the house's network — not its mesh address.",
                known.join(", ")
            )));
        };
        r.notes.push(format!(
            "Caddy at {caddy}, on the router's network {network} (the router is {own} there)."
        ));

        let ours = users.iter().find(|u| u.name == ACCOUNT);
        if ours.is_some_and(|u| !u.is_admin) {
            return Ok(r.stop(format!(
                "an account named \"{ACCOUNT}\" exists on the router and is not an \
                 administrator: Homelabus does not take over an account it did not make"
            )));
        }
        let former: Vec<_> = keys
            .iter()
            .filter(|k| k.username == ACCOUNT && k.key != given.key)
            .collect();
        if !apply {
            r.push(
                ACCOUNT,
                if ours.is_some() {
                    "router account kept"
                } else {
                    "router account made, in admins"
                },
                Outcome::ToDo,
            );
            r.push(ACCOUNT, "its own API key, kept in the vault", Outcome::ToDo);
            if holder != ACCOUNT {
                r.push(&holder, "the key given here, deleted", Outcome::ToDo);
            }
            if !former.is_empty() {
                r.push(
                    ACCOUNT,
                    format!("{} former key(s) deleted", former.len()),
                    Outcome::ToDo,
                );
            }
            return Ok(r);
        }

        if ours.is_none() {
            let gid = router.admins_gid().await?;
            router.add_user(ACCOUNT, COMMENT, &gid).await?;
            r.push(ACCOUNT, "router account made, in admins", Outcome::Done);
        }
        let own_key = router.add_api_key(ACCOUNT).await?;
        self.keep(KEY, &own_key.key).await?;
        self.keep(SECRET, &own_key.secret).await?;
        r.push(ACCOUNT, "its own API key, kept in the vault", Outcome::Done);

        // Through the new key from here: it is the one that has to work.
        let mine = Opnsense::new(url, pin, own_key.clone())?;
        mine.system().await?;
        self.state
            .set_router(&RouterConfig {
                url: url.to_string(),
                fingerprint: pin.hex(),
                caddy: caddy.to_string(),
            })
            .await?;
        for k in mine.api_keys().await? {
            let given_here = k.key == given.key && holder != ACCOUNT;
            let former = k.username == ACCOUNT && k.key != own_key.key;
            if given_here || former {
                mine.del_api_key(&k.id).await?;
                let whose = if given_here { holder.as_str() } else { ACCOUNT };
                r.push(
                    whose,
                    if given_here {
                        "the key given here, deleted"
                    } else {
                        "a former key, deleted"
                    },
                    Outcome::Done,
                );
            }
        }
        Ok(r)
    }

    /// Makes the router answer every name Caddy serves with Caddy's address, and
    /// forward every port the house publishes for the internet.
    pub async fn sync<O: Orchestrator + ?Sized>(
        &self,
        orch: &O,
        catalog: &hlb_catalog::Catalog,
        apply: bool,
    ) -> crate::Result<Report> {
        let mut r = Report::default();
        let (config, router) = match self.client().await? {
            Ok(c) => c,
            Err(why) => return Ok(r.stop(why)),
        };
        r.system = Some(router.system().await?);
        let caddy: Ipv4Addr = config.caddy.parse().map_err(|_| {
            crate::Error::RouterConfig(format!(
                "the router's Caddy address {} is no IPv4",
                config.caddy
            ))
        })?;
        let networks = router.networks().await?;
        if names::network_of(caddy, &networks).is_none() {
            return Ok(r.stop(format!(
                "Caddy's address {caddy} is on none of the router's networks any more: \
                 `hlb router connect --url {} --fingerprint {} --caddy <address> --apply` \
                 again, with a key of an administrator's",
                config.url, config.fingerprint
            )));
        }
        let names = house_names(orch, self.state).await?;
        self.sync_names(&router, &names, caddy, apply, &mut r)
            .await?;
        let wanted = house_forwards(orch, self.state, catalog, Some(caddy)).await?;
        let guard = guarded(&config.url, &networks);
        self.sync_forwards(&router, &wanted, guard, &networks, apply, &mut r)
            .await?;
        Ok(r)
    }

    async fn sync_names(
        &self,
        router: &Opnsense,
        names: &[String],
        caddy: Ipv4Addr,
        apply: bool,
        r: &mut Report,
    ) -> crate::Result<()> {
        let plan = names::plan(names, caddy, &router.host_overrides().await?);
        r.unchanged = plan.unchanged.len();
        for (name, answers) in &plan.theirs {
            r.notes.push(format!(
                "{name} is answered by an override of someone else's ({answers}): left as it is"
            ));
        }
        let mut changed = false;
        for c in &plan.changes {
            let (subject, change) = match c {
                Change::Add(o) => (o.fqdn(), format!("answered {} inside the house", o.server)),
                Change::Update { to, was, .. } => {
                    (to.fqdn(), format!("answered {} (was {was})", to.server))
                }
                Change::Remove { fqdn, .. } => (fqdn.clone(), "no longer answered".to_string()),
            };
            if !apply {
                r.push(&subject, change, Outcome::ToDo);
                continue;
            }
            let done = match c {
                Change::Add(o) => router.add_host_override(o).await.map(|_| ()),
                Change::Update { uuid, to, .. } => router.set_host_override(uuid, to).await,
                Change::Remove { uuid, .. } => router.del_host_override(uuid).await,
            };
            match done {
                Ok(()) => {
                    changed = true;
                    r.push(&subject, change, Outcome::Done);
                }
                Err(e) => r.push(&subject, change, Outcome::Failed(e.to_string())),
            }
        }
        if changed {
            if let Err(e) = router.reconfigure_unbound().await {
                r.push(
                    "unbound",
                    "reconfigured, to answer what was saved",
                    Outcome::Failed(e.to_string()),
                );
            }
        }
        Ok(())
    }

    async fn sync_forwards(
        &self,
        router: &Opnsense,
        house: &HouseForwards,
        guard: Option<Key>,
        networks: &[Network],
        apply: bool,
        r: &mut Report,
    ) -> crate::Result<()> {
        for (service, key, app) in &house.withheld {
            r.notes.push(format!(
                "{} of {service} is the site's in today's catalog and the internet's as \
                 installed: never forwarded — `hlb upgrade {app}`",
                forwards::key_text(*key)
            ));
        }
        for (service, node) in &house.unaddressed {
            r.push(
                service,
                "its ports forwarded from the internet",
                Outcome::NotConfigured(format!(
                    "it runs on {node}, whose address on the house's network is not \
                     declared: `hlb router address {node} --address <ip> --apply`"
                )),
            );
        }

        // 🔴 In `automatic`, outbound NAT ignores every rule written by hand — saved,
        // and listed nowhere. `hybrid` loads them beside the generated ones, which it
        // keeps as they were.
        let mode = router.outbound_mode().await?;
        let mut switched = false;
        let mut reflect = mode.reads_written();
        if mode == OutboundMode::Automatic && !house.wanted.is_empty() {
            let change = "outbound NAT made hybrid: the automatic rules, and Homelabus's \
                          for the forwards reached from inside";
            if apply {
                match router.set_outbound_mode(OutboundMode::Hybrid).await {
                    Ok(()) => {
                        switched = true;
                        reflect = true;
                        r.push("router", change, Outcome::Done);
                    }
                    Err(e) => r.push("router", change, Outcome::Failed(e.to_string())),
                }
            } else {
                reflect = true;
                r.push("router", change, Outcome::ToDo);
            }
        }
        if mode == OutboundMode::Disabled && !house.wanted.is_empty() {
            r.notes.push(
                "outbound NAT is disabled on the router: a machine in a forwarded \
                 service's own network cannot reach it at the house's public address"
                    .to_string(),
            );
        }
        // Listed in `automatic` they are not: an empty list, and the plan adds them.
        let reflections = if mode.reads_written() || switched {
            router.outbound_nat().await?
        } else {
            Vec::new()
        };
        let plan = forwards::plan(
            &house.wanted,
            &house.held,
            guard,
            networks,
            &router.port_forwards().await?,
            &reflections,
            reflect,
        );
        r.forwards_unchanged = plan.unchanged;
        for (key, to) in &plan.theirs {
            r.notes.push(format!(
                "{} is forwarded by a rule of someone else's (to {to}): left as it is",
                forwards::key_text(*key)
            ));
        }
        for (w, why) in &plan.refused {
            r.push(
                &forwards::key_text((w.protocol, w.port)),
                format!("forwarded to {} ({})", w.target, w.service),
                Outcome::NotConfigured(why.clone()),
            );
        }

        let mut added: Vec<String> = Vec::new();
        let mut changed = false;
        for e in &plan.forwards {
            let (subject, change) = match e {
                Edit::Add(f) => (
                    (f.protocol, f.port),
                    format!("forwarded to {} ({})", f.target, f.service),
                ),
                Edit::Update { to, was, .. } => (
                    (to.protocol, to.port),
                    format!("forwarded to {} ({}, was {was})", to.target, to.service),
                ),
                Edit::Remove { key, .. } => (*key, "no longer forwarded".to_string()),
            };
            let subject = forwards::key_text(subject);
            if !apply {
                r.push(&subject, change, Outcome::ToDo);
                continue;
            }
            let done = match e {
                Edit::Add(f) => router.add_port_forward(&f.body()).await.map(|u| {
                    added.push(u);
                }),
                Edit::Update { uuid, to, .. } => router.set_port_forward(uuid, &to.body()).await,
                Edit::Remove { uuid, .. } => router.del_port_forward(uuid).await,
            };
            match done {
                Ok(()) => {
                    changed = true;
                    r.push(&subject, change, Outcome::Done);
                }
                Err(e) => r.push(&subject, change, Outcome::Failed(e.to_string())),
            }
        }

        let mut added_nat: Vec<String> = Vec::new();
        let mut changed_nat = switched;
        for e in &plan.reflections {
            let (subject, change) = match e {
                Edit::Add(f) | Edit::Update { to: f, .. } => (
                    (f.protocol, f.port),
                    format!(
                        "reached from {} at the house's address (outbound NAT)",
                        f.network
                    ),
                ),
                Edit::Remove { key, .. } => (*key, "no longer reflected".to_string()),
            };
            let subject = forwards::key_text(subject);
            if !apply {
                r.push(&subject, change, Outcome::ToDo);
                continue;
            }
            let done = match e {
                Edit::Add(f) => router.add_outbound_nat(&f.body()).await.map(|u| {
                    added_nat.push(u);
                }),
                Edit::Update { uuid, to, .. } => router.set_outbound_nat(uuid, &to.body()).await,
                Edit::Remove { uuid, .. } => router.del_outbound_nat(uuid).await,
            };
            match done {
                Ok(()) => {
                    changed_nat = true;
                    r.push(&subject, change, Outcome::Done);
                }
                Err(e) => r.push(&subject, change, Outcome::Failed(e.to_string())),
            }
        }

        // Saved is not loaded: pf reads the rules at the reload. One that fails takes
        // back what this run added, so the router runs what it ran before; updates and
        // removals stay, said by the failure.
        for (which, did, mine) in [
            ("d_nat", changed, &added),
            ("source_nat", changed_nat, &added_nat),
        ] {
            if !did {
                continue;
            }
            if let Err(e) = router.apply_firewall(which).await {
                let mut taken_back = 0;
                for uuid in mine.iter() {
                    let gone = if which == "d_nat" {
                        router.del_port_forward(uuid).await
                    } else {
                        router.del_outbound_nat(uuid).await
                    };
                    if gone.is_ok() {
                        taken_back += 1;
                    }
                }
                let again = router.apply_firewall(which).await.err();
                r.push(
                    "firewall",
                    format!("{which} rules loaded"),
                    Outcome::Failed(format!(
                        "{e}; this run's {taken_back} new rule(s) taken back{}",
                        again
                            .map(|e| format!(", and the reload failed again: {e}"))
                            .unwrap_or_default()
                    )),
                );
            }
        }
        // Structurally no rule written here reaches the interface; read once more all
        // the same, so a reload that cut it is said the night it happened.
        if changed || changed_nat {
            if let Err(e) = router.system().await {
                r.push(
                    "router",
                    "its interface answering after the reload",
                    Outcome::Failed(e.to_string()),
                );
            }
        }
        Ok(())
    }

    /// Declares `node`'s address on the house's network: where the router forwards the
    /// ports its services publish.
    pub async fn address<O: Orchestrator + ?Sized>(
        &self,
        orch: &O,
        node: &str,
        address: Ipv4Addr,
        apply: bool,
    ) -> crate::Result<Report> {
        let mut r = Report::default();
        let nodes = orch.nodes().await?;
        if !nodes.iter().any(|n| n.hostname == node) {
            let mut known: Vec<&str> = nodes.iter().map(|n| n.hostname.as_str()).collect();
            known.sort_unstable();
            return Ok(r.stop(format!(
                "no node is named {node} in the Swarm ({})",
                known.join(", ")
            )));
        }
        let (_, router) = match self.client().await? {
            Ok(c) => c,
            Err(why) => return Ok(r.stop(why)),
        };
        let Some((network, _)) = names::network_of(address, &router.networks().await?) else {
            return Ok(r.stop(format!(
                "{address} is on none of the router's networks: the router could forward \
                 nothing there. Give {node}'s address on the house's network — not its \
                 mesh address."
            )));
        };
        let was = self
            .state
            .router_addresses()
            .await?
            .into_iter()
            .find(|(n, _)| n == node)
            .map(|(_, a)| a);
        if was.as_deref() == Some(address.to_string().as_str()) {
            r.unchanged = 1;
            r.notes
                .push(format!("{node} is already at {address}, on {network}."));
            return Ok(r);
        }
        let change = match &was {
            Some(w) => format!("at {address} on {network} (was {w})"),
            None => format!("at {address} on {network}"),
        };
        if apply {
            self.state
                .set_router_address(node, Some(&address.to_string()))
                .await?;
            r.push(node, change, Outcome::Done);
        } else {
            r.push(node, change, Outcome::ToDo);
        }
        Ok(r)
    }

    /// [`Router::sync`] applied, its outcome recorded for the inbox. The night's run
    /// and a person's alike: the `hlb router sync --apply` the inbox advises must clear
    /// what it says, not leave it until the next night. No router connected records
    /// nothing — there is nothing to answer.
    pub async fn sync_recorded<O: Orchestrator + ?Sized>(
        &self,
        orch: &O,
        catalog: &hlb_catalog::Catalog,
        now: i64,
    ) -> crate::Result<Report> {
        let connected = self.state.router().await?.is_some();
        let result = self.sync(orch, catalog, true).await;
        if connected {
            let failed = match &result {
                Ok(r) => r.failures(),
                // Unreachable, or refused: nothing is more synced than if a line had
                // failed.
                Err(e) => Some(format!("router sync stopped: {e}")),
            };
            let record = RouterSync { at: now, failed };
            if let Err(e) = self.state.record_router_sync(&record).await {
                tracing::warn!("router sync not recorded: {e}");
            }
        }
        result
    }

    /// What the router is, and what it answers and forwards for the house.
    pub async fn show<O: Orchestrator + ?Sized>(
        &self,
        orch: &O,
        catalog: &hlb_catalog::Catalog,
    ) -> crate::Result<(Option<RouterConfig>, Report)> {
        let config = self.state.router().await?;
        let r = self.sync(orch, catalog, false).await?;
        Ok((config, r))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn platform(name: &str) -> hlb_types::Manifest {
        let path = format!(
            "{}/../../catalog/_platform/{name}/manifest.yaml",
            env!("CARGO_MANIFEST_DIR")
        );
        serde_yaml_ng::from_str(&std::fs::read_to_string(path).expect("manifest")).expect("parsed")
    }

    fn node(name: &str, ingress: bool) -> hlb_orchestrator::NodeInfo {
        hlb_orchestrator::NodeInfo {
            id: format!("id-{name}"),
            hostname: name.into(),
            role: hlb_orchestrator::NodeRole::Manager,
            status: "ready".into(),
            availability: "active".into(),
            tier: None,
            protection: None,
            disk_tangs: Vec::new(),
            is_leader: false,
            memory_mb: None,
            failure_domain: None,
            data: Vec::new(),
            ingress,
            // The mesh's: never a target.
            addr: Some("10.42.0.2".into()),
        }
    }

    fn running(service: &str, on: &str) -> hlb_orchestrator::TaskInfo {
        hlb_orchestrator::TaskInfo {
            id: format!("t-{service}"),
            service: service.into(),
            slot: Some(1),
            node_id: Some(format!("id-{on}")),
            desired_state: "running".into(),
            state: "running".into(),
            image: String::new(),
            message: None,
            err: None,
            updated_at: None,
        }
    }

    async fn house() -> (State, crate::tests::Fake) {
        let state = State::in_memory().await.expect("state");
        for app in ["caddy", "stalwart"] {
            state
                .upsert_app(app, &platform(app), None)
                .await
                .expect("installed");
        }
        let orch = crate::tests::Fake::default();
        *orch.nodes.lock().expect("mutex") = vec![node("deb1", true), node("deb2", false)];
        (state, orch)
    }

    const CADDY: Ipv4Addr = Ipv4Addr::new(10, 77, 0, 11);

    fn catalog() -> hlb_catalog::Catalog {
        hlb_catalog::Catalog::load(concat!(env!("CARGO_MANIFEST_DIR"), "/../../catalog"))
            .expect("the catalog")
    }

    #[tokio::test]
    async fn a_port_frozen_before_reach_is_never_forwarded_when_the_catalog_says_site() {
        // The lab's Caddy, installed before `reach`: 10443 read as the internet's.
        let state = State::in_memory().await.expect("state");
        let mut old = platform("caddy");
        for p in &mut old.spec.security.published_ports {
            p.reach = Reach::Internet;
        }
        state
            .upsert_app("caddy", &old, None)
            .await
            .expect("installed");
        let orch = crate::tests::Fake::default();
        *orch.nodes.lock().expect("mutex") = vec![node("deb1", true)];
        *orch.tasks.lock().expect("mutex") = vec![running("caddy", "deb1")];
        let f = house_forwards(&orch, &state, &catalog(), Some(CADDY))
            .await
            .expect("read");
        assert!(f.wanted.iter().all(|w| w.port != 10443), "{:?}", f.wanted);
        assert_eq!(
            f.withheld,
            vec![("caddy".into(), (Protocol::Tcp, 10443), "caddy".into())]
        );
    }

    fn ports(f: &HouseForwards) -> Vec<(u16, Ipv4Addr, &str)> {
        let mut p: Vec<_> = f
            .wanted
            .iter()
            .map(|w| (w.port, w.target, w.service.as_str()))
            .collect();
        p.sort();
        p
    }

    #[tokio::test]
    async fn each_published_port_goes_to_the_declared_address_of_its_node() {
        let (state, orch) = house().await;
        *orch.tasks.lock().expect("mutex") =
            vec![running("caddy", "deb1"), running("stalwart", "deb2")];
        state
            .set_router_address("deb2", Some("10.77.0.12"))
            .await
            .expect("declared");
        let f = house_forwards(&orch, &state, &catalog(), Some(CADDY))
            .await
            .expect("read");
        let deb2 = Ipv4Addr::new(10, 77, 0, 12);
        assert_eq!(
            ports(&f),
            vec![
                (25, deb2, "stalwart"),
                (80, CADDY, "caddy"),
                (443, CADDY, "caddy"),
                (465, deb2, "stalwart"),
                (993, deb2, "stalwart"),
                (4190, deb2, "stalwart"),
            ],
            "Caddy's node falls back to Caddy's address; 10443 is the site's"
        );
        assert!(f.held.is_empty() && f.unaddressed.is_empty(), "{f:?}");
    }

    #[tokio::test]
    async fn with_a_site_the_front_doors_ports_are_never_forwarded_home() {
        let (state, orch) = house().await;
        *orch.tasks.lock().expect("mutex") = vec![running("caddy", "deb1")];
        state
            .store_secret_if_absent(crate::site_guard::TOPOLOGY, b"sealed", "site")
            .await
            .expect("a site");
        let f = house_forwards(&orch, &state, &catalog(), Some(CADDY))
            .await
            .expect("read");
        assert!(
            f.wanted.iter().all(|w| w.service != "caddy"),
            "{:?}",
            f.wanted
        );
    }

    #[tokio::test]
    async fn a_service_stopped_or_on_an_unaddressed_node_keeps_its_forwards() {
        let (state, orch) = house().await;
        *orch.tasks.lock().expect("mutex") = vec![running("stalwart", "deb2")];
        let f = house_forwards(&orch, &state, &catalog(), Some(CADDY))
            .await
            .expect("read");
        assert!(f.wanted.is_empty(), "{:?}", f.wanted);
        assert!(f.held.contains(&(Protocol::Tcp, 443)), "Caddy runs nowhere");
        assert!(f.held.contains(&(Protocol::Tcp, 25)));
        assert_eq!(f.unaddressed, vec![("stalwart".into(), "deb2".into())]);
    }

    #[test]
    fn the_routers_interface_is_guarded_unless_reached_inside() {
        let n = |id: &str, a: &str| Network {
            identifier: id.into(),
            description: String::new(),
            device: "vtnet0".into(),
            addr4: a.into(),
        };
        let nets = [n("lan", "10.77.0.3/24"), n("wan", "203.0.113.2/24")];
        assert_eq!(guarded("https://10.77.0.3", &nets), None);
        assert_eq!(
            guarded("https://203.0.113.2", &nets),
            Some((Protocol::Tcp, 443))
        );
        assert_eq!(
            guarded("https://router.home.arpa:8443/", &nets),
            Some((Protocol::Tcp, 8443)),
            "a name could be anywhere"
        );
        assert_eq!(guarded("https://10.77.0.3:8443", &nets), None);
    }

    fn line(subject: &str, outcome: Outcome) -> Line {
        Line {
            subject: subject.into(),
            change: "answered 10.77.0.11 inside the house".into(),
            outcome,
        }
    }

    #[test]
    fn what_was_done_is_no_failure_and_a_stop_is_one() {
        let held = Report {
            lines: vec![line("gitea.home.org", Outcome::Done)],
            unchanged: 3,
            ..Report::default()
        };
        assert_eq!(held.failures(), None);

        let mixed = Report {
            lines: vec![
                line("gitea.home.org", Outcome::Done),
                line("n8n.home.org", Outcome::Failed("500".into())),
            ],
            ..Report::default()
        };
        assert_eq!(
            mixed.failures().as_deref(),
            Some("n8n.home.org — answered 10.77.0.11 inside the house: 500")
        );

        let stopped = Report {
            stopped: Some("the router's API key is not in the vault".into()),
            ..Report::default()
        };
        assert_eq!(
            stopped.failures().as_deref(),
            Some("the router's API key is not in the vault")
        );
    }
}
