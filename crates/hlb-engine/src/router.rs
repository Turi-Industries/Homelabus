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

use std::net::Ipv4Addr;

use hlb_orchestrator::Orchestrator;
use hlb_router::client::{Credentials, System};
use hlb_router::names::{self, Change};
use hlb_router::{Fingerprint, Opnsense};
use hlb_secrets::Vault;
use hlb_state::{RouterConfig, RouterSync, State};

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
    /// Things already as they should be.
    pub unchanged: usize,
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

    /// Makes the router answer each of `names` with Caddy's address.
    pub async fn sync(&self, names: &[String], apply: bool) -> crate::Result<Report> {
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
        if names::network_of(caddy, &router.networks().await?).is_none() {
            return Ok(r.stop(format!(
                "Caddy's address {caddy} is on none of the router's networks any more: \
                 `hlb router connect --url {} --fingerprint {} --caddy <address> --apply` \
                 again, with a key of an administrator's",
                config.url, config.fingerprint
            )));
        }
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
        Ok(r)
    }

    /// [`Router::sync`] applied to the names Caddy serves, its outcome recorded for the
    /// inbox. The night's run and a person's alike: the `hlb router sync --apply` the
    /// inbox advises must clear what it says, not leave it until the next night. No
    /// router connected records nothing — there is nothing to answer.
    pub async fn sync_recorded<O: Orchestrator + ?Sized>(
        &self,
        orch: &O,
        now: i64,
    ) -> crate::Result<Report> {
        let connected = self.state.router().await?.is_some();
        let result = match house_names(orch, self.state).await {
            Ok(names) => self.sync(&names, true).await,
            Err(e) => Err(e),
        };
        if connected {
            let failed = match &result {
                Ok(r) => r.failures(),
                // Unreachable, or refused: the names are no more answered than if a
                // line had failed.
                Err(e) => Some(format!("router sync stopped: {e}")),
            };
            let record = RouterSync { at: now, failed };
            if let Err(e) = self.state.record_router_sync(&record).await {
                tracing::warn!("router sync not recorded: {e}");
            }
        }
        result
    }

    /// What the router is, and what it answers for the house.
    pub async fn show(&self, names: &[String]) -> crate::Result<(Option<RouterConfig>, Report)> {
        let config = self.state.router().await?;
        let r = self.sync(names, false).await?;
        Ok((config, r))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
