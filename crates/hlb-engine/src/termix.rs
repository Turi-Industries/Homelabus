//! Termix, given the cluster's nodes (`access.nodes: termix`), from the installation's
//! side: the vault's keys, Swarm's nodes, a job on each. The CLI (`hlb termix`) and the
//! controller's nightly loop both run it.
//!
//! 🔴 Preview by default: nothing is generated, written or shared unless `apply` —
//! a preview's jobs mount the host read-only and say what they would change.
//!
//! What a run makes true, in this order:
//!
//! 1. The nodes' key exists: ed25519, drawn in memory, kept in the vault.
//! 2. Every node holds the account and the key — [`hlb_termix::node`] — usable only
//!    from Termix's node: its address as the others see it, and on that node itself
//!    the subnet of `docker_gwbridge`, which a container's connection to its own host
//!    comes from.
//! 3. Termix holds the key, as a credential of Homelabus's own account.
//! 4. Termix's roles from `OIDC_ROLE_MAP` exist; one host per node, removed with it,
//!    shared with each of them.
//!
//! A rotation is ordered so no moment locks Termix out: the next key is authorized
//! beside the current one on every node, then given to Termix, then made current, and
//! only then is the former one taken off. An interrupted rotation is resumed by the
//! next run, from the vault: the next key is kept until it is current.

use hlb_orchestrator::swarm::DOCKER_CLI_IMAGE;
use hlb_orchestrator::{NodeInfo, Orchestrator, ServiceSpec};
use hlb_secrets::Vault;
use hlb_state::State;
use hlb_termix::hosts::{self, Change};
use hlb_termix::{node, NodeKey, Termix};
use hlb_types::access::Nodes;
use hlb_types::Manifest;

use crate::roles::{Line, Outcome};

/// The Termix account Homelabus works as, and its key's name.
pub const ACCOUNT: &str = "homelabus";
const KEY_NAME: &str = "Homelabus";
const CREDENTIAL: &str = "Homelabus — the nodes' key";
/// The purpose the keys are kept under. ⚠️ A stored value.
const PURPOSE: &str = "termix";
const JOB_TIMEOUT_S: u64 = 120;

/// What a run found, and did.
#[derive(Debug, Default)]
pub struct Report {
    /// The app holding the nodes.
    pub app: Option<String>,
    pub lines: Vec<Line>,
    /// Things already as they should be.
    pub unchanged: usize,
    /// Each node's ed25519 host key, as Termix will ask a person to accept it at their
    /// first connection: compared with this, accepting it is not a guess.
    pub host_keys: Vec<(String, String)>,
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

/// Everything a run reaches.
pub struct NodeAccess<'a> {
    pub state: &'a State,
    pub vault: &'a Vault,
    pub orchestrator: &'a dyn Orchestrator,
    /// Turns an overlay address into one this process reaches.
    pub reach: &'a (dyn Fn(&str) -> String + Send + Sync),
}

/// The installed app keeping the nodes.
struct App {
    name: String,
    port: u16,
    manifest: Manifest,
    domain: Option<String>,
}

/// What an administrator does, once, for Homelabus to work in Termix.
pub fn connect_steps(domain: Option<&str>) -> String {
    let at = domain.map_or_else(|| "Termix".to_string(), |d| format!("https://{d}"));
    format!(
        "Homelabus works in Termix as an account of its own, which an administrator lets \
         in once — making an API key takes a session:\n\
         \x20 1. Sign in to {at} through PocketID, as an administrator.\n\
         \x20 2. Administration → API Keys → create one for yourself, expiring tomorrow.\n\
         \x20 3. `hlb termix connect --apply`, and paste it when asked: Homelabus makes its \
         own account and key with it, then deletes yours."
    )
}

impl NodeAccess<'_> {
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

    async fn key(&self, name: &str) -> crate::Result<Option<NodeKey>> {
        Ok(match self.secret(name).await? {
            Some(pem) => Some(NodeKey::from_openssh(&pem)?),
            None => None,
        })
    }

    async fn app(&self) -> crate::Result<Result<App, String>> {
        let mut found = Vec::new();
        for (name, status) in self.state.installed_apps().await? {
            if status == "failed" {
                continue;
            }
            let m = self.state.app_manifest(&name).await?;
            if m.spec.access.as_ref().and_then(|a| a.nodes) == Some(Nodes::Termix) {
                found.push((name, m));
            }
        }
        Ok(match found.len() {
            1 => {
                let (name, manifest) = found.remove(0);
                let domain = self.state.app_domain(&name).await?;
                Ok(App {
                    port: manifest.spec.ingress.first().map_or(8080, |i| i.port),
                    name,
                    manifest,
                    domain,
                })
            }
            0 => Err("no app keeping the nodes is installed — `hlb install termix --apply`".into()),
            n => Err(format!(
                "{n} apps keep the nodes: one key and one account per node, and nothing says \
                 which app they are for"
            )),
        })
    }

    fn client(&self, app: &App, token: &str) -> Termix {
        Termix::new(
            (self.reach)(&format!("http://{}:{}", app.name, app.port)),
            token,
        )
    }

    /// Turns an administrator's key into Homelabus's own account and key, then deletes
    /// the administrator's. `token` is read from them, never from a command line.
    pub async fn connect(&self, token: &str, apply: bool) -> crate::Result<Report> {
        let mut r = Report::default();
        let app = match self.app().await? {
            Ok(a) => a,
            Err(why) => return Ok(r.stop(why)),
        };
        r.app = Some(app.name.clone());
        let given = self.client(&app, token);
        let me = match given.me().await {
            Ok(me) => me,
            Err(hlb_termix::Error::Unauthorized) => {
                return Ok(r.stop(format!(
                    "Termix refused that key.\n{}",
                    connect_steps(app.domain.as_deref())
                )))
            }
            Err(e) => return Err(e.into()),
        };
        if !me.is_admin {
            return Ok(r.stop(format!(
                "that key signs in as {}, who is not an administrator of Termix: only an \
                 administrator's key can make Homelabus's account",
                me.username
            )));
        }

        let ours = given
            .users()
            .await?
            .into_iter()
            .find(|u| u.username == ACCOUNT);
        if ours.as_ref().is_some_and(|u| u.is_external) {
            return Ok(r.stop(format!(
                "an account named \"{ACCOUNT}\" signs in to Termix through PocketID: Homelabus \
                 does not take over a person's account"
            )));
        }
        if !apply {
            let what = match &ours {
                None => "made, as an administrator",
                Some(u) if !u.is_admin => "made an administrator",
                Some(_) => "kept",
            };
            r.push(ACCOUNT, format!("Termix account {what}"), Outcome::ToDo);
            r.push(ACCOUNT, "its own API key, kept in the vault", Outcome::ToDo);
            r.push(&me.username, "the key given here, deleted", Outcome::ToDo);
            return Ok(r);
        }

        let user = match ours {
            Some(u) => u,
            None => {
                // Termix asks for a password and nobody signs in with one — password
                // sign-in is closed — so none is kept.
                given
                    .create_user(ACCOUNT, &hlb_secrets::generate_password(40))
                    .await?;
                r.push(ACCOUNT, "Termix account made", Outcome::Done);
                given
                    .users()
                    .await?
                    .into_iter()
                    .find(|u| u.username == ACCOUNT)
                    .ok_or_else(|| {
                        hlb_termix::Error::Unexpected(format!("\"{ACCOUNT}\" not found once made"))
                    })?
            }
        };
        if !user.is_admin {
            given.make_admin(&user.id).await?;
            r.push(ACCOUNT, "made an administrator", Outcome::Done);
        }
        let (made, own) = given.create_api_key(KEY_NAME, &user.id).await?;
        self.keep(&Nodes::api_key_secret(&app.name), &own).await?;
        r.push(ACCOUNT, "its own API key, kept in the vault", Outcome::Done);

        // Through the new key from here: it is the one that has to work.
        let termix = self.client(&app, &own);
        let given_prefix = hlb_termix::client::token_prefix(token);
        for k in termix.api_keys().await? {
            let former = k.user_id == user.id && k.name == KEY_NAME && k.id != made.id;
            if k.token_prefix == given_prefix || former {
                termix.delete_api_key(&k.id).await?;
                let whose = if former {
                    ACCOUNT
                } else {
                    me.username.as_str()
                };
                r.push(
                    whose,
                    format!("API key \"{}\" deleted", k.name),
                    Outcome::Done,
                );
            }
        }
        Ok(r)
    }

    /// Generates the next key — the run that follows moves every node and Termix to it.
    pub async fn rotate(&self, apply: bool) -> crate::Result<Report> {
        let app = match self.app().await? {
            Ok(a) => a,
            Err(why) => return Ok(Report::default().stop(why)),
        };
        let next = Nodes::next_node_key_secret(&app.name);
        if apply && self.secret(&next).await?.is_none() {
            let k = NodeKey::generate(&node::marker(&app.name));
            self.keep(&next, &k.openssh_private()).await?;
        }
        self.run(apply).await
    }

    /// Makes every node, and Termix, hold what they should.
    pub async fn run(&self, apply: bool) -> crate::Result<Report> {
        let mut r = Report::default();
        let app = match self.app().await? {
            Ok(a) => a,
            Err(why) => return Ok(r.stop(why)),
        };
        r.app = Some(app.name.clone());
        let Some(token) = self.secret(&Nodes::api_key_secret(&app.name)).await? else {
            return Ok(r.stop(connect_steps(app.domain.as_deref())));
        };
        let termix = self.client(&app, &token);
        match termix.me().await {
            Ok(me) if me.is_admin => {}
            Ok(me) => {
                r.push(
                    &me.username,
                    "is no longer an administrator of Termix",
                    Outcome::Failed(
                        "an administrator makes it one again: Administration → Users".into(),
                    ),
                );
                return Ok(r);
            }
            Err(hlb_termix::Error::Unauthorized) => {
                r.push(
                    ACCOUNT,
                    "its API key was refused",
                    Outcome::Failed(connect_steps(app.domain.as_deref())),
                );
                return Ok(r);
            }
            Err(e) => return Err(e.into()),
        }

        let nodes = {
            let mut n = self.orchestrator.nodes().await?;
            n.sort_by(|a, b| a.hostname.cmp(&b.hostname));
            n
        };
        let Some(here) = self.termix_node(&app.name, &nodes).await? else {
            return Ok(r.stop(format!(
                "{} runs on no node and none holds its data: where its connections come from \
                 cannot be told",
                app.name
            )));
        };
        let Some(addr) = here.addr.clone() else {
            return Ok(r.stop(format!(
                "Swarm gives no address for {}, where {} runs",
                here.hostname, app.name
            )));
        };
        // 🔴 Per node. Every node's `docker_gwbridge` has the same default subnet: on
        // any line but the Termix node's own, it would let a container of that node use
        // the key against its own host.
        let elsewhere = vec![addr];
        let at_home = match self.gateway_subnets(here).await {
            Ok(s) => s,
            Err(why) => {
                r.push(
                    &here.hostname,
                    "read docker_gwbridge's subnet",
                    Outcome::Failed(why),
                );
                return Ok(r);
            }
        };

        // 1. The keys.
        let current_name = Nodes::node_key_secret(&app.name);
        let next_name = Nodes::next_node_key_secret(&app.name);
        let marker = node::marker(&app.name);
        let current = match self.key(&current_name).await? {
            Some(k) => k,
            None => {
                let k = NodeKey::generate(&marker);
                if apply {
                    self.keep(&current_name, &k.openssh_private()).await?;
                }
                r.push(
                    "the nodes' key",
                    format!("generated ({})", k.fingerprint()),
                    done_if(apply),
                );
                k
            }
        };
        let next = self.key(&next_name).await?;

        // 2. The nodes: the current key, and the next beside it while a rotation runs.
        let lines = |keys: &[&NodeKey]| {
            let from = |n: &NodeInfo| {
                if n.id == here.id {
                    &at_home
                } else {
                    &elsewhere
                }
            };
            nodes
                .iter()
                .map(|n| {
                    let l = keys
                        .iter()
                        .map(|k| node::line(&k.public_body(), from(n), &marker))
                        .collect();
                    (n, l)
                })
                .collect::<Vec<(&NodeInfo, Vec<String>)>>()
        };
        let mut both = vec![&current];
        both.extend(next.as_ref());
        let everywhere = self.nodes(&mut r, &app.name, &lines(&both), apply).await;

        // 3. Termix holds the next key once every node accepts it; the current one until.
        let target = match &next {
            Some(n) if everywhere => n,
            Some(_) => {
                r.notes.push(
                    "a rotation waits on the nodes above: Termix moves to the new key once \
                     every node accepts it — a node down for good leaves the cluster first \
                     (`docker node rm`)"
                        .into(),
                );
                &current
            }
            None => &current,
        };
        let account = node::account(&app.name);
        let credential = self
            .credential(&mut r, &termix, target, &account, apply)
            .await?;

        // The rotation ends: the next key becomes the current one, and the former leaves
        // the nodes.
        if let Some(n) = next.as_ref().filter(|n| *n == target) {
            if apply {
                self.keep(&current_name, &n.openssh_private()).await?;
                self.state.forget_secret(&next_name).await?;
            }
            r.push(
                "the nodes' key",
                format!("rotated to {}", n.fingerprint()),
                done_if(apply),
            );
            self.nodes(&mut r, &app.name, &lines(&[n]), apply).await;
        }

        // 4. Roles, hosts, shares.
        let roles = self.roles(&mut r, &termix, &app, apply).await?;
        self.hosts(&mut r, &termix, &nodes, &account, credential, &roles, apply)
            .await?;
        Ok(r)
    }

    /// The node Termix runs on: its running task's, or the one holding its data.
    async fn termix_node<'n>(
        &self,
        app: &str,
        nodes: &'n [NodeInfo],
    ) -> crate::Result<Option<&'n NodeInfo>> {
        let running = self
            .orchestrator
            .tasks(Some(app))
            .await?
            .into_iter()
            .find(|t| t.is_alive())
            .and_then(|t| t.node_id);
        Ok(match running {
            Some(id) => nodes.iter().find(|n| n.id == id),
            None => nodes.iter().find(|n| n.data.iter().any(|d| d == app)),
        })
    }

    /// The subnet a container's connection to its own host comes from, on `node`.
    async fn gateway_subnets(&self, node: &NodeInfo) -> Result<Vec<String>, String> {
        let mut job = ServiceSpec::new(
            format!("hlb-termix-gw-{}", short(&node.id)),
            DOCKER_CLI_IMAGE,
        )
        .job()
        .constraint(format!("node.id=={}", node.id))
        .bind("/var/run/docker.sock", "/var/run/docker.sock", false)
        .command([
            "docker",
            "network",
            "inspect",
            "docker_gwbridge",
            "--format",
            "{{range .IPAM.Config}}{{.Subnet}} {{end}}",
        ]);
        job.hardening.read_only_rootfs = false;
        let out = self
            .orchestrator
            .run_job(&job, JOB_TIMEOUT_S)
            .await
            .map_err(|e| e.to_string())?;
        if !out.succeeded {
            return Err(out.output.join(" | "));
        }
        let subnets: Vec<String> = out
            .output
            .iter()
            .flat_map(|l| l.split_whitespace())
            .filter(|s| s.contains('/'))
            .map(str::to_string)
            .collect();
        if subnets.is_empty() {
            return Err(format!(
                "docker_gwbridge has no subnet on {}: {}",
                node.hostname,
                out.output.join(" | ")
            ));
        }
        Ok(subnets)
    }

    /// Runs the node script on every node, with that node's lines. `true` when every
    /// one holds them — or would, in a preview.
    async fn nodes(
        &self,
        r: &mut Report,
        app: &str,
        nodes: &[(&NodeInfo, Vec<String>)],
        apply: bool,
    ) -> bool {
        let user = node::account(app);
        let mut everywhere = true;
        for (n, lines) in nodes {
            let script = node::host_script(&user, &node::marker(app), lines, !apply);
            if !n.is_ready() {
                r.push(
                    &n.hostname,
                    "account and key",
                    Outcome::Waiting(format!("the node is {}: done when it is back", n.status)),
                );
                everywhere = false;
                continue;
            }
            let mut job =
                ServiceSpec::new(format!("hlb-termix-{}", short(&n.id)), DOCKER_CLI_IMAGE)
                    .job()
                    .constraint(format!("node.id=={}", n.id))
                    // A preview reads the host and cannot write it.
                    .bind("/", "/host", !apply)
                    .command(["chroot", "/host", "/bin/sh", "-c", script.as_str()]);
            // `useradd` and the files it writes, then `chroot` itself.
            job.hardening.cap_add = ["CHOWN", "DAC_OVERRIDE", "FOWNER", "SYS_CHROOT"]
                .map(String::from)
                .to_vec();
            let outcome = match self.orchestrator.run_job(&job, JOB_TIMEOUT_S).await {
                Ok(o) if o.succeeded => node::Outcome::read(&o.output)
                    .ok_or_else(|| format!("the script did not end: {}", o.output.join(" | "))),
                Ok(o) => Err(o.output.join(" | ")),
                Err(e) => Err(e.to_string()),
            };
            match outcome {
                Err(why) => {
                    r.push(&n.hostname, "account and key", Outcome::Failed(why));
                    everywhere = false;
                }
                Ok(o) => {
                    if let Some(k) = o.host_key {
                        r.host_keys.push((n.hostname.clone(), k));
                    }
                    if !o.refused.is_empty() {
                        r.push(
                            &n.hostname,
                            format!("{user} is refused by sshd"),
                            Outcome::NotConfigured(o.refused.join("; ")),
                        );
                        everywhere = false;
                    }
                    let change = match (o.created, o.written) {
                        (true, _) => format!("{user} made, its key authorized"),
                        (false, true) => format!("{user}'s key authorized"),
                        (false, false) => {
                            r.unchanged += 1;
                            continue;
                        }
                    };
                    r.push(&n.hostname, change, done_if(apply));
                }
            }
        }
        everywhere
    }

    /// The credential holding `key`, by its id — 0 in a preview that would make it.
    async fn credential(
        &self,
        r: &mut Report,
        termix: &Termix,
        key: &NodeKey,
        account: &str,
        apply: bool,
    ) -> crate::Result<i64> {
        let held = termix
            .credentials()
            .await?
            .into_iter()
            .find(|c| c.name == CREDENTIAL);
        let pem = key.openssh_private();
        Ok(match held {
            None => {
                let id = if apply {
                    termix
                        .create_credential(CREDENTIAL, account, &pem)
                        .await?
                        .id
                } else {
                    0
                };
                r.push(
                    "Termix",
                    format!("credential \"{CREDENTIAL}\" made"),
                    done_if(apply),
                );
                id
            }
            Some(c)
                if c.public_key.as_deref() != Some(key.public_body().as_str())
                    || c.username.as_deref() != Some(account) =>
            {
                if apply {
                    termix
                        .update_credential(c.id, CREDENTIAL, account, &pem)
                        .await?;
                }
                r.push(
                    "Termix",
                    format!("credential given the key {}", key.fingerprint()),
                    done_if(apply),
                );
                c.id
            }
            Some(c) => {
                r.unchanged += 1;
                c.id
            }
        })
    }

    /// The roles `OIDC_ROLE_MAP` gives, made where missing; their ids.
    async fn roles(
        &self,
        r: &mut Report,
        termix: &Termix,
        app: &App,
        apply: bool,
    ) -> crate::Result<Vec<i64>> {
        let wanted = app
            .manifest
            .spec
            .env
            .get("OIDC_ROLE_MAP")
            .map(|m| hosts::mapped_roles(m))
            .unwrap_or_default();
        if wanted.is_empty() {
            r.notes.push(format!(
                "{} gives no role at sign-in (`OIDC_ROLE_MAP`): the nodes are shared with nobody",
                app.name
            ));
            return Ok(Vec::new());
        }
        let mut held = termix.roles().await?;
        let mut ids = Vec::new();
        for name in wanted {
            if !held.iter().any(|h| h.name == name) {
                if apply {
                    termix
                        .create_role(
                            &name,
                            "The cluster's nodes",
                            "Given at sign-in from PocketID's groups: every node of the \
                             cluster, kept by Homelabus.",
                        )
                        .await?;
                    held = termix.roles().await?;
                }
                r.push("Termix", format!("role \"{name}\" made"), done_if(apply));
            } else {
                r.unchanged += 1;
            }
            ids.extend(held.iter().filter(|h| h.name == name).map(|h| h.id));
        }
        Ok(ids)
    }

    #[allow(clippy::too_many_arguments)]
    async fn hosts(
        &self,
        r: &mut Report,
        termix: &Termix,
        nodes: &[NodeInfo],
        account: &str,
        credential: i64,
        roles: &[i64],
        apply: bool,
    ) -> crate::Result<()> {
        let mut wanted = Vec::new();
        for n in nodes {
            match &n.addr {
                Some(a) => wanted.push(hosts::wanted(&n.hostname, a, account, credential)),
                None => r.push(
                    &n.hostname,
                    "its Termix host",
                    Outcome::Waiting("Swarm gives no address for it yet".into()),
                ),
            }
        }
        let held = termix.hosts().await?;
        // Homelabus's hosts once the plan is applied, by id and name: what is shared.
        let mut ours: Vec<(i64, String)> = Vec::new();
        for change in hosts::plan(&wanted, &held) {
            match change {
                Change::Same { id, name } => {
                    r.unchanged += 1;
                    ours.push((id, name));
                }
                Change::Create(h) => {
                    r.push(
                        &h.name,
                        format!("Termix host → {}:{}", h.ip, h.port),
                        done_if(apply),
                    );
                    if apply {
                        ours.push((termix.create_host(&h).await?.id, h.name));
                    } else {
                        for _ in roles {
                            r.push(&h.name, "shared with the role, to connect", Outcome::ToDo);
                        }
                    }
                }
                Change::Update { id, host, what } => {
                    if apply {
                        termix.update_host(id, &host).await?;
                    }
                    r.push(
                        &host.name,
                        format!("Termix host: {}", what.join(", ")),
                        done_if(apply),
                    );
                    ours.push((id, host.name));
                }
                Change::Delete { id, name } => {
                    if apply {
                        termix.delete_host(id).await?;
                    }
                    r.push(&name, "Termix host removed: the node left", done_if(apply));
                }
            }
        }
        for (id, name) in ours {
            let access = termix.host_access(id).await?;
            for role in roles {
                if access
                    .iter()
                    .any(|a| a.role_id == Some(*role) && a.permission_level == "connect")
                {
                    r.unchanged += 1;
                    continue;
                }
                if apply {
                    termix.share_host(id, *role).await?;
                }
                r.push(&name, "shared with the role, to connect", done_if(apply));
            }
        }
        Ok(())
    }
}

fn done_if(apply: bool) -> Outcome {
    if apply {
        Outcome::Done
    } else {
        Outcome::ToDo
    }
}

/// A job's name may not exceed Swarm's 63 characters; a node id is 25.
fn short(id: &str) -> &str {
    id.get(..12).unwrap_or(id)
}
