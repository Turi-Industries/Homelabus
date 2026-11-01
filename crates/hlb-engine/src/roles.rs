//! The roles, made true where they are read: PocketID's groups and claims, each native
//! client's restriction, a quota inside an app, a Bitwarden organisation's members.
//!
//! The rule is `hlb_users::access`; this reads what the copies hold, and changes the
//! difference — line by line, so a preview says exactly what an apply would do, and an
//! apply what it did. The CLI (`hlb role sync`) and the controller's loop both run it.
//!
//! What it does not do: a route behind the portal is checked against its groups at
//! every request, and those are written into the Caddyfile when it is published — which
//! allowing or denying a role does (`ingress::publish`).
//!
//! 🔴 Preview by default: nothing is written unless `apply`.

use std::collections::{BTreeMap, BTreeSet};

use hlb_identity::groups::Group as PocketGroup;
use hlb_identity::{PocketId, User as PocketUser, UserChange};
use hlb_orchestrator::Orchestrator;
use hlb_secrets::Vault;
use hlb_state::{AdminRecord, QuotaRecord, QuotaState, State};
use hlb_types::access::{
    role_of_group, AccountsApply, Members, QuotaApply, QuotaUnit, ABSENT_EXIT,
};
use hlb_types::{Capability, DbEngine, Manifest};
use hlb_users::access::{self, AdminTask, Desired, Entry, Installed, Opening, Person, QuotaTask};
use hlb_users::RoleDef;

/// How a quota already set is trusted before it is set again: someone may have
/// changed it in the app since.
const QUOTA_REFRESH_S: i64 = 86_400;

/// One difference, and what became of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
    /// What it concerns: a group, an app, a person in an app.
    pub subject: String,
    pub change: String,
    pub outcome: Outcome,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// What an apply would do.
    ToDo,
    Done,
    /// Not possible yet, and retried: someone who never signed in to the app.
    Waiting(String),
    /// What Homelabus cannot do until someone does something first.
    NotConfigured(String),
    Failed(String),
}

/// What a sync found, and did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    pub lines: Vec<Line>,
    /// What the rule could not do as asked (`hlb_users::access::Note`).
    pub notes: Vec<String>,
    /// How many things were already as they should be.
    pub unchanged: usize,
}

impl Report {
    pub fn failed(&self) -> bool {
        self.lines
            .iter()
            .any(|l| matches!(l.outcome, Outcome::Failed(_)))
    }

    fn push(&mut self, subject: impl Into<String>, change: impl Into<String>, outcome: Outcome) {
        self.lines.push(Line {
            subject: subject.into(),
            change: change.into(),
            outcome,
        });
    }
}

/// Everything a sync reaches.
pub struct RoleSync<'a> {
    pub state: &'a State,
    pub vault: &'a Vault,
    pub orchestrator: &'a dyn Orchestrator,
    /// Turns an overlay address into one this process reaches: the identity in the
    /// controller, a relay from a host (`relay::reach`).
    pub reach: &'a (dyn Fn(&str) -> String + Send + Sync),
    /// The apps' own APIs, for the accounts they keep (`access.accounts`).
    pub http: &'a dyn hlb_guide::ApiClient,
    pub now: i64,
}

/// What the rule is computed from.
pub struct Inputs {
    pub roles: Vec<RoleDef>,
    pub people: Vec<Person>,
    /// Installed apps, their frozen manifests, the roles they let in.
    pub apps: Vec<(Manifest, BTreeSet<String>)>,
}

impl Inputs {
    pub async fn read(state: &State) -> crate::Result<Self> {
        let roles = state.roles().await?;
        let mut own = state.person_quotas().await?;
        let accounts = state.accounts().await?;
        let people = accounts
            .into_iter()
            .map(|a| Person {
                quotas: own
                    .remove(&a.name)
                    .unwrap_or_default()
                    .into_iter()
                    .map(|q| (q.app, q.bytes))
                    .collect(),
                email: a.default_mailbox().map(|b| b.address()),
                sub: a.pocket_id,
                role: a.role,
                name: a.name,
            })
            .collect();
        let mut allowed = state.app_roles().await?;
        let mut apps = Vec::new();
        for (name, status) in state.installed_apps().await? {
            if status == "failed" {
                continue;
            }
            let m = state.app_manifest(&name).await?;
            apps.push((m, allowed.remove(&name).unwrap_or_default()));
        }
        Ok(Self {
            roles,
            people,
            apps,
        })
    }

    pub fn installed(&self) -> Vec<Installed<'_>> {
        self.apps
            .iter()
            .map(|(m, allowed)| Installed {
                manifest: m,
                allowed: allowed.clone(),
            })
            .collect()
    }

    pub fn desired(&self) -> Desired {
        access::desired(&self.roles, &self.people, &self.installed())
    }
}

/// What giving this role — or raising it to its level — opens beyond Homelabus.
pub async fn opened_by(state: &State, role: &RoleDef) -> crate::Result<Vec<Opening>> {
    let inputs = Inputs::read(state).await?;
    Ok(access::opens(role, &inputs.installed()))
}

/// The groups the portal checks for each app behind it, by app: what its route is
/// published with.
pub async fn portal_groups(state: &State) -> crate::Result<BTreeMap<String, Vec<String>>> {
    let inputs = Inputs::read(state).await?;
    Ok(inputs
        .desired()
        .doors
        .into_iter()
        .filter(|(_, d)| d.entry == Entry::Portal)
        .map(|(app, d)| (app, d.groups.into_iter().collect()))
        .collect())
}

impl RoleSync<'_> {
    async fn read_secret(&self, name: &str) -> crate::Result<Option<String>> {
        match self.state.secret(name).await? {
            Some(ct) => Ok(Some(self.vault.decrypt(&ct)?)),
            None => Ok(None),
        }
    }

    /// Makes the copies match, or — `apply` false — says what that would change.
    pub async fn run(&self, apply: bool) -> crate::Result<Report> {
        let inputs = Inputs::read(self.state).await?;
        let desired = inputs.desired();
        let mut report = Report {
            notes: desired.notes.iter().map(ToString::to_string).collect(),
            ..Report::default()
        };
        let names: BTreeMap<&str, &str> = inputs
            .people
            .iter()
            .filter_map(|p| Some((p.sub.as_deref()?, p.name.as_str())))
            .collect();

        let access = crate::access::from_vault(self.state, self.vault).await?;
        match &access.pocketid {
            None => report.push(
                "PocketID",
                "groups, claims and restrictions",
                Outcome::NotConfigured(
                    "PocketID is not installed, or its API key is not in the vault: no app \
                     can be restricted to its roles"
                        .into(),
                ),
            ),
            Some((url, key)) => {
                let pid = PocketId::new((self.reach)(url), key.clone());
                if let Err(e) = self
                    .pocketid(&pid, &desired, &names, &inputs.people, apply, &mut report)
                    .await
                {
                    report.push(
                        "PocketID",
                        "reading or writing",
                        Outcome::Failed(e.to_string()),
                    );
                }
            }
        }

        let manifests: BTreeMap<&str, &Manifest> = inputs
            .apps
            .iter()
            .map(|(m, _)| (m.metadata.name.as_str(), m))
            .collect();
        self.quotas(&desired.quotas, &manifests, &access, apply, &mut report)
            .await?;
        self.admins(&desired.admins, &manifests, apply, &mut report)
            .await?;
        self.members(&desired, &manifests, apply, &mut report)
            .await?;
        self.accounts(&desired, &manifests, &names, apply, &mut report)
            .await?;
        if let Some((url, user, password)) = &access.stalwart_admin {
            let mail = hlb_mail::Stalwart::new(
                (self.reach)(url),
                hlb_mail::Auth::Basic {
                    user: user.clone(),
                    password: password.clone(),
                },
            );
            let domains: BTreeSet<&str> = inputs
                .people
                .iter()
                .filter_map(|p| p.email.as_deref()?.split_once('@').map(|(_, d)| d))
                .collect();
            match crate::submission::protect_platform(self.orchestrator, &mail, apply).await {
                Ok(changed) if changed.is_empty() => report.unchanged += 1,
                Ok(changed) => {
                    for c in changed {
                        let outcome = if apply { Outcome::Done } else { Outcome::ToDo };
                        report.push("Stalwart", c, outcome);
                    }
                }
                Err(e) => report.push(
                    "Stalwart",
                    "never ban the platform network",
                    Outcome::Failed(e.to_string()),
                ),
            }
            match crate::submission::trace(&mail, apply).await {
                Ok(changed) if changed.is_empty() => report.unchanged += 1,
                Ok(changed) => {
                    for c in changed {
                        let outcome = if apply { Outcome::Done } else { Outcome::ToDo };
                        report.push("Stalwart", c, outcome);
                    }
                }
                Err(e) => report.push(
                    "Stalwart",
                    "its traces in its logs",
                    Outcome::Failed(e.to_string()),
                ),
            }
            match crate::submission::own_resolver(self.orchestrator, &mail, apply).await {
                Ok(changed) if changed.is_empty() => report.unchanged += 1,
                Ok(changed) => {
                    for c in changed {
                        let outcome = if apply { Outcome::Done } else { Outcome::ToDo };
                        report.push("Stalwart", c, outcome);
                    }
                }
                Err(e) => report.push(
                    "Stalwart",
                    "resolve through its own resolver",
                    Outcome::Failed(e.to_string()),
                ),
            }
            match crate::submission::name_server(self.state, &mail, apply).await {
                Ok(changed) if changed.is_empty() => report.unchanged += 1,
                Ok(changed) => {
                    for c in changed {
                        let outcome = if apply { Outcome::Done } else { Outcome::ToDo };
                        report.push("Stalwart", c, outcome);
                    }
                }
                Err(e) => report.push(
                    "Stalwart",
                    "answer as its public name",
                    Outcome::Failed(e.to_string()),
                ),
            }
            match crate::mail_dns::publish_dkim(self.state, self.vault, &mail, apply).await {
                Ok(changed) if changed.is_empty() => report.unchanged += 1,
                Ok(changed) => {
                    for c in changed {
                        let outcome = if apply { Outcome::Done } else { Outcome::ToDo };
                        report.push("Stalwart", c, outcome);
                    }
                }
                Err(e) => report.push(
                    "Stalwart",
                    "publish DKIM through the DNS provider",
                    Outcome::Failed(e.to_string()),
                ),
            }
            match crate::mail_tls::certify(self.state, self.vault, &mail, apply).await {
                Ok(changed) if changed.is_empty() => report.unchanged += 1,
                Ok(changed) => {
                    for c in changed {
                        let outcome = if apply { Outcome::Done } else { Outcome::ToDo };
                        report.push("Stalwart", c, outcome);
                    }
                }
                Err(e) => report.push(
                    "Stalwart",
                    "a certificate for people's mail clients",
                    Outcome::Failed(e.to_string()),
                ),
            }
            for domain in domains {
                if let Err(e) =
                    postmaster(&mail, domain, &desired.postmaster, apply, &mut report).await
                {
                    report.push(
                        format!("{}@{domain}", hlb_mail::POSTMASTER),
                        "reading or writing",
                        Outcome::Failed(e.to_string()),
                    );
                }
            }
        }
        Ok(report)
    }

    async fn pocketid(
        &self,
        pid: &PocketId,
        desired: &Desired,
        names: &BTreeMap<&str, &str>,
        people: &[Person],
        apply: bool,
        report: &mut Report,
    ) -> crate::Result<()> {
        let who = |subs: &BTreeSet<String>| -> String {
            subs.iter()
                .map(|s| names.get(s.as_str()).copied().unwrap_or(s.as_str()))
                .collect::<Vec<_>>()
                .join(", ")
        };
        let mut ids: BTreeMap<String, String> = BTreeMap::new();
        let existing = pid.groups("hlb-").await?;

        for (name, g) in &desired.groups {
            let found = existing.iter().find(|e| &e.name == name);
            let Some(found) = found else {
                report.push(
                    name,
                    format!(
                        "create \"{}\": {}{}",
                        g.friendly_name,
                        if g.members.is_empty() {
                            "nobody yet".to_string()
                        } else {
                            who(&g.members)
                        },
                        claims_said(&g.claims)
                    ),
                    if apply {
                        let id = pid.create_group(name, &g.friendly_name).await?;
                        pid.set_members(&id, &g.members).await?;
                        pid.set_group_claims(&id, &g.claims).await?;
                        ids.insert(name.clone(), id);
                        Outcome::Done
                    } else {
                        Outcome::ToDo
                    },
                );
                continue;
            };
            ids.insert(name.clone(), found.id.clone());
            let current: PocketGroup = pid.group(&found.id).await?;
            let mut same = true;
            if current.friendly_name != g.friendly_name {
                same = false;
                report.push(
                    name,
                    format!(
                        "rename \"{}\" → \"{}\"",
                        current.friendly_name, g.friendly_name
                    ),
                    done_if(apply, pid.rename_group(&found.id, name, &g.friendly_name)).await,
                );
            }
            if current.members != g.members {
                same = false;
                let gone: BTreeSet<String> =
                    current.members.difference(&g.members).cloned().collect();
                let new: BTreeSet<String> =
                    g.members.difference(&current.members).cloned().collect();
                let mut said = Vec::new();
                if !new.is_empty() {
                    said.push(format!("+ {}", who(&new)));
                }
                if !gone.is_empty() {
                    said.push(format!("− {}", who(&gone)));
                }
                report.push(
                    name,
                    format!("members {}", said.join(" ")),
                    done_if(apply, pid.set_members(&found.id, &g.members)).await,
                );
            }
            if current.claims != g.claims {
                same = false;
                report.push(
                    name,
                    if g.claims.is_empty() {
                        "claims: none".to_string()
                    } else {
                        format!("claims{}", claims_said(&g.claims))
                    },
                    done_if(apply, pid.set_group_claims(&found.id, &g.claims)).await,
                );
            }
            if same {
                report.unchanged += 1;
            }
        }
        for e in &existing {
            if role_of_group(&e.name).is_some() && !desired.groups.contains_key(&e.name) {
                report.push(
                    &e.name,
                    "delete: its role no longer exists",
                    done_if(apply, pid.delete_group(&e.id)).await,
                );
            }
        }

        if !desired.person_claims.is_empty() {
            let subs: BTreeSet<&str> = names.keys().copied().collect();
            for sub in subs {
                let current = pid.user_claims(sub).await?;
                let mut wanted: BTreeMap<String, serde_json::Value> = current
                    .iter()
                    .filter(|(k, _)| !desired.person_claims.contains(*k))
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
                if let Some(mine) = desired.claims_of.get(sub) {
                    wanted.extend(mine.clone());
                }
                if wanted == current {
                    report.unchanged += 1;
                    continue;
                }
                report.push(
                    names.get(sub).copied().unwrap_or(sub),
                    format!("own claims{}", claims_said(&wanted)),
                    done_if(apply, pid.set_user_claims(sub, &wanted)).await,
                );
            }
        }

        for (app, door) in &desired.doors {
            if door.entry != Entry::Client {
                continue;
            }
            let Some(client) = self.read_secret(&format!("{app}-oidc-client-id")).await? else {
                report.push(
                    app,
                    "restrict to its roles",
                    Outcome::NotConfigured(format!(
                        "no PocketID client is recorded for {app}: `hlb install {app} --apply` \
                         creates it"
                    )),
                );
                continue;
            };
            let wanted: BTreeSet<String> = door
                .groups
                .iter()
                .filter_map(|g| ids.get(g).cloned())
                .collect();
            // A group not made yet (a preview) has no id: the client is not as wanted.
            let complete = wanted.len() == door.groups.len();
            let (restricted, current) = pid.client_groups(&client).await?;
            if restricted && complete && current == wanted {
                report.unchanged += 1;
                continue;
            }
            let said = if door.closed() {
                "close: no role is let in".to_string()
            } else {
                format!(
                    "let in {}",
                    door.groups
                        .iter()
                        .map(|g| g.trim_start_matches("hlb-"))
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            };
            report.push(
                app,
                said,
                done_if(apply, pid.restrict_client(&client, &wanted)).await,
            );
        }

        // 🔴 Fluxer refuses a sign-in whose address PocketID does not say verified, and
        // a person's own came out unverified on the lab — however it got so. One read
        // per person, each on its own: one gone from PocketID stops nobody else's.
        for p in people {
            let (Some(sub), Some(own)) = (p.sub.as_deref(), p.email.as_deref()) else {
                continue;
            };
            let user = match pid.user(sub).await {
                Ok(u) => u,
                Err(e) => {
                    report.push(&p.name, "address", Outcome::Failed(e.to_string()));
                    continue;
                }
            };
            let Some(address) = unverified_own(own, &user) else {
                report.unchanged += 1;
                continue;
            };
            let change = UserChange::Email(address.clone());
            report.push(
                &p.name,
                format!("{address} verified: it is their own mailbox"),
                done_if(apply, async {
                    pid.update_user(sub, &change).await.map(drop)
                })
                .await,
            );
        }
        Ok(())
    }

    async fn quotas(
        &self,
        tasks: &[QuotaTask],
        manifests: &BTreeMap<&str, &Manifest>,
        access: &crate::access::PlatformAccess,
        apply: bool,
        report: &mut Report,
    ) -> crate::Result<()> {
        let last = self.state.quotas_applied().await?;
        for t in tasks {
            let Some(m) = manifests.get(t.app.as_str()) else {
                continue;
            };
            let Some(how) = m
                .spec
                .access
                .as_ref()
                .and_then(|a| a.quota.as_ref())
                .and_then(|q| q.apply.as_ref())
            else {
                continue;
            };
            if let Some(r) = last.get(&(t.person.clone(), t.app.clone())) {
                if r.state == QuotaState::Applied
                    && r.bytes == t.bytes
                    && self.now - r.at < QUOTA_REFRESH_S
                {
                    report.unchanged += 1;
                    continue;
                }
            }
            let said = format!(
                "quota {}{}",
                t.bytes.map_or("none".to_string(), human),
                if t.own {
                    ", their own"
                } else {
                    ", their role's"
                }
            );
            let subject = format!("{} in {}", t.person, t.app);
            if !apply {
                report.push(subject, said, Outcome::ToDo);
                continue;
            }
            let (state, detail) = match self.apply_quota(m, how, t, access).await {
                Ok(true) => (QuotaState::Applied, None),
                Ok(false) => (
                    QuotaState::Absent,
                    Some(format!(
                        "{} has not signed in to {} yet: set at the first sync after",
                        t.person, t.app
                    )),
                ),
                Err(e) => (QuotaState::Failed, Some(e)),
            };
            self.state
                .record_quota(
                    &t.person,
                    &t.app,
                    &QuotaRecord {
                        bytes: t.bytes,
                        state,
                        detail: detail.clone(),
                        at: self.now,
                    },
                )
                .await?;
            let outcome = match (state, detail) {
                (QuotaState::Applied, _) => Outcome::Done,
                (QuotaState::Absent, d) => Outcome::Waiting(d.unwrap_or_default()),
                (QuotaState::Failed, d) => Outcome::Failed(d.unwrap_or_default()),
            };
            report.push(subject, said, outcome);
        }
        Ok(())
    }

    /// Each person made an administrator of an app told by command, or no longer one.
    /// One already in step today is left: someone may have changed it in the app, and
    /// the next day says so.
    async fn admins(
        &self,
        tasks: &[AdminTask],
        manifests: &BTreeMap<&str, &Manifest>,
        apply: bool,
        report: &mut Report,
    ) -> crate::Result<()> {
        let last = self.state.admins_applied().await?;
        for t in tasks {
            let Some(m) = manifests.get(t.app.as_str()) else {
                continue;
            };
            let Some(how) = m
                .spec
                .access
                .as_ref()
                .and_then(|a| a.admins.as_ref())
                .and_then(|a| a.apply.as_ref())
            else {
                continue;
            };
            let known = last.get(&(t.person.clone(), t.app.clone()));
            if let Some(r) = known {
                if r.state == QuotaState::Applied
                    && r.admin == t.admin
                    && self.now - r.at < QUOTA_REFRESH_S
                {
                    report.unchanged += 1;
                    continue;
                }
            }
            // Nobody was ever made one: nothing to take back, and no exec per person
            // per night for it.
            if !t.admin && known.is_none() {
                report.unchanged += 1;
                continue;
            }
            let said = if t.admin {
                "made an administrator"
            } else {
                "no longer an administrator"
            };
            let subject = format!("{} in {}", t.person, t.app);
            if !apply {
                report.push(subject, said, Outcome::ToDo);
                continue;
            }
            let command = if t.admin { &how.grant } else { &how.revoke };
            let service = match &how.service {
                Some(c) => format!("{}-{c}", t.app),
                None => t.app.clone(),
            };
            let (state, detail) = match self.run_for_person(&service, command, &t.sub).await {
                Ok(true) => (QuotaState::Applied, None),
                Ok(false) => (
                    QuotaState::Absent,
                    Some(format!(
                        "{} has not signed in to {} yet: done at the first sync after",
                        t.person, t.app
                    )),
                ),
                Err(e) => (QuotaState::Failed, Some(e)),
            };
            self.state
                .record_admin(
                    &t.person,
                    &t.app,
                    &AdminRecord {
                        admin: t.admin,
                        state,
                        detail: detail.clone(),
                        at: self.now,
                    },
                )
                .await?;
            let outcome = match (state, detail) {
                (QuotaState::Applied, _) => Outcome::Done,
                (QuotaState::Absent, d) => Outcome::Waiting(d.unwrap_or_default()),
                (QuotaState::Failed, d) => Outcome::Failed(d.unwrap_or_default()),
            };
            report.push(subject, said, outcome);
        }
        Ok(())
    }

    /// `command` run in `service` for the person `sub`, never through a shell: `Ok(true)`
    /// once done, `Ok(false)` when they have no account there yet.
    async fn run_for_person(
        &self,
        service: &str,
        command: &[String],
        sub: &str,
    ) -> Result<bool, String> {
        // It goes into a command line: PocketID's ids are UUIDs, and anything else is
        // refused rather than written in.
        if sub.is_empty() || !sub.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(format!("\"{sub}\" is not a PocketID id"));
        }
        let cmd: Vec<String> = command
            .iter()
            .map(|c| {
                hlb_types::access::fill(c, |token| (token == "person.sub").then(|| sub.to_string()))
            })
            .collect();
        let out = self
            .orchestrator
            .exec_in_service(service, &cmd)
            .await
            .map_err(|e| e.to_string())?;
        match out.exit_code {
            0 => Ok(true),
            ABSENT_EXIT => Ok(false),
            code => Err(format!(
                "exit {code}: {}",
                last_line(&out.stderr)
                    .or(last_line(&out.stdout))
                    .unwrap_or("")
            )),
        }
    }

    /// Sets one person's quota in one app: `Ok(false)` when they have no account there.
    async fn apply_quota(
        &self,
        m: &Manifest,
        how: &QuotaApply,
        t: &QuotaTask,
        access: &crate::access::PlatformAccess,
    ) -> Result<bool, String> {
        // The subject goes into a command line and a statement: PocketID's ids are
        // UUIDs, and anything else is refused rather than written in.
        if t.sub.is_empty() || !t.sub.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(format!("\"{}\" is not a PocketID id", t.sub));
        }
        let fill = |text: &str, unit: QuotaUnit, none: &str| {
            hlb_types::access::fill(text, |token| match token {
                "person.sub" => Some(t.sub.clone()),
                "quota" => Some(t.bytes.map_or(none.to_string(), |b| unit.amount(b))),
                _ => None,
            })
        };
        match how {
            QuotaApply::Exec { command, unit } => {
                let cmd: Vec<String> = command.iter().map(|c| fill(c, *unit, "none")).collect();
                let out = self
                    .orchestrator
                    .exec_in_service(&m.metadata.name, &cmd)
                    .await
                    .map_err(|e| e.to_string())?;
                match out.exit_code {
                    0 => Ok(true),
                    ABSENT_EXIT => Ok(false),
                    code => Err(format!(
                        "exit {code}: {}",
                        last_line(&out.stderr)
                            .or(last_line(&out.stdout))
                            .unwrap_or("")
                    )),
                }
            }
            QuotaApply::Sql {
                statement,
                database,
                unit,
            } => {
                let (engine, db) = database_of(m, database.as_deref())
                    .ok_or_else(|| "the app requires no database".to_string())?;
                let statement = fill(statement, *unit, "NULL");
                let rows = match engine {
                    DbEngine::Postgres => {
                        let url = access
                            .postgres_admin
                            .as_deref()
                            .ok_or("PostgreSQL's administrator is not in the vault")?;
                        hlb_platform::PostgresProvisioner::connect(&(self.reach)(url))
                            .await
                            .map_err(|e| e.to_string())?
                            .write_one(&db, &statement)
                            .await
                    }
                    DbEngine::Mariadb => {
                        let url = access
                            .mariadb_admin
                            .as_deref()
                            .ok_or("MariaDB's administrator is not in the vault")?;
                        hlb_platform::MariadbProvisioner::connect(&(self.reach)(url))
                            .await
                            .map_err(|e| e.to_string())?
                            .write_one(&db, &statement)
                            .await
                    }
                }
                .map_err(|e| e.to_string())?;
                Ok(rows > 0)
            }
        }
    }

    async fn members(
        &self,
        desired: &Desired,
        manifests: &BTreeMap<&str, &Manifest>,
        apply: bool,
        report: &mut Report,
    ) -> crate::Result<()> {
        for (app, members) in &desired.members {
            let said = format!(
                "organisation members: {}",
                if members.is_empty() {
                    "none".to_string()
                } else {
                    members
                        .iter()
                        .map(|m| m.external_id.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                }
            );
            let id = self
                .read_secret(&Members::organization_id_secret(app))
                .await?;
            let key = self
                .read_secret(&Members::organization_key_secret(app))
                .await?;
            let (Some(id), Some(key)) = (id, key) else {
                report.push(
                    app,
                    said,
                    Outcome::NotConfigured(format!(
                        "no organisation to keep: an owner makes it in {app}, then stores its id \
                         and API key — `hlb secret-set {} --purpose organization` and `hlb \
                         secret-set {} --purpose organization`",
                        Members::organization_id_secret(app),
                        Members::organization_key_secret(app)
                    )),
                );
                continue;
            };
            if !apply {
                report.push(app, said, Outcome::ToDo);
                continue;
            }
            let port = manifests
                .get(app.as_str())
                .and_then(|m| m.spec.ingress.first())
                .map_or(80, |i| i.port);
            let dir = hlb_bitwarden::directory::Directory::new(
                &(self.reach)(&format!("http://{app}:{port}")),
                &id,
                &key,
            );
            let list: Vec<hlb_bitwarden::directory::Member> = members
                .iter()
                .map(|m| hlb_bitwarden::directory::Member {
                    email: m.email.clone(),
                    external_id: m.external_id.clone(),
                    deleted: false,
                })
                .collect();
            // A group per role let in; one written before whose role is gone is sent
            // once more with no member, or its people kept what its collections give.
            let wanted = desired.member_groups.get(app).cloned().unwrap_or_default();
            let before = self.state.directory_groups(app).await?;
            let mut groups: Vec<hlb_bitwarden::directory::Group> = wanted
                .iter()
                .map(|g| hlb_bitwarden::directory::Group {
                    name: g.name.clone(),
                    external_id: g.external_id.clone(),
                    member_external_ids: g.members.clone(),
                })
                .collect();
            let kept: BTreeSet<String> = wanted.iter().map(|g| g.external_id.clone()).collect();
            for gone in before.difference(&kept) {
                groups.push(hlb_bitwarden::directory::Group {
                    name: format!("{} (role removed)", gone.trim_start_matches("hlb-")),
                    external_id: gone.clone(),
                    member_external_ids: Vec::new(),
                });
            }
            let outcome = match dir.import(&list, &groups).await {
                Ok(()) => {
                    self.state.set_directory_groups(app, &kept).await?;
                    Outcome::Done
                }
                Err(e) => Outcome::Failed(e.to_string()),
            };
            report.push(app, said, outcome);
        }
        Ok(())
    }
}

impl RoleSync<'_> {
    /// Each account an app links to a PocketID identity, enabled while that person
    /// holds a role the app lets in and disabled otherwise — a person deleted from
    /// Homelabus included, which is why the app's links are walked, not the people.
    async fn accounts(
        &self,
        desired: &Desired,
        manifests: &BTreeMap<&str, &Manifest>,
        names: &BTreeMap<&str, &str>,
        apply: bool,
        report: &mut Report,
    ) -> crate::Result<()> {
        let readings = self.state.assertion_results().await?;
        for (app, m) in manifests {
            let Some(how) = m.spec.access.as_ref().and_then(|a| a.accounts.as_ref()) else {
                continue;
            };
            let AccountsApply::Http { sign_in, .. } = &how.apply;
            let proof_id = hlb_guide::assertions::recovery_id(sign_in);
            // 🔴 Never a password the app refused last time: Jellyfin disables its
            // administrator after five, and this pass runs every few minutes.
            if readings.iter().any(|(a, r)| {
                a == app && r.id == proof_id && r.verdict == hlb_api::assertions::Verdict::Broken
            }) {
                report.push(
                    *app,
                    "accounts enabled by role",
                    Outcome::NotConfigured(format!(
                        "{app} refused its recovery sign-in \"{sign_in}\" last time, and it \
                         is not tried again by itself: `hlb assert {app}` once it is fixed"
                    )),
                );
                continue;
            }
            let allowed: BTreeSet<&str> = desired
                .doors
                .get(*app)
                .into_iter()
                .flat_map(|d| &d.groups)
                .filter_map(|g| desired.groups.get(g))
                .flat_map(|g| g.members.iter().map(String::as_str))
                .collect();
            match self
                .app_accounts(app, m, &how.apply, &allowed, names, apply, report)
                .await
            {
                Ok(()) => {}
                Err(AccountsFailed::Refused(why)) => {
                    self.record_refusal(app, m, &proof_id, &why).await?;
                    report.push(*app, "accounts enabled by role", Outcome::Failed(why));
                }
                Err(AccountsFailed::Other(why)) => {
                    report.push(*app, "accounts enabled by role", Outcome::Failed(why));
                }
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn app_accounts(
        &self,
        app: &str,
        m: &Manifest,
        how: &AccountsApply,
        allowed: &BTreeSet<&str>,
        names: &BTreeMap<&str, &str>,
        apply: bool,
        report: &mut Report,
    ) -> Result<(), AccountsFailed> {
        let AccountsApply::Http {
            sign_in,
            headers,
            links,
            read,
            disabled,
            write,
        } = how;
        let other = |e: String| AccountsFailed::Other(e);
        let credential = crate::emergency::credentials(self.state, self.vault, app, m)
            .await
            .map_err(|e| other(e.to_string()))?
            .into_iter()
            .find(|c| &c.secret == sign_in);
        let proof = m
            .spec
            .recovery
            .iter()
            .find(|r| &r.secret == sign_in)
            .and_then(|r| r.proof.clone());
        let (Some(credential), Some(proof)) = (credential, proof) else {
            return Err(other(format!(
                "its recovery sign-in \"{sign_in}\" has no proof to sign in by: `hlb upgrade \
                 {app}` takes the catalog's"
            )));
        };
        let port = m.spec.ingress.first().map_or(80, |i| i.port);
        let base = (self.reach)(&format!("http://{app}:{port}"));
        let token = hlb_guide::sign_in(
            self.http,
            &base,
            &hlb_guide::ApiSignIn { credential, proof },
        )
        .await
        .map_err(|f| {
            if f.refused {
                AccountsFailed::Refused(f.why)
            } else {
                other(f.why)
            }
        })?;
        let headers: Vec<(String, String)> = headers
            .iter()
            .map(|(k, v)| (k.clone(), v.replace("{{ token }}", &token)))
            .collect();
        let get = |path: String| {
            let (url, headers) = (format!("{base}{path}"), &headers);
            async move {
                match self.http.call("GET", &url, headers, None).await {
                    Ok((200..=299, body)) => serde_json::from_str::<serde_json::Value>(&body)
                        .map_err(|_| format!("{path} answered no JSON")),
                    Ok((code, _)) => Err(format!("{path} answered {code}")),
                    Err(e) => Err(format!("{path}: {e}")),
                }
            }
        };

        let doc = get(links.path.clone()).await.map_err(other)?;
        let Some(serde_json::Value::Object(found)) = doc.pointer(&links.pointer) else {
            return Err(other(format!(
                "{} holds no object of links at {}",
                links.path, links.pointer
            )));
        };
        // One account may be linked twice — a link migrated from an older key stays
        // beside the new one: it is let in when any of its identities is.
        let mut by_account: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (sub, account) in found {
            let Some(account) = account.as_str() else {
                return Err(other(format!("the link of {sub} is not an account id")));
            };
            by_account
                .entry(account.to_string())
                .or_default()
                .push(sub.clone());
        }
        for (account, subs) in by_account {
            // It goes into a path: anything but an id is refused rather than written in.
            if account.is_empty()
                || !account
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-')
            {
                return Err(other(format!("\"{account}\" is not an account id")));
            }
            let let_in = subs.iter().any(|s| allowed.contains(s.as_str()));
            let subject = format!(
                "{} in {app}",
                subs.iter()
                    .find_map(|s| names.get(s.as_str()).copied())
                    .map_or_else(
                        || format!("PocketID id {}, no longer in Homelabus", subs.join(", ")),
                        str::to_string
                    )
            );
            let fill = |path: &str| {
                hlb_types::access::fill(path, |t| (t == "account").then(|| account.clone()))
            };
            let mut object = match get(fill(&read.path))
                .await
                .map(|j| j.pointer(&read.pointer).cloned())
            {
                Ok(Some(o)) => o,
                Ok(None) => {
                    report.push(
                        subject,
                        "reading the account",
                        Outcome::Failed(format!("no {} in its answer", read.pointer)),
                    );
                    continue;
                }
                Err(e) => {
                    report.push(subject, "reading the account", Outcome::Failed(e));
                    continue;
                }
            };
            let is_disabled = object
                .pointer(disabled)
                .and_then(serde_json::Value::as_bool);
            if is_disabled == Some(!let_in) {
                report.unchanged += 1;
                continue;
            }
            let said = if let_in {
                "enabled again: a role let in"
            } else {
                "disabled: no role let in"
            };
            if !apply {
                report.push(subject, said, Outcome::ToDo);
                continue;
            }
            let Some(flag) = object.pointer_mut(disabled) else {
                report.push(
                    subject,
                    said,
                    Outcome::Failed(format!("no {disabled} in the account to set")),
                );
                continue;
            };
            *flag = serde_json::Value::Bool(!let_in);
            let path = fill(&write.path);
            let outcome = match self
                .http
                .call(
                    &write.verb,
                    &format!("{base}{path}"),
                    &headers,
                    Some(&object.to_string()),
                )
                .await
            {
                Ok((200..=299, _)) => Outcome::Done,
                Ok((code, _)) => Outcome::Failed(format!("{path} answered {code}")),
                Err(e) => Outcome::Failed(format!("{path}: {e}")),
            };
            report.push(subject, said, outcome);
        }
        Ok(())
    }

    /// The app refused its recovery sign-in: read as the nightly proof reads it, so
    /// that neither tries it again before a person does.
    async fn record_refusal(
        &self,
        app: &str,
        m: &Manifest,
        id: &str,
        why: &str,
    ) -> crate::Result<()> {
        let mut mine: Vec<hlb_api::assertions::AssertionResult> = self
            .state
            .assertion_results()
            .await?
            .into_iter()
            .filter(|(a, _)| a == app)
            .map(|(_, r)| r)
            .collect();
        mine.retain(|r| r.id != id);
        mine.push(hlb_api::assertions::AssertionResult {
            id: id.to_string(),
            holds: hlb_guide::assertions::declared(m)
                .into_iter()
                .find(|d| d.id == id)
                .map(|d| d.holds)
                .unwrap_or_default(),
            verdict: hlb_api::assertions::Verdict::Broken,
            observed: format!("refused at the role sync: {why}"),
            checked_at: self.now,
            fix: None,
        });
        self.state.record_assertions(app, &mine).await?;
        Ok(())
    }
}

enum AccountsFailed {
    /// The recovery sign-in refused.
    Refused(String),
    Other(String),
}

/// `Done` once the write succeeded, `ToDo` when previewing — the write is not even
/// started then.
/// A mail domain's `postmaster@` and `abuse@` (RFC 2142): one shared mailbox, opened by
/// the administrators' own.
async fn postmaster(
    mail: &hlb_mail::Stalwart,
    domain: &str,
    readers: &BTreeSet<String>,
    apply: bool,
    report: &mut Report,
) -> hlb_mail::Result<()> {
    use hlb_mail::{POSTMASTER, POSTMASTER_ALIASES};
    let subject = format!("{POSTMASTER}@{domain}");
    let found = mail.shared_mailbox(POSTMASTER, domain).await?;
    let id = match found {
        Some(id) => {
            // Its aliases completed, should one have been taken away by hand.
            if apply {
                mail.ensure_shared_mailbox(POSTMASTER, domain, POSTMASTER_ALIASES)
                    .await?;
            }
            id
        }
        None => {
            let said = format!(
                "create, with {}",
                POSTMASTER_ALIASES
                    .iter()
                    .map(|a| format!("{a}@{domain}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            if !apply {
                report.push(&subject, said, Outcome::ToDo);
                if !readers.is_empty() {
                    report.push(
                        &subject,
                        format!(
                            "read by {}",
                            readers.iter().cloned().collect::<Vec<_>>().join(", ")
                        ),
                        Outcome::ToDo,
                    );
                }
                return Ok(());
            }
            let id = mail
                .ensure_shared_mailbox(POSTMASTER, domain, POSTMASTER_ALIASES)
                .await?;
            report.push(&subject, said, Outcome::Done);
            id
        }
    };

    let current: BTreeSet<String> = mail.members_of(&id).await?.into_iter().collect();
    let mut wanted = BTreeSet::new();
    for address in readers {
        match mail.account_of(address).await? {
            Some(account) => {
                wanted.insert(account.clone());
                if !current.contains(&account) {
                    report.push(
                        &subject,
                        format!("read by {address}"),
                        done_if(apply, mail.set_member(&account, &id, true)).await,
                    );
                }
            }
            None => report.push(
                &subject,
                format!("read by {address}"),
                Outcome::Waiting(format!("{address} has no mailbox in Stalwart yet")),
            ),
        }
    }
    for account in current.difference(&wanted) {
        report.push(
            &subject,
            format!("no longer read by account {account}: not an administrator's"),
            done_if(apply, mail.set_member(account, &id, false)).await,
        );
    }
    if current == wanted {
        report.unchanged += 1;
    }
    Ok(())
}

/// The address to say verified in PocketID: the person's own mailbox, when PocketID
/// holds it unverified. ⚠️ Never one they typed in PocketID themselves — Homelabus
/// vouches for the mailboxes it made them, and for nothing else.
fn unverified_own(own: &str, user: &PocketUser) -> Option<String> {
    let same = user
        .email
        .as_deref()
        .is_some_and(|e| e.eq_ignore_ascii_case(own));
    (same && !user.email_verified).then(|| own.to_string())
}

async fn done_if<F, E>(apply: bool, write: F) -> Outcome
where
    F: std::future::Future<Output = Result<(), E>>,
    E: std::fmt::Display,
{
    if !apply {
        return Outcome::ToDo;
    }
    match write.await {
        Ok(()) => Outcome::Done,
        Err(e) => Outcome::Failed(e.to_string()),
    }
}

fn claims_said(claims: &BTreeMap<String, serde_json::Value>) -> String {
    if claims.is_empty() {
        return String::new();
    }
    format!(
        " — {}",
        claims
            .iter()
            .map(|(k, v)| format!("{k}={}", hlb_identity::groups::stored(v)))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

/// A size as a person reads it.
pub fn human(bytes: u64) -> String {
    for (unit, size) in [("TiB", 1u64 << 40), ("GiB", 1 << 30), ("MiB", 1 << 20)] {
        if bytes >= size {
            let v = bytes as f64 / size as f64;
            return if bytes.is_multiple_of(size) {
                format!("{} {unit}", bytes / size)
            } else {
                format!("{v:.1} {unit}")
            };
        }
    }
    format!("{bytes} bytes")
}

fn last_line(text: &str) -> Option<&str> {
    text.lines().rev().map(str::trim).find(|l| !l.is_empty())
}

/// The database a quota statement runs in, and its engine.
fn database_of(m: &Manifest, named: Option<&str>) -> Option<(DbEngine, String)> {
    m.spec.requires.iter().find_map(|c| match c {
        Capability::Database { engine, name, .. } => {
            let db = name.clone().unwrap_or_else(|| m.metadata.name.clone());
            (named.is_none_or(|n| n == db)).then_some((*engine, db))
        }
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_persons_own_mailbox_is_said_verified() {
        let user = |email: &str, verified: bool| PocketUser {
            id: "u".into(),
            username: "sacha".into(),
            email: Some(email.into()),
            email_verified: verified,
            first_name: String::new(),
            last_name: None,
            display_name: String::new(),
            is_admin: false,
            disabled: false,
        };
        assert_eq!(
            unverified_own("sacha@example.org", &user("Sacha@example.org", false)),
            Some("sacha@example.org".into())
        );
        assert_eq!(
            unverified_own("sacha@example.org", &user("sacha@example.org", true)),
            None,
            "already verified: nothing to write"
        );
        assert_eq!(
            unverified_own("sacha@example.org", &user("someone@else.net", false)),
            None,
            "🔴 an address typed in PocketID is nobody's to vouch for"
        );
    }

    #[test]
    fn a_size_reads_as_a_person_says_it() {
        assert_eq!(human(50 << 30), "50 GiB");
        assert_eq!(human(3 << 29), "1.5 GiB");
        assert_eq!(human(512), "512 bytes");
    }
}
