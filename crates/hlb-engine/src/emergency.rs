//! The emergency vault, from the installation's side: the account Homelabus deposits
//! as, checked against what an owner gave it, and every recovery sign-in the installed
//! manifests declare (`spec.recovery`) written into the organisation's "Server"
//! collection. The CLI (`hlb emergency vault`) and the controller's nightly loop both
//! run it.
//!
//! 🔴 Preview by default: nothing is generated, set or written unless `apply`.
//!
//! What stays an owner's, by hand, once — an organisation's key is encrypted by its
//! owners' clients: the organisation and its collection, inviting the account and
//! confirming it, the two-step policy. Homelabus then gives the account its own second
//! factor and API key, and verifies everything before it writes ([`hlb_bitwarden::emergency::check`]).

use hlb_api::breakglass::EMERGENCY_VAULT;
use hlb_bitwarden::client::{Server, Session, SignIn};
use hlb_bitwarden::crypto::{self, MasterKey};
use hlb_bitwarden::emergency::{self as bw, Change, Check, Wanted, COLLECTION};
use hlb_secrets::Vault;
use hlb_state::State;
use hlb_types::access::{EmergencyPart, Members, Nodes};

use crate::roles::{Line, Outcome};

/// Where a deposit's proof is attested from, in the break-glass record.
const PROVED_BY: &str = "the emergency vault's deposit";
/// The purpose the account's parts are kept under. ⚠️ A stored value.
const PURPOSE: &str = "emergency vault";

/// What a run found, and did.
#[derive(Debug, Default)]
pub struct Report {
    /// The Bitwarden server the vault lives in.
    pub app: Option<String>,
    /// Setting the account up, then each deposit.
    pub lines: Vec<Line>,
    /// What the account was given, read back.
    pub checks: Vec<Check>,
    /// Deposits already as they should be.
    pub unchanged: usize,
    /// What was found and left alone.
    pub notes: Vec<String>,
    /// Why the run went no further, and what a person does about it.
    pub stopped: Option<String>,
}

impl Report {
    pub fn verified(&self) -> bool {
        !self.checks.is_empty() && bw::verified(&self.checks)
    }

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
pub struct EmergencyVault<'a> {
    pub state: &'a State,
    pub vault: &'a Vault,
    /// Turns an overlay address into one this process reaches.
    pub reach: &'a (dyn Fn(&str) -> String + Send + Sync),
    /// Unix seconds: the TOTP codes, and a replaced password's date.
    pub now: i64,
}

impl EmergencyVault<'_> {
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

    /// The installed app holding a Bitwarden organisation Homelabus keeps, and its port.
    async fn server(&self) -> crate::Result<Result<(String, u16), String>> {
        let mut found = Vec::new();
        for (name, status) in self.state.installed_apps().await? {
            if status == "failed" {
                continue;
            }
            let m = self.state.app_manifest(&name).await?;
            if m.spec.access.as_ref().and_then(|a| a.members) == Some(Members::BitwardenDirectory) {
                let port = m.spec.ingress.first().map_or(80, |i| i.port);
                found.push((name, port));
            }
        }
        Ok(match found.len() {
            1 => Ok(found.remove(0)),
            0 => Err("no Bitwarden server is installed — `hlb install vaultwarden --apply`".into()),
            _ => Err(format!(
                "{} Bitwarden servers are installed: the emergency vault is in one of them, \
                 and nothing says which",
                found.len()
            )),
        })
    }

    /// Sets the account up, verifies it, and deposits — or, `apply` false, says what
    /// that would do. `address` is the account's, when it is being set.
    pub async fn run(&self, address: Option<&str>, apply: bool) -> crate::Result<Report> {
        let mut r = Report::default();
        let (app, port) = match self.server().await? {
            Ok(found) => found,
            Err(why) => return Ok(r.stop(why)),
        };
        r.app = Some(app.clone());
        let Some(org) = self.secret(&Members::organization_id_secret(&app)).await? else {
            return Ok(r.stop(format!(
                "no organisation: an owner makes it in {app}, then stores its id — `hlb \
                 secret-set {} --purpose organization`",
                Members::organization_id_secret(&app)
            )));
        };

        let email_secret = Members::emergency_secret(&app, EmergencyPart::Email);
        let email = match (address, self.secret(&email_secret).await?) {
            (Some(a), Some(kept)) if a == kept => kept,
            (Some(a), _) => {
                let outcome = if apply {
                    self.keep(&email_secret, a).await?;
                    Outcome::Done
                } else {
                    Outcome::ToDo
                };
                r.push("account", format!("its address: {a}"), outcome);
                a.to_string()
            }
            (None, Some(kept)) => kept,
            (None, None) => {
                return Ok(r.stop(
                    "no account yet: `hlb emergency vault --address <a mailbox you read> \
                     --apply` — the member an owner invites, whose invitation arrives there",
                ))
            }
        };

        let password_secret = Members::emergency_secret(&app, EmergencyPart::Password);
        let password = match self.secret(&password_secret).await? {
            Some(p) => p,
            None if apply => {
                let p = hlb_secrets::generate_password(hlb_secrets::DEFAULT_PASSWORD_LEN);
                self.keep(&password_secret, &p).await?;
                r.push("account", "its master password, generated", Outcome::Done);
                p
            }
            None => {
                r.push("account", "its master password, generated", Outcome::ToDo);
                return Ok(r.stop(owner_steps(&app, &email)));
            }
        };

        let server = Server::new(&(self.reach)(&format!("http://{app}:{port}")));
        let key_secret = Members::emergency_secret(&app, EmergencyPart::ApiKey);
        let key = match self.secret(&key_secret).await? {
            Some(k) => k,
            None => match self
                .secure(&server, &app, &email, &password, apply, &mut r)
                .await?
            {
                Some(k) => k,
                None => return Ok(r),
            },
        };
        let Some((client_id, client_secret)) = key.split_once(':') else {
            return Ok(r.stop(format!(
                "{key_secret} is not `user.<id>:<key>` — delete it, and `hlb emergency vault \
                 --apply` makes it again"
            )));
        };

        let session = match server.sign_in_with_key(client_id, client_secret).await {
            Ok(s) => s,
            Err(e) => {
                r.push("account", "sign in", Outcome::Failed(e.to_string()));
                return Ok(r);
            }
        };
        let read = match session.unlock(&email, &password) {
            Ok(me) => match session.sync().await {
                Ok(sync) => bw::read(&sync, &org, &me),
                Err(e) => Err(e),
            },
            Err(e) => Err(e),
        };
        let (view, org_key) = match read {
            Ok(v) => v,
            Err(e) => {
                r.push(
                    "account",
                    "read the organisation",
                    Outcome::Failed(e.to_string()),
                );
                return Ok(r);
            }
        };
        r.checks = bw::check(&view, &email);
        if !r.verified() {
            // 🔴 Known not to hold: the safeguard stops counting at once, rather than
            // ageing for half a year on the strength of a deposit that no longer stands.
            if apply {
                self.state.forget_breakglass(EMERGENCY_VAULT).await?;
            }
            return Ok(r.stop(
                "nothing is deposited until every check holds — an account that sees more \
                 than the Server collection, or can be revoked, is not where secrets go",
            ));
        }
        let (Some(org_key), Some(collection)) = (
            org_key,
            view.collections.iter().find(|c| c.name == COLLECTION),
        ) else {
            return Ok(r.stop("verified, and yet no collection to write into"));
        };

        if view.unreadable > 0 {
            r.notes.push(format!(
                "{} the organisation holds {} cannot read — a format newer clients write; \
                 left as they are, none being Homelabus's",
                hlb_api::plural(view.unreadable as u64, "item", "items"),
                if view.unreadable == 1 { "it" } else { "they" }
            ));
        }
        let (wanted, waiting) = wanted(self.state, self.vault).await?;
        for (marker, why) in waiting {
            r.push(&marker, "deposit", Outcome::Waiting(why));
        }
        let now = chrono::DateTime::from_timestamp(self.now, 0)
            .unwrap_or_default()
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        for change in bw::plan(&wanted, &view.items) {
            match change {
                Change::Same(_) => r.unchanged += 1,
                Change::Create(w) => {
                    let outcome = if apply {
                        let cipher = bw::new_cipher(&org, &org_key, w);
                        done(
                            session
                                .create(&cipher, std::slice::from_ref(&collection.id))
                                .await,
                        )
                    } else {
                        Outcome::ToDo
                    };
                    r.push(&w.marker, format!("deposit, as \"{}\"", w.name), outcome);
                }
                Change::Update { item, wanted, what } => {
                    let outcome = if apply {
                        match bw::updated_cipher(item, wanted, &now) {
                            Ok(c) => done(session.update(&item.id, &c).await),
                            Err(e) => Outcome::Failed(e.to_string()),
                        }
                    } else {
                        Outcome::ToDo
                    };
                    r.push(
                        &wanted.marker,
                        format!("update its {}", what.join(", ")),
                        outcome,
                    );
                }
            }
        }
        if apply && !r.failed() {
            self.state
                .attest_breakglass(EMERGENCY_VAULT, PROVED_BY, None)
                .await?;
        }
        Ok(r)
    }

    /// Gives the account its own second factor and an API key, signing in by password
    /// once. `None`: it went no further, and `r` says why.
    async fn secure(
        &self,
        server: &Server,
        app: &str,
        email: &str,
        password: &str,
        apply: bool,
        r: &mut Report,
    ) -> crate::Result<Option<String>> {
        let failed = |r: &mut Report, what: &str, e: hlb_bitwarden::Error| {
            r.push("account", what, Outcome::Failed(e.to_string()));
            Ok(None)
        };
        let kdf = match server.prelogin(email).await {
            Ok(k) => k,
            Err(e) => return failed(r, "read its key derivation", e),
        };
        let hash = match MasterKey::derive(password, email, kdf) {
            Ok(m) => m.password_hash(password),
            Err(e) => return failed(r, "derive its master key", e),
        };
        let totp_secret = Members::emergency_secret(app, EmergencyPart::Totp);
        let totp = self.secret(&totp_secret).await?;
        let code = match &totp {
            Some(t) => Some(self.code(t)?),
            None => None,
        };
        let session = match server.sign_in(email, &hash, code.as_deref()).await {
            Ok(SignIn::Done(s)) => s,
            Ok(SignIn::SecondFactor) => {
                r.stopped = Some(if totp.is_some() {
                    format!(
                        "{email} refused the second factor Homelabus set — is this machine's \
                         clock right?"
                    )
                } else {
                    format!(
                        "{email} has a second factor Homelabus did not set: remove it (its \
                         Settings → Security → Two-step login), then run this again"
                    )
                });
                return Ok(None);
            }
            Err(hlb_bitwarden::Error::Refused(_)) => {
                r.stopped = Some(owner_steps(app, email));
                return Ok(None);
            }
            Err(e) => return failed(r, "sign in", e),
        };
        if !apply {
            r.push(
                "account",
                "its own second factor, and an API key",
                Outcome::ToDo,
            );
            r.stopped = Some("re-run with --apply to give it them, then verify".into());
            return Ok(None);
        }
        match self
            .second_factor(&session, &totp_secret, totp, &hash)
            .await
        {
            Ok(outcome) => r.push("account", "its own second factor", outcome),
            Err(e) => return failed(r, "its own second factor", e),
        }
        let key = match session.account_id().await {
            Ok(id) => match session.api_key(&hash).await {
                Ok(k) => format!("user.{id}:{k}"),
                Err(e) => return failed(r, "its API key", e),
            },
            Err(e) => return failed(r, "its API key", e),
        };
        self.keep(&Members::emergency_secret(app, EmergencyPart::ApiKey), &key)
            .await?;
        r.push("account", "its API key, kept in the vault", Outcome::Done);
        Ok(Some(key))
    }

    /// Turns the authenticator factor on, its secret kept BEFORE: turned on and not
    /// kept, nobody could sign in by password again.
    async fn second_factor(
        &self,
        session: &Session,
        name: &str,
        kept: Option<String>,
        hash: &str,
    ) -> hlb_bitwarden::Result<Outcome> {
        let sync = session.sync().await?;
        if sync["profile"]["twoFactorEnabled"].as_bool() == Some(true) {
            return Ok(Outcome::Done);
        }
        let secret = match kept {
            Some(s) => s,
            None => {
                let s = crypto::totp_secret();
                self.keep(name, &s).await.map_err(|e| {
                    hlb_bitwarden::Error::Unexpected(format!("keeping its secret: {e}"))
                })?;
                s
            }
        };
        let code = crypto::totp(&secret, u64::try_from(self.now).unwrap_or_default())?;
        session.enable_totp(hash, &secret, &code).await?;
        Ok(Outcome::Done)
    }

    fn code(&self, secret: &str) -> crate::Result<String> {
        Ok(crypto::totp(
            secret,
            u64::try_from(self.now).unwrap_or_default(),
        )?)
    }
}

fn done<T>(r: hlb_bitwarden::Result<T>) -> Outcome {
    match r {
        Ok(_) => Outcome::Done,
        Err(e) => Outcome::Failed(e.to_string()),
    }
}

/// What an owner does, once, for the account to exist and be let in.
pub fn owner_steps(app: &str, email: &str) -> String {
    let password = Members::emergency_secret(app, EmergencyPart::Password);
    format!(
        "Homelabus deposits as a member of the organisation, which an owner sets up once:\n\
         \x20 1. As an owner in {app}: Collections → New collection \"{COLLECTION}\".\n\
         \x20 2. Members → Invite member: {email}, as a User, with access to \"{COLLECTION}\" \
         only, \"Can edit\".\n\
         \x20 3. Open the invitation mailed to {email} and create the account; its master \
         password is `hlb secret-get {password}`.\n\
         \x20 4. `hlb emergency vault --apply`: Homelabus gives it its own second factor and \
         an API key.\n\
         \x20 5. As an owner: Members → {email} → Confirm; Policies → \"Require two-step \
         login\" → on.\n\
         \x20 6. `hlb emergency vault --apply` again: it verifies, then deposits."
    )
}

/// An app's recovery sign-ins as the vault holds them, in the manifest's order: what
/// the collection is given, and what the nightly proof signs in with — one reading, so
/// the two never hold different things.
pub async fn credentials(
    state: &State,
    vault: &Vault,
    app: &str,
    m: &hlb_types::Manifest,
) -> crate::Result<Vec<hlb_guide::assertions::Credential>> {
    let read = |name: String| async move {
        match state.secret(&name).await? {
            Some(ct) => Ok::<_, crate::Error>(Some(vault.decrypt(&ct)?)),
            None => Ok(None),
        }
    };
    let mut out = Vec::with_capacity(m.spec.recovery.len());
    for login in &m.spec.recovery {
        let sign_in = match read(format!("{app}-{}", login.secret)).await? {
            None => Err("its secret is not generated yet".to_string()),
            Some(password) => match &login.username {
                Some(u) if u.contains("{{ smtp.from }}") => {
                    match read(crate::submission::address_secret(app)).await? {
                        Some(a) => Ok((u.replace("{{ smtp.from }}", &a), password)),
                        None => Err("its mail address is not made yet".to_string()),
                    }
                }
                Some(u) => Ok((u.clone(), password)),
                None => Ok((String::new(), password)),
            },
        };
        out.push(hlb_guide::assertions::Credential {
            secret: login.secret.clone(),
            sign_in,
        });
    }
    Ok(out)
}

/// The recovery sign-ins the installed apps declare, as the collection should hold
/// them — and, apart, those whose secret is not generated yet.
pub async fn wanted(
    state: &State,
    vault: &Vault,
) -> crate::Result<(Vec<Wanted>, Vec<(String, String)>)> {
    let read = |name: String| async move {
        match state.secret(&name).await? {
            Some(ct) => Ok::<_, crate::Error>(Some(vault.decrypt(&ct)?)),
            None => Ok(None),
        }
    };
    let mut wanted = Vec::new();
    let mut waiting = Vec::new();
    for (app, status) in state.installed_apps().await? {
        if status == "failed" {
            continue;
        }
        let m = state.app_manifest(&app).await?;
        let display = m
            .metadata
            .display_name
            .clone()
            .unwrap_or_else(|| app.clone());
        let domain = state.app_domain(&app).await?;
        // The key every node lets Termix in with: the way to a node's shell, through
        // Termix, the day a person must find it without Homelabus.
        if m.spec.access.as_ref().and_then(|a| a.nodes) == Some(Nodes::Termix) {
            let marker = format!("{app}/node-key");
            match read(Nodes::node_key_secret(&app)).await? {
                None => waiting.push((marker, "the nodes' key is not generated yet".into())),
                Some(key) => {
                    let account = hlb_termix::node::account(&app);
                    wanted.push(Wanted {
                        name: format!("{display} — the nodes' key, as {account}"),
                        uri: domain.as_ref().map(|d| format!("https://{d}")),
                        notes: format!(
                            "The SSH key {display} reaches every node with, as {account} — \
                             accepted from {display}'s own node only. Homelabus keeps this \
                             item: a rotation (`hlb termix rotate`) replaces the key, and \
                             the one it replaces stays in this item's history. Saved to a \
                             file, it ends with a newline: `ssh` refuses a key without one, \
                             saying only \"error in libcrypto\"."
                        ),
                        username: account,
                        password: key,
                        marker,
                    });
                }
            }
        }
        for (login, credential) in m
            .spec
            .recovery
            .iter()
            .zip(credentials(state, vault, &app, &m).await?)
        {
            let marker = format!("{app}/{}", login.secret);
            let (username, password) = match credential.sign_in {
                Ok(c) => c,
                Err(why) => {
                    waiting.push((marker, why));
                    continue;
                }
            };
            wanted.push(Wanted {
                name: if username.is_empty() {
                    display.clone()
                } else {
                    format!("{display} — {username}")
                },
                uri: domain
                    .as_ref()
                    .map(|d| format!("https://{d}{}", login.path.as_deref().unwrap_or(""))),
                notes: format!(
                    "{display}'s own sign-in, generated by Homelabus: the way in when PocketID \
                     signs nobody in. Homelabus keeps this item — a change made here is put \
                     back; a password is changed by a rotation in Homelabus, and the one it \
                     replaces stays in this item's history."
                ),
                username,
                password,
                marker,
            });
        }
    }
    Ok((wanted, waiting))
}
