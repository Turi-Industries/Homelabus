//! The executor: applies a plan, action by action.
//!
//! Three properties, present from the start rather than retrofitted:
//!
//! - **Preview by default.** Nothing is modified without an explicit `--apply`.
//! - **Idempotency.** Rerunning against an already-installed app breaks nothing.
//! - **Resumability.** A failure at action 4/10 resumes at 4, not at zero.
//!
//! And a rule of honesty: an unimplemented action is recorded as such
//! (`Unimplemented`), **never** as successful.

pub mod reconcile;

pub use reconcile::{Drift, Reconciler, Report};

use hlb_identity::PocketId;
use hlb_ingress::CaddyAdmin;
use hlb_mail::Stalwart;
use hlb_objstore::Garage;
use hlb_orchestrator::{Orchestrator, ServiceSpec};
use hlb_platform::{MariadbProvisioner, PostgresProvisioner};
use hlb_registry::{ImageRef, RegistryClient};
use hlb_resolver::{Action, Plan};
use hlb_secrets::Vault;
use hlb_state::{ActionStatus, State};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    State(#[from] hlb_state::Error),

    #[error(transparent)]
    Orchestrator(#[from] hlb_orchestrator::Error),

    #[error(transparent)]
    Secrets(#[from] hlb_secrets::Error),

    #[error(transparent)]
    Platform(#[from] hlb_platform::Error),

    #[error(transparent)]
    Registry(#[from] hlb_registry::Error),

    #[error(transparent)]
    Identity(#[from] hlb_identity::Error),

    #[error(transparent)]
    Ingress(#[from] hlb_ingress::Error),

    #[error(transparent)]
    Mail(#[from] hlb_mail::Error),

    #[error(transparent)]
    ObjStore(#[from] hlb_objstore::Error),

    #[error(
        "🔴 extension \"{extension}\" could not be enabled on \"{database}\". An \
             extension is NOT installed from SQL: it must be present in the PostgreSQL \
             server image. Check the `postgres` service image in the \
             catalogue — pour les extensions vectorielles, \
             ghcr.io/immich-app/postgres:17-vectorchord0.4.3-pgvector0.8.0 les porte. \
             Cause : {cause}"
    )]
    MissingExtension {
        extension: String,
        database: String,
        cause: String,
    },

    #[error("secret \"{0}\" not found - was the plan executed in order?")]
    MissingSecret(String),

    #[error(
        "{blocking} action(s) manuelle(s) bloquante(s) en attente — \
             traite-les puis relance (hlb todo)"
    )]
    BlockedByGuide { blocking: usize },
}

pub type Result<T> = std::result::Result<T, Error>;

/// The platform's S3 endpoint.
///
/// ⚠️ A Swarm service name, not a public URL: object traffic stays on the internal
/// network. Exposing it would send bytes out of the cluster that have no reason to
/// leave, and Garage has no authentication beyond the S3 signature.
const S3_ENDPOINT: &str = "http://garage:3900";

/// Garage ignores the region, but the S3 SIGNATURE covers it: a client announcing a
/// different one has its requests refused on a signature error that says nothing about
/// the region.
const S3_REGION: &str = "garage";

/// What was done, for the report.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Outcome {
    pub executed: usize,
    pub skipped: usize,
    pub unimplemented: usize,
    pub failed: Option<(usize, String)>,
}

impl Outcome {
    pub fn is_success(&self) -> bool {
        self.failed.is_none()
    }
}

pub struct Executor<'a, O: Orchestrator> {
    orchestrator: &'a O,
    state: &'a State,
    /// Absent until the master key is loaded: without a vault, no secret can be
    /// generated or read back.
    vault: Option<&'a Vault>,
    /// Absent until PostgreSQL is deployed and reachable.
    postgres: Option<&'a PostgresProvisioner>,
    /// Same for MariaDB. Both can coexist: different apps have different
    /// requirements, and the resolver chooses per manifest.
    mariadb: Option<&'a MariadbProvisioner>,
    /// Absent when offline: without a registry, no digest can be resolved.
    registry: Option<&'a RegistryClient>,
    /// Absent until PocketID is deployed and an API key is available.
    identity: Option<&'a PocketId>,
    /// Absent when Caddy is not reachable yet: the app is deployed but not routed,
    /// which is a legitimate state.
    ingress: Option<&'a CaddyAdmin>,
    mail: Option<&'a Stalwart>,
    /// Absent until Garage is deployed and its admin token is available: no bucket
    /// can be provisioned before that.
    objstore: Option<&'a Garage>,
    /// CrowdSec API URL. Absent means no reputation filtering.
    crowdsec_url: Option<String>,
    /// False by default: nothing is written until it is asked for.
    apply: bool,
}

impl<'a, O: Orchestrator> Executor<'a, O> {
    pub fn new(orchestrator: &'a O, state: &'a State) -> Self {
        Self {
            orchestrator,
            state,
            vault: None,
            postgres: None,
            mariadb: None,
            registry: None,
            identity: None,
            ingress: None,
            mail: None,
            objstore: None,
            crowdsec_url: None,
            apply: false,
        }
    }

    pub fn with_vault(mut self, vault: &'a Vault) -> Self {
        self.vault = Some(vault);
        self
    }

    pub fn with_postgres(mut self, pg: &'a PostgresProvisioner) -> Self {
        self.postgres = Some(pg);
        self
    }

    pub fn with_mariadb(mut self, my: &'a MariadbProvisioner) -> Self {
        self.mariadb = Some(my);
        self
    }

    pub fn with_registry(mut self, r: &'a RegistryClient) -> Self {
        self.registry = Some(r);
        self
    }

    pub fn with_identity(mut self, p: &'a PocketId) -> Self {
        self.identity = Some(p);
        self
    }

    pub fn with_ingress(mut self, c: &'a CaddyAdmin) -> Self {
        self.ingress = Some(c);
        self
    }

    pub fn with_mail(mut self, s: &'a Stalwart) -> Self {
        self.mail = Some(s);
        self
    }

    pub fn with_objstore(mut self, g: &'a Garage) -> Self {
        self.objstore = Some(g);
        self
    }

    pub fn with_crowdsec(mut self, url: impl Into<String>) -> Self {
        self.crowdsec_url = Some(url.into());
        self
    }

    /// Switches to real application mode. The caller must ask for it explicitly.
    pub fn apply(mut self, yes: bool) -> Self {
        self.apply = yes;
        self
    }

    /// Executes the plan for `app`.
    ///
    /// Blocking manual actions stop execution **before** any modification: no point
    /// deploying an app whose DNS does not exist.
    pub async fn run(&self, app: &str, plan: &Plan) -> Result<Outcome> {
        let records: Vec<(String, String)> = plan
            .actions
            .iter()
            .map(|a| (kind_of(a).to_string(), a.to_string()))
            .collect();
        self.state.record_plan(app, &records).await?;

        // Guides are recorded even in preview: they describe real work.
        for a in &plan.actions {
            if let Action::PendingGuideStep {
                id,
                title,
                blocking,
                ..
            } = a
            {
                self.state.add_guide(app, id, title, *blocking).await?;
            }
        }

        // The state is queried, not the plan: an action the user has already handled
        // must stop blocking.
        let blocking = self.state.unverified_blocking(app).await?;
        if blocking > 0 && self.apply {
            return Err(Error::BlockedByGuide { blocking });
        }

        let done = self.state.completed_seqs(app).await?;
        let mut out = Outcome::default();

        for (seq, action) in plan.actions.iter().enumerate() {
            if done.contains(&(seq as i64)) {
                out.skipped += 1;
                tracing::debug!(seq, "already done, skipped");
                continue;
            }

            if !self.apply {
                out.executed += 1;
                continue;
            }

            match self.execute_one(app, action).await {
                Ok(Step::Done) => {
                    self.state
                        .set_action_status(app, seq, ActionStatus::Done, None)
                        .await?;
                    out.executed += 1;
                }
                Ok(Step::NotImplemented) => {
                    self.state
                        .set_action_status(app, seq, ActionStatus::Unimplemented, None)
                        .await?;
                    out.unimplemented += 1;
                }
                Err(e) => {
                    let msg = e.to_string();
                    self.state
                        .set_action_status(app, seq, ActionStatus::Failed, Some(&msg))
                        .await?;
                    self.state.set_app_status(app, "failed").await?;
                    out.failed = Some((seq, msg));
                    // Stop dead: continuing after a dependency failure would only
                    // produce cascading errors.
                    return Ok(out);
                }
            }
        }

        if self.apply {
            let status = if out.unimplemented > 0 {
                "partial"
            } else {
                "running"
            };
            self.state.set_app_status(app, status).await?;
        }

        Ok(out)
    }

    /// The ingress configuration, CrowdSec included when it is enrolled.
    ///
    /// 🔴 CrowdSec is enabled ONLY when its bouncer key is in the vault. Without it we
    /// generate a Caddyfile with no bouncer rather than one with an empty key: the
    /// latter would start normally and silently block nothing.
    async fn ingress_config(&self) -> Result<hlb_ingress::Config> {
        let mut cfg = hlb_ingress::Config::default();

        // Same rule as in the CLI: the portal only appears when it serves something.
        if self
            .all_routes()
            .await?
            .iter()
            .any(|r| r.needs_forward_auth)
        {
            cfg.forward_auth = Some(hlb_ingress::caddyfile::ForwardAuth::default());
        }

        let (Some(vault), Some(url)) = (self.vault, &self.crowdsec_url) else {
            return Ok(cfg);
        };

        match self
            .state
            .secret(hlb_ingress::crowdsec::SECRET_NAME)
            .await?
        {
            Some(ct) => {
                let cle = vault.decrypt(&ct)?;
                if hlb_ingress::crowdsec::looks_like_key(&cle) {
                    cfg.crowdsec = Some(hlb_ingress::CrowdSec {
                        api_url: url.clone(),
                        api_key: cle,
                    });
                } else {
                    // A damaged key in the vault must not produce a silent bouncer.
                    tracing::error!(
                        "🔴 invalid CrowdSec bouncer key in the vault - filtering \
                         DISABLED; re-enrol with `hlb crowdsec enroll --apply`"
                    );
                }
            }
            None => tracing::warn!(
                "CrowdSec is not enrolled: traffic is not filtered \
                 (hlb crowdsec enroll --apply)"
            ),
        }
        Ok(cfg)
    }

    /// The routes of every installed app.
    ///
    /// Recomputed from the state each time: the frozen manifest is authoritative, not
    /// today's catalog.
    async fn all_routes(&self) -> Result<Vec<hlb_ingress::Route>> {
        let mut routes = Vec::new();
        for (name, status) in self.state.installed_apps().await? {
            if status == "failed" {
                continue;
            }
            let m = self.state.app_manifest(&name).await?;
            let domain = self.state.app_domain(&name).await?;
            // The route only opens once the blocking actions are handled.
            let cleared = self.state.unverified_blocking(&name).await? == 0;
            routes.extend(hlb_ingress::routes_from_manifest(
                &m,
                domain.as_deref(),
                cleared,
            ));
        }
        Ok(routes)
    }

    /// Resolves the binding tokens of a set of variables.
    ///
    /// 🔴 **This is where, and nowhere earlier, secrets take their value.** The plan
    /// passes through `hlb plan`'s output, the SQLite state and the Git mirror: a
    /// password substituted upstream would be published in all three, one of which
    /// keeps history. Only Swarm sees the final value.
    ///
    /// ⚠️ A token we cannot fill is left **literal** rather than emptied. An empty
    /// variable looks like missing configuration: the app would complain about an
    /// incorrect password, where `{{ db.password }}` in its logs points at the real
    /// problem straight away.
    async fn resoudre_liaisons(
        &self,
        app: &str,
        env: &[(String, String)],
    ) -> Result<Vec<(String, String)>> {
        use hlb_types::binding::{substitute, tokens_in, Token};

        // Nothing to do when no token is used: this avoids fetching secrets for apps
        // that do not need any.
        let utilises: Vec<Token> = {
            let mut v: Vec<Token> = env.iter().flat_map(|(_, x)| tokens_in(x)).collect();
            v.sort_unstable();
            v.dedup();
            v
        };
        if utilises.is_empty() {
            return Ok(env.to_vec());
        }

        let manifest = self.state.app_manifest(app).await.ok();
        let domaine = self.state.app_domain(app).await.unwrap_or_default();

        let mut valeurs: std::collections::BTreeMap<Token, String> = Default::default();
        // 🔴 Like companions, S3 tokens live outside the `Token` enum: the bucket and
        // the key are free strings, and forcing an open set into a closed type would
        // have weakened exhaustiveness for everything else.
        let mut s3: std::collections::BTreeMap<String, String> = Default::default();

        if let Some(d) = &domaine {
            valeurs.insert(Token::Domain, d.clone());
        }

        // The database's coordinates come from the declared CAPABILITY, not from a
        // constant: that is what lets the same manifest follow the topology.
        if let Some(m) = &manifest {
            for c in &m.spec.requires {
                match c {
                    hlb_types::Capability::Database { engine, name, .. } => {
                        let base = name.clone().unwrap_or_else(|| app.to_string());
                        let hote = engine.service_name().to_string();
                        let port = match engine {
                            hlb_types::DbEngine::Postgres => "5432",
                            hlb_types::DbEngine::Mariadb => "3306",
                        };

                        valeurs.insert(Token::DbHost, hote.clone());
                        valeurs.insert(Token::DbPort, port.to_string());
                        valeurs.insert(Token::DbName, base.clone());
                        // 🔴 The role is named after the APP, not the database: an app
                        // with several databases connects with one account. Must stay
                        // aligned with the resolver's `ProvisionDatabase`.
                        valeurs.insert(Token::DbUser, app.to_string());

                        if let Some(password) =
                            self.lire_secret(&format!("{app}-db-password")).await?
                        {
                            let schema = match engine {
                                hlb_types::DbEngine::Postgres => "postgres",
                                hlb_types::DbEngine::Mariadb => "mysql",
                            };
                            valeurs.insert(
                                Token::DbUrl,
                                format!("{schema}://{app}:{password}@{hote}:{port}/{base}"),
                            );
                            valeurs.insert(Token::DbPassword, password);
                        }
                    }

                    hlb_types::Capability::Cache { engine, dedicated } => {
                        // A dedicated instance is prefixed with the app's name.
                        let hote = if *dedicated {
                            format!("{app}-{}", engine.service_name())
                        } else {
                            engine.service_name().to_string()
                        };
                        valeurs.insert(Token::CacheHost, hote.clone());
                        valeurs.insert(Token::CachePort, "6379".into());
                        valeurs.insert(Token::CacheUrl, format!("redis://{hote}:6379"));
                    }

                    hlb_types::Capability::Sso { .. } => {
                        valeurs.insert(Token::OidcClientId, app.to_string());
                        if let Some(s) = self.lire_secret(&format!("{app}-oidc-secret")).await? {
                            valeurs.insert(Token::OidcClientSecret, s);
                        }
                    }

                    hlb_types::Capability::Smtp => {
                        valeurs.insert(Token::SmtpHost, "stalwart".into());
                        valeurs.insert(Token::SmtpPort, "587".into());
                        valeurs.insert(Token::SmtpUser, app.to_string());
                        if let Some(s) = self.lire_secret(&format!("{app}-smtp-password")).await? {
                            valeurs.insert(Token::SmtpPassword, s);
                        }
                    }

                    hlb_types::Capability::ObjectStorage { bucket, .. } => {
                        let compartiment = bucket.clone().unwrap_or_else(|| app.to_string());
                        s3.insert("{{ s3.bucket }}".to_string(), compartiment);
                        s3.insert("{{ s3.endpoint }}".to_string(), S3_ENDPOINT.into());
                        s3.insert("{{ s3.region }}".to_string(), S3_REGION.into());
                        s3.insert("{{ s3.access_key }}".to_string(), app.to_string());
                        if let Some(k) = self.lire_secret(&format!("{app}-s3-secret")).await? {
                            s3.insert("{{ s3.secret_key }}".to_string(), k);
                        }
                    }

                    hlb_types::Capability::MailAccount { .. }
                    | hlb_types::Capability::Storage { .. } => {}
                }
            }
        }

        // The OIDC issuer depends on PocketID's domain, not the app's.
        if let Ok(Some(d)) = self.state.app_domain("pocket-id").await {
            valeurs.insert(Token::OidcIssuer, format!("https://{d}"));
        }

        // 🔴 Companions do NOT go through the `Token` enum: their set is open - each
        // app defines its own - where `Token` is closed by design, so that adding a
        // variant breaks compilation everywhere. A parameterised token does not fit
        // that contract, and forcing it in would have weakened the enum for all the
        // others.
        let compagnons: Vec<(String, String)> = manifest
            .as_ref()
            .map(|m| {
                m.spec
                    .companions
                    .iter()
                    .map(|c| {
                        (
                            format!("{{{{ companion.{}.host }}}}", c.name),
                            format!("{app}-{}", c.name),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();

        Ok(env
            .iter()
            .map(|(k, v)| {
                let mut s = substitute(v, &valeurs);
                for (jeton, valeur) in &s3 {
                    s = s.replace(jeton, valeur);
                }
                for (jeton, hote) in &compagnons {
                    s = s.replace(jeton, hote);
                }
                (k.clone(), s)
            })
            .collect())
    }

    /// Reads a secret from the vault, or `None` when it does not exist yet.
    ///
    /// ⚠️ Absent is not an error here: a plan can be executed before the secret is
    /// generated, and the matching action will take care of it. The token then stays
    /// literal, which is visible.
    async fn lire_secret(&self, nom: &str) -> Result<Option<String>> {
        let Some(vault) = self.vault else {
            return Ok(None);
        };
        match self.state.secret(nom).await? {
            Some(ct) => Ok(Some(vault.decrypt(&ct)?)),
            None => Ok(None),
        }
    }

    async fn execute_one(&self, app: &str, action: &Action) -> Result<Step> {
        match action {
            Action::DeployService {
                name,
                image,
                replicas,
                constraints,
                env,
                mounts,
                hardening,
                healthcheck,
            } => {
                // ⚠️ The plan was built BEFORE execution, so its `image` field still
                // carries the tag. The digest resolved at the previous step lives in
                // the state - and that is what is authoritative.
                let resolved = match self.state.app_manifest(app).await {
                    Ok(m) if m.spec.image.is_pinned() => m.spec.image.reference(),
                    _ => image.clone(),
                };

                // 🔴 Binding tokens take their value HERE, not in the plan. This is
                // what finally tells an app where its database is.
                let env = self.resoudre_liaisons(app, env).await?;

                let mut spec = ServiceSpec::new(name, &resolved)
                    .replicas(*replicas)
                    .env(env.clone())
                    // The hardening declared in the manifest is actually applied.
                    .hardening(hardening.clone());

                if let Some(h) = healthcheck {
                    spec = spec.healthcheck(h.clone());
                }
                for c in constraints {
                    spec = spec.constraint(c);
                }
                for (vol, path) in mounts {
                    spec = spec.mount(vol, path);
                }
                self.orchestrator.deploy(&spec).await?;
                Ok(Step::Done)
            }

            Action::WaitHealthy { name, timeout_secs } => {
                self.orchestrator.wait_healthy(name, *timeout_secs).await?;
                Ok(Step::Done)
            }

            Action::GenerateSecret { name, purpose } => {
                let Some(vault) = self.vault else {
                    return Ok(Step::NotImplemented);
                };

                let password = hlb_secrets::generate_password(hlb_secrets::DEFAULT_PASSWORD_LEN);
                let ct = vault.encrypt(&password)?;

                // `if_absent`: a password already injected into a service must never
                // change under its feet when a plan is rerun.
                let created = self
                    .state
                    .store_secret_if_absent(name, &ct, purpose)
                    .await?;
                if created {
                    tracing::info!(secret = name, "secret generated");
                }
                Ok(Step::Done)
            }

            Action::ProvisionBucket {
                bucket,
                key_name,
                secret_name,
            } => {
                let (Some(garage), Some(vault)) = (self.objstore, self.vault) else {
                    // 🔴 Never `Done`: claiming a bucket was created would start the
                    // app against storage that does not exist, and it would write into
                    // the void.
                    return Ok(Step::NotImplemented);
                };

                // 🔴 The vault is authoritative, not Garage. A key present in Garage
                // whose secret was lost is UNUSABLE - it is only given at creation
                // time. Asking Garage alone would restart a resumed run with no
                // secret, and the app would fail on an "invalid signature" that points
                // at nothing.
                let connu = match self.state.secret(secret_name).await? {
                    Some(ct) => Some(vault.decrypt(&ct)?),
                    None => None,
                };

                let id = garage.ensure_bucket(bucket).await?;
                let cle = garage.ensure_key(key_name, connu.as_deref()).await?;

                // The secret goes to the vault BEFORE the grant: if the grant fails
                // we keep enough to resume; the other order would lose the key.
                let ct = vault.encrypt(&cle.secret_access_key)?;
                if !self
                    .state
                    .store_secret_if_absent(secret_name, &ct, "S3 secret key")
                    .await?
                {
                    // The secret already existed: this is a resumed run, and
                    // `ensure_key` just handed back THAT secret. Rotating rewrites it
                    // identically, which is a no-op - but covers the case where Garage
                    // had lost the key and just created a fresh one.
                    self.state.rotate_secret(secret_name, &ct).await?;
                }

                garage.allow(&id, &cle.access_key_id).await?;
                Ok(Step::Done)
            }

            Action::ProvisionDatabase {
                engine,
                database,
                role,
                password_secret,
                extensions,
            } => {
                let Some(vault) = self.vault else {
                    return Ok(Step::NotImplemented);
                };

                let ct = self
                    .state
                    .secret(password_secret)
                    .await?
                    .ok_or_else(|| Error::MissingSecret(password_secret.clone()))?;
                let password = vault.decrypt(&ct)?;

                // 🔴 The `match` is exhaustive: adding an engine to `DbEngine` breaks
                // compilation here, which forces a decision on how to provision it
                // rather than letting it fall into a default arm that would claim
                // success.
                let created = match engine {
                    hlb_types::DbEngine::Postgres => {
                        let Some(pg) = self.postgres else {
                            return Ok(Step::NotImplemented);
                        };
                        pg.provision(database, role, &password).await?
                    }
                    hlb_types::DbEngine::Mariadb => {
                        let Some(my) = self.mariadb else {
                            return Ok(Step::NotImplemented);
                        };
                        my.provision(database, role, &password).await?
                    }
                };

                if created {
                    tracing::info!(database, role, engine = ?engine, "database provisioned");
                }

                // 🔴 Extensions AFTER the database, and on the app's database - not on
                // `postgres`. `CREATE EXTENSION` is per-database: installed in the
                // wrong place it succeeds and the app never sees it.
                if !extensions.is_empty() {
                    let Some(pg) = self.postgres else {
                        return Ok(Step::NotImplemented);
                    };
                    for ext in extensions {
                        if let Err(e) = pg.create_extension(database, ext).await {
                            // The remedy is in the message: an extension missing from
                            // the IMAGE cannot be installed from SQL, and PostgreSQL's
                            // raw error looks like a permissions problem.
                            return Err(Error::MissingExtension {
                                extension: ext.clone(),
                                database: database.clone(),
                                cause: e.to_string(),
                            });
                        }
                    }
                }
                Ok(Step::Done)
            }

            Action::PendingGuideStep {
                id, service, step, ..
            } => {
                // We try to handle it ourselves first. Many "inside the application"
                // steps can be scripted; treating them as manual by default is the
                // usual mistake.
                let issue = hlb_guide::try_automate(self.orchestrator, service, step, &[]).await;

                if issue.handled() {
                    tracing::info!(step = %id, "{}", issue.describe());
                    // The step is done: it must stop blocking.
                    self.state.verify_guide(app, id).await?;
                } else if !matches!(issue, hlb_guide::AutomationOutcome::NothingDeclared) {
                    // We say WHY it stays manual: without that, the user would not
                    // know why the system is asking them to do what it announced it
                    // would automate.
                    tracing::warn!(step = %id, "{}", issue.describe());
                }
                Ok(Step::Done)
            }

            Action::ResolveDigest { repo, tag } => {
                let Some(reg) = self.registry else {
                    return Ok(Step::NotImplemented);
                };

                let image = ImageRef::parse(&format!("{repo}:{tag}"));
                let digest = reg.resolve_digest(&image).await?;

                // The digest is frozen into the state: that is what gets deployed,
                // not the tag, which is mutable.
                self.state.set_app_digest(app, &digest).await?;
                tracing::info!(%image, digest, "digest resolved");
                Ok(Step::Done)
            }

            Action::CreateVolume {
                name,
                backup,
                sqlite,
                ..
            } => {
                let info = self.orchestrator.create_volume(name).await?;

                // The REAL mount point is recorded: it is what the backup will read.
                // Without it, we do not know what to back up.
                self.state
                    .add_volume(app, &info.name, &info.mountpoint, *backup, *sqlite)
                    .await?;

                if info.existed {
                    tracing::info!(name, "existing volume kept (it holds data)");
                }
                Ok(Step::Done)
            }

            Action::CreateOidcClient {
                app: client,
                redirect_uris,
            } => {
                let (Some(pid), Some(vault)) = (self.identity, self.vault) else {
                    return Ok(Step::NotImplemented);
                };

                // Idempotent: an existing client is kept, and its secret is NEVER
                // regenerated - it is already injected into the running app.
                let creds = pid.ensure(client, redirect_uris, true).await?;

                let secret_name = format!("{app}-oidc-secret");
                match creds.client_secret {
                    Some(s) => {
                        let ct = vault.encrypt(&s)?;
                        self.state
                            .store_secret_if_absent(&secret_name, &ct, "client secret OIDC")
                            .await?;
                    }
                    None => {
                        // Client already provisioned: the matching secret must be in
                        // the vault. If it is not, it cannot be recovered - PocketID
                        // never hands it back without regenerating it.
                        if self.state.secret(&secret_name).await?.is_none() {
                            return Err(Error::MissingSecret(format!(
                                "{secret_name} — le client OIDC « {client} » existe dans \
                                 PocketID mais son secret est absent du coffre ; \
                                 supprime le client pour le reprovisionner"
                            )));
                        }
                    }
                }

                self.state
                    .store_secret_if_absent(
                        &format!("{app}-oidc-client-id"),
                        &vault.encrypt(&creds.client_id)?,
                        "identifiant du client OIDC",
                    )
                    .await?;

                Ok(Step::Done)
            }

            Action::ConfigureIngress { .. } => {
                let Some(caddy) = self.ingress else {
                    return Ok(Step::NotImplemented);
                };

                // ⚠️ The WHOLE configuration is regenerated, not just this app's
                // route. Caddy replaces its entire config on every `/load`: sending a
                // fragment would delete the other apps' routes.
                let routes = self.all_routes().await?;
                let cfg = self.ingress_config().await?;
                caddy
                    .load_caddyfile(&hlb_ingress::render_frontend(&routes, &cfg))
                    .await?;

                tracing::info!(routes = routes.len(), "Caddy configuration reloaded");
                Ok(Step::Done)
            }

            Action::ProvisionMailAccount {
                address,
                aliases,
                quota_bytes,
            } => {
                let (Some(mail), Some(vault)) = (self.mail, self.vault) else {
                    return Ok(Step::NotImplemented);
                };

                // 🔴 A quota declared and not set is worse than no quota: the mailbox
                // would look bounded and grow without end, until it saturates the disk
                // that also carries the databases. `hlb-mail` has no quota operation,
                // Stalwart not exposing one over JMAP.
                //
                // So we refuse BEFORE creating anything, rather than creating the
                // mailbox and staying silent about the missing half - "Unimplemented is
                // never Done".
                if quota_bytes.is_some() {
                    tracing::warn!(
                        address,
                        "mailbox quota declared in the manifest but not applicable: \
                         Stalwart ne l'expose pas en JMAP. Retire `quotaBytes` du \
                         manifest, or set it by hand in Stalwart."
                    );
                    return Ok(Step::NotImplemented);
                }

                // The password lives in the vault, like the others. `if_absent`:
                // rerunning a plan must not manufacture a second one, which would no
                // longer match the one deposited in Stalwart.
                let secret_name = format!("{app}-mail-password");
                let password = match self.state.secret(&secret_name).await? {
                    Some(ct) => vault.decrypt(&ct)?,
                    None => {
                        let p = hlb_secrets::generate_password(hlb_secrets::DEFAULT_PASSWORD_LEN);
                        self.state
                            .store_secret_if_absent(
                                &secret_name,
                                &vault.encrypt(&p)?,
                                "mot de passe IMAP/SMTP",
                            )
                            .await?;
                        p
                    }
                };

                // The aliases declared in the manifest are a boolean: "this app is
                // allowed to have some". It asks for none at install time - they are
                // created in use.
                let demandes: Vec<String> = Vec::new();
                let p = mail.ensure_account(address, &password, &demandes).await?;

                if p.created {
                    tracing::info!(address = %p.address, "mailbox created");
                } else {
                    // 🔴 Concrete consequence: the vault's password is the one from
                    // before, and it was NOT touched. Changing it would cut the running
                    // app's IMAP access.
                    tracing::debug!(address = %p.address, "mailbox already present, kept");
                }
                let _ = aliases;
                Ok(Step::Done)
            }
        }
    }
}

enum Step {
    Done,
    NotImplemented,
}

/// A short, stable label, stored in the database and shown in reports.
fn kind_of(a: &Action) -> &'static str {
    match a {
        Action::ProvisionDatabase { .. } => "ProvisionDatabase",
        Action::ProvisionBucket { .. } => "ProvisionBucket",
        Action::GenerateSecret { .. } => "GenerateSecret",
        Action::CreateOidcClient { .. } => "CreateOidcClient",
        Action::CreateVolume { .. } => "CreateVolume",
        Action::ProvisionMailAccount { .. } => "ProvisionMailAccount",
        Action::DeployService { .. } => "DeployService",
        Action::ResolveDigest { .. } => "ResolveDigest",
        Action::WaitHealthy { .. } => "WaitHealthy",
        Action::ConfigureIngress { .. } => "ConfigureIngress",
        Action::PendingGuideStep { .. } => "PendingGuideStep",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use hlb_orchestrator::{ServiceStatus, UpdateState};
    use std::sync::Mutex;

    /// Fake orchestrator: records calls, and can fail on demand.
    /// What a deployment actually passed on: service name and variables.
    type Deploiement = (String, Vec<(String, String)>);

    #[derive(Default)]
    struct Fake {
        deployed: Mutex<Vec<String>>,
        waited: Mutex<Vec<String>>,
        updated: Mutex<Vec<(String, String)>>,
        scaled: Mutex<Vec<(String, u64)>>,
        /// The variables actually passed to Swarm, per service.
        ///
        /// 🔴 This is the ONLY place a token can be seen to have been resolved: the
        /// plan itself must keep carrying the literal token.
        deployed_env: Mutex<Vec<Deploiement>>,
        /// What `list()` will return: the cluster's "observed" state.
        observed: Mutex<Vec<ServiceStatus>>,
        fail_deploy: bool,
    }

    #[async_trait]
    impl Orchestrator for Fake {
        async fn ping(&self) -> hlb_orchestrator::Result<String> {
            Ok("fake".into())
        }
        async fn deploy(&self, s: &ServiceSpec) -> hlb_orchestrator::Result<String> {
            if self.fail_deploy {
                return Err(hlb_orchestrator::Error::Unexpected(
                    "simulated failure".into(),
                ));
            }
            self.deployed.lock().expect("mutex").push(s.name.clone());
            self.deployed_env
                .lock()
                .expect("mutex")
                .push((s.name.clone(), s.env.clone()));
            Ok("id".into())
        }
        async fn update_image(&self, name: &str, image: &str) -> hlb_orchestrator::Result<()> {
            self.updated
                .lock()
                .expect("mutex")
                .push((name.into(), image.into()));
            Ok(())
        }
        async fn scale(&self, name: &str, replicas: u64) -> hlb_orchestrator::Result<()> {
            self.scaled
                .lock()
                .expect("mutex")
                .push((name.into(), replicas));
            Ok(())
        }
        async fn enable_autolock(&self) -> hlb_orchestrator::Result<String> {
            Ok("SWMKEY-fake".into())
        }
        async fn autolock_enabled(&self) -> hlb_orchestrator::Result<bool> {
            Ok(false)
        }
        async fn cluster_init(&self, _: Option<&str>) -> hlb_orchestrator::Result<String> {
            Ok("swarm-fake".into())
        }
        async fn join_tokens(&self) -> hlb_orchestrator::Result<hlb_orchestrator::JoinTokens> {
            Ok(hlb_orchestrator::JoinTokens {
                manager: "SWMTKN-mgr".into(),
                worker: "SWMTKN-wrk".into(),
                advertise_addr: "127.0.0.1:2377".into(),
            })
        }
        async fn nodes(&self) -> hlb_orchestrator::Result<Vec<hlb_orchestrator::NodeInfo>> {
            Ok(Vec::new())
        }
        async fn label_node(&self, _: &str, _: &str, _: &str) -> hlb_orchestrator::Result<()> {
            Ok(())
        }
        async fn exec_in_service(
            &self,
            _: &str,
            _: &[String],
        ) -> hlb_orchestrator::Result<hlb_orchestrator::ExecOutput> {
            Ok(hlb_orchestrator::ExecOutput {
                exit_code: 0,
                stdout: String::new(),
                stderr: String::new(),
            })
        }
        async fn create_volume(
            &self,
            n: &str,
        ) -> hlb_orchestrator::Result<hlb_orchestrator::VolumeInfo> {
            Ok(hlb_orchestrator::VolumeInfo {
                name: n.into(),
                mountpoint: format!("/volumes/{n}"),
                existed: false,
            })
        }
        async fn inspect_volume(
            &self,
            n: &str,
        ) -> hlb_orchestrator::Result<hlb_orchestrator::VolumeInfo> {
            self.create_volume(n).await
        }
        async fn status(&self, name: &str) -> hlb_orchestrator::Result<ServiceStatus> {
            Ok(ServiceStatus {
                name: name.into(),
                id: "id".into(),
                desired_replicas: 1,
                running_replicas: 1,
                image: "img".into(),
                update_state: Some(UpdateState::Completed),
            })
        }
        async fn list(&self) -> hlb_orchestrator::Result<Vec<ServiceStatus>> {
            Ok(self.observed.lock().expect("mutex").clone())
        }
        async fn remove(&self, _: &str) -> hlb_orchestrator::Result<()> {
            Ok(())
        }
        async fn wait_healthy(
            &self,
            name: &str,
            _: u64,
        ) -> hlb_orchestrator::Result<ServiceStatus> {
            self.waited.lock().expect("mutex").push(name.into());
            self.status(name).await
        }

        async fn tasks(
            &self,
            _: Option<&str>,
        ) -> hlb_orchestrator::Result<Vec<hlb_orchestrator::TaskInfo>> {
            // A fake orchestrator has no tasks: empty is the honest answer.
            Ok(Vec::new())
        }

        async fn logs(
            &self,
            _: &str,
            _: u32,
        ) -> hlb_orchestrator::Result<Vec<hlb_orchestrator::LigneLog>> {
            Ok(Vec::new())
        }
    }

    const BASE: &str = r#"
apiVersion: hlb/v1
kind: App
metadata: { name: demo }
spec:
  image: { repo: a/b, tag: "1", digest: "sha256:x" }
"#;

    const WITH_DB: &str = r#"
apiVersion: hlb/v1
kind: App
metadata: { name: demo }
spec:
  image: { repo: a/b, tag: "1", digest: "sha256:x" }
  requires:
    - kind: database
      engine: postgres
"#;

    const WITH_GUIDE: &str = r#"
apiVersion: hlb/v1
kind: App
metadata: { name: demo }
spec:
  image: { repo: a/b, tag: "1", digest: "sha256:x" }
  ingress:
    - host: x.example.fr
      port: 80
      expose: after-guide
"#;

    fn manifest() -> hlb_types::Manifest {
        serde_yaml_ng::from_str(BASE).expect("manifest")
    }

    fn plan() -> Plan {
        hlb_resolver::resolve(&manifest(), &hlb_resolver::InstallParams::default()).expect("plan")
    }

    async fn state() -> State {
        let s = State::in_memory().await.expect("base");
        s.upsert_app("demo", &manifest(), None)
            .await
            .expect("upsert");
        s
    }

    #[tokio::test]
    async fn preview_changes_nothing() {
        let o = Fake::default();
        let s = state().await;

        let out = Executor::new(&o, &s)
            .run("demo", &plan())
            .await
            .expect("run");

        assert!(
            o.deployed.lock().unwrap().is_empty(),
            "no deployment in preview"
        );
        assert!(out.is_success());
        // Nothing is marked done: a preview does not consume the plan.
        assert!(s.completed_seqs("demo").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn apply_deploys_and_waits() {
        let o = Fake::default();
        let s = state().await;

        let out = Executor::new(&o, &s)
            .apply(true)
            .run("demo", &plan())
            .await
            .expect("run");

        assert_eq!(*o.deployed.lock().unwrap(), vec!["demo"]);
        assert_eq!(*o.waited.lock().unwrap(), vec!["demo"]);
        assert!(out.is_success());
        assert_eq!(out.executed, 2, "deployment + wait");
    }

    #[tokio::test]
    async fn rerun_is_idempotent() {
        let o = Fake::default();
        let s = state().await;
        let p = plan();

        Executor::new(&o, &s)
            .apply(true)
            .run("demo", &p)
            .await
            .unwrap();
        let second = Executor::new(&o, &s)
            .apply(true)
            .run("demo", &p)
            .await
            .expect("second run");

        assert_eq!(
            o.deployed.lock().unwrap().len(),
            1,
            "the deployment must not be replayed"
        );
        assert_eq!(second.executed, 0);
        assert!(second.skipped >= 2);
    }

    #[tokio::test]
    async fn failure_stops_and_is_recorded() {
        let o = Fake {
            fail_deploy: true,
            ..Default::default()
        };
        let s = state().await;

        let out = Executor::new(&o, &s)
            .apply(true)
            .run("demo", &plan())
            .await
            .expect("run");

        assert!(!out.is_success());
        assert!(
            o.waited.lock().unwrap().is_empty(),
            "we stop at the first failure"
        );

        let recorded = s.plan_actions("demo").await.unwrap();
        let failed = recorded
            .iter()
            .find(|a| a.status == ActionStatus::Failed)
            .expect("failure recorded");
        assert!(failed
            .error
            .as_deref()
            .unwrap()
            .contains("simulated failure"));
        assert_eq!(
            s.installed_apps().await.unwrap()[0].1,
            "failed",
            "the app is marked as failed"
        );
    }

    #[tokio::test]
    async fn resume_picks_up_after_the_failure() {
        let s = state().await;
        let p = plan();

        // First pass: fails at deployment.
        let failing = Fake {
            fail_deploy: true,
            ..Default::default()
        };
        Executor::new(&failing, &s)
            .apply(true)
            .run("demo", &p)
            .await
            .unwrap();

        // Second pass, orchestrator repaired.
        let ok = Fake::default();
        let out = Executor::new(&ok, &s)
            .apply(true)
            .run("demo", &p)
            .await
            .unwrap();

        assert!(out.is_success());
        assert_eq!(*ok.deployed.lock().unwrap(), vec!["demo"]);
    }

    #[tokio::test]
    async fn unimplemented_is_never_reported_as_done() {
        let o = Fake::default();
        let s = State::in_memory().await.unwrap();

        let m: hlb_types::Manifest = serde_yaml_ng::from_str(WITH_DB).unwrap();
        s.upsert_app("demo", &m, None).await.unwrap();

        let p = hlb_resolver::resolve(&m, &hlb_resolver::InstallParams::default()).unwrap();
        let out = Executor::new(&o, &s)
            .apply(true)
            .run("demo", &p)
            .await
            .unwrap();

        assert!(out.unimplemented >= 2, "database + secret unimplemented");
        assert_eq!(s.installed_apps().await.unwrap()[0].1, "partial");

        // And above all: nothing is wrongly marked `done`.
        let recorded = s.plan_actions("demo").await.unwrap();
        let db = recorded
            .iter()
            .find(|a| a.kind == "ProvisionDatabase")
            .expect("action present");
        assert_eq!(db.status, ActionStatus::Unimplemented);
    }

    const WITH_MAIL: &str = r#"
apiVersion: hlb/v1
kind: App
metadata: { name: demo }
spec:
  image: { repo: a/b, tag: "1", digest: "sha256:x" }
  requires:
    - kind: mail-account
      aliases: true
"#;

    #[tokio::test]
    async fn an_app_finally_learns_where_its_database_is() {
        // 🔴 THE defect this test guards: the resolver created the database, the
        // isolated role and the password - then deployed the app SAYING NOTHING TO IT.
        // It fell back to its internal SQLite. Healthy service, green probe, green
        // dashboard, and the data in a file nobody backed up while an empty database
        // was faithfully dumped every night.
        const AVEC_LIAISON: &str = r#"
apiVersion: hlb/v1
kind: App
metadata: { name: demo }
spec:
  image: { repo: acme/demo, tag: "1.0", digest: "sha256:abc" }
  requires:
    - kind: database
      engine: postgres
  env:
    DB_HOST: "{{ db.host }}"
    DB_NAME: "{{ db.name }}"
    DB_USER: "{{ db.user }}"
    DB_PASSWORD: "{{ db.password }}"
    DB_URL: "postgres://{{ db.user }}:{{ db.password }}@{{ db.host }}/{{ db.name }}"
"#;
        let o = Fake::default();
        let s = State::in_memory().await.unwrap();
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::init(dir.path().join("master.key")).unwrap();

        let m: hlb_types::Manifest = serde_yaml_ng::from_str(AVEC_LIAISON).unwrap();
        s.upsert_app("demo", &m, None).await.unwrap();

        let p = hlb_resolver::resolve(&m, &Default::default()).unwrap();

        // 🔴 The PLAN must carry only the token. It is displayed by `hlb plan`,
        // recorded in the state and exported to the Git mirror: a password substituted
        // here would be published in all three, one of which keeps history.
        let plan_text = p
            .actions
            .iter()
            .map(|a| a.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            !plan_text.contains("postgres://demo:"),
            "the plan must never carry resolved credentials: {plan_text}"
        );

        Executor::new(&o, &s)
            .with_vault(&vault)
            .apply(true)
            .run("demo", &p)
            .await
            .unwrap();

        // What reaches Swarm, on the other hand, must be RESOLVED.
        let deploiements = o.deployed_env.lock().unwrap().clone();
        let (_, env) = deploiements
            .iter()
            .find(|(n, _)| n == "demo")
            .expect("demo deployed");
        let table: std::collections::BTreeMap<&str, &str> =
            env.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();

        assert_eq!(table.get("DB_HOST"), Some(&"postgres"));
        assert_eq!(table.get("DB_NAME"), Some(&"demo"));
        assert_eq!(table.get("DB_USER"), Some(&"demo"));

        let password = table.get("DB_PASSWORD").expect("mot de passe transmis");
        assert!(!password.contains("{{"), "unresolved token: {password}");
        assert!(password.len() >= 16, "mot de passe trop court : {password}");

        // And the composite URL must carry the SAME password, not another draw.
        let url = table.get("DB_URL").expect("URL transmise");
        assert_eq!(*url, format!("postgres://demo:{password}@postgres/demo"));
    }

    #[tokio::test]
    async fn several_databases_share_one_role() {
        // 🔴 Seafile wants THREE databases and connects with ONE account. Naming the
        // role after the database would produce three accounts for one credential set,
        // and the app would fail on two of them - on an authentication error that would
        // not say which.
        const TROIS: &str = r#"
apiVersion: hlb/v1
kind: App
metadata: { name: seafile }
spec:
  image: { repo: acme/seafile, tag: "1.0", digest: "sha256:abc" }
  requires:
    - kind: database
      engine: mariadb
      name: ccnet_db
    - kind: database
      engine: mariadb
      name: seafile_db
    - kind: database
      engine: mariadb
      name: seahub_db
"#;
        let m: hlb_types::Manifest = serde_yaml_ng::from_str(TROIS).unwrap();
        let p = hlb_resolver::resolve(&m, &Default::default()).unwrap();

        let roles: Vec<&str> = p
            .actions
            .iter()
            .filter_map(|a| match a {
                Action::ProvisionDatabase { role, .. } => Some(role.as_str()),
                _ => None,
            })
            .collect();

        assert_eq!(
            roles,
            vec!["seafile", "seafile", "seafile"],
            "a single role"
        );

        let bases: Vec<&str> = p
            .actions
            .iter()
            .filter_map(|a| match a {
                Action::ProvisionDatabase { database, .. } => Some(database.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(
            bases,
            vec!["ccnet_db", "seafile_db", "seahub_db"],
            "trois bases"
        );

        // ⚠️ One role means one password: three identical generations would clutter
        // the plan and the state without changing anything.
        let secrets = p
            .actions
            .iter()
            .filter(|a| matches!(a, Action::GenerateSecret { name, .. } if name.ends_with("-db-password")))
            .count();
        assert_eq!(secrets, 1, "one password for one role");
    }

    #[tokio::test]
    async fn an_unresolvable_token_stays_visible_instead_of_becoming_empty() {
        // 🔴 Without a vault the password cannot be read. The token must stay LITERAL
        // rather than become an empty string: an empty variable looks like missing
        // configuration, and the app would complain about an incorrect password - you
        // would look at the password for a long time.
        const M: &str = r#"
apiVersion: hlb/v1
kind: App
metadata: { name: demo }
spec:
  image: { repo: acme/demo, tag: "1.0", digest: "sha256:abc" }
  requires:
    - kind: database
      engine: postgres
  env:
    DB_PASSWORD: "{{ db.password }}"
    DB_HOST: "{{ db.host }}"
"#;
        let o = Fake::default();
        let s = State::in_memory().await.unwrap();
        let m: hlb_types::Manifest = serde_yaml_ng::from_str(M).unwrap();
        s.upsert_app("demo", &m, None).await.unwrap();

        let p = hlb_resolver::resolve(&m, &Default::default()).unwrap();
        // Pas de `.with_vault(...)` : aucun secret n'est lisible.
        Executor::new(&o, &s)
            .apply(true)
            .run("demo", &p)
            .await
            .unwrap();

        let deploiements = o.deployed_env.lock().unwrap().clone();
        let (_, env) = deploiements
            .iter()
            .find(|(n, _)| n == "demo")
            .expect("deployed");
        let table: std::collections::BTreeMap<&str, &str> =
            env.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();

        assert_eq!(
            table.get("DB_PASSWORD"),
            Some(&"{{ db.password }}"),
            "an unresolved token must stay visible, never become empty"
        );
        // What is knowable without a vault still is: the host depends on no secret,
        // and hiding it would help nobody.
        assert_eq!(table.get("DB_HOST"), Some(&"postgres"));
    }

    #[tokio::test]
    async fn a_mailbox_is_never_pretended_without_a_stalwart() {
        // 🔴 Same principle as for the database: without a Stalwart client the action
        // is recorded as "unimplemented", never "done". Reporting a mailbox that does
        // not exist would make the app fail on its first send.
        let o = Fake::default();
        let s = State::in_memory().await.unwrap();
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::init(dir.path().join("master.key")).unwrap();

        let m: hlb_types::Manifest = serde_yaml_ng::from_str(WITH_MAIL).unwrap();
        s.upsert_app("demo", &m, None).await.unwrap();

        let params = hlb_resolver::InstallParams {
            mail_domain: Some("example.fr".into()),
            ..Default::default()
        };
        let p = hlb_resolver::resolve(&m, &params).unwrap();

        Executor::new(&o, &s)
            .with_vault(&vault)
            .apply(true)
            .run("demo", &p)
            .await
            .unwrap();

        let rec = s.plan_actions("demo").await.unwrap();
        let mail = rec
            .iter()
            .find(|a| a.kind == "ProvisionMailAccount")
            .expect("action present");
        assert_eq!(mail.status, ActionStatus::Unimplemented);

        // And no password was manufactured: it would have matched nothing.
        assert!(s.secret("demo-mail-password").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn secrets_need_a_vault_and_are_never_faked() {
        // Without a vault, secret generation is "unimplemented", never "done".
        let o = Fake::default();
        let s = State::in_memory().await.unwrap();
        let m: hlb_types::Manifest = serde_yaml_ng::from_str(WITH_DB).unwrap();
        s.upsert_app("demo", &m, None).await.unwrap();

        let p = hlb_resolver::resolve(&m, &hlb_resolver::InstallParams::default()).unwrap();
        Executor::new(&o, &s)
            .apply(true)
            .run("demo", &p)
            .await
            .unwrap();

        let rec = s.plan_actions("demo").await.unwrap();
        let secret = rec.iter().find(|a| a.kind == "GenerateSecret").unwrap();
        assert_eq!(secret.status, ActionStatus::Unimplemented);
        assert!(s.secret("demo-db-password").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn with_a_vault_the_secret_is_generated_and_encrypted() {
        let o = Fake::default();
        let s = State::in_memory().await.unwrap();
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::init(dir.path().join("master.key")).unwrap();

        let m: hlb_types::Manifest = serde_yaml_ng::from_str(WITH_DB).unwrap();
        s.upsert_app("demo", &m, None).await.unwrap();
        let p = hlb_resolver::resolve(&m, &hlb_resolver::InstallParams::default()).unwrap();

        Executor::new(&o, &s)
            .with_vault(&vault)
            .apply(true)
            .run("demo", &p)
            .await
            .unwrap();

        let ct = s
            .secret("demo-db-password")
            .await
            .unwrap()
            .expect("secret stored");
        let clear = vault.decrypt(&ct).expect("decryptable");
        assert_eq!(clear.len(), hlb_secrets::DEFAULT_PASSWORD_LEN);
        assert!(clear.chars().all(|c| c.is_ascii_alphanumeric()));

        // Provisioning stays unimplemented: no PostgreSQL supplied.
        let rec = s.plan_actions("demo").await.unwrap();
        let db = rec.iter().find(|a| a.kind == "ProvisionDatabase").unwrap();
        assert_eq!(db.status, ActionStatus::Unimplemented);
    }

    #[tokio::test]
    async fn a_replay_does_not_change_an_existing_password() {
        let o = Fake::default();
        let s = State::in_memory().await.unwrap();
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::init(dir.path().join("master.key")).unwrap();

        let m: hlb_types::Manifest = serde_yaml_ng::from_str(WITH_DB).unwrap();
        s.upsert_app("demo", &m, None).await.unwrap();
        let p = hlb_resolver::resolve(&m, &hlb_resolver::InstallParams::default()).unwrap();

        let exec = || Executor::new(&o, &s).with_vault(&vault).apply(true);
        exec().run("demo", &p).await.unwrap();
        let first = s.secret("demo-db-password").await.unwrap().unwrap();

        // A replay is forced by clearing the progress.
        s.set_action_status("demo", 0, ActionStatus::Pending, None)
            .await
            .unwrap();
        exec().run("demo", &p).await.unwrap();
        let second = s.secret("demo-db-password").await.unwrap().unwrap();

        assert_eq!(
            first, second,
            "le mot de passe ne doit pas changer sous les pieds du service"
        );
    }

    #[tokio::test]
    async fn blocking_guide_prevents_apply() {
        let o = Fake::default();
        let s = State::in_memory().await.unwrap();

        let m: hlb_types::Manifest = serde_yaml_ng::from_str(WITH_GUIDE).unwrap();
        s.upsert_app("demo", &m, None).await.unwrap();

        let p = hlb_resolver::resolve(&m, &hlb_resolver::InstallParams::default()).unwrap();
        let err = Executor::new(&o, &s)
            .apply(true)
            .run("demo", &p)
            .await
            .unwrap_err();

        assert!(
            matches!(err, Error::BlockedByGuide { blocking: 1 }),
            "{err}"
        );
        assert!(
            o.deployed.lock().unwrap().is_empty(),
            "nothing deployed before the guide"
        );

        // The guide is recorded anyway: it is real work to be done.
        assert_eq!(s.pending_guides().await.unwrap().len(), 1);

        // Once handled, the installation resumes.
        s.verify_guide("demo", "demo-first-admin").await.unwrap();
        let out = Executor::new(&o, &s)
            .apply(true)
            .run("demo", &p)
            .await
            .expect("run");
        assert!(out.is_success());
        assert_eq!(*o.deployed.lock().unwrap(), vec!["demo"]);
    }
}
