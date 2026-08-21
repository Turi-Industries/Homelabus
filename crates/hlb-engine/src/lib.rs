//! L'exécuteur : applique un plan, action par action.
//!
//! Trois propriétés imposées par le §2ter.5, dès le départ et non rétrofitées :
//!
//! - **Aperçu par défaut.** Rien n'est modifié sans `--apply` explicite.
//! - **Idempotence.** Relancer sur une app déjà installée ne casse rien.
//! - **Reprise.** Un échec à l'action 4/10 reprend à 4, pas à zéro.
//!
//! Et une règle d'honnêteté : une action non implémentée est enregistrée comme telle
//! (`Unimplemented`), **jamais** comme réussie.

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
        "🔴 l'extension « {extension} » n'a pas pu être activée sur « {database} ». \
             Une extension ne s'installe PAS depuis SQL : elle doit être présente dans \
             l'image du serveur PostgreSQL. Vérifie l'image du service `postgres` au \
             catalogue — pour les extensions vectorielles, \
             ghcr.io/immich-app/postgres:17-vectorchord0.4.3-pgvector0.8.0 les porte. \
             Cause : {cause}"
    )]
    MissingExtension {
        extension: String,
        database: String,
        cause: String,
    },

    #[error("le secret « {0} » est introuvable — le plan a-t-il été exécuté dans l'ordre ?")]
    MissingSecret(String),

    #[error(
        "{blocking} action(s) manuelle(s) bloquante(s) en attente — \
             traite-les puis relance (hlb todo)"
    )]
    BlockedByGuide { blocking: usize },
}

pub type Result<T> = std::result::Result<T, Error>;

/// Le point d'entrée S3 de la plateforme.
///
/// ⚠️ Nom de service Swarm, pas une URL publique : le trafic objet reste sur le réseau
/// interne. L'exposer ferait sortir du cluster des octets qui n'ont aucune raison d'en
/// sortir, et Garage n'a pas d'authentification autre que la signature S3.
const S3_ENDPOINT: &str = "http://garage:3900";

/// Garage ignore la région mais la SIGNATURE S3 la couvre : un client qui en annonce
/// une autre voit ses requêtes refusées sur une erreur de signature, qui ne dit rien
/// de la région.
const S3_REGION: &str = "garage";

/// Ce qui a été fait, pour le compte rendu.
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
    /// Absent tant que la clé maîtresse n'est pas chargée : sans coffre, aucun
    /// secret ne peut être généré ni relu.
    vault: Option<&'a Vault>,
    /// Absent tant que PostgreSQL n'est pas déployé et joignable.
    postgres: Option<&'a PostgresProvisioner>,
    /// Idem pour MariaDB. Les deux peuvent coexister : des apps différentes ont des
    /// exigences différentes, et le résolveur choisit par manifest.
    mariadb: Option<&'a MariadbProvisioner>,
    /// Absent hors ligne : sans registre, aucun digest ne peut être résolu.
    registry: Option<&'a RegistryClient>,
    /// Absent tant que PocketID n'est pas déployé et qu'on n'a pas de clé d'API.
    identity: Option<&'a PocketId>,
    /// Absent si Caddy n'est pas encore joignable : l'app est déployée mais pas
    /// encore routée, ce qui est un état légitime.
    ingress: Option<&'a CaddyAdmin>,
    mail: Option<&'a Stalwart>,
    /// Absent tant que Garage n'est pas déployé et qu'on n'a pas son jeton
    /// d'administration : aucun compartiment ne peut alors être provisionné.
    objstore: Option<&'a Garage>,
    /// URL de l'API CrowdSec. Absente : pas de filtrage réputationnel.
    crowdsec_url: Option<String>,
    /// Faux par défaut : on n'écrit rien tant que ce n'est pas demandé.
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

    /// Passe en mode application réelle. L'appelant doit le vouloir explicitement.
    pub fn apply(mut self, yes: bool) -> Self {
        self.apply = yes;
        self
    }

    /// Exécute le plan pour `app`.
    ///
    /// Les actions manuelles bloquantes arrêtent l'exécution **avant** toute
    /// modification (§4.6) : inutile de déployer une app dont le DNS n'existe pas.
    pub async fn run(&self, app: &str, plan: &Plan) -> Result<Outcome> {
        let records: Vec<(String, String)> = plan
            .actions
            .iter()
            .map(|a| (kind_of(a).to_string(), a.to_string()))
            .collect();
        self.state.record_plan(app, &records).await?;

        // Les guides sont enregistrés même en aperçu : ils décrivent du travail réel.
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

        // On interroge l'état, pas le plan : une action déjà traitée par
        // l'utilisateur ne doit plus bloquer.
        let blocking = self.state.unverified_blocking(app).await?;
        if blocking > 0 && self.apply {
            return Err(Error::BlockedByGuide { blocking });
        }

        let done = self.state.completed_seqs(app).await?;
        let mut out = Outcome::default();

        for (seq, action) in plan.actions.iter().enumerate() {
            if done.contains(&(seq as i64)) {
                out.skipped += 1;
                tracing::debug!(seq, "déjà fait, ignoré");
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
                    // On s'arrête net : continuer après un échec de dépendance ne
                    // produirait que des erreurs en cascade.
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

    /// La configuration d'entrée, CrowdSec compris quand il est enrôlé.
    ///
    /// 🔴 CrowdSec n'est activé QUE si sa clé de videur est au coffre. Sans elle, on
    /// génère un Caddyfile sans videur plutôt qu'un Caddyfile avec une clé vide : ce
    /// dernier démarrerait normalement et ne bloquerait plus rien, en silence.
    async fn ingress_config(&self) -> Result<hlb_ingress::Config> {
        let mut cfg = hlb_ingress::Config::default();

        // Même règle que dans le CLI : le portail n'apparaît que s'il sert.
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
                    // Une clé abîmée au coffre ne doit pas produire un videur muet.
                    tracing::error!(
                        "🔴 clé de videur CrowdSec invalide au coffre — filtrage DÉSACTIVÉ ; \
                         réenrôle avec `hlb crowdsec enroll --apply`"
                    );
                }
            }
            None => tracing::warn!(
                "CrowdSec non enrôlé : le trafic n'est pas filtré \
                 (hlb crowdsec enroll --apply)"
            ),
        }
        Ok(cfg)
    }

    /// Les routes de toutes les apps installées.
    ///
    /// Recalculées depuis l'état à chaque fois : c'est le manifest figé qui fait foi
    /// (§4.8), pas le catalogue courant.
    async fn all_routes(&self) -> Result<Vec<hlb_ingress::Route>> {
        let mut routes = Vec::new();
        for (name, status) in self.state.installed_apps().await? {
            if status == "failed" {
                continue;
            }
            let m = self.state.app_manifest(&name).await?;
            let domain = self.state.app_domain(&name).await?;
            // §4.6bis — la route ne s'ouvre qu'une fois les actions bloquantes traitées.
            let cleared = self.state.unverified_blocking(&name).await? == 0;
            routes.extend(hlb_ingress::routes_from_manifest(
                &m,
                domain.as_deref(),
                cleared,
            ));
        }
        Ok(routes)
    }

    /// Résout les jetons de liaison d'un ensemble de variables (§4.3).
    ///
    /// 🔴 **C'est ici, et nulle part avant, que les secrets prennent leur valeur.** Le
    /// plan traverse l'affichage de `hlb plan`, l'état SQLite et le miroir Git : un
    /// mot de passe substitué en amont serait publié aux trois endroits, dont un dépôt
    /// qui garde l'historique. Seule Swarm voit la valeur finale.
    ///
    /// ⚠️ Un jeton qu'on ne sait pas remplir est laissé **littéral** plutôt que vidé.
    /// Une variable vide ressemble à une configuration absente : l'app se plaindrait
    /// d'un mot de passe incorrect, alors que `{{ db.password }}` dans ses journaux
    /// désigne le vrai problème du premier coup.
    async fn resoudre_liaisons(
        &self,
        app: &str,
        env: &[(String, String)],
    ) -> Result<Vec<(String, String)>> {
        use hlb_types::binding::{substitute, tokens_in, Token};

        // Rien à faire si aucun jeton n'est utilisé : on évite d'aller chercher des
        // secrets pour des apps qui n'en ont pas besoin.
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
        // 🔴 Comme les compagnons, les jetons S3 vivent hors de l'énumération `Token` :
        // le compartiment et la clé sont des chaînes libres, et forcer un ensemble
        // ouvert dans un type fermé aurait affaibli l'exhaustivité pour tous les autres.
        let mut s3: std::collections::BTreeMap<String, String> = Default::default();

        if let Some(d) = &domaine {
            valeurs.insert(Token::Domain, d.clone());
        }

        // Les coordonnées de la base viennent de la CAPACITÉ déclarée, pas d'une
        // constante : c'est ce qui permet au même manifest de suivre la topologie.
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
                        // 🔴 Le rôle porte le nom de l'APP, pas celui de la base :
                        // une app à plusieurs bases s'y connecte avec un seul compte.
                        // Doit rester aligné sur `ProvisionDatabase` du résolveur.
                        valeurs.insert(Token::DbUser, app.to_string());

                        if let Some(mdp) = self.lire_secret(&format!("{app}-db-password")).await? {
                            let schema = match engine {
                                hlb_types::DbEngine::Postgres => "postgres",
                                hlb_types::DbEngine::Mariadb => "mysql",
                            };
                            valeurs.insert(
                                Token::DbUrl,
                                format!("{schema}://{app}:{mdp}@{hote}:{port}/{base}"),
                            );
                            valeurs.insert(Token::DbPassword, mdp);
                        }
                    }

                    hlb_types::Capability::Cache { engine, dedicated } => {
                        // Une instance dédiée porte le nom de l'app en préfixe (§3.3).
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

        // L'émetteur OIDC dépend du domaine de PocketID, pas de celui de l'app.
        if let Ok(Some(d)) = self.state.app_domain("pocket-id").await {
            valeurs.insert(Token::OidcIssuer, format!("https://{d}"));
        }

        // 🔴 Les compagnons ne passent PAS par l'énumération `Token` : leur ensemble
        // est ouvert — chaque app définit les siens — là où `Token` est fermé par
        // dessein, pour que l'ajout d'une variante fasse échouer la compilation
        // partout. Un jeton paramétré ne rentre pas dans ce contrat, et l'y forcer
        // aurait affaibli l'énumération pour tous les autres.
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

    /// Lit un secret du coffre, ou `None` s'il n'existe pas encore.
    ///
    /// ⚠️ Absent n'est pas une erreur ici : un plan peut être exécuté avant que le
    /// secret ne soit généré, et l'action correspondante s'en chargera. Le jeton reste
    /// alors littéral, ce qui se voit.
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
                // ⚠️ Le plan a été construit AVANT l'exécution, donc son champ `image`
                // porte encore le tag. Le digest résolu à l'étape précédente vit dans
                // l'état — c'est lui qui fait foi (§7).
                let resolved = match self.state.app_manifest(app).await {
                    Ok(m) if m.spec.image.is_pinned() => m.spec.image.reference(),
                    _ => image.clone(),
                };

                // 🔴 Les jetons de liaison prennent leur valeur ICI, pas dans le plan
                // (§4.3). C'est ce qui fait qu'une app apprend enfin où est sa base.
                let env = self.resoudre_liaisons(app, env).await?;

                let mut spec = ServiceSpec::new(name, &resolved)
                    .replicas(*replicas)
                    .env(env.clone())
                    // §9 — le durcissement déclaré au manifest est réellement appliqué.
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

                // `if_absent` : un mot de passe déjà injecté dans un service ne doit
                // jamais changer sous ses pieds à la relance d'un plan.
                let created = self
                    .state
                    .store_secret_if_absent(name, &ct, purpose)
                    .await?;
                if created {
                    tracing::info!(secret = name, "secret généré");
                }
                Ok(Step::Done)
            }

            Action::ProvisionBucket {
                bucket,
                key_name,
                secret_name,
            } => {
                let (Some(garage), Some(vault)) = (self.objstore, self.vault) else {
                    // 🔴 Jamais `Done` : prétendre avoir créé un compartiment ferait
                    // démarrer l'app sur un stockage qui n'existe pas, et elle
                    // écrirait dans le vide.
                    return Ok(Step::NotImplemented);
                };

                // 🔴 Le coffre fait autorité, pas Garage. Une clé présente chez Garage
                // dont le secret est perdu est INUTILISABLE — il n'est donné qu'à la
                // création. Interroger Garage seul ferait repartir une reprise sans
                // secret, et l'app échouerait sur une « signature invalide » qui
                // n'oriente vers rien.
                let connu = match self.state.secret(secret_name).await? {
                    Some(ct) => Some(vault.decrypt(&ct)?),
                    None => None,
                };

                let id = garage.ensure_bucket(bucket).await?;
                let cle = garage.ensure_key(key_name, connu.as_deref()).await?;

                // Le secret part au coffre AVANT d'accorder l'accès : si l'octroi
                // échoue, on garde de quoi reprendre ; l'inverse perdrait la clé.
                let ct = vault.encrypt(&cle.secret_access_key)?;
                if !self
                    .state
                    .store_secret_if_absent(secret_name, &ct, "clé secrète S3")
                    .await?
                {
                    // Le secret existait déjà : c'est une reprise, et `ensure_key`
                    // vient de nous rendre CE secret-là. La rotation le réécrit à
                    // l'identique, ce qui est sans effet — mais couvre le cas où
                    // Garage avait perdu la clé et vient d'en créer une neuve.
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

                // 🔴 Le `match` est exhaustif : ajouter un moteur à `DbEngine` fait
                // échouer la compilation ici, ce qui force à décider comment le
                // provisionner plutôt que de le laisser tomber dans un cas par défaut
                // qui prétendrait avoir réussi.
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
                    tracing::info!(database, role, moteur = ?engine, "base provisionnée");
                }

                // 🔴 Les extensions APRÈS la base, et sur la base de l'app — pas sur
                // `postgres`. `CREATE EXTENSION` est local à une base : posée au
                // mauvais endroit, elle réussit et l'app ne la voit pas.
                if !extensions.is_empty() {
                    let Some(pg) = self.postgres else {
                        return Ok(Step::NotImplemented);
                    };
                    for ext in extensions {
                        if let Err(e) = pg.create_extension(database, ext).await {
                            // Le remède est dans le message : une extension absente
                            // de l'IMAGE ne s'installe pas depuis SQL, et l'erreur
                            // brute de PostgreSQL ressemble à un problème de droits.
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
                // §4.6bis — on tente d'abord de s'en occuper tout seul. Beaucoup
                // d'étapes « dans l'application » se scriptent ; les traiter comme
                // manuelles par défaut est l'erreur habituelle.
                let issue = hlb_guide::try_automate(self.orchestrator, service, step, &[]).await;

                if issue.handled() {
                    tracing::info!(step = %id, "{}", issue.describe());
                    // L'étape est faite : elle ne doit plus bloquer.
                    self.state.verify_guide(app, id).await?;
                } else if !matches!(issue, hlb_guide::AutomationOutcome::NothingDeclared) {
                    // On dit POURQUOI ça reste manuel : sans ça, l'utilisateur ne
                    // saurait pas pourquoi le système lui demande de faire ce qu'il
                    // annonçait automatiser.
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

                // §7 — le digest est figé dans l'état : c'est lui qui sera déployé,
                // pas le tag, qui est mutable.
                self.state.set_app_digest(app, &digest).await?;
                tracing::info!(%image, digest, "digest résolu");
                Ok(Step::Done)
            }

            Action::CreateVolume {
                name,
                backup,
                sqlite,
                ..
            } => {
                let info = self.orchestrator.create_volume(name).await?;

                // On mémorise le point de montage RÉEL : c'est ce que la sauvegarde
                // ira lire (§8). Sans lui, on ne sait pas quoi sauvegarder.
                self.state
                    .add_volume(app, &info.name, &info.mountpoint, *backup, *sqlite)
                    .await?;

                if info.existed {
                    tracing::info!(name, "volume existant conservé (il porte des données)");
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

                // Idempotent : un client existant est conservé, et son secret n'est
                // JAMAIS régénéré — il est déjà injecté dans l'app qui tourne (§5.2).
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
                        // Client déjà provisionné : le secret correspondant doit être
                        // au coffre. S'il n'y est pas, on ne peut plus le retrouver —
                        // PocketID ne le redonne jamais sans le régénérer.
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

                // ⚠️ On régénère la configuration COMPLÈTE, pas seulement la route de
                // cette app. Caddy remplace toute sa config à chaque `/load` : envoyer
                // un fragment supprimerait les routes des autres apps.
                let routes = self.all_routes().await?;
                let cfg = self.ingress_config().await?;
                caddy
                    .load_caddyfile(&hlb_ingress::render_frontend(&routes, &cfg))
                    .await?;

                tracing::info!(routes = routes.len(), "configuration Caddy rechargée");
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

                // 🔴 Un quota déclaré et non posé est pire que pas de quota : la boîte
                // paraîtrait bornée et grossirait sans fin, jusqu'à saturer le disque
                // qui porte aussi les bases. `hlb-mail` n'a aucune opération de quota,
                // Stalwart ne l'exposant pas en JMAP.
                //
                // On refuse donc AVANT de créer quoi que ce soit, plutôt que de créer
                // la boîte et de taire la moitié manquante — « Unimplemented n'est
                // jamais Done ».
                if quota_bytes.is_some() {
                    tracing::warn!(
                        address,
                        "quota de boîte déclaré au manifest mais non applicable : \
                         Stalwart ne l'expose pas en JMAP. Retire `quotaBytes` du \
                         manifest, ou pose-le à la main dans Stalwart."
                    );
                    return Ok(Step::NotImplemented);
                }

                // Le mot de passe vit au coffre, comme les autres. `if_absent` :
                // relancer un plan ne doit pas en fabriquer un second, qui ne
                // correspondrait plus à celui déposé dans Stalwart.
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

                // Les aliases déclarés au manifest sont un booléen : « cette app a
                // le droit d'en avoir ». Elle n'en réclame aucun à l'installation —
                // ils se créent à l'usage (§5.9).
                let demandes: Vec<String> = Vec::new();
                let p = mail.ensure_account(address, &password, &demandes).await?;

                if p.created {
                    tracing::info!(adresse = %p.address, "boîte mail créée");
                } else {
                    // 🔴 Conséquence concrète : le mot de passe du coffre est celui
                    // d'avant, et on n'y a PAS touché. Le changer couperait l'accès
                    // IMAP de l'app qui tourne.
                    tracing::debug!(adresse = %p.address, "boîte déjà présente, conservée");
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

/// Étiquette courte et stable, stockée en base et affichée dans les rapports.
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

    /// Orchestrateur factice : enregistre les appels, peut échouer à la demande.
    /// Ce qu'un déploiement a réellement transmis : nom du service et variables.
    type Deploiement = (String, Vec<(String, String)>);

    #[derive(Default)]
    struct Fake {
        deployed: Mutex<Vec<String>>,
        waited: Mutex<Vec<String>>,
        updated: Mutex<Vec<(String, String)>>,
        scaled: Mutex<Vec<(String, u64)>>,
        /// Les variables réellement transmises à Swarm, par service.
        ///
        /// 🔴 C'est le SEUL endroit où l'on peut constater qu'un jeton a bien été
        /// résolu : le plan, lui, doit continuer à porter le jeton littéral.
        deployed_env: Mutex<Vec<Deploiement>>,
        /// Ce que `list()` renverra : l'état « observé » du cluster.
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
                return Err(hlb_orchestrator::Error::Unexpected("échec simulé".into()));
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
            // Un faux orchestrateur n'a pas de tâches : le vide est la réponse honnête.
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
            "aucun déploiement en aperçu"
        );
        assert!(out.is_success());
        // Rien n'est marqué fait : l'aperçu ne consomme pas le plan.
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
        assert_eq!(out.executed, 2, "déploiement + attente");
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
            "le déploiement ne doit pas être rejoué"
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
            "on s'arrête au premier échec"
        );

        let recorded = s.plan_actions("demo").await.unwrap();
        let failed = recorded
            .iter()
            .find(|a| a.status == ActionStatus::Failed)
            .expect("échec enregistré");
        assert!(failed.error.as_deref().unwrap().contains("échec simulé"));
        assert_eq!(
            s.installed_apps().await.unwrap()[0].1,
            "failed",
            "l'app est marquée en échec"
        );
    }

    #[tokio::test]
    async fn resume_picks_up_after_the_failure() {
        let s = state().await;
        let p = plan();

        // Premier passage : échoue au déploiement.
        let failing = Fake {
            fail_deploy: true,
            ..Default::default()
        };
        Executor::new(&failing, &s)
            .apply(true)
            .run("demo", &p)
            .await
            .unwrap();

        // Second passage, orchestrateur réparé.
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

        assert!(out.unimplemented >= 2, "base + secret non implémentés");
        assert_eq!(s.installed_apps().await.unwrap()[0].1, "partial");

        // Et surtout : rien n'est marqué `done` à tort.
        let recorded = s.plan_actions("demo").await.unwrap();
        let db = recorded
            .iter()
            .find(|a| a.kind == "ProvisionDatabase")
            .expect("action présente");
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
        // 🔴 LE défaut que ce test protège : le résolveur créait la base, le rôle
        // isolé et le mot de passe — puis déployait l'app SANS RIEN LUI DIRE. Elle
        // retombait sur son SQLite interne. Service sain, sonde verte, tableau de
        // bord au vert, et les données dans un fichier que personne ne sauvegardait
        // pendant qu'une base vide était fidèlement dumpée chaque nuit.
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

        // 🔴 Le PLAN ne doit porter que le jeton. Il est affiché par `hlb plan`,
        // enregistré dans l'état et exporté vers le miroir Git : un mot de passe
        // substitué ici serait publié aux trois endroits, dont un dépôt qui garde
        // l'historique.
        let texte_du_plan = p
            .actions
            .iter()
            .map(|a| a.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            !texte_du_plan.contains("postgres://demo:"),
            "le plan ne doit jamais porter d'identifiants résolus : {texte_du_plan}"
        );

        Executor::new(&o, &s)
            .with_vault(&vault)
            .apply(true)
            .run("demo", &p)
            .await
            .unwrap();

        // En revanche, ce qui atteint Swarm doit être RÉSOLU.
        let deploiements = o.deployed_env.lock().unwrap().clone();
        let (_, env) = deploiements
            .iter()
            .find(|(n, _)| n == "demo")
            .expect("demo déployée");
        let table: std::collections::BTreeMap<&str, &str> =
            env.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();

        assert_eq!(table.get("DB_HOST"), Some(&"postgres"));
        assert_eq!(table.get("DB_NAME"), Some(&"demo"));
        assert_eq!(table.get("DB_USER"), Some(&"demo"));

        let mdp = table.get("DB_PASSWORD").expect("mot de passe transmis");
        assert!(!mdp.contains("{{"), "jeton non résolu : {mdp}");
        assert!(mdp.len() >= 16, "mot de passe trop court : {mdp}");

        // Et l'URL composite doit porter le MÊME mot de passe, pas un autre tirage.
        let url = table.get("DB_URL").expect("URL transmise");
        assert_eq!(*url, format!("postgres://demo:{mdp}@postgres/demo"));
    }

    #[tokio::test]
    async fn several_databases_share_one_role() {
        // 🔴 Seafile veut TROIS bases et s'y connecte avec UN compte. Nommer le rôle
        // d'après la base produirait trois comptes pour un seul jeu d'identifiants, et
        // l'app échouerait sur deux d'entre elles — sur une erreur d'authentification
        // qui ne dirait pas laquelle.
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

        assert_eq!(roles, vec!["seafile", "seafile", "seafile"], "un seul rôle");

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

        // ⚠️ Un seul rôle veut dire un seul mot de passe : trois générations
        // identiques encombreraient le plan et l'état sans rien changer.
        let secrets = p
            .actions
            .iter()
            .filter(|a| matches!(a, Action::GenerateSecret { name, .. } if name.ends_with("-db-password")))
            .count();
        assert_eq!(secrets, 1, "un seul mot de passe pour un seul rôle");
    }

    #[tokio::test]
    async fn an_unresolvable_token_stays_visible_instead_of_becoming_empty() {
        // 🔴 Sans coffre, le mot de passe ne peut pas être lu. Le jeton doit rester
        // LITTÉRAL plutôt que devenir une chaîne vide : une variable vide ressemble à
        // une configuration absente, et l'app se plaindrait d'un mot de passe
        // incorrect — on chercherait longtemps du côté du mot de passe.
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
            .expect("déployée");
        let table: std::collections::BTreeMap<&str, &str> =
            env.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();

        assert_eq!(
            table.get("DB_PASSWORD"),
            Some(&"{{ db.password }}"),
            "un jeton irrésolu doit rester visible, jamais devenir vide"
        );
        // Ce qui est connaissable sans coffre l'est quand même : l'hôte ne dépend
        // d'aucun secret, et le taire n'aiderait personne.
        assert_eq!(table.get("DB_HOST"), Some(&"postgres"));
    }

    #[tokio::test]
    async fn a_mailbox_is_never_pretended_without_a_stalwart() {
        // 🔴 Le même principe que pour la base de données : sans client Stalwart,
        // l'action est enregistrée « non implémentée », jamais « faite ». Rapporter
        // une boîte créée qui n'existe pas ferait échouer l'app au premier envoi.
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
            .expect("action présente");
        assert_eq!(mail.status, ActionStatus::Unimplemented);

        // Et aucun mot de passe n'a été fabriqué : il n'aurait correspondu à rien.
        assert!(s.secret("demo-mail-password").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn secrets_need_a_vault_and_are_never_faked() {
        // Sans coffre, la génération de secret est « non implémentée », jamais « faite ».
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
            .expect("secret stocké");
        let clear = vault.decrypt(&ct).expect("déchiffrable");
        assert_eq!(clear.len(), hlb_secrets::DEFAULT_PASSWORD_LEN);
        assert!(clear.chars().all(|c| c.is_ascii_alphanumeric()));

        // Le provisionnement reste non implémenté : pas de PostgreSQL fourni.
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

        // On force un rejeu en effaçant la progression.
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
            "rien déployé avant le guide"
        );

        // Le guide est quand même enregistré : c'est du travail réel à faire.
        assert_eq!(s.pending_guides().await.unwrap().len(), 1);

        // Une fois traité, l'installation repart.
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
