//! The capability resolver - the heart of the design.
//!
//! A manifest **never** says "connect to postgres:5432". It declares a need:
//! `Capability::Database { engine: Postgres }`. The resolver turns that need into
//! concrete actions.
//!
//! Consequence: the same manifest works whether Postgres is local, on another node,
//! behind PgBouncer or elsewhere. **That is what makes the system genuinely
//! modular.**

pub mod graph;
pub mod plan;

use hlb_types::{Capability, ExposePolicy, Manifest, SsoMode};

pub use graph::{DependencyGraph, GraphError};
pub use plan::{Action, Plan};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Graph(#[from] GraphError),

    #[error(transparent)]
    Manifest(#[from] hlb_types::Error),

    #[error("parameter \"{0}\" is required but absent")]
    MissingParam(&'static str),
}

pub type Result<T> = std::result::Result<T, Error>;

/// The values supplied at install time, which cannot live in the manifest because
/// they depend on the installation itself.
#[derive(Debug, Clone)]
pub struct InstallParams {
    /// Domaine complet choisi par l'utilisateur, ex. `git.example.fr`.
    pub domain: Option<String>,
    /// Base mail domain, for `MailAccount` capabilities.
    pub mail_domain: Option<String>,
    pub health_timeout_secs: u64,
}

impl Default for InstallParams {
    fn default() -> Self {
        Self {
            domain: None,
            mail_domain: None,
            health_timeout_secs: 120,
        }
    }
}

impl InstallParams {
    pub fn with_domain(domain: impl Into<String>) -> Self {
        Self {
            domain: Some(domain.into()),
            ..Default::default()
        }
    }
}

/// The oauth2-proxy callback, served on the app's own domain.
///
/// ⚠️ Must stay aligned with the `handle /oauth2/*` block produced by
/// `hlb-ingress::rendre_forward_auth`. Both describe the same path seen from two
/// places: if they diverge, sign-in fails on the return leg, and PocketID's message
/// talks about an unregistered URI without saying which one it expected.
pub const CALLBACK_PORTAIL: &str = "/oauth2/callback";

/// Translates a manifest plus install parameters into an execution plan.
///
/// The order of actions is not cosmetic: the dependencies (database, secrets, OIDC
/// client) must exist **before** the service consuming them is deployed.
pub fn resolve(m: &Manifest, params: &InstallParams) -> Result<Plan> {
    resolve_with_guide(m, &hlb_types::Guide::default(), params)
}

/// Variant that takes the app's `guide.yaml` into account.
///
/// The declared steps replace the generic guide that used to be hard-coded here: an
/// app now describes its own prerequisites, and the resolver stops guessing.
pub fn resolve_with_guide(
    m: &Manifest,
    guide: &hlb_types::Guide,
    params: &InstallParams,
) -> Result<Plan> {
    hlb_types::validate(m)?;

    let app = &m.metadata.name;
    let mut plan = Plan::default();

    // 1. The prerequisites, capability by capability.
    for cap in &m.spec.requires {
        resolve_capability(cap, app, params, &mut plan)?;
    }

    // 2. The digest, if it is not already pinned.
    if !m.spec.image.is_pinned() {
        plan.push(Action::ResolveDigest {
            repo: m.spec.image.repo.clone(),
            tag: m.spec.image.tag.clone(),
        });
    }

    // 3. The guides' `method: env` automations.
    //
    // ⚠️ Subtlety: unlike `exec` and `api`, an environment variable can NOT be applied
    // after the fact - Swarm recreates the task to pick it up. So the automation ladder
    // is not purely sequential at run time: `env` is resolved HERE, at plan time, while
    // `exec` and `api` run once the service is healthy.
    // 🔴 The manifest's bindings: how the app receives what was provisioned for it.
    // This was the resolver's missing half - creating the database, the role and the
    // password without ever passing them on left the app falling back to its internal
    // SQLite: healthy service, green probe, green dashboard, and the data in a file
    // nobody backed up, while an empty database was faithfully dumped every night.
    //
    // 🔴 SECRET tokens are NOT resolved here. The plan is displayed by `hlb plan`,
    // recorded in the state and exported to the Git mirror: substituting a password
    // into it would publish it in all three places, one of which keeps history.
    // Substitution happens in the executor.
    //
    // ⚠️ `BTreeMap`: the ordering is what makes a plan reproducible from one run to the
    // next, and ordered insertion gives a clear precedence rule - the guide overrides
    // the manifest, because it carries a decision made at install time ("close
    // sign-ups") where the manifest carries a catalog default.
    let mut table: std::collections::BTreeMap<String, String> = m.spec.env.clone();
    for s in &guide.steps {
        for a in &s.automate {
            if let hlb_types::Automation::Env { vars } = a {
                for (k, v) in vars {
                    table.insert(k.clone(), hlb_types::guide::render(v, &domain_vars(params)));
                }
            }
        }
    }
    let env: Vec<(String, String)> = table.into_iter().collect();

    // 4. The volumes to mount, derived from the `storage` capabilities.
    //
    // 🔴 The name must match EXACTLY the one created by `CreateVolume`, or Swarm
    // creates a second empty volume on the fly and the data declared as backed up is
    // not the data the app uses.
    let mounts: Vec<(String, String)> = m
        .spec
        .requires
        .iter()
        .filter_map(|c| match c {
            Capability::Storage { name, path, .. } => Some((format!("{app}-{name}"), path.clone())),
            _ => None,
        })
        .collect();

    // 4bis. The companions, BEFORE the app.
    //
    // 🔴 The order is the mechanism, as for the dependency graph: Swarm has no
    // `depends_on`, and an app starting before its companion crash-loops - or worse,
    // starts degraded without saying so. Immich without its machine-learning service
    // indexes photos and never recognises a face, with nothing indicating that half
    // the feature is missing.
    for c in &m.spec.companions {
        let service = format!("{app}-{}", c.name);

        for v in &c.storage {
            plan.push(Action::CreateVolume {
                name: format!("{service}-{}", v.name),
                path: v.path.clone(),
                // A companion is always local: its volumes hold cache or models, and
                // NFS would only add latency.
                tier: hlb_types::StorageTier::Local,
                backup: v.backup,
                // Un compagnon ne porte pas de base applicative (pas de `requires`).
                sqlite: false,
            });
        }

        if !c.image.is_pinned() {
            plan.push(Action::ResolveDigest {
                repo: c.image.repo.clone(),
                tag: c.image.tag.clone(),
            });
        }

        let mut contraintes = Vec::new();
        // The companion's tier wins over the app's: a compute service deserves
        // `heavy` even when its app is `light`.
        if let Some(t) = c.tier.as_ref().or(m.spec.swarm.tier.as_ref()) {
            contraintes.push(format!("node.labels.tier=={t}"));
        }

        plan.push(Action::DeployService {
            name: service.clone(),
            image: c.image.reference(),
            // Un seul exemplaire : le type ne permet pas d'en demander plus.
            replicas: 1,
            constraints: contraintes,
            env: c.env.clone().into_iter().collect(),
            mounts: c
                .storage
                .iter()
                .map(|v| (format!("{service}-{}", v.name), v.path.clone()))
                .collect(),
            hardening: c.security.clone(),
            healthcheck: c.healthcheck.clone(),
        });

        // 🔴 We wait for it to be healthy before deploying the app. Without that
        // wait, the plan's order would only guarantee the order of the CALLS to Swarm,
        // not the order of the actual startups.
        plan.push(Action::WaitHealthy {
            name: service,
            timeout_secs: params.health_timeout_secs,
        });
    }

    // 5. The service itself.
    let mut constraints = Vec::new();
    if let Some(tier) = &m.spec.swarm.tier {
        // Placement follows from the tier, never from a hard-coded node name.
        constraints.push(format!("node.labels.tier=={tier}"));
    }

    plan.push(Action::DeployService {
        name: app.clone(),
        image: m.spec.image.reference(),
        replicas: m.spec.swarm.replicas,
        constraints,
        env,
        mounts,
        // The manifest's values are passed through to Swarm as they are.
        hardening: m.spec.security.clone(),
        healthcheck: m.spec.swarm.healthcheck.clone(),
    });

    // 6. §4.7 — on attend la convergence avant de rendre la main.
    plan.push(Action::WaitHealthy {
        name: app.clone(),
        timeout_secs: params.health_timeout_secs,
    });

    // 7. The guide's steps, BEFORE any exposure.
    //
    // The order is the protection mechanism itself: it is because these steps come
    // before the ingress that the "first to sign up becomes admin" window stays shut.
    let vars = domain_vars(params);
    for s in &guide.steps {
        plan.push(Action::PendingGuideStep {
            id: s.id.clone(),
            title: hlb_types::guide::render(&s.title, &vars),
            blocking: s.is_blocking(),
            service: app.clone(),
            step: Box::new(s.clone()),
        });
    }

    // An app on `after-guide` with no blocking step declared would be exposed
    // publicly with no guard rail: one is added by default rather than opening up.
    let expose_apres_guide = m
        .spec
        .ingress
        .iter()
        .any(|i| i.expose == ExposePolicy::AfterGuide);
    if expose_apres_guide && !guide.steps.iter().any(|s| s.is_blocking()) {
        plan.push(Action::PendingGuideStep {
            id: format!("{app}-first-admin"),
            title: format!("Check {app}'s administrator account and close sign-ups"),
            blocking: true,
            service: app.clone(),
            step: Box::new(hlb_types::GuideStep {
                id: format!("{app}-first-admin"),
                title: "Compte administrateur".into(),
                phase: hlb_types::Phase::PostInstall,
                severity: hlb_types::Severity::Blocking,
                body: String::new(),
                after: Vec::new(),
                automate: Vec::new(),
                verify: hlb_types::Verify::Attest,
                deeplink: None,
                recheck: None,
            }),
        });
    }

    // 8. L'exposition, en dernier.
    for ing in &m.spec.ingress {
        let host = render_host(&ing.host, params)?;

        plan.push(Action::ConfigureIngress {
            host,
            service: app.clone(),
            port: ing.port,
            chain: ing.chain.clone(),
            public: ing.expose == ExposePolicy::Public,
        });
    }

    Ok(plan)
}

/// Les variables disponibles pour rendre les gabarits d'un guide.
fn domain_vars(params: &InstallParams) -> Vec<(&str, &str)> {
    match &params.domain {
        Some(d) => vec![("domain", d.as_str())],
        None => Vec::new(),
    }
}

fn resolve_capability(
    cap: &Capability,
    app: &str,
    params: &InstallParams,
    plan: &mut Plan,
) -> Result<()> {
    // The `match` is exhaustive: adding a variant to `Capability` breaks compilation
    // here. That is exactly why this project is written in Rust.
    match cap {
        Capability::Database {
            engine,
            name,
            extensions,
        } => {
            let db = name.clone().unwrap_or_else(|| app.to_string());
            let secret = format!("{app}-db-password");

            // ⚠️ Order matters: the password must exist before the role that uses it.
            // The other way round produced a database that could not be created.
            //
            // ⚠️ And exactly once: an app with several databases (Seafile has three)
            // shares ONE role, and therefore ONE password. Three identical generations
            // would clutter the plan and the state without changing anything - the
            // second would be ignored regardless, `store_secret_if_absent` never
            // rewriting.
            let deja = plan
                .actions
                .iter()
                .any(|a| matches!(a, Action::GenerateSecret { name, .. } if name == &secret));
            if !deja {
                plan.push(Action::GenerateSecret {
                    name: secret.clone(),
                    // The role, not the database: the password protects the role.
                    purpose: format!("password for the {app} role"),
                });
            }
            plan.push(Action::ProvisionDatabase {
                engine: *engine,
                database: db.clone(),
                // 🔴 The role is named after the APP, not after the database.
                //
                // An app can have several databases - Seafile wants three - and it
                // connects to them with ONE account. Naming the role after the database
                // would produce three distinct accounts for one credential set, and the
                // app would fail on two of them.
                role: app.to_string(),
                password_secret: secret,
                extensions: extensions.clone(),
            });
        }

        Capability::Cache { engine, dedicated } => {
            if *dedicated {
                plan.push(Action::DeployService {
                    name: format!("{app}-{}", engine.service_name()),
                    image: format!("{}:latest", engine.service_name()),
                    replicas: 1,
                    constraints: Vec::new(),
                    env: Vec::new(),
                    mounts: Vec::new(),
                    // A dedicated cache is hardened like everything else.
                    hardening: hlb_types::SecuritySpec::default(),
                    healthcheck: None,
                });
            }
            plan.push(Action::GenerateSecret {
                name: format!("{app}-cache-password"),
                purpose: "authentification du cache".into(),
            });
        }

        Capability::Sso {
            mode,
            redirect_paths,
        } => {
            // 🔴 The `mode` decides, and it is matched exhaustively. The previous
            // version ignored it (`..`), with two silent consequences: an app in
            // deliberate exclusion still received an OIDC client with EMPTY URIs, and
            // an app behind a portal received a client pointing at itself instead of
            // the portal - an unusable client in both cases, plus a secret created for
            // nothing.
            //
            // A `..` over a field has the same effect as a `_ =>` arm: it silences the
            // compiler exactly where you want it to speak.
            match mode {
                // A deliberate exclusion: the app manages its own accounts, or its
                // protocol is incompatible (TV clients, native apps). Creating an OIDC
                // client here would suggest a protection that does not exist, and the
                // associated secret would never have a reader.
                SsoMode::None => {}

                // Le meilleur cas : l'app parle OIDC, les URI viennent d'elle.
                SsoMode::Native => {
                    // Callback URIs depend on the domain chosen at install time.
                    // Never hard-coded in the manifest.
                    let domain = params
                        .domain
                        .as_ref()
                        .ok_or(Error::MissingParam("domain"))?;

                    plan.push(Action::CreateOidcClient {
                        app: app.to_string(),
                        redirect_uris: redirect_paths
                            .iter()
                            .map(|p| format!("https://{domain}{p}"))
                            .collect(),
                    });
                    plan.push(Action::GenerateSecret {
                        name: format!("{app}-oidc-secret"),
                        purpose: "client secret OIDC".into(),
                    });
                }

                // 🔴 It is the PORTAL that speaks OIDC, not the app. So the callback
                // is oauth2-proxy's - `/oauth2/callback` on the app's domain, since
                // Caddy serves it there (see `rendre_forward_auth`). Registering the
                // app's own paths would produce a client whose redirect PocketID
                // rejects at sign-in time.
                SsoMode::ProxyOnly | SsoMode::ProxyHeader => {
                    let domain = params
                        .domain
                        .as_ref()
                        .ok_or(Error::MissingParam("domain"))?;

                    plan.push(Action::CreateOidcClient {
                        app: app.to_string(),
                        redirect_uris: vec![format!("https://{domain}{CALLBACK_PORTAIL}")],
                    });
                    plan.push(Action::GenerateSecret {
                        name: format!("{app}-oidc-secret"),
                        purpose: "client secret OIDC du portail".into(),
                    });
                }
            }
        }

        Capability::ObjectStorage { bucket, .. } => {
            let compartiment = bucket.clone().unwrap_or_else(|| app.to_string());
            let secret = format!("{app}-s3-secret");

            // Le secret AVANT le compartiment qui l'utilise, comme pour les bases.
            plan.push(Action::GenerateSecret {
                name: secret.clone(),
                purpose: "S3 secret key".into(),
            });
            plan.push(Action::ProvisionBucket {
                bucket: compartiment,
                // 🔴 One key per app. Sharing the admin key would give every app read
                // access to every other's buckets - Immich's photos readable from the
                // wiki, and the other way round.
                key_name: app.to_string(),
                secret_name: secret,
            });
        }

        Capability::Smtp => {
            plan.push(Action::GenerateSecret {
                name: format!("{app}-smtp-password"),
                purpose: "relais SMTP".into(),
            });
        }

        // 🔴 An EXHAUSTIVE pattern, with no `..`. The `..` that used to be here
        // swallowed `quota_bytes`, exactly as it had swallowed `mode` on
        // `Capability::Sso` - a `..` has the same effect as a `_ =>` arm, and the
        // compiler cannot say a thing about it.
        Capability::MailAccount {
            aliases,
            quota_bytes,
        } => {
            let domain = params
                .mail_domain
                .as_ref()
                .ok_or(Error::MissingParam("mail_domain"))?;
            plan.push(Action::ProvisionMailAccount {
                address: format!("{app}@{domain}"),
                aliases: *aliases,
                quota_bytes: *quota_bytes,
            });
        }

        Capability::Storage {
            name,
            path,
            tier,
            backup,
            sqlite,
        } => {
            plan.push(Action::CreateVolume {
                name: format!("{app}-{name}"),
                path: path.clone(),
                tier: *tier,
                backup: *backup,
                sqlite: *sqlite,
            });
        }
    }
    Ok(())
}

/// Replaces `{{ domain }}` with the value supplied at install time.
///
/// Deliberately minimal: this is only a substitution that can be checked.
fn render_host(tpl: &str, params: &InstallParams) -> Result<String> {
    if !tpl.contains("{{") {
        return Ok(tpl.to_string());
    }
    let domain = params
        .domain
        .as_ref()
        .ok_or(Error::MissingParam("domain"))?;
    Ok(tpl
        .replace("{{ domain }}", domain)
        .replace("{{domain}}", domain))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_declared_mailbox_quota_reaches_the_plan() {
        // 🔴 The `..` that used to be in this pattern swallowed `quota_bytes`: a
        // quota declared in the manifest never reached the plan, and the mailbox was
        // created without it. Same defect as on `Capability::Sso { mode }`, and the
        // compiler could say nothing about it - a `..` has the same effect as a
        // `_ =>` arm.
        let mut plan = Plan::default();
        let params = InstallParams {
            mail_domain: Some("turi.fr".into()),
            ..Default::default()
        };
        resolve_capability(
            &Capability::MailAccount {
                quota_bytes: Some(5_000_000),
                aliases: true,
            },
            "wiki",
            &params,
            &mut plan,
        )
        .expect("resolution");

        let a = plan
            .actions
            .iter()
            .find(|a| matches!(a, Action::ProvisionMailAccount { .. }))
            .expect("a mailbox action");
        match a {
            Action::ProvisionMailAccount {
                quota_bytes,
                aliases,
                ..
            } => {
                assert_eq!(
                    *quota_bytes,
                    Some(5_000_000),
                    "the quota was swallowed on the way"
                );
                assert!(*aliases);
            }
            _ => unreachable!(),
        }
        // And it must be VISIBLE in the preview: a quota we cannot set must show up
        // before installation, not be discovered in use.
        assert!(a.to_string().contains("NOT ENFORCED"), "{a}");
    }

    /// Ingress on `after-guide`. As a raw string: a Rust line-continuation `\` eats
    /// the newline AND the indentation, breaking the YAML confusingly.
    const AFTER_GUIDE: &str = r#"  ingress:
    - host: git.example.fr
      port: 3000
      expose: after-guide
"#;

    fn manifest(extra: &str) -> Manifest {
        let y = format!(
            "apiVersion: hlb/v1\nkind: App\nmetadata: {{ name: gitea }}\n\
             spec:\n  image: {{ repo: gitea/gitea, tag: \"1.24\", digest: \"sha256:abc\" }}\n{extra}"
        );
        serde_yaml_ng::from_str(&y).expect("manifest de test")
    }

    #[test]
    fn database_becomes_isolated_db_plus_secret() {
        let m = manifest("  requires:\n    - kind: database\n      engine: postgres\n");
        let p = resolve(&m, &InstallParams::default()).expect("plan");

        assert!(p.actions.contains(&Action::ProvisionDatabase {
            engine: hlb_types::DbEngine::Postgres,
            database: "gitea".into(),
            role: "gitea".into(),
            password_secret: "gitea-db-password".into(),
            extensions: Vec::new(),
        }));
        // One role per app, never a reused password.
        assert!(p.actions.iter().any(
            |a| matches!(a, Action::GenerateSecret { name, .. } if name == "gitea-db-password")
        ));
    }

    #[test]
    fn redirect_uris_are_built_from_the_chosen_domain() {
        let m = manifest(
            "  requires:\n    - kind: sso\n      mode: native\n      \
             redirectPaths: [\"/user/oauth2/pocketid/callback\"]\n",
        );
        let p = resolve(&m, &InstallParams::with_domain("git.example.fr")).expect("plan");

        let uris = p
            .actions
            .iter()
            .find_map(|a| match a {
                Action::CreateOidcClient { redirect_uris, .. } => Some(redirect_uris.clone()),
                _ => None,
            })
            .expect("OIDC client planned");

        assert_eq!(
            uris,
            vec!["https://git.example.fr/user/oauth2/pocketid/callback"]
        );
    }

    #[test]
    fn sso_without_domain_fails_early() {
        let m = manifest(
            "  requires:\n    - kind: sso\n      mode: native\n      \
             redirectPaths: [\"/callback\"]\n",
        );
        let err = resolve(&m, &InstallParams::default()).unwrap_err();
        assert!(matches!(err, Error::MissingParam("domain")), "{err}");
    }

    /// The redirect URIs of the planned OIDC client, if there is one.
    fn uris_oidc(p: &Plan) -> Option<Vec<String>> {
        p.actions.iter().find_map(|a| match a {
            Action::CreateOidcClient { redirect_uris, .. } => Some(redirect_uris.clone()),
            _ => None,
        })
    }

    #[test]
    fn a_deliberate_sso_exclusion_creates_nothing() {
        // 🔴 Found while adding Jellyfin: `mode: none` still produced an OIDC client,
        // with EMPTY redirect URIs, plus a secret nobody would ever read. `mode` was
        // ignored by a `..` - same effect as a `_ =>` arm: silencing the compiler
        // exactly where you want it to speak.
        //
        // `none` is a DELIBERATE exclusion (TV clients that cannot follow a redirect,
        // apps with their own accounts). Creating a client would suggest a protection
        // that does not exist.
        let m = manifest("  requires:\n    - kind: sso\n      mode: none\n");
        let p = resolve(&m, &InstallParams::with_domain("media.example.fr")).expect("plan");

        assert!(uris_oidc(&p).is_none(), "no OIDC client must be created");
        assert!(
            !p.actions.iter().any(|a| matches!(
                a,
                Action::GenerateSecret { name, .. } if name.ends_with("-oidc-secret")
            )),
            "ni secret OIDC, que personne ne lirait : {:?}",
            p.actions
        );
    }

    #[test]
    fn a_deliberate_exclusion_does_not_even_need_a_domain() {
        // Corollary: with no client to create, the domain is no longer required.
        // Requiring a parameter for a capability that provisions nothing would be a
        // false blocker.
        let m = manifest("  requires:\n    - kind: sso\n      mode: none\n");
        resolve(&m, &InstallParams::default()).expect("no domain is needed");
    }

    #[test]
    fn a_portal_backed_app_registers_the_portal_callback() {
        // 🔴 Behind a portal it is oauth2-proxy that speaks OIDC, not the app. A
        // client registered on the app's own paths would produce a redirect PocketID
        // refuses at sign-in - the failure happens on the RETURN leg, on a message
        // that does not say which URI was expected.
        for mode in ["proxy-only", "proxy-header"] {
            let m = manifest(&format!(
                "  requires:\n    - kind: sso\n      mode: {mode}\n      \
                 redirectPaths: [\"/rest/oauth2-credential/callback\"]\n"
            ));
            let p = resolve(&m, &InstallParams::with_domain("n8n.example.fr")).expect("plan");

            assert_eq!(
                uris_oidc(&p).expect("client OIDC"),
                vec![format!("https://n8n.example.fr{CALLBACK_PORTAIL}")],
                "mode {mode} : les chemins de l'app ne s'appliquent pas au portail"
            );
        }
    }

    #[test]
    fn an_oidc_client_is_never_created_without_a_redirect_uri() {
        // A client with no URI is unusable: PocketID has nothing to send the user
        // back to. Whatever the mode, either nothing is created or a complete client
        // is - never half a client.
        for mode in ["none", "proxy-only", "proxy-header"] {
            let m = manifest(&format!(
                "  requires:\n    - kind: sso\n      mode: {mode}\n"
            ));
            let p = resolve(&m, &InstallParams::with_domain("app.example.fr")).expect("plan");

            if let Some(uris) = uris_oidc(&p) {
                assert!(
                    !uris.is_empty(),
                    "mode {mode} : client sans URI de redirection"
                );
            }
        }

        // 🔴 `native` is the case that can NOT work it out alone: with no declared
        // path, nobody knows where to send the user back. Found by this very test,
        // which failed on that mode. So the manifest is refused at validation rather
        // than planning an unusable client.
        let m = manifest("  requires:\n    - kind: sso\n      mode: native\n");
        let e = resolve(&m, &InstallParams::with_domain("app.example.fr"))
            .expect_err("a native without redirectPaths must be refused");
        let msg = e.to_string();
        assert!(msg.contains("redirectPaths"), "{msg}");
        assert!(
            msg.contains("proxy-only"),
            "l'erreur doit dire quoi faire : {msg}"
        );
    }

    #[test]
    fn the_password_is_generated_before_the_role_that_uses_it() {
        let m = manifest("  requires:\n    - kind: database\n      engine: postgres\n");
        let p = resolve(&m, &InstallParams::default()).expect("plan");

        let secret = p
            .actions
            .iter()
            .position(|a| matches!(a, Action::GenerateSecret { .. }))
            .expect("secret planned");
        let db = p
            .actions
            .iter()
            .position(|a| matches!(a, Action::ProvisionDatabase { .. }))
            .expect("database planned");

        assert!(secret < db, "without a password the role cannot be created");
    }

    #[test]
    fn dependencies_come_before_the_service() {
        let m = manifest("  requires:\n    - kind: database\n      engine: postgres\n");
        let p = resolve(&m, &InstallParams::default()).expect("plan");

        let db = p
            .actions
            .iter()
            .position(|a| matches!(a, Action::ProvisionDatabase { .. }))
            .expect("database planned");
        let deploy = p
            .actions
            .iter()
            .position(|a| matches!(a, Action::DeployService { .. }))
            .expect("deployment planned");

        assert!(db < deploy, "la base doit exister avant le service");
    }

    #[test]
    fn a_declared_guide_step_becomes_a_blocking_action() {
        // The steps now come from the app's `guide.yaml`.
        let m = manifest("  ingress:\n    - host: git.example.fr\n      port: 3000\n");
        let g: hlb_types::Guide = serde_yaml_ng::from_str(
            "steps:\n  - id: dns\n    title: Create the DNS record\n    severity: blocking\n",
        )
        .expect("guide");

        let p = resolve_with_guide(&m, &g, &InstallParams::default()).expect("plan");
        assert_eq!(p.blocking_steps().len(), 1);
        assert!(p
            .actions
            .iter()
            .any(|a| matches!(a, Action::PendingGuideStep { id, .. } if id == "dns")));
    }

    #[test]
    fn guide_titles_are_rendered_with_the_domain() {
        let m = manifest("");
        let g: hlb_types::Guide = serde_yaml_ng::from_str(
            "steps:\n  - id: x\n    title: \"Pointer {{ domain }} vers le cluster\"\n",
        )
        .expect("guide");

        let p = resolve_with_guide(&m, &g, &InstallParams::with_domain("git.example.fr"))
            .expect("plan");
        assert!(p
            .actions
            .iter()
            .any(|a| a.to_string().contains("git.example.fr")));
    }

    #[test]
    fn after_guide_without_any_blocking_step_still_gets_a_guard() {
        // 🔴 Otherwise an app on `after-guide` with no declared guide would be
        // exposed publicly with no guard rail at all.
        let m = manifest(AFTER_GUIDE);
        let p = resolve_with_guide(&m, &hlb_types::Guide::default(), &InstallParams::default())
            .expect("plan");
        assert_eq!(
            p.blocking_steps().len(),
            1,
            "a default guard rail is expected"
        );
    }

    #[test]
    fn after_guide_blocks_before_exposing() {
        let m = manifest(
            "  ingress:\n    - host: \"{{ domain }}\"\n      port: 3000\n      \
             expose: after-guide\n",
        );
        let g: hlb_types::Guide = serde_yaml_ng::from_str(
            "steps:\n  - id: admin\n    title: Create the admin\n    severity: blocking\n",
        )
        .expect("guide");
        let p = resolve_with_guide(&m, &g, &InstallParams::with_domain("git.example.fr"))
            .expect("plan");

        let guide = p
            .actions
            .iter()
            .position(|a| matches!(a, Action::PendingGuideStep { blocking: true, .. }))
            .expect("blocking guide step");
        let ingress = p
            .actions
            .iter()
            .position(|a| matches!(a, Action::ConfigureIngress { .. }))
            .expect("ingress planned");

        assert!(guide < ingress, "le guide passe avant l'exposition");
        assert_eq!(p.blocking_steps().len(), 1);
    }

    #[test]
    fn private_is_the_default_exposure() {
        let m = manifest("  ingress:\n    - host: git.example.fr\n      port: 3000\n");
        let p = resolve(&m, &InstallParams::default()).expect("plan");
        assert!(p
            .actions
            .iter()
            .any(|a| matches!(a, Action::ConfigureIngress { public: false, .. })));
    }

    #[test]
    fn tier_becomes_a_placement_constraint() {
        let m = manifest("  swarm:\n    replicas: 2\n    tier: heavy\n");
        let p = resolve(&m, &InstallParams::default()).expect("plan");
        assert!(p.actions.iter().any(|a| matches!(
            a,
            Action::DeployService { constraints, replicas: 2, .. }
                if constraints == &["node.labels.tier==heavy"]
        )));
    }

    #[test]
    fn wait_healthy_follows_every_deploy() {
        let m = manifest("");
        let p = resolve(&m, &InstallParams::default()).expect("plan");
        let deploy = p
            .actions
            .iter()
            .position(|a| matches!(a, Action::DeployService { .. }))
            .expect("deployment");
        assert!(matches!(
            p.actions.get(deploy + 1),
            Some(Action::WaitHealthy { .. })
        ));
    }

    #[test]
    fn invalid_manifest_is_refused_before_planning() {
        let y = "apiVersion: hlb/v1\nkind: App\nmetadata: { name: x }\n\
                 spec:\n  image: { repo: a/b, tag: \"1\" }\n  update: { channel: latest }\n";
        let m: Manifest = serde_yaml_ng::from_str(y).unwrap();
        assert!(matches!(
            resolve(&m, &InstallParams::default()),
            Err(Error::Manifest(_))
        ));
    }

    #[test]
    fn unpinned_image_gets_a_digest_resolution_step() {
        let y = "apiVersion: hlb/v1\nkind: App\nmetadata: { name: gitea }\n\
                 spec:\n  image: { repo: gitea/gitea, tag: \"1.24\" }\n";
        let m: Manifest = serde_yaml_ng::from_str(y).unwrap();
        let p = resolve(&m, &InstallParams::default()).expect("plan");

        let resolve_pos = p
            .actions
            .iter()
            .position(|a| matches!(a, Action::ResolveDigest { .. }))
            .expect("digest resolution planned");
        let deploy = p
            .actions
            .iter()
            .position(|a| matches!(a, Action::DeployService { .. }))
            .expect("deployment");
        assert!(
            resolve_pos < deploy,
            "the digest is resolved before the deployment"
        );
    }
}
