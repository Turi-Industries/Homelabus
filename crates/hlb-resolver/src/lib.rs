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

    #[error("parameter \"{0}\" is required but absent{hint}", hint = hint(.0))]
    MissingParam(&'static str),

    #[error("{app}: {reason}")]
    Unsupported { app: String, reason: String },

    #[error(
        "\"{0}\" is not a time zone the tz database knows: hlb config timezone Europe/Paris \
         (your own zone)"
    )]
    UnknownTimezone(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Where a missing parameter is given, when it is not a flag of the command itself.
fn hint(param: &str) -> &'static str {
    match param {
        "timezone" => ": hlb config timezone Europe/Paris (your own zone)",
        _ => "",
    }
}

/// The values supplied at install time, which cannot live in the manifest because
/// they depend on the installation itself.
#[derive(Debug, Clone)]
pub struct InstallParams {
    /// The full domain chosen by the user, e.g. `git.example.fr`.
    pub domain: Option<String>,
    /// Base mail domain, for `MailAccount` capabilities.
    pub mail_domain: Option<String>,
    /// The installation's time zone (`hlb config timezone`), for `{{ timezone }}`.
    pub timezone: Option<String>,
    pub health_timeout_secs: u64,
}

impl Default for InstallParams {
    fn default() -> Self {
        Self {
            domain: None,
            mail_domain: None,
            timezone: None,
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
/// `hlb-ingress::render_forward_auth`. Both describe the same path seen from two
/// places: if they diverge, sign-in fails on the return leg, and PocketID's message
/// talks about an unregistered URI without saying which one it expected.
pub const PORTAL_CALLBACK: &str = "/oauth2/callback";

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

    // 🔴 Exhaustive on the runtime: nothing deploys `compose`. Ignored, it put Stalwart
    // in the Swarm anyway — without its mail ports, and with its first-run setup page
    // published at its domain, open to whoever reached it first.
    match m.spec.runtime {
        hlb_types::Runtime::Swarm => {}
        hlb_types::Runtime::Compose => {
            return Err(Error::Unsupported {
                app: app.clone(),
                reason: "runtime \"compose\" is not implemented: install it by hand for \
                         now — see the roadmap"
                    .into(),
            })
        }
    }

    // Asked for at preview: Seafile writes its zone into its own settings at its first
    // start and never reads it again, so a zone given after the install changes nothing.
    if m.spec
        .substituted()
        .flat_map(|v| hlb_types::binding::tokens_in(v))
        .any(|t| t == hlb_types::Token::Timezone)
    {
        // A zone stored before the database was consulted may be a misspelling.
        match &params.timezone {
            None => return Err(Error::MissingParam("timezone")),
            Some(z) if !hlb_types::binding::is_time_zone(z) => {
                return Err(Error::UnknownTimezone(z.clone()));
            }
            Some(_) => {}
        }
    }

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
                    table.insert(k.clone(), render_guide(v, &domain_vars(params)));
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
            Capability::Storage {
                name, path, owner, ..
            } => Some((
                format!("{}-{name}", owner.as_deref().unwrap_or(app)),
                path.clone(),
            )),
            _ => None,
        })
        .collect();

    // 4bis. The secrets the service's configuration asks Homelabus to generate,
    // BEFORE the service that reads them — and those a guide's `api` call sends, an
    // administrator's password the app is given once and never reads from its
    // environment.
    let api_bodies = guide
        .steps
        .iter()
        .flat_map(|s| &s.automate)
        .flat_map(|a| match a {
            hlb_types::Automation::Api { calls, .. } => calls
                .iter()
                .filter_map(|c| c.body.as_ref())
                .collect::<Vec<_>>(),
            hlb_types::Automation::Sql { params, .. } => params.iter().collect(),
            hlb_types::Automation::Env { .. } | hlb_types::Automation::Exec { .. } => Vec::new(),
        });
    // Before the companions too: Seafile's notification server reads the app's
    // `{{ secret.jwt-key }}`, and deployed first it would have had the token's text.
    let mut generated: Vec<hlb_types::binding::GeneratedSecret> = m
        .spec
        .substituted()
        .chain(api_bodies)
        .flat_map(|v| hlb_types::binding::generated_secrets(v))
        .filter_map(|r| r.ok())
        .collect();
    generated.sort();
    generated.dedup_by(|a, b| a.name == b.name);
    for g in &generated {
        plan.push(Action::GenerateSecret {
            name: g.vault_name(app),
            purpose: format!("{} of {app}, generated at install", g.name),
        });
    }

    // 4ter. The companions, BEFORE the app.
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
                // A companion carries no application database (no `requires`).
                sqlite: false,
            });
        }

        if !c.image.is_pinned() {
            plan.push(Action::ResolveDigest {
                repo: c.image.repo.clone(),
                tag: c.image.tag.clone(),
            });
        }

        let mut constraints = Vec::new();
        // The companion's tier wins over the app's: a compute service deserves
        // `heavy` even when its app is `light`.
        if let Some(t) = c.tier.as_ref().or(m.spec.swarm.tier.as_ref()) {
            constraints.extend(hlb_types::manifest::tier_constraint(t));
        }
        // Its own label only, never the app's: LiveKit goes where the router forwards
        // its ports, its app wherever there is room.
        if let Some(label) = &c.node_label {
            constraints.push(format!("node.labels.{label}==true"));
        }

        plan.push(Action::DeployService {
            name: service.clone(),
            image: c.image.reference(),
            // A single copy: the type does not allow asking for more.
            replicas: 1,
            constraints,
            env: c.environment(&m.spec).into_iter().collect(),
            mounts: c
                .storage
                .iter()
                .map(|v| (format!("{service}-{}", v.name), v.path.clone()))
                .collect(),
            hardening: c.security.clone(),
            healthcheck: c.healthcheck.clone(),
            files: c
                .files
                .iter()
                .map(|f| (f.path.clone(), f.content.clone()))
                .collect(),
            command: c.command.clone(),
            args: c.args.clone(),
            process: c.process.clone(),
            memory: c.memory,
        });

        // 🔴 We wait for it to be healthy before deploying the app. Without that
        // wait, the plan's order would only guarantee the order of the CALLS to Swarm,
        // not the order of the actual startups.
        plan.push(Action::WaitHealthy {
            name: service,
            timeout_secs: wait_for(c.healthcheck.as_ref(), params),
        });
    }

    // 5. The service itself.
    let mut constraints = Vec::new();
    if let Some(tier) = &m.spec.swarm.tier {
        // Placement follows from the tier, never from a hard-coded node name.
        constraints.extend(hlb_types::manifest::tier_constraint(tier));
    }
    // A label, never a hostname either: the machine is chosen by `hlb`, not by the
    // manifest's author.
    if let Some(label) = &m.spec.swarm.node_label {
        constraints.push(format!("node.labels.{label}==true"));
    }
    // Another app's volume is on its owner's node: anywhere else, Swarm would create
    // an empty one of the same name, and the app would read nothing without a word.
    for c in &m.spec.requires {
        if let Capability::Storage {
            owner: Some(owner), ..
        } = c
        {
            constraints.push(hlb_types::manifest::data_constraint(owner));
        }
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
        files: m
            .spec
            .files
            .iter()
            .map(|f| (f.path.clone(), f.content.clone()))
            .collect(),
        command: m.spec.command.clone(),
        args: m.spec.args.clone(),
        process: m.spec.process.clone(),
        memory: m.spec.swarm.memory,
    });

    // 6. Wait for convergence before handing back.
    plan.push(Action::WaitHealthy {
        name: app.clone(),
        timeout_secs: wait_for(m.spec.swarm.healthcheck.as_ref(), params),
    });

    // 7. The guide's steps, BEFORE any exposure.
    //
    // The order is the protection mechanism itself: it is because these steps come
    // before the ingress that the "first to sign up becomes admin" window stays shut.
    let vars = domain_vars(params);
    for s in &guide.steps {
        plan.push(Action::PendingGuideStep {
            id: s.id.clone(),
            title: render_guide(&s.title, &vars),
            blocking: s.is_blocking(),
            service: app.clone(),
            step: Box::new(s.clone()),
        });
    }

    // An app on `after-guide` with no blocking step declared would be exposed
    // publicly with no guard rail: one is added by default rather than opening up.
    let expose_after_guide = m
        .spec
        .ingress
        .iter()
        .any(|i| i.expose == ExposePolicy::AfterGuide);
    if expose_after_guide && !guide.steps.iter().any(|s| s.is_blocking()) {
        plan.push(Action::PendingGuideStep {
            id: format!("{app}-first-admin"),
            title: format!("Check {app}'s administrator account and close sign-ups"),
            blocking: true,
            service: app.clone(),
            step: Box::new(hlb_types::GuideStep {
                id: format!("{app}-first-admin"),
                title: "Administrator account".into(),
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

    // 8. The exposure, last.
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

/// The variables a guide's templates may use — and nothing else: a name left
/// unrendered reaches Swarm, which reads `{{ … }}` as one of its own templates and
/// refuses the service ("function not defined").
pub const GUIDE_VARS: &[&str] = &["domain", "base_domain"];

/// How long a service is waited for: as long as its own probe gives it — its start
/// period, then every retry —, never less than the installation's default. Fluxer's
/// api migrates its schema before it answers, and was waited for 120 s where its probe
/// allows seven minutes.
fn wait_for(probe: Option<&hlb_types::Healthcheck>, params: &InstallParams) -> u64 {
    probe.map_or(params.health_timeout_secs, |h| {
        params
            .health_timeout_secs
            .max(h.start_period_secs + h.interval_secs * h.retries)
    })
}

/// The variables available when rendering a guide's templates.
///
/// `base_domain` is the app's domain less its first label — `example.org` for
/// `git.example.org` — the zone a wildcard record covers.
fn domain_vars(params: &InstallParams) -> Vec<(&'static str, String)> {
    let Some(d) = &params.domain else {
        return Vec::new();
    };
    // 🔴 An apex domain (`example.org`) is its own zone: left out, `{{ base_domain }}`
    // stayed literal and Swarm refused the service on it.
    let base = match d.split_once('.') {
        Some((_, rest)) if rest.contains('.') => rest,
        _ => d.as_str(),
    };
    vec![("domain", d.clone()), ("base_domain", base.to_string())]
}

fn render_guide(template: &str, vars: &[(&'static str, String)]) -> String {
    let borrowed: Vec<(&str, &str)> = vars.iter().map(|(k, v)| (*k, v.as_str())).collect();
    hlb_types::guide::render(template, &borrowed)
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
            let already = plan
                .actions
                .iter()
                .any(|a| matches!(a, Action::GenerateSecret { name, .. } if name == &secret));
            if !already {
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
            // 🔴 A dedicated cache was deployed from `<engine>:latest`, which no digest
            // pins: the executor refused it as unpinned mid-install, after the app was
            // recorded. Refused here, at preview, before anything is.
            if *dedicated {
                return Err(Error::Unsupported {
                    app: app.to_string(),
                    reason: format!(
                        "a dedicated {} would run an image nothing pins — the shared one \
                         serves every app (`dedicated: false`)",
                        engine.service_name()
                    ),
                });
            }
            // No password: the platform's Valkey runs without one, on the overlay only,
            // and no binding hands one to an app. Generated, it was a secret nothing
            // read, which the rotation screen told people to change.
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

                // The best case: the app speaks OIDC, the URIs come from it.
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
                        purpose: "OIDC client secret".into(),
                    });
                }

                // 🔴 It is the PORTAL that speaks OIDC, not the app — and there is ONE
                // portal, signing in with ONE client: oauth2-proxy's own. The callback
                // is `/oauth2/callback` on the app's domain, since Caddy serves it there
                // (see `render_forward_auth`), and it goes on THAT client. Until
                // 2026-10-14 each app got a client of its own, which oauth2-proxy never
                // used, while PocketID refused the portal's redirect to the app's
                // domain.
                SsoMode::ProxyOnly | SsoMode::ProxyHeader => {
                    let domain = params
                        .domain
                        .as_ref()
                        .ok_or(Error::MissingParam("domain"))?;

                    plan.push(Action::AddPortalCallback {
                        uri: format!("https://{domain}{PORTAL_CALLBACK}"),
                    });
                }
            }
        }

        Capability::ObjectStorage {
            bucket,
            backup: _,
            expire_after_days,
        } => {
            let bucket_name = bucket.clone().unwrap_or_else(|| app.to_string());
            let secret = hlb_types::capability::s3_key_secrets(app).1;

            // The secret BEFORE the bucket that uses it, as for databases — once, for
            // an app's every bucket shares its one key.
            let already = plan
                .actions
                .iter()
                .any(|a| matches!(a, Action::GenerateSecret { name, .. } if name == &secret));
            if !already {
                plan.push(Action::GenerateSecret {
                    name: secret.clone(),
                    purpose: "S3 secret key".into(),
                });
            }
            plan.push(Action::ProvisionBucket {
                bucket: bucket_name,
                // 🔴 One key per app. Sharing the admin key would give every app read
                // access to every other's buckets - Immich's photos readable from the
                // wiki, and the other way round.
                key_name: app.to_string(),
                secret_name: secret,
                expire_after_days: *expire_after_days,
            });
        }

        Capability::Smtp { sender } => match sender {
            hlb_types::SmtpSender::App => {
                let domain = params
                    .mail_domain
                    .as_ref()
                    .ok_or(Error::MissingParam("mail_domain"))?;
                let secret_name = format!("{app}-smtp-password");
                // The password BEFORE the account that holds it, as for databases.
                plan.push(Action::GenerateSecret {
                    name: secret_name.clone(),
                    purpose: "SMTP submission".into(),
                });
                plan.push(Action::ProvisionSmtpAccount {
                    address: format!("{app}@{domain}"),
                    secret_name,
                });
            }
            // Each person sends with their own mailbox's credentials.
            hlb_types::SmtpSender::Person => {}
        },

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

        // Another app's: it exists where its owner put it, and is created there.
        Capability::Storage { owner: Some(_), .. } => {}
        Capability::Storage {
            name,
            path,
            tier,
            backup,
            sqlite,
            owner: None,
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
            mail_domain: Some("home.example".into()),
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

    /// 🔴 The resolver used to generate `<app>-smtp-password` and nothing else: no
    /// account in Stalwart held it, and no app could send.
    #[test]
    fn an_app_sending_mail_gets_an_account_of_its_own_after_its_password() {
        let params = InstallParams {
            mail_domain: Some("home.example".into()),
            ..Default::default()
        };
        let mut plan = Plan::default();
        resolve_capability(
            &Capability::Smtp {
                sender: hlb_types::SmtpSender::App,
            },
            "vikunja",
            &params,
            &mut plan,
        )
        .expect("resolution");
        assert_eq!(
            plan.actions,
            vec![
                Action::GenerateSecret {
                    name: "vikunja-smtp-password".into(),
                    purpose: "SMTP submission".into(),
                },
                Action::ProvisionSmtpAccount {
                    address: "vikunja@home.example".into(),
                    secret_name: "vikunja-smtp-password".into(),
                },
            ]
        );
        assert!(
            plan.actions[1].to_string().contains("vikunja@home.example"),
            "{}",
            plan.actions[1]
        );

        // A webmail sends as the person signed in: nothing to make.
        let mut plan = Plan::default();
        resolve_capability(
            &Capability::Smtp {
                sender: hlb_types::SmtpSender::Person,
            },
            "roundcube",
            &params,
            &mut plan,
        )
        .expect("resolution");
        assert!(plan.actions.is_empty(), "{:?}", plan.actions);

        // No mail domain, no address: refused at preview, never guessed.
        let mut plan = Plan::default();
        let e = resolve_capability(
            &Capability::Smtp {
                sender: hlb_types::SmtpSender::App,
            },
            "vikunja",
            &InstallParams::default(),
            &mut plan,
        )
        .unwrap_err();
        assert!(e.to_string().contains("mail_domain"), "{e}");
    }

    /// A database the app is told about: one it is not is refused by validation.
    const READS_ITS_DATABASE: &str =
        "  requires:\n    - kind: database\n      engine: postgres\n  env:\n    DB: \"{{ db.url }}\"\n";

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
        serde_yaml_ng::from_str(&y).expect("test manifest")
    }

    #[test]
    fn a_light_app_may_land_on_a_heavy_node_and_a_heavy_one_never_on_a_light_node() {
        let deploy = |tier: &str| {
            let plan = resolve(
                &manifest(&format!("  swarm:\n    tier: {tier}\n")),
                &InstallParams::default(),
            )
            .expect("plan");
            plan.actions
                .into_iter()
                .find_map(|a| match a {
                    Action::DeployService { constraints, .. } => Some(constraints),
                    _ => None,
                })
                .expect("a deployment")
        };
        assert!(deploy("light").is_empty(), "{:?}", deploy("light"));
        assert_eq!(deploy("heavy"), vec!["node.labels.tier==heavy".to_string()]);
    }

    #[test]
    fn an_apex_domain_is_its_own_base_domain() {
        let p = InstallParams::with_domain("example.org");
        assert!(domain_vars(&p).contains(&("base_domain", "example.org".to_string())));
        let p = InstallParams::with_domain("speed.example.org");
        assert!(domain_vars(&p).contains(&("base_domain", "example.org".to_string())));
    }

    #[test]
    fn a_dedicated_cache_is_refused_at_preview_and_no_cache_password_is_made() {
        let reads = "  env:\n    CACHE: \"{{ cache.url }}\"\n";
        let shared = manifest(&format!(
            "  requires:\n    - kind: cache\n      engine: valkey\n{reads}"
        ));
        let plan = resolve(&shared, &InstallParams::default()).expect("plan");
        assert!(
            !plan.actions.iter().any(|a| matches!(a,
                Action::GenerateSecret { name, .. } if name.ends_with("-cache-password"))),
            "a password nothing reads: {:?}",
            plan.actions
        );
        let dedicated = manifest(&format!(
            "  requires:\n    - kind: cache\n      engine: valkey\n      dedicated: true\n{reads}"
        ));
        let err = resolve(&dedicated, &InstallParams::default()).expect_err("refused");
        assert!(err.to_string().contains("nothing pins"), "{err}");
    }

    #[test]
    fn a_guide_s_env_gets_the_base_domain_of_the_app_s_own() {
        let guide: hlb_types::Guide = serde_yaml_ng::from_str(
            r#"
steps:
  - id: s
    title: t
    automate:
      - method: env
        vars:
          TITLE: "Throughput — {{ base_domain }}"
"#,
        )
        .expect("guide");
        let plan = resolve_with_guide(
            &manifest(""),
            &guide,
            &InstallParams::with_domain("speed.example.org"),
        )
        .expect("plan");
        let env = plan
            .actions
            .into_iter()
            .find_map(|a| match a {
                Action::DeployService { env, .. } => Some(env),
                _ => None,
            })
            .expect("a deployment");
        assert!(
            env.contains(&("TITLE".to_string(), "Throughput — example.org".to_string())),
            "{env:?}"
        );
    }

    #[test]
    fn a_node_label_reaches_the_placement() {
        let plan = resolve(
            &manifest("  swarm:\n    nodeLabel: hlb.ingress\n"),
            &InstallParams::default(),
        )
        .expect("plan");
        let constraints = plan
            .actions
            .into_iter()
            .find_map(|a| match a {
                Action::DeployService { constraints, .. } => Some(constraints),
                _ => None,
            })
            .expect("a deployment");
        assert_eq!(
            constraints,
            vec!["node.labels.hlb.ingress==true".to_string()]
        );
    }

    #[test]
    fn an_apps_buckets_share_one_key_and_keep_their_expiry() {
        let m = manifest(
            "  requires:\n    - { kind: object-storage, backup: false, bucket: chat }\n    \
             - { kind: object-storage, backup: false, bucket: chat-uploads, expireAfterDays: 1 }\n  \
             env:\n    S3: \"{{ s3.endpoint }}\"\n",
        );
        let p = resolve(&m, &InstallParams::default()).expect("plan");
        let secrets = p
            .actions
            .iter()
            .filter(
                |a| matches!(a, Action::GenerateSecret { name, .. } if name == "gitea-s3-secret"),
            )
            .count();
        assert_eq!(secrets, 1, "{p}");
        let buckets: Vec<(&str, &str, Option<u32>)> = p
            .actions
            .iter()
            .filter_map(|a| match a {
                Action::ProvisionBucket {
                    bucket,
                    key_name,
                    secret_name: _,
                    expire_after_days,
                } => Some((bucket.as_str(), key_name.as_str(), *expire_after_days)),
                _ => None,
            })
            .collect();
        assert_eq!(
            buckets,
            [("chat", "gitea", None), ("chat-uploads", "gitea", Some(1))]
        );
        assert!(p.to_string().contains("deleted after 1 days"), "{p}");
    }

    #[test]
    fn a_service_is_waited_for_as_long_as_its_probe_allows() {
        let m = manifest(
            "  companions:\n    - name: api\n      image: { repo: a/b, tag: \"1\" }\n      \
             healthcheck: { test: [CMD, x], intervalSecs: 10, retries: 30, startPeriodSecs: 120 }\n    \
             - name: quick\n      image: { repo: a/c, tag: \"1\" }\n      \
             healthcheck: { test: [CMD, y], intervalSecs: 1, retries: 1, startPeriodSecs: 1 }\n",
        );
        let p = resolve(&m, &InstallParams::default()).expect("plan");
        let wait = |service: &str| {
            p.actions
                .iter()
                .find_map(|a| match a {
                    Action::WaitHealthy { name, timeout_secs } if name == service => {
                        Some(*timeout_secs)
                    }
                    _ => None,
                })
                .unwrap_or_else(|| panic!("{service} waited for"))
        };
        let default = InstallParams::default().health_timeout_secs;
        assert_eq!(wait("gitea-api"), 120 + 10 * 30);
        assert_eq!(
            wait("gitea-quick"),
            default,
            "never below the installation's"
        );
        assert_eq!(wait("gitea"), default, "no probe declared");
    }

    #[test]
    fn a_companions_node_label_places_it_and_not_its_app() {
        let plan = resolve(
            &manifest(
                "  companions:\n    - name: media\n      image: { repo: a/b, tag: \"1\" }\n      \
                 nodeLabel: hlb.ingress\n",
            ),
            &InstallParams::default(),
        )
        .expect("plan");
        let of = |service: &str| {
            plan.actions
                .iter()
                .find_map(|a| match a {
                    Action::DeployService {
                        name, constraints, ..
                    } if name == service => Some(constraints.clone()),
                    _ => None,
                })
                .unwrap_or_else(|| panic!("{service} deployed"))
        };
        assert_eq!(of("gitea-media"), ["node.labels.hlb.ingress==true"]);
        assert!(of("gitea").is_empty(), "{:?}", of("gitea"));
    }

    #[test]
    fn a_generated_secret_exists_before_the_service_that_reads_it() {
        let m = manifest(
            r#"  env:
    POSTGRES_PASSWORD: "{{ secret.admin-password }}"
    RPC: "{{ secret.rpc:hex }}"
    AGAIN: "{{ secret.admin-password }}"
"#,
        );
        let p = resolve(&m, &InstallParams::default()).expect("plan");
        let generated: Vec<usize> = p
            .actions
            .iter()
            .enumerate()
            .filter(|(_, a)| {
                matches!(a, Action::GenerateSecret { name, .. }
                if name == "gitea-admin-password" || name == "gitea-rpc")
            })
            .map(|(i, _)| i)
            .collect();
        // Once each, however many variables use it.
        assert_eq!(generated.len(), 2);
        let deploy = p
            .actions
            .iter()
            .position(|a| matches!(a, Action::DeployService { name, .. } if name == "gitea"))
            .expect("deploy");
        assert!(generated.iter().all(|g| *g < deploy));
    }

    #[test]
    fn a_secret_a_companion_reads_exists_before_the_companion() {
        let m = manifest(
            r#"  env:
    KEY: "{{ secret.jwt-key }}"
  companions:
    - name: notify
      image: { repo: a/b, tag: "1" }
      env:
        KEY: "{{ secret.jwt-key }}"
        OWN: "{{ secret.own-only }}"
      files:
        - path: /etc/notify.conf
          content: "key = {{ secret.in-a-file }}"
"#,
        );
        let p = resolve(&m, &InstallParams::default()).expect("plan");
        let at = |want: &str| {
            p.actions
                .iter()
                .position(|a| match a {
                    Action::GenerateSecret { name, .. } | Action::DeployService { name, .. } => {
                        name == want
                    }
                    _ => false,
                })
                .unwrap_or_else(|| panic!("{want} in {p}"))
        };
        let companion = at("gitea-notify");
        assert!(at("gitea-jwt-key") < companion, "{p}");
        assert!(at("gitea-own-only") < companion, "{p}");
        assert!(at("gitea-in-a-file") < companion, "{p}");
    }

    #[test]
    fn a_companion_takes_the_shared_variables_beneath_its_own() {
        let m = manifest(
            r#"  sharedEnv:
    MODE: production
    PORT: "1"
  companions:
    - name: api
      image: { repo: a/api, tag: "1" }
      sharedEnv: true
      env: { PORT: "8080" }
    - name: cache
      image: { repo: a/cache, tag: "1" }
"#,
        );
        let p = resolve(&m, &InstallParams::default()).expect("plan");
        let env_of = |service: &str| {
            p.actions
                .iter()
                .find_map(|a| match a {
                    Action::DeployService { name, env, .. } if name == service => Some(env.clone()),
                    _ => None,
                })
                .unwrap_or_else(|| panic!("{service} deployed"))
        };
        assert_eq!(
            env_of("gitea-api"),
            [
                ("MODE".into(), "production".into()),
                ("PORT".into(), "8080".into())
            ]
        );
        assert!(env_of("gitea-cache").is_empty(), "it did not ask for them");
    }

    #[test]
    fn arguments_and_process_reach_the_plan_for_the_app_and_each_companion() {
        let m = manifest(
            r#"  args: [--port, "3000"]
  process: { init: true, stopGraceSecs: 60 }
  companions:
    - name: db
      image: { repo: a/db, tag: "1" }
      args: [-c, tcp_keepalives_idle=300]
      process: { stopSignal: SIGINT, sysctls: { net.core.somaxconn: "1024" } }
"#,
        );
        let p = resolve(&m, &InstallParams::default()).expect("plan");
        let of = |service: &str| {
            p.actions
                .iter()
                .find_map(|a| match a {
                    Action::DeployService {
                        name,
                        args,
                        process,
                        ..
                    } if name == service => Some((args.clone(), process.clone(), a.to_string())),
                    _ => None,
                })
                .unwrap_or_else(|| panic!("{service} deployed"))
        };
        let (args, process, _) = of("gitea");
        assert_eq!(args, ["--port", "3000"]);
        assert_eq!(process, m.spec.process);
        let (args, process, shown) = of("gitea-db");
        assert_eq!(args, ["-c", "tcp_keepalives_idle=300"]);
        assert_eq!(process, m.spec.companions[0].process);
        // What the container's namespace is given, and how it starts, read in the preview.
        assert!(
            shown.contains("arguments -c tcp_keepalives_idle=300"),
            "{shown}"
        );
        assert!(shown.contains("sysctl net.core.somaxconn=1024"), "{shown}");
    }

    #[test]
    fn a_companion_starts_on_its_own_command_and_files() {
        let m = manifest(
            r#"  companions:
    - name: queue
      image: { repo: a/nats, tag: "1" }
      command: [nats-server, -js, -sd, /data]
      files:
        - path: /etc/queue.conf
          content: "token = {{ secret.queue-token }}"
"#,
        );
        let p = resolve(&m, &InstallParams::default()).expect("plan");
        let (command, files) = p
            .actions
            .iter()
            .find_map(|a| match a {
                Action::DeployService {
                    name,
                    command,
                    files,
                    ..
                } if name == "gitea-queue" => Some((command, files)),
                _ => None,
            })
            .expect("the companion is deployed");
        assert_eq!(command, &["nats-server", "-js", "-sd", "/data"]);
        // The token stays literal in the plan: the executor fills it at deployment.
        assert_eq!(
            files,
            &[(
                "/etc/queue.conf".to_string(),
                "token = {{ secret.queue-token }}".to_string()
            )]
        );
    }

    #[test]
    fn a_runtime_nothing_deploys_is_refused_at_preview() {
        let m = manifest("  runtime: compose\n");
        let e = resolve(&m, &InstallParams::default()).expect_err("refused");
        assert!(e.to_string().contains("compose"), "{e}");
    }

    #[test]
    fn database_becomes_isolated_db_plus_secret() {
        let m = manifest(READS_ITS_DATABASE);
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
             redirectPaths: [\"/user/oauth2/pocketid/callback\"]\n  env:\n    ID: \"{{ oidc.client_id }}\"\n",
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
             redirectPaths: [\"/callback\"]\n  env:\n    ID: \"{{ oidc.client_id }}\"\n",
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
            "nor an OIDC secret, which nobody would read: {:?}",
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
            // An app's own paths beside the portal are refused by validation: the
            // portal's callback is the only one.
            let m = manifest(&format!(
                "  requires:\n    - kind: sso\n      mode: {mode}\n"
            ));
            let p = resolve(&m, &InstallParams::with_domain("n8n.example.fr")).expect("plan");

            // ONE portal, ONE client: the app adds its callback to the portal's client,
            // and gets no client of its own that oauth2-proxy would never sign in with.
            assert!(
                uris_oidc(&p).is_none(),
                "mode {mode}: no client of the app's own"
            );
            assert!(
                p.actions.contains(&Action::AddPortalCallback {
                    uri: format!("https://n8n.example.fr{PORTAL_CALLBACK}")
                }),
                "mode {mode}: the portal's callback, never the app's paths"
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
                assert!(!uris.is_empty(), "mode {mode}: client with no redirect URI");
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
            "the error must say what to do: {msg}"
        );
    }

    #[test]
    fn the_password_is_generated_before_the_role_that_uses_it() {
        let m = manifest(READS_ITS_DATABASE);
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
        let m = manifest(READS_ITS_DATABASE);
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

        assert!(db < deploy, "the database must exist before the service");
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
            "steps:\n  - id: x\n    title: \"Point {{ domain }} at the cluster\"\n",
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

        assert!(guide < ingress, "the guide comes before the exposure");
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
    fn a_zone_the_database_does_not_know_is_refused_before_the_install() {
        let m = manifest("  env:\n    TIME_ZONE: \"{{ timezone }}\"\n");
        let with = |z: Option<&str>| InstallParams {
            timezone: z.map(str::to_string),
            ..Default::default()
        };
        assert!(matches!(
            resolve(&m, &with(None)),
            Err(Error::MissingParam("timezone"))
        ));
        assert!(matches!(
            resolve(&m, &with(Some("Europe/Pariss"))),
            Err(Error::UnknownTimezone(z)) if z == "Europe/Pariss"
        ));
        resolve(&m, &with(Some("Europe/Paris"))).expect("a real zone plans");
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
