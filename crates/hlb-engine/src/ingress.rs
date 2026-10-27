//! Publishing the routes: the Caddyfile generated from every installed manifest, handed
//! to the `caddy` service as a file.
//!
//! One path for the executor (an install, an upgrade, the ingress's own deployment), for
//! `hlb ingress`, and for the controller: three copies of "which routes, which TLS,
//! which credentials" would drift, and the one used least would be the one publishing
//! an app without its portal.
//!
//! 🔴 Never through Caddy's admin API. It has no authentication: listening on the
//! overlay, it would have taken a configuration from any app — routing every other
//! app's traffic, sign-ins included, through itself. The admin API listens inside the
//! container only.
//!
//! The file lives in Caddy's own `config` volume, which Caddy watches: a one-off job on
//! its node has the new file checked by `caddy validate` — the same binary — and moves
//! it into place in one rename. Caddy reloads it without dropping a connection; a file
//! it would refuse never reaches it. (Delivered as a Swarm secret, each change was a new
//! secret, so a new task: Caddy stopped, for a few seconds, at every install.)

use hlb_ingress::{Config, Route, Tls, Wildcard};
use hlb_orchestrator::{Orchestrator, ServiceSpec, UpdateState};
use hlb_secrets::Vault;
use hlb_state::{Certificates, Exposure, State};
use hlb_types::manifest::INGRESS_SERVICE;

/// The file Caddy runs and watches, in its `config` volume.
pub const CADDYFILE: &str = "/config/hlb/Caddyfile";

/// The ingress's `config` volume, as its manifest's storage names it.
const CONFIG_VOLUME: &str = "caddy-config";

/// Its `logs` volume, which CrowdSec reads.
const LOGS_VOLUME: &str = "caddy-logs";

/// The one-off service that writes the file on the ingress's node.
const WRITER: &str = "hlb-caddyfile";

/// How Caddy is started: on the file in its volume, reloading it when it changes.
pub fn command() -> Vec<String> {
    [
        "caddy",
        "run",
        "--config",
        CADDYFILE,
        "--adapter",
        "caddyfile",
        "--watch",
    ]
    .map(String::from)
    .to_vec()
}

/// The controller's service and port, as `hlb fleet controller` deploys it.
pub const CONTROLLER_SERVICE: &str = "hlb-controller";
pub const CONTROLLER_PORT: u16 = 8420;

/// The action kind a route is recorded under, as the executor names it.
const ROUTE_ACTION: &str = "ConfigureIngress";

/// What a publication found to do.
#[derive(Debug)]
pub enum Published {
    /// `hlb config exposure` was never run: no domain, no certificate source. Nothing
    /// is published rather than guessed — a guessed domain is one the house may not own.
    NotConfigured,
    /// The `caddy` service is not deployed yet. Its own deployment publishes every
    /// route there is.
    NoIngress,
    /// Caddy serves `routes`. `restarted`: its names on the overlay changed, which
    /// only a new task carries — a new route alone restarts nothing.
    Done { routes: Vec<Route>, restarted: bool },
}

/// Every route there is to publish: the installed apps', and the interface's once the
/// controller runs as a service.
pub async fn routes<O: Orchestrator + ?Sized>(
    orch: &O,
    state: &State,
    exposure: Option<&Exposure>,
) -> crate::Result<Vec<Route>> {
    let mut routes = Vec::new();
    // Behind the portal, each route lets in the groups of the roles its app allows —
    // computed by the same rule as every native client's restriction.
    let portal = crate::roles::portal_groups(state).await?;
    for (name, status) in state.installed_apps().await? {
        if status == "failed" {
            continue;
        }
        // The FROZEN manifest, not today's catalog: the deployed state is what counts.
        let m = state.app_manifest(&name).await?;
        let domain = state.app_domain(&name).await?;
        // The route only opens once the blocking actions are handled.
        let cleared = state.unverified_blocking(&name).await? == 0;
        let groups = portal.get(&name).cloned().unwrap_or_default();
        routes.extend(
            hlb_ingress::routes_from_manifest(&m, domain.as_deref(), cleared)
                .into_iter()
                .map(|mut r| {
                    if r.needs_forward_auth {
                        r.allowed_groups = groups.clone();
                    }
                    r
                }),
        );
    }
    // A manifest frozen before validation refused Anubis without an Anubis: its route
    // would be a 502 for everyone, published as if it served. Withheld, and said — the
    // catalog's manifest reaches it through `hlb upgrade`.
    if routes.iter().any(|r| r.through_anubis)
        && matches!(
            orch.status("anubis").await,
            Err(hlb_orchestrator::Error::NotFound(_))
        )
    {
        routes.retain(|r| {
            if r.through_anubis {
                tracing::warn!(
                    app = %r.service,
                    host = %r.host,
                    "its route goes through Anubis, which is not installed: NOT published \
                     — hlb upgrade {}",
                    r.service
                );
            }
            !r.through_anubis
        });
    }
    // Public: invitations are opened from outside, and the interface has its own
    // sign-in. A route to a controller that does not run would be a 502 announced as
    // published.
    if let Some(e) = exposure {
        if orch.status(CONTROLLER_SERVICE).await.is_ok() {
            let mut r = Route::new(e.controller_host(), CONTROLLER_SERVICE, CONTROLLER_PORT);
            r.public = true;
            routes.push(r);
        }
    }
    Ok(routes)
}

/// A DNS provider's credentials from the vault, in its fields' order — what the
/// wildcard certificate is obtained with, and what Stalwart publishes DKIM with.
pub async fn dns_credentials(
    state: &State,
    vault: Option<&Vault>,
    provider: &hlb_ingress::dns::Provider,
) -> crate::Result<Vec<String>> {
    let mut credentials = Vec::new();
    for f in provider.fields {
        let secret = provider.secret_name(f);
        let stored = match (vault, state.secret(&secret).await?) {
            (Some(v), Some(ct)) => Some(v.decrypt(&ct)?),
            _ => None,
        };
        match (stored, f.default) {
            (Some(v), _) => credentials.push(v),
            (None, Some(d)) => credentials.push(d.to_string()),
            (None, None) => {
                return Err(crate::Error::Exposure(format!(
                    "{secret} is not in the vault — without it the wildcard cannot be \
                     obtained: hlb secret-set {secret} --purpose dns"
                )))
            }
        }
    }
    Ok(credentials)
}

/// The TLS, the portal and the bouncer, with the credentials from the vault.
///
/// 🔴 CrowdSec is enabled ONLY when its bouncer key is in the vault. Without it, the
/// Caddyfile carries no bouncer rather than one with an empty key: the latter would
/// start normally and silently block nothing. `crowdsec_runs` is whether its service
/// exists; its address is the state's, never a caller's — a caller passing none
/// dropped the bouncer from every route at the next role change.
pub async fn config(
    state: &State,
    vault: Option<&Vault>,
    exposure: Option<&Exposure>,
    routes: &[Route],
    crowdsec_runs: bool,
) -> crate::Result<Config> {
    let mut cfg = Config::default();

    // The portal only appears when it serves something: declared with no app behind
    // it, it would be a dead block.
    if routes.iter().any(|r| r.needs_forward_auth) {
        cfg.forward_auth = Some(hlb_ingress::caddyfile::ForwardAuth::default());
    }

    let read = |name: String| async move {
        match (vault, state.secret(&name).await?) {
            (Some(v), Some(ct)) => Ok::<_, crate::Error>(Some(v.decrypt(&ct)?)),
            _ => Ok(None),
        }
    };

    if let Some(e) = exposure {
        cfg.tls = match e.certificates {
            Certificates::Internal => Tls::Internal {
                own_root: match vault {
                    Some(v) => root(state, v).await?.is_some(),
                    None => false,
                },
            },
            Certificates::Acme => {
                let wildcard = match &e.dns_provider {
                    None => None,
                    Some(name) => {
                        let provider = hlb_ingress::dns::provider(name).ok_or_else(|| {
                            crate::Error::Exposure(format!(
                                "DNS provider \"{name}\" is not built into the ingress — \
                                 one of {}",
                                hlb_ingress::dns::names().join(", ")
                            ))
                        })?;
                        let credentials = dns_credentials(state, vault, provider).await?;
                        Some(Wildcard {
                            provider,
                            credentials,
                            base_domain: e.domain.clone(),
                        })
                    }
                };
                Tls::Acme {
                    email: e.acme_email.clone().ok_or_else(|| {
                        crate::Error::Exposure(
                            "no ACME address: hlb config exposure --email <address>".into(),
                        )
                    })?,
                    wildcard,
                    staging: e.staging,
                    ca: e.acme_ca.clone(),
                    ca_root: e.acme_ca_root.is_some(),
                }
            }
        };
    }

    if crowdsec_runs {
        match read(hlb_ingress::crowdsec::SECRET_NAME.to_string()).await? {
            Some(key) if hlb_ingress::crowdsec::looks_like_key(&key) => {
                let api_url = match state.crowdsec_url().await? {
                    Some(url) => url,
                    None => hlb_ingress::crowdsec::DEFAULT_URL.to_string(),
                };
                cfg.crowdsec = Some(hlb_ingress::CrowdSec {
                    api_url,
                    api_key: key,
                });
            }
            // A damaged key must not produce a silent bouncer.
            Some(_) => tracing::error!(
                "🔴 invalid CrowdSec bouncer key in the vault - filtering DISABLED; \
                 re-enrol with `hlb crowdsec enroll --apply`"
            ),
            None => tracing::debug!("CrowdSec is not enrolled: traffic is not filtered"),
        }
    }
    Ok(cfg)
}

/// The Caddyfile and the names Caddy answers to, for every route there is.
pub async fn render<O: Orchestrator + ?Sized>(
    orch: &O,
    state: &State,
    vault: Option<&Vault>,
) -> crate::Result<Rendered> {
    let exposure = state.exposure().await?;
    let routes = routes(orch, state, exposure.as_ref()).await?;
    // 🔴 The bouncer only where CrowdSec runs: a key left in the vault after its
    // removal would point every request at an API that does not answer.
    let crowdsec_runs = orch.status(hlb_ingress::crowdsec::SERVICE).await.is_ok();
    let config = config(state, vault, exposure.as_ref(), &routes, crowdsec_runs).await?;
    // What the Caddyfile names beside it: the roots it signs under or trusts.
    let mut files = Vec::new();
    if let (Tls::Internal { own_root: true }, Some(v)) = (&config.tls, vault) {
        if let Some((cert, key)) = root(state, v).await? {
            files.push((hlb_ingress::caddyfile::ROOT_CERT.to_string(), cert));
            files.push((hlb_ingress::caddyfile::ROOT_KEY.to_string(), key));
        }
    }
    if let Some(pem) = exposure.as_ref().and_then(|e| e.acme_ca_root.clone()) {
        files.push((hlb_ingress::caddyfile::ACME_ROOT.to_string(), pem));
    }
    Ok(Rendered {
        caddyfile: hlb_ingress::render(&routes, &config),
        routes,
        config,
        files,
    })
}

/// A publication, before it is handed to Caddy.
#[derive(Debug)]
pub struct Rendered {
    pub caddyfile: String,
    pub routes: Vec<Route>,
    pub config: Config,
    /// `(path in Caddy's volume, content)` for what the Caddyfile names.
    pub files: Vec<(String, String)>,
}

/// Where Homelabus's own root for the internal authority is kept: `{"cert", "key"}`.
pub const ROOT_SECRET: &str = "ingress-root";

/// Homelabus's own root, once `hlb config exposure --internal` generated it.
pub async fn root(state: &State, vault: &Vault) -> crate::Result<Option<(String, String)>> {
    let Some(ct) = state.secret(ROOT_SECRET).await? else {
        return Ok(None);
    };
    let j: serde_json::Value = serde_json::from_str(&vault.decrypt(&ct)?)
        .map_err(|e| crate::Error::Exposure(format!("{ROOT_SECRET} is unreadable: {e}")))?;
    let field = |k: &str| j[k].as_str().map(str::to_string);
    Ok(field("cert").zip(field("key")))
}

/// The root a client inside the house must trust to verify the ingress's certificates,
/// when no public authority signed them — the controller verifying PocketID's issuer.
pub async fn trusted_root(state: &State, vault: Option<&Vault>) -> Option<String> {
    let e = state.exposure().await.ok().flatten()?;
    match e.certificates {
        Certificates::Internal => root(state, vault?).await.ok().flatten().map(|(c, _)| c),
        Certificates::Acme => e.acme_ca_root,
    }
}

/// The names Caddy answers to on the overlay: the identity provider's, so an app or
/// the controller reaching `id.example.org` from inside the house meets Caddy itself
/// rather than a router's hairpin NAT, which many drop.
///
/// Only that one: a name is part of the task, and every route added would otherwise
/// restart Caddy. The other public names are not called from inside.
pub async fn aliases(state: &State) -> crate::Result<Vec<String>> {
    Ok(state.app_domain("pocket-id").await?.into_iter().collect())
}

/// Has `caddyfile` checked by the ingress's own binary, on its node, and moved into
/// the file Caddy watches. Refused, nothing changes.
pub async fn write<O: Orchestrator + ?Sized>(
    orch: &O,
    image: &str,
    rendered: &Rendered,
) -> crate::Result<()> {
    const STAGED: &str = "/run/hlb/Caddyfile";
    // The files it names go first: `validate` loads a root from its path.
    // 🔴 The access log exists before anything reads it: CrowdSec, started on a log
    // Caddy had not written yet, found no file for its pattern and never looked again —
    // it read nothing, and banned nobody.
    let mut script = format!(
        "set -e; mkdir -p /config/hlb; touch {}; ",
        hlb_ingress::caddyfile::ACCESS_LOG
    );
    let mut job = ServiceSpec::new(WRITER, image)
        .job()
        .constraint(format!(
            "node.labels.{}==true",
            hlb_types::manifest::INGRESS_NODE_LABEL
        ))
        .mount(CONFIG_VOLUME, "/config")
        .mount(LOGS_VOLUME, "/var/log/caddy")
        .file(STAGED, rendered.caddyfile.as_str());
    for (i, (dest, content)) in rendered.files.iter().enumerate() {
        let staged = format!("/run/hlb/file-{i}");
        script.push_str(&format!(
            "cp {staged} {dest}.next && mv {dest}.next {dest}; "
        ));
        job = job.file(staged, content.as_str());
    }
    script.push_str(&format!(
        "caddy validate --config {STAGED} --adapter caddyfile; \
         cp {STAGED} /config/hlb/.next && mv /config/hlb/.next {CADDYFILE}"
    ));
    job = job.command(["sh".to_string(), "-c".to_string(), script]);
    // The image's binary carries the capability to bind below 1024: without it in the
    // bounding set the kernel refuses to execute it at all. `validate` writes its
    // throwaway state into the container.
    job.hardening.cap_add = vec!["NET_BIND_SERVICE".into()];
    job.hardening.read_only_rootfs = false;
    let out = orch.run_job(&job, 180).await?;
    if !out.succeeded {
        return Err(crate::Error::Exposure(format!(
            "Caddy refused the new configuration — the one it serves is unchanged: {}",
            out.output.join(" | ")
        )));
    }
    Ok(())
}

/// Publishes every route on the running ingress.
pub async fn publish<O: Orchestrator + ?Sized>(
    orch: &O,
    state: &State,
    vault: Option<&Vault>,
) -> crate::Result<Published> {
    if state.exposure().await?.is_none() {
        return Ok(Published::NotConfigured);
    }
    let running = match orch.status(INGRESS_SERVICE).await {
        Ok(s) => s,
        Err(hlb_orchestrator::Error::NotFound(_)) => return Ok(Published::NoIngress),
        Err(e) => return Err(e.into()),
    };
    let rendered = render(orch, state, vault).await?;
    write(orch, &running.image, &rendered).await?;
    let routes = rendered.routes;
    let restarted = orch
        .reconfigure(INGRESS_SERVICE, &[], &aliases(state).await?)
        .await?;
    if restarted {
        settle(orch).await?;
    }
    published(state, &routes).await?;
    Ok(Published::Done { routes, restarted })
}

/// Records what Caddy now serves: the exposure screen compares it to what the manifests
/// ask for, and an app installed before the ingress stops waiting for its route.
///
/// 🔴 AFTER Caddy took the file, never before: recording first would describe a
/// configuration a rolled-back update left unapplied.
pub async fn published(state: &State, routes: &[Route]) -> crate::Result<()> {
    let served: Vec<(String, String, bool)> = routes
        .iter()
        .map(|r| (r.host.clone(), r.service.clone(), r.public))
        .collect();
    state.record_ingress(&served).await?;
    // Only the apps whose route IS among those served: one withheld or left out stays
    // unimplemented, for the publication that serves it.
    let mut routed: Vec<String> = routes.iter().map(|r| r.service.clone()).collect();
    routed.dedup();
    for app in state.complete_unimplemented(ROUTE_ACTION, &routed).await? {
        tracing::info!(app, "route published by the ingress");
    }
    Ok(())
}

/// Waits for Caddy's new task — its names changed — through the update's monitoring
/// window: a task that does not start is rolled back by Swarm.
async fn settle<O: Orchestrator + ?Sized>(orch: &O) -> crate::Result<()> {
    const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(180);
    let deadline = std::time::Instant::now() + TIMEOUT;
    while std::time::Instant::now() < deadline {
        let st = orch.status(INGRESS_SERVICE).await?;
        match st.update_state {
            Some(UpdateState::Completed) if st.is_converged() => return Ok(()),
            Some(s) if s.is_failure() => {
                return Err(crate::Error::Exposure(
                    "Caddy's new task did not start — Swarm went back to the previous \
                     one, which still serves. `docker service logs caddy` says why"
                        .into(),
                ))
            }
            _ => tokio::time::sleep(std::time::Duration::from_secs(2)).await,
        }
    }
    Err(crate::Error::Exposure(format!(
        "Caddy's update did not conclude within {} s",
        TIMEOUT.as_secs()
    )))
}

/// What an app needs from others, said before it is installed: through an Anubis
/// nobody installed its route would be withheld, and with another app's volume it
/// would be placed nowhere.
pub async fn app_blockers<O: Orchestrator + ?Sized>(
    orch: &O,
    m: &hlb_types::Manifest,
) -> Vec<String> {
    let through = m
        .spec
        .ingress
        .iter()
        .any(|i| i.chain.iter().any(|l| l == "anubis"));
    let mut out = Vec::new();
    if through && is_absent(orch, "anubis").await {
        out.push(format!(
            "{} goes through Anubis, which is not installed: hlb install anubis --apply \
             first",
            m.metadata.name
        ));
    }
    // Another app's volume exists once that app runs, on its node: before, the service
    // would be placed nowhere, and the install would time out saying "no suitable node".
    for c in &m.spec.requires {
        if let hlb_types::Capability::Storage {
            name,
            owner: Some(owner),
            ..
        } = c
        {
            if is_absent(orch, owner).await {
                out.push(format!(
                    "{} reads {owner}'s \"{name}\" volume, and {owner} is not installed: \
                     hlb install {owner} --apply first",
                    m.metadata.name
                ));
            }
        }
    }
    out
}

async fn is_absent<O: Orchestrator + ?Sized>(orch: &O, service: &str) -> bool {
    matches!(
        orch.status(service).await,
        Err(hlb_orchestrator::Error::NotFound(_))
    )
}

/// What stops the ingress from being installed, said at preview time: deployed anyway,
/// it would sit unplaced, or serve names nobody chose.
pub async fn blockers<O: Orchestrator + ?Sized>(orch: &O, state: &State) -> Vec<String> {
    let mut out = Vec::new();
    match state.exposure().await {
        Ok(Some(_)) => {}
        Ok(None) => out
            .push("no domain configured yet: hlb config exposure --domain <domain> --apply".into()),
        Err(e) => out.push(format!("the exposure settings are unreadable: {e}")),
    }
    let label = hlb_types::manifest::INGRESS_NODE_LABEL;
    match orch.nodes().await {
        Ok(nodes) if nodes.iter().any(|n| n.ingress) => {}
        Ok(_) => out.push(format!(
            "no node carries {label}: the router forwards 80 and 443 to one machine, \
             name it with hlb config exposure --node <hostname> --apply"
        )),
        Err(e) => out.push(format!("the nodes are unreadable: {e}")),
    }
    out
}
