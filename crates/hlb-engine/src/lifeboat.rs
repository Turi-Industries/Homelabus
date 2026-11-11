//! The lifeboat: the house's vital apps, rebuilt every night on its site from their
//! backups, started once, checked, and stopped — ready for the night the house is down.
//!
//! 🔴 **The house reads the backups, never the site.** One restic password encrypts
//! every app's snapshots: handed to the VPS so it could restore two apps, it would read
//! all of them. The house restores, and sends the site what those two apps hold and
//! nothing more.
//!
//! What the site is given is chosen here, capability by capability, and an app needing
//! something the site does not carry is refused whole: half an app started from a
//! backup looks healthy and is not the app.

use hlb_orchestrator::ServiceSpec;
use hlb_resolver::{Action, Plan};
use hlb_state::State;
use hlb_types::binding::Token;
use hlb_types::{Capability, Criticality, DbEngine, Manifest, SsoMode};

/// The overlay the lifeboat's services share on the site.
pub const NETWORK: &str = "hlb-lifeboat";

/// PocketID's service: carried with any app signing in through it.
pub const SIGN_IN: &str = "pocket-id";

/// Values a lifeboat's services never carry.
///
/// The submission password: Stalwart is not on the site and cannot be reached from it,
/// so the password would open nothing for the app — and a VPS holding it could send
/// mail as the house.
pub const WITHHELD: &[Token] = &[Token::SmtpPassword];

/// The vault's entry holding the site PostgreSQL's administrator password. A stored
/// name: the house's own never leaves it.
pub const ADMIN_SECRET: &str = "site-lifeboat-postgres-admin";

/// The vault entry the PostgreSQL service reads its administrator from — the one the
/// site's is rendered with instead.
pub fn admin_entry() -> String {
    admin_entry_of(POSTGRES)
}

/// The vault entry `service`, a PostgreSQL of the catalog, reads its administrator from.
///
/// 🔴 The vital server's standby is rendered with the site's administrator in its place:
/// its data directory, replicated, already holds every role, so the entrypoint never
/// reads the file — and the house's password never travels to the VPS for nothing.
pub fn admin_entry_of(service: &str) -> String {
    hlb_types::binding::GeneratedSecret {
        name: "admin-password".into(),
        form: hlb_types::binding::SecretForm::Plain,
    }
    .vault_name(service)
}

/// The PostgreSQL service, which the site runs for the databases it carries.
pub const POSTGRES: &str = "postgres";

/// An installed app's plan, as the house deployed it: its frozen manifest and guide,
/// its domain, mail domain and the house's zone.
pub async fn plan_of(state: &State, app: &str) -> crate::Result<Plan> {
    let manifest = state.app_manifest(app).await?;
    let guide = crate::install::installed_guide(state, app, || None).await?;
    let params = hlb_resolver::InstallParams {
        domain: state.app_domain(app).await?,
        mail_domain: crate::install::mail_domain(state, app, None).await?,
        timezone: state.timezone().await?,
        // The site runs one PostgreSQL, `postgres`, and carries the vital server's
        // databases into it.
        vital_postgres: false,
        ..Default::default()
    };
    Ok(hlb_resolver::resolve_with_guide(
        &manifest, &guide, &params,
    )?)
}

/// The services a plan deploys, companions first as the plan orders them.
pub fn services(plan: &Plan) -> Vec<&Action> {
    plan.actions
        .iter()
        .filter(|a| matches!(a, Action::DeployService { .. }))
        .collect()
}

/// A service rendered for the house, made the site's: one task, on its one node, on
/// the lifeboat's overlay, its volumes the site's own Docker volumes.
///
/// 🔴 Never the house's placement: a constraint naming a house node or an NFS backing
/// pointing at the house's pool would leave the task pending, or write into the house.
pub fn for_site(mut spec: ServiceSpec) -> ServiceSpec {
    spec.replicas = 1;
    spec.constraints.clear();
    spec.backings.clear();
    spec.networks = vec![NETWORK.to_string()];
    // The ingress's names are the house's: the site's services answer to their own.
    spec.aliases.clear();
    if spec.name == POSTGRES {
        spec.memory = Some(site_postgres_memory());
    }
    spec
}

/// The site's PostgreSQL serves the lifeboat's two or three databases, not the house's
/// every app: measured at 60 MiB idle. The house's 2 GiB limit alone refused a 2 GB VPS
/// at preview, for 100 MiB in use.
pub const SITE_POSTGRES_MIB: u64 = 512;

fn site_postgres_memory() -> hlb_types::manifest::Memory {
    const MIB: u64 = 1024 * 1024;
    hlb_types::manifest::Memory {
        reserve: hlb_types::manifest::Bytes(64 * MIB),
        limit: hlb_types::manifest::Bytes(SITE_POSTGRES_MIB * MIB),
    }
}

/// What the site is asked to hold.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Selection {
    /// The apps carried, sorted, PocketID among them when one signs in through it.
    pub apps: Vec<String>,
    /// The PostgreSQL databases to restore on the site's own server: `(app, database)`.
    pub postgres: Vec<(String, String)>,
    /// Vital apps the site cannot carry, and why.
    pub refused: Vec<(String, String)>,
    /// Said beside the selection: what an app will lack on the site.
    pub notes: Vec<String>,
}

impl Selection {
    pub fn is_empty(&self) -> bool {
        self.apps.is_empty()
    }
}

/// Why an app cannot be carried, or `None` — then `needs` says what else it brings.
fn carried(app: &str, m: &Manifest, needs: &mut Needs) -> Option<String> {
    // What it writes while the site serves it must have a way home, or the house would
    // start again on the day it fell.
    if m.spec.lifeboat.is_none() {
        return Some(
            "its manifest declares no way home for what it writes on the site \
             (`spec.lifeboat.returns`)"
                .into(),
        );
    }
    for c in &m.spec.requires {
        match c {
            Capability::Database {
                engine,
                name,
                extensions: _,
                connections: _,
            } => match engine {
                DbEngine::Postgres => needs
                    .postgres
                    .push(name.clone().unwrap_or_else(|| app.to_string())),
                DbEngine::Mariadb => {
                    return Some("its MariaDB database: the site runs no MariaDB".into())
                }
            },
            Capability::Cache {
                engine: _,
                dedicated: _,
            } => return Some("its cache: the site runs none".into()),
            Capability::Sso {
                mode,
                redirect_paths: _,
            } => match mode {
                SsoMode::Native => needs.sign_in = true,
                SsoMode::ProxyOnly | SsoMode::ProxyHeader => {
                    return Some("the portal it sits behind: the site runs none".into())
                }
                SsoMode::None => {}
            },
            Capability::ObjectStorage { .. } => {
                return Some("its bucket: the site runs no object storage".into())
            }
            Capability::MailAccount { .. } => {
                return Some("its mailbox: the site carries no mail".into())
            }
            Capability::Smtp { sender: _ } => needs.mail = true,
            Capability::Storage {
                name,
                path: _,
                tier: _,
                backup,
                sqlite: _,
                copy: _,
                owner,
            } => {
                if owner.is_some() {
                    return Some(format!("its volume {name} belongs to another app"));
                }
                if !backup {
                    needs.empty.push(name.clone());
                }
            }
        }
    }
    None
}

#[derive(Default)]
struct Needs {
    postgres: Vec<String>,
    sign_in: bool,
    mail: bool,
    /// Volumes no backup holds: they start empty on the site.
    empty: Vec<String>,
}

/// The vital apps among those installed, and what carrying them takes.
pub fn select(installed: &[(String, Manifest)]) -> Selection {
    let mut sel = Selection::default();
    let mut sign_in = false;
    let mut vital: Vec<&(String, Manifest)> = installed
        .iter()
        .filter(|(_, m)| m.criticality() == Criticality::Vital)
        .collect();
    vital.sort_by(|a, b| a.0.cmp(&b.0));
    for (app, m) in vital {
        let mut needs = Needs::default();
        if let Some(why) = carried(app, m, &mut needs) {
            sel.refused.push((app.clone(), why));
            continue;
        }
        sel.apps.push(app.clone());
        sel.postgres
            .extend(needs.postgres.into_iter().map(|d| (app.clone(), d)));
        sign_in |= needs.sign_in;
        if needs.mail {
            sel.notes.push(format!(
                "{app} sends no mail from the site: Stalwart stays home"
            ));
        }
        for v in needs.empty {
            sel.notes.push(format!(
                "{app}'s volume {v} is never backed up: it starts empty"
            ));
        }
    }
    if sign_in && !sel.apps.iter().any(|a| a == SIGN_IN) {
        match installed.iter().find(|(n, _)| n == SIGN_IN) {
            Some((_, m)) => {
                let mut needs = Needs::default();
                match carried(SIGN_IN, m, &mut needs) {
                    Some(why) => {
                        sel.refused.push((SIGN_IN.into(), why));
                        sel.notes.push(format!(
                            "without {SIGN_IN}, the apps on the site open by their own passwords only"
                        ));
                    }
                    None => {
                        sel.apps.push(SIGN_IN.into());
                        if needs.mail {
                            sel.notes.push(format!(
                                "{SIGN_IN} sends no mail from the site: no new-device notice"
                            ));
                        }
                    }
                }
            }
            None => sel.notes.push(format!(
                "{SIGN_IN} is not installed: signing in through it does not work on the site"
            )),
        }
        sel.apps.sort();
    }
    sel
}

/// The site's own Caddy: its volumes, the certificates and its configuration's.
pub const CADDY_DATA: &str = "hlb-site-caddy-data";
pub const CADDY_CONFIG: &str = "hlb-site-caddy-config";
/// Where the site's Caddy reads its file.
pub const CADDYFILE: &str = "/etc/caddy/Caddyfile";

/// What the site's Caddy serves once promoted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SiteIngress {
    pub caddyfile: String,
    /// The names the promoted door sends to it, sorted.
    pub names: Vec<String>,
    /// A private ACME directory's root, which the house's Caddy trusts too.
    pub acme_root: Option<String>,
}

/// The site's certificates: asked of the house's ACME directory over HTTP-01, per name.
///
/// 🔴 Never the house's internal authority: its root's key stays home, and a VPS
/// holding it could sign for any name. Nor the wildcard: DNS-01 hands the site the
/// provider's token, which opens the whole zone.
pub fn site_tls(e: Option<&hlb_state::Exposure>) -> crate::Result<hlb_ingress::caddyfile::Tls> {
    let refuse = |why: &str| Err(crate::Error::Exposure(why.into()));
    let Some(e) = e else {
        return refuse(
            "the house's exposure was never configured: the site would serve no name \
             (hlb config exposure)",
        );
    };
    match e.certificates {
        hlb_state::Certificates::Internal => refuse(
            "the house signs its certificates with its own authority, whose key never \
             leaves it: the site cannot serve TLS on its own — an ACME directory can \
             (hlb config exposure --email)",
        ),
        hlb_state::Certificates::Acme => Ok(hlb_ingress::caddyfile::Tls::Acme {
            email: e.acme_email.clone().ok_or_else(|| {
                crate::Error::Exposure(
                    "no ACME address: hlb config exposure --email <address>".into(),
                )
            })?,
            wildcard: None,
            staging: e.staging,
            ca: e.acme_ca.clone(),
            ca_root: e.acme_ca_root.is_some(),
        }),
    }
}

/// The site's Caddyfile for `routes` — the lifeboat's apps' —, its PROXY header read
/// from `overlay`, the lifeboat's network.
///
/// 🔴 Every route is opened, private ones included: the owner's decision (2026-11-09),
/// the site serving while the house is down — those away from it are who needs
/// Vaultwarden then. Behind the apps' own second factor and the rate limits, said by
/// the promotion, closed by the return.
pub fn site_ingress(
    mut routes: Vec<hlb_ingress::Route>,
    tls: hlb_ingress::caddyfile::Tls,
    overlay: &str,
    acme_root: Option<String>,
) -> crate::Result<SiteIngress> {
    for r in &mut routes {
        // The selection refuses an app behind the portal; one reaching here would be
        // served without it.
        if r.needs_forward_auth {
            return Err(crate::Error::Exposure(format!(
                "{} sits behind the portal, which the site does not run",
                r.host
            )));
        }
        r.public = true;
    }
    let cfg = hlb_ingress::Config {
        tls,
        site: Some(overlay.to_string()),
        ..hlb_ingress::Config::default()
    };
    let mut names: Vec<String> = routes.iter().map(|r| r.host.clone()).collect();
    names.sort();
    names.dedup();
    Ok(SiteIngress {
        caddyfile: hlb_ingress::render(&routes, &cfg),
        names,
        acme_root,
    })
}

/// The site's Caddy, deployed stopped: the house's image and hardening, none of its
/// ports — the door reaches it on the overlay — and none of its files.
pub fn site_caddy(caddy: &Manifest, ingress: &SiteIngress) -> ServiceSpec {
    let mut spec = caddy_on_site(
        caddy,
        ingress,
        hlb_ingress::front_door::SITE_CADDY,
        NETWORK,
        (CADDY_DATA, CADDY_CONFIG),
    );
    spec.replicas = 0;
    spec.memory = caddy.spec.swarm.memory;
    spec
}

/// A Caddy on the site, `name` on `network`, its data and config in `volumes`: the
/// lifeboat's, or the edge serving the site's own names.
pub fn caddy_on_site(
    caddy: &Manifest,
    ingress: &SiteIngress,
    name: &str,
    network: &str,
    volumes: (&str, &str),
) -> ServiceSpec {
    let mut hardening = caddy.spec.security.clone();
    // 🔴 The house's publishes 80 and 443 in host mode: on the site those are the
    // door's, and a second claim leaves the task pending.
    hardening.published_ports.clear();
    let mut spec = ServiceSpec::new(name, caddy.spec.image.reference())
        .network(network)
        .hardening(hardening)
        .mount(volumes.0, "/data")
        .mount(volumes.1, "/config")
        .file(CADDYFILE, ingress.caddyfile.clone());
    spec.command = [
        "caddy",
        "run",
        "--config",
        CADDYFILE,
        "--adapter",
        "caddyfile",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    if let Some(root) = &ingress.acme_root {
        spec = spec.file(hlb_ingress::caddyfile::ACME_ROOT, root.clone());
    }
    if let Some(h) = &caddy.spec.swarm.healthcheck {
        spec = spec.healthcheck(h.clone());
    }
    spec
}

/// Where the promotion is left on the site, and the mark it leaves.
pub const PROMOTE_SCRIPT: &str = "/usr/local/sbin/hlb-site-promote";
pub const PROMOTED_MARK: &str = "/etc/hlb/site/promoted";
/// The door's file once promoted, beside the one it runs.
pub const PROMOTED_DOOR: &str = "haproxy.promoted.cfg";

/// The promotion's exit when everything was started and the door swapped, but a name has
/// no certificate yet: promoted, and said apart from a promotion that stopped.
pub const PROMOTED_WITHOUT_CERTIFICATE: i32 = 3;
/// How long the promotion waits for every name's certificate, all names together. Caddy
/// retries a failed order after a minute, then backs off.
pub const CERTIFICATE_WAIT_SECS: u32 = 240;

/// The names a promotion script serves, read back from it: what `hlb site status` checks
/// against the public records, the script being what runs the night it is needed.
pub fn promoted_names(script: &str) -> Vec<String> {
    script
        .lines()
        .find_map(|l| l.strip_prefix("NAMES=\"")?.strip_suffix('"'))
        .map(|n| n.split_whitespace().map(str::to_string).collect())
        .unwrap_or_default()
}

/// Where a vital name's public records send its visitors, against the site's addresses.
#[derive(Debug, PartialEq, Eq)]
pub enum Pointing {
    /// Every address is the site's: the door answers, and the authority validates there.
    Site,
    /// Some address is not the site's: those visitors, and the authority, go elsewhere.
    Elsewhere(Vec<String>),
    /// No address at all.
    Nowhere,
    /// The resolver could not say.
    Unread(String),
}

/// Judges a name's A and AAAA records against the site's own addresses. One record
/// elsewhere is enough: a resolver hands either out, and the authority may pick it.
pub fn pointing(records: Result<Vec<String>, String>, site: &[String]) -> Pointing {
    let ip = |a: &str| a.trim().parse::<std::net::IpAddr>().ok();
    let records = match records {
        Err(e) => return Pointing::Unread(e),
        Ok(r) if r.is_empty() => return Pointing::Nowhere,
        Ok(r) => r,
    };
    if site.is_empty() {
        return Pointing::Unread("the site's own address resolves to nothing".into());
    }
    let ours: Vec<_> = site.iter().filter_map(|a| ip(a)).collect();
    let elsewhere: Vec<String> = records
        .into_iter()
        .filter(|r| ip(r).is_none_or(|a| !ours.contains(&a)))
        .collect();
    if elsewhere.is_empty() {
        Pointing::Site
    } else {
        Pointing::Elsewhere(elsewhere)
    }
}

/// Why the house's own copies of the carried apps are held stopped while the site
/// serves them: two copies written at once cannot be merged, and the return replaces
/// the house's. 🔴 A stored value (`service_holds.why`).
pub const HOUSE_HOLD: &str = "the site serves it";
/// As long as a promotion may last. Expired, reconciliation would start the house's
/// copy beside the site's, for the LAN, and the return would replace what it wrote.
pub const HOUSE_HOLD_SECS: i64 = 365 * 24 * 3600;

/// The promotion, a script of its own on the site: the night the house is down there is
/// no house to run `hlb` from, only SSH to the VPS.
///
/// `services` in the order they start — the databases' server first, the sign-in next.
/// `before`: shell run before a service starts, `(service, step)` — a vital SQLite put
/// back from its replica. A step stops nothing: it says what it could not do.
pub fn promote_script(
    services: &[String],
    names: &[String],
    before: &[(String, String)],
) -> String {
    let door = hlb_ingress::front_door::CONFIG_DIR;
    let inside = hlb_ingress::front_door::MOUNTED_AT;
    let image = hlb_ingress::front_door::IMAGE;
    let svc = services.join(" ");
    let caddy = hlb_ingress::front_door::SITE_CADDY;
    let door_service = hlb_ingress::front_door::SERVICE;
    let listed = names.join(" ");
    let watch = crate::site_watch::CONFIG_DIR;
    let gatus = crate::site_watch::GATUS_LIVE;
    let gatus_promoted = crate::site_watch::GATUS_PROMOTED;
    let cert_secs = CERTIFICATE_WAIT_SECS;
    let cert_polls = CERTIFICATE_WAIT_SECS / 2;
    let vital = hlb_types::VITAL_POSTGRES;
    let prepare = if before.is_empty() {
        String::new()
    } else {
        let arms: String = before
            .iter()
            .map(|(svc, step)| format!("    {svc})\n{step}        ;;\n"))
            .collect();
        format!("    case \"$s\" in\n{arms}    esac\n")
    };
    format!(
        r#"#!/bin/sh
# Generated by Homelabus each night with the lifeboat - do not edit by hand.
# The site serves the house's vital apps while the house is down.
#   {PROMOTE_SCRIPT}           says what it would do
#   {PROMOTE_SCRIPT} --apply   does it
# Undone from the house, once it is back: hlb site return --apply
set -eu
SERVICES="{svc}"
NAMES="{listed}"

if [ "${{1:-}}" != "--apply" ]; then
    echo "Would start on this site: $SERVICES"
    echo "then its own Caddy, which asks for a certificate for: $NAMES"
    echo "and send those names to it from the front door; every other name still goes home."
    echo "Private apps among them are open to the internet until the return."
    echo "Rerun with --apply."
    exit 0
fi
[ "$(id -u)" = 0 ] || {{ echo "run as root" >&2; exit 1; }}
[ -f {door}/{PROMOTED_DOOR} ] || {{
    echo "no promoted door was prepared here: the lifeboat never ran" >&2; exit 1; }}

# First: from now on the house's nightly lifeboat refuses to replace what serves.
mkdir -p "$(dirname {PROMOTED_MARK})"
[ -f {PROMOTED_MARK} ] || date -u +%Y-%m-%dT%H:%M:%SZ > {PROMOTED_MARK}

# Up and, where it has a probe, healthy: a database restored behind an app it serves.
ready() {{
    docker ps --filter "label=com.docker.swarm.service.name=$1" --format '{{{{.Status}}}}' |
        grep '^Up' | grep -qv -e '(health: starting)' -e '(unhealthy)'
}}
start() {{
    docker service scale --detach "$1=1" >/dev/null
    n=0
    until ready "$1"; do
        n=$((n + 1))
        [ "$n" -le 150 ] || {{ echo "$1 is not up after 300 s: docker service ps $1" >&2; exit 1; }}
        sleep 2
    done
    echo "  ✓ $1"
}}
# The vital server's standby replays the house's WAL every day: promoted before any
# app starts, having replayed whatever reached the site, or the apps meet a server that
# takes no write.
promote() {{
    id=$(docker ps -q --filter "label=com.docker.swarm.service.name=$1" | head -n 1)
    sql() {{ docker exec -u postgres "$id" psql -X -qtA -c "$1"; }}
    if [ "$(sql 'SELECT pg_is_in_recovery()')" = f ]; then
        echo "  ✓ $1 already takes writes"
        return 0
    fi
    [ "$(sql 'SELECT pg_promote(true, 60)')" = t ] || {{
        echo "$1 is still a standby after 60 s: docker service logs $1" >&2; exit 1; }}
    echo "  ✓ $1 promoted at $(sql 'SELECT pg_current_wal_lsn()'): it takes writes"
}}
for s in $SERVICES; do
{prepare}    start "$s"
    [ "$s" != {vital} ] || promote "$s"
done
start {caddy}

# Checked by the image that will run it, before the rename.
cp {door}/{PROMOTED_DOOR} {door}/haproxy.cfg.new
docker run --rm --network none --read-only --cap-drop ALL     --mount type=bind,src={door},dst={inside},readonly     {image} haproxy -c -q -f {inside}/haproxy.cfg.new
mv -f {door}/haproxy.cfg.new {door}/haproxy.cfg
for id in $(docker ps -q --filter label=com.docker.swarm.service.name={door_service}); do
    docker kill -s USR2 "$id" >/dev/null
done
# Its certificate asked for again, the door now sending its names here: asked at its
# start, it was validated through the door still pointing home, and failed or hung.
docker service update --force --quiet {caddy} >/dev/null
echo "  ✓ {caddy} asking for its certificate"
# The status page reads the private apps as served on purpose; Gatus reloads its file.
if [ -f {watch}/{gatus_promoted} ]; then
    cp {watch}/{gatus_promoted} {watch}/{gatus}.new
    mv -f {watch}/{gatus}.new {watch}/{gatus}
fi

# Promoted once each name holds its certificate, not before: the authority validates a
# name where its public records point, and one still naming the house is never served
# here while everything else reads promoted.
has_cert() {{
    for id in $(docker ps -q --filter label=com.docker.swarm.service.name={caddy}); do
        docker exec "$id" sh -c 'ls /data/caddy/certificates/*/"$1"/"$1".crt' sh "$1" \
            >/dev/null 2>&1 && return 0
    done
    return 1
}}
missing=""
n=0
for name in $NAMES; do
    until has_cert "$name"; do
        n=$((n + 1))
        [ "$n" -le {cert_polls} ] || break
        sleep 2
    done
    if has_cert "$name"; then echo "  ✓ certificate for $name"; else missing="$missing $name"; fi
done
if [ -n "$missing" ]; then
    echo "🔴 Promoted, but no certificate after {cert_secs} s for:$missing" >&2
    echo "   Its visitors are refused until one comes; {caddy} keeps asking. The" >&2
    echo "   authority validates a name where its public records point: they must" >&2
    echo "   name this site, not the house.  hlb site status, from the house, reads them." >&2
    exit {PROMOTED_WITHOUT_CERTIFICATE}
fi
echo "✓ Promoted: $NAMES served from this site since $(cat {PROMOTED_MARK})."
"#
    )
}

/// The order the promotion starts services in: the PostgreSQL servers, then the
/// sign-in, then the rest as carried.
pub fn start_order(services: &[String]) -> Vec<String> {
    let rank = |s: &String| match s.as_str() {
        POSTGRES | hlb_types::VITAL_POSTGRES => 0,
        SIGN_IN => 1,
        _ => 2,
    };
    let mut out = services.to_vec();
    out.sort_by_key(rank);
    out
}

/// The most memory the selection may take on the site, in MiB: each service's limit,
/// its companions', and each of `servers` — the PostgreSQL servers the site runs for
/// it. An error when a manifest declares none, since a guess would decide what fits.
pub fn memory_mib(
    sel: &Selection,
    installed: &[(String, Manifest)],
    servers: &[hlb_types::DbServer],
    caddy: Option<&Manifest>,
) -> Result<u64, String> {
    let limit = |name: &str, m: Option<&hlb_types::manifest::Memory>| {
        m.map(|m| m.limit.mib())
            .ok_or_else(|| format!("{name} declares no memory limit"))
    };
    let mut total = 0;
    for app in &sel.apps {
        let m = installed
            .iter()
            .find(|(n, _)| n == app)
            .map(|(_, m)| m)
            .ok_or_else(|| format!("{app} is not installed"))?;
        total += limit(app, m.spec.swarm.memory.as_ref())?;
        for c in &m.spec.companions {
            total += limit(&format!("{app}-{}", c.name), c.memory.as_ref())?;
        }
    }
    let manifest = |name: &str| {
        installed
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, m)| m)
            .ok_or_else(|| format!("{name} is not installed"))
    };
    for server in servers {
        match server {
            hlb_types::DbServer::Postgres => {
                manifest(POSTGRES)?;
                total += SITE_POSTGRES_MIB;
            }
            // Its own limit: the standby replays every day, not only the night it serves.
            hlb_types::DbServer::PostgresVital => {
                let m = manifest(hlb_types::VITAL_POSTGRES)?;
                total += limit(hlb_types::VITAL_POSTGRES, m.spec.swarm.memory.as_ref())?;
            }
            hlb_types::DbServer::Mariadb => return Err("the site runs no MariaDB".into()),
        }
    }
    // The site's own Caddy runs beside them once promoted, the night it matters.
    if !sel.apps.is_empty() {
        let c = caddy.ok_or("Caddy is not installed: the site would have no ingress")?;
        total += limit("caddy", c.spec.swarm.memory.as_ref())?;
    }
    // Beside them every night, and every day: the status page, its alerts, its edge.
    total += crate::site_watch::MEMORY_MIB;
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(yaml: &str) -> Manifest {
        serde_yaml_ng::from_str(yaml).expect("manifest")
    }

    fn vaultwarden() -> (String, Manifest) {
        (
            "vaultwarden".into(),
            manifest(
                r#"
apiVersion: hlb/v1
kind: App
metadata: { name: vaultwarden, criticality: vital }
spec:
  image: { repo: vaultwarden/server, tag: "1", digest: "sha256:abc" }
  requires:
    - kind: database
      engine: postgres
    - kind: sso
      mode: native
    - kind: storage
      name: data
      path: /data
    - kind: smtp
  swarm:
    memory: { reserve: 32M, limit: 256M }
  lifeboat: { returns: whole }
"#,
            ),
        )
    }

    fn pocket_id() -> (String, Manifest) {
        (
            "pocket-id".into(),
            manifest(
                r#"
apiVersion: hlb/v1
kind: PlatformService
metadata: { name: pocket-id }
spec:
  image: { repo: ghcr.io/pocket-id/pocket-id, tag: "v2", digest: "sha256:abc" }
  requires:
    - kind: storage
      name: data
      path: /app/data
      sqlite: true
    - kind: smtp
  swarm:
    memory: { reserve: 64M, limit: 256M }
  lifeboat: { returns: whole }
"#,
            ),
        )
    }

    fn normal(name: &str) -> (String, Manifest) {
        (
            name.into(),
            manifest(&format!(
                r#"
apiVersion: hlb/v1
kind: App
metadata: {{ name: {name} }}
spec:
  image: {{ repo: x/{name}, tag: "1", digest: "sha256:abc" }}
"#
            )),
        )
    }

    fn postgres() -> Manifest {
        manifest(
            r#"
apiVersion: hlb/v1
kind: PlatformService
metadata: { name: postgres }
spec:
  image: { repo: postgres, tag: "17", digest: "sha256:abc" }
  swarm:
    memory: { reserve: 256M, limit: 2G }
"#,
        )
    }

    #[test]
    fn a_vital_app_brings_its_sign_in_and_its_database() {
        let installed = vec![vaultwarden(), pocket_id(), normal("jellyfin")];
        let sel = select(&installed);
        assert_eq!(sel.apps, vec!["pocket-id", "vaultwarden"]);
        assert_eq!(
            sel.postgres,
            vec![("vaultwarden".to_string(), "vaultwarden".to_string())]
        );
        assert!(sel.refused.is_empty(), "{sel:?}");
        assert!(
            sel.notes
                .iter()
                .any(|n| n.contains("vaultwarden sends no mail")),
            "{sel:?}"
        );
    }

    #[test]
    fn nothing_vital_carries_nothing() {
        let sel = select(&[pocket_id(), normal("jellyfin")]);
        assert!(sel.is_empty(), "PocketID alone is no reason: {sel:?}");
    }

    #[test]
    fn a_vital_app_needing_what_the_site_lacks_is_refused_whole() {
        let mut m = vaultwarden();
        m.1.spec.requires.push(Capability::ObjectStorage {
            bucket: None,
            backup: true,
            expire_after_days: None,
        });
        let sel = select(&[m, pocket_id()]);
        assert!(sel.apps.is_empty(), "{sel:?}");
        assert!(
            sel.postgres.is_empty(),
            "its database is not restored either"
        );
        assert_eq!(sel.refused.len(), 1);
        assert!(sel.refused[0].1.contains("bucket"), "{sel:?}");
    }

    #[test]
    fn a_vital_app_declaring_no_way_home_is_refused() {
        let mut m = vaultwarden();
        m.1.spec.lifeboat = None;
        let sel = select(&[m, pocket_id()]);
        assert!(sel.apps.is_empty(), "{sel:?}");
        assert!(
            sel.refused
                .iter()
                .any(|(a, why)| a == "vaultwarden" && why.contains("spec.lifeboat")),
            "{sel:?}"
        );
    }

    #[test]
    fn a_sign_in_declaring_no_way_home_is_left_and_said() {
        let mut p = pocket_id();
        p.1.spec.lifeboat = None;
        let sel = select(&[vaultwarden(), p]);
        assert_eq!(sel.apps, vec!["vaultwarden".to_string()], "{sel:?}");
        assert!(sel.refused.iter().any(|(a, _)| a == SIGN_IN), "{sel:?}");
    }

    #[test]
    fn the_site_s_postgres_reads_its_own_administrator() {
        // The name the catalog's server reads its password from.
        assert_eq!(admin_entry(), "postgres-admin-password");
        assert_ne!(admin_entry(), ADMIN_SECRET);
        assert_eq!(
            admin_entry_of(hlb_types::VITAL_POSTGRES),
            "postgres-vital-admin-password"
        );
    }

    #[test]
    fn a_service_for_the_site_keeps_nothing_of_the_house_s_placement() {
        let mut spec = ServiceSpec::new("vaultwarden", "vaultwarden/server:1")
            .replicas(0)
            .network("hlb-platform")
            .constraint("node.labels.hlb.data.vaultwarden==true")
            .mount_backed(
                "vaultwarden-data",
                "/data",
                hlb_orchestrator::VolumeBacking::Nfs {
                    server: "10.0.0.2".into(),
                    export: "/tank/apps/vaultwarden/data".into(),
                },
            );
        spec.aliases.push("vault.example.org".into());
        let site = for_site(spec);
        assert_eq!(site.replicas, 1, "started once, whatever the house decided");
        assert!(site.constraints.is_empty() && site.backings.is_empty() && site.aliases.is_empty());
        assert_eq!(site.networks, vec![NETWORK.to_string()]);
        assert_eq!(site.memory, None, "an app keeps its own limit");
        assert_eq!(
            site.mounts,
            vec![("vaultwarden-data".to_string(), "/data".to_string())]
        );
    }

    #[test]
    fn the_site_s_postgres_has_a_limit_of_its_own() {
        let site = for_site(ServiceSpec::new(POSTGRES, "postgres:17"));
        assert_eq!(site.memory.map(|m| m.limit.mib()), Some(SITE_POSTGRES_MIB));
    }

    #[test]
    fn the_smtp_password_never_reaches_the_site() {
        assert!(WITHHELD.contains(&Token::SmtpPassword));
    }

    #[test]
    fn memory_is_every_limit_the_site_will_run() {
        use hlb_types::DbServer;
        let mut vital = postgres();
        vital.metadata.name = hlb_types::VITAL_POSTGRES.into();
        vital.spec.swarm.memory = Some(hlb_types::manifest::Memory {
            reserve: hlb_types::manifest::Bytes(64 << 20),
            limit: hlb_types::manifest::Bytes(384 << 20),
        });
        let installed = vec![
            vaultwarden(),
            pocket_id(),
            ("postgres".to_string(), postgres()),
            (hlb_types::VITAL_POSTGRES.to_string(), vital),
        ];
        let sel = select(&installed);
        let caddy = caddy();
        let apps = 256 + 256 + 512 + crate::site_watch::MEMORY_MIB;
        assert_eq!(
            memory_mib(&sel, &installed, &[DbServer::Postgres], Some(&caddy)),
            Ok(apps + SITE_POSTGRES_MIB)
        );
        // The standby at its own limit, every day.
        assert_eq!(
            memory_mib(&sel, &installed, &[DbServer::PostgresVital], Some(&caddy)),
            Ok(apps + 384)
        );
        assert_eq!(
            memory_mib(
                &sel,
                &installed,
                &[DbServer::Postgres, DbServer::PostgresVital],
                Some(&caddy)
            ),
            Ok(apps + SITE_POSTGRES_MIB + 384)
        );
        let mut silent = installed.clone();
        silent[0].1.spec.swarm.memory = None;
        assert!(memory_mib(&sel, &silent, &[DbServer::Postgres], Some(&caddy)).is_err());
        assert!(memory_mib(&sel, &installed, &[DbServer::Postgres], None).is_err());
        assert!(
            memory_mib(
                &sel,
                &installed[..2],
                &[DbServer::PostgresVital],
                Some(&caddy)
            )
            .is_err(),
            "a server not installed is no server counted at nothing"
        );
    }

    fn caddy() -> Manifest {
        manifest(
            r#"
apiVersion: hlb/v1
kind: PlatformService
metadata: { name: caddy }
spec:
  image: { repo: ghcr.io/turi-industries/hlb-caddy, tag: "0.4.8", digest: "sha256:abc" }
  security:
    publishedPorts: [80, 443, 10443]
    capAdd: [NET_BIND_SERVICE]
  swarm:
    memory: { reserve: 64M, limit: 512M }
    healthcheck:
      test: ["CMD", "wget", "-q", "-O", "/dev/null", "http://127.0.0.1:2019/config/"]
"#,
        )
    }

    fn acme() -> hlb_state::Exposure {
        hlb_state::Exposure {
            domain: "example.fr".into(),
            certificates: hlb_state::Certificates::Acme,
            acme_email: Some("admin@example.fr".into()),
            dns_provider: Some("hetzner".into()),
            staging: false,
            controller_host: None,
            acme_ca: None,
            acme_ca_root: None,
        }
    }

    #[test]
    fn the_site_asks_its_own_certificates_over_http_never_with_the_house_s_keys() {
        let tls = site_tls(Some(&acme())).expect("acme");
        let hlb_ingress::caddyfile::Tls::Acme { wildcard, .. } = &tls else {
            panic!("{tls:?}");
        };
        assert!(wildcard.is_none(), "the DNS token never reaches the site");
        let mut internal = acme();
        internal.certificates = hlb_state::Certificates::Internal;
        assert!(
            site_tls(Some(&internal)).is_err(),
            "the root's key stays home"
        );
        assert!(site_tls(None).is_err());
    }

    #[test]
    fn a_private_app_is_open_on_the_promoted_site() {
        let private = hlb_ingress::Route::new("vault.example.fr", "vaultwarden", 80);
        assert!(!private.public);
        let ingress = site_ingress(
            vec![private],
            site_tls(Some(&acme())).expect("acme"),
            "10.0.9.0/24",
            None,
        )
        .expect("rendered");
        assert_eq!(ingress.names, vec!["vault.example.fr".to_string()]);
        assert!(
            !ingress.caddyfile.contains("@external_"),
            "{}",
            ingress.caddyfile
        );
        assert!(ingress.caddyfile.contains("allow 10.0.9.0/24"));
    }

    #[test]
    fn an_app_behind_the_portal_is_never_served_without_it() {
        let mut r = hlb_ingress::Route::new("files.example.fr", "seafile", 80);
        r.needs_forward_auth = true;
        let tls = site_tls(Some(&acme())).expect("acme");
        assert!(site_ingress(vec![r], tls, "10.0.9.0/24", None).is_err());
    }

    #[test]
    fn the_site_s_caddy_waits_stopped_and_claims_no_port_of_the_door_s() {
        let ingress = SiteIngress {
            caddyfile: "{}".into(),
            names: vec![],
            acme_root: Some("ROOT".into()),
        };
        let spec = site_caddy(&caddy(), &ingress);
        assert_eq!(spec.replicas, 0);
        assert!(spec.hardening.published_ports.is_empty(), "{spec:?}");
        assert_eq!(spec.networks, vec![NETWORK.to_string()]);
        assert!(spec
            .hardening
            .cap_add
            .iter()
            .any(|c| c == "NET_BIND_SERVICE"));
        assert!(spec.files.iter().any(|(p, _)| p == CADDYFILE));
        assert!(spec
            .files
            .iter()
            .any(|(p, c)| p == hlb_ingress::caddyfile::ACME_ROOT && c == "ROOT"));
        assert!(spec.healthcheck.is_some());
        assert!(spec.image.contains("hlb-caddy"));
    }

    #[test]
    fn the_promotion_starts_the_database_then_the_sign_in() {
        let order = start_order(&[
            "vaultwarden".into(),
            "pocket-id".into(),
            "postgres-vital".into(),
            "postgres".into(),
            "immich".into(),
        ]);
        assert_eq!(
            order,
            [
                "postgres-vital",
                "postgres",
                "pocket-id",
                "vaultwarden",
                "immich"
            ]
        );
    }

    #[test]
    fn the_vital_standby_is_promoted_before_any_app_starts() {
        let script = promote_script(
            &start_order(&["vaultwarden".into(), "postgres-vital".into()]),
            &["vault.example.fr".into()],
            &[],
        );
        let out = std::process::Command::new("sh")
            .args(["-n", "-c", &script])
            .output()
            .expect("sh");
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            script.contains("SERVICES=\"postgres-vital vaultwarden\""),
            "{script}"
        );
        // Promoted inside the loop, as soon as it is up: the next service is an app.
        let at = |p: &str| script.find(p).unwrap_or_else(|| panic!("{p}: {script}"));
        assert!(
            at("pg_promote(true, 60)") < at("for s in $SERVICES"),
            "{script}"
        );
        assert!(
            script.contains("[ \"$s\" != postgres-vital ] || promote \"$s\""),
            "{script}"
        );
        // A second run finds it promoted and goes on.
        assert!(
            at("pg_is_in_recovery()") < at("pg_promote(true, 60)"),
            "{script}"
        );
    }

    #[test]
    fn a_service_s_step_runs_before_it_starts_and_the_shell_reads_it() {
        let step = "from_replica() {\n    echo \"$1\"\n}\nfrom_replica pocket-id-data\n";
        let script = promote_script(
            &["postgres".into(), "pocket-id".into()],
            &["id.example.fr".into()],
            &[("pocket-id".into(), step.into())],
        );
        let out = std::process::Command::new("sh")
            .args(["-n", "-c", &script])
            .output()
            .expect("sh");
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let at = |p: &str| script.find(p).unwrap_or_else(|| panic!("{p}: {script}"));
        assert!(
            at("for s in $SERVICES") < at("    pocket-id)\n"),
            "{script}"
        );
        assert!(
            at("from_replica pocket-id-data") < at("    start \"$s\""),
            "{script}"
        );
        assert!(!promote_script(&["postgres".into()], &[], &[]).contains("case \"$s\""));
    }

    #[test]
    fn the_promotion_is_a_script_the_shell_reads_and_it_marks_the_site_first() {
        let script = promote_script(
            &["postgres".into(), "vaultwarden".into()],
            &["vault.example.fr".into()],
            &[],
        );
        let out = std::process::Command::new("sh")
            .args(["-n", "-c", &script])
            .output()
            .expect("sh");
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let at = |p: &str| script.find(p).unwrap_or_else(|| panic!("{p}: {script}"));
        // Marked before anything starts: the house's nightly run refuses from then on.
        assert!(at(PROMOTED_MARK) < at("for s in $SERVICES"), "{script}");
        // Checked by HAProxy before the rename, reloaded after.
        assert!(at("haproxy -c") < at("mv -f"), "{script}");
        assert!(at("mv -f") < at("USR2"), "{script}");
        // Its certificate asked for again once the door sends its names to it.
        let again = format!(
            "docker service update --force --quiet {}",
            hlb_ingress::front_door::SITE_CADDY
        );
        assert!(at("USR2") < at(&again), "{script}");
        // The page swaps once the door has: a private app read open before it is.
        let page = format!(
            "cp {}/{} ",
            crate::site_watch::CONFIG_DIR,
            crate::site_watch::GATUS_PROMOTED
        );
        assert!(at("USR2") < at(&page), "{script}");
        // Promoted once every name holds its certificate, asked for again first.
        assert!(at(&again) < at("has_cert \"$name\""), "{script}");
        assert!(at("has_cert \"$name\"") < at("✓ Promoted"), "{script}");
        assert!(
            script.contains(&format!("exit {PROMOTED_WITHOUT_CERTIFICATE}")),
            "{script}"
        );
        assert!(script.contains("--format '{{.Status}}'"), "{script}");
        assert!(
            script.contains("SERVICES=\"postgres vaultwarden\""),
            "{script}"
        );
    }

    #[test]
    fn the_names_a_promotion_serves_are_read_back_from_its_script() {
        let names = vec!["vault.example.fr".to_string(), "id.example.fr".to_string()];
        let script = promote_script(&["vaultwarden".into()], &names, &[]);
        assert_eq!(promoted_names(&script), names);
        assert!(promoted_names("#!/bin/sh\n").is_empty());
    }

    #[test]
    fn a_name_points_at_the_site_only_when_every_address_is_the_site_s() {
        let site = ["203.0.113.7".to_string(), "2001:db8::7".to_string()];
        let ok = |r: &[&str]| Ok(r.iter().map(|s| s.to_string()).collect());
        assert_eq!(pointing(ok(&["203.0.113.7"]), &site), Pointing::Site);
        // The same address written another way is the same address.
        assert_eq!(
            pointing(ok(&["203.0.113.7", "2001:0db8:0:0::7"]), &site),
            Pointing::Site
        );
        // The house's address beside the site's: the authority may validate there.
        assert_eq!(
            pointing(ok(&["203.0.113.7", "198.51.100.9"]), &site),
            Pointing::Elsewhere(vec!["198.51.100.9".into()])
        );
        assert_eq!(pointing(ok(&[]), &site), Pointing::Nowhere);
        assert!(matches!(
            pointing(Err("SERVFAIL".into()), &site),
            Pointing::Unread(_)
        ));
        assert!(matches!(
            pointing(ok(&["203.0.113.7"]), &[]),
            Pointing::Unread(_)
        ));
    }
}
