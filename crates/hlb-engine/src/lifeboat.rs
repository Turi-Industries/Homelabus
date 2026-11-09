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
    hlb_types::binding::GeneratedSecret {
        name: "admin-password".into(),
        form: hlb_types::binding::SecretForm::Plain,
    }
    .vault_name(POSTGRES)
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
    spec
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

/// The most memory the selection may take on the site, in MiB: each service's limit,
/// its companions' and the site's PostgreSQL's — `None` when a manifest declares none,
/// since a guess would decide what fits.
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
    let mut hardening = caddy.spec.security.clone();
    // 🔴 The house's publishes 80 and 443 in host mode: on the site those are the
    // door's, and a second claim leaves the task pending.
    hardening.published_ports.clear();
    let mut spec = ServiceSpec::new(
        hlb_ingress::front_door::SITE_CADDY,
        caddy.spec.image.reference(),
    )
    .replicas(0)
    .network(NETWORK)
    .hardening(hardening)
    .mount(CADDY_DATA, "/data")
    .mount(CADDY_CONFIG, "/config")
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
    spec.memory = caddy.spec.swarm.memory;
    spec
}

/// Where the promotion is left on the site, and the mark it leaves.
pub const PROMOTE_SCRIPT: &str = "/usr/local/sbin/hlb-site-promote";
pub const PROMOTED_MARK: &str = "/etc/hlb/site/promoted";
/// The door's file once promoted, beside the one it runs.
pub const PROMOTED_DOOR: &str = "haproxy.promoted.cfg";

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
pub fn promote_script(services: &[String], names: &[String]) -> String {
    let door = hlb_ingress::front_door::CONFIG_DIR;
    let inside = hlb_ingress::front_door::MOUNTED_AT;
    let image = hlb_ingress::front_door::IMAGE;
    let svc = services.join(" ");
    let caddy = hlb_ingress::front_door::SITE_CADDY;
    let door_service = hlb_ingress::front_door::SERVICE;
    let listed = names.join(" ");
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
for s in $SERVICES; do start "$s"; done
start {caddy}

# Checked by the image that will run it, before the rename.
cp {door}/{PROMOTED_DOOR} {door}/haproxy.cfg.new
docker run --rm --network none --read-only --cap-drop ALL     --mount type=bind,src={door},dst={inside},readonly     {image} haproxy -c -q -f {inside}/haproxy.cfg.new
mv -f {door}/haproxy.cfg.new {door}/haproxy.cfg
for id in $(docker ps -q --filter label=com.docker.swarm.service.name={door_service}); do
    docker kill -s USR2 "$id" >/dev/null
done
echo "✓ Promoted: $NAMES served from this site since $(cat {PROMOTED_MARK})."
"#
    )
}

/// The order the promotion starts services in: PostgreSQL, then the sign-in, then the
/// rest as carried.
pub fn start_order(services: &[String]) -> Vec<String> {
    let rank = |s: &String| match s.as_str() {
        POSTGRES => 0,
        SIGN_IN => 1,
        _ => 2,
    };
    let mut out = services.to_vec();
    out.sort_by_key(rank);
    out
}

pub fn memory_mib(
    sel: &Selection,
    installed: &[(String, Manifest)],
    postgres: Option<&Manifest>,
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
    if !sel.postgres.is_empty() {
        let pg = postgres.ok_or("PostgreSQL is not installed")?;
        total += limit("postgres", pg.spec.swarm.memory.as_ref())?;
    }
    // The site's own Caddy runs beside them once promoted, the night it matters.
    if !sel.apps.is_empty() {
        let c = caddy.ok_or("Caddy is not installed: the site would have no ingress")?;
        total += limit("caddy", c.spec.swarm.memory.as_ref())?;
    }
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
        assert_eq!(
            site.mounts,
            vec![("vaultwarden-data".to_string(), "/data".to_string())]
        );
    }

    #[test]
    fn the_smtp_password_never_reaches_the_site() {
        assert!(WITHHELD.contains(&Token::SmtpPassword));
    }

    #[test]
    fn memory_is_every_limit_the_site_will_run() {
        let installed = vec![vaultwarden(), pocket_id()];
        let sel = select(&installed);
        let caddy = caddy();
        assert_eq!(
            memory_mib(&sel, &installed, Some(&postgres()), Some(&caddy)),
            Ok(256 + 256 + 2048 + 512)
        );
        let mut silent = installed.clone();
        silent[0].1.spec.swarm.memory = None;
        assert!(memory_mib(&sel, &silent, Some(&postgres()), Some(&caddy)).is_err());
        assert!(memory_mib(&sel, &installed, Some(&postgres()), None).is_err());
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
            "postgres".into(),
            "immich".into(),
        ]);
        assert_eq!(order, ["postgres", "pocket-id", "vaultwarden", "immich"]);
    }

    #[test]
    fn the_promotion_is_a_script_the_shell_reads_and_it_marks_the_site_first() {
        let script = promote_script(
            &["postgres".into(), "vaultwarden".into()],
            &["vault.example.fr".into()],
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
        assert!(script.contains("--format '{{.Status}}'"), "{script}");
        assert!(
            script.contains("SERVICES=\"postgres vaultwarden\""),
            "{script}"
        );
    }
}
