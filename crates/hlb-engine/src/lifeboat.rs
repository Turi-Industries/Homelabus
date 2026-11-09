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
pub fn memory_mib(
    sel: &Selection,
    installed: &[(String, Manifest)],
    postgres: Option<&Manifest>,
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
    fn the_smtp_password_never_reaches_the_site() {
        assert!(WITHHELD.contains(&Token::SmtpPassword));
    }

    #[test]
    fn memory_is_every_limit_the_site_will_run() {
        let installed = vec![vaultwarden(), pocket_id()];
        let sel = select(&installed);
        assert_eq!(
            memory_mib(&sel, &installed, Some(&postgres())),
            Ok(256 + 256 + 2048)
        );
        let mut silent = installed.clone();
        silent[0].1.spec.swarm.memory = None;
        assert!(memory_mib(&sel, &silent, Some(&postgres())).is_err());
    }
}
