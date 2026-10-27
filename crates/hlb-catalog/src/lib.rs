//! Catalog loading and validation.
//!
//! A catalog is a folder of folders, one per app, each with its `manifest.yaml`.
//! **Adding an app means adding a folder. No recompilation.**

pub mod themes;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use hlb_types::Manifest;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("catalog not found: {0}")]
    NotFound(PathBuf),

    #[error("reading {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("{path}: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: hlb_types::Error,
    },

    #[error("{path}: declared name \"{declared}\" does not match folder \"{dir}\"")]
    NameMismatch {
        path: PathBuf,
        declared: String,
        dir: String,
    },

    #[error("app \"{0}\" is not in the catalog")]
    UnknownApp(String),
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Default)]
pub struct Catalog {
    entries: BTreeMap<String, Entry>,
}

#[derive(Debug, Clone)]
pub struct Entry {
    pub manifest: Manifest,
    pub path: PathBuf,
    /// The neighbouring `guide.yaml`, if there is one. An app without a guide simply
    /// has none; that is not an error.
    pub guide: hlb_types::Guide,
}

impl Catalog {
    /// Recursively loads every `manifest.yaml` under `root`.
    ///
    /// Folders starting with `_` (such as `_platform`) are walked but are not apps
    /// themselves: they group, they do not declare.
    pub fn load(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref();
        if !root.is_dir() {
            return Err(Error::NotFound(root.to_path_buf()));
        }

        let mut entries = BTreeMap::new();
        collect(root, &mut entries)?;
        Ok(Self { entries })
    }

    pub fn get(&self, name: &str) -> Result<&Entry> {
        self.entries
            .get(name)
            .ok_or_else(|| Error::UnknownApp(name.to_string()))
    }

    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.entries.keys().map(|s| s.as_str())
    }

    pub fn entries(&self) -> impl Iterator<Item = &Entry> {
        self.entries.values()
    }

    pub fn manifests(&self) -> Vec<Manifest> {
        self.entries.values().map(|e| e.manifest.clone()).collect()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Validates every manifest and returns **all** the errors, not just the first:
    /// when repairing a catalog you want the whole list.
    pub fn validate_all(&self) -> Vec<(String, hlb_types::Error)> {
        let mut errs: Vec<_> = self
            .entries
            .iter()
            .filter_map(|(name, e)| {
                hlb_types::validate(&e.manifest)
                    .and_then(|()| hlb_types::validate_guide(&e.manifest, &e.guide))
                    // 🔴 What the catalog holds to beyond any manifest. Written in phase 7
                    // and called by nothing but its own tests until 2026-10-19: the
                    // digest it was said to require was never required.
                    .and_then(|()| hlb_types::validate_catalog_images(&e.manifest))
                    .and_then(|()| hlb_types::validate_catalog_memory(&e.manifest))
                    .and_then(|()| catalog_rules(e))
                    .err()
                    .map(|err| (name.clone(), err))
            })
            .collect();
        errs.extend(self.shared_claims());
        errs
    }

    /// A custom claim two apps write. PocketID gives a group's claims to every app its
    /// members sign in to: with two writers, the role's group carries one value and
    /// one of the apps reads the other's.
    fn shared_claims(&self) -> Vec<(String, hlb_types::Error)> {
        let mut writer: BTreeMap<&str, &str> = BTreeMap::new();
        let mut errs = Vec::new();
        for (name, e) in &self.entries {
            let Some(a) = &e.manifest.spec.access else {
                continue;
            };
            let quota = a.quota.as_ref().and_then(|q| q.claim.as_ref());
            for claim in a.claims.keys().chain(quota.map(|q| &q.name)) {
                if let Some(other) = writer.insert(claim, name) {
                    errs.push((
                        name.clone(),
                        hlb_types::Error::Validation(format!(
                            "{name}: access — claim \"{claim}\" is {other}'s too: every app \
                             a person signs in to sees it, so one would read the other's value"
                        )),
                    ));
                }
            }
        }
        errs
    }
}

/// What an entry is held to beyond what a manifest alone is: each a way an install
/// would fail late, or a declaration nobody would read.
fn catalog_rules(e: &Entry) -> hlb_types::Result<()> {
    let m = &e.manifest;
    let name = &m.metadata.name;
    let refuse = |why: String| Err(hlb_types::Error::Validation(format!("{name}: {why}")));
    for c in &m.spec.requires {
        // 🔴 Created with `CREATE EXTENSION`, which only PostgreSQL has: declared on
        // MariaDB, the install failed at the step, after the app was recorded.
        if let hlb_types::Capability::Database {
            engine: hlb_types::DbEngine::Mariadb,
            name: _,
            extensions,
        } = c
        {
            if !extensions.is_empty() {
                return refuse(format!(
                    "a MariaDB database takes no extensions ({}) — only PostgreSQL has them",
                    extensions.join(", ")
                ));
            }
        }
        // Deployed from `valkey:latest`, which no digest pins: refused mid-install as
        // unpinned. The shared Valkey serves every app.
        if let hlb_types::Capability::Cache {
            engine: _,
            dedicated: true,
        } = c
        {
            return refuse(
                "a dedicated cache runs an image nothing pins — use the shared one \
                 (`dedicated: false`)"
                    .into(),
            );
        }
    }
    let tiers = std::iter::once(m.spec.swarm.tier.as_deref())
        .chain(m.spec.companions.iter().map(|c| c.tier.as_deref()))
        .flatten();
    for t in tiers {
        if !hlb_types::manifest::TIERS.contains(&t) {
            return refuse(format!(
                "tier \"{t}\" is no node's — one of {}: placed nowhere, the install would \
                 time out on \"no suitable node\"",
                hlb_types::manifest::TIERS.join(", ")
            ));
        }
    }
    // 🔴 A template a guide uses that nothing fills reaches Swarm, which reads `{{ … }}`
    // as its own and refuses the service — LibreSpeed's `{{ base_domain }}` did. A
    // `{{ secret.* }}` there is refused too: the resolver plans no secret for it, and
    // the variable would reach the app literal.
    for step in &e.guide.steps {
        let mut texts = vec![step.title.as_str(), step.body.as_str()];
        texts.extend(step.deeplink.as_deref());
        for a in &step.automate {
            if let hlb_types::Automation::Env { vars } = a {
                texts.extend(vars.values().map(String::as_str));
            }
        }
        for t in texts {
            for (i, _) in t.match_indices("{{") {
                let token = t[i + 2..].split("}}").next().unwrap_or("").trim();
                if !hlb_resolver::GUIDE_VARS.contains(&token) {
                    return refuse(format!(
                        "guide step \"{}\" uses {{{{ {token} }}}}, which nothing fills — a \
                         guide's templates are {}",
                        step.id,
                        hlb_resolver::GUIDE_VARS.join(", ")
                    ));
                }
            }
        }
    }
    Ok(())
}

fn collect(dir: &Path, out: &mut BTreeMap<String, Entry>) -> Result<()> {
    let rd = std::fs::read_dir(dir).map_err(|source| Error::Io {
        path: dir.to_path_buf(),
        source,
    })?;

    for entry in rd {
        let entry = entry.map_err(|source| Error::Io {
            path: dir.to_path_buf(),
            source,
        })?;
        let path = entry.path();

        if path.is_dir() {
            collect(&path, out)?;
            continue;
        }

        if path.file_name().is_some_and(|f| f == "manifest.yaml") {
            let e = load_one(&path)?;
            out.insert(e.manifest.metadata.name.clone(), e);
        }
    }
    Ok(())
}

fn load_one(path: &Path) -> Result<Entry> {
    let raw = std::fs::read_to_string(path).map_err(|source| Error::Io {
        path: path.to_path_buf(),
        source,
    })?;

    let manifest: Manifest = serde_yaml_ng::from_str(&raw).map_err(|e| Error::Parse {
        path: path.to_path_buf(),
        source: hlb_types::Error::Parse(e),
    })?;

    // The folder name is authoritative. Without this, two apps declaring the same
    // `metadata.name` would silently overwrite each other.
    let dir = path
        .parent()
        .and_then(|p| p.file_name())
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();

    if dir != manifest.metadata.name {
        return Err(Error::NameMismatch {
            path: path.to_path_buf(),
            declared: manifest.metadata.name.clone(),
            dir,
        });
    }

    // The guide lives next to the manifest. Absent means no declared step.
    let guide_path = path.with_file_name("guide.yaml");
    let guide = if guide_path.exists() {
        let raw = std::fs::read_to_string(&guide_path).map_err(|source| Error::Io {
            path: guide_path.clone(),
            source,
        })?;
        serde_yaml_ng::from_str(&raw).map_err(|e| Error::Parse {
            path: guide_path,
            source: hlb_types::Error::Parse(e),
        })?
    } else {
        hlb_types::Guide::default()
    };

    Ok(Entry {
        manifest,
        path: path.to_path_buf(),
        guide,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repo_catalog() -> PathBuf {
        // CARGO_MANIFEST_DIR = crates/hlb-catalog
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("catalog")
    }

    #[test]
    fn loads_the_bundled_catalog() {
        let c = Catalog::load(repo_catalog()).expect("catalog should load");
        assert!(c.len() >= 6, "{} entries found", c.len());
        for expected in [
            "postgres",
            "valkey",
            "pocket-id",
            "gitea",
            "vikunja",
            "vaultwarden",
        ] {
            assert!(c.get(expected).is_ok(), "{expected} missing");
        }
    }

    #[test]
    fn bundled_catalog_is_valid() {
        let c = Catalog::load(repo_catalog()).expect("catalog should load");
        let errs = c.validate_all();
        assert!(errs.is_empty(), "invalid manifests: {errs:?}");
    }

    #[test]
    fn two_apps_never_write_the_same_claim() {
        let app = |name: &str| {
            let y = format!(
                "apiVersion: hlb/v1\nkind: App\nmetadata: {{ name: {name} }}\nspec:\n  \
                 image: {{ repo: a/{name}, tag: \"1\", digest: \"sha256:{d}\" }}\n  \
                 swarm: {{ memory: {{ reserve: 64M, limit: 128M }} }}\n  env: {{ ID: \"{{{{ oidc.client_id }}}}\" }}\n  \
                 requires: [ {{ kind: sso, mode: native, redirectPaths: [/cb] }} ]\n  \
                 access: {{ claims: {{ app_role: {{ byLevel: {{ user: user }} }} }} }}\n",
                d = "0".repeat(64)
            );
            Entry {
                manifest: serde_yaml_ng::from_str(&y).expect("manifest"),
                path: PathBuf::new(),
                guide: hlb_types::Guide::default(),
            }
        };
        let one = Catalog {
            entries: [("a".to_string(), app("a"))].into(),
        };
        assert!(one.validate_all().is_empty(), "{:?}", one.validate_all());
        let two = Catalog {
            entries: [("a".to_string(), app("a")), ("b".to_string(), app("b"))].into(),
        };
        let errs = two.validate_all();
        assert!(
            errs.iter().any(|(_, e)| e.to_string().contains("a's too")),
            "{errs:?}"
        );
    }

    #[test]
    fn the_catalog_refuses_an_image_without_its_digest_and_a_service_without_memory() {
        let entry = |y: &str| Entry {
            manifest: serde_yaml_ng::from_str(y).expect("manifest"),
            path: PathBuf::new(),
            guide: hlb_types::Guide::default(),
        };
        let d = "0".repeat(64);
        let whole = format!(
            "apiVersion: hlb/v1\nkind: App\nmetadata: {{ name: a }}\nspec:\n  \
             image: {{ repo: a/a, tag: \"1\", digest: \"sha256:{d}\" }}\n  \
             swarm: {{ memory: {{ reserve: 64M, limit: 128M }} }}\n"
        );
        let refused = |y: &str| {
            Catalog {
                entries: [("a".to_string(), entry(y))].into(),
            }
            .validate_all()
            .into_iter()
            .map(|(_, e)| e.to_string())
            .collect::<Vec<_>>()
        };
        assert_eq!(refused(&whole), Vec::<String>::new());
        let unpinned = whole.replace(&format!(", digest: \"sha256:{d}\""), "");
        assert!(refused(&unpinned)[0].contains("no digest"), "{unpinned}");
        let unbounded = whole.replace("  swarm: { memory: { reserve: 64M, limit: 128M } }\n", "");
        assert!(refused(&unbounded)[0].contains("no memory"), "{unbounded}");
        let backwards = whole.replace("reserve: 64M, limit: 128M", "reserve: 1G, limit: 128M");
        assert!(
            refused(&backwards)[0].contains("reserves 1G"),
            "{backwards}"
        );
    }

    #[test]
    fn bundled_catalog_has_no_dependency_cycle() {
        let c = Catalog::load(repo_catalog()).expect("catalog should load");
        let g = hlb_resolver::DependencyGraph::from_manifests(&c.manifests());
        let order = g.deployment_order().expect("order should be computable");

        let pos = |n: &str| order.iter().position(|x| x == n).expect("present");
        // Platform services must come before their consumers.
        assert!(pos("postgres") < pos("gitea"));
        assert!(pos("pocket-id") < pos("vaultwarden"));
    }

    #[test]
    fn a_guide_template_names_only_what_the_resolver_fills() {
        // 🔴 LibreSpeed's guide set `TITLE: "Throughput — {{ base_domain }}"`, which
        // nothing filled: Swarm read it as one of its own templates and refused the
        // service. The rule lived in this test alone until it moved into
        // `validate_all` — a validator nobody calls validates nothing.
        let c = Catalog::load(repo_catalog()).expect("catalog should load");
        let seen: usize = c
            .entries()
            .flat_map(|e| &e.guide.steps)
            .map(|s| s.body.matches("{{").count())
            .sum();
        assert!(
            seen > 10,
            "only {seen} templates — is the walk reading the guides?"
        );
        let mut entry = c.get("librespeed").expect("librespeed").clone();
        let refused = |e: &Entry| {
            Catalog {
                entries: [(e.manifest.metadata.name.clone(), e.clone())].into(),
            }
            .validate_all()
            .into_iter()
            .map(|(_, e)| e.to_string())
            .collect::<Vec<_>>()
        };
        assert_eq!(refused(&entry), Vec::<String>::new());
        for wrong in ["{{ zone }}", "{{ secret.admin-password }}"] {
            entry.guide.steps[0].body = format!("set {wrong}");
            let r = refused(&entry);
            assert!(r.len() == 1 && r[0].contains("nothing fills"), "{r:?}");
        }
    }

    #[test]
    fn a_step_holding_back_a_route_is_never_verified_by_the_app_being_healthy() {
        // 🔴 Immich's "create the administrator" was verified by `/api/server/ping`:
        // `hlb todo --verify` opened its `after-guide` route as soon as Immich ran,
        // while the first stranger to register would have become its administrator.
        let c = Catalog::load(repo_catalog()).expect("catalog should load");
        let held: Vec<(&str, &hlb_types::GuideStep)> = c
            .entries()
            .flat_map(|e| {
                e.guide
                    .steps
                    .iter()
                    .map(move |s| (e.manifest.metadata.name.as_str(), s))
            })
            .filter(|(_, s)| s.is_blocking() && s.phase != hlb_types::Phase::PreInstall)
            .collect();
        assert!(
            held.len() >= 8,
            "only {} blocking post-install steps — is the walk reading the guides?",
            held.len()
        );
        for (app, s) in &held {
            if let hlb_types::Verify::Http {
                expect_status,
                expect_json: None,
                ..
            } = &s.verify
            {
                assert!(
                    expect_status.iter().all(|c| !(200..300).contains(c)),
                    "{app}/{}: a 2xx alone says the app runs, not that the step is done",
                    s.id
                );
            }
        }

        let mut immich = c.get("immich").expect("immich").clone();
        let refused = |e: &Entry| {
            Catalog {
                entries: [("immich".to_string(), e.clone())].into(),
            }
            .validate_all()
            .into_iter()
            .map(|(_, e)| e.to_string())
            .collect::<Vec<_>>()
        };
        assert_eq!(refused(&immich), Vec::<String>::new());
        let step = immich
            .guide
            .steps
            .iter_mut()
            .find(|s| s.id == "first-account")
            .expect("first-account");
        step.verify = hlb_types::Verify::Http {
            url: "https://{{ domain }}/api/server/ping".into(),
            expect_status: vec![200],
            expect_json: None,
        };
        let r = refused(&immich);
        assert!(r.len() == 1 && r[0].contains("expectJson"), "{r:?}");
    }

    #[test]
    fn the_catalog_refuses_what_an_install_would_fail_on_late() {
        let c = Catalog::load(repo_catalog()).expect("catalog should load");
        let base = c.get("valkey").expect("valkey").clone();
        let refused = |e: &Entry| {
            Catalog {
                entries: [("valkey".to_string(), e.clone())].into(),
            }
            .validate_all()
            .into_iter()
            .map(|(_, e)| e.to_string())
            .collect::<Vec<_>>()
        };
        assert_eq!(refused(&base), Vec::<String>::new());

        let mut tier = base.clone();
        tier.manifest.spec.swarm.tier = Some("hevay".into());
        assert!(
            refused(&tier)[0].contains("no node's"),
            "{:?}",
            refused(&tier)
        );

        let mut maria = base.clone();
        maria
            .manifest
            .spec
            .requires
            .push(hlb_types::Capability::Database {
                engine: hlb_types::DbEngine::Mariadb,
                name: None,
                extensions: vec!["vector".into()],
            });
        maria
            .manifest
            .spec
            .env
            .insert("DB".into(), "{{ db.url }}".into());
        assert!(
            refused(&maria)[0].contains("no extensions"),
            "{:?}",
            refused(&maria)
        );

        let mut cache = base;
        cache
            .manifest
            .spec
            .requires
            .push(hlb_types::Capability::Cache {
                engine: hlb_types::CacheEngine::Valkey,
                dedicated: true,
            });
        cache
            .manifest
            .spec
            .env
            .insert("CACHE".into(), "{{ cache.url }}".into());
        assert!(
            refused(&cache)[0].contains("dedicated cache"),
            "{:?}",
            refused(&cache)
        );
    }

    #[test]
    fn the_ingress_runs_the_image_this_release_builds() {
        // `hlb-caddy` is built from this repository's Dockerfile and published under
        // the workspace's version: a catalog naming another one would pull an image
        // with modules that do not match the Caddyfile this code generates — or none.
        let c = Catalog::load(repo_catalog()).expect("catalog should load");
        let m = &c
            .get(hlb_types::manifest::INGRESS_SERVICE)
            .expect("the ingress is in the catalog")
            .manifest;
        assert!(
            m.spec.image.repo.ends_with("/hlb-caddy"),
            "{}",
            m.spec.image.repo
        );
        assert_eq!(m.spec.image.tag, env!("CARGO_PKG_VERSION"));
        assert_eq!(
            m.spec.swarm.node_label.as_deref(),
            Some(hlb_types::manifest::INGRESS_NODE_LABEL),
            "the router forwards to one machine: Caddy must run there"
        );
    }

    #[test]
    fn anubis_sends_back_to_the_listener_caddy_opens_for_it() {
        // One target for every app behind it: Caddy's return listener. Moved on one
        // side only, every visitor who passed the challenge would meet a closed port.
        let c = Catalog::load(repo_catalog()).expect("catalog should load");
        let m = &c.get("anubis").expect("anubis in the catalog").manifest;
        assert_eq!(
            m.spec.env.get("TARGET").map(String::as_str),
            Some(
                format!(
                    "http://{}:{}",
                    hlb_types::manifest::INGRESS_SERVICE,
                    hlb_ingress::caddyfile::ANUBIS_RETURN_PORT
                )
                .as_str()
            )
        );
    }

    /// Seafile's pools stay under the shared MariaDB's limit: two of `max_connections`
    /// in seaf-server, 16 in its Go file server, and room for seahub, seafevents and
    /// the notification server (`seaf-utils.c`, `fileserver.go`, 13.0). At Seafile's
    /// default of 100 it was past MariaDB's 151 alone.
    #[test]
    fn seafile_cannot_exhaust_the_shared_mariadb() {
        let c = Catalog::load(repo_catalog()).expect("catalog should load");
        let mariadb = &c.get("mariadb").expect("mariadb").manifest;
        // MariaDB's own default, unless its manifest sets one.
        let limit = mariadb
            .spec
            .command
            .iter()
            .find_map(|a| a.strip_prefix("--max-connections="))
            .map_or(151, |n| n.parse::<u32>().expect("a number"));
        let seafile = &c.get("seafile").expect("seafile").manifest;
        let script = seafile
            .spec
            .files
            .iter()
            .find(|f| f.path.ends_with("seafile-conf.py"))
            .expect("the configuration Seafile is given");
        let pool: u32 = script
            .content
            .split("\"max_connections\": \"")
            .nth(1)
            .and_then(|r| r.split('"').next())
            .and_then(|n| n.parse().ok())
            .expect("max_connections set");
        let others = 16 + 20;
        assert!(
            2 * pool + others < limit,
            "2 × {pool} + {others} against MariaDB's {limit}"
        );
    }

    /// Fluxer's pools stay a quarter of the shared PostgreSQL's limit: its compose
    /// gives the api, the worker, `users` and `messages` 25 + 25 + 20 + 20 — 90 of the
    /// server's 100, which every app shares.
    #[test]
    fn fluxer_cannot_exhaust_the_shared_postgres() {
        let c = Catalog::load(repo_catalog()).expect("catalog should load");
        let postgres = &c.get("postgres").expect("postgres").manifest;
        let limit = postgres
            .spec
            .command
            .iter()
            .find_map(|a| a.strip_prefix("max_connections="))
            .map_or(100, |n| n.parse::<u32>().expect("a number"));
        let fluxer = &c.get("fluxer").expect("fluxer").manifest;
        // The services that connect (`fluxer_svc/src/postgres.rs`, the api's
        // `APILifecycle`): each must say its pool, or it takes Fluxer's default.
        let mut sum = 0;
        for name in ["api", "worker", "users", "messages"] {
            let companion = fluxer
                .spec
                .companions
                .iter()
                .find(|x| x.name == name)
                .unwrap_or_else(|| panic!("{name} is a companion"));
            let pool: u32 = companion
                .environment(&fluxer.spec)
                .get("FLUXER_POSTGRES_MAX_CONNECTIONS")
                .unwrap_or_else(|| panic!("{name} says its pool"))
                .parse()
                .expect("a number");
            sum += pool;
        }
        assert!(
            sum * 4 <= limit,
            "{sum} connections against PostgreSQL's {limit}"
        );
    }

    /// What Fluxer's api writes into its own database at every start: JSON once its
    /// tokens are filled, sign-in through PocketID required, and nobody signing up.
    #[test]
    fn fluxer_is_configured_for_pocketid_alone() {
        let c = Catalog::load(repo_catalog()).expect("catalog should load");
        let fluxer = &c.get("fluxer").expect("fluxer").manifest;
        let api = fluxer
            .spec
            .companions
            .iter()
            .find(|x| x.name == "api")
            .expect("the api");
        let file = |path: &str| {
            api.files
                .iter()
                .find(|f| f.path == path)
                .unwrap_or_else(|| panic!("{path}"))
                .content
                .clone()
        };
        let instance = file("/run/hlb/fluxer-instance.json")
            .replace("{{ oidc.issuer }}", "https://id.example.org")
            .replace("{{ oidc.client_id }}", "id")
            // Homelabus's secrets are alphanumeric: nothing in them closes a string.
            .replace("{{ oidc.client_secret }}", "Zk3vQ9");
        let v: serde_json::Value = serde_json::from_str(&instance).expect("JSON");
        assert_eq!(v["sso"]["enabled"], true);
        assert_eq!(
            v["sso"]["enforced"], true,
            "a password would open past PocketID"
        );
        assert_eq!(
            v["sso"]["auto_provision"], true,
            "PocketID's people get an account"
        );
        assert_eq!(v["registration"]["mode"], "closed");
        // The scripts read the files where the manifest writes them.
        let start = file("/run/hlb/fluxer-start.mjs");
        assert!(start.contains("/run/hlb/fluxer-instance.json"));
        assert!(file("/run/hlb/fluxer-admin.mjs").contains("/run/hlb/fluxer-instance.json"));
        // The probe waits for the mark the start script writes.
        let mark = "/tmp/hlb-configured";
        assert!(start.contains(mark));
        assert!(api
            .healthcheck
            .as_ref()
            .expect("a probe")
            .test
            .iter()
            .any(|t| t.contains(mark)));
        // The setup screen never opens: its token would make the first administrator.
        assert_eq!(
            fluxer
                .spec
                .shared_env
                .get("FLUXER_INSTANCE_SETUP_CONFIGURED")
                .map(String::as_str),
            Some("true")
        );
        // 🔴 And the admin bootstrap is closed, which the setting above does not do: its
        // token stayed valid after an administrator was made (the lab) — none is written
        // in the log either, the api's own being the vault's.
        assert_eq!(v["app_public"]["setup"]["configured"], true);
        // Fluxer's default deletes a 500 MB attachment after fourteen days.
        assert_eq!(
            v["media"]["attachment_decay"]["enabled"], false,
            "nothing a household sends disappears by itself"
        );
        assert!(api
            .env
            .get("FLUXER_SETUP_TOKEN")
            .is_some_and(|t| t.starts_with("{{ secret.")));
    }

    #[test]
    fn vaultwarden_is_never_auto_updated() {
        // Vaultwarden is the emergency access to everything else: an automatic update
        // that broke it would lock you out of your own recovery path.
        let c = Catalog::load(repo_catalog()).expect("catalog should load");
        let vw = c.get("vaultwarden").expect("vaultwarden present");
        assert_eq!(
            vw.manifest.spec.update.channel,
            hlb_types::UpdateChannel::Pin
        );
    }

    #[test]
    fn guides_are_loaded_alongside_manifests() {
        let c = Catalog::load(repo_catalog()).expect("catalog should load");
        let gitea = c.get("gitea").expect("gitea present");
        assert!(
            !gitea.guide.steps.is_empty(),
            "gitea should declare its manual steps"
        );
    }

    #[test]
    fn an_app_without_a_guide_is_fine() {
        let c = Catalog::load(repo_catalog()).expect("catalog should load");
        // valkey has nothing that must be done by hand.
        assert!(c.get("valkey").expect("present").guide.steps.is_empty());
    }

    #[test]
    fn every_guide_step_has_a_unique_id() {
        // Two steps sharing an id would overwrite each other in the pending queue.
        let c = Catalog::load(repo_catalog()).expect("catalog should load");
        for e in c.entries() {
            let mut seen = std::collections::BTreeSet::new();
            for s in &e.guide.steps {
                assert!(
                    seen.insert(&s.id),
                    "{}: duplicate step id \"{}\"",
                    e.manifest.metadata.name,
                    s.id
                );
            }
        }
    }

    #[test]
    fn guide_dependencies_point_to_existing_steps() {
        let c = Catalog::load(repo_catalog()).expect("catalog should load");
        for e in c.entries() {
            let ids: std::collections::BTreeSet<_> =
                e.guide.steps.iter().map(|s| s.id.as_str()).collect();
            for s in &e.guide.steps {
                for dep in &s.after {
                    assert!(
                        ids.contains(dep.as_str()),
                        "{}: \"{}\" depends on \"{dep}\", which does not exist",
                        e.manifest.metadata.name,
                        s.id
                    );
                }
            }
        }
    }

    /// 🔴 `sso: native` creates the client in PocketID and its secret in the vault;
    /// nothing hands them to the app unless its manifest does. Vikunja declared it for
    /// months and configured nothing: its sign-in through PocketID never existed, and
    /// the client PocketID held answered nobody.
    #[test]
    fn an_app_signing_in_natively_is_given_its_client() {
        // Gitea, Immich and Termix were listed here as not wired, until 2026-10-18:
        // none is exempt now.
        let c = Catalog::load(repo_catalog()).expect("catalog should load");
        let mut native = 0;
        for e in c.entries() {
            let m = &e.manifest;
            let signs_in = m.spec.requires.iter().any(|r| {
                matches!(
                    r,
                    hlb_types::Capability::Sso {
                        mode: hlb_types::SsoMode::Native,
                        redirect_paths: _,
                    }
                )
            });
            if !signs_in {
                continue;
            }
            native += 1;
            let given = m
                .spec
                .substituted()
                .any(|v| v.contains("{{ oidc.client_id }}"));
            assert!(
                given,
                "{}: signs in through PocketID and is never told its client",
                m.metadata.name
            );
        }
        // The walk found the native apps, or it proved nothing.
        assert!(native >= 7, "only {native} apps sign in natively");
    }

    #[test]
    fn missing_catalog_is_reported_clearly() {
        let err = Catalog::load("/does/not/exist").unwrap_err();
        assert!(matches!(err, Error::NotFound(_)), "{err}");
    }
}
