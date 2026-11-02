//! Catalog loading and validation.
//!
//! A catalog is a folder of folders, one per app, each with its `manifest.yaml`.
//! **Adding an app means adding a folder. No recompilation.**

pub mod index;
pub mod themes;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use hlb_types::release::Version;
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

    /// In the catalog, for another `hlb`: its range leaves this one out.
    #[error("{why}")]
    SetAside { app: String, why: String },

    #[error(
        "\"{0}\" is no source name — lower-case letters, digits and dashes, 32 at most, \
         starting with a letter or a digit"
    )]
    SourceName(String),

    #[error("source \"{0}\" is added already")]
    SourceTaken(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Between a third-party source's name and its app's.
pub const SEPARATOR: char = '/';

/// The name an app is found under in a catalog holding several sources.
pub fn qualified(source: Option<&str>, app: &str) -> String {
    match source {
        Some(s) => format!("{s}{SEPARATOR}{app}"),
        None => app.to_string(),
    }
}

/// A source's name: what an app's catalog name carries, and a directory's.
pub fn is_source_name(name: &str) -> bool {
    let mut chars = name.chars();
    name.len() <= 32
        && chars
            .next()
            .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

#[derive(Debug, Default, Clone)]
pub struct Catalog {
    entries: BTreeMap<String, Entry>,
    /// The apps whose `metadata.hlb` leaves this `hlb` out, and why — read no further,
    /// since a field this build does not know would refuse the whole catalog.
    set_aside: BTreeMap<String, String>,
    /// The versions each signed source withdrew, under the name the app is found by:
    /// kept whether or not the source still offers the app, since a house may run one.
    revoked: BTreeMap<String, Vec<hlb_types::index::Revoked>>,
}

#[derive(Debug, Clone)]
pub struct Entry {
    /// The source it came from; `None` for the official catalog, whose apps keep their
    /// bare names. A third-party app is `<source>/<app>`, so it never shadows one.
    pub source: Option<String>,
    /// The counter of the signed index it came from, frozen with the install.
    pub index: Option<u64>,
    /// Its version in that index — what a revocation names.
    pub version: Option<String>,
    pub manifest: Manifest,
    pub path: PathBuf,
    /// The neighbouring `guide.yaml`, if there is one. An app without a guide simply
    /// has none; that is not an error.
    pub guide: hlb_types::Guide,
    /// The manifest and the guide as written, for the schema of an older release:
    /// parsed and written again, they would carry every default this build adds.
    written: (serde_json::Value, serde_json::Value),
}

impl Entry {
    /// The name it is found under: `<source>/<app>` for a third-party source.
    pub fn name(&self) -> String {
        qualified(self.source.as_deref(), &self.manifest.metadata.name)
    }
}

impl Catalog {
    /// Recursively loads every `manifest.yaml` under `root`.
    ///
    /// Folders starting with `_` (such as `_platform`) are walked but are not apps
    /// themselves: they group, they do not declare.
    pub fn load(root: impl AsRef<Path>) -> Result<Self> {
        Self::load_as(root, &hlb_types::release::running())
    }

    /// The catalog as `release` reads it: an app whose range leaves it out is set aside.
    pub fn load_as(root: impl AsRef<Path>, release: &Version) -> Result<Self> {
        let root = root.as_ref();
        if !root.is_dir() {
            return Err(Error::NotFound(root.to_path_buf()));
        }

        let mut catalog = Self::default();
        collect(root, release, &mut catalog)?;
        Ok(catalog)
    }

    /// Adds a third-party source's apps, each under `<source>/<app>`. A source that
    /// cannot be read leaves the catalog as it was: the official apps never go with it.
    ///
    /// 🔴 A third-party source may REQUIRE a capability, never PROVIDE one. The graph
    /// finds a capability's provider by its bare name (`postgres`, `pocket-id`), and a
    /// third-party app installs under its bare name: one called `postgres` would be the
    /// database every app's credentials go to. So a platform service, or an app named
    /// like one of the official catalog's, is set aside here.
    pub fn add_source(&mut self, source: &str, root: impl AsRef<Path>) -> Result<()> {
        if !is_source_name(source) {
            return Err(Error::SourceName(source.to_string()));
        }
        let prefix = format!("{source}{SEPARATOR}");
        if self
            .entries
            .keys()
            .chain(self.set_aside.keys())
            .any(|k| k.starts_with(&prefix))
        {
            return Err(Error::SourceTaken(source.to_string()));
        }
        let theirs = Self::load(root)?;
        self.merge(source, theirs);
        Ok(())
    }

    /// Adds a source whose directory holds a signed index (`index::verify`): for each
    /// app, the newest version this `hlb`'s range accepts.
    ///
    /// 🔴 An expired index sets every app of the source aside: nothing new is installed
    /// or upgraded from it. What runs is not touched — an installed app redeploys from
    /// its frozen manifest — and an upgrade waits for a fresh index.
    pub fn add_signed_source(
        &mut self,
        source: &str,
        dir: impl AsRef<Path>,
        key: &str,
        now: i64,
    ) -> std::result::Result<(), index::Error> {
        let dir = dir.as_ref();
        if !is_source_name(source) {
            return Err(Error::SourceName(source.to_string()).into());
        }
        let idx = index::verify(dir, source, key)?;
        let release = hlb_types::release::running();
        let mut theirs = Self::default();
        let expired = index::current(&idx, now).err();
        for (app, versions) in &idx.apps {
            if let Some(e) = &expired {
                theirs.set_aside.insert(
                    app.clone(),
                    format!(
                        "the index of \"{source}\" is out of date ({e}) — nothing new is \
                         installed from it until `hlb catalog source fetch {source}` \
                         brings a fresh one"
                    ),
                );
                continue;
            }
            let Some(v) = idx.newest_for(app, &release) else {
                // Its range accepts this hlb and the source withdrew it: the why is
                // the source's, and says what to do.
                if let Some(why) = versions.iter().rev().find_map(|v| {
                    hlb_types::release::accepts(&v.hlb, &release)
                        .unwrap_or(false)
                        .then(|| idx.revocation(app, &v.version))
                        .flatten()
                }) {
                    theirs.set_aside.insert(
                        app.clone(),
                        format!("every version of \"{app}\" this hlb runs is revoked: {why}"),
                    );
                    continue;
                }
                let ranges: Vec<&str> = versions.iter().map(|v| v.hlb.as_str()).collect();
                theirs.set_aside.insert(
                    app.clone(),
                    format!(
                        "\"{app}\" has no version for hlb {release} (theirs need {}) — update hlb \
                         to install it",
                        ranges.join(", ")
                    ),
                );
                continue;
            };
            let path = dir
                .join(hlb_types::index::version_dir(app, &v.version))
                .join("manifest.yaml");
            match load_one(&path, &release, Some(app))? {
                Loaded::Entry(mut e) => {
                    e.index = Some(idx.counter);
                    e.version = Some(v.version.clone());
                    theirs.entries.insert(app.clone(), *e);
                }
                Loaded::SetAside { app, why } => {
                    theirs.set_aside.insert(app, why);
                }
            }
        }
        theirs.revoked = idx.revoked;
        self.merge(source, theirs);
        Ok(())
    }

    /// A third-party source's apps, under `<source>/<app>`, held to what such a source
    /// may hold.
    fn merge(&mut self, source: &str, theirs: Self) {
        let prefix = format!("{source}{SEPARATOR}");
        let platform: Vec<String> = self
            .entries
            .values()
            .filter(|e| e.source.is_none() && e.manifest.kind == hlb_types::Kind::PlatformService)
            .map(|e| e.manifest.metadata.name.clone())
            .collect();
        for (app, why) in theirs.set_aside {
            self.set_aside.insert(format!("{prefix}{app}"), why);
        }
        for (app, revoked) in theirs.revoked {
            self.revoked.insert(format!("{prefix}{app}"), revoked);
        }
        for (app, mut e) in theirs.entries {
            let key = format!("{prefix}{app}");
            let refused = if e.manifest.kind == hlb_types::Kind::PlatformService {
                Some(format!(
                    "\"{key}\" is a platform service: a source other than the official \
                     catalog may require a capability, never provide one"
                ))
            } else if platform.contains(&app) {
                Some(format!(
                    "\"{key}\" is named like the official platform service \"{app}\", whose \
                     place it would take for every app that requires it"
                ))
            } else {
                None
            };
            match refused {
                Some(why) => {
                    self.set_aside.insert(key, why);
                }
                None => {
                    e.source = Some(source.to_string());
                    self.entries.insert(key, e);
                }
            }
        }
    }

    /// The entry an installed app follows: its own source's, never another's of the
    /// same name.
    pub fn followed(&self, app: &str, source: Option<&str>) -> Result<&Entry> {
        self.get(&qualified(source, app))
    }

    /// Why its source revoked `version` of an installed app, if it did.
    pub fn revocation(&self, app: &str, source: Option<&str>, version: &str) -> Option<&str> {
        self.revoked
            .get(&qualified(source, app))?
            .iter()
            .find(|r| r.version == version)
            .map(|r| r.why.as_str())
    }

    pub fn get(&self, name: &str) -> Result<&Entry> {
        if let Some(why) = self.set_aside.get(name) {
            return Err(Error::SetAside {
                app: name.to_string(),
                why: why.clone(),
            });
        }
        self.entries
            .get(name)
            .ok_or_else(|| Error::UnknownApp(name.to_string()))
    }

    /// The apps in the catalog for another `hlb`, and why each is left out.
    pub fn left_out(&self) -> impl Iterator<Item = (&str, &str)> {
        self.set_aside.iter().map(|(n, w)| (n.as_str(), w.as_str()))
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
        // A catalog is validated by the `hlb` meant to run all of it.
        let mut errs: Vec<_> = self
            .set_aside
            .iter()
            .map(|(name, why)| (name.clone(), hlb_types::Error::Validation(why.clone())))
            .collect();
        let release = hlb_types::release::running();
        errs.extend(self.entries.iter().filter_map(|(name, e)| {
            release_rules(e, &release)
                .err()
                .map(|err| (name.clone(), err))
        }));
        errs.extend(self.entries.iter().filter_map(|(name, e)| {
            hlb_types::validate_with_guide(&e.manifest, &e.guide)
                .and_then(|()| hlb_types::validate_guide(&e.manifest, &e.guide))
                // 🔴 What the catalog holds to beyond any manifest. Written in phase 7
                // and called by nothing but its own tests until 2026-10-19: the
                // digest it was said to require was never required.
                .and_then(|()| hlb_types::validate_catalog_images(&e.manifest))
                .and_then(|()| hlb_types::validate_catalog_memory(&e.manifest))
                .and_then(|()| catalog_rules(e))
                .err()
                .map(|err| (name.clone(), err))
        }));
        errs.extend(self.shared_claims());
        errs.extend(self.connection_budgets());
        errs
    }

    /// Every app's connections against its shared server's limit, all installed at
    /// once — and the largest twice over, being updated: its new task opens a pool
    /// before the old one closes its own.
    ///
    /// 🔴 Two tests each held ONE app to a share of its server, and nothing summed
    /// them; one of them read the limit from where the manifest no longer set it.
    fn connection_budgets(&self) -> Vec<(String, hlb_types::Error)> {
        let mut errs = Vec::new();
        for engine in [hlb_types::DbEngine::Postgres, hlb_types::DbEngine::Mariadb] {
            // Exhaustive: an engine added to `DbEngine` must be added above.
            match engine {
                hlb_types::DbEngine::Postgres | hlb_types::DbEngine::Mariadb => {}
            }
            let server = engine.service_name();
            let mut apps: Vec<(&str, u32)> = Vec::new();
            for (name, e) in &self.entries {
                let declared: u32 = e
                    .manifest
                    .spec
                    .requires
                    .iter()
                    .filter_map(|c| match c {
                        hlb_types::Capability::Database {
                            engine: on,
                            name: _,
                            extensions: _,
                            connections,
                        } if *on == engine => *connections,
                        _ => None,
                    })
                    .sum();
                if declared > 0 {
                    apps.push((name, declared));
                }
            }
            // A server absent from the catalog is the graph's refusal, not this one's.
            let Ok(entry) = self.get(server) else {
                continue;
            };
            if apps.is_empty() {
                continue;
            }
            let Some(limit) = Some(entry).and_then(|s| {
                s.manifest
                    .spec
                    .args
                    .iter()
                    .find_map(|a| a.strip_prefix(engine.limit_arg()))
                    .and_then(|n| n.parse::<u32>().ok())
            }) else {
                errs.push((
                    server.to_string(),
                    hlb_types::Error::Validation(format!(
                        "{server}: its connection limit must be one of its args \
                         (`{}N`) — the apps' budgets are summed against it",
                        engine.limit_arg()
                    )),
                ));
                continue;
            };
            let room = limit.saturating_sub(engine.kept_for_the_administrator());
            let sum: u32 = apps.iter().map(|(_, n)| n).sum();
            let updating = apps.iter().map(|(_, n)| *n).max().unwrap_or(0);
            if sum + updating > room {
                let each: Vec<String> = apps.iter().map(|(a, n)| format!("{a} {n}")).collect();
                errs.push((
                    server.to_string(),
                    hlb_types::Error::Validation(format!(
                        "{server}: the apps' connections ({}: {sum}, and {updating} more \
                         while the largest is updated) exceed the {room} its limit of \
                         {limit} leaves them",
                        each.join(", ")
                    )),
                ));
            }
        }
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
    // Optional on read for a frozen manifest, which reads as `normal`; in the catalog an
    // app says it, since the backup pass orders by it and the lifeboat will choose by it.
    match (m.kind, m.metadata.criticality) {
        (hlb_types::Kind::App, None) => {
            return refuse(
                "`metadata.criticality` is required in the catalog: vital, important or \
                 normal — what the household loses while it is down"
                    .into(),
            )
        }
        (hlb_types::Kind::PlatformService, Some(_)) => {
            return refuse(
                "a platform service declares no `metadata.criticality`: it matters as much \
                 as the apps requiring it"
                    .into(),
            )
        }
        (hlb_types::Kind::App, Some(_)) | (hlb_types::Kind::PlatformService, None) => {}
    }
    for c in &m.spec.requires {
        // 🔴 Created with `CREATE EXTENSION`, which only PostgreSQL has: declared on
        // MariaDB, the install failed at the step, after the app was recorded.
        if let hlb_types::Capability::Database {
            engine,
            name: _,
            extensions,
            connections,
        } = c
        {
            if *engine == hlb_types::DbEngine::Mariadb && !extensions.is_empty() {
                return refuse(format!(
                    "a MariaDB database takes no extensions ({}) — only PostgreSQL has them",
                    extensions.join(", ")
                ));
            }
            // Optional on read for a frozen manifest; in the catalog, an app that says
            // nothing takes whatever its author left — Gitea's pool is unlimited.
            if connections.is_none() {
                return refuse(format!(
                    "a {} database must say `connections`: the most the app opens to the \
                     shared server, its pools capped to it",
                    engine.service_name()
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
    // 🔴 A secret reaches a container as a file — a Swarm secret, mounted in memory —
    // never through its environment, which `docker inspect`, the Swarm API and every
    // process's `/proc/<pid>/environ` show. Reached zero over three changes, counted.
    // And a file an environment names is one the container mounts: Fluxer's push and
    // media proxy stop on a `FLUXER_*_FILE` naming a file that is not there.
    let containers = std::iter::once((String::new(), m.spec.env.clone(), &m.spec.files)).chain(
        m.spec.companions.iter().map(|c| {
            (
                format!("companion {}: ", c.name),
                c.environment(&m.spec),
                &c.files,
            )
        }),
    );
    for (at, env, files) in containers {
        for (var, value) in &env {
            if hlb_types::binding::carries_secret(value) {
                return refuse(format!(
                    "{at}{var} hands a secret through the environment, which `docker \
                     inspect` shows — mount it as a `files:` entry and give the app its path"
                ));
            }
            if value.starts_with("/run/secrets/") && !files.iter().any(|f| &f.path == value) {
                return refuse(format!(
                    "{at}{var} names {value}, which no `files:` entry mounts there"
                ));
            }
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

fn collect(dir: &Path, release: &Version, out: &mut Catalog) -> Result<()> {
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
            collect(&path, release, out)?;
            continue;
        }

        if path.file_name().is_some_and(|f| f == "manifest.yaml") {
            match load_one(&path, release, None)? {
                Loaded::Entry(e) => {
                    out.entries.insert(e.manifest.metadata.name.clone(), *e);
                }
                Loaded::SetAside { app, why } => {
                    out.set_aside.insert(app, why);
                }
            }
        }
    }
    Ok(())
}

enum Loaded {
    Entry(Box<Entry>),
    SetAside { app: String, why: String },
}

/// The `hlb` range a manifest declares, read before anything else in it: a manifest
/// for a newer `hlb` may hold fields this one would refuse.
fn declared_range(raw: &str) -> Option<String> {
    let doc: serde_yaml_ng::Value = serde_yaml_ng::from_str(raw).ok()?;
    doc.get("metadata")?
        .get("hlb")?
        .as_str()
        .map(str::to_string)
}

/// `name` is the app's when the folder is not named after it — a signed index keeps
/// each version in a folder of its own.
fn load_one(path: &Path, release: &Version, name: Option<&str>) -> Result<Loaded> {
    let raw = std::fs::read_to_string(path).map_err(|source| Error::Io {
        path: path.to_path_buf(),
        source,
    })?;
    // The folder names the app, whatever the manifest it holds can be read to say.
    let dir = name.map(str::to_string).unwrap_or_else(|| {
        path.parent()
            .and_then(|p| p.file_name())
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default()
    });

    if let Some(range) = declared_range(&raw) {
        let why = match hlb_types::release::accepts(&range, release) {
            Ok(true) => None,
            Ok(false) => Some(format!(
                "\"{dir}\" needs hlb {range}, and this one is {release} — update hlb to \
                 install it"
            )),
            Err(e) => Some(format!("\"{dir}\": {e}")),
        };
        if let Some(why) = why {
            return Ok(Loaded::SetAside { app: dir, why });
        }
    }

    let manifest: Manifest = serde_yaml_ng::from_str(&raw).map_err(|e| Error::Parse {
        path: path.to_path_buf(),
        source: hlb_types::Error::Parse(e),
    })?;

    // The folder name is authoritative. Without this, two apps declaring the same
    // `metadata.name` would silently overwrite each other.
    if dir != manifest.metadata.name {
        return Err(Error::NameMismatch {
            path: path.to_path_buf(),
            declared: manifest.metadata.name.clone(),
            dir,
        });
    }

    // The guide lives next to the manifest. Absent means no declared step.
    let guide_path = path.with_file_name("guide.yaml");
    let guide_raw = if guide_path.exists() {
        std::fs::read_to_string(&guide_path).map_err(|source| Error::Io {
            path: guide_path.clone(),
            source,
        })?
    } else {
        "{}".to_string()
    };
    let guide = serde_yaml_ng::from_str(&guide_raw).map_err(|e| Error::Parse {
        path: guide_path.clone(),
        source: hlb_types::Error::Parse(e),
    })?;
    // Read as JSON once each parses: YAML the types accept converts.
    let as_json = |text: &str, path: &Path| {
        serde_yaml_ng::from_str::<serde_json::Value>(text).map_err(|e| Error::Parse {
            path: path.to_path_buf(),
            source: hlb_types::Error::Parse(e),
        })
    };
    let written = (as_json(&raw, path)?, as_json(&guide_raw, &guide_path)?);

    Ok(Loaded::Entry(Box::new(Entry {
        source: None,
        index: None,
        version: None,
        manifest,
        path: path.to_path_buf(),
        guide,
        written,
    })))
}

/// The `hlb` range a catalog app must declare, and what its floor could read.
///
/// 🔴 A range is a promise to every older `hlb` it names, and nothing else checks it:
/// one too low makes that `hlb` refuse the manifest, and a catalog published apart from
/// `hlb` reaches it. Held to the schema the floor committed when it was released.
fn release_rules(e: &Entry, release: &Version) -> hlb_types::Result<()> {
    let name = &e.manifest.metadata.name;
    let refuse = |why: String| Err(hlb_types::Error::Validation(format!("{name}: {why}")));
    let Some(range) = &e.manifest.metadata.hlb else {
        return refuse(format!(
            "`metadata.hlb` is required in the catalog: the hlb versions the app runs on, \
             \">={}.{}.0\" for what this one reads",
            release.major, release.minor
        ));
    };
    let floor = match hlb_types::release::floor(range) {
        Ok(f) => f,
        Err(e) => return refuse(e),
    };
    // This build parsed it: its own release reads it.
    if &floor >= release {
        return Ok(());
    }
    let Some(schema) = hlb_types::release::release_schema(&floor) else {
        let known: Vec<&str> = hlb_types::release::RELEASE_SCHEMAS
            .iter()
            .map(|(v, _)| *v)
            .collect();
        return refuse(format!(
            "`metadata.hlb` {range} starts at {floor}, which is no release whose schema this hlb \
             carries ({}) — the floor names one of them, or {release}",
            known.join(", ")
        ));
    };
    for (part, written) in [("manifest", &e.written.0), ("guide", &e.written.1)] {
        let refused = jsonschema::validator_for(&schema[part])
            .map_err(|err| format!("{floor}'s {part} schema is unreadable: {err}"))
            .and_then(|v| match v.iter_errors(written).next() {
                Some(err) => Err(format!(
                    "`metadata.hlb` {range}: {floor} cannot read its {part} — at {}: {err}; raise the \
                     floor to the release that first reads it",
                    err.instance_path()
                )),
                None => Ok(()),
            });
        if let Err(why) = refused {
            return refuse(why);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    impl Entry {
        /// An app built in a test, its range this build's own unless it says one.
        fn of_yaml(yaml: &str) -> Self {
            let mut manifest: Manifest = serde_yaml_ng::from_str(yaml).expect("manifest");
            manifest
                .metadata
                .hlb
                .get_or_insert_with(|| ">=0.4.0".into());
            if manifest.kind == hlb_types::Kind::App {
                manifest
                    .metadata
                    .criticality
                    .get_or_insert(hlb_types::Criticality::Normal);
            }
            let written = serde_json::to_value(&manifest).expect("json");
            Self {
                source: None,
                index: None,
                version: None,
                manifest,
                path: PathBuf::new(),
                guide: hlb_types::Guide::default(),
                written: (written, serde_json::json!({})),
            }
        }
    }

    impl Catalog {
        fn of(entries: impl IntoIterator<Item = (String, Entry)>) -> Self {
            Self {
                entries: entries.into_iter().collect(),
                ..Self::default()
            }
        }
    }

    fn repo_catalog() -> PathBuf {
        // CARGO_MANIFEST_DIR = crates/hlb-catalog
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("catalog")
    }

    #[test]
    fn an_app_says_how_critical_it_is_and_a_platform_service_does_not() {
        let refusal = |kind: &str, criticality: Option<hlb_types::Criticality>| {
            let y = format!(
                "apiVersion: hlb/v1\nkind: {kind}\nmetadata: {{ name: a }}\nspec:\n  \
                 image: {{ repo: a/a, tag: \"1\" }}\n"
            );
            let mut e = Entry::of_yaml(&y);
            e.manifest.metadata.criticality = criticality;
            catalog_rules(&e).err().map(|e| e.to_string())
        };
        let vital = Some(hlb_types::Criticality::Vital);
        assert_eq!(refusal("App", vital), None);
        assert!(
            refusal("App", None).is_some_and(|w| w.contains("`metadata.criticality` is required"))
        );
        assert!(refusal("PlatformService", vital).is_some_and(|w| w.contains("declares no")));
        assert_eq!(refusal("PlatformService", None), None);
        // Through `validate_all`, where `catalog validate` reads it.
        let mut e = Entry::of_yaml(&format!(
            "apiVersion: hlb/v1\nkind: App\nmetadata: {{ name: a }}\nspec:\n  \
             image: {{ repo: a/a, tag: \"1\", digest: \"sha256:{}\" }}\n  \
             swarm: {{ memory: {{ reserve: 64M, limit: 128M }} }}\n",
            "0".repeat(64)
        ));
        e.manifest.metadata.criticality = None;
        let errs = Catalog::of([("a".to_string(), e)]).validate_all();
        assert!(
            errs.iter()
                .any(|(_, e)| e.to_string().contains("`metadata.criticality`")),
            "{errs:?}"
        );
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
            Entry::of_yaml(&y)
        };
        let one = Catalog::of([("a".to_string(), app("a"))]);
        assert!(one.validate_all().is_empty(), "{:?}", one.validate_all());
        let two = Catalog::of([("a".to_string(), app("a")), ("b".to_string(), app("b"))]);
        let errs = two.validate_all();
        assert!(
            errs.iter().any(|(_, e)| e.to_string().contains("a's too")),
            "{errs:?}"
        );
    }

    #[test]
    fn the_catalog_refuses_a_download_that_could_land_anywhere_but_its_directory() {
        let d = "0".repeat(64);
        let with = |download: &str| {
            let y = format!(
                "apiVersion: hlb/v1\nkind: App\nmetadata: {{ name: a }}\nspec:\n  \
                 image: {{ repo: a/a, tag: \"1\", digest: \"sha256:{d}\" }}\n  \
                 swarm: {{ memory: {{ reserve: 64M, limit: 128M }} }}\n  \
                 requires:\n    - {{ kind: storage, name: config, path: /config, tier: local }}\n    \
                 - {{ kind: storage, name: media, path: /media, owner: b, backup: false }}\n  \
                 downloads:\n{download}"
            );
            Catalog::of([("a".to_string(), Entry::of_yaml(&y))])
                .validate_all()
                .into_iter()
                .map(|(_, e)| e.to_string())
                .collect::<Vec<_>>()
        };
        let one = |url: &str, sha: &str, storage: &str, into: &str, unzip: bool| {
            format!(
                "    - {{ url: \"{url}\", sha256: \"{sha}\", storage: {storage}, into: \"{into}\", unzip: {unzip} }}\n"
            )
        };
        let good = one(
            "https://example.org/r/p.zip",
            &d,
            "config",
            "plugins/p",
            true,
        );
        assert_eq!(with(&good), Vec::<String>::new());
        for (download, why) in [
            (
                one(
                    "http://example.org/r/p.zip",
                    &d,
                    "config",
                    "plugins/p",
                    true,
                ),
                "not https",
            ),
            (
                one(
                    "https://example.org/r/p.zip?x=1",
                    &d,
                    "config",
                    "plugins/p",
                    true,
                ),
                "plain",
            ),
            (
                one(
                    "https://example.org/r/p.zip",
                    &d.replace('0', "A"),
                    "config",
                    "p",
                    true,
                ),
                "64 lowercase",
            ),
            (
                one("https://example.org/r/p.zip", &d[1..], "config", "p", true),
                "64 lowercase",
            ),
            (
                one("https://example.org/r/p.zip", &d, "cache", "p", true),
                "none of the app's own",
            ),
            // Another app's volume: its owner's data, never this app's to replace.
            (
                one("https://example.org/r/p.zip", &d, "media", "p", true),
                "none of the app's own",
            ),
            (
                one("https://example.org/r/p.zip", &d, "config", "../p", true),
                "relative directory",
            ),
            (
                one("https://example.org/r/p.zip", &d, "config", "/p", true),
                "relative directory",
            ),
            (
                one("https://example.org/r/p.zip", &d, "config", "a//p", true),
                "relative directory",
            ),
            (
                one("https://example.org/r/p.zip", &d, "config", "", true),
                "relative directory",
            ),
            (
                one("https://example.org/r/p.zip", &d, "config", "a/$(x)", true),
                "relative directory",
            ),
            (
                one("https://example.org/r/", &d, "config", "p", false),
                "no file name",
            ),
            (
                format!(
                    "{good}{}",
                    one("https://example.org/r/q.zip", &d, "config", "plugins", true)
                ),
                "overlaps",
            ),
        ] {
            let errs = with(&download);
            assert!(
                errs.first().is_some_and(|e| e.contains(why)),
                "{download} → {errs:?}, expected {why:?}"
            );
        }
    }

    #[test]
    fn the_catalog_refuses_an_image_without_its_digest_and_a_service_without_memory() {
        let entry = |y: &str| Entry::of_yaml(y);
        let d = "0".repeat(64);
        let whole = format!(
            "apiVersion: hlb/v1\nkind: App\nmetadata: {{ name: a }}\nspec:\n  \
             image: {{ repo: a/a, tag: \"1\", digest: \"sha256:{d}\" }}\n  \
             swarm: {{ memory: {{ reserve: 64M, limit: 128M }} }}\n"
        );
        let refused = |y: &str| {
            Catalog::of([("a".to_string(), entry(y))])
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
            Catalog::of([(e.manifest.metadata.name.clone(), e.clone())])
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
            Catalog::of([("immich".to_string(), e.clone())])
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
    fn the_catalog_refuses_a_secret_in_an_environment_and_a_file_it_does_not_mount() {
        let c = Catalog::load(repo_catalog()).expect("catalog should load");
        let base = c.get("fluxer").expect("fluxer").clone();
        let refused = |e: &Entry| {
            Catalog::of([("fluxer".to_string(), e.clone())])
                .validate_all()
                .into_iter()
                .map(|(_, e)| e.to_string())
                .collect::<Vec<_>>()
        };
        assert_eq!(refused(&base), Vec::<String>::new());

        let mut main = base.clone();
        main.manifest
            .spec
            .env
            .insert("TOKEN".into(), "{{ secret.t:hex }}".into());
        let r = refused(&main);
        assert!(r[0].contains("TOKEN hands a secret"), "{r:?}");

        // Through `sharedEnv`, which reaches each companion taking it.
        let mut shared = base.clone();
        shared.manifest.spec.shared_env.insert(
            "FLUXER_S3_SECRET_ACCESS_KEY".into(),
            "{{ s3.secret_key }}".into(),
        );
        let r = refused(&shared);
        assert!(
            r[0].contains("companion ") && r[0].contains("FLUXER_S3_SECRET_ACCESS_KEY"),
            "{r:?}"
        );

        let mut dangling = base;
        let push = dangling
            .manifest
            .spec
            .companions
            .iter_mut()
            .find(|c| c.name == "push")
            .expect("push");
        push.files
            .retain(|f| f.path != "/run/secrets/vapid-private");
        let r = refused(&dangling);
        assert!(
            r[0].contains("companion push: FLUXER_VAPID_PRIVATE_KEY_FILE names"),
            "{r:?}"
        );
    }

    #[test]
    fn the_catalog_refuses_what_an_install_would_fail_on_late() {
        let c = Catalog::load(repo_catalog()).expect("catalog should load");
        let base = c.get("valkey").expect("valkey").clone();
        let refused = |e: &Entry| {
            Catalog::of([("valkey".to_string(), e.clone())])
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
                connections: Some(10),
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

    /// A source holding copies of the official catalog's apps, under the names given.
    fn source_of(apps: &[(&str, &str)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        for (from, name) in apps {
            let at = dir.path().join(name);
            std::fs::create_dir_all(&at).expect("dir");
            let found = |under: &str| repo_catalog().join(under).join(from).join("manifest.yaml");
            let path = [found(""), found("_platform")]
                .into_iter()
                .find(|p| p.exists())
                .expect("an official app");
            let text = std::fs::read_to_string(path).expect("manifest");
            let text = text.replace(&format!("name: {from}\n"), &format!("name: {name}\n"));
            std::fs::write(at.join("manifest.yaml"), text).expect("written");
        }
        dir
    }

    #[test]
    fn a_third_party_app_never_shadows_the_official_one() {
        let theirs = source_of(&[("librespeed", "librespeed"), ("mealie", "recipes")]);
        let mut c = Catalog::load(repo_catalog()).expect("catalog");
        let official = c.len();
        c.add_source("community", theirs.path()).expect("added");

        assert_eq!(c.len(), official + 2);
        assert_eq!(c.get("librespeed").expect("official").source, None);
        let e = c.get("community/librespeed").expect("theirs");
        assert_eq!(e.source.as_deref(), Some("community"));
        assert_eq!(e.name(), "community/librespeed");
        // Installed, each follows its own source.
        let followed = c
            .followed("librespeed", Some("community"))
            .expect("followed");
        assert_eq!(followed.source.as_deref(), Some("community"));
        assert!(c.followed("recipes", None).is_err());
        assert!(c.followed("recipes", Some("community")).is_ok());
    }

    #[test]
    fn a_third_party_source_may_require_a_capability_never_provide_one() {
        // `postgres` as it is, and an app renamed `valkey`: either would be what every
        // app requiring a database or a cache is handed to.
        let theirs = source_of(&[
            ("postgres", "postgres"),
            ("librespeed", "valkey"),
            ("gitea", "forge"),
        ]);
        let mut c = Catalog::load(repo_catalog()).expect("catalog");
        c.add_source("community", theirs.path()).expect("added");

        let why = |app: &str| c.get(app).expect_err("set aside").to_string();
        assert!(
            why("community/postgres").contains("never provide"),
            "{}",
            why("community/postgres")
        );
        assert!(
            why("community/valkey").contains("official platform service \"valkey\""),
            "{}",
            why("community/valkey")
        );
        // Requiring a database is what an app does.
        assert!(c.get("community/forge").is_ok());
        assert_eq!(c.get("postgres").expect("official").source, None);
    }

    #[test]
    fn a_source_that_cannot_be_read_leaves_the_official_catalog_whole() {
        let mut c = Catalog::load(repo_catalog()).expect("catalog");
        let official = c.len();
        assert!(c.add_source("gone", "/does/not/exist").is_err());
        for bad in ["", "Community", "-x", "a/b", &"x".repeat(33)] {
            assert!(
                matches!(c.add_source(bad, repo_catalog()), Err(Error::SourceName(_))),
                "{bad:?} accepted"
            );
        }
        let theirs = source_of(&[("librespeed", "librespeed")]);
        c.add_source("mine", theirs.path()).expect("added");
        assert!(matches!(
            c.add_source("mine", theirs.path()),
            Err(Error::SourceTaken(_))
        ));
        assert_eq!(c.len(), official + 1);
    }

    /// A copy of the repository's catalog, one manifest's range rewritten.
    fn with_range(app: &str, range: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        let copy = |from: &Path, to: &Path| {
            std::process::Command::new("cp")
                .arg("-r")
                .arg(from)
                .arg(to)
                .status()
                .expect("cp")
        };
        assert!(copy(&repo_catalog(), dir.path()).success());
        let path = dir.path().join("catalog").join(app).join("manifest.yaml");
        let text = std::fs::read_to_string(&path).expect("manifest");
        let text = text.replace("hlb: \">=0.4.0\"", &format!("hlb: \"{range}\""));
        std::fs::write(&path, text).expect("written");
        dir
    }

    #[test]
    fn an_app_for_a_newer_hlb_is_set_aside_and_the_rest_still_load() {
        // 🔴 One manifest this `hlb` cannot read refused the whole catalog: every
        // install, every nightly re-check — for an app nobody here had asked for.
        let dir = with_range("jellyfin", ">=9.0.0");
        // And a field no release knows yet, which this build would refuse.
        let path = dir.path().join("catalog/jellyfin/manifest.yaml");
        let text = std::fs::read_to_string(&path).expect("manifest") + "futureField: true\n";
        std::fs::write(&path, text).expect("written");

        let c = Catalog::load(dir.path().join("catalog")).expect("the catalog still loads");
        assert!(c.get("gitea").is_ok());
        let err = c.get("jellyfin").expect_err("set aside").to_string();
        assert!(
            err.contains(">=9.0.0") && err.contains("update hlb"),
            "{err}"
        );
        assert_eq!(c.left_out().count(), 1);
        assert!(!c.names().any(|n| n == "jellyfin"));
        // Validated by this hlb, the catalog is not one it can run.
        assert!(c
            .validate_all()
            .iter()
            .any(|(n, e)| n == "jellyfin" && e.to_string().contains("update hlb")));

        // The release it names reads it.
        let later = Version::new(9, 1, 0);
        let c = Catalog::load_as(dir.path().join("catalog"), &later);
        assert!(
            c.is_err(),
            "9.1 reads it, and this build's types refuse the new field"
        );
    }

    #[test]
    fn a_range_is_held_to_the_schema_of_the_release_it_starts_at() {
        // `metadata.hlb` is itself unknown to 0.3.0: no manifest can start there.
        let dir = with_range("gitea", ">=0.3.0");
        let c = Catalog::load(dir.path().join("catalog")).expect("load");
        let errs: Vec<String> = c
            .validate_all()
            .into_iter()
            .filter(|(n, _)| n == "gitea")
            .map(|(_, e)| e.to_string())
            .collect();
        assert!(
            errs.len() == 1 && errs[0].contains("0.3.0 cannot read its manifest"),
            "{errs:?}"
        );

        let dir = with_range("gitea", ">=0.2.0");
        let c = Catalog::load(dir.path().join("catalog")).expect("load");
        let errs = c.validate_all();
        assert!(
            errs.iter()
                .any(|(n, e)| n == "gitea" && e.to_string().contains("no release whose schema")),
            "{errs:?}"
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
        // At a release, its own build; between releases (`0.4.0-dev`) no image is built,
        // and the catalog keeps the last release's until the next one moves it.
        let version = Version::parse(env!("CARGO_PKG_VERSION")).expect("version");
        if version.pre.is_empty() {
            assert_eq!(m.spec.image.tag, env!("CARGO_PKG_VERSION"));
        } else {
            let tag = Version::parse(&m.spec.image.tag).expect("a release's tag");
            assert!(
                tag.pre.is_empty() && tag < hlb_types::release::running(),
                "{tag}: a published release before {version}"
            );
        }
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

    /// Fluxer's four pools are what it declares: the role's limit is set from the
    /// declaration, and a companion whose pool grew past it is refused its connections.
    #[test]
    fn fluxer_s_pools_add_up_to_what_it_declares() {
        let c = Catalog::load(repo_catalog()).expect("catalog should load");
        let fluxer = &c.get("fluxer").expect("fluxer").manifest;
        let declared = fluxer
            .spec
            .requires
            .iter()
            .find_map(|r| match r {
                hlb_types::Capability::Database { connections, .. } => *connections,
                _ => None,
            })
            .expect("fluxer declares its connections");
        // Every companion saying a pool, not a list of the ones that connect today.
        let sum: u32 = fluxer
            .spec
            .companions
            .iter()
            .filter_map(|x| {
                x.environment(&fluxer.spec)
                    .get("FLUXER_POSTGRES_MAX_CONNECTIONS")
                    .map(|n| n.parse::<u32>().expect("a number"))
            })
            .sum();
        assert_eq!(sum, declared);
    }

    /// The apps' connections are summed against their server's limit, the largest
    /// counted twice for its update — through `validate_all`, which the CLI runs.
    #[test]
    fn the_catalog_refuses_apps_that_would_exhaust_their_shared_server() {
        let c = Catalog::load(repo_catalog()).expect("catalog should load");
        assert!(c.validate_all().is_empty(), "{:?}", c.validate_all());
        let refused = |c: &Catalog| {
            c.validate_all()
                .into_iter()
                .map(|(_, e)| e.to_string())
                .collect::<Vec<_>>()
        };
        let set = |c: &mut Catalog, app: &str, n: Option<u32>| {
            for r in &mut c.entries.get_mut(app).expect("app").manifest.spec.requires {
                if let hlb_types::Capability::Database { connections, .. } = r {
                    *connections = n;
                }
            }
        };

        // Vikunja left at its own default of 100.
        let mut over = c.clone();
        set(&mut over, "vikunja", Some(100));
        let r = refused(&over);
        assert!(
            r.len() == 1 && r[0].contains("postgres") && r[0].contains("vikunja 100"),
            "{r:?}"
        );

        // Saying nothing is not a budget.
        let mut silent = c.clone();
        set(&mut silent, "gitea", None);
        let r = refused(&silent);
        assert!(
            r.iter()
                .any(|e| e.contains("gitea") && e.contains("connections")),
            "{r:?}"
        );

        // A limit the server's manifest does not set is not one to sum against.
        let mut unset = c.clone();
        unset
            .entries
            .get_mut("postgres")
            .expect("postgres")
            .manifest
            .spec
            .args
            .retain(|a| !a.starts_with("max_connections="));
        let r = refused(&unset);
        assert!(
            r.iter().any(|e| e.contains("its connection limit")),
            "{r:?}"
        );
    }

    #[test]
    fn a_role_may_hold_twice_its_app_s_connections_on_that_engine_only() {
        use hlb_types::{Capability, DbEngine};
        let db = |engine, n| Capability::Database {
            engine,
            name: None,
            extensions: Vec::new(),
            connections: n,
        };
        let seafile = [
            db(DbEngine::Mariadb, Some(40)),
            db(DbEngine::Mariadb, Some(56)),
            db(DbEngine::Mariadb, Some(20)),
        ];
        let limit = hlb_types::capability::role_connection_limit;
        assert_eq!(limit(&seafile, DbEngine::Mariadb), Some(232));
        assert_eq!(limit(&seafile, DbEngine::Postgres), None);
        // Frozen before the field: the role is left as it was.
        assert_eq!(
            limit(&[db(DbEngine::Postgres, None)], DbEngine::Postgres),
            None
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
        let token = api
            .env
            .get("FLUXER_SETUP_TOKEN_FILE")
            .expect("the setup token, as a file");
        assert!(file(token).starts_with("{{ secret."));
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
            // Or by its guide, through the app's API: Jellyfin's SSO plugin.
            let calls = e
                .guide
                .steps
                .iter()
                .flat_map(|s| &s.automate)
                .flat_map(|a| match a {
                    hlb_types::Automation::Api { calls, .. } => {
                        calls.iter().filter_map(|c| c.body.as_ref()).collect()
                    }
                    hlb_types::Automation::Env { .. }
                    | hlb_types::Automation::Exec { .. }
                    | hlb_types::Automation::Sql { .. } => Vec::new(),
                });
            let given = m
                .spec
                .substituted()
                .chain(calls)
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
