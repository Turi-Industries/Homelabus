//! Homelabus shared types.
//!
//! This crate is deliberately the only place the schema is defined. It feeds:
//!   - the controller and the CLI (Rust, directly);
//!   - YAML autocompletion in the editor (through `schemars` → JSON Schema).
//!
//! ⚠️ The web interface never redefines them either: the types it sees are GENERATED
//! from the controller's OpenAPI document, which `hlb-api` and these types feed. A
//! TypeScript type written by hand would be the second definition this crate exists to
//! prevent.

pub mod access;
pub mod assertion;
pub mod capability;
pub mod domain;
pub mod guide;
pub mod index;
pub mod manifest;
pub mod rbac;
pub mod release;
pub mod swarm;
pub mod token;

pub use guide::{
    ApiCall, ApiProbe, Automation, Guide, GuideStep, JsonValue, Phase, Severity, Verify,
};
pub use rbac::Role;
pub use token::{generate as generate_token, StoredToken};
pub mod binding;

pub use assertion::{Assertion, Check};
pub use binding::{redact, substitute, Token};
pub use capability::{
    CacheEngine, Capability, DbEngine, SmtpSender, SsoMode, StorageTier, VolumeCopy,
};
pub use manifest::{
    ApiVersion, AuthRoute, Companion, CompanionVolume, ExposePolicy, Healthcheck, Image,
    ImageSigner, Ingress, Job, Kind, Manifest, Memory, Metadata, PathRoute, Period, Process,
    RecoveryLogin, Runtime, SecuritySpec, SignIn, Spec, SwarmSpec, Tmpfs, Ulimit, UpdateChannel,
    UpdatePolicy,
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid manifest: {0}")]
    Parse(#[from] serde_yaml_ng::Error),

    #[error("validation failed: {0}")]
    Validation(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Does any text a deployment fills say `placeholder`?
fn texts_use(m: &Manifest, placeholder: &str) -> bool {
    m.spec.substituted().any(|v| v.contains(placeholder))
}

/// What a manifest declares and nothing would read: refused, since honouring it
/// silently as its default is how an app starts, looks healthy and loses data.
fn declared_and_read(m: &Manifest, used: &[Token]) -> Result<()> {
    let app = &m.metadata.name;
    let refuse = |why: &str| Err(Error::Validation(format!("{app}: {why}")));
    // Rollback on a failed update is hard-coded in the orchestrator.
    if !m.spec.update.auto_rollback {
        return refuse(
            "update.autoRollback: false — a failed update is always rolled back; an app \
             that cannot cope belongs on `channel: pin`",
        );
    }
    if m.spec.update.watch_upstream.is_some() {
        return refuse(
            "update.watchUpstream — nothing watches an upstream repository: updates follow \
             the image's own registry",
        );
    }
    let databases: Vec<&DbEngine> = m
        .spec
        .requires
        .iter()
        .filter_map(|c| {
            if let Capability::Database {
                engine,
                name: _,
                extensions: _,
                connections: _,
            } = c
            {
                Some(engine)
            } else {
                None
            }
        })
        .collect();
    if databases.len() > 1 {
        // One set of `{{ db.* }}` tokens: each database overwrote the last.
        if databases.iter().any(|e| *e != databases[0])
            && used.iter().any(|t| t.requires() == Some("database"))
        {
            return refuse(
                "databases on two engines, and one set of {{ db.* }} tokens — they would \
                 name the last one's server",
            );
        }
        if let Some(t) = used
            .iter()
            .find(|t| matches!(t, Token::DbName | Token::DbUrl))
        {
            return refuse(&format!(
                "{} with several databases names the last one only — write each \
                 database's name in the app's variables",
                t.placeholder()
            ));
        }
    }
    // Each bucket by the name Garage gives it: one left out is the app's own.
    let buckets: Vec<(&str, Option<u32>)> = m
        .spec
        .requires
        .iter()
        .filter_map(|c| match c {
            Capability::ObjectStorage {
                bucket,
                backup: _,
                expire_after_days,
            } => Some((
                capability::bucket_name(bucket.as_deref(), app),
                *expire_after_days,
            )),
            _ => None,
        })
        .collect();
    for (i, (name, expire)) in buckets.iter().enumerate() {
        if buckets[..i].iter().any(|(n, _)| n == name) {
            return refuse(&format!(
                "bucket {name} declared twice — each `object-storage` of several names its own"
            ));
        }
        if *expire == Some(0) {
            return refuse(&format!(
                "bucket {name}: expireAfterDays 0 would delete every object the day it is written"
            ));
        }
    }
    if buckets.len() > 1 && texts_use(m, "{{ s3.bucket }}") {
        return refuse(
            "{{ s3.bucket }} with several buckets names the last one only — write each \
             bucket's name in the app's variables",
        );
    }
    for c in &m.spec.requires {
        if let Capability::MailAccount {
            quota_bytes: _,
            aliases: true,
        } = c
        {
            return refuse(
                "mail-account with `aliases: true` — nothing makes or limits an app's aliases",
            );
        }
        // Read for `native` only: elsewhere they would open paths past Anubis for a
        // sign-in nobody makes there.
        if let Capability::Sso {
            mode,
            redirect_paths,
        } = c
        {
            if *mode != SsoMode::Native && !redirect_paths.is_empty() {
                return refuse(
                    "redirectPaths without `mode: native` — only the app's own OIDC client \
                     has callbacks; the portal's is its own",
                );
            }
        }
    }
    Ok(())
}

/// What a download may say. Its values reach a shell in a job as positional
/// parameters, never in the script's text — these rules keep it to one place in one
/// of the app's volumes.
fn validate_downloads(m: &Manifest) -> Result<()> {
    let refuse = |d: &manifest::Download, why: &str| {
        Err(Error::Validation(format!(
            "{}: the download {} — {why}",
            m.metadata.name, d.url
        )))
    };
    // A name the job writes: no `..`, no hidden `-` option, no surprise for `rm -rf`.
    let segment_ok = |s: &str| {
        !s.is_empty()
            && s != "."
            && s != ".."
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    };
    for (i, d) in m.spec.downloads.iter().enumerate() {
        let Some(rest) = d.url.strip_prefix("https://") else {
            return refuse(d, "not https: nothing would say who served it");
        };
        if rest.split('/').count() < 2
            || rest.starts_with('/')
            || d.url
                .bytes()
                .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
            || d.url.contains(['?', '#'])
        {
            return refuse(d, "not a plain https://host/path URL");
        }
        if d.sha256.len() != 64
            || !d
                .sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return refuse(d, "its sha256 is not 64 lowercase hexadecimal digits");
        }
        let own = m.spec.requires.iter().any(
            |c| matches!(c, Capability::Storage { name, owner: None, .. } if *name == d.storage),
        );
        if !own {
            return refuse(
                d,
                &format!(
                    "storage {:?} is none of the app's own volumes (`kind: storage`, no \
                     `owner`)",
                    d.storage
                ),
            );
        }
        if !d.into.split('/').all(segment_ok) {
            return refuse(
                d,
                &format!(
                    "into {:?} is not a relative directory of the volume",
                    d.into
                ),
            );
        }
        if !d.unzip && !segment_ok(d.file_name()) {
            return refuse(d, "its URL ends in no file name to keep it under");
        }
        // Each replaces its directory whole: one inside another's would be erased by it.
        let within = |a: &str, b: &str| a == b || a.starts_with(&format!("{b}/"));
        if let Some(o) = m.spec.downloads[..i].iter().find(|o| {
            o.storage == d.storage && (within(&d.into, &o.into) || within(&o.into, &d.into))
        }) {
            return refuse(
                d,
                &format!(
                    "into {:?} overlaps {:?}, which {} replaces whole",
                    d.into, o.into, o.url
                ),
            );
        }
    }
    Ok(())
}

/// Rules that types alone cannot express.
///
/// Each rule here corresponds to a concrete way of shooting yourself in the foot.
pub fn validate(m: &Manifest) -> Result<()> {
    validate_with_guide(m, &Guide::default())
}

/// The same, a capability read by the guide's own calls counting as read: Jellyfin
/// hands its OIDC client to the SSO plugin through its API, from no variable.
pub fn validate_with_guide(m: &Manifest, g: &Guide) -> Result<()> {
    // An app on `proxy-header` trusts an HTTP header. If it is reachable without
    // going through the proxy, `curl -H "Remote-User: admin"` is enough to impersonate
    // any account.
    let header_auth =
        m.spec.requires.iter().any(
            |c| matches!(c, Capability::Sso { mode, .. } if mode.requires_network_isolation()),
        );

    // Every service of the app publishes on the node: a companion's port reaches the
    // app's network as surely as the app's own.
    let published: Vec<&manifest::PublishedPort> = std::iter::once(&m.spec.security)
        .chain(m.spec.companions.iter().map(|c| &c.security))
        .flat_map(|s| &s.published_ports)
        .collect();
    if header_auth && !published.is_empty() {
        return Err(Error::Validation(format!(
            "{} uses header authentication but publishes ports {}: the app must be \
             reachable only through the proxy",
            m.metadata.name,
            published
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        )));
    }
    // Host mode binds one port once per node: a second service asking for it would
    // never be placed beside the first, with "no suitable node" as the only reason.
    for (i, p) in published.iter().enumerate() {
        if p.port == 0 || published[..i].contains(p) {
            return Err(Error::Validation(format!(
                "{}: port {p} — published twice, or zero",
                m.metadata.name
            )));
        }
    }

    // A tmpfs is an absolute directory of its own: relative, Swarm refuses the service
    // at deploy time; over a volume, it hides the data the volume holds.
    let app_paths: Vec<&str> = m
        .spec
        .requires
        .iter()
        .filter_map(|c| match c {
            Capability::Storage { path, .. } => Some(path.as_str()),
            _ => None,
        })
        .collect();
    let services = std::iter::once((
        m.metadata.name.as_str(),
        &m.spec.security,
        m.spec.swarm.memory,
        app_paths,
    ))
    .chain(m.spec.companions.iter().map(|c| {
        let paths = c.storage.iter().map(|v| v.path.as_str()).collect();
        (c.name.as_str(), &c.security, c.memory, paths)
    }));
    for (service, security, memory, volumes) in services {
        for (i, t) in security.tmpfs.iter().enumerate() {
            let dir = &t.path;
            let clean = dir.starts_with('/')
                && dir != "/"
                && !dir.split('/').any(|seg| seg == "." || seg == "..");
            let why = if !clean {
                Some("not an absolute directory of its own")
            } else if security.tmpfs[..i].iter().any(|o| o.path == *dir) {
                Some("given twice")
            } else if volumes.contains(&dir.as_str()) {
                Some("a volume's path, whose data it would hide")
            // Filled past the limit, the service is killed before the tmpfs is full.
            } else if t.size.zip(memory).is_some_and(|(s, m)| s > m.limit) {
                Some("larger than the service's memory limit")
            } else {
                None
            };
            if let Some(why) = why {
                return Err(Error::Validation(format!(
                    "{}: {service}'s tmpfs {dir:?} is {why}",
                    m.metadata.name
                )));
            }
        }
    }

    // A signer is interpolated into the identity cosign expects: a malformed one names
    // a workflow no certificate carries, and every update of the image is refused.
    let images = std::iter::once(&m.spec.image).chain(m.spec.companions.iter().map(|c| &c.image));
    for (image, s) in images.filter_map(|i| Some((i, i.signed_by.as_ref()?))) {
        let name_ok = |p: &str| {
            !p.is_empty()
                && !p.starts_with('.')
                && p.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        };
        let why = match s.github.split_once('/') {
            Some((owner, repo)) if name_ok(owner) && name_ok(repo) => None,
            _ => Some(format!("github {:?} is not owner/repository", s.github)),
        }
        .or_else(|| {
            let file = s
                .workflow
                .strip_suffix(".yml")
                .or_else(|| s.workflow.strip_suffix(".yaml"));
            (!file.is_some_and(name_ok)).then(|| {
                format!(
                    "workflow {:?} is not a file name in .github/workflows/",
                    s.workflow
                )
            })
        });
        if let Some(why) = why {
            return Err(Error::Validation(format!(
                "{}: {}'s signer — {why}",
                m.metadata.name, image.repo
            )));
        }
    }

    validate_downloads(m)?;

    // 🔴 `mode: native` without `redirectPaths` produces an OIDC client with NO
    // redirect URI. PocketID then has nothing to send the user back to, and the failure
    // only shows on the return leg of the sign-in, as a message about an unregistered
    // URI that never says which one it expected.
    //
    // The manifest is refused here rather than letting a useless client be planned:
    // this is an authoring mistake, and it is reported with its line number.
    for c in &m.spec.requires {
        if let Capability::Sso {
            mode: SsoMode::Native,
            redirect_paths,
        } = c
        {
            if redirect_paths.is_empty() {
                return Err(Error::Validation(format!(
                    "{} declares \"sso: native\" with no redirectPaths: the OIDC \
                     client would have no redirect URI and sign-in would fail on the \
                     way back. Give the app's callback path, or switch to \
                     \"proxy-only\" if it does not speak OIDC",
                    m.metadata.name
                )));
            }
        }
    }

    // 🔴 A binding token requires the matching capability.
    //
    // Without this check, a `{{ db.password }}` in an app that declares no database
    // would go out to Swarm with the TOKEN TEXT as its value. The app would then
    // complain about an incorrect password, and the investigation would start at the
    // password - never at the manifest.
    //
    // Everywhere a deployment substitutes, and every value a guide's step sends.
    let mut texts: Vec<&str> = m.spec.substituted().map(String::as_str).collect();
    for a in g.steps.iter().flat_map(|s| &s.automate) {
        match a {
            Automation::Api {
                port: _,
                sign_in: _,
                // `{{ token }}` alone (`validate_guide`).
                headers: _,
                probe: _,
                calls,
            } => texts.extend(calls.iter().filter_map(|c| c.body.as_deref())),
            Automation::Sql {
                statement: _,
                params,
                probe: _,
                restart: _,
            } => texts.extend(params.iter().map(String::as_str)),
            Automation::Env { .. } | Automation::Exec { .. } => {}
        }
    }
    let mut used: Vec<Token> = texts.iter().flat_map(|v| binding::tokens_in(v)).collect();
    used.sort_unstable();
    used.dedup();
    for t in &used {
        let Some(needed) = t.requires() else { continue };

        let declared = m.spec.requires.iter().any(|c| c.id() == needed);
        if !declared {
            return Err(Error::Validation(format!(
                "{}: \"{}\" is used but the app declares no \"{needed}\" capability. \
                 It would go out with the token text as its value",
                m.metadata.name,
                t.placeholder()
            )));
        }
    }

    // Sent as the person signed in, mail has no account of the app's: its login,
    // password and address do not exist, and would reach the app as token text.
    let as_person = m.spec.requires.iter().any(|c| {
        matches!(
            c,
            Capability::Smtp {
                sender: SmtpSender::Person
            }
        )
    });
    if let Some(t) = used
        .iter()
        .find(|t| as_person && matches!(t, Token::SmtpUser | Token::SmtpPassword | Token::SmtpFrom))
    {
        return Err(Error::Validation(format!(
            "{}: \"{}\" — its mail goes out as the person signed in (sender: person), \
             with their own credentials: the app has no account to read this from",
            m.metadata.name,
            t.placeholder()
        )));
    }

    // 🔴 A capability no token reads is provisioned for nothing. Vikunja and Seafile
    // declared `smtp` and were never told about the account: neither could send, and
    // nothing said so. Exhaustive, so a new capability has to say what reading it is.
    for c in &m.spec.requires {
        let its_tokens = || used.iter().any(|t| t.requires() == Some(c.id()));
        let read = match c {
            // Its `connections` is read by the catalog, summed against the server's.
            Capability::Database {
                engine: _,
                name: _,
                extensions: _,
                connections: _,
            }
            | Capability::Cache {
                engine: _,
                dedicated: _,
            }
            | Capability::Smtp { sender: _ } => its_tokens(),
            Capability::Sso {
                mode,
                redirect_paths: _,
            } => match mode {
                SsoMode::Native => its_tokens(),
                // The portal signs in for the app, or the app signs in nobody.
                SsoMode::ProxyOnly | SsoMode::ProxyHeader | SsoMode::None => true,
            },
            // The bucket's tokens are not `Token`s: each names its own bucket.
            Capability::ObjectStorage {
                bucket: _,
                backup: _,
                expire_after_days: _,
            } => texts.iter().any(|v| v.contains("{{ s3.")),
            // A mailbox and a volume are used without being told anything.
            Capability::MailAccount {
                quota_bytes: _,
                aliases: _,
            }
            | Capability::Storage {
                name: _,
                path: _,
                tier: _,
                backup: _,
                sqlite: _,
                copy: _,
                owner: _,
            } => true,
        };
        if !read {
            return Err(Error::Validation(format!(
                "{}: requires \"{}\" and reads none of its tokens — what is provisioned \
                 for it would reach nothing, and the app run without it",
                m.metadata.name,
                c.id()
            )));
        }
    }

    declared_and_read(m, &used)?;

    // `hlb-` names Homelabus's own services: an app there would be taken for one of
    // them, and reconciliation would never look at it. (The prefix is
    // `hlb_orchestrator::SYSTEM_PREFIX`; this crate cannot depend on that one.)
    if m.metadata.name.starts_with("hlb-") {
        return Err(Error::Validation(format!(
            "{}: names starting with \"hlb-\" are Homelabus's own services",
            m.metadata.name
        )));
    }

    // A generated secret with a malformed name would reach the service as literal
    // text, and the service would fail on a "wrong password" that names nothing.
    for v in m.spec.substituted() {
        for found in binding::generated_secrets(v) {
            if let Err(bad) = found {
                return Err(Error::Validation(format!(
                    "{}: \"{bad}\" — a generated secret is written \
                     {{{{ secret.<name> }}}} or {{{{ secret.<name><form> }}}}, the form one \
                     of {}, with a name of lowercase letters, digits and hyphens",
                    m.metadata.name,
                    binding::SecretForm::WRITTEN
                        .iter()
                        .map(|f| f.suffix())
                        .collect::<Vec<_>>()
                        .join(" ")
                )));
            }
        }
    }

    // A file takes its tokens at deployment, like a variable — the plan keeps them
    // literal — and reaches the service as a Swarm secret, where a value is better
    // kept than in an environment `docker service inspect` prints.
    // A companion's files are its own container's: the same path in the app and in one
    // of its companions are two files.
    let services = std::iter::once((m.metadata.name.as_str(), &m.spec.files)).chain(
        m.spec
            .companions
            .iter()
            .map(|c| (c.name.as_str(), &c.files)),
    );
    for (service, files) in services {
        let mut paths: Vec<&str> = Vec::new();
        for f in files {
            if !f.path.starts_with('/') {
                return Err(Error::Validation(format!(
                    "{}: {service}'s file \"{}\" — the path must be absolute",
                    m.metadata.name, f.path
                )));
            }
            if paths.contains(&f.path.as_str()) {
                return Err(Error::Validation(format!(
                    "{}: {service}'s file {} declared twice",
                    m.metadata.name, f.path
                )));
            }
            paths.push(&f.path);
        }
    }

    // Shared variables nobody takes reach no service: the app would run without them.
    if !m.spec.shared_env.is_empty() && !m.spec.companions.iter().any(|c| c.shared_env) {
        return Err(Error::Validation(format!(
            "{}: sharedEnv, and no companion takes it (`sharedEnv: true`)",
            m.metadata.name
        )));
    }

    // A command reaches Swarm as written: nothing gives it its tokens, and a secret
    // would be readable in `ps` by every account of the node if something did.
    let commands = std::iter::once(&m.spec.command)
        .chain(std::iter::once(&m.spec.args))
        .chain(m.spec.companions.iter().flat_map(|c| [&c.command, &c.args]))
        .flatten();
    for arg in commands {
        if !binding::tokens_in(arg).is_empty() || !binding::generated_secrets(arg).is_empty() {
            return Err(Error::Validation(format!(
                "{}: command argument \"{arg}\" carries a token — a command takes none: \
                 put the value in a variable or a file",
                m.metadata.name
            )));
        }
    }

    let processes = std::iter::once((m.metadata.name.as_str(), &m.spec.process)).chain(
        m.spec
            .companions
            .iter()
            .map(|c| (c.name.as_str(), &c.process)),
    );
    for (service, process) in processes {
        validate_process(process)
            .map_err(|why| Error::Validation(format!("{}: {service}'s {why}", m.metadata.name)))?;
    }

    // A companion becomes a DNS name on the Swarm network.
    //
    // ⚠️ An uppercase letter or a dot produces a service Swarm creates without
    // complaint and the app cannot resolve: the failure shows on the first request, as
    // a "connection refused" that says nothing about the name.
    let mut seen: Vec<&str> = Vec::new();
    for c in &m.spec.companions {
        if c.name.is_empty()
            || !c
                .name
                .chars()
                .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-')
        {
            return Err(Error::Validation(format!(
                "{}: companion \"{}\" - the name becomes a DNS entry and accepts \
                 only lowercase letters, digits and hyphens",
                m.metadata.name, c.name
            )));
        }

        // Two companions sharing a name would produce two services with the same
        // name: the second would overwrite the first, silently.
        if seen.contains(&c.name.as_str()) {
            return Err(Error::Validation(format!(
                "{}: companion \"{}\" declared twice - the second would overwrite \
                 the first without a word",
                m.metadata.name, c.name
            )));
        }
        seen.push(&c.name);
    }

    // Another app's volume is read here, never kept: backed up or snapshotted by two
    // apps, its data would be restored twice over itself.
    for c in &m.spec.requires {
        if let Capability::Storage {
            name,
            owner: Some(owner),
            backup,
            sqlite,
            tier,
            copy,
            path: _,
        } = c
        {
            if owner == &m.metadata.name
                || *backup
                || *sqlite
                || *tier != StorageTier::Local
                || !copy.is_live()
            {
                return Err(Error::Validation(format!(
                    "{}: volume \"{name}\" is {owner}'s — a volume of another app is \
                     local, with backup and sqlite false and no copy of its own: its \
                     owner keeps it",
                    m.metadata.name
                )));
            }
        }
    }

    // How a volume nobody backs up is copied is a declaration nobody reads.
    let volumes = m.spec.requires.iter().filter_map(|c| match c {
        Capability::Storage {
            name, backup, copy, ..
        } => Some((name.as_str(), *backup, *copy)),
        _ => None,
    });
    let companions = m
        .spec
        .companions
        .iter()
        .flat_map(|c| c.storage.iter())
        .map(|v| (v.name.as_str(), v.backup, v.copy));
    for c in &m.spec.companions {
        if let Some(v) = c.storage.iter().find(|v| v.copy.engine().is_some()) {
            return Err(Error::Validation(format!(
                "{}: volume \"{}\" of {} is copied by an engine's tool, which connects to \
                 the app's own service: an engine runs as the app, never as a companion",
                m.metadata.name, v.name, c.name
            )));
        }
    }
    for (name, backup, copy) in volumes.chain(companions) {
        if !backup && !copy.is_live() {
            return Err(Error::Validation(format!(
                "{}: volume \"{name}\" says how its copy is taken, and is not backed up: \
                 nothing would read it",
                m.metadata.name
            )));
        }
    }

    // A database on NFS ends up corrupted: file locking is not reliable
    // there.
    for c in &m.spec.requires {
        if let Capability::Storage {
            tier, sqlite, name, ..
        } = c
        {
            if *sqlite && *tier == StorageTier::Nfs {
                return Err(Error::Validation(format!(
                    "volume \"{name}\": a SQLite database must never sit on NFS"
                )));
            }
            // 🔴 A local volume exists once per node. Vikunja ran two replicas over its
            // `files`: on two nodes, each wrote its own copy, the routing mesh served
            // either at random, and one was backed up; on one node, the "HA" was two
            // processes racing each other's migrations (found on a real cluster).
            if *tier == StorageTier::Local && m.spec.swarm.replicas > 1 {
                return Err(Error::Validation(format!(
                    "{}: {} replicas over the local volume \"{name}\" — a local volume \
                     exists once per node, and the data would split between them: one \
                     replica, or the volume on NFS",
                    m.metadata.name, m.spec.swarm.replicas
                )));
            }
        }
    }

    // A typo in a chain changes nothing visible: `anubls` would publish the app with
    // no proof-of-work in front of it, the declaration read by nobody.
    for ing in &m.spec.ingress {
        if let Some(bad) = ing
            .chain
            .iter()
            .find(|l| !manifest::CHAIN_LINKS.contains(&l.as_str()))
        {
            return Err(Error::Validation(format!(
                "{}: \"{bad}\" in an ingress chain — expected one of {}",
                m.metadata.name,
                manifest::CHAIN_LINKS.join(", ")
            )));
        }
    }

    // A path handed to a companion: a name that is none reaches no service, and Caddy
    // answers 502 there behind a route that otherwise works.
    for ing in &m.spec.ingress {
        let mut prefixes: Vec<&str> = Vec::new();
        for p in &ing.paths {
            let shaped = p.prefix.len() > 1
                && p.prefix.starts_with('/')
                && !p.prefix.ends_with('/')
                && p.prefix[1..].split('/').all(|seg| {
                    // A dot segment names another path once Caddy cleans it.
                    !seg.is_empty()
                        && seg != "."
                        && seg != ".."
                        && seg.chars().all(|c| {
                            c.is_ascii_lowercase() || c.is_ascii_digit() || "-_.".contains(c)
                        })
                });
            if !shaped {
                return Err(Error::Validation(format!(
                    "{}: path \"{}\" — a prefix such as /notification: a slash, then \
                     lowercase letters, digits, - _ . and slashes, with no slash at the end",
                    m.metadata.name, p.prefix
                )));
            }
            if !m.spec.companions.iter().any(|c| c.name == p.companion) {
                return Err(Error::Validation(format!(
                    "{}: path {} leads to \"{}\", which is none of its companions",
                    m.metadata.name, p.prefix, p.companion
                )));
            }
            if p.port == 0 || prefixes.contains(&p.prefix.as_str()) {
                return Err(Error::Validation(format!(
                    "{}: path {} — declared twice, or on port 0",
                    m.metadata.name, p.prefix
                )));
            }
            prefixes.push(&p.prefix);
        }
    }

    // The label becomes a placement constraint: anything Swarm cannot parse leaves the
    // service pending, with "no suitable node" as the only explanation.
    let labels = std::iter::once(&m.spec.swarm.node_label)
        .chain(m.spec.companions.iter().map(|c| &c.node_label))
        .flatten();
    for l in labels {
        if l.is_empty()
            || !l
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-')
        {
            return Err(Error::Validation(format!(
                "{}: nodeLabel \"{l}\" — lowercase letters, digits, dots and hyphens",
                m.metadata.name
            )));
        }
    }

    // A job is named on the command line and in the inbox; an empty command would
    // record a "failure" nobody can do anything about every night.
    let mut ids: Vec<&str> = Vec::new();
    for j in &m.spec.jobs {
        let named = !j.id.is_empty()
            && j.id
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
        if !named || ids.contains(&j.id.as_str()) || j.command.is_empty() || j.does.is_empty() {
            return Err(Error::Validation(format!(
                "{}: job \"{}\" — an id of lowercase letters, digits and hyphens, once, \
                 with what it does and a command",
                m.metadata.name, j.id
            )));
        }
        ids.push(&j.id);
    }

    validate_assertions(m)?;
    validate_access(m)?;

    // `latest` follows a mutable tag: a change cannot be detected reliably and there
    // is nothing to roll back to. It is an accident waiting to happen.
    if m.spec.update.channel == UpdateChannel::Latest {
        return Err(Error::Validation(format!(
            "{}: the \"latest\" channel is forbidden — use patch, minor or pin",
            m.metadata.name
        )));
    }
    for p in m.spec.ingress.iter().flat_map(|i| &i.open_paths) {
        let shape = p.starts_with('/')
            && !p.contains(char::is_whitespace)
            && !p.trim_end_matches('*').contains('*')
            && !p.trim_end_matches('*').trim_end_matches('/').is_empty();
        if !shape {
            return Err(Error::Validation(format!(
                "{}: openPaths — \"{p}\": an absolute path below the root, `*` only at its \
                 end; a whole host is opened by `expose`",
                m.metadata.name
            )));
        }
    }
    for route in m.spec.ingress.iter().flat_map(|i| &i.auth_routes) {
        let refuse = |why: String| {
            Err(Error::Validation(format!(
                "{}: authRoutes — {why}",
                m.metadata.name
            )))
        };
        if route.paths.is_empty() {
            return refuse("a route with no path limits nothing".into());
        }
        for p in &route.paths {
            let shape = p.starts_with('/')
                && !p.contains(char::is_whitespace)
                && !p.trim_end_matches('*').contains('*');
            if !shape {
                return refuse(format!("\"{p}\": an absolute path, `*` only at its end"));
            }
        }
        if let Some(code) = route.fails_with.filter(|c| !(400..500).contains(c)) {
            return refuse(format!(
                "failsWith {code}: a refusal is a 4xx — an app answering a wrong secret \
                 like a right one has no failure code, and leaves it out"
            ));
        }
    }
    let memories = std::iter::once(("the app", m.spec.swarm.memory)).chain(
        m.spec
            .companions
            .iter()
            .map(|c| (c.name.as_str(), c.memory)),
    );
    for (who, memory) in memories {
        if let Some(mem) = memory.filter(|mem| mem.reserve > mem.limit) {
            return Err(Error::Validation(format!(
                "{}: {who} reserves {} and is stopped at {} — Swarm would place it on a \
                 node with room it can never use",
                m.metadata.name,
                String::from(mem.reserve),
                String::from(mem.limit)
            )));
        }
    }
    if m.spec.update.maturation_days < manifest::MIN_MATURATION_DAYS {
        return Err(Error::Validation(format!(
            "{}: update.maturationDays is {} — never under {}",
            m.metadata.name,
            m.spec.update.maturation_days,
            manifest::MIN_MATURATION_DAYS
        )));
    }

    Ok(())
}

/// What the CATALOG holds to, beyond any manifest: every image by its digest.
///
/// A tag is mutable — `v2` was rebuilt the day before this was written — so two
/// installations of one catalog ran different code, and neither was the image anyone
/// had tried. The digest is the one the catalog was tested with; `hlb catalog images
/// --apply` moves it, never a person typing it.
/// Every value Swarm would refuse at deploy time — after the manifest is frozen — or
/// that would reach past the container, refused here instead.
fn validate_process(p: &Process) -> std::result::Result<(), String> {
    /// Swarm waits this long for each task of an update, one at a time: past an hour,
    /// a value is a typo of minutes for seconds.
    const MAX_GRACE_SECS: u64 = 3600;
    /// The limits Docker knows by name; any other is refused at deploy time.
    const ULIMITS: [&str; 15] = [
        "core",
        "cpu",
        "data",
        "fsize",
        "locks",
        "memlock",
        "msgqueue",
        "nice",
        "nofile",
        "nproc",
        "rss",
        "rtprio",
        "rttime",
        "sigpending",
        "stack",
    ];
    if p.stop_grace_secs.is_some_and(|s| s > MAX_GRACE_SECS) {
        return Err(format!("stopGraceSecs is over {MAX_GRACE_SECS}"));
    }
    if let Some(sig) = &p.stop_signal {
        let rest = sig.strip_prefix("SIG").unwrap_or_default();
        if rest.is_empty()
            || !rest
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'+')
        {
            return Err(format!(
                "stopSignal {sig:?} is not a signal's name (SIGINT)"
            ));
        }
    }
    if let Some(dir) = &p.working_dir {
        if !dir.starts_with('/') || dir.split('/').any(|seg| seg == "." || seg == "..") {
            return Err(format!("workingDir {dir:?} is not an absolute directory"));
        }
    }
    if let Some(h) = &p.hostname {
        let label = !h.is_empty()
            && h.len() <= 63
            && !h.starts_with('-')
            && !h.ends_with('-')
            && h.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if !label {
            return Err(format!(
                "hostname {h:?} is not a name of lowercase letters, digits and hyphens"
            ));
        }
    }
    for (name, l) in &p.ulimits {
        if !ULIMITS.contains(&name.as_str()) {
            return Err(format!("ulimit {name:?} is not one Docker knows"));
        }
        if l.soft > l.hard {
            return Err(format!("ulimit {name}'s soft limit is over its hard one"));
        }
    }
    for (key, value) in &p.sysctls {
        let named = key.strip_prefix("net.").is_some_and(|k| {
            !k.is_empty()
                && k.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        });
        if !named {
            return Err(format!(
                "sysctl {key:?} is not the container's own: only `net.*` lives in its namespace"
            ));
        }
        if value.is_empty() || value.contains(['\n', '\r']) {
            return Err(format!("sysctl {key} has no value on one line"));
        }
    }
    for g in &p.groups {
        if g.is_empty()
            || !g
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-'))
        {
            return Err(format!("group {g:?} is not a group's name or number"));
        }
    }
    Ok(())
}

pub fn validate_catalog_images(m: &Manifest) -> Result<()> {
    let images = std::iter::once(("the app", &m.spec.image)).chain(
        m.spec
            .companions
            .iter()
            .map(|c| (c.name.as_str(), &c.image)),
    );
    for (who, image) in images.filter(|(_, i)| !i.built_here) {
        let well_formed = image.digest.as_deref().is_some_and(|d| {
            d.strip_prefix("sha256:")
                .is_some_and(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()))
        });
        if !well_formed {
            return Err(Error::Validation(format!(
                "{}: {who}'s image {}:{} has no digest — the catalog pins every image \
                 (hlb catalog images --apply writes it)",
                m.metadata.name, image.repo, image.tag
            )));
        }
    }
    Ok(())
}

/// What the CATALOG holds to on memory: every service says what it needs and where it
/// is stopped, companions included. A manifest of a person's own may leave it out and
/// deploys without either, as every service did before the field.
pub fn validate_catalog_memory(m: &Manifest) -> Result<()> {
    let services = std::iter::once(("the app".to_string(), m.spec.swarm.memory)).chain(
        m.spec
            .companions
            .iter()
            .map(|c| (format!("companion {}", c.name), c.memory)),
    );
    for (who, memory) in services {
        if memory.is_none() {
            return Err(Error::Validation(format!(
                "{}: {who} declares no memory — the catalog reserves and limits every \
                 service (memory: {{ reserve: 256M, limit: 1G }})",
                m.metadata.name
            )));
        }
    }
    Ok(())
}

/// A guide's `api` calls, against the manifest whose app they reach.
///
/// 🔴 A call's body is filled at run time like a variable — the binding tokens, the
/// generated secrets and `{{ domain }}` — and anything else would reach the app as
/// token text: n8n's owner would be created with the password `{{ secret.typo }}`,
/// which nobody can then type.
pub fn validate_guide(m: &Manifest, g: &Guide) -> Result<()> {
    let app = &m.metadata.name;
    for step in &g.steps {
        let refuse = |why: String| {
            Err(Error::Validation(format!(
                "{app}: guide step \"{}\" — {why}",
                step.id
            )))
        };
        // A `recheck` is honoured by the nightly pass, or refused here: what it cannot
        // honour would read as a drift watched that nobody watches.
        let every = match step.recheck_secs() {
            Ok(every) => every,
            Err(why) => return refuse(why),
        };
        if let Some(every) = every {
            if every < guide::MIN_RECHECK_S {
                return refuse(format!(
                    "recheck {}: the pass that re-checks runs once a night, so never sooner \
                     than 24h",
                    step.recheck.as_deref().unwrap_or_default()
                ));
            }
            if step.phase != Phase::PreInstall {
                return refuse(
                    "a recheck re-reads a prerequisite (a DNS record, a router); a setting \
                     of the running app is judged nightly by `spec.assertions`"
                        .into(),
                );
            }
            if matches!(
                step.verify,
                Verify::Attest
                    | Verify::Exec {
                        command: _,
                        expect_contains: _
                    }
            ) {
                return refuse(format!(
                    "a recheck of a `{}` step checks nothing: it has no check the \
                     controller can run",
                    step.verify.kind()
                ));
            }
        }
        if step.phase == Phase::PostRestore {
            // Read by `hlb backup restore`, which runs the automations in order and
            // judges each by its exit: whatever else it said would be read by nothing.
            if step.is_blocking() {
                return refuse(
                    "a post-restore step blocks nothing: the restore is done when it runs".into(),
                );
            }
            if step.verify.is_automatic() {
                return refuse(
                    "a post-restore step is judged by its automation's exit; its `verify` \
                     would be read by nothing"
                        .into(),
                );
            }
            if !step.after.is_empty() {
                return refuse(
                    "post-restore steps run in the order they are written; `after` would be \
                     read by nothing"
                        .into(),
                );
            }
            for a in &step.automate {
                let unread = match a {
                    Automation::Env { .. } => Some("`env` is a deploy's"),
                    Automation::Sql { .. } => Some("`sql` is an install's"),
                    Automation::Exec { .. } | Automation::Api { .. } => None,
                };
                if let Some(whose) = unread {
                    return refuse(format!(
                        "a restore runs `exec` and `api` steps; {whose}, read by nothing here"
                    ));
                }
                let probed = match a {
                    Automation::Exec {
                        command: _,
                        service: _,
                        probe,
                        probe_matches,
                    } => probe.is_some() || probe_matches.is_some(),
                    Automation::Api {
                        port: _,
                        sign_in: _,
                        headers: _,
                        probe,
                        calls: _,
                    } => probe.is_some(),
                    Automation::Env { .. } | Automation::Sql { .. } => false,
                };
                if probed {
                    return refuse(
                        "a post-restore step runs on every restore: a probe saying it is done \
                         already would read what the restore just replaced"
                            .into(),
                    );
                }
            }
        }
        // An install never plans a post-restore step: one waiting on it would wait forever.
        for before in &step.after {
            if g.steps
                .iter()
                .any(|s| &s.id == before && s.phase == Phase::PostRestore)
                && step.phase.at_install()
            {
                return refuse(format!(
                    "it comes after \"{before}\", a post-restore step no install runs"
                ));
            }
        }
        for a in &step.automate {
            match a {
                Automation::Env { .. } => {}
                Automation::Exec {
                    command: _,
                    service,
                    probe: _,
                    probe_matches: _,
                } => {
                    if let Some(c) = service {
                        if !m.spec.companions.iter().any(|k| &k.name == c) {
                            return refuse(format!(
                                "its `exec` runs in \"{c}\", which is none of {app}'s companions"
                            ));
                        }
                    }
                }
                Automation::Api {
                    port,
                    sign_in,
                    headers,
                    probe,
                    calls,
                } => {
                    if let Some(secret) = sign_in {
                        // A restore is handed no sign-in: the step would fail on every
                        // restore, saying only that none was looked up.
                        if step.phase == Phase::PostRestore {
                            return refuse("a restore signs in nowhere yet".into());
                        }
                        if let Err(why) = token_sign_in(m, secret, headers) {
                            return refuse(why);
                        }
                    }
                    if let Err(why) = token_headers(headers, sign_in.is_some()) {
                        return refuse(why);
                    }
                    if calls.is_empty() {
                        return refuse(
                            "an `api` automation with no call does nothing, and says it did".into(),
                        );
                    }
                    if port.is_none() && m.spec.ingress.is_empty() {
                        return refuse(
                            "an `api` call with no port, and no ingress to take one from".into(),
                        );
                    }
                    if let Some(p) = probe {
                        if !p.pointer.starts_with('/')
                            || serde_json::from_str::<serde_json::Value>(&p.equals).is_err()
                        {
                            return refuse(format!(
                                "probe {} = {} — a JSON pointer, and a value written as JSON",
                                p.pointer, p.equals
                            ));
                        }
                    }
                    for c in calls {
                        if !c.path.starts_with('/') {
                            return refuse(format!("path \"{}\" starts with /", c.path));
                        }
                        if let Some(body) = &c.body {
                            check_run_tokens(m, body).or_else(refuse)?;
                        }
                        if c.merge {
                            let object = c
                                .body
                                .as_deref()
                                .and_then(|b| serde_json::from_str::<serde_json::Value>(b).ok())
                                .is_some_and(|v| v.is_object());
                            if !object || c.verb.eq_ignore_ascii_case("GET") {
                                return refuse(format!(
                                    "{} {} merges: a body that is one JSON object, sent by \
                                     another verb than the GET it is merged over",
                                    c.verb, c.path
                                ));
                            }
                        }
                    }
                }
                Automation::Sql {
                    statement,
                    params,
                    probe,
                    restart: _,
                } => {
                    let postgres = m.spec.requires.iter().any(|c| {
                        matches!(
                            c,
                            Capability::Database {
                                engine: DbEngine::Postgres,
                                ..
                            }
                        )
                    });
                    if !postgres {
                        return refuse(
                            "an `sql` automation writes in the app's PostgreSQL database, which \
                             it does not require"
                                .into(),
                        );
                    }
                    for (what, text, verb) in [
                        ("statement", statement, "update "),
                        ("probe", probe, "select "),
                    ] {
                        if !text.trim_start().to_ascii_lowercase().starts_with(verb)
                            || text.trim_end().trim_end_matches(';').contains(';')
                        {
                            return refuse(format!(
                                "the {what} is one {}",
                                verb.trim().to_uppercase()
                            ));
                        }
                        // A value written into the text would be logged with it: a
                        // secret is a parameter, never part of the statement.
                        if text.contains("{{") {
                            return refuse(format!(
                                "the {what} takes its values as $1, $2…, never as a token"
                            ));
                        }
                        if let Some(n) = highest_parameter(text).filter(|n| *n > params.len()) {
                            return refuse(format!(
                                "the {what} reads ${n}, and {} params are given",
                                params.len()
                            ));
                        }
                    }
                    if highest_parameter(statement) != Some(params.len()) {
                        return refuse("the statement binds every param, $1 to the last".into());
                    }
                    for p in params {
                        check_run_tokens(m, p).or_else(refuse)?;
                    }
                }
            }
        }
        if let Verify::Http {
            url: _,
            expect_status,
            expect_json,
        } = &step.verify
        {
            if let Some(j) = expect_json {
                if !j.pointer.starts_with('/')
                    || serde_json::from_str::<serde_json::Value>(&j.equals).is_err()
                {
                    return refuse(format!(
                        "expectJson {} = {} — a JSON pointer, and a value written as JSON",
                        j.pointer, j.equals
                    ));
                }
            }
            // 🔴 Immich's "create the administrator" was verified by `/api/server/ping`:
            // healthy, so `hlb todo --verify` opened the route to the internet while
            // the first stranger to register would have become its administrator.
            let success = expect_status.iter().any(|c| (200..300).contains(c));
            if step.phase != Phase::PreInstall && success && expect_json.is_none() {
                return refuse(
                    "a 2xx proves the app answers, which its install already established — \
                     read what the step changes with `expectJson`, or let a person attest it"
                        .into(),
                );
            }
        }
    }
    validate_recovery(m, g)
}

/// The highest `$n` a statement reads.
fn highest_parameter(text: &str) -> Option<usize> {
    let b = text.as_bytes();
    (0..b.len())
        .filter(|&i| b[i] == b'$')
        .filter_map(|i| {
            let digits: String = text[i + 1..]
                .chars()
                .take_while(char::is_ascii_digit)
                .collect();
            digits.parse().ok()
        })
        .max()
}

/// The tokens a guide automation fills at run time: generated secrets, the domain, and
/// the bindings of capabilities the app declares.
fn check_run_tokens(m: &Manifest, text: &str) -> std::result::Result<(), String> {
    for found in binding::generated_secrets(text) {
        if let Err(bad) = found {
            return Err(format!("\"{bad}\" is no generated secret"));
        }
    }
    let mut rest = text;
    while let Some(at) = rest.find("{{") {
        let inner = rest[at + 2..].split("}}").next().unwrap_or("").trim();
        rest = &rest[at + 2..];
        if inner.starts_with("secret.") || inner == "domain" {
            continue;
        }
        let Some(t) = Token::all()
            .iter()
            .find(|t| t.placeholder() == format!("{{{{ {inner} }}}}"))
        else {
            return Err(format!("{{{{ {inner} }}}} is filled by nothing"));
        };
        if let Some(needed) = t.requires() {
            if !m.spec.requires.iter().any(|c| c.id() == needed) {
                return Err(format!(
                    "{} needs the \"{needed}\" capability, which the app does not declare",
                    t.placeholder()
                ));
            }
        }
    }
    Ok(())
}

/// A recovery sign-in deposits a secret something generates, under a name the deposit
/// can fill — and a secret a guide sends a person to read in order to sign in IS one.
///
/// 🔴 Declared and generated nowhere, the emergency vault would hold nothing for the
/// app; generated and not declared, it holds nothing either, and nothing says so — the
/// day PocketID is down is when that is found.
fn validate_recovery(m: &Manifest, g: &Guide) -> Result<()> {
    let app = &m.metadata.name;
    let refuse = |why: String| Err(Error::Validation(format!("{app}: recovery — {why}")));
    let mut texts: Vec<&str> = m.spec.substituted().map(String::as_str).collect();
    texts.extend(m.spec.command.iter().map(String::as_str));
    for step in &g.steps {
        for a in &step.automate {
            match a {
                Automation::Api { calls, .. } => {
                    texts.extend(calls.iter().filter_map(|c| c.body.as_deref()));
                }
                Automation::Sql { params, .. } => texts.extend(params.iter().map(String::as_str)),
                Automation::Env { .. } | Automation::Exec { .. } => {}
            }
        }
    }
    let generated: std::collections::BTreeSet<String> = texts
        .iter()
        .flat_map(|t| binding::generated_secrets(t))
        .filter_map(|r| r.ok().map(|s| s.name))
        .collect();
    let smtp = m
        .spec
        .requires
        .iter()
        .any(|c| matches!(c, Capability::Smtp { .. }));
    for r in &m.spec.recovery {
        if !generated.contains(&r.secret) {
            return refuse(format!(
                "\"{}\" is generated nowhere — no `{{{{ secret.{} }}}}` in the manifest or its guide",
                r.secret, r.secret
            ));
        }
        let mut rest = r.username.as_deref().unwrap_or_default();
        while let Some(at) = rest.find("{{") {
            let inner = rest[at + 2..].split("}}").next().unwrap_or("").trim();
            if inner != "smtp.from" {
                return refuse(format!(
                    "the username's {{{{ {inner} }}}} is not filled by a deposit — only \
                     {{{{ smtp.from }}}} is"
                ));
            }
            if !smtp {
                return refuse("{{ smtp.from }} needs the \"smtp\" capability".into());
            }
            rest = &rest[at + 2..];
        }
        if r.path.as_deref().is_some_and(|p| !p.starts_with('/')) {
            return refuse(format!("path of \"{}\" starts with /", r.secret));
        }
        validate_sign_in(m, r)
            .or_else(|why| refuse(format!("proof of \"{}\": {why}", r.secret)))?;
    }
    let read_by_hand = format!("hlb secret-get {app}-");
    for step in &g.steps {
        let mut rest = step.body.as_str();
        while let Some(at) = rest.find(&read_by_hand) {
            rest = &rest[at + read_by_hand.len()..];
            let name: String = rest
                .chars()
                .take_while(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '-')
                .collect();
            if generated.contains(&name) && !m.spec.recovery.iter().any(|r| r.secret == name) {
                return refuse(format!(
                    "guide step \"{}\" signs a person in with \"{name}\", which is no \
                     recovery sign-in — declare it under `recovery`, or the emergency vault \
                     never holds it",
                    step.id
                ));
            }
        }
    }
    Ok(())
}

/// A recovery sign-in's proof sends what the deposit holds, and reads an answer.
fn validate_sign_in(m: &Manifest, r: &RecoveryLogin) -> std::result::Result<(), String> {
    let Some(p) = &r.proof else {
        return Err("none — a password nobody signs in with is not known to open anything".into());
    };
    if m.spec.ingress.is_empty() {
        return Err("the app has no ingress port to sign in on".into());
    }
    if !p.path.starts_with('/') || !p.pointer.starts_with('/') {
        return Err("its path and its pointer start with /".into());
    }
    let body: serde_json::Value =
        serde_json::from_str(&p.body).map_err(|e| format!("its body is not JSON: {e}"))?;
    let mut strings = Vec::new();
    json_strings(&body, &mut strings);
    let says = |token: &str| strings.iter().any(|s| s.contains(token));
    if p.form {
        if p.basic {
            return Err("a form or HTTP Basic, not both".into());
        }
        let flat = body
            .as_object()
            .is_some_and(|o| o.values().all(serde_json::Value::is_string));
        if !flat {
            return Err("a form's body is one JSON object of strings".into());
        }
    }
    if p.basic {
        if r.username.is_none() {
            return Err("HTTP Basic needs the username the deposit holds".into());
        }
        if strings.iter().any(|s| s.contains("{{")) {
            return Err(
                "under HTTP Basic the body sends neither {{ username }} nor {{ password }}".into(),
            );
        }
        return Ok(());
    }
    if !says("{{ password }}") {
        return Err("its body sends no {{ password }}".into());
    }
    // A username the deposit holds and the proof never sends proves another sign-in.
    if r.username.is_some() != says("{{ username }}") {
        return Err(if r.username.is_some() {
            "its body sends no {{ username }}, which the deposit holds".into()
        } else {
            "its body sends a {{ username }}, and the deposit holds none".into()
        });
    }
    // Outside a string, `{{` is no JSON at all: the parse above refused it.
    let unknown = |t: &str| {
        t.match_indices("{{").any(|(at, _)| {
            !["{{ username }}", "{{ password }}"]
                .iter()
                .any(|k| t[at..].starts_with(k))
        })
    };
    if strings.iter().any(|s| unknown(s)) {
        return Err("only {{ username }} and {{ password }} are filled".into());
    }
    if p.headers
        .iter()
        .any(|(k, v)| k.contains("{{") || v.contains("{{"))
    {
        return Err("a header is sent as written: no {{ }} in it".into());
    }
    Ok(())
}

fn json_strings<'v>(v: &'v serde_json::Value, out: &mut Vec<&'v str>) {
    match v {
        serde_json::Value::String(s) => out.push(s),
        serde_json::Value::Array(a) => a.iter().for_each(|v| json_strings(v, out)),
        serde_json::Value::Object(o) => o.values().for_each(|v| json_strings(v, out)),
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {}
    }
}

/// An assertion that can never pass is a door reported open forever — and one read
/// from nowhere is a door reported closed by nobody.
fn validate_assertions(m: &Manifest) -> Result<()> {
    let app = &m.metadata.name;
    let refuse = |id: &str, why: String| {
        Err(Error::Validation(format!(
            "{app}: assertion \"{id}\" — {why}"
        )))
    };
    let databases: Vec<Option<&str>> = m
        .spec
        .requires
        .iter()
        .filter_map(|c| match c {
            Capability::Database { name, .. } => Some(name.as_deref()),
            _ => None,
        })
        .collect();
    let mut seen: Vec<&str> = Vec::new();
    for a in &m.spec.assertions {
        let id = a.id.as_str();
        if id.is_empty()
            || !id
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        {
            return refuse(
                id,
                "an id is lowercase letters, digits and hyphens: results are stored under it"
                    .into(),
            );
        }
        if seen.contains(&id) {
            return refuse(
                id,
                "declared twice: the second result would overwrite the first".into(),
            );
        }
        seen.push(id);
        if a.holds.trim().is_empty() {
            return refuse(
                id,
                "`holds` says what is true while it passes — the inbox has nothing else to say"
                    .into(),
            );
        }
        match &a.check {
            Check::Http {
                path,
                port,
                status,
                pointer,
                equals,
                contains: _,
                host,
            } => {
                if host.as_deref().is_some_and(|h| {
                    h.is_empty()
                        || !h
                            .chars()
                            .all(|c| c.is_ascii_alphanumeric() || ".-".contains(c))
                }) {
                    return refuse(id, "host: a name, letters, digits, dots and hyphens".into());
                }
                if !path.starts_with('/') {
                    return refuse(
                        id,
                        format!(
                            "path \"{path}\" starts with /: it is read on the app's own address"
                        ),
                    );
                }
                if port.is_none() && m.spec.ingress.is_empty() {
                    return refuse(id, "no port, and no ingress to take one from".into());
                }
                if status.is_empty() {
                    return refuse(id, "no expected status: every answer would fail it".into());
                }
                match (pointer, equals) {
                    (Some(p), Some(_)) if !p.starts_with('/') => {
                        return refuse(
                            id,
                            format!("pointer \"{p}\" is a JSON pointer, starting with /"),
                        );
                    }
                    (Some(_), None) | (None, Some(_)) => {
                        return refuse(id, "`pointer` and `equals` go together: one without the other reads nothing".into());
                    }
                    _ => {}
                }
            }
            Check::Env { name, equals } => match m.spec.env.get(name) {
                None => {
                    return refuse(id, format!("{name} is not in spec.env: the assertion would check the image's default, which nothing here decides"));
                }
                Some(v) if v != equals => {
                    return refuse(id, format!("spec.env sets {name} to \"{v}\", the assertion expects \"{equals}\": it could never pass"));
                }
                Some(_) => {}
            },
            Check::Sql {
                query,
                database,
                equals: _,
            } => {
                if databases.is_empty() {
                    return refuse(
                        id,
                        "an SQL assertion reads the app's own database, and it requires none"
                            .into(),
                    );
                }
                match database {
                    None if databases.len() > 1 => {
                        return refuse(
                            id,
                            "the app has several databases: say which with `database`".into(),
                        );
                    }
                    Some(d) if !databases.iter().any(|n| n.unwrap_or(app.as_str()) == d) => {
                        return refuse(id, format!("database \"{d}\" is not one the app requires"));
                    }
                    _ => {}
                }
                // The transaction is read-only anyway; refused here, a write is a
                // mistake found at validation rather than a failure every night.
                let q = query.trim_start().to_ascii_lowercase();
                if !q.starts_with("select ") || query.trim_end().trim_end_matches(';').contains(';')
                {
                    return refuse(id, "an SQL assertion is one SELECT".into());
                }
            }
        }
    }
    Ok(())
}

/// A recovery sign-in a request signs in with, its token carried by `headers`: a
/// `recovery` entry with a proof, not HTTP Basic.
fn token_sign_in(
    m: &Manifest,
    secret: &str,
    headers: &std::collections::BTreeMap<String, String>,
) -> std::result::Result<(), String> {
    let Some(r) = m.spec.recovery.iter().find(|r| r.secret == secret) else {
        return Err(format!(
            "it signs in with \"{secret}\", which no `recovery` entry names"
        ));
    };
    let Some(proof) = &r.proof else {
        return Err(format!(
            "it signs in with \"{secret}\", whose recovery entry says no `proof` to sign in by"
        ));
    };
    // Basic sends the password with every request, and makes no token a request could
    // carry: no app of the catalog needs it here.
    if proof.basic {
        return Err(format!(
            "it signs in with \"{secret}\", whose proof is HTTP Basic: a request carries a \
             token, never the password"
        ));
    }
    if !headers.values().any(|v| v.contains("{{ token }}")) {
        return Err(format!(
            "it signs in with \"{secret}\" and sends the token in no header"
        ));
    }
    Ok(())
}

/// A header is sent as written but for the token: whatever else is between braces
/// would reach the app literal.
fn token_headers(
    headers: &std::collections::BTreeMap<String, String>,
    signed_in: bool,
) -> std::result::Result<(), String> {
    for (name, value) in headers {
        let mut rest = value.as_str();
        while let Some(at) = rest.find("{{") {
            let inner = rest[at + 2..].split("}}").next().unwrap_or("");
            rest = &rest[at + 2..];
            if inner != " token " || !signed_in {
                return Err(format!(
                    "header {name} holds {{{{{inner}}}}}: a header takes `{{{{ token }}}}`, and \
                     only from a `signIn`"
                ));
            }
        }
    }
    Ok(())
}

/// How an app's accounts are kept enabled: each request's path, pointer and verb.
fn validate_accounts(m: &Manifest, a: &access::Accounts) -> std::result::Result<(), String> {
    let access::AccountsApply::Http {
        sign_in,
        headers,
        links,
        read,
        disabled,
        write,
    } = &a.apply;
    if m.spec.ingress.is_empty() {
        return Err("no ingress to take the API's port from".into());
    }
    token_sign_in(m, sign_in, headers)?;
    token_headers(headers, true)?;
    for (what, pointer) in [
        ("links", &links.pointer),
        ("read", &read.pointer),
        ("disabled", disabled),
    ] {
        if !pointer.is_empty() && !pointer.starts_with('/') {
            return Err(format!(
                "{what}'s pointer \"{pointer}\" is a JSON pointer: \"\" or starting with /"
            ));
        }
    }
    // An empty pointer would make the flag the object itself: nothing to set.
    if disabled.is_empty() {
        return Err("`disabled` points at the flag inside the object read".into());
    }
    if !matches!(write.verb.as_str(), "POST" | "PUT" | "PATCH") {
        return Err(format!(
            "write's verb \"{}\" — POST, PUT or PATCH",
            write.verb
        ));
    }
    if !access::placeholders(&links.path).is_empty() {
        return Err(format!(
            "links' path \"{}\" is one request, filled by nothing",
            links.path
        ));
    }
    for (what, path) in [("read", &read.path), ("write", &write.path)] {
        let tokens = access::placeholders(path);
        if let Some(t) = tokens.iter().find(|t| !access::ACCOUNT_TOKENS.contains(t)) {
            return Err(format!(
                "{what}'s path: {{{{ {t} }}}} is filled by nothing — {}",
                access::ACCOUNT_TOKENS.join(", ")
            ));
        }
        // Without it, every account would be read or written at one path.
        if !tokens.contains(&"account") {
            return Err(format!(
                "{what}'s path \"{path}\" names no {{{{ account }}}}"
            ));
        }
    }
    for path in [&links.path, &read.path, &write.path] {
        if !path.starts_with('/') {
            return Err(format!("path \"{path}\" starts with /"));
        }
    }
    Ok(())
}

/// An app's access, against what reads it: a claim no token carries to the app, a
/// quota nothing applies, a level no allowed role ever reaches.
fn validate_access(m: &Manifest) -> Result<()> {
    use access::QuotaApply;
    let Some(a) = &m.spec.access else {
        return Ok(());
    };
    let app = &m.metadata.name;
    let refuse = |why: String| Err(Error::Validation(format!("{app}: access — {why}")));
    let mode = m.spec.requires.iter().find_map(|c| match c {
        Capability::Sso { mode, .. } => Some(*mode),
        _ => None,
    });
    let native = mode == Some(SsoMode::Native);
    if !matches!(
        mode,
        Some(SsoMode::Native | SsoMode::ProxyOnly | SsoMode::ProxyHeader)
    ) {
        return refuse(
            "the app signs nobody in through PocketID: no role would ever be checked".into(),
        );
    }
    if !native
        && (!a.claims.is_empty()
            || a.quota.is_some()
            || a.members.is_some()
            || a.accounts.is_some())
    {
        return refuse(
            "claims, quotas, members and accounts reach an app through its own OIDC client: \
             behind the portal it never sees them"
                .into(),
        );
    }
    if let Some(accounts) = &a.accounts {
        if let Err(why) = validate_accounts(m, accounts) {
            return refuse(format!("accounts.apply: {why}"));
        }
    }
    if let Some(admins) = &a.admins {
        if admins.level < a.floor {
            return refuse(format!(
                "admins at \"{}\", below the floor \"{}\": no allowed role is there",
                admins.level.as_str(),
                a.floor.as_str()
            ));
        }
        if admins.means.trim().is_empty() {
            return refuse("admins.means says what administering the app gives".into());
        }
        if let Some(how) = &admins.apply {
            if how.grant.is_empty() || how.revoke.is_empty() {
                return refuse("admins.apply grants and revokes, each by a command".into());
            }
            if let Some(s) = &how.service {
                if !m.spec.companions.iter().any(|c| &c.name == s) {
                    return refuse(format!(
                        "admins.apply runs in \"{s}\", which is none of its companions"
                    ));
                }
            }
            for t in access::placeholders(
                &how.grant
                    .iter()
                    .chain(&how.revoke)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(" "),
            ) {
                if !access::ADMIN_TOKENS.contains(&t) {
                    return refuse(format!(
                        "admins.apply: {{{{ {t} }}}} is filled by nothing — {}",
                        access::ADMIN_TOKENS.join(", ")
                    ));
                }
            }
        }
    }
    let quota_claim = a
        .quota
        .as_ref()
        .and_then(|q| q.claim.as_ref())
        .map(|c| c.name.as_str());
    for name in a.claims.keys().map(String::as_str).chain(quota_claim) {
        if name.is_empty()
            || !name
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        {
            return refuse(format!(
                "claim \"{name}\" — lowercase letters, digits and underscores"
            ));
        }
        if access::RESERVED_CLAIMS.contains(&name) {
            return refuse(format!(
                "claim \"{name}\" is PocketID's own: a custom one would be refused or ignored"
            ));
        }
    }
    if quota_claim.is_some_and(|q| a.claims.contains_key(q)) {
        return refuse(
            "the quota's claim is also in `claims`: one would overwrite the other".into(),
        );
    }
    for (name, claim) in &a.claims {
        match (&claim.by_level, &claim.json) {
            (Some(levels), None) => {
                // An allowed role with no value would sign in without the claim: Gitea
                // requiring it would refuse them, and nothing would say why.
                if levels.range(..=a.floor).next().is_none() {
                    return refuse(format!(
                        "claim \"{name}\" has no value at the floor \"{}\": a role allowed in \
                         would get none",
                        a.floor.as_str()
                    ));
                }
                if levels.values().any(|v| v.trim().is_empty()) {
                    return refuse(format!("claim \"{name}\" has an empty value"));
                }
            }
            (None, Some(v)) => {
                let text = v.to_string();
                for t in access::placeholders(&text) {
                    if !access::ROLE_TOKENS.contains(&t) {
                        return refuse(format!(
                            "claim \"{name}\": {{{{ {t} }}}} is filled by nothing — {}",
                            access::ROLE_TOKENS.join(", ")
                        ));
                    }
                }
            }
            _ => {
                return refuse(format!(
                    "claim \"{name}\" is `byLevel` or `json`, exactly one"
                ));
            }
        }
    }
    if let Some(q) = &a.quota {
        if q.claim.is_none() && q.apply.is_none() {
            return refuse("a quota with no claim and nothing to apply it reaches nobody".into());
        }
        let text = match &q.apply {
            None => String::new(),
            Some(QuotaApply::Exec { command, unit: _ }) => {
                if command.is_empty() {
                    return refuse("quota.apply runs no command".into());
                }
                command.join(" ")
            }
            Some(QuotaApply::Sql {
                statement,
                database,
                unit: _,
            }) => {
                let databases: Vec<&str> = m
                    .spec
                    .requires
                    .iter()
                    .filter_map(|c| match c {
                        Capability::Database { name, .. } => {
                            Some(name.as_deref().unwrap_or(app.as_str()))
                        }
                        _ => None,
                    })
                    .collect();
                match database {
                    _ if databases.is_empty() => {
                        return refuse(
                            "quota.apply's statement needs a database the app requires".into(),
                        );
                    }
                    None if databases.len() > 1 => {
                        return refuse(
                            "the app has several databases: say which with `database`".into(),
                        );
                    }
                    Some(d) if !databases.contains(&d.as_str()) => {
                        return refuse(format!("database \"{d}\" is not one the app requires"));
                    }
                    _ => {}
                }
                let s = statement.trim_start().to_ascii_lowercase();
                if !s.starts_with("update ")
                    || statement.trim_end().trim_end_matches(';').contains(';')
                {
                    return refuse("quota.apply's statement is one UPDATE".into());
                }
                // The subject is written into the statement: inside quotes, it is a
                // value whatever it holds — and it is checked to be an id first.
                if !statement.contains("'{{ person.sub }}'") {
                    return refuse(
                        "quota.apply's statement takes the subject as '{{ person.sub }}', quoted"
                            .into(),
                    );
                }
                statement.clone()
            }
        };
        let used = access::placeholders(&text);
        if let Some(t) = used.iter().find(|t| !access::QUOTA_TOKENS.contains(t)) {
            return refuse(format!(
                "quota.apply: {{{{ {t} }}}} is filled by nothing — {}",
                access::QUOTA_TOKENS.join(", ")
            ));
        }
        if q.apply.is_some() && access::QUOTA_TOKENS.iter().any(|t| !used.contains(t)) {
            return refuse("quota.apply takes both {{ person.sub }} and {{ quota }}: without one it sets nobody's, or nothing".into());
        }
    }
    Ok(())
}

/// What holds at deploy time for any manifest, the catalog's or a person's own: the
/// image resolved to a digest, which the catalog's carry already
/// ([`validate_catalog_images`]) and a person's gets at install.
pub fn validate_pinned(m: &Manifest) -> Result<()> {
    if !m.spec.image.is_pinned() {
        return Err(Error::Validation(format!(
            "{}: deployment refused without a resolved digest",
            m.metadata.name
        )));
    }
    Ok(())
}

/// The manifest's JSON Schema, for editor autocompletion.
pub fn manifest_json_schema() -> String {
    let schema = schemars::schema_for!(Manifest);
    serde_json::to_string_pretty(&schema).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(yaml: &str) -> Manifest {
        serde_yaml_ng::from_str(yaml).expect("valid test yaml")
    }

    const BASE: &str = r#"
apiVersion: hlb/v1
kind: App
metadata: { name: test }
spec:
  image: { repo: acme/test, tag: "1.0", digest: "sha256:abc" }
"#;

    #[test]
    fn a_signer_names_one_workflow_of_one_repository_on_a_tag() {
        let s = ImageSigner {
            github: "go-vikunja/vikunja".into(),
            workflow: "release.yml".into(),
        };
        let re = s.identity_regexp();
        assert_eq!(
            re,
            "^https://github\\.com/go-vikunja/vikunja/\\.github/workflows/release\\.yml\
             @refs/tags/[^@]+$"
        );
        let re = regex::Regex::new(&re).expect("an expression cosign reads");
        // The certificate's SAN, measured on Vikunja 2.7.1's signature.
        let release = "https://github.com/go-vikunja/vikunja/.github/workflows/release.yml";
        assert!(re.is_match(&format!("{release}@refs/tags/v2.7.1")));
        for other in [
            format!("{release}@refs/heads/main"),
            "https://github.com/go-vikunja/vikunja/.github/workflows/nightly.yml@refs/tags/v1"
                .into(),
            "https://githubXcom/go-vikunja/vikunja/.github/workflows/release.yml@refs/tags/v1"
                .into(),
            // Matched anywhere unless anchored: an attacker's workflow naming the real one.
            format!("https://github.com/attacker/x/.github/workflows/a.yml?{release}@refs/tags/v1"),
            format!("{release}@refs/tags/v1@evil"),
        ] {
            assert!(!re.is_match(&other), "{other}");
        }
    }

    #[test]
    fn a_signer_is_a_repository_and_a_workflow_file() {
        for (signer, why) in [
            (
                "{ github: go-vikunja, workflow: release.yml }",
                "owner/repository",
            ),
            (
                "{ github: a/b/c, workflow: release.yml }",
                "owner/repository",
            ),
            (
                "{ github: \"a/b c\", workflow: release.yml }",
                "owner/repository",
            ),
            ("{ github: a/b, workflow: ../x.yml }", "file name"),
            ("{ github: a/b, workflow: release }", "file name"),
            ("{ github: a/b, workflow: \"\" }", "file name"),
        ] {
            let yaml = BASE.replace(
                "digest: \"sha256:abc\" }",
                &format!("digest: \"sha256:abc\", signedBy: {signer} }}"),
            );
            let err = validate(&manifest(&yaml)).expect_err(signer).to_string();
            assert!(err.contains(why), "{signer}: {err}");
        }
        let yaml = BASE.replace(
            "digest: \"sha256:abc\" }",
            "digest: \"sha256:abc\", signedBy: { github: go-vikunja/vikunja, workflow: release.yml } }",
        );
        validate(&manifest(&yaml)).expect("a well-formed signer");
    }

    #[test]
    fn a_declaration_nothing_reads_is_refused() {
        // 🔴 Found by review: each of these was accepted, carried, and read by nothing —
        // a bucket shown as backed up that no pass backs up among them.
        for (extra, why) in [
            ("  update: { autoRollback: false }\n", "autoRollback"),
            (
                "  update: { watchUpstream: acme/upstream }\n",
                "watchUpstream",
            ),
            (
                "  requires:\n    - { kind: mail-account, aliases: true }\n",
                "aliases",
            ),
            (
                "  requires:\n    - { kind: sso, mode: none, redirectPaths: [/cb] }\n",
                "redirectPaths",
            ),
            (
                "  requires:\n    - { kind: database, engine: postgres, name: a }\n    - { kind: \
                 database, engine: postgres, name: b }\n  env: { U: \"{{ db.url }}\" }\n",
                "names the last one only",
            ),
            (
                "  requires:\n    - { kind: database, engine: postgres }\n    - { kind: \
                 database, engine: mariadb, name: b }\n  env: { H: \"{{ db.host }}\" }\n",
                "two engines",
            ),
            (
                "  requires:\n    - { kind: object-storage, backup: false, bucket: a }\n    - { \
                 kind: object-storage, backup: false, bucket: b }\n  env: { B: \"{{ s3.bucket }}\" }\n",
                "names the last one only",
            ),
            (
                "  requires:\n    - { kind: object-storage, backup: false }\n    - { \
                 kind: object-storage, backup: false, bucket: test }\n  env: { B: \"{{ s3.endpoint }}\" }\n",
                "declared twice",
            ),
            (
                "  requires:\n    - { kind: object-storage, backup: false, expireAfterDays: 0 }\n  \
                 env: { B: \"{{ s3.bucket }}\" }\n",
                "expireAfterDays 0",
            ),
        ] {
            let yaml = format!("{BASE}{extra}");
            let refusal = validate(&manifest(&yaml)).expect_err(why).to_string();
            assert!(refusal.contains(why), "{refusal}");
        }
        // What is read stays accepted.
        for fine in [
            "  requires:\n    - { kind: object-storage, backup: false }\n  env: { B: \"{{ s3.bucket }}\" }\n",
            // Backed up by the pass, since 2026-10-26.
            "  requires:\n    - { kind: object-storage }\n  env: { B: \"{{ s3.bucket }}\" }\n",
            "  requires:\n    - { kind: object-storage, backup: false, bucket: a }\n    - { kind: \
             object-storage, backup: false, bucket: b, expireAfterDays: 1 }\n  env: { B: \"a b {{ s3.endpoint }}\" }\n",
            "  requires:\n    - { kind: database, engine: mariadb, name: a }\n    - { kind: database, \
             engine: mariadb, name: b }\n  env: { H: \"{{ db.host }}\" }\n",
        ] {
            assert!(validate(&manifest(&format!("{BASE}{fine}"))).is_ok(), "{fine}");
        }
    }

    #[test]
    fn several_replicas_over_a_local_volume_are_refused() {
        let m: Manifest = serde_yaml_ng::from_str(
            r#"
apiVersion: hlb/v1
kind: App
metadata: { name: vikunja }
spec:
  image: { repo: vikunja/vikunja, tag: "0.24" }
  requires:
    - kind: storage
      name: files
      path: /files
      tier: local
  swarm:
    replicas: 2
"#,
        )
        .expect("parsable");
        let refusal = validate(&m).expect_err("refused").to_string();
        assert!(refusal.contains("exists once per node"), "{refusal}");
    }

    #[test]
    fn administrators_told_by_command_run_where_and_with_what_is_filled() {
        let with = |apply: &str| {
            let y = format!(
                "{BASE}  env: {{ ID: \"{{{{ oidc.client_id }}}}\" }}\n  requires:\n    \
                 - {{ kind: sso, mode: native, redirectPaths: [/cb] }}\n  companions:\n    \
                 - {{ name: api, image: {{ repo: a/api, tag: \"1\" }} }}\n  access:\n    \
                 admins:\n      level: admin\n      means: the instance\n      apply: {apply}\n"
            );
            validate(&manifest(&y)).map_err(|e| e.to_string())
        };
        let cmd = |verb: &str, token: &str| format!("[node, a.mjs, {verb}, \"{{{{ {token} }}}}\"]");
        let ok = format!(
            "{{ service: api, grant: {}, revoke: {} }}",
            cmd("grant", "person.sub"),
            cmd("revoke", "person.sub")
        );
        assert_eq!(with(&ok), Ok(()));
        assert!(with(&ok.replace("service: api", "service: apu"))
            .expect_err("no such companion")
            .contains("none of its companions"));
        assert!(with(&format!(
            "{{ grant: {}, revoke: [] }}",
            cmd("grant", "person.sub")
        ))
        .expect_err("nothing takes it back")
        .contains("grants and revokes"));
        assert!(
            with(&ok.replace("revoke, \"{{ person.sub }}\"", "revoke, \"{{ quota }}\""))
                .expect_err("a token nothing fills")
                .contains("filled by nothing")
        );
    }

    #[test]
    fn accounts_kept_by_role_sign_in_by_token_and_name_the_account_they_write() {
        const OK: &str = r#"
    accounts:
      apply:
        type: http
        signIn: admin-password
        headers: { Authorization: "Token={{ token }}" }
        links: { path: /Plugins/sso/Configuration, pointer: /OidConfigs/PocketID/CanonicalLinks }
        read: { path: "/Users/{{ account }}", pointer: /Policy }
        disabled: /IsDisabled
        write: { verb: POST, path: "/Users/{{ account }}/Policy" }
"#;
        let with = |sso: &str, proof: &str, accounts: &str| {
            let y = format!(
                "{BASE}  env: {{ ID: \"{{{{ oidc.client_id }}}}\" }}\n  requires:\n    - {sso}\n  \
                 ingress:\n    - {{ host: a.example.fr, port: 8096 }}\n  recovery:\n    \
                 - secret: admin-password\n      username: admin\n      proof: {proof}\n  \
                 access:{accounts}"
            );
            validate(&manifest(&y)).map_err(|e| e.to_string())
        };
        let native = "{ kind: sso, mode: native, redirectPaths: [/cb] }";
        let token = "{ path: /s, body: '{\"u\":\"{{ username }}\",\"p\":\"{{ password }}\"}', pointer: /T }";
        assert_eq!(with(native, token, OK), Ok(()));
        for (sso, proof, accounts, why) in [
            (
                "{ kind: sso, mode: proxy-only }",
                token,
                OK.to_string(),
                "behind the portal",
            ),
            (
                native,
                "{ path: /s, body: '{}', basic: true, pointer: /T }",
                OK.to_string(),
                "HTTP Basic",
            ),
            (
                native,
                token,
                OK.replace("signIn: admin-password", "signIn: nobody"),
                "no `recovery` entry",
            ),
            (
                native,
                token,
                OK.replace("Token={{ token }}", "Token=x"),
                "the token in no header",
            ),
            (
                native,
                token,
                OK.replace("Token={{ token }}", "{{ token }} {{ sub }}"),
                "a header takes",
            ),
            (
                native,
                token,
                OK.replace("\"/Users/{{ account }}\", pointer", "/Users/me, pointer"),
                "names no {{ account }}",
            ),
            (
                native,
                token,
                OK.replace("{{ account }}/Policy", "{{ person.sub }}/Policy"),
                "filled by nothing",
            ),
            (
                native,
                token,
                OK.replace("verb: POST", "verb: GET"),
                "POST, PUT or PATCH",
            ),
            (
                native,
                token,
                OK.replace("disabled: /IsDisabled", "disabled: IsDisabled"),
                "JSON pointer",
            ),
        ] {
            let refusal = with(sso, proof, &accounts).expect_err(why);
            assert!(refusal.contains(why), "{why}: {refusal}");
        }
    }

    #[test]
    fn an_access_nothing_would_read_is_refused() {
        let with = |sso: &str, access: &str| {
            let y = format!(
                "{BASE}  env: {{ DB: \"{{{{ db.url }}}}\", ID: \"{{{{ oidc.client_id }}}}\" }}\n  \
                 requires:\n    - {{ kind: database, engine: postgres }}\n    - {sso}\n  \
                 access:\n{access}"
            );
            validate(&manifest(&y)).map_err(|e| e.to_string())
        };
        let native = "{ kind: sso, mode: native, redirectPaths: [/cb] }";
        let ok = "    floor: user\n    admins: { level: admin, means: every repository }\n    \
                  claims:\n      hlb_test: { byLevel: { user: user, admin: admin } }\n      \
                  teams: { json: [ { name: \"{{ role.name }}\", id: \"{{ role.group }}\" } ] }\n    \
                  quota:\n      claim: { name: test_quota, unit: GiB }\n      apply:\n        \
                  type: sql\n        unit: bytes\n        statement: UPDATE u SET q = {{ quota }} \
                  WHERE sub = '{{ person.sub }}'\n";
        assert_eq!(with(native, ok), Ok(()));

        for (sso, access, why) in [
            (
                "{ kind: sso, mode: none }",
                "    floor: admin\n",
                "signs nobody in",
            ),
            (
                "{ kind: sso, mode: proxy-only }",
                "    claims: { a: { byLevel: { user: x } } }\n",
                "behind the portal",
            ),
            (
                native,
                "    floor: operator\n    claims: { a: { byLevel: { admin: x } } }\n",
                "no value at the floor",
            ),
            (native, "    claims: { email: { byLevel: { user: x } } }\n", "PocketID's own"),
            (native, "    claims: { a: { json: \"{{ role.typo }}\" } }\n", "filled by nothing"),
            (native, "    claims: { a: {} }\n", "exactly one"),
            (
                native,
                "    floor: admin\n    admins: { level: operator, means: x }\n",
                "below the floor",
            ),
            (native, "    quota: {}\n", "reaches nobody"),
            (
                native,
                "    quota: { apply: { type: sql, unit: bytes, statement: \"UPDATE u SET q = {{ quota }}\" } }\n",
                "quoted",
            ),
            (
                native,
                "    quota: { apply: { type: sql, unit: bytes, statement: \"DELETE FROM u WHERE s = '{{ person.sub }}'\" } }\n",
                "one UPDATE",
            ),
            (
                native,
                "    quota: { apply: { type: exec, unit: bytes, command: [set, \"{{ person.sub }}\"] } }\n",
                "both",
            ),
        ] {
            let got = with(sso, access);
            assert!(
                got.as_ref().is_err_and(|e| e.contains(why)),
                "{access} should be refused for \"{why}\": {got:?}"
            );
        }
    }

    #[test]
    fn an_assertion_that_could_never_pass_is_refused() {
        let with = |assertions: &str| {
            let y = format!(
                "{BASE}  env: {{ SIGNUPS: \"false\" }}\n  ingress:\n    - host: a.example.fr\n      \
                 port: 80\n  assertions:\n{assertions}"
            );
            validate(&manifest(&y)).map_err(|e| e.to_string())
        };
        let ok = "    - { id: closed, holds: nobody signs up, check: { type: env, name: SIGNUPS, \
                  equals: \"false\" } }\n    - { id: read, holds: x, check: { type: http, path: /a, \
                  pointer: /b, equals: true } }\n";
        assert_eq!(with(ok), Ok(()));

        for (bad, why) in [
            (
                "    - { id: c, holds: x, check: { type: env, name: SIGNUPS, equals: \"true\" } }\n",
                "could never pass",
            ),
            (
                "    - { id: c, holds: x, check: { type: env, name: UNSET, equals: \"1\" } }\n",
                "not in spec.env",
            ),
            (
                "    - { id: c, holds: x, check: { type: http, path: /a, pointer: /b } }\n",
                "go together",
            ),
            (
                "    - { id: c, holds: x, check: { type: http, path: a } }\n",
                "starts with /",
            ),
            (
                "    - { id: c, holds: x, check: { type: sql, query: SELECT 1, equals: \"1\" } }\n",
                "requires none",
            ),
            (
                "    - { id: C, holds: x, check: { type: http, path: /a } }\n",
                "lowercase",
            ),
            (
                "    - { id: c, holds: x, check: { type: http, path: /a } }\n    - { id: c, holds: \
                 y, check: { type: http, path: /b } }\n",
                "declared twice",
            ),
        ] {
            let refusal = with(bad).expect_err(bad);
            assert!(refusal.contains(why), "{refusal}");
        }
    }

    #[test]
    fn a_merged_call_sends_one_object_over_a_get() {
        let m = manifest(&format!(
            "{BASE}  ingress:\n    - {{ host: a.example.fr, port: 8096 }}\n"
        ));
        let with = |call: &str| {
            let g: Guide = serde_yaml_ng::from_str(&format!(
                "steps:\n  - id: s\n    title: x\n    automate:\n      - method: api\n        \
                 calls: [{call}]\n"
            ))
            .expect("guide");
            validate_guide(&m, &g).map_err(|e| e.to_string())
        };
        assert_eq!(
            with("{ verb: POST, path: /c, merge: true, body: '{\"A\":true}' }"),
            Ok(())
        );
        for bad in [
            "{ verb: POST, path: /c, merge: true }",
            "{ verb: POST, path: /c, merge: true, body: '[1]' }",
            "{ verb: GET, path: /c, merge: true, body: '{\"A\":true}' }",
        ] {
            assert!(with(bad).expect_err(bad).contains("merges"), "{bad}");
        }
    }

    #[test]
    fn an_api_body_names_only_what_is_filled_at_run_time() {
        let m = manifest(&format!(
            "{BASE}  requires:\n    - {{ kind: smtp }}\n  env: {{ A: \"{{{{ smtp.from }}}}\" }}\n  \
             ingress:\n    - {{ host: a.example.fr, port: 5678 }}\n"
        ));
        let with = |body: &str| {
            let g: Guide = serde_yaml_ng::from_str(&format!(
                "steps:\n  - id: owner\n    title: x\n    automate:\n      - method: api\n        \
                 calls:\n          - verb: POST\n            path: /rest/owner/setup\n            \
                 body: '{body}'\n"
            ))
            .expect("guide");
            validate_guide(&m, &g).map_err(|e| e.to_string())
        };
        assert_eq!(
            with(
                r#"{"email":"{{ smtp.from }}","password":"{{ secret.owner-password }}","host":"{{ domain }}"}"#
            ),
            Ok(())
        );
        assert!(with(r#"{"p":"{{ secret.Owner }}"}"#)
            .expect_err("bad")
            .contains("no generated secret"));
        assert!(with(r#"{"p":"{{ db.password }}"}"#)
            .expect_err("cap")
            .contains("does not declare"));
        assert!(with(r#"{"p":"{{ base_domain }}"}"#)
            .expect_err("unknown")
            .contains("filled by nothing"));
    }

    #[test]
    fn a_step_signs_in_by_a_proven_recovery_and_sends_its_token_in_a_header_only() {
        let m = manifest(&format!(
            "{BASE}  ingress:\n    - {{ host: a.example.fr, port: 8096 }}\n  recovery:\n    \
             - secret: admin-password\n      username: admin\n      proof: {{ path: /in, body: \
             '{{\"u\":\"{{{{ username }}}}\",\"p\":\"{{{{ password }}}}\"}}', pointer: \
             /AccessToken }}\n    - secret: basic-password\n      username: admin\n      \
             proof: {{ path: /in, body: '{{}}', basic: true, pointer: /t }}\n"
        ));
        // The wizard's step, generating what the recovery entries deposit.
        let first =
            "steps:\n  - id: first\n    title: x\n    automate:\n      - method: api\n        \
                     calls: [{ verb: POST, path: /u, body: '{\"a\":\"{{ secret.admin-password }}\",\
                     \"b\":\"{{ secret.basic-password }}\"}' }]\n";
        let with = |phase: &str, automate: &str| {
            let g: Guide = serde_yaml_ng::from_str(&format!(
                "{first}  - id: sso\n    title: x\n    phase: {phase}\n    automate:\n      \
                 - method: api\n{automate}        calls: [{{ verb: POST, path: /a }}]\n"
            ))
            .expect("guide");
            validate_guide(&m, &g).map_err(|e| e.to_string())
        };
        let signed = "        signIn: admin-password\n        headers: { Authorization: \
                      'Token=\"{{ token }}\"' }\n";
        assert_eq!(with("post-install", signed), Ok(()));
        assert_eq!(
            with("post-install", "        headers: { X-Client: hlb }\n"),
            Ok(()),
            "a header needs no sign-in"
        );
        for (phase, automate, why) in [
            (
                "post-install",
                "        signIn: nobody\n        headers: { A: '{{ token }}' }\n",
                "no `recovery` entry",
            ),
            (
                "post-install",
                "        signIn: basic-password\n        headers: { A: '{{ token }}' }\n",
                "HTTP Basic",
            ),
            (
                "post-install",
                "        signIn: admin-password\n        headers: { A: b }\n",
                "in no header",
            ),
            (
                "post-install",
                "        headers: { A: '{{ token }}' }\n",
                "only from a `signIn`",
            ),
            (
                "post-install",
                "        signIn: admin-password\n        headers: { A: '{{ token }} \
                 {{ secret.admin-password }}' }\n",
                "a header takes",
            ),
            ("post-restore", signed, "a restore signs in nowhere"),
        ] {
            let refusal = with(phase, automate).expect_err(why);
            assert!(refusal.contains(why), "{why}: {refusal}");
        }
        // Nowhere but a header: a body would carry it into whatever the app echoes.
        let g: Guide = serde_yaml_ng::from_str(&format!(
            "{first}  - id: sso\n    title: x\n    automate:\n      - method: api\n{signed}        \
             calls: [{{ verb: POST, path: /a, body: '{{\"t\":\"{{{{ token }}}}\"}}' }}]\n"
        ))
        .expect("guide");
        assert!(validate_guide(&m, &g)
            .expect_err("body")
            .to_string()
            .contains("filled by nothing"));
    }

    #[test]
    fn a_post_restore_step_declares_only_what_a_restore_runs() {
        let m = manifest(&format!(
            "{BASE}  requires:\n    - {{ kind: database, engine: postgres, connections: 5 }}\n  \
             ingress:\n    - {{ host: a.example.fr, port: 80 }}\n  companions:\n    \
             - name: api\n      image: {{ repo: a/b, tag: \"1\" }}\n"
        ));
        let with = |extra: &str, automate: &str| {
            let g: Guide = serde_yaml_ng::from_str(&format!(
                "steps:\n  - id: first\n    title: x\n  - id: reindex\n    title: x\n    \
                 phase: post-restore\n{extra}    automate:\n      - {automate}\n"
            ))
            .expect("guide");
            validate_guide(&m, &g).map_err(|e| e.to_string())
        };
        let exec = "{ method: exec, command: [reindex], service: api }";
        assert_eq!(with("", exec), Ok(()));
        assert_eq!(
            with(
                "",
                "{ method: api, calls: [{ verb: POST, path: /reindex }] }"
            ),
            Ok(())
        );
        for (extra, automate, why) in [
            ("    severity: blocking\n", exec, "blocks nothing"),
            ("    verify: { type: tcp, target: a:1 }\n", exec, "verify"),
            ("    after: [first]\n", exec, "order"),
            ("", "{ method: env, vars: { A: b } }", "`env`"),
            (
                "",
                "{ method: sql, statement: UPDATE t SET a = 1, params: [], probe: SELECT true }",
                "`sql`",
            ),
            (
                "",
                "{ method: exec, command: [a], probe: [b], probeMatches: done }",
                "probe",
            ),
            (
                "",
                "{ method: api, probe: { path: /a, pointer: /a, equals: 'true' }, calls: [{ verb: POST, path: /a }] }",
                "probe",
            ),
            (
                "",
                "{ method: exec, command: [a], service: worker }",
                "none of test's companions",
            ),
        ] {
            let refusal = with(extra, automate).expect_err(why);
            assert!(refusal.contains(why), "{why}: {refusal}");
        }

        // An install's step waiting on one no install runs would wait forever.
        let g: Guide = serde_yaml_ng::from_str(
            "steps:\n  - id: reindex\n    title: x\n    phase: post-restore\n  \
             - id: later\n    title: x\n    after: [reindex]\n",
        )
        .expect("guide");
        assert!(validate_guide(&m, &g)
            .expect_err("after")
            .to_string()
            .contains("no install runs"));
    }

    #[test]
    fn a_recheck_is_one_the_nightly_pass_can_honour() {
        // 🔴 Found by review: `recheck: 24h` sat in ten guides and nothing read it.
        let m = manifest(BASE);
        let with = |phase: &str, verify: &str, every: &str| {
            let g: Guide = serde_yaml_ng::from_str(&format!(
                "steps:\n  - id: dns-record\n    title: x\n    phase: {phase}\n    \
                 verify: {verify}\n    recheck: {every}\n"
            ))
            .expect("guide");
            validate_guide(&m, &g).map_err(|e| e.to_string())
        };
        let dns = "{ type: dns, record: a.example.fr }";
        assert_eq!(with("pre-install", dns, "24h"), Ok(()));
        assert_eq!(with("pre-install", dns, "7d"), Ok(()));
        assert!(with("pre-install", dns, "1h")
            .expect_err("soon")
            .contains("once a night"));
        assert!(with("pre-install", dns, "daily").is_err());
        assert!(with("pre-install", dns, "24é").is_err());
        assert!(with("post-install", dns, "24h")
            .expect_err("phase")
            .contains("assertions"));
        assert!(with("pre-install", "{ type: attest }", "24h")
            .expect_err("attest")
            .contains("checks nothing"));
    }

    #[test]
    fn a_step_after_the_install_is_never_verified_by_the_app_answering() {
        let m = manifest(&format!(
            "{BASE}  ingress:\n    - {{ host: a.example.fr, port: 2283 }}\n"
        ));
        let with = |phase: &str, verify: &str| {
            let g: Guide = serde_yaml_ng::from_str(&format!(
                "steps:\n  - id: first-account\n    title: x\n    phase: {phase}\n    \
                 severity: blocking\n    verify: {verify}\n"
            ))
            .expect("guide");
            validate_guide(&m, &g).map_err(|e| e.to_string())
        };
        let health = "{ type: http, url: 'https://a.example.fr/api/server/ping' }";
        assert!(with("post-install", health)
            .expect_err("health")
            .contains("expectJson"));
        assert!(with(
            "first-login",
            "{ type: http, url: 'https://a/x', expectStatus: [204] }"
        )
        .is_err());
        for fine in [
            "{ type: http, url: 'https://a/api/server/config', expectJson: { pointer: \
             /isInitialized, equals: 'true' } }",
            "{ type: http, url: 'https://a/user/sign_up', expectStatus: [403, 404] }",
            "{ type: attest }",
        ] {
            assert_eq!(with("post-install", fine), Ok(()), "{fine}");
        }
        // Before the install, the app answering is no foregone conclusion.
        assert_eq!(with("pre-install", health), Ok(()));
        assert!(with(
            "post-install",
            "{ type: http, url: 'https://a/c', expectJson: { pointer: isInitialized, equals: \
             'true' } }"
        )
        .expect_err("pointer")
        .contains("JSON pointer"));
    }

    #[test]
    fn an_sql_automation_binds_its_values_and_names_only_what_is_filled() {
        let with = |requires: &str, statement: &str, params: &str, probe: &str| {
            let m = manifest(&format!(
                "{BASE}  requires:\n{requires}    - {{ kind: sso, mode: native, redirectPaths: [/cb] }}\n"
            ));
            let g: Guide = serde_yaml_ng::from_str(&format!(
                "steps:\n  - id: s\n    title: x\n    automate:\n      - method: sql\n        \
                 statement: \"{statement}\"\n        params: {params}\n        probe: \"{probe}\"\n"
            ))
            .expect("guide");
            validate_guide(&m, &g).map_err(|e| e.to_string())
        };
        let pg = "    - { kind: database, engine: postgres }\n";
        let update = "UPDATE t SET c = $1 WHERE n = 'x'";
        let secret = r#"['{{ oidc.client_secret }}']"#;
        let probe = "SELECT c = $1 FROM t";
        assert_eq!(with(pg, update, secret, probe), Ok(()));
        for (requires, statement, params, probe, why) in [
            ("", update, secret, probe, "does not require"),
            (pg, "DELETE FROM t", "[]", probe, "one UPDATE"),
            (pg, update, secret, "SELECT 1; DROP TABLE t", "one SELECT"),
            (
                pg,
                "UPDATE t SET c = '{{ oidc.client_secret }}'",
                "[]",
                probe,
                "never as a token",
            ),
            (pg, "UPDATE t SET c = $2", secret, probe, "reads $2"),
            (
                pg,
                "UPDATE t SET c = 1",
                secret,
                "SELECT true",
                "binds every param",
            ),
            (pg, update, "['{{ db.typo }}']", probe, "filled by nothing"),
        ] {
            let got = with(requires, statement, params, probe);
            assert!(
                got.as_ref().is_err_and(|e| e.contains(why)),
                "{statement} / {probe} should be refused for \"{why}\": {got:?}"
            );
        }
    }

    #[test]
    fn a_recovery_sign_in_deposits_a_generated_secret_under_a_fillable_name() {
        let with = |recovery: &str, guide: &str| {
            let m = manifest(&format!(
                "{BASE}  requires:\n    - {{ kind: smtp }}\n  ingress: [{{ host: t.example.org, port: 80 }}]\n  \
                 env: {{ P: \"{{{{ secret.admin-password }}}}\", F: \"{{{{ smtp.from }}}}\" }}\n  \
                 recovery:\n{recovery}"
            ));
            let g: Guide = serde_yaml_ng::from_str(&format!(
                "steps:\n  - id: first\n    title: t\n    phase: post-install\n    body: \"{guide}\"\n"
            ))
            .expect("guide");
            validate_guide(&m, &g).map_err(|e| e.to_string())
        };
        let proof = r#"proof: { path: /login, body: '{"u":"{{ username }}","p":"{{ password }}"}', pointer: /ok }"#;
        let ok = format!(
            "    - {{ secret: admin-password, username: \"{{{{ smtp.from }}}}\", path: /login, {proof} }}\n"
        );
        assert_eq!(with(&ok, "hlb secret-get test-admin-password"), Ok(()));
        assert!(with("    - { secret: owner-password }\n", "")
            .expect_err("nothing generates it")
            .contains("generated nowhere"));
        assert!(with(
            "    - { secret: admin-password, username: \"{{ domain }}\" }\n",
            ""
        )
        .expect_err("not filled")
        .contains("not filled by a deposit"));
        // 🔴 A guide that sends a person to read a password to sign in, and a manifest
        // that does not deposit it: the emergency vault would lack the one it needs.
        assert!(with(
            "    []\n",
            "Sign in with: hlb secret-get test-admin-password"
        )
        .expect_err("undeclared")
        .contains("no recovery sign-in"));
    }

    #[test]
    fn a_recovery_sign_in_is_proven_by_a_request_sending_what_the_deposit_holds() {
        let with = |username: &str, proof: &str| {
            let m = manifest(&format!(
                "{BASE}  ingress: [{{ host: t.example.org, port: 80 }}]\n  \
                 env: {{ P: \"{{{{ secret.admin-password }}}}\" }}\n  recovery:\n    \
                 - secret: admin-password\n{username}      proof: {proof}\n"
            ));
            validate_guide(&m, &Guide::default()).map_err(|e| e.to_string())
        };
        let admin = "      username: admin\n";
        let both = r#"{ path: /login, body: '{"u":"{{ username }}","p":"{{ password }}"}', pointer: /token }"#;
        assert_eq!(with(admin, both), Ok(()));
        // 🔴 Without one, the vault holds a password nobody knows opens anything.
        let none = manifest(&format!(
            "{BASE}  ingress: [{{ host: t.example.org, port: 80 }}]\n  \
             env: {{ P: \"{{{{ secret.admin-password }}}}\" }}\n  recovery:\n    \
             - {{ secret: admin-password, username: admin }}\n"
        ));
        assert!(validate_guide(&none, &Guide::default())
            .expect_err("no proof")
            .to_string()
            .contains("proof"));
        let refused = |username: &str, proof: &str, says: &str| {
            let e = with(username, proof).expect_err(proof);
            assert!(e.contains(says), "{e}");
        };
        refused(
            admin,
            r#"{ path: /login, body: '{"u":"{{ username }}"}', pointer: /t }"#,
            "no {{ password }}",
        );
        // A username the deposit holds and the request never sends proves another one.
        refused(
            admin,
            r#"{ path: /login, body: '{"p":"{{ password }}"}', pointer: /t }"#,
            "no {{ username }}",
        );
        refused("", both, "the deposit holds none");
        refused(
            admin,
            r#"{ path: /login, body: '{"u":"{{ username }}","p":"{{ password }}","d":"{{ domain }}"}', pointer: /t }"#,
            "only {{ username }} and {{ password }}",
        );
        refused(
            admin,
            r#"{ path: /login, body: 'u={{ username }}', pointer: /t }"#,
            "not JSON",
        );
        refused(
            admin,
            r#"{ path: /jmap/, body: '{"p":"{{ password }}"}', basic: true, pointer: /s }"#,
            "under HTTP Basic",
        );
        assert_eq!(
            with(
                admin,
                r#"{ path: /jmap/, body: '{}', basic: true, pointer: /s }"#
            ),
            Ok(())
        );
        // A form: its body still JSON, flat — a field of a form is one string.
        let form = r#"{ path: /token, body: '{"username":"{{ username }}","password":"{{ password }}"}', form: true, pointer: /access_token }"#;
        assert_eq!(with(admin, form), Ok(()));
        refused(
            admin,
            r#"{ path: /token, body: '{"username":"{{ username }}","p":{"v":"{{ password }}"}}', form: true, pointer: /t }"#,
            "one JSON object of strings",
        );
        refused(
            admin,
            r#"{ path: /token, body: '{}', form: true, basic: true, pointer: /t }"#,
            "not both",
        );
    }

    #[test]
    fn an_sql_assertion_is_one_select_on_a_database_the_app_requires() {
        let with = |database: &str, query: &str| {
            let y = format!(
                "{BASE}  requires:\n    - {{ kind: database, engine: mariadb, name: ccnet_db }}\n    \
                 - {{ kind: database, engine: mariadb, name: seahub_db }}\n  env: {{ A: \"{{{{ db.host }}}}\" }}\n  \
                 assertions:\n    - id: q\n      holds: x\n      check:\n        type: sql\n{database}        \
                 query: \"{query}\"\n        equals: \"0\"\n"
            );
            validate(&manifest(&y)).map_err(|e| e.to_string())
        };
        let db = "        database: ccnet_db\n";
        assert_eq!(with(db, "SELECT count(*) FROM EmailUser"), Ok(()));
        assert!(with("", "SELECT 1").expect_err("which").contains("several"));
        assert!(with("        database: other\n", "SELECT 1")
            .expect_err("unknown")
            .contains("not one the app requires"));
        assert!(with(db, "DELETE FROM EmailUser")
            .expect_err("write")
            .contains("one SELECT"));
        assert!(with(db, "SELECT 1; DROP TABLE EmailUser")
            .expect_err("two")
            .contains("one SELECT"));
    }

    #[test]
    fn a_typo_in_an_ingress_chain_is_refused() {
        let y = format!(
            "{BASE}  ingress:\n    - host: a.example.fr\n      port: 80\n      \
             chain: [caddy-front, anubls]\n"
        );
        let err = validate(&manifest(&y)).unwrap_err().to_string();
        assert!(err.contains("\"anubls\""), "{err}");
    }

    #[test]
    fn shared_variables_nobody_takes_are_refused() {
        let y = format!(
            "{BASE}  sharedEnv: {{ MODE: x }}\n  companions:\n    - name: a\n      image: {{ repo: a/b, tag: \"1\" }}\n"
        );
        assert!(validate(&manifest(&y))
            .expect_err("nobody")
            .to_string()
            .contains("sharedEnv"));
        let taken = y.replace("tag: \"1\" }\n", "tag: \"1\" }\n      sharedEnv: true\n");
        assert_eq!(
            validate(&manifest(&taken)).map_err(|e| e.to_string()),
            Ok(())
        );
        // A token in them is checked like any other.
        let token = taken.replace("MODE: x", "MODE: \"{{ db.password }}\"");
        assert!(validate(&manifest(&token)).is_err());
    }

    #[test]
    fn a_companions_files_and_command_are_held_to_the_apps_rules() {
        let with = |companion: &str| {
            let y = format!(
                "{BASE}  companions:\n    - name: queue\n      image: {{ repo: a/b, tag: \"1\" }}\n{companion}"
            );
            validate(&manifest(&y)).map_err(|e| e.to_string())
        };
        assert_eq!(
            with("      files:\n        - { path: /etc/q.conf, content: \"x\" }\n"),
            Ok(())
        );
        assert!(
            with("      files:\n        - { path: etc/q.conf, content: \"x\" }\n")
                .expect_err("relative")
                .contains("absolute")
        );
        assert!(with(
            "      files:\n        - { path: /q, content: a }\n        - { path: /q, content: b }\n"
        )
        .expect_err("twice")
        .contains("twice"));
        // A token in a companion's file is checked like one in the app's variables:
        // no database declared, and the file would hold the token's text.
        assert!(
            with("      files:\n        - { path: /q, content: \"{{ db.password }}\" }\n")
                .expect_err("no database")
                .contains("\"database\"")
        );
        // Nothing gives a command its tokens.
        for arg in ["\"{{ db.password }}\"", "\"--key={{ secret.key }}\""] {
            assert!(with(&format!("      command: [run, {arg}]\n"))
                .expect_err("a token in a command")
                .contains("command takes none"));
        }
        let app = format!("{BASE}  command: [run, \"{{{{ secret.key }}}}\"]\n");
        assert!(
            validate(&manifest(&app)).is_err(),
            "the app's own command too"
        );
        // Nor its arguments, which reach `ps` the same way.
        assert!(with("      args: [\"--key={{ secret.key }}\"]\n")
            .expect_err("a token in a companion's arguments")
            .contains("command takes none"));
        let app = format!("{BASE}  args: [\"{{{{ secret.key }}}}\"]\n");
        assert!(
            validate(&manifest(&app)).is_err(),
            "the app's own arguments"
        );
    }

    #[test]
    fn a_process_is_refused_where_swarm_or_the_node_would_refuse_it() {
        let with = |process: &str| {
            let app = format!("{BASE}  process: {process}\n");
            let companion = format!(
                "{BASE}  companions:\n    - name: q\n      image: {{ repo: a/b, tag: \"1\" }}\n      \
                 process: {process}\n"
            );
            let (a, c) = (validate(&manifest(&app)), validate(&manifest(&companion)));
            assert_eq!(
                a.is_ok(),
                c.is_ok(),
                "{process}: the app and a companion alike"
            );
            a.map_err(|e| e.to_string())
        };
        assert_eq!(
            with(
                "{ init: true, stopGraceSecs: 60, stopSignal: SIGINT, workingDir: /app, \
                 hostname: zabbix-server, ulimits: { nofile: { soft: 65536, hard: 65536 } }, \
                 sysctls: { net.ipv4.ip_forward: \"1\" }, groups: [audio, \"44\"] }"
            ),
            Ok(())
        );
        assert_eq!(with("{ stopSignal: SIGRTMIN+3 }"), Ok(()));
        for (bad, why) in [
            ("{ stopGraceSecs: 3601 }", "over 3600"),
            ("{ stopSignal: INT }", "signal"),
            ("{ stopSignal: SIG }", "signal"),
            ("{ workingDir: app }", "absolute"),
            ("{ workingDir: /app/../etc }", "absolute"),
            ("{ hostname: Zabbix }", "lowercase"),
            ("{ hostname: a.b }", "lowercase"),
            ("{ hostname: -a }", "lowercase"),
            (
                "{ ulimits: { files: { soft: 1, hard: 1 } } }",
                "Docker knows",
            ),
            (
                "{ ulimits: { nofile: { soft: 2, hard: 1 } } }",
                "over its hard",
            ),
            ("{ sysctls: { kernel.shmmax: \"1\" } }", "namespace"),
            ("{ sysctls: { vm.overcommit_memory: \"1\" } }", "namespace"),
            ("{ sysctls: { net.: \"1\" } }", "namespace"),
            ("{ sysctls: { net.ipv4.ip_forward: \"\" } }", "no value"),
            ("{ groups: [\"a:b\"] }", "group"),
        ] {
            assert!(
                with(bad).expect_err(bad).contains(why),
                "{bad} refused for {why}"
            );
        }
        // Not a field: what would loosen isolation has nowhere to be written.
        for loose in [
            "{ privileged: true }",
            "{ networkMode: host }",
            "{ devices: [/dev/dri] }",
        ] {
            assert!(
                serde_yaml_ng::from_str::<Manifest>(&format!("{BASE}  process: {loose}\n"))
                    .is_err(),
                "{loose} refused as unknown"
            );
        }
    }

    #[test]
    fn a_companion_publishes_and_is_placed_under_the_apps_rules() {
        let with = |companion: &str, sso: &str| {
            let y = format!(
                "{BASE}{sso}  companions:\n    - name: media\n      image: {{ repo: a/b, tag: \"1\" }}\n{companion}"
            );
            validate(&manifest(&y)).map_err(|e| e.to_string())
        };
        let udp = "      security:\n        publishedPorts: [7881, \"7882/udp\"]\n";
        assert_eq!(with(udp, ""), Ok(()));
        assert_eq!(with("      nodeLabel: hlb.ingress\n", ""), Ok(()));
        assert!(with("      nodeLabel: \"Hlb Ingress\"\n", "")
            .expect_err("a label Swarm cannot parse")
            .contains("nodeLabel"));
        // The same port and protocol twice can never be placed on one node.
        assert!(with(
            "      security:\n        publishedPorts: [7881, 7881]\n",
            ""
        )
        .expect_err("twice")
        .contains("7881"));
        // TCP and UDP on one number are two ports.
        assert_eq!(
            with(
                "      security:\n        publishedPorts: [7882, \"7882/udp\"]\n",
                ""
            ),
            Ok(())
        );
        // A companion's port bypasses the proxy that header authentication trusts.
        let header = "  requires:\n    - kind: sso\n      mode: proxy-header\n";
        assert!(with(udp, header)
            .expect_err("published beside header authentication")
            .contains("7882/udp"));
    }

    #[test]
    fn a_tmpfs_is_an_absolute_directory_no_volume_holds() {
        let with = |tmpfs: &str| {
            let y = format!(
                "{BASE}  companions:\n    - name: api\n      image: {{ repo: a/b, tag: \"1\" }}\n      \
                 storage:\n        - name: data\n          path: /data\n      \
                 security:\n        tmpfs: {tmpfs}\n"
            );
            validate(&manifest(&y)).map_err(|e| e.to_string())
        };
        assert_eq!(with("[/tmp, /run/fluxer]"), Ok(()));
        assert_eq!(with("[/tmp, { path: /dev/shm, size: 256M }]"), Ok(()));
        for (bad, why) in [
            ("[{ path: /data, size: 1G }]", "volume"),
            ("[tmp]", "absolute"),
            ("[/]", "absolute"),
            ("[/run/../etc]", "absolute"),
            ("[/tmp, /tmp]", "twice"),
            ("[/data]", "volume"),
        ] {
            assert!(
                with(bad).expect_err(bad).contains(why),
                "{bad} refused for being {why}"
            );
        }
    }

    #[test]
    fn a_tmpfs_larger_than_its_service_s_memory_is_refused() {
        let with = |size: &str| {
            let y = format!(
                "{BASE}  swarm:\n    memory: {{ reserve: 128M, limit: 512M }}\n  \
                 security:\n    tmpfs: [{{ path: /dev/shm, size: {size} }}]\n"
            );
            validate(&manifest(&y)).map_err(|e| e.to_string())
        };
        assert_eq!(with("512M"), Ok(()));
        assert!(with("1G").expect_err("1G").contains("memory limit"));
    }

    #[test]
    fn a_tmpfs_written_as_a_path_is_still_written_so() {
        // A manifest frozen before sizes reads, and writes back, as it was.
        let y = format!("{BASE}  security:\n    tmpfs: [/tmp, {{ path: /dev/shm, size: 1G }}]\n");
        let m = manifest(&y);
        assert_eq!(
            m.spec.security.tmpfs,
            [
                Tmpfs::from("/tmp"),
                Tmpfs {
                    path: "/dev/shm".into(),
                    size: Some(manifest::Bytes(1 << 30))
                }
            ]
        );
        let written = serde_json::to_value(&m.spec.security.tmpfs).expect("written");
        assert_eq!(
            written,
            serde_json::json!(["/tmp", { "path": "/dev/shm", "size": "1G" }])
        );
        assert!(
            serde_yaml_ng::from_str::<Manifest>(&format!(
                "{BASE}  security:\n    tmpfs: [{{ path: /tmp, sise: 1G }}]\n"
            ))
            .is_err(),
            "a misspelt key is refused"
        );
        let nothing = serde_yaml_ng::from_str::<Manifest>(&format!(
            "{BASE}  security:\n    tmpfs: [{{ path: /tmp, size: 0M }}]\n"
        ))
        .expect_err("no room");
        assert!(
            nothing.to_string().contains("a size of nothing"),
            "{nothing}"
        );
    }

    #[test]
    fn a_path_leads_to_a_companion_the_app_has() {
        let with = |path: &str, to: &str| {
            let y = format!(
                "{BASE}  companions:\n    - name: notify\n      image: {{ repo: a/b, tag: \"1\" }}\n  \
                 ingress:\n    - host: a.example.fr\n      port: 80\n      paths:\n        \
                 - {{ prefix: \"{path}\", companion: {to}, port: 8083 }}\n"
            );
            validate(&manifest(&y)).map_err(|e| e.to_string())
        };
        assert_eq!(with("/notification", "notify"), Ok(()));
        assert!(with("/notification", "notifier")
            .expect_err("unknown")
            .contains("none of its companions"));
        assert_eq!(with("/.well-known/fluxer", "notify"), Ok(()));
        for bad in [
            "notification",
            "/notification/",
            "/",
            "/notif*",
            "/Notif",
            "/a/../b",
            "/./a",
        ] {
            assert!(with(bad, "notify").is_err(), "{bad}");
        }
    }

    #[test]
    fn a_node_label_swarm_cannot_parse_is_refused() {
        let ok = format!("{BASE}  swarm:\n    nodeLabel: hlb.ingress\n");
        assert!(validate(&manifest(&ok)).is_ok());
        let bad = format!("{BASE}  swarm:\n    nodeLabel: \"hlb ingress==x\"\n");
        assert!(validate(&manifest(&bad)).is_err());
    }

    #[test]
    fn base_manifest_is_valid() {
        assert!(validate(&manifest(BASE)).is_ok());
    }

    #[test]
    fn rejects_header_auth_with_published_ports() {
        let y = format!(
            "{BASE}  requires:\n    - kind: sso\n      mode: proxy-header\n  \
             security:\n    publishedPorts: [8080]\n"
        );
        let err = validate(&manifest(&y)).unwrap_err();
        assert!(err.to_string().contains("only through the proxy"));
    }

    #[test]
    fn rejects_sqlite_on_nfs() {
        let y = format!(
            "{BASE}  requires:\n    - kind: storage\n      name: data\n      \
             path: /data\n      tier: nfs\n      sqlite: true\n"
        );
        assert!(validate(&manifest(&y))
            .unwrap_err()
            .to_string()
            .contains("NFS"));
    }

    #[test]
    fn an_engine_s_copy_is_the_app_s_volume_never_a_companion_s() {
        let own = format!(
            "{BASE}  requires:\n    - kind: storage\n      name: data\n      path: /data\n      \
             copy: pg-basebackup\n"
        );
        let m = manifest(&own);
        assert_eq!(validate(&m).map_err(|e| e.to_string()), Ok(()));
        assert!(
            m.spec.stopped_for_copy("test").is_empty(),
            "it runs throughout"
        );
        let companion = format!(
            "{BASE}  companions:\n    - name: db\n      image: {{ repo: a/b, tag: \"1\" }}\n      \
             storage:\n        - {{ name: d, path: /d, backup: true, copy: mariadb-backup }}\n"
        );
        let e = validate(&manifest(&companion)).unwrap_err().to_string();
        assert!(e.contains("never as a companion"), "{e}");
    }

    #[test]
    fn a_stopped_copy_stops_the_service_writing_the_volume_and_only_a_backed_up_one() {
        let y = format!(
            "{BASE}  requires:\n    - kind: storage\n      name: data\n      path: /data\n      \
             copy: stopped\n  companions:\n    - name: index\n      \
             image: {{ repo: a/b, tag: \"1\" }}\n      storage:\n        \
             - {{ name: idx, path: /idx, backup: true, copy: stopped }}\n    \
             - name: cache\n      image: {{ repo: a/c, tag: \"1\" }}\n      storage:\n        \
             - {{ name: c, path: /c }}\n"
        );
        let m = manifest(&y);
        assert_eq!(validate(&m).map_err(|e| e.to_string()), Ok(()));
        assert_eq!(m.spec.stopped_for_copy("test"), ["test", "test-index"]);
        let live = y.replace("      copy: stopped\n", "");
        assert_eq!(
            manifest(&live).spec.stopped_for_copy("test"),
            ["test-index"]
        );

        // Not backed up, nothing reads how it would be copied.
        let unread = y.replace("backup: true, ", "");
        let e = validate(&manifest(&unread)).unwrap_err().to_string();
        assert!(e.contains("\"idx\"") && e.contains("not backed up"), "{e}");
        let unread = y.replace("/data\n", "/data\n      backup: false\n");
        let e = validate(&manifest(&unread)).unwrap_err().to_string();
        assert!(e.contains("\"data\"") && e.contains("not backed up"), "{e}");
        // Another app's volume is copied the way its owner says.
        let theirs = y.replace(
            "/data\n",
            "/data\n      owner: caddy\n      backup: false\n",
        );
        let e = validate(&manifest(&theirs)).unwrap_err().to_string();
        assert!(e.contains("caddy's"), "{e}");
    }

    #[test]
    fn rejects_a_binding_token_without_its_capability() {
        // 🔴 Without this refusal the variable would go out to Swarm with
        // "{{ db.password }}" as its value. The app would say "incorrect password", and
        // you would look at the password for a long time.
        let y = format!("{BASE}  env:\n    DB_PASSWORD: \"{{{{ db.password }}}}\"\n");
        let e = validate(&manifest(&y)).unwrap_err().to_string();
        assert!(e.contains("db.password"), "{e}");
        assert!(
            e.contains("database"),
            "the error must name the missing capability: {e}"
        );
    }

    #[test]
    fn accepts_a_binding_token_when_the_capability_is_declared() {
        let y = format!(
            "{BASE}  requires:\n    - kind: database\n      engine: postgres\n  \
             env:\n    DB_PASSWORD: \"{{{{ db.password }}}}\"\n"
        );
        validate(&manifest(&y)).expect("the capability is declared");
    }

    #[test]
    fn a_token_in_a_file_needs_its_capability_too() {
        // Files take their tokens like variables: Vikunja's OIDC providers live in one.
        let y = format!(
            "{BASE}  files:\n    - path: /etc/app.conf\n      \
             content: \"password = {{{{ db.password }}}}\"\n"
        );
        let e = validate(&manifest(&y)).unwrap_err().to_string();
        assert!(e.contains("db.password") && e.contains("database"), "{e}");
    }

    /// 🔴 Vikunja and Seafile declared `smtp` and read none of its tokens: the resolver
    /// provisioned for them, and neither could ever send.
    #[test]
    fn a_capability_no_token_reads_is_refused() {
        for (requires, kind) in [
            ("- kind: smtp", "smtp"),
            ("- kind: database\n      engine: postgres", "database"),
            ("- kind: cache\n      engine: valkey", "cache"),
            ("- kind: object-storage", "object-storage"),
            (
                "- kind: sso\n      mode: native\n      redirectPaths: [/cb]",
                "sso",
            ),
        ] {
            let y = format!("{BASE}  requires:\n    {requires}\n");
            let e = validate(&manifest(&y)).unwrap_err().to_string();
            assert!(e.contains(kind) && e.contains("reads"), "{kind}: {e}");
        }
        // Read from a companion, or from a file, is read.
        let y = format!(
            "{BASE}  requires:\n    - kind: smtp\n  files:\n    - path: /etc/mail.conf\n      \
             content: \"host = {{{{ smtp.host }}}}\"\n"
        );
        validate(&manifest(&y)).expect("read from a file");
        let y = format!(
            "{BASE}  requires:\n    - kind: database\n      engine: postgres\n  \
             companions:\n    - name: worker\n      image: {{ repo: a/w, tag: \"1\" }}\n      \
             env:\n        DB: \"{{{{ db.url }}}}\"\n"
        );
        validate(&manifest(&y)).expect("read by a companion");
        // Behind the portal, an app is told nothing: there is no token to read.
        let y = format!("{BASE}  requires:\n    - kind: sso\n      mode: proxy-only\n");
        validate(&manifest(&y)).expect("the portal signs in for it");
    }

    #[test]
    fn mail_sent_as_the_person_signed_in_has_no_account_of_its_own() {
        // Roundcube relays each person's own credentials: there is no app account, so
        // its user, password and address would reach the app as token text.
        for token in ["smtp.user", "smtp.password", "smtp.from"] {
            let y = format!(
                "{BASE}  requires:\n    - kind: smtp\n      sender: person\n  \
                 env:\n    HOST: \"{{{{ smtp.host }}}}\"\n    X: \"{{{{ {token} }}}}\"\n"
            );
            let e = validate(&manifest(&y)).unwrap_err().to_string();
            assert!(e.contains(token) && e.contains("person"), "{e}");
        }
        let y = format!(
            "{BASE}  requires:\n    - kind: smtp\n      sender: person\n  \
             env:\n    HOST: \"tls://{{{{ smtp.host }}}}:{{{{ smtp.port }}}}\"\n"
        );
        validate(&manifest(&y)).expect("the server's address is the app's to know");
    }

    #[test]
    fn the_domain_token_needs_no_capability() {
        // The domain comes from the install parameters: requiring it as a capability
        // would be a false blocker on every app.
        let y = format!("{BASE}  env:\n    URL: \"https://{{{{ domain }}}}\"\n");
        validate(&manifest(&y)).expect("the domain is always available");
    }

    #[test]
    fn rejects_latest_channel() {
        let y = format!("{BASE}  update: {{ channel: latest }}\n");
        assert!(validate(&manifest(&y))
            .unwrap_err()
            .to_string()
            .contains("latest"));
    }

    #[test]
    fn a_manifest_of_ones_own_may_omit_the_digest() {
        // Resolved at install time; only the catalog holds every image to one.
        let y = BASE.replace(", digest: \"sha256:abc\"", "");
        assert!(validate(&manifest(&y)).is_ok());
        assert!(validate_pinned(&manifest(&y)).is_err());
    }

    #[test]
    fn the_catalog_pins_every_image_companions_included() {
        let pinned = format!("sha256:{}", "a".repeat(64));
        let app = BASE.replace("sha256:abc", &pinned);
        validate_catalog_images(&manifest(&app)).expect("pinned");

        // A digest that is not one is no pin.
        let err = validate_catalog_images(&manifest(BASE)).unwrap_err();
        assert!(err.to_string().contains("no digest"), "{err}");

        let companion = format!(
            "{app}  companions:\n    - name: ml\n      image: {{ repo: acme/ml, tag: \"1\" }}\n"
        );
        let err = validate_catalog_images(&manifest(&companion)).unwrap_err();
        assert!(err.to_string().contains("ml's image acme/ml:1"), "{err}");

        // An image this repository builds has no digest before its release.
        let here = BASE.replace(", digest: \"sha256:abc\"", ", builtHere: true");
        validate_catalog_images(&manifest(&here)).expect("built here");
    }

    #[test]
    fn maturation_is_never_under_a_week() {
        let y = format!("{BASE}  update: {{ maturationDays: 3 }}\n");
        let err = validate(&manifest(&y)).unwrap_err();
        assert!(err.to_string().contains("never under 7"), "{err}");
        let y = format!("{BASE}  update: {{ maturationDays: 14 }}\n");
        assert_eq!(manifest(&y).spec.update.maturation_days, 14);
        assert!(validate(&manifest(&y)).is_ok());
        assert_eq!(manifest(BASE).spec.update.maturation_days, 7);
    }

    #[test]
    fn deploy_requires_a_resolved_digest() {
        assert!(validate_pinned(&manifest(BASE)).is_ok());
    }
}
