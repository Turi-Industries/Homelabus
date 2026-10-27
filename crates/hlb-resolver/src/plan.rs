//! The execution plan: what Homelabus **will** do, before it does it.
//!
//! This is what `--dry-run` prints, and the guiding principle behind it: *you approve
//! a plan, you do not endure a script*. Nothing may be modified without being
//! announced first.
//!
//! The plan is also a test object: CI checks it does not change unexpectedly between
//! versions.

use std::fmt;

use hlb_types::{DbEngine, StorageTier};

/// An atomic action. Deliberately descriptive: execution lives elsewhere.
///
/// `DeployService` is markedly larger than the other variants, and that is accepted: a
/// plan holds a few dozen actions, never millions, and boxing the variant would make
/// every match pattern heavier to read for a memory saving with no purpose here.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// One database and one role per app, never a shared superuser.
    ProvisionDatabase {
        engine: DbEngine,
        database: String,
        role: String,
        /// The secret carrying the password. It must be generated BEFORE.
        password_secret: String,
        /// Extensions to enable. ⚠️ They must be present in the IMAGE.
        #[allow(clippy::struct_field_names)]
        extensions: Vec<String>,
    },

    /// An S3 bucket with its own isolated access key.
    ///
    /// 🔴 One key PER APP, never a shared admin key - same reason as one PostgreSQL
    /// role per app: a single key would give every app read access to every other's
    /// buckets.
    ProvisionBucket {
        bucket: String,
        /// The access key's name, which carries the app's name.
        key_name: String,
        /// The secret that will carry the secret key. Generated BEFORE.
        secret_name: String,
        /// Garage deletes what is older, and abandons uploads left unfinished as long.
        expire_after_days: Option<u32>,
    },

    /// A randomly generated password, never typed, never in Git.
    GenerateSecret { name: String, purpose: String },

    /// The OIDC client is created in PocketID, not by hand.
    CreateOidcClient {
        app: String,
        redirect_uris: Vec<String>,
    },

    /// The app's `/oauth2/callback` is added to the PORTAL's OIDC client: the one
    /// oauth2-proxy signs in with for every app behind it.
    AddPortalCallback { uri: String },

    CreateVolume {
        name: String,
        path: String,
        tier: StorageTier,
        backup: bool,
        /// 🔴 The volume holds a SQLite database. It must NEVER be copied hot: the
        /// main file and its WAL are captured at different instants, and the restored
        /// database is corrupt - with nothing signalling it at backup time.
        sqlite: bool,
    },

    /// The account an app sends mail as, in Stalwart: created with the password
    /// generated before it, then tried on the submission port before it is done.
    ProvisionSmtpAccount {
        address: String,
        secret_name: String,
    },

    ProvisionMailAccount {
        address: String,
        aliases: bool,
        /// 🔴 Declared in the manifest, **not enforced**: `hlb-mail` has no quota
        /// operation, Stalwart not exposing one over JMAP to date.
        ///
        /// It is carried this far anyway rather than ignored by a `..` in the
        /// resolver's pattern - which is exactly what used to happen, making a declared
        /// quota silently decorative. The executor refuses the action instead of
        /// creating the mailbox without its quota.
        quota_bytes: Option<u64>,
    },

    DeployService {
        name: String,
        image: String,
        replicas: u64,
        constraints: Vec<String>,
        /// Environment variables, including those from the guides' `method: env`
        /// automations.
        env: Vec<(String, String)>,
        /// Volumes to mount: `(name, path)`. Derived from the `storage` capabilities.
        mounts: Vec<(String, String)>,
        /// Hardening, carried from the manifest through to Swarm.
        hardening: hlb_types::SecuritySpec,
        /// Without a probe, `wait_healthy` can only count running tasks.
        healthcheck: Option<hlb_types::Healthcheck>,
        /// Configuration files: `(path, content)`.
        files: Vec<(String, String)>,
        /// The image's entrypoint replaced; empty keeps it.
        command: Vec<String>,
        /// Swarm's reservation and limit, from the manifest.
        memory: Option<hlb_types::Memory>,
    },

    /// The catalog declares a tag; the digest is resolved against the registry and
    /// then frozen. A tag is mutable, a digest is not.
    ResolveDigest { repo: String, tag: String },

    /// An explicit wait: Swarm has no `depends_on`.
    WaitHealthy { name: String, timeout_secs: u64 },

    ConfigureIngress {
        host: String,
        service: String,
        port: u16,
        chain: Vec<String>,
        /// No public exposure before the guide is validated.
        public: bool,
    },

    /// An action to carry out, possibly automatable.
    PendingGuideStep {
        id: String,
        title: String,
        blocking: bool,
        /// The service in which to attempt the automation.
        service: String,
        /// The declared step, so the executor knows what to attempt.
        step: Box<hlb_types::GuideStep>,
    },
}

impl Action {
    /// An action that changes something outside the cluster, or that is expensive to
    /// undo. Used to colour the plan and decide what needs confirmation.
    pub fn is_mutating(&self) -> bool {
        !matches!(
            self,
            Self::WaitHealthy { .. } | Self::PendingGuideStep { .. }
        )
    }
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProvisionDatabase {
                engine,
                database,
                role,
                password_secret,
                extensions,
            } => {
                write!(
                    f,
                    "create database {database} on {} with role {role} \
                     (isolated, password {password_secret})",
                    engine.service_name()
                )?;
                if !extensions.is_empty() {
                    write!(f, " + extensions {}", extensions.join(", "))?;
                }
                Ok(())
            }
            Self::ProvisionBucket {
                bucket,
                key_name,
                secret_name,
                expire_after_days,
            } => {
                write!(
                    f,
                    "create bucket {bucket} with isolated key {key_name} \
                     (secret {secret_name})"
                )?;
                match expire_after_days {
                    Some(d) => write!(f, ", its objects deleted after {d} days"),
                    None => Ok(()),
                }
            }
            Self::GenerateSecret { name, purpose } => {
                write!(f, "generate secret {name} ({purpose})")
            }
            Self::CreateOidcClient { app, redirect_uris } => write!(
                f,
                "create OIDC client \"{app}\" in PocketID → {}",
                redirect_uris.join(", ")
            ),
            Self::AddPortalCallback { uri } => {
                write!(f, "allow {uri} on the portal's OIDC client in PocketID")
            }
            Self::CreateVolume {
                name,
                path,
                tier,
                backup,
                sqlite,
            } => write!(
                f,
                "create volume {name} at {path} (tier {tier:?}, backup {}{})",
                if *backup { "on" } else { "off" },
                if *sqlite { ", SQLite snapshot" } else { "" }
            ),
            Self::ProvisionSmtpAccount {
                address,
                secret_name: _,
            } => write!(f, "create sending account {address}, tried on port 587"),
            Self::ProvisionMailAccount {
                address,
                aliases,
                quota_bytes,
            } => {
                write!(
                    f,
                    "create mailbox {address}{}",
                    if *aliases { " with aliases" } else { "" }
                )?;
                if let Some(q) = quota_bytes {
                    // Shown in the preview: a quota we cannot set must be visible
                    // BEFORE installation, not discovered in use.
                    write!(f, " [quota {q} B - NOT ENFORCED]")?;
                }
                Ok(())
            }
            Self::DeployService {
                name,
                image,
                replicas,
                constraints,
                env,
                mounts,
                hardening,
                healthcheck,
                files,
                command,
                memory,
            } => {
                write!(f, "deploy {name} ×{replicas} from {image}")?;
                if !constraints.is_empty() {
                    write!(f, " [{}]", constraints.join(", "))?;
                }
                // Hardening appears in the plan: it must be visible before it is
                // applied, not discovered afterwards.
                let mut d = Vec::new();
                if hardening.read_only_rootfs {
                    d.push("rootfs ro".to_string());
                }
                if !hardening.tmpfs.is_empty() {
                    d.push(format!("tmpfs {}", hardening.tmpfs.join(", ")));
                }
                if hardening.no_new_privileges {
                    d.push("no-new-privileges".to_string());
                }
                if !hardening.cap_drop.is_empty() {
                    d.push(format!("cap_drop {}", hardening.cap_drop.join("+")));
                }
                // What a container gets back, and what it opens on the node: both are
                // decisions to read before they are applied.
                if !hardening.cap_add.is_empty() {
                    d.push(format!("cap_add {}", hardening.cap_add.join("+")));
                }
                if !hardening.published_ports.is_empty() {
                    d.push(format!(
                        "ports {} on the node",
                        hardening
                            .published_ports
                            .iter()
                            .map(|p| p.to_string())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ));
                }
                if healthcheck.is_some() {
                    d.push("probe".to_string());
                }
                if let Some(m) = memory {
                    d.push(format!(
                        "memory {} reserved, {} at most",
                        String::from(m.reserve),
                        String::from(m.limit)
                    ));
                }
                if !files.is_empty() {
                    d.push(format!(
                        "files {}",
                        files
                            .iter()
                            .map(|(p, _)| p.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ));
                }
                // What runs in place of the image's own start, read before it does.
                if !command.is_empty() {
                    d.push(format!("runs {}", command.join(" ")));
                }
                if !env.is_empty() {
                    d.push(format!("{} variables", env.len()));
                }
                for (vol, path) in mounts {
                    d.push(format!("{vol}→{path}"));
                }
                if !d.is_empty() {
                    write!(f, " ({})", d.join(", "))?;
                }
                Ok(())
            }
            Self::ResolveDigest { repo, tag } => {
                write!(f, "resolve the digest of {repo}:{tag} against the registry")
            }
            Self::WaitHealthy { name, timeout_secs } => {
                write!(
                    f,
                    "wait for {name} to become healthy (max {timeout_secs} s)"
                )
            }
            Self::ConfigureIngress {
                host,
                service,
                port,
                chain,
                public,
            } => write!(
                f,
                "route {host} → {service}:{port} through {} ({})",
                if chain.is_empty() {
                    "direct".to_string()
                } else {
                    chain.join(" → ")
                },
                if *public { "public" } else { "VPN only" }
            ),
            Self::PendingGuideStep {
                id,
                title,
                blocking,
                step,
                ..
            } => write!(
                f,
                "{} {} \"{title}\" [{id}]",
                if *blocking { "🔴" } else { "🟠" },
                if step.is_automatable() {
                    "action"
                } else {
                    "manual action"
                }
            ),
        }
    }
}

/// The ordered list of actions, exactly as it will be executed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Plan {
    pub actions: Vec<Action>,
}

impl Plan {
    pub fn push(&mut self, a: Action) {
        self.actions.push(a);
    }

    pub fn is_empty(&self) -> bool {
        self.actions.is_empty()
    }

    pub fn len(&self) -> usize {
        self.actions.len()
    }

    /// The blocking manual actions. If this list is not empty, the installation must
    /// not start.
    pub fn blocking_steps(&self) -> Vec<&Action> {
        self.actions
            .iter()
            .filter(|a| matches!(a, Action::PendingGuideStep { blocking: true, .. }))
            .collect()
    }

    /// The blocking steps that stop an install: a prerequisite — a DNS record, an
    /// account at a provider — without which deploying is pointless.
    ///
    /// 🔴 Not the post-install ones. "Print PocketID's recovery codes" or "create the
    /// administrator and close sign-ups" can only be done once the app runs: counted
    /// here, they made every such install impossible until someone attested, before
    /// doing it, work not yet doable. Those hold back the app's public route instead
    /// (`expose: after-guide`).
    pub fn pre_install_blockers(&self) -> Vec<&Action> {
        self.actions
            .iter()
            .filter(|a| {
                matches!(a, Action::PendingGuideStep { blocking: true, step, .. }
                    if step.phase == hlb_types::Phase::PreInstall)
            })
            .collect()
    }

    pub fn mutating_count(&self) -> usize {
        self.actions.iter().filter(|a| a.is_mutating()).count()
    }
}

impl fmt::Display for Plan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_empty() {
            return writeln!(f, "No action: the desired state is already reached.");
        }
        writeln!(
            f,
            "{} {}, {} of them mutating:\n",
            self.len(),
            if self.len() == 1 { "action" } else { "actions" },
            self.mutating_count()
        )?;
        for (i, a) in self.actions.iter().enumerate() {
            writeln!(f, "  {:>2}. {a}", i + 1)?;
        }
        let before = self.pre_install_blockers().len();
        let after = self.blocking_steps().len() - before;
        let plural = |n: usize| if n == 1 { "action" } else { "actions" };
        if before > 0 {
            writeln!(
                f,
                "\n🔴 {before} prerequisite {}: the installation will not start first.",
                plural(before)
            )?;
        }
        if after > 0 {
            writeln!(
                f,
                "\n🟠 {after} blocking manual {} once it runs: until then, a route \
                 meant to open after them stays private.",
                plural(after)
            )?;
        }
        Ok(())
    }
}
