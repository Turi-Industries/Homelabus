//! The privileged executor.
//!
//! Everything that is root on a node or reads a secret sits behind [`Privd`]: Docker's
//! socket, the vault, the admin clients. The web side holds a `Privd` and can do one
//! thing with it — ask an [`Intent`] — because every field is private to this crate: a
//! handler that wants the orchestrator does not compile, rather than relying on a
//! reviewer to notice.
//!
//! For now both sides run in one process. The answers already go through JSON, so the
//! day they become two processes joined by a socket, only the transport changes.

use std::sync::Arc;

use hlb_api::intent::{Ask, Intent};
use hlb_orchestrator::Orchestrator;
use hlb_state::State;

mod apps;
pub mod backup;
mod identity;
mod mail;
mod signup;
mod swarm;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// An answer that does not survive its own wire format: a bug on this side, found
    /// in process before a socket ever carries it.
    #[error("the privileged side's answer does not read back: {0}")]
    Wire(#[from] serde_json::Error),
}

/// The clients the executor needs, assembled once at startup.
///
/// 🔴 Grouped rather than scattered: installing needs the vault AND the database
/// clients AND the registry, and a field added to one place and forgotten in the other
/// is how a capability silently stops being provisioned. A missing client makes the
/// executor record `Unimplemented` for that action, which is visible.
///
/// ⚠️ The vault is opened at startup and kept, not reopened per request: opening it
/// reads the master key from disk, and doing that on every install would put the key
/// through one more code path for nothing.
pub struct InstallContext {
    pub vault: hlb_secrets::Vault,
    pub registry: hlb_registry::RegistryClient,
    pub postgres: Option<hlb_platform::PostgresProvisioner>,
    pub mariadb: Option<hlb_platform::MariadbProvisioner>,
    /// Where the volumes live. 🔴 An app declaring `tier: nfs` is refused when this
    /// carries no server — see `hlb_engine::StorageConfig`.
    pub storage: hlb_engine::StorageConfig,
    /// The apps' own APIs, for the guides' `api` steps: this side is on the overlay,
    /// and reaches them by name.
    pub api: hlb_guide::HttpApi,
}

/// Seconds since the epoch, the state's unit of time.
fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// What the privileged side holds, and the only door to it.
///
/// Every client is `Option`: `None` = not configured, unreachable, or the
/// demonstration, and each intent says so in its answer rather than fail.
pub struct Privd {
    state: Arc<State>,
    orchestrator: Option<Arc<dyn Orchestrator>>,
    /// The catalog every intent re-derives an application from.
    catalog: Option<Arc<hlb_catalog::Catalog>>,
    install: Option<Arc<InstallContext>>,
    identity: Option<Arc<hlb_identity::PocketId>>,
    mail: Option<Arc<hlb_mail::Stalwart>>,
    backup: Option<Arc<dyn backup::BackUpNow>>,
    /// The installation's mail domain, named when an alias's own cannot be found.
    mail_domain: String,
}

impl Privd {
    pub fn new(state: Arc<State>) -> Self {
        Self {
            state,
            orchestrator: None,
            catalog: None,
            install: None,
            identity: None,
            mail: None,
            backup: None,
            mail_domain: String::new(),
        }
    }

    pub fn with_orchestrator(mut self, o: Option<Arc<dyn Orchestrator>>) -> Self {
        self.orchestrator = o;
        self
    }

    pub fn with_catalog(mut self, c: Option<Arc<hlb_catalog::Catalog>>) -> Self {
        self.catalog = c;
        self
    }

    pub fn with_install(mut self, c: Option<Arc<InstallContext>>) -> Self {
        self.install = c;
        self
    }

    pub fn with_identity(mut self, c: Option<Arc<hlb_identity::PocketId>>) -> Self {
        self.identity = c;
        self
    }

    pub fn with_mail(mut self, c: Option<Arc<hlb_mail::Stalwart>>, domain: &str) -> Self {
        self.mail = c;
        self.mail_domain = domain.to_string();
        self
    }

    pub fn with_backup(mut self, b: Option<Arc<dyn backup::BackUpNow>>) -> Self {
        self.backup = b;
        self
    }

    /// The fingerprint a kit printed now would carry: it decrypts the whole kit, which
    /// is why only this side can say it.
    async fn kit_fingerprint(&self) -> Option<String> {
        let install = self.install.as_ref()?;
        hlb_backup_run::kit::fingerprint(&self.state, &install.vault)
            .await
            .ok()
    }

    /// Republishes the routes after something changed which apps they serve. Nothing
    /// to do without an orchestrator: there is no Caddy to tell.
    async fn republish(&self) -> Result<(), String> {
        let Some(o) = &self.orchestrator else {
            return Ok(());
        };
        let vault = self.install.as_ref().map(|c| &c.vault);
        hlb_engine::ingress::publish(o.as_ref(), &self.state, vault)
            .await
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    /// Asks one intent, and reads its answer back as its own type.
    pub async fn ask<A: Ask>(&self, intent: A) -> Result<A::Answer, Error> {
        let wire = self.answer(intent.into()).await?;
        Ok(serde_json::from_value(wire)?)
    }

    /// Answers an intent with its answer as it travels.
    ///
    /// 🔴 No `_ =>` arm: an intent added to the enum does not compile until it is
    /// answered here.
    pub async fn answer(&self, intent: Intent) -> Result<serde_json::Value, Error> {
        Ok(match intent {
            Intent::Scale(i) => serde_json::to_value(swarm::scale(self, i).await)?,
            Intent::NodeAvailability(i) => {
                serde_json::to_value(swarm::node_availability(self, i).await)?
            }
            Intent::Nodes(hlb_api::intent::Nodes {}) => {
                serde_json::to_value(swarm::nodes(self).await)?
            }
            Intent::Swarm(hlb_api::intent::Swarm { service }) => {
                serde_json::to_value(swarm::view(self, service.as_deref()).await)?
            }
            Intent::Install(i) => serde_json::to_value(apps::install(self, i).await)?,
            Intent::Upgrade(i) => serde_json::to_value(apps::upgrade(self, i).await)?,
            Intent::CatalogChanges(hlb_api::intent::CatalogChanges { app }) => {
                serde_json::to_value(apps::catalog_changes(self, &app).await)?
            }
            Intent::AttestGuide(i) => serde_json::to_value(apps::attest_guide(self, i).await)?,
            Intent::Remove(i) => serde_json::to_value(apps::remove(self, i).await)?,
            Intent::BackUp(i) => serde_json::to_value(backup::back_up(self, i).await)?,
            Intent::KitFingerprint(hlb_api::intent::KitFingerprint {}) => {
                serde_json::to_value(self.kit_fingerprint().await)?
            }
            Intent::MyIdentity(i) => serde_json::to_value(identity::my_identity(self, i).await)?,
            Intent::Rename(i) => serde_json::to_value(identity::rename(self, i).await)?,
            Intent::DefaultMailbox(i) => {
                serde_json::to_value(identity::default_mailbox(self, i).await)?
            }
            Intent::CreateAlias(i) => serde_json::to_value(mail::create_alias(self, i).await)?,
            Intent::CreateMailbox(i) => serde_json::to_value(mail::create_mailbox(self, i).await)?,
            Intent::PurgeAlias(i) => serde_json::to_value(mail::purge_alias(self, i).await)?,
            Intent::SignUp(i) => serde_json::to_value(signup::sign_up(self, i).await)?,
        })
    }
}
