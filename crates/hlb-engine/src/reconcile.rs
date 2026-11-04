//! The reconciliation loop.
//!
//! This is what separates Homelabus from an install script. The controller does not
//! perform one-shot imperative actions: it continuously maintains
//! **desired state → drift → correction → verification**.
//!
//! Concretely: if someone scales a service by hand, or swaps an image live, the system
//! converges again on its own.
//!
//! # What reconciliation NEVER does
//!
//! - **Touch an unmanaged service.** The label filter is absolute.
//! - **Delete an orphan service.** An orphan can come from a lost state database, not
//!   from an uninstall. Destroying data on that basis would be unacceptable - it is
//!   reported, and a human decides.
//! - **Restart a failed installation.** It would loop forever on the same error. That
//!   needs an explicit intervention.
//! - **Correct a convergence in flight.** If Swarm is starting tasks, it is left to
//!   finish rather than being given contradictory orders.
//! - **Recreate a deleted service.** It did, from the image and the tier alone: no
//!   volumes, no environment, no probe — the data then landed in the container's
//!   ephemeral layer, and the report said "1 gap corrected". Rebuilding it whole is the
//!   installation's job, and `hlb install <app> --apply` does it.
//! - **Recreate a bucket or a key Garage lost.** A new key's secret must reach the
//!   vault AND the app's environment, and the objects come back from a backup: the
//!   redeploy and the restore do that, and the drift names both.

use std::collections::BTreeSet;

use hlb_orchestrator::Orchestrator;
use hlb_state::State;

use crate::Error;

/// Where the app's key id is kept: what it signs with.
fn key_id_secret(app: &str) -> String {
    hlb_types::capability::s3_key_secrets(app).0
}

type Result<T> = std::result::Result<T, Error>;

/// A drift between the desired state and the observed one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Drift {
    /// The service should exist but is gone (`docker service rm`, a lost node...).
    ServiceMissing { app: String, image: String },

    /// Someone changed the replica count outside Homelabus.
    ReplicasDiverged {
        app: String,
        desired: u64,
        actual: u64,
    },

    /// The running image is not the frozen manifest's.
    ImageDiverged {
        app: String,
        expected: String,
        actual: String,
    },

    /// A managed service with no matching app in the database.
    /// **Never deleted automatically** - only reported.
    OrphanService { name: String },

    /// Swarm is converging. Informational, not correctable.
    Converging {
        app: String,
        running: usize,
        desired: u64,
    },
    /// Stopped on purpose — a restore, a store stopped for its copy — until the hold
    /// is released or lapses.
    Held { app: String, why: String },

    /// Garage no longer holds a bucket the app was given, or its key — or holds a key
    /// of its name that is not the one the app signs with. 🔴 The app's service runs
    /// 1/1 against `No such key` and no other check says a word.
    StorageLost {
        app: String,
        /// Each bucket gone, and whether the backup pass holds its objects.
        buckets: Vec<AppBucket>,
        /// What became of its key, when that is lost too.
        key: Option<String>,
    },

    /// Garage did not answer: whether the apps' buckets are there is not known — never
    /// read as "they are".
    StorageUnread { why: String },

    /// The portal's OIDC client accepts a return to a URL no installed app is served at:
    /// an app removed before its domain was kept, or moved, or added by hand.
    OrphanCallback { url: String },
}

impl Drift {
    /// Can reconciliation correct this drift on its own?
    pub fn is_correctable(&self) -> bool {
        matches!(
            self,
            Self::ReplicasDiverged { .. } | Self::ImageDiverged { .. }
        )
    }

    /// The command that repairs a drift reconciliation leaves alone, when there is one.
    pub fn fix(&self) -> Option<String> {
        match self {
            Self::StorageLost { app, buckets, .. } => {
                let mut fix = format!("hlb redeploy {app} --apply");
                // The objects come back from the backup: a bucket restored is named by
                // its own name, which is the app's only when it declared none.
                for b in buckets.iter().filter(|b| b.backed_up) {
                    fix.push_str(&format!(", then hlb backup restore {app} {}", b.name));
                }
                Some(fix)
            }
            Self::OrphanCallback { url } => Some(format!("hlb portal drop-callback {url} --apply")),
            Self::ServiceMissing { .. }
            | Self::ReplicasDiverged { .. }
            | Self::ImageDiverged { .. }
            | Self::OrphanService { .. }
            | Self::Converging { .. }
            | Self::Held { .. }
            | Self::StorageUnread { .. } => None,
        }
    }

    /// Why this drift is **deliberately not** corrected.
    ///
    /// 🔴 Without this sentence, nothing separates "there is nothing to do" from
    /// "there is something and I chose not to touch it". The two look alike on screen,
    /// and the second makes you doubt the system - you end up correcting by hand what
    /// it deliberately left alone, or believing it saw nothing.
    ///
    /// Returns `None` when the drift IS corrected: there is then no refusal to
    /// explain.
    pub fn refusal(&self) -> Option<&'static str> {
        match self {
            Self::ReplicasDiverged { .. } | Self::ImageDiverged { .. } => None,
            Self::ServiceMissing { .. } => Some(
                "recreated here it would lack its volumes, its environment and its \
                 probe, and write its data where nothing keeps it: `hlb install <app> \
                 --apply` rebuilds it whole",
            ),
            Self::OrphanService { .. } => Some(
                "an orphan is NEVER deleted automatically: this service may hold \
                 data, and a system that over-corrects is more dangerous than one \
                 that corrects nothing",
            ),
            Self::Converging { .. } => Some(
                "Swarm is converging: progress is transient and gets left alone - \
                 only the instruction is corrected",
            ),
            Self::Held { .. } => Some(
                "stopped on purpose, and started again by whoever stopped it: started \
                 here, it would write to a volume being copied or restored",
            ),
            Self::StorageLost { .. } => Some(
                "a key made here would reach neither the vault nor the app's \
                 environment, and an empty bucket holds none of the app's objects: \
                 the redeploy makes them and hands the app its new key, the restore \
                 puts the objects back",
            ),
            Self::StorageUnread { .. } => Some(
                "nothing is known of the apps' buckets until Garage answers: nothing \
                 is done on a guess",
            ),
            Self::OrphanCallback { .. } => Some(
                "a callback added by hand reads the same as one left behind, and only a \
                 person knows which this is",
            ),
        }
    }

    /// As the API shows it — the one translation, so a field cannot reach one screen
    /// and not another.
    pub fn summary(&self) -> hlb_api::DriftSummary {
        hlb_api::DriftSummary {
            target: self.app().to_string(),
            description: self.to_string(),
            corrigible: self.is_correctable(),
            refusal: self.refusal().map(str::to_string),
            fix: self.fix(),
            harm: self.harm(),
        }
    }

    /// What the gap does to the app while it stands, whoever corrects it.
    pub fn harm(&self) -> hlb_api::DriftHarm {
        use hlb_api::DriftHarm::{Broken, Harmless, Unknown};
        match self {
            // A missing companion is the silent kind: Immich without its machine
            // learning shows every photo and recognises nobody.
            Self::ServiceMissing { .. } | Self::StorageLost { .. } => Broken,
            Self::StorageUnread { .. } => Unknown,
            Self::ReplicasDiverged { .. }
            | Self::ImageDiverged { .. }
            | Self::OrphanService { .. }
            | Self::OrphanCallback { .. }
            | Self::Converging { .. }
            | Self::Held { .. } => Harmless,
        }
    }

    pub fn app(&self) -> &str {
        match self {
            Self::ServiceMissing { app, .. }
            | Self::ReplicasDiverged { app, .. }
            | Self::ImageDiverged { app, .. }
            | Self::Converging { app, .. }
            | Self::Held { app, .. }
            | Self::StorageLost { app, .. } => app,
            Self::OrphanService { name } => name,
            Self::StorageUnread { .. } => "garage",
            Self::OrphanCallback { .. } => hlb_types::capability::PORTAL_SERVICE,
        }
    }
}

impl std::fmt::Display for Drift {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ServiceMissing { app, image } => {
                write!(f, "{app}: service missing, should be running from {image}")
            }
            Self::ReplicasDiverged {
                app,
                desired,
                actual,
            } => write!(
                f,
                "{app}: {} {} instructed, the manifest asks for {desired}",
                actual,
                if *actual == 1 { "replica" } else { "replicas" }
            ),
            Self::ImageDiverged {
                app,
                expected,
                actual,
            } => {
                write!(f, "{app}: running {actual}, expected {expected}")
            }
            Self::OrphanService { name } => write!(
                f,
                "{name}: managed service with no matching app - check before deleting"
            ),
            Self::Converging {
                app,
                running,
                desired,
            } => {
                write!(f, "{app}: converging ({running}/{desired})")
            }
            Self::Held { app, why } => write!(f, "{app}: held stopped — {why}"),
            Self::StorageLost { app, buckets, key } => {
                let lost: Vec<String> = buckets
                    .iter()
                    .map(|b| {
                        if b.backed_up {
                            format!("its bucket {}", b.name)
                        } else {
                            format!("its bucket {} (not backed up: it comes back empty)", b.name)
                        }
                    })
                    .chain(key.iter().cloned())
                    .collect();
                write!(
                    f,
                    "{app}: Garage no longer has {} — the app runs against storage that is gone",
                    lost.join(", ")
                )
            }
            Self::StorageUnread { why } => {
                write!(f, "garage: the apps' buckets could not be read — {why}")
            }
            Self::OrphanCallback { url } => write!(
                f,
                "{}: accepts a return to {url}, where no installed app is served",
                hlb_types::capability::PORTAL_SERVICE
            ),
        }
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Report {
    pub drifts: Vec<Drift>,
    pub corrected: Vec<Drift>,
    pub failed: Vec<(Drift, String)>,
}

impl Report {
    pub fn is_clean(&self) -> bool {
        self.drifts.is_empty()
    }

    pub fn correctable(&self) -> impl Iterator<Item = &Drift> {
        self.drifts.iter().filter(|d| d.is_correctable())
    }
}

/// The app statuses reconciliation stays away from.
///
/// A failed or in-progress installation must not be "repaired": in the first case we
/// would loop on the same error, in the second we would race the installation
/// itself.
fn is_reconcilable(status: &str) -> bool {
    matches!(status, "running" | "partial")
}

/// A service an installed app should be running, as reconciliation holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Expected {
    service: String,
    /// `None`: not compared — a dedicated cache's image is not pinned by its manifest.
    image: Option<String>,
    replicas: u64,
}

/// What an app runs: its own service, at the count decided for it (`hlb stop`, `hlb
/// scale`) or else its manifest's, its companions, and its dedicated caches.
///
/// 🔴 The app's own service alone was known: every companion and dedicated cache was
/// reported an orphan at every pass and checked for nothing — gone, scaled down or
/// moved to another image, none was ever said. And the count `hlb stop` set lived in
/// Swarm only, so the next pass "corrected" a stopped app back up.
fn expected_services(
    app: &str,
    manifest: &hlb_types::Manifest,
    decided: Option<u64>,
) -> Vec<Expected> {
    let mut out = vec![Expected {
        service: app.to_string(),
        image: Some(manifest.spec.image.reference()),
        replicas: decided.unwrap_or(manifest.spec.swarm.replicas),
    }];
    out.extend(manifest.spec.companions.iter().map(|c| Expected {
        service: c.service(app),
        image: Some(c.image.reference()),
        replicas: 1,
    }));
    for c in &manifest.spec.requires {
        if let hlb_types::Capability::Cache {
            engine,
            dedicated: true,
        } = c
        {
            out.push(Expected {
                service: format!("{app}-{}", engine.service_name()),
                image: None,
                replicas: 1,
            });
        }
    }
    out
}

/// A bucket an app was given.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppBucket {
    pub name: String,
    /// Whether the backup pass reads it — whether there is anything to put back.
    pub backed_up: bool,
}

/// What the object store holds — Garage's admin API, or a test's.
#[async_trait::async_trait]
pub trait StoreInventory: Send + Sync {
    async fn inventory(&self) -> std::result::Result<hlb_objstore::Inventory, String>;
}

#[async_trait::async_trait]
impl StoreInventory for hlb_objstore::Garage {
    async fn inventory(&self) -> std::result::Result<hlb_objstore::Inventory, String> {
        hlb_objstore::Garage::inventory(self)
            .await
            .map_err(|e| e.to_string())
    }
}

/// The buckets an app was given — as the resolver named them — each with whether it is
/// backed up. Their one key is named after the app.
pub fn app_buckets(app: &str, manifest: &hlb_types::Manifest) -> Vec<AppBucket> {
    manifest
        .spec
        .requires
        .iter()
        .filter_map(|c| match c {
            hlb_types::Capability::ObjectStorage {
                bucket,
                backup,
                expire_after_days: _,
            } => Some(AppBucket {
                name: hlb_types::capability::bucket_name(bucket.as_deref(), app).to_string(),
                backed_up: *backup,
            }),
            _ => None,
        })
        .collect()
}

/// What the portal's OIDC client accepts, `None` with no such client — PocketID, or a
/// test's.
#[async_trait::async_trait]
pub trait PortalClient: Send + Sync {
    async fn callbacks(&self) -> std::result::Result<Option<Vec<String>>, String>;
}

#[async_trait::async_trait]
impl PortalClient for hlb_identity::PocketId {
    async fn callbacks(&self) -> std::result::Result<Option<Vec<String>>, String> {
        self.find_by_name(hlb_types::capability::PORTAL_SERVICE)
            .await
            .map(|client| client.map(|c| c.callback_urls))
            .map_err(|e| e.to_string())
    }
}

/// The callbacks an app has on the portal's client, as the resolver makes them.
fn portal_callbacks_of(app: &str, domain: &str, manifest: &hlb_types::Manifest) -> Vec<String> {
    let mut urls = Vec::new();
    for need in &manifest.spec.requires {
        if let hlb_types::Capability::Sso {
            mode,
            redirect_paths,
        } = need
        {
            match mode {
                hlb_types::SsoMode::None => {}
                // Its own client only for the portal itself; another app's is its own.
                hlb_types::SsoMode::Native => {
                    if app == hlb_types::capability::PORTAL_SERVICE {
                        urls.extend(
                            redirect_paths
                                .iter()
                                .map(|p| format!("https://{domain}{p}")),
                        );
                    }
                }
                hlb_types::SsoMode::ProxyOnly | hlb_types::SsoMode::ProxyHeader => {
                    urls.push(format!("https://{domain}{}", hlb_resolver::PORTAL_CALLBACK));
                }
            }
        }
    }
    urls
}

/// Every callback an installed app has on the portal's client, whatever its status: a
/// failed install is still its app's.
pub async fn claimed_callbacks(state: &State) -> Result<BTreeSet<String>> {
    let mut claimed = BTreeSet::new();
    for (app, _) in state.installed_apps().await? {
        if let Some(domain) = state.app_domain(&app).await? {
            let manifest = state.app_manifest(&app).await?;
            claimed.extend(portal_callbacks_of(&app, &domain, &manifest));
        }
    }
    Ok(claimed)
}

pub struct Reconciler<'a, O: Orchestrator> {
    orchestrator: &'a O,
    state: &'a State,
    /// Without it the apps' buckets are not looked at — said by the caller, which
    /// knows whether it holds Garage's token.
    store: Option<&'a dyn StoreInventory>,
    /// To compare Garage's key with the one the app signs with.
    vault: Option<&'a hlb_secrets::Vault>,
    /// Without it the portal's callbacks are not looked at.
    portal: Option<&'a dyn PortalClient>,
}

impl<'a, O: Orchestrator> Reconciler<'a, O> {
    pub fn new(orchestrator: &'a O, state: &'a State) -> Self {
        Self {
            orchestrator,
            state,
            store: None,
            vault: None,
            portal: None,
        }
    }

    /// Checks what the portal's client accepts against what the apps are served at.
    pub fn with_portal(mut self, portal: &'a dyn PortalClient) -> Self {
        self.portal = Some(portal);
        self
    }

    /// A callback no installed app has. Reported only: PocketID is another service's
    /// outage to report, so silence here says nothing about what it accepts.
    async fn portal_drifts(
        &self,
        apps: &[(String, String)],
        drifts: &mut Vec<Drift>,
    ) -> Result<()> {
        let Some(portal) = self.portal else {
            return Ok(());
        };
        if !apps
            .iter()
            .any(|(name, _)| name == hlb_types::capability::PORTAL_SERVICE)
        {
            return Ok(());
        }
        let accepted = match portal.callbacks().await {
            Ok(Some(urls)) => urls,
            Ok(None) => return Ok(()),
            Err(why) => {
                tracing::warn!("the portal's callbacks could not be read: {why}");
                return Ok(());
            }
        };
        let claimed = claimed_callbacks(self.state).await?;
        drifts.extend(
            accepted
                .into_iter()
                .filter(|url| !claimed.contains(url))
                .map(|url| Drift::OrphanCallback { url }),
        );
        Ok(())
    }

    /// Checks every app's buckets and key against what the store holds.
    pub fn with_store(
        mut self,
        store: &'a dyn StoreInventory,
        vault: Option<&'a hlb_secrets::Vault>,
    ) -> Self {
        self.store = Some(store);
        self.vault = vault;
        self
    }

    /// What Garage lost of each running app's storage: read once for all of them.
    async fn storage_drifts(
        &self,
        given: &[(String, Vec<AppBucket>)],
        drifts: &mut Vec<Drift>,
    ) -> Result<()> {
        let Some(store) = self.store else {
            return Ok(());
        };
        if given.is_empty() {
            return Ok(());
        }
        let held = match store.inventory().await {
            Ok(h) => h,
            Err(why) => {
                drifts.push(Drift::StorageUnread { why });
                return Ok(());
            }
        };
        for (app, buckets) in given {
            let gone: Vec<AppBucket> = buckets
                .iter()
                .filter(|b| !held.buckets.contains(&b.name))
                .cloned()
                .collect();
            let key = match held.keys.get(app) {
                None => Some(format!("its key {app}")),
                Some(id) => {
                    let signs_with =
                        match (self.vault, self.state.secret(&key_id_secret(app)).await?) {
                            (Some(v), Some(ct)) => Some(v.decrypt(&ct)?),
                            _ => None,
                        };
                    signs_with.filter(|s| s != id).map(|_| {
                        format!("the key {app} signs with (a key of that name is another)")
                    })
                }
            };
            if !gone.is_empty() || key.is_some() {
                drifts.push(Drift::StorageLost {
                    app: app.clone(),
                    buckets: gone,
                    key,
                });
            }
        }
        Ok(())
    }

    /// Detects drifts. **Strictly read-only.**
    pub async fn detect(&self) -> Result<Vec<Drift>> {
        let apps = self.state.installed_apps().await?;
        let observed = self.orchestrator.list().await?;

        let mut drifts = Vec::new();
        // Every service an app runs, whatever its status: a failed install's companion
        // is its app's, not an orphan.
        let mut known: BTreeSet<String> = BTreeSet::new();
        let mut storage = Vec::new();

        for (name, status) in &apps {
            let manifest = self.state.app_manifest(name).await?;
            let decided = self.state.app_replicas(name).await?;
            let expected = expected_services(name, &manifest, decided);
            known.extend(expected.iter().map(|e| e.service.clone()));
            if !is_reconcilable(status) {
                continue;
            }
            let buckets = app_buckets(name, &manifest);
            if !buckets.is_empty() {
                storage.push((name.clone(), buckets));
            }

            for e in expected {
                let Some(svc) = observed.iter().find(|s| s.name == e.service) else {
                    drifts.push(Drift::ServiceMissing {
                        app: e.service,
                        image: e.image.unwrap_or_default(),
                    });
                    continue;
                };
                if let Some(why) = self.state.held(&e.service).await? {
                    if svc.desired_replicas != e.replicas {
                        drifts.push(Drift::Held {
                            app: e.service,
                            why,
                        });
                    }
                    continue;
                }

                // The essential distinction: what Swarm has been instructed (`desired`)
                // comes from a decision - ours or a human's. What actually runs
                // (`running`) is just progress. We correct the instruction, never the
                // progress.
                if svc.desired_replicas != e.replicas {
                    drifts.push(Drift::ReplicasDiverged {
                        app: e.service.clone(),
                        desired: e.replicas,
                        actual: svc.desired_replicas,
                    });
                } else if !svc.is_converged() {
                    drifts.push(Drift::Converging {
                        app: e.service.clone(),
                        running: svc.running_replicas,
                        desired: svc.desired_replicas,
                    });
                }

                // The image is only compared when the manifest is pinned to a digest or
                // a precise tag; Swarm often rewrites the reference with the resolved
                // digest, hence a prefix comparison rather than a strict one.
                if let Some(expected_image) = e.image {
                    if !svc.image.starts_with(&expected_image) && svc.image != expected_image {
                        drifts.push(Drift::ImageDiverged {
                            app: e.service,
                            expected: expected_image,
                            actual: svc.image.clone(),
                        });
                    }
                }
            }
        }

        self.storage_drifts(&storage, &mut drifts).await?;
        self.portal_drifts(&apps, &mut drifts).await?;

        // A managed service the state does not know about.
        for svc in &observed {
            if !known.contains(&svc.name) && !svc.name.starts_with(hlb_orchestrator::SYSTEM_PREFIX)
            {
                drifts.push(Drift::OrphanService {
                    name: svc.name.clone(),
                });
            }
        }

        Ok(drifts)
    }

    /// Detects and then, when `apply`, corrects what is correctable.
    pub async fn reconcile(&self, apply: bool) -> Result<Report> {
        let drifts = self.detect().await?;
        let mut report = Report {
            drifts: drifts.clone(),
            ..Default::default()
        };

        if !apply {
            return Ok(report);
        }

        for d in drifts.into_iter().filter(Drift::is_correctable) {
            match self.correct(&d).await {
                Ok(()) => {
                    tracing::info!(app = d.app(), "drift corrected");
                    report.corrected.push(d);
                }
                Err(e) => {
                    // A failure on one service does not stop the others being
                    // repaired: unlike installation, corrections have no dependency
                    // between them.
                    tracing::warn!(app = d.app(), error = %e, "correction impossible");
                    report.failed.push((d, e.to_string()));
                }
            }
        }

        Ok(report)
    }

    async fn correct(&self, drift: &Drift) -> Result<()> {
        match drift {
            Drift::ReplicasDiverged { app, desired, .. } => {
                self.orchestrator.scale(app, *desired).await?;
                Ok(())
            }

            Drift::ImageDiverged { app, expected, .. } => {
                self.orchestrator.update_image(app, expected).await?;
                Ok(())
            }

            // Deliberately inert: see the module header.
            Drift::ServiceMissing { .. }
            | Drift::OrphanService { .. }
            | Drift::Converging { .. }
            | Drift::Held { .. }
            | Drift::StorageLost { .. }
            | Drift::StorageUnread { .. }
            | Drift::OrphanCallback { .. } => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_uncorrected_drift_explains_why_it_was_left_alone() {
        // 🔴 A drift reported with no refusal reason makes you doubt: you cannot tell
        // whether the system does not know how, failed, or deliberately chose not to
        // touch it. You then correct by hand what it was protecting - or believe it saw
        // nothing.
        let all = [
            Drift::ServiceMissing {
                app: "gitea".into(),
                image: "a/b:1".into(),
            },
            Drift::ReplicasDiverged {
                app: "gitea".into(),
                desired: 2,
                actual: 1,
            },
            Drift::ImageDiverged {
                app: "gitea".into(),
                expected: "a/b:2".into(),
                actual: "a/b:1".into(),
            },
            Drift::OrphanService { name: "old".into() },
            Drift::Converging {
                app: "gitea".into(),
                running: 1,
                desired: 2,
            },
            Drift::Held {
                app: "gitea".into(),
                why: "restore of gitea-data".into(),
            },
            Drift::StorageLost {
                app: "fluxer".into(),
                buckets: Vec::new(),
                key: Some("its key fluxer".into()),
            },
            Drift::StorageUnread {
                why: "connection refused".into(),
            },
            Drift::OrphanCallback {
                url: "https://old.example.test/oauth2/callback".into(),
            },
        ];

        for d in &all {
            // The exact rule: correctable ⇔ no refusal to explain. A drift that was
            // both (or neither) would leave a hole on screen.
            assert_eq!(
                d.is_correctable(),
                d.refusal().is_none(),
                "{d}: correctable and refused must be exactly complementary"
            );
        }
    }

    #[test]
    fn a_single_replica_is_not_announced_in_the_plural() {
        // The "replica(s)" tic, spotted in the drift message: this is text the CLI
        // displays, and the interface after it.
        let d = Drift::ReplicasDiverged {
            app: "gitea".into(),
            desired: 2,
            actual: 1,
        };
        let text = d.to_string();
        let tic = format!("({})", "s");
        assert!(!text.contains(&tic), "{text}");
        assert!(text.contains("1 replica instructed"), "{text}");
    }
}
