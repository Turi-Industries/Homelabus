//! Reconciliation: the real state brought back to the desired one, every pass.

use std::sync::Arc;

use hlb_engine::Reconciler;
use hlb_orchestrator::Orchestrator;
use hlb_state::State;

/// Report of one loop pass. Used by the tests and by supervision.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TickReport {
    pub examined: usize,
    pub acted: usize,
    pub errors: Vec<String>,
}

impl TickReport {
    pub fn is_clean(&self) -> bool {
        self.errors.is_empty()
    }
}

/// Periodic reconciliation: the real state must match the desired state.
pub struct ReconcileLoop<O: Orchestrator> {
    orchestrator: Arc<O>,
    state: Arc<State>,
    /// False by default: observe before correcting.
    apply: bool,
    /// Where the loop publishes what it saw — and what it refused to touch.
    drifts: Option<DriftState>,
    /// When a pass last reconciled, for the heartbeat.
    reconciled: Option<LastReconciled>,
    /// Garage, whose buckets and keys each pass checks the apps' against.
    store: Option<Arc<hlb_objstore::Garage>>,
    portal: Option<Arc<hlb_identity::PocketId>>,
    vault: Option<Arc<hlb_secrets::Vault>>,
}

/// When reconciliation last completed a pass, in seconds since the epoch. Shared with
/// the heartbeat: a loop that died or hangs stops moving it, and the beat stops.
pub type LastReconciled = Arc<std::sync::atomic::AtomicI64>;

/// The gaps of the last reconciliation pass, deliberate refusals included.
///
/// Same pattern as the alerts: the loop writes, the API reads. Without this sharing, the
/// system's non-actions never left the logs — that is, nowhere.
pub type DriftState = Arc<tokio::sync::RwLock<Vec<hlb_api::DriftSummary>>>;

impl<O: Orchestrator> ReconcileLoop<O> {
    pub fn new(orchestrator: Arc<O>, state: Arc<State>) -> Self {
        Self {
            orchestrator,
            state,
            apply: false,
            drifts: None,
            reconciled: None,
            store: None,
            portal: None,
            vault: None,
        }
    }

    /// Check the apps' buckets and keys against Garage on every pass.
    pub fn with_store(
        mut self,
        store: Arc<hlb_objstore::Garage>,
        vault: Option<Arc<hlb_secrets::Vault>>,
    ) -> Self {
        self.store = Some(store);
        self.vault = vault;
        self
    }

    /// Check what the portal's client accepts on every pass.
    pub fn with_portal(mut self, portal: Arc<hlb_identity::PocketId>) -> Self {
        self.portal = Some(portal);
        self
    }

    /// Record, on every pass that completes, when it did.
    pub fn reports_to(mut self, last: LastReconciled) -> Self {
        self.reconciled = Some(last);
        self
    }

    pub fn apply(mut self, yes: bool) -> Self {
        self.apply = yes;
        self
    }

    /// Publish the observed gaps on every pass.
    pub fn published_in(mut self, drifts: DriftState) -> Self {
        self.drifts = Some(drifts);
        self
    }

    pub async fn tick(&self) -> TickReport {
        let mut r = TickReport::default();

        let mut reconciler = Reconciler::new(&*self.orchestrator, &self.state);
        if let Some(g) = &self.store {
            reconciler = reconciler.with_store(&**g, self.vault.as_deref());
        }
        if let Some(pid) = &self.portal {
            reconciler = reconciler.with_portal(&**pid);
        }
        match reconciler.reconcile(self.apply).await {
            Ok(report) => {
                r.examined = report.drifts.len();
                r.acted = report.corrected.len();
                for d in &report.drifts {
                    tracing::info!("gap: {d}");
                }

                if let Some(t) = &self.reconciled {
                    t.store(crate::now(), std::sync::atomic::Ordering::Relaxed);
                }
                if let Some(shared) = &self.drifts {
                    // 🔴 CORRECTED gaps are not republished: they are no longer gaps.
                    // Leaving them would make the system look permanently adrift when
                    // it has just done its job.
                    *shared.write().await = report
                        .drifts
                        .iter()
                        .filter(|d| !report.corrected.contains(d))
                        .map(hlb_engine::Drift::summary)
                        .collect();
                }
            }
            Err(e) => {
                // We log and hand back: the next pass will retry.
                tracing::warn!("reconciliation impossible this pass: {e}");
                r.errors.push(e.to_string());
            }
        }

        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_tick_report_without_errors_is_clean() {
        assert!(TickReport::default().is_clean());
        let r = TickReport {
            errors: vec!["boum".into()],
            ..Default::default()
        };
        assert!(!r.is_clean());
    }
}
