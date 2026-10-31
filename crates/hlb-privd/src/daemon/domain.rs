//! The house's domain, read every night and compared with the baseline `hlb domain
//! accept` recorded.

use hlb_api::domain::{Account, Drift};
use hlb_state::{Certificates, State};

/// What a night's reading found.
#[derive(Debug, Default)]
pub struct Found {
    /// What moved since the baseline; nothing before one was accepted.
    pub drifts: Vec<Drift>,
    /// The house's ACME accounts the CAA refuses, baseline or not: their
    /// certificates stop renewing.
    pub refused: Vec<Account>,
}

/// Reads the exposure's domain and records the reading. Nothing without an exposure
/// or under the house's own root: there is nothing public to watch.
pub async fn read_and_record(
    state: &State,
    net: &dyn hlb_engine::domain::Internet,
    orch: Option<&dyn hlb_orchestrator::Orchestrator>,
    mail: Option<&hlb_mail::Stalwart>,
    now: i64,
) -> Result<Found, String> {
    let Some(exposure) = state.exposure().await.map_err(|e| e.to_string())? else {
        return Ok(Found::default());
    };
    if exposure.certificates == Certificates::Internal {
        return Ok(Found::default());
    }
    let mut reading = hlb_engine::domain::read(net, &exposure.domain, now).await;
    let (accounts, unread) = hlb_engine::domain::accounts(state, orch, mail).await;
    for u in unread {
        tracing::warn!("{u}");
    }
    reading.accounts = accounts;
    state
        .record_domain_reading(&reading)
        .await
        .map_err(|e| e.to_string())?;
    let refused = hlb_api::domain::refused(&reading)
        .into_iter()
        .cloned()
        .collect();
    let baseline = state.domain_baseline().await.map_err(|e| e.to_string())?;
    let drifts = match baseline.filter(|b| b.zone == reading.zone) {
        Some(b) => hlb_api::domain::drifts(&b, &reading),
        None => {
            tracing::info!(
                zone = %reading.zone,
                "the domain is not watched: `hlb domain accept --apply` sets its baseline"
            );
            Vec::new()
        }
    };
    Ok(Found { drifts, refused })
}
