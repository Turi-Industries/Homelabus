//! The house's domain, read every night and compared with the baseline `hlb domain
//! accept` recorded.

use hlb_api::domain::Drift;
use hlb_state::{Certificates, State};

/// Reads the exposure's domain and records the reading. What moved since the
/// baseline; nothing without an exposure, under the house's own root, or before a
/// baseline was accepted — there is nothing to compare with.
pub async fn read_and_record(
    state: &State,
    net: &dyn hlb_engine::domain::Internet,
    now: i64,
) -> Result<Vec<Drift>, String> {
    let Some(exposure) = state.exposure().await.map_err(|e| e.to_string())? else {
        return Ok(Vec::new());
    };
    if exposure.certificates == Certificates::Internal {
        return Ok(Vec::new());
    }
    let reading = hlb_engine::domain::read(net, &exposure.domain, now).await;
    state
        .record_domain_reading(&reading)
        .await
        .map_err(|e| e.to_string())?;
    let baseline = state.domain_baseline().await.map_err(|e| e.to_string())?;
    match baseline.filter(|b| b.zone == reading.zone) {
        Some(b) => Ok(hlb_api::domain::drifts(&b, &reading)),
        None => {
            tracing::info!(
                zone = %reading.zone,
                "the domain is not watched: `hlb domain accept --apply` sets its baseline"
            );
            Ok(Vec::new())
        }
    }
}
