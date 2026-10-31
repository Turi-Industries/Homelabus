//! The house's domain, read every night and compared with the baseline `hlb domain
//! accept` recorded.

use hlb_api::domain::{Account, Drift, Issuance};
use hlb_state::{Certificates, State};

/// What a night's reading found.
#[derive(Debug, Default)]
pub struct Found {
    /// What moved since the baseline; nothing before one was accepted.
    pub drifts: Vec<Drift>,
    /// The house's ACME accounts the CAA refuses, baseline or not: their
    /// certificates stop renewing.
    pub refused: Vec<Account>,
    /// Certificates for the house's names under a key it does not hold, found this
    /// night or before and not accepted since.
    pub foreign: Vec<Issuance>,
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
    // Apart from the drifts: a watch that cannot be read must not silence them.
    let foreign = watch_logs(state, net, orch, mail, &exposure.domain)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!("the certificates issued were not judged: {e}");
            Vec::new()
        });
    Ok(Found {
        drifts,
        refused,
        foreign,
    })
}

/// Judges what the logs hold since the last night, and keeps what was foreign until
/// `hlb domain accept` takes it.
async fn watch_logs(
    state: &State,
    net: &dyn hlb_engine::domain::Internet,
    orch: Option<&dyn hlb_orchestrator::Orchestrator>,
    mail: Option<&hlb_mail::Stalwart>,
    domain: &str,
) -> Result<Vec<Issuance>, String> {
    let mut watch = state
        .domain_transparency()
        .await
        .map_err(|e| e.to_string())?;
    let Some(after) = watch.after.clone() else {
        tracing::info!(
            "the certificates are not watched: `hlb domain accept --apply` takes those \
             already issued as the baseline"
        );
        return Ok(Vec::new());
    };
    match hlb_engine::domain::transparency(state, net, orch, mail, domain, Some(&after)).await {
        Ok((found, judged)) => {
            for i in &judged.elsewhere {
                tracing::info!(
                    "a certificate for names the house does not serve: {}",
                    hlb_api::domain::issuance_line(i)
                );
            }
            watch.advance(&found, judged.foreign);
            state
                .set_domain_transparency(&watch)
                .await
                .map_err(|e| e.to_string())?;
        }
        // Not read is not judged: the cursor stays, the next night reads from it.
        Err(e) => tracing::warn!("the certificates issued were not judged: {e}"),
    }
    Ok(watch.foreign)
}
