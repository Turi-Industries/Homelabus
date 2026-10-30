//! The mail records, read every night from Stalwart and a public resolver.

use hlb_api::mail_dns::{MailRecord, RecordState};
use hlb_state::State;

/// Reads every record and records the reading. What is wrong, one line each, for the
/// notification; `Err` when Stalwart could not be read, the last reading then kept.
pub async fn read_and_record(
    state: &State,
    mail: &hlb_mail::Stalwart,
    dns: &dyn hlb_engine::mail_dns::Lookup,
    now: i64,
) -> Result<Vec<String>, String> {
    let relay = state.mail_relay_spf().await.map_err(|e| e.to_string())?;
    let ports = hlb_engine::mail_dns::served_ports(state)
        .await
        .map_err(|e| e.to_string())?;
    let reading = hlb_engine::mail_dns::read(mail, dns, relay.as_deref(), &ports, now)
        .await
        .map_err(|e| e.to_string())?;
    state
        .record_mail_records(&reading.records)
        .await
        .map_err(|e| e.to_string())?;
    match &reading.refused_blocklists {
        Ok(tags) => state
            .record_refused_blocklists(tags)
            .await
            .map_err(|e| e.to_string())?,
        // The last reading stands: a probe not answered says nothing of the lists.
        Err(e) => tracing::warn!("spam blocklists not probed: {e}"),
    }
    Ok(reading
        .records
        .iter()
        .filter(|r| matches!(r.state, RecordState::Missing | RecordState::Differs))
        .map(wrong)
        .collect())
}

fn wrong(r: &MailRecord) -> String {
    format!(
        "{} ({}) is {}: {}",
        r.name,
        r.purpose.as_str(),
        r.state.as_str(),
        r.observed
    )
}
