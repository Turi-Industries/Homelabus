//! The web side's half of a passkey per destruction: it asks the daemon where to send
//! the person, and carries PocketID's answer back. The checks are all the daemon's.

use axum::http::HeaderMap;
use hlb_api::intent::{BeginConfirmation, Intent, Proof};

use crate::api::AppState;
use crate::error::ApiError;

/// Where a 428 names the PocketID address the panel opens.
pub const URL_HEADER: &str = "x-hlb-passkey-url";
/// What PocketID's return carried, sent again with the action.
pub const STATE_HEADER: &str = "x-hlb-passkey-state";
pub const CODE_HEADER: &str = "x-hlb-passkey-code";

/// The proof a request carries, when it carries both halves.
pub fn proof(headers: &HeaderMap) -> Option<Proof> {
    let read = |h: &str| headers.get(h)?.to_str().ok().map(str::to_string);
    Some(Proof {
        state: read(STATE_HEADER)?,
        code: read(CODE_HEADER)?,
    })
}

/// The proof to send `intents` with: the request's own, nothing where none of them
/// destroys or nothing signs in by passkey — else a 428 naming where to present one.
pub async fn confirm(
    s: &AppState,
    headers: &HeaderMap,
    intents: Vec<Intent>,
) -> Result<Option<Proof>, ApiError> {
    if intents.iter().all(|i| i.passkey().is_none()) {
        return Ok(None);
    }
    if let Some(p) = proof(headers) {
        return Ok(Some(p));
    }
    match s.privd().ask(BeginConfirmation { intents }).await {
        Ok(Ok(None)) => Ok(None),
        Ok(Ok(Some(url))) => Err(ApiError::PasskeyRequired { url }),
        Ok(Err(why)) => Err(ApiError::Internal(why)),
        Err(e) => Err(ApiError::Internal(e.to_string())),
    }
}
