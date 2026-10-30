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

/// What PocketID's return carries; the page reads it itself.
#[derive(utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ConfirmedQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    /// Said when the person refused, or PocketID refused for them.
    pub error: Option<String>,
}

/// The page PocketID returns to: it hands what it carried to the panel that opened it,
/// and closes.
///
/// Static: the page reads its own address, so nothing from the query is ever written
/// into it. A `BroadcastChannel`, not `window.opener`: a PocketID answering with
/// `Cross-Origin-Opener-Policy` severs the opener for good, and the panel would wait
/// for a message nobody can send. The channel reaches this origin's pages only, and
/// the code is worth nothing without the action the daemon began it for.
#[utoipa::path(
    get,
    path = "/auth/confirmed",
    params(ConfirmedQuery),
    responses(
        (status = 200, description = "A page handing the return to the panel that asked", content_type = "text/html")
    ),
    extensions(
        ("x-hlb-public" = json!(true))
    )
)]
pub async fn passkey_returned() -> axum::response::Response {
    use axum::http::header;
    use axum::response::IntoResponse;
    (
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            // The address carries a single-use code: neither kept nor passed on.
            (header::CACHE_CONTROL, "no-store"),
            (header::REFERRER_POLICY, "no-referrer"),
        ],
        CONFIRMED_PAGE,
    )
        .into_response()
}

const CONFIRMED_PAGE: &str = r#"<!doctype html>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width">
<title>Passkey</title>
<p id="said">Passkey presented: this window can be closed.</p>
<script>
  const q = new URLSearchParams(location.search);
  const channel = new BroadcastChannel('hlb-passkey');
  channel.postMessage({ state: q.get('state'), code: q.get('code'), error: q.get('error') });
  channel.close();
  // The code is no longer needed in the address bar, nor in the history.
  history.replaceState(null, '', location.pathname);
  window.close();
</script>
"#;

#[cfg(test)]
mod tests {
    /// What the page answers on and the panel listens on: a name on two sides.
    const CHANNEL: &str = "hlb-passkey";

    #[test]
    fn the_page_answers_on_the_channel_the_panel_listens_on() {
        let panel = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../web/src/lib/action.svelte.ts"),
        )
        .expect("the panel's source");
        assert!(
            panel.contains(&format!("PASSKEY_CHANNEL = '{}'", CHANNEL)),
            "the panel listens elsewhere"
        );
        assert!(
            super::CONFIRMED_PAGE.contains(&format!("BroadcastChannel('{}')", CHANNEL)),
            "the page answers elsewhere"
        );
    }
}
