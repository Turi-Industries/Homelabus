//! Muting an alert: the routes that set and lift one.
//!
//! A mute silences the NOTIFICATION, never the display: the alert stays listed, one
//! notch lower, with its deadline. Without a way to acknowledge an alert it notifies on
//! every evaluation, and the response to that is turning notifications off wholesale.

use std::sync::Arc;

use axum::extract::State as AxumState;
use axum::http::StatusCode;

use crate::api::AppState;
use crate::auth::{Authorized, CanOperate};
use crate::error::ApiError;
use crate::extract::{Json, Path};

#[derive(Debug, serde::Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct MuteRequest {
    /// How long, in seconds. At most a week: see [`hlb_api::MUTE_MAX_S`].
    pub for_s: i64,
    /// Why — required. A mute nobody can explain afterwards is the one nobody dares lift.
    pub reason: String,
}

/// Mutes an alert rule for a while.
///
/// ⚠️ No preview, like attesting a safeguard: it is a declaration, undone in one click,
/// and it changes nothing on the infrastructure. It is audited all the same.
#[utoipa::path(
    post,
    path = "/api/alerts/{rule}/mute",
    request_body = MuteRequest,
    responses(
        (status = 204, description = "Muted")
    ),
    extensions(
        ("x-hlb-requires" = json!("operate")),
        ("x-hlb-preview" = json!(false))
    )
)]
pub async fn mute(
    auth: Authorized<CanOperate>,
    AxumState(s): AxumState<Arc<AppState>>,
    Path(rule): Path<String>,
    Json(d): Json<MuteRequest>,
) -> Result<StatusCode, ApiError> {
    // 🔴 An unknown rule is REFUSED, never stored: stored, it would silence nothing,
    // and the rule actually firing — under its real name — would keep notifying while
    // everyone believed it muted.
    known(&rule)?;
    if d.for_s <= 0 || d.for_s > hlb_api::MUTE_MAX_S {
        return Err(ApiError::Unprocessable(format!(
            "a mute lasts between 1 second and {} days: one with no end is a deleted alert",
            hlb_api::MUTE_MAX_S / 86_400
        )));
    }
    let reason = d.reason.trim();
    if reason.is_empty() {
        return Err(ApiError::Unprocessable(
            "say why: a mute nobody can explain afterwards is the one nobody dares lift".into(),
        ));
    }

    let actor = auth.identity().actor.name().to_string();
    s.record(hlb_api::intent::MuteAlert {
        mute: hlb_api::AlertMute {
            rule: rule.clone(),
            until: crate::auth::now() + d.for_s,
            by: actor.clone(),
            reason: reason.to_string(),
        },
    })
    .await
    .map_err(ApiError::Internal)?;
    let detail = format!("{} s: {reason}", d.for_s);
    let _ = s
        .append_audit(
            &actor,
            auth.identity().role,
            "alert-mute",
            &rule,
            "ok",
            Some(&detail),
        )
        .await;
    Ok(StatusCode::NO_CONTENT)
}

/// Lifts an alert rule's mute: it notifies again from the next evaluation.
#[utoipa::path(
    delete,
    path = "/api/alerts/{rule}/mute",
    responses(
        (status = 204, description = "Lifted")
    ),
    extensions(
        ("x-hlb-requires" = json!("operate")),
        ("x-hlb-preview" = json!(false))
    )
)]
pub async fn unmute(
    auth: Authorized<CanOperate>,
    AxumState(s): AxumState<Arc<AppState>>,
    Path(rule): Path<String>,
) -> Result<StatusCode, ApiError> {
    known(&rule)?;
    let asked = hlb_api::intent::UnmuteAlert { rule: rule.clone() };
    if !s.record(asked).await.map_err(ApiError::Internal)? {
        return Err(ApiError::NotFound(format!("\"{rule}\" is not muted")));
    }
    let actor = auth.identity().actor.name().to_string();
    let _ = s
        .append_audit(
            &actor,
            auth.identity().role,
            "alert-unmute",
            &rule,
            "ok",
            None,
        )
        .await;
    Ok(StatusCode::NO_CONTENT)
}

/// A rule `hlb-metrics` evaluates — derived from the rules themselves, never a list.
fn known(rule: &str) -> Result<(), ApiError> {
    if hlb_metrics::rules::default_rules()
        .iter()
        .any(|r| r.name == rule)
    {
        Ok(())
    } else {
        Err(ApiError::NotFound(format!(
            "no alert rule is called \"{rule}\""
        )))
    }
}
