//! The updates waiting, and the click that approves one.
//!
//! Who applies each update is the privileged side's hourly pass's to decide, and it
//! stores what it decided: this side reads that and asks no registry — the page is
//! polled, and a registry's or GitHub's rate limit would be spent in minutes.
//!
//! ## The click approves; it does not switch
//!
//! An update copies the data first, scans, then waits up to three minutes for Swarm: no
//! request should hold that long, and a person closing the tab must not leave a switch
//! half watched. The click approves the digest the person was shown; the pass applies
//! it in the app's window, through every guard it keeps with nobody there.

use std::sync::Arc;

use axum::extract::State as AxumState;
use hlb_api::intent::Acted;
use hlb_api::issues::{Cause, Finding};
use hlb_api::updates::{UpdateNeed, WaitingUpdate};
use hlb_api::Attention;
use hlb_state::State;

use crate::actions::{action_error, privd_error, respond, ActionQuery};
use crate::api::AppState;
use crate::auth::{Authorized, CanOperate, CanRead};
use crate::error::{ActionReply, ApiResult};
use crate::extract::{Json, Path, Query};

/// Every update waiting, by app: who applies it, why a person is needed, and its notes.
#[utoipa::path(
    get,
    path = "/api/updates",
    responses(
        (status = 200, body = Vec<hlb_api::updates::WaitingUpdate>)
    ),
    extensions(
        ("x-hlb-requires" = json!("read"))
    )
)]
pub async fn updates(
    _auth: Authorized<CanRead>,
    AxumState(s): AxumState<Arc<AppState>>,
) -> ApiResult<Vec<WaitingUpdate>> {
    Ok(Json(waiting(&s.state).await?))
}

/// The updates waiting, as the state holds them. A row a later version wrote is left
/// out rather than guessed at.
pub async fn waiting(state: &State) -> hlb_state::Result<Vec<WaitingUpdate>> {
    Ok(state
        .update_decisions()
        .await?
        .iter()
        .filter_map(|d| d.waiting())
        .collect())
}

/// Approves an app's waiting update, for the hourly pass to apply in its window.
///
/// What is approved is the image the decision named — a newer one proposed since needs
/// its own click. A major is refused: it is applied by hand, with its migration guide.
#[utoipa::path(
    post,
    path = "/api/apps/{name}/update/approve",
    params(crate::actions::ActionQuery),
    responses(
        (status = 200, body = hlb_api::ActionResult),
        (status = 422, description = "Nothing waits to be approved: the body's `blockers` say why", body = hlb_api::ActionResult)
    ),
    extensions(
        ("x-hlb-requires" = json!("operate")),
        ("x-hlb-preview" = json!(true))
    )
)]
pub async fn approve(
    auth: Authorized<CanOperate>,
    AxumState(s): AxumState<Arc<AppState>>,
    Path(app): Path<String>,
    Query(q): Query<ActionQuery>,
) -> ActionReply {
    let answer = s
        .privd()
        .ask(hlb_api::intent::ApproveUpdate {
            app: app.clone(),
            by: auth.identity().actor.name().to_string(),
            apply: q.apply,
        })
        .await
        .map_err(privd_error)?;
    match answer {
        Acted::Planned(r) => respond(&s, auth.identity(), "app-update-approve", &app, r).await,
        Acted::Unplannable(m) => {
            action_error(&s, auth.identity(), "app-update-approve", &app, &m).await
        }
    }
}

/// The inbox's lines: what waits for a person. An update going on alone — automatic, or
/// approved — is no line until it is refused.
pub async fn findings(state: &State) -> Vec<Finding> {
    waiting(state)
        .await
        .unwrap_or_default()
        .into_iter()
        .filter_map(|u| {
            let (cause, attention) = match u.needs()? {
                UpdateNeed::Approval => (Cause::UpdateNeedsApproval, Attention::Notice),
                UpdateNeed::Hands => (Cause::UpdateNeedsHands, Attention::Notice),
                UpdateNeed::Look => (Cause::UpdateRefused, Attention::Critical),
            };
            Some((cause, attention, Some(u.app)))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decided(app: &str, who: &str) -> hlb_state::UpdateDecision {
        hlb_state::UpdateDecision {
            app: app.into(),
            digest: format!("sha256:{app}"),
            from_tag: "1.24.3".into(),
            kind: "version".into(),
            to_tag: Some("1.25.0".into()),
            who: who.into(),
            why: None,
            notes: None,
            decided_at: 1,
            refused: None,
            refused_at: None,
            approved_by: None,
            approved_at: None,
        }
    }

    #[tokio::test]
    async fn the_inbox_says_what_waits_for_a_person_and_not_what_goes_on_alone() {
        let s = State::in_memory().await.expect("state");
        for (app, who) in [
            ("gitea", "one-click"),
            ("immich", "manual"),
            ("vikunja", "automatic"),
            ("n8n", "automatic"),
            ("mealie", "one-click"),
        ] {
            s.record_update_decision(&decided(app, who))
                .await
                .expect("decided");
        }
        s.refuse_update("n8n", "sha256:n8n", r#"{"kind":"paused"}"#, 5)
            .await
            .expect("refused");
        s.approve_update("mealie", "sha256:mealie", "alice", 6)
            .await
            .expect("approved");

        let mut found = findings(&s).await;
        found.sort_by(|a, b| a.2.cmp(&b.2));
        assert_eq!(
            found,
            vec![
                (
                    Cause::UpdateNeedsApproval,
                    Attention::Notice,
                    Some("gitea".into())
                ),
                (
                    Cause::UpdateNeedsHands,
                    Attention::Notice,
                    Some("immich".into())
                ),
                (
                    Cause::UpdateRefused,
                    Attention::Critical,
                    Some("n8n".into())
                ),
            ]
        );
    }
}
