//! The state's records the web side asks for, written here because only this side
//! writes `hlb.db`.

use hlb_api::intent::Audit;

use crate::Privd;

pub(crate) async fn audit(p: &Privd, i: Audit) -> Result<(), String> {
    p.state
        .audit(
            &i.actor,
            i.role,
            &i.action,
            &i.target,
            &i.outcome,
            i.detail.as_deref(),
        )
        .await
        .map_err(|e| e.to_string())
}
