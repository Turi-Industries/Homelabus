//! The UPS, as the privileged side's power loop read it, and the stop it ordered: the
//! inbox's lines. That loop says aloud when the apps stop and start; this side reads the
//! state.

use hlb_api::issues::{Cause, Finding};
use hlb_api::Attention;
use hlb_state::State;

/// How long a UPS set may go unread before the inbox says so: the loop reads it every
/// fifteen seconds, and an outage is ridden out five minutes before the apps stop.
pub const UNREAD_AFTER_S: i64 = 300;

/// The apps stopped for the power, a UPS set and not read.
pub async fn findings(state: &State, now: i64) -> Vec<Finding> {
    let mut out = Vec::new();
    if state.power_stop().await.ok().flatten().is_some() {
        out.push((Cause::PowerStopped, Attention::Critical, None));
    }
    let set = state.ups_policy().await.is_ok_and(|p| p.server.is_some());
    if set {
        // 🔴 The last GOOD reading: a failure is recorded too, and is not a reading.
        let read_at = state
            .ups_state()
            .await
            .ok()
            .flatten()
            .and_then(|u| u.read_at);
        if read_at.is_none_or(|r| now - r > UNREAD_AFTER_S) {
            out.push((Cause::UpsUnknown, Attention::Notice, None));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use hlb_state::{UpsPolicy, UpsReading};

    fn on_mains() -> UpsReading {
        UpsReading {
            status: "OL".into(),
            runtime_s: Some(1800),
            charge: Some(100),
        }
    }

    #[tokio::test]
    async fn no_ups_set_says_nothing() {
        let state = State::in_memory().await.expect("state");
        assert!(findings(&state, 1000).await.is_empty());
    }

    #[tokio::test]
    async fn a_ups_set_and_not_read_is_said() {
        let state = State::in_memory().await.expect("state");
        state
            .set_ups_policy(&UpsPolicy {
                server: Some("nut.lan".into()),
                ..UpsPolicy::default()
            })
            .await
            .expect("policy");
        assert_eq!(
            findings(&state, 1000).await,
            vec![(Cause::UpsUnknown, Attention::Notice, None)]
        );
        state.record_ups(1000, Ok(&on_mains())).await.expect("read");
        assert!(findings(&state, 1100).await.is_empty());
        // A failure after it keeps the good reading's date: unknown once that ages.
        state
            .record_ups(1200, Err("NUT's server does not answer"))
            .await
            .expect("failed");
        assert!(findings(&state, 1250).await.is_empty());
        assert_eq!(findings(&state, 1000 + UNREAD_AFTER_S + 1).await.len(), 1);
    }

    #[tokio::test]
    async fn the_apps_stopped_for_the_power_are_critical() {
        let state = State::in_memory().await.expect("state");
        state
            .begin_power_stop("on battery for 5 min", &[], 1000)
            .await
            .expect("begin");
        assert_eq!(
            findings(&state, 1000).await,
            vec![(Cause::PowerStopped, Attention::Critical, None)]
        );
    }
}
