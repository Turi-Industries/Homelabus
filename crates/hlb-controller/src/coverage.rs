//! The bridge between the state and the backup coverage calculation.
//!
//! ## Why this module exists, and not elsewhere
//!
//! `hlb_backup::coverage_of` needs to read the state; `hlb-state` cannot implement the
//! trait itself — `hlb-backup` depends on `hlb-updater`, which depends on `hlb-state`,
//! and the reverse would close a cycle Cargo refuses.
//!
//! The adapter lives in `hlb-backup-run`, which depends on both and which the CLI
//! uses too; here are only the gatherings the controller's screens need. The business
//! logic stays in `hlb-backup`, testable in memory.
//!
//! ## What it unblocks
//!
//! `Coverage` was only built in the CLI. Direct consequence: the controller did not
//! emit `hlb_backup_copies`, and the `single-copy` alert rule — the one guarding the
//! 3-2-1 — **never fired once**. It queried a metric that existed nowhere.

use hlb_backup::Coverage;
use hlb_state::State;

/// The time, in seconds since the epoch.
fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Adapts the state to what the coverage calculation needs — `hlb-backup-run`'s, the
/// one the CLI reads too: two adapters had drifted, one reading ages across kinds.
pub use hlb_backup_run::StateSource as SourceState;

/// The coverage of every installed app holding something to back up.
///
/// 🔴 An app holding nothing is left out: counted, Valkey and LibreSpeed were "never
/// backed up" in the inbox and in `hlb_backup_copies` forever, an alarm nobody could
/// clear and one that hid the next.
pub async fn all_of_them(state: &State, threshold_s: i64) -> Vec<Coverage> {
    let source = SourceState(state);
    let mut out = Vec::new();
    for (app, _) in state.installed_apps().await.unwrap_or_default() {
        let c = hlb_backup::coverage_of(&source, &app, threshold_s).await;
        if c.needs_backup() {
            out.push(c);
        }
    }
    out
}

/// An app's restorability — copies held, and whether one was ever read back.
///
/// ⚠️ Same reason for being as the adapter above: the calculation lives in `hlb-backup`,
/// and only gathering the ingredients happens here.
pub async fn restorability(
    state: &State,
    app: &str,
    threshold_s: i64,
) -> hlb_backup::Restorability {
    let source = SourceState(state);
    let coverage = hlb_backup::coverage_of(&source, app, threshold_s).await;

    let verified = state
        .seconds_since_last_verification(app)
        .await
        .ok()
        .flatten();
    // ⚠️ Unreadable reads as failed: confidence lowered is the safe direction.
    let verification_failed = state.last_verification_failed(app).await.unwrap_or(true);

    // Recovery drills are not per app: it is restoring IN GENERAL that they exercise
    //. 🔴 `days_since_successful_drill` only counts SUCCESSFUL drills — a failed
    // drill counted as "done" would say "we verified" about a verification that failed.
    let drills = hlb_backup::drill::Readiness::from_days(
        state.days_since_successful_drill().await.unwrap_or(None),
    );

    // PITR depth only exists for apps with continuous archiving. An app with no base
    // backup has no window, and that is `None` — not zero, which would read as "we can go
    // back as far as now", the opposite.
    let pitr = state
        .base_backups(app)
        .await
        .unwrap_or_default()
        .iter()
        .map(|(_, at)| *at)
        .min()
        .map(|t| now() - t);

    hlb_backup::Restorability::compute(&coverage, verified, pitr, drills)
        .with_failed_verification(verification_failed)
}

/// The translation to the API contract.
pub fn in_summary(r: &hlb_backup::Restorability) -> hlb_api::RestorabilitySummary {
    use hlb_backup::Confidence;
    hlb_api::RestorabilitySummary {
        app: r.app.clone(),
        rpo_s: r.rpo_s,
        verdict: r.verdict(),
        confidence: match r.confidence() {
            Confidence::Nothing => hlb_api::ConfidenceLevel::Nothing,
            Confidence::Assumed => hlb_api::ConfidenceLevel::Assumed,
            Confidence::Previous => hlb_api::ConfidenceLevel::Previous,
            Confidence::Verified => hlb_api::ConfidenceLevel::Verified,
        },
        confidence_explanation: r.confidence().describe().to_string(),
        remedies: r.remedies(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(name: &str) -> hlb_types::Manifest {
        let y = format!(
            "apiVersion: hlb/v1\nkind: App\nmetadata: {{ name: {name} }}\n\
             spec:\n  image: {{ repo: a/b, tag: \"1\" }}\n"
        );
        serde_yaml_ng::from_str(&y).expect("test manifest")
    }

    #[tokio::test]
    async fn coverage_is_computed_from_the_real_state() {
        // The bridge, exercised end to end: two destinations, one served, the other
        // never. This is the path the controller was missing.
        let s = State::in_memory().await.expect("state");
        s.upsert_app("immich", &manifest("immich"), None)
            .await
            .expect("app");
        s.add_volume("immich", "immich-upload", "/data", true, false)
            .await
            .expect("volume");
        s.upsert_destination("nas", "/mnt/nas", "critical,bulky", None)
            .await
            .expect("destination");
        s.upsert_destination("offsite", "s3:x/y", "bulky", None)
            .await
            .expect("destination");
        s.record_backup_to("immich", "volume", "nas", Some("abc"), None)
            .await
            .expect("backup");

        let c = all_of_them(&s, 12 * 3_600).await;
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].app, "immich");
        assert_eq!(c[0].per_destination.len(), 2);
        // 🔴 Only one copy really protects: this is the number the `single-copy` rule
        // expected and that existed nowhere.
        assert_eq!(c[0].up_to_date_copies(), 1);
    }

    #[tokio::test]
    async fn an_app_with_no_destination_at_all_is_not_silently_fine() {
        // No destination declared: zero copies. Returning an empty coverage would make
        // the app look covered by default.
        let s = State::in_memory().await.expect("state");
        s.upsert_app("seafile", &manifest("seafile"), None)
            .await
            .expect("app");
        s.add_volume("seafile", "seafile-data", "/data", true, false)
            .await
            .expect("volume");

        let c = all_of_them(&s, 12 * 3_600).await;
        assert_eq!(c[0].up_to_date_copies(), 0);
    }

    #[tokio::test]
    async fn an_app_holding_nothing_is_owed_no_copy() {
        // 🔴 Found by review: Valkey had `hlb_app_up` and no backup ever, so
        // `backup-absent` and `single-copy` fired forever, and the inbox said "never
        // backed up" about an app with nothing to lose.
        let s = State::in_memory().await.expect("state");
        s.upsert_app("valkey", &manifest("valkey"), None)
            .await
            .expect("app");
        s.add_volume("valkey", "valkey-cache", "/data", false, false)
            .await
            .expect("a cache");
        s.upsert_destination("nas", "/mnt/nas", "critical,bulky", None)
            .await
            .expect("destination");
        assert!(all_of_them(&s, 12 * 3_600).await.is_empty());
    }

    #[tokio::test]
    async fn a_verification_failed_after_a_success_leaves_no_confidence() {
        let s = State::in_memory().await.expect("state");
        s.upsert_app("immich", &manifest("immich"), None)
            .await
            .expect("app");
        s.add_volume("immich", "immich-upload", "/data", true, false)
            .await
            .expect("volume");
        for d in ["nas", "offsite"] {
            s.upsert_destination(d, &format!("/mnt/{d}"), "bulky", None)
                .await
                .expect("destination");
            s.record_backup_to("immich", "volume", d, Some("abc"), None)
                .await
                .expect("backup");
        }
        s.record_verification("immich", "abc", true, None)
            .await
            .expect("verified");
        let r = restorability(&s, "immich", 12 * 3_600).await;
        assert_eq!(r.confidence(), hlb_backup::Confidence::Verified);

        s.record_verification("immich", "abc", false, Some("files missing"))
            .await
            .expect("failed");
        let r = restorability(&s, "immich", 12 * 3_600).await;
        assert_eq!(r.confidence(), hlb_backup::Confidence::Nothing);
    }
}
