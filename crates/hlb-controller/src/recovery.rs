//! The break-glass access safeguards.
//!
//! ## 🔴 This module verifies little, and that is the point
//!
//! Homelabus does not know how many passkeys are registered, nor whether single-use codes
//! are printed and stored outside the cluster. It therefore cannot tick those boxes — it
//! can ask for them to be attested, keep the date, and turn red again when the
//! attestation ages.
//!
//! Four it proves itself ([`hlb_api::breakglass::proof`]), and no hand attests: the
//! restore drill by its trace, the emergency vault by its last verified deposit, the
//! emergency kit by the fingerprint it was printed with — which must still be today's —
//! and the family's rehearsal by the code they read off the kit they opened.

use hlb_api::breakglass::{proof, safeguards, Proof, Safeguard};
use hlb_state::State;

/// The fingerprint a kit printed now would carry; `None` when the controller holds no
/// vault to compute it with — and then no printed kit can be shown current.
pub async fn kit_now(s: &crate::api::AppState) -> Option<String> {
    s.privd()
        .ask(hlb_api::intent::KitFingerprint {})
        .await
        .ok()
        .flatten()
}

/// The state of the safeguards. `kit` is [`kit_now`].
pub async fn state(state: &State, kit: Option<&str>) -> Vec<Safeguard> {
    let attestations = state.breakglass().await.unwrap_or_default();
    let mut out = safeguards();

    for g in out.iter_mut() {
        let attested = attestations
            .iter()
            .find(|(id, ..)| id == &g.id)
            .map(|(_, age, by)| (*age, by.clone()));
        let proved = match proof(&g.id) {
            None | Some(Proof::Deposit) => attested,
            // 🔴 The restore drill is a point Homelabus holds the trace of. A human
            // attestation must not be able to declare it done: it is precisely the
            // safeguard you believe held and that is not.
            Some(Proof::Drill) => state
                .days_since_successful_drill()
                .await
                .unwrap_or(None)
                .map(|j| (j * 86_400, "recovery drill".to_string())),
            // A kit printed with what is no longer current restores nothing.
            Some(Proof::Kit) => {
                let printed = state.breakglass_note(&g.id).await.unwrap_or(None);
                attested.filter(|_| printed.is_some() && printed.as_deref() == kit)
            }
            // Recorded only on its code, withdrawn by a new split — and the family
            // opening the kit they hold proves nothing once it is not today's.
            Some(Proof::Rehearsal) => {
                let sealed = state
                    .breakglass_note(hlb_api::breakglass::FAMILY_KIT)
                    .await
                    .unwrap_or(None);
                attested.filter(|_| sealed.is_some() && sealed.as_deref() == kit)
            }
        };
        if let Some((age, by)) = proved {
            g.attested_ago_s = Some(age);
            g.attested_by = Some(by);
        }
    }
    out
}

/// Attests a safeguard.
///
/// ⚠️ A CONFIGURATION route, with no preview: ticking "yes, two passkeys are registered"
/// is a declaration reversible in one click. A round trip would train people to confirm
/// twice, which would drain the preview of its meaning where it matters.
#[utoipa::path(
    post,
    path = "/api/recovery/{id}",
    responses(
        (status = 200, body = hlb_api::breakglass::BreakGlass)
    ),
    extensions(
        ("x-hlb-requires" = json!("manage-accounts")),
        ("x-hlb-preview" = json!(false))
    )
)]
pub async fn attest(
    auth: crate::auth::Authorized<crate::auth::CanManageAccounts>,
    axum::extract::State(s): axum::extract::State<std::sync::Arc<crate::api::AppState>>,
    crate::extract::Path(id): crate::extract::Path<String>,
) -> crate::error::ApiResult<hlb_api::breakglass::BreakGlass> {
    use crate::error::ApiError;

    // 🔴 An unknown id is REFUSED, not recorded: accepted, it would be stored, would
    // appear on no screen, and the safeguard would be believed attested.
    if !hlb_api::breakglass::safeguards().iter().any(|g| g.id == id) {
        return Err(ApiError::NotFound(format!("unknown safeguard: \"{id}\"")));
    }

    // And one Homelabus verifies itself is not attested by hand: its proof is what
    // counts, and nothing else.
    if let Some(p) = proof(&id) {
        return Err(ApiError::Conflict(
            match p {
                Proof::Drill => {
                    "this safeguard is not attested: it is proved by a successful \
                     recovery drill (\"hlb dr exercise --disposable --apply\")"
                }
                Proof::Deposit => {
                    "this safeguard is not attested: it is proved by a verified deposit \
                     (\"hlb emergency vault --apply\")"
                }
                Proof::Kit => {
                    "this safeguard is not attested: it is proved by printing the kit \
                     (\"hlb emergency kit\")"
                }
                Proof::Rehearsal => {
                    "this safeguard is not attested: it is proved by the code the family \
                     reads off the kit they opened (\"hlb emergency rehearsed <code>\")"
                }
            }
            .into(),
        ));
    }

    let actor = auth.identity().actor.name().to_string();
    s.record(hlb_api::intent::AttestBreakglass {
        id: id.clone(),
        by: actor.clone(),
        note: None,
    })
    .await
    .map_err(ApiError::Internal)?;

    let _ = s
        .append_audit(
            &actor,
            auth.identity().role,
            "breakglass-attest",
            &id,
            "ok",
            None,
        )
        .await;

    Ok(crate::extract::Json(hlb_api::breakglass::BreakGlass {
        safeguards: state(&s.state, kit_now(&s).await.as_deref()).await,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_human_attestation_cannot_stand_in_for_the_real_drill() {
        // 🔴 The point: someone can sincerely believe they have exercised PocketID's
        // restore. The trace believes nothing. Letting the attestation win would paint
        // the most important safeguard green with no drill having happened.
        let s = State::in_memory().await.expect("state");
        s.attest_breakglass("pocketid-restored", "lena", None)
            .await
            .expect("attestation");

        let g = state(&s, None).await;
        let pocket = g
            .iter()
            .find(|g| g.id == "pocketid-restored")
            .expect("the safeguard");

        assert_eq!(
            pocket.attested_ago_s, None,
            "no drill has happened: the attestation does not count"
        );
        assert_eq!(pocket.attention(), hlb_api::Attention::Critical);
    }

    #[tokio::test]
    async fn a_real_drill_fills_it_in_without_anyone_attesting() {
        let s = State::in_memory().await.expect("state");
        s.record_drill("postgres", true, Some(42), 187, "sandbox")
            .await
            .expect("drill");

        let g = state(&s, None).await;
        let pocket = g
            .iter()
            .find(|g| g.id == "pocketid-restored")
            .expect("the safeguard");

        assert!(pocket.attested_ago_s.is_some());
        assert_eq!(pocket.attested_by.as_deref(), Some("recovery drill"));
    }

    #[tokio::test]
    async fn a_kit_counts_only_while_what_it_holds_is_current() {
        // 🔴 A rekey or a new destination later, the sheet in the drawer opens nothing.
        let s = State::in_memory().await.expect("state");
        s.attest_breakglass(hlb_api::breakglass::EMERGENCY_KIT, "lena", Some("0123abcd"))
            .await
            .expect("printed");
        let kit = |g: Vec<Safeguard>| {
            g.into_iter()
                .find(|g| g.id == hlb_api::breakglass::EMERGENCY_KIT)
                .expect("the safeguard")
                .attested_ago_s
        };
        assert!(kit(state(&s, Some("0123abcd")).await).is_some());
        assert_eq!(
            kit(state(&s, Some("ffff0000")).await),
            None,
            "changed since"
        );
        assert_eq!(kit(state(&s, None).await), None, "nothing to compare with");
    }

    #[tokio::test]
    async fn a_rehearsal_counts_only_while_the_familys_kit_is_current() {
        use hlb_api::breakglass::{EMERGENCY_KIT, FAMILY_KIT, FAMILY_REHEARSAL};
        let s = State::in_memory().await.expect("state");
        let family = |g: Vec<Safeguard>| {
            g.into_iter()
                .find(|g| g.id == FAMILY_REHEARSAL)
                .expect("the safeguard")
                .attested_ago_s
        };
        s.attest_breakglass(FAMILY_KIT, "hlb emergency split", Some("0123abcd"))
            .await
            .expect("sealed");
        assert_eq!(
            family(state(&s, Some("0123abcd")).await),
            None,
            "never opened"
        );
        s.attest_breakglass(FAMILY_REHEARSAL, "hlb emergency rehearsed", Some("lbkd"))
            .await
            .expect("rehearsed");
        assert!(family(state(&s, Some("0123abcd")).await).is_some());
        // 🔴 A destination added, the plain kit printed again: the owner's sheet is
        // current, the family's copy is not.
        s.attest_breakglass(EMERGENCY_KIT, "hlb emergency kit", Some("ffff0000"))
            .await
            .expect("printed");
        assert_eq!(
            family(state(&s, Some("ffff0000")).await),
            None,
            "theirs is old"
        );
        s.attest_breakglass(FAMILY_KIT, "hlb emergency kit --sealed", Some("ffff0000"))
            .await
            .expect("sealed again");
        assert!(family(state(&s, Some("ffff0000")).await).is_some());
        assert_eq!(
            family(state(&s, None).await),
            None,
            "nothing to compare with"
        );
    }

    #[tokio::test]
    async fn a_deposit_withdrawn_stops_counting_at_once() {
        let s = State::in_memory().await.expect("state");
        let vault = |g: Vec<Safeguard>| {
            g.into_iter()
                .find(|g| g.id == hlb_api::breakglass::EMERGENCY_VAULT)
                .expect("the safeguard")
                .attention()
        };
        s.attest_breakglass(hlb_api::breakglass::EMERGENCY_VAULT, "the deposit", None)
            .await
            .expect("proved");
        assert_eq!(vault(state(&s, None).await), hlb_api::Attention::Ok);
        s.forget_breakglass(hlb_api::breakglass::EMERGENCY_VAULT)
            .await
            .expect("withdrawn");
        assert_eq!(vault(state(&s, None).await), hlb_api::Attention::Critical);
    }

    #[tokio::test]
    async fn the_three_human_guardrails_take_the_attestation() {
        let s = State::in_memory().await.expect("state");
        s.attest_breakglass("two-passkeys", "camille", None)
            .await
            .expect("attestation");

        let g = state(&s, None).await;
        let pk = g
            .iter()
            .find(|g| g.id == "two-passkeys")
            .expect("safeguard");
        assert_eq!(pk.attested_by.as_deref(), Some("camille"));
        assert_eq!(pk.attention(), hlb_api::Attention::Ok);
    }
}
