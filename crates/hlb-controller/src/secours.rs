//! Les garde-fous d'accès de secours (lot 10.2, §5.7bis).
//!
//! ## 🔴 Ce module ne vérifie presque rien, et c'est le sujet
//!
//! HomelabUS ne sait pas combien de passkeys sont enregistrées, ni si des codes à usage
//! unique sont imprimés et rangés hors du cluster. Il ne peut donc pas cocher ces cases
//! — il peut demander qu'on les atteste, garder la date, et redevenir rouge quand
//! l'attestation vieillit.
//!
//! Le seul point qu'il vérifie lui-même est l'exercice de restauration : il en a la
//! trace. Les trois autres sont des attestations humaines, et l'écran le dit.

use hlb_api::breakglass::{garde_fous, GardeFou};
use hlb_state::State;

/// L'état des quatre garde-fous.
pub async fn etat(state: &State) -> Vec<GardeFou> {
    let attestations = state.breakglass().await.unwrap_or_default();
    let mut out = garde_fous();

    for g in out.iter_mut() {
        if let Some((_, age, par)) = attestations.iter().find(|(id, ..)| id == &g.id) {
            g.atteste_il_y_a_s = Some(*age);
            g.atteste_par = Some(par.clone());
        }

        // 🔴 L'exercice de restauration est le SEUL point dont HomelabUS a la trace.
        // Une attestation humaine ne doit pas pouvoir le déclarer fait : c'est
        // précisément le garde-fou qu'on croit tenu et qui ne l'est pas.
        if g.verifiable {
            g.atteste_il_y_a_s = state
                .days_since_successful_drill()
                .await
                .unwrap_or(None)
                .map(|j| j * 86_400);
            g.atteste_par = g
                .atteste_il_y_a_s
                .map(|_| "exercice de reprise".to_string());
        }
    }
    out
}

/// Atteste un garde-fou.
///
/// ⚠️ Route de CONFIGURATION, sans aperçu : cocher « oui, deux passkeys sont
/// enregistrées » est une déclaration réversible d'un clic. Un aller-retour ferait
/// prendre l'habitude de confirmer deux fois, ce qui viderait l'aperçu de son sens là
/// où il compte.
pub async fn attester(
    auth: crate::auth::Autorise<crate::auth::PeutGererComptes>,
    axum::extract::State(s): axum::extract::State<std::sync::Arc<crate::api::AppState>>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> axum::response::Response {
    use axum::response::IntoResponse as _;

    // 🔴 Un identifiant inconnu est REFUSÉ, pas enregistré : accepté, il serait stocké,
    // n'apparaîtrait sur aucun écran, et l'on croirait le garde-fou attesté.
    if !hlb_api::breakglass::garde_fous().iter().any(|g| g.id == id) {
        return (
            axum::http::StatusCode::NOT_FOUND,
            format!("garde-fou inconnu : « {id} »"),
        )
            .into_response();
    }

    // Et celui que HomelabUS vérifie lui-même ne s'atteste pas à la main : la trace de
    // l'exercice fait foi, et rien d'autre.
    if hlb_api::breakglass::garde_fous()
        .iter()
        .any(|g| g.id == id && g.verifiable)
    {
        return (
            axum::http::StatusCode::CONFLICT,
            "ce garde-fou ne s'atteste pas : il se prouve par un exercice de reprise \
             réussi (« hlb dr exercise --apply »)"
                .to_string(),
        )
            .into_response();
    }

    let acteur = auth.identite().acteur.nom().to_string();
    if let Err(e) = s.state.attester_breakglass(&id, &acteur, None).await {
        return (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            e.to_string(),
        )
            .into_response();
    }

    let _ = s
        .state
        .audit(&acteur, auth.identite().role, "breakglass-attester", &id, "ok", None)
        .await;

    axum::Json(etat(&s.state).await).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_human_attestation_cannot_stand_in_for_the_real_drill() {
        // 🔴 Le point : quelqu'un peut sincèrement croire avoir éprouvé la restauration
        // de PocketID. La trace, elle, ne croit rien. Laisser l'attestation l'emporter
        // ferait afficher en vert le garde-fou le plus important sans qu'aucun exercice
        // n'ait eu lieu.
        let s = State::in_memory().await.expect("état");
        s.attester_breakglass("pocketid-restaure", "remy", None)
            .await
            .expect("attestation");

        let g = etat(&s).await;
        let pocket = g
            .iter()
            .find(|g| g.id == "pocketid-restaure")
            .expect("le garde-fou");

        assert_eq!(
            pocket.atteste_il_y_a_s, None,
            "aucun exercice n'a eu lieu : l'attestation ne compte pas"
        );
        assert_eq!(pocket.attention(), hlb_api::Attention::Critical);
    }

    #[tokio::test]
    async fn a_real_drill_fills_it_in_without_anyone_attesting() {
        let s = State::in_memory().await.expect("état");
        s.record_drill("postgres", true, Some(42), 187, "bac à sable")
            .await
            .expect("exercice");

        let g = etat(&s).await;
        let pocket = g
            .iter()
            .find(|g| g.id == "pocketid-restaure")
            .expect("le garde-fou");

        assert!(pocket.atteste_il_y_a_s.is_some());
        assert_eq!(pocket.atteste_par.as_deref(), Some("exercice de reprise"));
    }

    #[tokio::test]
    async fn the_three_human_guardrails_take_the_attestation() {
        let s = State::in_memory().await.expect("état");
        s.attester_breakglass("deux-passkeys", "camille", None)
            .await
            .expect("attestation");

        let g = etat(&s).await;
        let pk = g.iter().find(|g| g.id == "deux-passkeys").expect("garde-fou");
        assert_eq!(pk.atteste_par.as_deref(), Some("camille"));
        assert_eq!(pk.attention(), hlb_api::Attention::Ok);
    }
}
