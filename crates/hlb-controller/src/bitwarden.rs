//! L'assistant Bitwarden (lot 11.1, §5bis.3).
//!
//! ## 🔴 Ce que cet écran remplace
//!
//! Aujourd'hui, câbler Bitwarden se fait de mémoire : créer un jeton `operator`, penser
//! à le rattacher à la bonne boîte, retrouver l'URL du serveur, et deviner ce que le
//! champ « domaine » attend. La migration `0013_token_mailbox` n'existe QUE pour ça, et
//! rien ne l'expliquait nulle part.
//!
//! ## ⚠️ Deux pièges que l'assistant doit nommer
//!
//! - **Un jeton `admin` non rattaché est refusé** là où un `operator` rattaché passe :
//!   un jeton porte un RÔLE, pas une identité, et sans rattachement il créerait des
//!   aliases sur la boîte de n'importe qui.
//! - **La destination vit sur le JETON**, parce que le protocole addy.io n'a aucun
//!   champ pour la choisir : Bitwarden n'envoie que `domain` et `description`. Un jeton
//!   par boîte, et changer de destination revient à changer de jeton.

use serde::Deserialize;

/// Ce que l'assistant demande.
#[derive(Debug, Deserialize)]
pub struct Demande {
    /// Le compte propriétaire de la boîte.
    pub compte: String,
    /// La boîte de destination. `None` = la boîte par défaut du compte.
    #[serde(default)]
    pub boite: Option<String>,
    /// Un nom pour le jeton, afin de savoir lequel révoquer plus tard.
    #[serde(default)]
    pub nom: Option<String>,
}

/// Ce qu'il faut coller dans Bitwarden.
///
/// 🔴 La valeur du jeton n'apparaît QUE dans cette réponse, une seule fois : l'état
/// n'en garde qu'une empreinte. Elle n'est ni journalisée, ni relisible.
#[derive(Debug, serde::Serialize)]
pub struct Reglages {
    /// Le nom du jeton créé, pour le révoquer plus tard.
    pub nom_du_jeton: String,
    /// 🔴 Affichée une seule fois.
    pub jeton: String,
    /// L'adresse à coller dans « Self-host server URL ».
    pub url_serveur: String,
    /// Le domaine à coller dans « Domain ».
    pub domaine: String,
    /// La boîte qui recevra les aliases.
    pub boite: String,
    /// Ce qu'il faut faire, dans l'ordre, dans l'interface de Bitwarden.
    pub etapes: Vec<String>,
}

/// Les étapes, telles qu'elles apparaissent dans Bitwarden.
///
/// ⚠️ Les noms des champs sont ceux de l'interface anglophone de Bitwarden — les
/// traduire ferait chercher un champ qui n'existe pas à l'écran.
pub fn etapes(url: &str, domaine: &str) -> Vec<String> {
    vec![
        "Dans Bitwarden : Settings, puis Options, puis Username Generator.".to_string(),
        "Choisir « Forwarded email alias », puis le service « addy.io ».".to_string(),
        "Coller le jeton ci-dessus dans « API access token ».".to_string(),
        format!("Mettre « {url} » dans « Self-host server URL »."),
        format!("Mettre « {domaine} » dans « Domain »."),
        "Générer un alias pour vérifier : il doit apparaître dans « Ma boîte » ici même."
            .to_string(),
    ]
}

/// Le nom du jeton, déduit si l'on n'en donne pas.
///
/// ⚠️ Le nom porte la boîte : avec un jeton par boîte, « bitwarden » tout court
/// deviendrait ambigu dès la seconde, et l'on révoquerait le mauvais.
pub fn nom_du_jeton(compte: &str, boite: Option<&str>) -> String {
    match boite {
        Some(b) => format!("bitwarden-{compte}-{b}"),
        None => format!("bitwarden-{compte}"),
    }
}

/// Crée le jeton rattaché à la boîte, et rend ce qu'il faut coller.
///
/// ⚠️ Route de configuration : elle CRÉE un jeton, ce qui n'est ni destructeur ni
/// irréversible (on le révoque d'un clic), et il n'y a rien à prévisualiser — la valeur
/// n'existe qu'au moment de la création.
pub async fn assistant(
    auth: crate::auth::Autorise<crate::auth::PeutGererComptes>,
    axum::extract::State(s): axum::extract::State<std::sync::Arc<crate::api::AppState>>,
    axum::Json(d): axum::Json<Demande>,
) -> axum::response::Response {
    use axum::response::IntoResponse as _;

    let refus = |code: axum::http::StatusCode, msg: String| (code, msg).into_response();

    // 🔴 La boîte doit EXISTER. Un jeton rattaché à une boîte absente échouerait à
    // chaque génération d'alias, des semaines plus tard, sur un message que Bitwarden
    // n'affiche même pas — il se contente de ne pas remplir le champ.
    let boites = s.state.mailboxes(&d.compte).await.unwrap_or_default();
    if boites.is_empty() {
        return refus(
            axum::http::StatusCode::NOT_FOUND,
            format!(
                "« {} » n'a aucune boîte : rien ne recevrait les aliases.",
                d.compte
            ),
        );
    }

    let boite = match &d.boite {
        Some(b) => {
            if !boites.iter().any(|(local, ..)| local == b) {
                return refus(
                    axum::http::StatusCode::NOT_FOUND,
                    format!("« {b} » n'est pas une boîte de « {} ».", d.compte),
                );
            }
            b.clone()
        }
        // La boîte par défaut du compte : c'est le cas courant, et il ne demande rien.
        None => boites
            .iter()
            .find(|(_, _, defaut)| *defaut)
            .map(|(local, ..)| local.clone())
            .unwrap_or_else(|| boites[0].0.clone()),
    };

    let domaine = boites
        .iter()
        .find(|(local, ..)| local == &boite)
        .map(|(_, dom, _)| dom.clone())
        .unwrap_or_default();

    // ⚠️ L'URL publique, jamais l'adresse d'écoute : Bitwarden appelle depuis un
    // téléphone, où « 127.0.0.1 » désigne le téléphone.
    let Some(url) = s.url_publique.clone() else {
        return refus(
            axum::http::StatusCode::CONFLICT,
            "l'URL publique du controller est inconnue (--public-url) : Bitwarden \
             appelle depuis l'extérieur, et une adresse locale n'y désigne pas cette \
             machine"
                .to_string(),
        );
    };

    let nom = d
        .nom
        .clone()
        .unwrap_or_else(|| nom_du_jeton(&d.compte, d.boite.as_deref()));

    let mut alea = [0u8; hlb_types::token::TOKEN_BYTES];
    hlb_secrets::fill_random(&mut alea);
    // 🔴 `operator` et non `admin` : un jeton d'API porte un rôle, pas une identité, et
    // celui-ci n'a besoin que de créer des aliases sur UNE boîte.
    let (valeur, stocke) = hlb_types::token::generate(&nom, hlb_types::Role::Operator, alea);

    if let Err(e) = s.state.store_token(&stocke).await {
        return refus(axum::http::StatusCode::CONFLICT, e.to_string());
    }
    // 🔴 DEUX rattachements, et le second a été oublié dans un premier jet : le jeton
    // portait sa boîte mais aucun COMPTE, et l'API d'aliases le refusait — « cette
    // requête n'agit au nom de personne ». L'assistant aurait livré, avec ses six
    // étapes rassurantes, un jeton que Bitwarden ne pouvait pas utiliser.
    //
    // Un jeton porte un RÔLE, pas une identité : sans rattachement, il créerait des
    // aliases sur la boîte de n'importe qui, donc il ne crée rien du tout.
    if let Err(e) = s.state.set_token_user(&nom, Some(&d.compte)).await {
        return refus(axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string());
    }
    if let Err(e) = s.state.set_token_mailbox(&nom, Some(&boite)).await {
        return refus(axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string());
    }

    // 🔴 Le journal note la CRÉATION, jamais la valeur.
    let _ = s
        .state
        .audit(
            auth.identite().acteur.nom(),
            auth.identite().role,
            "bitwarden-assistant",
            &nom,
            "ok",
            Some(&format!("jeton operator rattaché à « {boite} »")),
        )
        .await;

    axum::Json(Reglages {
        etapes: etapes(&url, &domaine),
        nom_du_jeton: nom,
        jeton: valeur,
        url_serveur: url,
        domaine,
        boite,
    })
    .into_response()
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn the_token_is_bound_to_the_account_not_only_to_the_mailbox() {
        // 🔴 Le défaut tel qu'il s'est présenté, et qu'aucun test unitaire n'aurait
        // attrapé : le premier jet rattachait la BOÎTE et pas le COMPTE. L'assistant
        // livrait alors, avec ses six étapes rassurantes, un jeton que l'API d'aliases
        // refuse — « cette requête n'agit au nom de personne » — et l'on aurait cherché
        // du côté de Bitwarden.
        //
        // Constaté en appelant réellement `/api/v1/aliases` avec le jeton produit.
        let s = hlb_state::State::in_memory().await.expect("état");
        s.upsert_user("remy", "standard", None)
            .await
            .expect("compte");
        s.add_mailbox("remy", "remy", "turi.fr", true)
            .await
            .expect("boîte");

        let mut alea = [0u8; hlb_types::token::TOKEN_BYTES];
        hlb_secrets::fill_random(&mut alea);
        let (_, stocke) =
            hlb_types::token::generate("bitwarden-remy", hlb_types::Role::Operator, alea);
        s.store_token(&stocke).await.expect("jeton");
        s.set_token_user("bitwarden-remy", Some("remy"))
            .await
            .expect("compte");
        s.set_token_mailbox("bitwarden-remy", Some("remy"))
            .await
            .expect("boîte");

        // Les DEUX rattachements, sans quoi l'un des deux manque en silence.
        let (compte, boite) = s.token_target("bitwarden-remy").await.expect("lecture");
        assert_eq!(
            compte,
            Some("remy".to_string()),
            "sans compte, l'API d'aliases refuse la requête"
        );
        assert_eq!(
            boite,
            Some("remy".to_string()),
            "sans boîte, les aliases iraient sur la boîte par défaut"
        );
    }

    use super::*;

    #[test]
    fn the_token_name_carries_the_mailbox_so_two_never_collide() {
        // ⚠️ Un jeton par boîte : « bitwarden » tout court deviendrait ambigu dès la
        // seconde boîte, et l'on révoquerait le mauvais en croyant fermer l'autre.
        assert_eq!(nom_du_jeton("remy", None), "bitwarden-remy");
        assert_eq!(
            nom_du_jeton("remy", Some("achats")),
            "bitwarden-remy-achats"
        );
        assert_ne!(
            nom_du_jeton("remy", Some("achats")),
            nom_du_jeton("remy", Some("banque"))
        );
    }

    #[test]
    fn the_steps_name_the_fields_as_bitwarden_shows_them() {
        // 🔴 Traduire « Self-host server URL » ferait chercher un champ qui n'existe pas
        // à l'écran : l'interface de Bitwarden est en anglais.
        let e = etapes("https://hlb.turi.fr", "turi.fr");
        let tout = e.join(" ");
        assert!(tout.contains("Self-host server URL"), "{tout}");
        assert!(tout.contains("API access token"), "{tout}");
        assert!(tout.contains("addy.io"), "{tout}");
        // Et l'URL et le domaine y figurent tels qu'on doit les coller.
        assert!(tout.contains("https://hlb.turi.fr"));
        assert!(tout.contains("turi.fr"));
    }

    #[test]
    fn the_last_step_is_a_verification() {
        // Un assistant qui s'arrête au collage laisse croire que c'est câblé. Le seul
        // moyen de savoir est de générer un alias et de le voir arriver.
        let e = etapes("https://x", "y");
        assert!(e.last().is_some_and(|d| d.contains("vérifier")), "{e:?}");
    }
}
