//! Les routes de connexion : entrer et sortir (§9ter).
//!
//! Trois routes, et un aller-retour vers PocketID entre les deux premières :
//!
//! ```text
//! GET  /auth/connexion?retour=/apps   → 302 vers PocketID
//!                                       (la personne s'authentifie par clé d'accès)
//! GET  /auth/retour?code=…&state=…    → échange serveur-à-serveur, pose le cookie,
//!                                       302 vers `retour`
//! POST /auth/deconnexion              → ferme la session, efface le cookie
//! ```
//!
//! ## 🔴 Une identité PocketID ne suffit PAS à entrer
//!
//! PocketID dit *qui* est la personne. Il ne dit pas qu'elle a le droit d'être ici.
//! Sans compte Homelabus correspondant, la connexion est **refusée** — et non pas
//! honorée en créant un compte à la volée.
//!
//! C'est délibéré et cohérent avec l'exposition privée par défaut du projet : PocketID
//! peut servir d'autres applications, et son annuaire n'est pas la liste des personnes
//! autorisées sur le controller. Ouvrir l'un ouvrirait l'autre, silencieusement, le jour
//! où quelqu'un ajoute un compte pour Jellyfin.
//!
//! L'entrée se fait donc par `hlb user add`, ou par une invitation.

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Query, State as AxumState};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use hlb_identity::oidc::{DemandeEnCours, Oidc};

use crate::api::AppState;
use crate::auth::{maintenant, Autorise, Identite, PeutLireSoi, COOKIE, DUREE_SESSION_S};

/// Au-delà, on refuse d'entamer une nouvelle connexion.
///
/// Sans plafond, marteler `/auth/connexion` ferait grossir la table des demandes en
/// attente jusqu'à épuiser la mémoire du controller — une panne totale déclenchée par
/// une route publique.
const DEMANDES_MAX: usize = 256;

/// Ce que le controller retient entre le départ vers PocketID et le retour.
///
/// En mémoire et non en base : une demande vit dix minutes, et un redémarrage entre les
/// deux se solde par « relance la connexion », ce qui est acceptable. Une table de plus
/// ne se justifie pas, et elle partirait dans les sauvegardes.
pub struct Connexion {
    pub oidc: Oidc,
    /// `true` = poser le cookie avec `Secure`.
    ///
    /// ⚠️ Déduit de l'URL publique, pas codé en dur : un cookie `Secure` n'est **pas
    /// posé du tout** sur `http://`, et le développement local se solderait par une
    /// boucle de connexion sans message d'erreur.
    pub securise: bool,
    en_cours: tokio::sync::Mutex<HashMap<String, DemandeEnCours>>,
}

impl Connexion {
    pub fn new(oidc: Oidc, url_publique: &str) -> Self {
        Self {
            oidc,
            securise: url_publique.starts_with("https://"),
            en_cours: tokio::sync::Mutex::new(HashMap::new()),
        }
    }

    async fn retenir(&self, d: DemandeEnCours) -> Result<(), &'static str> {
        let mut m = self.en_cours.lock().await;
        // Ménage d'abord : une demande périmée n'a plus de raison d'occuper la place.
        let now = maintenant();
        m.retain(|_, d| !d.est_expiree(now));
        if m.len() >= DEMANDES_MAX {
            return Err("trop de connexions en cours d'établissement — réessaie dans un instant");
        }
        m.insert(d.state.clone(), d);
        Ok(())
    }

    /// Retire et rend la demande correspondant à cet état.
    ///
    /// 🔴 **Retire**, systématiquement : une demande consommée ne doit pas pouvoir
    /// resservir, sinon un code d'autorisation intercepté serait rejouable tant que la
    /// demande vit.
    async fn consommer(&self, state: &str) -> Option<DemandeEnCours> {
        self.en_cours.lock().await.remove(state)
    }
}

#[derive(serde::Deserialize)]
pub struct DepartQuery {
    /// Où revenir après connexion. Filtré par `DemandeEnCours::retour_sur`.
    pub retour: Option<String>,
}

/// Envoie la personne s'authentifier chez PocketID.
pub async fn depart(
    AxumState(s): AxumState<Arc<AppState>>,
    Query(q): Query<DepartQuery>,
) -> Response {
    let Some(cx) = &s.connexion else {
        return indisponible();
    };

    let mut alea = [0u8; 96];
    hlb_secrets::fill_random(&mut alea);
    let (url, demande) = cx.oidc.demarrer(&alea, q.retour, maintenant());

    if let Err(e) = cx.retenir(demande).await {
        return (StatusCode::SERVICE_UNAVAILABLE, format!("{e}\n")).into_response();
    }

    (
        StatusCode::FOUND,
        [(header::LOCATION, url)],
        // Une redirection ne doit jamais être mise en cache : l'URL porte un état à
        // usage unique, et un cache la resservirait après consommation.
        [(header::CACHE_CONTROL, "no-store")],
    )
        .into_response()
}

#[derive(serde::Deserialize)]
pub struct RetourQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    /// PocketID renvoie une erreur ici quand la personne refuse l'autorisation.
    pub error: Option<String>,
    pub error_description: Option<String>,
}

/// Le retour de PocketID : échange le code, ouvre la session.
pub async fn retour(
    AxumState(s): AxumState<Arc<AppState>>,
    Query(q): Query<RetourQuery>,
    entetes: axum::http::HeaderMap,
) -> Response {
    let Some(cx) = &s.connexion else {
        return indisponible();
    };

    // La personne a refusé, ou PocketID a refusé pour elle. Ce n'est pas une panne : on
    // le dit tel quel plutôt que de rendre une erreur technique.
    if let Some(e) = q.error {
        let d = q.error_description.unwrap_or_default();
        return (
            StatusCode::FORBIDDEN,
            format!("connexion refusée par le fournisseur d'identité : {e} {d}\n"),
        )
            .into_response();
    }

    let (Some(code), Some(state)) = (q.code, q.state) else {
        return (
            StatusCode::BAD_REQUEST,
            "retour de connexion incomplet — recommence depuis /auth/connexion\n",
        )
            .into_response();
    };

    let Some(demande) = cx.consommer(&state).await else {
        // Aucune demande pour cet état : soit elle a expiré, soit elle a déjà servi,
        // soit la requête est forgée. Les trois donnent le même message : distinguer
        // dirait à un attaquant si un état essayé a existé.
        return (
            StatusCode::BAD_REQUEST,
            "connexion expirée ou déjà utilisée — relance la connexion\n",
        )
            .into_response();
    };

    let identite = match cx
        .oidc
        .terminer(&demande, &state, &code, maintenant())
        .await
    {
        Ok(i) => i,
        Err(e) => {
            tracing::warn!(erreur = %e, "échec de connexion OIDC");
            return (
                StatusCode::BAD_GATEWAY,
                format!("connexion impossible : {e}\n"),
            )
                .into_response();
        }
    };

    // 🔴 Rattachement par le `sub` PocketID d'abord : il est stable, alors que le nom
    // d'utilisateur peut être renommé — et un rattachement par le nom perdrait le lien
    // en silence au premier renommage.
    let compte = match s.state.user_by_pocket_id(&identite.sub).await {
        Ok(Some(c)) => Some(c),
        _ => {
            // À défaut, par le nom — c'est ce qui permet à un compte créé par
            // `hlb user add` avant la première connexion de fonctionner.
            let nom = identite.nom_de_compte().to_string();
            match s.state.users().await {
                Ok(u) if u.iter().any(|(n, _, _)| n == &nom) => Some(nom),
                _ => None,
            }
        }
    };

    let Some(compte) = compte else {
        let _ = s
            .state
            .audit(
                identite.nom_de_compte(),
                hlb_types::Role::User,
                "connexion",
                &identite.sub,
                "refused",
                Some("aucun compte Homelabus pour cette identité PocketID"),
            )
            .await;
        return (
            StatusCode::FORBIDDEN,
            format!(
                "« {} » est bien connu de PocketID, mais n'a pas de compte Homelabus.\n\
                 \n\
                 C'est voulu : l'annuaire de PocketID sert aussi les autres applications, \
                 et y figurer ne donne pas accès au controller.\n\
                 \n\
                 Un administrateur peut ouvrir l'accès :  hlb user add {} --apply\n",
                identite.nom_affiche(),
                identite.nom_de_compte()
            ),
        )
            .into_response();
    };

    // Le lien `sub` ↔ compte est consigné à la première connexion : un renommage chez
    // PocketID ne cassera plus rien ensuite.
    let _ = s.state.upsert_user_pocket_id(&compte, &identite.sub).await;

    let mut brut = [0u8; 32];
    hlb_secrets::fill_random(&mut brut);
    // Base32 comme les jetons : pas de `/`, `+` ni `=` — un cookie n'a pas à être
    // réencodé, et un caractère mal échappé se solderait par une session introuvable.
    let valeur = hlb_types::token::base32(&brut);

    let agent = entetes
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.chars().take(120).collect::<String>());

    if let Err(e) = s
        .state
        .open_session(
            &valeur,
            &compte,
            Some(&identite.sub),
            maintenant(),
            DUREE_SESSION_S,
            agent.as_deref(),
        )
        .await
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("session impossible à ouvrir : {e}\n"),
        )
            .into_response();
    }

    let role = s.state.user_role(&compte).await.unwrap_or_default();
    let _ = s
        .state
        .audit(&compte, role, "connexion", &identite.sub, "ok", None)
        .await;

    (
        StatusCode::FOUND,
        [
            (header::LOCATION, demande.retour_sur().to_string()),
            (header::SET_COOKIE, cookie_session(&valeur, cx.securise)),
            (header::CACHE_CONTROL, "no-store".to_string()),
        ],
    )
        .into_response()
}

/// Ferme la session courante.
pub async fn deconnexion(
    identite: Identite,
    AxumState(s): AxumState<Arc<AppState>>,
    entetes: axum::http::HeaderMap,
) -> Response {
    let securise = s.connexion.as_ref().map(|c| c.securise).unwrap_or(true);

    if let Some(valeur) = entetes
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| crate::auth::cookie(v, COOKIE))
    {
        let _ = s.state.close_session(&valeur).await;
    }

    let _ = s
        .state
        .audit(
            identite.acteur.nom(),
            identite.role,
            "deconnexion",
            identite.acteur.nom(),
            "ok",
            None,
        )
        .await;

    (
        StatusCode::OK,
        [(header::SET_COOKIE, cookie_efface(securise))],
        "déconnecté\n",
    )
        .into_response()
}

/// Qui suis-je ?
///
/// La première requête que fait l'UI : elle détermine quels écrans afficher. Rendre
/// `403` ici plutôt qu'un objet vide permet à l'interface de proposer la connexion au
/// lieu d'afficher une console dont tout est grisé.
pub async fn moi(
    auth: Autorise<PeutLireSoi>,
    AxumState(s): AxumState<Arc<AppState>>,
) -> axum::Json<hlb_api::Moi> {
    let i = auth.identite();
    let compte = i.acteur.pour_compte().map(str::to_string);

    let boites = match &compte {
        Some(c) => s
            .state
            .mailboxes(c)
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|(local, domaine, defaut)| hlb_api::BoiteBreve {
                adresse: format!("{local}@{domaine}"),
                par_defaut: defaut,
            })
            .collect(),
        None => Vec::new(),
    };

    axum::Json(hlb_api::Moi {
        compte,
        role: i.role.as_str().to_string(),
        role_libelle: i.role.describe().to_string(),
        par_jeton: !i.acteur.est_personne(),
        peut: hlb_api::Droits::pour(i.role),
        boites,
    })
}

fn cookie_session(valeur: &str, securise: bool) -> String {
    // `SameSite=Lax` : le cookie suit une navigation normale vers le site (c'est
    // indispensable au retour depuis PocketID, où `Strict` l'empêcherait d'être envoyé
    // et la connexion boucherait), mais pas une requête inter-site. La protection CSRF
    // des requêtes mutantes est complétée par l'en-tête `X-HLB-UI` (cf. `auth.rs`).
    let s = if securise { "; Secure" } else { "" };
    format!("{COOKIE}={valeur}; Path=/; HttpOnly; SameSite=Lax; Max-Age={DUREE_SESSION_S}{s}")
}

fn cookie_efface(securise: bool) -> String {
    let s = if securise { "; Secure" } else { "" };
    format!("{COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0{s}")
}

fn indisponible() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        "connexion par PocketID non configurée sur ce controller.\n\
         Lance-le avec --oidc-issuer, --oidc-client-id et --oidc-client-secret, \
         ou utilise un jeton d'API.\n",
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_session_cookie_is_unreachable_from_javascript() {
        // 🔴 Sans `HttpOnly`, une seule faille XSS dans une page servie par le
        // controller suffirait à exfiltrer la session — et l'UI wasm est servie par le
        // controller lui-même.
        let c = cookie_session("abc", true);
        assert!(c.contains("HttpOnly"), "{c}");
        assert!(c.contains("SameSite=Lax"), "{c}");
        assert!(c.contains("Path=/"), "{c}");
        assert!(c.contains("Secure"), "{c}");
    }

    #[test]
    fn a_plain_http_deployment_still_gets_a_cookie() {
        // ⚠️ Un cookie `Secure` n'est PAS posé sur http:// — le développement local
        // boucherait sur l'écran de connexion, sans message d'erreur.
        let c = cookie_session("abc", false);
        assert!(!c.contains("Secure"), "{c}");
        assert!(c.contains("HttpOnly"), "{c}");
    }

    #[test]
    fn secure_follows_the_public_url_not_a_guess() {
        let ep = hlb_identity::oidc::Endpoints {
            issuer: "https://id.turi.fr".into(),
            authorization_endpoint: "https://id.turi.fr/authorize".into(),
            token_endpoint: "https://id.turi.fr/token".into(),
            userinfo_endpoint: "https://id.turi.fr/userinfo".into(),
            end_session_endpoint: None,
        };
        let oidc =
            |_: ()| Oidc::avec_endpoints(ep.clone(), "hlb", "s", "https://hlb.turi.fr/auth/retour");
        assert!(Connexion::new(oidc(()), "https://hlb.turi.fr").securise);
        assert!(!Connexion::new(oidc(()), "http://127.0.0.1:8420").securise);
    }

    #[test]
    fn logging_out_expires_the_cookie_rather_than_leaving_it() {
        // Ne pas l'effacer laisserait le navigateur envoyer une valeur morte à chaque
        // requête : la personne se croirait connectée jusqu'au prochain 401.
        let c = cookie_efface(true);
        assert!(c.contains("Max-Age=0"), "{c}");
        assert!(c.starts_with(&format!("{COOKIE}=;")), "{c}");
    }

    #[tokio::test]
    async fn a_consumed_request_cannot_be_replayed() {
        // 🔴 Une demande consommée ne doit pas resservir : sinon un code d'autorisation
        // intercepté serait rejouable tant que la demande vit.
        let ep = hlb_identity::oidc::Endpoints {
            issuer: "https://id.turi.fr".into(),
            authorization_endpoint: "https://id.turi.fr/authorize".into(),
            token_endpoint: "https://id.turi.fr/token".into(),
            userinfo_endpoint: "https://id.turi.fr/userinfo".into(),
            end_session_endpoint: None,
        };
        let cx = Connexion::new(
            Oidc::avec_endpoints(ep, "hlb", "s", "https://hlb.turi.fr/auth/retour"),
            "https://hlb.turi.fr",
        );

        let (_, d) = cx.oidc.demarrer(&[1u8; 96], None, maintenant());
        let etat = d.state.clone();
        cx.retenir(d).await.expect("retenue");

        assert!(cx.consommer(&etat).await.is_some(), "première fois");
        assert!(cx.consommer(&etat).await.is_none(), "pas deux fois");
    }

    #[tokio::test]
    async fn hammering_the_login_route_does_not_exhaust_memory() {
        // Sans plafond, marteler /auth/connexion ferait grossir la table jusqu'à la
        // panne — une indisponibilité totale déclenchée par une route publique.
        let ep = hlb_identity::oidc::Endpoints {
            issuer: "https://id.turi.fr".into(),
            authorization_endpoint: "https://id.turi.fr/authorize".into(),
            token_endpoint: "https://id.turi.fr/token".into(),
            userinfo_endpoint: "https://id.turi.fr/userinfo".into(),
            end_session_endpoint: None,
        };
        let cx = Connexion::new(
            Oidc::avec_endpoints(ep, "hlb", "s", "https://hlb.turi.fr/auth/retour"),
            "https://hlb.turi.fr",
        );

        let mut refuse = false;
        for n in 0..(DEMANDES_MAX + 10) {
            let mut a = [0u8; 96];
            a[0] = (n % 251) as u8;
            a[1] = (n / 251) as u8;
            let (_, d) = cx.oidc.demarrer(&a, None, maintenant());
            if cx.retenir(d).await.is_err() {
                refuse = true;
                break;
            }
        }
        assert!(refuse, "la table des demandes devrait être plafonnée");
    }

    #[tokio::test]
    async fn expired_requests_make_room_for_new_ones() {
        // Le ménage doit précéder le plafond, sinon un pic de connexions abandonnées
        // bloquerait le site jusqu'au redémarrage.
        let ep = hlb_identity::oidc::Endpoints {
            issuer: "https://id.turi.fr".into(),
            authorization_endpoint: "https://id.turi.fr/authorize".into(),
            token_endpoint: "https://id.turi.fr/token".into(),
            userinfo_endpoint: "https://id.turi.fr/userinfo".into(),
            end_session_endpoint: None,
        };
        let cx = Connexion::new(
            Oidc::avec_endpoints(ep, "hlb", "s", "https://hlb.turi.fr/auth/retour"),
            "https://hlb.turi.fr",
        );

        // Des demandes déjà périmées au moment où on les range.
        for n in 0..DEMANDES_MAX {
            let mut a = [0u8; 96];
            a[0] = (n % 251) as u8;
            a[1] = (n / 251) as u8;
            let (_, d) = cx.oidc.demarrer(&a, None, 0);
            let _ = cx.retenir(d).await;
        }

        let (_, fraiche) = cx.oidc.demarrer(&[9u8; 96], None, maintenant());
        assert!(
            cx.retenir(fraiche).await.is_ok(),
            "les demandes périmées auraient dû laisser la place"
        );
    }
}
