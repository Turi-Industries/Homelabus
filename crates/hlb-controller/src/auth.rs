//! Qui fait la requête, et a-t-il le droit (§9ter).
//!
//! ## Deux façons d'être authentifié, une seule façon d'être autorisé
//!
//! | Porteur | Mécanisme | Pour qui |
//! |---|---|---|
//! | `Authorization: Bearer hlb_…` | jeton d'API, empreinte en base | le CLI, Bitwarden, un scrape |
//! | `Cookie: hlb_session=…` | session posée après OIDC PocketID | une personne, dans un navigateur |
//!
//! Les deux produisent une [`Identite`]. À partir de là, le contrôle est le même : le
//! rôle est confronté à une [`Action`](hlb_types::rbac::Action) par [`Autorise`].
//!
//! ## 🔴 Pourquoi le rôle d'une personne est relu à chaque requête
//!
//! Il serait moins coûteux de figer le rôle dans la session à la connexion. Mais alors,
//! retirer les droits d'administrateur à quelqu'un n'aurait aucun effet tant que sa
//! session vit — jusqu'à douze heures. Or on retire des droits précisément quand on est
//! pressé de le faire. Le rôle est donc relu dans `user_roles` à chaque requête.
//!
//! Un jeton, lui, porte son rôle : il n'appartient pas à une personne mais à un usage,
//! et on le révoque en le supprimant.

use std::marker::PhantomData;
use std::sync::Arc;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use hlb_types::rbac::Action;

use crate::api::AppState;

/// Nom du cookie de session.
pub const COOKIE: &str = "hlb_session";

/// Durée d'une session, glissante : chaque requête la repousse.
pub const DUREE_SESSION_S: i64 = 12 * 3600;

/// 🔴 En-tête exigé sur toute requête mutante authentifiée par COOKIE.
///
/// `SameSite=Lax` empêche le cookie de partir sur une navigation croisée, mais **pas**
/// sur un `POST` de formulaire déclenché depuis un autre site dans certains navigateurs
/// et configurations. Un en-tête personnalisé, si : le navigateur ne l'ajoute qu'à une
/// requête `fetch` de même origine, et une requête inter-origines qui le porterait
/// déclencherait un contrôle préalable CORS que le controller ne satisfait pas.
///
/// Les appels par jeton en sont dispensés : sans cookie, il n'y a pas d'autorité
/// ambiante à détourner, donc pas de CSRF.
pub const ENTETE_UI: &str = "x-hlb-ui";

/// Qui agit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Acteur {
    /// Une machine. `user` est le compte au nom duquel le jeton peut agir (§5bis.3) —
    /// `None` pour un jeton de service, qui n'agit au nom de personne.
    Jeton { nom: String, user: Option<String> },
    /// Une personne, connectée dans un navigateur.
    Personne { user: String },
    /// Mode `--insecure-no-auth`. Nommé, pour que le journal d'audit ne prétende pas
    /// qu'un administrateur identifié a agi.
    Anonyme,
}

impl Acteur {
    /// Le nom à écrire au journal d'audit.
    pub fn nom(&self) -> &str {
        match self {
            Self::Jeton { nom, .. } => nom,
            Self::Personne { user } => user,
            Self::Anonyme => "anonyme",
        }
    }

    /// Le compte au nom duquel cette requête agit, s'il y en a un.
    ///
    /// 🔴 C'est ce que consulte tout ce qui touche aux données d'une personne (aliases,
    /// boîtes, Sieve). Un jeton de service rend `None`, et l'appelant doit refuser :
    /// le privilège ne remplace pas l'identité — un jeton `admin` volé ne doit pas
    /// pouvoir créer des adresses sur la boîte de n'importe qui.
    pub fn pour_compte(&self) -> Option<&str> {
        match self {
            Self::Jeton { user, .. } => user.as_deref(),
            Self::Personne { user } => Some(user),
            Self::Anonyme => None,
        }
    }

    pub fn est_personne(&self) -> bool {
        matches!(self, Self::Personne { .. })
    }
}

/// L'identité derrière une requête : qui, et avec quel rôle.
///
/// 🔴 Un extracteur, donc une route qui en a besoin ne peut pas oublier de le demander :
/// le compilateur l'exige dans sa signature. Une vérification écrite à la main dans
/// chaque gestionnaire finit toujours par manquer quelque part.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identite {
    pub role: hlb_types::Role,
    pub acteur: Acteur,
}

impl Identite {
    pub fn peut(&self, action: Action) -> bool {
        self.role.allows(action)
    }

    /// Le message d'un refus, ou `None` si l'action est permise.
    pub fn refus(&self, action: Action) -> Option<String> {
        self.role.refus(action)
    }
}

/// L'horloge murale en secondes Unix.
///
/// ⚠️ Jamais `Instant` : ici on compare à des échéances stockées en base, pas des
/// durées. Un `Instant` ne survit pas à un redémarrage.
pub fn maintenant() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// La valeur d'un cookie dans un en-tête `Cookie`.
///
/// Analyse écrite à la main : l'en-tête est une liste `nom=valeur` séparée par `; `, et
/// une dépendance de plus pour ça ne se justifie pas.
///
/// ⚠️ On compare le nom **exactement**. Sans ça, un cookie `xhlb_session` posé par un
/// sous-domaine tiers serait accepté à la place du nôtre.
pub fn cookie(entete: &str, nom: &str) -> Option<String> {
    entete.split(';').find_map(|part| {
        let part = part.trim();
        let (k, v) = part.split_once('=')?;
        (k.trim() == nom).then(|| v.trim().to_string())
    })
}

fn refus_401() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(axum::http::header::WWW_AUTHENTICATE, "Bearer")],
        "authentification requise : jeton d'API, ou connexion sur /auth/connexion\n",
    )
        .into_response()
}

impl axum::extract::FromRequestParts<Arc<AppState>> for Identite {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        s: &Arc<AppState>,
    ) -> std::result::Result<Self, Self::Rejection> {
        if s.no_auth {
            // Mode ouvert assumé : le démarrage l'a annoncé bruyamment. L'acteur reste
            // nommé `anonyme` pour que le journal d'audit ne prétende pas mieux.
            return Ok(Self {
                role: hlb_types::Role::Admin,
                acteur: Acteur::Anonyme,
            });
        }

        // 1. Le cookie de session d'abord : c'est le cas courant depuis un navigateur.
        let brut = parts
            .headers
            .get(axum::http::header::COOKIE)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| cookie(v, COOKIE));

        if let Some(valeur) = brut {
            let now = maintenant();
            if let Ok(Some((user, _sub))) = s.state.find_session(&valeur, now).await {
                // 🔴 CSRF : une requête mutante portée par un cookie doit prouver
                // qu'elle vient de notre propre interface.
                if mute(&parts.method) && !parts.headers.contains_key(ENTETE_UI) {
                    return Err((
                        StatusCode::FORBIDDEN,
                        format!(
                            "requête refusée : une action authentifiée par session doit porter \
                             l'en-tête « {ENTETE_UI} ». C'est la protection contre les requêtes \
                             déclenchées depuis un autre site.\n"
                        ),
                    )
                        .into_response());
                }

                // Prolonge la session sans attendre : noter l'usage ne doit ni ralentir
                // la requête ni la faire échouer.
                let st = s.state.clone();
                let v = valeur.clone();
                tokio::spawn(async move {
                    let _ = st.touch_session(&v, now, DUREE_SESSION_S).await;
                });

                // 🔴 Le rôle est relu ici, pas lu dans la session : voir l'en-tête.
                let role = s.state.user_role(&user).await.unwrap_or_default();
                return Ok(Self {
                    role,
                    acteur: Acteur::Personne { user },
                });
            }
        }

        // 2. Sinon un jeton d'API.
        let presente = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .unwrap_or("");

        // ⚠️ Même réponse pour « pas de jeton », « jeton inconnu » et « session
        // expirée ». Les distinguer dirait à un attaquant si une valeur essayée existe.
        match s.state.find_token(presente).await {
            Ok(Some(t)) => {
                let st = s.state.clone();
                let nom = t.name.clone();
                tokio::spawn(async move {
                    let _ = st.touch_token(&nom).await;
                });

                let user = s.state.token_user(&t.name).await.unwrap_or(None);
                Ok(Self {
                    role: t.role,
                    acteur: Acteur::Jeton { nom: t.name, user },
                })
            }
            _ => Err(refus_401()),
        }
    }
}

/// La requête change-t-elle quelque chose ?
fn mute(m: &axum::http::Method) -> bool {
    !matches!(
        *m,
        axum::http::Method::GET | axum::http::Method::HEAD | axum::http::Method::OPTIONS
    )
}

// ---------------------------------------------------------------------------
// L'autorisation, portée par le type de l'argument du gestionnaire
// ---------------------------------------------------------------------------

/// Ce qu'une route exige.
///
/// 🔴 Rust n'accepte pas une variante d'énumération comme paramètre const générique.
/// D'où un marqueur par action plutôt qu'un `Autorise<{Action::Operate}>`. Le bénéfice
/// est le même : l'exigence est **dans la signature du gestionnaire**, donc visible en
/// relecture et impossible à oublier.
pub trait Exige {
    const ACTION: Action;
}

macro_rules! marqueur {
    ($($nom:ident => $action:ident, $doc:literal;)*) => {
        $(
            #[doc = $doc]
            pub struct $nom;
            impl Exige for $nom {
                const ACTION: Action = Action::$action;
            }
        )*

        /// Tous les marqueurs et l'action qu'ils exigent.
        ///
        /// Sert au test d'exhaustivité : une action sans marqueur serait une action
        /// qu'aucune route ne peut exiger.
        #[cfg(test)]
        const MARQUEURS: &[Action] = &[$(Action::$action),*];
    };
}

marqueur! {
    PeutLireSoi => ReadSelf, "Consulter ses propres données.";
    PeutAgirSurSoi => ActOnSelf, "Modifier ses propres données : aliases, tri, thème.";
    PeutLire => Read, "Consulter l'exploitation : cluster, nœuds, journaux, métriques.";
    PeutPublier => Publish, "Publier une annonce, ouvrir ou clore un incident.";
    PeutOperer => Operate, "Installer, mettre à jour, sauvegarder, drainer.";
    PeutGererComptes => ManageAccounts, "Créer un compte, inviter, changer un rôle.";
    PeutDetruire => Destroy, "🔴 Détruire, purger, restaurer en production.";
}

/// Une identité **dont le droit a été vérifié**.
///
/// 🔴 La garantie est structurelle : un gestionnaire qui prend `Autorise<PeutOperer>`
/// ne peut pas s'exécuter sans que le contrôle ait eu lieu, parce que l'extraction
/// échoue avant lui. C'est la même idée que `Freshness` côté UI — le type oblige à
/// regarder.
pub struct Autorise<E: Exige>(pub Identite, PhantomData<E>);

impl<E: Exige> Autorise<E> {
    pub fn identite(&self) -> &Identite {
        &self.0
    }

    pub fn acteur(&self) -> &Acteur {
        &self.0.acteur
    }
}

impl<E: Exige> axum::extract::FromRequestParts<Arc<AppState>> for Autorise<E> {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        s: &Arc<AppState>,
    ) -> std::result::Result<Self, Self::Rejection> {
        let identite = Identite::from_request_parts(parts, s).await?;

        match identite.refus(E::ACTION) {
            None => Ok(Self(identite, PhantomData)),
            // 🔴 Le refus nomme l'action, le rôle requis, le rôle détenu et le remède.
            // Un `403` nu laisserait deviner si on s'est trompé d'écran, si le système
            // est cassé, ou s'il manque un droit.
            Some(message) => {
                // 🔴 Et il est JOURNALISÉ. Constaté en essayant : un viewer qui tentait
                // de supprimer une app recevait un 403 et ne laissait aucune trace —
                // quelqu'un qui sonde ce qu'il peut détruire passait invisible, alors
                // que c'est précisément ce qu'un journal d'audit existe pour montrer.
                //
                // ⚠️ L'issue est « refused », distincte de « failed » : le système a
                // protégé, il n'est pas tombé en panne. Les peindre pareil ferait
                // chercher un incident là où une garde a fonctionné.
                let _ = s
                    .state
                    .audit(
                        identite.acteur.nom(),
                        identite.role,
                        E::ACTION.nom(),
                        // La cible exacte demande de connaître la route ; le chemin la
                        // porte, et c'est ce qu'on veut relire après coup.
                        parts.uri.path(),
                        "refused",
                        Some(&message),
                    )
                    .await;

                Err((StatusCode::FORBIDDEN, format!("{message}\n")).into_response())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hlb_types::Role;

    #[test]
    fn every_action_can_be_demanded_by_some_route() {
        // 🔴 Une action sans marqueur serait une action qu'aucune route ne peut exiger :
        // elle existerait dans le modèle et ne protégerait rien. Le `match` exhaustif
        // ci-dessous fait échouer la compilation si une variante est ajoutée sans
        // marqueur correspondant.
        for a in [
            Action::ReadSelf,
            Action::ActOnSelf,
            Action::Read,
            Action::Publish,
            Action::Operate,
            Action::ManageAccounts,
            Action::Destroy,
        ] {
            // Le match force la mise à jour de cette liste quand `Action` change.
            let _nom = match a {
                Action::ReadSelf => "LireSoi",
                Action::ActOnSelf => "AgirSurSoi",
                Action::Read => "Lire",
                Action::Publish => "Publier",
                Action::Operate => "Operer",
                Action::ManageAccounts => "GererComptes",
                Action::Destroy => "Detruire",
            };
            assert!(MARQUEURS.contains(&a), "{_nom} n'a pas de marqueur Peut*");
        }
        assert_eq!(MARQUEURS.len(), 7);
    }

    #[test]
    fn markers_demand_what_they_are_named_after() {
        assert_eq!(PeutLire::ACTION, Action::Read);
        assert_eq!(PeutOperer::ACTION, Action::Operate);
        assert_eq!(PeutDetruire::ACTION, Action::Destroy);
        assert_eq!(PeutGererComptes::ACTION, Action::ManageAccounts);
    }

    #[test]
    fn a_service_token_acts_for_nobody() {
        // 🔴 Le privilège ne remplace pas l'identité : un jeton admin non rattaché ne
        // doit pas pouvoir créer d'aliases sur la boîte de quelqu'un.
        let a = Acteur::Jeton {
            nom: "collecte".into(),
            user: None,
        };
        assert_eq!(a.pour_compte(), None);
        assert_eq!(a.nom(), "collecte");
        assert!(!a.est_personne());
    }

    #[test]
    fn a_bound_token_acts_for_its_account() {
        let a = Acteur::Jeton {
            nom: "bitwarden".into(),
            user: Some("remy".into()),
        };
        assert_eq!(a.pour_compte(), Some("remy"));
    }

    #[test]
    fn an_open_mode_actor_is_never_passed_off_as_a_person() {
        // Le journal d'audit ne doit pas laisser croire qu'un administrateur identifié
        // a agi alors que l'API était ouverte.
        let a = Acteur::Anonyme;
        assert_eq!(a.nom(), "anonyme");
        assert_eq!(a.pour_compte(), None);
        assert!(!a.est_personne());
    }

    #[test]
    fn a_cookie_is_matched_by_its_exact_name() {
        // 🔴 Sans comparaison exacte, un `xhlb_session` posé par un sous-domaine tiers
        // serait accepté à la place du nôtre.
        assert_eq!(cookie("hlb_session=abc", COOKIE), Some("abc".into()));
        assert_eq!(
            cookie("autre=1; hlb_session=abc; x=2", COOKIE),
            Some("abc".into())
        );
        assert_eq!(cookie(" hlb_session = abc ", COOKIE), Some("abc".into()));
        assert_eq!(cookie("xhlb_session=abc", COOKIE), None);
        assert_eq!(cookie("hlb_session_bis=abc", COOKIE), None);
        assert_eq!(cookie("", COOKIE), None);
        assert_eq!(cookie("sans-egal", COOKIE), None);
    }

    #[test]
    fn only_reading_methods_escape_the_csrf_header() {
        use axum::http::Method;
        assert!(!mute(&Method::GET));
        assert!(!mute(&Method::HEAD));
        assert!(!mute(&Method::OPTIONS));
        for m in [Method::POST, Method::PUT, Method::DELETE, Method::PATCH] {
            assert!(mute(&m), "{m} devrait exiger l'en-tête");
        }
    }

    #[test]
    fn a_refusal_carries_the_remedy() {
        let i = Identite {
            role: Role::Viewer,
            acteur: Acteur::Personne {
                user: "remy".into(),
            },
        };
        assert!(i.peut(Action::Read));
        let m = i.refus(Action::Operate).expect("un viewer n'opère pas");
        assert!(m.contains("operator"), "{m}");
        assert!(m.contains("viewer"), "{m}");
    }

    #[test]
    fn a_plain_user_is_not_a_viewer() {
        let i = Identite {
            role: Role::User,
            acteur: Acteur::Personne {
                user: "invite".into(),
            },
        };
        assert!(i.peut(Action::ReadSelf));
        assert!(i.peut(Action::ActOnSelf));
        assert!(!i.peut(Action::Read), "le portail n'est pas la console");
    }
}
