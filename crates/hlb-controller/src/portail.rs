//! Le portail : ce que voit quelqu'un qui a un compte et rien d'autre (lot 7).
//!
//! ## 🔴 Ce que Homelabus n'accorde pas
//!
//! Le portail **annonce** les applications disponibles ; il ne donne pas l'accès. Celui-ci
//! vient de PocketID et du forward-auth. La distinction n'est pas théorique : afficher
//! une app comme « disponible » ne la rend pas accessible, et laisser croire l'inverse
//! ferait chercher une panne là où il manque une autorisation.
//!
//! L'écran le dit, plutôt que de laisser deviner.
//!
//! ## Et une annonce qui ne concerne pas son lecteur est du bruit
//!
//! L'inonder de messages d'exploitation lui fait cesser de les lire — au moment précis
//! où l'un d'eux comptera. D'où l'audience par rôle.

use std::sync::Arc;

use axum::extract::{Path, Query, State as AxumState};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use hlb_api::{EtapeAction, EtatEtape, ResultatAction};

use crate::actions::ActionQuery;
use crate::api::AppState;
use crate::auth::{Autorise, PeutLireSoi, PeutPublier};

/// Les annonces destinées à celui qui regarde.
pub async fn annonces(
    auth: Autorise<PeutLireSoi>,
    AxumState(s): AxumState<Arc<AppState>>,
) -> Json<Vec<hlb_api::Annonce>> {
    Json(
        s.state
            .annonces(auth.identite().role, crate::auth::maintenant(), false)
            .await
            .unwrap_or_default(),
    )
}

/// Ce que le portail affiche.
#[derive(Debug, serde::Serialize)]
pub struct Portail {
    /// Les applications exposées, avec leur adresse.
    pub apps: Vec<AppPortail>,
    pub annonces: Vec<hlb_api::Annonce>,
    /// Le compte, s'il y en a un.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compte: Option<String>,
    #[serde(default)]
    pub boites: Vec<hlb_api::BoiteBreve>,
}

#[derive(Debug, serde::Serialize)]
pub struct AppPortail {
    pub nom: String,
    pub nom_affiche: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domaine: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub categorie: Option<String>,
    /// 🔴 L'app tourne-t-elle **en ce moment** ?
    ///
    /// Afficher un lien vers une app arrêtée envoie sur une page d'erreur, et l'on
    /// croit que c'est son propre accès qui est cassé.
    pub disponible: bool,
}

/// Le portail d'une personne.
pub async fn portail(
    auth: Autorise<PeutLireSoi>,
    AxumState(s): AxumState<Arc<AppState>>,
) -> Json<Portail> {
    let i = auth.identite();
    let compte = i.acteur.pour_compte().map(str::to_string);

    let installees = s.state.installed_apps().await.unwrap_or_default();
    let mut apps = Vec::new();

    for (nom, statut) in installees {
        // ⚠️ Seules les apps qui ont un domaine sont montrées : les services de
        // plateforme (postgres, valkey) n'ont rien à offrir à un utilisateur, et les
        // lister ferait chercher un lien qui n'existe pas.
        let Ok(Some(domaine)) = s.state.app_domain(&nom).await else {
            continue;
        };

        let nom_affiche = s
            .state
            .app_manifest(&nom)
            .await
            .ok()
            .and_then(|m| m.metadata.display_name.clone())
            .unwrap_or_else(|| nom.clone());
        let categorie = s
            .state
            .app_manifest(&nom)
            .await
            .ok()
            .and_then(|m| m.metadata.category.clone());

        apps.push(AppPortail {
            nom,
            nom_affiche,
            domaine: Some(domaine),
            categorie,
            disponible: statut == "running",
        });
    }
    apps.sort_by(|a, b| a.nom_affiche.cmp(&b.nom_affiche));

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

    Json(Portail {
        apps,
        annonces: s
            .state
            .annonces(i.role, crate::auth::maintenant(), false)
            .await
            .unwrap_or_default(),
        compte,
        boites,
    })
}

/// Les thèmes livrés par l'interface.
///
/// 🔴 La liste vit ICI et non côté wasm : si chacun avait la sienne, un thème retiré
/// resterait proposé jusqu'au prochain déploiement de l'interface, et le choisir
/// donnerait un thème par défaut sans explication.
///
/// ⚠️ Elle doit rester alignée sur `hlb_ui::design::Theme::livres()`. Le controller ne
/// peut pas dépendre de l'interface — ce serait le sens inverse de la flèche — donc un
/// test côté `hlb-ui` vérifie l'accord.
pub const THEMES: &[&str] = &["Turi sombre", "Turi clair", "Contraste élevé"];

/// Les préférences d'affichage de la personne connectée.
pub async fn preferences(
    auth: Autorise<PeutLireSoi>,
    AxumState(s): AxumState<Arc<AppState>>,
) -> Json<hlb_api::Preferences> {
    let theme = match auth.acteur().pour_compte() {
        Some(c) => s.state.theme_de(c).await.unwrap_or(None),
        // Un jeton de service n'a pas de préférence : il n'appartient à personne.
        None => None,
    };

    Json(hlb_api::Preferences {
        theme,
        disponibles: THEMES.iter().map(|t| t.to_string()).collect(),
        defaut: s.state.marque().await.ok().and_then(|m| m.theme_defaut),
    })
}

#[derive(Debug, Default, serde::Deserialize)]
pub struct DemandeTheme {
    /// Le nom du thème. `null` = revenir à celui de l'installation.
    #[serde(default)]
    pub theme: Option<String>,
}

/// Change le thème de la personne connectée.
///
/// ⚠️ Pas d'aperçu : choisir un thème est immédiat, réversible d'un clic, et sans effet
/// sur qui que ce soit d'autre. Imposer un aller-retour ferait prendre l'habitude de
/// confirmer deux fois — ce qui viderait la protection de son sens là où elle compte.
pub async fn changer_theme(
    auth: Autorise<crate::auth::PeutAgirSurSoi>,
    AxumState(s): AxumState<Arc<AppState>>,
    corps: Option<Json<DemandeTheme>>,
) -> Response {
    let d = corps.map(|Json(d)| d).unwrap_or_default();

    let Some(compte) = auth.acteur().pour_compte() else {
        return (
            StatusCode::FORBIDDEN,
            "un jeton de service n'a pas de préférences : il n'appartient à personne\n",
        )
            .into_response();
    };

    // 🔴 Un thème inconnu est REFUSÉ, pas accepté silencieusement : accepté, il serait
    // stocké, retomberait sur le défaut à l'affichage, et l'on croirait le choix perdu
    // par un défaut de l'interface.
    if let Some(t) = &d.theme {
        if !THEMES.contains(&t.as_str()) {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                format!(
                    "thème « {t} » inconnu. Disponibles : {}\n",
                    THEMES.join(", ")
                ),
            )
                .into_response();
        }
    }

    match s.state.set_theme_de(compte, d.theme.as_deref()).await {
        Ok(()) => (StatusCode::NO_CONTENT).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("{e}\n")).into_response(),
    }
}

/// La page de statut.
///
/// ## 🔴 Privée par défaut
///
/// Elle est servie derrière l'authentification tant que `--statut-public` n'est pas
/// posé. Une page de statut publique révèle la liste de ce qui tourne chez vous et le
/// calendrier de vos pannes — c'est un choix légitime, mais qui se décide.
///
/// ⚠️ Quand elle est publique, elle ne montre que les services **exposés** et les
/// incidents : jamais les nœuds, jamais les sauvegardes, jamais les comptes.
pub async fn statut(AxumState(s): AxumState<Arc<AppState>>) -> Response {
    if !s.statut_public {
        // Le refus dit COMMENT ouvrir la page, pour ne pas laisser croire à une panne.
        return (
            StatusCode::NOT_FOUND,
            "page de statut non publiée. Un administrateur peut l'ouvrir : \
             --statut-public au démarrage du controller.\n",
        )
            .into_response();
    }
    Json(construire_statut(&s).await).into_response()
}

/// La même page, pour qui est déjà authentifié.
///
/// Toujours disponible : voir l'état des services fait partie de la lecture normale.
pub async fn statut_prive(
    _auth: Autorise<PeutLireSoi>,
    AxumState(s): AxumState<Arc<AppState>>,
) -> Json<hlb_api::PageStatut> {
    Json(construire_statut(&s).await)
}

async fn construire_statut(s: &AppState) -> hlb_api::PageStatut {
    let maintenant = crate::auth::maintenant();

    // Les incidents ouverts, vus comme le public les verrait : aucune annonce
    // réservée à l'exploitation ne doit fuiter sur une page potentiellement publique.
    let incidents: Vec<hlb_api::Annonce> = s
        .state
        .annonces(hlb_types::Role::User, maintenant, false)
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|a| a.incident_ouvert())
        .collect();

    // Une maintenance annoncée change l'état affiché : c'était prévu, et le dire évite
    // qu'on cherche ce qui ne va pas.
    let en_maintenance: Vec<String> = s
        .state
        .annonces(hlb_types::Role::User, maintenant, false)
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|a| a.niveau == hlb_api::NiveauAnnonce::Maintenance)
        .map(|a| a.titre.to_lowercase())
        .collect();

    let mut services = Vec::new();
    for (nom, statut) in s.state.installed_apps().await.unwrap_or_default() {
        // ⚠️ Seules les apps EXPOSÉES : les services de plateforme ne regardent pas
        // l'extérieur, et les lister sur une page publique dresserait l'inventaire de
        // l'installation.
        let Ok(Some(domaine)) = s.state.app_domain(&nom).await else {
            continue;
        };

        let annoncee = en_maintenance.iter().any(|t| t.contains(&nom));
        services.push(hlb_api::ServiceStatut {
            etat: match statut.as_str() {
                _ if annoncee => hlb_api::EtatService::Maintenance,
                "running" => hlb_api::EtatService::Operationnel,
                "partial" => hlb_api::EtatService::Degrade,
                _ => hlb_api::EtatService::Indisponible,
            },
            nom,
            domaine: Some(domaine),
        });
    }
    services.sort_by(|a, b| {
        b.etat
            .attention()
            .cmp(&a.etat.attention())
            .then_with(|| a.nom.cmp(&b.nom))
    });

    hlb_api::PageStatut {
        services,
        incidents,
        publique: s.statut_public,
    }
}

#[derive(Debug, Default, serde::Deserialize)]
pub struct DemandeAnnonce {
    #[serde(default)]
    pub titre: Option<String>,
    #[serde(default)]
    pub corps: Option<String>,
    #[serde(default)]
    pub niveau: Option<String>,
    #[serde(default)]
    pub epinglee: bool,
    /// Rôle minimal pour la voir. Absent = tout le monde.
    #[serde(default)]
    pub audience: Option<String>,
    /// Durée de visibilité en secondes. Absente = permanente.
    #[serde(default)]
    pub duree_s: Option<i64>,
}

/// Publie une annonce.
pub async fn publier(
    auth: Autorise<PeutPublier>,
    AxumState(s): AxumState<Arc<AppState>>,
    Query(q): Query<ActionQuery>,
    corps: Option<Json<DemandeAnnonce>>,
) -> Response {
    let d = corps.map(|Json(d)| d).unwrap_or_default();
    let mut blocages = Vec::new();
    let mut avertissements = Vec::new();

    let titre = d.titre.clone().unwrap_or_default();
    let texte = d.corps.clone().unwrap_or_default();
    if titre.trim().is_empty() {
        blocages.push("titre manquant".to_string());
    }
    if texte.trim().is_empty() {
        blocages.push("corps manquant — une annonce sans texte n'annonce rien".to_string());
    }

    let niveau = hlb_api::NiveauAnnonce::parse(d.niveau.as_deref().unwrap_or("info"));
    let audience = d.audience.as_deref().and_then(hlb_types::Role::parse);

    // 🔴 Un incident sans échéance reste ouvert indéfiniment, et c'est VOULU : le
    // silence ne doit pas passer pour une résolution. Mais il faut le savoir.
    if niveau == hlb_api::NiveauAnnonce::Incident && d.duree_s.is_none() {
        avertissements.push(
            "cet incident restera affiché jusqu'à ce que quelqu'un le clôture — c'est \
             voulu : une panne qui disparaît toute seule de l'écran laisse croire \
             qu'elle est réglée"
                .to_string(),
        );
    }

    if audience.is_none() && niveau == hlb_api::NiveauAnnonce::Maintenance {
        avertissements.push(
            "sans audience, cette maintenance sera visible de tous, y compris des \
             personnes qui n'ont qu'une boîte mail"
                .to_string(),
        );
    }

    let applique = q.apply && blocages.is_empty();
    let mut etape = EtapeAction {
        description: format!("publier « {titre} » ({})", niveau.libelle()),
        etat: EtatEtape::Prevue,
        erreur: None,
    };

    if applique {
        let expire = d
            .duree_s
            .map(|s| crate::auth::maintenant().saturating_add(s));
        match s
            .state
            .publier_annonce(
                &titre,
                &texte,
                niveau,
                d.epinglee,
                audience,
                auth.acteur().nom(),
                expire,
            )
            .await
        {
            Ok(_) => etape.etat = EtatEtape::Faite,
            Err(e) => {
                etape.etat = EtatEtape::Echouee;
                etape.erreur = Some(e.to_string());
            }
        }
    }

    let r = ResultatAction {
        applique,
        resume: format!("publier « {titre} »"),
        etapes: vec![etape],
        commande_cli: format!(
            "hlb annonce publier \"{titre}\" --niveau {} --apply",
            niveau.as_str()
        ),
        blocages,
        avertissements,
        confirmation_requise: None,
    };

    repondre(&s, auth.identite(), "annonce", &titre, r).await
}

#[derive(Debug, Default, serde::Deserialize)]
pub struct DemandeSuivi {
    #[serde(default)]
    pub corps: Option<String>,
}

/// Ajoute une nouvelle au fil d'un incident.
pub async fn suivre(
    auth: Autorise<PeutPublier>,
    AxumState(s): AxumState<Arc<AppState>>,
    Path(id): Path<i64>,
    Query(q): Query<ActionQuery>,
    corps: Option<Json<DemandeSuivi>>,
) -> Response {
    let d = corps.map(|Json(d)| d).unwrap_or_default();
    let texte = d.corps.clone().unwrap_or_default();
    let mut blocages = Vec::new();

    if texte.trim().is_empty() {
        blocages.push("texte manquant".to_string());
    }

    let applique = q.apply && blocages.is_empty();
    let mut etape = EtapeAction {
        // ⚠️ Le mot « ajouter » est délibéré : une mise à jour s'AJOUTE au fil, elle ne
        // remplace pas le message d'origine. C'est la chronologie qu'on relit après.
        description: format!("ajouter une nouvelle au fil de l'annonce {id}"),
        etat: EtatEtape::Prevue,
        erreur: None,
    };

    if applique {
        match s
            .state
            .suivre_annonce(id, &texte, auth.acteur().nom())
            .await
        {
            Ok(()) => etape.etat = EtatEtape::Faite,
            Err(e) => {
                etape.etat = EtatEtape::Echouee;
                etape.erreur = Some(e.to_string());
            }
        }
    }

    let r = ResultatAction {
        applique,
        resume: format!("suivi de l'annonce {id}"),
        etapes: vec![etape],
        commande_cli: format!("hlb annonce suivre {id} \"…\" --apply"),
        blocages,
        avertissements: Vec::new(),
        confirmation_requise: None,
    };

    repondre(&s, auth.identite(), "annonce-suivi", &id.to_string(), r).await
}

/// Retire une annonce.
pub async fn retirer(
    auth: Autorise<PeutPublier>,
    AxumState(s): AxumState<Arc<AppState>>,
    Path(id): Path<i64>,
    Query(q): Query<ActionQuery>,
) -> Response {
    let applique = q.apply;
    let mut etape = EtapeAction {
        description: format!("retirer l'annonce {id}"),
        etat: EtatEtape::Prevue,
        erreur: None,
    };

    if applique {
        match s.state.retirer_annonce(id).await {
            Ok(true) => etape.etat = EtatEtape::Faite,
            Ok(false) => {
                etape.etat = EtatEtape::Echouee;
                etape.erreur = Some(format!("aucune annonce {id}"));
            }
            Err(e) => {
                etape.etat = EtatEtape::Echouee;
                etape.erreur = Some(e.to_string());
            }
        }
    }

    let r = ResultatAction {
        applique,
        resume: format!("retirer l'annonce {id}"),
        etapes: vec![etape],
        commande_cli: format!("hlb annonce retirer {id} --apply"),
        blocages: Vec::new(),
        // ⚠️ Retirer efface le fil de suivi avec l'annonce. Pour un incident clos, on
        // préfère le laisser expirer : l'historique se relit.
        avertissements: vec![
            "retirer efface aussi le fil de suivi — pour un incident clos, laisse-le \
             plutôt expirer : l'historique reste consultable"
                .to_string(),
        ],
        confirmation_requise: None,
    };

    repondre(&s, auth.identite(), "annonce-retrait", &id.to_string(), r).await
}

async fn repondre(
    s: &AppState,
    identite: &crate::auth::Identite,
    action: &str,
    cible: &str,
    r: ResultatAction,
) -> Response {
    let issue = if !r.applique {
        "preview"
    } else if r.reussie() {
        "ok"
    } else {
        "failed"
    };
    let _ = s
        .state
        .audit(
            identite.acteur.nom(),
            identite.role,
            action,
            cible,
            issue,
            Some(&r.verdict()),
        )
        .await;
    (StatusCode::OK, Json(r)).into_response()
}
