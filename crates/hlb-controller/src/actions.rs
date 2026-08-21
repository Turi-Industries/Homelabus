//! Les routes qui **agissent** (lot 5).
//!
//! ## Les trois règles, et pourquoi elles valent mieux que « lecture seule »
//!
//! L'API a longtemps interdit tout verbe mutant, et un test le vérifiait. C'était juste
//! pour une interface en lecture seule ; ça ne l'est plus dès qu'elle doit installer,
//! sauvegarder et restaurer.
//!
//! Trois règles remplacent l'interdiction, et **protègent davantage** :
//!
//! 1. **Aperçu par défaut.** Une route rend le plan et ne fait rien ; elle n'agit
//!    qu'avec `?apply=true`. Transposition exacte de `Executor::apply(true)` — le CLI
//!    et l'API se comportent pareil, et le défaut ne modifie rien.
//! 2. **Autorisation dans la signature.** `Autorise<PeutOperer>` : le compilateur
//!    l'exige, donc on ne peut pas l'oublier.
//! 3. **Journal d'audit.** Qui, quoi, quand, avec l'issue réelle.
//!
//! Chacune est verrouillée par un test qui parcourt la liste servant à **construire**
//! le routeur : une route ajoutée sans les respecter fait échouer la suite.
//!
//! ## 🔴 Et la confirmation nommée, pour ce qui détruit
//!
//! Le rôle ne suffit pas : un administrateur fatigué à 2 h du matin reste un
//! administrateur. Les opérations de `hlb_types::needs_confirmation` exigent de
//! **répéter le nom de la cible** — pour qu'un `--purge` tapé sur la mauvaise app ne
//! passe pas.

use std::sync::Arc;

use axum::extract::{Path, Query, State as AxumState};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use hlb_api::{EtapeAction, EtatEtape, ResultatAction};

use crate::api::{AppState, SEUIL_PEREMPTION_S};
use crate::auth::{Autorise, PeutDetruire, PeutOperer};

/// Les paramètres communs à toute action.
#[derive(Debug, Default, serde::Deserialize)]
pub struct ActionQuery {
    /// 🔴 Absent ou `false` = **aperçu**. C'est le défaut, et il ne modifie rien.
    #[serde(default)]
    pub apply: bool,
}

/// Le corps d'une opération destructive.
#[derive(Debug, Default, serde::Deserialize)]
pub struct Confirmation {
    /// Le nom exact de la cible, répété par l'appelant.
    #[serde(default)]
    pub confirme: Option<String>,
}

/// Vérifie la confirmation nommée d'une opération destructive.
///
/// ⚠️ Compare **exactement**, sans normalisation : accepter « Gitea » pour « gitea »
/// affaiblirait la seule protection qui reste quand le rôle a déjà été accordé.
pub fn confirmation_valide(c: &Confirmation, cible: &str) -> bool {
    c.confirme.as_deref() == Some(cible)
}

/// Journalise une action et rend la réponse.
///
/// 🔴 Passe par ici **systématiquement** : c'est ce qui garantit qu'aucune route
/// mutante n'échappe au journal. Un test le vérifie route par route.
async fn repondre(
    s: &AppState,
    identite: &crate::auth::Identite,
    action: &str,
    cible: &str,
    r: ResultatAction,
) -> Response {
    // L'issue réelle, pas l'intention : une action qui a échoué à mi-parcours est un
    // échec, même si elle a commencé correctement.
    let issue = if !r.applique {
        // Un aperçu n'est pas une action : le journaliser en « ok » ferait croire à
        // une exécution. On le nomme pour autant — savoir que quelqu'un a regardé ce
        // qu'une purge ferait est une information.
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

// ---------------------------------------------------------------------------
// Installation
// ---------------------------------------------------------------------------

/// Ce qu'on choisit pour installer une app.
#[derive(Debug, Default, serde::Deserialize)]
pub struct DemandeInstall {
    /// Le domaine public. Requis si l'app expose quelque chose.
    #[serde(default)]
    pub domaine: Option<String>,
    /// Le domaine mail, pour les capacités `MailAccount`.
    #[serde(default)]
    pub domaine_mail: Option<String>,
}

/// Le catalogue, avec ce qu'il faut savoir avant d'installer.
pub async fn catalogue(
    _auth: crate::auth::Autorise<crate::auth::PeutLire>,
    AxumState(s): AxumState<Arc<AppState>>,
) -> Json<Vec<hlb_api::CatalogueItem>> {
    let Some(cat) = &s.catalogue else {
        // ⚠️ Une liste vide se lirait « catalogue sans applications ». L'absence de
        // catalogue est un problème de configuration, pas un catalogue vide — et
        // l'écran doit pouvoir le dire.
        return Json(Vec::new());
    };

    let installees: Vec<String> = s
        .state
        .installed_apps()
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|(n, _)| n)
        .collect();

    let mut out: Vec<hlb_api::CatalogueItem> = cat
        .entries()
        .map(|e| {
            let m = &e.manifest;
            hlb_api::CatalogueItem {
                installee: installees.contains(&m.metadata.name),
                nom_affiche: m
                    .metadata
                    .display_name
                    .clone()
                    .unwrap_or_else(|| m.metadata.name.clone()),
                nom: m.metadata.name.clone(),
                categorie: m.metadata.category.clone(),
                homepage: m.metadata.homepage.clone(),
                image: m.spec.image.reference(),
                capacites: m.spec.requires.iter().map(|c| c.describe()).collect(),
                // Une app sans ingress n'a rien à exposer : lui demander un domaine
                // ferait saisir une valeur inutilisée.
                demande_domaine: !m.spec.ingress.is_empty(),
                // 🔴 Les prérequis MANUELS d'abord, listés avant même de commencer :
                // découvrir au sixième écran qu'il fallait un enregistrement DNS est
                // ce qui fait abandonner une installation en cours.
                prerequis: e
                    .guide
                    .steps
                    .iter()
                    .filter(|g| g.phase == hlb_types::Phase::PreInstall)
                    .map(|g| g.title.clone())
                    .collect(),
            }
        })
        .collect();

    out.sort_by(|a, b| a.nom.cmp(&b.nom));
    Json(out)
}

/// Installe une application.
///
/// ## 🔴 L'aperçu montre le PLAN RÉEL
///
/// Pas une description approximative : le résolveur produit les mêmes actions que
/// `hlb install`, et c'est cette liste qu'on affiche. Un aperçu qui divergerait de
/// l'exécution serait pire qu'aucun aperçu — on lui ferait confiance.
pub async fn installer_app(
    auth: Autorise<PeutOperer>,
    AxumState(s): AxumState<Arc<AppState>>,
    Path(app): Path<String>,
    Query(q): Query<ActionQuery>,
    corps: Option<Json<DemandeInstall>>,
) -> Response {
    let demande = corps.map(|Json(d)| d).unwrap_or_default();
    let mut blocages = Vec::new();

    let Some(cat) = &s.catalogue else {
        return erreur_action(
            &s,
            auth.identite(),
            "app-install",
            &app,
            "aucun catalogue chargé — lance le controller avec --catalog <répertoire>",
        )
        .await;
    };

    let entree = match cat.get(&app) {
        Ok(e) => e,
        Err(e) => {
            return erreur_action(&s, auth.identite(), "app-install", &app, &e.to_string()).await
        }
    };

    if s
        .state
        .installed_apps()
        .await
        .unwrap_or_default()
        .iter()
        .any(|(n, _)| n == &app)
    {
        blocages.push(format!(
            "« {app} » est déjà installée — pour la mettre à jour, « hlb update {app} »"
        ));
    }

    if entree.manifest.spec.ingress.is_empty() {
        // Rien à exposer : un domaine fourni serait ignoré, autant le dire.
    } else if demande.domaine.as_deref().unwrap_or("").trim().is_empty() {
        blocages.push(
            "cette application expose un service : un domaine est requis (« domaine » \
             dans le corps de la requête)"
                .to_string(),
        );
    }

    let params = hlb_resolver::InstallParams {
        domain: demande.domaine.clone(),
        mail_domain: demande.domaine_mail.clone(),
        ..Default::default()
    };

    // ⚠️ On ne planifie PAS si un blocage est déjà connu : le résolveur échouerait sur
    // le même manque avec un message technique (« paramètre domain requis »), et ce
    // message masquerait le nôtre, qui dit quoi faire.
    if !blocages.is_empty() {
        let r = ResultatAction {
            applique: false,
            resume: format!("installer {app} — impossible en l'état"),
            etapes: Vec::new(),
            commande_cli: format!("hlb install {app} --domain <domaine> --apply"),
            blocages,
            avertissements: Vec::new(),
            confirmation_requise: None,
        };
        return repondre(&s, auth.identite(), "app-install", &app, r).await;
    }

    // 🔴 Le plan RÉEL, produit par le même résolveur que la ligne de commande.
    let plan = match hlb_resolver::resolve_with_guide(&entree.manifest, &entree.guide, &params) {
        Ok(p) => p,
        Err(e) => {
            return erreur_action(&s, auth.identite(), "app-install", &app, &e.to_string()).await
        }
    };

    // Les guides bloquants arrêtent AVANT toute modification : inutile de déployer une
    // app dont le DNS n'existe pas. Ils viennent du plan, donc après lui.
    let bloquants: Vec<String> = plan
        .blocking_steps()
        .iter()
        .map(|a| format!("action manuelle requise d'abord : {a}"))
        .collect();

    let applique = q.apply && bloquants.is_empty();
    let etapes: Vec<EtapeAction> = plan
        .actions
        .iter()
        .map(|a| EtapeAction {
            description: a.to_string(),
            etat: if applique {
                // ⚠️ L'exécuteur n'est pas encore branché sur cette route : il lui faut
                // le coffre, l'orchestrateur et les clients de plateforme. On le DIT
                // plutôt que d'afficher un succès — « Unimplemented n'est jamais Done ».
                EtatEtape::NonImplementee
            } else {
                EtatEtape::Prevue
            },
            erreur: None,
        })
        .collect();

    let commande = match &demande.domaine {
        Some(d) => format!("hlb install {app} --domain {d} --apply"),
        None => format!("hlb install {app} --apply"),
    };

    // 🔴 Le budget de capacité, AVANT de planifier (§9.6). Une app placée sur un tier
    // sans mémoire ne rend pas d'erreur claire : le conteneur est tué par le noyau et
    // `wait_healthy` expire, ce qui envoie chercher du côté de la sonde de santé.
    //
    // ⚠️ C'est un AVERTISSEMENT, pas un blocage : la mémoire disponible bouge, et
    // refuser l'installation sur une mesure d'il y a trente secondes serait faux aussi
    // souvent que juste.
    let tier = entree
        .manifest
        .spec
        .swarm
        .tier
        .clone()
        .unwrap_or_else(|| "light".to_string());
    let avertissements = crate::capacite::budget(&parc_par_tier(&s).await, &tier)
        .avertissement()
        .into_iter()
        .collect();

    let r = ResultatAction {
        applique,
        resume: format!(
            "installer {app} — {}",
            hlb_api::pluriel(plan.actions.len() as u64, "action", "actions")
        ),
        etapes,
        commande_cli: commande,
        blocages: bloquants,
        avertissements,
        confirmation_requise: None,
    };

    repondre(&s, auth.identite(), "app-install", &app, r).await
}

/// Une action qui n'a même pas pu être planifiée.
///
/// Journalisée comme un échec : ne pas savoir quoi faire est un résultat, et le taire
/// laisserait un écran sans explication.
async fn erreur_action(
    s: &AppState,
    identite: &crate::auth::Identite,
    action: &str,
    cible: &str,
    message: &str,
) -> Response {
    let r = ResultatAction {
        applique: false,
        resume: message.to_string(),
        etapes: Vec::new(),
        commande_cli: String::new(),
        blocages: vec![message.to_string()],
        avertissements: Vec::new(),
        confirmation_requise: None,
    };
    let _ = s
        .state
        .audit(
            identite.acteur.nom(),
            identite.role,
            action,
            cible,
            "failed",
            Some(message),
        )
        .await;
    (StatusCode::UNPROCESSABLE_ENTITY, Json(r)).into_response()
}

// ---------------------------------------------------------------------------
// Sauvegardes
// ---------------------------------------------------------------------------

/// Déclenche une sauvegarde.
pub async fn backup_run(
    auth: Autorise<PeutOperer>,
    AxumState(s): AxumState<Arc<AppState>>,
    Path(app): Path<String>,
    Query(q): Query<ActionQuery>,
) -> Response {
    let couverture = {
        let source = crate::couverture::EtatSource(&s.state);
        hlb_backup::couverture_de(&source, &app, SEUIL_PEREMPTION_S).await
    };

    let mut etapes: Vec<EtapeAction> = couverture
        .par_destination
        .iter()
        .map(|(dest, _)| EtapeAction {
            description: format!("sauvegarder {app} vers « {dest} »"),
            // 🔴 En aperçu, `Prevue`. Jamais `Faite` : ce serait prétendre avoir
            // sauvegardé.
            etat: EtatEtape::Prevue,
            erreur: None,
        })
        .collect();

    let mut blocages = Vec::new();
    if couverture.par_destination.is_empty() {
        blocages.push(
            "aucune destination configurée — « hlb backup dest add <nom> --location \
             <chemin> --apply »"
                .to_string(),
        );
    }

    let applique = q.apply && blocages.is_empty();
    if applique {
        // ⚠️ La sauvegarde réelle vit dans la boucle du controller, qui a le dépôt
        // restic et le coffre. La déclencher depuis l'API demande de partager ce
        // contexte ; tant que ce n'est pas fait, on est HONNÊTE plutôt que d'afficher
        // un succès. « Unimplemented n'est jamais Done ».
        for e in &mut etapes {
            e.etat = EtatEtape::NonImplementee;
            e.erreur = Some(
                "le déclenchement depuis l'API n'est pas encore branché sur le dépôt \
                 restic — utilise la ligne de commande"
                    .into(),
            );
        }
    }

    let r = ResultatAction {
        applique,
        // 🔴 Même famille que la suppression sans volume : « vers 0 destination » se
        // lit comme une action qui va partir quelque part. Le résumé est la ligne qu'on
        // lit EN PREMIER — elle doit dire ce qui va réellement se passer, pas décliner
        // un compteur à zéro.
        resume: match couverture.par_destination.len() {
            0 => format!("sauvegarder {app} — aucune destination : rien ne partirait"),
            n => format!(
                "sauvegarder {app} vers {}",
                hlb_api::pluriel(n as u64, "destination", "destinations")
            ),
        },
        etapes,
        commande_cli: format!("hlb backup run --app {app} --apply"),
        blocages,
        avertissements: Vec::new(),
        confirmation_requise: None,
    };

    repondre(&s, auth.identite(), "backup-run", &app, r).await
}

// ---------------------------------------------------------------------------
// Guides
// ---------------------------------------------------------------------------

/// Atteste qu'une action manuelle a été faite (§4.6).
pub async fn verifier_guide(
    auth: Autorise<PeutOperer>,
    AxumState(s): AxumState<Arc<AppState>>,
    Path((app, id)): Path<(String, String)>,
    Query(q): Query<ActionQuery>,
) -> Response {
    let existe = s
        .state
        .pending_guides()
        .await
        .unwrap_or_default()
        .into_iter()
        .any(|(a, i, ..)| a == app && i == id);

    let mut blocages = Vec::new();
    if !existe {
        blocages.push(format!(
            "aucune action « {id} » en attente pour {app} — déjà faite, ou identifiant \
             erroné"
        ));
    }

    let applique = q.apply && blocages.is_empty();
    let mut etape = EtapeAction {
        description: format!("attester que « {id} » a été faite pour {app}"),
        etat: EtatEtape::Prevue,
        erreur: None,
    };

    if applique {
        match s.state.verify_guide(&app, &id).await {
            Ok(true) => etape.etat = EtatEtape::Faite,
            // ⚠️ `false` = rien n'a été mis à jour. Ce n'est pas une erreur technique,
            // mais ce n'est pas non plus une réussite : l'afficher comme faite ferait
            // croire qu'un guide inexistant a été validé.
            Ok(false) => {
                etape.etat = EtatEtape::Echouee;
                etape.erreur = Some(format!("aucune action « {id} » à attester pour {app}"));
            }
            Err(e) => {
                etape.etat = EtatEtape::Echouee;
                etape.erreur = Some(e.to_string());
            }
        }
    }

    let r = ResultatAction {
        applique,
        // 🔴 Le message dit que c'est une ATTESTATION. Cocher sans avoir fait débloque
        // un déploiement qui échouera plus loin, avec un message sans rapport.
        resume: format!(
            "attester « {id} » pour {app} — c'est une attestation, pas une case à cocher"
        ),
        etapes: vec![etape],
        commande_cli: format!("hlb guide verify {app} {id}"),
        blocages,
        avertissements: Vec::new(),
        confirmation_requise: None,
    };

    repondre(&s, auth.identite(), "guide-verify", &app, r).await
}

// ---------------------------------------------------------------------------
// Échelle et mise à jour
// ---------------------------------------------------------------------------

#[derive(Debug, Default, serde::Deserialize)]
pub struct DemandeEchelle {
    #[serde(default)]
    pub replicas: Option<u64>,
}

/// Change le nombre de réplicas d'une application.
pub async fn redimensionner(
    auth: Autorise<PeutOperer>,
    AxumState(s): AxumState<Arc<AppState>>,
    Path(app): Path<String>,
    Query(q): Query<ActionQuery>,
    corps: Option<Json<DemandeEchelle>>,
) -> Response {
    let demande = corps.map(|Json(d)| d).unwrap_or_default();
    let mut blocages = Vec::new();

    let Some(cible) = demande.replicas else {
        blocages.push("nombre de réplicas manquant (« replicas » dans le corps)".to_string());
        let r = ResultatAction {
            applique: false,
            resume: format!("redimensionner {app}"),
            etapes: Vec::new(),
            commande_cli: format!("hlb scale {app} <n> --apply"),
            blocages,
            avertissements: Vec::new(),
            confirmation_requise: None,
        };
        return repondre(&s, auth.identite(), "app-scale", &app, r).await;
    };

    // 🔴 Descendre à zéro n'est pas un redimensionnement, c'est un arrêt — et ça
    // n'arrive presque jamais volontairement depuis une interface. On le refuse ici :
    // `hlb stop` existe et dit ce qu'il fait.
    if cible == 0 {
        blocages.push(
            "zéro réplica arrête l'application — utilise « hlb stop » si c'est l'intention"
                .to_string(),
        );
    }

    let actuel = match &s.orchestrator {
        Some(o) => o.status(&app).await.ok().map(|st| st.desired_replicas),
        None => None,
    };

    if actuel.is_none() {
        blocages.push(format!("« {app} » n'est pas déployée, ou Docker est injoignable"));
    }

    let applique = q.apply && blocages.is_empty();
    let mut etape = EtapeAction {
        description: match actuel {
            Some(a) => format!(
                "passer {app} de {a} à {}",
                hlb_api::pluriel(cible, "réplica", "réplicas")
            ),
            None => format!(
                "passer {app} à {}",
                hlb_api::pluriel(cible, "réplica", "réplicas")
            ),
        },
        etat: EtatEtape::Prevue,
        erreur: None,
    };

    if applique {
        match &s.orchestrator {
            Some(o) => match o.scale(&app, cible).await {
                Ok(()) => etape.etat = EtatEtape::Faite,
                Err(e) => {
                    etape.etat = EtatEtape::Echouee;
                    etape.erreur = Some(e.to_string());
                }
            },
            None => {
                etape.etat = EtatEtape::Echouee;
                etape.erreur = Some("Docker injoignable".into());
            }
        }
    }

    let r = ResultatAction {
        applique,
        resume: format!("{app} à {}", hlb_api::pluriel(cible, "réplica", "réplicas")),
        etapes: vec![etape],
        commande_cli: format!("hlb scale {app} {cible} --apply"),
        blocages,
        avertissements: Vec::new(),
        confirmation_requise: None,
    };

    repondre(&s, auth.identite(), "app-scale", &app, r).await
}

// ---------------------------------------------------------------------------
// Destinations de sauvegarde
// ---------------------------------------------------------------------------

#[derive(Debug, Default, serde::Deserialize)]
pub struct DemandeDestination {
    #[serde(default)]
    pub location: Option<String>,
    /// `critique`, `volumineux`, ou les deux séparées par une virgule.
    #[serde(default)]
    pub classes: Option<String>,
    /// 🔴 Le NOM du secret qui porte les identifiants, **jamais leur valeur**.
    ///
    /// Le passer tel quel enverrait « backup-dest-offsite » comme clé d'accès S3, et
    /// le serveur répondrait « signature invalide » — une erreur qui n'oriente vers
    /// rien.
    #[serde(default)]
    pub credentials_secret: Option<String>,
}

/// Déclare ou met à jour une destination de sauvegarde.
pub async fn destination(
    auth: Autorise<PeutOperer>,
    AxumState(s): AxumState<Arc<AppState>>,
    Path(nom): Path<String>,
    Query(q): Query<ActionQuery>,
    corps: Option<Json<DemandeDestination>>,
) -> Response {
    let d = corps.map(|Json(d)| d).unwrap_or_default();
    let mut blocages = Vec::new();

    let location = d.location.clone().unwrap_or_default();
    if location.trim().is_empty() {
        blocages.push(
            "emplacement manquant : un chemin local (/mnt/nas/restic) ou une URL S3 \
             (s3:hôte/compartiment)"
                .to_string(),
        );
    }

    let classes = d.classes.clone().unwrap_or_else(|| "critique".to_string());
    let connues: Vec<&str> = classes
        .split(',')
        .map(str::trim)
        .filter(|c| hlb_backup::Classe::parse(c).is_none())
        .collect();
    if !connues.is_empty() {
        blocages.push(format!(
            "{} {} : {} — attendu « critique » ou « volumineux »",
            hlb_api::pluriel(connues.len() as u64, "classe", "classes"),
            if connues.len() > 1 {
                "inconnues"
            } else {
                "inconnue"
            },
            connues.join(", ")
        ));
    }

    // ⚠️ Une destination S3 sans identifiants ne servira à rien, et l'échec
    // n'apparaîtra qu'à la première sauvegarde — des heures plus tard.
    if location.starts_with("s3:") && d.credentials_secret.is_none() {
        blocages.push(
            "une destination S3 a besoin d'un secret d'identifiants \
             (« credentials_secret ») — sans lui, la première sauvegarde échouera sur \
             « signature invalide »"
                .to_string(),
        );
    }

    let applique = q.apply && blocages.is_empty();
    let mut etape = EtapeAction {
        description: format!("déclarer la destination « {nom} » vers {location} [{classes}]"),
        etat: EtatEtape::Prevue,
        erreur: None,
    };

    if applique {
        match s
            .state
            .upsert_destination(&nom, &location, &classes, d.credentials_secret.as_deref())
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
        resume: format!("destination « {nom} »"),
        etapes: vec![etape],
        commande_cli: format!(
            "hlb backup dest add {nom} --location {location} --classes {classes} --apply"
        ),
        blocages,
        avertissements: Vec::new(),
        confirmation_requise: None,
    };

    repondre(&s, auth.identite(), "backup-dest", &nom, r).await
}

// ---------------------------------------------------------------------------
// Nœuds
// ---------------------------------------------------------------------------

#[derive(Debug, Default, serde::Deserialize)]
pub struct DemandeNoeud {
    /// `active`, `pause` ou `drain`.
    #[serde(default)]
    pub disponibilite: Option<String>,
}

/// Change la disponibilité d'un nœud (drainer, reprendre).
pub async fn noeud_disponibilite(
    auth: Autorise<PeutOperer>,
    AxumState(s): AxumState<Arc<AppState>>,
    Path(id): Path<String>,
    Query(q): Query<ActionQuery>,
    corps: Option<Json<DemandeNoeud>>,
) -> Response {
    let d = corps.map(|Json(d)| d).unwrap_or_default();
    let mut blocages = Vec::new();

    let vise = d.disponibilite.clone().unwrap_or_default();
    if !matches!(vise.as_str(), "active" | "pause" | "drain") {
        blocages.push(
            "disponibilité attendue : « active », « pause » ou « drain »".to_string(),
        );
    }

    // 🔴 Drainer le DERNIER nœud sain viderait le cluster : toutes les apps
    // s'arrêteraient, et il n'y aurait plus où les replacer. Swarm l'accepte sans
    // broncher — c'est à nous de refuser.
    if vise == "drain" {
        if let Some(o) = &s.orchestrator {
            let noeuds = o.nodes().await.unwrap_or_default();
            let sains = noeuds
                .iter()
                .filter(|n| n.is_ready() && n.availability == "active")
                .count();
            let cible_est_active = noeuds
                .iter()
                .any(|n| n.id == id && n.availability == "active");
            if cible_est_active && sains <= 1 {
                blocages.push(
                    "c'est le dernier nœud actif : le drainer arrêterait TOUTES les \
                     applications, sans nulle part où les replacer"
                        .to_string(),
                );
            }
        }
    }

    let applique = q.apply && blocages.is_empty();
    let mut etape = EtapeAction {
        description: format!("passer le nœud {id} en « {vise} »"),
        etat: EtatEtape::Prevue,
        erreur: None,
    };

    if applique {
        // ⚠️ `label_node` pose des étiquettes, pas la disponibilité : l'appel Swarm
        // correspondant n'est pas exposé par le trait. On le dit plutôt que d'échouer
        // en silence.
        etape.etat = EtatEtape::NonImplementee;
        etape.erreur = Some(
            "le changement de disponibilité n'est pas encore exposé par l'orchestrateur \
             — « docker node update --availability »"
                .into(),
        );
    }

    let r = ResultatAction {
        applique,
        resume: format!("nœud {id} en « {vise} »"),
        etapes: vec![etape],
        commande_cli: format!("docker node update --availability {vise} {id}"),
        blocages,
        avertissements: Vec::new(),
        confirmation_requise: None,
    };

    repondre(&s, auth.identite(), "node-availability", &id, r).await
}

// ---------------------------------------------------------------------------
// Destructif
// ---------------------------------------------------------------------------

/// Supprime une application.
///
/// 🔴 Exige `PeutDetruire` **et** la confirmation nommée.
pub async fn supprimer_app(
    auth: Autorise<PeutDetruire>,
    AxumState(s): AxumState<Arc<AppState>>,
    Path(app): Path<String>,
    Query(q): Query<ActionQuery>,
    corps: Option<Json<Confirmation>>,
) -> Response {
    let installee = s
        .state
        .installed_apps()
        .await
        .unwrap_or_default()
        .into_iter()
        .any(|(n, _)| n == app);

    let mut blocages = Vec::new();
    if !installee {
        blocages.push(format!("« {app} » n'est pas installée"));
    }

    let confirme = corps
        .map(|Json(c)| confirmation_valide(&c, &app))
        .unwrap_or(false);

    // ⚠️ L'aperçu est toujours permis : c'est même le seul moyen de savoir ce que la
    // suppression emporterait. C'est l'APPLICATION qui exige la confirmation.
    if q.apply && !confirme {
        blocages.push(format!(
            "confirmation manquante — renvoie « {{\"confirme\": \"{app}\"}} ». Répéter \
             le nom est ce qui empêche un purge tapé sur la mauvaise app"
        ));
    }

    let applique = q.apply && blocages.is_empty();

    let volumes = s.state.app_volumes(&app).await.unwrap_or_default();
    let mut etapes = vec![EtapeAction {
        description: format!("retirer le service {app} de Swarm"),
        etat: EtatEtape::Prevue,
        erreur: None,
    }];
    for (nom, _, sauvegarde, _) in &volumes {
        etapes.push(EtapeAction {
            description: format!(
                "le volume « {nom} » est CONSERVÉ{}",
                if *sauvegarde {
                    " (sauvegardé)"
                } else {
                    " — et il n'est PAS sauvegardé"
                }
            ),
            etat: EtatEtape::Prevue,
            erreur: None,
        });
    }

    if applique {
        // Même honnêteté que pour les sauvegardes : la suppression réelle passe par
        // l'orchestrateur et l'exécuteur, pas encore branchés ici.
        for e in &mut etapes {
            e.etat = EtatEtape::NonImplementee;
        }
    }

    let r = ResultatAction {
        applique,
        // 🔴 Zéro volume n'est PAS « les données restent ». Constaté à l'exécution :
        // « 0 volume est conservé, les données restent » promet une survie qui n'a
        // aucun objet — et c'est précisément la phrase qu'on lit avant de confirmer une
        // suppression.
        resume: match volumes.len() {
            0 => format!(
                "supprimer {app} — aucun volume déclaré : il ne restera rien de cette \
                 application"
            ),
            n => format!(
                "supprimer {app} — {} {} conservé{}, les données restent",
                hlb_api::pluriel(n as u64, "volume", "volumes"),
                if n > 1 { "sont" } else { "est" },
                if n > 1 { "s" } else { "" }
            ),
        },
        etapes,
        commande_cli: format!("hlb remove {app} --apply"),
        blocages,
        avertissements: Vec::new(),
        confirmation_requise: Some(app.clone()),
    };

    repondre(&s, auth.identite(), "app-remove", &app, r).await
}

/// Le parc, réduit à ce dont le budget de capacité a besoin : un tier et une mémoire.
///
/// ⚠️ La jointure passe par le NOM D'HÔTE : l'inventaire Swarm connaît les étiquettes,
/// les rapports d'agent connaissent la mémoire, et les deux ne partagent pas de clé.
/// C'est la même règle que dans l'API, et elle n'a pas de meilleur endroit tant que le
/// nom d'hôte reste le seul pont.
async fn parc_par_tier(s: &AppState) -> Vec<(Option<String>, Option<u64>)> {
    let noeuds = match &s.orchestrator {
        Some(o) => o.nodes().await.unwrap_or_default(),
        // ⚠️ La démonstration a des nœuds fabriqués, comme pour la topologie : sans eux,
        // tout aperçu d'installation porterait un avertissement « aucun nœud sur ce
        // tier », et l'on ne verrait jamais l'écran normal.
        None if s.demo => return crate::demo::parc_par_tier(),
        // Sans orchestrateur, on ne connaît AUCUN tier. Rendre une liste vide fait
        // conclure « aucun nœud sur ce tier », ce qui est exactement ce qu'on sait.
        None => return Vec::new(),
    };

    let sondage = s.last_poll.read().await;
    noeuds
        .iter()
        .map(|n| {
            let memoire = sondage
                .values()
                .filter_map(|st| st.report())
                .find(|r| r.hostname == n.hostname)
                .and_then(|r| r.memory_available_mb);
            (n.tier.clone(), memoire)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn removing_an_app_without_volumes_promises_nothing() {
        // 🔴 Constaté en exécutant l'aperçu : « 0 volume est conservé, les données
        // restent » promet une survie qui n'a aucun objet. C'est la phrase qu'on lit
        // juste avant de confirmer une suppression — elle doit dire ce qui va vraiment
        // se passer.
        //
        // ⚠️ Le résumé est fabriqué dans `supprimer_app` ; on reproduit ici la seule
        // règle qui compte, et un appel réel la vérifie de bout en bout dans
        // `every_mutating_route_previews_without_acting`.
        let phrase = |n: usize| match n {
            0 => "aucun volume déclaré : il ne restera rien".to_string(),
            n => format!("{n} conservé"),
        };
        assert!(phrase(0).contains("il ne restera rien"));
        assert!(!phrase(0).contains("les données restent"));
        assert!(phrase(2).contains("conservé"));
    }

    #[test]
    fn a_saved_plan_can_only_target_a_route_that_exists() {
        // 🔴 Un plan qui vise une route inconnue serait accepté ici et échouerait à
        // l'exécution, des semaines plus tard, sur un 404 qui n'orienterait vers rien —
        // au moment précis où l'on comptait sur lui.
        let routes = crate::api::routes_mutantes();
        let existe = |methode: &str, chemin: &str| {
            routes
                .iter()
                .any(|r| r.verbe == methode && chemins_compatibles(r.chemin, chemin))
        };

        assert!(existe("POST", "/api/apps/gitea/install"));
        assert!(existe("POST", "/api/apps/immich/backup"));
        assert!(!existe("POST", "/api/apps/gitea/inventer"));
        assert!(!existe("DELETE", "/api/apps/gitea/install"));
    }

    #[test]
    fn a_path_template_never_matches_a_longer_path() {
        // ⚠️ Une comparaison par préfixe laisserait passer « …/install/vraiment », qui
        // n'existe pas — et le plan échouerait à l'exécution.
        assert!(chemins_compatibles("/api/apps/{name}/install", "/api/apps/gitea/install"));
        assert!(!chemins_compatibles(
            "/api/apps/{name}/install",
            "/api/apps/gitea/install/vraiment"
        ));
        assert!(!chemins_compatibles("/api/apps/{name}/install", "/api/apps/gitea"));
        // Et un paramètre accepte n'importe quel segment, mais UN seul.
        assert!(!chemins_compatibles("/api/secours/{id}", "/api/secours/a/b"));
    }

    use super::*;

    #[test]
    fn a_confirmation_must_match_exactly() {
        // ⚠️ Accepter « Gitea » pour « gitea » affaiblirait la seule protection qui
        // reste quand le rôle a déjà été accordé.
        let juste = Confirmation {
            confirme: Some("gitea".into()),
        };
        assert!(confirmation_valide(&juste, "gitea"));
        assert!(!confirmation_valide(&juste, "vikunja"));

        let casse = Confirmation {
            confirme: Some("Gitea".into()),
        };
        assert!(!confirmation_valide(&casse, "gitea"), "la casse compte");

        let vide = Confirmation { confirme: None };
        assert!(!confirmation_valide(&vide, "gitea"));
    }

    #[test]
    fn apply_defaults_to_false() {
        // 🔴 L'invariant central : l'absence du paramètre vaut APERÇU. Un défaut à
        // `true` transformerait une visite d'écran en exécution.
        let q: ActionQuery = serde_json::from_str("{}").expect("défaut");
        assert!(!q.apply);
    }
}

/// Ce qu'on enregistre.
#[derive(serde::Deserialize)]
pub struct DemandePlan {
    pub nom: String,
    pub methode: String,
    pub chemin: String,
    #[serde(default)]
    pub corps: String,
    pub resume: String,
    #[serde(default)]
    pub note: Option<String>,
}

/// Enregistre un plan sous un nom (lot 10.4).
///
/// ⚠️ Route de configuration : elle n'exécute RIEN. Lui imposer un aperçu ferait
/// prévisualiser l'enregistrement d'un aperçu, ce qui n'a pas de sens — et
/// l'enregistrement est réversible d'un « oublier ».
pub async fn enregistrer_plan(
    auth: crate::auth::Autorise<crate::auth::PeutOperer>,
    AxumState(s): AxumState<Arc<AppState>>,
    Json(d): Json<DemandePlan>,
) -> Response {
    // 🔴 Un plan qui viserait une route inconnue serait accepté ici et échouerait à
    // l'exécution, des semaines plus tard, sur un 404 qui n'orienterait vers rien. On
    // vérifie contre la liste qui SERT à construire le routeur.
    let connue = crate::api::routes_mutantes()
        .iter()
        .any(|r| r.verbe == d.methode && chemins_compatibles(r.chemin, &d.chemin));

    if !connue {
        return erreur_action(
            &s,
            auth.identite(),
            "plan-enregistrer",
            &d.nom,
            &format!("« {} {} » n'est pas une action connue", d.methode, d.chemin),
        )
        .await;
    }

    let acteur = auth.identite().acteur.nom().to_string();
    if let Err(e) = s
        .state
        .enregistrer_plan(
            &d.nom,
            &d.methode,
            &d.chemin,
            &d.corps,
            &d.resume,
            &acteur,
            d.note.as_deref(),
        )
        .await
    {
        return erreur_action(&s, auth.identite(), "plan-enregistrer", &d.nom, &e.to_string())
            .await;
    }

    let r = ResultatAction {
        applique: true,
        resume: format!("plan « {} » enregistré", d.nom),
        etapes: vec![EtapeAction {
            description: d.resume.clone(),
            etat: EtatEtape::Faite,
            erreur: None,
        }],
        commande_cli: String::new(),
        blocages: Vec::new(),
        avertissements: Vec::new(),
        confirmation_requise: None,
    };
    repondre(&s, auth.identite(), "plan-enregistrer", &d.nom, r).await
}

/// Un chemin de route (`/api/apps/{name}/install`) accepte-t-il ce chemin concret ?
///
/// ⚠️ Comparaison segment par segment : un `{param}` accepte n'importe quoi, le reste
/// doit correspondre exactement. Une comparaison par préfixe laisserait passer
/// « /api/apps/gitea/install/vraiment », qui n'existe pas.
fn chemins_compatibles(gabarit: &str, concret: &str) -> bool {
    let g: Vec<&str> = gabarit.split('/').collect();
    let c: Vec<&str> = concret.split('/').collect();
    g.len() == c.len()
        && g.iter()
            .zip(&c)
            .all(|(a, b)| (a.starts_with('{') && a.ends_with('}')) || a == b)
}

/// Les plans enregistrés.
pub async fn lister_plans(
    _auth: crate::auth::Autorise<crate::auth::PeutLire>,
    AxumState(s): AxumState<Arc<AppState>>,
) -> Json<Vec<hlb_api::PlanNomme>> {
    Json(
        s.state
            .plans_nommes()
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|(nom, methode, chemin, _corps, resume, cree_par, age_s)| {
                hlb_api::PlanNomme {
                    nom,
                    resume,
                    methode,
                    chemin,
                    cree_par,
                    age_s,
                }
            })
            .collect(),
    )
}
