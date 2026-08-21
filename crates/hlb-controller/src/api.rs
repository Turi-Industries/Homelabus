//! L'API HTTP du controller (§11bis).
//!
//! ## Ce qui a remplacé « lecture seule »
//!
//! Ce module a longtemps interdit tout verbe mutant, et un test le vérifiait. C'était
//! la bonne règle pour la phase 2.5 : une UI qui n'agit pas ne peut rien casser.
//!
//! Elle ne l'est plus, parce que l'interface doit maintenant installer, sauvegarder,
//! restaurer et gérer des comptes. Trois règles la remplacent, et **elles protègent
//! davantage** que l'interdiction qu'elles lèvent :
//!
//! 1. **Aperçu par défaut.** Une route d'action rend le plan et ne fait rien ; elle
//!    n'agit qu'avec `?apply=true`. C'est la transposition exacte de
//!    `Executor::apply(true)` — le CLI et l'API se comportent pareil.
//! 2. **Autorisation dans la signature.** Toute route mutante prend un
//!    [`Autorise<…>`](crate::auth::Autorise), donc le contrôle ne peut pas être oublié.
//! 3. **Journal d'audit.** Toute route mutante consigne qui, quoi, quand et l'issue.
//!
//! Chacune est verrouillée par un test qui parcourt le routeur : ajouter une route
//! mutante sans respecter les trois fait échouer la suite.

use std::sync::Arc;

use axum::extract::{Path, State as AxumState};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use hlb_api::{AppSummary, AuditItem, GuideItem, Health, SecretItem};

use hlb_state::State;

use crate::auth::{Autorise, PeutAgirSurSoi, PeutGererComptes, PeutLire, PeutOperer};

use crate::agents::AgentStatus;
use crate::metrics::{self, AppMetrics};

/// Dernier tour d'interrogation des agents, partagé entre la boucle et l'API.
///
/// La boucle écrit, l'API lit. Un `RwLock` plutôt qu'un `Mutex` parce que plusieurs
/// requêtes `/metrics` concurrentes ne doivent pas se sérialiser derrière un tour de
/// sondage.
pub type LastPoll = Arc<tokio::sync::RwLock<std::collections::BTreeMap<String, AgentStatus>>>;

pub struct AppState {
    pub state: Arc<State>,
    pub started_at: std::time::Instant,
    pub version: &'static str,
    pub last_poll: LastPoll,
    /// Répertoire de l'UI web. `None` = API seule.
    pub ui_dir: Option<std::path::PathBuf>,
    /// 🔴 `true` = API ouverte, sans authentification.
    ///
    /// N'existe que parce qu'un déploiement existant ne doit pas casser d'un coup.
    /// Le controller refuse de démarrer dans cet état sans `--insecure-no-auth`
    /// explicite : ouvert doit être une DÉCISION, jamais un défaut.
    pub no_auth: bool,
    /// La connexion par PocketID. `None` = pas configurée : seuls les jetons d'API
    /// authentifient, et `/auth/connexion` répond `503` **en disant comment
    /// l'activer** plutôt qu'un 404 qui laisserait croire à un bug.
    pub connexion: Option<Arc<crate::connexion::Connexion>>,
    /// Limitation de débit. Voir `crate::debit` pour ce qu'elle protège.
    pub debit: Arc<crate::debit::Limiteur>,
    /// Le provisionnement des comptes : identité et boîte.
    ///
    /// 🔴 Sans eux, l'inscription crée un compte en base et RIEN d'autre — état
    /// `Vide`, que l'écran de gestion montre en rouge et qu'une relance répare. C'est
    /// honnête, mais ce n'est pas du libre-service : quelqu'un doit finir à la main.
    pub identite: Option<Arc<hlb_identity::PocketId>>,
    pub mail: Option<Arc<hlb_mail::Stalwart>>,
    /// Le domaine des adresses créées.
    pub domaine_mail: String,
    /// Le catalogue d'applications. `None` = répertoire absent ou illisible ; les
    /// écrans le disent plutôt que d'afficher une liste vide.
    pub catalogue: Option<Arc<hlb_catalog::Catalog>>,
    /// 🔴 La page de statut est-elle publique ?
    ///
    /// `false` par défaut : une page de statut publique révèle la liste de ce qui
    /// tourne chez vous et le calendrier de vos pannes. C'est un choix qui se décide,
    /// pas un défaut qu'on découvre.
    pub statut_public: bool,
    /// Mode démonstration : certaines vues sont fabriquées faute d'orchestrateur.
    pub demo: bool,
    /// L'orchestrateur, pour lire les tâches Swarm. `None` = Docker injoignable, ou
    /// mode démonstration : les écrans le disent plutôt que d'afficher une liste vide
    /// qu'on prendrait pour « aucune tâche ne tourne ».
    pub orchestrator: Option<Arc<dyn hlb_orchestrator::Orchestrator>>,
    /// L'état courant des alertes, écrit par `AlerteLoop`.
    ///
    /// Même motif que `last_poll` : la boucle écrit, l'API lit.
    pub alertes: crate::loops::EtatAlertes,
    /// Les écarts du dernier tour de réconciliation, écrits par `ReconcileLoop`.
    pub ecarts: crate::loops::EtatEcarts,
    /// Le fichier de battement du deadman, quand il est configuré (§8bis).
    ///
    /// ⚠️ Sert à la liste de contrôle, qui doit distinguer « pas de deadman » de
    /// « deadman silencieux » — le second est une alerte, le premier une absence.
    pub battement: Option<std::path::PathBuf>,
    /// Le miroir Git, quand il est configuré : le seul endroit qui garde l'historique
    /// des manifests (§9.11).
    pub miroir: Option<std::path::PathBuf>,
    /// L'URL publique du controller, telle qu'un client extérieur la voit.
    ///
    /// ⚠️ `None` = inconnue. L'assistant Bitwarden le DIT plutôt que de coller
    /// « http://127.0.0.1:8420 » dans un champ que Bitwarden appellera depuis le
    /// téléphone, où cette adresse ne désigne pas la même machine.
    pub url_publique: Option<String>,
    /// La base de séries temporelles. `None` = pas déployée : les graphes affichent
    /// « indisponible » **en disant comment l'installer**, plutôt qu'une courbe plate.
    pub series: Option<Arc<crate::promql::Metriques>>,
    /// 🔴 `true` = croire `X-Forwarded-For`.
    ///
    /// À ne poser QUE si un proxy de confiance est réellement devant : sinon chaque
    /// attaquant se donne un compteur neuf à chaque requête, et la limitation ne
    /// limite plus rien tout en donnant l'impression du contraire.
    pub confiance_proxy: bool,
}

/// Les types MIME dont le navigateur a besoin.
///
/// 🔴 `application/wasm` n'est pas décoratif : `WebAssembly.instantiateStreaming`
/// **refuse** un flux servi en `application/octet-stream`, et le message d'erreur
/// parle de « incorrect response MIME type » sans dire lequel il attendait. C'est
/// l'échec le plus courant quand on sert une UI wasm depuis son propre serveur.
fn mime_de(fichier: &str) -> &'static str {
    match fichier.rsplit('.').next() {
        Some("wasm") => "application/wasm",
        Some("js") => "text/javascript",
        Some("html") => "text/html; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("json") => "application/json",
        // ⚠️ Le manifeste d'application web a son propre type. Servi en
        // `application/json`, Chrome l'accepte mais Safari REFUSE d'installer la page,
        // sans message : l'entrée « Ajouter à l'écran d'accueil » manque simplement.
        Some("webmanifest") => "application/manifest+json",
        // Idem pour l'icône : un SVG servi en octet-stream n'est pas affiché du tout.
        Some("svg") => "image/svg+xml",
        _ => "application/octet-stream",
    }
}

/// Un nom de fichier sûr ?
///
/// 🔴 Sans ce contrôle, `GET /../../etc/shadow` sort du répertoire de l'UI. Le
/// serveur tourne souvent en root sur un nœud de cluster : l'enjeu n'est pas
/// théorique.
fn nom_sur(fichier: &str) -> bool {
    !fichier.is_empty()
        && !fichier.contains("..")
        && !fichier.starts_with('/')
        && !fichier.contains('\\')
        // Un octet nul tronque le chemin côté système de fichiers.
        && !fichier.contains('\0')
}

async fn ui_index(AxumState(s): AxumState<Arc<AppState>>) -> Response {
    servir(&s, "index.html").await
}

async fn ui_fichier(
    AxumState(s): AxumState<Arc<AppState>>,
    Path(fichier): Path<String>,
) -> Response {
    servir(&s, &fichier).await
}

async fn servir(s: &AppState, fichier: &str) -> Response {
    let Some(dir) = &s.ui_dir else {
        return (
            StatusCode::NOT_FOUND,
            "UI web non déployée — lance le controller avec --ui-dir\n",
        )
            .into_response();
    };

    if !nom_sur(fichier) {
        return (StatusCode::BAD_REQUEST, "nom de fichier refusé\n").into_response();
    }

    match tokio::fs::read(dir.join(fichier)).await {
        Ok(octets) => (
            [(axum::http::header::CONTENT_TYPE, mime_de(fichier))],
            octets,
        )
            .into_response(),
        Err(_) => (StatusCode::NOT_FOUND, "fichier absent\n").into_response(),
    }
}

/// Les nœuds du cluster.
///
/// 🔴 Un nœud injoignable **apparaît quand même**, marqué comme tel. Le filtrer
/// donnerait une liste de nœuds sains, et la machine dont on ne sait rien serait
/// exactement celle qu'on ne verrait pas.
async fn noeuds(
    _auth: Autorise<PeutLire>,
    AxumState(s): AxumState<Arc<AppState>>,
) -> Json<Vec<hlb_api::NoeudSummary>> {
    Json(noeuds_summary(&s).await)
}

/// L'inventaire des nœuds, tel que l'API le présente.
///
/// Extrait du gestionnaire parce que la chaîne causale en a besoin elle aussi : elle
/// remonte d'une tâche en échec vers le nœud qui la portait. Deux assemblages
/// divergents du même nœud finiraient par donner deux diagnostics différents.
pub(crate) async fn noeuds_summary(s: &AppState) -> Vec<hlb_api::NoeudSummary> {
    let maintenant = crate::auth::maintenant();
    let sondage = s.last_poll.read().await;
    let seuils = hlb_agent::disk::Thresholds::default();

    // Les tâches, pour dire ce que chaque nœud héberge. Un échec ici ne doit pas
    // priver de la liste des nœuds : on affiche les nœuds sans leurs tâches.
    let taches = match &s.orchestrator {
        Some(o) => o.tasks(None).await.unwrap_or_default(),
        None => Vec::new(),
    };

    let mut out = Vec::new();
    for (adresse, statut) in sondage.iter() {
        let r = statut.report();

        // ⚠️ Le nom d'hôte du rapport ne sert qu'à l'affichage ; l'ADRESSE est
        // l'identité (voir `NoeudSummary::adresse`).
        let hostname = r.map(|r| r.hostname.clone());
        let sur_ce_noeud: Vec<String> = taches
            .iter()
            .filter(|t| t.est_vivante())
            .filter(|t| {
                t.node_id
                    .as_deref()
                    .is_some_and(|n| hostname.as_deref().is_some_and(|h| n == h) || n == adresse)
            })
            .map(|t| t.service.clone())
            .collect();

        out.push(hlb_api::NoeudSummary {
            adresse: adresse.clone(),
            hostname,
            joignable: r.is_some(),
            detail: match statut {
                crate::agents::AgentStatus::Unreachable { detail } => Some(detail.clone()),
                crate::agents::AgentStatus::Reporting(_) => None,
            },
            rapport_age_s: r.map(|r| maintenant.saturating_sub(r.at as i64)),
            cpu_occupation: r.and_then(|r| r.cpu_occupation),
            charge_par_coeur: r.and_then(|r| r.charge_par_coeur()),
            memoire_utilisee: r.and_then(|r| r.memoire_utilisee()),
            swap_utilise: r.and_then(|r| match (r.swap_total_mb, r.swap_utilise_mb) {
                (Some(t), Some(u)) if t > 0 => Some(u as f64 / t as f64),
                _ => None,
            }),
            disques: r
                .map(|r| {
                    r.disks
                        .iter()
                        .map(|d| hlb_api::DisqueSummary {
                            chemin: d.path.clone(),
                            utilise: d.used_percent() / 100.0,
                            total_mb: d.total_mb,
                            libre_mb: d.free_mb,
                            pression: crate::metrics::palier_public(d.pressure(&seuils)),
                        })
                        .collect()
                })
                .unwrap_or_default(),
            uptime_s: r.and_then(|r| r.systeme.as_ref()).and_then(|y| y.uptime_s),
            distro: r
                .and_then(|r| r.systeme.as_ref())
                .and_then(|y| y.distro.clone()),
            noyau: r
                .and_then(|r| r.systeme.as_ref())
                .and_then(|y| y.noyau.clone()),
            agent_version: r.map(|r| r.agent_version.clone()),
            protocole: r.map(|r| r.protocol),
            taches: sur_ce_noeud,
        });
    }

    // Les nœuds qui demandent de l'attention en premier : sur dix machines, celle qui
    // ne répond pas se perdrait au milieu d'un tri alphabétique.
    out.sort_by(|a, b| {
        b.attention()
            .cmp(&a.attention())
            .then_with(|| a.adresse.cmp(&b.adresse))
    });
    out
}

/// La topologie du cluster, groupée par domaine de panne.
///
/// 🔴 L'écran qui justifie à lui seul l'existence de l'interface (§11bis) : en ligne de
/// commande on voit trois nœuds et on se croit protégé ; ici on voit que deux d'entre
/// eux sont deux VM sur le même fer.
async fn topologie(
    _auth: Autorise<PeutLire>,
    AxumState(s): AxumState<Arc<AppState>>,
) -> Json<hlb_api::Topologie> {
    let Some(o) = &s.orchestrator else {
        // En démonstration, une topologie fabriquée : sans elle, l'écran qui justifie
        // l'existence de l'interface serait vide et impossible à écrire.
        if s.demo {
            return Json(crate::demo::topologie());
        }
        // ⚠️ Sinon, on ne rend pas une topologie vide — qui se lirait « aucun nœud »,
        // soit un cluster détruit. Le cas est distingué par `noeuds_total: 0`, et
        // l'écran le dit.
        return Json(hlb_api::Topologie {
            domaines: Vec::new(),
            violations: Vec::new(),
            managers: Vec::new(),
            noeuds_total: 0,
        });
    };

    let noeuds = o.nodes().await.unwrap_or_default();
    let taches = o.tasks(None).await.unwrap_or_default();

    // Seuls les réplicas VIVANTS comptent pour l'anti-affinité : une tâche morte ne
    // partage plus rien, et l'inclure ferait remonter des violations résolues.
    let placements: Vec<(String, String)> = taches
        .iter()
        .filter(|t| t.est_vivante())
        .filter_map(|t| t.node_id.clone().map(|n| (t.service.clone(), n)))
        .collect();

    let violations = hlb_orchestrator::cluster::violations_anti_affinite(&placements, &noeuds);
    let groupes = hlb_orchestrator::cluster::grouper_par_domaine(&noeuds);
    let total = noeuds.len();

    Json(hlb_api::Topologie {
        // Ce que le simulateur de panne a besoin de savoir pour juger du quorum.
        managers: noeuds
            .iter()
            .filter(|n| n.role == hlb_orchestrator::cluster::NodeRole::Manager)
            .map(|n| n.id.clone())
            .collect(),
        domaines: groupes
            .iter()
            .map(|g| hlb_api::DomaineSummary {
                concentre: g.concentre(total),
                nom: g.nom.clone(),
                noeuds: g
                    .noeuds
                    .iter()
                    .filter_map(|id| noeuds.iter().find(|n| &n.id == id))
                    .map(|n| hlb_api::NoeudDansDomaine {
                        services: placements
                            .iter()
                            .filter(|(_, noeud)| noeud == &n.id)
                            .map(|(svc, _)| svc.clone())
                            .collect(),
                        id: n.id.clone(),
                        hostname: n.hostname.clone(),
                        tier: n.tier.clone(),
                        joignable: n.is_ready(),
                    })
                    .collect(),
            })
            .collect(),
        violations: violations
            .iter()
            .map(|v| hlb_api::ViolationSummary {
                totale: v.totale(),
                explication: v.describe(),
                service: v.service.clone(),
                domaine: v.domaine.clone(),
                replicas: v.replicas,
                total: v.total,
            })
            .collect(),
        noeuds_total: total,
    })
}

/// Les tâches Swarm, avec leur placement et leur erreur.
async fn taches(
    _auth: Autorise<PeutLire>,
    AxumState(s): AxumState<Arc<AppState>>,
) -> Json<Vec<hlb_api::TacheSummary>> {
    let Some(o) = &s.orchestrator else {
        return Json(Vec::new());
    };

    let brutes = o.tasks(None).await.unwrap_or_default();
    Json(
        brutes
            .into_iter()
            .map(|t| hlb_api::TacheSummary {
                vivante: t.est_vivante(),
                echouee: t.a_echoue(),
                explication: t.explication().map(str::to_string),
                id: t.id,
                service: t.service,
                slot: t.slot,
                noeud: t.node_id,
                etat: t.state,
                etat_voulu: t.desired_state,
                image: Some(t.image).filter(|i| !i.is_empty()),
            })
            .collect(),
    )
}

/// L'historique des sauvegardes.
async fn sauvegardes(
    _auth: Autorise<PeutLire>,
    AxumState(s): AxumState<Arc<AppState>>,
) -> ApiResult<Vec<hlb_api::SauvegardeRun>> {
    Ok(Json(
        s.state
            .backup_history_all(200)
            .await?
            .into_iter()
            .map(|r| hlb_api::SauvegardeRun {
                app: r.app,
                kind: r.kind,
                destination: r.destination,
                reussie: r.status == "ok",
                erreur: r.error,
                quand: r.finished_at,
            })
            .collect(),
    ))
}

/// La couverture réelle des sauvegardes, app par app.
async fn couverture(
    _auth: Autorise<PeutLire>,
    AxumState(s): AxumState<Arc<AppState>>,
) -> Json<Vec<hlb_api::CouvertureSummary>> {
    let mut out: Vec<hlb_api::CouvertureSummary> =
        crate::couverture::toutes(&s.state, SEUIL_PEREMPTION_S)
            .await
            .into_iter()
            .map(|c| hlb_api::CouvertureSummary {
                copies_a_jour: c.copies_a_jour(),
                par_destination: c
                    .par_destination
                    .iter()
                    .map(|(nom, etat)| {
                        let age = match etat {
                            // 🔴 `None` = jamais servie, ce qui n'est PAS « il y a très
                            // longtemps ». Le type conserve la distinction.
                            hlb_backup::EtatDestination::Jamais => None,
                            hlb_backup::EtatDestination::Frais { age_s }
                            | hlb_backup::EtatDestination::Perime { age_s } => Some(*age_s),
                        };
                        (nom.clone(), age)
                    })
                    .collect(),
                app: c.app,
            })
            .collect();

    out.sort_by(|a, b| {
        b.attention()
            .cmp(&a.attention())
            .then_with(|| a.app.cmp(&b.app))
    });
    Json(out)
}

/// Les versions successives du manifest d'une app, avec leur diff (lot 9.11).
async fn manifest_versions(
    _auth: Autorise<PeutLire>,
    AxumState(s): AxumState<Arc<AppState>>,
    Path(name): Path<String>,
) -> Json<Vec<hlb_api::VersionManifest>> {
    // ⚠️ Sans miroir Git, il n'y a PAS d'historique — et une liste vide le dit
    // correctement : l'état ne garde que la version courante, il n'y a rien à
    // reconstituer. L'écran affiche alors comment activer le miroir.
    let Some(chemin) = &s.miroir else {
        return Json(Vec::new());
    };
    match hlb_gitops::GitMirror::open_or_init(chemin) {
        Ok(m) => Json(crate::diff::versions(&m, &name, 20)),
        Err(_) => Json(Vec::new()),
    }
}

/// La frise chronologique unifiée (lot 9.5).
async fn frise(
    _auth: Autorise<PeutLire>,
    AxumState(s): AxumState<Arc<AppState>>,
) -> Json<Vec<hlb_api::Evenement>> {
    Json(crate::frise::evenements(&s.state, 200).await)
}

/// Un export CSV d'une vue tabulaire (lot 11.5).
///
/// ⚠️ Le journal et les comptes exigent plus que `Lire` : le premier dit qui a fait
/// quoi, le second qui existe. Ce sont les deux tableaux qu'on ne met pas entre toutes
/// les mains, même sans valeur de secret.
async fn export_csv(
    auth: Autorise<PeutLire>,
    AxumState(s): AxumState<Arc<AppState>>,
    Path(quoi): Path<String>,
) -> axum::response::Response {
    use axum::response::IntoResponse as _;

    let (csv, nom) = match quoi.as_str() {
        "audit" => {
            if let Some(refus) = auth
                .identite()
                .role
                .refus(hlb_types::rbac::Action::ManageAccounts)
            {
                return (StatusCode::FORBIDDEN, refus).into_response();
            }
            (
                crate::export::audit(&s.state.audit_trail(5_000).await.unwrap_or_default()),
                "journal.csv",
            )
        }
        "sauvegardes" => (
            crate::export::sauvegardes(
                &s.state.backup_history_all(5_000).await.unwrap_or_default(),
            ),
            "sauvegardes.csv",
        ),
        "comptes" => {
            if let Some(refus) = auth
                .identite()
                .role
                .refus(hlb_types::rbac::Action::ManageAccounts)
            {
                return (StatusCode::FORBIDDEN, refus).into_response();
            }
            (
                crate::export::comptes(&crate::comptes::resumes(&s).await),
                "comptes.csv",
            )
        }
        // 🔴 Une vue inconnue rend 404, jamais un fichier vide : un CSV vide se lit
        // « il n'y avait rien », ce qui est faux et indétectable.
        _ => {
            return (
                StatusCode::NOT_FOUND,
                format!("« {quoi} » n'est pas une vue exportable"),
            )
                .into_response()
        }
    };

    (
        [
            (
                axum::http::header::CONTENT_TYPE,
                "text/csv; charset=utf-8".to_string(),
            ),
            (
                axum::http::header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{nom}\""),
            ),
        ],
        csv,
    )
        .into_response()
}

/// Le runbook, en Markdown, généré depuis l'état réel (lot 10.3).
///
/// 🔴 Exige `PeutGererComptes` : le document décrit l'inventaire complet de
/// l'installation et la procédure de reprise. Il ne porte aucun secret, mais c'est une
/// carte.
async fn runbook(
    _auth: Autorise<PeutGererComptes>,
    AxumState(s): AxumState<Arc<AppState>>,
) -> impl axum::response::IntoResponse {
    let noeuds = noeuds_summary(&s).await;
    let texte = crate::runbook::engendrer(&s.state, &noeuds, crate::auth::maintenant()).await;
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/markdown; charset=utf-8",
        )],
        texte,
    )
}

/// Les garde-fous d'accès de secours (lot 10.2).
async fn breakglass(
    _auth: Autorise<PeutGererComptes>,
    AxumState(s): AxumState<Arc<AppState>>,
) -> Json<Vec<hlb_api::breakglass::GardeFou>> {
    Json(crate::secours::etat(&s.state).await)
}

/// Les secrets et ce que leur rotation impliquerait (lot 10.1).
///
/// 🔴 Exige `PeutGererComptes` et non `PeutLire` : la liste des secrets décrit à quoi
/// l'installation est câblée. Elle ne porte aucune valeur — mais savoir qu'il existe un
/// « gitea-db-password » est déjà une carte.
async fn rotation_secrets(
    _auth: Autorise<PeutGererComptes>,
    AxumState(s): AxumState<Arc<AppState>>,
) -> Json<Vec<hlb_api::rotation::SecretARouler>> {
    let secrets = s.state.secrets_ages().await.unwrap_or_default();
    Json(
        secrets
            .into_iter()
            .map(
                |(nom, usage, age_s, jamais_tourne)| hlb_api::rotation::SecretARouler {
                    nature: hlb_api::rotation::Nature::deduire(&nom, &usage),
                    app: hlb_api::rotation::app_de(&nom),
                    nom,
                    usage,
                    age_s,
                    jamais_tourne,
                },
            )
            .collect(),
    )
}

/// La liste de contrôle de l'installation (lot 9.7).
async fn sante_installation(
    _auth: Autorise<PeutLire>,
    AxumState(s): AxumState<Arc<AppState>>,
) -> Json<Vec<hlb_api::ControleSante>> {
    Json(crate::sante::controles(&s.state, s.battement.as_deref(), crate::auth::maintenant()).await)
}

/// Ce que chaque app déclare, et ce qui est réellement publié (lot 9.10).
async fn exposition(
    _auth: Autorise<PeutLire>,
    AxumState(s): AxumState<Arc<AppState>>,
) -> Json<Vec<hlb_api::ExpositionSummary>> {
    let mut out = crate::exposition::tout(&s.state).await;
    // 🔴 Les routes orphelines EN TÊTE : une app retirée dont la route répond encore
    // n'apparaît dans aucun manifest, donc dans aucun parcours des apps installées.
    // C'est exactement celle qu'on ne voit jamais.
    let mut orphelines = crate::exposition::orphelines(&s.state).await;
    orphelines.append(&mut out);
    Json(orphelines)
}

/// Les écarts entre ce qui devrait tourner et ce qui tourne (lot 9.8).
async fn ecarts(
    _auth: Autorise<PeutLire>,
    AxumState(s): AxumState<Arc<AppState>>,
) -> Json<Vec<hlb_api::EcartSummary>> {
    Json(s.ecarts.read().await.clone())
}

/// Les alertes actives.
///
/// 🔴 Inclut celles en **sourdine** : elles restent visibles, marquées, avec leur
/// échéance. Les filtrer ici donnerait un tableau de bord vert pour un problème connu
/// et non résolu.
async fn alertes(
    _auth: Autorise<PeutLire>,
    AxumState(s): AxumState<Arc<AppState>>,
) -> Json<Vec<hlb_api::AlerteActive>> {
    Json(s.alertes.read().await.clone())
}

/// Une série temporelle, relayée vers VictoriaMetrics.
///
/// 🔴 Rend **toujours** `200` avec une [`hlb_api::Serie`], même en cas de problème :
/// une base de séries injoignable n'est pas une panne du controller, c'est une
/// information à afficher. Rendre `503` obligerait chaque écran à traiter deux formes
/// d'échec — et la seconde finirait par afficher une courbe vide.
async fn serie(
    _auth: Autorise<PeutLire>,
    AxumState(s): AxumState<Arc<AppState>>,
    axum::extract::Query(q): axum::extract::Query<SerieQuery>,
) -> Json<hlb_api::Serie> {
    let Some(m) = &s.series else {
        return Json(hlb_api::Serie::Indisponible {
            raison: "aucune base de séries configurée. Lance le controller avec \
                     --metrics-url, après « hlb install victoriametrics --apply »"
                .into(),
        });
    };

    let unite = match q.unite.as_deref() {
        Some("octets") => hlb_api::Unite::Octets,
        Some("octets_par_seconde") => hlb_api::Unite::OctetsParSeconde,
        Some("secondes") => hlb_api::Unite::Secondes,
        Some("nombre") => hlb_api::Unite::Nombre,
        // Le ratio par défaut : c'est la forme de la plupart de nos métriques, et se
        // tromper d'unité affiche « 0,42 » au lieu de « 42 % » — lisible, mais faux.
        _ => hlb_api::Unite::Ratio,
    };

    Json(
        m.plage(
            &q.q,
            q.depuis.unwrap_or(3_600),
            q.pas.unwrap_or(60),
            unite,
            crate::auth::maintenant(),
        )
        .await,
    )
}

#[derive(serde::Deserialize)]
struct SerieQuery {
    q: String,
    /// Profondeur en secondes. Défaut : une heure.
    depuis: Option<i64>,
    /// Pas d'échantillonnage en secondes. Défaut : une minute.
    pas: Option<i64>,
    unite: Option<String>,
}

/// L'identité visuelle de l'installation.
///
/// 🔴 **Sans authentification, délibérément.** L'écran de connexion doit porter le nom
/// et les couleurs de la maison : c'est ce qui distingue une page légitime d'une page
/// d'hameçonnage. Exiger un jeton pour la lire rendrait l'écran de connexion anonyme,
/// donc exactement celui qu'un attaquant sait imiter.
///
/// Ce qui fuite est le nom de la maison et une couleur — ce qui est affiché à quiconque
/// ouvre la page de toute façon. Aucune donnée d'exploitation ne passe par ici.
async fn apparence(AxumState(s): AxumState<Arc<AppState>>) -> ApiResult<hlb_api::Marque> {
    Ok(Json(s.state.marque().await?))
}

/// Le logo, en PNG.
async fn apparence_logo(AxumState(s): AxumState<Arc<AppState>>) -> Response {
    match s.state.logo().await {
        Ok(Some(png)) => (
            [
                (axum::http::header::CONTENT_TYPE, "image/png"),
                // Une heure : assez pour ne pas le retélécharger à chaque écran, assez
                // peu pour qu'un changement de logo se voie le jour même.
                (axum::http::header::CACHE_CONTROL, "public, max-age=3600"),
            ],
            png,
        )
            .into_response(),
        // 404 plutôt qu'une image vide : l'interface peint alors son monogramme, au
        // lieu d'afficher un rectangle transparent qu'on prendrait pour un bug.
        Ok(None) => (StatusCode::NOT_FOUND, "aucun logo\n").into_response(),
        Err(e) => ApiError(e.to_string()).into_response(),
    }
}

/// Change l'identité visuelle.
async fn changer_apparence(
    auth: Autorise<PeutOperer>,
    AxumState(s): AxumState<Arc<AppState>>,
    Json(m): Json<hlb_api::Marque>,
) -> Response {
    if m.nom.trim().is_empty() || m.produit.trim().is_empty() {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({
                "error": "le nom de la maison et celui du produit ne peuvent pas être vides — \
                          l'en-tête deviendrait un espace blanc qu'on prendrait pour un défaut \
                          de chargement"
            })),
        )
            .into_response();
    }

    if let Err(e) = s.state.set_marque(&m).await {
        return ApiError(e.to_string()).into_response();
    }

    let _ = s
        .state
        .audit(
            auth.acteur().nom(),
            auth.identite().role,
            "apparence",
            &m.nom,
            "ok",
            Some(&format!("marque « {} · {} »", m.produit, m.nom)),
        )
        .await;

    (StatusCode::OK, Json(m)).into_response()
}

/// Téléverse un logo PNG.
async fn televerser_logo(
    auth: Autorise<PeutOperer>,
    AxumState(s): AxumState<Arc<AppState>>,
    corps: axum::body::Bytes,
) -> Response {
    /// 256 Ko. Un logo d'interface tient très largement dedans, et la limite évite
    /// qu'un téléversement fasse grossir la base — qui part dans les sauvegardes.
    const MAX: usize = 256 * 1024;

    if corps.len() > MAX {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            format!(
                "logo trop lourd ({} Ko, maximum {} Ko)\n",
                corps.len() / 1024,
                MAX / 1024
            ),
        )
            .into_response();
    }

    // 🔴 On vérifie la SIGNATURE, pas l'extension ni l'en-tête déclaré. Servir un
    // fichier arbitraire en `image/png` depuis notre propre origine offrirait un point
    // d'appui à qui saurait en faire quelque chose.
    const PNG: &[u8] = &[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
    let retrait = corps.is_empty();
    if !retrait && !corps.starts_with(PNG) {
        return (
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "ce fichier n'est pas un PNG (signature absente)\n",
        )
            .into_response();
    }

    let png = if retrait { None } else { Some(corps.as_ref()) };
    if let Err(e) = s.state.set_logo(png).await {
        return ApiError(e.to_string()).into_response();
    }

    let _ = s
        .state
        .audit(
            auth.acteur().nom(),
            auth.identite().role,
            "apparence-logo",
            "logo",
            "ok",
            Some(if retrait { "retiré" } else { "posé" }),
        )
        .await;

    StatusCode::NO_CONTENT.into_response()
}

/// Crée un alias jetable, au format attendu par Bitwarden / addy.io (§5bis.3).
///
/// 🔴 La requête doit agir POUR quelqu'un. Deux façons : un jeton rattaché à un compte,
/// ou une personne connectée. Un jeton de service — celui d'un script d'exploitation —
/// n'a pas le droit d'agir au nom de quelqu'un, **même en rôle admin** : sinon, le voler
/// donnerait le pouvoir de créer des adresses sur la boîte de n'importe qui. Le
/// privilège ne remplace pas l'identité.
async fn creer_alias(
    auth: Autorise<PeutAgirSurSoi>,
    AxumState(s): AxumState<Arc<AppState>>,
    Json(demande): Json<hlb_users::CreationDemandee>,
) -> Response {
    // ⚠️ La boîte visée ne vit que sur le JETON : le protocole addy.io n'a aucun champ
    // pour la choisir. Une personne connectée n'en a donc pas, et reçoit sa boîte par
    // défaut — ce qui est le comportement attendu depuis une interface où elle peut,
    // elle, choisir explicitement.
    let (utilisateur, boite_visee) = match auth.acteur() {
        crate::auth::Acteur::Jeton { nom, .. } => {
            s.state.token_target(nom).await.unwrap_or((None, None))
        }
        crate::auth::Acteur::Personne { user } => (Some(user.clone()), None),
        crate::auth::Acteur::Anonyme => (None, None),
    };

    let Some(user) = utilisateur else {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "cette requête n'agit au nom de personne. Rattache le jeton à un \
                          compte — « hlb token create <nom> --role operator --user <compte> » \
                          — ou connecte-toi : un jeton de service ne peut pas créer d'alias \
                          au nom de quelqu'un"
            })),
        )
            .into_response();
    };

    // La boîte par défaut du compte reçoit l'alias. C'est le seul choix qui a du sens
    // ici : le client ne connaît pas les boîtes, et lui demander de choisir ferait
    // sortir du protocole que Bitwarden sait parler.
    let boites = match s.state.mailboxes(&user).await {
        Ok(b) => b,
        Err(e) => return ApiError(e.to_string()).into_response(),
    };
    // 🔴 La boîte visée par le JETON l'emporte : c'est le seul moyen de choisir, le
    // protocole addy.io n'ayant aucun champ pour ça. À défaut, la boîte par défaut.
    let choisie = match &boite_visee {
        Some(nom) => boites.iter().find(|(l, ..)| l == nom).cloned(),
        None => boites.iter().find(|(.., d)| *d).cloned(),
    };

    let Some((boite, domaine_boite, _)) = choisie else {
        // ⚠️ Un jeton qui vise une boîte supprimée doit ÉCHOUER, pas retomber
        // silencieusement sur la boîte par défaut : l'utilisateur croirait ses aliases
        // rangés là où ils ne sont pas, et les règles de tri ne s'appliqueraient plus.
        let détail = match &boite_visee {
            Some(nom) => format!(
                "la boîte « {nom} » visée par ce jeton n'existe plus pour {user}. \
                 Recrée-la, ou refais un jeton sans --mailbox"
            ),
            None => {
                format!("{user} n'a aucune boîte par défaut : l'alias n'aurait nulle part où aller")
            }
        };
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({ "error": détail })),
        )
            .into_response();
    };

    // ⚠️ Le domaine demandé par le client n'est retenu QUE s'il correspond à celui de
    // la boîte. Accepter n'importe quel domaine créerait une adresse sur un domaine
    // qu'on ne sert pas : elle ne recevrait jamais rien, et l'utilisateur la croirait
    // active parce que le client l'a affichée.
    let domaine = match demande.domain.as_deref() {
        Some(d) if d != domaine_boite => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({
                    "error": format!("domaine « {d} » non servi pour ce compte ; \
                                      attendu « {domaine_boite} »")
                })),
            )
                .into_response();
        }
        _ => domaine_boite,
    };

    let description = demande.description.clone().unwrap_or_default();
    let indice = hlb_users::forwarder::indice_depuis_description(&description);

    let mut alea = [0u8; hlb_users::generation::SUFFIXE_LEN];
    hlb_secrets::fill_random(&mut alea);
    let genere = hlb_users::Genere::pour(indice.as_deref().unwrap_or(""), &alea);

    // 🔴 Le quota s'applique ICI aussi. Un commentaire l'affirmait déjà et c'était FAUX :
    // `add_alias` était appelé directement, si bien qu'un profil `invite` limité à zéro
    // alias permanent en créait autant qu'il voulait par HTTP. Une limite qu'une API
    // contourne ne limite rien, et rend les profils décoratifs.
    match s.state.compte(&user).await {
        Ok(compte) => {
            let profil = hlb_users::Profil::par_nom(&compte.profil)
                .unwrap_or_else(hlb_users::Profil::standard);
            let usage = compte.usage(crate::auth::maintenant());
            if let Err(refus) = profil.autorise(&usage, hlb_users::Demande::AliasPermanent) {
                // 429 : la demande est légitime, c'est la quantité qui ne passe pas.
                // Un 403 laisserait croire à un problème de droits.
                return (
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(serde_json::json!({ "error": refus.raison })),
                )
                    .into_response();
            }
        }
        Err(e) => return ApiError(e.to_string()).into_response(),
    }

    // ⚠️ Permanent par défaut — Bitwarden n'a aucune notion de durée, et fabriquer une
    // expiration que l'utilisateur n'a pas demandée ferait mourir ses adresses sans
    // prévenir.
    if let Err(e) = s
        .state
        .add_alias(
            &user,
            &boite,
            &genere.local,
            None,
            indice.as_deref(),
            Some(&description),
        )
        .await
    {
        return ApiError(e.to_string()).into_response();
    }

    // Le dossier de tri proposé, que l'utilisateur pourra changer.
    if let Some(d) = hlb_users::sieve::Regle::dossier_par_defaut(indice.as_deref()) {
        let _ = s
            .state
            .set_alias_folder(&user, &genere.local, Some(&d))
            .await;
    }

    tracing::info!(user, alias = %genere.local, "alias créé par l'API addy.io");

    // 201 : Bitwarden accepte 200 comme 201, et 201 est le code juste pour une
    // création.
    (
        StatusCode::CREATED,
        Json(hlb_users::AliasCree::new(
            genere.adresse(&domaine),
            description,
        )),
    )
        .into_response()
}

/// Erreur d'API, rendue en JSON plutôt qu'en page HTML.
pub struct ApiError(String);

impl From<hlb_state::Error> for ApiError {
    fn from(e: hlb_state::Error) -> Self {
        Self(e.to_string())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": self.0 })),
        )
            .into_response()
    }
}

type ApiResult<T> = Result<Json<T>, ApiError>;

/// Une route qui change quelque chose.
///
/// 🔴 Le routeur est **construit à partir de cette liste**, et les tests d'invariants
/// la parcourent. Une route mutante déclarée ailleurs échapperait donc aux tests qui
/// vérifient qu'elle refuse un anonyme, qu'elle exige un rôle et qu'elle journalise.
/// C'est le seul garde-fou disponible : axum ne sait pas énumérer son propre routeur.
pub struct RouteMutante {
    pub chemin: &'static str,
    pub verbe: &'static str,
    /// Ce que la route exige — redit ici pour que le test puisse fabriquer un appelant
    /// juste en dessous du seuil, et vérifier qu'il est refusé.
    pub action: hlb_types::rbac::Action,
    /// Cette route suit-elle le protocole d'aperçu (`?apply=true`) ?
    ///
    /// ## 🔴 Le critère, et pourquoi il n'est pas « toutes les routes »
    ///
    /// L'aperçu existe pour les actions qui **touchent l'infrastructure** : installer,
    /// sauvegarder, supprimer. Là, savoir ce qui va se passer avant que ça se passe est
    /// vital — c'est tout le §11bis.
    ///
    /// Une route de **configuration** n'a rien à prévisualiser : écrire le nom de la
    /// marque ou poser un logo est idempotent, sans effet de bord et immédiatement
    /// réversible. Lui imposer un aperçu ferait un aller-retour pour rien, et
    /// l'habitude prise de cliquer deux fois viderait la protection de son sens là où
    /// elle compte.
    ///
    /// ⚠️ Le doute profite à `true` : mieux vaut un aperçu inutile qu'une action
    /// déclenchée par une visite d'écran.
    pub apercu: bool,
    /// 🔴 Cette route est-elle accessible SANS authentification ?
    ///
    /// L'exception se justifie dans un seul cas : la requête vient de quelqu'un qui
    /// n'a pas encore de compte, et porte sa propre autorisation. L'inscription est
    /// exactement ça — l'invitation, à usage unique et vérifiée en transaction, EST
    /// l'autorisation.
    ///
    /// ⚠️ Le doute profite à `false`. Une route publique par distraction ouvre le
    /// système entier, et rien ne le signalerait.
    pub publique: bool,
    routeur: axum::routing::MethodRouter<Arc<AppState>>,
}

/// Toutes les routes mutantes de l'API.
pub(crate) fn routes_mutantes() -> Vec<RouteMutante> {
    vec![
        // 🔴 API compatible addy.io : c'est BITWARDEN qui impose cette route et cette
        // forme, relevées dans son code source. Voir `hlb_users::forwarder`.
        // La déconnexion mute (elle ferme une session), donc elle passe par ici — et
        // hérite ainsi du contrôle CSRF, qu'une déconnexion forcée depuis un autre site
        // contournerait sinon. `LireSoi` suffit : se déconnecter n'est pas un privilège.
        RouteMutante {
            chemin: "/auth/deconnexion",
            verbe: "POST",
            // Se déconnecter n'a rien à prévisualiser.
            apercu: false,
            publique: false,
            action: hlb_types::rbac::Action::ReadSelf,
            routeur: axum::routing::post(crate::connexion::deconnexion),
        },
        RouteMutante {
            chemin: "/api/apparence",
            verbe: "PUT",
            action: hlb_types::rbac::Action::Operate,
            // Configuration : idempotente, sans effet de bord, réversible d'un clic.
            apercu: false,
            publique: false,
            routeur: axum::routing::put(changer_apparence),
        },
        RouteMutante {
            chemin: "/api/apparence/logo",
            verbe: "POST",
            action: hlb_types::rbac::Action::Operate,
            // Configuration : idempotente, sans effet de bord, réversible d'un clic.
            apercu: false,
            publique: false,
            routeur: axum::routing::post(televerser_logo),
        },
        // Les actions du lot 5. Chacune hérite des trois invariants par le seul fait
        // d'être ici : refus de l'anonyme, rôle exigé, journal d'audit.
        // 🔴 SANS authentification : c'est la personne invitée qui appelle, et elle
        // n'a pas encore de compte. L'invitation EST l'autorisation, et sa
        // consommation est atomique.
        RouteMutante {
            chemin: "/api/bitwarden",
            verbe: "POST",
            action: hlb_types::rbac::Action::ManageAccounts,
            // Crée un jeton et rend sa valeur UNE fois : il n'y a rien à prévisualiser,
            // et un aperçu devrait soit montrer la valeur (donc la révéler deux fois),
            // soit décrire une création qui n'a pas eu lieu.
            apercu: false,
            publique: false,
            routeur: axum::routing::post(crate::bitwarden::assistant),
        },
        RouteMutante {
            chemin: "/api/plans",
            verbe: "POST",
            action: hlb_types::rbac::Action::Operate,
            // Enregistrer un plan n'EXÉCUTE rien : prévisualiser l'enregistrement d'un
            // aperçu n'aurait aucun sens, et c'est réversible d'un « oublier ».
            apercu: false,
            publique: false,
            routeur: axum::routing::post(crate::actions::enregistrer_plan),
        },
        RouteMutante {
            chemin: "/api/secours/{id}",
            verbe: "POST",
            action: hlb_types::rbac::Action::ManageAccounts,
            // Déclaration réversible d'un clic : rien à prévisualiser. Un aller-retour
            // ferait prendre l'habitude de confirmer deux fois.
            apercu: false,
            publique: false,
            routeur: axum::routing::post(crate::secours::attester),
        },
        RouteMutante {
            chemin: "/api/preferences/theme",
            // Choisir un thème est immédiat et réversible d'un clic : rien à
            // prévisualiser, et un aller-retour ferait prendre l'habitude de confirmer
            // deux fois — ce qui viderait la protection là où elle compte.
            apercu: false,
            publique: false,
            verbe: "PUT",
            action: hlb_types::rbac::Action::ActOnSelf,
            routeur: axum::routing::put(crate::portail::changer_theme),
        },
        RouteMutante {
            chemin: "/api/annonces",
            apercu: true,
            publique: false,
            verbe: "POST",
            action: hlb_types::rbac::Action::Publish,
            routeur: axum::routing::post(crate::portail::publier),
        },
        RouteMutante {
            chemin: "/api/annonces/{id}/suivi",
            apercu: true,
            publique: false,
            verbe: "POST",
            action: hlb_types::rbac::Action::Publish,
            routeur: axum::routing::post(crate::portail::suivre),
        },
        RouteMutante {
            chemin: "/api/annonces/{id}",
            apercu: true,
            publique: false,
            verbe: "DELETE",
            action: hlb_types::rbac::Action::Publish,
            routeur: axum::routing::delete(crate::portail::retirer),
        },
        RouteMutante {
            chemin: "/api/inscription",
            apercu: true,
            publique: true,
            verbe: "POST",
            action: hlb_types::rbac::Action::ReadSelf,
            routeur: axum::routing::post(crate::comptes::inscrire),
        },
        RouteMutante {
            chemin: "/api/invitations",
            apercu: true,
            publique: false,
            verbe: "POST",
            action: hlb_types::rbac::Action::ManageAccounts,
            routeur: axum::routing::post(crate::comptes::creer_invitation),
        },
        RouteMutante {
            chemin: "/api/invitations/{reference}",
            apercu: true,
            publique: false,
            verbe: "DELETE",
            action: hlb_types::rbac::Action::ManageAccounts,
            routeur: axum::routing::delete(crate::comptes::revoquer_invitation),
        },
        RouteMutante {
            chemin: "/api/comptes/{compte}/role/{role}",
            apercu: true,
            publique: false,
            verbe: "POST",
            action: hlb_types::rbac::Action::ManageAccounts,
            routeur: axum::routing::post(crate::comptes::changer_role),
        },
        RouteMutante {
            chemin: "/api/apps/{name}/install",
            apercu: true,
            publique: false,
            verbe: "POST",
            action: hlb_types::rbac::Action::Operate,
            routeur: axum::routing::post(crate::actions::installer_app),
        },
        RouteMutante {
            chemin: "/api/apps/{name}/scale",
            apercu: true,
            publique: false,
            verbe: "POST",
            action: hlb_types::rbac::Action::Operate,
            routeur: axum::routing::post(crate::actions::redimensionner),
        },
        RouteMutante {
            chemin: "/api/backup/destinations/{nom}",
            apercu: true,
            publique: false,
            verbe: "PUT",
            action: hlb_types::rbac::Action::Operate,
            routeur: axum::routing::put(crate::actions::destination),
        },
        RouteMutante {
            chemin: "/api/noeuds/{id}/disponibilite",
            apercu: true,
            publique: false,
            verbe: "POST",
            action: hlb_types::rbac::Action::Operate,
            routeur: axum::routing::post(crate::actions::noeud_disponibilite),
        },
        RouteMutante {
            chemin: "/api/apps/{name}/backup",
            apercu: true,
            publique: false,
            verbe: "POST",
            action: hlb_types::rbac::Action::Operate,
            routeur: axum::routing::post(crate::actions::backup_run),
        },
        RouteMutante {
            chemin: "/api/todo/{app}/{id}",
            apercu: true,
            publique: false,
            verbe: "POST",
            action: hlb_types::rbac::Action::Operate,
            routeur: axum::routing::post(crate::actions::verifier_guide),
        },
        RouteMutante {
            chemin: "/api/apps/{name}",
            apercu: true,
            publique: false,
            verbe: "DELETE",
            action: hlb_types::rbac::Action::Destroy,
            routeur: axum::routing::delete(crate::actions::supprimer_app),
        },
        RouteMutante {
            chemin: "/api/v1/aliases",
            verbe: "POST",
            // Contrat addy.io imposé par Bitwarden : il n'a pas de notion d'aperçu.
            apercu: false,
            publique: false,
            action: hlb_types::rbac::Action::ActOnSelf,
            routeur: axum::routing::post(creer_alias),
        },
    ]
}

pub fn router(state: Arc<AppState>) -> Router {
    let mut r = Router::new()
        .route("/healthz", get(healthz))
        .route("/api/apps", get(list_apps))
        .route("/api/apps/{name}", get(get_app))
        .route("/api/todo", get(list_todo))
        // Noms et usages seulement — jamais les valeurs, même derrière l'API.
        .route("/api/secrets", get(list_secrets))
        .route("/api/audit", get(list_audit))
        .route("/metrics", get(prometheus))
        // Qui suis-je : la première requête de l'interface, c'est elle qui décide des
        // écrans à montrer.
        .route("/api/moi", get(crate::connexion::moi))
        // Connexion : ces deux routes sont forcément ouvertes — on ne peut pas exiger
        // une authentification de celui qui vient s'authentifier.
        .route("/auth/connexion", get(crate::connexion::depart))
        .route("/auth/retour", get(crate::connexion::retour))
        // 🔴 Ouvertes : l'écran de connexion doit porter le nom et les couleurs de la
        // maison, sinon il ressemble à toutes les pages d'hameçonnage du monde.
        .route("/api/apparence", get(apparence))
        .route("/api/apparence/logo", get(apparence_logo))
        .route("/api/v1/metriques/serie", get(serie))
        .route("/api/alertes", get(alertes))
        .route("/api/noeuds", get(noeuds))
        .route("/api/taches", get(taches))
        .route("/api/topologie", get(topologie))
        .route("/api/catalogue", get(crate::actions::catalogue))
        .route("/api/comptes", get(crate::comptes::liste))
        .route("/api/annuaire", get(crate::comptes::annuaire))
        .route("/api/invitations", get(crate::comptes::invitations))
        .route("/api/portail", get(crate::portail::portail))
        .route("/api/annonces", get(crate::portail::annonces))
        .route("/api/statut", get(crate::portail::statut_prive))
        .route("/api/preferences", get(crate::portail::preferences))
        // 🔴 Sans authentification, et servie SEULEMENT si `--statut-public`. Le
        // gestionnaire refuse lui-même dans le cas contraire, en disant comment
        // l'ouvrir plutôt qu'en laissant croire à une panne.
        .route("/statut", get(crate::portail::statut))
        .route("/api/sauvegardes", get(sauvegardes))
        .route("/api/couverture", get(couverture))
        .route("/api/apps/{name}/detail", get(app_detail))
        .route("/api/derive", get(ecarts))
        .route("/api/exposition", get(exposition))
        .route("/api/sante", get(sante_installation))
        .route("/api/frise", get(frise))
        .route("/api/secrets/rotation", get(rotation_secrets))
        .route("/api/secours", get(breakglass))
        .route("/api/runbook", get(runbook))
        .route("/api/plans", get(crate::actions::lister_plans))
        .route("/api/export/{quoi}", get(export_csv))
        .route("/api/apps/{name}/versions", get(manifest_versions));

    for m in routes_mutantes() {
        r = r.route(m.chemin, m.routeur);
    }

    // ⚠️ En dernier : `/{*fichier}` capte tout ce qui reste, y compris `/api/…` si on
    // le posait avant. L'UI masquerait alors l'API sans le moindre message.
    r.route("/", get(ui_index))
        .route("/{*fichier}", get(ui_fichier))
        // 🔴 En couche globale plutôt que route par route : une route ajoutée demain
        // hérite de la limitation sans que personne ait à y penser. C'est le même
        // raisonnement que l'extracteur d'autorisation — ce qu'on peut oublier finit
        // par être oublié.
        .layer(axum::middleware::from_fn_with_state(state.clone(), limiter))
        .with_state(state)
}

/// La couche de limitation de débit.
async fn limiter(
    AxumState(s): AxumState<Arc<AppState>>,
    requete: axum::extract::Request,
    suite: axum::middleware::Next,
) -> Response {
    // ⚠️ Lu dans les extensions plutôt que par un extracteur : `ConnectInfo` n'est
    // présent que si le serveur est monté avec `into_make_service_with_connect_info`,
    // et un extracteur obligatoire ferait échouer TOUTES les requêtes des tests, qui
    // n'ont pas de socket. Ici, son absence dégrade la précision, pas le service.
    let pair = requete
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|c| c.0.ip());

    // ⚠️ `/healthz` est exempté : c'est la sonde de Swarm, elle frappe à intervalle
    // fixe et depuis des adresses variables. La limiter ferait redémarrer le controller
    // en boucle, précisément quand le cluster est chargé.
    if requete.uri().path() == "/healthz" {
        return suite.run(requete).await;
    }

    let classe = crate::debit::Classe::de(requete.method(), requete.uri().path());
    let qui = crate::debit::client(requete.headers(), pair, s.confiance_proxy);

    match s.debit.verifier(&qui, classe, crate::auth::maintenant()) {
        crate::debit::Verdict::Passe => suite.run(requete).await,
        crate::debit::Verdict::Refuse { retry_after_s } => {
            tracing::warn!(client = %qui, ?classe, "débit dépassé");
            (
                StatusCode::TOO_MANY_REQUESTS,
                // Sans `Retry-After`, un client automatique martèle de plus belle.
                [(axum::http::header::RETRY_AFTER, retry_after_s.to_string())],
                format!("trop de requêtes — réessaie dans {retry_after_s} s\n"),
            )
                .into_response()
        }
    }
}

async fn healthz(AxumState(s): AxumState<Arc<AppState>>) -> Json<Health> {
    Json(Health {
        status: "ok".into(),
        version: s.version.to_string(),
        uptime_secs: s.started_at.elapsed().as_secs(),
    })
}

async fn summarise(s: &AppState, name: &str, status: String) -> Result<AppSummary, ApiError> {
    let m = s.state.app_manifest(name).await?;
    Ok(AppSummary {
        name: name.to_string(),
        status,
        image: m.spec.image.reference(),
        domain: s.state.app_domain(name).await?,
        last_backup_secs: s.state.seconds_since_last_success(name).await?,
        last_verification_secs: s.state.seconds_since_last_verification(name).await?,
        blocking_guides: s.state.unverified_blocking(name).await? as i64,
    })
}

async fn list_apps(
    _auth: Autorise<PeutLire>,
    AxumState(s): AxumState<Arc<AppState>>,
) -> ApiResult<Vec<AppSummary>> {
    let mut out = Vec::new();
    for (name, status) in s.state.installed_apps().await? {
        out.push(summarise(&s, &name, status).await?);
    }
    Ok(Json(out))
}

// `Response` fait 128 octets, ce que clippy juge gros pour un variant d'erreur. C'est
// pourtant LE type d'erreur d'un handler axum : le boxer ajouterait une allocation sur
// chaque chemin d'erreur pour rendre la signature moins lisible.
#[allow(clippy::result_large_err)]
async fn get_app(
    _auth: Autorise<PeutLire>,
    AxumState(s): AxumState<Arc<AppState>>,
    Path(name): Path<String>,
) -> Result<Json<AppSummary>, Response> {
    let apps = s
        .state
        .installed_apps()
        .await
        .map_err(|e| ApiError::from(e).into_response())?;

    let Some((_, status)) = apps.into_iter().find(|(n, _)| n == &name) else {
        return Err((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": format!("app « {name} » inconnue") })),
        )
            .into_response());
    };

    summarise(&s, &name, status)
        .await
        .map(Json)
        .map_err(|e| e.into_response())
}

/// Le détail complet d'une application.
///
/// ## Ce qui n'est PAS ici
///
/// 🔴 Aucune valeur de secret. Les variables d'environnement sont rendues **telles
/// qu'elles sont dans le manifest**, jetons compris (`{{ db.password }}`). C'est
/// délibéré : la valeur ne doit pas traverser l'API, et un jeton visible dit à quoi
/// l'app est câblée — ce que des astérisques ne disent pas.
// `Response` fait 128 octets, ce que clippy juge gros pour un variant d'erreur. C'est
// pourtant LE type d'erreur d'un handler axum : le boxer ajouterait une allocation sur
// chaque chemin d'erreur pour rendre la signature moins lisible.
#[allow(clippy::result_large_err)]
async fn app_detail(
    _auth: Autorise<PeutLire>,
    AxumState(s): AxumState<Arc<AppState>>,
    Path(name): Path<String>,
) -> Result<Json<hlb_api::AppDetail>, Response> {
    let apps = s
        .state
        .installed_apps()
        .await
        .map_err(|e| ApiError::from(e).into_response())?;

    let Some((_, status)) = apps.into_iter().find(|(n, _)| n == &name) else {
        return Err((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": format!("app « {name} » inconnue") })),
        )
            .into_response());
    };

    let resume = summarise(&s, &name, status)
        .await
        .map_err(|e| e.into_response())?;

    // ⚠️ Le manifest FIGÉ au déploiement (§4.8), pas celui du catalogue courant : c'est
    // ce qui tourne qu'on veut lire, pas ce qu'on installerait aujourd'hui.
    let manifest = s.state.app_manifest(&name).await.ok();

    // Chaque source est facultative : une erreur sur l'une ne doit pas priver de tout
    // l'écran. Un détail à moitié rempli reste utile ; un 500 ne l'est pas.
    let taches = match &s.orchestrator {
        Some(o) => o
            .tasks(Some(&name))
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|t| hlb_api::TacheSummary {
                vivante: t.est_vivante(),
                echouee: t.a_echoue(),
                explication: t.explication().map(str::to_string),
                id: t.id,
                service: t.service,
                slot: t.slot,
                noeud: t.node_id,
                etat: t.state,
                etat_voulu: t.desired_state,
                image: Some(t.image).filter(|i| !i.is_empty()),
            })
            .collect(),
        // ⚠️ Même précédent que la topologie : sans orchestrateur, la démonstration
        // fabrique des tâches. Sans elles, la chaîne causale s'arrêterait au premier
        // maillon partout, et l'écran qu'on veut écrire serait invisible.
        None if s.demo => crate::demo::taches(&name),
        None => Vec::new(),
    };

    let couverture = {
        let source = crate::couverture::EtatSource(&s.state);
        let c = hlb_backup::couverture_de(&source, &name, SEUIL_PEREMPTION_S).await;
        Some(hlb_api::CouvertureSummary {
            copies_a_jour: c.copies_a_jour(),
            par_destination: c
                .par_destination
                .iter()
                .map(|(nom, etat)| {
                    let age = match etat {
                        hlb_backup::EtatDestination::Jamais => None,
                        hlb_backup::EtatDestination::Frais { age_s }
                        | hlb_backup::EtatDestination::Perime { age_s } => Some(*age_s),
                    };
                    (nom.clone(), age)
                })
                .collect(),
            app: c.app,
        })
    };

    // 🔴 La somme que personne ne fait de tête : RPO, copies, vérification, exercices
    // et fenêtre PITR ramenés à un verdict et à des remèdes ordonnés.
    let restaurabilite = Some(crate::couverture::en_resume(
        &crate::couverture::restaurabilite(&s.state, &name, SEUIL_PEREMPTION_S).await,
    ));

    let detail = hlb_api::AppDetail {
        // Rempli juste après : la chaîne causale a besoin du détail assemblé.
        diagnostic: None,
        restaurabilite,
        capacites: manifest
            .as_ref()
            .map(|m| m.spec.requires.iter().map(|c| c.describe()).collect())
            .unwrap_or_default(),
        env: manifest
            .as_ref()
            .map(|m| {
                m.spec
                    .env
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect()
            })
            .unwrap_or_default(),
        image: manifest.as_ref().map(|m| m.spec.image.reference()),
        manifest: manifest
            .as_ref()
            .and_then(|m| serde_yaml_ng::to_string(m).ok()),
        volumes: s
            .state
            .app_volumes(&name)
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|(nom, chemin, sauvegarde, sqlite)| hlb_api::VolumeSummary {
                nom,
                chemin,
                sauvegarde,
                sqlite,
            })
            .collect(),
        guides: s
            .state
            .pending_guides()
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|(app, ..)| app == &name)
            .map(|(app, id, title, blocking)| GuideItem {
                app,
                id,
                title,
                blocking,
            })
            .collect(),
        sauvegardes: s
            .state
            .backup_history(&name, 50)
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|r| hlb_api::SauvegardeRun {
                app: r.app,
                kind: r.kind,
                destination: r.destination,
                reussie: r.status == "ok",
                erreur: r.error,
                quand: r.finished_at,
            })
            .collect(),
        journal: s
            .state
            .audit_pour(&name, 30)
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|e| AuditItem {
                id: e.id,
                at: e.at,
                actor: e.actor,
                role: e.role,
                action: e.action,
                target: e.target,
                outcome: e.outcome,
                detail: e.detail,
            })
            .collect(),
        domaine: s.state.app_domain(&name).await.ok().flatten(),
        couverture,
        taches,
        resume,
    };

    // 🔴 La chaîne causale : le serveur est le seul à voir en même temps les tâches, les
    // nœuds et les alertes. L'interface les affiche sur trois écrans et ne peut pas
    // faire le lien — c'est exactement ce qui sépare un tableau de bord d'un
    // diagnostic.
    let diagnostic = hlb_api::diagnostic::expliquer(
        &detail,
        &noeuds_summary(&s).await,
        &s.alertes.read().await.clone(),
    );

    Ok(Json(hlb_api::AppDetail {
        diagnostic: Some(diagnostic),
        ..detail
    }))
}

async fn list_todo(
    _auth: Autorise<PeutLire>,
    AxumState(s): AxumState<Arc<AppState>>,
) -> ApiResult<Vec<GuideItem>> {
    Ok(Json(
        s.state
            .pending_guides()
            .await?
            .into_iter()
            .map(|(app, id, title, blocking)| GuideItem {
                app,
                id,
                title,
                blocking,
            })
            .collect(),
    ))
}

async fn list_audit(
    _auth: Autorise<PeutLire>,
    AxumState(s): AxumState<Arc<AppState>>,
) -> ApiResult<Vec<AuditItem>> {
    Ok(Json(
        s.state
            .audit_trail(100)
            .await?
            .into_iter()
            .map(|e| AuditItem {
                id: e.id,
                at: e.at,
                actor: e.actor,
                role: e.role,
                action: e.action,
                target: e.target,
                outcome: e.outcome,
                detail: e.detail,
            })
            .collect(),
    ))
}

/// Exposition Prometheus (§8bis).
///
/// Texte brut, pas JSON : c'est le format d'exposition attendu par les collecteurs.
async fn prometheus(_auth: Autorise<PeutLire>, AxumState(s): AxumState<Arc<AppState>>) -> Response {
    let mut apps = Vec::new();

    let installees = match s.state.installed_apps().await {
        Ok(a) => a,
        Err(e) => return ApiError::from(e).into_response(),
    };

    for (name, status) in installees {
        // 🔴 Une app dont on n'arrive pas à lire l'état ne doit pas faire échouer
        // TOUT le lot : le collecteur perdrait aussi les métriques des autres, et
        // la panne d'une seule app rendrait la supervision aveugle.
        let (b, v, g) = (
            s.state
                .seconds_since_last_success(&name)
                .await
                .ok()
                .flatten(),
            s.state
                .seconds_since_last_verification(&name)
                .await
                .ok()
                .flatten(),
            s.state.unverified_blocking(&name).await.unwrap_or(0),
        );
        apps.push(AppMetrics {
            name,
            status,
            last_backup_secs: b,
            last_verification_secs: v,
            blocking_guides: g as i64,
        });
    }

    // La couverture réelle des sauvegardes : c'est elle qui porte `hlb_backup_copies`,
    // le chiffre du 3-2-1 qu'attendait la règle `copie-unique` et qui n'existait nulle
    // part.
    let couvertures = crate::couverture::toutes(&s.state, SEUIL_PEREMPTION_S).await;

    let noeuds = s.last_poll.read().await;
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        metrics::render_avec_couverture(&apps, &noeuds, &couvertures),
    )
        .into_response()
}

/// Au-delà, une sauvegarde ne compte plus comme une copie à jour.
///
/// Douze heures : l'intervalle visé est de quatre heures (§8.1), et trois cycles ratés
/// signifient que quelque chose est cassé.
pub const SEUIL_PEREMPTION_S: i64 = 12 * 3_600;

async fn list_secrets(
    _auth: Autorise<PeutLire>,
    AxumState(s): AxumState<Arc<AppState>>,
) -> ApiResult<Vec<SecretItem>> {
    Ok(Json(
        s.state
            .secret_names()
            .await?
            .into_iter()
            .map(|(name, purpose)| SecretItem { name, purpose })
            .collect(),
    ))
}

#[cfg(test)]
mod tests {
    /// Les littéraux de chaîne d'un source, commentaires exclus.
    fn chaines_de(source: &str) -> Vec<String> {
        let sans_commentaires: String = source
            .lines()
            .map(|l| l.split("//").next().unwrap_or(""))
            .collect::<Vec<_>>()
            .join("\n");

        let mut out = Vec::new();
        let mut courant = String::new();
        let mut dedans = false;
        let mut echappe = false;

        for c in sans_commentaires.chars() {
            if echappe {
                echappe = false;
                continue;
            }
            match c {
                '\\' if dedans => echappe = true,
                '"' => {
                    if dedans {
                        out.push(std::mem::take(&mut courant));
                    }
                    dedans = !dedans;
                }
                _ if dedans => courant.push(c),
                _ => {}
            }
        }
        out
    }

    #[tokio::test]
    async fn a_refused_attempt_leaves_a_trace() {
        // 🔴 Constaté en essayant : un viewer qui tentait de SUPPRIMER une app recevait
        // un 403 et ne laissait aucune trace. Quelqu'un qui sonde ce qu'il peut
        // détruire passait donc invisible — or c'est exactement ce qu'un journal
        // d'audit existe pour montrer.
        // ⚠️ L'état est partagé avec le routeur : on garde une référence pour relire le
        // journal APRÈS la requête, ce que l'API ne permettrait pas à un viewer.
        let st = Arc::new(State::in_memory().await.expect("état"));
        let (valeur, jeton) = hlb_types::token::generate(
            "obs",
            hlb_types::Role::Viewer,
            [7u8; hlb_types::token::TOKEN_BYTES],
        );
        st.store_token(&jeton).await.expect("jeton");

        let r = router(etat_partage(st.clone(), false));

        let reponse = r
            .oneshot(
                axum::http::Request::builder()
                    .method("DELETE")
                    .uri("/api/apps/gitea?apply=true")
                    .header("authorization", format!("Bearer {valeur}"))
                    .body(axum::body::Body::empty())
                    .expect("requête"),
            )
            .await
            .expect("réponse");

        assert_eq!(reponse.status(), StatusCode::FORBIDDEN);

        let journal = st.audit_trail(10).await.expect("journal");
        let refus = journal
            .iter()
            .find(|e| e.outcome == "refused")
            .expect("le refus doit être journalisé");

        assert_eq!(refus.actor, "obs");
        // ⚠️ « refused » et non « failed » : le système a protégé, il n'est pas tombé
        // en panne. Les confondre ferait chercher un incident là où une garde a joué.
        assert_ne!(refus.outcome, "failed");
        assert!(refus.target.contains("/api/apps/gitea"), "{}", refus.target);
        assert!(
            refus.detail.as_deref().is_some_and(|d| d.contains("admin")),
            "le détail doit nommer le rôle requis"
        );
    }

    #[test]
    fn no_read_route_is_dead() {
        // 🔴 Le lot 12.3. `/api/apps/{name}` existait déjà et n'était consommé par
        // personne : avec cinquante routes, ce genre de dette se multiplie sans que
        // rien ne le signale, et l'on finit par maintenir du code que rien n'appelle.
        //
        // ⚠️ Le test croise les routes DÉCLARÉES avec ce que l'interface et le CLI
        // demandent réellement. Une route servie à un client extérieur (Bitwarden, le
        // veilleur) est listée explicitement — c'est une décision, pas un oubli.
        let routeur = include_str!("api.rs");
        let ui = include_str!("../../hlb-ui/src/client.rs");
        let ui_ecrans = include_str!("../../hlb-ui/src/ecrans/mod.rs");
        let shell = include_str!("../../hlb-ui/src/shell.rs");

        // Servies à d'autres que l'interface, et donc légitimement absentes d'elle.
        let externes = [
            // Bitwarden, via le protocole addy.io.
            "/api/v1/aliases",
            // Le veilleur et Prometheus.
            "/metrics",
            "/api/sante",
            // Le CLI et les scripts.
            "/api/runbook",
            "/api/export/{quoi}",
            "/api/audit",
            "/api/annuaire",
            "/api/catalogue",
            "/api/apparence/logo",
            "/api/v1/metriques/serie",
            "/api/apps/{name}",
            "/api/todo",
            "/api/secrets",
            "/api/moi",
            "/api/apparence",
            "/api/health",
        ];

        let mut mortes = Vec::new();
        for ligne in routeur.lines() {
            let Some(reste) = ligne.trim().strip_prefix(".route(\"") else {
                continue;
            };
            let Some(chemin) = reste.split('"').next() else {
                continue;
            };
            if !chemin.starts_with("/api/") || externes.contains(&chemin) {
                continue;
            }
            // Le gabarit devient un préfixe : l'interface construit ses URL par
            // `format!`, donc le nom exact n'y figure pas.
            let motif = chemin.split('{').next().unwrap_or(chemin);
            let consommee =
                ui.contains(motif) || ui_ecrans.contains(motif) || shell.contains(motif);
            if !consommee {
                mortes.push(chemin.to_string());
            }
        }

        assert!(
            mortes.is_empty(),
            "routes déclarées que personne ne consomme : {mortes:?} — soit un écran \
             manque, soit la route est à retirer"
        );
    }

    #[test]
    fn no_server_text_carries_a_collapsed_line_continuation() {
        // 🔴 Le piège documenté du projet, côté serveur cette fois. Sans le « \\ » de
        // fin de ligne, l'indentation Rust reste DANS la chaîne, et le texte s'affiche
        // avec un trou au milieu. Constaté à la lecture du runbook engendré : le
        // paragraphe partait à quinze espaces de la marge.
        //
        // ⚠️ Le scan est fait LIGNE PAR LIGNE, comme celui de l'interface. Extraire les
        // chaînes du fichier entier ferait échouer le test sur toutes les continuations
        // légitimes : mon extracteur mange la newline mais pas l'indentation qui suit,
        // là où rustc mange les deux. Par ligne, une continuation est un fragment
        // distinct dont l'indentation initiale se retire par `trim`.
        let trou = "  ";
        for (fichier, source) in [
            ("runbook.rs", include_str!("runbook.rs")),
            ("sante.rs", include_str!("sante.rs")),
            ("exposition.rs", include_str!("exposition.rs")),
            ("capacite.rs", include_str!("capacite.rs")),
            ("secours.rs", include_str!("secours.rs")),
            ("frise.rs", include_str!("frise.rs")),
        ] {
            for (n, ligne) in source.lines().enumerate() {
                let code = ligne.split("//").next().unwrap_or("");
                for texte in chaines_de(code) {
                    assert!(
                        !texte.trim().contains(trou),
                        "{fichier} ligne {} : « {texte} » porte une indentation avalée \
                         — il manque un antislash de continuation",
                        n + 1
                    );
                }
            }
        }
    }

    #[test]
    fn no_text_the_interface_shows_uses_the_parenthesised_plural() {
        // 🔴 Le tic que le projet s'interdit, verrouillé côté serveur aussi. Il y était
        // resté quatre fois — dans le résumé d'une installation, d'une sauvegarde et
        // d'un redimensionnement — parce que le test ne couvrait que l'interface. Or
        // ces phrases sont fabriquées ICI et affichées telles quelles.
        //
        // ⚠️ Motif ASSEMBLÉ : l'écrire ferait échouer ce test sur son propre code.
        let tic = format!("({})", "s");
        for (fichier, source) in [
            ("actions.rs", include_str!("actions.rs")),
            ("comptes.rs", include_str!("comptes.rs")),
            ("portail.rs", include_str!("portail.rs")),
            ("sante.rs", include_str!("sante.rs")),
            ("exposition.rs", include_str!("exposition.rs")),
            ("frise.rs", include_str!("frise.rs")),
            ("capacite.rs", include_str!("capacite.rs")),
        ] {
            for texte in chaines_de(source) {
                assert!(
                    !texte.contains(&tic),
                    "{fichier} : « {texte} » — hlb_api::pluriel existe pour ça"
                );
            }
        }
    }

    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    fn manifest(name: &str) -> hlb_types::Manifest {
        let y = format!(
            "apiVersion: hlb/v1\nkind: App\nmetadata: {{ name: {name} }}\n\
             spec:\n  image: {{ repo: a/b, tag: \"1\" }}\n"
        );
        serde_yaml_ng::from_str(&y).expect("manifest de test")
    }

    /// L'état applicatif d'un test, en un seul endroit.
    ///
    /// Cinq copies du même littéral, c'était cinq endroits à corriger chaque fois
    /// qu'`AppState` gagnait un champ.
    fn etat(st: State, no_auth: bool) -> Arc<AppState> {
        etat_partage(Arc::new(st), no_auth)
    }

    /// La même chose, mais avec un état que l'appelant garde : de quoi relire le
    /// journal après une requête que l'API n'autoriserait pas à relire.
    fn etat_partage(st: Arc<State>, no_auth: bool) -> Arc<AppState> {
        Arc::new(AppState {
            state: st,
            started_at: std::time::Instant::now(),
            version: "test",
            last_poll: Default::default(),
            ui_dir: None,
            no_auth,
            connexion: None,
            debit: Arc::new(crate::debit::Limiteur::new()),
            confiance_proxy: false,
            series: None,
            alertes: Default::default(),
            ecarts: Default::default(),
            battement: None,
            miroir: None,
            url_publique: None,
            orchestrator: None,
            demo: false,
            catalogue: None,
            statut_public: false,
            identite: None,
            mail: None,
            domaine_mail: "local".into(),
        })
    }

    /// Un état dont la page de statut est publiée.
    ///
    /// Un constructeur de plus plutôt qu'un paramètre supplémentaire sur `etat` : la
    /// publication du statut est l'exception, et la signaler par le NOM de la fonction
    /// rend le test lisible sans aller lire ses arguments.
    fn etat_statut_public(st: State) -> Arc<AppState> {
        let mut e = etat(st, false);
        // `Arc::get_mut` : l'état vient d'être créé, personne d'autre ne le tient.
        if let Some(m) = Arc::get_mut(&mut e) {
            m.statut_public = true;
        }
        e
    }

    async fn app() -> Router {
        let st = State::in_memory().await.expect("base");
        st.upsert_app("gitea", &manifest("gitea"), Some("git.example.fr"))
            .await
            .expect("upsert");
        st.set_app_status("gitea", "running").await.expect("statut");
        st.add_guide("gitea", "first-admin", "Créer l'admin", true)
            .await
            .expect("guide");

        router(etat(st, true))
    }

    async fn get(r: Router, uri: &str) -> (StatusCode, serde_json::Value) {
        let resp = r
            .oneshot(
                Request::builder()
                    .uri(uri)
                    .body(Body::empty())
                    .expect("requête"),
            )
            .await
            .expect("réponse");
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .expect("corps");
        let v = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, v)
    }

    #[tokio::test]
    async fn healthz_reports_liveness() {
        let (s, v) = get(app().await, "/healthz").await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(v["status"], "ok");
        assert_eq!(v["version"], "test");
    }

    #[tokio::test]
    async fn apps_are_listed_with_their_backup_state() {
        let (s, v) = get(app().await, "/api/apps").await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(v[0]["name"], "gitea");
        assert_eq!(v[0]["domain"], "git.example.fr");
        assert_eq!(v[0]["last_backup_secs"], serde_json::Value::Null);
        assert_eq!(v[0]["blocking_guides"], 1);
    }

    #[tokio::test]
    async fn an_unknown_app_gives_404_not_500() {
        let (s, v) = get(app().await, "/api/apps/nexiste-pas").await;
        assert_eq!(s, StatusCode::NOT_FOUND);
        assert!(v["error"].as_str().expect("message").contains("inconnue"));
    }

    #[tokio::test]
    async fn pending_guides_are_exposed() {
        let (_, v) = get(app().await, "/api/todo").await;
        assert_eq!(v[0]["id"], "first-admin");
        assert_eq!(v[0]["blocking"], true);
    }

    #[tokio::test]
    async fn the_audit_trail_is_exposed() {
        let (s, v) = get(app().await, "/api/audit").await;
        assert_eq!(s, StatusCode::OK);
        assert!(v.is_array());
    }

    #[tokio::test]
    async fn secrets_expose_names_never_values() {
        let (s, v) = get(app().await, "/api/secrets").await;
        assert_eq!(s, StatusCode::OK);
        // Le type ne porte tout simplement pas de champ « valeur ».
        let brut = serde_json::to_string(&v).expect("sérialisable");
        assert!(!brut.contains("value"), "{brut}");
        assert!(!brut.contains("secret_value"), "{brut}");
    }

    async fn texte(r: Router, uri: &str) -> (StatusCode, String, String) {
        let resp = r
            .oneshot(
                Request::builder()
                    .uri(uri)
                    .body(Body::empty())
                    .expect("requête"),
            )
            .await
            .expect("réponse");
        let status = resp.status();
        let ct = resp
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .expect("corps");
        (status, ct, String::from_utf8_lossy(&bytes).into_owned())
    }

    #[tokio::test]
    async fn metrics_are_served_as_prometheus_text() {
        let (s, ct, body) = texte(app().await, "/metrics").await;
        assert_eq!(s, StatusCode::OK);
        // Un `application/json` ferait rejeter tout le lot par le collecteur.
        assert!(ct.starts_with("text/plain"), "{ct}");
        assert!(
            body.contains("hlb_app_up{app=\"gitea\",status=\"running\"} 1"),
            "{body}"
        );
        assert!(
            body.contains("hlb_blocking_guides{app=\"gitea\"} 1"),
            "{body}"
        );
        // Jamais sauvegardée : aucun échantillon d'âge (cf. metrics::render).
        assert!(!body.contains("hlb_backup_age_seconds{app="), "{body}");
    }

    #[tokio::test]
    async fn metrics_never_leak_secret_values() {
        // Le point d'exposition est le plus susceptible d'être scrapé par un tiers.
        let (_, _, body) = texte(app().await, "/metrics").await;
        assert!(!body.contains("PrivateKey"), "{body}");
        assert!(!body.to_lowercase().contains("password"), "{body}");
    }

    /// Une API protégée, et la valeur du jeton qui l'ouvre.
    async fn app_protegee() -> (Router, String) {
        let st = State::in_memory().await.expect("base");
        st.upsert_app("gitea", &manifest("gitea"), None)
            .await
            .expect("upsert");

        let (valeur, stocke) =
            hlb_types::generate_token("test", hlb_types::Role::Viewer, [42u8; 32]);
        st.store_token(&stocke).await.expect("jeton");

        let r = router(etat(st, false));
        (r, valeur)
    }

    /// Comme `get`, mais avec un jeton facultatif et le corps décodé.
    async fn get_avec_jeton(
        r: Router,
        uri: &str,
        jeton: Option<&str>,
    ) -> (StatusCode, serde_json::Value) {
        let mut req = Request::builder().uri(uri);
        if let Some(j) = jeton {
            req = req.header("Authorization", format!("Bearer {j}"));
        }
        let resp = r
            .oneshot(req.body(Body::empty()).expect("requête"))
            .await
            .expect("réponse");
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .expect("corps");
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
        )
    }

    async fn get_route_avec_jeton(r: Router, route: &str, jeton: Option<&str>) -> StatusCode {
        let mut req = Request::builder().uri(route);
        if let Some(j) = jeton {
            req = req.header("Authorization", format!("Bearer {j}"));
        }
        r.oneshot(req.body(Body::empty()).expect("requête"))
            .await
            .expect("réponse")
            .status()
    }

    #[tokio::test]
    async fn every_route_refuses_an_anonymous_caller() {
        // 🔴 L'API expose l'état du parc, le journal d'audit et les NOMS des secrets.
        // Une seule route oubliée suffit à tout donner.
        for route in [
            "/api/apps",
            "/api/todo",
            "/api/audit",
            "/api/secrets",
            "/metrics",
        ] {
            let (r, _) = app_protegee().await;
            let s = get_route_avec_jeton(r, route, None).await;
            assert_eq!(s, StatusCode::UNAUTHORIZED, "{route} accepte un anonyme");
        }
    }

    #[tokio::test]
    async fn a_wrong_token_is_refused_like_no_token() {
        // ⚠️ Réponse identique : les distinguer dirait à un attaquant si une valeur
        // essayée existe.
        let (r, _) = app_protegee().await;
        assert_eq!(
            get_route_avec_jeton(r, "/api/apps", Some("FAUXJETON")).await,
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn a_valid_token_gets_through() {
        let (r, jeton) = app_protegee().await;
        assert_eq!(
            get_route_avec_jeton(r, "/api/apps", Some(&jeton)).await,
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn health_stays_open_for_probes() {
        // Une sonde de vivacité ne peut pas porter de jeton : Swarm ne lui en donne
        // pas. Fermer /healthz ferait redémarrer le controller en boucle.
        let (r, _) = app_protegee().await;
        assert_eq!(
            get_route_avec_jeton(r, "/healthz", None).await,
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn the_open_mode_is_explicit_not_a_default() {
        // 🔴 `no_auth` n'existe que pour ne pas casser un déploiement existant, et le
        // controller refuse de démarrer dans cet état sans drapeau explicite.
        let (s, _) = get(app().await, "/api/apps").await;
        assert_eq!(s, StatusCode::OK, "le mode ouvert doit rester ouvert");
    }

    #[test]
    fn wasm_is_served_with_the_mime_the_browser_demands() {
        // 🔴 `WebAssembly.instantiateStreaming` REFUSE un flux en
        // application/octet-stream, avec un message qui ne dit pas ce qu'il attendait.
        assert_eq!(mime_de("hlb_ui_bg.wasm"), "application/wasm");
        // ⚠️ Un SVG servi en octet-stream n'est pas affiché du tout : l'icône de la PWA
        // serait vide, et rien ne dirait pourquoi.
        assert_eq!(mime_de("icone.svg"), "image/svg+xml");
        assert_eq!(mime_de("hlb_ui.js"), "text/javascript");
        assert!(mime_de("index.html").starts_with("text/html"));
    }

    #[test]
    fn path_traversal_is_refused() {
        // 🔴 Le controller tourne souvent en root sur un nœud : sortir du répertoire
        // de l'UI n'est pas un risque théorique.
        assert!(!nom_sur("../../etc/shadow"));
        assert!(!nom_sur("/etc/passwd"));
        assert!(!nom_sur("a/../../b"));
        assert!(!nom_sur(""));
        assert!(nom_sur("hlb_ui_bg.wasm"));
        assert!(nom_sur("index.html"));
    }

    #[tokio::test]
    async fn without_a_ui_directory_the_root_says_so() {
        // Une 404 muette laisserait croire à une panne du controller.
        let (s, _, corps) = texte(app().await, "/").await;
        assert_eq!(s, StatusCode::NOT_FOUND);
        assert!(corps.contains("--ui-dir"), "{corps}");
    }

    #[tokio::test]
    async fn a_verb_no_route_declares_is_still_rejected() {
        // L'ancienne règle — « aucun verbe mutant nulle part » — a été levée : l'API
        // doit maintenant installer, sauvegarder et gérer des comptes. Ce qui reste
        // vrai, et qu'on vérifie ici, c'est qu'un verbe mutant sur une route de lecture
        // n'est pas silencieusement accepté.
        for method in ["POST", "PUT", "DELETE", "PATCH"] {
            let r = app().await;
            let resp = r
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri("/api/apps")
                        .body(Body::empty())
                        .expect("requête"),
                )
                .await
                .expect("réponse");
            assert_eq!(
                resp.status(),
                StatusCode::METHOD_NOT_ALLOWED,
                "{method} /api/apps devrait être refusé"
            );
        }
    }

    #[tokio::test]
    async fn no_route_acts_without_apply() {
        // 🔴 L'INVARIANT CENTRAL du projet, transposé en HTTP : le mode par défaut ne
        // modifie rien. Une visite d'écran ne doit jamais devenir une exécution.
        //
        // Le test parcourt la liste qui SERT à construire le routeur : une action
        // ajoutée sans respecter la règle le fait échouer.
        for m in routes_mutantes() {
            // ⚠️ Le champ, pas une liste de chemins à maintenir : une route ajoutée
            // sans le déclarer serait couverte par le test suivant, qui exige un choix
            // explicite.
            if !m.apercu {
                continue;
            }

            let st = State::in_memory().await.expect("base");
            st.upsert_app("gitea", &manifest("gitea"), None)
                .await
                .expect("app");
            st.add_guide("gitea", "premier-admin", "Créer l'admin", true)
                .await
                .expect("guide");
            let etat = etat(st, true);
            let r = router(etat.clone());

            let uri = m
                .chemin
                .replace("{name}", "gitea")
                .replace("{app}", "gitea")
                .replace("{nom}", "nas")
                .replace("{reference}", "a1b2c3d4")
                .replace("{compte}", "remy")
                .replace("{role}", "viewer")
                // ⚠️ `{id}` ne veut pas dire la même chose selon la route : un nœud,
                // un identifiant de guide, ou un entier d'annonce. Un remplacement
                // unique donnerait des URI que le routeur refuse, et le test croirait
                // à un défaut de la route.
                .replace(
                    "{id}",
                    if m.chemin.contains("/noeuds/") {
                        "n1"
                    } else if m.chemin.contains("/annonces/") {
                        "1"
                    } else {
                        "premier-admin"
                    },
                );

            let resp = r
                .oneshot(
                    Request::builder()
                        .method(m.verbe)
                        .uri(&uri)
                        .header("content-type", "application/json")
                        .body(Body::from("{}"))
                        .expect("requête"),
                )
                .await
                .expect("réponse");

            // ⚠️ Le code de retour n'est PAS ce qu'on vérifie. Une route peut refuser
            // de planifier (422 : catalogue absent, app inconnue) — c'est un « rien
            // n'a été fait » parfaitement valide. Ce qui compte est `applique`.
            let status = resp.status();
            assert!(
                status == StatusCode::OK || status == StatusCode::UNPROCESSABLE_ENTITY,
                "{} {uri} rend {status}",
                m.verbe
            );

            let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
                .await
                .expect("corps");
            let v: serde_json::Value =
                serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);

            assert_eq!(
                v["applique"], false,
                "{} {uri} a AGI sans ?apply=true",
                m.verbe
            );
            // Et rien ne doit être marqué comme fait.
            if let Some(etapes) = v["etapes"].as_array() {
                for e in etapes {
                    assert_eq!(
                        e["etat"], "prevue",
                        "{} {uri} : une étape est marquée faite en aperçu",
                        m.verbe
                    );
                }
            }
        }
    }

    #[test]
    fn only_registration_is_public() {
        // 🔴 Une route publique par distraction ouvre le système entier, et rien ne le
        // signalerait. La liste est donc verrouillée : la seule exception légitime est
        // la requête de quelqu'un qui n'a pas encore de compte et porte sa propre
        // autorisation.
        let publiques: Vec<&str> = routes_mutantes()
            .iter()
            .filter(|m| m.publique)
            .map(|m| m.chemin)
            .collect();
        assert_eq!(publiques, vec!["/api/inscription"], "{publiques:?}");
    }

    #[test]
    fn opting_out_of_preview_is_an_explicit_short_list() {
        // 🔴 Le garde-fou du garde-fou : `apercu: false` doit rester l'exception. Si
        // la liste s'allonge, c'est que la règle se vide — et le test le dit avant
        // qu'on s'en aperçoive à l'usage.
        let sans: Vec<&str> = routes_mutantes()
            .iter()
            .filter(|m| !m.apercu)
            .map(|m| m.chemin)
            .collect();

        // Les seules exemptions légitimes : configuration idempotente, déconnexion, et
        // le contrat addy.io imposé par Bitwarden.
        let attendues = [
            "/api/apparence",
            "/api/apparence/logo",
            "/api/preferences/theme",
            "/auth/deconnexion",
            "/api/v1/aliases",
            // Attester un garde-fou de secours est une DÉCLARATION, pas une action sur
            // l'infrastructure : rien ne se déploie, rien ne se détruit, et l'on
            // décoche d'un clic. Il n'y a littéralement rien à prévisualiser.
            "/api/secours/{id}",
            // Enregistrer un plan n'exécute rien : c'est l'aperçu qu'on range, pas une
            // action qu'on lance.
            "/api/plans",
            // La valeur du jeton n'existe qu'au moment de la création : un aperçu
            // devrait la montrer une première fois, ou décrire une création qui n'a pas
            // eu lieu. Ni l'un ni l'autre n'a de sens.
            "/api/bitwarden",
        ];
        for c in &sans {
            assert!(
                attendues.contains(c),
                "« {c} » se dispense de l'aperçu sans raison documentée"
            );
        }
    }

    #[tokio::test]
    async fn installing_previews_the_real_plan() {
        // 🔴 L'aperçu montre le plan RÉEL, produit par le même résolveur que la ligne
        // de commande. Un aperçu qui divergerait de l'exécution serait pire qu'aucun
        // aperçu : on lui ferait confiance.
        let Ok(cat) = hlb_catalog::Catalog::load("../../catalog") else {
            // Le catalogue du dépôt n'est pas là (exécution hors arborescence) : on ne
            // fait pas échouer la suite pour autant.
            return;
        };

        let st = State::in_memory().await.expect("base");
        let mut e = AppState {
            state: Arc::new(st),
            started_at: std::time::Instant::now(),
            version: "test",
            last_poll: Default::default(),
            ui_dir: None,
            no_auth: true,
            connexion: None,
            debit: Arc::new(crate::debit::Limiteur::new()),
            confiance_proxy: false,
            series: None,
            alertes: Default::default(),
            ecarts: Default::default(),
            battement: None,
            miroir: None,
            url_publique: None,
            orchestrator: None,
            demo: false,
            catalogue: None,
            statut_public: false,
            identite: None,
            mail: None,
            domaine_mail: "local".into(),
        };
        e.catalogue = Some(Arc::new(cat));
        let r = router(Arc::new(e));

        let resp = r
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/apps/gitea/install")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"domaine":"git.example.fr"}"#))
                    .expect("requête"),
            )
            .await
            .expect("réponse");

        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .expect("corps");
        let v: serde_json::Value = serde_json::from_slice(&bytes).expect("json");

        assert_eq!(v["applique"], false, "un aperçu ne fait rien");
        let etapes = v["etapes"].as_array().expect("des étapes");
        assert!(
            etapes.len() > 3,
            "le plan réel de gitea fait plusieurs actions : {etapes:?}"
        );
        // Et le plan nomme ce qu'il fera vraiment : une base, un client OIDC.
        let tout = v["etapes"].to_string();
        assert!(tout.contains("base") || tout.contains("Postgres"), "{tout}");

        assert!(
            v["commande_cli"]
                .as_str()
                .unwrap_or("")
                .contains("--domain git.example.fr"),
            "la commande équivalente doit porter le domaine choisi"
        );
    }

    #[tokio::test]
    async fn installing_without_a_domain_is_blocked_not_guessed() {
        // Une app qui expose un service a besoin d'un domaine. Le deviner produirait
        // des URL de rappel OIDC fausses, et l'app échouerait à la connexion avec un
        // message sans rapport.
        let Ok(cat) = hlb_catalog::Catalog::load("../../catalog") else {
            return;
        };
        let st = State::in_memory().await.expect("base");
        let r = router(Arc::new(AppState {
            state: Arc::new(st),
            started_at: std::time::Instant::now(),
            version: "test",
            last_poll: Default::default(),
            ui_dir: None,
            no_auth: true,
            connexion: None,
            debit: Arc::new(crate::debit::Limiteur::new()),
            confiance_proxy: false,
            series: None,
            alertes: Default::default(),
            ecarts: Default::default(),
            battement: None,
            miroir: None,
            url_publique: None,
            orchestrator: None,
            demo: false,
            catalogue: Some(Arc::new(cat)),
            statut_public: false,
            identite: None,
            mail: None,
            domaine_mail: "local".into(),
        }));

        let resp = r
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/apps/gitea/install?apply=true")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .expect("requête"),
            )
            .await
            .expect("réponse");

        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .expect("corps");
        let v: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        assert_eq!(v["applique"], false);
        assert!(
            v["blocages"].to_string().contains("domaine"),
            "{}",
            v["blocages"]
        );
    }

    #[tokio::test]
    async fn scaling_to_zero_is_refused_because_it_is_a_stop() {
        // Descendre à zéro n'est pas un redimensionnement, c'est un arrêt — et ça
        // n'arrive presque jamais volontairement depuis un champ numérique.
        let st = State::in_memory().await.expect("base");
        let r = router(etat(st, true));

        let resp = r
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/apps/gitea/scale?apply=true")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"replicas":0}"#))
                    .expect("requête"),
            )
            .await
            .expect("réponse");

        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .expect("corps");
        let v: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        assert_eq!(v["applique"], false);
        assert!(
            v["blocages"].to_string().contains("arrête"),
            "{}",
            v["blocages"]
        );
    }

    #[tokio::test]
    async fn an_s3_destination_without_credentials_is_refused() {
        // 🔴 Sans identifiants, l'échec n'apparaîtrait qu'à la première sauvegarde,
        // des heures plus tard, sur une « signature invalide » qui n'oriente vers rien.
        let st = State::in_memory().await.expect("base");
        let r = router(etat(st, true));

        let resp = r
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/backup/destinations/offsite?apply=true")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"location":"s3:s3.example/hlb"}"#))
                    .expect("requête"),
            )
            .await
            .expect("réponse");

        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .expect("corps");
        let v: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        assert_eq!(v["applique"], false);
        assert!(
            v["blocages"].to_string().contains("signature invalide"),
            "le message doit nommer l'erreur qu'on verrait sinon : {}",
            v["blocages"]
        );
    }

    #[tokio::test]
    async fn a_local_destination_is_actually_written() {
        // Le chemin nominal : une action qui, elle, est branchée pour de vrai.
        let st = State::in_memory().await.expect("base");
        let etat = etat(st, true);
        let state = etat.state.clone();
        let r = router(etat);

        let resp = r
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/backup/destinations/nas?apply=true")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"location":"/mnt/nas/restic","classes":"critique,volumineux"}"#,
                    ))
                    .expect("requête"),
            )
            .await
            .expect("réponse");

        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .expect("corps");
        let v: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        assert_eq!(v["applique"], true);
        assert_eq!(v["etapes"][0]["etat"], "faite");

        let d = state.destinations().await.expect("destinations");
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].0, "nas");
    }

    #[tokio::test]
    async fn an_unknown_backup_class_is_named_not_silently_dropped() {
        // Une classe mal orthographiée créerait une destination qui n'accepte rien, et
        // qui ne recevrait donc jamais de sauvegarde — sans que rien ne le signale.
        let st = State::in_memory().await.expect("base");
        let r = router(etat(st, true));

        let resp = r
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/backup/destinations/nas?apply=true")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"location":"/mnt/nas","classes":"importante"}"#,
                    ))
                    .expect("requête"),
            )
            .await
            .expect("réponse");

        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .expect("corps");
        let v: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        assert_eq!(v["applique"], false);
        assert!(
            v["blocages"].to_string().contains("importante"),
            "{}",
            v["blocages"]
        );
    }

    #[tokio::test]
    async fn an_invitation_can_only_create_one_account() {
        // 🔴 Le lien est à usage unique. Le réutiliser créerait un second compte avec
        // les mêmes droits, au nom de quelqu'un qui n'a rien demandé.
        let st = State::in_memory().await.expect("base");
        st.creer_invitation(
            "lien-test",
            "remy",
            "standard",
            hlb_types::Role::User,
            None,
            crate::auth::maintenant(),
            3_600,
            1,
            None,
        )
        .await
        .expect("invitation");

        let etat = etat(st, false);
        let inscrire = |r: Router, nom: &str| {
            let corps = format!(r#"{{"invitation":"lien-test","nom":"{nom}"}}"#);
            async move {
                let resp = r
                    .oneshot(
                        Request::builder()
                            .method("POST")
                            .uri("/api/inscription?apply=true")
                            .header("content-type", "application/json")
                            .body(Body::from(corps))
                            .expect("requête"),
                    )
                    .await
                    .expect("réponse");
                let status = resp.status();
                let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
                    .await
                    .expect("corps");
                (
                    status,
                    serde_json::from_slice::<serde_json::Value>(&bytes)
                        .unwrap_or(serde_json::Value::Null),
                )
            }
        };

        let (s1, v1) = inscrire(router(etat.clone()), "alice").await;
        assert_eq!(s1, StatusCode::OK, "{v1}");
        assert_eq!(v1["applique"], true);

        let (s2, v2) = inscrire(router(etat.clone()), "mallory").await;
        assert_eq!(
            s2,
            StatusCode::UNPROCESSABLE_ENTITY,
            "un lien à usage unique a resservi : {v2}"
        );

        // Et le second compte n'existe pas.
        let comptes = etat.state.users().await.expect("comptes");
        assert!(comptes.iter().any(|(n, _, _)| n == "alice"));
        assert!(!comptes.iter().any(|(n, _, _)| n == "mallory"));
    }

    #[tokio::test]
    async fn registration_preview_does_not_burn_the_link() {
        // ⚠️ Il faut pouvoir vérifier que son nom est libre sans consommer le lien.
        let st = State::in_memory().await.expect("base");
        st.creer_invitation(
            "lien-test",
            "remy",
            "standard",
            hlb_types::Role::User,
            None,
            crate::auth::maintenant(),
            3_600,
            1,
            None,
        )
        .await
        .expect("invitation");
        let etat = etat(st, false);

        let r = router(etat.clone());
        let resp = r
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/inscription")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"invitation":"lien-test","nom":"alice"}"#))
                    .expect("requête"),
            )
            .await
            .expect("réponse");
        assert_eq!(resp.status(), StatusCode::OK);

        // Le lien sert toujours.
        let reste = etat
            .state
            .invitations(crate::auth::maintenant())
            .await
            .expect("invitations");
        assert!(reste[0].utilisable(), "l'aperçu a brûlé le lien");
    }

    #[tokio::test]
    async fn an_invalid_name_is_refused_before_the_link_is_spent() {
        // Un nom refusé après consommation gâcherait le lien pour une faute de frappe.
        let st = State::in_memory().await.expect("base");
        st.creer_invitation(
            "lien-test",
            "remy",
            "standard",
            hlb_types::Role::User,
            None,
            crate::auth::maintenant(),
            3_600,
            1,
            None,
        )
        .await
        .expect("invitation");
        let etat = etat(st, false);

        let r = router(etat.clone());
        let resp = r
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/inscription?apply=true")
                    .header("content-type", "application/json")
                    // Majuscules et espace : invalide comme partie locale d'adresse.
                    .body(Body::from(
                        r#"{"invitation":"lien-test","nom":"Alice Martin"}"#,
                    ))
                    .expect("requête"),
            )
            .await
            .expect("réponse");
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);

        let reste = etat
            .state
            .invitations(crate::auth::maintenant())
            .await
            .expect("invitations");
        assert!(
            reste[0].utilisable(),
            "le lien a été gâché par une faute de frappe"
        );
    }

    #[tokio::test]
    async fn a_half_created_account_is_visible_and_repairable() {
        // 🔴 Le cœur du lot 6 : PocketID n'étant pas branché, le compte est créé
        // `SansIdentite`. Ce n'est PAS un échec silencieux — l'état est nommé, visible,
        // et une relance le répare.
        let st = State::in_memory().await.expect("base");
        st.creer_invitation(
            "lien-test",
            "remy",
            "standard",
            hlb_types::Role::User,
            None,
            crate::auth::maintenant(),
            3_600,
            1,
            None,
        )
        .await
        .expect("invitation");
        let etat = etat(st, false);

        let r = router(etat.clone());
        let resp = r
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/inscription?apply=true")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"invitation":"lien-test","nom":"alice"}"#))
                    .expect("requête"),
            )
            .await
            .expect("réponse");

        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .expect("corps");
        let v: serde_json::Value = serde_json::from_slice(&bytes).expect("json");

        // Appliqué, mais INCOMPLET — et le verdict le dit.
        assert_eq!(v["applique"], true);
        assert!(
            v["etapes"].to_string().contains("nonimplementee"),
            "les étapes non faites doivent être marquées : {}",
            v["etapes"]
        );

        // Et l'état du compte est nommé.
        let c = etat.state.compte("alice").await.expect("compte");
        assert_eq!(c.coherence(), hlb_users::Coherence::Vide);
        assert!(
            c.coherence().describe().contains("aucune"),
            "{}",
            c.coherence().describe()
        );
    }

    #[tokio::test]
    async fn the_status_page_is_closed_until_someone_opens_it() {
        // 🔴 Une page de statut publique révèle la liste de ce qui tourne chez vous et
        // le calendrier de vos pannes. Le défaut fermé est une décision, pas un oubli.
        let st = State::in_memory().await.expect("base");
        let r = router(etat(st, false));

        let resp = r
            .oneshot(
                Request::builder()
                    .uri("/statut")
                    .body(Body::empty())
                    .expect("requête"),
            )
            .await
            .expect("réponse");

        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 16)
            .await
            .expect("corps");
        let texte = String::from_utf8_lossy(&bytes);
        // Le refus dit COMMENT ouvrir, pour ne pas laisser croire à une panne.
        assert!(texte.contains("--statut-public"), "{texte}");
    }

    #[tokio::test]
    async fn an_open_status_page_never_leaks_the_inventory() {
        // ⚠️ Quand elle est publique, elle ne montre que les services EXPOSÉS : lister
        // postgres ou valkey dresserait l'inventaire de l'installation pour qui la lit.
        let st = State::in_memory().await.expect("base");
        st.upsert_app("gitea", &manifest("gitea"), Some("git.example.fr"))
            .await
            .expect("app");
        st.set_app_status("gitea", "running").await.expect("statut");
        // Un service de plateforme : pas de domaine, donc pas exposé.
        st.upsert_app("postgres", &manifest("postgres"), None)
            .await
            .expect("app");
        st.set_app_status("postgres", "running")
            .await
            .expect("statut");

        let r = router(etat_statut_public(st));

        let resp = r
            .oneshot(
                Request::builder()
                    .uri("/statut")
                    .body(Body::empty())
                    .expect("requête"),
            )
            .await
            .expect("réponse");
        assert_eq!(resp.status(), StatusCode::OK);

        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .expect("corps");
        let v: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        let services = v["services"].as_array().expect("services");
        assert_eq!(
            services.len(),
            1,
            "un service non exposé a fuité : {services:?}"
        );
        assert_eq!(services[0]["nom"], "gitea");
    }

    #[tokio::test]
    async fn a_preview_still_leaves_a_trace() {
        // Savoir que quelqu'un a regardé ce qu'une purge ferait est une information.
        // Mais elle n'est PAS journalisée comme une exécution.
        let st = State::in_memory().await.expect("base");
        st.upsert_app("gitea", &manifest("gitea"), None)
            .await
            .expect("app");
        let etat = etat(st, true);
        let state = etat.state.clone();
        let r = router(etat);

        let _ = r
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/api/apps/gitea")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .expect("requête"),
            )
            .await
            .expect("réponse");

        let journal = state.audit_trail(10).await.expect("journal");
        let e = journal
            .iter()
            .find(|e| e.action == "app-remove")
            .expect("l'aperçu doit laisser une trace");
        assert_eq!(e.outcome, "preview", "un aperçu n'est pas une exécution");
    }

    #[tokio::test]
    async fn destroying_needs_the_target_named_back() {
        // 🔴 Le rôle ne suffit pas : un administrateur fatigué à 2 h du matin reste un
        // administrateur. Répéter le nom empêche un purge tapé sur la mauvaise app.
        let st = State::in_memory().await.expect("base");
        st.upsert_app("gitea", &manifest("gitea"), None)
            .await
            .expect("app");
        let r = router(etat(st, true));

        let resp = r
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/api/apps/gitea?apply=true")
                    .header("content-type", "application/json")
                    // Sans confirmation.
                    .body(Body::from("{}"))
                    .expect("requête"),
            )
            .await
            .expect("réponse");

        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .expect("corps");
        let v: serde_json::Value = serde_json::from_slice(&bytes).expect("json");

        assert_eq!(v["applique"], false, "appliqué sans confirmation");
        let blocages = v["blocages"].as_array().expect("des blocages");
        assert!(
            blocages
                .iter()
                .any(|b| b.as_str().unwrap_or("").contains("confirme")),
            "{blocages:?}"
        );
    }

    #[tokio::test]
    async fn a_wrong_confirmation_does_not_pass() {
        // Confirmer « vikunja » pour supprimer « gitea » est exactement l'accident que
        // la confirmation nommée existe pour attraper.
        let st = State::in_memory().await.expect("base");
        st.upsert_app("gitea", &manifest("gitea"), None)
            .await
            .expect("app");
        let r = router(etat(st, true));

        let resp = r
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/api/apps/gitea?apply=true")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"confirme":"vikunja"}"#))
                    .expect("requête"),
            )
            .await
            .expect("réponse");

        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .expect("corps");
        let v: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        assert_eq!(
            v["applique"], false,
            "une confirmation erronée a été acceptée"
        );
    }

    #[tokio::test]
    async fn an_applied_action_never_claims_more_than_it_did() {
        // 🔴 « Unimplemented n'est jamais Done ». Une action dont l'exécuteur n'est pas
        // branché doit le DIRE, pas afficher un succès.
        let st = State::in_memory().await.expect("base");
        st.upsert_app("gitea", &manifest("gitea"), None)
            .await
            .expect("app");
        st.upsert_destination("nas", "/mnt/nas", "critique", None)
            .await
            .expect("destination");
        let r = router(etat(st, true));

        let resp = r
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/apps/gitea/backup?apply=true")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .expect("requête"),
            )
            .await
            .expect("réponse");

        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .expect("corps");
        let v: serde_json::Value = serde_json::from_slice(&bytes).expect("json");

        assert_eq!(v["applique"], true);
        let etapes = v["etapes"].as_array().expect("des étapes");
        assert!(
            etapes.iter().all(|e| e["etat"] == "nonimplementee"),
            "une étape prétend avoir sauvegardé : {etapes:?}"
        );
    }

    #[tokio::test]
    async fn a_guide_can_actually_be_attested() {
        // Le chemin nominal : une action qui, elle, EST branchée.
        let st = State::in_memory().await.expect("base");
        st.upsert_app("gitea", &manifest("gitea"), None)
            .await
            .expect("app");
        st.add_guide("gitea", "premier-admin", "Créer l'admin", true)
            .await
            .expect("guide");
        let etat = etat(st, true);
        let state = etat.state.clone();
        let r = router(etat);

        let resp = r
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/todo/gitea/premier-admin?apply=true")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .expect("requête"),
            )
            .await
            .expect("réponse");

        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .expect("corps");
        let v: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        assert_eq!(v["applique"], true);
        assert_eq!(v["etapes"][0]["etat"], "faite");

        // Et le guide n'est plus en attente.
        assert_eq!(state.unverified_blocking("gitea").await.expect("guides"), 0);
    }

    #[tokio::test]
    async fn every_mutating_route_refuses_an_anonymous_caller() {
        // 🔴 Parcourt la liste qui SERT à construire le routeur : une route mutante
        // ajoutée ailleurs échapperait à ce test, d'où la règle écrite sur
        // `RouteMutante`.
        for m in routes_mutantes() {
            if m.publique {
                continue;
            }
            let (r, _) = app_protegee().await;
            let resp = r
                .oneshot(
                    Request::builder()
                        .method(m.verbe)
                        .uri(m.chemin)
                        .header("content-type", "application/json")
                        .body(Body::from("{}"))
                        .expect("requête"),
                )
                .await
                .expect("réponse");
            assert_eq!(
                resp.status(),
                StatusCode::UNAUTHORIZED,
                "{} {} accepte un anonyme",
                m.verbe,
                m.chemin
            );
        }
    }

    #[tokio::test]
    async fn every_mutating_route_refuses_a_role_below_its_threshold() {
        // Le rôle était authentifié mais JAMAIS confronté : `Role::allows` n'avait aucun
        // appelant en production. Un jeton `viewer` pouvait créer des aliases.
        for m in routes_mutantes() {
            if m.publique {
                continue;
            }
            let Some(trop_bas) = hlb_types::Role::tous()
                .into_iter()
                .find(|r| !r.allows(m.action))
            else {
                // Une action que même le rôle le plus bas autorise : rien à vérifier.
                continue;
            };

            let st = State::in_memory().await.expect("base");
            let (valeur, stocke) = hlb_types::generate_token("bas", trop_bas, [7u8; 32]);
            st.store_token(&stocke).await.expect("jeton");
            let r = router(etat(st, false));

            let resp = r
                .oneshot(
                    Request::builder()
                        .method(m.verbe)
                        .uri(m.chemin)
                        .header("Authorization", format!("Bearer {valeur}"))
                        .header("content-type", "application/json")
                        .body(Body::from("{}"))
                        .expect("requête"),
                )
                .await
                .expect("réponse");
            assert_eq!(
                resp.status(),
                StatusCode::FORBIDDEN,
                "{} {} accepte le rôle {}",
                m.verbe,
                m.chemin,
                trop_bas.as_str()
            );
        }
    }

    #[tokio::test]
    async fn a_missing_time_series_database_is_said_not_drawn_flat() {
        // 🔴 Sans base de séries, la route rend « indisponible » AVEC le remède — et
        // surtout pas une série vide, qui se dessinerait en ligne plate à zéro et se
        // lirait « machine au repos ».
        let (s, v) = get_avec_jeton(
            app().await,
            "/api/v1/metriques/serie?q=hlb_cpu_used_ratio",
            None,
        )
        .await;
        assert_eq!(
            s,
            StatusCode::OK,
            "une base absente n'est pas une panne du controller"
        );
        let raison = v["raison"].as_str().expect("une raison");
        assert!(raison.contains("--metrics-url"), "{raison}");
        assert!(v["points"].is_null(), "aucune série ne doit être fabriquée");
    }

    #[tokio::test]
    async fn a_plain_user_token_cannot_read_the_console() {
        // 🔴 Le rôle `utilisateur` est celui d'une personne qui a un compte. Lui ouvrir
        // /api/audit et /api/secrets reviendrait à donner l'inventaire des secrets et
        // l'historique des opérations à quiconque a une boîte mail.
        for route in [
            "/api/apps",
            "/api/todo",
            "/api/audit",
            "/api/secrets",
            "/metrics",
        ] {
            let st = State::in_memory().await.expect("base");
            let (valeur, stocke) =
                hlb_types::generate_token("portail", hlb_types::Role::User, [9u8; 32]);
            st.store_token(&stocke).await.expect("jeton");
            let r = router(etat(st, false));

            let s = get_route_avec_jeton(r, route, Some(&valeur)).await;
            assert_eq!(
                s,
                StatusCode::FORBIDDEN,
                "{route} ouvert à un simple utilisateur"
            );
        }
    }

    #[tokio::test]
    async fn a_refusal_says_which_role_is_needed() {
        // Un 403 nu laisse deviner si on s'est trompé d'écran, si le système est cassé,
        // ou s'il manque un droit.
        let st = State::in_memory().await.expect("base");
        let (valeur, stocke) =
            hlb_types::generate_token("portail", hlb_types::Role::User, [9u8; 32]);
        st.store_token(&stocke).await.expect("jeton");
        let r = router(etat(st, false));

        let resp = r
            .oneshot(
                Request::builder()
                    .uri("/api/apps")
                    .header("Authorization", format!("Bearer {valeur}"))
                    .body(Body::empty())
                    .expect("requête"),
            )
            .await
            .expect("réponse");
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let corps = axum::body::to_bytes(resp.into_body(), 1 << 16)
            .await
            .expect("corps");
        let texte = String::from_utf8_lossy(&corps);
        assert!(
            texte.contains("viewer"),
            "le rôle requis doit être nommé : {texte}"
        );
        assert!(
            texte.contains("user"),
            "le rôle détenu doit être nommé : {texte}"
        );
    }

    #[tokio::test]
    async fn the_quota_applies_over_http_too() {
        // 🔴 Le défaut corrigé : un commentaire affirmait « le quota s'applique ICI
        // aussi » alors que `add_alias` était appelé directement. Un profil `invite`,
        // limité à ZÉRO alias permanent, en créait autant qu'il voulait par HTTP.
        let st = State::in_memory().await.expect("base");
        st.upsert_user("invite", "invite", None)
            .await
            .expect("compte");
        st.add_mailbox("invite", "invite", "turi.fr", true)
            .await
            .expect("boîte");

        let (valeur, stocke) =
            hlb_types::generate_token("bw", hlb_types::Role::Operator, [3u8; 32]);
        st.store_token(&stocke).await.expect("jeton");
        st.set_token_user("bw", Some("invite"))
            .await
            .expect("rattachement");

        let r = router(etat(st, false));

        let resp = r
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/aliases")
                    .header("Authorization", format!("Bearer {valeur}"))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"description":"Generated by Bitwarden (amazon.fr)"}"#,
                    ))
                    .expect("requête"),
            )
            .await
            .expect("réponse");

        assert_eq!(
            resp.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "le profil invité n'a droit à aucun alias permanent"
        );
    }

    #[tokio::test]
    async fn a_service_token_never_acts_for_someone() {
        // Le privilège ne remplace pas l'identité : un jeton ADMIN non rattaché doit
        // être refusé là où un jeton rattaché passe.
        let st = State::in_memory().await.expect("base");
        let (valeur, stocke) =
            hlb_types::generate_token("service", hlb_types::Role::Admin, [4u8; 32]);
        st.store_token(&stocke).await.expect("jeton");

        let r = router(etat(st, false));

        let resp = r
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/aliases")
                    .header("Authorization", format!("Bearer {valeur}"))
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .expect("requête"),
            )
            .await
            .expect("réponse");
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }
}
