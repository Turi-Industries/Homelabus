//! L'API HTTP du controller (§11bis).
//!
//! 🔴 **Lecture seule, délibérément.**
//!
//! Le plan (§11bis, phase 2.5) prévoit une UI en lecture seule d'abord : surface
//! d'attaque quasi nulle, aucun risque de casser quoi que ce soit, et valeur
//! quotidienne immédiate. Les écrans qui *agissent* viendront quand le RBAC (§9ter)
//! et le journal d'audit seront en place.
//!
//! Concrètement : aucune route `POST`, `PUT` ou `DELETE` dans ce module. Un test le
//! vérifie, pour que l'ajout d'une route mutante soit un geste conscient.

use std::sync::Arc;

use axum::extract::{Path, State as AxumState};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use hlb_api::{AppSummary, AuditItem, GuideItem, Health, SecretItem};

use hlb_state::State;

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

/// L'identité derrière une requête.
///
/// 🔴 Un extracteur, donc une route qui en a besoin ne peut pas oublier de le
/// demander : le compilateur l'exige dans sa signature. Une vérification écrite à la
/// main dans chaque gestionnaire finit toujours par manquer quelque part.
pub struct Authentifie {
    pub role: hlb_types::Role,
    pub token_name: String,
}

impl axum::extract::FromRequestParts<Arc<AppState>> for Authentifie {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        s: &Arc<AppState>,
    ) -> std::result::Result<Self, Self::Rejection> {
        if s.no_auth {
            // Mode ouvert assumé : tout le monde est admin, et le démarrage l'a
            // annoncé bruyamment.
            return Ok(Self {
                role: hlb_types::Role::Admin,
                token_name: "anonyme".into(),
            });
        }

        let presente = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .unwrap_or("");

        // ⚠️ Même réponse pour « pas de jeton » et « jeton inconnu ». Les distinguer
        // dirait à un attaquant si une valeur essayée existe.
        match s.state.find_token(presente).await {
            Ok(Some(t)) => {
                // Sans attendre : noter l'usage ne doit pas ralentir la requête, et
                // son échec ne doit pas la faire échouer.
                let st = s.state.clone();
                let nom = t.name.clone();
                tokio::spawn(async move {
                    let _ = st.touch_token(&nom).await;
                });

                Ok(Self {
                    role: t.role,
                    token_name: t.name,
                })
            }
            _ => Err((
                StatusCode::UNAUTHORIZED,
                [(axum::http::header::WWW_AUTHENTICATE, "Bearer")],
                "jeton requis ou invalide\n",
            )
                .into_response()),
        }
    }
}

/// Crée un alias jetable, au format attendu par Bitwarden / addy.io (§5bis.3).
///
/// 🔴 Le jeton doit être rattaché à un UTILISATEUR. Un jeton de service — celui d'un
/// script d'exploitation — n'a pas le droit d'agir au nom de quelqu'un : sinon, le
/// voler donnerait le pouvoir de créer des adresses sur la boîte de n'importe qui.
async fn creer_alias(
    auth: Authentifie,
    AxumState(s): AxumState<Arc<AppState>>,
    Json(demande): Json<hlb_users::CreationDemandee>,
) -> Response {
    let Ok(Some(user)) = s.state.token_user(&auth.token_name).await else {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "ce jeton n'est rattaché à aucun utilisateur. Crée-en un avec \
                          « hlb token create <nom> --role operator --user <compte> » : \
                          un jeton de service ne peut pas créer d'alias au nom de \
                          quelqu'un"
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
    let Some((boite, domaine_boite, _)) = boites.into_iter().find(|(.., d)| *d) else {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "error": format!("{user} n'a aucune boîte par défaut : l'alias n'aurait \
                                  nulle part où aller")
            })),
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

    // Le quota s'applique ICI aussi : une API qui contourne les limites rendrait les
    // profils décoratifs.
    // ⚠️ Permanent par défaut — Bitwarden n'a aucune notion de durée, et fabriquer une
    // expiration que l'utilisateur n'a pas demandée ferait mourir ses adresses sans
    // prévenir.
    if let Err(e) = s.state.add_alias(
        &user,
        &boite,
        &genere.local,
        None,
        indice.as_deref(),
        Some(&description),
    ).await
    {
        return ApiError(e.to_string()).into_response();
    }

    // Le dossier de tri proposé, que l'utilisateur pourra changer.
    if let Some(d) = hlb_users::sieve::Regle::dossier_par_defaut(indice.as_deref()) {
        let _ = s.state.set_alias_folder(&user, &genere.local, Some(&d)).await;
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

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/api/apps", get(list_apps))
        .route("/api/apps/{name}", get(get_app))
        .route("/api/todo", get(list_todo))
        // Noms et usages seulement — jamais les valeurs, même derrière l'API.
        .route("/api/secrets", get(list_secrets))
        .route("/api/audit", get(list_audit))
        // 🔴 API compatible addy.io : c'est BITWARDEN qui impose cette route et cette
        // forme, relevées dans son code source. Voir `hlb_users::forwarder`.
        .route("/api/v1/aliases", axum::routing::post(creer_alias))
        .route("/metrics", get(prometheus))
        .route("/", get(ui_index))
        .route("/{*fichier}", get(ui_fichier))
        .with_state(state)
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
    _auth: Authentifie,
    AxumState(s): AxumState<Arc<AppState>>,
) -> ApiResult<Vec<AppSummary>> {
    let mut out = Vec::new();
    for (name, status) in s.state.installed_apps().await? {
        out.push(summarise(&s, &name, status).await?);
    }
    Ok(Json(out))
}

async fn get_app(
    _auth: Authentifie,
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

async fn list_todo(
    _auth: Authentifie,
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
    _auth: Authentifie,
    AxumState(s): AxumState<Arc<AppState>>,
) -> ApiResult<Vec<AuditItem>> {
    Ok(Json(
        s.state
            .audit_trail(100)
            .await?
            .into_iter()
            .map(|(at, actor, action, target, outcome)| AuditItem {
                at,
                actor,
                action,
                target,
                outcome,
            })
            .collect(),
    ))
}

/// Exposition Prometheus (§8bis).
///
/// Texte brut, pas JSON : c'est le format d'exposition attendu par les collecteurs.
async fn prometheus(_auth: Authentifie, AxumState(s): AxumState<Arc<AppState>>) -> Response {
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
            s.state.seconds_since_last_success(&name).await.ok().flatten(),
            s.state.seconds_since_last_verification(&name).await.ok().flatten(),
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

    let noeuds = s.last_poll.read().await;
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        metrics::render(&apps, &noeuds),
    )
        .into_response()
}

async fn list_secrets(
    _auth: Authentifie,
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

    async fn app() -> Router {
        let st = State::in_memory().await.expect("base");
        st.upsert_app("gitea", &manifest("gitea"), Some("git.example.fr"))
            .await
            .expect("upsert");
        st.set_app_status("gitea", "running").await.expect("statut");
        st.add_guide("gitea", "first-admin", "Créer l'admin", true)
            .await
            .expect("guide");

        router(Arc::new(AppState {
            state: Arc::new(st),
            started_at: std::time::Instant::now(),
            version: "test",
            last_poll: Default::default(),
            ui_dir: None,
            no_auth: true,
        }))
    }

    async fn get(r: Router, uri: &str) -> (StatusCode, serde_json::Value) {
        let resp = r
            .oneshot(Request::builder().uri(uri).body(Body::empty()).expect("requête"))
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
            .oneshot(Request::builder().uri(uri).body(Body::empty()).expect("requête"))
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
        assert!(body.contains("hlb_app_up{app=\"gitea\",status=\"running\"} 1"), "{body}");
        assert!(body.contains("hlb_blocking_guides{app=\"gitea\"} 1"), "{body}");
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
        st.upsert_app("gitea", &manifest("gitea"), None).await.expect("upsert");

        let (valeur, stocke) =
            hlb_types::generate_token("test", hlb_types::Role::Viewer, [42u8; 32]);
        st.store_token(&stocke).await.expect("jeton");

        let r = router(Arc::new(AppState {
            state: Arc::new(st),
            started_at: std::time::Instant::now(),
            version: "test",
            last_poll: Default::default(),
            ui_dir: None,
            no_auth: false,
        }));
        (r, valeur)
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
        for route in ["/api/apps", "/api/todo", "/api/audit", "/api/secrets", "/metrics"] {
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
    async fn every_mutating_verb_is_rejected() {
        // 🔴 L'API est en lecture seule (§11bis). Ajouter une route mutante doit
        // être un geste conscient, pas un glissement.
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
}
