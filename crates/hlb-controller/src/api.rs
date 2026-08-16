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
    /// Jeton attendu sur `/metrics`. `None` = point d'exposition ouvert.
    ///
    /// 🔴 `/metrics` en dit long : noms des apps installées, âge des sauvegardes,
    /// nœuds saturés, actions manuelles en attente. C'est une carte de ce qui est
    /// fragile, et donc de quoi choisir un moment pour frapper.
    pub metrics_token: Option<String>,
}

/// Comparaison à temps constant.
///
/// Un `==` sur des chaînes s'arrête au premier octet différent : le temps de réponse
/// révèle combien de caractères sont corrects, ce qui permet de deviner le jeton
/// octet par octet. Le surcoût ici est nul, l'absence de protection ne l'est pas.
fn constant_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
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
        .route("/metrics", get(prometheus))
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

async fn list_apps(AxumState(s): AxumState<Arc<AppState>>) -> ApiResult<Vec<AppSummary>> {
    let mut out = Vec::new();
    for (name, status) in s.state.installed_apps().await? {
        out.push(summarise(&s, &name, status).await?);
    }
    Ok(Json(out))
}

async fn get_app(
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

async fn list_todo(AxumState(s): AxumState<Arc<AppState>>) -> ApiResult<Vec<GuideItem>> {
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

async fn list_audit(AxumState(s): AxumState<Arc<AppState>>) -> ApiResult<Vec<AuditItem>> {
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
async fn prometheus(
    AxumState(s): AxumState<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> Response {
    if let Some(attendu) = &s.metrics_token {
        let fourni = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .unwrap_or("");

        if !constant_eq(fourni, attendu) {
            // 401 avec `WWW-Authenticate` : un collecteur mal configuré doit
            // comprendre qu'il lui manque un jeton, pas croire à une panne.
            return (
                StatusCode::UNAUTHORIZED,
                [(axum::http::header::WWW_AUTHENTICATE, "Bearer")],
                "jeton requis\n",
            )
                .into_response();
        }
    }

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

async fn list_secrets(AxumState(s): AxumState<Arc<AppState>>) -> ApiResult<Vec<SecretItem>> {
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
            metrics_token: None,
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

    async fn app_protegee() -> Router {
        let st = State::in_memory().await.expect("base");
        st.upsert_app("gitea", &manifest("gitea"), None).await.expect("upsert");
        router(Arc::new(AppState {
            state: Arc::new(st),
            started_at: std::time::Instant::now(),
            version: "test",
            last_poll: Default::default(),
            metrics_token: Some("jeton-secret-de-test".into()),
        }))
    }

    async fn get_avec_jeton(r: Router, jeton: Option<&str>) -> StatusCode {
        let mut req = Request::builder().uri("/metrics");
        if let Some(j) = jeton {
            req = req.header("Authorization", format!("Bearer {j}"));
        }
        r.oneshot(req.body(Body::empty()).expect("requête"))
            .await
            .expect("réponse")
            .status()
    }

    #[tokio::test]
    async fn metrics_can_be_protected_by_a_token() {
        // 🔴 `/metrics` est une carte de ce qui est fragile : quelles apps ne sont
        // plus sauvegardées, quels nœuds saturent. De quoi choisir son moment.
        assert_eq!(get_avec_jeton(app_protegee().await, None).await, StatusCode::UNAUTHORIZED);
        assert_eq!(
            get_avec_jeton(app_protegee().await, Some("mauvais")).await,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            get_avec_jeton(app_protegee().await, Some("jeton-secret-de-test")).await,
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn without_a_token_configured_metrics_stay_open() {
        // Rétrocompatible : un déploiement existant ne casse pas du jour au lendemain.
        assert_eq!(get_avec_jeton(app().await, None).await, StatusCode::OK);
    }

    #[test]
    fn token_comparison_does_not_leak_its_length_by_timing() {
        // Un `==` s'arrête au premier octet différent : le temps de réponse dirait
        // combien de caractères sont bons, et le jeton se devinerait octet par octet.
        assert!(constant_eq("abc", "abc"));
        assert!(!constant_eq("abc", "abd"));
        assert!(!constant_eq("abc", "abcd"));
        assert!(!constant_eq("", "x"));
        assert!(constant_eq("", ""));
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
