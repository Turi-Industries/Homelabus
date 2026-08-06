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
use serde::Serialize;

use hlb_state::State;

pub struct AppState {
    pub state: Arc<State>,
    pub started_at: std::time::Instant,
    pub version: &'static str,
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

#[derive(Serialize)]
pub struct Health {
    pub status: &'static str,
    pub version: &'static str,
    pub uptime_secs: u64,
}

#[derive(Serialize)]
pub struct AppSummary {
    pub name: String,
    pub status: String,
    pub image: String,
    pub domain: Option<String>,
    /// Âge de la dernière sauvegarde réussie, en secondes. `null` = jamais.
    pub last_backup_secs: Option<i64>,
    pub last_verification_secs: Option<i64>,
    /// Actions manuelles bloquantes encore en attente (§4.6).
    pub blocking_guides: i64,
}

#[derive(Serialize)]
pub struct GuideItem {
    pub app: String,
    pub id: String,
    pub title: String,
    pub blocking: bool,
}

#[derive(Serialize)]
pub struct SecretItem {
    pub name: String,
    pub purpose: String,
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/api/apps", get(list_apps))
        .route("/api/apps/{name}", get(get_app))
        .route("/api/todo", get(list_todo))
        // Noms et usages seulement — jamais les valeurs, même derrière l'API.
        .route("/api/secrets", get(list_secrets))
        .with_state(state)
}

async fn healthz(AxumState(s): AxumState<Arc<AppState>>) -> Json<Health> {
    Json(Health {
        status: "ok",
        version: s.version,
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
    async fn secrets_expose_names_never_values() {
        let (s, v) = get(app().await, "/api/secrets").await;
        assert_eq!(s, StatusCode::OK);
        // Le type ne porte tout simplement pas de champ « valeur ».
        let brut = serde_json::to_string(&v).expect("sérialisable");
        assert!(!brut.contains("value"), "{brut}");
        assert!(!brut.contains("secret_value"), "{brut}");
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
