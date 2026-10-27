//! axum's extractors, refusing in the API's own shape.
//!
//! axum answers a body that does not parse, or a path or query that does not
//! deserialise, with a line of plain text. Every other refusal is an
//! `hlb_api::ErrorBody`, and the OpenAPI document says so: left alone, these would be
//! the one 400 whose body the generated client cannot read. Each wrapper here does what
//! axum's does and turns its rejection into an [`ApiError`].
//!
//! [`Json`] is also the response type, so a handler imports one `Json` and cannot pick
//! up axum's for its arguments by habit. `Path` and `Query` keep axum's names because
//! `utoipa` recognises the parameters by those names.

use axum::extract::rejection::{BytesRejection, JsonRejection, PathRejection, QueryRejection};
use axum::extract::{FromRequest, FromRequestParts, OptionalFromRequest, Request};
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::error::ApiError;

/// A JSON body in, or a JSON body out.
#[derive(Debug, Clone, Copy, Default)]
pub struct Json<T>(pub T);

impl<T: DeserializeOwned, S: Send + Sync> FromRequest<S> for Json<T> {
    type Rejection = ApiError;

    async fn from_request(req: Request, state: &S) -> Result<Self, ApiError> {
        let axum::Json(v) =
            <axum::Json<serde_json::Value> as FromRequest<S>>::from_request(req, state)
                .await
                .map_err(json_rejection)?;
        bounded::<T>(v).map(Self)
    }
}

/// `Option<Json<T>>`: no `Content-Type` is no body; a body that is there and wrong is
/// still refused, never read as absent.
impl<T: DeserializeOwned, S: Send + Sync> OptionalFromRequest<S> for Json<T> {
    type Rejection = ApiError;

    async fn from_request(req: Request, state: &S) -> Result<Option<Self>, ApiError> {
        let v = <axum::Json<serde_json::Value> as OptionalFromRequest<S>>::from_request(req, state)
            .await
            .map_err(json_rejection)?;
        v.map(|axum::Json(v)| bounded::<T>(v).map(Self)).transpose()
    }
}

/// The body as `T`, once it is within the bounds the document gives `T`'s schema
/// ([`crate::limits`]) — refused field by field otherwise, like a body that does not
/// parse, and before any handler reads it.
///
/// ⚠️ The schema is found by the type's own name, which is the name `utoipa` gives it.
/// A body type the document does not describe has no bounds to step out of.
fn bounded<T: DeserializeOwned>(v: serde_json::Value) -> Result<T, ApiError> {
    let name = std::any::type_name::<T>()
        .rsplit("::")
        .next()
        .unwrap_or_default();
    let refused = crate::limits::refusals(crate::openapi::as_json(), name, &v);
    if !refused.is_empty() {
        return Err(ApiError::Unprocessable(refused.join("; ")));
    }
    serde_json::from_value(v).map_err(|e| {
        ApiError::Unprocessable(format!(
            "Failed to deserialize the JSON body into the target type: {e}"
        ))
    })
}

impl<T: Serialize> IntoResponse for Json<T> {
    fn into_response(self) -> Response {
        axum::Json(self.0).into_response()
    }
}

fn json_rejection(e: JsonRejection) -> ApiError {
    ApiError::rejected(e.status(), e.body_text())
}

/// Parameters taken from the path.
#[derive(Debug)]
pub struct Path<T>(pub T);

impl<T: DeserializeOwned + Send, S: Send + Sync> FromRequestParts<S> for Path<T> {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, ApiError> {
        <axum::extract::Path<T> as FromRequestParts<S>>::from_request_parts(parts, state)
            .await
            .map(|axum::extract::Path(v)| Self(v))
            .map_err(|e: PathRejection| ApiError::rejected(e.status(), e.body_text()))
    }
}

/// Parameters taken from the query string.
#[derive(Debug)]
pub struct Query<T>(pub T);

impl<T: DeserializeOwned, S: Send + Sync> FromRequestParts<S> for Query<T> {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, ApiError> {
        <axum::extract::Query<T> as FromRequestParts<S>>::from_request_parts(parts, state)
            .await
            .map(|axum::extract::Query(v)| Self(v))
            .map_err(|e: QueryRejection| ApiError::rejected(e.status(), e.body_text()))
    }
}

/// A raw body. Its rejection is the body limit, which axum answers 413 in plain text.
#[derive(Debug)]
pub struct Bytes(pub axum::body::Bytes);

impl<S: Send + Sync> FromRequest<S> for Bytes {
    type Rejection = ApiError;

    async fn from_request(req: Request, state: &S) -> Result<Self, ApiError> {
        <axum::body::Bytes as FromRequest<S>>::from_request(req, state)
            .await
            .map(Self)
            .map_err(|e: BytesRejection| ApiError::rejected(e.status(), e.body_text()))
    }
}
