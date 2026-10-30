//! Why a request was not served, in one shape.
//!
//! Before this module, a refusal reached the client as one of three bodies depending on
//! the handler that wrote it: `{"error": …}` JSON, a bare line of text, or nothing. A
//! generated client types ONE error body per status; three would leave it guessing, and
//! a guess is where a refusal turns into a blank screen.

use crate::extract::Json;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};

/// A refused or failed request. Every variant answers `hlb_api::ErrorBody`.
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    /// 400: the request does not parse — a body, a path or a query string.
    #[error("{0}")]
    BadRequest(String),
    /// 401, with the `WWW-Authenticate` that tells a client to authenticate rather
    /// than give up.
    #[error("authentication required: API token, or sign in at /auth/signin")]
    Unauthenticated,
    /// 403: the caller is known and not entitled.
    #[error("{0}")]
    Forbidden(String),
    #[error("{0}")]
    NotFound(String),
    /// 409: the request is well-formed, the installation's state forbids it.
    #[error("{0}")]
    Conflict(String),
    #[error("{0}")]
    PayloadTooLarge(String),
    #[error("{0}")]
    UnsupportedMediaType(String),
    /// 422: the request is understood and its content is refused.
    #[error("{0}")]
    Unprocessable(String),
    /// 429 for a QUANTITY that does not pass — a quota, not a right. A 403 here would
    /// send someone looking for a permission they already have.
    #[error("{0}")]
    TooMany(String),
    /// 429 from the rate limiter, with the `Retry-After` an automated client needs or
    /// it hammers all the harder.
    #[error("too many requests — try again in {retry_after_s} s")]
    RateLimited { retry_after_s: i64 },
    /// 428: the action destroys, and a passkey presented for it at PocketID — the
    /// address in [`crate::passkey::URL_HEADER`] — is what it waits for.
    #[error("this destroys: present your passkey to confirm it")]
    PasskeyRequired { url: String },
    #[error("{0}")]
    Internal(String),
    #[error(transparent)]
    State(#[from] hlb_state::Error),
}

impl ApiError {
    pub fn status(&self) -> StatusCode {
        match self {
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::Unauthenticated => StatusCode::UNAUTHORIZED,
            Self::Forbidden(_) => StatusCode::FORBIDDEN,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
            Self::Conflict(_) => StatusCode::CONFLICT,
            Self::PayloadTooLarge(_) => StatusCode::PAYLOAD_TOO_LARGE,
            Self::UnsupportedMediaType(_) => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            Self::Unprocessable(_) => StatusCode::UNPROCESSABLE_ENTITY,
            Self::TooMany(_) | Self::RateLimited { .. } => StatusCode::TOO_MANY_REQUESTS,
            Self::PasskeyRequired { .. } => StatusCode::PRECONDITION_REQUIRED,
            Self::State(hlb_state::Error::MailboxTaken { .. }) => StatusCode::CONFLICT,
            Self::Internal(_) | Self::State(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl ApiError {
    /// An extractor's rejection, under the status axum chose for it.
    pub(crate) fn rejected(status: StatusCode, message: String) -> Self {
        match status {
            StatusCode::PAYLOAD_TOO_LARGE => Self::PayloadTooLarge(message),
            StatusCode::UNSUPPORTED_MEDIA_TYPE => Self::UnsupportedMediaType(message),
            StatusCode::UNPROCESSABLE_ENTITY => Self::Unprocessable(message),
            s if s.is_client_error() => Self::BadRequest(message),
            _ => Self::Internal(message),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status();
        let body = Json(hlb_api::ErrorBody {
            error: self.to_string(),
        });
        match self {
            Self::Unauthenticated => (
                status,
                [(header::WWW_AUTHENTICATE, "Bearer".to_string())],
                body,
            )
                .into_response(),
            Self::RateLimited { retry_after_s } => (
                status,
                [(header::RETRY_AFTER, retry_after_s.to_string())],
                body,
            )
                .into_response(),
            Self::PasskeyRequired { url } => {
                (status, [(crate::passkey::URL_HEADER, url)], body).into_response()
            }
            _ => (status, body).into_response(),
        }
    }
}

/// What a JSON read route answers.
pub type ApiResult<T> = Result<Json<T>, ApiError>;

/// Why an action route answers something other than its plan with a 200.
///
/// ⚠️ Not folded into [`ApiError`]: an action that cannot even be planned (no catalog,
/// an unknown app) still answers the action's own body, so the interface shows the
/// blockers where it would have shown the steps. A route that reports the refusal as
/// `{"error": …}` instead is a route whose screen has nothing to put there.
#[derive(Debug)]
pub enum ActionError<T> {
    /// 422, with the action's body.
    Unplannable(Box<T>),
    Api(ApiError),
}

impl<T> From<ApiError> for ActionError<T> {
    fn from(e: ApiError) -> Self {
        Self::Api(e)
    }
}

impl<T> From<hlb_state::Error> for ActionError<T> {
    fn from(e: hlb_state::Error) -> Self {
        Self::Api(e.into())
    }
}

impl<T: serde::Serialize> IntoResponse for ActionError<T> {
    fn into_response(self) -> Response {
        match self {
            Self::Unplannable(body) => {
                (StatusCode::UNPROCESSABLE_ENTITY, Json(*body)).into_response()
            }
            Self::Api(e) => e.into_response(),
        }
    }
}

/// What an action route answers: 200 with the plan — previewed, blocked or applied, the
/// body's `applied` and `blockers` say which — or an [`ActionError`].
pub type ActionReply<T = hlb_api::ActionResult> = Result<Json<T>, ActionError<T>>;

#[cfg(test)]
mod tests {
    /// Every source file of this crate, tests and comments cut off.
    fn production_sources() -> Vec<(String, String)> {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut out = Vec::new();
        for entry in std::fs::read_dir(&dir).expect("source directory") {
            let path = entry.expect("entry").path();
            if path.extension().is_none_or(|e| e != "rs") {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("source");
            // At the start of a line: the one `auth.rs` carries inside a macro is indented,
            // and cutting there hid the rest of that file.
            let (code, tests) = text.split_once("\n#[cfg(test)]").unwrap_or((&text, ""));
            // Every scan here cuts a file at its tests. Code written after a test
            // module would be cut with them, and checked by none of them — `record_plan`
            // was, until 2026-10-05.
            let mut after = tests.split_once("\n}\n").map_or("", |(_, rest)| rest);
            while let Some(next) = after.trim_start().strip_prefix("#[cfg(test)]") {
                after = next.split_once("\n}\n").map_or("", |(_, rest)| rest);
            }
            assert!(
                after.trim().is_empty(),
                "{}: code after the test module escapes every source scan — move the \
                 module to the end of the file",
                path.display()
            );
            // A route's `#[utoipa::path(…)]` is metadata about it — its `json!` is an
            // extension's value, not a body — so it is not what these scans read.
            let code = without_path_attributes(code);
            let code = code
                .lines()
                .map(|l| l.split("//").next().unwrap_or(""))
                .collect::<Vec<_>>()
                .join("\n");
            let name = path.file_name().map(|n| n.to_string_lossy().into_owned());
            out.push((name.unwrap_or_default(), code));
        }
        out
    }

    fn without_path_attributes(code: &str) -> String {
        let mut out = String::new();
        let mut inside = false;
        for line in code.lines() {
            if line.starts_with("#[utoipa::path(") {
                inside = true;
            }
            if !inside {
                out.push_str(line);
                out.push('\n');
            }
            if inside && line.starts_with(")]") {
                inside = false;
            }
        }
        out
    }

    /// Each function's name and what follows its `->`, up to the body.
    fn signatures(code: &str) -> Vec<(String, String)> {
        let mut out = Vec::new();
        let mut rest = code;
        while let Some(at) = rest.find("fn ") {
            let after = &rest[at + 3..];
            let name: String = after
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            let end = after.find(['{', ';']).unwrap_or(after.len());
            let returns = after[..end]
                .rsplit_once("->")
                .map(|(_, r)| r.split_whitespace().collect::<Vec<_>>().join(" "))
                .unwrap_or_default();
            if !name.is_empty() {
                out.push((name, returns));
            }
            rest = &after[end..];
        }
        out
    }

    #[test]
    fn the_controller_creates_the_vaults_key_in_one_place_and_only_for_a_new_state() {
        // `open_or_init` beside an existing state made a new key whenever the real one
        // was not where the controller looked — and encrypted with it from then on.
        let (mut guarded, mut opened, mut offenders) = (0, 0, Vec::new());
        // The daemon's composition opens it at start-up, in `hlb-privd`: read with the
        // controller's own, or the one creation would be counted nowhere.
        fn walk(dir: &std::path::Path, out: &mut Vec<(String, String)>) {
            for e in std::fs::read_dir(dir).expect("hlb-privd's sources") {
                let path = e.expect("entry").path();
                if path.is_dir() {
                    walk(&path, out);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    let text = std::fs::read_to_string(&path).expect("source");
                    let code = text.split_once("\n#[cfg(test)]").map_or(&*text, |(c, _)| c);
                    out.push((path.display().to_string(), code.to_string()));
                }
            }
        }
        let mut sources = production_sources();
        walk(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../hlb-privd/src"),
            &mut sources,
        );
        for (name, code) in sources {
            guarded += code.matches(concat!("Vault::", "open_for_state(")).count();
            opened += code.matches(concat!("Vault::", "open(")).count();
            if code.contains(concat!("Vault::", "open_or_init(")) {
                offenders.push(name);
            }
        }
        assert!(offenders.is_empty(), "{offenders:?}");
        assert_eq!(guarded, 1, "the key is created at start-up, once");
        assert!(
            opened >= 3,
            "only {opened} vault openings found: the scan reads nothing"
        );
    }

    #[test]
    fn no_handler_answers_an_untyped_body() {
        // 🔴 A handler returning `Response` can put anything in it, and the OpenAPI
        // document generated from the signatures would describe nothing: the generated
        // client then types the body as `unknown`, and a renamed field is an
        // `undefined` on a screen weeks later. 35 of the 70 routes had that signature
        // before 2026-10-05. What is left is what is NOT JSON, each with its reason.
        let not_json = [
            (
                "into_response",
                "the `IntoResponse` impls that produce the typed bodies",
            ),
            ("ui_index", "the web interface's own files"),
            ("ui_file", "the web interface's own files"),
            ("serve", "the web interface's own files"),
            ("start", "a browser navigation to PocketID: a redirect"),
            (
                "return_to",
                "a browser navigation back from PocketID: a redirect",
            ),
            (
                "passkey_returned",
                "a page PocketID's return lands on, handing it to the panel",
            ),
            (
                "unavailable",
                "read by a person whose browser followed a sign-in link",
            ),
            (
                "throttle",
                "middleware: passes the routes' own responses through",
            ),
            (
                "reissue",
                "middleware: passes the routes' own responses through",
            ),
            ("export_csv", "a CSV download"),
            ("runbook", "a Markdown document"),
            ("appearance_logo", "a PNG"),
            ("catalog_icon", "a PNG"),
            ("theme_font", "a font file"),
            ("prometheus", "Prometheus's text exposition format"),
        ];

        let sources = production_sources();
        // A walk that found nothing would pass on nothing.
        assert!(sources.len() >= 20, "only {} source files", sources.len());

        let mut seen = std::collections::BTreeSet::new();
        for (file, code) in &sources {
            for (name, returns) in signatures(code) {
                let untyped = returns
                    .split(|c: char| !c.is_alphanumeric() && c != '_')
                    .any(|w| w == "Response" || w == "IntoResponse");
                if !untyped {
                    continue;
                }
                assert!(
                    not_json.iter().any(|(n, _)| *n == name),
                    "{file}: `fn {name}` returns `{returns}` — return `ApiResult<T>`, \
                     `ActionReply` or another typed body, so the API document can say what \
                     it answers"
                );
                seen.insert(name);
            }
        }

        // An exemption whose function is gone would wave through the next one to take
        // its name.
        for (name, why) in not_json {
            assert!(
                seen.contains(name),
                "`{name}` ({why}) no longer returns an untyped body: drop it from the list"
            );
        }
    }

    #[test]
    fn no_handler_takes_an_extractor_that_refuses_in_plain_text() {
        // axum's own `Json`, `Path`, `Query` and `Bytes` answer a malformed request in
        // plain text, the one refusal the API document's error body would not describe.
        // `crate::extract` wraps each; this keeps the originals from coming back by
        // habit, which the compiler would accept without a word.
        let sources = production_sources();
        assert!(sources.len() >= 20, "only {} source files", sources.len());
        let inline = [
            format!("axum::{}", "Json"),
            format!("axum::extract::{}", "Path"),
            format!("axum::extract::{}", "Query"),
            format!("axum::body::{}", "Bytes"),
        ];
        let wrapped = ["Json", "Path", "Query", "Bytes"];
        let mut imports = 0;
        for (file, code) in &sources {
            if file == "extract.rs" {
                continue;
            }
            for pattern in &inline {
                assert!(
                    !code.contains(pattern.as_str()),
                    "{file} names `{pattern}` — take `crate::extract`'s, which refuses with \
                     the API's error body"
                );
            }
            // A `use` statement read whole, since a grouped one spans lines.
            for statement in code.split(';') {
                let statement = statement.trim();
                let Some(path) = statement.strip_prefix("use axum::") else {
                    continue;
                };
                imports += 1;
                let names: Vec<&str> = path
                    .split(|c: char| !c.is_alphanumeric() && c != '_')
                    .collect();
                for w in wrapped {
                    assert!(
                        !names.contains(&w),
                        "{file}: `{statement}` imports axum's `{w}` — take \
                         `crate::extract`'s, which refuses with the API's error body"
                    );
                }
            }
        }
        // Ten `use axum::` statements on 2026-10-05; a split that stopped finding them
        // would pass on nothing.
        assert!(imports >= 8, "only {imports} axum imports read");
    }

    #[test]
    fn no_body_is_built_by_hand() {
        // `json!` builds an object no type declares: the shape the client receives is
        // then whatever that one call site spelled, and nothing generated from the Rust
        // can know it.
        let sources = production_sources();
        assert!(sources.len() >= 20, "only {} source files", sources.len());
        let pattern = format!("json{}(", "!");
        for (file, code) in &sources {
            assert!(
                !code.contains(&pattern),
                "{file} builds a body with `{pattern}` — declare its type in `hlb-api`"
            );
        }
    }
}
