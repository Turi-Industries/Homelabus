//! The API's OpenAPI document: what the web interface's client is generated from.
//!
//! Each handler carries its own `#[utoipa::path]`, and [`crate::api::api`] registers
//! them with `routes!()`, which takes the path from that attribute: a route is written
//! once, and the document cannot list a path the router does not serve.
//!
//! ## What the operations carry beyond OpenAPI
//!
//! Three extensions, read back by [`routes`] — for the invariant tests, and for
//! `record_plan`, which refuses a plan aimed at a route that does not exist:
//!
//! - [`REQUIRES`]: the action the caller's role must allow, as `Action::name` spells it
//!   — the same token the audit log records.
//!   Absent only where [`PUBLIC`] says so.
//! - [`PUBLIC`]: `true` on a route that answers without authentication.
//! - [`PREVIEW`]: on every route that changes something — does it follow the preview
//!   protocol (`?apply=true`)?

use utoipa::openapi::path::Operation;
use utoipa::openapi::response::ResponseBuilder;
use utoipa::openapi::schema::{
    AdditionalProperties, ArrayItems, KnownFormat, ObjectBuilder, SchemaFormat, Type,
};
use utoipa::openapi::{Content, Ref, RefOr, Schema};
use utoipa::{Modify, PartialSchema, ToSchema};

/// The action an operation's caller must be allowed.
pub const REQUIRES: &str = "x-hlb-requires";

/// 🔴 An operation reachable WITHOUT authentication.
///
/// For a route that changes something, justified in one case only: the request comes
/// from someone who does not have an account yet, and carries its own authorization.
/// Sign-up is exactly that — the invitation, single-use and verified in a transaction,
/// IS the authorization.
///
/// ⚠️ Doubt goes to private. A route made public by inattention opens the whole system,
/// and nothing would say so.
pub const PUBLIC: &str = "x-hlb-public";

/// Does this route follow the preview protocol (`?apply=true`)?
///
/// ## 🔴 The criterion, and why it is not "every route"
///
/// The preview exists for the actions that **touch the infrastructure**: install, back
/// up, delete. There, knowing what will happen before it happens is vital — that is the
/// whole point.
///
/// A **configuration** route has nothing to preview: writing the brand name or setting a
/// logo is idempotent, side-effect free and immediately reversible. Forcing a preview on
/// it would be a round trip for nothing, and the habit of clicking twice would drain the
/// protection of its meaning where it matters.
///
/// ⚠️ Doubt goes to `true`: better a useless preview than an action triggered by visiting
/// a screen.
pub const PREVIEW: &str = "x-hlb-preview";

/// Who calls a read route from outside this repository, on a route no screen requests.
/// The exemption sits on the handler, where every reader of it sees it.
pub const CLIENT: &str = "x-hlb-client";

/// A file answered as it is: an image, a typeface.
pub struct Binary;

impl PartialSchema for Binary {
    fn schema() -> RefOr<Schema> {
        ObjectBuilder::new()
            .schema_type(Type::String)
            .format(Some(SchemaFormat::KnownFormat(KnownFormat::Binary)))
            .into()
    }
}

impl ToSchema for Binary {}

#[derive(utoipa::OpenApi)]
#[openapi(
    info(
        title = "Homelabus controller",
        description = "The controller's HTTP API. Every refusal answers `ErrorBody`; an \
                       action route answers its plan, and acts only with `?apply=true`."
    ),
    components(schemas(hlb_api::ErrorBody))
)]
pub struct ApiDoc;

/// The document, every route in it.
///
/// ⚠️ `Refusals` is applied here and not as a `modifiers(...)` of [`ApiDoc`]: those run
/// when `ApiDoc::openapi()` is built, before a single route has been added to it, and
/// would modify an empty document.
pub fn document() -> utoipa::openapi::OpenApi {
    let mut doc = crate::api::api().split_for_parts().1;
    Refusals.modify(&mut doc);
    Present.modify(&mut doc);
    crate::limits::Bounds.modify(&mut doc);
    doc
}

/// The document as JSON, built once: what [`crate::extract::Json`] reads bounds from.
pub fn as_json() -> &'static serde_json::Value {
    static JSON: std::sync::OnceLock<serde_json::Value> = std::sync::OnceLock::new();
    JSON.get_or_init(|| serde_json::to_value(document()).unwrap_or_default())
}

/// Marks every field of every schema a response reaches as required.
///
/// `utoipa` leaves a field out of `required` when it is an `Option` or carries
/// `#[serde(default)]` — both about what DESERIALISING tolerates. The server serialises
/// every field every time, so the generated client wrote `domain?: string | null` for a
/// key that is never absent, and a screen would test for two kinds of nothing. Absence
/// on the wire would take `skip_serializing_if`, which the crates serving these types
/// refuse (`tests::no_field_on_the_wire_is_left_out`); `null` says "none" instead.
///
/// A schema only requests reach keeps what `utoipa` computed: there, `serde(default)`
/// really does mean the client may leave the field out.
struct Present;

impl Modify for Present {
    fn modify(&self, doc: &mut utoipa::openapi::OpenApi) {
        let mut queue = Vec::new();
        for item in doc.paths.paths.values_mut() {
            for op in operations(item) {
                for response in op.responses.responses.values_mut() {
                    let RefOr::T(response) = response else {
                        continue;
                    };
                    for content in response.content.values_mut() {
                        let RefOr::T(content) = content else { continue };
                        if let Some(schema) = &mut content.schema {
                            require_every_field(schema, &mut queue);
                        }
                    }
                }
            }
        }
        let Some(components) = doc.components.as_mut() else {
            return;
        };
        let mut done = std::collections::BTreeSet::new();
        while let Some(name) = queue.pop() {
            if !done.insert(name.clone()) {
                continue;
            }
            if let Some(schema) = components.schemas.get_mut(&name) {
                require_every_field(schema, &mut queue);
            }
        }
    }
}

/// Requires every property of `schema` and of the objects inlined in it, and pushes the
/// components it references onto `queue`.
fn require_every_field(schema: &mut RefOr<Schema>, queue: &mut Vec<String>) {
    let schema = match schema {
        RefOr::Ref(r) => {
            if let Some(name) = r.ref_location.strip_prefix("#/components/schemas/") {
                queue.push(name.to_string());
            }
            return;
        }
        RefOr::T(schema) => schema,
    };
    match schema {
        Schema::Object(o) => {
            o.required = o.properties.keys().cloned().collect();
            for property in o.properties.values_mut() {
                require_every_field(property, queue);
            }
            if let Some(AdditionalProperties::RefOr(extra)) = o.additional_properties.as_deref_mut()
            {
                require_every_field(extra, queue);
            }
        }
        Schema::Array(a) => {
            if let ArrayItems::RefOrSchema(items) = &mut a.items {
                require_every_field(items, queue);
            }
        }
        Schema::OneOf(s) => s
            .items
            .iter_mut()
            .for_each(|s| require_every_field(s, queue)),
        Schema::AllOf(s) => s
            .items
            .iter_mut()
            .for_each(|s| require_every_field(s, queue)),
        Schema::AnyOf(s) => s
            .items
            .iter_mut()
            .for_each(|s| require_every_field(s, queue)),
        // `Schema` is `#[non_exhaustive]`: a kind added upstream is left as generated,
        // and `the_committed_document_is_the_generated_one` shows the difference.
        _ => {}
    }
}

/// Says, on every operation, what a refusal answers.
///
/// Written once here rather than on 68 handlers because it is true of all of them by
/// construction: every JSON handler's error is an `ApiError`, which answers
/// `ErrorBody` — `error::tests` refuses a handler that could answer anything else. An
/// operation that answers otherwise declares its own `default`, and keeps it.
///
/// Also fills a response's description when the handler gave none: OpenAPI requires
/// one, and the status's reason phrase is the honest minimum.
struct Refusals;

impl Modify for Refusals {
    fn modify(&self, doc: &mut utoipa::openapi::OpenApi) {
        let refusal = ResponseBuilder::new()
            .description(
                "Refused or failed: the status says which, the body says why, in a \
                 sentence for a person.",
            )
            .content(
                "application/json",
                Content::new(Some(RefOr::Ref(Ref::from_schema_name(
                    hlb_api::ErrorBody::name(),
                )))),
            )
            .build();
        for item in doc.paths.paths.values_mut() {
            for op in operations(item) {
                let responses = &mut op.responses.responses;
                responses
                    .entry("default".to_string())
                    .or_insert_with(|| refusal.clone().into());
                for (status, response) in responses.iter_mut() {
                    let RefOr::T(response) = response else {
                        continue;
                    };
                    if response.description.is_empty() {
                        response.description = reason(status);
                    }
                }
            }
        }
    }
}

fn reason(status: &str) -> String {
    status
        .parse::<u16>()
        .ok()
        .and_then(|s| axum::http::StatusCode::from_u16(s).ok())
        .and_then(|s| s.canonical_reason())
        .unwrap_or(status)
        .to_string()
}

/// Every operation of a path, whatever its verb.
pub fn operations(item: &mut utoipa::openapi::PathItem) -> Vec<&mut Operation> {
    [
        &mut item.get,
        &mut item.put,
        &mut item.post,
        &mut item.delete,
        &mut item.options,
        &mut item.head,
        &mut item.patch,
        &mut item.trace,
        &mut item.query,
    ]
    .into_iter()
    .filter_map(Option::as_mut)
    .chain(item.additional_operations.values_mut())
    .collect()
}

/// A route as the document declares it.
#[derive(Debug, Clone)]
pub struct Route {
    pub path: String,
    /// `GET`, `POST`…
    pub verb: String,
    /// [`REQUIRES`], as `Action::name` spells it.
    pub requires: Option<String>,
    /// [`PUBLIC`].
    pub public: bool,
    /// [`PREVIEW`]: present on a route that changes something, absent on a read.
    pub preview: Option<bool>,
    /// [`CLIENT`].
    pub client: Option<String>,
}

impl Route {
    /// Does it change anything? What the verb says, since the router serves nothing
    /// else under a read verb.
    pub fn mutates(&self) -> bool {
        self.verb != "GET"
    }
}

/// Every route the router serves, read back from the document, in path order.
pub fn routes() -> &'static [Route] {
    static ROUTES: std::sync::OnceLock<Vec<Route>> = std::sync::OnceLock::new();
    ROUTES.get_or_init(|| {
        let mut doc = document();
        let mut out = Vec::new();
        for (path, item) in doc.paths.paths.iter_mut() {
            let verbs = [
                ("GET", &item.get),
                ("PUT", &item.put),
                ("POST", &item.post),
                ("DELETE", &item.delete),
                ("PATCH", &item.patch),
            ];
            for (verb, op) in verbs {
                let Some(op) = op else { continue };
                let ext = |name: &str| op.extensions.as_ref().and_then(|e| e.get(name)).cloned();
                out.push(Route {
                    path: path.clone(),
                    verb: verb.to_string(),
                    requires: ext(REQUIRES).and_then(|v| v.as_str().map(str::to_string)),
                    public: ext(PUBLIC).and_then(|v| v.as_bool()).unwrap_or(false),
                    preview: ext(PREVIEW).and_then(|v| v.as_bool()),
                    client: ext(CLIENT).and_then(|v| v.as_str().map(str::to_string)),
                });
            }
        }
        out
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Where the web interface reads the document from: its client is generated from
    /// this file, at build time, without a running controller.
    fn committed() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../web/openapi.json")
    }

    fn generated() -> String {
        // Through a `Value`, whose keys come out sorted: `utoipa` keeps extensions in a
        // `HashMap`, and the file came out in a different order on every run.
        let mut text = serde_json::to_string_pretty(&as_json()).expect("the document serialises");
        text.push('\n');
        text
    }

    #[test]
    fn the_committed_document_is_the_generated_one() {
        // A route or a field changed here and not in `web/` leaves the interface
        // type-checking against an API that no longer exists, and the first sign is a
        // screen failing at run time — the failure the generated client is for.
        let fresh = generated();
        if std::env::var_os("HLB_UPDATE_OPENAPI").is_some() {
            std::fs::write(committed(), &fresh).expect("write web/openapi.json");
        }
        let on_disk = std::fs::read_to_string(committed()).unwrap_or_default();
        assert!(
            on_disk == fresh,
            "web/openapi.json is not the document this code generates — regenerate it \
             with `HLB_UPDATE_OPENAPI=1 cargo test -p hlb-controller --lib \
             the_committed_document_is_the_generated_one`, and commit it with the change"
        );
    }

    /// The document as JSON, which is what a validator reads.
    fn as_json() -> serde_json::Value {
        serde_json::to_value(document()).expect("the document is JSON")
    }

    /// Every component schema closed against keys it does not declare.
    ///
    /// 🔴 Without this, a schema missing a field validates a body that carries it: JSON
    /// Schema allows what it does not mention. A `judged!` type whose schema forgot its
    /// rules, a field added to a struct and not to the document — both would pass a test
    /// that only checks what IS declared, and the generated client would never see the
    /// key.
    ///
    /// `unevaluatedProperties` rather than `additionalProperties`, because it sees
    /// through `allOf` — the shape `#[serde(flatten)]` takes. The base of an `allOf` is
    /// left open, or it would refuse the keys its sibling adds; wherever it is used on
    /// its own, the reference is pointed at a closed copy instead.
    fn closed(doc: &serde_json::Value) -> serde_json::Value {
        use serde_json::{json, Value};

        fn bases(v: &Value, out: &mut std::collections::BTreeSet<String>) {
            match v {
                Value::Object(m) => {
                    if let Some(Value::Array(members)) = m.get("allOf") {
                        for member in members {
                            if let Some(Value::String(r)) = member.get("$ref") {
                                out.insert(r.clone());
                            }
                        }
                    }
                    m.values().for_each(|c| bases(c, out));
                }
                Value::Array(a) => a.iter().for_each(|c| bases(c, out)),
                _ => {}
            }
        }

        fn close(v: &mut Value, member: bool, bases: &std::collections::BTreeSet<String>) {
            let Value::Object(m) = v else { return };
            if let Some(Value::String(r)) = m.get_mut("$ref") {
                if !member && bases.contains(r.as_str()) {
                    *r = format!("{r}__closed");
                }
            }
            let composed = m.contains_key("allOf");
            for (key, child) in m.iter_mut() {
                match (key.as_str(), child) {
                    ("allOf", Value::Array(members)) => {
                        members.iter_mut().for_each(|c| close(c, true, bases));
                    }
                    ("oneOf" | "anyOf" | "prefixItems", Value::Array(members)) => {
                        members.iter_mut().for_each(|c| close(c, false, bases));
                    }
                    ("properties", Value::Object(props)) => {
                        props.values_mut().for_each(|c| close(c, false, bases));
                    }
                    ("items" | "additionalProperties", c) => close(c, false, bases),
                    _ => {}
                }
            }
            if !member && (composed || m.contains_key("properties")) {
                m.insert("unevaluatedProperties".into(), Value::Bool(false));
            }
        }

        let mut schemas = doc["components"]["schemas"].clone();
        let mut found = std::collections::BTreeSet::new();
        bases(doc, &mut found);
        let Value::Object(map) = &mut schemas else {
            panic!("no component schemas")
        };
        for r in &found {
            let name = r.trim_start_matches("#/components/schemas/");
            map.insert(
                format!("{name}__closed"),
                json!({ "allOf": [{ "$ref": r }], "unevaluatedProperties": false }),
            );
        }
        for (name, schema) in map.iter_mut() {
            if name.ends_with("__closed") {
                continue;
            }
            let member = found.contains(&format!("#/components/schemas/{name}"));
            close(schema, member, &found);
        }
        json!({ "schemas": schemas, "bases": found })
    }

    /// A concrete URI for a route of the demo installation, or `None` if its template
    /// has parameters this table does not fill.
    ///
    /// ⚠️ A table, so a list — but one with a floor: a parameterised read route missing
    /// here fails the test by name instead of going unchecked.
    fn sample(path: &str) -> Option<String> {
        let concrete = match path {
            "/api/apps/{name}" | "/api/apps/{name}/detail" | "/api/apps/{name}/versions" => {
                path.replace("{name}", "gitea")
            }
            "/api/catalog/{name}/icon" => path.replace("{name}", "gitea"),
            "/api/nodes/{address}/detail" => path.replace("{address}", "10.0.0.1:8421"),
            "/api/export/{what}" => path.replace("{what}", "audit"),
            "/api/themes/{name}/font/{family}" => path
                .replace("{name}", "Maison")
                .replace("{family}", "proportional"),
            "/api/v1/metrics/series" => format!("{path}?q=up"),
            p if p.contains('{') => return None,
            p => p.to_string(),
        };
        Some(concrete)
    }

    /// The demo installation, the way `--demo` builds it, plus what it leaves empty and
    /// a route needs to answer something: a logo, a theme with a typeface, an
    /// invitation, a recorded plan. With the token of a person, so the routes about
    /// "me" have someone to describe.
    async fn demo(dir: &std::path::Path) -> (axum::Router, String) {
        let st = hlb_state::State::in_memory().await.expect("state");
        crate::demo::seed(&st).await.expect("demo data");
        let (token, stored) =
            hlb_types::generate_token("lena-laptop", hlb_types::Role::Admin, [9u8; 32]);
        st.store_token(&stored).await.expect("token");
        st.set_token_user("lena-laptop", Some("lena"))
            .await
            .expect("binding");
        let logo = std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../catalog/gitea/icon.png"),
        )
        .expect("a PNG to use as a logo");
        st.set_logo(Some(&logo)).await.expect("logo");
        std::fs::write(dir.join("Maison.ttf"), b"font bytes").expect("typeface");

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        st.create_invitation(
            "a1b2c3d4e5f6",
            "lena",
            "standard",
            now as i64,
            7 * 86_400,
            1,
            Some("for Lou"),
        )
        .await
        .expect("invitation");
        st.save_named_plan(
            "gitea-again",
            "POST",
            "/api/apps/gitea/install",
            "{}",
            "install gitea",
            "lena",
            None,
        )
        .await
        .expect("plan");
        let mut s = crate::api::tests::base_state(std::sync::Arc::new(st), false);
        s.demo = true;
        s.public_status = true;
        let catalog = std::sync::Arc::new(
            hlb_catalog::Catalog::load(&s.catalog_dir).expect("the repository's catalog"),
        );
        s.privd = hlb_privd::Privd::new(s.state.clone())
            .with_mail(None, &s.mail_domain)
            .with_catalog(Some(catalog.clone()))
            .with_published(
                std::sync::Arc::new(tokio::sync::RwLock::new(crate::demo::alerts(now as i64))),
                std::sync::Arc::new(tokio::sync::RwLock::new(crate::demo::drifts())),
            );
        s.catalog = Some(catalog);
        *s.last_poll.write().await = crate::demo::nodes(now);
        s.themes_dir = dir.to_path_buf();
        s.custom_themes = vec![hlb_api::CustomTheme {
            name: "Maison".into(),
            base: "dark".into(),
            background: "#0F1216".into(),
            surface: "#171B21".into(),
            raised_surface: "#1E242B".into(),
            border: "#2A323B".into(),
            text: "#E6EAEF".into(),
            muted_text: "#96A1AD".into(),
            accent: "#7B8CFF".into(),
            on_accent: "#0F1216".into(),
            ok: "#38C7B4".into(),
            attention: "#FFC94D".into(),
            critical: "#F05C5C".into(),
            info: "#7EA4F8".into(),
            typeface: Some("Maison.ttf".into()),
            typeface_mono: None,
            scale: None,
        }];
        (crate::api::router(std::sync::Arc::new(s)), token)
    }

    #[tokio::test]
    async fn every_read_route_answers_what_the_document_declares() {
        // 🔴 `responses(...)` is written by hand on each handler, and nothing in the
        // compiler checks it against what the handler returns: it is free to lie. This
        // calls every read route of the demo installation and holds the REAL answer to
        // the declaration — status, content type and, for JSON, the body against its
        // schema, closed against keys it does not declare.
        use tower::ServiceExt;

        // Answers other than 200, each with why. The answer is still checked against
        // what the document declares for it.
        let not_ok = [
            (
                "/auth/signin",
                "a browser navigation to PocketID, not configured in a test",
            ),
            (
                "/auth/return_to",
                "a browser navigation back from PocketID, not configured in a test",
            ),
        ];

        // An empty list validates against any item schema: these two are empty for a
        // reason the demo cannot remove, and every other list must hold something.
        let empty = [
            (
                "/api/tasks",
                "Swarm's own tasks, and the demo runs no orchestrator; `TaskSummary` is \
                 validated inside `/api/apps/{name}/detail`",
            ),
            (
                "/api/apps/{name}/versions",
                "an app's history read from the Git mirror, which the demo has none of",
            ),
        ];

        let doc = as_json();
        let components = closed(&doc);
        let dir = tempfile::tempdir().expect("tmp");
        let (app, token) = demo(dir.path()).await;

        let mut checked = 0;
        let mut validated = 0;
        for r in routes().iter().filter(|r| !r.mutates()) {
            let uri = sample(&r.path).unwrap_or_else(|| {
                panic!("{}: no sample URI — add its parameters to `sample`", r.path)
            });
            let resp = app
                .clone()
                .oneshot(
                    axum::http::Request::builder()
                        .uri(&uri)
                        .header("Authorization", format!("Bearer {token}"))
                        .body(axum::body::Body::empty())
                        .expect("request"),
                )
                .await
                .expect("response");
            let status = resp.status();
            let content_type = resp
                .headers()
                .get(axum::http::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            let bytes = axum::body::to_bytes(resp.into_body(), 1 << 24)
                .await
                .expect("body");

            let excused = not_ok.iter().any(|(p, _)| *p == r.path);
            assert!(
                excused || status == axum::http::StatusCode::OK,
                "GET {uri} answers {status} on the demo installation: {}",
                String::from_utf8_lossy(&bytes)
            );

            let op = &doc["paths"][&r.path]["get"];
            let declared = op["responses"]
                .get(status.as_str())
                .or_else(|| op["responses"].get("default"))
                .unwrap_or_else(|| panic!("GET {uri}: {status} is not declared"));
            let media = content_type.split(';').next().unwrap_or("").trim();
            let content = declared["content"]
                .as_object()
                .and_then(|c| {
                    c.iter()
                        .find(|(k, _)| k.split(';').next().unwrap_or("").trim() == media)
                })
                .map(|(_, v)| v)
                .unwrap_or_else(|| {
                    panic!(
                        "GET {uri} answers {status} as `{content_type}`, which its \
                         declaration does not list: {}",
                        declared["content"]
                    )
                });
            checked += 1;

            if media != "application/json" {
                continue;
            }
            let body: serde_json::Value =
                serde_json::from_slice(&bytes).expect("a JSON body that parses");
            let is_empty = body.as_array().is_some_and(Vec::is_empty);
            assert_eq!(
                is_empty,
                empty.iter().any(|(p, _)| *p == r.path),
                "GET {uri}: an empty list checks no item against its schema — fill the \
                 demo, or say in `empty` why it cannot be"
            );
            let root = serde_json::json!({
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "components": { "schemas": components["schemas"] },
                "allOf": [ content["schema"] ],
            });
            let mut schema = root;
            // The response's own schema references components the same way the
            // components do: close it as well.
            if let Some(serde_json::Value::Array(members)) = schema.get_mut("allOf") {
                for m in members.iter_mut() {
                    if let Some(serde_json::Value::String(r)) = m.get_mut("$ref") {
                        if components["bases"]
                            .as_array()
                            .is_some_and(|b| b.iter().any(|x| x == r.as_str()))
                        {
                            r.push_str("__closed");
                        }
                    }
                }
            }
            let validator = jsonschema::draft202012::new(&schema)
                .unwrap_or_else(|e| panic!("GET {uri}: the schema does not compile: {e}"));
            let errors: Vec<String> = validator
                .iter_errors(&body)
                .take(5)
                .map(|e| format!("{} at {}", e, e.instance_path()))
                .collect();
            assert!(
                errors.is_empty(),
                "GET {uri} answers what its schema does not describe:\n  {}",
                errors.join("\n  ")
            );
            validated += 1;
        }
        // Forty-three read routes on 2026-10-05, thirty-three of them JSON.
        assert!(checked >= 40, "only {checked} read routes checked");
        assert!(validated >= 30, "only {validated} bodies validated");
    }

    #[test]
    fn every_path_parameter_is_the_one_its_template_names() {
        // `utoipa` names a path parameter after the template, a handler binds it under
        // any name it likes, and a declared `params(...)` can name a third thing. A
        // parameter the template does not have is one the client sends nowhere; one the
        // template has and the document omits is a `{name}` the client never fills.
        let doc = as_json();
        let paths = doc["paths"].as_object().expect("paths");
        for (path, item) in paths {
            let mut in_template: Vec<&str> = path
                .split('{')
                .skip(1)
                .filter_map(|p| p.split('}').next())
                .collect();
            in_template.sort_unstable();
            for (verb, op) in item.as_object().expect("path item") {
                let mut declared: Vec<&str> = op["parameters"]
                    .as_array()
                    .map(|ps| {
                        ps.iter()
                            .filter(|p| p["in"] == "path")
                            .filter_map(|p| p["name"].as_str())
                            .collect()
                    })
                    .unwrap_or_default();
                declared.sort_unstable();
                assert_eq!(declared, in_template, "{verb} {path}");
            }
        }
    }

    #[test]
    fn no_route_is_added_beside_the_document() {
        // 🔴 axum cannot enumerate its router, so the tests walk the document — and a
        // route added with a bare `.route(` is served while being in no document: none
        // of the invariant tests sees it, no client is generated for it. Three are
        // legitimately outside, each said where it is written.
        let source = include_str!("api.rs");
        let code = source.split("\n#[cfg(test)]").next().unwrap_or("");
        let bare: Vec<&str> = code
            .lines()
            .map(str::trim)
            .filter(|l| !l.starts_with("//") && l.contains(&format!(".route{}", "(")))
            .collect();
        assert_eq!(
            bare,
            [
                r#"api.route("/api/openapi.json", get(openapi_document))"#,
                r#".route("/", get(ui_index))"#,
                r#".route("/{*file}", get(ui_file))"#,
            ],
            "a route outside `routes!` escapes every test that walks the document"
        );
        let elsewhere: Vec<String> = ["accounts.rs", "actions.rs", "portal.rs", "signin.rs"]
            .iter()
            .flat_map(|f| {
                std::fs::read_to_string(
                    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                        .join("src")
                        .join(f),
                )
                .map(|t| {
                    t.lines()
                        .filter(|l| !l.starts_with("//") && l.contains(&format!(".route{}", "(")))
                        .map(|l| format!("{f}: {}", l.trim()))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default()
            })
            .collect();
        assert!(elsewhere.is_empty(), "{elsewhere:?}");
    }

    #[test]
    fn no_field_on_the_wire_is_left_out() {
        // 🔴 `Present` declares every response field required, because the server always
        // sends it. A `skip_serializing_if` makes that a lie the compiler cannot see: the
        // generated type promises a key the body does not carry, and a screen reads
        // `undefined` where its type said `string | null`. Every crate deriving
        // `ToSchema` is walked — found by reading the sources, not named here.
        fn files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
            for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
                let path = entry.path();
                if path.is_dir() {
                    files(&path, out);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    out.push(path);
                }
            }
        }
        let attribute = format!("{}_if=", "skip_serializing");
        let crates = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let mut wire = Vec::new();
        let mut left_out = Vec::new();
        for krate in std::fs::read_dir(&crates).expect("crates/").flatten() {
            let mut sources = Vec::new();
            files(&krate.path().join("src"), &mut sources);
            let texts: Vec<(std::path::PathBuf, String)> = sources
                .into_iter()
                .filter_map(|p| std::fs::read_to_string(&p).ok().map(|t| (p, t)))
                .collect();
            if !texts.iter().any(|(_, t)| t.contains("ToSchema")) {
                continue;
            }
            wire.push(krate.file_name());
            for (path, text) in &texts {
                for (n, line) in text.lines().enumerate() {
                    if line.replace(' ', "").contains(&attribute) {
                        left_out.push(format!("{}:{}", path.display(), n + 1));
                    }
                }
            }
        }
        // hlb-api, hlb-controller and hlb-users on 2026-10-05.
        assert!(wire.len() >= 3, "only {wire:?} derive ToSchema");
        assert!(
            left_out.is_empty(),
            "a response field the server leaves out, while the document says it is always \
             there — send `null` instead:\n  {}",
            left_out.join("\n  ")
        );
    }

    #[test]
    fn no_two_operations_share_an_id() {
        // 🔴 utoipa names an operation after its handler's function, and the generated
        // client keys operations by that name: `roles::list` beside `accounts::list`
        // gave `/api/accounts` the roles' response type, and only `svelte-check`
        // noticed — on 2026-10-18, the day the second `list` was written.
        let doc = serde_json::to_value(document()).expect("document");
        let mut seen: std::collections::BTreeMap<String, Vec<String>> = Default::default();
        let mut operations = 0;
        for (path, item) in doc["paths"].as_object().expect("paths") {
            for (verb, op) in item.as_object().expect("item") {
                if let Some(id) = op["operationId"].as_str() {
                    operations += 1;
                    seen.entry(id.to_string())
                        .or_default()
                        .push(format!("{} {path}", verb.to_uppercase()));
                }
            }
        }
        assert!(operations > 80, "the walk found {operations} operations");
        let shared: Vec<_> = seen.into_iter().filter(|(_, at)| at.len() > 1).collect();
        assert!(shared.is_empty(), "one id, several operations: {shared:?}");
    }

    #[test]
    fn no_two_wire_types_share_a_name() {
        // 🔴 The document keys its schemas by the type's NAME, and a second type of the
        // same name replaces the first without a word: on 2026-10-18 an assertion's
        // `Verdict` took the restorability's place, and the interface's types for the
        // backups tab changed under it — only `svelte-check` noticed, by luck of a
        // comparison. Every crate's sources are read for what derives `ToSchema` (and
        // what `judged!` wraps), under the name `schema(as = …)` gives it.
        fn files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
            for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
                let path = entry.path();
                if path.is_dir() {
                    files(&path, out);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    out.push(path);
                }
            }
        }
        let named = |line: &str| -> Option<String> {
            let rest = line
                .trim_start()
                .trim_start_matches("pub ")
                .trim_start_matches("pub(crate) ");
            let rest = rest
                .strip_prefix("struct ")
                .or_else(|| rest.strip_prefix("enum "))?;
            let name: String = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            (!name.is_empty()).then_some(name)
        };
        let derive = format!("{}Schema", "To");
        let crates = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let mut found: Vec<(String, String)> = Vec::new();
        for krate in std::fs::read_dir(&crates).expect("crates/").flatten() {
            let mut sources = Vec::new();
            files(&krate.path().join("src"), &mut sources);
            for path in sources {
                let Ok(text) = std::fs::read_to_string(&path) else {
                    continue;
                };
                let code = text.split("\n#[cfg(test)]").next().unwrap_or("");
                let lines: Vec<&str> = code.lines().collect();
                for (n, line) in lines.iter().enumerate() {
                    let t = line.trim_start();
                    // Written by hand: `impl ToSchema for Binary`.
                    if let Some(rest) = t.strip_prefix("impl ") {
                        let rest = rest.trim_start_matches("utoipa::");
                        if let Some(ty) = rest.strip_prefix(&format!("{derive} for ")) {
                            let name: String =
                                ty.chars().take_while(|c| c.is_alphanumeric()).collect();
                            found.push((name, format!("{}:{}", path.display(), n + 1)));
                        }
                        continue;
                    }
                    // A derive may span lines: read it to its `)]`.
                    let derives = t.starts_with("#[derive(") && {
                        let mut d = String::new();
                        for l in &lines[n..] {
                            d.push_str(l);
                            if l.contains(")]") {
                                break;
                            }
                        }
                        d.contains(&derive)
                    };
                    if !t.starts_with("judged! {") && !derives {
                        continue;
                    }
                    // The next item is the type: past its attributes and its comments,
                    // however long.
                    let mut alias = None;
                    for next in &lines[n + 1..] {
                        if let Some(a) = next.trim_start().strip_prefix("#[schema(as = ") {
                            alias = Some(a.trim_end_matches(")]").to_string());
                        }
                        if let Some(name) = named(next) {
                            let name = alias.take().unwrap_or(name);
                            // The macro's own definition names `$ty`.
                            if !name.starts_with('$') {
                                found.push((name, format!("{}:{}", path.display(), n + 1)));
                            }
                            break;
                        }
                    }
                }
            }
        }
        let mut twice: Vec<String> = Vec::new();
        for (i, (name, at)) in found.iter().enumerate() {
            if let Some((_, first)) = found[..i].iter().find(|(n, _)| n == name) {
                twice.push(format!("{name}: {first} and {at}"));
            }
        }
        assert!(
            twice.is_empty(),
            "one name, two wire types — the document keeps one:\n  {}",
            twice.join("\n  ")
        );
        // 🔴 The floor: every schema the document holds is one this scan found, or a
        // shape it misses would let the next collision through.
        let doc = as_json();
        let missed: Vec<&String> = doc["components"]["schemas"]
            .as_object()
            .expect("schemas")
            .keys()
            .filter(|k| !found.iter().any(|(n, _)| n == *k))
            .collect();
        assert!(
            missed.is_empty(),
            "schemas the scan did not find: {missed:?}"
        );
    }

    #[test]
    fn a_response_field_is_required_and_a_request_field_keeps_its_default() {
        let doc = as_json();
        let schemas = &doc["components"]["schemas"];
        let required = |schema: &str| -> Vec<String> {
            schemas[schema]["required"]
                .as_array()
                .map(|r| {
                    r.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default()
        };
        // An `Option` and a `serde(default)` field, both answered.
        assert!(required("Preferences").contains(&"theme".to_string()));
        assert!(required("Preferences").contains(&"available".to_string()));
        // Only ever sent: `pinned` has a default, and a client may leave it out.
        assert!(!required("AnnouncementRequest").contains(&"pinned".to_string()));
    }

    #[tokio::test]
    async fn the_document_is_served_as_it_is_generated() {
        use tower::ServiceExt;
        let st = hlb_state::State::in_memory().await.expect("state");
        let app = crate::api::router(std::sync::Arc::new(crate::api::tests::base_state(
            std::sync::Arc::new(st),
            false,
        )));
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/api/openapi.json")
                    .body(axum::body::Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 24)
            .await
            .expect("body");
        let served: serde_json::Value = serde_json::from_slice(&bytes).expect("JSON");
        assert_eq!(served, as_json());
    }
}
