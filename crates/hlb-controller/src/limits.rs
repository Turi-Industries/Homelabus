//! What each field of a request accepts, declared once.
//!
//! [`BOUNDS`] is written into the OpenAPI document ([`Bounds`]), and the body extractor
//! ([`crate::extract::Json`]) refuses a body that steps outside the document — so what
//! the interface's fields allow, what the document says and what the server takes are
//! one table, not three. A field without a bound fails
//! `tests::every_field_a_request_carries_is_bounded`.
//!
//! 🔴 Refused, never trimmed to fit. The invitation route used to clamp: ninety days
//! became thirty and nothing said so — the link expired two months before the person
//! who made it expected.

use serde_json::Value;
use utoipa::openapi::schema::Schema;
use utoipa::openapi::RefOr;
use utoipa::Modify;

/// What one field accepts.
#[derive(Debug, Clone, Copy)]
pub enum Bound {
    /// Text of at most this many characters.
    Text(usize),
    /// A whole number between the two, both included.
    Range(i64, i64),
    /// One of these words.
    OneOf(&'static [&'static str]),
}

/// A short free text: a reason, a note, a name for something.
pub const SHORT: usize = 200;
/// A paragraph a person writes: an announcement, an update to one.
pub const PARAGRAPH: usize = 4_000;
/// A domain name, as DNS allows it.
pub const DOMAIN: usize = 253;
/// A name a person picks for a thing: a theme, a plan, a token.
pub const NAME: usize = 60;
/// An account name: it becomes an address's local part and a PocketID identifier.
pub const ACCOUNT: usize = 50;
/// An address's local part, as SMTP allows it.
pub const LOCAL_PART: usize = 64;
/// An invitation's bounds, shared with `hlb user invite`.
pub use hlb_api::invitation::{
    MAX_S as INVITATION_MAX_S, MIN_S as INVITATION_MIN_S, USES_MAX as INVITATION_USES_MAX,
};
/// More replicas than a homelab has machines times a few is a typo, not a plan.
pub const REPLICAS_MAX: i64 = 20;
/// An announcement shown for at most a year: past that it is part of the page.
pub const ANNOUNCEMENT_MAX_S: i64 = 365 * 86_400;
/// A plan's recorded body: what a preview sent, never a file.
pub const PLAN_BODY: usize = 64 * 1_024;

const ROLES: &[&str] = &["viewer", "user", "operator", "admin"];

/// A role's id, as `hlb_types::access::valid_role_id` takes it.
pub const ROLE_ID: usize = 40;
/// A count a role allows: the unlimited role's is `u32::MAX`, "no limit" as a number.
pub const COUNT_MAX: i64 = u32::MAX as i64;
/// A storage quota: a pebibyte is past any homelab's disks.
pub const QUOTA_MAX: i64 = 1 << 50;

/// Every bounded field: the schema, the field, what it accepts.
///
/// ⚠️ A schema is named as `utoipa` names it — the type's own name. An entry naming a
/// field the document does not have fails `tests::every_bound_lands_on_a_field`.
pub const BOUNDS: &[(&str, &str, Bound)] = &[
    ("AnnouncementRequest", "title", Bound::Text(120)),
    ("AnnouncementRequest", "body", Bound::Text(PARAGRAPH)),
    (
        "AnnouncementRequest",
        "level",
        Bound::OneOf(&["info", "maintenance", "warning", "incident"]),
    ),
    ("AnnouncementRequest", "audience", Bound::OneOf(ROLES)),
    (
        "AnnouncementRequest",
        "duration_s",
        Bound::Range(60, ANNOUNCEMENT_MAX_S),
    ),
    ("FollowUpRequest", "body", Bound::Text(PARAGRAPH)),
    (
        "AsideRequest",
        "for_s",
        Bound::Range(1, hlb_api::issues::ASIDE_MAX_S),
    ),
    ("MuteRequest", "for_s", Bound::Range(1, hlb_api::MUTE_MAX_S)),
    ("MuteRequest", "reason", Bound::Text(SHORT)),
    ("Brand", "name", Bound::Text(NAME)),
    ("Brand", "product", Bound::Text(NAME)),
    ("Brand", "footer", Bound::Text(SHORT)),
    ("Brand", "default_theme", Bound::Text(NAME)),
    ("Confirmation", "confirmed", Bound::Text(SHORT)),
    ("InstallRequest", "domain", Bound::Text(DOMAIN)),
    ("InstallRequest", "mail_domain", Bound::Text(DOMAIN)),
    // Zero reaches the handler, which refuses it as the stop it is, and says to stop instead.
    ("ScaleRequest", "replicas", Bound::Range(0, REPLICAS_MAX)),
    ("DestinationRequest", "location", Bound::Text(SHORT)),
    ("DestinationRequest", "classes", Bound::Text(NAME)),
    (
        "DestinationRequest",
        "credentials_secret",
        Bound::Text(SHORT),
    ),
    ("Request", "account", Bound::Text(ACCOUNT)),
    ("Request", "mailbox", Bound::Text(DOMAIN)),
    ("Request", "name", Bound::Text(NAME)),
    // A role's id: a PocketID group's name, `hlb_types::access::valid_role_id`.
    ("InvitationRequest", "role", Bound::Text(ROLE_ID)),
    // PocketID's bounds for a group's name.
    ("RoleRequest", "name", Bound::Text(50)),
    ("RoleRequest", "level", Bound::OneOf(ROLES)),
    ("MailLimits", "max_mailboxes", Bound::Range(0, COUNT_MAX)),
    (
        "MailLimits",
        "max_permanent_aliases",
        Bound::Range(0, COUNT_MAX),
    ),
    (
        "MailLimits",
        "max_temporary_aliases",
        Bound::Range(0, COUNT_MAX),
    ),
    // "No limit" is still a number: the unlimited role's is the largest there is.
    ("MailLimits", "max_duration_s", Bound::Range(0, i64::MAX)),
    ("MailLimits", "quota_bytes", Bound::Range(0, QUOTA_MAX)),
    ("QuotaRequest", "bytes", Bound::Range(1, QUOTA_MAX)),
    ("PersonQuotaRequest", "bytes", Bound::Range(1, QUOTA_MAX)),
    ("InvitationRequest", "note", Bound::Text(SHORT)),
    (
        "InvitationRequest",
        "duration_s",
        Bound::Range(INVITATION_MIN_S, INVITATION_MAX_S),
    ),
    (
        "InvitationRequest",
        "max_uses",
        Bound::Range(1, INVITATION_USES_MAX),
    ),
    ("CreateMailboxRequest", "local", Bound::Text(LOCAL_PART)),
    ("DefaultMailboxRequest", "local", Bound::Text(LOCAL_PART)),
    // PocketID's own bounds (`UserCreateDto`): past them it refuses the whole update.
    ("NamesRequest", "first_name", Bound::Text(50)),
    ("NamesRequest", "last_name", Bound::Text(50)),
    ("NamesRequest", "display_name", Bound::Text(100)),
    (
        "NodeRequest",
        "availability",
        Bound::OneOf(&["active", "pause", "drain"]),
    ),
    ("NodeRequest", "confirmed", Bound::Text(SHORT)),
    ("PlanRequest", "name", Bound::Text(NAME)),
    (
        "PlanRequest",
        "method",
        Bound::OneOf(&["POST", "PUT", "PATCH", "DELETE"]),
    ),
    ("PlanRequest", "path", Bound::Text(SHORT)),
    ("PlanRequest", "body", Bound::Text(PLAN_BODY)),
    ("PlanRequest", "summary", Bound::Text(PARAGRAPH)),
    ("PlanRequest", "note", Bound::Text(SHORT)),
    ("HomeTile", "w", Bound::Range(1, hlb_api::TILE_W_MAX as i64)),
    ("HomeTile", "h", Bound::Range(1, hlb_api::TILE_H_MAX as i64)),
    ("ThemeRequest", "theme", Bound::Text(NAME)),
    ("SignupRequest", "invitation", Bound::Text(SHORT)),
    ("SignupRequest", "name", Bound::Text(ACCOUNT)),
    ("SignupRequest", "display_name", Bound::Text(120)),
    // Bitwarden's contract: it writes the site in the description, however long.
    ("CreationRequest", "description", Bound::Text(PARAGRAPH)),
    ("CreationRequest", "domain", Bound::Text(DOMAIN)),
];

/// Writes [`BOUNDS`] into the document's schemas.
pub struct Bounds;

impl Modify for Bounds {
    fn modify(&self, doc: &mut utoipa::openapi::OpenApi) {
        let Some(components) = doc.components.as_mut() else {
            return;
        };
        for (schema, field, bound) in BOUNDS {
            let Some(RefOr::T(Schema::Object(o))) = components.schemas.get_mut(*schema) else {
                continue;
            };
            let Some(RefOr::T(Schema::Object(p))) = o.properties.get_mut(*field) else {
                continue;
            };
            match bound {
                Bound::Text(max) => p.max_length = Some(*max),
                Bound::Range(min, max) => {
                    p.minimum = Some((*min as f64).into());
                    p.maximum = Some((*max as f64).into());
                }
                Bound::OneOf(words) => {
                    let mut values: Vec<Value> = words.iter().map(|w| Value::from(*w)).collect();
                    // A field that may be left out says so in its enum too, or `null` would
                    // read as a word outside the list.
                    if serde_json::to_value(&p.schema_type)
                        .is_ok_and(|t| t.to_string().contains("null"))
                    {
                        values.push(Value::Null);
                    }
                    p.enum_values = Some(values);
                }
            }
        }
    }
}

/// What is wrong with `body`, read against the schema `name` in the document `doc` —
/// one sentence per field out of bounds, empty when there is nothing.
pub fn refusals(doc: &Value, name: &str, body: &Value) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(schema) = doc.pointer(&format!("/components/schemas/{name}")) {
        check(doc, schema, body, "", &mut out);
    }
    out
}

fn check(doc: &Value, schema: &Value, v: &Value, at: &str, out: &mut Vec<String>) {
    if let Some(r) = schema["$ref"].as_str() {
        if let Some(target) = r.strip_prefix('#').and_then(|p| doc.pointer(p)) {
            check(doc, target, v, at, out);
        }
        return;
    }
    // A value matches `allOf` when it matches every branch, `oneOf` and `anyOf` when it
    // matches one — a tagged enum is a `oneOf` of its variants. `null` matches the
    // `Option<T>` of a component.
    if let Some(branches) = schema["allOf"].as_array() {
        branches.iter().for_each(|b| check(doc, b, v, at, out));
        return;
    }
    for key in ["oneOf", "anyOf"] {
        if let Some(branches) = schema[key].as_array() {
            let tried: Vec<Vec<String>> = branches
                .iter()
                .filter(|b| !(v.is_null() ^ (b["type"] == "null")))
                .map(|b| {
                    let mut found = Vec::new();
                    check(doc, b, v, at, &mut found);
                    found
                })
                .collect();
            if !tried.iter().any(Vec::is_empty) {
                // The branch the value came closest to says what is wrong with it.
                if let Some(closest) = tried.into_iter().min_by_key(Vec::len) {
                    out.extend(closest);
                }
            }
            return;
        }
    }
    let field = if at.is_empty() {
        "the body".to_string()
    } else {
        format!("\"{at}\"")
    };
    if let Some(words) = schema["enum"].as_array() {
        if !words.contains(v) {
            let listed: Vec<String> = words
                .iter()
                .filter(|w| !w.is_null())
                .map(Value::to_string)
                .collect();
            out.push(format!(
                "{field} is {v}: one of {} is expected",
                listed.join(", ")
            ));
            return;
        }
    }
    match v {
        Value::String(s) => {
            if let Some(max) = schema["maxLength"].as_u64() {
                let n = s.chars().count() as u64;
                if n > max {
                    out.push(format!("{field} is {n} characters long: at most {max}"));
                }
            }
        }
        Value::Number(n) => {
            let n = n.as_f64().unwrap_or(f64::NAN);
            let (min, max) = (schema["minimum"].as_f64(), schema["maximum"].as_f64());
            if min.is_some_and(|m| n < m) || max.is_some_and(|m| n > m) {
                let range = match (min, max) {
                    (Some(a), Some(b)) => format!("between {a} and {b}"),
                    (Some(a), None) => format!("at least {a}"),
                    (None, Some(b)) => format!("at most {b}"),
                    (None, None) => String::new(),
                };
                out.push(format!("{field} is {n}: {range} is expected"));
            }
        }
        Value::Object(map) => {
            if let Some(properties) = schema["properties"].as_object() {
                for (k, sub) in properties {
                    if let Some(x) = map.get(k) {
                        let path = if at.is_empty() {
                            k.clone()
                        } else {
                            format!("{at}.{k}")
                        };
                        check(doc, sub, x, &path, out);
                    }
                }
            }
        }
        Value::Array(items) => {
            for (i, x) in items.iter().enumerate() {
                check(doc, &schema["items"], x, &format!("{at}[{i}]"), out);
            }
        }
        Value::Null | Value::Bool(_) => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn document() -> Value {
        serde_json::to_value(crate::openapi::document()).expect("json")
    }

    /// The components `v` references, pushed onto `queue`.
    fn refs(v: &Value, queue: &mut Vec<String>) {
        match v {
            Value::Object(m) => {
                if let Some(r) = m.get("$ref").and_then(Value::as_str) {
                    queue.push(r.trim_start_matches("#/components/schemas/").to_string());
                }
                m.values().for_each(|x| refs(x, queue));
            }
            Value::Array(a) => a.iter().for_each(|x| refs(x, queue)),
            _ => {}
        }
    }

    /// Every schema a request body reaches, by name, through references and lists.
    fn requested(doc: &Value) -> Vec<String> {
        let mut queue: Vec<String> = Vec::new();
        for item in doc["paths"].as_object().expect("paths").values() {
            for op in item.as_object().expect("operations").values() {
                refs(&op["requestBody"], &mut queue);
            }
        }
        let mut seen: Vec<String> = Vec::new();
        while let Some(name) = queue.pop() {
            if seen.contains(&name) {
                continue;
            }
            refs(&doc["components"]["schemas"][&name], &mut queue);
            seen.push(name);
        }
        seen.sort();
        seen
    }

    #[test]
    fn every_field_a_request_carries_is_bounded() {
        // 🔴 An unbounded field is a field the interface cannot limit either: the
        // invitation's note took a megabyte, and its duration took ninety days the
        // server then cut to thirty without a word.
        let doc = document();
        let schemas = requested(&doc);
        assert!(
            schemas.len() >= 20,
            "the walk found {} request schemas",
            schemas.len()
        );
        let mut unbounded = Vec::new();
        let mut fields = 0;
        for name in &schemas {
            let Some(props) = doc["components"]["schemas"][name]["properties"].as_object() else {
                continue;
            };
            for (field, p) in props {
                let kind = p["type"].to_string();
                let text = kind.contains("string");
                let whole = kind.contains("integer");
                if !text && !whole {
                    continue;
                }
                fields += 1;
                let bounded = p.get("enum").is_some()
                    || (text && p.get("maxLength").is_some())
                    || (whole && p.get("minimum").is_some() && p.get("maximum").is_some());
                if !bounded {
                    unbounded.push(format!("{name}.{field}"));
                }
            }
        }
        assert!(fields >= 40, "the walk found {fields} fields");
        assert_eq!(unbounded, Vec::<String>::new());
    }

    #[test]
    fn every_bound_lands_on_a_field() {
        let doc = document();
        let stale: Vec<String> = BOUNDS
            .iter()
            .filter(|(s, f, _)| doc["components"]["schemas"][*s]["properties"][*f].is_null())
            .map(|(s, f, _)| format!("{s}.{f}"))
            .collect();
        assert_eq!(stale, Vec::<String>::new());
    }

    #[test]
    fn a_body_out_of_bounds_is_refused_field_by_field() {
        let doc = document();
        let body = serde_json::json!({
            "note": "x".repeat(SHORT + 1),
            "max_uses": INVITATION_USES_MAX + 1,
            "duration_s": INVITATION_MIN_S,
            "role": "r".repeat(ROLE_ID + 1),
        });
        let found = refusals(&doc, "InvitationRequest", &body);
        assert_eq!(found.len(), 3, "{found:?}");
        assert!(found
            .iter()
            .any(|r| r.contains("\"note\"") && r.contains("at most 200")));
        assert!(found.iter().any(|r| r.contains("\"max_uses\"")));
        assert!(found
            .iter()
            .any(|r| r.contains("\"role\"") && r.contains("at most 40")));
        // Within bounds, and through a list of components: nothing to say.
        let home = serde_json::json!({ "home": [{ "widget": "apps", "w": 4, "h": 3 }] });
        assert_eq!(refusals(&doc, "HomeRequest", &home), Vec::<String>::new());
        let wide = serde_json::json!({ "home": [{ "widget": "apps", "w": 5, "h": 1 }] });
        assert_eq!(refusals(&doc, "HomeRequest", &wide).len(), 1);
    }
}
