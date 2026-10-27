//! What a running app must keep true, read by its EFFECT.
//!
//! ## 🔴 Judged by the effect, never by the line that sets it
//!
//! A sibling installation's production had `SIGNUPS_ALLOWED=true` and an open Termix
//! registration while its files said otherwise: a variable removed by hand, a setting
//! brought back by a restore, a `config.json` beating the environment. Reading the
//! manifest again says what was MEANT. An assertion asks the running app — its own
//! public endpoint, the environment its task was really started with, its own
//! database — and is run every night, so a door reopened after the install is seen.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// One property of the running app.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Assertion {
    /// Stable: the last result is stored under it.
    pub id: String,
    /// What is true while it passes, as a sentence: "nobody signs up without an
    /// invitation". Said as it is when it does not.
    pub holds: String,
    pub check: Check,
    /// What a person does when it does not hold, said beside it. A door reported open
    /// with no way given to close it stays open: Seafile's default administrator was
    /// reported on the lab for nine days.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fix: Option<String>,
}

/// How an assertion is read.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(
    tag = "type",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum Check {
    /// A GET to the app itself, by its service name on the overlay: the app's own
    /// answer, never the ingress's — a portal in front would answer for it. Redirects
    /// are not followed: a `303` to the sign-in page IS the answer.
    Http {
        path: String,
        /// Absent: the first ingress's port.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        port: Option<u16>,
        #[serde(default = "ok_status")]
        status: Vec<u16>,
        /// A JSON pointer into the body (`/settings/disableUserRegistration`), read
        /// with `equals`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pointer: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        equals: Option<serde_json::Value>,
        /// Text the body must carry.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        contains: Option<String>,
        /// The `Host` sent, in place of the service's name: a name the app was told
        /// nothing of, to see it refused (Django's `ALLOWED_HOSTS`).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        host: Option<String>,
    },
    /// A variable of the environment the running task was started with — Swarm's
    /// record of it, which a `docker service update --env-rm` changes and the
    /// manifest does not.
    Env { name: String, equals: String },
    /// A read-only query on the app's own database: the first column of its first row,
    /// as text.
    Sql {
        query: String,
        /// Which of the app's databases, when it has several (Seafile has three).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        database: Option<String>,
        equals: String,
    },
}

impl Check {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Http { .. } => "http",
            Self::Env { .. } => "env",
            Self::Sql { .. } => "sql",
        }
    }
}

fn ok_status() -> Vec<u16> {
    vec![200]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_kind_parses_and_an_unknown_field_is_refused() {
        let a: Vec<Assertion> = serde_yaml_ng::from_str(
            r#"
- id: signups-closed
  holds: nobody signs up without an invitation
  check:
    type: http
    path: /api/config
    pointer: /settings/disableUserRegistration
    equals: true
- id: hints-off
  holds: no password hint is kept
  check: { type: env, name: PASSWORD_HINTS_ALLOWED, equals: "false" }
- id: no-default-admin
  holds: the image's default administrator does not exist
  check:
    type: sql
    database: ccnet_db
    query: SELECT count(*) FROM EmailUser WHERE email = 'me@example.com'
    equals: "0"
"#,
        )
        .expect("assertions should parse");
        assert_eq!(
            a.iter().map(|a| a.check.kind()).collect::<Vec<_>>(),
            ["http", "env", "sql"]
        );
        match &a[0].check {
            Check::Http { status, equals, .. } => {
                assert_eq!(status, &[200]);
                assert_eq!(equals, &Some(serde_json::Value::Bool(true)));
            }
            other => panic!("{other:?}"),
        }
        let typo = "id: x\nholds: y\ncheck: { type: env, name: A, equal: b }\n";
        assert!(serde_yaml_ng::from_str::<Assertion>(typo).is_err());
    }
}
