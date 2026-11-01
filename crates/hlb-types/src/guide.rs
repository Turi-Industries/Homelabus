//! Manual actions and hints, declared per app.
//!
//! ## The two families
//!
//! | Family | Examples | Handling |
//! |---|---|---|
//! | **Outside the system** | DNS, port forwarding, rDNS | irreducibly manual |
//! | **Inside the application** | create the admin, close sign-ups | **automatable** |
//!
//! The second is the one usually handled badly: it gets documented as if it were
//! manual when most of those steps can be scripted. Hence [`Automation`], attempted
//! **before** falling back to manual.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// An app's `guide.yaml` file.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Guide {
    #[serde(default)]
    pub steps: Vec<GuideStep>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GuideStep {
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub phase: Phase,
    #[serde(default)]
    pub severity: Severity,
    /// Text shown to the user. `{{ domain }}` templates are resolved in it.
    #[serde(default)]
    pub body: String,
    /// Steps that must be handled before this one.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub after: Vec<String>,
    /// Automation attempts, tried in order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub automate: Vec<Automation>,
    /// How to observe that it is done.
    #[serde(default)]
    pub verify: Verify,
    /// A direct link to the page in question - not "go into the settings".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deeplink: Option<String>,
    /// Periodic re-check, e.g. "24h" or "7d". Catches drift: a deleted DNS record, a
    /// home router that loses its NAT rule after a firmware update. The controller's
    /// nightly pass checks again every handled step this old, and opens it again when
    /// its check now fails (`hlb_engine::recheck_guides`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recheck: Option<String>,
}

/// The shortest `recheck`: the pass that reads it runs once a night.
pub const MIN_RECHECK_S: i64 = 86_400;

impl GuideStep {
    /// `recheck` in seconds: `Nh` or `Nd`.
    pub fn recheck_secs(&self) -> Result<Option<i64>, String> {
        let Some(r) = self.recheck.as_deref() else {
            return Ok(None);
        };
        let r = r.trim();
        let unit = match r.chars().last() {
            Some('h') => 3_600,
            Some('d') => 86_400,
            _ => {
                return Err(format!(
                    "recheck \"{r}\": a number of hours or days, 24h or 7d"
                ))
            }
        };
        r[..r.len() - 1]
            .parse::<i64>()
            .ok()
            .and_then(|n| n.checked_mul(unit))
            .filter(|s| *s >= 0)
            .map(Some)
            .ok_or_else(|| format!("recheck \"{r}\": a number of hours or days, 24h or 7d"))
    }

    /// Does it block the installation?
    pub fn is_blocking(&self) -> bool {
        self.severity == Severity::Blocking
    }

    /// Can we attempt to handle it ourselves?
    pub fn is_automatable(&self) -> bool {
        !self.automate.is_empty()
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum Phase {
    /// A prerequisite: no point deploying without it.
    PreInstall,
    #[default]
    PostInstall,
    /// On first opening the app.
    FirstLogin,
    /// Recurring.
    Maintenance,
    /// Only when crossing a version boundary.
    PostUpgrade,
    /// After a restore of the app's data, once it runs again: run by `hlb backup
    /// restore`, never by an install — a search index rebuilt from the database, the
    /// files restored checked against their blocks.
    PostRestore,
}

impl Phase {
    /// Is a step of this phase part of the install plan?
    pub fn at_install(self) -> bool {
        match self {
            Self::PreInstall
            | Self::PostInstall
            | Self::FirstLogin
            | Self::Maintenance
            | Self::PostUpgrade => true,
            Self::PostRestore => false,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum Severity {
    /// The install does not start until this is done.
    Blocking,
    /// The app is deployed but marked incomplete.
    #[default]
    Required,
    Recommended,
    /// A tip, which a person may dismiss.
    Tip,
}

/// A way of doing the step without human intervention.
///
/// Order matters: the ladder is walked down until something works. Environment
/// variables first - declarative and checkable - and the web interface dead last.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(
    tag = "method",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum Automation {
    /// Level 1: environment variables. The most reliable.
    Env {
        vars: std::collections::BTreeMap<String, String>,
    },
    /// Level 2: a command inside the container (`gitea admin`, `occ`…).
    Exec {
        command: Vec<String>,
        /// A companion's container, by its name under `companions`; absent, the app's
        /// own. Fluxer rebuilds its search from its api, not from the proxy in front.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        service: Option<String>,
        /// Detection command, so that what is already done is not replayed.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        probe: Option<Vec<String>>,
        /// Pattern expected in `probe`'s output when it is already done.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        probe_matches: Option<String>,
    },
    /// Level 3: the app's own API, by its service name on the overlay — calls made in
    /// order, since a first-run wizard is several. A body takes the binding tokens and
    /// the generated secrets (`{{ secret.admin-password }}`) at run time, like `env`:
    /// never in the plan.
    Api {
        /// Absent: the first ingress's port.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        port: Option<u16>,
        /// A GET saying it is done already, so a step is never replayed — most
        /// first-run endpoints refuse a second call, or worse, accept it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        probe: Option<ApiProbe>,
        calls: Vec<ApiCall>,
    },
    /// One write in the app's own PostgreSQL database, its values BOUND as parameters
    /// (`$1`, `$2`… for `params`, in order), never written into the statement — for
    /// what only a command line writes otherwise: an argument is readable in `ps` by
    /// every account of the node, and Gitea's CLI takes its sign-in secret no other way.
    /// `params` take the binding tokens and generated secrets at run time, like a body.
    Sql {
        statement: String,
        params: Vec<String>,
        /// A query on the same parameters whose first column is `true` once the write
        /// is there: read before (nothing is written twice) and after (it took).
        probe: String,
        /// Restart the app after writing, for one that reads the value at its start
        /// only.
        #[serde(default)]
        restart: bool,
    },
}

/// One request of an `api` automation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApiCall {
    // `verb` and not `method`: the serde tag distinguishing the automations is already
    // called `method`, and a field of the same name would shadow it.
    pub verb: String,
    pub path: String,
    /// JSON.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
}

/// A GET whose JSON says an `api` automation's work is there already.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApiProbe {
    pub path: String,
    /// A JSON pointer into the answer.
    pub pointer: String,
    /// The value it holds once done, written as JSON: `true`, `"done"`.
    pub equals: String,
}

/// A value an answer's JSON holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JsonValue {
    /// A JSON pointer into the answer.
    pub pointer: String,
    /// The value it holds once done, written as JSON: `true`, `"done"`.
    pub equals: String,
}

/// How to establish that a step is done.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(
    tag = "type",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum Verify {
    /// 🔴 No check is possible: the user attests, and the UI must say so.
    ///
    /// A deliberate default: a step with no declared `verify` is **not** treated as
    /// verifiable. Better to display "not verified" than to let someone believe.
    #[default]
    Attest,
    /// A DNS record resolves.
    Dns {
        record: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expect_contains: Option<String>,
    },
    /// A URL answers with one of the expected codes — and, with `expectJson`, says in
    /// its body what the step changed. Its first answer is judged: a redirect is not
    /// followed, since a sign-in page answering 200 says nothing of the app behind it.
    Http {
        url: String,
        #[serde(default = "http_ok")]
        expect_status: Vec<u16>,
        /// A value in the JSON answer. A post-install step expecting a 2xx needs one:
        /// an app answering is what its install already established, not that an
        /// administrator exists.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expect_json: Option<JsonValue>,
    },
    /// A port is reachable.
    Tcp { target: String },
    /// A command inside the container.
    Exec {
        command: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expect_contains: Option<String>,
    },
}

impl Verify {
    /// Can the system establish this on its own?
    pub fn is_automatic(&self) -> bool {
        !matches!(self, Self::Attest)
    }

    pub fn kind(&self) -> &'static str {
        match self {
            Self::Attest => "attest",
            Self::Dns { .. } => "dns",
            Self::Http { .. } => "http",
            Self::Tcp { .. } => "tcp",
            Self::Exec { .. } => "exec",
        }
    }
}

fn http_ok() -> Vec<u16> {
    vec![200, 204]
}

/// Substitutes the templates in a guide text.
pub fn render(template: &str, vars: &[(&str, &str)]) -> String {
    let mut out = template.to_string();
    for (k, v) in vars {
        out = out.replace(&format!("{{{{ {k} }}}}"), v);
        out = out.replace(&format!("{{{{{k}}}}}"), v);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const GITEA: &str = r#"
steps:
  - id: dns-record
    title: Create the DNS record
    phase: pre-install
    severity: blocking
    body: |
      Add at your registrar:
        {{ domain }}  CNAME  {{ cluster_fqdn }}
    verify:
      type: dns
      record: "{{ domain }}"
    recheck: 24h

  - id: close-registration
    title: Close sign-ups
    after: [create-admin]
    severity: blocking
    automate:
      - method: env
        vars:
          GITEA__service__DISABLE_REGISTRATION: "true"
      - method: exec
        command: [gitea, admin, config, set, service.DISABLE_REGISTRATION, "true"]
    verify:
      type: http
      url: "https://{{ domain }}/user/sign_up"
      expectStatus: [403, 404]

  - id: backup-codes
    title: Print the recovery codes
    severity: recommended
"#;

    fn guide() -> Guide {
        serde_yaml_ng::from_str(GITEA).expect("guide should parse")
    }

    #[test]
    fn a_full_guide_parses() {
        let g = guide();
        assert_eq!(g.steps.len(), 3);
        assert_eq!(g.steps[0].phase, Phase::PreInstall);
        assert!(g.steps[0].is_blocking());
    }

    #[test]
    fn the_automation_ladder_keeps_its_order() {
        // Env first, exec as a fallback. The order is significant.
        let g = guide();
        let steps = &g.steps[1].automate;
        assert!(matches!(steps[0], Automation::Env { .. }));
        assert!(matches!(steps[1], Automation::Exec { .. }));
        assert!(g.steps[1].is_automatable());
    }

    #[test]
    fn a_step_without_verify_is_only_attested() {
        // 🔴 A deliberate default: better to display "not verified" than to suggest
        // something was checked.
        let g = guide();
        assert_eq!(g.steps[2].verify, Verify::Attest);
        assert!(!g.steps[2].verify.is_automatic());
    }

    #[test]
    fn automatic_verifications_are_recognised() {
        let g = guide();
        assert!(g.steps[0].verify.is_automatic());
        assert_eq!(g.steps[0].verify.kind(), "dns");
        assert_eq!(g.steps[1].verify.kind(), "http");
    }

    #[test]
    fn http_verification_defaults_to_success_codes() {
        let v: Verify =
            serde_yaml_ng::from_str("type: http\nurl: https://x.fr").expect("analysable");
        match v {
            Verify::Http { expect_status, .. } => assert_eq!(expect_status, vec![200, 204]),
            _ => panic!("mauvaise variante"),
        }
    }

    #[test]
    fn ordering_between_steps_is_declared() {
        assert_eq!(guide().steps[1].after, vec!["create-admin"]);
    }

    #[test]
    fn templates_are_rendered() {
        let out = render(
            "{{ domain }} CNAME {{ cluster_fqdn }}",
            &[
                ("domain", "git.example.fr"),
                ("cluster_fqdn", "hlb.example.fr"),
            ],
        );
        assert_eq!(out, "git.example.fr CNAME hlb.example.fr");
    }

    #[test]
    fn an_unknown_field_is_rejected() {
        // A typo in a guide must not be silently ignored.
        let y = "steps:\n  - id: x\n    title: y\n    severty: blocking\n";
        assert!(serde_yaml_ng::from_str::<Guide>(y).is_err());
    }

    #[test]
    fn an_unknown_verification_type_is_rejected() {
        let y = "steps:\n  - id: x\n    title: y\n    verify:\n      type: telepathie\n";
        assert!(serde_yaml_ng::from_str::<Guide>(y).is_err());
    }
}
