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

/// Le fichier `guide.yaml` d'une app.
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
    /// Comment constater que c'est fait.
    #[serde(default)]
    pub verify: Verify,
    /// A direct link to the page in question - not "go into the settings".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deeplink: Option<String>,
    /// Periodic re-check, e.g. "24h". Catches drift: a deleted DNS record, a home
    /// router that loses its NAT rule after a firmware update.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recheck: Option<String>,
}

impl GuideStep {
    /// Bloque-t-elle l'installation ?
    pub fn is_blocking(&self) -> bool {
        self.severity == Severity::Blocking
    }

    /// Peut-on tenter de s'en occuper tout seul ?
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
    /// Uniquement au franchissement d'une version.
    PostUpgrade,
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
    /// Simple astuce, rejetable.
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
    /// Niveau 1 : variables d'environnement. Le plus fiable.
    Env {
        vars: std::collections::BTreeMap<String, String>,
    },
    /// Niveau 2 : commande dans le conteneur (`gitea admin`, `occ`…).
    Exec {
        command: Vec<String>,
        /// Detection command, so that what is already done is not replayed.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        probe: Option<Vec<String>>,
        /// Pattern expected in `probe`'s output when it is already done.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        probe_matches: Option<String>,
    },
    /// Level 3: a call to the app's API.
    Api {
        // `verb` and not `method`: the serde tag distinguishing the variants is
        // already called `method`, and a field of the same name would shadow it.
        verb: String,
        path: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        body: Option<String>,
    },
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
    /// A URL answers with one of the expected codes.
    Http {
        url: String,
        #[serde(default = "http_ok")]
        expect_status: Vec<u16>,
    },
    /// Un port est joignable.
    Tcp { target: String },
    /// Commande dans le conteneur.
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

/// Remplace les gabarits d'un texte de guide.
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
        // §4.6bis — env d'abord, exec en repli. L'ordre est significatif.
        let g = guide();
        let etapes = &g.steps[1].automate;
        assert!(matches!(etapes[0], Automation::Env { .. }));
        assert!(matches!(etapes[1], Automation::Exec { .. }));
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
