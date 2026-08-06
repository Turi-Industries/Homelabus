//! Actions manuelles et astuces, déclarées par app (§4.6, §4.6bis).
//!
//! Jusqu'ici les guides étaient codés en dur dans le résolveur : le format existait
//! dans le plan mais pas dans le produit. Une app du catalogue ne pouvait donc pas
//! décrire ses propres prérequis.
//!
//! ## Les deux familles
//!
//! | Famille | Exemples | Traitement |
//! |---|---|---|
//! | **Hors du système** | DNS, redirection de port, rDNS | irréductiblement manuel |
//! | **Dans l'application** | créer l'admin, fermer les inscriptions | **automatisable** |
//!
//! La seconde est celle qu'on traite mal d'habitude : on la documente comme si elle
//! était manuelle alors que la plupart de ces étapes se scriptent. D'où
//! [`Automation`], essayé **avant** de basculer en manuel.

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
    /// Texte affiché à l'utilisateur. Les gabarits `{{ domain }}` y sont résolus.
    #[serde(default)]
    pub body: String,
    /// Étapes qui doivent être traitées avant celle-ci.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub after: Vec<String>,
    /// Tentatives d'automatisation, essayées dans l'ordre (§4.6bis).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub automate: Vec<Automation>,
    /// Comment constater que c'est fait.
    #[serde(default)]
    pub verify: Verify,
    /// Lien direct vers la page concernée — pas « va dans les paramètres ».
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deeplink: Option<String>,
    /// Re-vérification périodique, ex. « 24h ». Attrape la dérive : un
    /// enregistrement DNS supprimé, une box qui perd son NAT après une MAJ.
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
    /// Prérequis : inutile de déployer sans.
    PreInstall,
    #[default]
    PostInstall,
    /// À la première ouverture de l'app.
    FirstLogin,
    /// Récurrent.
    Maintenance,
    /// Uniquement au franchissement d'une version.
    PostUpgrade,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum Severity {
    /// L'installation ne démarre pas tant que ce n'est pas fait.
    Blocking,
    /// L'app est déployée mais marquée incomplète.
    #[default]
    Required,
    Recommended,
    /// Simple astuce, rejetable.
    Tip,
}

/// Une façon de faire l'étape sans intervention humaine.
///
/// L'ordre compte : on descend l'échelle jusqu'à ce que quelque chose marche
/// (§4.6bis). Variables d'environnement d'abord — déclaratif et vérifiable —,
/// interface web en tout dernier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "method", rename_all = "kebab-case", rename_all_fields = "camelCase", deny_unknown_fields)]
pub enum Automation {
    /// Niveau 1 : variables d'environnement. Le plus fiable.
    Env {
        vars: std::collections::BTreeMap<String, String>,
    },
    /// Niveau 2 : commande dans le conteneur (`gitea admin`, `occ`…).
    Exec {
        command: Vec<String>,
        /// Commande de détection, pour ne pas rejouer ce qui est déjà fait.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        probe: Option<Vec<String>>,
        /// Motif attendu dans la sortie de `probe` si c'est déjà fait.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        probe_matches: Option<String>,
    },
    /// Niveau 3 : appel à l'API de l'app.
    Api {
        // `verb` et non `method` : l'étiquette serde qui distingue les variantes
        // s'appelle déjà `method`, et un champ homonyme la masquerait.
        verb: String,
        path: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        body: Option<String>,
    },
}

/// Comment constater qu'une étape est faite.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "kebab-case", rename_all_fields = "camelCase", deny_unknown_fields)]
pub enum Verify {
    /// 🔴 Aucune vérification possible : l'utilisateur atteste, et l'UI doit le dire.
    ///
    /// Défaut volontaire : une étape sans `verify` déclaré n'est **pas** considérée
    /// comme vérifiable. Mieux vaut afficher « non vérifié » que laisser croire.
    #[default]
    Attest,
    /// Un enregistrement DNS résout.
    Dns {
        record: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expect_contains: Option<String>,
    },
    /// Une URL répond avec l'un des codes attendus.
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
    /// Le système sait-il constater ça tout seul ?
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
    title: Créer l'enregistrement DNS
    phase: pre-install
    severity: blocking
    body: |
      Ajoute chez ton registrar :
        {{ domain }}  CNAME  {{ cluster_fqdn }}
    verify:
      type: dns
      record: "{{ domain }}"
    recheck: 24h

  - id: close-registration
    title: Fermer les inscriptions
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
    title: Imprimer les codes de récupération
    severity: recommended
"#;

    fn guide() -> Guide {
        serde_yaml_ng::from_str(GITEA).expect("guide analysable")
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
        // 🔴 Défaut volontaire : mieux vaut afficher « non vérifié » que laisser
        // croire qu'on a contrôlé quelque chose.
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
        let v: Verify = serde_yaml_ng::from_str("type: http\nurl: https://x.fr")
            .expect("analysable");
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
            &[("domain", "git.example.fr"), ("cluster_fqdn", "hlb.example.fr")],
        );
        assert_eq!(out, "git.example.fr CNAME hlb.example.fr");
    }

    #[test]
    fn an_unknown_field_is_rejected() {
        // Une faute de frappe dans un guide ne doit pas être ignorée en silence.
        let y = "steps:\n  - id: x\n    title: y\n    severty: blocking\n";
        assert!(serde_yaml_ng::from_str::<Guide>(y).is_err());
    }

    #[test]
    fn an_unknown_verification_type_is_rejected() {
        let y = "steps:\n  - id: x\n    title: y\n    verify:\n      type: telepathie\n";
        assert!(serde_yaml_ng::from_str::<Guide>(y).is_err());
    }
}
