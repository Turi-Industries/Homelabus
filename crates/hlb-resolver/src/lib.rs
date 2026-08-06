//! Le résolveur de capacités — le cœur du design (§4.3 du plan).
//!
//! Un manifest ne dit **jamais** « connecte-toi à postgres:5432 ». Il déclare un
//! besoin : `Capability::Database { engine: Postgres }`. Le résolveur transforme ce
//! besoin en actions concrètes.
//!
//! Conséquence : le même manifest fonctionne que Postgres soit local, sur un autre
//! nœud, derrière PgBouncer ou ailleurs. **C'est ce qui rend le système réellement
//! modulaire.**

pub mod graph;
pub mod plan;

use hlb_types::{Capability, ExposePolicy, Manifest};

pub use graph::{DependencyGraph, GraphError};
pub use plan::{Action, Plan};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Graph(#[from] GraphError),

    #[error(transparent)]
    Manifest(#[from] hlb_types::Error),

    #[error("paramètre « {0} » requis mais absent")]
    MissingParam(&'static str),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Les valeurs fournies au moment de l'installation, qui ne peuvent pas être dans le
/// manifest parce qu'elles dépendent de l'installation elle-même.
#[derive(Debug, Clone)]
pub struct InstallParams {
    /// Domaine complet choisi par l'utilisateur, ex. `git.example.fr`.
    pub domain: Option<String>,
    /// Domaine mail de base, pour les capacités `MailAccount`.
    pub mail_domain: Option<String>,
    pub health_timeout_secs: u64,
}

impl Default for InstallParams {
    fn default() -> Self {
        Self {
            domain: None,
            mail_domain: None,
            health_timeout_secs: 120,
        }
    }
}

impl InstallParams {
    pub fn with_domain(domain: impl Into<String>) -> Self {
        Self {
            domain: Some(domain.into()),
            ..Default::default()
        }
    }
}

/// Traduit un manifest + des paramètres d'installation en plan d'exécution.
///
/// L'ordre des actions n'est pas cosmétique : les dépendances (base, secrets, client
/// OIDC) doivent exister **avant** le déploiement du service qui les consomme.
pub fn resolve(m: &Manifest, params: &InstallParams) -> Result<Plan> {
    hlb_types::validate(m)?;

    let app = &m.metadata.name;
    let mut plan = Plan::default();

    // 1. Les prérequis, capacité par capacité.
    for cap in &m.spec.requires {
        resolve_capability(cap, app, params, &mut plan)?;
    }

    // 2. Le digest, s'il n'est pas déjà figé (§7).
    if !m.spec.image.is_pinned() {
        plan.push(Action::ResolveDigest {
            repo: m.spec.image.repo.clone(),
            tag: m.spec.image.tag.clone(),
        });
    }

    // 3. Le service lui-même.
    let mut constraints = Vec::new();
    if let Some(tier) = &m.spec.swarm.tier {
        // §2bis.2 — le placement découle du tier, jamais d'un nom de nœud en dur.
        constraints.push(format!("node.labels.tier=={tier}"));
    }

    plan.push(Action::DeployService {
        name: app.clone(),
        image: m.spec.image.reference(),
        replicas: m.spec.swarm.replicas,
        constraints,
        // §9 — les valeurs du manifest sont transmises telles quelles jusqu'à Swarm.
        hardening: m.spec.security.clone(),
        healthcheck: m.spec.swarm.healthcheck.clone(),
    });

    // 4. §4.7 — on attend la convergence avant de rendre la main.
    plan.push(Action::WaitHealthy {
        name: app.clone(),
        timeout_secs: params.health_timeout_secs,
    });

    // 5. L'exposition, en dernier.
    for ing in &m.spec.ingress {
        let host = render_host(&ing.host, params)?;

        // §4.6bis — `after-guide` interdit l'exposition publique tant que le guide
        // n'est pas validé. C'est ce qui ferme la fenêtre « premier inscrit = admin ».
        if ing.expose == ExposePolicy::AfterGuide {
            plan.push(Action::PendingGuideStep {
                id: format!("{app}-first-admin"),
                title: format!(
                    "Créer le compte administrateur de {app}, puis fermer les inscriptions"
                ),
                blocking: true,
            });
        }

        plan.push(Action::ConfigureIngress {
            host,
            service: app.clone(),
            port: ing.port,
            chain: ing.chain.clone(),
            public: ing.expose == ExposePolicy::Public,
        });
    }

    Ok(plan)
}

fn resolve_capability(
    cap: &Capability,
    app: &str,
    params: &InstallParams,
    plan: &mut Plan,
) -> Result<()> {
    // Le `match` est exhaustif : ajouter une variante à `Capability` fait échouer la
    // compilation ici. C'est exactement pourquoi le plan a retenu Rust (§1).
    match cap {
        Capability::Database { engine, name } => {
            let db = name.clone().unwrap_or_else(|| app.to_string());
            let secret = format!("{app}-db-password");

            // ⚠️ L'ordre compte : le mot de passe doit exister avant le rôle qui
            // l'utilise. L'inverse produisait une base impossible à créer.
            plan.push(Action::GenerateSecret {
                name: secret.clone(),
                purpose: format!("mot de passe du rôle {db}"),
            });
            plan.push(Action::ProvisionDatabase {
                engine: *engine,
                database: db.clone(),
                role: db.clone(),
                password_secret: secret,
            });
        }

        Capability::Cache { engine, dedicated } => {
            if *dedicated {
                plan.push(Action::DeployService {
                    name: format!("{app}-{}", engine.service_name()),
                    image: format!("{}:latest", engine.service_name()),
                    replicas: 1,
                    constraints: Vec::new(),
                    // Un cache dédié est durci comme tout le reste (§9).
                    hardening: hlb_types::SecuritySpec::default(),
                    healthcheck: None,
                });
            }
            plan.push(Action::GenerateSecret {
                name: format!("{app}-cache-password"),
                purpose: "authentification du cache".into(),
            });
        }

        Capability::Sso { redirect_paths, .. } => {
            // §5.2 — les URI de callback dépendent du domaine choisi à l'installation.
            // Jamais en dur dans le manifest.
            let domain = params
                .domain
                .as_ref()
                .ok_or(Error::MissingParam("domain"))?;

            let uris = redirect_paths
                .iter()
                .map(|p| format!("https://{domain}{p}"))
                .collect();

            plan.push(Action::CreateOidcClient {
                app: app.to_string(),
                redirect_uris: uris,
            });
            plan.push(Action::GenerateSecret {
                name: format!("{app}-oidc-secret"),
                purpose: "client secret OIDC".into(),
            });
        }

        Capability::Smtp => {
            plan.push(Action::GenerateSecret {
                name: format!("{app}-smtp-password"),
                purpose: "relais SMTP".into(),
            });
        }

        Capability::MailAccount { aliases, .. } => {
            let domain = params
                .mail_domain
                .as_ref()
                .ok_or(Error::MissingParam("mail_domain"))?;
            plan.push(Action::ProvisionMailAccount {
                address: format!("{app}@{domain}"),
                aliases: *aliases,
            });
        }

        Capability::Storage { name, path, tier, backup, .. } => {
            plan.push(Action::CreateVolume {
                name: format!("{app}-{name}"),
                path: path.clone(),
                tier: *tier,
                backup: *backup,
            });
        }
    }
    Ok(())
}

/// Remplace `{{ domain }}` par la valeur fournie à l'installation.
///
/// Volontairement minimal : le vrai moteur de templates (minijinja) arrivera avec le
/// rendu des fichiers compose. Ici, on ne veut qu'une substitution vérifiable.
fn render_host(tpl: &str, params: &InstallParams) -> Result<String> {
    if !tpl.contains("{{") {
        return Ok(tpl.to_string());
    }
    let domain = params
        .domain
        .as_ref()
        .ok_or(Error::MissingParam("domain"))?;
    Ok(tpl
        .replace("{{ domain }}", domain)
        .replace("{{domain}}", domain))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(extra: &str) -> Manifest {
        let y = format!(
            "apiVersion: hlb/v1\nkind: App\nmetadata: {{ name: gitea }}\n\
             spec:\n  image: {{ repo: gitea/gitea, tag: \"1.24\", digest: \"sha256:abc\" }}\n{extra}"
        );
        serde_yaml_ng::from_str(&y).expect("manifest de test")
    }

    #[test]
    fn database_becomes_isolated_db_plus_secret() {
        let m = manifest("  requires:\n    - kind: database\n      engine: postgres\n");
        let p = resolve(&m, &InstallParams::default()).expect("plan");

        assert!(p.actions.contains(&Action::ProvisionDatabase {
            engine: hlb_types::DbEngine::Postgres,
            database: "gitea".into(),
            role: "gitea".into(),
            password_secret: "gitea-db-password".into(),
        }));
        // §3.1 — un rôle par app, jamais de mot de passe réutilisé.
        assert!(p
            .actions
            .iter()
            .any(|a| matches!(a, Action::GenerateSecret { name, .. } if name == "gitea-db-password")));
    }

    #[test]
    fn redirect_uris_are_built_from_the_chosen_domain() {
        let m = manifest(
            "  requires:\n    - kind: sso\n      mode: native\n      \
             redirectPaths: [\"/user/oauth2/pocketid/callback\"]\n",
        );
        let p = resolve(&m, &InstallParams::with_domain("git.example.fr")).expect("plan");

        let uris = p
            .actions
            .iter()
            .find_map(|a| match a {
                Action::CreateOidcClient { redirect_uris, .. } => Some(redirect_uris.clone()),
                _ => None,
            })
            .expect("client OIDC planifié");

        assert_eq!(uris, vec!["https://git.example.fr/user/oauth2/pocketid/callback"]);
    }

    #[test]
    fn sso_without_domain_fails_early() {
        let m = manifest("  requires:\n    - kind: sso\n      mode: native\n");
        let err = resolve(&m, &InstallParams::default()).unwrap_err();
        assert!(matches!(err, Error::MissingParam("domain")), "{err}");
    }

    #[test]
    fn the_password_is_generated_before_the_role_that_uses_it() {
        let m = manifest("  requires:\n    - kind: database\n      engine: postgres\n");
        let p = resolve(&m, &InstallParams::default()).expect("plan");

        let secret = p.actions.iter().position(|a| matches!(a, Action::GenerateSecret { .. }))
            .expect("secret planifié");
        let db = p.actions.iter().position(|a| matches!(a, Action::ProvisionDatabase { .. }))
            .expect("base planifiée");

        assert!(secret < db, "sans mot de passe, le rôle ne peut pas être créé");
    }

    #[test]
    fn dependencies_come_before_the_service() {
        let m = manifest("  requires:\n    - kind: database\n      engine: postgres\n");
        let p = resolve(&m, &InstallParams::default()).expect("plan");

        let db = p
            .actions
            .iter()
            .position(|a| matches!(a, Action::ProvisionDatabase { .. }))
            .expect("base planifiée");
        let deploy = p
            .actions
            .iter()
            .position(|a| matches!(a, Action::DeployService { .. }))
            .expect("déploiement planifié");

        assert!(db < deploy, "la base doit exister avant le service");
    }

    #[test]
    fn after_guide_blocks_before_exposing() {
        let m = manifest(
            "  ingress:\n    - host: \"{{ domain }}\"\n      port: 3000\n      \
             expose: after-guide\n",
        );
        let p = resolve(&m, &InstallParams::with_domain("git.example.fr")).expect("plan");

        let guide = p
            .actions
            .iter()
            .position(|a| matches!(a, Action::PendingGuideStep { blocking: true, .. }))
            .expect("étape de guide bloquante");
        let ingress = p
            .actions
            .iter()
            .position(|a| matches!(a, Action::ConfigureIngress { .. }))
            .expect("ingress planifié");

        assert!(guide < ingress, "le guide passe avant l'exposition");
        assert_eq!(p.blocking_steps().len(), 1);
    }

    #[test]
    fn private_is_the_default_exposure() {
        let m = manifest("  ingress:\n    - host: git.example.fr\n      port: 3000\n");
        let p = resolve(&m, &InstallParams::default()).expect("plan");
        assert!(p.actions.iter().any(
            |a| matches!(a, Action::ConfigureIngress { public: false, .. })
        ));
    }

    #[test]
    fn tier_becomes_a_placement_constraint() {
        let m = manifest("  swarm:\n    replicas: 2\n    tier: heavy\n");
        let p = resolve(&m, &InstallParams::default()).expect("plan");
        assert!(p.actions.iter().any(|a| matches!(
            a,
            Action::DeployService { constraints, replicas: 2, .. }
                if constraints == &["node.labels.tier==heavy"]
        )));
    }

    #[test]
    fn wait_healthy_follows_every_deploy() {
        let m = manifest("");
        let p = resolve(&m, &InstallParams::default()).expect("plan");
        let deploy = p
            .actions
            .iter()
            .position(|a| matches!(a, Action::DeployService { .. }))
            .expect("déploiement");
        assert!(matches!(
            p.actions.get(deploy + 1),
            Some(Action::WaitHealthy { .. })
        ));
    }

    #[test]
    fn invalid_manifest_is_refused_before_planning() {
        let y = "apiVersion: hlb/v1\nkind: App\nmetadata: { name: x }\n\
                 spec:\n  image: { repo: a/b, tag: \"1\" }\n  update: { channel: latest }\n";
        let m: Manifest = serde_yaml_ng::from_str(y).unwrap();
        assert!(matches!(
            resolve(&m, &InstallParams::default()),
            Err(Error::Manifest(_))
        ));
    }

    #[test]
    fn unpinned_image_gets_a_digest_resolution_step() {
        let y = "apiVersion: hlb/v1\nkind: App\nmetadata: { name: gitea }\n\
                 spec:\n  image: { repo: gitea/gitea, tag: \"1.24\" }\n";
        let m: Manifest = serde_yaml_ng::from_str(y).unwrap();
        let p = resolve(&m, &InstallParams::default()).expect("plan");

        let resolve_pos = p.actions.iter().position(|a| matches!(a, Action::ResolveDigest { .. }))
            .expect("résolution de digest planifiée");
        let deploy = p.actions.iter().position(|a| matches!(a, Action::DeployService { .. }))
            .expect("déploiement");
        assert!(resolve_pos < deploy, "le digest est résolu avant le déploiement");
    }
}
