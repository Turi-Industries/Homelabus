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

use hlb_types::{Capability, ExposePolicy, Manifest, SsoMode};

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

/// Le callback d'oauth2-proxy, servi sur le domaine de l'app elle-même.
///
/// ⚠️ Doit rester aligné sur le bloc `handle /oauth2/*` que produit
/// `hlb-ingress::rendre_forward_auth`. Les deux décrivent le même chemin vu de deux
/// endroits : s'ils divergent, la connexion échoue à l'étape du retour, et le message
/// de PocketID parle d'URI non enregistrée sans dire laquelle il attendait.
pub const CALLBACK_PORTAIL: &str = "/oauth2/callback";

/// Traduit un manifest + des paramètres d'installation en plan d'exécution.
///
/// L'ordre des actions n'est pas cosmétique : les dépendances (base, secrets, client
/// OIDC) doivent exister **avant** le déploiement du service qui les consomme.
pub fn resolve(m: &Manifest, params: &InstallParams) -> Result<Plan> {
    resolve_with_guide(m, &hlb_types::Guide::default(), params)
}

/// Variante qui prend en compte le `guide.yaml` de l'app (§4.6).
///
/// Les étapes déclarées remplacent le guide générique qui était codé en dur ici :
/// une app décrit désormais ses propres prérequis, et le résolveur ne devine plus.
pub fn resolve_with_guide(
    m: &Manifest,
    guide: &hlb_types::Guide,
    params: &InstallParams,
) -> Result<Plan> {
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

    // 3. Les automatisations `method: env` des guides.
    //
    // ⚠️ Subtilité : contrairement à `exec` et `api`, une variable d'environnement
    // ne peut PAS être appliquée après coup — Swarm recrée la tâche pour la prendre
    // en compte. L'échelle du §4.6bis n'est donc pas purement séquentielle à
    // l'exécution : `env` est résolu ICI, au moment du plan, tandis que `exec` et
    // `api` s'exécutent une fois le service sain.
    // 🔴 Les liaisons du manifest : comment l'app reçoit ce qu'on a provisionné pour
    // elle (§4.3). C'était la moitié manquante du résolveur — créer la base, le rôle
    // et le mot de passe sans jamais les transmettre laissait l'app retomber sur son
    // SQLite interne : service sain, sonde verte, tableau de bord au vert, et les
    // données dans un fichier que personne ne sauvegardait, pendant qu'une base vide
    // était fidèlement dumpée chaque nuit.
    //
    // 🔴 Les jetons de SECRET ne sont PAS résolus ici. Le plan est affiché par
    // `hlb plan`, enregistré dans l'état et exporté vers le miroir Git (§2.3) : y
    // substituer un mot de passe le publierait aux trois endroits, dont un dépôt qui
    // garde l'historique. La substitution a lieu dans l'exécuteur.
    //
    // ⚠️ `BTreeMap` : le tri est ce qui rend le plan reproductible d'une exécution à
    // l'autre, et l'insertion ordonnée donne une règle de priorité claire — le guide
    // écrase le manifest, parce qu'il porte une décision prise à l'installation
    // (« fermer les inscriptions ») là où le manifest porte un défaut de catalogue.
    let mut table: std::collections::BTreeMap<String, String> = m.spec.env.clone();
    for s in &guide.steps {
        for a in &s.automate {
            if let hlb_types::Automation::Env { vars } = a {
                for (k, v) in vars {
                    table.insert(
                        k.clone(),
                        hlb_types::guide::render(v, &domain_vars(params)),
                    );
                }
            }
        }
    }
    let env: Vec<(String, String)> = table.into_iter().collect();

    // 4. Les volumes à monter, déduits des capacités `storage`.
    //
    // 🔴 Le nom doit correspondre EXACTEMENT à celui créé par `CreateVolume`,
    // sinon Swarm crée un second volume vide à la volée et les données déclarées
    // sauvegardées ne sont pas celles que l'app utilise.
    let mounts: Vec<(String, String)> = m
        .spec
        .requires
        .iter()
        .filter_map(|c| match c {
            Capability::Storage { name, path, .. } => {
                Some((format!("{app}-{name}"), path.clone()))
            }
            _ => None,
        })
        .collect();

    // 4bis. Les compagnons, AVANT l'app (§4.8).
    //
    // 🔴 L'ordre est le mécanisme, comme pour le graphe de dépendances (§4.7) : Swarm
    // n'a pas de `depends_on`, et une app qui démarre avant son compagnon boucle en
    // erreur — ou pire, démarre en mode dégradé sans le dire. Immich sans son service
    // d'apprentissage indexe les photos sans jamais reconnaître un visage, et rien
    // n'indique que la moitié de la fonctionnalité est absente.
    for c in &m.spec.companions {
        let service = format!("{app}-{}", c.name);

        for v in &c.storage {
            plan.push(Action::CreateVolume {
                name: format!("{service}-{}", v.name),
                path: v.path.clone(),
                // Un compagnon est toujours local : ses volumes sont du cache ou du
                // modèle, et NFS n'apporterait que de la latence.
                tier: hlb_types::StorageTier::Local,
                backup: v.backup,
                // Un compagnon ne porte pas de base applicative (pas de `requires`).
                sqlite: false,
            });
        }

        if !c.image.is_pinned() {
            plan.push(Action::ResolveDigest {
                repo: c.image.repo.clone(),
                tag: c.image.tag.clone(),
            });
        }

        let mut contraintes = Vec::new();
        // Le tier du compagnon prime sur celui de l'app : un service de calcul mérite
        // `heavy` même quand son app est `light`.
        if let Some(t) = c.tier.as_ref().or(m.spec.swarm.tier.as_ref()) {
            contraintes.push(format!("node.labels.tier=={t}"));
        }

        plan.push(Action::DeployService {
            name: service.clone(),
            image: c.image.reference(),
            // Un seul exemplaire : le type ne permet pas d'en demander plus.
            replicas: 1,
            constraints: contraintes,
            env: c.env.clone().into_iter().collect(),
            mounts: c
                .storage
                .iter()
                .map(|v| (format!("{service}-{}", v.name), v.path.clone()))
                .collect(),
            hardening: c.security.clone(),
            healthcheck: c.healthcheck.clone(),
        });

        // 🔴 On attend qu'il soit sain avant de déployer l'app. Sans cette attente,
        // l'ordre du plan ne garantirait que l'ordre des APPELS à Swarm, pas celui
        // des démarrages réels.
        plan.push(Action::WaitHealthy {
            name: service,
            timeout_secs: params.health_timeout_secs,
        });
    }

    // 5. Le service lui-même.
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
        env,
        mounts,
        // §9 — les valeurs du manifest sont transmises telles quelles jusqu'à Swarm.
        hardening: m.spec.security.clone(),
        healthcheck: m.spec.swarm.healthcheck.clone(),
    });

    // 6. §4.7 — on attend la convergence avant de rendre la main.
    plan.push(Action::WaitHealthy {
        name: app.clone(),
        timeout_secs: params.health_timeout_secs,
    });

    // 7. Les étapes du guide, AVANT toute exposition (§4.6bis).
    //
    // L'ordre est le mécanisme de protection lui-même : c'est parce que ces étapes
    // précèdent l'ingress que la fenêtre « premier inscrit = admin » reste fermée.
    let vars = domain_vars(params);
    for s in &guide.steps {
        plan.push(Action::PendingGuideStep {
            id: s.id.clone(),
            title: hlb_types::guide::render(&s.title, &vars),
            blocking: s.is_blocking(),
            service: app.clone(),
            step: Box::new(s.clone()),
        });
    }

    // Une app en `after-guide` sans aucune étape bloquante déclarée serait exposée
    // publiquement sans garde-fou : on en pose un par défaut plutôt que d'ouvrir.
    let expose_apres_guide = m
        .spec
        .ingress
        .iter()
        .any(|i| i.expose == ExposePolicy::AfterGuide);
    if expose_apres_guide && !guide.steps.iter().any(|s| s.is_blocking()) {
        plan.push(Action::PendingGuideStep {
            id: format!("{app}-first-admin"),
            title: format!(
                "Vérifier le compte administrateur de {app} et fermer les inscriptions"
            ),
            blocking: true,
            service: app.clone(),
            step: Box::new(hlb_types::GuideStep {
                id: format!("{app}-first-admin"),
                title: "Compte administrateur".into(),
                phase: hlb_types::Phase::PostInstall,
                severity: hlb_types::Severity::Blocking,
                body: String::new(),
                after: Vec::new(),
                automate: Vec::new(),
                verify: hlb_types::Verify::Attest,
                deeplink: None,
                recheck: None,
            }),
        });
    }

    // 8. L'exposition, en dernier.
    for ing in &m.spec.ingress {
        let host = render_host(&ing.host, params)?;

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

/// Les variables disponibles pour rendre les gabarits d'un guide.
fn domain_vars(params: &InstallParams) -> Vec<(&str, &str)> {
    match &params.domain {
        Some(d) => vec![("domain", d.as_str())],
        None => Vec::new(),
    }
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
        Capability::Database { engine, name, extensions } => {
            let db = name.clone().unwrap_or_else(|| app.to_string());
            let secret = format!("{app}-db-password");

            // ⚠️ L'ordre compte : le mot de passe doit exister avant le rôle qui
            // l'utilise. L'inverse produisait une base impossible à créer.
            //
            // ⚠️ Et une seule fois : une app à plusieurs bases (Seafile en a trois)
            // partage UN rôle, donc UN mot de passe. Trois générations identiques
            // encombreraient le plan et l'état sans rien changer — la seconde serait
            // de toute façon ignorée, `store_secret_if_absent` ne réécrivant jamais.
            let deja = plan.actions.iter().any(
                |a| matches!(a, Action::GenerateSecret { name, .. } if name == &secret),
            );
            if !deja {
                plan.push(Action::GenerateSecret {
                    name: secret.clone(),
                    // Le rôle, pas la base : c'est lui que le mot de passe protège.
                    purpose: format!("mot de passe du rôle {app}"),
                });
            }
            plan.push(Action::ProvisionDatabase {
                engine: *engine,
                database: db.clone(),
                // 🔴 Le rôle porte le nom de l'APP, pas celui de la base.
                //
                // Une app peut avoir plusieurs bases — Seafile en veut trois — et elle
                // s'y connecte avec UN seul compte. Nommer le rôle d'après la base
                // produirait trois comptes distincts pour un seul jeu d'identifiants,
                // et l'app échouerait sur deux d'entre elles.
                role: app.to_string(),
                password_secret: secret,
                extensions: extensions.clone(),
            });
        }

        Capability::Cache { engine, dedicated } => {
            if *dedicated {
                plan.push(Action::DeployService {
                    name: format!("{app}-{}", engine.service_name()),
                    image: format!("{}:latest", engine.service_name()),
                    replicas: 1,
                    constraints: Vec::new(),
                    env: Vec::new(),
                    mounts: Vec::new(),
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

        Capability::Sso { mode, redirect_paths } => {
            // 🔴 Le `mode` décide, et il est examiné exhaustivement. La version
            // précédente l'ignorait (`..`), avec deux conséquences silencieuses :
            // une app en exclusion volontaire recevait quand même un client OIDC
            // aux URI VIDES, et une app derrière portail recevait un client pointant
            // vers elle au lieu du portail — donc un client inutilisable dans les
            // deux cas, plus un secret créé pour rien.
            //
            // Un `..` sur un champ a le même effet qu'un bras `_ =>` : il fait taire
            // le compilateur là où on veut justement qu'il parle.
            match mode {
                // §5 — exclusion assumée : l'app gère ses propres comptes, ou son
                // protocole est incompatible (clients TV, applications natives).
                // Créer un client OIDC ici laisserait croire à une protection qui
                // n'existe pas, et le secret associé n'aurait jamais de lecteur.
                SsoMode::None => {}

                // Le meilleur cas : l'app parle OIDC, les URI viennent d'elle.
                SsoMode::Native => {
                    // §5.2 — les URI de callback dépendent du domaine choisi à
                    // l'installation. Jamais en dur dans le manifest.
                    let domain = params
                        .domain
                        .as_ref()
                        .ok_or(Error::MissingParam("domain"))?;

                    plan.push(Action::CreateOidcClient {
                        app: app.to_string(),
                        redirect_uris: redirect_paths
                            .iter()
                            .map(|p| format!("https://{domain}{p}"))
                            .collect(),
                    });
                    plan.push(Action::GenerateSecret {
                        name: format!("{app}-oidc-secret"),
                        purpose: "client secret OIDC".into(),
                    });
                }

                // 🔴 C'est le PORTAIL qui parle OIDC, pas l'app. Le callback est
                // donc celui d'oauth2-proxy — `/oauth2/callback` sur le domaine de
                // l'app, puisque Caddy le sert là (voir `rendre_forward_auth`).
                // Enregistrer les chemins de l'app produirait un client dont
                // PocketID rejetterait la redirection au moment de la connexion.
                SsoMode::ProxyOnly | SsoMode::ProxyHeader => {
                    let domain = params
                        .domain
                        .as_ref()
                        .ok_or(Error::MissingParam("domain"))?;

                    plan.push(Action::CreateOidcClient {
                        app: app.to_string(),
                        redirect_uris: vec![format!("https://{domain}{CALLBACK_PORTAIL}")],
                    });
                    plan.push(Action::GenerateSecret {
                        name: format!("{app}-oidc-secret"),
                        purpose: "client secret OIDC du portail".into(),
                    });
                }
            }
        }

        Capability::ObjectStorage { bucket, .. } => {
            let compartiment = bucket.clone().unwrap_or_else(|| app.to_string());
            let secret = format!("{app}-s3-secret");

            // Le secret AVANT le compartiment qui l'utilise, comme pour les bases.
            plan.push(Action::GenerateSecret {
                name: secret.clone(),
                purpose: "clé secrète S3".into(),
            });
            plan.push(Action::ProvisionBucket {
                bucket: compartiment,
                // 🔴 Une clé par app. Partager la clé d'administration donnerait à
                // chaque app la lecture des compartiments de toutes les autres —
                // les photos d'Immich lisibles depuis le wiki, et réciproquement.
                key_name: app.to_string(),
                secret_name: secret,
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

        Capability::Storage { name, path, tier, backup, sqlite } => {
            plan.push(Action::CreateVolume {
                name: format!("{app}-{name}"),
                path: path.clone(),
                tier: *tier,
                backup: *backup,
                sqlite: *sqlite,
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

    /// Ingress en `after-guide`. En chaîne brute : un `\` de continuation Rust
    /// mange la newline ET l'indentation, ce qui casse le YAML de façon déroutante.
    const AFTER_GUIDE: &str = r#"  ingress:
    - host: git.example.fr
      port: 3000
      expose: after-guide
"#;

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
            extensions: Vec::new(),
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
        let m = manifest(
            "  requires:\n    - kind: sso\n      mode: native\n      \
             redirectPaths: [\"/callback\"]\n",
        );
        let err = resolve(&m, &InstallParams::default()).unwrap_err();
        assert!(matches!(err, Error::MissingParam("domain")), "{err}");
    }

    /// Les URI de redirection du client OIDC planifié, s'il y en a un.
    fn uris_oidc(p: &Plan) -> Option<Vec<String>> {
        p.actions.iter().find_map(|a| match a {
            Action::CreateOidcClient { redirect_uris, .. } => Some(redirect_uris.clone()),
            _ => None,
        })
    }

    #[test]
    fn a_deliberate_sso_exclusion_creates_nothing() {
        // 🔴 Constaté en ajoutant Jellyfin : `mode: none` produisait quand même un
        // client OIDC, aux URI de redirection VIDES, plus un secret que personne ne
        // lirait jamais. Le `mode` était ignoré par un `..` — même effet qu'un bras
        // `_ =>` : faire taire le compilateur là où on veut justement qu'il parle.
        //
        // `none` est une exclusion VOLONTAIRE (clients TV incapables de suivre une
        // redirection, app à comptes propres). Créer un client laisserait croire à
        // une protection qui n'existe pas.
        let m = manifest("  requires:\n    - kind: sso\n      mode: none\n");
        let p = resolve(&m, &InstallParams::with_domain("media.example.fr")).expect("plan");

        assert!(uris_oidc(&p).is_none(), "aucun client OIDC ne doit être créé");
        assert!(
            !p.actions.iter().any(|a| matches!(
                a,
                Action::GenerateSecret { name, .. } if name.ends_with("-oidc-secret")
            )),
            "ni secret OIDC, que personne ne lirait : {:?}",
            p.actions
        );
    }

    #[test]
    fn a_deliberate_exclusion_does_not_even_need_a_domain() {
        // Corollaire : sans client à créer, le domaine n'est plus requis. Exiger un
        // paramètre pour une capacité qui ne provisionne rien serait un faux blocage.
        let m = manifest("  requires:\n    - kind: sso\n      mode: none\n");
        resolve(&m, &InstallParams::default()).expect("aucun domaine n'est nécessaire");
    }

    #[test]
    fn a_portal_backed_app_registers_the_portal_callback() {
        // 🔴 Derrière un portail, c'est oauth2-proxy qui parle OIDC, pas l'app. Un
        // client enregistré sur les chemins de l'app produirait une redirection que
        // PocketID refuse au moment de la connexion — la panne survient au RETOUR,
        // sur un message qui ne dit pas quelle URI était attendue.
        for mode in ["proxy-only", "proxy-header"] {
            let m = manifest(&format!(
                "  requires:\n    - kind: sso\n      mode: {mode}\n      \
                 redirectPaths: [\"/rest/oauth2-credential/callback\"]\n"
            ));
            let p = resolve(&m, &InstallParams::with_domain("n8n.example.fr")).expect("plan");

            assert_eq!(
                uris_oidc(&p).expect("client OIDC"),
                vec![format!("https://n8n.example.fr{CALLBACK_PORTAIL}")],
                "mode {mode} : les chemins de l'app ne s'appliquent pas au portail"
            );
        }
    }

    #[test]
    fn an_oidc_client_is_never_created_without_a_redirect_uri() {
        // Un client sans URI est inutilisable : PocketID n'a rien vers quoi renvoyer.
        // Quel que soit le mode, ou bien on ne crée rien, ou bien on crée un client
        // complet — jamais un client à moitié.
        for mode in ["none", "proxy-only", "proxy-header"] {
            let m = manifest(&format!("  requires:\n    - kind: sso\n      mode: {mode}\n"));
            let p = resolve(&m, &InstallParams::with_domain("app.example.fr")).expect("plan");

            if let Some(uris) = uris_oidc(&p) {
                assert!(!uris.is_empty(), "mode {mode} : client sans URI de redirection");
            }
        }

        // 🔴 `native` est le cas qui ne peut PAS s'en sortir seul : sans chemin
        // déclaré, personne ne sait où renvoyer. Trouvé par ce test même, qui
        // échouait sur ce mode. Le manifest est donc refusé à la validation plutôt
        // que de planifier un client inutilisable.
        let m = manifest("  requires:\n    - kind: sso\n      mode: native\n");
        let e = resolve(&m, &InstallParams::with_domain("app.example.fr"))
            .expect_err("un native sans redirectPaths doit être refusé");
        let msg = e.to_string();
        assert!(msg.contains("redirectPaths"), "{msg}");
        assert!(msg.contains("proxy-only"), "l'erreur doit dire quoi faire : {msg}");
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
    fn a_declared_guide_step_becomes_a_blocking_action() {
        // §4.6 — les étapes viennent désormais du `guide.yaml` de l'app.
        let m = manifest("  ingress:\n    - host: git.example.fr\n      port: 3000\n");
        let g: hlb_types::Guide = serde_yaml_ng::from_str(
            "steps:\n  - id: dns\n    title: Créer le DNS\n    severity: blocking\n",
        )
        .expect("guide");

        let p = resolve_with_guide(&m, &g, &InstallParams::default()).expect("plan");
        assert_eq!(p.blocking_steps().len(), 1);
        assert!(p
            .actions
            .iter()
            .any(|a| matches!(a, Action::PendingGuideStep { id, .. } if id == "dns")));
    }

    #[test]
    fn guide_titles_are_rendered_with_the_domain() {
        let m = manifest("");
        let g: hlb_types::Guide = serde_yaml_ng::from_str(
            "steps:\n  - id: x\n    title: \"Pointer {{ domain }} vers le cluster\"\n",
        )
        .expect("guide");

        let p = resolve_with_guide(&m, &g, &InstallParams::with_domain("git.example.fr"))
            .expect("plan");
        assert!(p
            .actions
            .iter()
            .any(|a| a.to_string().contains("git.example.fr")));
    }

    #[test]
    fn after_guide_without_any_blocking_step_still_gets_a_guard() {
        // 🔴 Sinon une app en `after-guide` sans guide déclaré serait exposée
        // publiquement sans le moindre garde-fou.
        let m = manifest(AFTER_GUIDE);
        let p = resolve_with_guide(&m, &hlb_types::Guide::default(), &InstallParams::default())
            .expect("plan");
        assert_eq!(p.blocking_steps().len(), 1, "un garde-fou par défaut est attendu");
    }

    #[test]
    fn after_guide_blocks_before_exposing() {
        let m = manifest(
            "  ingress:\n    - host: \"{{ domain }}\"\n      port: 3000\n      \
             expose: after-guide\n",
        );
        let g: hlb_types::Guide = serde_yaml_ng::from_str(
            "steps:\n  - id: admin\n    title: Créer l'admin\n    severity: blocking\n",
        )
        .expect("guide");
        let p = resolve_with_guide(&m, &g, &InstallParams::with_domain("git.example.fr"))
            .expect("plan");

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
