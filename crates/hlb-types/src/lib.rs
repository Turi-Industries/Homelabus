//! Types partagés de HomelabUS.
//!
//! Ce crate est volontairement le seul endroit où le schéma est défini. Il alimente :
//!   - le controller et le CLI (Rust, directement) ;
//!   - l'autocomplétion YAML dans l'éditeur (via `schemars` → JSON Schema).
//!
//! ⚠️ L'UI ne passe PAS par un client généré : depuis le choix d'egui, elle est en
//! Rust et consomme `hlb-api` directement. L'OpenAPI `utoipa` + la génération
//! TypeScript prévus au §11bis sont sans objet — c'est le principal bénéfice
//! d'architecture de ce choix, et il vaut mieux qu'il soit dit ici.

pub mod capability;
pub mod guide;
pub mod rbac;
pub mod token;
pub mod manifest;

pub use token::{generate as generate_token, StoredToken};
pub use rbac::Role;
pub use guide::{Automation, Guide, GuideStep, Phase, Severity, Verify};
pub mod binding;

pub use binding::{redact, substitute, Token};
pub use capability::{CacheEngine, Capability, DbEngine, SsoMode, StorageTier};
pub use manifest::{
    ApiVersion, Companion, CompanionVolume, ExposePolicy, Healthcheck, Image, Ingress, Kind,
    Manifest, Metadata, Runtime,
    SecuritySpec, Spec, SwarmSpec, UpdateChannel, UpdatePolicy,
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("manifest invalide : {0}")]
    Parse(#[from] serde_yaml_ng::Error),

    #[error("validation échouée : {0}")]
    Validation(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Règles qui ne peuvent pas être exprimées par le typage seul.
///
/// Chaque règle ici correspond à un moyen concret de se tirer une balle dans le pied,
/// documenté dans le plan.
pub fn validate(m: &Manifest) -> Result<()> {
    // §5.4 — une app en `proxy-header` fait confiance à un en-tête HTTP. Si elle est
    // joignable sans passer par le proxy, `curl -H "Remote-User: admin"` suffit à
    // usurper n'importe quel compte.
    let header_auth = m
        .spec
        .requires
        .iter()
        .any(|c| matches!(c, Capability::Sso { mode, .. } if mode.requires_network_isolation()));

    if header_auth && !m.spec.security.published_ports.is_empty() {
        return Err(Error::Validation(format!(
            "{} utilise l'authentification par en-tête mais publie des ports {:?} : \
             l'app doit être joignable uniquement via le proxy",
            m.metadata.name, m.spec.security.published_ports
        )));
    }

    // 🔴 §5.2 — `mode: native` sans `redirectPaths` produit un client OIDC SANS URI
    // de redirection. PocketID n'a alors rien vers quoi renvoyer, et la panne ne se
    // voit qu'au retour de la connexion, sur un message qui parle d'URI non
    // enregistrée sans dire laquelle il attendait.
    //
    // Le manifest est refusé ici plutôt que de laisser planifier un client inutile :
    // c'est une faute de rédaction, elle se dit avec son numéro de ligne.
    for c in &m.spec.requires {
        if let Capability::Sso { mode: SsoMode::Native, redirect_paths } = c {
            if redirect_paths.is_empty() {
                return Err(Error::Validation(format!(
                    "{} déclare « sso: native » sans redirectPaths : le client OIDC \
                     n'aurait aucune URI de redirection et la connexion échouerait au \
                     retour. Donne le chemin de callback de l'app, ou passe en \
                     « proxy-only » si elle ne parle pas OIDC",
                    m.metadata.name
                )));
            }
        }
    }

    // 🔴 §4.3 — un jeton de liaison exige la capacité correspondante.
    //
    // Sans ce contrôle, un `{{ db.password }}` dans une app qui ne déclare aucune base
    // partirait vers Swarm avec le TEXTE DU JETON pour valeur. L'app se plaindrait
    // alors d'un mot de passe incorrect, et le diagnostic partirait du côté du mot de
    // passe — jamais du côté du manifest.
    for t in binding::tokens_used(&m.spec.env) {
        let Some(besoin) = t.requires() else { continue };

        let declaree = m.spec.requires.iter().any(|c| c.id() == besoin);
        if !declaree {
            return Err(Error::Validation(format!(
                "{} : « {} » est utilisé dans env mais l'app ne déclare aucune capacité \
                 « {besoin} ». La variable partirait avec le texte du jeton pour valeur",
                m.metadata.name,
                t.placeholder()
            )));
        }
    }

    // §4.7bis — un compagnon devient un nom DNS dans le réseau Swarm.
    //
    // ⚠️ Une majuscule ou un point produit un service que Swarm crée sans broncher et
    // que l'app ne résout pas : la panne apparaît à la première requête, sur un
    // « connection refused » qui ne dit rien du nom.
    let mut vus: Vec<&str> = Vec::new();
    for c in &m.spec.companions {
        if c.name.is_empty()
            || !c
                .name
                .chars()
                .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-')
        {
            return Err(Error::Validation(format!(
                "{} : compagnon « {} » — le nom devient une entrée DNS et n'accepte \
                 que minuscules, chiffres et tirets",
                m.metadata.name, c.name
            )));
        }

        // Deux compagnons homonymes produiraient deux services de même nom : le
        // second écraserait le premier, en silence.
        if vus.contains(&c.name.as_str()) {
            return Err(Error::Validation(format!(
                "{} : compagnon « {} » déclaré deux fois — le second écraserait le \
                 premier sans un mot",
                m.metadata.name, c.name
            )));
        }
        vus.push(&c.name);
    }

    // §10.2 — une base sur NFS finit par se corrompre : le verrouillage de fichiers
    // n'y est pas fiable.
    for c in &m.spec.requires {
        if let Capability::Storage { tier, sqlite, name, .. } = c {
            if *sqlite && *tier == StorageTier::Nfs {
                return Err(Error::Validation(format!(
                    "volume « {name} » : une base SQLite ne doit jamais être sur NFS"
                )));
            }
        }
    }

    // §7 — `latest` suit un tag mutable : on ne peut ni détecter un changement de
    // façon fiable, ni revenir en arrière. C'est un accident programmé.
    if m.spec.update.channel == UpdateChannel::Latest {
        return Err(Error::Validation(format!(
            "{} : le canal « latest » est interdit — utilise patch, minor ou pin",
            m.metadata.name
        )));
    }

    Ok(())
}

/// Invariants qui ne valent qu'**au moment du déploiement**, pas dans le catalogue.
///
/// Un manifest de catalogue déclare une intention (`tag` + `channel`) ; le digest,
/// lui, est résolu contre le registre à l'installation puis figé dans l'état. Exiger
/// un digest dans le catalogue obligerait à le mettre à jour à chaque publication
/// amont — c'est le rôle du veilleur, pas de l'auteur du manifest.
pub fn validate_pinned(m: &Manifest) -> Result<()> {
    if !m.spec.image.is_pinned() {
        return Err(Error::Validation(format!(
            "{} : déploiement refusé sans digest résolu",
            m.metadata.name
        )));
    }
    Ok(())
}

/// Le JSON Schema du manifest, pour l'autocomplétion dans l'éditeur.
pub fn manifest_json_schema() -> String {
    let schema = schemars::schema_for!(Manifest);
    serde_json::to_string_pretty(&schema).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(yaml: &str) -> Manifest {
        serde_yaml_ng::from_str(yaml).expect("yaml de test valide")
    }

    const BASE: &str = r#"
apiVersion: hlb/v1
kind: App
metadata: { name: test }
spec:
  image: { repo: acme/test, tag: "1.0", digest: "sha256:abc" }
"#;

    #[test]
    fn base_manifest_is_valid() {
        assert!(validate(&manifest(BASE)).is_ok());
    }

    #[test]
    fn rejects_header_auth_with_published_ports() {
        let y = format!(
            "{BASE}  requires:\n    - kind: sso\n      mode: proxy-header\n  \
             security:\n    publishedPorts: [8080]\n"
        );
        let err = validate(&manifest(&y)).unwrap_err();
        assert!(err.to_string().contains("uniquement via le proxy"));
    }

    #[test]
    fn rejects_sqlite_on_nfs() {
        let y = format!(
            "{BASE}  requires:\n    - kind: storage\n      name: data\n      \
             path: /data\n      tier: nfs\n      sqlite: true\n"
        );
        assert!(validate(&manifest(&y)).unwrap_err().to_string().contains("NFS"));
    }

    #[test]
    fn rejects_a_binding_token_without_its_capability() {
        // 🔴 Sans ce refus, la variable partirait vers Swarm avec « {{ db.password }} »
        // pour valeur. L'app dirait « mot de passe incorrect », et l'on chercherait
        // pendant longtemps du côté du mot de passe.
        let y = format!(
            "{BASE}  env:\n    DB_PASSWORD: \"{{{{ db.password }}}}\"\n"
        );
        let e = validate(&manifest(&y)).unwrap_err().to_string();
        assert!(e.contains("db.password"), "{e}");
        assert!(e.contains("database"), "l'erreur doit nommer la capacité manquante : {e}");
    }

    #[test]
    fn accepts_a_binding_token_when_the_capability_is_declared() {
        let y = format!(
            "{BASE}  requires:\n    - kind: database\n      engine: postgres\n  \
             env:\n    DB_PASSWORD: \"{{{{ db.password }}}}\"\n"
        );
        validate(&manifest(&y)).expect("la capacité est déclarée");
    }

    #[test]
    fn the_domain_token_needs_no_capability() {
        // Le domaine vient des paramètres d'installation : l'exiger comme capacité
        // serait un faux blocage sur toutes les apps.
        let y = format!("{BASE}  env:\n    URL: \"https://{{{{ domain }}}}\"\n");
        validate(&manifest(&y)).expect("le domaine est toujours disponible");
    }

    #[test]
    fn rejects_latest_channel() {
        let y = format!("{BASE}  update: {{ channel: latest }}\n");
        assert!(validate(&manifest(&y)).unwrap_err().to_string().contains("latest"));
    }

    #[test]
    fn catalog_manifest_may_omit_the_digest() {
        // Le digest est résolu à l'installation, pas écrit à la main (§7).
        let y = BASE.replace(", digest: \"sha256:abc\"", "");
        assert!(validate(&manifest(&y)).is_ok());
        assert!(validate_pinned(&manifest(&y)).is_err());
    }

    #[test]
    fn deploy_requires_a_resolved_digest() {
        assert!(validate_pinned(&manifest(BASE)).is_ok());
    }
}
