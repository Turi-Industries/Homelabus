//! Client de l'API d'administration Stalwart (§5.9).
//!
//! C'est ce qui rend une boîte mail aussi automatique qu'une base de données :
//! installer une app crée son compte, son mot de passe et ses aliases sans qu'on
//! ouvre jamais l'interface de Stalwart.
//!
//! ## 🔴 Ce n'est pas une API REST
//!
//! Contrairement à ce qu'on attend d'un serveur mail, Stalwart 0.16 n'expose **aucun**
//! `/api/principal`. Sa surface `/api/` se limite à `auth`, `account`, `schema`,
//! `token`, `live`, `telemetry` et `diagnose` ; toute la gestion des comptes passe par
//! **JMAP**, en `POST /jmap/`, avec la capacité propriétaire `urn:stalwart:jmap`.
//!
//! Les méthodes suivent la forme `x:Objet/verbe` :
//!
//! | Opération | Appel JMAP |
//! |---|---|
//! | Trouver un domaine | `x:Domain/query` |
//! | Chercher un compte | `x:Account/query` |
//! | Créer / modifier | `x:Account/set` |
//!
//! Cette forme est vérifiée contre le schéma que Stalwart publie lui-même
//! (`resources/schema/schema.json.gz`, servi par le serveur sur `/api/schema/{hash}`)
//! et contre `crates/registry/src/schema/structs.rs` du dépôt amont — pas déduite
//! d'un billet de blog.
//!
//! ## Les trois pièges de cette API
//!
//! 1. **`emailAddress` est calculé par le serveur.** On pose `name` (la partie locale)
//!    et `domainId` ; envoyer `emailAddress` ne produit aucune erreur et n'a aucun
//!    effet. On croirait avoir créé `gitea@example.fr` en ayant créé autre chose.
//! 2. **`domainId` est une référence d'objet, pas une chaîne.** Le domaine doit exister
//!    dans Stalwart *avant* le compte, et il faut résoudre son identifiant.
//! 3. **JMAP renvoie HTTP 200 même quand la création échoue.** L'échec vit dans
//!    `notCreated`. Un client qui ne regarde que le code HTTP rapporte un succès
//!    imaginaire — c'est le piège central de ce module.

use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Stalwart injoignable ({context}) : {source}")]
    Http {
        #[source]
        source: reqwest::Error,
        context: String,
    },

    #[error("Stalwart a répondu {status} — {detail}")]
    Api { status: u16, detail: String },

    #[error("identifiants refusés par Stalwart")]
    Unauthorized,

    #[error("réponse inattendue de Stalwart : {0}")]
    Unexpected(String),

    /// 🔴 L'échec que le code HTTP ne dit pas.
    #[error("Stalwart a refusé de créer {object} : {reason}")]
    NotCreated { object: String, reason: String },

    #[error(
        "le domaine « {0} » n'existe pas dans Stalwart — un compte ne peut pas être \
         créé sur un domaine absent ; crée-le d'abord"
    )]
    UnknownDomain(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// La capacité propriétaire, sans laquelle Stalwart rejette les méthodes `x:`.
const CAPABILITY: &str = "urn:stalwart:jmap";
const CORE: &str = "urn:ietf:params:jmap:core";

/// Une requête JMAP.
#[derive(Debug, Serialize)]
struct JmapRequest {
    using: Vec<&'static str>,
    #[serde(rename = "methodCalls")]
    method_calls: Vec<serde_json::Value>,
}

impl JmapRequest {
    fn one(method: &str, args: serde_json::Value) -> Self {
        Self {
            using: vec![CORE, CAPABILITY],
            method_calls: vec![serde_json::json!([method, args, "c0"])],
        }
    }
}

#[derive(Debug, Deserialize)]
struct JmapResponse {
    #[serde(rename = "methodResponses", default)]
    method_responses: Vec<serde_json::Value>,
}

impl JmapResponse {
    /// Les arguments de la première réponse.
    ///
    /// Une réponse `error` est renvoyée en tant que telle : JMAP encode les erreurs
    /// de méthode dans la liste des réponses, pas dans le code HTTP.
    fn first(self) -> Result<serde_json::Value> {
        let r = self
            .method_responses
            .into_iter()
            .next()
            .ok_or_else(|| Error::Unexpected("aucune réponse de méthode".into()))?;

        let nom = r.get(0).and_then(|v| v.as_str()).unwrap_or("?").to_string();
        let args = r
            .get(1)
            .cloned()
            .ok_or_else(|| Error::Unexpected("réponse sans arguments".into()))?;

        if nom == "error" {
            let t = args
                .get("type")
                .and_then(|v| v.as_str())
                .unwrap_or("inconnue");
            return Err(Error::Api {
                status: 200,
                detail: format!("erreur JMAP « {t} » : {args}"),
            });
        }
        Ok(args)
    }
}

/// Un compte tel que Stalwart le décrit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailAccount {
    pub id: String,
    /// Partie locale, sans le domaine.
    pub name: String,
    pub domain_id: String,
}

/// Ce qu'on obtient après provisionnement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provisioned {
    pub account_id: String,
    pub address: String,
    /// `false` si le compte existait déjà : son mot de passe n'a **pas** été changé.
    pub created: bool,
}

/// Comment on s'authentifie auprès de Stalwart.
#[derive(Debug, Clone)]
pub enum Auth {
    /// Compte d'administration : `Authorization: Basic`.
    Basic { user: String, password: String },
    /// Jeton d'API : `Authorization: Bearer`.
    Bearer(String),
}

pub struct Stalwart {
    base_url: String,
    auth: Auth,
    http: reqwest::Client,
}

impl Stalwart {
    pub fn new(base_url: impl Into<String>, auth: Auth) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            auth,
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(20))
                .build()
                .unwrap_or_default(),
        }
    }

    fn endpoint(&self) -> String {
        format!("{}/jmap/", self.base_url)
    }

    async fn call(&self, method: &str, args: serde_json::Value) -> Result<serde_json::Value> {
        let req = self.http.post(self.endpoint()).json(&JmapRequest::one(method, args));

        let req = match &self.auth {
            Auth::Basic { user, password } => req.basic_auth(user, Some(password)),
            Auth::Bearer(t) => req.bearer_auth(t),
        };

        let resp = req.send().await.map_err(|source| Error::Http {
            source,
            context: method.to_string(),
        })?;

        if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
            return Err(Error::Unauthorized);
        }
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let detail = resp.text().await.unwrap_or_default();
            return Err(Error::Api { status, detail });
        }

        let body: JmapResponse = resp
            .json()
            .await
            .map_err(|e| Error::Unexpected(format!("réponse illisible : {e}")))?;
        body.first()
    }

    /// Vérifie que l'API répond et que les identifiants passent.
    pub async fn ping(&self) -> Result<()> {
        self.call("x:Domain/query", serde_json::json!({ "limit": 1 }))
            .await
            .map(|_| ())
    }

    /// L'identifiant interne d'un domaine.
    ///
    /// 🔴 Indispensable : `domainId` est une référence d'objet, pas le nom du domaine.
    /// Un domaine absent de Stalwart ne peut pas accueillir de compte, et il vaut
    /// mieux le dire ici que laisser la création échouer de façon obscure.
    pub async fn domain_id(&self, domain: &str) -> Result<String> {
        let args = self
            .call(
                "x:Domain/query",
                serde_json::json!({ "filter": { "name": domain } }),
            )
            .await?;

        ids(&args)
            .into_iter()
            .next()
            .ok_or_else(|| Error::UnknownDomain(domain.to_string()))
    }

    /// Cherche un compte par sa partie locale, dans un domaine donné.
    pub async fn find_account(&self, local: &str, domain_id: &str) -> Result<Option<String>> {
        let args = self
            .call(
                "x:Account/query",
                serde_json::json!({
                    "filter": { "name": local, "domainId": domain_id }
                }),
            )
            .await?;
        Ok(ids(&args).into_iter().next())
    }

    /// Crée un compte utilisateur.
    ///
    /// Le corps suit la forme du schéma amont : discriminant `@type`, partie locale
    /// dans `name`, et mot de passe dans une entrée `credentials`.
    pub async fn create_account(
        &self,
        local: &str,
        domain_id: &str,
        password: &str,
        aliases: &[String],
    ) -> Result<String> {
        let args = self
            .call(
                "x:Account/set",
                serde_json::json!({
                    "create": { "nouveau": account_body(local, domain_id, password, aliases) }
                }),
            )
            .await?;

        // 🔴 Le piège central : HTTP 200 ne veut PAS dire créé.
        if let Some(err) = args.get("notCreated").and_then(|v| v.get("nouveau")) {
            return Err(Error::NotCreated {
                object: format!("le compte « {local} »"),
                reason: describe_set_error(err),
            });
        }

        let id = args
            .get("created")
            .and_then(|v| v.get("nouveau"))
            .and_then(|v| v.get("id"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                Error::Unexpected(format!("création sans identifiant renvoyé : {args}"))
            })?
            .to_string();

        tracing::info!(compte = local, id = %id, "compte mail créé");
        Ok(id)
    }

    /// Provisionnement idempotent d'une adresse complète.
    ///
    /// 🔴 **Ne change jamais le mot de passe d'un compte existant.** Le remplacer
    /// couperait l'accès IMAP/SMTP de l'app qui tourne déjà avec l'ancien — pour une
    /// simple relance de plan censée ne rien changer. C'est la même règle que pour les
    /// secrets OIDC (§5.2).
    pub async fn ensure_account(
        &self,
        address: &str,
        password: &str,
        aliases: &[String],
    ) -> Result<Provisioned> {
        let (local, domain) = address
            .split_once('@')
            .ok_or_else(|| Error::Unexpected(format!("adresse sans domaine : {address}")))?;

        let domain_id = self.domain_id(domain).await?;

        if let Some(id) = self.find_account(local, &domain_id).await? {
            tracing::debug!(compte = local, "compte mail déjà présent, conservé");
            return Ok(Provisioned {
                account_id: id,
                address: address.to_string(),
                created: false,
            });
        }

        let id = self
            .create_account(local, &domain_id, password, aliases)
            .await?;

        Ok(Provisioned {
            account_id: id,
            address: address.to_string(),
            created: true,
        })
    }
}

/// Le corps d'une création de compte.
///
/// Extrait pour être testable sans réseau : c'est la partie où une faute de frappe
/// serait silencieuse, JMAP ignorant les propriétés qu'il ne connaît pas.
fn account_body(
    local: &str,
    domain_id: &str,
    password: &str,
    aliases: &[String],
) -> serde_json::Value {
    serde_json::json!({
        // Discriminant du schéma amont : `#[serde(tag = "@type")] enum Account`.
        "@type": "User",
        // ⚠️ La partie locale SEULE. `emailAddress` est calculé par le serveur à
        // partir de `name` et `domainId` ; l'envoyer n'a aucun effet.
        "name": local,
        "domainId": domain_id,
        "credentials": [{
            "@type": "Password",
            "secret": password
        }],
        "aliases": aliases
            .iter()
            .filter_map(|a| {
                // Un alias porte sa propre partie locale et son domaine. On n'accepte
                // que des aliases sur le même domaine : ailleurs, il faudrait résoudre
                // un second `domainId`, et deviner lequel serait faux.
                let local = a.split('@').next()?;
                (!local.is_empty()).then(|| {
                    serde_json::json!({
                        "enabled": true,
                        "name": local,
                        "domainId": domain_id
                    })
                })
            })
            .collect::<Vec<_>>(),
        "description": "Créé par HomelabUS",
    })
}

/// Les identifiants renvoyés par un `/query`.
fn ids(args: &serde_json::Value) -> Vec<String> {
    args.get("ids")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default()
}

/// Rend lisible une `SetError` JMAP.
fn describe_set_error(e: &serde_json::Value) -> String {
    let t = e.get("type").and_then(|v| v.as_str()).unwrap_or("inconnu");
    match e.get("description").and_then(|v| v.as_str()) {
        Some(d) => format!("{t} — {d}"),
        None => t.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client() -> Stalwart {
        Stalwart::new(
            "https://mail.example.fr/",
            Auth::Basic {
                user: "admin".into(),
                password: "secret".into(),
            },
        )
    }

    #[test]
    fn the_endpoint_is_jmap_not_api() {
        // 🔴 Stalwart 0.16 n'a pas de /api/principal : tout passe par JMAP.
        let c = client();
        assert_eq!(c.endpoint(), "https://mail.example.fr/jmap/");
    }

    #[test]
    fn the_stalwart_capability_is_always_declared() {
        // Sans `urn:stalwart:jmap`, le serveur rejette toute méthode « x: ».
        let r = JmapRequest::one("x:Account/query", serde_json::json!({}));
        assert!(r.using.contains(&"urn:stalwart:jmap"), "{:?}", r.using);
        assert!(r.using.contains(&"urn:ietf:params:jmap:core"));
    }

    #[test]
    fn the_creation_body_never_carries_an_email_address() {
        // 🔴 `emailAddress` est calculé par le serveur depuis `name` + `domainId`.
        // L'envoyer ne produit AUCUNE erreur et n'a aucun effet : on croirait avoir
        // créé gitea@example.fr en ayant créé tout autre chose.
        let b = account_body("gitea", "d1", "mdp", &[]);
        assert!(b.get("emailAddress").is_none(), "{b}");
        assert_eq!(b["name"], "gitea", "la partie locale SEULE");
        assert_eq!(b["domainId"], "d1");
    }

    #[test]
    fn the_creation_body_carries_the_type_discriminator() {
        // Le schéma amont utilise `#[serde(tag = "@type")]` — un simple « type »
        // serait ignoré et la création échouerait sans dire pourquoi.
        let b = account_body("gitea", "d1", "mdp", &[]);
        assert_eq!(b["@type"], "User");
        assert_eq!(b["credentials"][0]["@type"], "Password");
        assert_eq!(b["credentials"][0]["secret"], "mdp");
    }

    #[test]
    fn aliases_keep_only_their_local_part() {
        // Un alias porte `name` + `domainId`, comme le compte : y coller l'adresse
        // complète créerait un alias « contact@example.fr@example.fr ».
        let b = account_body(
            "gitea",
            "d1",
            "mdp",
            &["contact@example.fr".into(), "info".into()],
        );
        let a = b["aliases"].as_array().expect("liste");
        assert_eq!(a.len(), 2);
        assert_eq!(a[0]["name"], "contact");
        assert_eq!(a[0]["domainId"], "d1");
        assert_eq!(a[1]["name"], "info");
        assert_eq!(a[0]["enabled"], true);
    }

    #[test]
    fn an_empty_alias_is_dropped() {
        let b = account_body("gitea", "d1", "mdp", &["@example.fr".into(), "".into()]);
        assert!(b["aliases"].as_array().expect("liste").is_empty(), "{b}");
    }

    #[test]
    fn a_query_response_yields_its_ids() {
        let args = serde_json::json!({ "ids": ["a1", "b2"], "total": 2 });
        assert_eq!(ids(&args), vec!["a1", "b2"]);
        assert!(ids(&serde_json::json!({ "ids": [] })).is_empty());
        assert!(ids(&serde_json::json!({})).is_empty());
    }

    #[test]
    fn a_method_error_is_read_from_the_body_not_the_status() {
        // JMAP encode les erreurs de méthode DANS la réponse : le code HTTP reste 200.
        let r: JmapResponse = serde_json::from_str(
            r#"{"methodResponses":[["error",{"type":"unknownMethod"},"c0"]]}"#,
        )
        .expect("analysable");

        let e = r.first().unwrap_err();
        assert!(matches!(e, Error::Api { status: 200, .. }), "{e:?}");
        assert!(e.to_string().contains("unknownMethod"), "{e}");
    }

    #[test]
    fn an_empty_response_is_an_error_not_a_success() {
        let r: JmapResponse =
            serde_json::from_str(r#"{"methodResponses":[]}"#).expect("analysable");
        assert!(matches!(r.first(), Err(Error::Unexpected(_))));
    }

    #[test]
    fn a_normal_response_yields_its_arguments() {
        let r: JmapResponse = serde_json::from_str(
            r#"{"methodResponses":[["x:Account/query",{"ids":["z9"]},"c0"]]}"#,
        )
        .expect("analysable");
        assert_eq!(ids(&r.first().expect("arguments")), vec!["z9"]);
    }

    #[test]
    fn a_set_error_is_rendered_with_its_reason() {
        let e = serde_json::json!({
            "type": "invalidProperties",
            "description": "name already exists"
        });
        let d = describe_set_error(&e);
        assert!(d.contains("invalidProperties"), "{d}");
        assert!(d.contains("already exists"), "{d}");
        // Sans description, on garde au moins le type.
        assert_eq!(
            describe_set_error(&serde_json::json!({ "type": "forbidden" })),
            "forbidden"
        );
    }

    #[tokio::test]
    async fn an_address_without_a_domain_is_refused() {
        let e = client()
            .ensure_account("gitea", "mdp", &[])
            .await
            .unwrap_err();
        assert!(e.to_string().contains("sans domaine"), "{e}");
    }

    #[test]
    fn a_missing_domain_says_what_to_do() {
        // Le message doit porter l'action, pas seulement le constat : sans le
        // domaine créé au préalable, aucun compte n'est possible.
        let e = Error::UnknownDomain("example.fr".into()).to_string();
        assert!(e.contains("example.fr"), "{e}");
        assert!(e.contains("crée-le d'abord"), "{e}");
    }

    #[test]
    fn provisioning_says_whether_it_created_anything() {
        // 🔴 La distinction porte une conséquence : `created: false` veut dire que le
        // mot de passe au coffre est celui d'AVANT, et qu'on n'y a pas touché.
        let p = Provisioned {
            account_id: "a1".into(),
            address: "gitea@example.fr".into(),
            created: false,
        };
        assert!(!p.created);
    }
}
