//! Client de l'API PocketID (§5.2 du plan).
//!
//! C'est ce qui rend le SSO réellement automatique : installer une app crée son client
//! OIDC, calcule ses URI de rappel depuis le domaine choisi, et récupère le secret —
//! sans qu'on ouvre jamais l'interface de PocketID.
//!
//! ## L'API, telle qu'elle est
//!
//! Vérifiée contre une instance réelle, faute de spécification publiée :
//!
//! | Opération | Appel |
//! |---|---|
//! | Lister / rechercher | `GET /api/oidc/clients?search=<nom>` |
//! | Créer | `POST /api/oidc/clients` |
//! | Obtenir le secret | `POST /api/oidc/clients/{id}/secret` |
//! | Supprimer | `DELETE /api/oidc/clients/{id}` |
//!
//! Authentification par en-tête `X-API-KEY`.
//!
//! ⚠️ **Le secret n'est pas renvoyé à la création** : il faut un second appel, et
//! chaque appel en **régénère un nouveau**, invalidant le précédent. D'où
//! [`OidcClient::ensure`], qui ne le régénère jamais pour un client existant.

use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("PocketID injoignable ({context}) : {source}")]
    Http {
        #[source]
        source: reqwest::Error,
        context: String,
    },

    #[error("PocketID a répondu {status} — {detail}")]
    Api { status: u16, detail: String },

    #[error("clé d'API refusée par PocketID")]
    Unauthorized,

    #[error("réponse inattendue de PocketID : {0}")]
    Unexpected(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Un compte HUMAIN, tel que PocketID le rend.
///
/// ⚠️ À ne pas confondre avec [`OidcClient`] : l'un est une personne, l'autre une
/// application. Les deux vivent dans le même service, et c'est la source de confusion
/// principale de cette API.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub username: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default, rename = "displayName")]
    pub display_name: String,
    #[serde(default, rename = "isAdmin")]
    pub is_admin: bool,
    #[serde(default)]
    pub disabled: bool,
}

/// Un client OIDC tel que PocketID le décrit — une APPLICATION, pas une personne.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct OidcClient {
    pub id: String,
    pub name: String,
    #[serde(default, rename = "callbackURLs")]
    pub callback_urls: Vec<String>,
    #[serde(default, rename = "isPublic")]
    pub is_public: bool,
    #[serde(default, rename = "pkceEnabled")]
    pub pkce_enabled: bool,
}

#[derive(Debug, Serialize)]
struct CreateRequest<'a> {
    name: &'a str,
    #[serde(rename = "callbackURLs")]
    callback_urls: &'a [String],
    #[serde(rename = "isPublic")]
    is_public: bool,
    #[serde(rename = "pkceEnabled")]
    pkce_enabled: bool,
}

#[derive(Debug, Deserialize)]
struct Page<T> {
    data: Vec<T>,
}

#[derive(Debug, Deserialize)]
struct SecretResponse {
    secret: String,
}

/// Ce qu'on obtient après provisionnement : de quoi configurer l'app.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credentials {
    pub client_id: String,
    /// Absent si le client existait déjà : on ne régénère jamais un secret en service.
    pub client_secret: Option<String>,
}

pub struct PocketId {
    base_url: String,
    api_key: String,
    http: reqwest::Client,
}

impl PocketId {
    pub fn new(base_url: impl Into<String>, api_key: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            api_key: api_key.into(),
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(15))
                .build()
                .unwrap_or_default(),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base_url)
    }

    async fn send(&self, req: reqwest::RequestBuilder, ctx: &str) -> Result<reqwest::Response> {
        let resp = req
            .header("X-API-KEY", &self.api_key)
            .send()
            .await
            .map_err(|source| Error::Http {
                source,
                context: ctx.to_string(),
            })?;

        if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
            return Err(Error::Unauthorized);
        }
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let detail = resp.text().await.unwrap_or_default();
            return Err(Error::Api { status, detail });
        }
        Ok(resp)
    }

    /// L'endpoint de découverte, à donner aux apps.
    pub fn issuer(&self) -> &str {
        &self.base_url
    }

    pub async fn ping(&self) -> Result<usize> {
        Ok(self.list(None).await?.len())
    }

    /// Liste les clients, éventuellement filtrés par nom.
    pub async fn list(&self, search: Option<&str>) -> Result<Vec<OidcClient>> {
        let mut url = self.url("/api/oidc/clients");
        if let Some(s) = search {
            url = format!("{url}?search={s}");
        }
        let resp = self.send(self.http.get(&url), "liste des clients").await?;
        let page: Page<OidcClient> = resp
            .json()
            .await
            .map_err(|e| Error::Unexpected(format!("liste illisible : {e}")))?;
        Ok(page.data)
    }

    /// Retrouve un client par son nom exact.
    ///
    /// `search` fait une correspondance partielle : on filtre donc nous-mêmes, sinon
    /// « gitea » retrouverait « gitea-runner ».
    pub async fn find_by_name(&self, name: &str) -> Result<Option<OidcClient>> {
        Ok(self
            .list(Some(name))
            .await?
            .into_iter()
            .find(|c| c.name == name))
    }

    pub async fn create(
        &self,
        name: &str,
        callback_urls: &[String],
        pkce: bool,
    ) -> Result<OidcClient> {
        let body = CreateRequest {
            name,
            callback_urls,
            // Une app serveur garde son secret : elle n'est jamais « publique ».
            is_public: false,
            pkce_enabled: pkce,
        };

        let resp = self
            .send(
                self.http.post(self.url("/api/oidc/clients")).json(&body),
                "création du client",
            )
            .await?;

        let c: OidcClient = resp
            .json()
            .await
            .map_err(|e| Error::Unexpected(format!("réponse de création illisible : {e}")))?;
        tracing::info!(client = %c.name, id = %c.id, "client OIDC créé");
        Ok(c)
    }

    /// ⚠️ Génère un **nouveau** secret et invalide l'ancien.
    /// Crée un compte HUMAIN dans PocketID.
    ///
    /// ⚠️ À ne pas confondre avec [`Self::create`], qui enregistre une *application*.
    /// Les deux vivent dans le même service et n'ont rien à voir : l'un décrit qui a le
    /// droit de se connecter, l'autre à quoi.
    ///
    /// Vérifié contre le code amont (`UserCreateDto`) : `username` est requis, `email`
    /// facultatif mais validé, et `userGroupIds` porte les groupes.
    pub async fn create_user(
        &self,
        username: &str,
        email: Option<&str>,
        display_name: &str,
        groups: &[String],
    ) -> Result<User> {
        let mut corps = serde_json::json!({
            "username": username,
            "displayName": display_name,
            "firstName": display_name,
            // 🔴 Jamais administrateur par défaut. Un compte créé en une commande ne
            // doit pas pouvoir en créer d'autres ni supprimer le cluster : l'élévation
            // se demande explicitement.
            "isAdmin": false,
            "disabled": false,
            "userGroupIds": groups,
        });

        if let Some(e) = email {
            corps["email"] = serde_json::Value::String(e.to_string());
            // ⚠️ L'adresse vient d'être créée PAR NOUS dans Stalwart : elle est vérifiée
            // par construction. La laisser « non vérifiée » enverrait un courriel de
            // confirmation dans une boîte à laquelle la personne n'a pas encore accès.
            corps["emailVerified"] = serde_json::Value::Bool(true);
        }

        let resp = self
            .send(
                self.http.post(self.url("/api/users")).json(&corps),
                "création d'utilisateur",
            )
            .await?;

        resp.json().await.map_err(|e| Error::Unexpected(format!(
            "réponse de création d'utilisateur illisible : {e}"
        )))
    }

    /// Le compte portant ce nom, s'il existe.
    ///
    /// 🔴 Sert à rendre la création **reprenable**. Sans cette recherche, relancer
    /// `hlb user add` après un échec à mi-parcours produirait un doublon — ou une
    /// erreur « déjà pris » qui bloquerait la reprise au lieu de la permettre.
    pub async fn find_user(&self, username: &str) -> Result<Option<User>> {
        let resp = self
            .send(
                self.http.get(self.url(&format!("/api/users?search={username}"))),
                "recherche d'utilisateur",
            )
            .await?;

        let brut: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| Error::Unexpected(format!("liste d'utilisateurs illisible : {e}")))?;

        // ⚠️ La forme varie selon la version : liste nue ou page `{data: [...]}`. On
        // accepte les deux plutôt que de figer celle qu'on n'a pas vérifiée partout —
        // une reprise qui échouerait ici recréerait un doublon.
        let items = brut
            .get("data")
            .and_then(|d| d.as_array())
            .or_else(|| brut.as_array())
            .cloned()
            .unwrap_or_default();

        Ok(items
            .into_iter()
            .filter_map(|v| serde_json::from_value::<User>(v).ok())
            .find(|u| u.username == username))
    }

    /// Un jeton d'accès à usage unique, pour l'inscription.
    ///
    /// 🔴 C'est ce qui remplace un mot de passe initial. PocketID s'authentifie par
    /// clé d'accès (passkey) : il n'y a **pas** de mot de passe à transmettre, et
    /// vouloir en inventer un serait à la fois impossible et moins sûr.
    ///
    /// ⚠️ Le jeton est à usage unique et expire. Le noter dans un journal ou le passer
    /// en argument de commande reviendrait à publier une session : il est affiché une
    /// fois, sur la sortie standard, et jamais enregistré.
    pub async fn one_time_token(&self, user_id: &str, ttl: &str) -> Result<String> {
        let resp = self
            .send(
                self.http
                    .post(self.url(&format!("/api/users/{user_id}/one-time-access-token")))
                    .json(&serde_json::json!({ "ttl": ttl })),
                "jeton d'inscription",
            )
            .await?;

        let rep: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| Error::Unexpected(format!("jeton illisible : {e}")))?;

        rep.get("token")
            .and_then(|t| t.as_str())
            .map(str::to_string)
            .ok_or_else(|| Error::Api {
                status: 200,
                detail: "aucun jeton dans la réponse — la personne ne pourrait pas \
                         s'inscrire, et le compte resterait inutilisable"
                    .into(),
            })
    }

    pub async fn regenerate_secret(&self, id: &str) -> Result<String> {
        let resp = self
            .send(
                self.http
                    .post(self.url(&format!("/api/oidc/clients/{id}/secret"))),
                "génération du secret",
            )
            .await?;

        let s: SecretResponse = resp
            .json()
            .await
            .map_err(|e| Error::Unexpected(format!("secret illisible : {e}")))?;
        Ok(s.secret)
    }

    pub async fn delete(&self, id: &str) -> Result<()> {
        self.send(
            self.http.delete(self.url(&format!("/api/oidc/clients/{id}"))),
            "suppression du client",
        )
        .await?;
        tracing::info!(id, "client OIDC supprimé");
        Ok(())
    }

    /// Provisionnement idempotent : crée le client s'il manque, ne touche à rien sinon.
    ///
    /// 🔴 **Ne régénère jamais le secret d'un client existant.** Chaque appel à
    /// `/secret` en produit un nouveau et invalide le précédent — celui qui est déjà
    /// injecté dans l'app tournante. Relancer une installation casserait donc le SSO
    /// de l'app qu'on croyait simplement re-vérifier.
    pub async fn ensure(
        &self,
        name: &str,
        callback_urls: &[String],
        pkce: bool,
    ) -> Result<Credentials> {
        if let Some(existing) = self.find_by_name(name).await? {
            tracing::debug!(client = name, "client OIDC déjà présent, conservé");
            return Ok(Credentials {
                client_id: existing.id,
                client_secret: None,
            });
        }

        let created = self.create(name, callback_urls, pkce).await?;
        let secret = self.regenerate_secret(&created.id).await?;
        Ok(Credentials {
            client_id: created.id,
            client_secret: Some(secret),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_base_url_is_normalised() {
        let p = PocketId::new("https://id.example.fr/", "k");
        assert_eq!(p.issuer(), "https://id.example.fr");
        assert_eq!(
            p.url("/api/oidc/clients"),
            "https://id.example.fr/api/oidc/clients"
        );
    }

    #[test]
    fn clients_deserialize_from_the_real_shape() {
        // Capturé sur une instance réelle.
        let json = r#"{"id":"88e0-c62d","name":"vikunja","hasLogo":false,
                       "callbackURLs":["https://tasks.example.fr/auth/openid/pocketid"],
                       "logoutCallbackURLs":[],"isPublic":false,"pkceEnabled":true,
                       "credentials":{},"allowedUserGroups":[]}"#;
        let c: OidcClient = serde_json::from_str(json).expect("analysable");
        assert_eq!(c.name, "vikunja");
        assert_eq!(c.callback_urls.len(), 1);
        assert!(c.pkce_enabled);
        assert!(!c.is_public);
    }

    #[test]
    fn a_page_unwraps_to_its_data() {
        let json = r#"{"data":[{"id":"a","name":"gitea"}],
                       "pagination":{"totalPages":1,"totalItems":1}}"#;
        let p: Page<OidcClient> = serde_json::from_str(json).expect("analysable");
        assert_eq!(p.data.len(), 1);
    }

    #[test]
    fn the_creation_body_uses_the_expected_field_names() {
        // Les noms sont en camelCase côté PocketID : une faute ici passerait
        // silencieusement, le champ étant simplement ignoré.
        let urls = vec!["https://x.fr/cb".to_string()];
        let body = CreateRequest {
            name: "gitea",
            callback_urls: &urls,
            is_public: false,
            pkce_enabled: true,
        };
        let j = serde_json::to_value(&body).expect("sérialisable");
        assert!(j.get("callbackURLs").is_some(), "{j}");
        assert!(j.get("isPublic").is_some());
        assert!(j.get("pkceEnabled").is_some());
    }

    #[test]
    fn credentials_say_when_the_secret_is_unavailable() {
        let c = Credentials {
            client_id: "abc".into(),
            client_secret: None,
        };
        assert!(c.client_secret.is_none(), "client existant : pas de nouveau secret");
    }
}
