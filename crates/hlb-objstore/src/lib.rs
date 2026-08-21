//! Client d'administration Garage : compartiments et clés isolées (§3.5).
//!
//! ## Pourquoi Garage plutôt que MinIO
//!
//! Les deux parlent S3. Garage est conçu pour exactement notre cas : des nœuds
//! hétérogènes, chez soi, reliés par un réseau ordinaire. Il réplique entre nœuds sans
//! exiger de disques identiques, tient dans quelques dizaines de mégaoctets de RAM, et
//! n'a pas de console web à protéger — l'administration passe par cette API.
//!
//! ⚠️ **Sa compatibilité S3 n'est pas totale.** Les points d'attention connus : pas de
//! versionnement d'objets, et quelques cas limites du téléversement par parties. Pour
//! restic, Outline et Matrix c'est sans conséquence. Une app qui exigerait le
//! versionnement devrait être signalée à l'ajout du manifest, pas découverte en panne.
//!
//! ## 🔴 Le piège central : la clé secrète n'est donnée QU'UNE FOIS
//!
//! `CreateKey` renvoie `secretAccessKey`. Toute lecture ultérieure via `GetKeyInfo` la
//! rend **nulle** : Garage ne la conserve pas en clair et ne peut donc pas la
//! redonner. Une clé dont on a perdu le secret n'est pas récupérable, elle est à
//! remplacer.
//!
//! Conséquences directes sur la conception :
//!
//! 1. Le secret part au coffre **dans la foulée immédiate** de la création.
//! 2. L'idempotence ne peut PAS reposer sur « la clé existe-t-elle chez Garage ? ».
//!    Une seconde exécution y répondrait oui, et repartirait sans secret — l'app
//!    recevrait alors une clé vide et échouerait à l'authentification, sur un message
//!    S3 qui parle de signature invalide. C'est le coffre qui fait autorité :
//!    [`Garage::ensure_key`] prend le secret déjà connu quand il y en a un.
//!
//! ## 🔴 Une app n'est jamais propriétaire de son compartiment
//!
//! Les permissions accordées sont `read` + `write`, jamais `owner`. Propriétaire, une
//! app compromise pourrait supprimer son propre compartiment — donc effacer d'un coup
//! ce que les sauvegardes protégeaient — ou s'accorder l'accès à d'autres. C'est le
//! même raisonnement que le rôle PostgreSQL isolé (§3.1).

use serde::Deserialize;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Garage injoignable : {0}")]
    Unreachable(String),

    #[error("Garage a refusé {operation} : {status} — {body}")]
    Rejected {
        operation: &'static str,
        status: u16,
        body: String,
    },

    #[error("réponse Garage illisible pour {operation} : {reason}")]
    Malformed {
        operation: &'static str,
        reason: String,
    },

    #[error(
        "🔴 la clé « {0} » existe chez Garage mais son secret est inconnu. \
             Garage ne redonne JAMAIS une clé secrète après sa création : \
             supprime cette clé et relance pour en obtenir une neuve"
    )]
    LostSecret(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Les identifiants remis à une app.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessKey {
    pub access_key_id: String,
    /// 🔴 Ne transite jamais par un plan ni par un journal.
    pub secret_access_key: String,
}

pub struct Garage {
    base: String,
    token: String,
    http: reqwest::Client,
}

#[derive(Deserialize)]
struct BucketCree {
    id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CleCreee {
    access_key_id: String,
    /// Nulle sur toute lecture ultérieure — voir la note en tête de module.
    secret_access_key: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BucketListe {
    id: String,
    #[serde(default)]
    global_aliases: Vec<String>,
}

impl Garage {
    /// `base` est l'URL de l'API d'administration, ex. `http://garage:3903`.
    ///
    /// ⚠️ Ce n'est PAS le point d'entrée S3 (port 3900) : les deux écoutent sur des
    /// ports différents et le jeton d'administration ne vaut rien sur le second.
    pub fn new(base: impl Into<String>, token: impl Into<String>) -> Self {
        Self {
            base: base.into().trim_end_matches('/').to_string(),
            token: token.into(),
            http: reqwest::Client::new(),
        }
    }

    async fn appel(
        &self,
        operation: &'static str,
        methode: reqwest::Method,
        chemin: &str,
        corps: Option<serde_json::Value>,
    ) -> Result<String> {
        let mut req = self
            .http
            .request(methode, format!("{}{chemin}", self.base))
            .bearer_auth(&self.token);

        if let Some(c) = corps {
            req = req.json(&c);
        }

        let rep = req
            .send()
            .await
            .map_err(|e| Error::Unreachable(e.to_string()))?;

        let status = rep.status();
        let body = rep.text().await.unwrap_or_default();

        if !status.is_success() {
            return Err(Error::Rejected {
                operation,
                status: status.as_u16(),
                body: body.chars().take(300).collect(),
            });
        }
        Ok(body)
    }

    /// Garage répond-il ?
    pub async fn health(&self) -> Result<()> {
        self.appel("health", reqwest::Method::GET, "/health", None)
            .await?;
        Ok(())
    }

    /// L'identifiant du compartiment portant cet alias, s'il existe.
    pub async fn bucket_id(&self, alias: &str) -> Result<Option<String>> {
        let corps = self
            .appel("ListBuckets", reqwest::Method::GET, "/v2/ListBuckets", None)
            .await?;

        let liste: Vec<BucketListe> =
            serde_json::from_str(&corps).map_err(|e| Error::Malformed {
                operation: "ListBuckets",
                reason: e.to_string(),
            })?;

        Ok(liste
            .into_iter()
            .find(|b| b.global_aliases.iter().any(|a| a == alias))
            .map(|b| b.id))
    }

    /// Crée le compartiment, ou rend l'existant.
    ///
    /// ⚠️ Idempotent par le nom : recréer un alias déjà pris échouerait, et l'échec
    /// ferait passer une installation reprise pour une panne.
    pub async fn ensure_bucket(&self, alias: &str) -> Result<String> {
        if let Some(id) = self.bucket_id(alias).await? {
            tracing::debug!(alias, "compartiment déjà présent");
            return Ok(id);
        }

        let corps = self
            .appel(
                "CreateBucket",
                reqwest::Method::POST,
                "/v2/CreateBucket",
                Some(serde_json::json!({ "globalAlias": alias })),
            )
            .await?;

        let b: BucketCree = serde_json::from_str(&corps).map_err(|e| Error::Malformed {
            operation: "CreateBucket",
            reason: e.to_string(),
        })?;

        tracing::info!(alias, id = %b.id, "compartiment créé");
        Ok(b.id)
    }

    /// Crée la clé d'accès, ou reprend celle dont on connaît déjà le secret.
    ///
    /// 🔴 `secret_connu` vient du coffre. C'est LUI qui fait autorité, pas Garage :
    /// une clé présente chez Garage dont on a perdu le secret est inutilisable, et
    /// repartir sans lui donnerait à l'app une clé vide — l'échec apparaîtrait comme
    /// une signature S3 invalide, ce qui n'oriente vers rien.
    pub async fn ensure_key(&self, nom: &str, secret_connu: Option<&str>) -> Result<AccessKey> {
        if let Some(s) = secret_connu {
            if let Some(id) = self.key_id(nom).await? {
                return Ok(AccessKey {
                    access_key_id: id,
                    secret_access_key: s.to_string(),
                });
            }
            // Le coffre connaît un secret pour une clé que Garage n'a plus : on en
            // recrée une, et le nouveau secret remplacera l'ancien au coffre.
            tracing::warn!(nom, "clé absente chez Garage malgré un secret au coffre");
        } else if self.key_id(nom).await?.is_some() {
            // Le cas irrattrapable : elle existe, et personne ne connaît son secret.
            return Err(Error::LostSecret(nom.to_string()));
        }

        let corps = self
            .appel(
                "CreateKey",
                reqwest::Method::POST,
                "/v2/CreateKey",
                Some(serde_json::json!({ "name": nom, "neverExpires": true })),
            )
            .await?;

        let k: CleCreee = serde_json::from_str(&corps).map_err(|e| Error::Malformed {
            operation: "CreateKey",
            reason: e.to_string(),
        })?;

        let secret = k.secret_access_key.ok_or_else(|| Error::Malformed {
            operation: "CreateKey",
            reason: "aucune clé secrète dans la réponse de création — \
                     elle n'est donnée qu'à ce moment-là et n'est plus récupérable"
                .into(),
        })?;

        tracing::info!(nom, "clé d'accès créée");
        Ok(AccessKey {
            access_key_id: k.access_key_id,
            secret_access_key: secret,
        })
    }

    /// L'identifiant d'une clé portant ce nom, s'il existe.
    pub async fn key_id(&self, nom: &str) -> Result<Option<String>> {
        let corps = self
            .appel("ListKeys", reqwest::Method::GET, "/v2/ListKeys", None)
            .await?;

        let liste: Vec<serde_json::Value> =
            serde_json::from_str(&corps).map_err(|e| Error::Malformed {
                operation: "ListKeys",
                reason: e.to_string(),
            })?;

        Ok(liste
            .into_iter()
            .find(|k| k.get("name").and_then(|n| n.as_str()) == Some(nom))
            .and_then(|k| {
                k.get("id")
                    .or_else(|| k.get("accessKeyId"))
                    .and_then(|v| v.as_str())
                    .map(str::to_string)
            }))
    }

    /// Donne à la clé la lecture et l'écriture sur le compartiment — **jamais** la
    /// propriété.
    ///
    /// 🔴 `owner: false` n'est pas un détail. Propriétaire, une app compromise pourrait
    /// supprimer son propre compartiment — effaçant d'un coup ce que les sauvegardes
    /// protégeaient — ou s'accorder d'autres accès. Même raisonnement que le rôle
    /// PostgreSQL isolé (§3.1) : l'app peut travailler, pas se déchaîner.
    pub async fn allow(&self, bucket_id: &str, access_key_id: &str) -> Result<()> {
        self.appel(
            "AllowBucketKey",
            reqwest::Method::POST,
            "/v2/AllowBucketKey",
            Some(serde_json::json!({
                "bucketId": bucket_id,
                "accessKeyId": access_key_id,
                "permissions": { "read": true, "write": true, "owner": false }
            })),
        )
        .await?;

        tracing::info!(bucket_id, access_key_id, "accès accordé (lecture/écriture)");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_admin_port_is_not_the_s3_port() {
        // ⚠️ 3903 (administration) et 3900 (S3) sont deux écoutes distinctes. Pointer
        // le client vers le port S3 donnerait des 403 que rien ne rattache au port.
        let g = Garage::new("http://garage:3903/", "jeton");
        assert_eq!(
            g.base, "http://garage:3903",
            "la barre finale doit être retirée"
        );
    }

    #[test]
    fn a_lost_secret_says_what_to_do() {
        // 🔴 Garage ne redonne jamais une clé secrète. Le message doit dire quoi faire,
        // parce que l'action n'a rien d'évident : il faut SUPPRIMER la clé.
        let e = Error::LostSecret("immich".into()).to_string();
        assert!(e.contains("JAMAIS"), "{e}");
        assert!(e.contains("supprime cette clé"), "{e}");
    }

    #[test]
    fn a_creation_without_a_secret_is_an_error_not_an_empty_key() {
        // 🔴 Si `secretAccessKey` manque à la création, on ÉCHOUE. Rendre une clé vide
        // ferait échouer l'app à l'authentification, sur un message S3 qui parle de
        // signature invalide — et qui n'oriente vers rien.
        let sans_secret = r#"{"accessKeyId":"GK123","name":"immich"}"#;
        let k: CleCreee = serde_json::from_str(sans_secret).expect("forme valide");
        assert!(k.secret_access_key.is_none());
    }

    #[test]
    fn a_creation_response_is_parsed() {
        let json = r#"{"accessKeyId":"GK31c2f218","secretAccessKey":"b892c0","name":"immich"}"#;
        let k: CleCreee = serde_json::from_str(json).expect("réponse valide");
        assert_eq!(k.access_key_id, "GK31c2f218");
        assert_eq!(k.secret_access_key.as_deref(), Some("b892c0"));
    }

    #[test]
    fn a_bucket_is_found_by_its_global_alias() {
        let json = r#"[
            {"id":"aaa","globalAliases":["autre"]},
            {"id":"bbb","globalAliases":["immich","photos"]}
        ]"#;
        let l: Vec<BucketListe> = serde_json::from_str(json).expect("liste valide");
        let trouve = l
            .iter()
            .find(|b| b.global_aliases.iter().any(|a| a == "immich"));
        assert_eq!(trouve.map(|b| b.id.as_str()), Some("bbb"));
    }

    #[test]
    fn a_bucket_without_alias_is_never_matched() {
        // Un compartiment sans alias global existe (Garage le permet) : il ne doit
        // jamais être pris pour celui qu'on cherche.
        let json = r#"[{"id":"aaa"}]"#;
        let l: Vec<BucketListe> = serde_json::from_str(json).expect("liste valide");
        assert!(l[0].global_aliases.is_empty());
    }
}
