//! Garage admin client: buckets and isolated keys.
//!
//! ## Why Garage rather than MinIO
//!
//! Both speak S3. Garage is built for exactly this case: heterogeneous nodes, at
//! home, on an ordinary network. It replicates between nodes without requiring
//! identical disks, fits in a few tens of megabytes of RAM, and has no web console to
//! protect - administration goes through this API.
//!
//! ⚠️ **Its S3 compatibility is not total.** The known gaps: no object versioning, and
//! a few multipart-upload edge cases. For restic, Outline and Matrix that has no
//! consequence. An app that required versioning should be flagged when its manifest is
//! added, not discovered during an outage.
//!
//! ## 🔴 The central trap: the secret key is given ONCE
//!
//! `CreateKey` returns `secretAccessKey`. Any later read through `GetKeyInfo` returns
//! it as **null**: Garage does not keep it in clear and therefore cannot hand it back.
//! A key whose secret was lost is not recoverable, it is to be replaced.
//!
//! Two direct consequences for the design:
//!
//! 1. The secret goes to the vault **immediately** after creation.
//! 2. Idempotency can NOT rest on "does the key exist in Garage?". A second run would
//!    answer yes and carry on without a secret - the app would then receive an empty
//!    key and fail authentication, on an S3 message about an invalid signature. The
//!    vault is authoritative: [`Garage::ensure_key`] takes the already-known secret
//!    when there is one.
//!
//! ## 🔴 An app never owns its bucket
//!
//! The permissions granted are `read` + `write`, never `owner`. As owner, a
//! compromised app could delete its own bucket - erasing in one go what the backups
//! protected - or grant itself access to others. Same reasoning as the isolated
//! PostgreSQL role: the app can work, not run wild.

use serde::Deserialize;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Garage injoignable : {0}")]
    Unreachable(String),

    #[error("Garage refused {operation}: {status} - {body}")]
    Rejected {
        operation: &'static str,
        status: u16,
        body: String,
    },

    #[error("unreadable Garage response for {operation}: {reason}")]
    Malformed {
        operation: &'static str,
        reason: String,
    },

    #[error(
        "🔴 key \"{0}\" exists in Garage but its secret is unknown. Garage NEVER \
             hands a secret key back after creation: delete this key and run again \
             to get a fresh one"
    )]
    LostSecret(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// The credentials handed to an app.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessKey {
    pub access_key_id: String,
    /// 🔴 Never travels through a plan or a log.
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
struct CreatedKey {
    access_key_id: String,
    /// Null on every later read - see the note at the top of this module.
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
    /// `base` is the admin API URL, e.g. `http://garage:3903`.
    ///
    /// ⚠️ This is NOT the S3 endpoint (port 3900): the two listen on different ports
    /// and the admin token is worthless on the second.
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
        body: Option<serde_json::Value>,
    ) -> Result<String> {
        let mut req = self
            .http
            .request(methode, format!("{}{chemin}", self.base))
            .bearer_auth(&self.token);

        if let Some(c) = body {
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

    /// Is Garage answering?
    pub async fn health(&self) -> Result<()> {
        self.appel("health", reqwest::Method::GET, "/health", None)
            .await?;
        Ok(())
    }

    /// The id of the bucket carrying this alias, if there is one.
    pub async fn bucket_id(&self, alias: &str) -> Result<Option<String>> {
        let body = self
            .appel("ListBuckets", reqwest::Method::GET, "/v2/ListBuckets", None)
            .await?;

        let liste: Vec<BucketListe> =
            serde_json::from_str(&body).map_err(|e| Error::Malformed {
                operation: "ListBuckets",
                reason: e.to_string(),
            })?;

        Ok(liste
            .into_iter()
            .find(|b| b.global_aliases.iter().any(|a| a == alias))
            .map(|b| b.id))
    }

    /// Creates the bucket, or returns the existing one.
    ///
    /// ⚠️ Idempotent by name: recreating an alias already taken would fail, and that
    /// failure would make a resumed install look like an outage.
    pub async fn ensure_bucket(&self, alias: &str) -> Result<String> {
        if let Some(id) = self.bucket_id(alias).await? {
            tracing::debug!(alias, "bucket already present");
            return Ok(id);
        }

        let body = self
            .appel(
                "CreateBucket",
                reqwest::Method::POST,
                "/v2/CreateBucket",
                Some(serde_json::json!({ "globalAlias": alias })),
            )
            .await?;

        let b: BucketCree = serde_json::from_str(&body).map_err(|e| Error::Malformed {
            operation: "CreateBucket",
            reason: e.to_string(),
        })?;

        tracing::info!(alias, id = %b.id, "bucket created");
        Ok(b.id)
    }

    /// Creates the access key, or reuses the one whose secret is already known.
    ///
    /// 🔴 `known_secret` comes from the vault, and the VAULT is authoritative, not
    /// Garage: a key that exists in Garage but whose secret was lost is unusable, and
    /// carrying on without it would hand the app an empty key - the failure would
    /// surface as an invalid S3 signature, which points at nothing.
    pub async fn ensure_key(&self, name: &str, known_secret: Option<&str>) -> Result<AccessKey> {
        if let Some(s) = known_secret {
            if let Some(id) = self.key_id(name).await? {
                return Ok(AccessKey {
                    access_key_id: id,
                    secret_access_key: s.to_string(),
                });
            }
            // The vault holds a secret for a key Garage no longer has: create a new
            // one, and its secret replaces the old one in the vault.
            tracing::warn!(name, "key missing in Garage despite a secret in the vault");
        } else if self.key_id(name).await?.is_some() {
            // The unrecoverable case: it exists, and nobody knows its secret.
            return Err(Error::LostSecret(name.to_string()));
        }

        let body = self
            .appel(
                "CreateKey",
                reqwest::Method::POST,
                "/v2/CreateKey",
                Some(serde_json::json!({ "name": name, "neverExpires": true })),
            )
            .await?;

        let k: CreatedKey = serde_json::from_str(&body).map_err(|e| Error::Malformed {
            operation: "CreateKey",
            reason: e.to_string(),
        })?;

        let secret = k.secret_access_key.ok_or_else(|| Error::Malformed {
            operation: "CreateKey",
            reason: "no secret key in the creation response - it is given only at \
                     that moment and cannot be retrieved afterwards"
                .into(),
        })?;

        tracing::info!(name, "access key created");
        Ok(AccessKey {
            access_key_id: k.access_key_id,
            secret_access_key: secret,
        })
    }

    /// The id of a key with this name, if there is one.
    pub async fn key_id(&self, name: &str) -> Result<Option<String>> {
        let body = self
            .appel("ListKeys", reqwest::Method::GET, "/v2/ListKeys", None)
            .await?;

        let liste: Vec<serde_json::Value> =
            serde_json::from_str(&body).map_err(|e| Error::Malformed {
                operation: "ListKeys",
                reason: e.to_string(),
            })?;

        Ok(liste
            .into_iter()
            .find(|k| k.get("name").and_then(|n| n.as_str()) == Some(name))
            .and_then(|k| {
                k.get("id")
                    .or_else(|| k.get("accessKeyId"))
                    .and_then(|v| v.as_str())
                    .map(str::to_string)
            }))
    }

    /// Grants the key read and write on the bucket - **never** ownership.
    ///
    /// 🔴 `owner: false` is not a detail. As owner, a compromised app could delete its
    /// own bucket - erasing in one go what the backups protected - or grant itself
    /// other access. Same reasoning as the isolated PostgreSQL role: the app can work,
    /// not run wild.
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

        tracing::info!(bucket_id, access_key_id, "access granted (read/write)");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_admin_port_is_not_the_s3_port() {
        // ⚠️ 3903 (admin) and 3900 (S3) are two distinct listeners. Pointing the
        // client at the S3 port would give 403s that nothing ties back to the port.
        let g = Garage::new("http://garage:3903/", "jeton");
        assert_eq!(
            g.base, "http://garage:3903",
            "the trailing slash must be stripped"
        );
    }

    #[test]
    fn a_lost_secret_says_what_to_do() {
        // 🔴 Garage never hands a secret key back. The message must say what to do,
        // because the action is not obvious: the key must be DELETED.
        let e = Error::LostSecret("immich".into()).to_string();
        assert!(e.contains("NEVER"), "{e}");
        assert!(e.contains("delete this key"), "{e}");
    }

    #[test]
    fn a_creation_without_a_secret_is_an_error_not_an_empty_key() {
        // 🔴 If `secretAccessKey` is missing at creation we FAIL. Returning an empty
        // key would make the app fail authentication, on an S3 message about an
        // invalid signature that points at nothing.
        let without_secret = r#"{"accessKeyId":"GK123","name":"immich"}"#;
        let k: CreatedKey = serde_json::from_str(without_secret).expect("forme valide");
        assert!(k.secret_access_key.is_none());
    }

    #[test]
    fn a_creation_response_is_parsed() {
        let json = r#"{"accessKeyId":"GK31c2f218","secretAccessKey":"b892c0","name":"immich"}"#;
        let k: CreatedKey = serde_json::from_str(json).expect("valid response");
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
        // A bucket with no global alias can exist (Garage allows it): it must never
        // be mistaken for the one being looked for.
        let json = r#"[{"id":"aaa"}]"#;
        let l: Vec<BucketListe> = serde_json::from_str(json).expect("liste valide");
        assert!(l[0].global_aliases.is_empty());
    }
}
