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
//!
//! ## Multi-node goes through `layout`, not through `replicas`
//!
//! One Garage process holds its data in a local LMDB database. Two Swarm replicas of
//! the same service would each open their own, independent copy - not a cluster, two
//! silently diverging ones. A second Garage node is a SEPARATE process (its own Swarm
//! service, its own volume, sharing only the RPC secret), and once it has joined the
//! cluster it carries **zero capacity** until [`Garage::assign_layout`] gives it some.
//!
//! [`Garage::assign_layout`] only **stages** a change - nothing is redistributed until
//! [`Garage::apply_layout`] confirms the exact version just staged. Applying blind
//! would let two operators' changes overwrite each other in silence, the same race
//! `record_plan`'s versioning exists to prevent elsewhere in this codebase.
//!
//! ⚠️ Written from Garage's admin API documentation, not exercised against a running
//! multi-node cluster - the same caveat as the rest of this crate's untested paths.

pub mod s3;

// The HTTP client a streamed object's body is built with.
pub use reqwest;

use serde::Deserialize;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Garage unreachable : {0}")]
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
    /// Where `hlb` reaches the S3 API, when it must speak it: a bucket's lifecycle is
    /// an S3 call, which the admin API does not offer.
    s3: Option<String>,
}

/// The S3 API, as the overlay names it — what the apps are handed.
pub const S3_URL: &str = "http://garage:3900";

#[derive(Deserialize)]
struct BucketCreated {
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
struct BucketList {
    id: String,
    #[serde(default)]
    global_aliases: Vec<String>,
}

/// What Garage holds, as the apps' storage is checked against it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Inventory {
    /// Every bucket's global aliases.
    pub buckets: std::collections::BTreeSet<String>,
    /// Every key's id, by its name.
    pub keys: std::collections::BTreeMap<String, String>,
}

/// A node Garage has seen on the network, whether or not it carries any capacity yet.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KnownNode {
    pub id: String,
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default)]
    pub is_up: bool,
    /// The disk under the node's data directory, as the node itself measures it.
    #[serde(default)]
    pub data_partition: Option<Partition>,
}

/// A partition's size and free space, in bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub struct Partition {
    pub available: u64,
    pub total: u64,
}

impl KnownNode {
    /// The capacity offered to a node that has none: nine tenths of the space free on
    /// its data partition NOW. Free space rather than size — the partition may hold
    /// the system and other volumes — and a tenth kept back so that Garage filling its
    /// share does not fill the disk. `None` when the node reports no partition.
    pub fn proposed_capacity(&self) -> Option<u64> {
        self.data_partition
            .map(|p| p.available / 10 * 9)
            .filter(|c| *c > 0)
    }
}

/// One node's place in the layout: where it sits, and how much it carries.
///
/// `capacity` is `None` for a node that has joined but was never assigned any -
/// exactly the state a freshly added Garage node starts in.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeRole {
    pub id: String,
    #[serde(default)]
    pub zone: Option<String>,
    #[serde(default)]
    pub capacity: Option<u64>,
}

/// The cluster's data layout, as Garage currently has it applied.
///
/// 🔴 `version` is not informational: [`Garage::apply_layout`] must repeat it exactly,
/// or a change staged by someone else in the meantime would be silently applied
/// alongside yours instead of being seen and reconciled.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClusterLayout {
    /// The version CURRENTLY applied — not the one a staged change becomes.
    pub version: u64,
    #[serde(default)]
    pub roles: Vec<NodeRole>,
}

impl ClusterLayout {
    /// The version that applying the staged changes produces, the one
    /// [`Garage::apply_layout`] must be given.
    ///
    /// ⚠️ Garage answers a staging with the CURRENT layout. `hlb garage assign` printed
    /// that number as the one to commit, and committing it was refused — checked
    /// against Garage v2.3.0 on 2026-10-11.
    pub fn next_version(&self) -> u64 {
        self.version + 1
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClusterStatusBrute {
    // ⚠️ Garage has renamed this field across versions; accepting both is cheaper
    // than a client that silently sees zero nodes after an upgrade.
    #[serde(default, alias = "knownNodes")]
    nodes: Vec<KnownNode>,
}

/// Known nodes that have not been given a place in the layout yet.
///
/// ⚠️ Kept as a pure function of two already-fetched lists, not a method on either
/// type: testable without a server, the same reasoning as `zfs::PoolDecision::decide`.
pub fn awaiting_assignment<'a>(
    known: &'a [KnownNode],
    layout: &ClusterLayout,
) -> Vec<&'a KnownNode> {
    known
        .iter()
        .filter(|n| !layout.roles.iter().any(|r| r.id == n.id))
        .collect()
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
            s3: None,
        }
    }

    /// The S3 API reached at `endpoint` from here — [`S3_URL`] on the overlay, a relay
    /// from a host.
    pub fn with_s3(mut self, endpoint: impl Into<String>) -> Self {
        self.s3 = Some(endpoint.into().trim_end_matches('/').to_string());
        self
    }

    pub fn s3_endpoint(&self) -> Option<&str> {
        self.s3.as_deref()
    }

    async fn call(
        &self,
        operation: &'static str,
        method: reqwest::Method,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> Result<String> {
        let mut req = self
            .http
            .request(method, format!("{}{path}", self.base))
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
        self.call("health", reqwest::Method::GET, "/health", None)
            .await?;
        Ok(())
    }

    /// The id of the bucket carrying this alias, if there is one.
    pub async fn bucket_id(&self, alias: &str) -> Result<Option<String>> {
        Ok(self
            .buckets()
            .await?
            .into_iter()
            .find(|b| b.global_aliases.iter().any(|a| a == alias))
            .map(|b| b.id))
    }

    async fn buckets(&self) -> Result<Vec<BucketList>> {
        let body = self
            .call("ListBuckets", reqwest::Method::GET, "/v2/ListBuckets", None)
            .await?;
        serde_json::from_str(&body).map_err(|e| Error::Malformed {
            operation: "ListBuckets",
            reason: e.to_string(),
        })
    }

    /// Every bucket alias and every key Garage holds, in two calls — what a check over
    /// every app reads once rather than twice per app.
    pub async fn inventory(&self) -> Result<Inventory> {
        Ok(Inventory {
            buckets: self
                .buckets()
                .await?
                .into_iter()
                .flat_map(|b| b.global_aliases)
                .collect(),
            keys: self.keys().await?,
        })
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
            .call(
                "CreateBucket",
                reqwest::Method::POST,
                "/v2/CreateBucket",
                Some(serde_json::json!({ "globalAlias": alias })),
            )
            .await?;

        let b: BucketCreated = serde_json::from_str(&body).map_err(|e| Error::Malformed {
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
            .call(
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
        Ok(self.keys().await?.remove(name))
    }

    /// Every named key, by name. ⚠️ Two keys of one name: the first listed wins, as
    /// `key_id` always had it.
    async fn keys(&self) -> Result<std::collections::BTreeMap<String, String>> {
        let body = self
            .call("ListKeys", reqwest::Method::GET, "/v2/ListKeys", None)
            .await?;

        let list: Vec<serde_json::Value> =
            serde_json::from_str(&body).map_err(|e| Error::Malformed {
                operation: "ListKeys",
                reason: e.to_string(),
            })?;

        let mut keys = std::collections::BTreeMap::new();
        for k in list {
            let name = k.get("name").and_then(|n| n.as_str());
            let id = k
                .get("id")
                .or_else(|| k.get("accessKeyId"))
                .and_then(|v| v.as_str());
            if let (Some(name), Some(id)) = (name, id) {
                keys.entry(name.to_string())
                    .or_insert_with(|| id.to_string());
            }
        }
        Ok(keys)
    }

    /// Grants the key read and write on the bucket - **never** ownership.
    ///
    /// 🔴 `owner: false` is not a detail. As owner, a compromised app could delete its
    /// own bucket - erasing in one go what the backups protected - or grant itself
    /// other access. Same reasoning as the isolated PostgreSQL role: the app can work,
    /// not run wild.
    pub async fn allow(&self, bucket_id: &str, access_key_id: &str) -> Result<()> {
        self.call(
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

    /// Nodes Garage has seen on the network — joined or not, assigned or not.
    pub async fn known_nodes(&self) -> Result<Vec<KnownNode>> {
        let body = self
            .call(
                "GetClusterStatus",
                reqwest::Method::GET,
                "/v2/GetClusterStatus",
                None,
            )
            .await?;

        let s: ClusterStatusBrute = serde_json::from_str(&body).map_err(|e| Error::Malformed {
            operation: "GetClusterStatus",
            reason: e.to_string(),
        })?;
        Ok(s.nodes)
    }

    /// The layout currently applied.
    pub async fn layout(&self) -> Result<ClusterLayout> {
        let body = self
            .call(
                "GetClusterLayout",
                reqwest::Method::GET,
                "/v2/GetClusterLayout",
                None,
            )
            .await?;

        serde_json::from_str(&body).map_err(|e| Error::Malformed {
            operation: "GetClusterLayout",
            reason: e.to_string(),
        })
    }

    /// Stages a capacity and zone for one node.
    ///
    /// 🔴 This only STAGES the change — see the module doc. Nothing is redistributed
    /// until [`Garage::apply_layout`] confirms the version this call returns.
    pub async fn assign_layout(
        &self,
        node_id: &str,
        zone: &str,
        capacity_bytes: u64,
    ) -> Result<ClusterLayout> {
        let body = self
            .call(
                "UpdateClusterLayout",
                reqwest::Method::POST,
                "/v2/UpdateClusterLayout",
                Some(serde_json::json!({
                    "roles": [{
                        "id": node_id,
                        "zone": zone,
                        "capacity": capacity_bytes,
                        "tags": [],
                    }]
                })),
            )
            .await?;

        serde_json::from_str(&body).map_err(|e| Error::Malformed {
            operation: "UpdateClusterLayout",
            reason: e.to_string(),
        })
    }

    /// Applies the staged layout, redistributing data across the cluster.
    ///
    /// 🔴 `version` must be the exact one just staged — the same discipline as
    /// `record_plan`'s versioning. Garage refuses a mismatched version rather than
    /// guessing which change was meant, so a change staged by someone else in the
    /// meantime is seen, never silently applied alongside yours.
    pub async fn apply_layout(&self, version: u64) -> Result<()> {
        self.call(
            "ApplyClusterLayout",
            reqwest::Method::POST,
            "/v2/ApplyClusterLayout",
            Some(serde_json::json!({ "version": version })),
        )
        .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn a_node_is_offered_nine_tenths_of_what_is_free_on_its_disk() {
        // The shape Garage v2.3.0 answers GetClusterStatus with.
        let n: KnownNode = serde_json::from_str(
            r#"{"id":"3d7f","hostname":"a9f2","isUp":true,"role":null,
                "dataPartition":{"available":64648163328,"total":499789058048}}"#,
        )
        .expect("parsable");
        assert_eq!(n.proposed_capacity(), Some(58_183_346_988));
        let none: KnownNode = serde_json::from_str(r#"{"id":"x"}"#).expect("parsable");
        assert_eq!(none.proposed_capacity(), None);
    }

    use super::*;

    #[test]
    fn the_admin_port_is_not_the_s3_port() {
        // ⚠️ 3903 (admin) and 3900 (S3) are two distinct listeners. Pointing the
        // client at the S3 port would give 403s that nothing ties back to the port.
        let g = Garage::new("http://garage:3903/", "token");
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
            {"id":"aaa","globalAliases":["other"]},
            {"id":"bbb","globalAliases":["immich","photos"]}
        ]"#;
        let l: Vec<BucketList> = serde_json::from_str(json).expect("list valide");
        let found = l
            .iter()
            .find(|b| b.global_aliases.iter().any(|a| a == "immich"));
        assert_eq!(found.map(|b| b.id.as_str()), Some("bbb"));
    }

    #[test]
    fn a_bucket_without_alias_is_never_matched() {
        // A bucket with no global alias can exist (Garage allows it): it must never
        // be mistaken for the one being looked for.
        let json = r#"[{"id":"aaa"}]"#;
        let l: Vec<BucketList> = serde_json::from_str(json).expect("list valide");
        assert!(l[0].global_aliases.is_empty());
    }

    #[test]
    fn a_node_present_in_roles_is_not_awaiting_assignment() {
        let known = vec![
            KnownNode {
                id: "aaa".into(),
                hostname: Some("nas-01".into()),
                is_up: true,
                data_partition: None,
            },
            KnownNode {
                id: "bbb".into(),
                hostname: Some("nas-02".into()),
                is_up: true,
                data_partition: None,
            },
        ];
        let layout = ClusterLayout {
            version: 3,
            roles: vec![NodeRole {
                id: "aaa".into(),
                zone: Some("home".into()),
                capacity: Some(1_000_000_000),
            }],
        };
        let waiting = awaiting_assignment(&known, &layout);
        assert_eq!(waiting.len(), 1);
        assert_eq!(waiting[0].id, "bbb");
    }

    #[test]
    fn an_empty_layout_leaves_every_known_node_awaiting() {
        let known = vec![KnownNode {
            id: "aaa".into(),
            hostname: None,
            is_up: true,
            data_partition: None,
        }];
        let layout = ClusterLayout {
            version: 0,
            roles: Vec::new(),
        };
        assert_eq!(awaiting_assignment(&known, &layout).len(), 1);
    }

    #[test]
    fn the_cluster_status_field_rename_is_accepted_both_ways() {
        let recent = r#"{"nodes":[{"id":"aaa","hostname":"nas-01","isUp":true}]}"#;
        let older = r#"{"knownNodes":[{"id":"aaa","hostname":"nas-01","isUp":true}]}"#;
        let a: ClusterStatusBrute = serde_json::from_str(recent).expect("recent shape");
        let b: ClusterStatusBrute = serde_json::from_str(older).expect("older shape");
        assert_eq!(a.nodes.len(), 1);
        assert_eq!(b.nodes.len(), 1);
    }

    #[test]
    fn a_role_with_no_capacity_is_a_gateway_not_a_parse_error() {
        // Garage allows a node that routes requests without storing anything: its
        // `capacity` is `null`, not absent and not zero.
        let json = r#"{"version":5,"roles":[{"id":"aaa","zone":"home","capacity":null}]}"#;
        let l: ClusterLayout = serde_json::from_str(json).expect("valid layout");
        assert_eq!(l.roles[0].capacity, None);
    }
}
