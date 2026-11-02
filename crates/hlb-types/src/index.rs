//! A catalog source's `index.json`: what a mirror serves, held to what the source's key
//! signed.
//!
//! The signature covers the file's exact bytes (`index.json.sig`, beside it). What it
//! protects against is a host that serves the source: altering a file breaks its digest,
//! serving an older index is caught by `counter`, and withholding every new one by
//! `expires`. The host can still withhold the source altogether — never forge, replay or
//! freeze it.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// How long an index stays valid once built: the owner signs at least this often, and a
/// mirror can hide a fix this long at most (decided 2026-11-02).
pub const VALIDITY_SECS: i64 = 30 * 24 * 3600;

/// The file a source publishes, and the name of its detached signature.
pub const FILE: &str = "index.json";
pub const SIGNATURE_FILE: &str = "index.json.sig";

/// Where an app version's files sit under the index: kept apart per version, so an
/// older `hlb` still finds the last one its range accepts.
pub fn version_dir(app: &str, version: &str) -> String {
    format!("apps/{app}/{version}")
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Index {
    /// The source this index is for: an index signed for another one is refused, even
    /// under the same key.
    pub source: String,
    /// Rises with every index signed: lower than the highest one seen is a replay.
    pub counter: u64,
    /// Unix seconds. Past it, nothing new is installed from the source; what runs
    /// keeps running.
    pub expires: i64,
    /// Each app's versions, oldest first.
    pub apps: BTreeMap<String, Vec<AppVersion>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AppVersion {
    /// The image's tag, `~hlbN` after it for the Nth packaging of that tag: a fix to
    /// the manifest or the guide alone is an update too.
    pub version: String,
    /// The `hlb` range its manifest declares (`metadata.hlb`).
    pub hlb: String,
    /// Each file of the version, by its path under `version_dir`, and its SHA-256.
    pub files: BTreeMap<String, String>,
    /// Every image it runs, pinned: its own and its companions'.
    pub images: Vec<String>,
}
