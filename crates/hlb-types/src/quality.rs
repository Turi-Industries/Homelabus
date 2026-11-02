//! A catalog source's `quality-v1.json`: what its CI proved of each app — installed,
//! updated from the version published before, backed up, restored, removed — beside the
//! index, signed by the same key.
//!
//! A file of its own and not a field of the index: `index.json` is read
//! `deny_unknown_fields` by every release already out, so one field more would make
//! them refuse the whole catalog (`tests/index_format.rs`). An `hlb` that does not know
//! this file never asks for it. Its format is frozen the same way, under the same test.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// The file a source publishes beside its index, and its detached signature.
pub const FILE: &str = "quality-v1.json";
pub const SIGNATURE_FILE: &str = "quality-v1.json.sig";

/// Where a source's CI leaves one app's run, before an index gathers them: `<app>.json`
/// holding a [`Run`].
pub fn run_file(app: &str) -> String {
    format!("{app}.json")
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Quality {
    /// The source it is for, as the index's.
    pub source: String,
    /// The counter of the index it was built with. 🔴 Held equal to it when read: a
    /// mirror could otherwise serve today's index beside an older file saying an app
    /// that broke since still restores.
    pub index: u64,
    pub apps: BTreeMap<String, AppQuality>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AppQuality {
    /// The day the app entered the catalog (`YYYY-MM-DD`): how long it has been
    /// maintained there.
    pub since: String,
    /// The newest run of its cycle; `None` until one ran.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last: Option<Run>,
}

/// One run of an app's cycle on a fresh single-node house.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Run {
    /// The app's version the run installed — what it says nothing beyond.
    pub version: String,
    /// The `hlb` that ran it.
    pub hlb: String,
    /// `YYYY-MM-DD`.
    pub date: String,
    pub install: Outcome,
    /// From the version published before; `notRun` for an app that had none.
    pub update: Outcome,
    pub backup: Outcome,
    pub restore: Outcome,
    pub uninstall: Outcome,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum Outcome {
    Passed,
    Failed,
    /// Not reached — a step before it failed — or nothing to run.
    NotRun,
}

impl Run {
    /// Its steps, in the order the cycle runs them.
    pub fn steps(&self) -> [(&'static str, Outcome); 5] {
        [
            ("install", self.install),
            ("update", self.update),
            ("backup", self.backup),
            ("restore", self.restore),
            ("uninstall", self.uninstall),
        ]
    }
}
