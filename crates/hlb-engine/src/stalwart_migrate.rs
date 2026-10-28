//! Moving an installed Stalwart from 0.16 to 1.0 (`hlb mail migrate`).
//!
//! 1.0 refuses to open a 0.16 store: the data moves only through `stalwart-migrate`,
//! which copies it into a NEW, empty store and never writes to the old one. So the
//! catalog's 1.0 manifest names a new volume ([`TO_STORAGE`]), the copy is made by the
//! tool's own image as Swarm jobs on Stalwart's node, and the 0.16 volume stays as it
//! was — going back before 1.0 has served anyone is starting 0.16 on it again.
//!
//! Measured on 1.0.3 (fresh 0.16.27 store and a copy of a lab's): it runs without a
//! terminal once `answers.toml` answers every question `prepare` lists, and
//! `run --final --yes` needs none either.

use hlb_orchestrator::{Orchestrator, ServiceSpec};
use hlb_types::{Capability, Manifest};

/// The tool, by digest: the release every measurement here was made with.
pub const IMAGE: &str = "stalwartlabs/stalwart-migrate:1.0.3@sha256:1e936a872424bb8856ac2186129266f5179e516d9dbf58853c73364e6e0fc563";

/// The one 0.16 the tool migrates. 🔴 It does not check: a store from a 0.16 built
/// 2026-10-11 was prepared without a word, so the digest is checked here.
pub const SOURCE_TAG: &str = "v0.16.27";
pub const SOURCE_DIGEST: &str =
    "sha256:c429b311c93db5606598abc1c68225a85a6953183848ae01bee9c6a98885836c";

/// The 0.16 store's storage, and the 1.0 one's: a new name is a new, empty volume.
pub const FROM_STORAGE: &str = "data";
pub const TO_STORAGE: &str = "data-v1";

/// Where the tool keeps its progress between runs: its answers, the position of every
/// account, the report. Outside both stores, which it refuses otherwise.
pub const STATE_STORAGE: &str = "migrate";

const REPO: &str = "stalwartlabs/stalwart";
const DATA_PATH: &str = "/var/lib/stalwart";
const TARGET_PATH: &str = "/var/lib/stalwart-v1";
const STATE_PATH: &str = "/var/lib/stalwart-migrate";
const SOURCE_CONFIG: &str = "/run/hlb/source.json";
const TARGET_CONFIG: &str = "/run/hlb/target.json";
const ANSWERS: &str = "/run/hlb/answers.toml";

/// The catalog's own line on both sides: 1.0 mounts its new volume where 0.16 had its
/// own, and `--target-path-map` points the tool at it instead.
const CONFIG: &str = r#"{"@type":"RocksDb","path":"/var/lib/stalwart/"}"#;

/// Every question a store made by Homelabus raises, answered. 🔴 Each one: the file's own
/// "fields left out take the recommended value" is false — `prepare` lists every one
/// left out as "not answered", and `run` refuses to start.
///
/// Every category, the queue included: it is handed over by the final run, with 0.16
/// stopped, so nothing is delivered twice. OAuth clients are accepted as v1 registers
/// them — Homelabus registers none of its own with Stalwart.
pub const ANSWERS_TOML: &str = r#"version = 1

[global.categories]
include = ["settings", "principals", "mail", "calendars", "contacts", "files", "sieve", "identities", "push_subscriptions", "spam_samples", "reports", "archive", "spam_model", "queue", "tasks", "telemetry"]

[global.changed_defaults]
policy = "recommended"

[global.new_permissions]
action = "grant"

[instance.oauth_registration."x:OidcProvider"]
action = "accept"
"#;

/// A pass of the tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pass {
    /// With 0.16 serving: copies everything, and on a second pass what changed since.
    Copy,
    /// With 0.16 stopped: the last changes, the queue and the tasks, the store finalized,
    /// then every account compared.
    Final,
}

/// How a pass ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Done(Vec<String>),
    /// `prepare` asks what [`ANSWERS_TOML`] does not answer: the store holds something
    /// a person must decide on. Nothing was copied.
    Questions(Vec<String>),
    Failed(Vec<String>),
}

/// Is `next` a Stalwart that opens a new store where `frozen` has a 0.16 one?
pub fn crossing(frozen: &Manifest, next: &Manifest) -> bool {
    frozen.spec.image.repo == REPO
        && next.spec.image.repo == REPO
        && own_storage(frozen, FROM_STORAGE)
        && !own_storage(frozen, TO_STORAGE)
        && own_storage(next, TO_STORAGE)
}

/// What stops the migration before anything is touched.
pub fn blockers(frozen: &Manifest, catalog: &Manifest) -> Vec<String> {
    let mut out = Vec::new();
    if !crossing(frozen, catalog) {
        out.push(format!(
            "nothing to migrate: the installed Stalwart has no \"{FROM_STORAGE}\" store for the \
             catalog's \"{TO_STORAGE}\" — it is migrated already, or the catalog has not moved"
        ));
        return out;
    }
    let image = &frozen.spec.image;
    if image.digest.as_deref() != Some(SOURCE_DIGEST) {
        out.push(format!(
            "it runs {}:{}{}, and the tool migrates {SOURCE_TAG} only: `hlb update apply \
             stalwart` takes it there first",
            image.repo,
            image.tag,
            image
                .digest
                .as_deref()
                .map(|d| format!("@{}", &d[..d.len().min(19)]))
                .unwrap_or_default()
        ));
    }
    out
}

/// The installation as the copy leaves it: its store in the new volume. What an upgrade
/// to the catalog then refuses, it refuses for every other reason.
pub fn after_copy(frozen: &Manifest) -> Manifest {
    let mut m = frozen.clone();
    for c in &mut m.spec.requires {
        if let Capability::Storage {
            name, owner: None, ..
        } = c
        {
            if name == FROM_STORAGE {
                *name = TO_STORAGE.to_string();
            }
        }
    }
    m
}

/// The volumes a migration of `app` reads and writes: the 0.16 store, the 1.0 one, the
/// tool's state.
pub fn volumes(app: &str) -> [String; 3] {
    [
        format!("{app}-{FROM_STORAGE}"),
        format!("{app}-{TO_STORAGE}"),
        format!("{app}-{STATE_STORAGE}"),
    ]
}

/// The job of one pass, on the node holding `app`'s data.
pub fn job(app: &str, pass: Pass) -> ServiceSpec {
    let common = format!(
        "--source {SOURCE_CONFIG} --target {TARGET_CONFIG} --state {STATE_PATH} \
         --target-path-map {DATA_PATH}={TARGET_PATH}"
    );
    // `prepare` every pass: a setting changed since the last one may raise a question,
    // and `run` would refuse it less clearly.
    let run = match pass {
        Pass::Copy => format!("stalwart-migrate run {common}"),
        Pass::Final => format!(
            "stalwart-migrate run --final --yes {common} && stalwart-migrate verify --full {common}"
        ),
    };
    let script = format!(
        "set -e; cp {ANSWERS} {STATE_PATH}/answers.toml; \
         stalwart-migrate prepare --non-interactive --source {SOURCE_CONFIG} --state {STATE_PATH}; \
         {run}"
    );
    let [from, to, state] = volumes(app);
    // Its image runs as Stalwart's own user (uid 2000): a new volume first mounted there
    // takes that owner, and 1.0 opens it as its own.
    let mut job = ServiceSpec::new(format!("{app}-migrate"), IMAGE)
        .job()
        .constraint(hlb_types::manifest::data_constraint(app))
        .mount(from, DATA_PATH)
        .mount(to, TARGET_PATH)
        .mount(state, STATE_PATH)
        .file(SOURCE_CONFIG, CONFIG)
        .file(TARGET_CONFIG, CONFIG)
        .file(ANSWERS, ANSWERS_TOML)
        .command(["sh", "-c", &script]);
    job.hardening.tmpfs = vec!["/tmp".into()];
    job
}

/// Runs one pass and reads how it ended.
pub async fn run<O: Orchestrator + ?Sized>(
    orch: &O,
    app: &str,
    pass: Pass,
    timeout_secs: u64,
) -> crate::Result<Outcome> {
    let out = orch.run_job(&job(app, pass), timeout_secs).await?;
    if out.succeeded {
        return Ok(Outcome::Done(out.output));
    }
    let questions = open_questions(&out.output);
    Ok(if questions.is_empty() {
        Outcome::Failed(out.output)
    } else {
        Outcome::Questions(questions)
    })
}

/// The questions `prepare --non-interactive` says are not answered, one per line after
/// its "run will refuse to start" — a log line may carry a prefix before it.
pub fn open_questions(output: &[String]) -> Vec<String> {
    let mut lines = output.iter();
    for line in lines.by_ref() {
        if line.contains("run will refuse to start until these are resolved") {
            break;
        }
    }
    lines
        .map(|l| l.trim())
        .take_while(|l| l.ends_with("not answered"))
        .map(str::to_string)
        .collect()
}

fn own_storage(m: &Manifest, wanted: &str) -> bool {
    m.spec
        .requires
        .iter()
        .any(|c| matches!(c, Capability::Storage { name, owner: None, .. } if name == wanted))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stalwart(tag: &str, digest: &str, storage: &str) -> Manifest {
        let yaml = format!(
            r#"
apiVersion: hlb/v1
kind: PlatformService
metadata: {{ name: stalwart }}
spec:
  image: {{ repo: stalwartlabs/stalwart, tag: "{tag}", digest: "{digest}" }}
  requires:
    - {{ kind: storage, name: {storage}, path: /var/lib/stalwart, tier: local, backup: true }}
"#
        );
        serde_yaml_ng::from_str(&yaml).expect("manifest")
    }

    #[test]
    fn only_a_027_store_facing_a_new_volume_is_migrated() {
        let old = stalwart(SOURCE_TAG, SOURCE_DIGEST, FROM_STORAGE);
        let catalog = stalwart("v1.0.0", "sha256:new", TO_STORAGE);
        assert!(crossing(&old, &catalog));
        assert_eq!(blockers(&old, &catalog), Vec::<String>::new());

        // The lab's: a 0.16 built before 0.16.27, which the tool takes without a word.
        let older = stalwart("v0.16", "sha256:254ce5d7f3dbe4bb", FROM_STORAGE);
        let b = blockers(&older, &catalog);
        assert!(b[0].contains("`hlb update apply stalwart`"), "{b:?}");

        // Migrated already: its frozen manifest is the catalog's.
        assert!(!crossing(&catalog, &catalog));
        assert!(blockers(&catalog, &catalog)[0].contains("nothing to migrate"));
    }

    #[test]
    fn after_the_copy_the_store_is_the_new_volume() {
        let old = stalwart(SOURCE_TAG, SOURCE_DIGEST, FROM_STORAGE);
        let catalog = stalwart("v1.0.0", "sha256:new", TO_STORAGE);
        // An upgrade alone is refused, and says the way rather than "remove and install".
        let refused = crate::upgrade::refusals(&old, &crate::upgrade::next(&old, &catalog));
        assert!(refused[0].contains("`hlb mail migrate --apply`"), "{refused:?}");
        let copied = after_copy(&old);
        assert!(!crossing(&copied, &catalog));
        assert_eq!(
            crate::upgrade::refusals(&copied, &crate::upgrade::next(&copied, &catalog)),
            Vec::<String>::new()
        );
    }

    #[test]
    fn every_question_a_homelabus_store_raises_is_answered() {
        // The four `prepare` listed on a fresh 0.16.27 store and on the lab's, by key.
        for key in [
            "[global.categories]",
            "[global.changed_defaults]",
            "[global.new_permissions]",
            "[instance.oauth_registration.\"x:OidcProvider\"]",
        ] {
            assert!(ANSWERS_TOML.contains(key), "{key}");
        }
        // The queue and the tasks too: the final run hands them over with 0.16 stopped.
        for category in ["\"queue\"", "\"tasks\"", "\"mail\"", "\"principals\""] {
            assert!(ANSWERS_TOML.contains(category), "{category}");
        }
    }

    #[test]
    fn the_copy_runs_live_and_the_final_pass_alone_stops_and_compares() {
        let copy = job("stalwart", Pass::Copy);
        let script = copy.command.last().expect("script");
        assert!(script.contains("prepare --non-interactive"));
        assert!(!script.contains("--final"));
        let fin = job("stalwart", Pass::Final);
        let script = fin.command.last().expect("script");
        assert!(script.contains("run --final --yes"));
        assert!(script.contains("verify --full"));
        // Where Stalwart's data is, by digest, onto the three volumes.
        assert!(fin
            .constraints
            .contains(&hlb_types::manifest::data_constraint("stalwart")));
        assert!(IMAGE.contains("@sha256:"));
        assert_eq!(
            fin.mounts,
            vec![
                ("stalwart-data".to_string(), DATA_PATH.to_string()),
                ("stalwart-data-v1".to_string(), TARGET_PATH.to_string()),
                ("stalwart-migrate".to_string(), STATE_PATH.to_string()),
            ]
        );
    }

    #[test]
    fn the_questions_left_open_are_read_from_preparess_output() {
        // As 1.0.3 printed it with no answers.
        let out: Vec<String> = [
            "Summary: 2770 objects to write, 0 dropped, 47 warnings, 0 errors, 0 questions answered now.",
            "run will refuse to start until these are resolved:",
            "  categories: not answered",
            "  oauth_registration for x:OidcProvider: not answered",
            "something else",
        ]
        .map(String::from)
        .to_vec();
        assert_eq!(
            open_questions(&out),
            vec![
                "categories: not answered",
                "oauth_registration for x:OidcProvider: not answered"
            ]
        );
        assert!(open_questions(&["Error: the target store is not empty".into()]).is_empty());
    }
}
