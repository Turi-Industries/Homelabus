//! A secret reaches a container as a file, never through its environment.
//!
//! An environment is readable by whoever reads the service: `docker inspect`, the Swarm
//! API, every process's `/proc/<pid>/environ` in the container, a crash report that
//! dumps it. A `files:` entry is a Swarm secret — encrypted in the Raft log, mounted in
//! memory, seen by nobody listing the service.
//!
//! The catalog is moving over: this counts what is left, and is held EQUAL to it, so a
//! migration lowers the number in the same change and a new secret in an environment
//! fails here rather than waiting for someone to count.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use hlb_types::binding::carries_secret;

/// What is left. Lowered by each app moved; it only ever goes down, to zero — then this
/// test becomes a refusal in `catalog validate`.
const STILL_IN_AN_ENVIRONMENT: usize = 21;

/// Every variable of the catalog handing a container a secret, `app scope VARIABLE`,
/// and how many variables were read in all.
fn secrets_in_environments() -> (Vec<String>, usize) {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../../catalog");
    let catalog = hlb_catalog::Catalog::load(root).expect("catalog");
    let (mut found, mut read) = (Vec::new(), 0);
    for m in catalog.manifests() {
        let app = &m.metadata.name;
        let scopes = [("env".to_string(), &m.spec.env)]
            .into_iter()
            .chain([("sharedEnv".to_string(), &m.spec.shared_env)])
            .chain(
                m.spec
                    .companions
                    .iter()
                    .map(|c| (format!("companion {}", c.name), &c.env)),
            );
        for (scope, env) in scopes {
            for (name, value) in env {
                read += 1;
                if carries_secret(value) {
                    found.push(format!("{app} {scope} {name}"));
                }
            }
        }
    }
    found.sort();
    (found, read)
}

#[test]
fn no_new_secret_reaches_a_container_through_its_environment() {
    let (found, read) = secrets_in_environments();
    // The floor under the scan, which must hold at zero secrets too: the catalog's
    // environments held 300 variables or more on 2026-10-28.
    assert!(
        read >= 300,
        "the scan read {read} variables: it stopped reading the catalog"
    );
    assert_eq!(
        found.len(),
        STILL_IN_AN_ENVIRONMENT,
        "secrets in an environment:\n  {}\n\nMoved one to a file? Lower \
         STILL_IN_AN_ENVIRONMENT. Added one? Hand it over as a `files:` entry instead.",
        found.join("\n  ")
    );
}
