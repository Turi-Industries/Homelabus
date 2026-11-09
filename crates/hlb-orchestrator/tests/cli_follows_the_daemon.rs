//! Every `docker` the orchestrator runs goes through `SwarmOrchestrator::cli`, which
//! aims it at the orchestrator's own daemon. A bare one reached the local daemon from an
//! orchestrator of a site's, bridged over SSH: the house's probe and previous spec were
//! read for the site's services of the same name (the lab, 2026-11-09).

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::Path;

fn sources(dir: &Path, out: &mut Vec<(String, String)>) {
    for entry in std::fs::read_dir(dir).expect("src") {
        let path = entry.expect("entry").path();
        if path.is_dir() {
            sources(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            let text = std::fs::read_to_string(&path).expect("read");
            out.push((path.display().to_string(), text));
        }
    }
}

#[test]
fn the_docker_cli_is_built_in_one_place() {
    let mut files = Vec::new();
    sources(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut files,
    );
    // The floor: lib.rs, swarm.rs and tar.rs today. A walk that reads nothing passes.
    assert!(files.len() >= 3, "read {} files", files.len());

    let bare = format!("{}::new(\"{}\")", "Command", "docker");
    let mut found = Vec::new();
    for (path, text) in &files {
        for (i, line) in text.lines().enumerate() {
            let code = line.trim_start();
            if code.contains(&bare) && !code.starts_with("//") {
                found.push(format!("{path}:{}", i + 1));
            }
        }
    }
    assert_eq!(
        found.len(),
        1,
        "only `SwarmOrchestrator::cli` builds the docker CLI: {found:?}"
    );
    let swarm = files
        .iter()
        .find(|(p, _)| p.ends_with("swarm.rs"))
        .expect("swarm.rs");
    let cli = swarm.1.find("fn cli(&self)").expect("fn cli");
    let line = swarm.1[..cli].lines().count();
    let built: usize = found[0]
        .rsplit(':')
        .next()
        .and_then(|n| n.parse().ok())
        .expect("line");
    assert!(
        built > line && built < line + 5,
        "the one docker CLI is not cli()'s: {found:?}"
    );
}
