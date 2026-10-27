//! What runs in this repository's CI is pinned, and holds a token that writes nothing
//! it was not given.
//!
//! An action named by its tag runs whatever that tag names on the day — a tag is moved
//! by whoever holds the action's repository, or whoever took it over. By the commit, it
//! runs the code that was read. And a token that can push is what a compromised step
//! needs to rewrite the repository it builds.
//!
//! The workflows are walked, never listed: a workflow added tomorrow is held the same.

#![allow(clippy::expect_used)]

use std::path::PathBuf;

fn workflows() -> Vec<(String, String)> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.github/workflows");
    let mut out: Vec<(String, String)> = std::fs::read_dir(&dir)
        .expect("the workflows directory")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "yml" || x == "yaml"))
        .map(|p| {
            let name = p.file_name().expect("a name").to_string_lossy().to_string();
            (name, std::fs::read_to_string(&p).expect("readable"))
        })
        .collect();
    out.sort();
    out
}

#[test]
fn every_action_is_pinned_by_its_commit() {
    let mut uses = 0;
    for (file, text) in workflows() {
        for (n, line) in text.lines().enumerate() {
            let Some(reference) = line
                .trim_start()
                .trim_start_matches("- ")
                .strip_prefix("uses:")
            else {
                continue;
            };
            uses += 1;
            let reference = reference.split('#').next().unwrap_or("").trim();
            let pinned = reference
                .rsplit_once('@')
                .is_some_and(|(_, at)| at.len() == 40 && at.bytes().all(|b| b.is_ascii_hexdigit()));
            assert!(
                pinned,
                "{file}:{}: `{reference}` — pin it by the commit its tag names, the tag in a comment",
                n + 1
            );
        }
    }
    // The floor: a walk that read nothing would pass.
    assert!(uses >= 20, "only {uses} `uses:` read");
}

/// The workflow's lines before `jobs:`, then each job's lines, keyed by the job's name.
fn jobs(text: &str) -> (Vec<&str>, Vec<(String, Vec<&str>)>) {
    let mut lines = text.lines();
    let head = lines.by_ref().take_while(|l| *l != "jobs:").collect();
    let mut jobs: Vec<(String, Vec<&str>)> = Vec::new();
    for line in lines {
        let name = line
            .strip_prefix("  ")
            .filter(|rest| !rest.starts_with(' ') && rest.ends_with(':'));
        match (name, jobs.last_mut()) {
            (Some(name), _) => jobs.push((name.trim_end_matches(':').to_string(), Vec::new())),
            (None, Some((_, body))) => body.push(line),
            (None, None) => {}
        }
    }
    (head, jobs)
}

#[test]
fn every_workflow_says_what_its_token_may_do() {
    let all = workflows();
    assert!(all.len() >= 3, "{} workflows read", all.len());
    let mut writes = 0;
    for (file, text) in all {
        let (head, jobs) = jobs(&text);
        assert!(!jobs.is_empty(), "{file}: no job read");
        // At the top level: a job without its own block takes this one, and a
        // workflow without it takes the repository's default, which may write.
        assert!(
            head.contains(&"permissions:"),
            "{file}: no top-level `permissions:`"
        );
        let write = |l: &&str| l.trim_end().ends_with(": write");
        assert!(
            !head.iter().any(write),
            "{file}: a write given to every job — give it to the one job that needs it"
        );
        for (job, body) in jobs {
            for grant in body.iter().filter(|l| write(l)).map(|l| l.trim()) {
                writes += 1;
                let scope = grant.trim_end_matches(": write");
                // Images to publish; a keyless signature's identity, which proves who
                // signed and writes nothing; a build's provenance; code-scanning alerts,
                // which reach no file.
                let harmless =
                    ["packages", "id-token", "attestations", "security-events"].contains(&scope);
                // A token that can push is what a compromised build step needs to
                // rewrite the repository — so the job holding it runs none: it never
                // checks the repository out.
                let release = scope == "contents"
                    && !body.iter().any(|l| l.contains("uses: actions/checkout@"));
                assert!(
                    harmless || release,
                    "{file}: job `{job}` holds `{grant}`{}",
                    if scope == "contents" {
                        " beside a checkout of the repository"
                    } else {
                        ""
                    }
                );
            }
        }
    }
    // The floor: images and releases both write something.
    assert!(writes >= 2, "only {writes} write grants read");
}

#[test]
fn no_checkout_leaves_its_token_behind() {
    // `actions/checkout` writes the token into `.git/config` unless told not to, where
    // every later step — a build script among them — reads it.
    for (file, text) in workflows() {
        let lines: Vec<&str> = text.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            if !line.contains("uses: actions/checkout@") {
                continue;
            }
            let block = lines[i + 1..]
                .iter()
                .take_while(|l| !l.trim_start().starts_with("- "));
            assert!(
                block
                    .into_iter()
                    .any(|l| l.trim() == "persist-credentials: false"),
                "{file}:{}: checkout keeps its credentials",
                i + 1
            );
        }
    }
}
