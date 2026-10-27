//! No `docker run` is handed a variable's value on its command line.
//!
//! `-e NAME=value` is readable in `ps` by every account of the node for as long as the
//! container runs: a restic password, an S3 secret and the database passwords went
//! through it in three builders, beside comments saying "never on the command line".
//! `hlb_backup::docker_env::pass_by_name` hands the value through the client's own
//! environment; every other file that starts `docker` is refused an `-e` or `--env` of
//! its own — found by walking the sources, not from a list of the builders.

mod scan;

use scan::{crates_root, rust_files, short, split};

/// The one place `-e` is written, with its own test proving it passes names only.
const HELPER: &str = "hlb-backup/src/docker_env.rs";

fn is_env_flag(s: &str) -> bool {
    s == "-e" || s == "--env" || s == "--env-file" || s.starts_with("--env=")
}

#[test]
fn no_docker_command_takes_a_variable_but_through_the_helper() {
    let mut docker_files = 0;
    let mut helper_seen = false;
    let mut offenders = Vec::new();
    for file in rust_files(&crates_root()) {
        if file.components().any(|c| c.as_os_str() == "tests") {
            continue;
        }
        let source = std::fs::read_to_string(&file).unwrap_or_default();
        let production = source.split("\n#[cfg(test)]").next().unwrap_or("");
        let (_, strings) = split(production);
        let name = short(&file);
        if name == HELPER {
            helper_seen = strings.iter().any(|s| is_env_flag(s));
            continue;
        }
        if !strings.iter().any(|s| s == "docker") {
            continue;
        }
        docker_files += 1;
        if strings.iter().any(|s| is_env_flag(s)) {
            offenders.push(name);
        }
    }
    assert!(
        offenders.is_empty(),
        "a docker command given variables by hand — `-e NAME=value` puts the value in \
         `ps`; use hlb_backup::docker_env::pass_by_name:\n  {}",
        offenders.join("\n  ")
    );
    // Seven files start `docker` on 2026-10-21: a walk finding fewer is not reading them.
    assert!(
        docker_files >= 7,
        "only {docker_files} sources starting docker were walked"
    );
    assert!(
        helper_seen,
        "{HELPER} was not read, or no longer writes `-e`: the scan's exemption names a \
         file it does not look at"
    );
}
