//! Nothing waits for a stop by counting `running_replicas` down to zero.
//!
//! A scale to zero turns each task's desired state to `shutdown`/`remove` at once, and
//! `running_replicas` counts only tasks Swarm still WANTS running: it reads 0 while the
//! container runs its stop — writing — for seconds more. Five waits trusted it; on the
//! lab (2026-11-08) the power's three waves stopped PostgreSQL in the same second as the
//! apps writing to it. `hlb_orchestrator::wait_stopped` reads the tasks' own state.
//! Found by walking the sources, not from a list of the waits.

mod scan;

use scan::{code_only, crates_root, rust_files, short};

/// Whatever asks "does anything still run": the field against 0, or `< 1` / `>= 1`.
const NONE_LEFT: [&str; 8] = [">0", "==0", "!=0", "<=0", ">=1", "<1", "<0", ">=0"];

/// The field, compared so: `running_replicas > 0`, `== 0`, `< 1`…, whitespace ignored.
fn compares_with_zero(code: &str) -> Vec<String> {
    let field = format!("running_{}", "replicas");
    let mut found = Vec::new();
    for (at, _) in code.match_indices(&field) {
        let rest: String = code[at + field.len()..]
            .chars()
            .filter(|c| !c.is_whitespace())
            .take(4)
            .collect();
        // `> 0` but not `> 0.5` or `== 10`: the number ends there.
        let hit = NONE_LEFT.iter().any(|s| {
            rest.strip_prefix(s)
                .is_some_and(|after| !after.starts_with(|c: char| c.is_ascii_digit() || c == '.'))
        });
        if hit {
            found.push(format!("{field}{rest}"));
        }
    }
    found
}

#[test]
fn the_matcher_sees_each_shape_of_the_old_wait() {
    let f = format!("running_{}", "replicas");
    for shape in [
        format!("while st.{f} > 0 {{"),
        format!("if o.status(s).await?.{f} == 0 {{"),
        format!(".{f}\n            > 0"),
        format!("{f} < 1"),
    ] {
        assert_eq!(compares_with_zero(&shape).len(), 1, "missed: {shape}");
    }
    // Progress compared with what is wanted is not a stop being waited for.
    assert!(compares_with_zero(&format!("{f} as u64 >= st.desired_replicas")).is_empty());
    assert!(compares_with_zero(&format!("{f}: 10,")).is_empty());
}

#[test]
fn no_stop_is_waited_for_on_running_replicas() {
    let mut read = 0;
    let mut waits = Vec::new();
    for file in rust_files(&crates_root()) {
        if file.components().any(|c| c.as_os_str() == "tests") {
            continue;
        }
        let source = std::fs::read_to_string(&file).unwrap_or_default();
        let production = code_only(source.split("\n#[cfg(test)]").next().unwrap_or(""));
        read += production.matches("running_replicas").count();
        for w in compares_with_zero(&production) {
            waits.push(format!("{}: {w}", short(&file)));
        }
    }
    // The orchestrator's own counting, the reconciliation's progress, the power's start:
    // a scan that stopped finding the field would pass on nothing.
    assert!(
        read >= 8,
        "only {read} reads of the field found in the sources"
    );
    assert!(
        waits.is_empty(),
        "a stop waited for on running_replicas, which reads 0 before the task exits — \
         `hlb_orchestrator::wait_stopped`:\n  {}",
        waits.join("\n  ")
    );
}
