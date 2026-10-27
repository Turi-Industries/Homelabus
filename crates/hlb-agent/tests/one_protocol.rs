//! The agent ↔ controller protocol is numbered in one place.
//!
//! A second `PROTOCOL` in `hlb-selfupdate` said 1 while the agents reported 2; nothing
//! compared the two, and `hlb self status` printed the wrong one.

use std::path::Path;

fn rust_files(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            if p.file_name().is_some_and(|n| n == "target") {
                continue;
            }
            rust_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

#[test]
fn the_protocol_is_defined_once_by_the_agent() {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/");
    let mut files = Vec::new();
    rust_files(crates, &mut files);
    // The floor: a walk that found nothing would pass on nothing.
    assert!(files.len() > 100, "{} files", files.len());

    let needle = format!("const {}: u32", "PROTOCOL");
    let defining: Vec<_> = files
        .iter()
        .filter(|f| {
            std::fs::read_to_string(f)
                .unwrap_or_default()
                .contains(&needle)
        })
        .map(|f| f.strip_prefix(crates).unwrap_or(f).display().to_string())
        .collect();
    assert_eq!(defining, ["hlb-agent/src/lib.rs"], "{defining:?}");
}
