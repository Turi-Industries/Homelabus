//! A machine holding `hlb` alone reads the catalog the binary carries — all of it.

#![allow(clippy::expect_used)]

use std::path::Path;

fn manifests(dir: &Path) -> usize {
    std::fs::read_dir(dir)
        .expect("catalog directory")
        .flatten()
        .map(|e| e.path())
        .map(|p| {
            if p.is_dir() {
                manifests(&p)
            } else {
                usize::from(p.file_name().is_some_and(|f| f == "manifest.yaml"))
            }
        })
        .sum()
}

#[test]
fn hlb_run_where_there_is_no_catalog_reads_every_manifest_it_was_built_with() {
    let on_disk = manifests(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../../catalog"));
    // The floor: a walk that found nothing would make the comparison below vacuous.
    assert!(on_disk >= 20, "only {on_disk} manifests found on disk");

    let empty = tempfile::tempdir().expect("an empty directory");
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_hlb"))
        .current_dir(empty.path())
        .args(["catalog", "validate"])
        .output()
        .expect("hlb runs");
    let said = String::from_utf8_lossy(&out.stdout);
    assert!(
        said.contains(&format!("{on_disk} manifests valid")),
        "expected {on_disk} manifests, hlb said: {said}{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn the_exported_catalog_is_every_manifest_carried_and_never_written_over() {
    let on_disk = manifests(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../../catalog"));
    assert!(on_disk >= 20, "only {on_disk} manifests found on disk");

    let tmp = tempfile::tempdir().expect("a directory");
    let dir = tmp.path().join("catalog");
    let export = || {
        std::process::Command::new(env!("CARGO_BIN_EXE_hlb"))
            .args(["catalog", "export"])
            .arg(&dir)
            .output()
            .expect("hlb runs")
    };
    assert!(export().status.success());
    // What the catalog repository's quality runs lay its apps over: the platform above all.
    assert!(dir.join("_platform/postgres/manifest.yaml").is_file());
    assert_eq!(manifests(&dir), on_disk);
    // A second export would mix into the first.
    assert!(!export().status.success());
}
