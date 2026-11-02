//! The formats a source publishes are frozen: every `hlb` reads `index.json` with
//! `deny_unknown_fields`, so one field added to it makes every house already installed
//! refuse the whole official catalog — and it would not say why until it fetched.
//! `quality-v1.json` is read the same way, by every release from 0.4.1.
//!
//! Something new a source publishes goes in a file of its own beside the index, which an
//! older `hlb` never asks for; a change to one of these is a new file name, served
//! beside the old one for as long as releases reading it run.
//!
//! ```sh
//! HLB_UPDATE_INDEX_FORMAT=1 cargo test -p hlb-types --test index_format   # never, but at a new file name
//! ```

#![allow(clippy::expect_used)]

use std::collections::BTreeMap;
use std::path::Path;

/// Each published file, by the name it is served under, and the format it is read with.
fn formats() -> BTreeMap<&'static str, serde_json::Value> {
    let json = |s| serde_json::to_value(s).expect("json");
    BTreeMap::from([
        (
            hlb_types::index::FILE,
            json(schemars::schema_for!(hlb_types::index::Index)),
        ),
        (
            hlb_types::quality::FILE,
            json(schemars::schema_for!(hlb_types::quality::Quality)),
        ),
    ])
}

#[test]
fn every_published_file_reads_as_every_released_hlb_reads_it() {
    // `index.json` keeps its first name; its format is `index-v1.json` here.
    let held = |file: &str| match file {
        "index.json" => "index-v1.json".to_string(),
        other => other.to_string(),
    };
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("formats");
    let formats = formats();
    if std::env::var_os("HLB_UPDATE_INDEX_FORMAT").is_some() {
        for (file, live) in &formats {
            let text = serde_json::to_string_pretty(live).expect("json") + "\n";
            std::fs::write(dir.join(held(file)), text).expect("format written");
        }
    }
    // A format left in the directory with nothing compared to it guards nothing.
    let mut on_disk: Vec<String> = std::fs::read_dir(&dir)
        .expect("formats/")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    on_disk.sort();
    let mut expected: Vec<String> = formats.keys().map(|f| held(f)).collect();
    expected.sort();
    assert_eq!(
        on_disk, expected,
        "formats/ holds one file per published format"
    );
    for (file, live) in &formats {
        let path = dir.join(held(file));
        let committed: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("format")).expect("json");
        assert_eq!(
            &committed, live,
            "{file} no longer reads as the releases out read it: a house running one would \
             refuse it. Publish the new information in a file of its own."
        );
    }
}
