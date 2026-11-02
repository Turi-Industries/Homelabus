//! The index's format is frozen: every `hlb` reads `index.json` with
//! `deny_unknown_fields`, so one field added to it makes every house already installed
//! refuse the whole official catalog — and it would not say why until it fetched.
//!
//! Something new a source publishes goes in a file of its own beside the index, which an
//! older `hlb` never asks for; a change to the index itself is a new file name, served
//! beside the old one for as long as releases reading it run.
//!
//! ```sh
//! HLB_UPDATE_INDEX_FORMAT=1 cargo test -p hlb-types --test index_format   # never, but at a new file name
//! ```

#![allow(clippy::expect_used)]

use std::path::Path;

#[test]
fn the_index_reads_as_every_released_hlb_reads_it() {
    let file = Path::new(env!("CARGO_MANIFEST_DIR")).join("formats/index-v1.json");
    let live = serde_json::to_value(schemars::schema_for!(hlb_types::index::Index)).expect("json");
    if std::env::var_os("HLB_UPDATE_INDEX_FORMAT").is_some() {
        let text = serde_json::to_string_pretty(&live).expect("json") + "\n";
        std::fs::write(&file, text).expect("format written");
    }
    let committed: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&file).expect("formats/index-v1.json"))
            .expect("json");
    assert_eq!(
        committed,
        live,
        "index.json no longer reads as 0.4.0 reads it: a house running it would refuse \
         the whole official catalog. Publish the new information in a file of its own."
    );
}
