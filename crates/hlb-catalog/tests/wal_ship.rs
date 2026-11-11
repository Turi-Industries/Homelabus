//! The vital server archives what `hlb_backup::wal_ship` ships.
//!
//! Its archive settings are arguments of a manifest, and the standby that replays them
//! is configured from Rust: written twice, a directory or a suffix changed on one side
//! would leave the site receiving nothing, or replaying nothing, with both sides healthy.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use hlb_backup::wal_ship;
use hlb_types::Capability;

fn vital() -> hlb_types::Manifest {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../../catalog");
    let catalog = hlb_catalog::Catalog::load(root).expect("catalog");
    catalog
        .get(hlb_types::DbServer::PostgresVital.service_name())
        .expect("postgres-vital is in the catalog")
        .manifest
        .clone()
}

#[test]
fn the_vital_server_archives_as_the_pusher_reads() {
    let m = vital();
    let args = &m.spec.args;
    let primary = wal_ship::primary_args();
    assert!(
        args.ends_with(&primary),
        "postgres-vital's args must end with wal_ship::primary_args():\n{primary:#?}\ngot:\n{args:#?}"
    );
}

#[test]
fn the_archive_directory_is_a_volume_given_to_postgres() {
    let m = vital();
    let script = m.spec.command.join(" ");
    assert!(
        script.contains(&format!(
            "install -d -o postgres -g postgres -m 700 {}",
            wal_ship::ARCHIVE_DIR
        )),
        "{script}"
    );
    let volume = m.spec.requires.iter().find_map(|c| match c {
        Capability::Storage {
            path,
            backup,
            tier,
            name,
            sqlite: _,
            copy: _,
            owner,
        } if path == wal_ship::ARCHIVE_DIR => Some((name.clone(), *backup, *tier, owner.clone())),
        _ => None,
    });
    let (name, backup, tier, owner) = volume.expect("a volume at the archive's path");
    assert_eq!(name, "wal");
    assert!(
        !backup,
        "the archive is gone in seconds: nothing to back up"
    );
    assert_eq!(tier, hlb_types::StorageTier::Local);
    assert_eq!(owner, None);
}
