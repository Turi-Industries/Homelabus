//! The dump clients follow the catalog's database servers.
//!
//! `pg_dump` refuses a server of a later major, and `mariadb-dump` is the server's own
//! tool: the clients `hlb-backup` runs are constants, the servers are the catalog's, and
//! a comment saying "aligned with the catalog" was all that kept them together.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use hlb_types::{DbEngine, Image};

fn catalog_image(engine: DbEngine) -> Image {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../../catalog");
    let catalog = hlb_catalog::Catalog::load(root).expect("catalog");
    catalog
        .get(engine.service_name())
        .expect("the database server is in the catalog")
        .manifest
        .spec
        .image
        .clone()
}

fn major(tag: &str) -> &str {
    tag.split(['.', '-']).next().unwrap_or(tag)
}

#[test]
fn the_postgres_client_is_the_servers_major() {
    let server = catalog_image(DbEngine::Postgres);
    let client = hlb_backup::images::POSTGRES_CLIENT;
    let tag = client
        .split_once(':')
        .and_then(|(_, t)| t.split('@').next())
        .expect("a tag");
    assert_eq!(
        major(tag),
        major(&server.tag),
        "pg_dump {client} against the catalog's {}",
        server.reference()
    );
}

#[test]
fn the_mariadb_client_is_the_servers_own_image() {
    let server = catalog_image(DbEngine::Mariadb);
    assert_eq!(hlb_backup::images::MARIADB_CLIENT, server.reference());
}
