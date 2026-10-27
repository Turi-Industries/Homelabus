//! The images backups, dumps and restores run in — each by its digest.
//!
//! `restic/restic:latest` was four of these: every node pulled whichever restic Docker
//! Hub named the day it first needed one, so the repository was written by several, and
//! the one reading it back in a year would be another again.

/// restic. Its repository format is read back by the same build that writes it.
pub const RESTIC: &str =
    "restic/restic:0.19.1@sha256:136600b6ff6843d61d355f7f71f460a166429f35de6fd11b568fece3c9a4d510";

/// `pg_dump` and `pg_basebackup`. Their major is the catalog server's, which a test of
/// the catalog holds; the libc does not matter to a client, it does to a restore.
pub const POSTGRES_CLIENT: &str =
    "postgres:17-alpine@sha256:b0f9560a2de083e2cc7382e75f808c7381a32852a7ec49117deedb300e552b24";

/// `mariadb-dump`: the catalog's own MariaDB image, whose tools are the server's — a
/// test of the catalog holds the two to one reference.
pub const MARIADB_CLIENT: &str =
    "mariadb:12.3.2@sha256:a02fe89cb597d4375812b2eac90cf9d0775d4686daa7f7cc750ebbcad7525bbc";
