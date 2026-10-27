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
    "mariadb:11.8.8@sha256:24e76fcec8c003a0362d0dd53f4806e7e79458d7fdeaf47437760e19496f5a9c";
