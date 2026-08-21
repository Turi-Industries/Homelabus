//! The platform's shared services.
//!
//! One instance per engine, shared by every application, with an isolated database
//! and role per app. One database server per database system, not one per app.

pub mod mariadb;
pub mod postgres;

pub use mariadb::MariadbProvisioner;
pub use postgres::{connection_url, PostgresProvisioner};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("cannot connect to the admin database: {0}")]
    Connect(String),

    #[error("erreur SQL : {0}")]
    Sql(String),

    #[error("identifier refused: {0}")]
    InvalidIdentifier(String),
}

pub type Result<T> = std::result::Result<T, Error>;
