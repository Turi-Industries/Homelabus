//! Les services mutualisés de la plateforme (§3 du plan).
//!
//! Une instance par moteur, partagée par toutes les applications, avec une base et un
//! rôle isolés par app. C'est ce que demandait le cahier des charges : « une seule db
//! par système de db pour toutes les applis ».

pub mod mariadb;
pub mod postgres;

pub use mariadb::MariadbProvisioner;
pub use postgres::{connection_url, PostgresProvisioner};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("connexion à la base d'administration impossible : {0}")]
    Connect(String),

    #[error("erreur SQL : {0}")]
    Sql(String),

    #[error("identifiant refusé : {0}")]
    InvalidIdentifier(String),
}

pub type Result<T> = std::result::Result<T, Error>;
