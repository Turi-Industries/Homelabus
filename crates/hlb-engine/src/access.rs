//! How Homelabus reaches the platform services it installed, from the vault.
//!
//! PostgreSQL, MariaDB and Garage are deployed with administrator credentials Homelabus
//! generated (`{{ secret.* }}` in their manifests). Asking the user to copy them back
//! into `--postgres-admin` was a second place for the same value, and the one that went
//! stale: the vault is where they live, so it is where they are read from.
//!
//! ⚠️ The hosts are Swarm service names. They resolve on the platform overlay — from
//! the controller, and from the containers backups run in — not from a shell on the
//! host.

use hlb_secrets::Vault;
use hlb_state::State;
use hlb_types::binding::GeneratedSecret;

/// The administrator URLs and tokens Homelabus can derive. `None` where the service
/// was not installed by it, or not yet.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PlatformAccess {
    pub postgres_admin: Option<String>,
    /// The vital apps' own PostgreSQL, installed with a site.
    pub postgres_vital_admin: Option<String>,
    pub mariadb_admin: Option<String>,
    /// `(admin API URL, token)`.
    pub garage_admin: Option<(String, String)>,
    /// `(URL, user, password)` — the administrator `STALWART_RECOVERY_ADMIN` pins.
    pub stalwart_admin: Option<(String, String, String)>,
    /// `(API URL, key)`. Generated at PocketID's install and handed to it as its
    /// `STATIC_API_KEY`; an install from before v2 has the one a person created in
    /// PocketID's settings, stored under the same name with `hlb secret-set`.
    pub pocketid: Option<(String, String)>,
    /// `(user, password)` the controller publishes its alerts to ntfy as.
    pub ntfy_publisher: Option<(String, String)>,
    /// `(user, password)` the deadman's watchdog publishes as, from another machine.
    pub ntfy_watchdog: Option<(String, String)>,
}

impl PlatformAccess {
    /// The administrator of the server a database lives on.
    pub fn database_admin(&self, server: hlb_types::DbServer) -> Option<&str> {
        match server {
            hlb_types::DbServer::Postgres => self.postgres_admin.as_deref(),
            hlb_types::DbServer::PostgresVital => self.postgres_vital_admin.as_deref(),
            hlb_types::DbServer::Mariadb => self.mariadb_admin.as_deref(),
        }
    }
}

/// ntfy's declared accounts that publish, `(user, {{ secret.* }} name)`, as its
/// manifest's `auth-users` declares them.
pub const NTFY_PUBLISHER: (&str, &str) = ("homelabus", "publisher-password");
pub const NTFY_WATCHDOG: (&str, &str) = ("watchdog", "watchdog-password");

/// The vault entry holding the watchdog's password — what `hlb metrics deadman` prints,
/// and so the target its audit entry names.
pub fn ntfy_watchdog_secret() -> String {
    generated("ntfy", NTFY_WATCHDOG.1)
}

/// Where the PocketID API key is kept: `{{ secret.api-key }}` in its manifest.
pub const POCKETID_KEY_SECRET: &str = "pocket-id-api-key";

/// The interface's own sign-in client in PocketID, registered by `hlb fleet
/// controller`: named like an app's (`<app>-oidc-*`), for the app `homelabus`.
pub const CONTROLLER_OIDC_CLIENT: &str = "homelabus";
pub const CONTROLLER_OIDC_ID: &str = "homelabus-oidc-client-id";
pub const CONTROLLER_OIDC_SECRET: &str = "homelabus-oidc-secret";

/// PocketID on the overlay. Its public URL is the issuer; this is where its API is.
pub const POCKETID_URL: &str = "http://pocket-id:1411";

/// Must match the `{{ secret.<name> }}` the platform manifests declare: the name is
/// built the same way the resolver builds it, never written out by hand.
fn generated(app: &str, name: &str) -> String {
    GeneratedSecret {
        name: name.to_string(),
        form: hlb_types::binding::SecretForm::Plain,
    }
    .vault_name(app)
}

/// Where a person opens PocketID: its public name, recorded at its install.
///
/// 🔴 Never the API URL. That one is the overlay's `http://pocket-id:1411`, and an
/// enrolment link built on it — the first thing an invited person receives — opens on
/// no machine outside the cluster.
pub async fn pocketid_public(state: &State) -> Option<String> {
    state
        .app_domain("pocket-id")
        .await
        .ok()
        .flatten()
        .map(|d| format!("https://{d}"))
}

/// The single-use link a person registers their first passkey with.
pub fn enrolment_link(public: &str, token: &str) -> String {
    format!("{}/lc/{token}", public.trim_end_matches('/'))
}

pub async fn from_vault(state: &State, vault: &Vault) -> crate::Result<PlatformAccess> {
    let read = |name: String| async move {
        match state.secret(&name).await? {
            Some(ct) => Ok::<_, crate::Error>(Some(vault.decrypt(&ct)?)),
            None => Ok(None),
        }
    };
    let admin = |server: hlb_types::DbServer| async move {
        let name = generated(server.service_name(), server.admin_password_name());
        Ok::<_, crate::Error>(read(name).await?.map(|p| server.admin_url(&p)))
    };
    Ok(PlatformAccess {
        postgres_admin: admin(hlb_types::DbServer::Postgres).await?,
        postgres_vital_admin: admin(hlb_types::DbServer::PostgresVital).await?,
        mariadb_admin: admin(hlb_types::DbServer::Mariadb).await?,
        garage_admin: read(generated("garage", "admin-token"))
            .await?
            .map(|t| ("http://garage:3903".to_string(), t)),
        stalwart_admin: read(generated("stalwart", "admin-password"))
            .await?
            .map(|p| ("http://stalwart:8080".to_string(), "admin".to_string(), p)),
        pocketid: read(POCKETID_KEY_SECRET.to_string())
            .await?
            .map(|k| (POCKETID_URL.to_string(), k)),
        ntfy_publisher: read(generated("ntfy", NTFY_PUBLISHER.1))
            .await?
            .map(|p| (NTFY_PUBLISHER.0.to_string(), p)),
        ntfy_watchdog: read(ntfy_watchdog_secret())
            .await?
            .map(|p| (NTFY_WATCHDOG.0.to_string(), p)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn admin_urls_come_from_the_secrets_the_manifests_generate() {
        let s = State::in_memory().await.expect("state");
        let dir = tempfile::tempdir().expect("tmp");
        let v = Vault::init(dir.path().join("k.key")).expect("vault");
        assert_eq!(
            from_vault(&s, &v).await.expect("read"),
            PlatformAccess::default()
        );

        s.store_secret_if_absent(
            "postgres-admin-password",
            &v.encrypt("pw1").expect("enc"),
            "x",
        )
        .await
        .expect("store");
        s.store_secret_if_absent("garage-admin-token", &v.encrypt("tok").expect("enc"), "x")
            .await
            .expect("store");
        let a = from_vault(&s, &v).await.expect("read");
        assert_eq!(
            a.postgres_admin.as_deref(),
            Some("postgres://postgres:pw1@postgres:5432/postgres")
        );
        assert_eq!(
            a.garage_admin,
            Some(("http://garage:3903".into(), "tok".into()))
        );
        assert_eq!(a.mariadb_admin, None);
        assert_eq!(a.postgres_vital_admin, None);

        s.store_secret_if_absent(
            "postgres-vital-admin-password",
            &v.encrypt("pw2").expect("enc"),
            "x",
        )
        .await
        .expect("store");
        let a = from_vault(&s, &v).await.expect("read");
        assert_eq!(
            a.database_admin(hlb_types::DbServer::PostgresVital),
            Some("postgres://postgres:pw2@postgres-vital:5432/postgres")
        );
        assert_eq!(
            a.database_admin(hlb_types::DbServer::Postgres),
            Some("postgres://postgres:pw1@postgres:5432/postgres")
        );
    }

    #[test]
    fn the_pocketid_key_is_the_one_its_manifest_generates() {
        // Named by hand for `hlb secret-set` when a person made the key; the install
        // now generates it under the name the resolver builds.
        assert_eq!(POCKETID_KEY_SECRET, generated("pocket-id", "api-key"));
    }

    #[test]
    fn the_names_match_the_platform_manifests() {
        // The manifests are the source; a renamed `{{ secret.* }}` there must fail here
        // rather than leave the vault lookup pointing at nothing.
        let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../../catalog/_platform");
        for (app, name) in [
            ("postgres", "admin-password"),
            ("mariadb", "root-password"),
            ("garage", "admin-token"),
            ("stalwart", "admin-password"),
            ("pocket-id", "api-key"),
        ] {
            let m =
                std::fs::read_to_string(format!("{root}/{app}/manifest.yaml")).expect("manifest");
            assert!(
                m.contains(&format!("{{{{ secret.{name} }}}}")),
                "{app} no longer declares {{{{ secret.{name} }}}}"
            );
        }
        // ntfy is given the hash, as the account's own entry in `auth-users`.
        let ntfy = std::fs::read_to_string(format!("{root}/ntfy/manifest.yaml")).expect("ntfy");
        for (user, name) in [NTFY_PUBLISHER, NTFY_WATCHDOG] {
            assert!(
                ntfy.contains(&format!("{user}:{{{{ secret.{name}:bcrypt }}}}:")),
                "ntfy no longer declares {user} with {{{{ secret.{name}:bcrypt }}}}"
            );
        }
    }
}
