//! Assisted secret rotation.
//!
//! ## 🔴 The trap this module exists to name
//!
//! The vault is **not** the source of truth for a database password. Rotating it there
//! changes nothing: PostgreSQL keeps the old one, the container keeps the old one in
//! its environment, and everything keeps working — until the next redeploy, where the
//! app starts failing on "incorrect password" with nobody connecting it to a rotation
//! three weeks earlier.
//!
//! A rotation is therefore an **ordered procedure**, not a write. This module says
//! which one, for each kind of secret, and refuses to treat them all alike.
//!
//! ## What decides is the use, not the name
//!
//! A secret injected into an app's environment requires a redeploy; a secret re-read on
//! every use does not. Confusing the two leaves an app running on a stale value while
//! you believe you rotated it.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// What a secret is, from the point of view of rotating it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Nature {
    /// A database role's password: lives in PostgreSQL **and** in the vault.
    DatabasePassword,
    /// An OIDC client secret: lives in PocketID **and** in the vault.
    OidcClient,
    /// An S3 access key: Garage never returns the secret key twice.
    ObjectKey,
    /// An IMAP/SMTP password: lives at Stalwart **and** in the vault.
    MailPassword,
    /// A restic repository passphrase. 🔴 Losing it makes the backups unreadable.
    RepoPassphrase,
    /// A third-party service API key, re-read on every use.
    ApiKey,
    /// Credentials of a backup destination (`backup-dest-<name>`).
    ///
    /// 🔴 Belongs to no app: nothing to redeploy. But a failed rotation only shows on
    /// the next backup, as an "invalid signature" that points nowhere.
    DestinationCredentials,
    /// A Valkey cache password an older install generated. Nothing reads it: the
    /// platform's Valkey runs without one, on the overlay only.
    CachePassword,
    /// We do not know: no procedure is guessed.
    Unknown,
}

impl Nature {
    /// Derived from the recorded name and purpose.
    ///
    /// ⚠️ `Unknown` is a legitimate result: inventing a procedure for a secret you do
    /// not recognise would run the wrong steps in the wrong order.
    pub fn infer(name: &str, usage: &str) -> Self {
        let n = name.to_ascii_lowercase();
        let u = usage.to_ascii_lowercase();

        // ⚠️ The suffixes come from the names the RESOLVER really produces
        // (`hlb-resolver`), not from a supposed convention. A kind derived from a name
        // that does not exist would never fire, and the screen would stay silent about
        // exactly the secrets that matter most.
        //
        // 🔴 The NAME decides wherever a name exists to decide on. `purpose` is free
        // text written by whichever crate created the secret: it is a hint, never the
        // only evidence. A kind resting on the wording alone stops firing the day
        // someone rewrites the sentence, and the screen goes quiet about that secret
        // instead of saying anything.
        if n.ends_with("-db-password") || u.contains("postgresql password") {
            Self::DatabasePassword
        } else if n.ends_with("-oidc-secret") || u.contains("oidc client") {
            Self::OidcClient
        } else if n.ends_with("-s3-secret") || u.contains("s3 secret key") {
            Self::ObjectKey
        } else if n.ends_with("-mail-password")
            || n.ends_with("-smtp-password")
            || u.contains("imap")
        {
            Self::MailPassword
        } else if n.ends_with("-cache-password") {
            Self::CachePassword
        } else if n.starts_with("backup-dest-") || u.contains("s3 credentials") {
            Self::DestinationCredentials
        } else if n.ends_with("-repo-password") || u.contains("repository encryption") {
            // ⚠️ `restic-repo-password` used to be recognised by its purpose ALONE —
            // the one kind with no name to fall back on. Losing it is the worst case
            // here: no procedure is offered for the passphrase whose loss makes every
            // backup unreadable, and nothing on screen says so.
            Self::RepoPassphrase
        } else if u.contains("api key") || n.contains("crowdsec") {
            Self::ApiKey
        } else {
            Self::Unknown
        }
    }

    /// Does rotating this secret require redeploying the app that uses it?
    ///
    /// 🔴 THE question. A database password rotated without a redeploy breaks the app
    /// silently: it complains about an incorrect password, and you go looking at the
    /// password when the problem is that the app holds the old one.
    pub fn needs_redeploy(&self) -> bool {
        match self {
            Self::DatabasePassword | Self::OidcClient | Self::ObjectKey | Self::MailPassword => {
                true
            }
            // Re-read on every use, belonging to no app, or read by nothing.
            Self::ApiKey
            | Self::RepoPassphrase
            | Self::DestinationCredentials
            | Self::CachePassword => false,
            // ⚠️ We do NOT know: the answer is "yes" because redeploying needlessly
            // costs a few seconds of interruption, while failing to redeploy when it was
            // needed breaks the app without saying so.
            Self::Unknown => true,
        }
    }

    /// The procedure, in order. Empty when unknown.
    ///
    /// 🔴 STEPS, not sentences. The order is the knowledge here — a Garage key is
    /// created before the old one is deleted, a restic passphrase is not rotated
    /// before a restore has been verified — and the tests below hold it. The words are
    /// the interface's, one message per step in each catalogue, and an exhaustive
    /// `match` there means a step added here does not compile until it has them.
    pub fn procedure(&self) -> Vec<Step> {
        use Step::*;
        match self {
            Self::DatabasePassword => vec![ChangeInPostgres, WriteToVault, RedeployForNewVariable],
            Self::OidcClient => vec![RegenerateInPocketId, WriteToVault, Redeploy],
            Self::ObjectKey => vec![
                CreateNewKeyInGarage,
                WriteToVaultGarageNeverReturnsIt,
                Redeploy,
                DeleteOldKeyOnlyAfterAppWorks,
            ],
            Self::MailPassword => vec![ChangeOnStalwart, WriteToVault, RedeployAndReconfigureMail],
            Self::RepoPassphrase => vec![
                DoNotRotateBeforeVerifiedRestore,
                AddKeyToResticRepository,
                WriteToVault,
                RemoveOldResticKeyAfterDrill,
            ],
            // 🔴 The procedure promised a change in Valkey and a redeployment for a
            // password no app received and Valkey never asked for.
            Self::CachePassword => vec![NothingReadsIt],
            Self::DestinationCredentials => vec![
                CreateNewKeyAtS3Provider,
                WriteToVault,
                BackUpAndVerifyItSucceeds,
                RevokeOldKeyAfterBackupPasses,
            ],
            Self::ApiKey => vec![GenerateNewKeyAtProvider, WriteToVault, ReloadWhatReadsIt],
            Self::Unknown => Vec::new(),
        }
    }
}

/// One step of a rotation procedure: see [`Nature::procedure`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Step {
    /// Change the password IN PostgreSQL (`ALTER ROLE ... PASSWORD`).
    ChangeInPostgres,
    /// Write the new value to the vault.
    WriteToVault,
    /// Redeploy the app so it receives the new variable.
    RedeployForNewVariable,
    /// Regenerate the client secret IN PocketID.
    RegenerateInPocketId,
    Redeploy,
    /// Create a NEW key in Garage; the old one stays valid.
    CreateNewKeyInGarage,
    /// Write it to the vault — Garage will never return it again.
    WriteToVaultGarageNeverReturnsIt,
    /// 🔴 Delete the old key ONLY after seeing the app work.
    DeleteOldKeyOnlyAfterAppWorks,
    ChangeOnStalwart,
    /// Redeploy the app, and reconfigure the mail clients.
    RedeployAndReconfigureMail,
    /// 🔴 Do NOT rotate without having verified a restore first.
    DoNotRotateBeforeVerifiedRestore,
    /// Add the new key to the restic repository (`restic key add`).
    AddKeyToResticRepository,
    /// Remove the old key from the repository only after a successful drill.
    RemoveOldResticKeyAfterDrill,
    /// Nothing reads this secret: rotating it changes nothing, and it can be forgotten.
    NothingReadsIt,
    CreateNewKeyAtS3Provider,
    /// Run a backup and VERIFY that it succeeds: a failed rotation only shows there,
    /// as an "invalid signature".
    BackUpAndVerifyItSucceeds,
    RevokeOldKeyAfterBackupPasses,
    GenerateNewKeyAtProvider,
    /// Reload the configuration that reads it.
    ReloadWhatReadsIt,
}

/// What rotating a secret would involve: see [`SecretToRotate::consequence`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Consequence {
    /// 🔴 REQUIRES redeploying this app: without it, the app keeps the old value and
    /// fails without saying why.
    RedeployApp { app: String },
    /// Requires redeploying whatever uses it; the app could not be derived from the
    /// name.
    RedeployWhateverUsesIt,
    /// Re-read on every use: reloading the configuration is enough.
    ReloadIsEnough,
}

judged! {
    /// A secret, and what rotating it would involve.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct SecretToRotate {
        pub name: String,
        pub usage: String,
        pub nature: Nature,
        /// Age since the last rotation — or since creation if never rotated.
        pub age_s: i64,
        /// True if the secret has NEVER been rotated since it was created.
        pub never_rotated: bool,
        /// The app to redeploy, when it can be derived from the name.
        #[serde(default)]
        pub app: Option<String>,
    }

    rules {
        attention: crate::Attention = SecretToRotate::attention,
        consequence: Consequence = SecretToRotate::consequence,
        procedure: Vec<Step> = |s: &SecretToRotate| s.nature.procedure(),
    }
}

/// Beyond that, rotation is offered: once a year at least.
pub const RECOMMENDED_AGE_S: i64 = 365 * 86_400;

impl SecretToRotate {
    pub fn attention(&self) -> crate::Attention {
        if self.age_s > 2 * RECOMMENDED_AGE_S {
            crate::Attention::Critical
        } else if self.age_s > RECOMMENDED_AGE_S {
            crate::Attention::Notice
        } else {
            crate::Attention::Ok
        }
    }

    /// What the rotation would imply — the decision; the interface has the sentence.
    pub fn consequence(&self) -> Consequence {
        match (self.nature.needs_redeploy(), &self.app) {
            (true, Some(app)) => Consequence::RedeployApp { app: app.clone() },
            (true, None) => Consequence::RedeployWhateverUsesIt,
            (false, _) => Consequence::ReloadIsEnough,
        }
    }
}

/// The app that owns a secret, derived from its name (`gitea-db-password`).
///
/// ⚠️ Returns `None` rather than guessing: naming the wrong app would redeploy an
/// unrelated service while you believed the rotation was finished.
pub fn app_of(name: &str) -> Option<String> {
    for suffix in [
        "-db-password",
        "-oidc-secret",
        "-oidc-client-id",
        "-s3-secret",
        "-mail-password",
        "-smtp-password",
        "-smtp-address",
        "-cache-password",
    ] {
        if let Some(app) = name.strip_suffix(suffix) {
            return (!app.is_empty()).then(|| app.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_database_password_can_never_be_rotated_in_the_vault_alone() {
        // 🔴 The central trap: the vault is not the source of truth. The procedure
        // starts IN PostgreSQL, and ends with a redeploy.
        let n = Nature::infer("gitea-db-password", "generated secret");
        assert_eq!(n, Nature::DatabasePassword);
        assert!(n.needs_redeploy());

        let p = n.procedure();
        assert_eq!(p[0], Step::ChangeInPostgres, "{p:?}");
        assert_eq!(p.last(), Some(&Step::RedeployForNewVariable), "{p:?}");
    }

    #[test]
    fn an_object_key_is_replaced_before_the_old_one_is_removed() {
        // ⚠️ Garage NEVER returns a secret key twice. Deleting the old one before
        // seeing the new one work leaves the app with no access at all, and no way
        // back.
        let p = Nature::ObjectKey.procedure();
        let creation = p
            .iter()
            .position(|e| *e == Step::CreateNewKeyInGarage)
            .expect("creation");
        let deletion = p
            .iter()
            .position(|e| *e == Step::DeleteOldKeyOnlyAfterAppWorks)
            .expect("deletion");
        assert!(creation < deletion, "{p:?}");
        assert_eq!(
            p.last(),
            Some(&Step::DeleteOldKeyOnlyAfterAppWorks),
            "{p:?}"
        );
    }

    #[test]
    fn a_repository_passphrase_is_the_one_that_must_not_be_lost() {
        // Rotating it without having verified a restore can make EVERY backup
        // unreadable. The only case where the first step is a refusal.
        let p = Nature::RepoPassphrase.procedure();
        assert_eq!(p[0], Step::DoNotRotateBeforeVerifiedRestore, "{p:?}");
        // And it belongs to no app: nothing to redeploy.
        assert!(!Nature::RepoPassphrase.needs_redeploy());
    }

    #[test]
    fn an_unknown_secret_gets_no_invented_procedure() {
        // 🔴 Inventing steps for a secret you do not recognise would have them run in
        // the wrong order, on the wrong system.
        let n = Nature::infer("truc-bizarre", "");
        assert_eq!(n, Nature::Unknown);
        assert!(n.procedure().is_empty());
        // But the worst is assumed: redeploying for nothing costs a few seconds,
        // forgetting to breaks the app silently.
        assert!(n.needs_redeploy());
    }

    #[test]
    fn every_name_the_resolver_produces_is_recognised() {
        // 🔴 Seen while reading the output: two secrets fell into "unknown kind"
        // because the suffixes had been guessed. A rule matching no real name never
        // fires, and the screen stays silent about exactly the secrets that matter.
        //
        // These names come from `hlb-resolver` and `hlb-backup`.
        for (name, usage, expected) in [
            (
                "gitea-db-password",
                "generated secret",
                Nature::DatabasePassword,
            ),
            (
                "gitea-oidc-secret",
                "client secret OIDC",
                Nature::OidcClient,
            ),
            ("immich-s3-secret", "S3 secret key", Nature::ObjectKey),
            (
                "lena-smtp-password",
                "IMAP/SMTP password",
                Nature::MailPassword,
            ),
            (
                "seafile-cache-password",
                "generated secret",
                Nature::CachePassword,
            ),
            (
                "backup-dest-offsite",
                "backup S3 credentials",
                Nature::DestinationCredentials,
            ),
            (
                "restic-repo-password",
                "repository encryption",
                Nature::RepoPassphrase,
            ),
        ] {
            assert_eq!(Nature::infer(name, usage), expected, "{name}");
        }
    }

    #[test]
    fn a_destination_rotation_is_verified_before_the_old_key_dies() {
        // ⚠️ A failed rotation only shows on the next backup, as an "invalid signature"
        // that points nowhere. Revoking the old key before seeing a backup pass leaves
        // the off-site silent without anyone knowing.
        let p = Nature::DestinationCredentials.procedure();
        let verif = p
            .iter()
            .position(|e| *e == Step::BackUpAndVerifyItSucceeds)
            .expect("verification");
        let revoc = p
            .iter()
            .position(|e| *e == Step::RevokeOldKeyAfterBackupPasses)
            .expect("revocation");
        assert!(verif < revoc, "{p:?}");
        // And nothing to redeploy: no app carries these credentials.
        assert!(!Nature::DestinationCredentials.needs_redeploy());
    }

    #[test]
    fn the_owning_app_is_deduced_or_left_unknown() {
        assert_eq!(app_of("gitea-db-password").as_deref(), Some("gitea"));
        assert_eq!(app_of("immich-s3-secret").as_deref(), Some("immich"));
        // What `ProvisionSmtpAccount` keeps beside the password, once tried.
        assert_eq!(app_of("vikunja-smtp-address").as_deref(), Some("vikunja"));
        // ⚠️ No guessing: naming the wrong app would redeploy an unrelated service
        // while you believed the rotation was finished.
        assert_eq!(app_of("restic-repo-passphrase"), None);
        assert_eq!(app_of("-db-password"), None);
    }

    #[test]
    fn a_secret_that_needs_a_redeploy_says_which_app() {
        let s = SecretToRotate {
            name: "gitea-db-password".into(),
            usage: "generated secret".into(),
            nature: Nature::DatabasePassword,
            age_s: 400 * 86_400,
            never_rotated: true,
            app: Some("gitea".into()),
        };
        assert_eq!(
            s.consequence(),
            Consequence::RedeployApp {
                app: "gitea".into()
            }
        );
        assert_eq!(s.attention(), crate::Attention::Notice);
    }

    #[test]
    fn a_reloadable_secret_does_not_claim_a_redeploy() {
        // Saying "you must redeploy" when it is not true interrupts a service for
        // nothing — and in time you stop believing the screen.
        let s = SecretToRotate {
            name: "crowdsec-bouncer-key".into(),
            usage: "API key".into(),
            nature: Nature::ApiKey,
            age_s: 10 * 86_400,
            never_rotated: true,
            app: None,
        };
        assert_eq!(s.consequence(), Consequence::ReloadIsEnough);
        assert_eq!(s.attention(), crate::Attention::Ok);
    }

    #[test]
    fn a_cache_password_nothing_reads_is_said_so_never_given_a_procedure() {
        let n = Nature::infer("immich-cache-password", "cache authentication");
        assert_eq!(n, Nature::CachePassword);
        assert_eq!(n.procedure(), vec![Step::NothingReadsIt]);
        assert!(!n.needs_redeploy());
    }
}
