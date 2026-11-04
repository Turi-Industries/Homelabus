//! What removing an app leaves behind, so the preview someone decides on says it.
//!
//! `hlb remove` keeps the vault's secrets on purpose: a volume or a backup kept was
//! written with them, and a reinstall finds them there. `hlb secrets-forget` deletes them
//! once the app is really gone. What its needs made in other services stays too: a
//! database holds its data, and nothing but a person should decide that goes.

use hlb_state::State;
use hlb_types::capability::{bucket_name, s3_key_secrets, Capability, SmtpSender, SsoMode};
use hlb_types::Manifest;

/// Said when an app declares no volume. "Nothing will be left" read true for a signing
/// key that stayed in the vault; "the data stays" would promise what no volume holds.
pub const NO_VOLUME: &str = "no volume declared: no file of this app survives";

/// The vault's secrets of an app, by their names: `<app>-…`, sorted.
///
/// A name another installed app could also claim is left out: with `pocket-id` running,
/// `pocket-id-api-key` starts like a secret of a removed `pocket`.
pub fn secrets_of(app: &str, names: &[String], installed: &[String]) -> Vec<String> {
    let claims = |owner: &str, name: &str| {
        name.strip_prefix(owner)
            .is_some_and(|rest| rest.starts_with('-'))
    };
    let mut found: Vec<String> = names
        .iter()
        .filter(|n| claims(app, n))
        .filter(|n| !installed.iter().any(|o| o != app && claims(o, n)))
        .cloned()
        .collect();
    found.sort();
    found
}

/// [`secrets_of`], read from the state.
pub async fn secrets_left(state: &State, app: &str) -> hlb_state::Result<Vec<String>> {
    let names: Vec<String> = state
        .secret_names()
        .await?
        .into_iter()
        .map(|(name, _)| name)
        .collect();
    let installed: Vec<String> = state
        .installed_apps()
        .await?
        .into_iter()
        .map(|(name, _)| name)
        .collect();
    Ok(secrets_of(app, &names, &installed))
}

/// What a removal's preview says about the secrets it keeps; `None` when there are none.
pub fn secrets_line(app: &str, count: usize) -> Option<String> {
    match count {
        0 => None,
        1 => Some(format!(
            "1 secret stays in the vault, for a reinstall: `hlb secrets-forget {app}` deletes it"
        )),
        n => Some(format!(
            "{n} secrets stay in the vault, for a reinstall: `hlb secrets-forget {app}` deletes them"
        )),
    }
}

/// What the app's needs made in other services, which removing it leaves there. Said
/// before the confirmation: the list that follows reads as all that stays.
pub fn kept_elsewhere(app: &str, manifest: &Manifest) -> Vec<String> {
    manifest
        .spec
        .requires
        .iter()
        .filter_map(|need| match need {
            Capability::Database {
                engine,
                name,
                extensions: _,
                connections: _,
            } => Some(format!(
                "the {} database \"{}\" is KEPT, and the role \"{app}\" that opens it",
                engine.service_name(),
                name.as_deref().unwrap_or(app)
            )),
            Capability::Sso {
                mode,
                redirect_paths: _,
            } => match mode {
                SsoMode::None => None,
                SsoMode::Native => Some(format!(
                    "the OIDC client \"{app}\" stays in PocketID, still accepting its callbacks"
                )),
                SsoMode::ProxyOnly | SsoMode::ProxyHeader => Some(format!(
                    "{app}'s callback stays on the portal's OIDC client"
                )),
            },
            Capability::ObjectStorage {
                bucket,
                backup: _,
                expire_after_days: _,
            } => Some(format!(
                "the bucket \"{}\" is KEPT in Garage, and {app}'s key to it",
                bucket_name(bucket.as_deref(), app)
            )),
            Capability::Smtp { sender } => match sender {
                SmtpSender::App => {
                    Some(format!("the account {app} sends mail as stays in Stalwart"))
                }
                SmtpSender::Person => None,
            },
            Capability::MailAccount {
                quota_bytes: _,
                aliases: _,
            } => Some(format!(
                "{app}'s mail account is KEPT in Stalwart, with what it holds"
            )),
            // Nothing of the app's own in a cache anyone must decide about.
            Capability::Cache {
                engine: _,
                dedicated: _,
            } => None,
            // The state lists the volumes, which the preview says one by one.
            Capability::Storage {
                name: _,
                path: _,
                tier: _,
                backup: _,
                sqlite: _,
                copy: _,
                owner: _,
            } => None,
        })
        .collect()
}

/// What forgetting these secrets does to the services still holding their other half.
///
/// Read from the names: `hlb secrets-forget` runs once the manifest is gone. A secret
/// here is not revoked by forgetting it, and only a database's follows the next install.
pub fn forget_warnings(app: &str, secrets: &[String]) -> Vec<String> {
    let stops = "a reinstall stops on it until it is deleted there";
    [
        (
            format!("{app}-db-password"),
            "its role still signs in with it, until a reinstall gives the role a new one"
                .to_string(),
        ),
        (
            format!("{app}-oidc-secret"),
            format!("the OIDC client stays in PocketID, and {stops}"),
        ),
        (
            s3_key_secrets(app).1,
            format!("the key stays in Garage, and {stops}"),
        ),
        (
            format!("{app}-smtp-password"),
            format!("the account stays in Stalwart, and {stops}"),
        ),
        (
            format!("{app}-mail-password"),
            "the mail account keeps this password, and a reinstalled app would be refused \
             until it is changed there"
                .to_string(),
        ),
    ]
    .into_iter()
    .filter(|(name, _)| secrets.contains(name))
    .map(|(name, what)| format!("{name}: {what}"))
    .collect()
}

#[cfg(test)]
mod tests {
    use super::{forget_warnings, kept_elsewhere, secrets_line, secrets_of};
    use hlb_resolver::{resolve, Action, InstallParams};
    use hlb_types::Manifest;

    fn strings(names: &[&str]) -> Vec<String> {
        names.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn an_app_s_secrets_are_those_named_after_it() {
        let vault = strings(&[
            "anubis-signing-key",
            "anubis-other",
            "anubiskey",
            "cluster-ca",
            "restic-repo-password",
        ]);
        assert_eq!(
            secrets_of("anubis", &vault, &[]),
            strings(&["anubis-other", "anubis-signing-key"])
        );
    }

    #[test]
    fn a_name_an_installed_app_could_claim_is_left_alone() {
        let vault = strings(&["pocket-api-key", "pocket-id-api-key", "pocket-id-smtp"]);
        // `pocket` removed, `pocket-id` running: its secrets start with `pocket-` too.
        assert_eq!(
            secrets_of("pocket", &vault, &strings(&["pocket-id"])),
            strings(&["pocket-api-key"])
        );
        // The other way round: `fluxer` running may own `fluxer-admin-key`.
        let vault = strings(&["fluxer-admin-key"]);
        assert_eq!(
            secrets_of("fluxer-admin", &vault, &strings(&["fluxer"])),
            Vec::<String>::new()
        );
        // The app itself, still installed while `hlb remove` previews: its own count.
        assert_eq!(
            secrets_of("fluxer", &vault, &strings(&["fluxer"])),
            strings(&["fluxer-admin-key"])
        );
    }

    #[test]
    fn a_removal_with_no_secret_mentions_none() {
        assert_eq!(secrets_line("a", 0), None);
        assert!(secrets_line("a", 1).is_some_and(|l| l.starts_with("1 secret stays")));
        assert!(secrets_line("a", 2).is_some_and(|l| l.starts_with("2 secrets stay")));
    }

    /// `env` lists the tokens it reads: a need nothing reads does not resolve.
    fn app(env: &[&str], requires: &str) -> Manifest {
        let env: String = env
            .iter()
            .enumerate()
            .map(|(i, token)| format!("    V{i}: \"{{{{ {token} }}}}\"\n"))
            .collect();
        serde_yaml_ng::from_str(&format!(
            "apiVersion: hlb/v1\nkind: App\nmetadata: {{ name: gitea }}\n\
             spec:\n  image: {{ repo: a/b, tag: \"1\" }}\n  env:\n{env}  requires:\n{requires}"
        ))
        .expect("test manifest")
    }

    fn every_need() -> Manifest {
        app(
            &["db.host", "oidc.client_id", "s3.access_key", "smtp.host"],
            "    - { kind: database, engine: postgres }\n\
             \x20   - { kind: database, engine: postgres, name: other }\n\
             \x20   - { kind: sso, mode: native, redirectPaths: [/cb] }\n\
             \x20   - { kind: object-storage, bucket: files }\n\
             \x20   - { kind: smtp }\n\
             \x20   - { kind: mail-account }\n",
        )
    }

    /// Every need that reaches another service, as the plan makes it. Read through the
    /// resolver: a secret renamed there, or an action added, is held to what is said.
    fn outside(manifest: &Manifest) -> (usize, Vec<String>) {
        let params = InstallParams {
            domain: Some("git.example.test".into()),
            mail_domain: Some("example.test".into()),
            ..InstallParams::default()
        };
        let mut made = 0;
        let mut secrets = Vec::new();
        for action in resolve(manifest, &params).expect("plan").actions {
            match action {
                Action::ProvisionDatabase {
                    password_secret, ..
                } => {
                    made += 1;
                    secrets.push(password_secret);
                }
                Action::ProvisionBucket { secret_name, .. }
                | Action::ProvisionSmtpAccount { secret_name, .. } => {
                    made += 1;
                    secrets.push(secret_name);
                }
                Action::CreateOidcClient { app, .. } => {
                    made += 1;
                    secrets.push(format!("{app}-oidc-secret"));
                }
                Action::ProvisionMailAccount { .. } => {
                    made += 1;
                    secrets.push("gitea-mail-password".to_string());
                }
                Action::AddPortalCallback { .. } => made += 1,
                Action::GenerateSecret { .. }
                | Action::CreateVolume { .. }
                | Action::DeployService { .. }
                | Action::FetchDownload { .. }
                | Action::ResolveDigest { .. }
                | Action::WaitHealthy { .. }
                | Action::ConfigureIngress { .. }
                | Action::PendingGuideStep { .. } => {}
            }
        }
        (made, secrets)
    }

    #[test]
    fn a_removal_names_all_the_plan_made_in_other_services() {
        let every = every_need();
        let (made, _) = outside(&every);
        let said = kept_elsewhere("gitea", &every);
        assert_eq!(said.len(), made, "{said:?}");
        for name in [
            "\"gitea\" is KEPT",
            "\"other\" is KEPT",
            "\"files\" is KEPT",
        ] {
            assert!(said.iter().any(|l| l.contains(name)), "{name}: {said:?}");
        }

        let portal = app(&[], "    - { kind: sso, mode: proxy-only }\n");
        assert_eq!(
            kept_elsewhere("gitea", &portal).len(),
            outside(&portal).0,
            "the portal's callback"
        );
    }

    #[test]
    fn a_need_nothing_outlives_is_not_said_to_stay() {
        let none = app(
            &["smtp.host"],
            "    - { kind: sso, mode: none }\n\
             \x20   - { kind: smtp, sender: person }\n\
             \x20   - { kind: storage, name: data, path: /data }\n",
        );
        assert_eq!(kept_elsewhere("gitea", &none), Vec::<String>::new());
        assert_eq!(outside(&none).0, 0);
    }

    #[test]
    fn forgetting_warns_of_every_secret_with_another_half() {
        let (_, mut secrets) = outside(&every_need());
        secrets.dedup();
        let said = forget_warnings("gitea", &secrets);
        assert_eq!(said.len(), secrets.len(), "{secrets:?}: {said:?}");
        for name in &secrets {
            assert!(said.iter().any(|l| l.starts_with(name.as_str())), "{name}");
        }
        assert_eq!(
            forget_warnings("gitea", &strings(&["gitea-signing-key"])),
            Vec::<String>::new()
        );
    }
}
