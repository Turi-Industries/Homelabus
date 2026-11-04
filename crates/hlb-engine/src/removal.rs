//! What removing an app leaves behind, so the preview someone decides on says it.
//!
//! `hlb remove` keeps the vault's secrets on purpose: a volume or a backup kept was
//! written with them, and a reinstall finds them there. `hlb secrets-forget` deletes them
//! once the app is really gone, with what only those secrets opened in other services
//! (`Leftover`). A database, a bucket and a mail account stay: they hold data, and nothing
//! but a person should decide that goes.

use hlb_identity::{CallbackDrop, PocketId};
use hlb_mail::Stalwart;
use hlb_objstore::Garage;
use hlb_secrets::Vault;
use hlb_state::State;
use hlb_types::capability::{
    bucket_name, s3_key_secrets, Capability, SmtpSender, SsoMode, PORTAL_SERVICE,
};
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
                    "the OIDC client \"{app}\" stays in PocketID, still accepting its \
                     callbacks, until `hlb secrets-forget {app}`"
                )),
                SsoMode::ProxyOnly | SsoMode::ProxyHeader => Some(format!(
                    "{app}'s callback stays on the portal's OIDC client, until `hlb \
                     secrets-forget {app}`"
                )),
            },
            Capability::ObjectStorage {
                bucket,
                backup: _,
                expire_after_days: _,
            } => Some(format!(
                "the bucket \"{}\" is KEPT in Garage; {app}'s key to it stays until `hlb \
                 secrets-forget {app}`",
                bucket_name(bucket.as_deref(), app)
            )),
            Capability::Smtp { sender } => match sender {
                SmtpSender::App => Some(format!(
                    "the account {app} sends mail as stays in Stalwart, until `hlb \
                         secrets-forget {app}`"
                )),
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

/// What a removed app's needs made in another service, opened by the secrets being
/// forgotten and holding no data. `hlb secrets-forget` deletes these: forgetting the secret
/// alone leaves a door nobody holds the key to, on which a reinstall stops.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Leftover {
    OidcClient,
    GarageKey,
    SmtpAccount,
    PortalCallback { url: String },
}

impl Leftover {
    /// What it is, as a refusal names it.
    pub fn named(&self, app: &str) -> String {
        match self {
            Self::OidcClient => format!("the OIDC client \"{app}\""),
            Self::GarageKey => format!("{app}'s key in Garage"),
            Self::SmtpAccount => format!("the account {app} sends mail as"),
            Self::PortalCallback { url } => url.clone(),
        }
    }

    /// What the preview says will go.
    pub fn said(&self, app: &str) -> String {
        match self {
            Self::OidcClient => format!("the OIDC client \"{app}\" is deleted from PocketID"),
            Self::GarageKey => {
                format!("{app}'s key is deleted from Garage: its buckets and their objects stay")
            }
            Self::SmtpAccount => format!(
                "the account {app} sends mail as is deleted from Stalwart, with any bounce it holds"
            ),
            Self::PortalCallback { url } => {
                format!("{url} is taken off the portal's OIDC client")
            }
        }
    }

    /// The secrets that stay while this does: one forgotten alone is the door above.
    pub fn secrets(&self, app: &str) -> Vec<String> {
        match self {
            Self::OidcClient => {
                vec![
                    format!("{app}-oidc-secret"),
                    format!("{app}-oidc-client-id"),
                ]
            }
            Self::GarageKey => {
                let (id, secret) = s3_key_secrets(app);
                vec![id, secret]
            }
            Self::SmtpAccount => vec![
                format!("{app}-smtp-password"),
                crate::submission::address_secret(app),
            ],
            Self::PortalCallback { url: _ } => Vec::new(),
        }
    }
}

/// What forgetting `app` deletes elsewhere, read from the names: the manifest is gone.
///
/// A secret proves the app made its other half. `domains` are where it was published, less
/// those `served` by an app still installed, whose portal callback is the same URL. An
/// account that is also the app's mail account stays: it holds mail.
pub fn leftovers(
    app: &str,
    secrets: &[String],
    domains: &[String],
    served: &[String],
) -> Vec<Leftover> {
    let holds = |leftover: &Leftover| {
        leftover
            .secrets(app)
            .iter()
            .any(|name| secrets.contains(name))
    };
    let mailbox = secrets.contains(&format!("{app}-mail-password"));
    let mut found: Vec<Leftover> = [Leftover::OidcClient, Leftover::GarageKey]
        .into_iter()
        .filter(holds)
        .collect();
    if !mailbox && holds(&Leftover::SmtpAccount) {
        found.push(Leftover::SmtpAccount);
    }
    found.extend(domains.iter().filter(|d| !served.contains(d)).map(|d| {
        Leftover::PortalCallback {
            url: format!("https://{d}{}", hlb_resolver::PORTAL_CALLBACK),
        }
    }));
    found
}

/// [`leftovers`], read from the state.
pub async fn leftovers_in(
    state: &State,
    app: &str,
    secrets: &[String],
) -> hlb_state::Result<Vec<Leftover>> {
    let mut served = Vec::new();
    for (name, _) in state.installed_apps().await? {
        served.extend(state.app_domain(&name).await?);
    }
    let domains = state.removed_domains(app).await?;
    Ok(leftovers(app, secrets, &domains, &served))
}

/// The admin clients this command was given.
#[derive(Clone, Copy, Default)]
pub struct Services<'a> {
    pub identity: Option<&'a PocketId>,
    pub objstore: Option<&'a Garage>,
    pub mail: Option<&'a Stalwart>,
}

/// What came of asking a service to delete a [`Leftover`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Taken {
    /// It is gone, or was: its secrets may go.
    Gone(String),
    /// It is still there, and why: its secrets stay, and running again finishes it.
    Stays(String),
}

/// What a name in a service is, against the id the vault kept for it.
#[derive(Debug, PartialEq, Eq)]
enum Found<'a> {
    Nothing,
    Ours(&'a str),
    /// Someone else's under that name: made by hand, or after the vault's was deleted.
    Another,
}

fn found<'a>(there: Option<&'a str>, kept: Option<&str>) -> Found<'a> {
    match (there, kept) {
        (None, _) => Found::Nothing,
        (Some(id), Some(ours)) if id != ours => Found::Another,
        (Some(id), _) => Found::Ours(id),
    }
}

async fn kept(state: &State, vault: &Vault, name: &str) -> crate::Result<Option<String>> {
    match state.secret(name).await? {
        Some(ct) => Ok(Some(vault.decrypt(&ct)?)),
        None => Ok(None),
    }
}

/// Deletes one [`Leftover`], or says why it stays.
pub async fn take(
    leftover: &Leftover,
    app: &str,
    state: &State,
    vault: &Vault,
    services: Services<'_>,
) -> crate::Result<Taken> {
    let not_given =
        |service: &str, vars: &str| Taken::Stays(format!("no {service} given here ({vars})"));
    let asked = |service: &str, e: &dyn std::fmt::Display| Taken::Stays(format!("{service}: {e}"));
    match leftover {
        Leftover::OidcClient => {
            let Some(pid) = services.identity else {
                return Ok(not_given("PocketID", "HLB_POCKETID_URL, HLB_POCKETID_KEY"));
            };
            let client = match pid.find_by_name(app).await {
                Ok(c) => c,
                Err(e) => return Ok(asked("PocketID", &e)),
            };
            let ours = kept(state, vault, &format!("{app}-oidc-client-id")).await?;
            Ok(
                match found(client.as_ref().map(|c| c.id.as_str()), ours.as_deref()) {
                    Found::Nothing => Taken::Gone(format!("no OIDC client \"{app}\" in PocketID")),
                    Found::Another => Taken::Stays(
                        "PocketID holds another under that name: it is for you to delete".into(),
                    ),
                    Found::Ours(id) => match pid.delete(id).await {
                        Ok(()) => {
                            Taken::Gone(format!("the OIDC client \"{app}\" deleted from PocketID"))
                        }
                        Err(e) => asked("PocketID", &e),
                    },
                },
            )
        }
        Leftover::GarageKey => {
            let Some(garage) = services.objstore else {
                return Ok(not_given("Garage", "HLB_GARAGE_URL, HLB_GARAGE_TOKEN"));
            };
            let key = match garage.key_id(app).await {
                Ok(k) => k,
                Err(e) => return Ok(asked("Garage", &e)),
            };
            let ours = kept(state, vault, &s3_key_secrets(app).0).await?;
            Ok(match found(key.as_deref(), ours.as_deref()) {
                Found::Nothing => Taken::Gone(format!("no key \"{app}\" in Garage")),
                Found::Another => Taken::Stays(
                    "Garage holds another under that name: it is for you to delete".into(),
                ),
                Found::Ours(id) => match garage.delete_key(id).await {
                    Ok(()) => Taken::Gone(format!("{app}'s key deleted from Garage")),
                    Err(e) => asked("Garage", &e),
                },
            })
        }
        Leftover::SmtpAccount => {
            let Some(mail) = services.mail else {
                return Ok(not_given(
                    "Stalwart",
                    "HLB_STALWART_URL, HLB_STALWART_ADMIN, HLB_STALWART_PASSWORD",
                ));
            };
            let address = kept(state, vault, &crate::submission::address_secret(app)).await?;
            let password = kept(state, vault, &format!("{app}-smtp-password")).await?;
            let (Some(address), Some(password)) = (address, password) else {
                return Ok(Taken::Gone(format!(
                    "the vault holds no address and password for {app}'s account: if Stalwart \
                     has one, delete it there"
                )));
            };
            take_account(state, mail, &address, &password).await
        }
        Leftover::PortalCallback { url } => {
            let Some(pid) = services.identity else {
                return Ok(not_given("PocketID", "HLB_POCKETID_URL, HLB_POCKETID_KEY"));
            };
            Ok(match pid.drop_callback(PORTAL_SERVICE, url).await {
                Ok(CallbackDrop::Dropped) => {
                    Taken::Gone(format!("{url} taken off the portal's OIDC client"))
                }
                Ok(CallbackDrop::NotThere) => {
                    Taken::Gone(format!("the portal's OIDC client does not accept {url}"))
                }
                Ok(CallbackDrop::OnlyOne) => {
                    Taken::Stays("it is the only callback of the portal's OIDC client".into())
                }
                Err(e) => asked("PocketID", &e),
            })
        }
    }
}

/// An address is handed out again once its app is gone, and deleting an account takes its
/// mail: it goes only if nobody owns it and the app's own password still opens it.
async fn take_account(
    state: &State,
    mail: &Stalwart,
    address: &str,
    password: &str,
) -> crate::Result<Taken> {
    let (local, domain) = address.split_once('@').unwrap_or((address, ""));
    if let Some(owner) = state.mailbox_owner(local, domain).await? {
        return Ok(Taken::Stays(format!("{address} is {owner}'s mailbox now")));
    }
    let asked = |e: hlb_mail::Error| Taken::Stays(format!("Stalwart: {e}"));
    let domain_id = match mail.domain_id(domain).await {
        Ok(id) => Some(id),
        Err(hlb_mail::Error::UnknownDomain(_)) => None,
        Err(e) => return Ok(asked(e)),
    };
    let there = match domain_id {
        Some(id) => match mail.find_account(local, &id).await {
            Ok(found) => found.is_some(),
            Err(e) => return Ok(asked(e)),
        },
        None => false,
    };
    if !there {
        return Ok(Taken::Gone(format!("no account {address} in Stalwart")));
    }
    match mail.accepts(address, password).await {
        Ok(true) => {}
        Ok(false) => {
            return Ok(Taken::Stays(format!(
                "{address} does not open with the app's password, so it is not the app's: it \
                 is for you to delete"
            )))
        }
        Err(e) => return Ok(asked(e)),
    }
    Ok(match mail.destroy_account(address).await {
        Ok(_) => Taken::Gone(format!("{address} deleted from Stalwart")),
        Err(e) => asked(e),
    })
}

/// What forgetting these secrets leaves behind, in the services nothing deletes from.
///
/// Read from the names: `hlb secrets-forget` runs once the manifest is gone. These stay:
/// only a database's follows the next install.
pub fn forget_warnings(app: &str, secrets: &[String]) -> Vec<String> {
    let mailbox = format!("{app}-mail-password");
    let mut said = vec![(
        format!("{app}-db-password"),
        "its role still signs in with it, until a reinstall gives the role a new one".to_string(),
    )];
    if secrets.contains(&mailbox) {
        said.push((
            format!("{app}-smtp-password"),
            "the account stays in Stalwart: it is also the app's mail account".to_string(),
        ));
    }
    said.push((
        mailbox,
        "the mail account keeps this password, and a reinstalled app would be refused until it \
         is changed there"
            .to_string(),
    ));
    said.into_iter()
        .filter(|(name, _)| secrets.contains(name))
        .map(|(name, what)| format!("{name}: {what}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{
        forget_warnings, found, kept_elsewhere, leftovers, secrets_line, secrets_of, Found,
        Leftover,
    };
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

    /// Every secret the plan made with another half is either deleted with it or said
    /// to stay: read through the resolver, so one added there is held to this.
    #[test]
    fn forgetting_accounts_for_every_secret_with_another_half() {
        let held = |secrets: &[String], name: &str| {
            leftovers("gitea", secrets, &[], &[])
                .iter()
                .any(|l| l.secrets("gitea").iter().any(|s| s == name))
        };
        let (_, secrets) = outside(&every_need());
        let said = forget_warnings("gitea", &secrets);
        for name in &secrets {
            assert!(
                held(&secrets, name) || said.iter().any(|l| l.starts_with(name.as_str())),
                "{name}: {said:?}"
            );
        }
        assert_eq!(
            forget_warnings("gitea", &strings(&["gitea-signing-key"])),
            Vec::<String>::new()
        );
    }

    #[test]
    fn what_goes_is_named_by_the_secrets_that_open_it() {
        assert_eq!(
            leftovers("gitea", &strings(&["gitea-signing-key"]), &[], &[]),
            Vec::<Leftover>::new()
        );
        assert_eq!(
            leftovers(
                "gitea",
                &strings(&[
                    "gitea-oidc-secret",
                    "gitea-s3-secret",
                    "gitea-smtp-password"
                ]),
                &[],
                &[]
            ),
            vec![
                Leftover::OidcClient,
                Leftover::GarageKey,
                Leftover::SmtpAccount
            ]
        );
    }

    /// The same address: deleting the sender's account would take the mailbox's mail.
    #[test]
    fn an_account_that_also_holds_mail_stays() {
        let both = strings(&["gitea-smtp-password", "gitea-mail-password"]);
        assert_eq!(leftovers("gitea", &both, &[], &[]), Vec::<Leftover>::new());
        assert!(forget_warnings("gitea", &both)
            .iter()
            .any(|l| l.starts_with("gitea-smtp-password")));
    }

    #[test]
    fn a_callback_goes_unless_an_installed_app_is_served_there() {
        let domains = strings(&["old.example.test", "shared.example.test"]);
        assert_eq!(
            leftovers(
                "gitea",
                &[],
                &domains,
                &strings(&["shared.example.test", "other.example.test"])
            ),
            vec![Leftover::PortalCallback {
                url: "https://old.example.test/oauth2/callback".into()
            }]
        );
    }

    #[test]
    fn a_name_in_a_service_is_deleted_only_if_it_is_the_id_the_vault_kept() {
        assert_eq!(found(None, Some("a")), Found::Nothing);
        assert_eq!(found(Some("a"), Some("a")), Found::Ours("a"));
        assert_eq!(found(Some("b"), Some("a")), Found::Another);
        // Its secret proves the app made it, where no id was kept beside.
        assert_eq!(found(Some("b"), None), Found::Ours("b"));
    }

    /// Before anything is asked of Stalwart: this client reaches nothing.
    #[tokio::test]
    async fn an_address_handed_to_a_person_since_is_left_with_them() {
        let state = hlb_state::State::in_memory().await.expect("state");
        state
            .upsert_user("lena", "standard", None)
            .await
            .expect("user");
        state
            .add_mailbox("lena", "gitea", "example.test", true)
            .await
            .expect("mailbox");
        let nowhere = hlb_mail::Stalwart::new(
            "http://127.0.0.1:9",
            hlb_mail::Auth::Bearer("unused".into()),
        );
        let taken = super::take_account(&state, &nowhere, "gitea@example.test", "x")
            .await
            .expect("answered");
        assert_eq!(
            taken,
            super::Taken::Stays("gitea@example.test is lena's mailbox now".into())
        );
    }
}
