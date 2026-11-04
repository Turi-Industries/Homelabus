//! What removing an app leaves behind, so the preview someone decides on says it.
//!
//! `hlb remove` keeps the vault's secrets on purpose: a volume or a backup kept was
//! written with them, and a reinstall finds them there. `hlb secrets-forget` deletes them
//! once the app is really gone.

use hlb_state::State;

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

#[cfg(test)]
mod tests {
    use super::{secrets_line, secrets_of};

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
}
