//! Binding tokens: how an app receives what was provisioned for it.
//!
//! ## 🔴 What this fixes
//!
//! The resolver created the database, the isolated role and the password - then
//! deployed the app **without telling it anything**. It started, found no database
//! configuration, and fell back to its internal SQLite. Everything looked healthy: the
//! service runs, the probe answers, the dashboard is green. But the data lived in a
//! file nobody had declared, and therefore nobody backed up, while an empty PostgreSQL
//! database was faithfully dumped every night.
//!
//! That was the missing half of the project's central idea: translating a *need* into
//! resources is worthless if the app never learns where they are.
//!
//! ## 🔴 Why secrets are not resolved in the plan
//!
//! A plan is not a private object. It is **displayed** by `hlb plan`, **recorded** in
//! the SQLite state, and **exported** to the Git mirror of the desired state.
//! Substituting a password into it would publish it in all three places at once, one
//! of which is a Git repository that keeps history.
//!
//! So the plan carries the token as-is (`{{ db.password }}`), and substitution happens
//! in the executor at deploy time. [`Token::is_secret`] marks the ones that must never
//! leak, and [`redact`] is used everywhere something is displayed.

use std::collections::BTreeMap;

/// Un jeton substituable dans `spec.env`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Token {
    /// The database server's host - the platform's service name.
    DbHost,
    DbPort,
    DbName,
    DbUser,
    /// 🔴 Secret.
    DbPassword,
    /// Full URL, for apps that accept nothing else. 🔴 Contains the password.
    DbUrl,

    CacheHost,
    CachePort,
    /// The cache's full URL.
    CacheUrl,

    OidcIssuer,
    OidcClientId,
    /// 🔴 Secret.
    OidcClientSecret,

    SmtpHost,
    SmtpPort,
    SmtpUser,
    /// 🔴 Secret.
    SmtpPassword,

    /// The full domain chosen at install time.
    Domain,
}

impl Token {
    /// The written form used in a manifest.
    pub fn placeholder(&self) -> &'static str {
        match self {
            Self::DbHost => "{{ db.host }}",
            Self::DbPort => "{{ db.port }}",
            Self::DbName => "{{ db.name }}",
            Self::DbUser => "{{ db.user }}",
            Self::DbPassword => "{{ db.password }}",
            Self::DbUrl => "{{ db.url }}",
            Self::CacheHost => "{{ cache.host }}",
            Self::CachePort => "{{ cache.port }}",
            Self::CacheUrl => "{{ cache.url }}",
            Self::OidcIssuer => "{{ oidc.issuer }}",
            Self::OidcClientId => "{{ oidc.client_id }}",
            Self::OidcClientSecret => "{{ oidc.client_secret }}",
            Self::SmtpHost => "{{ smtp.host }}",
            Self::SmtpPort => "{{ smtp.port }}",
            Self::SmtpUser => "{{ smtp.user }}",
            Self::SmtpPassword => "{{ smtp.password }}",
            Self::Domain => "{{ domain }}",
        }
    }

    /// Every token. Used by validation and by exhaustiveness tests.
    pub fn all() -> &'static [Token] {
        &[
            Self::DbHost,
            Self::DbPort,
            Self::DbName,
            Self::DbUser,
            Self::DbPassword,
            Self::DbUrl,
            Self::CacheHost,
            Self::CachePort,
            Self::CacheUrl,
            Self::OidcIssuer,
            Self::OidcClientId,
            Self::OidcClientSecret,
            Self::SmtpHost,
            Self::SmtpPort,
            Self::SmtpUser,
            Self::SmtpPassword,
            Self::Domain,
        ]
    }

    /// Does this token carry a value that must never be displayed?
    ///
    /// 🔴 `DbUrl` is one of them: it contains the password. That is the case people
    /// forget, precisely because it looks like an address.
    pub fn is_secret(&self) -> bool {
        matches!(
            self,
            Self::DbPassword | Self::DbUrl | Self::OidcClientSecret | Self::SmtpPassword
        )
    }

    /// The capability this token requires in the manifest.
    ///
    /// 🔴 Used to refuse a `{{ db.password }}` in an app declaring no database:
    /// without this check the variable would go out with the token text as its value,
    /// and the app would complain about an incorrect password - sending you to look at
    /// the password, not the manifest.
    pub fn requires(&self) -> Option<&'static str> {
        match self {
            Self::DbHost
            | Self::DbPort
            | Self::DbName
            | Self::DbUser
            | Self::DbPassword
            | Self::DbUrl => Some("database"),
            Self::CacheHost | Self::CachePort | Self::CacheUrl => Some("cache"),
            Self::OidcIssuer | Self::OidcClientId | Self::OidcClientSecret => Some("sso"),
            Self::SmtpHost | Self::SmtpPort | Self::SmtpUser | Self::SmtpPassword => Some("smtp"),
            // Always available: the domain comes from the install parameters.
            Self::Domain => None,
        }
    }
}

/// The tokens present in a value.
pub fn tokens_in(valeur: &str) -> Vec<Token> {
    Token::all()
        .iter()
        .filter(|t| valeur.contains(t.placeholder()))
        .copied()
        .collect()
}

/// The tokens present in a set of variables.
pub fn tokens_used(env: &BTreeMap<String, String>) -> Vec<Token> {
    let mut v: Vec<Token> = env.values().flat_map(|s| tokens_in(s)).collect();
    v.sort_unstable();
    v.dedup();
    v
}

/// Replaces tokens with their values.
///
/// A token with no value supplied is **left as-is** rather than emptied: an empty
/// variable looks like missing configuration and diagnoses badly, where a literal
/// `{{ db.password }}` in the container logs points straight at the problem.
pub fn substitute(valeur: &str, valeurs: &BTreeMap<Token, String>) -> String {
    let mut out = valeur.to_string();
    for (t, v) in valeurs {
        out = out.replace(t.placeholder(), v);
    }
    out
}

/// Masks the values of variables whose name betrays a secret.
///
/// 🔴 Used everywhere environment variables are displayed or logged. The criterion is
/// the NAME, not the value: by display time the substitution has already happened and
/// a value is just a string - too late to know where it came from.
pub fn redact(nom: &str, valeur: &str) -> String {
    let n = nom.to_ascii_uppercase();
    let sensible = ["PASSWORD", "SECRET", "TOKEN", "KEY", "_URL", "URI", "DSN"]
        .iter()
        .any(|m| n.contains(m));

    if sensible && !valeur.is_empty() {
        "••••••".into()
    } else {
        valeur.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_database_url_is_treated_as_a_secret() {
        // 🔴 The case people forget: `db.url` looks like an address and contains the
        // password. Marking it public would make it appear in plans, in the state and
        // in the Git mirror.
        assert!(Token::DbUrl.is_secret());
        assert!(Token::DbPassword.is_secret());
        assert!(Token::OidcClientSecret.is_secret());
        assert!(Token::SmtpPassword.is_secret());

        assert!(!Token::DbHost.is_secret());
        assert!(!Token::DbName.is_secret());
        assert!(!Token::OidcClientId.is_secret());
    }

    #[test]
    fn every_token_has_a_distinct_placeholder() {
        // Two tokens sharing a written form would substitute for each other at the
        // mercy of iteration order.
        let mut p: Vec<&str> = Token::all().iter().map(|t| t.placeholder()).collect();
        let before = p.len();
        p.sort_unstable();
        p.dedup();
        assert_eq!(p.len(), before, "duplicate written forms");
    }

    #[test]
    fn substitution_leaves_unknown_tokens_visible() {
        // 🔴 A token with no value stays literal. Emptying it would produce an empty
        // variable, indistinguishable from missing configuration: the app would
        // complain about an incorrect password and you would look at the password.
        let mut v = BTreeMap::new();
        v.insert(Token::DbHost, "postgres".into());

        let r = substitute("{{ db.host }}:{{ db.port }}", &v);
        assert_eq!(r, "postgres:{{ db.port }}");
    }

    #[test]
    fn substitution_handles_a_full_url() {
        let mut v = BTreeMap::new();
        v.insert(Token::DbUser, "n8n".into());
        v.insert(Token::DbPassword, "s3cr3t".into());
        v.insert(Token::DbHost, "postgres".into());
        v.insert(Token::DbName, "n8n".into());

        assert_eq!(
            substitute(
                "postgres://{{ db.user }}:{{ db.password }}@{{ db.host }}/{{ db.name }}",
                &v
            ),
            "postgres://n8n:s3cr3t@postgres/n8n"
        );
    }

    #[test]
    fn a_token_declares_the_capability_it_needs() {
        // 🔴 Sans ce lien, un `{{ db.password }}` dans une app sans base partirait
        // avec le texte du jeton pour valeur — et le diagnostic partirait sur une
        // fausse piste.
        assert_eq!(Token::DbPassword.requires(), Some("database"));
        assert_eq!(Token::CacheUrl.requires(), Some("cache"));
        assert_eq!(Token::OidcClientId.requires(), Some("sso"));
        assert_eq!(Token::SmtpUser.requires(), Some("smtp"));
        // The domain comes from the install parameters, not from a capability.
        assert_eq!(Token::Domain.requires(), None);
    }

    #[test]
    fn redaction_looks_at_the_name_because_the_value_no_longer_tells() {
        // By display time the substitution has happened: the value is just a string
        // and no longer says where it came from.
        assert_eq!(redact("DB_POSTGRESDB_PASSWORD", "s3cr3t"), "••••••");
        assert_eq!(redact("DATABASE_URL", "postgres://u:p@h/d"), "••••••");
        assert_eq!(redact("N8N_ENCRYPTION_KEY", "abcd"), "••••••");
        assert_eq!(redact("OIDC_CLIENT_SECRET", "x"), "••••••");

        // What is not sensitive stays readable: masking everything would make
        // diagnosis impossible and push people to bypass the display.
        assert_eq!(redact("DB_POSTGRESDB_HOST", "postgres"), "postgres");
        assert_eq!(redact("DB_TYPE", "postgresdb"), "postgresdb");
    }

    #[test]
    fn an_empty_value_is_not_masked() {
        // Masquer une variable vide ferait croire qu'un secret est en place.
        assert_eq!(redact("DB_PASSWORD", ""), "");
    }

    #[test]
    fn used_tokens_are_found_and_deduplicated() {
        let mut env = BTreeMap::new();
        env.insert("A".to_string(), "{{ db.host }}".to_string());
        env.insert("B".to_string(), "{{ db.host }}:{{ db.port }}".to_string());
        env.insert("C".to_string(), "literal".to_string());

        assert_eq!(tokens_used(&env), vec![Token::DbHost, Token::DbPort]);
    }
}
