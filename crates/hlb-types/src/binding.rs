//! Les jetons de liaison : comment une app reçoit ce qu'on a provisionné pour elle
//! (§4.3).
//!
//! ## 🔴 Ce que ça répare
//!
//! Le résolveur créait la base, le rôle isolé et le mot de passe — puis déployait
//! l'app **sans rien lui dire**. Elle démarrait, ne trouvait aucune configuration de
//! base de données, et retombait sur son SQLite interne. Tout paraissait sain : le
//! service tourne, la sonde répond, le tableau de bord est vert. Mais les données
//! vivaient dans un fichier que personne n'avait déclaré, donc que personne ne
//! sauvegardait, pendant qu'une base PostgreSQL vide était fidèlement dumpée toutes
//! les nuits.
//!
//! C'était la moitié manquante de l'idée centrale du projet : traduire un *besoin*
//! en ressources ne sert à rien si l'app n'apprend jamais où elles sont.
//!
//! ## 🔴 Pourquoi les secrets ne sont pas résolus dans le plan
//!
//! Un plan n'est pas un objet privé. Il est **affiché** par `hlb plan`, **enregistré**
//! dans l'état SQLite, et **exporté** vers le miroir Git de l'état désiré (§2.3). Y
//! substituer un mot de passe le publierait aux trois endroits d'un coup, dont un
//! dépôt Git qui garde l'historique.
//!
//! Le plan porte donc le jeton tel quel (`{{ db.password }}`), et la substitution a
//! lieu dans l'exécuteur au moment du déploiement. [`Token::is_secret`] marque ceux
//! qui ne doivent jamais fuiter, et [`redact`] sert partout où l'on affiche.

use std::collections::BTreeMap;

/// Un jeton substituable dans `spec.env`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Token {
    /// Hôte du serveur de base de données — le nom de service de la plateforme.
    DbHost,
    DbPort,
    DbName,
    DbUser,
    /// 🔴 Secret.
    DbPassword,
    /// URL complète, pour les apps qui n'acceptent qu'elle. 🔴 Contient le mot de passe.
    DbUrl,

    CacheHost,
    CachePort,
    /// URL complète du cache.
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

    /// Domaine complet choisi à l'installation.
    Domain,
}

impl Token {
    /// La forme écrite dans un manifest.
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

    /// Tous les jetons. Sert aux validations et aux tests d'exhaustivité.
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

    /// Ce jeton porte-t-il une valeur qui ne doit jamais être affichée ?
    ///
    /// 🔴 `DbUrl` en fait partie : elle contient le mot de passe. C'est le cas qu'on
    /// oublie, précisément parce qu'elle ressemble à une adresse.
    pub fn is_secret(&self) -> bool {
        matches!(
            self,
            Self::DbPassword | Self::DbUrl | Self::OidcClientSecret | Self::SmtpPassword
        )
    }

    /// La capacité que ce jeton exige dans le manifest.
    ///
    /// 🔴 Sert à refuser un `{{ db.password }}` dans une app qui ne déclare aucune
    /// base : sans ce contrôle, la variable partirait avec le texte du jeton pour
    /// valeur, et l'app se plaindrait d'un mot de passe incorrect — en cherchant du
    /// côté du mot de passe, pas du manifest.
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
            // Toujours disponible : le domaine vient des paramètres d'installation.
            Self::Domain => None,
        }
    }
}

/// Les jetons présents dans une valeur.
pub fn tokens_in(valeur: &str) -> Vec<Token> {
    Token::all()
        .iter()
        .filter(|t| valeur.contains(t.placeholder()))
        .copied()
        .collect()
}

/// Les jetons présents dans un ensemble de variables.
pub fn tokens_used(env: &BTreeMap<String, String>) -> Vec<Token> {
    let mut v: Vec<Token> = env.values().flat_map(|s| tokens_in(s)).collect();
    v.sort_unstable();
    v.dedup();
    v
}

/// Remplace les jetons par leurs valeurs.
///
/// Un jeton sans valeur fournie est **laissé tel quel** plutôt que vidé : une variable
/// vide ressemble à une configuration absente et se diagnostique mal, là où
/// `{{ db.password }}` littéral dans les journaux du conteneur désigne le problème.
pub fn substitute(valeur: &str, valeurs: &BTreeMap<Token, String>) -> String {
    let mut out = valeur.to_string();
    for (t, v) in valeurs {
        out = out.replace(t.placeholder(), v);
    }
    out
}

/// Masque les valeurs des variables dont le nom trahit un secret.
///
/// 🔴 Utilisé partout où des variables d'environnement sont affichées ou
/// journalisées. Le critère porte sur le NOM et non sur la valeur : au moment où l'on
/// affiche, la substitution a déjà eu lieu et une valeur est une chaîne comme une
/// autre — il est trop tard pour savoir d'où elle vient.
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
        // 🔴 Le cas qu'on oublie : `db.url` ressemble à une adresse et contient le
        // mot de passe. La marquer publique la ferait apparaître dans les plans, dans
        // l'état et dans le miroir Git.
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
        // Deux jetons partageant une forme écrite se substitueraient l'un l'autre au
        // hasard de l'ordre d'itération.
        let mut p: Vec<&str> = Token::all().iter().map(|t| t.placeholder()).collect();
        let avant = p.len();
        p.sort_unstable();
        p.dedup();
        assert_eq!(p.len(), avant, "formes écrites en double");
    }

    #[test]
    fn substitution_leaves_unknown_tokens_visible() {
        // 🔴 Un jeton sans valeur reste littéral. Le vider produirait une variable
        // vide, indiscernable d'une configuration absente : l'app se plaindrait d'un
        // mot de passe incorrect et l'on chercherait du côté du mot de passe.
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
        // Le domaine vient des paramètres d'installation, pas d'une capacité.
        assert_eq!(Token::Domain.requires(), None);
    }

    #[test]
    fn redaction_looks_at_the_name_because_the_value_no_longer_tells() {
        // Au moment de l'affichage, la substitution a eu lieu : la valeur est une
        // chaîne comme une autre et ne dit plus d'où elle vient.
        assert_eq!(redact("DB_POSTGRESDB_PASSWORD", "s3cr3t"), "••••••");
        assert_eq!(redact("DATABASE_URL", "postgres://u:p@h/d"), "••••••");
        assert_eq!(redact("N8N_ENCRYPTION_KEY", "abcd"), "••••••");
        assert_eq!(redact("OIDC_CLIENT_SECRET", "x"), "••••••");

        // Ce qui n'est pas sensible reste lisible : masquer tout rendrait le
        // diagnostic impossible et pousserait à contourner l'affichage.
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
        env.insert("C".to_string(), "littéral".to_string());

        assert_eq!(tokens_used(&env), vec![Token::DbHost, Token::DbPort]);
    }
}
