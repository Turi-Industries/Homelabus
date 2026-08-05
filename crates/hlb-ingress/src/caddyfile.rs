//! Génération des Caddyfile (§6.1 du plan).
//!
//! La chaîne d'entrée est à trois maillons :
//!
//! ```text
//! Internet → [Caddy frontend] → [Anubis] → [Caddy backend] → services
//!                TLS, ACME       anti-bot      routage
//! ```
//!
//! Les deux Caddyfile sont **entièrement générés** depuis les manifests. On n'écrit
//! plus de configuration à la main, donc on ne l'oublie plus non plus.
//!
//! La sortie est déterministe : les routes sont triées, ce qui rend les tests
//! d'instantané possibles et les diffs lisibles (§12bis).

use std::fmt::Write;

/// Une route à publier, dérivée d'un `Ingress` de manifest.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Route {
    pub host: String,
    /// Nom du service Swarm, résolu par le DNS interne de l'overlay.
    pub service: String,
    pub port: u16,
    /// Passe par Anubis ? Déduit de `chain` dans le manifest.
    pub through_anubis: bool,
    /// `false` = joignable uniquement depuis le VPN (§9).
    pub public: bool,
    /// Chemins de callback OIDC de cette app, à exclure d'Anubis (§5.8).
    pub sso_paths: Vec<String>,
}

impl Route {
    pub fn new(host: impl Into<String>, service: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            service: service.into(),
            port,
            through_anubis: false,
            public: false,
            sso_paths: Vec::new(),
        }
    }
}

/// Chemins qu'Anubis ne doit **jamais** intercepter (§5.8).
///
/// Un challenge proof-of-work devant un callback OAuth casse la connexion : la
/// redirection depuis le fournisseur d'identité est une navigation automatique, pas
/// une action de l'utilisateur, et certains agents ne résoudront jamais le challenge.
pub const ANUBIS_ALWAYS_BYPASS: &[&str] = &[
    "/.well-known/*",
    "/oauth2/*",
    "/login/oauth/*",
    "/identity/connect/*",
];

/// Plages considérées comme « internes » pour les routes non publiques.
const PRIVATE_RANGES: &[&str] = &["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fd00::/8"];

#[derive(Debug, Clone)]
pub struct Config {
    /// Hôte:port du service Anubis dans l'overlay.
    pub anubis_upstream: String,
    /// Hôte:port du Caddy backend.
    pub backend_upstream: String,
    /// Adresse mail pour l'inscription ACME.
    pub acme_email: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            anubis_upstream: "anubis:8923".into(),
            backend_upstream: "caddy-back:8080".into(),
            acme_email: "admin@example.invalid".into(),
        }
    }
}

/// Le Caddyfile du frontal : TLS, filtrage réseau, aiguillage vers Anubis ou non.
pub fn render_frontend(routes: &[Route], cfg: &Config) -> String {
    let mut routes = routes.to_vec();
    routes.sort();

    let mut out = String::new();

    let _ = writeln!(out, "# Généré par HomelabUS — ne pas éditer à la main.");
    let _ = writeln!(out, "# Toute modification sera écrasée à la prochaine réconciliation.\n");
    let _ = writeln!(out, "{{");
    let _ = writeln!(out, "\temail {}", cfg.acme_email);
    let _ = writeln!(out, "\tadmin 0.0.0.0:2019");
    let _ = writeln!(out, "}}\n");

    for r in &routes {
        let _ = writeln!(out, "{} {{", r.host);

        // §9 — en-têtes de sécurité posés une fois, au point d'entrée.
        let _ = writeln!(out, "\theader {{");
        let _ = writeln!(out, "\t\tStrict-Transport-Security \"max-age=31536000; includeSubDomains\"");
        let _ = writeln!(out, "\t\tX-Content-Type-Options nosniff");
        let _ = writeln!(out, "\t\tReferrer-Policy strict-origin-when-cross-origin");
        let _ = writeln!(out, "\t\t-Server");
        let _ = writeln!(out, "\t}}");

        if !r.public {
            // Exposition privée par défaut : seul le réseau interne passe.
            let _ = writeln!(out, "\n\t# Route privée : accessible uniquement depuis le VPN.");
            let _ = writeln!(out, "\t@externe not remote_ip {}", PRIVATE_RANGES.join(" "));
            let _ = writeln!(out, "\trespond @externe 403");
        }

        if r.through_anubis {
            // Les chemins d'authentification contournent Anubis, sinon le flux OIDC
            // se casse (§5.8).
            let mut bypass: Vec<String> =
                ANUBIS_ALWAYS_BYPASS.iter().map(|s| s.to_string()).collect();
            for p in &r.sso_paths {
                let p = p.trim_end_matches('*').trim_end_matches('/');
                if !p.is_empty() {
                    bypass.push(format!("{p}*"));
                }
            }
            bypass.sort();
            bypass.dedup();

            let _ = writeln!(out, "\n\t# §5.8 — Anubis casserait les callbacks OIDC.");
            let _ = writeln!(out, "\t@auth path {}", bypass.join(" "));
            let _ = writeln!(out, "\treverse_proxy @auth {}", cfg.backend_upstream);
            let _ = writeln!(out, "\n\treverse_proxy {}", cfg.anubis_upstream);
        } else {
            let _ = writeln!(out, "\n\treverse_proxy {}", cfg.backend_upstream);
        }

        let _ = writeln!(out, "}}\n");
    }

    out
}

/// Le Caddyfile arrière : aiguillage vers les services de l'overlay.
pub fn render_backend(routes: &[Route], cfg: &Config) -> String {
    let mut routes = routes.to_vec();
    routes.sort();

    let mut out = String::new();
    let _ = writeln!(out, "# Généré par HomelabUS — ne pas éditer à la main.\n");
    let _ = writeln!(out, "{{");
    let _ = writeln!(out, "\tadmin 0.0.0.0:2019");
    // Le TLS est déjà terminé par le frontal : on écoute en clair sur l'overlay,
    // lui-même chiffré par IPsec (§6.3).
    let _ = writeln!(out, "\tauto_https off");
    let _ = writeln!(out, "}}\n");

    let listen = cfg
        .backend_upstream
        .rsplit(':')
        .next()
        .unwrap_or("8080");

    // ⚠️ Un SEUL bloc pour l'adresse d'écoute : Caddy refuse deux définitions de site
    // sur la même adresse (« ambiguous site definition »). Tous les hôtes cohabitent
    // donc dans ce bloc, distingués par des matchers.
    let _ = writeln!(out, ":{listen} {{");
    for r in &routes {
        let m = sanitize(&r.host);
        let _ = writeln!(out, "\t@{m} host {}", r.host);
        let _ = writeln!(out, "\treverse_proxy @{m} {}:{}", r.service, r.port);
    }
    if routes.is_empty() {
        let _ = writeln!(out, "\trespond \"aucune application publiée\" 404");
    }
    let _ = writeln!(out, "}}");

    out
}

/// Les noms de matcher Caddy n'acceptent pas les points ni les tirets.
fn sanitize(host: &str) -> String {
    host.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gitea() -> Route {
        Route {
            host: "git.example.fr".into(),
            service: "gitea".into(),
            port: 3000,
            through_anubis: false,
            public: true,
            sso_paths: vec!["/user/oauth2/PocketID/callback".into()],
        }
    }

    fn vikunja() -> Route {
        Route {
            host: "tasks.example.fr".into(),
            service: "vikunja".into(),
            port: 3456,
            through_anubis: true,
            public: true,
            sso_paths: vec!["/auth/openid/pocketid".into()],
        }
    }

    #[test]
    fn output_is_deterministic() {
        let cfg = Config::default();
        let a = render_frontend(&[vikunja(), gitea()], &cfg);
        let b = render_frontend(&[gitea(), vikunja()], &cfg);
        assert_eq!(a, b, "l'ordre d'entrée ne doit pas changer la sortie");
    }

    #[test]
    fn anubis_is_only_applied_where_declared() {
        let cfg = Config::default();
        let out = render_frontend(&[gitea(), vikunja()], &cfg);

        // Gitea n'a pas Anubis : un proof-of-work casserait `git clone`.
        let gitea_block = out
            .split("git.example.fr {")
            .nth(1)
            .and_then(|s| s.split("\n}").next())
            .expect("bloc gitea");
        assert!(!gitea_block.contains("anubis"), "gitea ne doit pas passer par Anubis");

        let vikunja_block = out
            .split("tasks.example.fr {")
            .nth(1)
            .and_then(|s| s.split("\n}").next())
            .expect("bloc vikunja");
        assert!(vikunja_block.contains("anubis:8923"));
    }

    #[test]
    fn oidc_callbacks_bypass_anubis() {
        // §5.8 — sans ça, la connexion SSO se casse de façon très difficile à diagnostiquer.
        let out = render_frontend(&[vikunja()], &Config::default());

        assert!(out.contains("/.well-known/*"));
        assert!(out.contains("/oauth2/*"));
        // Le chemin déclaré par l'app est ajouté aux exclusions.
        assert!(
            out.contains("/auth/openid/pocketid*"),
            "le redirectPath de l'app doit contourner Anubis :\n{out}"
        );
    }

    #[test]
    fn a_route_without_anubis_has_no_bypass_block() {
        let out = render_frontend(&[gitea()], &Config::default());
        assert!(!out.contains("@auth"), "inutile sans Anubis :\n{out}");
    }

    #[test]
    fn private_routes_reject_external_traffic() {
        let mut r = gitea();
        r.public = false;
        let out = render_frontend(&[r], &Config::default());

        assert!(out.contains("@externe not remote_ip"));
        assert!(out.contains("respond @externe 403"));
        assert!(out.contains("192.168.0.0/16"));
    }

    #[test]
    fn public_routes_have_no_ip_restriction() {
        let out = render_frontend(&[gitea()], &Config::default());
        assert!(!out.contains("@externe"));
    }

    #[test]
    fn security_headers_are_always_present() {
        let out = render_frontend(&[gitea()], &Config::default());
        assert!(out.contains("Strict-Transport-Security"));
        assert!(out.contains("X-Content-Type-Options nosniff"));
        assert!(out.contains("-Server"), "la bannière serveur doit être retirée");
    }

    #[test]
    fn backend_routes_to_the_swarm_service() {
        let out = render_backend(&[gitea()], &Config::default());
        assert!(out.contains("host git.example.fr"));
        assert!(out.contains("reverse_proxy @git_example_fr gitea:3000"));
        // Le TLS est terminé au frontal.
        assert!(out.contains("auto_https off"));
    }

    #[test]
    fn the_backend_declares_its_listener_only_once() {
        // Caddy refuse deux définitions de site sur la même adresse.
        let out = render_backend(&[gitea(), vikunja()], &Config::default());
        assert_eq!(
            out.matches(":8080 {").count(),
            1,
            "un seul bloc d'écoute attendu :\n{out}"
        );
        assert!(out.contains("gitea:3000"));
        assert!(out.contains("vikunja:3456"));
    }

    #[test]
    fn matcher_names_are_valid_identifiers() {
        // Caddy refuse les points et les tirets dans un nom de matcher.
        assert_eq!(sanitize("git.example.fr"), "git_example_fr");
        assert_eq!(sanitize("mon-app.example.fr"), "mon_app_example_fr");
    }

    #[test]
    fn generated_files_warn_against_hand_editing() {
        let cfg = Config::default();
        for out in [render_frontend(&[gitea()], &cfg), render_backend(&[gitea()], &cfg)] {
            assert!(out.contains("Généré par HomelabUS"));
        }
    }

    #[test]
    fn no_routes_still_produces_a_valid_skeleton() {
        let out = render_frontend(&[], &Config::default());
        assert!(out.contains("email"));
        assert!(out.contains("admin 0.0.0.0:2019"));
    }
}
