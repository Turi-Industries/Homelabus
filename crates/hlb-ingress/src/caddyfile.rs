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

/// Le videur CrowdSec, posé sur le frontal (§8bis).
///
/// 🔴 **Il n'a de sens qu'au tout premier maillon de la chaîne.**
///
/// CrowdSec bannit sur l'adresse IP source. Le Caddy *backend* ne voit que l'adresse
/// du frontal (ou d'Anubis) : y poser le videur reviendrait à bannir son propre
/// frontal au premier attaquant, coupant le site pour tout le monde. C'est pour ça
/// que `render_backend` n'émet jamais de directive `crowdsec`, et qu'un test le
/// vérifie.
#[derive(Debug, Clone)]
pub struct CrowdSec {
    /// L'API locale de CrowdSec dans l'overlay.
    pub api_url: String,
    /// Clé du bouncer, obtenue par `cscli bouncers add`. Vient du coffre (§7) —
    /// elle n'est jamais écrite dans un manifest.
    pub api_key: String,
}

impl Default for CrowdSec {
    fn default() -> Self {
        Self {
            api_url: "http://crowdsec:8080".into(),
            api_key: String::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    /// Hôte:port du service Anubis dans l'overlay.
    pub anubis_upstream: String,
    /// Hôte:port du Caddy backend.
    pub backend_upstream: String,
    /// Adresse mail pour l'inscription ACME.
    pub acme_email: String,
    /// Videur CrowdSec. `None` = pas de filtrage réputationnel.
    pub crowdsec: Option<CrowdSec>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            anubis_upstream: "anubis:8923".into(),
            backend_upstream: "caddy-back:8080".into(),
            acme_email: "admin@example.invalid".into(),
            crowdsec: None,
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

    if let Some(cs) = &cfg.crowdsec {
        // ⚠️ `order crowdsec first` est indispensable : sans lui, Caddy applique la
        // directive après le `reverse_proxy`, c'est-à-dire APRÈS avoir transmis la
        // requête au service. Le videur ne bloquerait plus rien.
        let _ = writeln!(out, "\torder crowdsec first");
        let _ = writeln!(out, "\tcrowdsec {{");
        let _ = writeln!(out, "\t\tapi_url {}", cs.api_url);
        let _ = writeln!(out, "\t\tapi_key {}", cs.api_key);
        let _ = writeln!(out, "\t\tticker_interval 15s");
        let _ = writeln!(out, "\t}}");
    }

    let _ = writeln!(out, "}}\n");

    if cfg.crowdsec.is_some() {
        let _ = writeln!(
            out,
            "# ⚠️ Ce Caddyfile exige une image Caddy construite avec le module\n\
             # github.com/hslatman/caddy-crowdsec-bouncer. Une image Caddy standard\n\
             # refusera de démarrer sur la directive « crowdsec ».\n"
        );
    }

    for r in &routes {
        let _ = writeln!(out, "{} {{", r.host);

        // 🔴 Avant tout le reste : un attaquant déjà connu ne doit consommer ni le
        // proof-of-work d'Anubis, ni un aller-retour vers le service.
        if cfg.crowdsec.is_some() {
            let _ = writeln!(out, "\tcrowdsec");
        }

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

    fn avec_crowdsec() -> Config {
        Config {
            crowdsec: Some(CrowdSec {
                api_url: "http://crowdsec:8080".into(),
                api_key: "CLE-DU-VIDEUR".into(),
            }),
            ..Config::default()
        }
    }

    #[test]
    fn the_crowdsec_bouncer_runs_before_everything_else() {
        let out = render_frontend(&[vikunja()], &avec_crowdsec());

        // ⚠️ Sans `order crowdsec first`, Caddy évalue la directive APRÈS le
        // reverse_proxy : la requête est déjà partie, le videur ne bloque rien.
        assert!(out.contains("order crowdsec first"), "{out}");

        let bloc = out
            .split("tasks.example.fr {")
            .nth(1)
            .and_then(|s| s.split("\n}").next())
            .expect("bloc vikunja");
        let i_cs = bloc.find("crowdsec").expect("directive crowdsec");
        let i_px = bloc.find("reverse_proxy").expect("reverse_proxy");
        assert!(i_cs < i_px, "le videur doit précéder le proxy :\n{bloc}");
    }

    #[test]
    fn the_bouncer_never_lands_on_the_backend() {
        // 🔴 L'invariant central : le backend ne voit que l'IP du frontal. Y poser
        // le videur ferait bannir le frontal lui-même au premier attaquant, coupant
        // le site pour TOUT LE MONDE.
        let out = render_backend(&[gitea(), vikunja()], &avec_crowdsec());
        assert!(!out.contains("crowdsec"), "{out}");
    }

    #[test]
    fn without_crowdsec_nothing_is_emitted() {
        // Une image Caddy standard refuse de démarrer sur une directive inconnue :
        // il ne doit rien rester quand le videur n'est pas configuré.
        let out = render_frontend(&[gitea()], &Config::default());
        assert!(!out.contains("crowdsec"), "{out}");
        assert!(!out.contains("order "), "{out}");
    }

    #[test]
    fn the_required_caddy_build_is_announced() {
        // Le message d'erreur de Caddy sur une directive inconnue n'aide pas :
        // autant le dire dans le fichier lui-même.
        let out = render_frontend(&[gitea()], &avec_crowdsec());
        assert!(out.contains("caddy-crowdsec-bouncer"), "{out}");
    }

    #[test]
    fn crowdsec_and_anubis_coexist() {
        // Les deux répondent à des menaces différentes : réputation connue d'un
        // côté, automatisation anonyme de l'autre. L'un ne remplace pas l'autre.
        let out = render_frontend(&[vikunja()], &avec_crowdsec());
        assert!(out.contains("crowdsec"));
        assert!(out.contains("anubis:8923"));
        // Et les callbacks OIDC contournent toujours Anubis.
        assert!(out.contains("/auth/openid/pocketid*"), "{out}");
    }

    #[test]
    fn no_routes_still_produces_a_valid_skeleton() {
        let out = render_frontend(&[], &Config::default());
        assert!(out.contains("email"));
        assert!(out.contains("admin 0.0.0.0:2019"));
    }
}
