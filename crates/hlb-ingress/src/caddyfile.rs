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
    /// L'app a-t-elle besoin du portail ? Vrai pour `proxy-header` et `proxy-only`,
    /// faux pour `native` (elle parle OIDC elle-même) et `none`.
    pub needs_forward_auth: bool,
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
            needs_forward_auth: false,
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

/// Portail d'authentification devant les apps sans OIDC natif (§5.0).
///
/// 🔴 **La faille classique du forward-auth : les en-têtes entrants.**
///
/// Le portail authentifie l'utilisateur puis ajoute `X-Auth-Request-User` à la requête
/// transmise à l'app, qui lui fait confiance. Si le proxy laisse passer un en-tête du
/// même nom **envoyé par le client**, alors :
///
/// ```text
/// curl -H "X-Auth-Request-User: admin" https://app.example.fr/
/// ```
///
/// …suffit à devenir administrateur. La requête est authentifiée par le portail (avec
/// un compte quelconque, ou même sans), et l'app lit l'en-tête falsifié.
///
/// D'où le `request_header -X-Auth-Request-*` posé **avant** tout le reste : les
/// en-têtes d'identité ne peuvent venir que du portail, jamais du réseau.
#[derive(Debug, Clone)]
pub struct ForwardAuth {
    /// Hôte:port du portail dans l'overlay.
    pub upstream: String,
    /// Chemin de vérification. `/oauth2/auth` pour oauth2-proxy.
    pub verify_path: String,
    /// Chemin de connexion, vers lequel un 401 redirige.
    pub sign_in_path: String,
}

impl Default for ForwardAuth {
    fn default() -> Self {
        Self {
            upstream: "oauth2-proxy:4180".into(),
            verify_path: "/oauth2/auth".into(),
            sign_in_path: "/oauth2/sign_in".into(),
        }
    }
}

/// Les en-têtes que le portail pose, et que le client ne doit JAMAIS pouvoir poser.
///
/// ⚠️ `copy_headers` n'a d'effet que si oauth2-proxy tourne avec `--set-xauthrequest` :
/// sans ce drapeau, les en-têtes sont simplement absents et l'app voit un utilisateur
/// anonyme — sans la moindre erreur.
pub const AUTH_HEADERS: &[&str] = &[
    "X-Auth-Request-User",
    "X-Auth-Request-Email",
    "X-Auth-Request-Preferred-Username",
    "X-Auth-Request-Groups",
];

/// Obtention des certificats par DNS-01 (§6.4).
///
/// ## Pourquoi DNS-01 plutôt que HTTP-01
///
/// HTTP-01 exige que chaque nom soit déjà joignable en HTTP depuis Internet, donc un
/// enregistrement DNS **par app**, créé avant l'installation. DNS-01 permet un
/// **certificat wildcard** : un seul `*.example.fr` créé une fois, et toute nouvelle
/// app est immédiatement servie en TLS sans la moindre action DNS.
///
/// Bénéfice de sécurité en prime : les sous-domaines n'apparaissent pas dans les
/// journaux de Certificate Transparency, qui sont publics et indexés. Sans wildcard,
/// installer `comptabilite.example.fr` l'annonce au monde entier.
///
/// ## 🔴 Le piège des quotas Let's Encrypt
///
/// Une boucle de réconciliation qui redemande un certificat en continu fait bannir le
/// domaine **pour une semaine** — et tous les services passent en TLS invalide d'un
/// coup. C'est pour ça que `staging` existe, et qu'il faut s'en servir au premier
/// essai. Les certificats de staging ne sont pas reconnus par les navigateurs : c'est
/// le but, on vérifie la mécanique sans consommer de quota.
#[derive(Debug, Clone)]
pub struct Acme {
    /// Le module DNS de Caddy : `cloudflare`, `ovh`, `desec`, `gandi`…
    pub provider: String,
    /// Jeton d'API du fournisseur. Vient du coffre, jamais d'un manifest.
    pub api_token: String,
    /// Domaine de base, sans le `*.`.
    pub base_domain: String,
    /// 🔴 Utiliser l'environnement de test de Let's Encrypt.
    pub staging: bool,
}

impl Acme {
    /// Les noms couverts par le certificat.
    ///
    /// 🔴 **`*.example.fr` ne couvre PAS `example.fr`.** C'est la règle des jokers
    /// TLS, et l'erreur est classique : le wildcard est obtenu, tous les sous-domaines
    /// fonctionnent, et le domaine nu affiche une erreur de certificat que personne ne
    /// comprend. Les deux noms sont donc toujours demandés ensemble.
    pub fn subjects(&self) -> Vec<String> {
        vec![format!("*.{}", self.base_domain), self.base_domain.clone()]
    }

    /// L'URL de l'autorité, ou `None` pour le défaut (production).
    pub fn ca_url(&self) -> Option<&'static str> {
        self.staging
            .then_some("https://acme-staging-v02.api.letsencrypt.org/directory")
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
    /// Portail d'authentification. `None` = pas de forward-auth.
    pub forward_auth: Option<ForwardAuth>,
    /// Certificats par DNS-01. `None` = Caddy se débrouille en HTTP-01, ce qui
    /// impose un enregistrement DNS par app.
    pub acme: Option<Acme>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            anubis_upstream: "anubis:8923".into(),
            backend_upstream: "caddy-back:8080".into(),
            acme_email: "admin@example.invalid".into(),
            crowdsec: None,
            forward_auth: None,
            acme: None,
        }
    }
}

/// Le Caddyfile du frontal : TLS, filtrage réseau, aiguillage vers Anubis ou non.
pub fn render_frontend(routes: &[Route], cfg: &Config) -> String {
    let mut routes = routes.to_vec();
    routes.sort();

    let mut out = String::new();

    let _ = writeln!(out, "# Généré par Homelabus — ne pas éditer à la main.");
    let _ = writeln!(
        out,
        "# Toute modification sera écrasée à la prochaine réconciliation.\n"
    );
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

    if let Some(a) = &cfg.acme {
        rendre_acme(&mut out, a);
    }

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

        if let Some(fa) = &cfg.forward_auth {
            if r.needs_forward_auth {
                rendre_forward_auth(&mut out, fa);
            }
        }

        // §9 — en-têtes de sécurité posés une fois, au point d'entrée.
        let _ = writeln!(out, "\theader {{");
        let _ = writeln!(
            out,
            "\t\tStrict-Transport-Security \"max-age=31536000; includeSubDomains\""
        );
        let _ = writeln!(out, "\t\tX-Content-Type-Options nosniff");
        let _ = writeln!(out, "\t\tReferrer-Policy strict-origin-when-cross-origin");
        let _ = writeln!(out, "\t\t-Server");
        let _ = writeln!(out, "\t}}");

        if !r.public {
            // Exposition privée par défaut : seul le réseau interne passe.
            let _ = writeln!(
                out,
                "\n\t# Route privée : accessible uniquement depuis le VPN."
            );
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

/// Le bloc qui obtient le certificat wildcard.
///
/// Il est déclaré **une fois**, pour tous les noms : chaque site le réutilise ensuite
/// automatiquement. Un `tls` par site redemanderait un certificat par sous-domaine,
/// ce qui épuise le quota Let's Encrypt en quelques apps et fait bannir le domaine.
fn rendre_acme(out: &mut String, a: &Acme) {
    if a.staging {
        let _ = writeln!(
            out,
            "# 🔴 ENVIRONNEMENT DE TEST Let's Encrypt : ces certificats ne sont PAS\n\
             # reconnus par les navigateurs. C'est voulu — on vérifie la mécanique\n\
             # sans consommer de quota. Retire --acme-staging quand ça marche.\n"
        );
    }

    let _ = writeln!(
        out,
        "# ⚠️ Exige une image Caddy construite avec le module DNS « {} » :\n\
         #   xcaddy build --with github.com/caddy-dns/{}\n\
         # Une image Caddy standard refuse de démarrer sur « dns {} ».\n",
        a.provider, a.provider, a.provider
    );

    // 🔴 Les DEUX noms : `*.example.fr` ne couvre pas `example.fr`.
    let _ = writeln!(out, "{} {{", a.subjects().join(", "));
    let _ = writeln!(out, "\ttls {{");
    let _ = writeln!(out, "\t\tdns {} {}", a.provider, a.api_token);
    if let Some(url) = a.ca_url() {
        let _ = writeln!(out, "\t\tca {url}");
    }
    let _ = writeln!(out, "\t}}");
    // Ce bloc n'existe que pour obtenir le certificat : il ne sert rien.
    let _ = writeln!(out, "\trespond \"Homelabus\" 200");
    let _ = writeln!(out, "}}\n");
}

/// Le bloc forward-auth d'une route.
///
/// L'ordre des directives à l'intérieur porte deux décisions de sécurité :
///
/// 1. **Le nettoyage des en-têtes en PREMIER.** Sans lui, un client qui envoie
///    `X-Auth-Request-User: admin` voit son en-tête transmis tel quel à l'app, qui lui
///    fait confiance. C'est l'authentification contournée en une seule requête `curl`.
/// 2. **Les chemins du portail exclus du portail.** `/oauth2/*` doit atteindre
///    oauth2-proxy directement : le faire passer par `forward_auth` créerait une
///    boucle — pour s'authentifier il faudrait déjà être authentifié.
fn rendre_forward_auth(out: &mut String, fa: &ForwardAuth) {
    let _ = writeln!(out, "\n\t# §5.0 — portail d'authentification.");
    let _ = writeln!(
        out,
        "\t# 🔴 Les en-têtes d'identité ne peuvent venir QUE du portail : sans cette"
    );
    let _ = writeln!(
        out,
        "\t# ligne, « curl -H \"X-Auth-Request-User: admin\" » suffit à usurper un compte."
    );
    for h in AUTH_HEADERS {
        let _ = writeln!(out, "\trequest_header -{h}");
    }

    // Le portail doit être joignable sans passer par lui-même.
    let _ = writeln!(out, "\n\t# Le portail lui-même, sinon la connexion boucle.");
    let _ = writeln!(out, "\thandle /oauth2/* {{");
    let _ = writeln!(out, "\t\treverse_proxy {}", fa.upstream);
    let _ = writeln!(out, "\t}}");

    let _ = writeln!(out, "\n\tforward_auth {} {{", fa.upstream);
    let _ = writeln!(out, "\t\turi {}", fa.verify_path);
    // ⚠️ Sans `--set-xauthrequest` côté oauth2-proxy, ces en-têtes n'existent pas et
    // l'app voit un utilisateur anonyme — sans erreur nulle part.
    let _ = writeln!(out, "\t\tcopy_headers {}", AUTH_HEADERS.join(" "));

    // 🔴 `status` est un matcher de RÉPONSE : il n'existe qu'à l'intérieur du bloc
    // forward_auth. Écrit au niveau du site, Caddy refuse de démarrer sur
    // « module not registered: http.matchers.status » — un message qui ne dit pas
    // que c'est une question de portée.
    //
    // Sans cette redirection, un utilisateur non connecté reçoit un 401 brut et n'a
    // jamais vu de page de connexion : de son point de vue, le SSO est cassé.
    let _ = writeln!(out, "\n\t\t@non-authentifie status 401");
    let _ = writeln!(out, "\t\thandle_response @non-authentifie {{");
    let _ = writeln!(
        out,
        "\t\t\tredir * {}?rd={{scheme}}://{{host}}{{uri}}",
        fa.sign_in_path
    );
    let _ = writeln!(out, "\t\t}}");
    let _ = writeln!(out, "\t}}");
}

/// Le Caddyfile arrière : aiguillage vers les services de l'overlay.
pub fn render_backend(routes: &[Route], cfg: &Config) -> String {
    let mut routes = routes.to_vec();
    routes.sort();

    let mut out = String::new();
    let _ = writeln!(out, "# Généré par Homelabus — ne pas éditer à la main.\n");
    let _ = writeln!(out, "{{");
    let _ = writeln!(out, "\tadmin 0.0.0.0:2019");
    // Le TLS est déjà terminé par le frontal : on écoute en clair sur l'overlay,
    // lui-même chiffré par IPsec (§6.3).
    let _ = writeln!(out, "\tauto_https off");
    let _ = writeln!(out, "}}\n");

    let listen = cfg.backend_upstream.rsplit(':').next().unwrap_or("8080");

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
            needs_forward_auth: false,
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
            needs_forward_auth: false,
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
        assert!(
            !gitea_block.contains("anubis"),
            "gitea ne doit pas passer par Anubis"
        );

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
        assert!(
            out.contains("-Server"),
            "la bannière serveur doit être retirée"
        );
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
        for out in [
            render_frontend(&[gitea()], &cfg),
            render_backend(&[gitea()], &cfg),
        ] {
            assert!(out.contains("Généré par Homelabus"));
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

    fn avec_portail() -> Config {
        Config {
            forward_auth: Some(ForwardAuth::default()),
            ..Config::default()
        }
    }

    fn protegee() -> Route {
        Route {
            needs_forward_auth: true,
            ..vikunja()
        }
    }

    #[test]
    fn incoming_identity_headers_are_stripped() {
        // 🔴 LA faille du forward-auth. Sans ce nettoyage :
        //   curl -H "X-Auth-Request-User: admin" https://app/
        // suffit à devenir administrateur, parce que l'app fait confiance à l'en-tête
        // et que le proxy l'a laissé passer tel quel.
        let out = render_frontend(&[protegee()], &avec_portail());

        for h in AUTH_HEADERS {
            assert!(
                out.contains(&format!("request_header -{h}")),
                "{h} non nettoyé :\n{out}"
            );
        }
    }

    #[test]
    fn headers_are_stripped_before_the_portal_runs() {
        // L'ordre décide de tout : nettoyer APRÈS le forward_auth effacerait aussi
        // les en-têtes légitimes posés par le portail.
        let out = render_frontend(&[protegee()], &avec_portail());
        let bloc = out
            .split("tasks.example.fr {")
            .nth(1)
            .and_then(|s| s.split("\n}").next())
            .expect("bloc");

        let i_nettoyage = bloc
            .find("request_header -X-Auth-Request-User")
            .expect("nettoyage");
        let i_portail = bloc.find("forward_auth ").expect("forward_auth");
        assert!(
            i_nettoyage < i_portail,
            "le nettoyage doit précéder le portail :\n{bloc}"
        );
    }

    #[test]
    fn the_portal_itself_bypasses_the_portal() {
        // 🔴 Sans ça, la connexion boucle : pour s'authentifier il faudrait déjà
        // l'être. L'utilisateur voit une redirection infinie.
        let out = render_frontend(&[protegee()], &avec_portail());
        assert!(out.contains("handle /oauth2/* {"), "{out}");

        let bloc = out.split("handle /oauth2/* {").nth(1).expect("bloc");
        assert!(
            bloc.trim_start()
                .starts_with("reverse_proxy oauth2-proxy:4180"),
            "{bloc}"
        );
    }

    #[test]
    fn an_unauthenticated_request_is_redirected_not_rejected() {
        // Un 401 brut donnerait « le SSO ne marche pas » du point de vue de
        // l'utilisateur, qui n'a jamais vu de page de connexion.
        let out = render_frontend(&[protegee()], &avec_portail());
        assert!(out.contains("@non-authentifie status 401"), "{out}");
        // 🔴 Le matcher `status` n'existe QUE dans le bloc forward_auth : au niveau
        // du site, Caddy refuse de démarrer. Vérifié par caddy_validates.rs.
        let apres = out.split("forward_auth ").nth(1).expect("bloc");
        assert!(
            apres.contains("@non-authentifie"),
            "doit être imbriqué :\n{apres}"
        );
        assert!(out.contains("redir * /oauth2/sign_in?rd="), "{out}");
    }

    #[test]
    fn an_app_with_native_sso_gets_no_portal() {
        // Vikunja parle OIDC : lui mettre un portail devant ajouterait une seconde
        // page de connexion, et casserait son propre flux de callback.
        let out = render_frontend(&[vikunja()], &avec_portail());
        assert!(!out.contains("forward_auth"), "{out}");
        assert!(!out.contains("request_header -X-Auth"), "{out}");
    }

    #[test]
    fn without_a_portal_configured_nothing_is_emitted() {
        // Une app qui EN A BESOIN mais sans portail configuré : on ne doit pas
        // produire une configuration à moitié faite.
        let out = render_frontend(&[protegee()], &Config::default());
        assert!(!out.contains("forward_auth"), "{out}");
    }

    #[test]
    fn the_backend_never_carries_the_portal() {
        // Même raison que CrowdSec : le portail va au premier maillon. Le dupliquer
        // au backend ferait une double authentification et casserait les callbacks.
        let out = render_backend(&[protegee()], &avec_portail());
        assert!(!out.contains("forward_auth"), "{out}");
    }

    #[test]
    fn a_route_needing_a_portal_is_derived_from_the_manifest() {
        // Le besoin vient du mode SSO déclaré, pas d'un drapeau à cocher à la main.
        let y = r#"
apiVersion: hlb/v1
kind: App
metadata: { name: vieux-truc }
spec:
  image: { repo: a/b, tag: "1" }
  requires:
    - kind: sso
      mode: proxy-only
  ingress:
    - host: vieux.example.fr
      port: 80
      expose: public
"#;
        let m: hlb_types::Manifest = serde_yaml_ng::from_str(y).expect("manifest");
        let routes = crate::routes_from_manifest(&m, None, true);
        assert!(routes[0].needs_forward_auth, "proxy-only exige un portail");
    }

    fn avec_acme(staging: bool) -> Config {
        Config {
            acme: Some(Acme {
                provider: "cloudflare".into(),
                api_token: "JETON-DE-TEST".into(),
                base_domain: "example.fr".into(),
                staging,
            }),
            ..Config::default()
        }
    }

    #[test]
    fn the_wildcard_also_covers_the_bare_domain() {
        // 🔴 `*.example.fr` ne couvre PAS `example.fr` — règle des jokers TLS. Sans
        // les deux, le wildcard marche pour tous les sous-domaines et le domaine nu
        // affiche une erreur de certificat que personne ne comprend.
        let a = Acme {
            provider: "cloudflare".into(),
            api_token: "x".into(),
            base_domain: "example.fr".into(),
            staging: false,
        };
        assert_eq!(a.subjects(), vec!["*.example.fr", "example.fr"]);

        let out = render_frontend(&[], &avec_acme(false));
        assert!(out.contains("*.example.fr, example.fr {"), "{out}");
    }

    #[test]
    fn the_certificate_is_requested_once_not_per_site() {
        // 🔴 Un bloc `tls` par site redemanderait un certificat par sous-domaine :
        // le quota Let's Encrypt saute en quelques apps, et le domaine est banni
        // une semaine — tous les services en TLS invalide d'un coup.
        let out = render_frontend(&[gitea(), vikunja()], &avec_acme(false));
        // La directive elle-même, pas sa mention en commentaire.
        let directives = out
            .lines()
            .filter(|l| l.trim_start().starts_with("dns "))
            .count();
        assert_eq!(directives, 1, "{out}");
    }

    #[test]
    fn staging_says_loudly_that_certificates_are_untrusted() {
        let out = render_frontend(&[], &avec_acme(true));
        assert!(out.contains("acme-staging-v02"), "{out}");
        assert!(
            out.contains("ne sont PAS"),
            "l'avertissement doit être visible :\n{out}"
        );
    }

    #[test]
    fn production_uses_no_explicit_ca() {
        // Laisser Caddy sur son défaut évite de figer une URL qui peut changer.
        let out = render_frontend(&[], &avec_acme(false));
        assert!(!out.contains("acme-staging"), "{out}");
        assert!(!out.contains("\t\tca "), "{out}");
    }

    #[test]
    fn the_required_caddy_module_is_announced() {
        // Le message d'erreur de Caddy sur une directive inconnue n'aide pas.
        let out = render_frontend(&[], &avec_acme(false));
        assert!(out.contains("caddy-dns/cloudflare"), "{out}");
        assert!(out.contains("xcaddy build"), "{out}");
    }

    #[test]
    fn without_acme_nothing_is_emitted() {
        let out = render_frontend(&[gitea()], &Config::default());
        assert!(!out.contains("tls {"), "{out}");
        assert!(!out.contains("dns "), "{out}");
    }

    #[test]
    fn no_routes_still_produces_a_valid_skeleton() {
        let out = render_frontend(&[], &Config::default());
        assert!(out.contains("email"));
        assert!(out.contains("admin 0.0.0.0:2019"));
    }
}
