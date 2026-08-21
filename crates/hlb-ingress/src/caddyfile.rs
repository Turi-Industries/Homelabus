//! Generating the Caddyfiles.
//!
//! The ingress chain has three links:
//!
//! ```text
//! Internet → [Caddy frontend] → [Anubis] → [Caddy backend] → services
//!                TLS, ACME       anti-bot      routing
//! ```
//!
//! Both Caddyfiles are **entirely generated** from the manifests. No configuration is
//! written by hand any more, so none is forgotten either.
//!
//! The output is deterministic: routes are sorted, which makes snapshot tests possible
//! and diffs readable.

use std::fmt::Write;

/// A route to publish, derived from a manifest's `Ingress`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Route {
    pub host: String,
    /// The Swarm service name, resolved by the overlay's internal DNS.
    pub service: String,
    pub port: u16,
    /// Goes through Anubis? Derived from `chain` in the manifest.
    pub through_anubis: bool,
    /// `false` = joignable uniquement depuis le VPN (§9).
    pub public: bool,
    /// This app's OIDC callback paths, to be excluded from Anubis.
    pub sso_paths: Vec<String>,
    /// Does the app need the portal? True for `proxy-header` and `proxy-only`, false
    /// for `native` (it speaks OIDC itself) and `none`.
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

/// Paths Anubis must **never** intercept.
///
/// A proof-of-work challenge in front of an OAuth callback breaks sign-in: the redirect
/// from the identity provider is an automatic navigation, not a user action, and some
/// agents will never solve the challenge.
pub const ANUBIS_ALWAYS_BYPASS: &[&str] = &[
    "/.well-known/*",
    "/oauth2/*",
    "/login/oauth/*",
    "/identity/connect/*",
];

/// The ranges treated as "internal" for non-public routes.
const PRIVATE_RANGES: &[&str] = &["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fd00::/8"];

/// The CrowdSec bouncer, installed on the front.
///
/// 🔴 **It only makes sense on the very first link of the chain.**
///
/// CrowdSec bans on the source IP address. The *backend* Caddy only sees the front's
/// address (or Anubis'): putting the bouncer there would ban its own front on the first
/// attacker, cutting the site for everyone. That is why `render_backend` never emits a
/// `crowdsec` directive, and why a test checks it.
#[derive(Debug, Clone)]
pub struct CrowdSec {
    /// L'API locale de CrowdSec dans l'overlay.
    pub api_url: String,
    /// The bouncer key, obtained with `cscli bouncers add`. It comes from the vault -
    /// it is never written into a manifest.
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

/// The authentication portal in front of apps without native OIDC.
///
/// 🔴 **The classic forward-auth flaw: incoming headers.**
///
/// The portal authenticates the user and then adds `X-Auth-Request-User` to the request
/// forwarded to the app, which trusts it. If the proxy lets a header of the same name
/// **sent by the client** through, then:
///
/// ```text
/// curl -H "X-Auth-Request-User: admin" https://app.example.org/
/// ```
///
/// ...is enough to become an administrator. The request is authenticated by the portal
/// (with any account, or even none), and the app reads the forged header.
///
/// Hence the `request_header -X-Auth-Request-*` placed **before** everything else:
/// identity headers can only come from the portal, never from the network.
#[derive(Debug, Clone)]
pub struct ForwardAuth {
    /// The portal's host:port on the overlay.
    pub upstream: String,
    /// Verification path. `/oauth2/auth` for oauth2-proxy.
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

/// The headers the portal sets, and that the client must NEVER be able to set.
///
/// ⚠️ `copy_headers` only has an effect when oauth2-proxy runs with
/// `--set-xauthrequest`: without that flag the headers are simply absent and the app
/// sees an anonymous user - with no error at all.
pub const AUTH_HEADERS: &[&str] = &[
    "X-Auth-Request-User",
    "X-Auth-Request-Email",
    "X-Auth-Request-Preferred-Username",
    "X-Auth-Request-Groups",
];

/// Obtaining certificates through DNS-01.
///
/// ## Why DNS-01 rather than HTTP-01
///
/// HTTP-01 requires every name to already be reachable over HTTP from the internet,
/// and therefore a DNS record **per app**, created before installation. DNS-01 allows a
/// **wildcard certificate**: one `*.example.org` created once, and any new app is
/// immediately served over TLS with no DNS action at all.
///
/// A security benefit comes with it: subdomains do not appear in Certificate
/// Transparency logs, which are public and indexed. Without a wildcard, installing
/// `accounting.example.org` announces it to the whole world.
///
/// ## 🔴 The Let's Encrypt rate-limit trap
///
/// A reconciliation loop that keeps re-requesting a certificate gets the domain banned
/// **for a week** - and every service switches to an invalid certificate at once. That
/// is why `staging` exists, and why it should be used on the first attempt. Staging
/// certificates are not trusted by browsers: that is the point, the mechanism is
/// checked without consuming quota.
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
    /// The names covered by the certificate.
    ///
    /// 🔴 **`*.example.org` does NOT cover `example.org`.** That is the TLS wildcard
    /// rule, and the mistake is classic: the wildcard is obtained, every subdomain
    /// works, and the bare domain shows a certificate error nobody understands. So both
    /// names are always requested together.
    pub fn subjects(&self) -> Vec<String> {
        vec![format!("*.{}", self.base_domain), self.base_domain.clone()]
    }

    /// The authority URL, or `None` for the default (production).
    pub fn ca_url(&self) -> Option<&'static str> {
        self.staging
            .then_some("https://acme-staging-v02.api.letsencrypt.org/directory")
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    /// The Anubis service's host:port on the overlay.
    pub anubis_upstream: String,
    /// The backend Caddy's host:port.
    pub backend_upstream: String,
    /// Adresse mail pour l'inscription ACME.
    pub acme_email: String,
    /// CrowdSec bouncer. `None` means no reputation filtering.
    pub crowdsec: Option<CrowdSec>,
    /// Portail d'authentification. `None` = pas de forward-auth.
    pub forward_auth: Option<ForwardAuth>,
    /// DNS-01 certificates. `None` means Caddy falls back to HTTP-01, which requires
    /// a DNS record per app.
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

/// The front Caddyfile: TLS, network filtering, and whether to route through Anubis.
pub fn render_frontend(routes: &[Route], cfg: &Config) -> String {
    let mut routes = routes.to_vec();
    routes.sort();

    let mut out = String::new();

    let _ = writeln!(out, "# Generated by Homelabus - do not edit by hand.");
    let _ = writeln!(
        out,
        "# Any change will be overwritten on the next reconciliation.\n"
    );
    let _ = writeln!(out, "{{");
    let _ = writeln!(out, "\temail {}", cfg.acme_email);
    let _ = writeln!(out, "\tadmin 0.0.0.0:2019");

    if let Some(cs) = &cfg.crowdsec {
        // ⚠️ `order crowdsec first` is essential: without it, Caddy applies the
        // directive after the `reverse_proxy`, that is AFTER forwarding the request to
        // the service. The bouncer would block nothing.
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
            "# ⚠️ This Caddyfile needs a Caddy image built with the module\n\
             # github.com/hslatman/caddy-crowdsec-bouncer. A standard Caddy image\n\
             # will refuse to start on the \"crowdsec\" directive.\n"
        );
    }

    for r in &routes {
        let _ = writeln!(out, "{} {{", r.host);

        // 🔴 Before everything else: an already-known attacker must consume neither
        // Anubis' proof-of-work nor a round trip to the service.
        if cfg.crowdsec.is_some() {
            let _ = writeln!(out, "\tcrowdsec");
        }

        if let Some(fa) = &cfg.forward_auth {
            if r.needs_forward_auth {
                rendre_forward_auth(&mut out, fa);
            }
        }

        // Security headers, set once, at the entry point.
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
            // Private exposure by default: only the internal network gets through.
            let _ = writeln!(out, "\n\t# Private route: reachable from the VPN only.");
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

/// The block that obtains the wildcard certificate.
///
/// It is declared **once**, for every name: each site then reuses it automatically. A
/// `tls` per site would request a certificate per subdomain, which exhausts the Let's
/// Encrypt quota within a few apps and gets the domain banned.
fn rendre_acme(out: &mut String, a: &Acme) {
    if a.staging {
        let _ = writeln!(
            out,
            "# 🔴 Let's Encrypt STAGING ENVIRONMENT: these certificates are NOT\n\
             # trusted by browsers. That is intended - the mechanism is checked\n\
             # without consuming quota. Drop --acme-staging once it works.\n"
        );
    }

    let _ = writeln!(
        out,
        "# ⚠️ Needs a Caddy image built with the \"{}\" DNS module:\n\
         #   xcaddy build --with github.com/caddy-dns/{}\n\
         # A standard Caddy image refuses to start on \"dns {}\".\n",
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

/// A route's forward-auth block.
///
/// The order of the directives inside carries two security decisions:
///
/// 1. **Header scrubbing FIRST.** Without it, a client sending
///    `X-Auth-Request-User: admin` has its header forwarded as-is to the app, which
///    trusts it. That is authentication bypassed in a single `curl`.
/// 2. **The portal's own paths excluded from the portal.** `/oauth2/*` must reach
///    oauth2-proxy directly: sending it through `forward_auth` would create a loop -
///    to authenticate you would already have to be authenticated.
fn rendre_forward_auth(out: &mut String, fa: &ForwardAuth) {
    let _ = writeln!(out, "\n\t# Authentication portal.");
    let _ = writeln!(
        out,
        "\t# 🔴 Identity headers can come ONLY from the portal: without this"
    );
    let _ = writeln!(
        out,
        "\t# line, `curl -H \"X-Auth-Request-User: admin\"` is enough to impersonate."
    );
    for h in AUTH_HEADERS {
        let _ = writeln!(out, "\trequest_header -{h}");
    }

    // The portal must be reachable without going through itself.
    let _ = writeln!(out, "\n\t# The portal itself, or sign-in loops.");
    let _ = writeln!(out, "\thandle /oauth2/* {{");
    let _ = writeln!(out, "\t\treverse_proxy {}", fa.upstream);
    let _ = writeln!(out, "\t}}");

    let _ = writeln!(out, "\n\tforward_auth {} {{", fa.upstream);
    let _ = writeln!(out, "\t\turi {}", fa.verify_path);
    // ⚠️ Without `--set-xauthrequest` on the oauth2-proxy side, these headers do not
    // exist and the app sees an anonymous user - with no error anywhere.
    let _ = writeln!(out, "\t\tcopy_headers {}", AUTH_HEADERS.join(" "));

    // 🔴 `status` is a RESPONSE matcher: it only exists inside the forward_auth block.
    // Written at site level, Caddy refuses to start on
    // "module not registered: http.matchers.status" - a message that does not say this
    // is a question of scope.
    //
    // Without this redirect, a signed-out user receives a bare 401 and has never seen a
    // sign-in page: from their point of view, the SSO is broken.
    let _ = writeln!(out, "\n\t\t@unauthenticated status 401");
    let _ = writeln!(out, "\t\thandle_response @unauthenticated {{");
    let _ = writeln!(
        out,
        "\t\t\tredir * {}?rd={{scheme}}://{{host}}{{uri}}",
        fa.sign_in_path
    );
    let _ = writeln!(out, "\t\t}}");
    let _ = writeln!(out, "\t}}");
}

/// The backend Caddyfile: routing to the overlay's services.
pub fn render_backend(routes: &[Route], cfg: &Config) -> String {
    let mut routes = routes.to_vec();
    routes.sort();

    let mut out = String::new();
    let _ = writeln!(out, "# Generated by Homelabus - do not edit by hand.\n");
    let _ = writeln!(out, "{{");
    let _ = writeln!(out, "\tadmin 0.0.0.0:2019");
    // TLS is already terminated by the front: we listen in clear on the overlay, which
    // is itself encrypted by IPsec.
    let _ = writeln!(out, "\tauto_https off");
    let _ = writeln!(out, "}}\n");

    let listen = cfg.backend_upstream.rsplit(':').next().unwrap_or("8080");

    // ⚠️ ONE block for the listen address: Caddy refuses two site definitions on the
    // same address ("ambiguous site definition"). So every host lives in this block,
    // distinguished by matchers.
    let _ = writeln!(out, ":{listen} {{");
    for r in &routes {
        let m = sanitize(&r.host);
        let _ = writeln!(out, "\t@{m} host {}", r.host);
        let _ = writeln!(out, "\treverse_proxy @{m} {}:{}", r.service, r.port);
    }
    if routes.is_empty() {
        let _ = writeln!(out, "\trespond \"no application published\" 404");
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
        assert_eq!(a, b, "input order must not change the output");
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
        // Without this, SSO sign-in breaks in a way that is very hard to diagnose.
        let out = render_frontend(&[vikunja()], &Config::default());

        assert!(out.contains("/.well-known/*"));
        assert!(out.contains("/oauth2/*"));
        // The path the app declares is added to the exclusions.
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
        assert!(out.contains("-Server"), "the server banner must be removed");
    }

    #[test]
    fn backend_routes_to_the_swarm_service() {
        let out = render_backend(&[gitea()], &Config::default());
        assert!(out.contains("host git.example.fr"));
        assert!(out.contains("reverse_proxy @git_example_fr gitea:3000"));
        // TLS is terminated at the front.
        assert!(out.contains("auto_https off"));
    }

    #[test]
    fn the_backend_declares_its_listener_only_once() {
        // Caddy refuses two site definitions on the same address.
        let out = render_backend(&[gitea(), vikunja()], &Config::default());
        assert_eq!(
            out.matches(":8080 {").count(),
            1,
            "exactly one listen block expected:\n{out}"
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
            assert!(out.contains("Generated by Homelabus"));
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

        // ⚠️ Without `order crowdsec first`, Caddy evaluates the directive AFTER the
        // reverse_proxy: the request has already gone, and the bouncer blocks nothing.
        assert!(out.contains("order crowdsec first"), "{out}");

        let bloc = out
            .split("tasks.example.fr {")
            .nth(1)
            .and_then(|s| s.split("\n}").next())
            .expect("bloc vikunja");
        let i_cs = bloc.find("crowdsec").expect("directive crowdsec");
        let i_px = bloc.find("reverse_proxy").expect("reverse_proxy");
        assert!(i_cs < i_px, "the bouncer must precede the proxy:\n{bloc}");
    }

    #[test]
    fn the_bouncer_never_lands_on_the_backend() {
        // 🔴 The central invariant: the backend only sees the front's IP. Putting the
        // bouncer there would ban the front itself on the first attacker, cutting the
        // site for EVERYONE.
        let out = render_backend(&[gitea(), vikunja()], &avec_crowdsec());
        assert!(!out.contains("crowdsec"), "{out}");
    }

    #[test]
    fn without_crowdsec_nothing_is_emitted() {
        // A standard Caddy image refuses to start on an unknown directive: nothing may
        // remain when the bouncer is not configured.
        let out = render_frontend(&[gitea()], &Config::default());
        assert!(!out.contains("crowdsec"), "{out}");
        assert!(!out.contains("order "), "{out}");
    }

    #[test]
    fn the_required_caddy_build_is_announced() {
        // Caddy's error message on an unknown directive does not help: better to say
        // it in the file itself.
        let out = render_frontend(&[gitea()], &avec_crowdsec());
        assert!(out.contains("caddy-crowdsec-bouncer"), "{out}");
    }

    #[test]
    fn crowdsec_and_anubis_coexist() {
        // The two answer different threats: known reputation on one side, anonymous
        // automation on the other. Neither replaces the other.
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
        // 🔴 THE forward-auth flaw. Without this scrubbing:
        //   curl -H "X-Auth-Request-User: admin" https://app/
        // is enough to become an administrator, because the app trusts the header and
        // the proxy let it through as-is.
        let out = render_frontend(&[protegee()], &avec_portail());

        for h in AUTH_HEADERS {
            assert!(
                out.contains(&format!("request_header -{h}")),
                "{h} not scrubbed:\n{out}"
            );
        }
    }

    #[test]
    fn headers_are_stripped_before_the_portal_runs() {
        // Order decides everything: scrubbing AFTER the forward_auth would also erase
        // the legitimate headers the portal sets.
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
            "scrubbing must precede the portal:\n{bloc}"
        );
    }

    #[test]
    fn the_portal_itself_bypasses_the_portal() {
        // 🔴 Without this, sign-in loops: to authenticate you would already have to be
        // authenticated. The user sees an infinite redirect.
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
        assert!(out.contains("@unauthenticated status 401"), "{out}");
        // 🔴 The `status` matcher exists ONLY inside the forward_auth block: at site
        // level Caddy refuses to start. Checked by caddy_validates.rs.
        let apres = out.split("forward_auth ").nth(1).expect("bloc");
        assert!(
            apres.contains("@unauthenticated"),
            "must be nested:\n{apres}"
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
        // An app that NEEDS one but has no portal configured: a half-built
        // configuration must not be produced.
        let out = render_frontend(&[protegee()], &Config::default());
        assert!(!out.contains("forward_auth"), "{out}");
    }

    #[test]
    fn the_backend_never_carries_the_portal() {
        // Same reason as CrowdSec: the portal goes on the first link. Duplicating it
        // on the backend would double-authenticate and break the callbacks.
        let out = render_backend(&[protegee()], &avec_portail());
        assert!(!out.contains("forward_auth"), "{out}");
    }

    #[test]
    fn a_route_needing_a_portal_is_derived_from_the_manifest() {
        // The need comes from the declared SSO mode, not from a flag ticked by hand.
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
        // 🔴 `*.example.org` does NOT cover `example.org` - the TLS wildcard rule.
        // Without both, the wildcard works for every subdomain and the bare domain shows
        // a certificate error nobody understands.
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
        // The directive itself, not its mention in a comment.
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
            out.contains("are NOT"),
            "the warning must be visible:\n{out}"
        );
    }

    #[test]
    fn production_uses_no_explicit_ca() {
        // Leaving Caddy on its default avoids freezing a URL that can change.
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
