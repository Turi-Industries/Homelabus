//! Generating the Caddyfile.
//!
//! One Caddy, the catalog's `caddy`, is the whole ingress:
//!
//! ```text
//! Internet → [Caddy] → services on the overlay, by name
//!            TLS, CrowdSec, the portal, private routes
//! ```
//!
//! It is **entirely generated** from the manifests — no configuration is written by
//! hand, so none is forgotten — and delivered to Caddy as a file, never through its
//! admin API: that API has no authentication, and on the overlay every app could have
//! rewritten the routes of every other one.
//!
//! The output is deterministic: routes are sorted, which makes snapshot tests possible
//! and diffs readable — and an unchanged file is an unchanged secret, so nothing restarts.

use std::fmt::Write;

use crate::dns::Provider;

/// A route to publish, derived from a manifest's `Ingress`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Route {
    pub host: String,
    /// The Swarm service name, resolved by the overlay's internal DNS.
    pub service: String,
    pub port: u16,
    /// Goes through Anubis? Derived from `chain` in the manifest.
    pub through_anubis: bool,
    /// `false` = reachable from private addresses only.
    pub public: bool,
    /// This app's OIDC callback paths, to be excluded from Anubis.
    pub sso_paths: Vec<String>,
    /// Does the app need the portal? True for `proxy-header` and `proxy-only`, false
    /// for `native` (it speaks OIDC itself) and `none`.
    pub needs_forward_auth: bool,
    /// Behind the portal, the PocketID groups let in — the roles the app allows.
    ///
    /// 🔴 Empty is NOBODY: the route answers 403 and never asks the portal. Handed to
    /// oauth2-proxy as an empty `allowed_groups`, it would have let in everyone signed
    /// in (`checkAllowedGroups`, v7.15.3).
    pub allowed_groups: Vec<String>,
    /// Paths of this host a companion of the app answers.
    pub paths: Vec<CompanionPath>,
    /// Where the app checks a secret, from its manifest.
    pub auth_routes: Vec<hlb_types::AuthRoute>,
    /// Paths anyone reaches — past the portal, the private ranges and Anubis.
    pub open_paths: Vec<String>,
}

/// A path of a route's host, and the companion answering it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct CompanionPath {
    pub prefix: String,
    /// `<service>:<port>`.
    pub upstream: String,
    /// Handed on whole, rather than with the prefix taken off.
    pub keep_prefix: bool,
}

impl CompanionPath {
    /// The prefix taken off, as most companions want it.
    pub fn stripped(prefix: impl Into<String>, upstream: impl Into<String>) -> Self {
        Self {
            prefix: prefix.into(),
            upstream: upstream.into(),
            keep_prefix: false,
        }
    }
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
            allowed_groups: Vec::new(),
            paths: Vec::new(),
            auth_routes: Vec::new(),
            open_paths: Vec::new(),
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

/// Where Caddy takes back what Anubis let through: the `anubis` manifest's `TARGET`.
pub const ANUBIS_RETURN_PORT: u16 = 8080;

/// The ranges treated as "internal" for non-public routes.
/// Paths no app of the catalog serves and every scanner asks for: answered here, never
/// by the app. A 404, not an abort: CrowdSec's probing scenarios count 404s, and an
/// aborted request leaves no status for them to read.
///
/// ⚠️ No `\.php$` at large: Roundcube is PHP, and Gitea shows `.php` files of a
/// repository under their own paths.
pub const PROBES: &[&str] = &[
    "/.env",
    "/.env.*",
    "/.git",
    "/.git/*",
    "/.svn/*",
    "/.aws/*",
    "/.ssh/*",
    "/.DS_Store",
    "/.vscode/*",
    "/.idea/*",
    "/wp-admin",
    "/wp-admin/*",
    "/wp-login.php",
    "/wp-content/*",
    "/wp-includes/*",
    "/xmlrpc.php",
    "/wordpress",
    "/wordpress/*",
    "/phpmyadmin",
    "/phpmyadmin/*",
    "/vendor/phpunit/*",
    "/cgi-bin/*",
    "/actuator/*",
    "/server-status",
    "/boaform/*",
    "/HNAP1/*",
];

/// How many secrets an address may try a minute on one app's sign-in routes.
pub const AUTH_EVENTS_PER_MINUTE: u32 = 10;

const PRIVATE_RANGES: &[&str] = &["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fd00::/8"];

/// The CrowdSec bouncer.
///
/// 🔴 **It only makes sense where the client's own address is seen.** CrowdSec bans on
/// the source IP: behind another proxy it would see that proxy, and ban it on the first
/// attacker — cutting the site for everyone. Caddy is the first link here, and its
/// ports are published in host mode precisely so the address survives.
#[derive(Debug, Clone)]
pub struct CrowdSec {
    /// CrowdSec's local API on the overlay.
    pub api_url: String,
    /// The bouncer key, obtained with `cscli bouncers add`. It comes from the vault -
    /// it is never written into a manifest.
    pub api_key: String,
}

impl Default for CrowdSec {
    fn default() -> Self {
        Self {
            api_url: crate::crowdsec::DEFAULT_URL.into(),
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
/// Hence the `request_header -X-Auth-Request-*` run **before** `forward_auth`:
/// identity headers can only come from the portal, never from the network. 🔴 Caddy
/// sorts a site's directives by its own order, not as written, and that order puts
/// `request_header` AFTER `forward_auth`: the scrubbing erased the portal's headers
/// too, and every app reading them saw nobody. The global `order request_header before
/// forward_auth` is what makes the written order the one that runs.
#[derive(Debug, Clone)]
pub struct ForwardAuth {
    /// The portal's host:port on the overlay.
    pub upstream: String,
    /// Verification path. `/oauth2/auth` for oauth2-proxy.
    pub verify_path: String,
    /// The sign-in path a 401 redirects to.
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

/// Let's Encrypt's staging directory.
pub const STAGING_CA: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";

/// Where the certificates come from.
#[derive(Debug, Clone)]
pub enum Tls {
    /// Let's Encrypt.
    Acme {
        /// The mail address for ACME registration: expiry notices go there.
        email: String,
        /// One certificate for the whole domain, over DNS-01. `None`: one certificate
        /// per name over HTTP-01, which needs port 80 reachable from the internet and
        /// a DNS record per app BEFORE it is installed.
        wildcard: Option<Wildcard>,
        /// 🔴 Let's Encrypt's staging environment: certificates no browser trusts.
        /// That is the point — the mechanism is checked without spending the quota a
        /// loop of failed attempts would exhaust, banning the domain for a week.
        staging: bool,
        /// A private ACME directory (step-ca, a home PKI) in place of Let's Encrypt.
        ca: Option<String>,
        /// Its root is written at [`ACME_ROOT`]: Caddy talks to the directory over a
        /// TLS no public authority signed.
        ca_root: bool,
    },
    /// Caddy's own authority: for an installation no public name reaches. Browsers warn
    /// until its root is trusted on the device.
    Internal {
        /// Homelabus's root, written at [`ROOT_CERT`] and [`ROOT_KEY`], rather than one
        /// Caddy generates in its volume: the controller has to verify PocketID's
        /// certificate to sign anyone in, and only a root Homelabus holds can be given
        /// to it — and to the devices, by `hlb config exposure --root`.
        own_root: bool,
    },
}

/// Where the writer job puts the files a Caddyfile names, beside it in Caddy's volume.
pub const ROOT_CERT: &str = "/config/hlb/root.crt";
pub const ROOT_KEY: &str = "/config/hlb/root.key";
pub const ACME_ROOT: &str = "/config/hlb/acme-root.crt";

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
#[derive(Debug, Clone)]
pub struct Wildcard {
    pub provider: &'static Provider,
    /// One value per `provider.fields`, from the vault.
    pub credentials: Vec<String>,
    /// The base domain, without the `*.`.
    pub base_domain: String,
}

impl Wildcard {
    /// The names covered by the certificate.
    ///
    /// 🔴 **`*.example.org` does NOT cover `example.org`.** That is the TLS wildcard
    /// rule, and the mistake is classic: the wildcard is obtained, every subdomain
    /// works, and the bare domain shows a certificate error nobody understands. So both
    /// names are always requested together.
    pub fn subjects(&self) -> Vec<String> {
        vec![format!("*.{}", self.base_domain), self.base_domain.clone()]
    }

    /// Does the certificate cover this host? Only one label deep: `*.example.org`
    /// covers `git.example.org`, never `a.git.example.org`.
    pub fn covers(&self, host: &str) -> bool {
        host == self.base_domain
            || host
                .strip_suffix(&format!(".{}", self.base_domain))
                .is_some_and(|label| !label.is_empty() && !label.contains('.'))
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    /// The Anubis service's host:port on the overlay.
    pub anubis_upstream: String,
    /// CrowdSec bouncer. `None` means no reputation filtering.
    pub crowdsec: Option<CrowdSec>,
    /// The authentication portal. `None` = no forward-auth.
    pub forward_auth: Option<ForwardAuth>,
    pub tls: Tls,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            anubis_upstream: "anubis:8923".into(),
            crowdsec: None,
            forward_auth: None,
            tls: Tls::Internal { own_root: false },
        }
    }
}

impl Config {
    /// The same configuration with every credential replaced, for a preview: the
    /// Caddyfile carries the DNS provider's token and the bouncer's key.
    pub fn redacted(&self) -> Self {
        let mut c = self.clone();
        if let Some(cs) = &mut c.crowdsec {
            cs.api_key = "<from the vault>".into();
        }
        if let Tls::Acme {
            wildcard: Some(w), ..
        } = &mut c.tls
        {
            for v in &mut w.credentials {
                *v = "<from the vault>".into();
            }
        }
        c
    }
}

/// The Caddyfile: TLS, network filtering, the portal, and every route.
pub fn render(routes: &[Route], cfg: &Config) -> String {
    let mut routes = routes.to_vec();
    // 🔴 A host is written into the file as is: one carrying a newline or a brace opens
    // a site of its own — a `file_server` over `/config`, where the DNS token and the
    // root's key live. Installs refuse such a domain; this is the last door.
    routes.retain(|r| {
        let ok = hlb_types::domain::is_host(&r.host);
        if !ok {
            tracing::error!(
                app = %r.service,
                host = %r.host.escape_debug(),
                "not a host name: its route is NOT published"
            );
        }
        ok
    });
    routes.sort();
    routes.dedup_by(|a, b| a.host == b.host);

    let mut out = String::new();

    let _ = writeln!(out, "# Generated by Homelabus - do not edit by hand.");
    let _ = writeln!(
        out,
        "# Any change is overwritten on the next publication.\n"
    );
    let _ = writeln!(out, "{{");
    match &cfg.tls {
        Tls::Acme {
            email,
            staging,
            ca,
            ca_root,
            wildcard: _,
        } => {
            let _ = writeln!(out, "\temail {email}");
            if let Some(ca) = ca {
                let _ = writeln!(out, "\tacme_ca {ca}");
            } else if *staging {
                let _ = writeln!(
                    out,
                    "\t# 🔴 Let's Encrypt STAGING: these certificates are NOT trusted by\n\
                     \t# browsers. Intended - the mechanism is checked without spending\n\
                     \t# quota. Drop --staging once it works."
                );
                let _ = writeln!(out, "\tacme_ca {STAGING_CA}");
            }
            if *ca_root {
                let _ = writeln!(out, "\tacme_ca_root {ACME_ROOT}");
            }
        }
        Tls::Internal { own_root: false } => {
            let _ = writeln!(out, "\tlocal_certs");
            let _ = writeln!(out, "\tskip_install_trust");
        }
        Tls::Internal { own_root: true } => {
            // 🔴 An authority of its own name, not Caddy's `local` given another root:
            // the certificates `local` had already issued, signed by the root Caddy
            // generated, kept being served until they renewed — and nothing trusts that
            // root. And no attempt at the container's own trust store, which is
            // read-only and logged an error at every reload.
            let _ = writeln!(out, "\tskip_install_trust");
            let _ = writeln!(out, "\tcert_issuer internal {{");
            let _ = writeln!(out, "\t\tca homelabus");
            let _ = writeln!(out, "\t}}");
            let _ = writeln!(out, "\tpki {{");
            let _ = writeln!(out, "\t\tca homelabus {{");
            let _ = writeln!(out, "\t\t\tname \"Homelabus\"");
            let _ = writeln!(out, "\t\t\troot {{");
            let _ = writeln!(out, "\t\t\t\tformat pem_file");
            let _ = writeln!(out, "\t\t\t\tcert {ROOT_CERT}");
            let _ = writeln!(out, "\t\t\t\tkey {ROOT_KEY}");
            let _ = writeln!(out, "\t\t\t}}");
            let _ = writeln!(out, "\t\t}}");
            let _ = writeln!(out, "\t}}");
        }
    }
    // Inside the container only: nothing on the overlay can reach it. It serves the
    // health probe; the routes arrive as a file.
    let _ = writeln!(out, "\tadmin localhost:2019");
    // Only TCP is published: HTTP/3 would be announced over a UDP port nobody reaches.
    let _ = writeln!(out, "\tservers {{");
    let _ = writeln!(out, "\t\tprotocols h1 h2");
    // Slowloris: a client trickling its headers holds a connection for nothing. No
    // limit on the BODY — a 1 GiB upload to Seafile is legitimately long.
    let _ = writeln!(out, "\t\ttimeouts {{");
    let _ = writeln!(out, "\t\t\tread_header 10s");
    let _ = writeln!(out, "\t\t\tidle 2m");
    let _ = writeln!(out, "\t\t}}");
    let _ = writeln!(out, "\t}}");
    if routes.iter().any(|r| !r.auth_routes.is_empty()) {
        // 🔴 Before `basic_auth`, so before `forward_auth` and `handle`: a sibling
        // installation ordered it `before reverse_proxy`, which Caddy places AFTER the
        // `handle` every site sends its traffic through — no limit of theirs ever ran,
        // and `caddy validate` said nothing.
        let _ = writeln!(out, "\torder rate_limit before basic_auth");
    }

    if cfg.forward_auth.is_some() && routes.iter().any(|r| r.needs_forward_auth) {
        // Not a `route { }` around the two: `route` runs after every `handle`, and a
        // companion's path would then be served before the portal was asked.
        let _ = writeln!(out, "\torder request_header before forward_auth");
    }

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

    let wildcard = match &cfg.tls {
        Tls::Acme {
            wildcard: Some(w), ..
        } => Some(w),
        _ => None,
    };

    // 🔴 Under a wildcard, every covered route lives INSIDE its site block, as a host
    // matcher. A route in a block of its own gets a certificate of its own — per name,
    // over HTTP-01 — whatever wildcard sits beside it: the quota goes after a handful
    // of apps, the domain is banned for a week, and the names land in public logs.
    let (covered, own): (Vec<&Route>, Vec<&Route>) = routes
        .iter()
        .partition(|r| wildcard.is_some_and(|w| w.covers(&r.host)));

    if let Some(w) = wildcard {
        let _ = writeln!(out, "{} {{", w.subjects().join(", "));
        let _ = writeln!(out, "\ttls {{");
        out.push_str(&w.provider.directive(&w.credentials, "\t\t"));
        // A site's own `tls` makes its own issuer: the global directory is said again,
        // or the wildcard would be asked of Let's Encrypt's production whatever was set.
        if let Tls::Acme {
            ca,
            staging,
            ca_root,
            ..
        } = &cfg.tls
        {
            match (ca, staging) {
                (Some(ca), _) => {
                    let _ = writeln!(out, "\t\tca {ca}");
                }
                (None, true) => {
                    let _ = writeln!(out, "\t\tca {STAGING_CA}");
                }
                (None, false) => {}
            }
            if *ca_root {
                let _ = writeln!(out, "\t\tca_root {ACME_ROOT}");
            }
        }
        let _ = writeln!(out, "\t}}");
        render_log(&mut out, cfg, "\t");
        for r in &covered {
            let m = sanitize(&r.host);
            let _ = writeln!(out, "\n\t@{m} host {}", r.host);
            let _ = writeln!(out, "\thandle @{m} {{");
            render_route(&mut out, r, cfg, "\t\t");
            let _ = writeln!(out, "\t}}");
        }
        // A name nobody installed says so, rather than an empty page or a TLS error.
        let _ = writeln!(out, "\n\thandle {{");
        let _ = writeln!(out, "\t\trespond \"no application at this address\" 404");
        let _ = writeln!(out, "\t}}");
        let _ = writeln!(out, "}}\n");
    }

    for r in own {
        let _ = writeln!(out, "{} {{", r.host);
        render_log(&mut out, cfg, "\t");
        render_route(&mut out, r, cfg, "\t");
        let _ = writeln!(out, "}}\n");
    }

    // Anubis forwards what it lets through to ONE target, keeping the Host: this
    // listener, which routes by it. Plain HTTP on the overlay — TLS, the bouncer and
    // the portal already ran on the way in.
    let through: Vec<&Route> = routes.iter().filter(|r| r.through_anubis).collect();
    if !through.is_empty() {
        let _ = writeln!(out, "# What Anubis let through, back to its application.");
        let _ = writeln!(out, "http://:{ANUBIS_RETURN_PORT} {{");
        for r in through {
            let m = sanitize(&r.host);
            let _ = writeln!(out, "\t@back_{m} host {}", r.host);
            let _ = writeln!(out, "\thandle @back_{m} {{");
            let _ = writeln!(out, "\t\treverse_proxy {}:{}", r.service, r.port);
            let _ = writeln!(out, "\t}}");
        }
        let _ = writeln!(out, "\thandle {{");
        let _ = writeln!(out, "\t\trespond \"no application at this address\" 404");
        let _ = writeln!(out, "\t}}");
        let _ = writeln!(out, "}}\n");
    }

    out
}

/// Where CrowdSec reads what happened: Caddy's `logs` volume, mounted by CrowdSec too.
pub const ACCESS_LOG: &str = "/var/log/caddy/access.log";

/// The site's access log, when the bouncer is on — the detection half of CrowdSec,
/// without which it bans nobody on what it sees here. One file for every site: Caddy
/// shares one writer per file name.
fn render_log(out: &mut String, cfg: &Config, indent: &str) {
    if cfg.crowdsec.is_none() {
        return;
    }
    let _ = writeln!(out, "{indent}log {{");
    let _ = writeln!(out, "{indent}\toutput file {ACCESS_LOG} {{");
    let _ = writeln!(out, "{indent}\t\troll_size 50MiB");
    let _ = writeln!(out, "{indent}\t\troll_keep 3");
    let _ = writeln!(out, "{indent}\t}}");
    // What CrowdSec reads stays — the client's address, the method, the path, the
    // status. What carries a secret goes: every request header (an API token, a
    // session cookie), the query string (an OIDC `code`, a reset link's token), and a
    // response's cookies. CrowdSec reads a missing header as absent, never as an error;
    // what it loses is the User-Agent and the arguments its SQL-injection and XSS
    // scenarios read.
    let _ = writeln!(out, "{indent}\tformat filter {{");
    let _ = writeln!(out, "{indent}\t\twrap json");
    let _ = writeln!(out, "{indent}\t\tfields {{");
    let _ = writeln!(out, "{indent}\t\t\trequest>headers delete");
    let _ = writeln!(out, "{indent}\t\t\trequest>uri regexp \\?.*$ \"\"");
    let _ = writeln!(out, "{indent}\t\t\tresp_headers>Set-Cookie delete");
    let _ = writeln!(out, "{indent}\t\t}}");
    let _ = writeln!(out, "{indent}\t}}");
    let _ = writeln!(out, "{indent}}}");
}

/// One route's directives, at `indent`.
///
/// Matcher names carry the host: under a wildcard every route shares one site block,
/// where two `@external` would be one name defined twice.
fn render_route(out: &mut String, r: &Route, cfg: &Config, indent: &str) {
    let m = sanitize(&r.host);
    let upstream = format!("{}:{}", r.service, r.port);

    // 🔴 Before everything else: an already-known attacker must consume neither
    // Anubis' proof-of-work nor a round trip to the service.
    if cfg.crowdsec.is_some() {
        let _ = writeln!(out, "{indent}crowdsec");
    }

    if let Some(fa) = &cfg.forward_auth {
        if r.needs_forward_auth {
            if r.allowed_groups.is_empty() {
                let _ = writeln!(
                    out,
                    "{indent}# No role is let in: nobody, not the portal's every account."
                );
                let _ = writeln!(
                    out,
                    "{indent}respond \"No role is let into {} yet.\" 403",
                    r.service
                );
                return;
            }
            render_forward_auth(out, fa, &r.allowed_groups, &r.open_paths, &m, indent);
        }
    }

    // Security headers, set once, at the entry point.
    let _ = writeln!(out, "{indent}header {{");
    let _ = writeln!(
        out,
        "{indent}\tStrict-Transport-Security \"max-age=31536000; includeSubDomains\""
    );
    let _ = writeln!(out, "{indent}\tX-Content-Type-Options nosniff");
    let _ = writeln!(
        out,
        "{indent}\tReferrer-Policy strict-origin-when-cross-origin"
    );
    let _ = writeln!(out, "{indent}\t-Server");
    let _ = writeln!(out, "{indent}}}");

    render_auth_routes(out, r, &m, indent);

    let _ = writeln!(
        out,
        "\n{indent}# Scanners' probes: no app here serves them."
    );
    let _ = writeln!(out, "{indent}@probe_{m} path {}", PROBES.join(" "));
    // A page anywhere can make its visitor's browser ask for them (`<img src>`): the
    // browser says so, and that visitor is not counted for it.
    let _ = writeln!(out, "{indent}@probe_xs_{m} {{");
    let _ = writeln!(out, "{indent}\tpath {}", PROBES.join(" "));
    let _ = writeln!(out, "{indent}\theader Sec-Fetch-Site cross-site");
    let _ = writeln!(out, "{indent}}}");
    let _ = writeln!(out, "{indent}log_skip @probe_xs_{m}");
    let _ = writeln!(out, "{indent}respond @probe_{m} 404");

    // 🔴 A write another site's page made the browser send — a form posting itself, a
    // `fetch` with no preflight. Refused before the app; and never logged, or CrowdSec,
    // which bans five POSTs answered 403 in ten seconds, would ban the visitor the page
    // was attacking. Cross-SITE only: an app may write to a sibling on its own domain.
    // A browser extension (`chrome-extension://`), an app and a server send no web
    // `Origin`, and pass.
    let _ = writeln!(out, "\n{indent}# Writes sent by another site's page.");
    let _ = writeln!(out, "{indent}@forced_{m} {{");
    let _ = writeln!(out, "{indent}\tnot method GET HEAD OPTIONS");
    let _ = writeln!(out, "{indent}\theader Sec-Fetch-Site cross-site");
    let _ = writeln!(out, "{indent}\theader_regexp Origin ^https?://");
    let _ = writeln!(out, "{indent}}}");
    let _ = writeln!(out, "{indent}log_skip @forced_{m}");
    let _ = writeln!(out, "{indent}respond @forced_{m} {FORCED_REFUSAL} 403");

    if !r.public {
        // Private exposure by default: only the internal network gets through.
        let _ = writeln!(out, "\n{indent}# Private route: private addresses only.");
        if r.open_paths.is_empty() {
            let _ = writeln!(
                out,
                "{indent}@external_{m} not remote_ip {}",
                PRIVATE_RANGES.join(" ")
            );
        } else {
            let _ = writeln!(out, "{indent}@external_{m} {{");
            let _ = writeln!(out, "{indent}\tnot remote_ip {}", PRIVATE_RANGES.join(" "));
            write_not_open(out, &r.open_paths, &format!("{indent}\t"));
            let _ = writeln!(out, "{indent}}}");
        }
        let _ = writeln!(out, "{indent}respond @external_{m} 403");
    }

    // 🔴 `handle` runs before `respond` in Caddy's directive order: the private
    // ranges' 403 above would not reach a path, so it is said again inside. Before
    // Anubis too, whose challenge a websocket cannot solve.
    for (i, p) in r.paths.iter().enumerate() {
        let (prefix, to) = (&p.prefix, &p.upstream);
        let _ = writeln!(
            out,
            "\n{indent}# {prefix}: a companion of the app answers it."
        );
        let _ = writeln!(out, "{indent}@path{i}_{m} path {prefix} {prefix}/*");
        let _ = writeln!(out, "{indent}handle @path{i}_{m} {{");
        if !p.keep_prefix {
            let _ = writeln!(out, "{indent}\turi strip_prefix {prefix}");
        }
        if !r.public {
            let _ = writeln!(out, "{indent}\trespond @external_{m} 403");
        }
        let _ = writeln!(out, "{indent}\trespond @forced_{m} {FORCED_REFUSAL} 403");
        let _ = writeln!(out, "{indent}\treverse_proxy {to}");
        let _ = writeln!(out, "{indent}}}");
    }

    if r.through_anubis {
        // Authentication paths bypass Anubis, or the OIDC flow breaks.
        let mut bypass: Vec<String> = ANUBIS_ALWAYS_BYPASS.iter().map(|s| s.to_string()).collect();
        for p in &r.sso_paths {
            let p = p.trim_end_matches('*').trim_end_matches('/');
            if !p.is_empty() {
                bypass.push(format!("{p}*"));
            }
        }
        // A service calling a webhook solves no proof-of-work.
        bypass.extend(r.open_paths.iter().cloned());
        bypass.sort();
        bypass.dedup();

        let _ = writeln!(out, "\n{indent}# Anubis would break the OIDC callbacks.");
        let _ = writeln!(out, "{indent}@auth_{m} path {}", bypass.join(" "));
        let _ = writeln!(out, "{indent}reverse_proxy @auth_{m} {upstream}");
        // Anubis binds its pass to the client's address, read from X-Real-IP: without
        // it every visitor would share the one address Caddy has on the overlay.
        let _ = writeln!(out, "\n{indent}reverse_proxy {} {{", cfg.anubis_upstream);
        let _ = writeln!(out, "{indent}\theader_up X-Real-IP {{remote_host}}");
        let _ = writeln!(out, "{indent}}}");
    } else {
        let _ = writeln!(out, "\n{indent}reverse_proxy {upstream}");
    }
}

const FORCED_REFUSAL: &str = "\"A write sent by another site is refused.\"";

/// The routes where an app checks a secret: limited per address, and marked in the
/// access log with what the app answers a wrong secret, for CrowdSec's
/// `homelabus/auth-failures` to count.
fn render_auth_routes(out: &mut String, r: &Route, m: &str, indent: &str) {
    for (i, a) in r.auth_routes.iter().enumerate() {
        let name = format!("signin{i}_{m}");
        let _ = writeln!(
            out,
            "\n{indent}# {} checks a secret here: {AUTH_EVENTS_PER_MINUTE} tries a minute an address.",
            r.service
        );
        // `path` matches the decoded, cleaned path — the one the app routes.
        let _ = writeln!(out, "{indent}@{name} path {}", a.paths.join(" "));
        let _ = writeln!(out, "{indent}rate_limit @{name} {{");
        let _ = writeln!(out, "{indent}\tzone {name} {{");
        let _ = writeln!(out, "{indent}\t\tkey {{client_ip}}");
        let _ = writeln!(out, "{indent}\t\tevents {AUTH_EVENTS_PER_MINUTE}");
        let _ = writeln!(out, "{indent}\t\twindow 1m");
        let _ = writeln!(out, "{indent}\t}}");
        let _ = writeln!(out, "{indent}}}");
        // Written by Caddy, escaped as JSON: a client cannot forge the field.
        let _ = writeln!(out, "{indent}log_append @{name} {AUTH_MARK} {}", r.service);
        if let Some(code) = a.fails_with {
            let _ = writeln!(out, "{indent}log_append @{name} {AUTH_FAILS_MARK} {code}");
        }
    }
}

/// The access-log field naming the app whose sign-in a request reached.
pub const AUTH_MARK: &str = "hlb_auth";
/// The field carrying the status that app answers a wrong secret with.
pub const AUTH_FAILS_MARK: &str = "hlb_auth_fails";

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
fn render_forward_auth(
    out: &mut String,
    fa: &ForwardAuth,
    groups: &[String],
    open: &[String],
    m: &str,
    indent: &str,
) {
    let _ = writeln!(out, "\n{indent}# Authentication portal.");
    let _ = writeln!(
        out,
        "{indent}# 🔴 Identity headers can come ONLY from the portal: without this"
    );
    let _ = writeln!(
        out,
        "{indent}# line, `curl -H \"X-Auth-Request-User: admin\"` is enough to impersonate."
    );
    for h in AUTH_HEADERS {
        let _ = writeln!(out, "{indent}request_header -{h}");
    }

    // The portal must be reachable without going through itself.
    let _ = writeln!(out, "\n{indent}# The portal itself, or sign-in loops.");
    let _ = writeln!(out, "{indent}handle /oauth2/* {{");
    let _ = writeln!(out, "{indent}\treverse_proxy {}", fa.upstream);
    let _ = writeln!(out, "{indent}}}");

    // What the manifest opens to anyone is the one place the portal is not asked.
    let gated = if open.is_empty() {
        String::new()
    } else {
        let _ = writeln!(
            out,
            "\n{indent}# Open to anyone, by the manifest: not through the portal."
        );
        let _ = writeln!(out, "{indent}@gated_{m} {{");
        write_not_open(out, open, &format!("{indent}\t"));
        let _ = writeln!(out, "{indent}}}");
        format!("@gated_{m} ")
    };
    let _ = writeln!(out, "\n{indent}forward_auth {gated}{} {{", fa.upstream);
    // The roles the app lets in, checked by oauth2-proxy at every request against the
    // groups PocketID put in the session. Names are `hlb-<role id>`: nothing to escape.
    let _ = writeln!(
        out,
        "{indent}\turi {}?allowed_groups={}",
        fa.verify_path,
        groups.join(",")
    );
    // ⚠️ Without `--set-xauthrequest` on the oauth2-proxy side, these headers do not
    // exist and the app sees an anonymous user - with no error anywhere.
    let _ = writeln!(out, "{indent}\tcopy_headers {}", AUTH_HEADERS.join(" "));

    // 🔴 `status` is a RESPONSE matcher: it only exists inside the forward_auth block.
    // Written at site level, Caddy refuses to start on
    // "module not registered: http.matchers.status" - a message that does not say this
    // is a question of scope.
    //
    // Without this redirect, a signed-out user receives a bare 401 and has never seen a
    // sign-in page: from their point of view, the SSO is broken.
    let _ = writeln!(out, "\n{indent}\t@unauthenticated_{m} status 401");
    let _ = writeln!(out, "{indent}\thandle_response @unauthenticated_{m} {{");
    let _ = writeln!(
        out,
        "{indent}\t\tredir * {}?rd={{scheme}}://{{host}}{{uri}}",
        fa.sign_in_path
    );
    let _ = writeln!(out, "{indent}\t}}");
    let _ = writeln!(out, "{indent}}}");
}

/// A raw path that means something else once cleaned: an encoded `/`, `\` or `.`, a
/// literal `\`, or a `.`/`..` segment — read on the request as sent, its query aside.
///
/// 🔴 `path` matches the decoded, CLEANED path, and the app receives the raw one:
/// `/rest/x/..%2F..%2Fwebhook/a` matched `/webhook/*` and skipped the portal, while n8n
/// routed what it was sent. A path opened to anyone is opened only as it is written.
pub const UNCLEAN_PATH: &str = r"^[^?]*(%2[fF]|%5[cC]|%2[eE]|\\|/\.\.?(/|\?|$))";

/// The matcher line set "not one of `open`, written cleanly": a request on an open
/// path whose raw form cleans into it is treated as any other.
fn write_not_open(out: &mut String, open: &[String], indent: &str) {
    let _ = writeln!(out, "{indent}not {{");
    let _ = writeln!(out, "{indent}\tpath {}", open.join(" "));
    let _ = writeln!(
        out,
        "{indent}\tnot vars_regexp {{http.request.uri}} `{UNCLEAN_PATH}`"
    );
    let _ = writeln!(out, "{indent}}}");
}

/// Caddy matcher names accept neither dots nor hyphens.
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
            allowed_groups: Vec::new(),
            paths: Vec::new(),
            auth_routes: Vec::new(),
            open_paths: Vec::new(),
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
            allowed_groups: Vec::new(),
            paths: Vec::new(),
            auth_routes: Vec::new(),
            open_paths: Vec::new(),
        }
    }

    /// The text of the block serving `host`, whether its own site or a `handle`.
    fn block<'a>(out: &'a str, host: &str) -> &'a str {
        let m = sanitize(host);
        out.split(&format!("handle @{m} {{"))
            .nth(1)
            .or_else(|| out.split(&format!("{host} {{")).nth(1))
            .and_then(|s| s.split("\n}").next())
            .expect("the host's block")
    }

    #[test]
    fn a_host_that_is_not_a_host_name_writes_nothing() {
        let mut evil = gitea();
        evil.host =
            "x.example.fr {\n\tfile_server {\n\t\troot /config\n\t}\n}\nevil.example.fr".into();
        let out = render(&[evil, vikunja()], &Config::default());
        assert!(!out.contains("file_server"), "{out}");
        assert!(!out.contains("evil.example.fr"), "{out}");
        assert!(
            out.contains("tasks.example.fr"),
            "the other routes are still published"
        );
    }

    #[test]
    fn output_is_deterministic() {
        let cfg = Config::default();
        let a = render(&[vikunja(), gitea()], &cfg);
        let b = render(&[gitea(), vikunja()], &cfg);
        assert_eq!(a, b, "input order must not change the output");
    }

    #[test]
    fn a_route_reaches_its_service_directly() {
        let out = render(&[gitea()], &Config::default());
        assert!(block(&out, "git.example.fr").contains("reverse_proxy gitea:3000"));
    }

    #[test]
    fn the_admin_api_is_never_reachable_from_the_overlay() {
        // 🔴 It has no authentication: on 0.0.0.0, any app on the overlay could load a
        // configuration routing every other app's traffic through itself.
        let out = render(&[gitea()], &Config::default());
        assert!(out.contains("\tadmin localhost:2019\n"), "{out}");
        assert!(!out.contains("0.0.0.0:2019"), "{out}");
    }

    #[test]
    fn anubis_is_only_applied_where_declared() {
        let out = render(&[gitea(), vikunja()], &Config::default());
        // Gitea has no Anubis: a proof-of-work would break `git clone`.
        assert!(!block(&out, "git.example.fr").contains("anubis"));
        assert!(block(&out, "tasks.example.fr").contains("anubis:8923"));
    }

    #[test]
    fn oidc_callbacks_bypass_anubis() {
        // Without this, SSO sign-in breaks in a way that is very hard to diagnose.
        let out = render(&[vikunja()], &Config::default());

        assert!(out.contains("/.well-known/*"));
        assert!(out.contains("/oauth2/*"));
        // The path the app declares is added to the exclusions.
        assert!(
            out.contains("/auth/openid/pocketid*"),
            "the app's redirectPath must bypass Anubis:\n{out}"
        );
        assert!(out.contains("reverse_proxy @auth_tasks_example_fr vikunja:3456"));
    }

    #[test]
    fn what_anubis_lets_through_comes_back_to_its_application() {
        let out = render(&[gitea(), vikunja()], &Config::default());
        let back = out
            .split("http://:8080 {")
            .nth(1)
            .expect("the return listener");
        assert!(
            back.contains("@back_tasks_example_fr host tasks.example.fr"),
            "{back}"
        );
        assert!(back.contains("reverse_proxy vikunja:3456"), "{back}");
        assert!(
            !back.contains("gitea"),
            "only what goes through Anubis: {back}"
        );
        assert!(out.contains("header_up X-Real-IP {remote_host}"), "{out}");
    }

    #[test]
    fn without_anubis_there_is_no_return_listener() {
        assert!(!render(&[gitea()], &Config::default()).contains(":8080"));
    }

    #[test]
    fn a_route_without_anubis_has_no_bypass_block() {
        let out = render(&[gitea()], &Config::default());
        assert!(!out.contains("@auth"), "pointless without Anubis:\n{out}");
    }

    #[test]
    fn private_routes_reject_external_traffic() {
        let mut r = gitea();
        r.public = false;
        let out = render(&[r], &Config::default());

        assert!(out.contains("@external_git_example_fr not remote_ip"));
        assert!(out.contains("respond @external_git_example_fr 403"));
        assert!(out.contains("192.168.0.0/16"));
    }

    #[test]
    fn a_path_kept_whole_reaches_its_companion_with_its_prefix() {
        let mut r = gitea();
        r.paths = vec![
            CompanionPath {
                prefix: "/.well-known/fluxer".into(),
                upstream: "fluxer-api:8080".into(),
                keep_prefix: true,
            },
            CompanionPath::stripped("/api", "fluxer-api:8080"),
        ];
        let out = render(&[r], &Config::default());
        let block = |i: usize| {
            out.split(&format!("handle @path{i}_git_example_fr {{"))
                .nth(1)
                .and_then(|b| b.split('}').next())
                .unwrap_or_else(|| panic!("no path block {i}:\n{out}"))
                .to_string()
        };
        assert!(!block(0).contains("strip_prefix"), "{}", block(0));
        assert!(block(0).contains("reverse_proxy fluxer-api:8080"));
        assert!(block(1).contains("uri strip_prefix /api"), "{}", block(1));
    }

    /// 🔴 Tried on Caddy: without the 403 inside the path's block, a client outside
    /// the private ranges reached the companion of a private route.
    #[test]
    fn a_companion_s_path_keeps_the_route_s_private_ranges() {
        let mut r = gitea();
        r.public = false;
        r.through_anubis = true;
        r.paths = vec![CompanionPath::stripped(
            "/notification",
            "gitea-notify:8083",
        )];
        let out = render(&[r], &Config::default());
        let block = out
            .split("handle @path0_git_example_fr {")
            .nth(1)
            .and_then(|b| b.split('}').next())
            .unwrap_or_else(|| panic!("no path block:\n{out}"));
        assert!(
            out.contains("@path0_git_example_fr path /notification /notification/*"),
            "{out}"
        );
        assert!(block.contains("uri strip_prefix /notification"), "{block}");
        assert!(
            block.contains("respond @external_git_example_fr 403"),
            "{block}"
        );
        assert!(block.contains("reverse_proxy gitea-notify:8083"), "{block}");
        // Before Anubis: a websocket solves no challenge.
        assert!(out.find("@path0").unwrap_or(usize::MAX) < out.find("anubis:").unwrap_or(0));
    }

    #[test]
    fn public_routes_have_no_ip_restriction() {
        let out = render(&[gitea()], &Config::default());
        assert!(!out.contains("@external"));
    }

    #[test]
    fn security_headers_are_always_present() {
        let out = render(&[gitea()], &Config::default());
        assert!(out.contains("Strict-Transport-Security"));
        assert!(out.contains("X-Content-Type-Options nosniff"));
        assert!(out.contains("-Server"), "the server banner must be removed");
    }

    fn vaultwarden_signing_in() -> Route {
        let mut r = Route::new("vault.example.fr", "vaultwarden", 80);
        r.public = true;
        r.auth_routes = vec![hlb_types::AuthRoute {
            paths: vec!["/identity/connect/token".into()],
            fails_with: Some(400),
        }];
        r
    }

    #[test]
    fn a_client_trickling_its_headers_is_cut_after_ten_seconds() {
        let out = render(&[gitea()], &Config::default());
        assert!(out.contains("read_header 10s"), "{out}");
        // Never the body: an upload is legitimately long.
        assert!(!out.contains("read_body"), "{out}");
    }

    #[test]
    fn a_sign_in_route_is_limited_and_marked_for_crowdsec() {
        let out = render(&[vaultwarden_signing_in()], &Config::default());
        let b = block(&out, "vault.example.fr");
        assert!(
            b.contains("@signin0_vault_example_fr path /identity/connect/token"),
            "{b}"
        );
        assert!(b.contains("rate_limit @signin0_vault_example_fr {"), "{b}");
        assert!(b.contains("key {client_ip}"), "{b}");
        assert!(
            b.contains(&format!("events {AUTH_EVENTS_PER_MINUTE}")),
            "{b}"
        );
        assert!(b.contains("log_append @signin0_vault_example_fr hlb_auth vaultwarden"));
        assert!(b.contains("log_append @signin0_vault_example_fr hlb_auth_fails 400"));
        // 🔴 The order that makes it run at all, said once, globally.
        assert!(
            out.contains("\torder rate_limit before basic_auth\n"),
            "{out}"
        );
    }

    #[test]
    fn an_app_answering_a_wrong_secret_with_success_is_limited_and_not_marked() {
        let mut r = vaultwarden_signing_in();
        r.auth_routes[0].fails_with = None;
        let out = render(&[r], &Config::default());
        assert!(out.contains("rate_limit @signin0"), "{out}");
        assert!(!out.contains("hlb_auth_fails"), "{out}");
    }

    #[test]
    fn an_open_path_skips_the_portal_and_the_private_ranges_and_nothing_else_does() {
        let mut r = Route::new("n8n.example.fr", "n8n", 5678);
        r.needs_forward_auth = true;
        r.allowed_groups = vec!["hlb-admin".into()];
        r.open_paths = vec!["/webhook/*".into()];
        let cfg = Config {
            forward_auth: Some(ForwardAuth::default()),
            ..Config::default()
        };
        let out = render(&[r.clone()], &cfg);
        // Read line by line, whatever the depth the block sits at.
        let lines = |b: &str| b.lines().map(str::trim).collect::<Vec<_>>().join("\n");
        let not_open = format!(
            "not {{\npath /webhook/*\nnot vars_regexp {{http.request.uri}} `{UNCLEAN_PATH}`\n}}"
        );
        let matcher = |name: &str| lines(out.split(&format!("{name} {{\n")).nth(1).expect(name));
        let gated = matcher("@gated_n8n_example_fr");
        assert!(gated.contains(&not_open), "{gated}");
        assert!(
            out.contains("forward_auth @gated_n8n_example_fr oauth2-proxy:4180 {"),
            "{out}"
        );
        let external = matcher("@external_n8n_example_fr");
        assert!(external.contains(&not_open), "{external}");
        // Without one, the portal and the 403 cover the whole host, as before.
        r.open_paths.clear();
        let closed = render(&[r], &cfg);
        assert!(!closed.contains("gated"), "{closed}");
        assert!(
            closed.contains("forward_auth oauth2-proxy:4180 {"),
            "{closed}"
        );
    }

    #[test]
    fn an_open_path_is_open_only_as_written_never_as_it_cleans() {
        // Caddy's `path` reads the decoded, cleaned path; the app the raw one.
        let unclean = regex::Regex::new(UNCLEAN_PATH).expect("RE2-compatible");
        for (uri, refused) in [
            ("/webhook/7c1e-order", false),
            ("/webhook/7c1e?next=https%3A%2F%2Fx.fr%2F..%2F", false),
            ("/webhook/.well-known", false),
            ("/rest/x/..%2F..%2Fwebhook/a", true),
            ("/rest/x/%2e%2e/webhook/a", true),
            ("/webhook/..%5Crest", true),
            ("/webhook/../rest/credentials", true),
            ("/webhook/./a", true),
            ("/webhook/a\\b", true),
            ("/webhook/..", true),
        ] {
            assert_eq!(unclean.is_match(uri), refused, "{uri}");
        }
    }

    #[test]
    fn identity_headers_are_scrubbed_before_the_portal_in_the_order_caddy_runs() {
        // Written first is not run first: Caddy sorts `request_header` after
        // `forward_auth`, and the scrubbing took the portal's headers off too.
        let out = render(&[protected()], &with_portal());
        let global = out.split("\n}\n").next().expect("global options");
        assert!(
            global
                .lines()
                .any(|l| l == "\torder request_header before forward_auth"),
            "{global}"
        );
        // Nothing reordered where no route asks the portal.
        let open = render(&[vikunja()], &with_portal());
        assert!(!open.contains("order request_header"), "{open}");
    }

    #[test]
    fn without_a_sign_in_route_no_rate_limit_is_ordered() {
        // An image without the module still reads a configuration that names none.
        let out = render(&[gitea()], &Config::default());
        assert!(!out.contains("rate_limit"), "{out}");
    }

    #[test]
    fn probes_are_answered_here_and_a_browser_made_to_ask_is_not_counted() {
        let out = render(&[gitea()], &Config::default());
        let b = block(&out, "git.example.fr");
        for p in ["/.env", "/wp-login.php", "/.git/*"] {
            assert!(b.contains(&format!(" {p}")), "{p}: {b}");
        }
        assert!(b.contains("respond @probe_git_example_fr 404"), "{b}");
        assert!(b.contains("header Sec-Fetch-Site cross-site"), "{b}");
        assert!(b.contains("log_skip @probe_xs_git_example_fr"), "{b}");
        // Roundcube is PHP: no rule on `.php` at large.
        assert!(!b.contains("path_regexp"), "{b}");
    }

    #[test]
    fn a_write_another_site_sent_is_refused_and_never_counted() {
        let mut r = gitea();
        r.paths = vec![CompanionPath::stripped(
            "/notification",
            "gitea-notification:8083",
        )];
        let out = render(&[r], &Config::default());
        let b = block(&out, "git.example.fr");
        assert!(b.contains("not method GET HEAD OPTIONS"), "{b}");
        assert!(b.contains("header_regexp Origin ^https?://"), "{b}");
        assert!(b.contains("log_skip @forced_git_example_fr"), "{b}");
        // Said at the route and again inside the companion's path, which `handle`
        // reaches before any `respond`.
        assert_eq!(
            b.matches("respond @forced_git_example_fr").count(),
            2,
            "{b}"
        );
    }

    #[test]
    fn the_access_log_keeps_no_header_and_no_query_string() {
        let out = render(&[gitea()], &with_crowdsec());
        assert!(out.contains("request>headers delete"), "{out}");
        assert!(out.contains("request>uri regexp \\?.*$ \"\""), "{out}");
        assert!(out.contains("resp_headers>Set-Cookie delete"), "{out}");
        // What CrowdSec reads stays: the client's address and the status are never
        // filtered out.
        assert!(!out.contains("client_ip delete") && !out.contains("status delete"));
    }

    #[test]
    fn matcher_names_are_valid_identifiers() {
        // Caddy refuses dots and hyphens in a matcher name.
        assert_eq!(sanitize("git.example.fr"), "git_example_fr");
        assert_eq!(sanitize("mon-app.example.fr"), "mon_app_example_fr");
    }

    #[test]
    fn generated_files_warn_against_hand_editing() {
        assert!(render(&[gitea()], &Config::default()).contains("Generated by Homelabus"));
    }

    #[test]
    fn a_host_is_routed_once() {
        // Two site blocks for one name: Caddy refuses the whole file.
        let out = render(&[gitea(), gitea()], &Config::default());
        assert_eq!(out.matches("git.example.fr {").count(), 1, "{out}");
    }

    fn with_crowdsec() -> Config {
        Config {
            crowdsec: Some(CrowdSec {
                api_url: "http://crowdsec:8080".into(),
                api_key: "BOUNCER-KEY".into(),
            }),
            ..Config::default()
        }
    }

    #[test]
    fn the_crowdsec_bouncer_runs_before_everything_else() {
        let out = render(&[vikunja()], &with_crowdsec());

        // ⚠️ Without `order crowdsec first`, Caddy evaluates the directive AFTER the
        // reverse_proxy: the request has already gone, and the bouncer blocks nothing.
        assert!(out.contains("order crowdsec first"), "{out}");

        let b = block(&out, "tasks.example.fr");
        let i_cs = b.find("crowdsec").expect("directive crowdsec");
        let i_px = b.find("reverse_proxy").expect("reverse_proxy");
        assert!(i_cs < i_px, "the bouncer must precede the proxy:\n{b}");
    }

    #[test]
    fn with_the_bouncer_every_site_logs_where_crowdsec_reads() {
        let mut cfg = with_crowdsec();
        let mut other = gitea();
        other.host = "photos.other.org".into();
        let out = render(&[gitea(), other], &cfg);
        assert_eq!(
            out.matches("output file /var/log/caddy/access.log").count(),
            2,
            "{out}"
        );
        cfg.tls = with_acme(false).tls;
        let out = render(&[gitea()], &cfg);
        assert_eq!(
            out.matches("output file /var/log/caddy/access.log").count(),
            1,
            "{out}"
        );
    }

    #[test]
    fn without_crowdsec_nothing_is_emitted() {
        // A Caddy without the module refuses to start on an unknown directive: nothing
        // may remain when the bouncer is not configured.
        let out = render(&[gitea()], &Config::default());
        assert!(!out.contains("crowdsec"), "{out}");
        assert!(!out.contains("order "), "{out}");
        assert!(!out.contains("log {"), "nothing reads it: {out}");
    }

    #[test]
    fn crowdsec_and_anubis_coexist() {
        // The two answer different threats: known reputation on one side, anonymous
        // automation on the other. Neither replaces the other.
        let out = render(&[vikunja()], &with_crowdsec());
        assert!(out.contains("crowdsec"));
        assert!(out.contains("anubis:8923"));
        // And OIDC callbacks always bypass Anubis.
        assert!(out.contains("/auth/openid/pocketid*"), "{out}");
    }

    fn with_portal() -> Config {
        Config {
            forward_auth: Some(ForwardAuth::default()),
            ..Config::default()
        }
    }

    fn protected() -> Route {
        Route {
            needs_forward_auth: true,
            allowed_groups: vec!["hlb-family".into()],
            paths: Vec::new(),
            ..vikunja()
        }
    }

    #[test]
    fn incoming_identity_headers_are_stripped() {
        // 🔴 THE forward-auth flaw. Without this scrubbing:
        //   curl -H "X-Auth-Request-User: admin" https://app/
        // is enough to become an administrator, because the app trusts the header and
        // the proxy let it through as-is.
        let out = render(&[protected()], &with_portal());

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
        let out = render(&[protected()], &with_portal());
        let b = block(&out, "tasks.example.fr");

        let i_cleanup = b
            .find("request_header -X-Auth-Request-User")
            .expect("scrubbing");
        let i_portal = b.find("forward_auth ").expect("forward_auth");
        assert!(
            i_cleanup < i_portal,
            "scrubbing must precede the portal:\n{b}"
        );
    }

    #[test]
    fn the_portal_itself_bypasses_the_portal() {
        // 🔴 Without this, sign-in loops: to authenticate you would already have to be
        // authenticated. The user sees an infinite redirect.
        let out = render(&[protected()], &with_portal());
        assert!(out.contains("handle /oauth2/* {"), "{out}");

        let b = out.split("handle /oauth2/* {").nth(1).expect("block");
        assert!(
            b.trim_start()
                .starts_with("reverse_proxy oauth2-proxy:4180"),
            "{b}"
        );
    }

    #[test]
    fn an_unauthenticated_request_is_redirected_not_rejected() {
        // A bare 401 would read as "the SSO does not work" from the point of view of
        // the user, who has never seen a sign-in page.
        let out = render(&[protected()], &with_portal());
        assert!(
            out.contains("@unauthenticated_tasks_example_fr status 401"),
            "{out}"
        );
        // 🔴 The `status` matcher exists ONLY inside the forward_auth block: at site
        // level Caddy refuses to start. Checked by caddy_validates.rs.
        let after = out.split("forward_auth ").nth(1).expect("block");
        assert!(
            after.contains("@unauthenticated"),
            "must be nested:\n{after}"
        );
        assert!(out.contains("redir * /oauth2/sign_in?rd="), "{out}");
    }

    #[test]
    fn the_portal_checks_the_roles_the_app_lets_in() {
        let out = render(&[protected()], &with_portal());
        assert!(
            out.contains("uri /oauth2/auth?allowed_groups=hlb-family\n"),
            "{out}"
        );
    }

    #[test]
    fn an_app_behind_the_portal_with_no_role_lets_nobody_in() {
        // 🔴 An empty `allowed_groups` is "everyone signed in" to oauth2-proxy: the
        // route must never ask it.
        let closed = Route {
            allowed_groups: Vec::new(),
            paths: Vec::new(),
            ..protected()
        };
        let out = render(&[closed], &with_portal());
        let b = block(&out, "tasks.example.fr");
        assert!(
            b.contains("respond \"No role is let into vikunja yet.\" 403"),
            "{b}"
        );
        assert!(!b.contains("forward_auth"), "{b}");
        assert!(
            !b.contains("reverse_proxy"),
            "nothing reaches the app:\n{b}"
        );
    }

    #[test]
    fn an_app_with_native_sso_gets_no_portal() {
        // Vikunja speaks OIDC: putting a portal in front would add a second sign-in
        // page, and would break its own callback flow.
        let out = render(&[vikunja()], &with_portal());
        assert!(!out.contains("forward_auth"), "{out}");
        assert!(!out.contains("request_header -X-Auth"), "{out}");
    }

    #[test]
    fn without_a_portal_configured_nothing_is_emitted() {
        // An app that NEEDS one but has no portal configured: a half-built
        // configuration must not be produced.
        let out = render(&[protected()], &Config::default());
        assert!(!out.contains("forward_auth"), "{out}");
    }

    #[test]
    fn a_route_needing_a_portal_is_derived_from_the_manifest() {
        // The need comes from the declared SSO mode, not from a flag ticked by hand.
        let y = r#"
apiVersion: hlb/v1
kind: App
metadata: { name: old-app }
spec:
  image: { repo: a/b, tag: "1" }
  requires:
    - kind: sso
      mode: proxy-only
  ingress:
    - host: old.example.fr
      port: 80
      expose: public
"#;
        let m: hlb_types::Manifest = serde_yaml_ng::from_str(y).expect("manifest");
        let routes = crate::routes_from_manifest(&m, None, true);
        assert!(routes[0].needs_forward_auth, "proxy-only requires a portal");
    }

    fn wildcard() -> Wildcard {
        Wildcard {
            provider: crate::dns::provider("cloudflare").expect("known"),
            credentials: vec!["TEST-TOKEN".into()],
            base_domain: "example.fr".into(),
        }
    }

    fn with_acme(staging: bool) -> Config {
        Config {
            tls: Tls::Acme {
                email: "admin@example.fr".into(),
                wildcard: Some(wildcard()),
                staging,
                ca: None,
                ca_root: false,
            },
            ..Config::default()
        }
    }

    #[test]
    fn the_wildcard_also_covers_the_bare_domain() {
        // 🔴 `*.example.org` does NOT cover `example.org` - the TLS wildcard rule.
        // Without both, the wildcard works for every subdomain and the bare domain shows
        // a certificate error nobody understands.
        assert_eq!(wildcard().subjects(), vec!["*.example.fr", "example.fr"]);

        let out = render(&[], &with_acme(false));
        assert!(out.contains("*.example.fr, example.fr {"), "{out}");
    }

    #[test]
    fn a_wildcard_covers_one_label_only() {
        let w = wildcard();
        assert!(w.covers("git.example.fr"));
        assert!(w.covers("example.fr"));
        assert!(!w.covers("a.git.example.fr"), "TLS allows one label");
        assert!(!w.covers("git.example.org"));
        assert!(!w.covers("badexample.fr"));
    }

    #[test]
    fn covered_routes_live_inside_the_wildcard_block() {
        // 🔴 A route in a site block of its own gets its own certificate, whatever
        // wildcard sits beside it: per-name issuance is what the wildcard exists to
        // avoid — the quota, and the names published in CT logs.
        let mut other = gitea();
        other.host = "photos.other.org".into();
        let out = render(&[gitea(), vikunja(), other], &with_acme(false));

        assert!(!out.contains("\ngit.example.fr {"), "{out}");
        assert!(
            out.contains("\t@git_example_fr host git.example.fr\n"),
            "{out}"
        );
        assert!(out.contains("\thandle @tasks_example_fr {"), "{out}");
        // A name outside the domain still gets its own site, and its own certificate.
        assert!(out.contains("\nphotos.other.org {"), "{out}");
    }

    #[test]
    fn the_certificate_is_requested_once_not_per_site() {
        let out = render(&[gitea(), vikunja()], &with_acme(false));
        let directives = out
            .lines()
            .filter(|l| l.trim_start().starts_with("dns "))
            .count();
        assert_eq!(directives, 1, "{out}");
    }

    #[test]
    fn staging_says_loudly_that_certificates_are_untrusted() {
        let out = render(&[], &with_acme(true));
        assert!(out.contains("acme_ca https://acme-staging-v02"), "{out}");
        assert!(
            out.contains("are NOT"),
            "the warning must be visible:\n{out}"
        );
    }

    #[test]
    fn production_uses_no_explicit_ca() {
        // Leaving Caddy on its default avoids freezing a URL that can change.
        let out = render(&[], &with_acme(false));
        assert!(!out.contains("acme_ca"), "{out}");
    }

    #[test]
    fn per_name_certificates_need_no_tls_block() {
        let cfg = Config {
            tls: Tls::Acme {
                email: "a@example.fr".into(),
                wildcard: None,
                staging: false,
                ca: None,
                ca_root: false,
            },
            ..Config::default()
        };
        let out = render(&[gitea()], &cfg);
        assert!(!out.contains("tls {"), "{out}");
        assert!(out.contains("\temail a@example.fr\n"), "{out}");
        assert!(out.contains("\ngit.example.fr {"), "{out}");
    }

    #[test]
    fn a_wildcard_under_staging_asks_staging_too() {
        // A site's `tls` block makes its own issuer: without the directory said there,
        // the wildcard would be requested from production while staging was set.
        let out = render(&[gitea()], &with_acme(true));
        let wildcard = out
            .split("*.example.fr, example.fr {")
            .nth(1)
            .expect("wildcard");
        assert!(
            wildcard.contains("\t\tca https://acme-staging-v02"),
            "{wildcard}"
        );
    }

    #[test]
    fn a_private_authority_replaces_let_s_encrypt_with_its_root() {
        let cfg = Config {
            tls: Tls::Acme {
                email: "a@example.fr".into(),
                wildcard: Some(wildcard()),
                staging: true,
                ca: Some("https://ca.home:9000/acme/acme/directory".into()),
                ca_root: true,
            },
            ..Config::default()
        };
        let out = render(&[gitea()], &cfg);
        assert!(out.contains("\tacme_ca https://ca.home:9000/"), "{out}");
        assert!(!out.contains("acme-staging"), "the private one wins: {out}");
        assert!(
            out.contains("\tacme_ca_root /config/hlb/acme-root.crt"),
            "{out}"
        );
        assert!(
            out.contains("\t\tca_root /config/hlb/acme-root.crt"),
            "{out}"
        );
    }

    #[test]
    fn homelabus_s_own_root_signs_the_internal_certificates() {
        let cfg = Config {
            tls: Tls::Internal { own_root: true },
            ..Config::default()
        };
        let out = render(&[gitea()], &cfg);
        assert!(out.contains("cert /config/hlb/root.crt"), "{out}");
        assert!(out.contains("key /config/hlb/root.key"), "{out}");
        // Under a name of its own: `local` kept serving what its own root had signed.
        assert!(
            out.contains("\tcert_issuer internal {\n\t\tca homelabus\n"),
            "{out}"
        );
        assert!(!out.contains("local_certs"), "{out}");
    }

    #[test]
    fn an_internal_authority_is_one_global_option() {
        let out = render(&[gitea()], &Config::default());
        assert!(out.contains("\tlocal_certs\n"), "{out}");
        assert!(
            !out.contains("email"),
            "no ACME account without ACME:\n{out}"
        );
    }

    #[test]
    fn a_preview_shows_no_credential() {
        let mut cfg = with_acme(false);
        cfg.crowdsec = with_crowdsec().crowdsec;
        let out = render(&[gitea()], &cfg.redacted());
        assert!(!out.contains("TEST-TOKEN"), "{out}");
        assert!(!out.contains("BOUNCER-KEY"), "{out}");
    }

    #[test]
    fn no_routes_still_produces_a_valid_skeleton() {
        let out = render(&[], &Config::default());
        assert!(out.contains("admin localhost:2019"));
    }
}
