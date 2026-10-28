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

/// A token substitutable in `spec.env`.
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
    /// The app's login: its address, never its name — Stalwart refuses `gitea` and
    /// takes `gitea@example.org` (0.16.26).
    SmtpUser,
    /// 🔴 Secret.
    SmtpPassword,
    /// The address the app sends as, the only one Stalwart lets it use.
    SmtpFrom,

    /// The full domain chosen at install time.
    Domain,
    /// The installation's time zone, `Europe/Paris` — `hlb config timezone`. Some apps
    /// read it once, at their first start (Seafile), so it is asked for before.
    Timezone,
    /// The installation's logo (`hlb config appearance --logo`), as an SVG carrying it:
    /// an app's own logo, written from here at every start rather than read from a volume
    /// a restore may have forged; [`NO_LOGO`] when there is none. For a `files:` entry:
    /// at up to 256 KB it does not fit a variable, which Linux caps at 128 KiB.
    BrandLogo,
}

/// Is this a zone of the tz database — `Europe/Paris`, `America/Argentina/Salta`, `UTC`,
/// `Etc/GMT+2`? Checked against the database itself: a well-formed name nobody uses
/// (`Europe/Pariss`) passed a check of the shape, and Seafile, which reads it once at its
/// first start, then failed there.
pub fn is_time_zone(z: &str) -> bool {
    z.parse::<chrono_tz::Tz>().is_ok()
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
            Self::SmtpFrom => "{{ smtp.from }}",
            Self::Domain => "{{ domain }}",
            Self::Timezone => "{{ timezone }}",
            Self::BrandLogo => "{{ brand.logo }}",
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
            Self::SmtpFrom,
            Self::Domain,
            Self::Timezone,
            Self::BrandLogo,
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
            Self::SmtpHost
            | Self::SmtpPort
            | Self::SmtpUser
            | Self::SmtpPassword
            | Self::SmtpFrom => Some("smtp"),
            // Always available: the domain comes from the install parameters.
            Self::Domain | Self::Timezone | Self::BrandLogo => None,
        }
    }
}

/// `{{ brand.logo }}` without a logo: never empty, since a file rides on a Swarm secret
/// and Swarm refuses one of no bytes. An app's start looks for `<svg`.
pub const NO_LOGO: &str = "<!-- no logo set -->\n";

/// The value of `{{ brand.logo }}`: the PNG inside an SVG sized as the PNG is, which an
/// app showing `logo.svg` takes as its own. `None` when it is not a PNG.
pub fn brand_logo_svg(png: &[u8]) -> Option<String> {
    // The IHDR chunk's width and height, right after the signature and its header.
    if png.len() < 24 || png[..8] != [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A] {
        return None;
    }
    let dim = |at: usize| u32::from_be_bytes([png[at], png[at + 1], png[at + 2], png[at + 3]]);
    let (w, h) = (dim(16), dim(20));
    Some(format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 {w} {h}\">\
         <image width=\"{w}\" height=\"{h}\" href=\"data:image/png;base64,{}\"/></svg>\n",
        crate::token::base64_standard(png)
    ))
}

/// A secret Homelabus generates for the service itself, at install time.
///
/// `{{ secret.<name> }}` is a random password; `{{ secret.<name>:hex }}` is 64 hex
/// characters (32 bytes), for software that wants exactly that — Garage's RPC secret;
/// `{{ secret.<name>:bcrypt }}` is the password's bcrypt hash, for software that is
/// given the hash and checks the password — ntfy's declared users;
/// `{{ secret.<name>:base64url }}` is 32 bytes in unpadded base64url, 43 characters —
/// Gitea's `JWT_SECRET`, which it refuses to start on otherwise; `:base64` the same 32
/// bytes in standard base64 — Fluxer's upload relay secret. Key pairs: `:vapid-private`
/// and `:vapid-public` are a P-256 pair for Web Push, unpadded base64url (the scalar,
/// then the uncompressed point), and `:rsa` an RSA-2048 key, PKCS#8 DER in standard
/// base64 — Fluxer's ActivityPub signing key.
///
/// 🔴 This is what lets a platform service start configured. PostgreSQL refuses to
/// initialise without a superuser password, MariaDB without a root one, and Grafana
/// starts on `admin`/`admin` when given none — each needed a value someone had to
/// invent, type and keep, and nothing in the catalog provided it.
///
/// Like the S3 and companion tokens these live outside [`Token`]: the name is free.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct GeneratedSecret {
    pub name: String,
    pub form: SecretForm,
}

/// How a generated secret is handed to the service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SecretForm {
    Plain,
    Hex,
    Bcrypt,
    Base64url,
    Base64,
    VapidPrivate,
    VapidPublic,
    Rsa,
}

impl SecretForm {
    /// Every form but the plain one, as a manifest writes them.
    pub const WRITTEN: [Self; 7] = [
        Self::Hex,
        Self::Bcrypt,
        Self::Base64url,
        Self::Base64,
        Self::VapidPrivate,
        Self::VapidPublic,
        Self::Rsa,
    ];

    /// A public key, handed out on purpose: Web Push gives it to every browser.
    pub fn is_public(self) -> bool {
        match self {
            Self::VapidPublic => true,
            Self::Plain
            | Self::Hex
            | Self::Bcrypt
            | Self::Base64url
            | Self::Base64
            | Self::VapidPrivate
            | Self::Rsa => false,
        }
    }

    pub fn suffix(self) -> &'static str {
        match self {
            Self::Plain => "",
            Self::Hex => ":hex",
            Self::Bcrypt => ":bcrypt",
            Self::Base64url => ":base64url",
            Self::Base64 => ":base64",
            Self::VapidPrivate => ":vapid-private",
            Self::VapidPublic => ":vapid-public",
            Self::Rsa => ":rsa",
        }
    }
}

/// The P-256 key a stored value names: its SHA-256, drawn again in the vanishing case
/// (one in 2^32) it is not a valid scalar.
fn vapid_key(stored: &str) -> Option<p256::SecretKey> {
    (0u32..16).find_map(|i| {
        let d = crate::token::sha256(format!("hlb-vapid:{i}:{stored}").as_bytes());
        p256::SecretKey::from_bytes(&d.into()).ok()
    })
}

/// The RSA-2048 key a stored value names, PKCS#8 DER. The same value, the same key —
/// for one `rsa` version: its prime search is what turns the seed into a key, so a
/// version that searched otherwise would hand the service a new key. Fluxer reads it
/// again within five minutes, and a remote server fetches the public half it serves.
fn rsa_key(stored: &str) -> Option<Vec<u8>> {
    use rand_chacha::rand_core::SeedableRng;
    use rsa::pkcs8::EncodePrivateKey;
    let seed = crate::token::sha256(format!("hlb-rsa:{stored}").as_bytes());
    let mut rng = rand_chacha::ChaCha20Rng::from_seed(seed);
    let key = rsa::RsaPrivateKey::new(&mut rng, 2048).ok()?;
    Some(key.to_pkcs8_der().ok()?.as_bytes().to_vec())
}

impl GeneratedSecret {
    /// The vault entry it is stored under: one per app, so two services declaring
    /// `admin-password` never share one.
    pub fn vault_name(&self, app: &str) -> String {
        format!("{app}-{}", self.name)
    }

    /// How it is written in a manifest.
    pub fn placeholder(&self) -> String {
        format!("{{{{ secret.{}{} }}}}", self.name, self.form.suffix())
    }

    /// The value handed to the service, from the one stored in the vault.
    ///
    /// Every form is DERIVED from the stored password rather than stored apart: the
    /// vault keeps one value per name, and the forms can never disagree.
    ///
    /// ⚠️ The bcrypt salt is derived from the password too. Drawn at random, the hash
    /// — and so the service's environment — would change at every deployment, and
    /// Swarm would restart the service each time for nothing.
    pub fn render(&self, stored: &str) -> String {
        match self.form {
            SecretForm::Plain => stored.to_string(),
            SecretForm::Hex => crate::token::sha256_hex(stored.as_bytes()),
            SecretForm::Base64url => {
                crate::token::base64url(&crate::token::sha256(stored.as_bytes()))
            }
            SecretForm::Base64 => {
                crate::token::base64_standard(&crate::token::sha256(stored.as_bytes()))
            }
            // Only a value no 16 draws make a scalar of fails, which no hash gives.
            SecretForm::VapidPrivate => vapid_key(stored)
                .map(|k| crate::token::base64url(&k.to_bytes()))
                .unwrap_or_default(),
            SecretForm::VapidPublic => vapid_key(stored)
                .map(|k| {
                    use p256::elliptic_curve::sec1::ToSec1Point;
                    crate::token::base64url(k.public_key().to_sec1_point(false).as_bytes())
                })
                .unwrap_or_default(),
            SecretForm::Rsa => rsa_key(stored)
                .map(|der| crate::token::base64_standard(&der))
                .unwrap_or_default(),
            SecretForm::Bcrypt => {
                let digest = crate::token::sha256(format!("hlb-bcrypt-salt:{stored}").as_bytes());
                let mut salt = [0u8; 16];
                salt.copy_from_slice(&digest[..16]);
                bcrypt::hash_with_salt(stored, BCRYPT_COST, salt)
                    .map(|h| h.format_for_version(bcrypt::Version::TwoB))
                    // Only a cost out of range fails, and the cost is a constant.
                    .unwrap_or_default()
            }
        }
    }
}

/// ntfy refuses a hash below 10, its own default.
const BCRYPT_COST: u32 = 10;

/// The generated secrets a value refers to. A malformed name is returned as `Err`, for
/// validation to refuse: the token would otherwise reach the service as literal text.
pub fn generated_secrets(value: &str) -> Vec<Result<GeneratedSecret, String>> {
    let mut out = Vec::new();
    let mut rest = value;
    while let Some(start) = rest.find("{{ secret.") {
        let after = &rest[start + "{{ secret.".len()..];
        let Some(end) = after.find(" }}") else {
            out.push(Err(rest[start..].to_string()));
            break;
        };
        let inner = &after[..end];
        let (name, form) = SecretForm::WRITTEN
            .into_iter()
            .find_map(|f| inner.strip_suffix(f.suffix()).map(|n| (n, f)))
            .unwrap_or((inner, SecretForm::Plain));
        if !name.is_empty()
            && name
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        {
            out.push(Ok(GeneratedSecret {
                name: name.to_string(),
                form,
            }));
        } else {
            out.push(Err(format!("{{{{ secret.{inner} }}}}")));
        }
        rest = &after[end + 3..];
    }
    out
}

/// The S3 secret key, a token outside [`Token`] as the bucket's are.
pub const S3_SECRET_KEY: &str = "{{ s3.secret_key }}";

/// Does this value hand the service something that must never be seen — a secret
/// token, a generated secret in any but its public form, or the S3 secret key?
///
/// 🔴 [`Token::is_secret`] alone misses most of them: of the catalog's secrets in an
/// environment on 2026-10-28, 41 of 62 were generated (`{{ secret.x }}`) and one an S3
/// key, both outside `Token`.
pub fn carries_secret(value: &str) -> bool {
    tokens_in(value).iter().any(Token::is_secret)
        || value.contains(S3_SECRET_KEY)
        || generated_secrets(value)
            .iter()
            .flatten()
            .any(|g| !g.form.is_public())
}

/// The tokens present in a value.
pub fn tokens_in(value: &str) -> Vec<Token> {
    Token::all()
        .iter()
        .filter(|t| value.contains(t.placeholder()))
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
pub fn substitute(value: &str, values: &BTreeMap<Token, String>) -> String {
    let mut out = value.to_string();
    for (t, v) in values {
        out = out.replace(t.placeholder(), v);
    }
    out
}

/// Masks the values of variables whose name betrays a secret.
///
/// 🔴 Used everywhere environment variables are displayed or logged. The criterion is
/// the NAME, not the value: by display time the substitution has already happened and
/// a value is just a string - too late to know where it came from.
pub fn redact(name: &str, value: &str) -> String {
    let n = name.to_ascii_uppercase();
    // `PASS` covers PASSWORD, PASSWD, PASSPHRASE and a bare `_PASS`: masking a
    // `BYPASS` costs a look at the manifest, missing a `MYSQL_PASS` costs the password.
    let sensitive = [
        "PASS",
        "SECRET",
        "TOKEN",
        "KEY",
        "CREDENTIAL",
        "PRIVATE",
        "_URL",
        "URI",
        "DSN",
    ]
    .iter()
    .any(|m| n.contains(m))
        // `MYSQL_PWD`: a segment, so a working directory's `PWD` alone is spared too.
        || (n.split('_').any(|seg| seg == "PWD") && n != "PWD");

    if sensitive && !value.is_empty() {
        "••••••".into()
    } else {
        value.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_logo_is_carried_in_an_svg_of_its_own_size() {
        let mut png = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A, 0, 0, 0, 13];
        png.extend(b"IHDR");
        png.extend(120u32.to_be_bytes());
        png.extend(40u32.to_be_bytes());
        let svg = brand_logo_svg(&png).expect("a PNG");
        assert!(svg.contains("viewBox=\"0 0 120 40\""), "{svg}");
        assert!(svg.contains("data:image/png;base64,iVBORw0KGgo"), "{svg}");
        assert_eq!(brand_logo_svg(b"<svg/>"), None);
    }

    #[test]
    fn a_time_zone_is_one_the_database_knows() {
        for ok in [
            "Europe/Paris",
            "America/Argentina/Salta",
            "UTC",
            "Etc/GMT+2",
            "America/Port-au-Prince",
        ] {
            assert!(is_time_zone(ok), "{ok}");
        }
        for bad in [
            "",
            "Paris",
            "europe/paris",
            "Europe/",
            "Europe/Paris/x/y",
            "Europe Paris",
            "../etc",
            "Europe/Pariss",
            "Mars/Olympus_Mons",
        ] {
            assert!(!is_time_zone(bad), "{bad}");
        }
    }

    #[test]
    fn generated_secrets_are_found_with_their_form() {
        let found = generated_secrets(
            "admin:{{ secret.admin-password }} rpc={{ secret.rpc:hex }} \
             user={{ secret.publisher:bcrypt }}",
        );
        let form = |name: &str, form| {
            Ok(GeneratedSecret {
                name: name.into(),
                form,
            })
        };
        assert_eq!(
            found,
            vec![
                form("admin-password", SecretForm::Plain),
                form("rpc", SecretForm::Hex),
                form("publisher", SecretForm::Bcrypt),
            ]
        );
        for f in found.into_iter().flatten() {
            assert!(generated_secrets(&f.placeholder())[0] == Ok(f.clone()));
        }
    }

    #[test]
    fn every_kind_of_secret_is_told_from_a_coordinate() {
        for secret in [
            "{{ db.password }}",
            "postgres://u:{{ db.password }}@h",
            "{{ db.url }}",
            "{{ oidc.client_secret }}",
            "{{ smtp.password }}",
            "{{ s3.secret_key }}",
            "{{ secret.x }}",
            "u:{{ secret.x:bcrypt }}",
            "{{ secret.x:vapid-private }}",
            "{{ secret.x:rsa }}",
        ] {
            assert!(carries_secret(secret), "{secret}");
        }
        for coordinate in [
            "{{ db.host }}",
            "{{ oidc.client_id }}",
            "{{ s3.access_key }}",
            "{{ secret.x:vapid-public }}",
            "{{ companion.api.host }}",
            "plain",
        ] {
            assert!(!carries_secret(coordinate), "{coordinate}");
        }
    }

    #[test]
    fn a_malformed_generated_secret_is_reported_not_skipped() {
        assert!(generated_secrets("{{ secret.Bad_Name }}")[0].is_err());
        assert!(generated_secrets("{{ secret.unclosed")[0].is_err());
        assert!(generated_secrets("{{ secret.x:md5 }}")[0].is_err());
    }

    #[test]
    fn the_hex_form_is_32_bytes_and_stable() {
        let s = GeneratedSecret {
            name: "rpc".into(),
            form: SecretForm::Hex,
        };
        let v = s.render("some-password");
        assert_eq!(v.len(), 64);
        assert!(v.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(v, s.render("some-password"));
    }

    #[test]
    fn the_base64url_form_is_32_bytes_gitea_decodes() {
        let s = GeneratedSecret {
            name: "jwt-secret".into(),
            form: SecretForm::Base64url,
        };
        let v = s.render("some-password");
        assert_eq!(v.len(), 43, "{v}");
        assert_eq!(
            crate::token::base64url_decode(&v).map(|b| b.len()),
            Some(32)
        );
        assert_eq!(v, s.render("some-password"));
        assert_eq!(
            generated_secrets("{{ secret.jwt-secret:base64url }}"),
            vec![Ok(s)]
        );
    }

    #[test]
    fn the_bcrypt_form_checks_the_password_and_does_not_move() {
        let s = GeneratedSecret {
            name: "publisher".into(),
            form: SecretForm::Bcrypt,
        };
        let h = s.render("some-password");
        assert!(h.starts_with("$2b$10$"), "{h}");
        assert!(bcrypt::verify("some-password", &h).expect("a bcrypt hash"));
        assert!(!bcrypt::verify("another", &h).expect("a bcrypt hash"));
        // The same hash at every deployment, or Swarm restarts the service each time.
        assert_eq!(h, s.render("some-password"));
        assert_ne!(h, s.render("another-password"));
    }

    fn rendered(form: SecretForm, stored: &str) -> String {
        GeneratedSecret {
            name: "k".into(),
            form,
        }
        .render(stored)
    }

    #[test]
    fn every_form_a_manifest_writes_reads_back_as_itself() {
        for f in SecretForm::WRITTEN {
            let g = GeneratedSecret {
                name: "a-key".into(),
                form: f,
            };
            assert_eq!(
                generated_secrets(&g.placeholder()),
                vec![Ok(g.clone())],
                "{f:?}"
            );
        }
    }

    #[test]
    fn the_base64_form_is_32_bytes_in_the_standard_alphabet() {
        let v = rendered(SecretForm::Base64, "some-password");
        assert_eq!(v.len(), 44, "{v}");
        assert!(v.ends_with('='), "padded: {v}");
        assert!(!v.contains('-') && !v.contains('_'), "{v}");
        let url = rendered(SecretForm::Base64url, "some-password");
        assert_eq!(
            v.trim_end_matches('='),
            url.replace('-', "+").replace('_', "/")
        );
    }

    #[test]
    fn a_vapid_pair_s_halves_belong_together_and_do_not_move() {
        use p256::elliptic_curve::sec1::ToSec1Point;
        let private = rendered(SecretForm::VapidPrivate, "some-password");
        let public = rendered(SecretForm::VapidPublic, "some-password");
        let d = crate::token::base64url_decode(&private).expect("base64url");
        let q = crate::token::base64url_decode(&public).expect("base64url");
        assert_eq!(
            (d.len(), q.len(), q[0]),
            (32, 65, 0x04),
            "Web Push's own shapes"
        );
        assert!(!private.contains('=') && !public.contains('='), "unpadded");
        // The public half is the private half's: what Fluxer signs with is what the
        // browser was given.
        let key = p256::SecretKey::from_slice(&d).expect("a scalar");
        assert_eq!(
            key.public_key().to_sec1_point(false).as_bytes(),
            q.as_slice()
        );
        assert_eq!(private, rendered(SecretForm::VapidPrivate, "some-password"));
        assert_ne!(public, rendered(SecretForm::VapidPublic, "another"));
    }

    #[test]
    fn the_rsa_form_is_a_2048_bit_pkcs8_key_that_does_not_move() {
        use rsa::pkcs8::DecodePrivateKey;
        use rsa::traits::PublicKeyParts;
        let started = std::time::Instant::now();
        let v = rendered(SecretForm::Rsa, "some-password");
        let took = started.elapsed();
        let der =
            crate::token::base64url_decode(&v.replace('+', "-").replace('/', "_")).expect("base64");
        let key = rsa::RsaPrivateKey::from_pkcs8_der(&der).expect("PKCS#8");
        assert_eq!(key.size() * 8, 2048);
        assert_eq!(
            v,
            rendered(SecretForm::Rsa, "some-password"),
            "the same key each time"
        );
        println!("an RSA key in {took:?}");
    }

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
        // 🔴 Without this link, a `{{ db.password }}` in an app with no database would
        // go out with the token's text as its value — and the diagnosis would head off
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
        // 🔴 Found by review: these passed through in clear.
        for name in [
            "SMTP_PASSWD",
            "DB_PASS",
            "MYSQL_PWD",
            "RESTIC_PASSPHRASE",
            "GOOGLE_APPLICATION_CREDENTIALS",
            "SSH_PRIVATE",
        ] {
            assert_eq!(redact(name, "x"), "••••••", "{name}");
        }

        // What is not sensitive stays readable: masking everything would make
        // diagnosis impossible and push people to bypass the display.
        assert_eq!(redact("DB_POSTGRESDB_HOST", "postgres"), "postgres");
        assert_eq!(redact("DB_TYPE", "postgresdb"), "postgresdb");
    }

    #[test]
    fn an_empty_value_is_not_masked() {
        // Masking an empty variable would suggest a secret is in place.
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
