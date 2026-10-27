//! The DNS providers a wildcard certificate can be obtained through.
//!
//! Each is a Caddy module that must be COMPILED INTO the image: a standard Caddy refuses
//! to start on `dns <provider>`. The `caddy` stage of the repository's `Dockerfile`
//! builds every provider listed here, and a test holds the two together.
//!
//! Every credential is a vault secret named `dns-<provider>-<field>`: it is written into
//! the Caddyfile at publication time, which travels as a Swarm secret — never in a
//! plan, never in the service's environment, where `docker service inspect` shows it.

/// One credential, or setting, a provider's module asks for.
#[derive(Debug)]
pub struct Field {
    /// The module's own name for it, as its Caddyfile block spells it.
    pub name: &'static str,
    /// Used when the vault holds nothing — for settings that are not secrets.
    pub default: Option<&'static str>,
}

#[derive(Debug)]
pub struct Provider {
    /// The module's name after `dns`.
    pub name: &'static str,
    /// The Go module `xcaddy` builds.
    pub module: &'static str,
    pub fields: &'static [Field],
    /// The module takes its one field as a bare argument, not in a block: Gandi's and
    /// Hetzner's have no block form at all.
    pub positional: bool,
}

const fn secret(name: &'static str) -> Field {
    Field {
        name,
        default: None,
    }
}

/// What the image carries. The syntax of each was read from the module's own README.
pub const PROVIDERS: &[Provider] = &[
    Provider {
        name: "cloudflare",
        module: "github.com/caddy-dns/cloudflare",
        // One token with Zone:Read and DNS:Edit; the split-token block is deprecated.
        fields: &[secret("api_token")],
        positional: true,
    },
    Provider {
        name: "desec",
        module: "github.com/caddy-dns/desec",
        fields: &[secret("token")],
        positional: false,
    },
    Provider {
        name: "duckdns",
        module: "github.com/caddy-dns/duckdns",
        fields: &[secret("api_token")],
        positional: false,
    },
    Provider {
        name: "gandi",
        module: "github.com/caddy-dns/gandi",
        // A personal access token: API keys are no longer accepted by Gandi.
        fields: &[secret("bearer_token")],
        positional: true,
    },
    Provider {
        name: "hetzner",
        // 🔴 v2, the Cloud API: v1 spoke to `dns.hetzner.com`, which has answered every
        // call with a redirect to the console's home since Hetzner moved DNS into its
        // Cloud (checked 2026-10-19) — a certificate could no longer be renewed. A
        // token from the former DNS console is refused by this one: make a Cloud token.
        module: "github.com/caddy-dns/hetzner/v2",
        fields: &[secret("api_token")],
        positional: true,
    },
    Provider {
        name: "ovh",
        module: "github.com/caddy-dns/ovh",
        fields: &[
            Field {
                name: "endpoint",
                default: Some("ovh-eu"),
            },
            secret("application_key"),
            secret("application_secret"),
            secret("consumer_key"),
        ],
        positional: false,
    },
    Provider {
        name: "porkbun",
        module: "github.com/caddy-dns/porkbun",
        fields: &[secret("api_key"), secret("api_secret_key")],
        positional: false,
    },
];

pub fn provider(name: &str) -> Option<&'static Provider> {
    PROVIDERS.iter().find(|p| p.name == name)
}

/// The names `hlb config exposure` lists when one is refused.
pub fn names() -> Vec<&'static str> {
    PROVIDERS.iter().map(|p| p.name).collect()
}

impl Provider {
    /// The vault secret holding a field: `dns-ovh-application-key`.
    pub fn secret_name(&self, field: &Field) -> String {
        format!("dns-{}-{}", self.name, field.name.replace('_', "-"))
    }

    /// The `dns …` line, or block, inside a `tls` block. `values` follow `fields`.
    pub fn directive(&self, values: &[String], indent: &str) -> String {
        if self.positional {
            let v = values.first().map(String::as_str).unwrap_or_default();
            return format!("{indent}dns {} {}\n", self.name, quote(v));
        }
        let mut out = format!("{indent}dns {} {{\n", self.name);
        for (f, v) in self.fields.iter().zip(values) {
            out.push_str(&format!("{indent}\t{} {}\n", f.name, quote(v)));
        }
        out.push_str(&format!("{indent}}}\n"));
        out
    }
}

/// A Caddyfile token in quotes: a credential holding a space or a quote would otherwise
/// split into two arguments, and Caddy would refuse the whole file.
fn quote(v: &str) -> String {
    format!("\"{}\"", v.replace('\\', "\\\\").replace('"', "\\\""))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_provider_offered_is_built_into_the_image_and_back() {
        // 🔴 A provider offered and not compiled in is accepted by `hlb config
        // exposure`, then refused by Caddy at the first reload — after the routes were
        // promised. And one built and not offered is a module nobody can choose.
        let dockerfile = include_str!("../../../Dockerfile");
        let built: Vec<&str> = dockerfile
            .split("--with ")
            .skip(1)
            .filter_map(|s| s.split('@').next())
            .filter(|m| m.starts_with("github.com/caddy-dns/"))
            .collect();
        assert!(built.len() >= 5, "only {built:?} read from the Dockerfile");
        for p in PROVIDERS {
            assert!(built.contains(&p.module), "{} is not built", p.module);
        }
        for m in &built {
            assert!(
                PROVIDERS.iter().any(|p| &p.module == m),
                "{m} is built and offered by no provider"
            );
        }
    }

    #[test]
    fn a_positional_module_gets_its_token_as_an_argument() {
        let p = provider("cloudflare").expect("known");
        assert_eq!(
            p.directive(&["tok".into()], "\t"),
            "\tdns cloudflare \"tok\"\n"
        );
    }

    #[test]
    fn a_block_module_gets_every_field_by_name() {
        let p = provider("ovh").expect("known");
        let out = p.directive(
            &["ovh-eu".into(), "ak".into(), "as".into(), "ck".into()],
            "",
        );
        assert!(out.starts_with("dns ovh {\n"), "{out}");
        assert!(out.contains("\tapplication_secret \"as\"\n"), "{out}");
        assert!(out.ends_with("}\n"), "{out}");
    }

    #[test]
    fn a_credential_cannot_break_out_of_its_token() {
        let p = provider("hetzner").expect("known");
        let out = p.directive(&["a\" b".into()], "");
        assert_eq!(out, "dns hetzner \"a\\\" b\"\n");
    }

    #[test]
    fn secret_names_are_kebab_case_per_provider() {
        let p = provider("porkbun").expect("known");
        assert_eq!(p.secret_name(&p.fields[1]), "dns-porkbun-api-secret-key");
    }
}
