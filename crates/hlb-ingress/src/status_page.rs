//! The site's status page: Gatus on the VPS, its configuration generated from the
//! house's routes, its alerts sent to an ntfy of the VPS's own.
//!
//! 🔴 **Nothing here goes through the house.** The status page is read when the house
//! is down, and an alert relayed by the house's own ntfy or Stalwart does not leave
//! when the house is what fell. Nor through a third party: the owner's phone
//! subscribes to the VPS's ntfy itself.
//!
//! Each app is probed THROUGH THE FRONT DOOR, as a visitor reaches it: Gatus resolves
//! the app's name to the door's address on the site's overlay, whatever the public DNS
//! says today. A second probe reads the house's Caddy straight over the site link, so
//! a red app beside a green house is the app, and everything red with it the house or
//! the link.
//!
//! A private app is refused to the VPS by design — relayed traffic is a stranger — so
//! from here it cannot be read whether it works, only that it stays CLOSED: its probe
//! expects the 403, and a 200 is a door left open to the internet.

use std::net::Ipv4Addr;

use serde::Serialize;

/// Gatus, pinned by digest.
pub const IMAGE: &str = "ghcr.io/twin/gatus:v5.38.0@sha256:085ed63da963728965d00a3c78aa6167e3bf135218485b893201758e079e8415";

/// The service on the site's own Swarm, and where it answers on the overlay.
pub const SERVICE: &str = "hlb-site-gatus";
pub const PORT: u16 = 8080;

/// The site's ntfy, which Gatus publishes to on the overlay.
pub const NTFY: &str = "hlb-site-ntfy";

/// The topic the alerts are published on, and the owner's phone subscribes to.
pub const TOPIC: &str = "homelabus";

/// The groups the page shows, in the order a reader looks for them.
pub const SERVICES: &str = "Services";
pub const CLOSED: &str = "Closed to the internet";
pub const HOUSE: &str = "The house";

/// One name the house serves, as the status page shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Probe {
    /// What the family calls it: the app's display name.
    pub title: String,
    pub host: String,
    /// Open to the internet; otherwise refused to anyone the door relays.
    pub public: bool,
}

/// What the page is made of.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page {
    pub probes: Vec<Probe>,
    /// The house's Caddy on the site link — the ingress node's address. `None` when
    /// nothing says which node runs it: no probe then, rather than one on a node
    /// where nothing listens.
    pub house: Option<Ipv4Addr>,
    /// The ntfy token Gatus publishes with.
    pub token: String,
    /// The page's own address, which an alert links to.
    pub url: String,
}

/// Gatus's configuration. `served`: the names the site serves itself — the
/// lifeboat's, once promoted — whose private apps are open on purpose then.
pub fn render(page: &Page, served: &[String]) -> String {
    let mut probes = page.probes.clone();
    probes.sort_by(|a, b| (a.title.as_str(), &a.host).cmp(&(b.title.as_str(), &b.host)));
    probes.dedup_by(|a, b| a.host == b.host);
    // Gatus keys an endpoint by its group and name: two routes of one app under one
    // title would be one endpoint, the second probe's history written over the first's.
    let titles: Vec<String> = probes.iter().map(|p| p.title.clone()).collect();
    for p in &mut probes {
        if titles.iter().filter(|t| **t == p.title).count() > 1 {
            let label = p.host.split('.').next().unwrap_or(&p.host).to_string();
            p.title = format!("{} ({label})", p.title);
        }
    }
    let mut endpoints: Vec<Endpoint> = probes
        .iter()
        .map(|p| {
            let promoted = served.iter().any(|s| s.eq_ignore_ascii_case(&p.host));
            let (group, condition, description) = if p.public || promoted {
                (
                    SERVICES,
                    // A redirect to the sign-in, a 401: the app answered. A 502 is
                    // Caddy saying the app behind it did not.
                    "[STATUS] < 500",
                    format!("{} does not answer from the internet", p.title),
                )
            } else {
                (
                    CLOSED,
                    "[STATUS] == 403",
                    format!(
                        "{} should be refused from the internet (403): it either answers \
                         nothing or answers strangers",
                        p.title
                    ),
                )
            };
            Endpoint {
                name: p.title.clone(),
                group: group.into(),
                url: format!("https://{}/", p.host),
                headers: None,
                interval: "1m".into(),
                client: Client::default(),
                conditions: vec![condition.into()],
                ui: Ui::hidden(),
                alerts: vec![Alert::ntfy(description)],
            }
        })
        .collect();
    if let Some(address) = page.house {
        endpoints.push(Endpoint {
            name: "Reached over the site link".into(),
            group: HOUSE.into(),
            url: format!("http://{address}/"),
            // The door's own health check asks for this name: no app's.
            headers: Some(Headers {
                host: "front-door.check".into(),
            }),
            interval: "1m".into(),
            client: Client::default(),
            conditions: vec!["[CONNECTED] == true".into()],
            ui: Ui::hidden(),
            alerts: vec![Alert::ntfy(
                "the house's Caddy does not answer over the site link: the house, or the \
                 link, is down"
                    .into(),
            )],
        });
    }
    let config = Config {
        storage: Storage {
            kind: "sqlite".into(),
            path: "/data/gatus.db".into(),
        },
        web: Web { port: PORT },
        ui: PageUi {
            title: "Status".into(),
            header: "Status".into(),
            description: "Whether the house's services answer, seen from outside.".into(),
        },
        alerting: Alerting {
            ntfy: Ntfy {
                url: format!("http://{NTFY}"),
                topic: TOPIC.into(),
                token: page.token.clone(),
                priority: 4,
                click: page.url.clone(),
                default_alert: DefaultAlert {
                    // One minute apart: three missed is an outage, not a hiccup.
                    failure_threshold: 3,
                    success_threshold: 2,
                    send_on_resolved: true,
                },
            },
        },
        endpoints,
    };
    let yaml = serde_yaml_ng::to_string(&config)
        // A struct of strings and numbers: nothing serde_yaml_ng refuses.
        .unwrap_or_default();
    format!("# Generated by Homelabus - do not edit by hand.\n{yaml}")
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct Config {
    storage: Storage,
    web: Web,
    ui: PageUi,
    alerting: Alerting,
    endpoints: Vec<Endpoint>,
}

#[derive(Serialize)]
struct Storage {
    #[serde(rename = "type")]
    kind: String,
    path: String,
}

#[derive(Serialize)]
struct Web {
    port: u16,
}

#[derive(Serialize)]
struct PageUi {
    title: String,
    header: String,
    description: String,
}

#[derive(Serialize)]
struct Alerting {
    ntfy: Ntfy,
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct Ntfy {
    url: String,
    topic: String,
    token: String,
    priority: u8,
    click: String,
    default_alert: DefaultAlert,
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct DefaultAlert {
    failure_threshold: u8,
    success_threshold: u8,
    send_on_resolved: bool,
}

#[derive(Serialize)]
struct Endpoint {
    name: String,
    group: String,
    url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    headers: Option<Headers>,
    interval: String,
    client: Client,
    conditions: Vec<String>,
    ui: Ui,
    alerts: Vec<Alert>,
}

#[derive(Serialize)]
struct Headers {
    #[serde(rename = "Host")]
    host: String,
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct Client {
    timeout: String,
    // The first answer is the app's: followed, a redirect to the sign-in would be
    // judged as the sign-in.
    ignore_redirect: bool,
}

impl Default for Client {
    fn default() -> Self {
        Self {
            timeout: "10s".into(),
            ignore_redirect: true,
        }
    }
}

/// The page is public: it says what answers, never where nor how it is judged — a
/// hostname, an address, an error naming an overlay.
#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct Ui {
    hide_hostname: bool,
    hide_url: bool,
    hide_port: bool,
    hide_conditions: bool,
    hide_errors: bool,
}

impl Ui {
    fn hidden() -> Self {
        Self {
            hide_hostname: true,
            hide_url: true,
            hide_port: true,
            hide_conditions: true,
            hide_errors: true,
        }
    }
}

#[derive(Serialize)]
struct Alert {
    #[serde(rename = "type")]
    kind: String,
    description: String,
}

impl Alert {
    fn ntfy(description: String) -> Self {
        Self {
            kind: "ntfy".into(),
            description,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn page() -> Page {
        Page {
            probes: vec![
                Probe {
                    title: "Vaultwarden".into(),
                    host: "vault.example.fr".into(),
                    public: false,
                },
                Probe {
                    title: "Jellyfin".into(),
                    host: "films.example.fr".into(),
                    public: true,
                },
            ],
            house: Some(Ipv4Addr::new(10, 43, 0, 2)),
            token: "tk_0123456789abcdefghijklmnopqrs".into(),
            url: "https://status.example.fr".into(),
        }
    }

    fn parsed(yaml: &str) -> serde_yaml_ng::Value {
        serde_yaml_ng::from_str(yaml).expect("YAML")
    }

    fn endpoint<'a>(v: &'a serde_yaml_ng::Value, name: &str) -> &'a serde_yaml_ng::Value {
        v["endpoints"]
            .as_sequence()
            .expect("endpoints")
            .iter()
            .find(|e| e["name"].as_str() == Some(name))
            .unwrap_or_else(|| panic!("no endpoint {name}"))
    }

    #[test]
    fn a_private_app_must_stay_refused_and_a_public_one_answer() {
        let v = parsed(&render(&page(), &[]));
        let vault = endpoint(&v, "Vaultwarden");
        assert_eq!(vault["conditions"][0].as_str(), Some("[STATUS] == 403"));
        assert_eq!(vault["group"].as_str(), Some(CLOSED));
        let films = endpoint(&v, "Jellyfin");
        assert_eq!(films["conditions"][0].as_str(), Some("[STATUS] < 500"));
        assert_eq!(films["group"].as_str(), Some(SERVICES));
        assert_eq!(films["url"].as_str(), Some("https://films.example.fr/"));
    }

    #[test]
    fn a_promoted_site_serves_its_private_apps_on_purpose() {
        let v = parsed(&render(&page(), &["VAULT.example.fr".into()]));
        let vault = endpoint(&v, "Vaultwarden");
        assert_eq!(vault["conditions"][0].as_str(), Some("[STATUS] < 500"));
    }

    #[test]
    fn the_house_is_read_over_the_link_by_the_door_s_own_check() {
        let v = parsed(&render(&page(), &[]));
        let house = endpoint(&v, "Reached over the site link");
        assert_eq!(house["url"].as_str(), Some("http://10.43.0.2/"));
        assert_eq!(house["headers"]["Host"].as_str(), Some("front-door.check"));
        let mut p = page();
        p.house = None;
        let v = parsed(&render(&p, &[]));
        assert_eq!(v["endpoints"].as_sequence().expect("endpoints").len(), 2);
    }

    #[test]
    fn the_public_page_says_what_answers_never_where() {
        let v = parsed(&render(&page(), &[]));
        for e in v["endpoints"].as_sequence().expect("endpoints") {
            for key in [
                "hide-hostname",
                "hide-url",
                "hide-port",
                "hide-conditions",
                "hide-errors",
            ] {
                assert_eq!(e["ui"][key].as_bool(), Some(true), "{key}: {e:?}");
            }
        }
    }

    #[test]
    fn alerts_leave_by_the_site_s_own_ntfy_with_its_token() {
        let v = parsed(&render(&page(), &[]));
        let n = &v["alerting"]["ntfy"];
        assert_eq!(n["url"].as_str(), Some("http://hlb-site-ntfy"));
        assert_eq!(n["topic"].as_str(), Some(TOPIC));
        assert_eq!(
            n["token"].as_str(),
            Some("tk_0123456789abcdefghijklmnopqrs")
        );
        assert_eq!(n["default-alert"]["send-on-resolved"].as_bool(), Some(true));
        for e in v["endpoints"].as_sequence().expect("endpoints") {
            assert_eq!(e["alerts"][0]["type"].as_str(), Some("ntfy"), "{e:?}");
        }
    }

    #[test]
    fn a_name_that_would_break_yaml_is_quoted() {
        let mut p = page();
        p.probes[0].title = "Vault: \"famille\" # 1".into();
        let v = parsed(&render(&p, &[]));
        endpoint(&v, "Vault: \"famille\" # 1");
    }

    #[test]
    fn two_names_of_one_app_are_two_endpoints() {
        let mut p = page();
        p.probes.push(Probe {
            title: "Jellyfin".into(),
            host: "tv.example.fr".into(),
            public: true,
        });
        let v = parsed(&render(&p, &[]));
        endpoint(&v, "Jellyfin (films)");
        endpoint(&v, "Jellyfin (tv)");
        endpoint(&v, "Vaultwarden");
    }

    #[test]
    fn one_house_renders_one_file() {
        let mut reversed = page();
        reversed.probes.reverse();
        assert_eq!(render(&page(), &[]), render(&reversed, &[]));
    }

    #[test]
    fn the_image_is_pinned_by_digest() {
        assert!(IMAGE.contains("@sha256:"));
    }
}
