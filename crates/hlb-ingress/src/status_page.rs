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
//!
//! Each alert carries an "Announce" button: pressed, the phone publishes the alert's
//! [`Notice::id`] to [`ACK_TOPIC`], and the site's announcer puts the notice's words
//! on the page — words written here, never the ones the button sends.

use std::collections::BTreeMap;
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

/// The topic an alert's button publishes to, and the site's announcer reads.
pub const ACK_TOPIC: &str = "homelabus-acks";

/// An alert's tag naming its notice, `hlb-<id>` — how the announcer tells which
/// announcement an alert's resolution closes.
pub const NOTICE_TAG: &str = "hlb-";

/// The tag a resolution carries.
pub const RESOLVED_TAG: &str = "resolved";

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
    /// What the house pushes its heartbeats with.
    pub push_token: String,
    /// The site's ntfy as the phone reaches it: where the button publishes.
    pub alerts_url: String,
    /// What the button publishes with — to [`ACK_TOPIC`] and nothing else.
    pub ack_token: String,
}

/// What the house says by itself, every few minutes: Gatus alerts when it stops.
///
/// 🔴 The name is the endpoint's KEY, with its group: the house pushes to
/// `/api/v1/endpoints/<key>/external`. Renamed, every push is a 404 and the
/// heartbeat goes missing — an alert for a house that is fine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Heartbeat {
    pub name: &'static str,
    /// How long without a push before it is an outage.
    pub interval_mins: u64,
    pub description: &'static str,
    /// What the page says once the owner announces it, and once it is over.
    pub kind: Kind,
    pub down: &'static str,
    pub up: &'static str,
}

/// The house's controller: pushed while it runs and reaches the site.
pub const CONTROLLER: Heartbeat = Heartbeat {
    name: "Homelabus answers",
    interval_mins: 20,
    description: "the house has said nothing for 20 minutes: the house, its internet \
                  connection or Homelabus itself is down",
    kind: Kind::Outage,
    down: "The house has stopped answering: every service may be unavailable. We know, \
           and we are on it.",
    up: "The house answers again.",
};

/// The backups: pushed failing while an app is overdue — and missing, like the
/// controller's, when the house says nothing at all. Longer, so one outage is one alert.
pub const BACKUPS: Heartbeat = Heartbeat {
    name: "Backups up to date",
    interval_mins: 120,
    description: "an app has gone too long without a successful backup, or the house has \
                  not said otherwise for two hours",
    kind: Kind::Warning,
    down: "Backups are running late. Nothing is lost, and we are on it.",
    up: "Backups are up to date again.",
};

pub const HEARTBEATS: [Heartbeat; 2] = [CONTROLLER, BACKUPS];

/// Gatus's announcement types, as far as a notice uses them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Outage,
    Warning,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Outage => "outage",
            Self::Warning => "warning",
        }
    }
}

/// What the page says of one alert, once the owner presses its button.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notice {
    /// What the button sends and the announcer looks up: `[a-z0-9-]` and nothing
    /// else, so the announcer can refuse anything else without parsing it.
    pub id: String,
    pub kind: Kind,
    pub down: String,
    pub up: String,
}

/// Gatus's key for an endpoint: its group and name, lower case, each of ` /_,.#+&`
/// a dash (`util.ConvertGroupAndEndpointNameToKey`, v5.38).
pub fn key(group: &str, name: &str) -> String {
    let clean = |s: &str| {
        s.to_lowercase()
            .chars()
            .map(|c| if " /_,.#+&".contains(c) { '-' } else { c })
            .collect::<String>()
    };
    format!("{}_{}", clean(group), clean(name))
}

/// A notice's id: the group and name, ASCII letters and digits, a dash for the rest.
fn slug(group: &str, name: &str) -> String {
    let mut out = String::new();
    for c in format!("{group} {name}").chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
        } else if !out.is_empty() && !out.ends_with('-') {
            out.push('-');
        }
    }
    out.trim_end_matches('-').to_string()
}

/// Where the house pushes `beat`, on the page's own name.
pub fn push_path(beat: &Heartbeat) -> String {
    format!("/api/v1/endpoints/{}/external", key(HOUSE, beat.name))
}

/// Whether the page would hold no endpoint Gatus probes: Gatus refuses to start on
/// heartbeats alone ("at least one endpoint", v5.38).
pub fn probes_nothing(page: &Page) -> bool {
    page.probes.is_empty() && page.house.is_none()
}

/// What one alert is about, before it is written for Gatus.
struct Watched {
    group: &'static str,
    name: String,
    description: String,
    notice: Notice,
}

/// A probe's alert, and what it reads.
struct Probed {
    w: Watched,
    url: String,
    condition: &'static str,
}

/// The probes, in the page's order, each name once: `served` are the names the site
/// serves itself — the lifeboat's, once promoted — whose private apps are open on
/// purpose then.
fn probed(page: &Page, served: &[String]) -> Vec<Probed> {
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
    probes
        .into_iter()
        .map(|p| {
            let promoted = served.iter().any(|s| s.eq_ignore_ascii_case(&p.host));
            let title = p.title;
            let (group, condition, description, kind, down, up) = if p.public || promoted {
                (
                    SERVICES,
                    // A redirect to the sign-in, a 401: the app answered. A 502 is
                    // Caddy saying the app behind it did not.
                    "[STATUS] < 500",
                    format!("{title} does not answer from the internet"),
                    Kind::Outage,
                    format!("{title} is unavailable at the moment. We know, and we are on it."),
                    format!("{title} is back."),
                )
            } else {
                (
                    CLOSED,
                    "[STATUS] == 403",
                    format!(
                        "{title} should be refused from the internet (403): it either answers \
                         nothing or answers strangers"
                    ),
                    // 🔴 Never "open to the internet" on a public page: that would tell
                    // every reader which door to try.
                    Kind::Warning,
                    format!("{title} is being looked at. We know, and we are on it."),
                    format!("{title} is back to normal."),
                )
            };
            let watched = Watched {
                group,
                name: title,
                description,
                notice: Notice {
                    id: String::new(),
                    kind,
                    down,
                    up,
                },
            };
            Probed {
                w: watched,
                url: format!("https://{}/", p.host),
                condition,
            }
        })
        .collect()
}

/// Everything the page alerts on, its notices' ids drawn unique.
fn watched(page: &Page, served: &[String]) -> (Vec<Probed>, Vec<Watched>) {
    let mut probes = probed(page, served);
    let mut house = Vec::new();
    if page.house.is_some() {
        house.push(Watched {
            group: HOUSE,
            name: "Reached over the site link".into(),
            description: "the house's Caddy does not answer over the site link: the house, \
                          or the link, is down"
                .into(),
            notice: Notice {
                id: String::new(),
                kind: Kind::Outage,
                down: "The house cannot be reached: every service may be unavailable. We \
                       know, and we are on it."
                    .into(),
                up: "The house can be reached again.".into(),
            },
        });
    }
    let mut beats: Vec<Watched> = HEARTBEATS
        .iter()
        .map(|h| Watched {
            group: HOUSE,
            name: h.name.into(),
            description: h.description.into(),
            notice: Notice {
                id: String::new(),
                kind: h.kind,
                down: h.down.into(),
                up: h.up.into(),
            },
        })
        .collect();
    let mut taken: Vec<String> = Vec::new();
    let all = probes
        .iter_mut()
        .map(|p| &mut p.w)
        .chain(house.iter_mut())
        .chain(beats.iter_mut());
    for w in all {
        let base = slug(w.group, &w.name);
        let mut id = base.clone();
        let mut n = 1;
        while taken.contains(&id) {
            n += 1;
            id = format!("{base}-{n}");
        }
        taken.push(id.clone());
        w.notice.id = id;
    }
    house.extend(beats);
    (probes, house)
}

/// Gatus's configuration. `served`: the names the site serves itself — the
/// lifeboat's, once promoted — whose private apps are open on purpose then.
pub fn render(page: &Page, served: &[String]) -> String {
    let (probes, mut house) = watched(page, served);
    let mut endpoints: Vec<Endpoint> = probes
        .iter()
        .map(|p| Endpoint {
            name: p.w.name.clone(),
            group: p.w.group.into(),
            url: p.url.clone(),
            headers: None,
            interval: "1m".into(),
            client: Client::default(),
            conditions: vec![p.condition.into()],
            ui: Ui::hidden(),
            alerts: vec![Alert::announced(&p.w, page, None)],
        })
        .collect();
    let beats = house.split_off(house.len() - HEARTBEATS.len());
    if let (Some(address), Some(w)) = (page.house, house.first()) {
        endpoints.push(Endpoint {
            name: w.name.clone(),
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
            alerts: vec![Alert::announced(w, page, None)],
        });
    }
    let mut headers = BTreeMap::new();
    headers.insert(
        "Authorization".to_string(),
        format!("Bearer {}", page.token),
    );
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
            // Gatus's own ntfy alert carries no button: its custom one sends ntfy the
            // JSON ntfy publishes, each alert filling in its own part.
            custom: Custom {
                url: format!("http://{NTFY}/"),
                method: "POST".into(),
                headers,
                body: format!("{{\"topic\":\"{TOPIC}\",{STATE}}}"),
                default_alert: DefaultAlert {
                    // One minute apart: three missed is an outage, not a hiccup.
                    failure_threshold: 3,
                    success_threshold: 2,
                    send_on_resolved: true,
                },
            },
        },
        endpoints,
        external_endpoints: HEARTBEATS
            .iter()
            .zip(&beats)
            .map(|(h, w)| External {
                name: h.name.into(),
                group: HOUSE.into(),
                token: page.push_token.clone(),
                heartbeat: Beat {
                    interval: format!("{}m", h.interval_mins),
                },
                // The interval is the grace already: missed once is an outage.
                alerts: vec![Alert::announced(w, page, Some(1))],
            })
            .collect(),
    };
    let yaml = serde_yaml_ng::to_string(&config)
        // A struct of strings and numbers: nothing serde_yaml_ng refuses.
        .unwrap_or_default();
    format!(
        "# Generated by Homelabus - do not edit by hand.\n{}",
        literal(&yaml)
    )
}

/// 🔴 Gatus expands `$NAME` in its configuration from its environment, `$$` being a
/// dollar: an app named "Budget $HOME" would be read "Budget /root".
fn literal(text: &str) -> String {
    text.replace('$', "$$")
}

/// The announcer's table: one line per notice, `id`, Gatus's type, then the two
/// messages as JSON strings — which a YAML file reads as they are, quoted and escaped.
/// Both pages' notices: the promotion swaps the page under alerts already raised.
pub fn texts(page: &Page, served: &[String]) -> String {
    let mut notices: BTreeMap<String, Notice> = BTreeMap::new();
    for s in [&[][..], served] {
        let (probes, house) = watched(page, s);
        for w in probes.into_iter().map(|p| p.w).chain(house) {
            notices.entry(w.notice.id.clone()).or_insert(w.notice);
        }
    }
    let quoted = |s: &str| literal(&serde_json::Value::String(s.into()).to_string());
    notices
        .values()
        .map(|n| {
            format!(
                "{}\t{}\t{}\t{}\n",
                n.id,
                n.kind.as_str(),
                quoted(&n.down),
                quoted(&n.up)
            )
        })
        .collect()
}

/// The placeholder each alert fills in Gatus's body: the rest of ntfy's JSON.
const STATE: &str = "[ALERT_TRIGGERED_OR_RESOLVED]";

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct Config {
    storage: Storage,
    web: Web,
    ui: PageUi,
    alerting: Alerting,
    endpoints: Vec<Endpoint>,
    external_endpoints: Vec<External>,
}

#[derive(Serialize)]
struct External {
    name: String,
    group: String,
    token: String,
    heartbeat: Beat,
    alerts: Vec<Alert>,
}

#[derive(Serialize)]
struct Beat {
    interval: String,
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
    custom: Custom,
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct Custom {
    url: String,
    method: String,
    headers: BTreeMap<String, String>,
    body: String,
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
#[serde(rename_all = "kebab-case")]
struct Alert {
    #[serde(rename = "type")]
    kind: String,
    description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    failure_threshold: Option<u8>,
    provider_override: Override,
}

#[derive(Serialize)]
struct Override {
    placeholders: Placeholders,
}

#[derive(Serialize)]
struct Placeholders {
    #[serde(rename = "ALERT_TRIGGERED_OR_RESOLVED")]
    state: State,
}

#[derive(Serialize)]
struct State {
    #[serde(rename = "TRIGGERED")]
    triggered: String,
    #[serde(rename = "RESOLVED")]
    resolved: String,
}

impl Alert {
    fn announced(w: &Watched, page: &Page, failure_threshold: Option<u8>) -> Self {
        let tag = format!("{NOTICE_TAG}{}", w.notice.id);
        let triggered = serde_json::json!({
            "title": format!("Down: {}", w.name),
            "message": format!(
                "{}.\n\nAnnounce: tell the status page's readers you are on it.",
                w.description
            ),
            "priority": 4,
            "click": page.url,
            "tags": ["rotating_light", tag],
            "actions": [{
                "action": "http",
                "label": "Announce",
                "url": format!("{}/{ACK_TOPIC}", page.alerts_url.trim_end_matches('/')),
                "method": "POST",
                "headers": { "Authorization": format!("Bearer {}", page.ack_token) },
                "body": w.notice.id,
                "clear": true,
            }],
        });
        let resolved = serde_json::json!({
            "title": format!("Back: {}", w.name),
            "message": "It answers again.",
            "priority": 3,
            "click": page.url,
            "tags": ["white_check_mark", RESOLVED_TAG, tag],
        });
        Self {
            kind: "custom".into(),
            description: w.description.clone(),
            failure_threshold,
            provider_override: Override {
                placeholders: Placeholders {
                    state: State {
                        triggered: members(&triggered),
                        resolved: members(&resolved),
                    },
                },
            },
        }
    }
}

/// An object's members without its braces: Gatus puts them after the topic.
fn members(object: &serde_json::Value) -> String {
    let s = object.to_string();
    s.strip_prefix('{')
        .and_then(|s| s.strip_suffix('}'))
        .unwrap_or_default()
        .to_string()
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
            push_token: "push-0123456789".into(),
            alerts_url: "https://alerts.example.fr".into(),
            ack_token: "tk_ack456789abcdefghijklmnopqrs".into(),
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

    /// Every alert of the page, probes and heartbeats alike.
    fn alerts(v: &serde_yaml_ng::Value) -> Vec<serde_yaml_ng::Value> {
        ["endpoints", "external-endpoints"]
            .iter()
            .flat_map(|k| v[*k].as_sequence().expect(k).clone())
            .map(|e| e["alerts"][0].clone())
            .collect()
    }

    /// What ntfy receives: Gatus's body, its placeholder filled as Gatus fills it.
    fn sent(
        v: &serde_yaml_ng::Value,
        alert: &serde_yaml_ng::Value,
        state: &str,
    ) -> serde_json::Value {
        let body = v["alerting"]["custom"]["body"].as_str().expect("body");
        let part = alert["provider-override"]["placeholders"]["ALERT_TRIGGERED_OR_RESOLVED"][state]
            .as_str()
            .expect("placeholder");
        serde_json::from_str(&body.replace(STATE, part)).expect("ntfy's JSON")
    }

    #[test]
    fn alerts_leave_by_the_site_s_own_ntfy_with_its_token() {
        let v = parsed(&render(&page(), &[]));
        let c = &v["alerting"]["custom"];
        assert_eq!(c["url"].as_str(), Some("http://hlb-site-ntfy/"));
        assert_eq!(c["method"].as_str(), Some("POST"));
        assert_eq!(
            c["headers"]["Authorization"].as_str(),
            Some("Bearer tk_0123456789abcdefghijklmnopqrs")
        );
        assert_eq!(c["default-alert"]["send-on-resolved"].as_bool(), Some(true));
        for a in alerts(&v) {
            assert_eq!(a["type"].as_str(), Some("custom"), "{a:?}");
            assert_eq!(sent(&v, &a, "TRIGGERED")["topic"], TOPIC);
            assert_eq!(sent(&v, &a, "RESOLVED")["topic"], TOPIC);
        }
    }

    #[test]
    fn an_alert_s_button_announces_its_own_notice_and_nothing_else() {
        let p = page();
        let v = parsed(&render(&p, &[]));
        let mut ids = Vec::new();
        for a in alerts(&v) {
            let m = sent(&v, &a, "TRIGGERED");
            let action = &m["actions"][0];
            assert_eq!(action["action"], "http");
            assert_eq!(action["url"], "https://alerts.example.fr/homelabus-acks");
            assert_eq!(action["method"], "POST");
            assert_eq!(
                action["headers"]["Authorization"],
                format!("Bearer {}", p.ack_token)
            );
            let id = action["body"].as_str().expect("an id").to_string();
            assert!(
                !id.is_empty()
                    && id
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'),
                "{id}"
            );
            let tag = format!("{NOTICE_TAG}{id}");
            assert!(m["tags"]
                .as_array()
                .expect("tags")
                .contains(&tag.clone().into()));
            // The resolution closes the same notice, and asks nothing more.
            let r = sent(&v, &a, "RESOLVED");
            let tags = r["tags"].as_array().expect("tags");
            assert!(tags.contains(&tag.into()) && tags.contains(&RESOLVED_TAG.into()));
            assert!(r["actions"].is_null(), "{r}");
            ids.push(id);
        }
        let mut unique = ids.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), ids.len(), "{ids:?}");
    }

    #[test]
    fn the_announcer_knows_every_notice_a_button_sends_on_either_page() {
        let p = page();
        let served = vec!["vault.example.fr".to_string()];
        let table = texts(&p, &served);
        let known: Vec<&str> = table
            .lines()
            .map(|l| l.split('\t').next().expect("id"))
            .collect();
        for page_served in [&[][..], &served[..]] {
            let v = parsed(&render(&p, page_served));
            for a in alerts(&v) {
                let id = sent(&v, &a, "TRIGGERED")["actions"][0]["body"].clone();
                assert!(
                    known.contains(&id.as_str().expect("id")),
                    "{id} not in {table}"
                );
            }
        }
        for line in table.lines() {
            let f: Vec<&str> = line.split('\t').collect();
            assert_eq!(f.len(), 4, "{line}");
            assert!(["outage", "warning"].contains(&f[1]), "{line}");
            // Each message is read as YAML by Gatus, as it stands.
            for m in &f[2..] {
                let y: serde_yaml_ng::Value = serde_yaml_ng::from_str(m).expect("YAML");
                assert!(y.as_str().is_some_and(|s| !s.is_empty()), "{m}");
            }
        }
    }

    #[test]
    fn a_closed_app_s_notice_never_says_its_door_is_open() {
        let t = texts(&page(), &[]);
        let line = t
            .lines()
            .find(|l| l.starts_with("closed-to-the-internet-vaultwarden\t"))
            .unwrap_or_else(|| panic!("{t}"));
        assert!(line.contains("\twarning\t"), "{line}");
        // The id stays between the phone and the announcer; the words are the page's.
        let words = line.split('\t').skip(2).collect::<Vec<_>>().join(" ");
        for word in ["open", "internet", "stranger", "403"] {
            assert!(!words.to_lowercase().contains(word), "{word}: {line}");
        }
    }

    #[test]
    fn a_dollar_reaches_gatus_as_a_dollar() {
        let mut p = page();
        p.probes[1].title = "Budget $HOME".into();
        let yaml = render(&p, &[]);
        assert!(yaml.contains("Budget $$HOME"), "{yaml}");
        assert!(!yaml.replace("$$", "").contains('$'), "{yaml}");
        assert!(texts(&p, &[]).contains("Budget $$HOME is back."));
    }

    #[test]
    fn two_names_that_slug_alike_are_two_notices() {
        let mut p = page();
        p.probes.push(Probe {
            title: "Jellyfin!".into(),
            host: "tv.example.fr".into(),
            public: true,
        });
        let ids: Vec<String> = texts(&p, &[])
            .lines()
            .map(|l| l.split('\t').next().expect("id").to_string())
            .collect();
        assert!(ids.contains(&"services-jellyfin".to_string()), "{ids:?}");
        assert!(ids.contains(&"services-jellyfin-2".to_string()), "{ids:?}");
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
    fn the_house_s_heartbeats_are_awaited_and_alert_at_the_first_miss() {
        let v = parsed(&render(&page(), &[]));
        let beats = v["external-endpoints"].as_sequence().expect("external");
        assert_eq!(beats.len(), HEARTBEATS.len());
        for (b, h) in beats.iter().zip(HEARTBEATS) {
            assert_eq!(b["name"].as_str(), Some(h.name));
            assert_eq!(b["group"].as_str(), Some(HOUSE));
            assert_eq!(b["token"].as_str(), Some("push-0123456789"));
            assert_eq!(
                b["heartbeat"]["interval"].as_str(),
                Some(format!("{}m", h.interval_mins).as_str())
            );
            assert_eq!(b["alerts"][0]["failure-threshold"].as_u64(), Some(1));
        }
        // The probes keep the default threshold: one slow answer is not an outage.
        let films = endpoint(&v, "Jellyfin");
        assert!(
            films["alerts"][0]["failure-threshold"].is_null(),
            "{films:?}"
        );
    }

    #[test]
    fn a_heartbeat_is_pushed_where_gatus_keys_it() {
        assert_eq!(key("The house", "Backups"), "the-house_backups");
        assert_eq!(
            push_path(&BACKUPS),
            "/api/v1/endpoints/the-house_backups-up-to-date/external"
        );
        assert_eq!(key("A/b_c,d.e#f+g&h", "X"), "a-b-c-d-e-f-g-h_x");
    }

    #[test]
    fn a_page_of_heartbeats_alone_is_told_apart() {
        let mut p = page();
        assert!(!probes_nothing(&p));
        p.probes.clear();
        assert!(!probes_nothing(&p), "the house's probe is still there");
        p.house = None;
        assert!(probes_nothing(&p));
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
