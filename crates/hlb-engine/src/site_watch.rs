//! What watches the house from its site, permanently: Gatus probing every name through
//! the front door, an ntfy of the site's own carrying the alerts to the owner's phone,
//! and the site's edge — a Caddy serving those two under the site's own names.
//!
//! 🔴 **Nothing here goes through the house, nor through a third party.** An alert
//! relayed by the house's own ntfy does not leave when the house is what fell; one
//! relayed by ntfy.sh is read by someone else. The phone subscribes to the site's ntfy.
//!
//! An alert's "Announce" button reaches the page through ntfy alone: the phone publishes
//! the alert's notice id to [`status_page::ACK_TOPIC`], and the announcer — the ntfy
//! image subscribed to it, nothing listening — writes the notice the house prepared
//! into a directory Gatus reads. No service of the site's is opened for it.
//!
//! 🔴 **The edge serves the site's names, never a house's.** Its certificates are the
//! site's own, for `status.` and `alerts.` — kept on the VPS, unlike the lifeboat's,
//! which are asked for at promotion only (the owner's decision, 2026-11-09).

use hlb_ingress::status_page;
use hlb_orchestrator::ServiceSpec;
use hlb_types::binding::{GeneratedSecret, SecretForm};
use hlb_types::manifest::{Bytes, Healthcheck, Memory};
use hlb_types::Manifest;

/// The overlay the door, the edge, Gatus and ntfy share — not the lifeboat's, where the
/// site's PostgreSQL runs while promoted: a page the internet reads sits nowhere near it.
pub const NETWORK: &str = "hlb-site-watch";

/// ntfy, as the catalog's platform service pins it.
pub const NTFY_IMAGE: &str = "binwiederhier/ntfy:v2.34.0@sha256:901e14503d3f605f445be0e68f2ac71f0aa73391897ce6ceb599f8c48d8b3792";

/// Volumes on the site. Stored names: renamed, the next sync starts over empty — the
/// phone's subscription and Gatus's history with it.
pub const NTFY_CACHE: &str = "hlb-site-ntfy-cache";
pub const GATUS_DATA: &str = "hlb-site-gatus-data";
pub const EDGE_DATA: &str = "hlb-site-edge-data";
pub const EDGE_CONFIG: &str = "hlb-site-edge-config";

/// On the VPS: Gatus's configuration, mounted read-only. A file Gatus watches, never a
/// Swarm secret: the promotion swaps it with a rename, and Gatus reloads it in place.
pub const CONFIG_DIR: &str = "/etc/hlb/site-watch";
/// Where Gatus reads it.
pub const MOUNTED_AT: &str = "/config";
/// The directory Gatus runs, every `.yaml` under it merged: the page and the
/// announcements. 🔴 Not [`CONFIG_DIR`] itself, where the two pages waiting would be
/// merged into the one running.
pub const LIVE: &str = "live";
/// The file Gatus runs, and the two it is copied from: the house serving everything,
/// and the site serving the lifeboat.
pub const GATUS_LIVE: &str = "live/gatus.yaml";
pub const GATUS_HOME: &str = "gatus.home.yaml";
pub const GATUS_PROMOTED: &str = "gatus.promoted.yaml";
/// Where the page ran before the announcements: removed once Gatus reads [`LIVE`].
pub const GATUS_BEFORE: &str = "gatus.yaml";
/// The announcer's only writable place, inside [`LIVE`].
pub const ANNOUNCED: &str = "live/announced";

/// Where a private ACME directory's root is put, for Gatus to trust what it signed.
const ACME_ROOT: &str = "/etc/hlb/acme-root.pem";

/// ntfy's accounts: the phone reads, Gatus publishes, the phone's button publishes to
/// the acknowledgements alone, the announcer reads both. Stored names, in the vault.
pub const READER: &str = "reader";
pub const PUBLISHER: &str = "gatus";
pub const ACKNOWLEDGER: &str = "ack";
pub const ANNOUNCER: &str = "announcer";
pub const READER_SECRET: &str = "site-ntfy-reader-password";
pub const TOKEN_SECRET: &str = "site-ntfy-gatus-token";
/// 🔴 Written into every alert, so read by whoever reads them: it opens nothing but
/// publishing an id the announcer looks up.
pub const ACK_SECRET: &str = "site-ntfy-ack-token";
pub const ANNOUNCER_SECRET: &str = "site-ntfy-announcer-token";

/// The service turning a pressed button into an announcement.
pub const ANNOUNCER_SERVICE: &str = "hlb-site-announcer";
/// What the house pushes its heartbeats to the site's Gatus with. A stored name: the
/// house's daemon pushes only once it is in the vault — that is, once a watch exists.
pub const PUSH_SECRET: &str = "site-gatus-push-token";

/// How often the house pushes, well inside the shortest heartbeat's interval: three
/// pushes lost in a row are still not an outage there.
pub const PUSH_EVERY_SECS: u64 = 300;

/// The site's own names.
pub fn status_host(domain: &str) -> String {
    format!("status.{domain}")
}

pub fn alerts_host(domain: &str) -> String {
    format!("alerts.{domain}")
}

/// An ntfy access token: `tk_` and 29 more, 32 in all — ntfy refuses any other length.
pub fn draw_token() -> String {
    format!(
        "tk_{}",
        hlb_secrets::generate_password(29).to_ascii_lowercase()
    )
}

fn bcrypt(stored: &str) -> String {
    GeneratedSecret {
        name: String::new(),
        form: SecretForm::Bcrypt,
    }
    .render(stored)
}

/// The tokens the site's ntfy knows, one per account signing in by token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tokens {
    /// Gatus, publishing the alerts.
    pub gatus: String,
    /// The alerts' button, publishing an acknowledgement.
    pub ack: String,
    /// The announcer, reading both.
    pub announcer: String,
}

/// ntfy's `server.yml`: closed to anyone without an account, its accounts declared.
///
/// 🔴 No `upstream-base-url`: set, ntfy asks ntfy.sh to wake iPhones for each message —
/// a third party told when the house has an alert.
pub fn ntfy_config(alerts_host: &str, reader_password: &str, tokens: &Tokens) -> String {
    let topic = status_page::TOPIC;
    let acks = status_page::ACK_TOPIC;
    format!(
        "# Generated by Homelabus - do not edit by hand.\n\
         base-url: \"https://{alerts_host}\"\n\
         cache-file: /var/cache/ntfy/cache.db\n\
         auth-file: /var/cache/ntfy/auth.db\n\
         auth-default-access: deny-all\n\
         # Behind the site's edge: each visitor's address from X-Forwarded-For.\n\
         behind-proxy: true\n\
         auth-users:\n  \
           - \"{READER}:{reader}:user\"\n  \
           - \"{PUBLISHER}:{publisher}:user\"\n  \
           - \"{ACKNOWLEDGER}:{acknowledger}:user\"\n  \
           - \"{ANNOUNCER}:{announcer}:user\"\n\
         auth-access:\n  \
           - \"{READER}:{topic}:read-only\"\n  \
           - \"{PUBLISHER}:{topic}:write-only\"\n  \
           - \"{ACKNOWLEDGER}:{acks}:write-only\"\n  \
           - \"{ANNOUNCER}:{topic}:read-only\"\n  \
           - \"{ANNOUNCER}:{acks}:read-only\"\n\
         auth-tokens:\n  \
           - \"{PUBLISHER}:{gatus}:gatus\"\n  \
           - \"{ACKNOWLEDGER}:{ack}:button\"\n  \
           - \"{ANNOUNCER}:{announcer_token}:announcer\"\n",
        reader = bcrypt(reader_password),
        // Each signs in by its token alone: the account's password is the token's
        // hash, which opens nothing the token does not.
        publisher = bcrypt(&tokens.gatus),
        acknowledger = bcrypt(&tokens.ack),
        announcer = bcrypt(&tokens.announcer),
        gatus = tokens.gatus,
        ack = tokens.ack,
        announcer_token = tokens.announcer,
    )
}

fn memory(reserve: u64, limit: u64) -> Memory {
    const MIB: u64 = 1024 * 1024;
    Memory {
        reserve: Bytes(reserve * MIB),
        limit: Bytes(limit * MIB),
    }
}

/// Memory limits, MiB, of what runs on the site permanently. Measured idle on a real
/// Docker: Gatus 14 MiB; ntfy and a two-name Caddy about 20; the announcer 17.
pub const GATUS_MIB: u64 = 64;
pub const NTFY_MIB: u64 = 128;
pub const EDGE_MIB: u64 = 128;
pub const ANNOUNCER_MIB: u64 = 64;
pub const MEMORY_MIB: u64 = GATUS_MIB + NTFY_MIB + EDGE_MIB + ANNOUNCER_MIB;

fn probe(test: &[&str]) -> Healthcheck {
    Healthcheck {
        test: test.iter().map(|s| s.to_string()).collect(),
        interval_secs: 30,
        timeout_secs: 5,
        retries: 3,
        start_period_secs: 10,
    }
}

/// The site's ntfy.
pub fn ntfy(config: &str) -> ServiceSpec {
    let mut spec = ServiceSpec::new(status_page::NTFY, NTFY_IMAGE)
        .network(NETWORK)
        .mount(NTFY_CACHE, "/var/cache/ntfy")
        .file("/etc/ntfy/server.yml", config)
        .healthcheck(probe(&[
            "CMD-SHELL",
            "wget -qO- http://127.0.0.1/v1/health | grep -q true",
        ]));
    // 🔴 The image's entrypoint is `ntfy` alone: without `serve` it prints its help.
    spec.args = vec!["serve".into()];
    // As the catalog's: it writes its SQLite cache outside the volume, and drops its
    // privileges at startup.
    spec.hardening.read_only_rootfs = false;
    spec.hardening.cap_add = ["CHOWN", "SETGID", "SETUID"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    spec.memory = Some(memory(16, NTFY_MIB));
    spec
}

/// The site's Gatus: every probed name resolved to the door, `door` its address on
/// [`NETWORK`].
pub fn gatus(names: &[String], door: &str, acme_root: Option<&str>) -> ServiceSpec {
    let mut spec = ServiceSpec::new(status_page::SERVICE, status_page::IMAGE)
        .network(NETWORK)
        .mount(GATUS_DATA, "/data")
        .bind(CONFIG_DIR, MOUNTED_AT, true)
        .env(vec![(
            "GATUS_CONFIG_PATH".into(),
            format!("{MOUNTED_AT}/{LIVE}"),
        )]);
    let mut names = names.to_vec();
    names.sort();
    names.dedup();
    spec.hosts = names.into_iter().map(|n| (n, door.to_string())).collect();
    if let Some(root) = acme_root {
        spec = spec.file(ACME_ROOT, root);
        spec.env.push(("SSL_CERT_FILE".into(), ACME_ROOT.into()));
    }
    spec.memory = Some(memory(8, GATUS_MIB));
    spec
}

/// Where the announcer's files are, in its container.
const ANNOUNCER_DIR: &str = "/hlb";
const ANNOUNCER_WRITES: &str = "/announced";

/// The announcer's script. It reads ntfy's JSON lines rather than having ntfy run a
/// command per message: ntfy writes that command to `/tmp` and executes it, and
/// Swarm's tmpfs is `noexec` (measured, ntfy 2.34).
///
/// 🔴 It trusts the button with an id and nothing more: an id is `[a-z0-9-]` read off
/// the JSON, looked up in the house's table, and anything else is dropped — the words
/// the page shows are the table's. An announcement is made only while its alert is
/// open, so a button pressed after the resolution announces nothing over.
///
/// Gatus reloads a directory when one of its files is newer than its last reading, to
/// the second: a file written in the second it reloaded would wait for the next
/// change. Each one is dated two seconds ahead.
const ANNOUNCE_SH: &str = r#"#!/bin/sh
set -u
TEXTS=@DIR@/texts
DIR=@WRITES@

field() { awk -F '\t' -v id="$1" -v n="$2" '$1 == id { print $n; exit }' "$TEXTS"; }
now() { date -u +%Y-%m-%dT%H:%M:%SZ; }
fresh() { touch -d "@$(( $(date +%s) + 2 ))" "$1"; }

opened() {
    [ -n "$(field "$1" 1)" ] && : > "$DIR/.open-$1"
}

announce() {
    [ -f "$DIR/.open-$1" ] || return 0
    [ -f "$DIR/$1.yaml" ] && return 0
    kind=$(field "$1" 2)
    down=$(field "$1" 3)
    [ -n "$down" ] || return 0
    printf 'announcements:\n  - timestamp: %s\n    type: %s\n    message: %s\n' \
        "$(now)" "$kind" "$down" > "$DIR/.$1.tmp" &&
        mv -f "$DIR/.$1.tmp" "$DIR/$1.yaml" && fresh "$DIR/$1.yaml"
}

resolved() {
    rm -f "$DIR/.open-$1"
    [ -f "$DIR/$1.yaml" ] || return 0
    since=$(sed -n 's/^  - timestamp: //p' "$DIR/$1.yaml" | head -n 1)
    kind=$(field "$1" 2)
    down=$(field "$1" 3)
    up=$(field "$1" 4)
    past="$DIR/$1.$(date +%s).yaml"
    printf 'announcements:\n  - timestamp: %s\n    type: %s\n    message: %s\n    archived: true\n  - timestamp: %s\n    type: operational\n    message: %s\n    archived: true\n' \
        "$since" "$kind" "$down" "$(now)" "$up" > "$DIR/.$1.tmp" &&
        mv -f "$DIR/.$1.tmp" "$past" && rm -f "$DIR/$1.yaml" && fresh "$past"
    find "$DIR" -name '*.*.yaml' -mtime +30 -exec rm -f {} +
}

handle() {
    topic=$(printf '%s' "$1" | sed -n 's/.*"topic":"\([a-z0-9-]*\)".*/\1/p')
    case "$topic" in
    "@ACKS@")
        id=$(printf '%s' "$1" | sed -n 's/.*"message":"\([a-z0-9-]*\)".*/\1/p')
        [ -n "$id" ] && announce "$id"
        ;;
    "@ALERTS@")
        id=$(printf '%s' "$1" | sed -n 's/.*[[,]"@TAG@\([a-z0-9-]*\)".*/\1/p')
        [ -n "$id" ] || return 0
        if printf '%s' "$1" | grep -Eq '"tags":\[[^]]*"@RESOLVED@"'; then
            resolved "$id"
        else
            opened "$id"
        fi
        ;;
    esac
    return 0
}

# One message, for the tests: the same function the subscription runs.
[ "${1:-}" = "--line" ] && { handle "$2"; exit; }
ntfy subscribe -c @DIR@/client.yml --from-config | while IFS= read -r line; do
    handle "$line"
done
# The subscription ended: Swarm starts it again.
exit 1
"#;

/// The announcer's script, its names filled in.
pub fn announce_sh() -> String {
    ANNOUNCE_SH
        .replace("@DIR@", ANNOUNCER_DIR)
        .replace("@WRITES@", ANNOUNCER_WRITES)
        .replace("@ACKS@", status_page::ACK_TOPIC)
        .replace("@ALERTS@", status_page::TOPIC)
        .replace("@TAG@", status_page::NOTICE_TAG)
        .replace("@RESOLVED@", status_page::RESOLVED_TAG)
}

/// The announcer's ntfy client: both topics, printed — no command per message.
pub fn announcer_client(token: &str) -> String {
    format!(
        "# Generated by Homelabus - do not edit by hand.\n\
         default-host: \"http://{ntfy}\"\n\
         default-token: \"{token}\"\n\
         subscribe:\n  \
           - topic: \"{acks}\"\n  \
           - topic: \"{alerts}\"\n",
        ntfy = status_page::NTFY,
        acks = status_page::ACK_TOPIC,
        alerts = status_page::TOPIC,
    )
}

/// The announcer: the ntfy image, subscribed, writing [`ANNOUNCED`] and nothing else.
/// `texts`: [`status_page::texts`].
pub fn announcer(token: &str, texts: &str) -> ServiceSpec {
    let mut spec = ServiceSpec::new(ANNOUNCER_SERVICE, NTFY_IMAGE)
        .network(NETWORK)
        .bind(format!("{CONFIG_DIR}/{ANNOUNCED}"), ANNOUNCER_WRITES, false)
        .file(format!("{ANNOUNCER_DIR}/announce.sh"), announce_sh())
        .file(
            format!("{ANNOUNCER_DIR}/client.yml"),
            announcer_client(token),
        )
        .file(format!("{ANNOUNCER_DIR}/texts"), texts)
        // The process's exact name: `-f` would find the probe's own shell.
        .healthcheck(probe(&["CMD-SHELL", "pgrep -x ntfy >/dev/null"]));
    spec.command = vec!["sh".into(), format!("{ANNOUNCER_DIR}/announce.sh")];
    spec.memory = Some(memory(8, ANNOUNCER_MIB));
    spec
}

/// The edge's Caddyfile: the status page and the alerts, on the door's listener alone,
/// the PROXY header taken from `subnet` — [`NETWORK`]'s.
pub fn edge_caddyfile(
    domain: &str,
    tls: hlb_ingress::caddyfile::Tls,
    subnet: &str,
) -> crate::lifeboat::SiteIngress {
    let route = |host: String, service: &str, port: u16| {
        let mut r = hlb_ingress::Route::new(host, service, port);
        r.public = true;
        r
    };
    let routes = vec![
        route(status_host(domain), status_page::SERVICE, status_page::PORT),
        route(alerts_host(domain), status_page::NTFY, 80),
    ];
    let cfg = hlb_ingress::Config {
        tls,
        site: Some(subnet.to_string()),
        ..hlb_ingress::Config::default()
    };
    let mut names: Vec<String> = routes.iter().map(|r| r.host.clone()).collect();
    names.sort();
    crate::lifeboat::SiteIngress {
        caddyfile: hlb_ingress::render(&routes, &cfg),
        names,
        acme_root: None,
    }
}

/// The edge: the house's Caddy image and hardening, its own volumes, always running.
pub fn edge(caddy: &Manifest, ingress: &crate::lifeboat::SiteIngress) -> ServiceSpec {
    let mut spec = crate::lifeboat::caddy_on_site(
        caddy,
        ingress,
        hlb_ingress::front_door::SITE_EDGE,
        NETWORK,
        (EDGE_DATA, EDGE_CONFIG),
    );
    spec.memory = Some(memory(16, EDGE_MIB));
    spec
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_house_pushes_well_inside_every_heartbeat() {
        for h in status_page::HEARTBEATS {
            assert!(
                PUSH_EVERY_SECS * 3 < h.interval_mins * 60,
                "{} would go missing on three lost pushes",
                h.name
            );
        }
    }

    #[test]
    fn a_token_has_the_length_ntfy_reads() {
        let t = draw_token();
        assert_eq!(t.len(), 32, "{t}");
        assert!(t.starts_with("tk_"), "{t}");
        assert!(
            t[3..]
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()),
            "{t}"
        );
        assert_ne!(draw_token(), t);
    }

    fn tokens() -> Tokens {
        Tokens {
            gatus: "tk_abc".into(),
            ack: "tk_ack".into(),
            announcer: "tk_ann".into(),
        }
    }

    #[test]
    fn the_site_s_ntfy_is_closed_and_asks_no_third_party() {
        let c = ntfy_config("alerts.example.fr", "reader-pw", &tokens());
        assert!(c.contains("auth-default-access: deny-all\n"), "{c}");
        assert!(c.contains("\"reader:homelabus:read-only\""), "{c}");
        assert!(c.contains("\"gatus:homelabus:write-only\""), "{c}");
        assert!(c.contains("\"gatus:tk_abc:gatus\""), "{c}");
        assert!(!c.contains("reader-pw"), "a password in clear: {c}");
        assert!(!c.contains("upstream"), "{c}");
        assert!(!c.contains("ntfy.sh"), "{c}");
        let v: serde_yaml_ng::Value = serde_yaml_ng::from_str(&c).expect("YAML");
        assert_eq!(v["auth-users"].as_sequence().map(Vec::len), Some(4));
    }

    #[test]
    fn the_button_publishes_acknowledgements_and_reads_nothing() {
        let c = ntfy_config("alerts.example.fr", "pw", &tokens());
        let v: serde_yaml_ng::Value = serde_yaml_ng::from_str(&c).expect("YAML");
        let access: Vec<&str> = v["auth-access"]
            .as_sequence()
            .expect("access")
            .iter()
            .filter_map(|a| a.as_str())
            .collect();
        let of = |who: &str| -> Vec<&str> {
            access
                .iter()
                .copied()
                .filter(|a| a.starts_with(&format!("{who}:")))
                .collect()
        };
        assert_eq!(of(ACKNOWLEDGER), vec!["ack:homelabus-acks:write-only"]);
        assert_eq!(
            of(ANNOUNCER),
            vec![
                "announcer:homelabus:read-only",
                "announcer:homelabus-acks:read-only"
            ]
        );
        assert!(c.contains("\"ack:tk_ack:button\""), "{c}");
        assert!(c.contains("\"announcer:tk_ann:announcer\""), "{c}");
    }

    #[test]
    fn the_same_secrets_render_the_same_file() {
        // A hash drawn with a new salt each time would restart ntfy at every sync.
        assert_eq!(
            ntfy_config("a.example.fr", "pw", &tokens()),
            ntfy_config("a.example.fr", "pw", &tokens())
        );
    }

    /// The announcer's script, run on one ntfy line in `dir`, its table `texts`.
    fn announce(dir: &std::path::Path, line: &serde_json::Value) {
        let script = announce_sh()
            .replace(
                &format!("TEXTS={ANNOUNCER_DIR}/texts"),
                &format!("TEXTS={}/texts", dir.display()),
            )
            .replace(
                &format!("DIR={ANNOUNCER_WRITES}"),
                &format!("DIR={}/announced", dir.display()),
            );
        let out = std::process::Command::new("sh")
            .args(["-c", &script, "announce", "--line", &line.to_string()])
            .output()
            .expect("sh");
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    fn announced(dir: &std::path::Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir.join("announced"))
            .expect("dir")
            .map(|e| e.expect("entry").file_name().to_string_lossy().to_string())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn a_pressed_button_announces_the_house_s_words_while_its_alert_is_open() {
        let tmp = tempfile::tempdir().expect("tmp");
        let dir = tmp.path();
        std::fs::create_dir(dir.join("announced")).expect("mkdir");
        let page = status_page::Page {
            probes: vec![status_page::Probe {
                title: "Budget $HOME".into(),
                host: "budget.example.fr".into(),
                public: true,
            }],
            house: None,
            token: "tk_g".into(),
            url: "https://status.example.fr".into(),
            push_token: "p".into(),
            alerts_url: "https://alerts.example.fr".into(),
            ack_token: "tk_a".into(),
        };
        std::fs::write(dir.join("texts"), status_page::texts(&page, &[])).expect("texts");
        let id = "services-budget-home";
        let ack = |message: &str| {
            serde_json::json!({
                "id": "a1", "event": "message", "topic": status_page::ACK_TOPIC,
                "message": message,
            })
        };
        let alert = |resolved: bool| {
            let mut tags = vec!["rotating_light".to_string()];
            if resolved {
                tags.push(status_page::RESOLVED_TAG.into());
            }
            tags.push(format!("{}{id}", status_page::NOTICE_TAG));
            serde_json::json!({
                "id": "g1", "event": "message", "topic": status_page::TOPIC,
                // A title cannot pass for a field: ntfy escapes its quotes.
                "title": "\",\"message\":\"services-budget-home",
                "message": "Budget does not answer", "tags": tags,
            })
        };

        // Pressed before the alert is known: nothing is open to announce.
        announce(dir, &ack(id));
        assert!(announced(dir).is_empty(), "{:?}", announced(dir));

        announce(dir, &alert(false));
        announce(dir, &ack("services-unknown"));
        announce(
            dir,
            &ack(&format!("{id}\"; touch {}/owned; \"", dir.display())),
        );
        announce(dir, &ack("../texts"));
        assert_eq!(announced(dir), vec![format!(".open-{id}")]);
        assert!(!dir.join("owned").exists());

        announce(dir, &ack(id));
        let file = dir.join("announced").join(format!("{id}.yaml"));
        let first = std::fs::read_to_string(&file).expect("announced");
        // Gatus reads `$$` as a dollar once the directory is merged.
        let v: serde_yaml_ng::Value = serde_yaml_ng::from_str(&first).expect("YAML");
        let a = &v["announcements"][0];
        assert_eq!(a["type"].as_str(), Some("outage"));
        assert_eq!(
            a["message"].as_str(),
            Some("Budget $$HOME is unavailable at the moment. We know, and we are on it.")
        );
        // Pressed twice: still the first announcement, its time kept.
        announce(dir, &ack(id));
        assert_eq!(std::fs::read_to_string(&file).expect("kept"), first);

        announce(dir, &alert(true));
        let names = announced(dir);
        assert_eq!(names.len(), 1, "{names:?}");
        let past = std::fs::read_to_string(dir.join("announced").join(&names[0])).expect("past");
        let v: serde_yaml_ng::Value = serde_yaml_ng::from_str(&past).expect("YAML");
        let list = v["announcements"].as_sequence().expect("two");
        assert_eq!(list.len(), 2, "{past}");
        assert_eq!(list[0]["timestamp"], a["timestamp"]);
        assert_eq!(list[1]["type"].as_str(), Some("operational"));
        assert_eq!(list[1]["message"].as_str(), Some("Budget $$HOME is back."));
        assert!(list.iter().all(|e| e["archived"].as_bool() == Some(true)));

        // Pressed once it is over: nothing new is announced.
        announce(dir, &ack(id));
        assert_eq!(announced(dir), names);
    }

    #[test]
    fn the_announcer_writes_its_directory_and_reads_its_subscription() {
        let s = announcer("tk_ann", "x\toutage\t\"a\"\t\"b\"\n");
        assert_eq!(s.binds.len(), 1);
        assert!(!s.binds[0].read_only);
        assert_eq!(s.binds[0].source, format!("{CONFIG_DIR}/{ANNOUNCED}"));
        assert!(s.hardening.read_only_rootfs);
        assert!(s.hardening.cap_add.is_empty());
        let client = announcer_client("tk_ann");
        let v: serde_yaml_ng::Value = serde_yaml_ng::from_str(&client).expect("YAML");
        assert_eq!(v["default-token"].as_str(), Some("tk_ann"));
        let topics: Vec<&str> = v["subscribe"]
            .as_sequence()
            .expect("subscribe")
            .iter()
            .filter_map(|t| t["topic"].as_str())
            .collect();
        assert_eq!(topics, vec![status_page::ACK_TOPIC, status_page::TOPIC]);
        // No command: ntfy would write it to a noexec /tmp.
        assert!(!client.contains("command"), "{client}");
    }

    #[test]
    fn the_announced_directory_is_inside_what_gatus_reads() {
        assert!(ANNOUNCED.starts_with(&format!("{LIVE}/")));
        assert!(GATUS_LIVE.starts_with(&format!("{LIVE}/")));
        for waiting in [GATUS_HOME, GATUS_PROMOTED, GATUS_BEFORE] {
            assert!(!waiting.contains('/'), "{waiting} would be merged");
        }
    }

    #[test]
    fn the_site_s_ntfy_is_the_catalog_s_image() {
        let catalog = include_str!("../../../catalog/_platform/ntfy/manifest.yaml");
        let m: Manifest = serde_yaml_ng::from_str(catalog).expect("manifest");
        assert_eq!(NTFY_IMAGE, m.spec.image.reference());
    }

    #[test]
    fn gatus_reaches_every_name_at_the_door_and_reads_its_file_only() {
        let s = gatus(
            &[
                "b.example.fr".into(),
                "a.example.fr".into(),
                "a.example.fr".into(),
            ],
            "10.0.5.2",
            None,
        );
        assert_eq!(
            s.hosts,
            vec![
                ("a.example.fr".to_string(), "10.0.5.2".to_string()),
                ("b.example.fr".to_string(), "10.0.5.2".to_string()),
            ]
        );
        assert!(s.hardening.read_only_rootfs);
        assert!(s.hardening.cap_add.is_empty(), "no NET_RAW: no ping");
        assert_eq!(s.binds.len(), 1);
        assert!(s.binds[0].read_only);
        assert_eq!(s.networks, vec![NETWORK.to_string()]);
    }

    #[test]
    fn a_private_acme_root_is_trusted_by_gatus() {
        let s = gatus(&[], "10.0.5.2", Some("-----BEGIN CERTIFICATE-----"));
        assert!(s
            .env
            .contains(&("SSL_CERT_FILE".to_string(), ACME_ROOT.to_string())));
        assert!(s.files.iter().any(|(p, _)| p == ACME_ROOT));
    }

    #[test]
    fn the_edge_serves_the_site_s_two_names_on_the_door_s_listener() {
        let i = edge_caddyfile(
            "example.fr",
            hlb_ingress::caddyfile::Tls::Acme {
                email: "a@example.fr".into(),
                wildcard: None,
                staging: false,
                ca: None,
                ca_root: false,
            },
            "10.0.7.0/24",
        );
        assert_eq!(i.names, vec!["alerts.example.fr", "status.example.fr"]);
        assert!(
            i.caddyfile.contains("hlb-site-gatus:8080"),
            "{}",
            i.caddyfile
        );
        assert!(i.caddyfile.contains("hlb-site-ntfy:80"), "{}", i.caddyfile);
        assert!(i.caddyfile.contains("10.0.7.0/24"), "{}", i.caddyfile);
    }

    #[test]
    fn what_runs_permanently_on_the_site_is_counted() {
        assert_eq!(
            MEMORY_MIB,
            [ntfy(""), gatus(&[], "x", None), announcer("t", "")]
                .iter()
                .map(|s| s.memory.expect("a limit").limit.mib())
                .sum::<u64>()
                + EDGE_MIB
        );
    }
}
