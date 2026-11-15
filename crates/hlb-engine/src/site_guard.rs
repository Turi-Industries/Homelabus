//! Both sides never written at once: a house cut from its site stops its vital apps, and
//! the site's promotion waits until a house still up has.
//!
//! Each end reads the same thing by its own clock — the link's last WireGuard handshake —
//! so no clock is compared with another. The house's node holding the state runs
//! [`decide`] every [`GUARD_EVERY_SECS`] (a systemd timer, not the controller: a watcher
//! must not depend on what it guards); the site's promotion runs [`house_wait_fn`].
//!
//! 🔴 **The house stops before the site may start.** The house stops once its handshake
//! is [`stops_at`] old; the site promotes once every house node's is
//! [`promotion_waits`] old, later by one guard period and a stop's grace. A site
//! promoted early would be written beside a house still serving its LAN, and the return
//! replaces what the house wrote.

/// A handshake older than this is a link down: with a keepalive every 25 s, WireGuard
/// renews its session every two minutes while the tunnel lives. A threshold below it
/// would stop the apps on a healthy link.
pub const STALE_AFTER_SECS: u64 = 180;

/// How long past [`STALE_AFTER_SECS`] the house waits before stopping, unless the owner
/// set another (`hlb config site-link`): most cuts are shorter.
pub const DEFAULT_STOP_AFTER_SECS: u64 = 120;

/// How often the guard looks: its timer's period.
pub const GUARD_EVERY_SECS: u64 = 30;

/// From the guard deciding to stop to the apps no longer taking writes: Docker's grace
/// is 10 s, the rest is Swarm's.
pub const STOP_GRACE_SECS: u64 = 30;

/// Why the carried apps are held stopped while the link is down. 🔴 A stored value
/// (`service_holds.why`): the guard starts again only what it held itself.
pub const LINK_HOLD: &str = "the site link is down";
/// As long as a cut may last: lapsed, reconciliation would start the apps on a house
/// that cannot tell whether its site serves them.
pub const LINK_HOLD_SECS: i64 = 365 * 24 * 3600;

/// On the site: the seconds the promotion waits for the house's last handshake, written
/// by `hlb site sync` and `hlb config site-link`. A stored path.
pub const WAIT_FILE: &str = "/etc/hlb/site/house-wait";

/// The promotion's exit when a house node still handshakes: the house is up, its apps
/// serve, and a promotion would have both sides written.
pub const HOUSE_UP: i32 = 4;

/// The guard's systemd units on the house's node, `.service` and `.timer`.
pub const UNIT: &str = "hlb-site-guard";

/// The handshake's age at which the house stops its vital apps.
pub fn stops_at(stop_after: u64) -> u64 {
    STALE_AFTER_SECS + stop_after
}

/// The handshake's age at which the site may promote: the house has stopped by then.
pub fn promotion_waits(stop_after: u64) -> u64 {
    stops_at(stop_after) + GUARD_EVERY_SECS + STOP_GRACE_SECS
}

/// The link as this node reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Link {
    /// No handshake since the interface came up.
    Never,
    /// `wg` did not answer: no interface, or no tool.
    Unread(String),
    /// Seconds since the youngest handshake.
    Age(u64),
}

/// Reads `wg show <if> latest-handshakes` — a public key and an epoch per line, 0 for
/// never. The youngest handshake speaks for the link.
pub fn reading(out: Result<&str, String>, now: u64) -> Link {
    let out = match out {
        Ok(o) => o,
        Err(e) => return Link::Unread(e),
    };
    out.lines()
        .filter_map(|l| l.split_whitespace().nth(1)?.parse::<u64>().ok())
        .filter(|&t| t > 0)
        .max()
        .map_or(Link::Never, |t| Link::Age(now.saturating_sub(t)))
}

/// Who holds the carried services stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Held {
    Not,
    /// By the guard, every one of them that is held.
    ByGuard,
    /// By something else — a promotion, a return, a restore, the UPS: theirs to release.
    Other(String),
}

/// From the holds, `(service, why)`, and the carried services.
pub fn held(holds: &[(String, String)], carried: &[String]) -> Held {
    let ours: Vec<&(String, String)> = holds.iter().filter(|(s, _)| carried.contains(s)).collect();
    if let Some((_, why)) = ours.iter().find(|(_, why)| why != LINK_HOLD) {
        return Held::Other(why.clone());
    }
    if ours.is_empty() {
        Held::Not
    } else {
        Held::ByGuard
    }
}

/// What the guard does now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Act {
    Nothing,
    /// Stop the carried services, held for [`LINK_HOLD`].
    Stop,
    /// The link is back: ask the site whether it was promoted meanwhile.
    AskSite,
}

/// 🔴 A link that cannot be read is a link down: stopping when it was not needed costs a
/// minute, the link answering again; not stopping when it was costs the writes.
///
/// Between [`STALE_AFTER_SECS`] and [`stops_at`] nothing moves either way: a link going
/// down is given its delay, one coming back must handshake afresh first.
pub fn decide(link: &Link, stop_after: u64, held: &Held) -> Act {
    let down = match link {
        Link::Never | Link::Unread(_) => true,
        Link::Age(age) => *age > stops_at(stop_after),
    };
    let up = matches!(link, Link::Age(age) if *age <= STALE_AFTER_SECS);
    match held {
        Held::Other(_) => Act::Nothing,
        Held::Not if down => Act::Stop,
        Held::ByGuard if up => Act::AskSite,
        Held::Not | Held::ByGuard => Act::Nothing,
    }
}

/// Whether the house starts its apps again, from the site's answer: promoted since
/// (`Some`), it serves them until the return; unanswered, the house cannot know.
pub fn start_again(promoted: &Result<Option<String>, String>) -> bool {
    matches!(promoted, Ok(None))
}

/// The site's half: a shell function, `house_stopped`, that returns once every house
/// node's last handshake is at least `$HOUSE_WAIT` seconds old, and exits [`HOUSE_UP`]
/// as soon as a node handshakes again while it waits.
///
/// 🔴 A handshake that is merely recent says nothing: the owner promotes when the
/// alert comes, two to three minutes after a cut, while the dead house's last handshake
/// is still under [`STALE_AFTER_SECS`]. A house that is up renews it within two minutes
/// — a handshake dated after the wait began is the proof.
///
/// A node that never handshook since the site's interface came up says nothing: a
/// site rebooted while the house was down would otherwise wait forever. A link that
/// cannot be read refuses: the house may be up, and only a person can say it is not.
pub fn house_wait_fn() -> String {
    let wg = hlb_mesh::site::INTERFACE;
    let up = HOUSE_UP;
    let every = GUARD_EVERY_SECS;
    let default = promotion_waits(DEFAULT_STOP_AFTER_SECS);
    format!(
        r#"house_stopped() {{
    case "$HOUSE_WAIT" in ''|*[!0-9]*) HOUSE_WAIT={default} ;; esac
    began=$(date +%s)
    while :; do
        now=$(date +%s)
        youngest=""
        seen=$(wg show {wg} latest-handshakes) || {{
            echo "🔴 the link to the house cannot be read here, so whether the house" >&2
            echo "   still serves is unknown. Sure it is down: $0 --apply --house-stopped" >&2
            exit 1
        }}
        for t in $(echo "$seen" | awk '{{print $2}}'); do
            [ "$t" -gt 0 ] || continue
            if [ "$t" -gt "$began" ]; then
                echo "🔴 the house is up: a node handshook $((now - t)) s ago, after this began," >&2
                echo "   so its vital apps still serve. Promoting would have both sides written." >&2
                echo "   From the house: hlb site promote --apply stops them first." >&2
                exit {up}
            fi
            age=$((now - t))
            if [ -z "$youngest" ] || [ "$age" -lt "$youngest" ]; then youngest=$age; fi
        done
        [ -n "$youngest" ] || return 0
        [ "$youngest" -lt "$HOUSE_WAIT" ] || return 0
        left=$((HOUSE_WAIT - youngest))
        echo "  … the house's last handshake is $youngest s old; a house still up handshakes" \
            "again, one cut stops its vital apps before $HOUSE_WAIT s: waiting $left s more"
        [ "$left" -le {every} ] || left={every}
        sleep "$left"
    done
}}
"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const D: u64 = DEFAULT_STOP_AFTER_SECS;

    #[test]
    fn the_site_waits_past_the_house_stopping() {
        assert_eq!(stops_at(D), 300);
        assert_eq!(promotion_waits(D), 360);
        for d in [60, 120, 3600] {
            assert!(promotion_waits(d) > stops_at(d) + GUARD_EVERY_SECS);
        }
    }

    #[test]
    fn the_youngest_handshake_speaks_and_never_is_zero() {
        let now = 1_000;
        assert_eq!(reading(Ok("k1\t900\nk2\t990\n"), now), Link::Age(10));
        assert_eq!(reading(Ok("k1\t0\n"), now), Link::Never);
        assert_eq!(reading(Ok(""), now), Link::Never);
        assert!(matches!(reading(Err("no".into()), now), Link::Unread(_)));
    }

    #[test]
    fn a_link_down_past_its_delay_stops_and_one_unread_does_too() {
        let not = Held::Not;
        assert_eq!(decide(&Link::Age(stops_at(D) + 1), D, &not), Act::Stop);
        assert_eq!(decide(&Link::Never, D, &not), Act::Stop);
        assert_eq!(decide(&Link::Unread("x".into()), D, &not), Act::Stop);
        // Inside the delay, and healthy: nothing.
        assert_eq!(decide(&Link::Age(stops_at(D)), D, &not), Act::Nothing);
        assert_eq!(decide(&Link::Age(30), D, &not), Act::Nothing);
    }

    #[test]
    fn only_a_fresh_handshake_starts_what_the_guard_held() {
        let ours = Held::ByGuard;
        assert_eq!(decide(&Link::Age(5), D, &ours), Act::AskSite);
        assert_eq!(decide(&Link::Age(STALE_AFTER_SECS), D, &ours), Act::AskSite);
        // Stale but within the delay: the link has not come back.
        assert_eq!(
            decide(&Link::Age(STALE_AFTER_SECS + 1), D, &ours),
            Act::Nothing
        );
        assert_eq!(decide(&Link::Never, D, &ours), Act::Nothing);
    }

    #[test]
    fn a_hold_of_someone_else_is_theirs_to_release() {
        let other = Held::Other("the site serves it".into());
        for link in [Link::Never, Link::Age(5), Link::Age(10_000)] {
            assert_eq!(decide(&link, D, &other), Act::Nothing);
        }
        let carried = vec!["vaultwarden".to_string(), "pocket-id".to_string()];
        let h = |s: &str, w: &str| (s.to_string(), w.to_string());
        assert_eq!(held(&[], &carried), Held::Not);
        assert_eq!(held(&[h("immich", "a restore")], &carried), Held::Not);
        assert_eq!(held(&[h("pocket-id", LINK_HOLD)], &carried), Held::ByGuard);
        assert_eq!(
            held(
                &[
                    h("pocket-id", LINK_HOLD),
                    h("vaultwarden", "the site serves it")
                ],
                &carried
            ),
            Held::Other("the site serves it".into())
        );
    }

    #[test]
    fn the_house_starts_again_only_on_a_site_saying_not_promoted() {
        assert!(start_again(&Ok(None)));
        assert!(!start_again(&Ok(Some("2026-11-12T10:00:00Z".into()))));
        assert!(!start_again(&Err("unreachable".into())));
    }

    /// Runs `house_stopped` in `sh` with a `wg` on PATH printing `handshakes`.
    fn wait(handshakes: &str, house_wait: u64) -> (i32, std::time::Duration, String) {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let wg = dir.path().join("wg");
        std::fs::write(&wg, format!("#!/bin/sh\nprintf \"{handshakes}\"\n")).expect("wg");
        std::fs::set_permissions(&wg, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        let script = format!(
            "{}HOUSE_WAIT={house_wait}\nhouse_stopped\necho waited\n",
            house_wait_fn()
        );
        let path = format!(
            "{}:{}",
            dir.path().display(),
            std::env::var("PATH").unwrap_or_default()
        );
        let at = std::time::Instant::now();
        let out = std::process::Command::new("sh")
            .args(["-c", &script])
            .env("PATH", path)
            .output()
            .expect("sh");
        let said = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        (out.status.code().unwrap_or(-1), at.elapsed(), said)
    }

    #[test]
    fn an_unreadable_link_or_wait_never_lets_the_promotion_through_unasked() {
        // `wg` failing: the house may be up.
        let (code, _, said) = wait("x\" ; exit 1 ; \"", 360);
        assert_eq!(code, 1, "{said}");
        assert!(said.contains("--house-stopped"), "{said}");
    }

    fn epoch(ago: u64) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or_default()
            - ago
    }

    #[test]
    fn the_promotion_refuses_a_house_handshaking_again_while_it_waits() {
        // A handshake dated after the wait began: what a house still up renews.
        let (code, took, said) = wait("a\\t$(( $(date +%s) + 1 ))\\n", 360);
        assert_eq!(code, HOUSE_UP, "{said}");
        assert!(!said.contains("waited"), "{said}");
        assert!(took.as_secs() < 2, "{took:?}");
    }

    #[test]
    fn a_handshake_merely_recent_is_waited_out_not_refused() {
        // The dead house's last handshake, 5 s before the owner promotes.
        let (code, took, said) = wait(&format!("a\\t{}\\n", epoch(5)), 7);
        assert_eq!(code, 0, "{said}");
        assert!(said.ends_with("waited\n"), "{said}");
        assert!((2..6).contains(&took.as_secs()), "{took:?}");
    }

    #[test]
    fn the_promotion_goes_on_once_every_handshake_is_old_enough() {
        let (code, took, said) = wait(&format!("a\\t{}\\nb\\t0\\n", epoch(400)), 360);
        assert_eq!((code, said.trim()), (0, "waited"));
        assert!(took.as_secs() < 2, "{took:?}");
        // Nobody ever handshook: no house to wait for.
        let (code, _, said) = wait("a\\t0\\n", 360);
        assert_eq!((code, said.trim()), (0, "waited"));
    }

    #[test]
    fn the_promotion_waits_out_what_is_left() {
        let (code, took, said) = wait(&format!("a\\t{}\\n", epoch(298)), 300);
        assert_eq!(code, 0, "{said}");
        assert!(said.contains("waiting 2 s more"), "{said}");
        assert!(said.ends_with("waited\n"), "{said}");
        assert!((2..6).contains(&took.as_secs()), "{took:?}");
    }
}
