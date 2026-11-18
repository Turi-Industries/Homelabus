//! The house's ports, forwarded from the internet: each port a manifest publishes for
//! the internet reaches the node its service runs on, by a port forward on the router's
//! WAN.
//!
//! And reached from inside at the house's public address as well. OPNsense reflects a
//! forward onto its other networks (`purenat`), but a client in the TARGET's own network
//! is then answered by the target directly, from an address it never spoke to, and drops
//! the reply. An outbound NAT rule per forward sends the answer back through the router.
//! The system's switch doing that for every forward has no API in 26.7 (its legacy page
//! only), so Homelabus writes the rule itself.
//!
//! What is Homelabus's is marked ([`MARK`]) and only that is changed or removed. A
//! person's own forward of a port is left as it is, and said: it decides where that port
//! goes whatever Homelabus would write.

use std::net::Ipv4Addr;

use serde_json::{json, Value};

use crate::client::{Network, OutboundNat, PortForward};
use crate::names::network_of;

/// The description of every rule Homelabus writes, and how it knows its own.
/// ⚠️ A stored value: the router keeps it.
pub const MARK: &str = crate::names::MARK;

/// The network the internet arrives on.
pub const WAN: &str = "wan";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Protocol {
    Tcp,
    Udp,
}

impl Protocol {
    pub fn wire(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }

    /// Whether a rule listed with `listed` (`TCP`, `tcp/udp`, empty for any) takes it.
    fn within(self, listed: &str) -> bool {
        let listed = listed.trim().to_ascii_lowercase();
        listed.is_empty() || listed == "any" || listed.split('/').any(|p| p == self.wire())
    }
}

/// A rule's identity: one forward per protocol and port on the WAN.
pub type Key = (Protocol, u16);

pub fn key_text((protocol, port): Key) -> String {
    format!("{port}/{}", protocol.wire())
}

/// A port the house wants forwarded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Wanted {
    pub protocol: Protocol,
    pub port: u16,
    pub target: Ipv4Addr,
    /// The service publishing it, said in what is reported.
    pub service: String,
}

impl Wanted {
    fn key(&self) -> Key {
        (self.protocol, self.port)
    }
}

/// The forward Homelabus writes: the router's WAN address, the same port on the target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardRule {
    pub protocol: Protocol,
    pub port: u16,
    pub target: Ipv4Addr,
    pub service: String,
}

impl ForwardRule {
    /// As `d_nat/add_rule` takes it: nested, where the listing flattens. `pass` lets
    /// the forwarded traffic in by itself — no filter rule of its own to keep in step.
    pub fn body(&self) -> Value {
        json!({
            "interface": WAN,
            "ipprotocol": "inet",
            "protocol": self.protocol.wire(),
            "destination": {"network": "wanip", "port": self.port.to_string()},
            "target": self.target.to_string(),
            "local-port": self.port.to_string(),
            "natreflection": "purenat",
            "pass": "pass",
            "descr": MARK,
        })
    }

    fn same(&self, l: &PortForward) -> bool {
        !l.disabled
            && l.interface == WAN
            && l.protocol.eq_ignore_ascii_case(self.protocol.wire())
            && l.destination == "wanip"
            && l.port == self.port.to_string()
            && l.target == self.target.to_string()
            && l.local_port == self.port.to_string()
    }
}

/// The outbound NAT rule making a forward reachable from the target's own network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReflectionRule {
    pub protocol: Protocol,
    pub port: u16,
    pub target: Ipv4Addr,
    /// The router's network the target sits in: `lan`. As a source it names that
    /// network's subnet, and `<network>ip` the router's address there — both follow a
    /// renumbering.
    pub network: String,
}

impl ReflectionRule {
    pub fn body(&self) -> Value {
        json!({
            "enabled": "1",
            "interface": self.network,
            "ipprotocol": "inet",
            "protocol": self.protocol.wire().to_ascii_uppercase(),
            "source_net": self.network,
            "destination_net": self.target.to_string(),
            "destination_port": self.port.to_string(),
            "target": format!("{}ip", self.network),
            "description": MARK,
        })
    }

    fn same(&self, l: &OutboundNat) -> bool {
        l.enabled
            && l.interface == self.network
            && l.protocol.eq_ignore_ascii_case(self.protocol.wire())
            && l.source_net == self.network
            && l.destination_net == self.target.to_string()
            && l.destination_port == self.port.to_string()
            && l.target == format!("{}ip", self.network)
    }
}

/// One change to the router's rules of one kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Edit<T> {
    Add(T),
    /// One of Homelabus's, written again: `was` is what it forwarded to.
    Update {
        uuid: String,
        to: T,
        was: String,
    },
    /// One of Homelabus's for a port nothing publishes any more, or a second one.
    Remove {
        uuid: String,
        key: Key,
    },
}

/// What a sync would do.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Plan {
    pub forwards: Vec<Edit<ForwardRule>>,
    pub reflections: Vec<Edit<ReflectionRule>>,
    /// Ports already forwarded as they should be.
    pub unchanged: usize,
    /// A person's own forward takes the port: `(port, where it goes)`.
    pub theirs: Vec<(Key, String)>,
    /// Ports wanted and not forwarded, and why.
    pub refused: Vec<(Wanted, String)>,
}

/// What a listed rule is to the plan.
trait Listed {
    fn uuid(&self) -> &str;
    fn ours(&self) -> bool;
    /// `None` for a port that is no single number: never one of ours.
    fn key(&self) -> Option<Key>;
    fn was(&self) -> String;
}

impl Listed for PortForward {
    fn uuid(&self) -> &str {
        &self.uuid
    }
    fn ours(&self) -> bool {
        self.descr == MARK && !self.is_automatic
    }
    fn key(&self) -> Option<Key> {
        let port = self.port.parse().ok()?;
        [Protocol::Tcp, Protocol::Udp]
            .into_iter()
            .find(|p| self.protocol.eq_ignore_ascii_case(p.wire()))
            .map(|p| (p, port))
    }
    fn was(&self) -> String {
        self.target.clone()
    }
}

impl Listed for OutboundNat {
    fn uuid(&self) -> &str {
        &self.uuid
    }
    fn ours(&self) -> bool {
        self.description == MARK && !self.is_automatic
    }
    fn key(&self) -> Option<Key> {
        let port = self.destination_port.parse().ok()?;
        [Protocol::Tcp, Protocol::Udp]
            .into_iter()
            .find(|p| self.protocol.eq_ignore_ascii_case(p.wire()))
            .map(|p| (p, port))
    }
    fn was(&self) -> String {
        self.destination_net.clone()
    }
}

/// Whether a port `listed` (`25`, `1000:2000`, `1000-2000`) covers `port`. An alias
/// cannot be read here, and covers nothing.
fn covers(listed: &str, port: u16) -> bool {
    let listed = listed.trim();
    if let Ok(p) = listed.parse::<u16>() {
        return p == port;
    }
    listed
        .split_once([':', '-'])
        .and_then(|(a, b)| Some((a.trim().parse::<u16>().ok()?, b.trim().parse::<u16>().ok()?)))
        .is_some_and(|(a, b)| a <= port && port <= b)
}

/// The edits making `actual`'s rules of Homelabus's hold `wanted`, `held` keys left as
/// they are. Returns the edits and how many already held.
fn edits<W, L: Listed>(
    wanted: &[(Key, W)],
    held: &[Key],
    actual: &[L],
    same: impl Fn(&W, &L) -> bool,
) -> (Vec<Edit<W>>, usize)
where
    W: Clone,
{
    // Ours with a port that is no single number was edited by hand: left, as theirs.
    let ours: Vec<&L> = actual
        .iter()
        .filter(|l| l.ours() && l.key().is_some())
        .collect();
    let mut out = Vec::new();
    let mut unchanged = 0;
    for (key, want) in wanted {
        let mine: Vec<&&L> = ours.iter().filter(|l| l.key() == Some(*key)).collect();
        match mine.split_first() {
            None => out.push(Edit::Add(want.clone())),
            Some((first, rest)) => {
                if same(want, first) {
                    unchanged += 1;
                } else {
                    out.push(Edit::Update {
                        uuid: first.uuid().to_string(),
                        to: want.clone(),
                        was: first.was(),
                    });
                }
                for extra in rest {
                    out.push(Edit::Remove {
                        uuid: extra.uuid().to_string(),
                        key: *key,
                    });
                }
            }
        }
    }
    let mut gone: Vec<(Key, &str)> = ours
        .iter()
        .filter_map(|l| Some((l.key()?, l.uuid())))
        .filter(|(k, _)| !wanted.iter().any(|(w, _)| w == k) && !held.contains(k))
        .collect();
    gone.sort();
    for (key, uuid) in gone {
        out.push(Edit::Remove {
            uuid: uuid.to_string(),
            key,
        });
    }
    (out, unchanged)
}

/// The changes making the router forward each of `wanted`, given what it holds.
///
/// `held` are the ports of services not running now, whose rules stay as they are:
/// removed, a restart would find its port closed until the next sync. `guarded` is the
/// one port never forwarded — the router's own interface, when it is reached at its
/// WAN address. `reflect` is false where the router loads no rule written by hand.
pub fn plan(
    wanted: &[Wanted],
    held: &[Key],
    guarded: Option<Key>,
    networks: &[Network],
    forwards: &[PortForward],
    reflections: &[OutboundNat],
    reflect: bool,
) -> Plan {
    let mut out = Plan::default();
    let mut wanted: Vec<Wanted> = wanted.to_vec();
    wanted.sort_by(|a, b| (a.key(), &a.service).cmp(&(b.key(), &b.service)));

    let mut kept: Vec<(Wanted, String)> = Vec::new();
    for w in wanted {
        let key = w.key();
        if let Some((first, _)) = kept.iter().find(|(k, _)| k.key() == key) {
            let why = format!("{} already takes it", first.service);
            out.refused.push((w, why));
            continue;
        }
        if guarded == Some(key) {
            out.refused.push((
                w,
                "the router's own interface answers there, at its WAN address".to_string(),
            ));
            continue;
        }
        let theirs = forwards.iter().find(|l| {
            !l.ours()
                && !l.is_automatic
                && !l.disabled
                && l.interface == WAN
                && w.protocol.within(&l.protocol)
                && covers(&l.port, w.port)
        });
        if let Some(t) = theirs {
            if !out.theirs.iter().any(|(k, _)| *k == key) {
                out.theirs.push((key, t.target.clone()));
            }
            continue;
        }
        let Some((network, _)) = network_of(w.target, networks) else {
            let why = format!("{} is on none of the router's networks", w.target);
            out.refused.push((w, why));
            continue;
        };
        kept.push((w, network));
    }

    let rules: Vec<(Key, ForwardRule)> = kept
        .iter()
        .map(|(w, _)| {
            (
                w.key(),
                ForwardRule {
                    protocol: w.protocol,
                    port: w.port,
                    target: w.target,
                    service: w.service.clone(),
                },
            )
        })
        .collect();
    let (f, unchanged) = edits(&rules, held, forwards, ForwardRule::same);
    out.forwards = f;
    out.unchanged = unchanged;

    if reflect {
        let rules: Vec<(Key, ReflectionRule)> = kept
            .iter()
            .map(|(w, network)| {
                (
                    w.key(),
                    ReflectionRule {
                        protocol: w.protocol,
                        port: w.port,
                        target: w.target,
                        network: network.clone(),
                    },
                )
            })
            .collect();
        out.reflections = edits(&rules, held, reflections, ReflectionRule::same).0;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEB1: Ipv4Addr = Ipv4Addr::new(10, 77, 0, 11);
    const DEB2: Ipv4Addr = Ipv4Addr::new(10, 77, 0, 12);

    fn nets() -> Vec<Network> {
        let n = |id: &str, a: &str| Network {
            identifier: id.into(),
            description: String::new(),
            device: "vtnet0".into(),
            addr4: a.into(),
        };
        vec![n("lan", "10.77.0.3/24"), n("wan", "")]
    }

    fn want(protocol: Protocol, port: u16, target: Ipv4Addr, service: &str) -> Wanted {
        Wanted {
            protocol,
            port,
            target,
            service: service.into(),
        }
    }

    fn listed_forward(uuid: &str, rule: &ForwardRule) -> PortForward {
        PortForward {
            uuid: uuid.into(),
            disabled: false,
            interface: WAN.into(),
            protocol: rule.protocol.wire().into(),
            destination: "wanip".into(),
            port: rule.port.to_string(),
            target: rule.target.to_string(),
            local_port: rule.port.to_string(),
            descr: MARK.into(),
            is_automatic: false,
        }
    }

    fn listed_reflection(uuid: &str, rule: &ReflectionRule) -> OutboundNat {
        OutboundNat {
            uuid: uuid.into(),
            enabled: true,
            interface: rule.network.clone(),
            protocol: rule.protocol.wire().to_ascii_uppercase(),
            source_net: rule.network.clone(),
            destination_net: rule.target.to_string(),
            destination_port: rule.port.to_string(),
            target: format!("{}ip", rule.network),
            description: MARK.into(),
            is_automatic: false,
        }
    }

    fn smtp() -> Wanted {
        want(Protocol::Tcp, 25, DEB1, "stalwart")
    }

    fn forward_of(w: &Wanted) -> ForwardRule {
        ForwardRule {
            protocol: w.protocol,
            port: w.port,
            target: w.target,
            service: w.service.clone(),
        }
    }

    fn reflection_of(w: &Wanted) -> ReflectionRule {
        ReflectionRule {
            protocol: w.protocol,
            port: w.port,
            target: w.target,
            network: "lan".into(),
        }
    }

    #[test]
    fn a_published_port_is_forwarded_and_reflected_into_its_targets_network() {
        let p = plan(&[smtp()], &[], None, &nets(), &[], &[], true);
        assert_eq!(p.forwards, vec![Edit::Add(forward_of(&smtp()))]);
        assert_eq!(p.reflections, vec![Edit::Add(reflection_of(&smtp()))]);
        let body = forward_of(&smtp()).body();
        assert_eq!(body["destination"]["port"], "25");
        assert_eq!(body["local-port"], "25");
        assert_eq!(body["target"], "10.77.0.11");
        assert_eq!(body["descr"], MARK);
        let r = reflection_of(&smtp()).body();
        assert_eq!(
            (&r["source_net"], &r["target"], &r["protocol"]),
            (&json!("lan"), &json!("lanip"), &json!("TCP"))
        );
    }

    #[test]
    fn what_already_forwards_rightly_is_left() {
        let w = smtp();
        let p = plan(
            std::slice::from_ref(&w),
            &[],
            None,
            &nets(),
            &[listed_forward("f1", &forward_of(&w))],
            &[listed_reflection("r1", &reflection_of(&w))],
            true,
        );
        assert!(p.forwards.is_empty() && p.reflections.is_empty(), "{p:?}");
        assert_eq!(p.unchanged, 1);
    }

    #[test]
    fn a_service_moved_rewrites_its_rules_and_says_where_they_went() {
        let before = want(Protocol::Tcp, 25, DEB2, "stalwart");
        let p = plan(
            &[smtp()],
            &[],
            None,
            &nets(),
            &[listed_forward("f1", &forward_of(&before))],
            &[listed_reflection("r1", &reflection_of(&before))],
            true,
        );
        assert_eq!(
            p.forwards,
            vec![Edit::Update {
                uuid: "f1".into(),
                to: forward_of(&smtp()),
                was: "10.77.0.12".into()
            }]
        );
        assert!(matches!(p.reflections.as_slice(), [Edit::Update { .. }]));
    }

    #[test]
    fn a_port_no_longer_published_is_closed_unless_its_service_is_only_stopped() {
        let w = smtp();
        let rules = [listed_forward("f1", &forward_of(&w))];
        let gone = plan(&[], &[], None, &nets(), &rules, &[], true);
        assert_eq!(
            gone.forwards,
            vec![Edit::Remove {
                uuid: "f1".into(),
                key: (Protocol::Tcp, 25)
            }]
        );
        let held = plan(
            &[],
            &[(Protocol::Tcp, 25)],
            None,
            &nets(),
            &rules,
            &[],
            true,
        );
        assert!(held.forwards.is_empty(), "{held:?}");
    }

    #[test]
    fn a_persons_forward_is_never_touched_and_wins_its_port() {
        let mut theirs = listed_forward("p1", &forward_of(&smtp()));
        theirs.descr = "mail server".into();
        theirs.target = "192.168.1.20".into();
        let mut range = theirs.clone();
        range.uuid = "p2".into();
        range.protocol = "TCP/UDP".into();
        range.port = "7000:8000".into();
        let anti_lockout: PortForward = serde_json::from_str(
            r#"{"uuid":"lockout_2","ipprotocol":"","protocol":"tcp","disabled":"0","nordr":"1","interface":"lan","destination.network":"lanip","destination.port":"443","descr":"Anti-Lockout Rule","is_automatic":true}"#,
        )
        .expect("a row");
        let p = plan(
            &[
                smtp(),
                want(Protocol::Udp, 7882, DEB2, "livekit"),
                want(Protocol::Tcp, 443, DEB1, "caddy"),
            ],
            &[],
            None,
            &nets(),
            &[theirs, range, anti_lockout],
            &[],
            true,
        );
        assert_eq!(
            p.theirs,
            vec![
                ((Protocol::Tcp, 25), "192.168.1.20".into()),
                ((Protocol::Udp, 7882), "192.168.1.20".into())
            ]
        );
        assert_eq!(
            p.forwards,
            vec![Edit::Add(forward_of(&want(
                Protocol::Tcp,
                443,
                DEB1,
                "caddy"
            )))],
            "the anti-lockout rule is the LAN's, never a person's forward"
        );
    }

    #[test]
    fn the_routers_own_interface_is_never_forwarded_away() {
        let caddy = want(Protocol::Tcp, 443, DEB1, "caddy");
        let p = plan(
            std::slice::from_ref(&caddy),
            &[],
            Some((Protocol::Tcp, 443)),
            &nets(),
            &[],
            &[],
            true,
        );
        assert!(p.forwards.is_empty());
        assert_eq!(p.refused.len(), 1);
        assert_eq!(p.refused[0].0, caddy);
    }

    #[test]
    fn two_services_on_one_port_forward_to_the_first_and_refuse_the_second() {
        let p = plan(
            &[
                want(Protocol::Tcp, 25, DEB2, "zmail"),
                smtp(),
                want(Protocol::Udp, 25, DEB2, "zmail"),
            ],
            &[],
            None,
            &nets(),
            &[],
            &[],
            false,
        );
        assert_eq!(p.forwards.len(), 2, "tcp and udp are two ports: {p:?}");
        assert_eq!(p.refused.len(), 1);
        assert_eq!(p.refused[0].0.service, "zmail");
        assert!(
            p.reflections.is_empty(),
            "nothing reflected when told not to"
        );
    }

    #[test]
    fn a_target_off_the_routers_networks_is_refused() {
        let mesh = want(Protocol::Tcp, 25, Ipv4Addr::new(10, 42, 0, 2), "stalwart");
        let p = plan(&[mesh], &[], None, &nets(), &[], &[], true);
        assert!(p.forwards.is_empty());
        assert!(p.refused[0].1.contains("none of the router's networks"));
    }

    #[test]
    fn a_listed_reflection_reads_as_the_router_lists_it() {
        // As OPNsense 26.7 listed the probe written in lower case, in hybrid mode.
        let row = r#"{"uuid":"cc79","enabled":"1","nonat":"0","sequence":"200","interface":"lan","ipprotocol":"inet","protocol":"UDP","source_net":"lan","source_not":"0","source_port":"","destination_net":"10.77.0.11","destination_not":"0","destination_port":"4190","target":"lanip","target_port":"","description":"homelabus","category_colors":[]}"#;
        let l: OutboundNat = serde_json::from_str(row).expect("a row");
        let w = want(Protocol::Udp, 4190, DEB1, "stalwart");
        assert!(reflection_of(&w).same(&l));
        assert_eq!(l.key(), Some((Protocol::Udp, 4190)));
        let automatic = r#"{"uuid":"automatic_wan","enabled":"1","interface":"wan","protocol":"any","source_net":"lan,lo0","destination_net":"any","destination_port":"","target":"wanip","description":"Auto created rule","is_automatic":true}"#;
        let a: OutboundNat = serde_json::from_str(automatic).expect("a row");
        assert!(a.is_automatic && !a.ours());
    }
}
