//! What the house's other networks may reach: the router's DNS, Caddy for the devices
//! network, the internet — never the trusted network, nor the router itself.
//!
//! Written on the interfaces Homelabus made ([`crate::networks`]) and on none other:
//! the trusted network, which the router's API is reached by, keeps whatever it had, so
//! no sync can lock Homelabus out of the router.
//!
//! The rules, read first to last on each network's interface:
//!
//! | Role | Rule |
//! |---|---|
//! | `dns` | pass TCP/UDP 53 to the router's address on the network |
//! | `caddy-80`, `caddy-443` | devices only: pass TCP to Caddy's address |
//! | `router` | block whatever else is for the router (`(self)`: every address of its) |
//! | `private-…` | block each range no internet host is in |
//! | `internet` | pass the rest |
//!
//! DHCP needs none: the router passes it itself on an interface dnsmasq serves.
//!
//! 🔴 One rule per range: a rule's network field takes a list of NAMES (`opt1`,
//! `(self)`, an alias) but a literal network only alone — `10.0.0.0/8,172.16.0.0/12`
//! is refused "not a valid source IP address or alias" (26.7, measured). An alias
//! would hold the list, and a rule naming an alias a person removed loads nothing.

use serde::Deserialize;
use serde_json::{json, Value};
use std::net::Ipv4Addr;

use crate::networks::Kind;

/// ⚠️ A stored value: every rule's description is `"{MARK} {role}"`.
pub const MARK: &str = crate::names::MARK;

/// Where Homelabus's rules sit among the router's. pf reads an interface's rules by
/// sequence, the first matching one deciding; the router numbers a new rule after every
/// other (the highest plus 100), so a person's own rule on one of these networks is read
/// AFTER Homelabus's unless given a sequence below this.
pub const SEQUENCE: u32 = 300_000;

/// The ranges no host of the internet's is in: RFC 1918's, and the shared address space
/// (RFC 6598) a provider's own network may number the router's upstream in.
pub const PRIVATE: [&str; 4] = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "100.64.0.0/10",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Role {
    Dns,
    Caddy(u16),
    Router,
    /// An index into [`PRIVATE`].
    Private(usize),
    Internet,
}

impl Role {
    /// ⚠️ A stored value: the rule's description carries it.
    pub fn wire(self) -> String {
        match self {
            Self::Dns => "dns".into(),
            Self::Caddy(port) => format!("caddy-{port}"),
            Self::Router => "router".into(),
            Self::Private(i) => format!("private-{}", PRIVATE.get(i).copied().unwrap_or("?")),
            Self::Internet => "internet".into(),
        }
    }

    fn offset(self) -> u32 {
        match self {
            Self::Dns => 10,
            Self::Caddy(port) => 20 + u32::from(port == 443),
            Self::Router => 30,
            Self::Private(i) => 31 + u32::try_from(i).unwrap_or(0),
            Self::Internet => 90,
        }
    }

    /// What it does, as a sync reports it.
    pub fn says(self, caddy: Option<Ipv4Addr>) -> String {
        match self {
            Self::Dns => "may ask the router's DNS".into(),
            Self::Caddy(port) => match caddy {
                Some(c) => format!("may reach Caddy at {c}:{port}"),
                None => format!("may reach Caddy on {port}"),
            },
            Self::Router => "may reach nothing else of the router's".into(),
            Self::Private(i) => format!("may not reach {}", PRIVATE.get(i).copied().unwrap_or("?")),
            Self::Internet => "may reach the internet".into(),
        }
    }
}

/// A filter rule, as `firewall/filter/search_rule` lists it — beside the router's own,
/// generated ones (`legacy`, `is_automatic`), which are never anyone's to change.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Listed {
    pub uuid: String,
    #[serde(default, deserialize_with = "crate::client::flag")]
    pub enabled: bool,
    #[serde(default)]
    pub sequence: String,
    #[serde(default)]
    pub action: String,
    #[serde(default, deserialize_with = "crate::client::flag")]
    pub quick: bool,
    /// One interface or several, comma-separated: `opt1`, `lan,opt1`.
    #[serde(default)]
    pub interface: String,
    #[serde(default)]
    pub direction: String,
    #[serde(default)]
    pub ipprotocol: String,
    /// `TCP/UDP`, `any`.
    #[serde(default)]
    pub protocol: String,
    #[serde(default)]
    pub source_net: String,
    #[serde(default)]
    pub destination_net: String,
    #[serde(default)]
    pub destination_port: String,
    #[serde(default)]
    pub description: String,
    #[serde(default, deserialize_with = "crate::client::truthy")]
    pub legacy: bool,
    #[serde(default, deserialize_with = "crate::client::truthy")]
    pub is_automatic: bool,
}

impl Listed {
    fn generated(&self) -> bool {
        self.legacy || self.is_automatic
    }

    /// Its role, when it is one of Homelabus's.
    fn role(&self) -> Option<&str> {
        if self.generated() {
            return None;
        }
        self.description
            .strip_prefix(MARK)
            .and_then(|r| r.strip_prefix(' '))
    }

    fn on(&self, interface: &str) -> bool {
        self.interface.split(',').any(|i| i.trim() == interface)
    }
}

/// A rule Homelabus writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub kind: Kind,
    /// The router's interface: `opt1`.
    pub interface: String,
    pub role: Role,
    pub caddy: Option<Ipv4Addr>,
}

impl Rule {
    fn sequence(&self) -> u32 {
        let network = match self.kind {
            Kind::Devices => 0,
            Kind::Guests => 1_000,
        };
        SEQUENCE + network + self.role.offset()
    }

    fn action(&self) -> &'static str {
        match self.role {
            Role::Dns | Role::Caddy(_) | Role::Internet => "pass",
            Role::Router | Role::Private(_) => "block",
        }
    }

    fn protocol(&self) -> &'static str {
        match self.role {
            Role::Dns => "TCP/UDP",
            Role::Caddy(_) => "TCP",
            Role::Router | Role::Private(_) | Role::Internet => "any",
        }
    }

    fn destination(&self) -> String {
        match self.role {
            Role::Dns => format!("{}ip", self.interface),
            Role::Caddy(_) => self
                .caddy
                .map_or_else(|| "(self)".into(), |c| c.to_string()),
            Role::Router => "(self)".into(),
            Role::Private(i) => PRIVATE.get(i).copied().unwrap_or_default().into(),
            Role::Internet => "any".into(),
        }
    }

    fn port(&self) -> String {
        match self.role {
            Role::Dns => "53".into(),
            Role::Caddy(port) => port.to_string(),
            Role::Router | Role::Private(_) | Role::Internet => String::new(),
        }
    }

    pub fn description(&self) -> String {
        format!("{MARK} {}", self.role.wire())
    }

    /// As `firewall/filter/add_rule` takes it. The source is the network's own subnet,
    /// named by its interface: it follows a renumbering.
    pub fn body(&self) -> Value {
        json!({
            "enabled": "1",
            "sequence": self.sequence().to_string(),
            "action": self.action(),
            "quick": "1",
            "interface": self.interface,
            "direction": "in",
            "ipprotocol": "inet",
            "protocol": self.protocol(),
            "source_net": self.interface,
            "destination_net": self.destination(),
            "destination_port": self.port(),
            "description": self.description(),
        })
    }

    fn same(&self, l: &Listed) -> bool {
        l.enabled
            && l.quick
            && l.sequence.trim() == self.sequence().to_string()
            && l.action == self.action()
            && l.interface == self.interface
            && l.direction == "in"
            && l.ipprotocol == "inet"
            && l.protocol.eq_ignore_ascii_case(self.protocol())
            && l.source_net == self.interface
            && l.destination_net == self.destination()
            && l.destination_port == self.port()
    }
}

/// The rules a network on `interface` is held to, first to last. Caddy's address is
/// the devices network's alone to reach.
pub fn rules_for(kind: Kind, interface: &str, caddy: Ipv4Addr) -> Vec<Rule> {
    let rule = |role| Rule {
        kind,
        interface: interface.to_string(),
        role,
        caddy: matches!(role, Role::Caddy(_)).then_some(caddy),
    };
    let mut out = vec![rule(Role::Dns)];
    match kind {
        Kind::Devices => out.extend([rule(Role::Caddy(80)), rule(Role::Caddy(443))]),
        Kind::Guests => {}
    }
    out.push(rule(Role::Router));
    out.extend((0..PRIVATE.len()).map(|i| rule(Role::Private(i))));
    out.push(rule(Role::Internet));
    out
}

/// One change to the filter rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Edit {
    Add(Rule),
    /// One of Homelabus's, written again.
    Update {
        uuid: String,
        to: Rule,
    },
    /// One of Homelabus's on a network no longer declared, for a role it no longer has,
    /// or a second one.
    Remove {
        uuid: String,
        interface: String,
        description: String,
    },
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Plan {
    pub edits: Vec<Edit>,
    pub unchanged: usize,
    /// A person's own rules on one of these networks: `(interface, description,
    /// sequence)`. Left; whether they are read before Homelabus's is their sequence's.
    pub theirs: Vec<(String, String, String)>,
}

/// The edits making the router's rules of Homelabus's hold `wanted`.
pub fn plan(wanted: &[Rule], actual: &[Listed]) -> Plan {
    let mut out = Plan::default();
    let ours: Vec<&Listed> = actual.iter().filter(|l| l.role().is_some()).collect();
    let mut kept: Vec<&str> = Vec::new();
    for w in wanted {
        let wire = w.role.wire();
        let mine: Vec<&&Listed> = ours
            .iter()
            .filter(|l| l.on(&w.interface) && l.role() == Some(wire.as_str()))
            .collect();
        match mine.split_first() {
            None => out.edits.push(Edit::Add(w.clone())),
            Some((first, rest)) => {
                kept.push(&first.uuid);
                if w.same(first) {
                    out.unchanged += 1;
                } else {
                    out.edits.push(Edit::Update {
                        uuid: first.uuid.clone(),
                        to: w.clone(),
                    });
                }
                for extra in rest {
                    kept.push(&extra.uuid);
                    out.edits.push(Edit::Remove {
                        uuid: extra.uuid.clone(),
                        interface: w.interface.clone(),
                        description: extra.description.clone(),
                    });
                }
            }
        }
    }
    for gone in ours.iter().filter(|l| !kept.contains(&l.uuid.as_str())) {
        out.edits.push(Edit::Remove {
            uuid: gone.uuid.clone(),
            interface: gone.interface.clone(),
            description: gone.description.clone(),
        });
    }
    let mut interfaces: Vec<&str> = wanted.iter().map(|w| w.interface.as_str()).collect();
    interfaces.sort_unstable();
    interfaces.dedup();
    for i in interfaces {
        for t in actual
            .iter()
            .filter(|l| !l.generated() && l.role().is_none() && l.on(i))
        {
            out.theirs.push((
                i.to_string(),
                t.description.clone(),
                t.sequence.trim().to_string(),
            ));
        }
    }
    out
}

/// Whether a person's rule at `sequence` is read before Homelabus's.
pub fn read_first(sequence: &str) -> bool {
    sequence.trim().parse::<u32>().is_ok_and(|s| s < SEQUENCE)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CADDY: Ipv4Addr = Ipv4Addr::new(10, 77, 0, 11);

    fn listed(uuid: &str, r: &Rule) -> Listed {
        let b = r.body();
        let s = |k: &str| b[k].as_str().unwrap_or_default().to_string();
        Listed {
            uuid: uuid.into(),
            enabled: true,
            sequence: s("sequence"),
            action: s("action"),
            quick: true,
            interface: s("interface"),
            direction: s("direction"),
            ipprotocol: s("ipprotocol"),
            protocol: s("protocol"),
            source_net: s("source_net"),
            destination_net: s("destination_net"),
            destination_port: s("destination_port"),
            description: s("description"),
            legacy: false,
            is_automatic: false,
        }
    }

    fn order(rules: &[Rule]) -> Vec<(u32, String)> {
        let mut v: Vec<(u32, String)> = rules
            .iter()
            .map(|r| (r.sequence(), r.role.wire()))
            .collect();
        v.sort();
        v
    }

    #[test]
    fn a_network_reaches_dns_then_caddy_before_anything_private_is_blocked() {
        let devices = rules_for(Kind::Devices, "opt1", CADDY);
        let roles: Vec<String> = order(&devices).into_iter().map(|(_, r)| r).collect();
        assert_eq!(
            roles,
            [
                "dns",
                "caddy-80",
                "caddy-443",
                "router",
                "private-10.0.0.0/8",
                "private-172.16.0.0/12",
                "private-192.168.0.0/16",
                "private-100.64.0.0/10",
                "internet"
            ]
        );
        let guests = rules_for(Kind::Guests, "opt2", CADDY);
        assert!(
            guests.iter().all(|r| !matches!(r.role, Role::Caddy(_))),
            "guests reach no app of the house's"
        );
        let dns = devices[0].body();
        assert_eq!(
            (
                &dns["destination_net"],
                &dns["destination_port"],
                &dns["source_net"]
            ),
            (&json!("opt1ip"), &json!("53"), &json!("opt1"))
        );
        let caddy = devices[1].body();
        assert_eq!(caddy["destination_net"], "10.77.0.11");
        assert!(
            order(&devices)
                .iter()
                .chain(order(&guests).iter())
                .all(|(s, _)| *s > SEQUENCE),
            "every rule after a person's set below the mark"
        );
    }

    #[test]
    fn a_rule_reads_back_as_the_router_lists_it() {
        // As OPNsense 26.7 listed the probe written on the lab.
        let row = r#"{"uuid":"5220","enabled":"1","statetype":"keep","sequence":"300010","sort_order":"400000.0300010","prio_group":"400000","action":"pass","%action":"Pass","quick":"1","interfacenot":"0","interface":"opt1","%interface":"Devices","direction":"in","ipprotocol":"inet","protocol":"TCP/UDP","source_net":"opt1","source_not":"0","destination_net":"opt1ip","destination_not":"0","destination_port":"53","description":"homelabus dns","category_colors":[]}"#;
        let l: Listed = serde_json::from_str(row).expect("a row");
        let dns = &rules_for(Kind::Devices, "opt1", CADDY)[0];
        assert!(dns.same(&l), "{l:?}");
        assert_eq!(l.role(), Some("dns"));
        let generated = r#"{"log":true,"ipprotocol":"inet","enabled":"1","action":"pass","description":"homelabus dns","interface":"opt1","uuid":"d31a","direction":"in","legacy":true,"is_automatic":true}"#;
        let g: Listed = serde_json::from_str(generated).expect("a row");
        assert_eq!(g.role(), None, "the router's own is nobody's");
    }

    #[test]
    fn a_held_network_is_left_and_a_moved_caddy_rewritten() {
        let wanted = rules_for(Kind::Devices, "opt1", CADDY);
        let actual: Vec<Listed> = wanted
            .iter()
            .enumerate()
            .map(|(i, r)| listed(&format!("u{i}"), r))
            .collect();
        let p = plan(&wanted, &actual);
        assert!(p.edits.is_empty(), "{p:?}");
        assert_eq!(p.unchanged, wanted.len());

        let moved = rules_for(Kind::Devices, "opt1", Ipv4Addr::new(10, 77, 0, 12));
        let p = plan(&moved, &actual);
        assert_eq!(
            p.edits
                .iter()
                .map(|e| match e {
                    Edit::Update { uuid, .. } => uuid.as_str(),
                    _ => "other",
                })
                .collect::<Vec<_>>(),
            ["u1", "u2"],
            "Caddy's two rules, nothing else: {p:?}"
        );
    }

    #[test]
    fn a_rule_a_person_reordered_is_put_back_and_a_dropped_network_loses_its_rules() {
        let wanted = rules_for(Kind::Guests, "opt2", CADDY);
        let mut actual: Vec<Listed> = wanted
            .iter()
            .enumerate()
            .map(|(i, r)| listed(&format!("u{i}"), r))
            .collect();
        actual[0].sequence = "999999".into();
        let p = plan(&wanted, &actual);
        assert!(matches!(p.edits.as_slice(), [Edit::Update { uuid, .. }] if uuid == "u0"));

        let gone = plan(&[], &actual);
        assert_eq!(gone.edits.len(), wanted.len());
        assert!(gone
            .edits
            .iter()
            .all(|e| matches!(e, Edit::Remove { interface, .. } if interface == "opt2")));
    }

    #[test]
    fn a_persons_rule_is_left_and_said_with_where_it_is_read() {
        let wanted = rules_for(Kind::Devices, "opt1", CADDY);
        let mut theirs = listed("p1", &wanted[0]);
        theirs.description = "tv to nas".into();
        theirs.sequence = "100".into();
        let mut lan = theirs.clone();
        lan.uuid = "p2".into();
        lan.interface = "lan".into();
        let mut twice = listed("d1", &wanted[0]);
        twice.sequence = "5".into();
        let p = plan(&wanted, &[theirs, lan, listed("d0", &wanted[0]), twice]);
        assert_eq!(
            p.theirs,
            vec![("opt1".into(), "tv to nas".into(), "100".into())],
            "the LAN's rules are no network of Homelabus's"
        );
        assert!(read_first("100") && !read_first("300500") && !read_first(""));
        assert!(
            p.edits.contains(&Edit::Remove {
                uuid: "d1".into(),
                interface: "opt1".into(),
                description: "homelabus dns".into()
            }),
            "a second dns rule goes: {p:?}"
        );
    }
}
