//! The house's networks beyond the trusted one: one for its devices (a television, a
//! console, what speaks to a cloud of its own), one for its guests. Each a VLAN tagged on
//! the trusted network's port, so a VLAN-aware switch or access point carries all three
//! on the router's one LAN cable.
//!
//! What Homelabus makes there, each step once the one before holds:
//!
//! 1. The VLAN, on the device of the network Caddy is on, with the tag declared.
//! 2. Its assignment: an interface of the router's (`opt1`…) on that VLAN.
//! 3. — a person's: the interface enabled and given its address. 🔴 OPNsense 26.7 has no
//!    API for an interface's addressing (`interfaces/assignment` takes a device and a
//!    name, nothing more; the rest is the legacy page's), so Homelabus says what to do
//!    and reads the address back. The router is where the address lives.
//! 4. A DHCP range of dnsmasq's on it, its names under [`DOMAIN`].
//!
//! The network is recognised by its VLAN's tag and parent, whoever made it: a VLAN a
//! person made with the declared tag IS the declared network.

use std::net::Ipv4Addr;

use serde::Deserialize;
use serde_json::{json, Value};

use crate::client::Network;

/// The description of what Homelabus writes. ⚠️ A stored value: the router keeps it.
pub const MARK: &str = crate::names::MARK;

/// The domain a machine's name is registered under by DHCP (RFC 8375): never the
/// internet's, never the house's public zone.
pub const DOMAIN: &str = "home.arpa";

/// How far into a network the range starts: the first addresses stay a person's, for a
/// machine they number by hand.
const RANGE_OFFSET: u32 = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Kind {
    Devices,
    Guests,
}

impl Kind {
    /// ⚠️ A stored value: the state keys its declaration by it.
    pub fn wire(self) -> &'static str {
        match self {
            Self::Devices => "devices",
            Self::Guests => "guests",
        }
    }

    pub fn from_wire(s: &str) -> Option<Self> {
        match s {
            "devices" => Some(Self::Devices),
            "guests" => Some(Self::Guests),
            _ => None,
        }
    }

    /// The interface's description on the router, as its pages show it.
    pub fn label(self) -> &'static str {
        match self {
            Self::Devices => "Devices",
            Self::Guests => "Guests",
        }
    }
}

/// A VLAN, as `interfaces/vlan_settings/search_item` lists it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Vlan {
    pub uuid: String,
    /// Its parent device: `vtnet0`.
    #[serde(rename = "if")]
    pub parent: String,
    pub tag: String,
    /// The device it is, named by the router: `vlan01`.
    pub vlanif: String,
    #[serde(default)]
    pub descr: String,
}

/// The VLAN Homelabus writes: the router names its device.
pub fn vlan_body(kind: Kind, parent: &str, tag: u16) -> Value {
    json!({
        "if": parent,
        "tag": tag.to_string(),
        "pcp": "0",
        "descr": format!("{MARK} {}", kind.wire()),
    })
}

/// The VLAN tagged `tag` on `parent`, whoever made it.
pub fn vlan_of<'a>(vlans: &'a [Vlan], parent: &str, tag: u16) -> Option<&'a Vlan> {
    vlans
        .iter()
        .find(|v| v.parent == parent && v.tag.trim() == tag.to_string())
}

/// The router's interface on `device`. The overview lists an unassigned device too,
/// with no identifier: that one is no interface yet.
pub fn interface_of<'a>(networks: &'a [Network], device: &str) -> Option<&'a Network> {
    networks
        .iter()
        .find(|n| n.device == device && !n.identifier.is_empty())
}

/// What a person does on the router for a network Homelabus cannot address itself.
pub fn address_steps(kind: Kind, identifier: &str, tag: u16) -> String {
    let example = if tag <= 255 {
        format!(" (192.168.{tag}.1/24, say)")
    } else {
        String::new()
    };
    format!(
        "the router's API cannot address an interface: on its pages, Interfaces → {} \
         ({identifier}) → Enable, IPv4 Configuration Type \"Static IPv4\", the router's \
         address on it{example} → Save → Apply changes. Then `hlb router sync --apply`.",
        kind.label()
    )
}

/// A dnsmasq DHCP range, as `dnsmasq/settings/search_range` lists it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct DhcpRange {
    pub uuid: String,
    /// `lan`, `opt1`; empty for any.
    #[serde(default)]
    pub interface: String,
    pub start_addr: String,
    #[serde(default)]
    pub end_addr: String,
    #[serde(default)]
    pub domain: String,
    #[serde(default)]
    pub description: String,
}

impl DhcpRange {
    fn ours(&self) -> bool {
        self.description == MARK
    }

    /// An IPv6 range (`::1000`) is the router's advertisement's, never a network's
    /// IPv4 range.
    fn v4(&self) -> bool {
        self.start_addr.parse::<Ipv4Addr>().is_ok()
    }
}

/// The range Homelabus writes on a network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RangeRule {
    pub kind: Kind,
    /// The router's interface: `opt1`.
    pub interface: String,
    pub start: Ipv4Addr,
    pub end: Ipv4Addr,
}

impl RangeRule {
    pub fn body(&self) -> Value {
        json!({
            "interface": self.interface,
            "start_addr": self.start.to_string(),
            "end_addr": self.end.to_string(),
            "domain_type": "range",
            "domain": DOMAIN,
            "description": MARK,
        })
    }

    fn same(&self, l: &DhcpRange) -> bool {
        l.interface == self.interface
            && l.start_addr == self.start.to_string()
            && l.end_addr == self.end.to_string()
            && l.domain == DOMAIN
    }
}

/// The range a network the router is at `addr4` (`192.168.20.1/24`) hands out: from
/// [`RANGE_OFFSET`] in to the last address but the broadcast, the router's own outside it.
pub fn range_of(addr4: &str) -> Result<(Ipv4Addr, Ipv4Addr), String> {
    let (own, len) = addr4
        .split_once('/')
        .ok_or_else(|| format!("{addr4} is no address and prefix"))?;
    let own: Ipv4Addr = own
        .parse()
        .map_err(|_| format!("{addr4} is no IPv4 address"))?;
    let len: u32 = len
        .parse()
        .ok()
        .filter(|l| (8..=27).contains(l))
        .ok_or_else(|| format!("{addr4}: a network between /8 and /27 leaves room for a range"))?;
    let mask = u32::MAX << (32 - len);
    let network = u32::from(own) & mask;
    let broadcast = network | !mask;
    let start = network + RANGE_OFFSET;
    let mut end = broadcast - 1;
    let router = u32::from(own);
    if router == end {
        end -= 1;
    }
    if (start..=end).contains(&router) {
        return Err(format!(
            "the router is at {own}, inside the range a network that size hands out \
             ({}–{}): give it the network's first address, or its last",
            Ipv4Addr::from(start),
            Ipv4Addr::from(end)
        ));
    }
    Ok((Ipv4Addr::from(start), Ipv4Addr::from(end)))
}

/// One change to the ranges.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RangeEdit {
    Add(RangeRule),
    Update {
        uuid: String,
        to: RangeRule,
        was: String,
    },
    /// One of Homelabus's on a network no longer declared, or a second one.
    Remove {
        uuid: String,
        interface: String,
    },
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RangePlan {
    pub edits: Vec<RangeEdit>,
    pub unchanged: usize,
    /// A person's own range on the network: `(interface, its addresses)`. It hands out
    /// that network's addresses, and Homelabus writes none beside it.
    pub theirs: Vec<(String, String)>,
}

/// The edits making the router's ranges of Homelabus's hold `wanted`.
pub fn ranges(wanted: &[RangeRule], actual: &[DhcpRange]) -> RangePlan {
    let mut out = RangePlan::default();
    let ours: Vec<&DhcpRange> = actual.iter().filter(|l| l.ours()).collect();
    let mut kept: Vec<&str> = Vec::new();
    for w in wanted {
        if let Some(t) = actual
            .iter()
            .find(|l| !l.ours() && l.v4() && l.interface == w.interface)
        {
            out.theirs.push((
                w.interface.clone(),
                format!("{}–{}", t.start_addr, t.end_addr),
            ));
            continue;
        }
        kept.push(&w.interface);
        let mine: Vec<&&DhcpRange> = ours.iter().filter(|l| l.interface == w.interface).collect();
        match mine.split_first() {
            None => out.edits.push(RangeEdit::Add(w.clone())),
            Some((first, rest)) => {
                if w.same(first) {
                    out.unchanged += 1;
                } else {
                    out.edits.push(RangeEdit::Update {
                        uuid: first.uuid.clone(),
                        to: w.clone(),
                        was: format!("{}–{}", first.start_addr, first.end_addr),
                    });
                }
                for extra in rest {
                    out.edits.push(RangeEdit::Remove {
                        uuid: extra.uuid.clone(),
                        interface: extra.interface.clone(),
                    });
                }
            }
        }
    }
    for gone in ours
        .iter()
        .filter(|l| !wanted.iter().any(|w| w.interface == l.interface))
    {
        out.edits.push(RangeEdit::Remove {
            uuid: gone.uuid.clone(),
            interface: gone.interface.clone(),
        });
    }
    // A range of someone else's on a network: Homelabus's own there would hand out a
    // second pool, so it goes.
    for (iface, _) in &out.theirs {
        if kept.contains(&iface.as_str()) {
            continue;
        }
        for mine in ours.iter().filter(|l| &l.interface == iface) {
            out.edits.push(RangeEdit::Remove {
                uuid: mine.uuid.clone(),
                interface: iface.clone(),
            });
        }
    }
    out
}

/// What of dnsmasq's general settings Homelabus reads and writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dnsmasq {
    pub enabled: bool,
    /// Where it listens; empty for every interface.
    pub interfaces: Vec<String>,
}

/// The settings making dnsmasq serve `ours` too, or `None` when it already does.
///
/// 🔴 Turned on, dnsmasq serves every range on every interface it listens on — and a
/// fresh router holds one on its LAN (192.168.1.100–199). Off until now, it is made to
/// listen on Homelabus's networks alone: whatever it held for the LAN stays unserved,
/// as it was. On already, it keeps listening where it did.
pub fn dnsmasq_wanted(current: &Dnsmasq, ours: &[String]) -> Option<Dnsmasq> {
    if ours.is_empty() {
        return None;
    }
    let mut interfaces: Vec<String> = if current.enabled {
        if current.interfaces.is_empty() {
            return None;
        }
        current.interfaces.clone()
    } else {
        Vec::new()
    };
    for o in ours {
        if !interfaces.contains(o) {
            interfaces.push(o.clone());
        }
    }
    interfaces.sort();
    let mut was = current.interfaces.clone();
    was.sort();
    let wanted = Dnsmasq {
        enabled: true,
        interfaces,
    };
    (!(current.enabled && was == wanted.interfaces)).then_some(wanted)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(identifier: &str, device: &str, addr4: &str) -> Network {
        Network {
            identifier: identifier.into(),
            description: String::new(),
            device: device.into(),
            addr4: addr4.into(),
        }
    }

    fn rule(interface: &str, start: [u8; 4], end: [u8; 4]) -> RangeRule {
        RangeRule {
            kind: Kind::Devices,
            interface: interface.into(),
            start: start.into(),
            end: end.into(),
        }
    }

    fn listed(uuid: &str, r: &RangeRule) -> DhcpRange {
        DhcpRange {
            uuid: uuid.into(),
            interface: r.interface.clone(),
            start_addr: r.start.to_string(),
            end_addr: r.end.to_string(),
            domain: DOMAIN.into(),
            description: MARK.into(),
        }
    }

    #[test]
    fn a_kind_reads_back_from_what_is_stored() {
        for k in [Kind::Devices, Kind::Guests] {
            assert_eq!(Kind::from_wire(k.wire()), Some(k));
        }
        assert_eq!(Kind::from_wire("trusted"), None);
    }

    #[test]
    fn a_vlan_is_found_by_its_tag_and_parent_whoever_made_it() {
        // As OPNsense 26.7 listed one made on the lab.
        let row = r#"{"uuid":"0cde","if":"vtnet0","%if":"vtnet0 (52:54:00:77:00:03) [LAN]","tag":"20","pcp":"0","%pcp":"Best Effort (0, default)","proto":"","descr":"probe","vlanif":"vlan01"}"#;
        let v: Vlan = serde_json::from_str(row).expect("a row");
        let vlans = [v];
        assert_eq!(
            vlan_of(&vlans, "vtnet0", 20).map(|v| v.vlanif.as_str()),
            Some("vlan01")
        );
        assert!(vlan_of(&vlans, "vtnet1", 20).is_none());
        assert!(vlan_of(&vlans, "vtnet0", 30).is_none());
        let body = vlan_body(Kind::Guests, "vtnet0", 30);
        assert_eq!(
            (&body["if"], &body["tag"]),
            (&json!("vtnet0"), &json!("30"))
        );
    }

    #[test]
    fn an_unassigned_device_is_no_interface() {
        let networks = [net("lan", "vtnet0", "10.77.0.3/24"), net("", "vlan01", "")];
        assert!(interface_of(&networks, "vlan01").is_none());
        let assigned = [net("opt1", "vlan01", "")];
        assert_eq!(
            interface_of(&assigned, "vlan01").map(|n| n.identifier.as_str()),
            Some("opt1")
        );
    }

    #[test]
    fn a_range_leaves_the_router_and_the_first_addresses_out() {
        assert_eq!(
            range_of("192.168.20.1/24"),
            Ok(([192, 168, 20, 10].into(), [192, 168, 20, 254].into()))
        );
        assert_eq!(
            range_of("192.168.20.254/24"),
            Ok(([192, 168, 20, 10].into(), [192, 168, 20, 253].into()))
        );
        assert_eq!(
            range_of("10.20.0.1/16"),
            Ok(([10, 20, 0, 10].into(), [10, 20, 255, 254].into()))
        );
        assert!(range_of("192.168.20.100/24")
            .expect_err("inside")
            .contains("inside the range"));
        assert!(range_of("192.168.20.1/28").is_err(), "too small for one");
        assert!(range_of("").is_err());
    }

    #[test]
    fn a_network_gets_one_range_and_keeps_it() {
        let w = rule("opt1", [192, 168, 20, 10], [192, 168, 20, 254]);
        let p = ranges(std::slice::from_ref(&w), &[]);
        assert_eq!(p.edits, vec![RangeEdit::Add(w.clone())]);
        let body = w.body();
        assert_eq!(
            (&body["domain"], &body["description"]),
            (&json!(DOMAIN), &json!(MARK))
        );
        let again = ranges(std::slice::from_ref(&w), &[listed("r1", &w)]);
        assert!(again.edits.is_empty(), "{again:?}");
        assert_eq!(again.unchanged, 1);
    }

    #[test]
    fn a_renumbered_network_moves_its_range_and_a_dropped_one_loses_it() {
        let before = rule("opt1", [192, 168, 20, 10], [192, 168, 20, 254]);
        let after = rule("opt1", [10, 20, 0, 10], [10, 20, 0, 254]);
        let p = ranges(std::slice::from_ref(&after), &[listed("r1", &before)]);
        assert_eq!(
            p.edits,
            vec![RangeEdit::Update {
                uuid: "r1".into(),
                to: after,
                was: "192.168.20.10–192.168.20.254".into()
            }]
        );
        let gone = ranges(&[], &[listed("r1", &before)]);
        assert_eq!(
            gone.edits,
            vec![RangeEdit::Remove {
                uuid: "r1".into(),
                interface: "opt1".into()
            }]
        );
    }

    #[test]
    fn a_persons_range_on_the_network_is_left_and_wins_it() {
        let w = rule("opt1", [192, 168, 20, 10], [192, 168, 20, 254]);
        let mut theirs = listed("p1", &w);
        theirs.description = "my devices".into();
        theirs.start_addr = "192.168.20.50".into();
        // The router's own IPv6 range on the LAN, from its first boot.
        let v6: DhcpRange = serde_json::from_str(
            r#"{"uuid":"a3a4","interface":"lan","start_addr":"::1000","end_addr":"::2000","domain":"","description":""}"#,
        )
        .expect("a row");
        let p = ranges(
            &[w.clone(), rule("lan", [10, 77, 0, 10], [10, 77, 0, 254])],
            &[theirs, listed("r1", &w), v6],
        );
        assert_eq!(
            p.theirs,
            vec![(
                "opt1".to_string(),
                "192.168.20.50–192.168.20.254".to_string()
            )]
        );
        assert!(
            p.edits.contains(&RangeEdit::Remove {
                uuid: "r1".into(),
                interface: "opt1".into()
            }),
            "two pools on one network: ours goes, {p:?}"
        );
        assert!(
            p.edits
                .iter()
                .any(|e| matches!(e, RangeEdit::Add(r) if r.interface == "lan")),
            "an IPv6 range is no IPv4 one's: {p:?}"
        );
    }

    #[test]
    fn dnsmasq_turned_on_listens_on_homelabuss_networks_alone() {
        let off = Dnsmasq {
            enabled: false,
            interfaces: vec!["lan".into()],
        };
        assert_eq!(
            dnsmasq_wanted(&off, &["opt2".into(), "opt1".into()]),
            Some(Dnsmasq {
                enabled: true,
                interfaces: vec!["opt1".into(), "opt2".into()]
            }),
            "the LAN's first-boot range stays unserved"
        );
        let on = Dnsmasq {
            enabled: true,
            interfaces: vec!["lan".into()],
        };
        assert_eq!(
            dnsmasq_wanted(&on, &["opt1".into()]),
            Some(Dnsmasq {
                enabled: true,
                interfaces: vec!["lan".into(), "opt1".into()]
            })
        );
        let done = Dnsmasq {
            enabled: true,
            interfaces: vec!["opt1".into(), "lan".into()],
        };
        assert_eq!(dnsmasq_wanted(&done, &["opt1".into()]), None);
        let everywhere = Dnsmasq {
            enabled: true,
            interfaces: vec![],
        };
        assert_eq!(dnsmasq_wanted(&everywhere, &["opt1".into()]), None);
        assert_eq!(dnsmasq_wanted(&off, &[]), None, "nothing of ours: left");
    }
}
