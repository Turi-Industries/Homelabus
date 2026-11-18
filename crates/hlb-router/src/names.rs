//! The house's names, answered inside the house: each name Caddy serves resolves to
//! Caddy's own address on the house's network, by an Unbound host override.
//!
//! Without it, a name resolves to the front door — the VPS — and a client at home goes
//! out and comes back: through a router that does not loop back (many do not), not at
//! all; and a private route, which the relayed listener refuses to everyone, never.
//!
//! What is Homelabus's is marked ([`MARK`]) and only that is changed or removed. A
//! person's own override for a name is left as it is, and said: it answers that name
//! whatever Homelabus would write.

use std::net::Ipv4Addr;

use crate::client::{HostOverride, Network};

/// The description of every override Homelabus writes, and how it knows its own.
/// ⚠️ A stored value: the router keeps it.
pub const MARK: &str = "homelabus";

/// One change to the router's overrides.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    Add(HostOverride),
    /// One of Homelabus's, written again: `was` is the address it answered.
    Update {
        uuid: String,
        to: HostOverride,
        was: String,
    },
    /// One of Homelabus's for a name Caddy no longer serves, or a second one for a name.
    Remove {
        uuid: String,
        fqdn: String,
    },
}

/// What a sync would do.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Plan {
    pub changes: Vec<Change>,
    /// Names already answered as they should be.
    pub unchanged: Vec<String>,
    /// A person's own override answers the name: `(name, what it answers)`.
    pub theirs: Vec<(String, String)>,
}

/// `gitea.example.org` → (`gitea`, `example.org`); a name of one label has no domain.
fn split(fqdn: &str) -> Option<(&str, &str)> {
    fqdn.split_once('.')
        .filter(|(h, d)| !h.is_empty() && !d.is_empty())
}

fn normal(name: &str) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// The override Homelabus writes for `fqdn`; `None` for a name of one label.
pub fn wanted(fqdn: &str, address: Ipv4Addr) -> Option<HostOverride> {
    let fqdn = normal(fqdn);
    let (hostname, domain) = split(&fqdn)?;
    Some(HostOverride {
        uuid: String::new(),
        enabled: true,
        hostname: hostname.to_string(),
        domain: domain.to_string(),
        rr: "A".to_string(),
        server: address.to_string(),
        addptr: false,
        description: MARK.to_string(),
    })
}

fn same(a: &HostOverride, b: &HostOverride) -> bool {
    a.enabled == b.enabled
        && a.rr == b.rr
        && a.server == b.server
        && a.addptr == b.addptr
        && a.fqdn() == b.fqdn()
}

/// The changes making the router answer each of `names` with `address`, given what it
/// holds. Sorted by name: the same state plans the same changes.
pub fn plan(names: &[String], address: Ipv4Addr, actual: &[HostOverride]) -> Plan {
    let mut names: Vec<String> = names.iter().map(|n| normal(n)).collect();
    names.sort();
    names.dedup();

    let mut out = Plan::default();
    let (ours, others): (Vec<&HostOverride>, Vec<&HostOverride>) =
        actual.iter().partition(|o| o.description == MARK);

    for name in &names {
        let Some(want) = wanted(name, address) else {
            continue;
        };
        // A person's, enabled, for the very name: theirs to answer.
        if let Some(t) = others.iter().find(|o| o.enabled && o.fqdn() == *name) {
            let answers = if t.server.is_empty() {
                t.rr.clone()
            } else {
                t.server.clone()
            };
            out.theirs.push((name.clone(), answers));
            continue;
        }
        let mine: Vec<&&HostOverride> = ours.iter().filter(|o| o.fqdn() == *name).collect();
        match mine.split_first() {
            None => out.changes.push(Change::Add(want)),
            Some((first, rest)) => {
                if same(first, &want) {
                    out.unchanged.push(name.clone());
                } else {
                    out.changes.push(Change::Update {
                        uuid: first.uuid.clone(),
                        was: first.server.clone(),
                        to: want,
                    });
                }
                for extra in rest {
                    out.changes.push(Change::Remove {
                        uuid: extra.uuid.clone(),
                        fqdn: name.clone(),
                    });
                }
            }
        }
    }

    let mut gone: Vec<&&HostOverride> =
        ours.iter().filter(|o| !names.contains(&o.fqdn())).collect();
    gone.sort_by_key(|o| (o.fqdn(), o.uuid.clone()));
    for o in gone {
        out.changes.push(Change::Remove {
            uuid: o.uuid.clone(),
            fqdn: o.fqdn(),
        });
    }
    // Same name in theirs AND a stale one of ours: ours goes, theirs answers.
    for (name, _) in &out.theirs {
        for o in ours.iter().filter(|o| o.fqdn() == *name) {
            out.changes.push(Change::Remove {
                uuid: o.uuid.clone(),
                fqdn: name.clone(),
            });
        }
    }
    out
}

/// The router's network `address` sits in, as `(identifier, its own address)`. Caddy's
/// address must be one the router reaches directly — a mesh address is not.
pub fn network_of(address: Ipv4Addr, networks: &[Network]) -> Option<(String, String)> {
    networks.iter().find_map(|n| {
        let (own, len) = n.addr4.split_once('/')?;
        let own: Ipv4Addr = own.parse().ok()?;
        let len: u32 = len.parse().ok().filter(|l| *l <= 32)?;
        let mask = if len == 0 { 0 } else { u32::MAX << (32 - len) };
        (u32::from(own) & mask == u32::from(address) & mask)
            .then(|| (n.identifier.clone(), own.to_string()))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const CADDY: Ipv4Addr = Ipv4Addr::new(10, 77, 0, 11);

    fn ours(uuid: &str, fqdn: &str, server: &str) -> HostOverride {
        let mut o = wanted(fqdn, server.parse().expect("an address")).expect("a name");
        o.uuid = uuid.to_string();
        o
    }

    fn names(n: &[&str]) -> Vec<String> {
        n.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn each_name_caddy_serves_is_added_once() {
        let p = plan(
            &names(&[
                "Gitea.Example.org.",
                "gitea.example.org",
                "vault.example.org",
            ]),
            CADDY,
            &[],
        );
        assert_eq!(p.changes.len(), 2);
        let Change::Add(o) = &p.changes[0] else {
            panic!("an addition: {:?}", p.changes[0]);
        };
        assert_eq!(
            (o.hostname.as_str(), o.domain.as_str()),
            ("gitea", "example.org")
        );
        assert_eq!(o.server, "10.77.0.11");
        assert!(!o.addptr, "one address cannot carry a reverse name per app");
        assert_eq!(o.description, MARK);
    }

    #[test]
    fn what_already_answers_rightly_is_left() {
        let p = plan(
            &names(&["gitea.example.org"]),
            CADDY,
            &[ours("u1", "gitea.example.org", "10.77.0.11")],
        );
        assert!(p.changes.is_empty());
        assert_eq!(p.unchanged, names(&["gitea.example.org"]));
    }

    #[test]
    fn caddy_moved_rewrites_ours_and_says_where_it_was() {
        let p = plan(
            &names(&["gitea.example.org"]),
            CADDY,
            &[ours("u1", "gitea.example.org", "10.77.0.12")],
        );
        assert_eq!(p.changes.len(), 1);
        let Change::Update { uuid, was, to } = &p.changes[0] else {
            panic!("an update: {:?}", p.changes[0]);
        };
        assert_eq!(
            (uuid.as_str(), was.as_str(), to.server.as_str()),
            ("u1", "10.77.0.12", "10.77.0.11")
        );
    }

    #[test]
    fn a_name_no_longer_served_is_removed_and_a_duplicate_too() {
        let p = plan(
            &names(&["gitea.example.org"]),
            CADDY,
            &[
                ours("u1", "gitea.example.org", "10.77.0.11"),
                ours("u2", "gitea.example.org", "10.77.0.11"),
                ours("u3", "old.example.org", "10.77.0.11"),
            ],
        );
        assert_eq!(
            p.changes,
            vec![
                Change::Remove {
                    uuid: "u2".into(),
                    fqdn: "gitea.example.org".into()
                },
                Change::Remove {
                    uuid: "u3".into(),
                    fqdn: "old.example.org".into()
                },
            ]
        );
    }

    #[test]
    fn a_persons_override_is_never_touched_and_wins_its_name() {
        let mut theirs = ours("p1", "gitea.example.org", "192.168.1.50");
        theirs.description = "my own".into();
        let mut unrelated = ours("p2", "printer.example.org", "192.168.1.9");
        unrelated.description = String::new();
        let p = plan(&names(&["gitea.example.org"]), CADDY, &[theirs, unrelated]);
        assert!(p.changes.is_empty(), "{:?}", p.changes);
        assert_eq!(
            p.theirs,
            vec![("gitea.example.org".into(), "192.168.1.50".into())]
        );
    }

    #[test]
    fn a_persons_disabled_override_does_not_hold_the_name() {
        let mut theirs = ours("p1", "gitea.example.org", "192.168.1.50");
        theirs.description = "my own".into();
        theirs.enabled = false;
        let p = plan(&names(&["gitea.example.org"]), CADDY, &[theirs]);
        assert!(matches!(p.changes.as_slice(), [Change::Add(_)]));
    }

    #[test]
    fn caddy_must_sit_in_one_of_the_routers_networks() {
        let n = |id: &str, a: &str| Network {
            identifier: id.into(),
            description: String::new(),
            device: "vtnet0".into(),
            addr4: a.into(),
        };
        let nets = [n("wan", ""), n("lan", "10.77.0.3/24")];
        assert_eq!(
            network_of(CADDY, &nets),
            Some(("lan".into(), "10.77.0.3".into()))
        );
        assert_eq!(
            network_of(Ipv4Addr::new(10, 42, 0, 2), &nets),
            None,
            "a mesh address"
        );
    }
}
