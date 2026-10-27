//! The hosts Termix should hold — one per node — against those it holds.
//!
//! Only hosts carrying [`TAG`] are Homelabus's: one a person made in the same account
//! is never touched. A node gone from the cluster takes its host with it.

use crate::client::Host;

/// What marks a host, and a credential, as Homelabus's.
pub const TAG: &str = "homelabus";
pub const FOLDER: &str = "Homelabus";

/// The Termix roles `OIDC_ROLE_MAP` gives at sign-in — `group:role` entries, split on
/// commas or lines and at the LAST colon, as Termix reads them — sorted, once each.
/// They are who the hosts are shared with: the map is the one place saying who gets
/// in, so the roles are read from it rather than named a second time.
pub fn mapped_roles(role_map: &str) -> Vec<String> {
    let mut out: Vec<String> = role_map
        .split([',', '\n'])
        .filter_map(|e| e.trim().rsplit_once(':'))
        .filter(|(group, role)| !group.trim().is_empty() && !role.trim().is_empty())
        .map(|(_, role)| role.trim().to_string())
        .collect();
    out.sort();
    out.dedup();
    out
}

/// The host a node should have: `addr` is where Termix reaches it.
pub fn wanted(hostname: &str, addr: &str, account: &str, credential: i64) -> Host {
    Host {
        id: 0,
        name: hostname.to_string(),
        ip: addr.to_string(),
        port: 22,
        username: account.to_string(),
        credential_id: Some(credential),
        share_ssh_auth: true,
        folder: Some(FOLDER.into()),
        tags: vec![TAG.into()],
        notes: Some(
            "A node of the cluster, kept by Homelabus: changed here, it is put back; \
             removed when the node leaves."
                .into(),
        ),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    Create(Host),
    /// What differs, by name.
    Update {
        id: i64,
        host: Host,
        what: Vec<&'static str>,
    },
    /// Its node left the cluster.
    Delete {
        id: i64,
        name: String,
    },
    Same {
        id: i64,
        name: String,
    },
}

fn differences(have: &Host, want: &Host) -> Vec<&'static str> {
    let mut what = Vec::new();
    if have.ip != want.ip || have.port != want.port {
        what.push("address");
    }
    if have.username != want.username {
        what.push("account");
    }
    if have.credential_id != want.credential_id {
        what.push("key");
    }
    if have.share_ssh_auth != want.share_ssh_auth {
        what.push("shared sign-in");
    }
    if have.folder != want.folder || !have.tags.iter().any(|t| t == TAG) {
        what.push("folder");
    }
    what
}

/// Each wanted host against Homelabus's hosts in Termix, matched by name; then the
/// hosts no node wants any more. Sorted by name, so a preview reads the same twice.
pub fn plan(wanted: &[Host], held: &[Host]) -> Vec<Change> {
    let ours: Vec<&Host> = held
        .iter()
        .filter(|h| h.tags.iter().any(|t| t == TAG))
        .collect();
    let mut out: Vec<Change> = wanted
        .iter()
        .map(|w| match ours.iter().find(|h| h.name == w.name) {
            None => Change::Create(w.clone()),
            Some(h) => {
                let what = differences(h, w);
                if what.is_empty() {
                    Change::Same {
                        id: h.id,
                        name: h.name.clone(),
                    }
                } else {
                    Change::Update {
                        id: h.id,
                        host: w.clone(),
                        what,
                    }
                }
            }
        })
        .collect();
    out.extend(
        ours.iter()
            .filter(|h| !wanted.iter().any(|w| w.name == h.name))
            .map(|h| Change::Delete {
                id: h.id,
                name: h.name.clone(),
            }),
    );
    out.sort_by(|a, b| name(a).cmp(name(b)));
    out
}

fn name(c: &Change) -> &str {
    match c {
        Change::Create(h) | Change::Update { host: h, .. } => &h.name,
        Change::Delete { name, .. } | Change::Same { name, .. } => name,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(name: &str, addr: &str) -> Host {
        wanted(name, addr, "hlb-termix", 7)
    }

    fn held(id: i64, h: Host) -> Host {
        Host { id, ..h }
    }

    #[test]
    fn the_roles_are_read_as_termix_reads_its_map() {
        assert_eq!(
            mapped_roles("admin:homelabus-nodes, ops:a:b\nbad, :x, y: ,admin:homelabus-nodes"),
            vec!["b".to_string(), "homelabus-nodes".to_string()]
        );
        assert!(mapped_roles("").is_empty());
    }

    #[test]
    fn a_node_gone_takes_its_host_with_it() {
        let have = vec![
            held(1, node("deb1", "10.42.0.1")),
            held(2, node("deb2", "10.42.0.2")),
        ];
        let p = plan(&[node("deb1", "10.42.0.1")], &have);
        assert_eq!(
            p,
            vec![
                Change::Same {
                    id: 1,
                    name: "deb1".into()
                },
                Change::Delete {
                    id: 2,
                    name: "deb2".into()
                },
            ]
        );
    }

    #[test]
    fn a_host_a_person_made_is_never_touched() {
        let mut theirs = held(9, node("nas", "192.168.1.5"));
        theirs.tags = vec!["home".into()];
        assert!(plan(&[], &[theirs]).is_empty());
    }

    #[test]
    fn a_moved_node_or_a_new_key_is_rewritten_and_says_what() {
        let mut have = held(1, node("deb1", "10.42.0.1"));
        have.credential_id = Some(3);
        have.share_ssh_auth = false;
        let p = plan(&[node("deb1", "10.42.0.9")], &[have]);
        let [Change::Update { id: 1, what, .. }] = p.as_slice() else {
            panic!("{p:?}");
        };
        assert_eq!(what, &vec!["address", "key", "shared sign-in"]);
    }

    #[test]
    fn a_new_node_gets_a_host_and_the_plan_is_sorted() {
        let p = plan(&[node("deb2", "b"), node("deb1", "a")], &[]);
        assert!(
            matches!(p.as_slice(), [Change::Create(a), Change::Create(b)] if a.name == "deb1" && b.name == "deb2")
        );
    }
}
