//! What PocketID and the apps should hold, computed from Homelabus's own records.
//!
//! The roles, the people holding them and the roles each installed app lets in are
//! Homelabus's; PocketID's groups, their claims, each client's restriction, a quota
//! inside Seafile are copies of it. This computes what the copies should be — the
//! executor reads what they are and changes the difference — so the whole rule is
//! here, testable without a server.
//!
//! ## 🔴 Closed unless a role is allowed
//!
//! An app no role is allowed into lets nobody in: a native client is restricted to an
//! empty set of groups, a route behind the portal answers 403. Never the opposite —
//! PocketID's restriction turned OFF and oauth2-proxy's `allowed_groups` left EMPTY
//! both mean "everyone". And a role the app is said to allow that does not exist closes
//! the app rather than being skipped: whoever typed it meant someone to get in, and
//! "the others still can" is not what anyone decided.

use std::collections::{BTreeMap, BTreeSet};

use hlb_types::access::{group_of, RoleView};
use hlb_types::capability::PORTAL_SERVICE;
use hlb_types::{Capability, Manifest, Role, SsoMode};
use serde_json::Value;

use crate::RoleDef;

/// A person, as the sync needs them.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Person {
    pub name: String,
    /// Their PocketID id — the `sub` every app knows them by. `None` until the identity
    /// exists.
    pub sub: Option<String>,
    /// Their default mailbox, the address PocketID gives the apps.
    pub email: Option<String>,
    pub role: Option<String>,
    /// Per app, a quota given to them over their role's: `Some(None)` is "none at all".
    pub quotas: BTreeMap<String, Option<u64>>,
}

/// An installed app, and the roles it lets in.
#[derive(Debug, Clone)]
pub struct Installed<'a> {
    pub manifest: &'a Manifest,
    pub allowed: BTreeSet<String>,
}

/// How an app is entered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Entry {
    /// Its own OIDC client: PocketID refuses whoever is in none of the groups.
    Client,
    /// The portal's: Caddy asks oauth2-proxy with the groups at every request.
    Portal,
}

/// Who may enter an app: the groups, and none means closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Door {
    pub entry: Entry,
    pub groups: BTreeSet<String>,
}

impl Door {
    pub fn closed(&self) -> bool {
        self.groups.is_empty()
    }
}

/// One role's group in PocketID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    pub role: String,
    pub friendly_name: String,
    /// PocketID ids.
    pub members: BTreeSet<String>,
    pub claims: BTreeMap<String, Value>,
}

/// A quota to set inside one app, for one person.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuotaTask {
    pub app: String,
    pub person: String,
    pub sub: String,
    /// `None`: no quota.
    pub bytes: Option<u64>,
    /// Given to the person themselves, rather than their role's.
    pub own: bool,
}

/// Whether one person administers one app, for an app that is told by command
/// (`access.admins.apply`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminTask {
    pub app: String,
    pub person: String,
    pub sub: String,
    pub admin: bool,
}

/// A member Homelabus keeps inside an app.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Member {
    pub email: String,
    /// The Homelabus account — what the app's import keys the member on.
    pub external_id: String,
}

/// A group of an app's members: one per role the app lets in.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct MemberGroup {
    /// The role's PocketID group name (`hlb-<id>`): stable, as the role's id is.
    pub external_id: String,
    /// The role's name, as people read it.
    pub name: String,
    /// The members' external ids — their Homelabus accounts.
    pub members: Vec<String>,
}

/// What the computation could not do as asked, said rather than guessed around.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Note {
    /// The app is said to allow a role that does not exist: it is closed.
    UnknownRole { app: String, role: String },
    /// A role below the app's floor is never let in.
    BelowFloor {
        app: String,
        role: String,
        floor: Role,
    },
    /// Not in PocketID yet: in no group, so in no app.
    NoIdentity { person: String },
    /// No address to invite them by.
    NoEmail { app: String, person: String },
    /// Mail is in use and no administrator has a mailbox: `postmaster@` reaches nobody.
    NobodyReadsPostmaster,
}

impl std::fmt::Display for Note {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownRole { app, role } => write!(
                f,
                "{app} is said to let in the role \"{role}\", which does not exist: it is \
                 closed until that is corrected — `hlb role deny {role} {app} --apply`"
            ),
            Self::BelowFloor { app, role, floor } => write!(
                f,
                "{app} lets in \"{floor}\" roles and above: \"{role}\" is below, and stays out",
                floor = floor.as_str()
            ),
            Self::NoIdentity { person } => write!(
                f,
                "{person} has no PocketID identity yet: in no group, so in no app — \
                 `hlb user add {person} --apply` finishes the account"
            ),
            Self::NoEmail { app, person } => write!(
                f,
                "{person} has no mailbox: {app} invites by address, and is not told about them"
            ),
            Self::NobodyReadsPostmaster => write!(
                f,
                "no administrator has a mailbox: postmaster@ and abuse@, where other servers \
                 report this one, are read by nobody"
            ),
        }
    }
}

/// Everything the copies should hold.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Desired {
    /// By group name.
    pub groups: BTreeMap<String, Group>,
    /// A person's own claims, by PocketID id — only the keys in [`Self::person_claims`]:
    /// the others are not Homelabus's and are left as they are.
    pub claims_of: BTreeMap<String, BTreeMap<String, Value>>,
    /// The claim names a person's own claims may carry from Homelabus.
    pub person_claims: BTreeSet<String>,
    /// By app.
    pub doors: BTreeMap<String, Door>,
    pub quotas: Vec<QuotaTask>,
    /// Every person with an identity, in each app told its administrators by command:
    /// those who are, and those who are not — a role lowered, or taken away, takes the
    /// right back.
    pub admins: Vec<AdminTask>,
    /// By app.
    pub members: BTreeMap<String, Vec<Member>>,
    /// By app: a group per role it lets in, beside its members.
    pub member_groups: BTreeMap<String, Vec<MemberGroup>>,
    /// The mailboxes that open each mail domain's `postmaster@`: every administrator's.
    /// Other servers write there about this one's mail, and only someone who can act on
    /// it should read it.
    pub postmaster: BTreeSet<String>,
    pub notes: Vec<Note>,
}

/// How the app is entered through PocketID, if it is.
pub fn entry_of(m: &Manifest) -> Option<Entry> {
    if m.metadata.name == PORTAL_SERVICE {
        // The portal's own client signs in for every app behind it; each route is
        // checked on its own.
        return None;
    }
    m.spec.requires.iter().find_map(|c| match c {
        Capability::Sso { mode, .. } => match mode {
            SsoMode::Native => Some(Entry::Client),
            SsoMode::ProxyOnly | SsoMode::ProxyHeader => Some(Entry::Portal),
            SsoMode::None => None,
        },
        _ => None,
    })
}

/// The lowest level a role must hold to be let into the app.
pub fn floor_of(m: &Manifest) -> Role {
    m.spec.access.as_ref().map(|a| a.floor).unwrap_or_default()
}

/// Why this role may not be let into the app, if it may not.
pub fn refusal(role: &RoleDef, m: &Manifest) -> Option<String> {
    let app = &m.metadata.name;
    if entry_of(m).is_none() {
        return Some(format!(
            "{app} signs nobody in through PocketID: who enters it is not a role's to decide"
        ));
    }
    let floor = floor_of(m);
    (role.level < floor).then(|| {
        format!(
            "{app} lets in \"{}\" roles and above; \"{}\" is \"{}\"",
            floor.as_str(),
            role.label(),
            role.level.as_str()
        )
    })
}

fn view(r: &RoleDef) -> RoleView<'_> {
    RoleView {
        id: &r.id,
        name: &r.name,
        level: r.level,
    }
}

/// What PocketID and the apps should hold.
pub fn desired(roles: &[RoleDef], people: &[Person], apps: &[Installed<'_>]) -> Desired {
    let mut d = Desired::default();
    let by_id: BTreeMap<&str, &RoleDef> = roles.iter().map(|r| (r.id.as_str(), r)).collect();

    for r in roles {
        d.groups.insert(
            group_of(&r.id),
            Group {
                role: r.id.clone(),
                friendly_name: r.name.clone(),
                members: BTreeSet::new(),
                claims: BTreeMap::new(),
            },
        );
    }
    for p in people {
        let Some(role) = p.role.as_deref().filter(|r| by_id.contains_key(r)) else {
            continue;
        };
        if let (Some(email), Some(r)) = (&p.email, by_id.get(role)) {
            if r.level == Role::Admin {
                d.postmaster.insert(email.clone());
            }
        }
        match &p.sub {
            Some(sub) => {
                if let Some(g) = d.groups.get_mut(&group_of(role)) {
                    g.members.insert(sub.clone());
                }
            }
            None => d.notes.push(Note::NoIdentity {
                person: p.name.clone(),
            }),
        }
    }

    if d.postmaster.is_empty() && people.iter().any(|p| p.email.is_some()) {
        d.notes.push(Note::NobodyReadsPostmaster);
    }

    for app in apps {
        let m = app.manifest;
        let name = m.metadata.name.as_str();
        let Some(entry) = entry_of(m) else { continue };
        let floor = floor_of(m);
        let access = m.spec.access.clone().unwrap_or_default();

        let mut unknown = false;
        let mut admitted: Vec<&RoleDef> = Vec::new();
        for id in &app.allowed {
            match by_id.get(id.as_str()) {
                None => {
                    unknown = true;
                    d.notes.push(Note::UnknownRole {
                        app: name.into(),
                        role: id.clone(),
                    });
                }
                Some(r) if r.level < floor => d.notes.push(Note::BelowFloor {
                    app: name.into(),
                    role: id.clone(),
                    floor,
                }),
                Some(r) => admitted.push(r),
            }
        }
        if unknown {
            admitted.clear();
        }
        d.doors.insert(
            name.into(),
            Door {
                entry,
                groups: admitted.iter().map(|r| group_of(&r.id)).collect(),
            },
        );

        // What the app is told about each role it lets in. A role it does not let in
        // carries none of its claims: Gitea's required claim then refuses it too.
        for r in &admitted {
            let Some(g) = d.groups.get_mut(&group_of(&r.id)) else {
                continue;
            };
            for (claim, how) in &access.claims {
                if let Some(v) = how.value_for(view(r)) {
                    g.claims.insert(claim.clone(), v);
                }
            }
            let quota_claim = access.quota.as_ref().and_then(|q| q.claim.as_ref());
            if let (Some(c), Some(bytes)) = (quota_claim, r.quotas.get(name)) {
                g.claims.insert(c.name.clone(), c.unit.claim_value(*bytes));
            }
        }

        let admitted_ids: BTreeSet<&str> = admitted.iter().map(|r| r.id.as_str()).collect();
        let inside: Vec<&Person> = people
            .iter()
            .filter(|p| p.role.as_deref().is_some_and(|r| admitted_ids.contains(r)))
            .collect();

        if let Some(q) = &access.quota {
            if let Some(c) = &q.claim {
                d.person_claims.insert(c.name.clone());
            }
            for p in &inside {
                let Some(sub) = &p.sub else { continue };
                let own = p.quotas.get(name).copied();
                let role_quota = p
                    .role
                    .as_deref()
                    .and_then(|r| by_id.get(r))
                    .and_then(|r| r.quotas.get(name).copied());
                // PocketID gives a person's claim over their group's. 🔴 Never `null`
                // for "none at all": PocketID 2.18 fails on a null claim when it builds
                // the token, and a person's claims go to EVERY app they sign in to —
                // one quota would have shut them out of all of them. Their role's
                // claim stands at creation, and `apply` sets "none" after.
                if let (Some(c), Some(Some(bytes))) = (&q.claim, own) {
                    d.claims_of
                        .entry(sub.clone())
                        .or_default()
                        .insert(c.name.clone(), c.unit.claim_value(bytes));
                }
                if q.apply.is_some() {
                    d.quotas.push(QuotaTask {
                        app: name.into(),
                        person: p.name.clone(),
                        sub: sub.clone(),
                        bytes: own.unwrap_or(role_quota),
                        own: own.is_some(),
                    });
                }
            }
        }

        if let Some(admins) = access.admins.as_ref().filter(|a| a.apply.is_some()) {
            for p in people {
                let Some(sub) = &p.sub else { continue };
                let admin = inside.iter().any(|i| i.name == p.name)
                    && p.role
                        .as_deref()
                        .and_then(|r| by_id.get(r))
                        .is_some_and(|r| r.level >= admins.level);
                d.admins.push(AdminTask {
                    app: name.into(),
                    person: p.name.clone(),
                    sub: sub.clone(),
                    admin,
                });
            }
        }

        if access.members.is_some() {
            let mut members = Vec::new();
            for p in &inside {
                match &p.email {
                    Some(email) => members.push(Member {
                        email: email.clone(),
                        external_id: p.name.clone(),
                    }),
                    None => d.notes.push(Note::NoEmail {
                        app: name.into(),
                        person: p.name.clone(),
                    }),
                }
            }
            members.sort();
            let mut groups: Vec<MemberGroup> = admitted
                .iter()
                .map(|r| MemberGroup {
                    external_id: group_of(&r.id),
                    name: r.name.clone(),
                    members: inside
                        .iter()
                        .filter(|p| p.role.as_deref() == Some(r.id.as_str()) && p.email.is_some())
                        .map(|p| p.name.clone())
                        .collect(),
                })
                .collect();
            groups.sort();
            d.member_groups.insert(name.into(), groups);
            d.members.insert(name.into(), members);
        }
    }
    d
}

/// What giving this role opens beyond Homelabus: each installed app it administers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Opening {
    pub app: String,
    pub display_name: String,
    pub means: String,
}

/// The apps a role administers — listed before it is given, or before its level is
/// raised, so "admin" is read as what it is: Gitea's every repository, every machine's
/// SSH access in Termix. Computed from the manifests, never from a list.
pub fn opens(role: &RoleDef, apps: &[Installed<'_>]) -> Vec<Opening> {
    apps.iter()
        .filter(|a| a.allowed.contains(&role.id) && refusal(role, a.manifest).is_none())
        .filter_map(|a| {
            let admins = a.manifest.spec.access.as_ref()?.admins.as_ref()?;
            (role.level >= admins.level).then(|| Opening {
                app: a.manifest.metadata.name.clone(),
                display_name: a
                    .manifest
                    .metadata
                    .display_name
                    .clone()
                    .unwrap_or_else(|| a.manifest.metadata.name.clone()),
                means: admins.means.clone(),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MailLimits;

    fn manifest(name: &str, sso: &str, access: &str) -> Manifest {
        serde_yaml_ng::from_str(&format!(
            "apiVersion: hlb/v1\nkind: App\nmetadata: {{ name: {name}, displayName: {name}! }}\n\
             spec:\n  image: {{ repo: a/{name}, tag: \"1\" }}\n  requires: [ {sso} ]\n{access}"
        ))
        .expect("manifest")
    }

    const NATIVE: &str = "{ kind: sso, mode: native, redirectPaths: [/cb] }";
    const PORTAL: &str = "{ kind: sso, mode: proxy-only }";

    fn role(id: &str, level: Role) -> RoleDef {
        RoleDef::new(id, level, MailLimits::standard())
    }

    fn person(name: &str, role: &str) -> Person {
        Person {
            name: name.into(),
            sub: Some(format!("sub-{name}")),
            email: Some(format!("{name}@example.org")),
            role: Some(role.into()),
            quotas: BTreeMap::new(),
        }
    }

    fn allowing<'a>(m: &'a Manifest, roles: &[&str]) -> Installed<'a> {
        Installed {
            manifest: m,
            allowed: roles.iter().map(|r| r.to_string()).collect(),
        }
    }

    #[test]
    fn an_app_told_by_command_learns_who_administers_it_and_who_no_longer_does() {
        let m = manifest(
            "chat",
            NATIVE,
            "  access:\n    admins:\n      level: admin\n      means: everything\n      \
             apply: { grant: [g, \"{{ person.sub }}\"], revoke: [r, \"{{ person.sub }}\"] }\n",
        );
        let roles = [
            role("family", Role::User),
            role("owners", Role::Admin),
            role("guests", Role::User),
        ];
        let mut nobody = person("nobody", "guests");
        nobody.sub = None;
        let people = [
            person("ada", "owners"),
            person("bob", "family"),
            // Not let into the app at all: still told, so a right given before goes.
            person("cyd", "guests"),
            nobody,
        ];
        let d = desired(&roles, &people, &[allowing(&m, &["family", "owners"])]);
        let said: Vec<(&str, bool)> = d
            .admins
            .iter()
            .map(|t| (t.person.as_str(), t.admin))
            .collect();
        assert_eq!(said, [("ada", true), ("bob", false), ("cyd", false)]);
        assert!(d
            .admins
            .iter()
            .all(|t| t.app == "chat" && t.sub == format!("sub-{}", t.person)));

        // An app that reads a claim instead is told nothing by command.
        let claimed = manifest(
            "other",
            NATIVE,
            "  access:\n    admins: { level: admin, means: x }\n",
        );
        assert!(desired(&roles, &people, &[allowing(&claimed, &["owners"])])
            .admins
            .is_empty());
    }

    #[test]
    fn postmaster_is_read_by_every_administrator_with_a_mailbox_and_nobody_else() {
        let roles = [role("owner", Role::Admin), role("family", Role::User)];
        let mut nomail = person("lena", "owner");
        nomail.email = None;
        let d = desired(
            &roles,
            &[person("ana", "owner"), person("bob", "family"), nomail],
            &[],
        );
        assert_eq!(
            d.postmaster,
            BTreeSet::from(["ana@example.org".to_string()])
        );
        assert!(!d.notes.contains(&Note::NobodyReadsPostmaster));

        let d = desired(&roles, &[person("bob", "family")], &[]);
        assert!(d.postmaster.is_empty());
        assert!(d.notes.contains(&Note::NobodyReadsPostmaster));
        // No mailbox anywhere: mail is not in use, and nothing is said.
        let mut bob = person("bob", "family");
        bob.email = None;
        assert!(desired(&roles, &[bob], &[]).notes.is_empty());
    }

    #[test]
    fn an_app_no_role_is_allowed_into_is_closed() {
        let gitea = manifest("gitea", NATIVE, "");
        let n8n = manifest("n8n", PORTAL, "");
        let d = desired(
            &[role("family", Role::User)],
            &[person("lena", "family")],
            &[allowing(&gitea, &[]), allowing(&n8n, &[])],
        );
        assert!(d.doors["gitea"].closed());
        assert!(
            d.doors["n8n"].closed(),
            "an empty allowed_groups is everyone: never sent"
        );
        assert_eq!(d.doors["n8n"].entry, Entry::Portal);
    }

    #[test]
    fn a_role_that_does_not_exist_closes_the_app() {
        let gitea = manifest("gitea", NATIVE, "");
        let d = desired(
            &[role("family", Role::User)],
            &[],
            &[allowing(&gitea, &["family", "famly"])],
        );
        assert!(
            d.doors["gitea"].closed(),
            "family is let in only if what was typed is all true"
        );
        assert!(matches!(&d.notes[..], [Note::UnknownRole { role, .. }] if role == "famly"));
    }

    #[test]
    fn a_role_below_the_floor_stays_out_and_is_said_to() {
        let termix = manifest("termix", NATIVE, "  access: { floor: admin }\n");
        let d = desired(
            &[role("family", Role::User), role("admins", Role::Admin)],
            &[],
            &[allowing(&termix, &["family", "admins"])],
        );
        assert_eq!(
            d.doors["termix"].groups,
            BTreeSet::from(["hlb-admins".to_string()])
        );
        assert!(d
            .notes
            .iter()
            .any(|n| matches!(n, Note::BelowFloor { role, .. } if role == "family")));
        assert!(refusal(&role("family", Role::User), &termix).is_some());
        assert!(refusal(&role("admins", Role::Admin), &termix).is_none());
    }

    #[test]
    fn each_role_is_a_group_of_its_people_carrying_its_claims() {
        let gitea = manifest(
            "gitea",
            NATIVE,
            "  access: { claims: { hlb_gitea: { byLevel: { user: user, admin: admin } } } }\n",
        );
        let d = desired(
            &[role("family", Role::User), role("admins", Role::Admin)],
            &[
                person("lena", "admins"),
                person("sacha", "family"),
                Person {
                    sub: None,
                    ..person("new", "family")
                },
            ],
            &[allowing(&gitea, &["family", "admins"])],
        );
        let admins = &d.groups["hlb-admins"];
        assert_eq!(admins.members, BTreeSet::from(["sub-lena".to_string()]));
        assert_eq!(admins.claims["hlb_gitea"], "admin");
        assert_eq!(d.groups["hlb-family"].claims["hlb_gitea"], "user");
        assert!(
            d.groups["hlb-family"].members.len() == 1,
            "someone not in PocketID is in no group"
        );
        assert!(d
            .notes
            .iter()
            .any(|n| matches!(n, Note::NoIdentity { person } if person == "new")));
    }

    #[test]
    fn a_role_an_app_does_not_let_in_carries_none_of_its_claims() {
        // Gitea requires its claim: a role without it is refused by Gitea itself, even
        // were PocketID's restriction lifted by hand.
        let gitea = manifest(
            "gitea",
            NATIVE,
            "  access: { claims: { hlb_gitea: { byLevel: { user: user } } } }\n",
        );
        let d = desired(
            &[role("family", Role::User), role("guests", Role::User)],
            &[],
            &[allowing(&gitea, &["family"])],
        );
        assert!(d.groups["hlb-guests"].claims.is_empty());
    }

    #[test]
    fn a_person_quota_beats_the_role_and_none_is_never_a_null_claim() {
        let immich = manifest(
            "immich",
            NATIVE,
            "  access:\n    quota:\n      claim: { name: immich_quota, unit: GiB }\n      \
             apply: { type: sql, unit: bytes, statement: \"UPDATE u SET q = {{ quota }} WHERE \
             s = '{{ person.sub }}'\" }\n",
        );
        let mut family = role("family", Role::User);
        family.quotas.insert("immich".into(), 50 << 30);
        let mut lena = person("lena", "family");
        lena.quotas.insert("immich".into(), None);
        let mut sacha = person("sacha", "family");
        sacha.quotas.insert("immich".into(), Some(200 << 30));
        let d = desired(
            &[family],
            &[lena, sacha, person("dominique", "family")],
            &[allowing(&immich, &["family"])],
        );
        assert_eq!(d.groups["hlb-family"].claims["immich_quota"], 50);
        assert!(
            !d.claims_of.contains_key("sub-lena"),
            "a null claim breaks every sign-in: \"none\" is apply's to set"
        );
        assert_eq!(d.claims_of["sub-sacha"]["immich_quota"], 200);
        assert!(
            !d.claims_of.contains_key("sub-dominique"),
            "the role's suffices"
        );
        let of = |who: &str| {
            d.quotas
                .iter()
                .find(|t| t.person == who)
                .map(|t| (t.bytes, t.own))
        };
        assert_eq!(of("lena"), Some((None, true)));
        assert_eq!(of("sacha"), Some((Some(200 << 30), true)));
        assert_eq!(of("dominique"), Some((Some(50 << 30), false)));
    }

    #[test]
    fn a_role_without_a_quota_carries_no_quota_claim() {
        // ⚠️ Immich reads `0` as "no space at all": no quota is no claim, never zero.
        let immich = manifest(
            "immich",
            NATIVE,
            "  access: { quota: { claim: { name: immich_quota, unit: GiB } } }\n",
        );
        let d = desired(
            &[role("family", Role::User)],
            &[],
            &[allowing(&immich, &["family"])],
        );
        assert!(!d.groups["hlb-family"].claims.contains_key("immich_quota"));
    }

    #[test]
    fn members_follow_the_roles_let_in() {
        let vw = manifest(
            "vaultwarden",
            NATIVE,
            "  access: { members: bitwarden-directory }\n",
        );
        let d = desired(
            &[role("family", Role::User), role("guests", Role::User)],
            &[
                person("lena", "family"),
                person("sacha", "guests"),
                Person {
                    email: None,
                    ..person("new", "family")
                },
            ],
            &[allowing(&vw, &["family"])],
        );
        assert_eq!(
            d.members["vaultwarden"],
            [Member {
                email: "lena@example.org".into(),
                external_id: "lena".into()
            }]
        );
        assert!(d
            .notes
            .iter()
            .any(|n| matches!(n, Note::NoEmail { person, .. } if person == "new")));
        // A group per role let in, holding the members it has — never a role kept out.
        assert_eq!(
            d.member_groups["vaultwarden"],
            [MemberGroup {
                external_id: "hlb-family".into(),
                name: "family".into(),
                members: vec!["lena".into()],
            }]
        );
    }

    #[test]
    fn the_portal_itself_is_no_door() {
        let portal = manifest(PORTAL_SERVICE, NATIVE, "");
        let d = desired(&[], &[], &[allowing(&portal, &[])]);
        assert!(d.doors.is_empty(), "every app behind it would be closed");
    }

    #[test]
    fn an_admin_role_lists_what_it_administers() {
        let gitea = manifest(
            "gitea",
            NATIVE,
            "  access: { admins: { level: admin, means: every repository } }\n",
        );
        let termix = manifest(
            "termix",
            NATIVE,
            "  access: { floor: admin, admins: { level: admin, means: every machine's SSH } }\n",
        );
        let vikunja = manifest("vikunja", NATIVE, "");
        let apps = [
            allowing(&gitea, &["admins", "family"]),
            allowing(&termix, &["admins"]),
            allowing(&vikunja, &["admins"]),
        ];
        let opened: Vec<String> = opens(&role("admins", Role::Admin), &apps)
            .into_iter()
            .map(|o| o.app)
            .collect();
        assert_eq!(opened, ["gitea", "termix"]);
        assert!(opens(&role("family", Role::User), &apps).is_empty());
        assert!(
            opens(&role("ops", Role::Admin), &apps).is_empty(),
            "an app not letting the role in opens nothing"
        );
    }
}
