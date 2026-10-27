//! The emergency vault: one collection of the household's organisation, where every
//! recovery sign-in Homelabus generated is kept — so that the day PocketID signs nobody
//! in, an owner opens Vaultwarden with their master password and finds each app's own
//! administrator there.
//!
//! An owner makes the organisation, the collection and the service account's
//! membership, once, by hand: an organisation's key is encrypted by its owners'
//! clients. Homelabus then signs in as that account and VERIFIES what it was given
//! ([`check`]) before it writes anything ([`plan`]).

use serde_json::{json, Value};

use crate::client::Unlocked;
use crate::crypto::SymmetricKey;
use crate::{Error, Result};

/// The collection Homelabus deposits into, by its name as an owner types it.
pub const COLLECTION: &str = "Server";

/// The custom field marking an item Homelabus keeps, valued `<app>/<secret>`. An item
/// without it was made by someone else and is never touched.
pub const MARKER: &str = "homelabus";

/// How many former passwords an item keeps — the official clients' own limit.
const HISTORY: usize = 5;

/// Bitwarden's membership types, as the server numbers them.
const OWNER: i64 = 0;
const ADMIN: i64 = 1;
const USER: i64 = 2;
const MANAGER: i64 = 3;
/// Bitwarden's "require two-step login" organisation policy.
const TWO_STEP_POLICY: i64 = 0;

/// What the account sees of the organisation, decrypted.
#[derive(Debug)]
pub struct View {
    /// `None`: the account is no CONFIRMED member — invited and not confirmed, or
    /// revoked; Vaultwarden lists neither to the account itself.
    pub membership: Option<Membership>,
    pub collections: Vec<Collection>,
    pub two_step_required: bool,
    pub own_second_factor: bool,
    pub items: Vec<Item>,
    /// Items this crate cannot decrypt — a format newer clients write. Left as they
    /// are: none can be Homelabus's, and one of them must not stop every deposit.
    pub unreadable: usize,
}

#[derive(Debug)]
pub struct Membership {
    pub organization: String,
    pub kind: i64,
    pub enabled: bool,
}

#[derive(Debug)]
pub struct Collection {
    pub id: String,
    pub name: String,
    pub read_only: bool,
    pub hide_passwords: bool,
}

/// An item of the organisation, decrypted.
#[derive(Debug)]
pub struct Item {
    pub id: String,
    pub marker: Option<String>,
    pub name: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub uri: Option<String>,
    pub notes: Option<String>,
    /// The key its fields are encrypted under: its own when a client gave it one, the
    /// organisation's otherwise.
    key: SymmetricKey,
    /// As the server sent it, for a rewrite that keeps what Homelabus does not own.
    raw: Value,
}

/// Reads the account's sync for one organisation. The organisation's key comes back
/// with it: `None` while the account is no confirmed member.
pub fn read(
    sync: &Value,
    organization: &str,
    me: &Unlocked,
) -> Result<(View, Option<SymmetricKey>)> {
    let profile = &sync["profile"];
    let found = profile["organizations"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|o| o["id"].as_str() == Some(organization));
    let membership = found.map(|o| Membership {
        organization: o["name"].as_str().unwrap_or(organization).to_string(),
        kind: o["type"].as_i64().unwrap_or(-1),
        enabled: o["enabled"].as_bool().unwrap_or(false),
    });
    let org_key = match found.and_then(|o| o["key"].as_str()) {
        Some(sealed) => Some(me.pair.open(sealed)?),
        None => None,
    };
    let two_step_required = sync["policies"].as_array().into_iter().flatten().any(|p| {
        p["organizationId"].as_str() == Some(organization)
            && p["type"].as_i64() == Some(TWO_STEP_POLICY)
            && p["enabled"].as_bool() == Some(true)
    });
    let own_second_factor = profile["twoFactorEnabled"].as_bool() == Some(true);

    let mut collections = Vec::new();
    let mut items = Vec::new();
    let mut unreadable = 0;
    if let Some(key) = &org_key {
        for c in sync["collections"].as_array().into_iter().flatten() {
            if c["organizationId"].as_str() != Some(organization) {
                continue;
            }
            collections.push(Collection {
                id: c["id"].as_str().unwrap_or_default().to_string(),
                name: key.decrypt_str(c["name"].as_str().unwrap_or_default())?,
                read_only: c["readOnly"].as_bool().unwrap_or(true),
                hide_passwords: c["hidePasswords"].as_bool().unwrap_or(true),
            });
        }
        for c in sync["ciphers"].as_array().into_iter().flatten() {
            if c["organizationId"].as_str() != Some(organization) || !c["deletedDate"].is_null() {
                continue;
            }
            match item(c, key) {
                Ok(i) => items.push(i),
                Err(_) => unreadable += 1,
            }
        }
    }
    Ok((
        View {
            membership,
            collections,
            two_step_required,
            own_second_factor,
            items,
            unreadable,
        },
        org_key,
    ))
}

fn item(c: &Value, org: &SymmetricKey) -> Result<Item> {
    let key = match c["key"].as_str() {
        Some(k) => SymmetricKey::from_bytes(&org.decrypt(k)?)?,
        None => org.clone(),
    };
    let text = |v: &Value| -> Result<Option<String>> {
        v.as_str().map(|e| key.decrypt_str(e)).transpose()
    };
    let mut marker = None;
    for f in c["fields"].as_array().into_iter().flatten() {
        if text(&f["name"])?.as_deref() == Some(MARKER) {
            marker = text(&f["value"])?;
        }
    }
    Ok(Item {
        id: c["id"].as_str().unwrap_or_default().to_string(),
        marker,
        name: text(&c["name"])?.unwrap_or_default(),
        username: text(&c["login"]["username"])?,
        password: text(&c["login"]["password"])?,
        uri: text(&c["login"]["uris"][0]["uri"])?,
        notes: text(&c["notes"])?,
        key,
        raw: c.clone(),
    })
}

/// One thing the account was to be given.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    pub what: String,
    pub verdict: Verdict,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Holds,
    /// Not done yet: what an owner does, by hand.
    Missing(String),
    /// Done in a way Homelabus refuses to write through.
    Wrong(String),
}

/// What the account must hold before anything is written: a confirmed `User`, one
/// collection named [`COLLECTION`] it may edit and nothing else, its own second factor,
/// and an organisation that requires one of every member.
pub fn check(view: &View, email: &str) -> Vec<Check> {
    let mut out = Vec::new();
    let mut say = |what: &str, verdict: Verdict| {
        out.push(Check {
            what: what.to_string(),
            verdict,
        });
    };
    let Some(m) = &view.membership else {
        say(
            "a confirmed member of the organisation",
            Verdict::Missing(format!(
                "an owner invites {email} as a User with the \"{COLLECTION}\" collection, \
                 and confirms it in Members once Homelabus has set its second factor — or \
                 restores it, if the two-step policy revoked it"
            )),
        );
        return out;
    };
    say(
        &format!("a confirmed member of {}", m.organization),
        if m.enabled {
            Verdict::Holds
        } else {
            Verdict::Wrong("the organisation is disabled".into())
        },
    );
    say(
        "a User, and nothing more",
        match m.kind {
            USER => Verdict::Holds,
            OWNER | ADMIN | MANAGER => Verdict::Wrong(format!(
                "it is {} — it would read every collection: make it a User in Members",
                match m.kind {
                    OWNER => "an Owner",
                    ADMIN => "an Admin",
                    _ => "a Manager",
                }
            )),
            other => Verdict::Wrong(format!(
                "its type is {other} (custom permissions): make it a User in Members"
            )),
        },
    );
    let server: Vec<&Collection> = view
        .collections
        .iter()
        .filter(|c| c.name == COLLECTION)
        .collect();
    say(
        &format!("the \"{COLLECTION}\" collection, editable"),
        match server.as_slice() {
            [] => Verdict::Missing(format!(
                "an owner gives it the \"{COLLECTION}\" collection — Collections → \
                 {COLLECTION} → Access, \"Can edit\""
            )),
            [c] if c.read_only || c.hide_passwords => Verdict::Wrong(format!(
                "it may only view \"{COLLECTION}\": give it \"Can edit\""
            )),
            [_] => Verdict::Holds,
            _ => Verdict::Wrong(format!(
                "it sees two collections named \"{COLLECTION}\": rename one"
            )),
        },
    );
    let others: Vec<&str> = view
        .collections
        .iter()
        .filter(|c| c.name != COLLECTION)
        .map(|c| c.name.as_str())
        .collect();
    say(
        "no other collection",
        if others.is_empty() {
            Verdict::Holds
        } else {
            Verdict::Wrong(format!(
                "it also sees {} — what it sees, a compromise of Homelabus reads: take its \
                 access away",
                others.join(", ")
            ))
        },
    );
    say(
        "its own second factor",
        if view.own_second_factor {
            Verdict::Holds
        } else {
            Verdict::Wrong(
                "its second factor was removed — and the two-step policy removes such a \
                 member: `hlb emergency vault --apply` sets it again"
                    .into(),
            )
        },
    );
    say(
        "two-step login required of every member",
        if view.two_step_required {
            Verdict::Holds
        } else {
            Verdict::Missing(
                "an owner turns on Policies → \"Require two-step login\" — owners and \
                 admins are exempt from it: their own second factor is read every night"
                    .into(),
            )
        },
    );
    out
}

/// Whether every check holds: nothing is written otherwise.
pub fn verified(checks: &[Check]) -> bool {
    checks.iter().all(|c| c.verdict == Verdict::Holds)
}

/// A recovery sign-in as it should read in the collection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Wanted {
    /// `<app>/<secret>`.
    pub marker: String,
    pub name: String,
    pub username: String,
    pub password: String,
    pub uri: Option<String>,
    pub notes: String,
}

/// What a deposit does with one wanted item.
#[derive(Debug)]
pub enum Change<'a> {
    Create(&'a Wanted),
    /// Rewritten: what differs, by name — never the values.
    Update {
        item: &'a Item,
        wanted: &'a Wanted,
        what: Vec<&'static str>,
    },
    Same(&'a Wanted),
}

/// Each wanted item against what the collection holds, matched by [`MARKER`]. An item
/// Homelabus made whose app is gone is left as it is: the data it opens may be restored.
pub fn plan<'a>(wanted: &'a [Wanted], items: &'a [Item]) -> Vec<Change<'a>> {
    wanted
        .iter()
        .map(|w| {
            let Some(item) = items
                .iter()
                .find(|i| i.marker.as_deref() == Some(w.marker.as_str()))
            else {
                return Change::Create(w);
            };
            let mut what = Vec::new();
            if item.password.as_deref() != Some(w.password.as_str()) {
                what.push("password");
            }
            if item.username.as_deref() != Some(w.username.as_str()) {
                what.push("username");
            }
            if item.uri != w.uri {
                what.push("address");
            }
            if item.name != w.name || item.notes.as_deref() != Some(w.notes.as_str()) {
                what.push("name or notes");
            }
            if what.is_empty() {
                Change::Same(w)
            } else {
                Change::Update {
                    item,
                    wanted: w,
                    what,
                }
            }
        })
        .collect()
}

/// A new item, every field encrypted under the organisation's key.
pub fn new_cipher(organization: &str, key: &SymmetricKey, w: &Wanted) -> Value {
    json!({
        "type": 1,
        "organizationId": organization,
        "folderId": null,
        "name": key.encrypt_str(&w.name),
        "notes": key.encrypt_str(&w.notes),
        "favorite": false,
        "reprompt": 0,
        "login": {
            "username": key.encrypt_str(&w.username),
            "password": key.encrypt_str(&w.password),
            "uris": uris(key, w.uri.as_deref()),
            "totp": null,
        },
        "fields": [ marker_field(key, &w.marker) ],
        "passwordHistory": null,
    })
}

/// The item rewritten to read as wanted, what Homelabus does not own kept — a field an
/// owner added, a TOTP — and a replaced password pushed into its history: the app may
/// still hold it, after a rotation that stopped halfway.
pub fn updated_cipher(item: &Item, w: &Wanted, now: &str) -> Result<Value> {
    let k = &item.key;
    let mut c = item.raw.clone();
    let obj = c
        .as_object_mut()
        .ok_or_else(|| Error::Unexpected("an item that is not an object".into()))?;
    obj.insert("name".into(), json!(k.encrypt_str(&w.name)));
    obj.insert("notes".into(), json!(k.encrypt_str(&w.notes)));
    // What the server checks the rewrite against: a change made since is not overwritten.
    if let Some(rev) = item.raw.get("revisionDate") {
        obj.insert("lastKnownRevisionDate".into(), rev.clone());
    }
    if let Some(old) = item.password.as_deref().filter(|p| *p != w.password) {
        let mut history: Vec<Value> = item.raw["passwordHistory"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        history.insert(
            0,
            json!({ "password": k.encrypt_str(old), "lastUsedDate": now }),
        );
        history.truncate(HISTORY);
        obj.insert("passwordHistory".into(), Value::Array(history));
    }
    let login = obj
        .entry("login")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .ok_or_else(|| Error::Unexpected("an item whose login is not an object".into()))?;
    login.insert("username".into(), json!(k.encrypt_str(&w.username)));
    login.insert("password".into(), json!(k.encrypt_str(&w.password)));
    login.insert("uris".into(), uris(k, w.uri.as_deref()));
    Ok(c)
}

fn uris(key: &SymmetricKey, uri: Option<&str>) -> Value {
    match uri {
        Some(u) => json!([{ "uri": key.encrypt_str(u), "match": null }]),
        None => json!([]),
    }
}

fn marker_field(key: &SymmetricKey, marker: &str) -> Value {
    json!({ "type": 0, "name": key.encrypt_str(MARKER), "value": key.encrypt_str(marker), "linkedId": null })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KeyPair;

    fn wanted(marker: &str, password: &str) -> Wanted {
        Wanted {
            marker: marker.into(),
            name: format!("{marker} — admin"),
            username: "admin".into(),
            password: password.into(),
            uri: Some("https://grafana.example.org".into()),
            notes: "kept by Homelabus".into(),
        }
    }

    fn unlocked() -> (Unlocked, SymmetricKey, String) {
        let me = Unlocked {
            key: SymmetricKey::generate(),
            pair: KeyPair::generate().expect("pair"),
        };
        let org = SymmetricKey::generate();
        let sealed = crate::crypto::seal(&me.pair.public().expect("public"), &org).expect("sealed");
        (me, org, sealed)
    }

    fn sync(
        sealed: &str,
        org: &SymmetricKey,
        kind: i64,
        collections: &[&str],
        ciphers: Value,
    ) -> Value {
        json!({
            "profile": {
                "twoFactorEnabled": true,
                "organizations": [{ "id": "o1", "name": "Household", "type": kind, "enabled": true, "key": sealed }],
            },
            "policies": [{ "organizationId": "o1", "type": 0, "enabled": true }],
            "collections": collections.iter().enumerate().map(|(i, n)| json!({
                "id": format!("c{i}"), "organizationId": "o1", "name": org.encrypt_str(n),
                "readOnly": false, "hidePasswords": false,
            })).collect::<Vec<_>>(),
            "ciphers": ciphers,
        })
    }

    #[test]
    fn a_user_with_the_server_collection_only_is_verified() {
        let (me, org, sealed) = unlocked();
        let (view, key) = read(
            &sync(&sealed, &org, USER, &["Server"], json!([])),
            "o1",
            &me,
        )
        .expect("read");
        assert_eq!(key, Some(org));
        let checks = check(&view, "homelabus@example.org");
        assert!(verified(&checks), "{checks:#?}");
    }

    #[test]
    fn an_account_seeing_more_than_it_writes_is_refused() {
        // 🔴 What the account reads, a compromised controller reads.
        let (me, org, sealed) = unlocked();
        for (kind, collections) in [(ADMIN, vec!["Server"]), (USER, vec!["Server", "Family"])] {
            let (view, _) = read(
                &sync(&sealed, &org, kind, &collections, json!([])),
                "o1",
                &me,
            )
            .expect("read");
            let checks = check(&view, "h@example.org");
            assert!(!verified(&checks));
            assert!(
                checks.iter().any(|c| matches!(&c.verdict, Verdict::Wrong(w) if w.contains("Admin") || w.contains("Family"))),
                "{checks:#?}"
            );
        }
    }

    #[test]
    fn no_membership_names_the_owners_steps_and_stops() {
        let (me, _, _) = unlocked();
        let (view, key) =
            read(&json!({ "profile": { "organizations": [] } }), "o1", &me).expect("read");
        assert!(key.is_none());
        let checks = check(&view, "h@example.org");
        assert_eq!(checks.len(), 1);
        assert!(matches!(&checks[0].verdict, Verdict::Missing(m) if m.contains("confirms")));
    }

    #[test]
    fn a_deposit_creates_updates_and_leaves_the_rest() {
        let (me, org, sealed) = unlocked();
        let mine = new_cipher("o1", &org, &wanted("grafana/admin-password", "old"));
        let mut theirs = new_cipher("o1", &org, &wanted("x", "y"));
        theirs["fields"] = json!([]);
        let newer = json!({ "id": "i2", "organizationId": "o1", "name": "7.a-format-to-come" });
        let mut items = json!([mine, theirs, newer]);
        items[0]["id"] = json!("i0");
        items[1]["id"] = json!("i1");
        let (view, _) =
            read(&sync(&sealed, &org, USER, &["Server"], items), "o1", &me).expect("read");
        assert_eq!(
            (view.items.len(), view.unreadable),
            (2, 1),
            "the newer one set aside"
        );
        assert_eq!(view.items[1].marker, None, "made by someone else");

        let want = [
            wanted("grafana/admin-password", "new"),
            wanted("seafile/admin-password", "s"),
        ];
        let p = plan(&want, &view.items);
        assert!(matches!(&p[0], Change::Update { what, .. } if what == &["password"]));
        assert!(matches!(&p[1], Change::Create(w) if w.marker == "seafile/admin-password"));

        let Change::Update { item, wanted, .. } = &p[0] else {
            unreachable!()
        };
        let rewritten = updated_cipher(item, wanted, "2026-10-18T00:00:00Z").expect("rewritten");
        let back = super::item(&rewritten, &org).expect("decrypted");
        assert_eq!(back.password.as_deref(), Some("new"));
        assert_eq!(
            back.marker.as_deref(),
            Some("grafana/admin-password"),
            "the marker kept"
        );
        let old = rewritten["passwordHistory"][0]["password"]
            .as_str()
            .expect("history");
        assert_eq!(
            org.decrypt_str(old).expect("decrypted"),
            "old",
            "the replaced one kept"
        );
        assert!(matches!(plan(&want[..1], &[back])[0], Change::Same(_)));
    }
}
