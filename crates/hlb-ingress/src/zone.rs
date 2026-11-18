//! The house's own zone, signed at home by Knot.
//!
//! 🔴 **A hidden primary** (decided 2026-11-18): the house's Knot answers the site alone,
//! over the site link, and the VPS's Knot is the only server the internet asks. Every
//! public name already resolves to the VPS's front door, so a house answering too would
//! add nothing the day the VPS is down — and it would need a port open at home, which a
//! CGNAT does not give, and would name the address the door hides.
//!
//! The signing key never leaves the house's Knot. Rolling it over means a new DS at the
//! registrar, which only the owner can enter: Knot never rolls it on its own
//! (`ksk-lifetime: 0`).
//!
//! What `hlb` writes is two files in Knot's volume, which the image's own configuration
//! includes ([`BASE_CONF`]): the zone's configuration and the zone itself. Knot keeps
//! the serial (`zonefile-load: difference-no-serial`), so a rendering carries none and
//! one house renders one file.
//!
//! The site's Knot is a secondary ([`site_conf`]): it transfers the signed zone over the
//! site link and keeps it in its journal, so it answers alone while the house is down —
//! until the signatures run out, which the house renews. Both ends share one TSIG key:
//! the house hands the zone to whoever presents it from the site's address, the site
//! takes a NOTIFY from the house's addresses presenting it, and nobody else. The site
//! learns WHICH zones from a catalog the house generates (RFC 9432): a zone added at
//! home is served by the site without its configuration being written again.
//!
//! Once the registrar delegates to the zone ([`Delegated`]), Caddy's DNS-01 challenges
//! and Stalwart's DKIM keys are written into it over RFC 2136, signed by a key of their
//! own. 🔴 Never into the zone `hlb` writes: with `difference-no-serial` every reload
//! brings the zone back to its file, an unchanged file and a restart included (measured
//! on 3.6.2) — a challenge answered nothing, a DKIM key published by Stalwart was gone
//! at the next install. Each name written that way is a zone of its own ([`Child`]),
//! kept in Knot's journal alone, which `hlb` creates once and never writes again; the
//! house's zone delegates to it and carries its DS.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr};

/// The service, as its manifest names it.
pub const SERVICE: &str = "knot";

/// Where the house's Knot listens, on every interface of its node: not 53, which a
/// node's own resolver may hold, and nobody but the site asks it anything.
pub const PORT: u16 = 10053;

/// Knot's volume, where its keys and journal live.
pub const STORAGE: &str = "/storage";

/// Where `hlb` writes inside it.
pub const DIR: &str = "/storage/hlb";

/// Knot's control socket, in the volume, so a job on its node mounting the volume
/// reaches it.
pub const SOCKET: &str = "/storage/run/knot.sock";

/// The image's configuration, which the manifest mounts: everything but the zone.
///
/// 🔴 `include` of a glob that matches nothing is no error: Knot starts serving nothing
/// before the first publication, so its install never waits on one.
pub const BASE_CONF: &str = "\
server:
    rundir: /storage/run
    listen: [ 0.0.0.0@10053, ::@10053 ]
    identity: \"\"
    version: \"\"
log:
  - target: stdout
    any: info
database:
    storage: /storage
include: /storage/hlb/*.conf
";

/// Seconds a name's address is kept by a resolver: short, a move of house is one
/// WireGuard peer and should not wait on caches.
const ADDRESS_TTL: u32 = 300;

/// The TSIG key both Knots share, base64 as Knot reads it. Its `Debug` hides it: the
/// zone is logged.
#[derive(Clone, PartialEq, Eq)]
pub struct TransferKey(pub String);

impl std::fmt::Debug for TransferKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TransferKey(…)")
    }
}

/// The key's name in both configurations.
pub const KEY_ID: &str = "hlb-site";

/// The house's side of the transfer: the site's Knot, at the hub's address on the link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transfer {
    pub key: TransferKey,
    pub site: Ipv4Addr,
    /// Where the site's Knot answers there: [`SITE_PORT`], published.
    pub port: u16,
}

/// The TSIG key Caddy and Stalwart sign their updates with: not the transfer key, which
/// the site holds too — a site holding this one could rewrite the house's challenges.
#[derive(Clone, PartialEq, Eq)]
pub struct UpdateKey(pub String);

impl std::fmt::Debug for UpdateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("UpdateKey(…)")
    }
}

/// The update key's name, in Knot's configuration and in each client's.
pub const UPDATE_KEY_ID: &str = "hlb-update";

/// Its algorithm, as Knot, Caddy's module and Stalwart all spell it.
pub const UPDATE_ALGORITHM: &str = "hmac-sha256";

/// The registrar delegates to the zone: what is written into it from then on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delegated {
    pub key: UpdateKey,
    /// The domain Caddy's wildcard is asked for, when the house's certificates are
    /// ACME's: its challenges are answered at `_acme-challenge.<domain>`.
    pub challenge: Option<String>,
}

/// A zone of its own, below the house's, written over RFC 2136 alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Child {
    /// `_acme-challenge.example.org`, `_domainkey.example.org`.
    pub name: String,
    pub kind: ChildKind,
    /// What it holds when it is created — Stalwart's keys the house already knew, so
    /// the delegation never answers fewer than the zone did before it.
    pub seed: Vec<Record>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChildKind {
    /// Caddy's challenge: a TXT at the zone's own name, nothing else.
    Challenge,
    /// Stalwart's DKIM keys: TXT below the zone's name, one name per selector.
    Dkim,
}

impl ChildKind {
    /// Its ACL in the house's configuration.
    fn acl(self) -> &'static str {
        match self {
            ChildKind::Challenge => "challenge",
            ChildKind::Dkim => "dkim",
        }
    }
}

/// The catalog the house generates and the site reads its zones from. `.invalid`: a
/// name nobody can register, so it shadows nothing.
pub const CATALOG: &str = "catalog.hlb.invalid";

/// The zone, as the house wants it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Zone {
    /// `example.org`: the registered name whose NS the registrar holds.
    pub apex: String,
    /// The front door's public addresses: every published name, and both name
    /// servers, resolve there.
    pub addresses: Vec<IpAddr>,
    /// The names Caddy serves.
    pub names: Vec<String>,
    /// The owner's own lines, relative to the apex — what the house does not publish
    /// itself and the zone must still hold.
    pub extra: String,
    /// The site's secondary, once `hlb site sync` gave it a key; `None`, the zone is
    /// signed and answers nobody.
    pub transfer: Option<Transfer>,
    /// The records the house's mail needs, as Stalwart computed them.
    pub mail: Vec<Record>,
    /// The authorities allowed to issue for the house's names.
    pub caa: Option<Caa>,
    /// The registrar delegates to this zone; `None`, the provider's zone is still the
    /// one the internet asks, and nothing is written into this one.
    pub delegated: Option<Delegated>,
}

/// One record a service of the house's computed, its line as that service wrote it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// Absolute, without the final dot.
    pub name: String,
    pub kind: String,
    /// The data, a TXT's strings joined.
    pub value: String,
    /// The line, absolute names, as it goes into the zone.
    pub line: String,
}

/// A CAA set, at one name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caa {
    /// The exposure's domain: what governs the house's names and its wildcard, and
    /// nothing of the owner's beside them.
    pub at: String,
    /// Each record's data: `0 issue "letsencrypt.org; accounturi=…"`.
    pub records: Vec<String>,
}

/// What [`render`] makes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rendered {
    /// `zone.conf`, included by [`BASE_CONF`].
    pub conf: String,
    /// The zone file.
    pub zone: String,
    /// Published names outside the apex: no record of this zone can serve them.
    pub outside: Vec<String>,
    /// What the house would publish and does not, and why: a person reads it.
    pub withheld: Vec<String>,
    /// The zones below it, which the writer creates when Knot has none of them yet.
    pub children: Vec<Child>,
}

/// `example.org.` → `example.org`, lowercased; `None` when it is no domain name.
pub fn normalize(name: &str) -> Option<String> {
    let n = name.trim().trim_end_matches('.').to_ascii_lowercase();
    let label_ok = |l: &str| {
        !l.is_empty()
            && l.len() <= 63
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    };
    let labels: Vec<&str> = n.split('.').collect();
    (labels.len() >= 2 && n.len() <= 253 && labels.iter().all(|l| label_ok(l))).then_some(n)
}

/// `name`'s owner relative to `apex`: `@` for the apex itself, `None` outside it.
fn relative(name: &str, apex: &str) -> Option<String> {
    if name == apex {
        return Some("@".into());
    }
    name.strip_suffix(apex)
        .and_then(|rest| rest.strip_suffix('.'))
        .filter(|rest| !rest.is_empty())
        .map(str::to_string)
}

/// The two name servers: two names, as every registry asks, both on the door's
/// addresses — the VPS is the only server there is.
pub const NAME_SERVERS: [&str; 2] = ["ns1", "ns2"];

/// The zone and its configuration. Owners sorted, so one house renders one file.
pub fn render(z: &Zone) -> Rendered {
    let apex = z.apex.as_str();
    let mut owners = BTreeSet::new();
    let mut outside = Vec::new();
    for name in &z.names {
        match normalize(name).and_then(|n| relative(&n, apex)) {
            Some(owner) => {
                owners.insert(owner);
            }
            None => outside.push(name.clone()),
        }
    }
    for ns in NAME_SERVERS {
        owners.insert(ns.to_string());
    }
    let mut addresses = z.addresses.clone();
    addresses.sort();
    addresses.dedup();

    let mut zone = format!(
        "; Generated by Homelabus - do not edit by hand: hlb zone\n\
         $ORIGIN {apex}.\n\
         $TTL {ADDRESS_TTL}\n\
         @ 3600 SOA {soa}\n",
        soa = soa_data(apex),
    );
    for ns in NAME_SERVERS {
        let _ = writeln!(zone, "@ 3600 NS {ns}.{apex}.");
    }
    for owner in &owners {
        for a in &addresses {
            let kind = if a.is_ipv4() { "A" } else { "AAAA" };
            let _ = writeln!(zone, "{owner} {kind} {a}");
        }
    }
    let theirs = owner_records(&z.extra, apex);
    let mut withheld = Vec::new();
    let mut children = children(z, &theirs, &mut withheld);
    if !children.is_empty() {
        // Their DS follows, read from each by the writer once Knot signed it.
        let _ = writeln!(zone, "; Written over RFC 2136, each a zone of its own");
        for c in &children {
            let owner = relative(&c.name, apex).unwrap_or_default();
            for ns in NAME_SERVERS {
                let _ = writeln!(zone, "{owner} 3600 NS {ns}.{apex}.");
            }
        }
    }
    let mut mail = String::new();
    for r in &z.mail {
        let below = children
            .iter_mut()
            .find(|c| c.kind == ChildKind::Dkim && under(&r.name.to_ascii_lowercase(), &c.name));
        if let Some(child) = below {
            child.seed.push(r.clone());
        } else if relative(&r.name, apex).is_none() {
            withheld.push(format!(
                "{} {}: outside {apex}, its record stays where it is",
                r.name, r.kind
            ));
        } else if let Some(t) = theirs.iter().find(|t| collides(t, r)) {
            withheld.push(format!(
                "{} {}: the owner's lines hold one ({}), which stays — merge Stalwart's \
                 into it: {}",
                r.name, r.kind, t.value, r.line
            ));
        } else {
            let _ = writeln!(mail, "{}", r.line.trim());
        }
    }
    if !mail.is_empty() {
        let _ = write!(zone, "; The house's mail, as Stalwart computes it\n{mail}");
    }
    if let Some(caa) = &z.caa {
        match caa_withheld(caa, apex, &theirs) {
            Some(why) => withheld.push(why),
            None => {
                let owner = relative(&caa.at, apex).unwrap_or_else(|| "@".into());
                let _ = writeln!(zone, "; Who may issue for the house's names");
                for r in &caa.records {
                    let _ = writeln!(zone, "{owner} 3600 CAA {r}");
                }
            }
        }
    }
    let extra = z.extra.trim();
    if !extra.is_empty() {
        let _ = writeln!(
            zone,
            "; The owner's own lines: hlb zone set --extra\n{extra}"
        );
    }

    Rendered {
        conf: house_conf(z, &children),
        zone,
        outside,
        withheld,
        children,
    }
}

/// Every zone's SOA data: ns1, the house's hostmaster, and a serial Knot replaces.
fn soa_data(apex: &str) -> String {
    format!(
        "{ns}.{apex}. hostmaster.{apex}. 1 3600 900 1209600 300",
        ns = NAME_SERVERS[0]
    )
}

/// Is `name` `zone` itself or below it? Both absolute, lowercased, without the dot.
fn under(name: &str, zone: &str) -> bool {
    name == zone || name.ends_with(&format!(".{zone}"))
}

/// The zones written over RFC 2136 once the registrar delegates: Caddy's challenge, and
/// each mail domain's DKIM keys — what Stalwart published there is seeded into them.
///
/// 🔴 A line of the owner's at or below one keeps it out, and says so: below a
/// delegation it would be served by nobody, and the owner put it there for a reason (an
/// `_acme-challenge` CNAME to another service, say).
fn children(z: &Zone, theirs: &[Theirs], withheld: &mut Vec<String>) -> Vec<Child> {
    let Some(d) = &z.delegated else {
        return Vec::new();
    };
    let apex = z.apex.as_str();
    let mut wanted: Vec<(String, ChildKind)> = Vec::new();
    if let Some(domain) = &d.challenge {
        wanted.push((format!("_acme-challenge.{domain}"), ChildKind::Challenge));
    }
    for r in &z.mail {
        let name = r.name.to_ascii_lowercase();
        if let Some((_, domain)) = name.split_once("._domainkey.") {
            wanted.push((format!("_domainkey.{domain}"), ChildKind::Dkim));
        }
    }
    wanted.sort_by(|a, b| a.0.cmp(&b.0));
    wanted.dedup();
    let mut out = Vec::new();
    for (name, kind) in wanted {
        if relative(&name, apex).is_none() {
            withheld.push(format!(
                "{name}: outside {apex}, it is written where it was before the delegation"
            ));
        } else if let Some(t) = theirs.iter().find(|t| under(&t.name, &name)) {
            withheld.push(format!(
                "{name}: the owner's lines hold {} {} — below it, which the house would \
                 delegate; written where it was before the delegation",
                t.name, t.kind
            ));
        } else {
            out.push(Child {
                name,
                kind,
                seed: Vec::new(),
            });
        }
    }
    out
}

/// The house's configuration: the keys, the site's transfer, the updates' ACLs, the
/// policy, and every zone it serves — the catalog naming them first.
fn house_conf(z: &Zone, children: &[Child]) -> String {
    let apex = z.apex.as_str();
    let mut keys = Vec::new();
    let mut acls = String::new();
    let mut remote = String::new();
    if let Some(t) = &z.transfer {
        keys.push(key_entry(KEY_ID, &t.key.0));
        let _ = write!(
            remote,
            "remote:\n\
             \x20 - id: site\n\
             \x20   address: {site}@{port}\n\
             \x20   key: {KEY_ID}\n",
            site = t.site,
            port = t.port,
        );
        let _ = write!(
            acls,
            "\x20 - id: site\n\
             \x20   address: {site}\n\
             \x20   key: {KEY_ID}\n\
             \x20   action: transfer\n",
            site = t.site,
        );
    }
    if let Some(d) = &z.delegated {
        keys.push(key_entry(UPDATE_KEY_ID, &d.key.0));
        // TXT only, and only where each client writes: the key Caddy holds cannot
        // move a name's address, Stalwart's cannot write a challenge.
        for (kind, matching) in [(ChildKind::Challenge, "equal"), (ChildKind::Dkim, "sub")] {
            let _ = write!(
                acls,
                "\x20 - id: {id}\n\
                 \x20   key: {UPDATE_KEY_ID}\n\
                 \x20   action: update\n\
                 \x20   update-type: [ TXT ]\n\
                 \x20   update-owner: zone\n\
                 \x20   update-owner-match: {matching}\n",
                id = kind.acl(),
            );
        }
    }
    let mut conf = String::from("# Generated by Homelabus - do not edit by hand: hlb zone\n");
    if !keys.is_empty() {
        let _ = write!(conf, "key:\n{}", keys.concat());
    }
    conf.push_str(&remote);
    if !acls.is_empty() {
        let _ = write!(conf, "acl:\n{acls}");
    }
    let _ = write!(
        conf,
        "policy:\n\
         \x20 - id: hlb\n\
         \x20   algorithm: ecdsap256sha256\n\
         \x20   single-type-signing: on\n\
         \x20   # Never rolled on its own: a new key needs a new DS at the registrar.\n\
         \x20   ksk-lifetime: 0\n\
         \x20   nsec3: on\n\
         \x20   nsec3-iterations: 0\n\
         \x20   nsec3-salt-length: 0\n\
         \x20   # The DS each zone needs above it, read from the zone itself: the writer's\n\
         \x20   # for the zones below, the owner's for the registrar.\n\
         \x20   cds-cdnskey-publish: always\n\
         \x20   cds-digest-type: sha256\n\
         zone:\n"
    );
    let site = z.transfer.is_some();
    // Told of each new serial, the only one a transfer is handed to, and listed in the
    // catalog the site reads its zones from.
    let follows = |conf: &mut String, acl: &[&str]| {
        let mut acl: Vec<&str> = acl.to_vec();
        if site {
            acl.insert(0, "site");
            let _ = write!(
                conf,
                "\x20   notify: site\n\
                 \x20   catalog-role: member\n\
                 \x20   catalog-zone: {CATALOG}\n"
            );
        }
        if !acl.is_empty() {
            let _ = writeln!(conf, "    acl: [ {} ]", acl.join(", "));
        }
    };
    if site {
        let _ = write!(
            conf,
            "\x20 - domain: {CATALOG}\n\
             \x20   catalog-role: generate\n\
             \x20   zonefile-sync: -1\n\
             \x20   zonefile-load: none\n\
             \x20   journal-content: all\n\
             \x20   notify: site\n\
             \x20   acl: [ site ]\n"
        );
    }
    let _ = write!(
        conf,
        "\x20 - domain: {apex}\n\
         \x20   file: {DIR}/zone\n\
         \x20   # Knot keeps the serial and never writes the file back.\n\
         \x20   zonefile-sync: -1\n\
         \x20   zonefile-load: difference-no-serial\n\
         \x20   journal-content: all\n\
         \x20   serial-policy: unixtime\n\
         \x20   dnssec-signing: on\n\
         \x20   dnssec-policy: hlb\n"
    );
    follows(&mut conf, &[]);
    for c in children {
        let _ = write!(
            conf,
            "\x20 - domain: {name}\n\
             \x20   # Written over RFC 2136 alone: no file, the journal holds it whole.\n\
             \x20   zonefile-sync: -1\n\
             \x20   zonefile-load: none\n\
             \x20   journal-content: all\n\
             \x20   serial-policy: unixtime\n\
             \x20   dnssec-signing: on\n\
             \x20   dnssec-policy: hlb\n",
            name = c.name,
        );
        follows(&mut conf, &[c.kind.acl()]);
    }
    conf
}

/// One record of the owner's own lines, as far as the house needs to read them.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Theirs {
    /// Absolute, lowercased, without the final dot.
    name: String,
    kind: String,
    value: String,
}

/// The owner's lines, read for what the house must not write beside them: each
/// record's owner made absolute — `@` the apex, a name without a final dot relative to
/// it, a line starting blank the previous owner —, its type and data. A TTL and a class
/// are stepped over; a directive and a comment are not records.
fn owner_records(extra: &str, apex: &str) -> Vec<Theirs> {
    let mut out = Vec::new();
    let mut last: Option<String> = None;
    let mut lines = extra.lines();
    while let Some(raw) = lines.next() {
        let mut line = strip_comment(raw).to_string();
        // A record across lines, `( … )`, read as one.
        while line.matches('(').count() > line.matches(')').count() {
            let Some(next) = lines.next() else { break };
            line.push(' ');
            line.push_str(strip_comment(next));
        }
        if line.trim().is_empty() || line.trim_start().starts_with('$') {
            continue;
        }
        let mut words = line.split_whitespace();
        let owner = if line.starts_with([' ', '\t']) {
            last.clone()
        } else {
            words.next().map(|o| absolute(o, apex))
        };
        let Some(owner) = owner else { continue };
        last = Some(owner.clone());
        let mut rest: Vec<&str> = words.collect();
        while let Some(w) = rest.first() {
            let class = ["IN", "CH", "HS"].contains(&w.to_ascii_uppercase().as_str());
            if class || w.bytes().all(|b| b.is_ascii_digit()) {
                rest.remove(0);
            } else {
                break;
            }
        }
        let Some((kind, data)) = rest.split_first() else {
            continue;
        };
        let data = data.join(" ");
        let data = data.trim_matches(['(', ')', ' ']);
        out.push(Theirs {
            name: owner,
            kind: kind.to_ascii_uppercase(),
            value: if kind.eq_ignore_ascii_case("TXT") {
                txt_strings(data)
            } else {
                data.to_string()
            },
        });
    }
    out
}

/// A line without its comment: a `;` outside quotes.
fn strip_comment(line: &str) -> &str {
    let mut quoted = false;
    let mut escaped = false;
    for (i, c) in line.char_indices() {
        match c {
            _ if escaped => escaped = false,
            '\\' => escaped = true,
            '"' => quoted = !quoted,
            ';' if !quoted => return &line[..i],
            _ => {}
        }
    }
    line
}

/// `@`, `www`, `www.example.org.` → absolute, lowercased, without the final dot.
fn absolute(owner: &str, apex: &str) -> String {
    let o = owner.to_ascii_lowercase();
    if o == "@" {
        apex.to_string()
    } else if let Some(abs) = o.strip_suffix('.') {
        abs.to_string()
    } else {
        format!("{o}.{apex}")
    }
}

/// A TXT's quoted strings joined; as is when unquoted.
fn txt_strings(data: &str) -> String {
    if !data.contains('"') {
        return data.to_string();
    }
    let mut out = String::new();
    let (mut quoted, mut escaped) = (false, false);
    for c in data.chars() {
        match c {
            _ if escaped => {
                out.push(c);
                escaped = false;
            }
            '\\' if quoted => escaped = true,
            '"' => quoted = !quoted,
            c if quoted => out.push(c),
            _ => {}
        }
    }
    out
}

/// `v=spf1 mx -all` → `v=spf1`: what kind of TXT it is, when it says.
fn txt_tag(value: &str) -> Option<String> {
    let first = value.split([';', ' ']).next()?.trim().to_ascii_lowercase();
    first.starts_with("v=").then_some(first)
}

/// Would `ours` beside `theirs` be a second of one thing? 🔴 Two SPF records at a name
/// are read by receivers as none, two DMARC the same: the owner's stays, the house's is
/// said. A CNAME of the owner's refuses any other data at its name, and Knot the zone.
fn collides(theirs: &Theirs, ours: &Record) -> bool {
    if theirs.name != ours.name.to_ascii_lowercase() {
        return false;
    }
    match (theirs.kind.as_str(), ours.kind.as_str()) {
        ("CNAME", _) => true,
        ("TXT", "TXT") => txt_tag(&theirs.value).is_some_and(|t| txt_tag(&ours.value) == Some(t)),
        (a, b) => a == b,
    }
}

/// Why the house's CAA set is left out, if it is.
///
/// 🔴 A CAA governs every name below it that has none of its own: a name of the
/// owner's served elsewhere — a blog, a shop — would have its next certificate refused
/// by its own host's authority, silently, months later. So the set goes in only where
/// none of the owner's names lies under it, and never beside a CAA the owner wrote.
fn caa_withheld(caa: &Caa, apex: &str, theirs: &[Theirs]) -> Option<String> {
    let pins = caa
        .records
        .iter()
        .map(|r| format!("{} CAA {r}", caa.at))
        .collect::<Vec<_>>()
        .join("\n    ");
    if relative(&caa.at, apex).is_none() {
        return Some(format!(
            "CAA: {} is not in {apex}, the house's CAA stays out:\n    {pins}",
            caa.at
        ));
    }
    if theirs.iter().any(|t| t.kind == "CAA") {
        return Some(format!(
            "CAA: the owner's lines hold their own, which stand alone; the house's would \
             be:\n    {pins}"
        ));
    }
    let mut under: Vec<&str> = theirs
        .iter()
        .filter(|t| ["A", "AAAA", "CNAME"].contains(&t.kind.as_str()))
        .filter(|t| t.name == caa.at || t.name.ends_with(&format!(".{}", caa.at)))
        .map(|t| t.name.as_str())
        .collect();
    under.sort_unstable();
    under.dedup();
    (!under.is_empty()).then(|| {
        format!(
            "CAA: the owner's {} would fall under the house's CAA, which would refuse its \
             host's certificates — give each a CAA of its own in --extra, then these join \
             them:\n    {pins}",
            under.join(", ")
        )
    })
}

/// One key, as a configuration's `key:` section lists it.
fn key_entry(id: &str, secret: &str) -> String {
    format!(
        "\x20 - id: {id}\n\
         \x20   algorithm: {UPDATE_ALGORITHM}\n\
         \x20   secret: {secret}\n"
    )
}

/// The site's Knot: one image, pinned here rather than read from the catalog — the
/// site's services are never the catalog's — and held equal to the catalog's `knot` by
/// a test, so both ends run one Knot.
pub const SITE_IMAGE: &str =
    "cznic/knot:v3.6.2@sha256:174b0fcb24c6c3bc5065c9d1ce46b588eec607a5f32bc40ff0cda60150f00bd9";

/// The service on the site's own Swarm.
pub const SITE_SERVICE: &str = "hlb-site-knot";

/// Where the internet asks the site: 53, published from [`PORT`] inside the container,
/// which binds no privileged port and needs no capability.
pub const SITE_PORT: u16 = 53;

/// Where the site's configuration lives, on the VPS, mounted read-only at `/etc/knot`.
pub const SITE_CONFIG_DIR: &str = "/etc/hlb/knot";

/// The site's volume: its journal holds the zone it transferred, served through a
/// restart while the house is down.
pub const SITE_VOLUME: &str = "hlb-site-knot";

/// The site's whole configuration: a secondary of every zone the house's catalog lists,
/// transferring from whichever house node runs Knot — tried in order — and taking a
/// NOTIFY from any of them.
///
/// 🔴 `zonefile-load: none` and the journal holding everything: a zone survives a
/// restart without a file, and a file nobody wrote never replaces what was transferred.
/// 🔴 The catalog, not a list: a zone the house adds — a mail domain's DKIM keys, the
/// day it is delegated — would otherwise be delegated to a site that does not serve it
/// until someone ran `hlb site sync` again, and nothing would say so.
pub fn site_conf(house: &[Ipv4Addr], key: &TransferKey) -> String {
    let at_port: Vec<String> = house.iter().map(|a| format!("{a}@{PORT}")).collect();
    let bare: Vec<String> = house.iter().map(|a| a.to_string()).collect();
    let from_house = "\x20   master: house\n\
                      \x20   acl: house\n\
                      \x20   zonefile-sync: -1\n\
                      \x20   zonefile-load: none\n\
                      \x20   journal-content: all\n";
    format!(
        "# Generated by Homelabus - do not edit by hand: hlb site sync\n\
         {base}\
         key:\n\
         {key}\
         remote:\n\
         \x20 - id: house\n\
         \x20   address: [ {at_port} ]\n\
         \x20   key: {KEY_ID}\n\
         acl:\n\
         \x20 - id: house\n\
         \x20   address: [ {bare} ]\n\
         \x20   key: {KEY_ID}\n\
         \x20   action: notify\n\
         template:\n\
         \x20 - id: default\n\
         \x20 - id: member\n\
         {from_house}\
         zone:\n\
         \x20 - domain: {CATALOG}\n\
         {from_house}\
         \x20   catalog-role: interpret\n\
         \x20   catalog-template: member\n",
        base = BASE_CONF
            .strip_suffix(&format!("include: {DIR}/*.conf\n"))
            .unwrap_or(BASE_CONF),
        key = key_entry(KEY_ID, &key.0),
        at_port = at_port.join(", "),
        bare = bare.join(", "),
    )
}

/// The serial of a SOA line as `knotc zone-read` or `kdig` print it.
pub fn soa_serial(line: &str) -> Option<u32> {
    let mut words = line.split_whitespace().skip_while(|w| *w != "SOA");
    words.next()?;
    words.nth(2)?.parse().ok()
}

/// Where the writer finds what it is given.
pub const STAGED_ZONE: &str = "/run/hlb/zone";
pub const STAGED_CONF: &str = "/run/hlb/zone.conf";
pub const STAGED_CHECK: &str = "/run/hlb/check.conf";

/// What `knotc conf-check` reads: the staged configuration alone.
pub fn check_conf() -> String {
    format!("include: {STAGED_CONF}\n")
}

/// The writer: a job on Knot's node, from Knot's image, mounting its volume. Both
/// files are checked by Knot's own tools before either is put in place; the zones below
/// the house's are created when Knot has none of them yet, and their DS appended to the
/// house's zone — checked again — before Knot reloads it. Its last line is the SOA Knot
/// serves.
///
/// 🔴 A zone refused leaves the one served unchanged: nothing is put in place until the
/// first checks pass, and the house's zone only once it holds every DS. The
/// configuration goes first: the zones it declares exist before the zone delegating to
/// them is served.
pub fn writer_script(apex: &str, children: &[Child]) -> String {
    let knotc = format!("knotc -s {SOCKET}");
    let mut out = format!(
        "set -e\n\
         mkdir -p {DIR} {STORAGE}/run\n\
         kzonecheck -o '{apex}' {STAGED_ZONE}\n\
         knotc -c {STAGED_CHECK} conf-check\n\
         if [ ! -S {SOCKET} ]; then\n\
         \x20   cp {STAGED_ZONE} {DIR}/.zone.next && mv {DIR}/.zone.next {DIR}/zone\n\
         \x20   cp {STAGED_CONF} {DIR}/.conf.next && mv {DIR}/.conf.next {DIR}/zone.conf\n\
         \x20   echo 'Knot is not running: it reads the zone when it starts'\n\
         \x20   exit 0\n\
         fi\n\
         cp {STAGED_CONF} {DIR}/.conf.next && mv {DIR}/.conf.next {DIR}/zone.conf\n\
         {knotc} reload\n\
         cp {STAGED_ZONE} {DIR}/.zone.next\n"
    );
    for c in children {
        let name = c.name.as_str();
        let mut create = vec![
            format!("{knotc} zone-begin '{name}'"),
            format!("{knotc} zone-set '{name}' @ 3600 SOA {}", soa_data(apex)),
        ];
        for ns in NAME_SERVERS {
            create.push(format!("{knotc} zone-set '{name}' @ 3600 NS {ns}.{apex}."));
        }
        for r in &c.seed {
            create.push(format!(
                "{knotc} zone-set '{name}' '{}.' 3600 TXT {}",
                r.name.to_ascii_lowercase(),
                shell_quote(&txt_rdata(&r.value)),
            ));
        }
        create.push(format!("{knotc} zone-commit '{name}'"));
        let _ = write!(
            out,
            "i=0\n\
             until {knotc} zone-status '{name}' >/dev/null 2>&1; do\n\
             \x20   i=$((i + 1))\n\
             \x20   [ $i -lt 30 ] || {{ echo 'Knot did not take {name} within 30 s' >&2; exit 1; }}\n\
             \x20   sleep 1\n\
             done\n\
             if {knotc} zone-status '{name}' | grep -q 'serial: -'; then\n\
             \x20   if ! {{ {create}; }}; then\n\
             \x20       {knotc} zone-abort '{name}' >/dev/null 2>&1 || true\n\
             \x20       echo 'Knot refused to create {name}' >&2\n\
             \x20       exit 1\n\
             \x20   fi\n\
             fi\n\
             i=0\n\
             until {knotc} zone-read '{name}' @ CDS >/dev/null 2>&1; do\n\
             \x20   i=$((i + 1))\n\
             \x20   [ $i -lt 30 ] || {{ echo 'Knot did not sign {name} within 30 s' >&2; exit 1; }}\n\
             \x20   sleep 1\n\
             done\n\
             {knotc} zone-read '{name}' @ CDS | sed -E 's/^([^ ]+) [0-9]+ CDS /\\1 3600 DS /' >> {DIR}/.zone.next\n",
            create = create.join(" && "),
        );
    }
    let _ = write!(
        out,
        "kzonecheck -o '{apex}' {DIR}/.zone.next\n\
         mv {DIR}/.zone.next {DIR}/zone\n\
         {knotc} -b zone-reload '{apex}'\n\
         i=0\n\
         until {knotc} zone-read '{apex}' @ DNSKEY >/dev/null 2>&1; do\n\
         \x20   i=$((i + 1))\n\
         \x20   [ $i -lt 30 ] || {{ echo 'Knot did not sign the zone within 30 s' >&2; exit 1; }}\n\
         \x20   sleep 1\n\
         done\n\
         {knotc} zone-read '{apex}' @ SOA\n"
    );
    out
}

/// A TXT's data as a zone file writes it: strings of 255 bytes at most, each quoted.
fn txt_rdata(value: &str) -> String {
    let escaped = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"");
    let bytes = value.as_bytes();
    let mut parts = Vec::new();
    let mut at = 0;
    while at < bytes.len() || parts.is_empty() {
        let mut end = (at + 255).min(bytes.len());
        while !value.is_char_boundary(end) {
            end -= 1;
        }
        parts.push(format!("\"{}\"", escaped(&value[at..end])));
        at = end;
    }
    parts.join(" ")
}

/// One word for `sh`, whatever it holds.
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zone() -> Zone {
        Zone {
            apex: "example.org".into(),
            addresses: vec![
                "2001:db8::4".parse().unwrap(),
                "203.0.113.4".parse().unwrap(),
            ],
            names: vec![
                "vault.example.org".into(),
                "id.home.example.org".into(),
                "example.org".into(),
                "Vault.Example.org.".into(),
                "photos.other.net".into(),
            ],
            extra: String::new(),
            transfer: None,
            mail: Vec::new(),
            caa: None,
            delegated: None,
        }
    }

    fn key() -> TransferKey {
        TransferKey("c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0MTI=".into())
    }

    #[test]
    fn every_published_name_and_both_name_servers_resolve_to_the_door() {
        let r = render(&zone());
        for owner in ["@", "id.home", "ns1", "ns2", "vault"] {
            assert!(
                r.zone.contains(&format!("\n{owner} A 203.0.113.4\n")),
                "{owner}\n{}",
                r.zone
            );
            assert!(
                r.zone.contains(&format!("\n{owner} AAAA 2001:db8::4\n")),
                "{owner}"
            );
        }
        assert!(r
            .zone
            .contains("@ 3600 NS ns1.example.org.\n@ 3600 NS ns2.example.org.\n"));
    }

    #[test]
    fn a_name_outside_the_apex_is_named_not_served() {
        let r = render(&zone());
        assert_eq!(r.outside, ["photos.other.net"]);
        assert!(!r.zone.contains("photos"));
    }

    #[test]
    fn one_house_renders_one_zone() {
        let mut shuffled = zone();
        shuffled.names.reverse();
        shuffled.addresses.reverse();
        assert_eq!(render(&zone()), render(&shuffled));
        assert_eq!(render(&zone()).zone.matches("\nvault A ").count(), 1);
    }

    #[test]
    fn the_owners_lines_follow_the_houses() {
        let mut z = zone();
        z.extra = "\n@ TXT \"google-site-verification=abc\"\n".into();
        let r = render(&z);
        assert!(
            r.zone.ends_with("@ TXT \"google-site-verification=abc\"\n"),
            "{}",
            r.zone
        );
    }

    #[test]
    fn the_key_is_never_rolled_without_the_owner() {
        let r = render(&zone());
        assert!(r.conf.contains("ksk-lifetime: 0\n"));
        assert!(r.conf.contains("single-type-signing: on\n"));
        assert!(r.conf.contains("  - domain: example.org\n"));
        assert!(r.conf.contains(&format!("file: {DIR}/zone\n")));
    }

    #[test]
    fn the_base_configuration_includes_what_the_writer_writes() {
        assert!(BASE_CONF.contains(&format!("include: {DIR}/*.conf\n")));
        assert!(BASE_CONF.contains(&format!("@{PORT},")));
        let rundir = SOCKET.strip_suffix("/knot.sock").unwrap();
        assert!(BASE_CONF.contains(&format!("rundir: {rundir}\n")));
        assert!(BASE_CONF.contains(&format!("storage: {STORAGE}\n")));
        // The temporary names never match the include.
        assert!(writer_script("example.org", &[]).contains(&format!("{DIR}/.conf.next")));
    }

    #[test]
    fn the_zone_is_handed_to_the_site_alone_and_the_site_told_of_each_serial() {
        assert!(
            !render(&zone()).conf.contains("acl"),
            "no site, no transfer"
        );
        let mut z = zone();
        z.transfer = Some(Transfer {
            key: key(),
            site: Ipv4Addr::new(10, 43, 0, 1),
            port: SITE_PORT,
        });
        let conf = render(&z).conf;
        assert!(conf.contains(&format!("secret: {}\n", key().0)));
        assert!(conf.contains("address: 10.43.0.1@53\n"), "{conf}");
        assert!(conf.contains("address: 10.43.0.1\n    key: hlb-site\n    action: transfer\n"));
        assert!(
            conf.ends_with(&format!(
                "dnssec-policy: hlb\n    notify: site\n    catalog-role: member\n    \
                 catalog-zone: {CATALOG}\n    acl: [ site ]\n"
            )),
            "{conf}"
        );
        assert!(conf.contains(&format!(
            "  - domain: {CATALOG}\n    catalog-role: generate\n"
        )));
        assert!(
            !format!("{z:?}").contains(&key().0),
            "the key never reaches a log"
        );
    }

    #[test]
    fn the_site_transfers_from_every_house_node_and_keeps_what_it_got() {
        let house = [Ipv4Addr::new(10, 43, 0, 2), Ipv4Addr::new(10, 43, 0, 3)];
        let conf = site_conf(&house, &key());
        assert!(conf.contains("address: [ 10.43.0.2@10053, 10.43.0.3@10053 ]\n"));
        assert!(conf.contains("address: [ 10.43.0.2, 10.43.0.3 ]\n"));
        assert!(conf.contains("action: notify\n"));
        assert!(conf.contains(&format!("  - domain: {CATALOG}\n    master: house\n")));
        assert!(conf.contains("catalog-role: interpret\n    catalog-template: member\n"));
        assert!(
            conf.contains("  - id: member\n    master: house\n"),
            "every zone of the catalog transfers from the house: {conf}"
        );
        assert_eq!(conf.matches("zonefile-load: none\n").count(), 2);
        assert!(conf.contains("listen: [ 0.0.0.0@10053, ::@10053 ]\n"));
        assert!(
            !conf.contains("include:"),
            "the site writes no zone of its own"
        );
    }

    #[test]
    fn a_serial_is_read_from_either_tools_soa() {
        assert_eq!(
            soa_serial(
                "[lab.test.] lab.test. 3600 SOA ns1.lab.test. hostmaster.lab.test. 1794989743 3600 900 1209600 300"
            ),
            Some(1_794_989_743)
        );
        assert_eq!(
            soa_serial("ns1.lab.test. hostmaster.lab.test. 7 3600 900 1209600 300"),
            None,
            "kdig +short prints no type: read it with the type"
        );
        assert_eq!(
            soa_serial("lab.test. 300 IN SOA a. b. 42 1 2 3 4"),
            Some(42)
        );
    }

    fn mail(name: &str, kind: &str, value: &str) -> Record {
        let data = if kind == "TXT" {
            format!("\"{value}\"")
        } else {
            value.to_string()
        };
        Record {
            name: name.into(),
            kind: kind.into(),
            value: value.into(),
            line: format!("{name}. IN {kind} {data}"),
        }
    }

    fn pins() -> Caa {
        Caa {
            at: "example.org".into(),
            records: vec!["0 issue \"letsencrypt.org; accounturi=https://a/1\"".into()],
        }
    }

    #[test]
    fn the_houses_mail_and_its_caa_are_in_the_zone() {
        let mut z = zone();
        z.mail = vec![
            mail("example.org", "MX", "10 mail.example.org."),
            mail("example.org", "TXT", "v=spf1 mx -all"),
        ];
        z.caa = Some(pins());
        let r = render(&z);
        assert!(
            r.zone
                .contains("\nexample.org. IN MX 10 mail.example.org.\n"),
            "{}",
            r.zone
        );
        assert!(r
            .zone
            .contains("\nexample.org. IN TXT \"v=spf1 mx -all\"\n"));
        assert!(r
            .zone
            .contains("\n@ 3600 CAA 0 issue \"letsencrypt.org; accounturi=https://a/1\"\n"));
        assert_eq!(r.withheld, Vec::<String>::new());
    }

    #[test]
    fn a_second_spf_or_mx_beside_the_owners_is_withheld_and_said() {
        let mut z = zone();
        z.extra = "@ 3600 IN TXT \"v=spf1 include:_spf.google.com ~all\"\n\
                   \x20  TXT \"google-site-verification=abc\"\n\
                   @ MX 5 mx.elsewhere.example.\n"
            .into();
        z.mail = vec![
            mail("example.org", "TXT", "v=spf1 mx -all"),
            mail("example.org", "MX", "10 mail.example.org."),
            mail("_dmarc.example.org", "TXT", "v=DMARC1; p=reject"),
        ];
        let r = render(&z);
        assert!(!r.zone.contains("v=spf1 mx -all"), "{}", r.zone);
        assert!(!r.zone.contains("IN MX 10"));
        assert!(r.zone.contains("_dmarc.example.org. IN TXT"));
        assert_eq!(r.withheld.len(), 2, "{:?}", r.withheld);
        assert!(r.withheld[0].contains("v=spf1 include:_spf.google.com ~all"));
        // A verification string is no SPF: nothing of the house's collides with it.
        z.extra = "@ TXT \"google-site-verification=abc\"\n".into();
        assert!(render(&z).zone.contains("v=spf1 mx -all"));
    }

    #[test]
    fn mail_of_another_domain_stays_where_it_is() {
        let mut z = zone();
        z.mail = vec![mail("other.net", "MX", "10 mail.other.net.")];
        let r = render(&z);
        assert!(!r.zone.contains("other.net"));
        assert!(
            r.withheld[0].contains("outside example.org"),
            "{:?}",
            r.withheld
        );
    }

    #[test]
    fn the_caa_never_governs_a_name_of_the_owners_served_elsewhere() {
        let mut z = zone();
        z.caa = Some(pins());
        z.extra = "blog CNAME owner.github.io.\n".into();
        let r = render(&z);
        assert!(!r.zone.contains(" CAA "), "{}", r.zone);
        assert!(
            r.withheld[0].contains("blog.example.org"),
            "{:?}",
            r.withheld
        );
        assert!(r.withheld[0].contains("example.org CAA 0 issue"));

        // Under the exposure's own domain only, the owner's blog beside it is not.
        let mut z = zone();
        z.caa = Some(Caa {
            at: "home.example.org".into(),
            ..pins()
        });
        z.extra = "blog CNAME owner.github.io.\n".into();
        let r = render(&z);
        assert!(r.zone.contains("\nhome 3600 CAA 0 issue"), "{}", r.zone);

        // The owner's own CAA stands alone.
        let mut z = zone();
        z.caa = Some(pins());
        z.extra = "@ CAA 0 issue \"sectigo.com\"\n".into();
        let r = render(&z);
        assert_eq!(r.zone.matches(" CAA ").count(), 1, "{}", r.zone);
        assert!(r.withheld[0].contains("their own"));
    }

    #[test]
    fn the_owners_lines_are_read_as_a_zone_file_reads_them() {
        let got = owner_records(
            "$TTL 600\n\
             ; a comment\n\
             www 300 IN A 192.0.2.1 ; served elsewhere\n\
             \x20   AAAA 2001:db8::1\n\
             mail.example.org. MX 10 mx.example.\n\
             @ TXT ( \"v=spf1 \" \"-all\" )\n\
             big TXT (\n  \"a;b\"\n  \"c\" )\n",
            "example.org",
        );
        let short: Vec<(&str, &str, &str)> = got
            .iter()
            .map(|t| (t.name.as_str(), t.kind.as_str(), t.value.as_str()))
            .collect();
        assert_eq!(
            short,
            [
                ("www.example.org", "A", "192.0.2.1"),
                ("www.example.org", "AAAA", "2001:db8::1"),
                ("mail.example.org", "MX", "10 mx.example."),
                ("example.org", "TXT", "v=spf1 -all"),
                ("big.example.org", "TXT", "a;bc"),
            ]
        );
    }

    #[test]
    fn names_are_normalized_or_refused() {
        assert_eq!(normalize("Example.ORG.").as_deref(), Some("example.org"));
        for bad in ["org", "", "-a.org", "a..org", "a b.org", "a_b.org"] {
            assert_eq!(normalize(bad), None, "{bad}");
        }
    }
}
