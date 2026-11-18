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
//! takes a NOTIFY from the house's addresses presenting it, and nobody else.

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
         @ 3600 SOA {ns}.{apex}. hostmaster.{apex}. 1 3600 900 1209600 300\n",
        ns = NAME_SERVERS[0],
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
    let extra = z.extra.trim();
    if !extra.is_empty() {
        let _ = writeln!(
            zone,
            "; The owner's own lines: hlb zone set --extra\n{extra}"
        );
    }

    let mut conf = format!(
        "# Generated by Homelabus - do not edit by hand: hlb zone\n\
         {transfer}\
         policy:\n\
         \x20 - id: hlb\n\
         \x20   algorithm: ecdsap256sha256\n\
         \x20   single-type-signing: on\n\
         \x20   # Never rolled on its own: a new key needs a new DS at the registrar.\n\
         \x20   ksk-lifetime: 0\n\
         \x20   nsec3: on\n\
         \x20   nsec3-iterations: 0\n\
         \x20   nsec3-salt-length: 0\n\
         zone:\n\
         \x20 - domain: {apex}\n\
         \x20   file: {DIR}/zone\n\
         \x20   # Knot keeps the serial and never writes the file back.\n\
         \x20   zonefile-sync: -1\n\
         \x20   zonefile-load: difference-no-serial\n\
         \x20   journal-content: all\n\
         \x20   serial-policy: unixtime\n\
         \x20   dnssec-signing: on\n\
         \x20   dnssec-policy: hlb\n",
        transfer = z.transfer.as_ref().map(house_transfer).unwrap_or_default(),
    );
    if z.transfer.is_some() {
        // Told of each new serial, and the only one a transfer is handed to.
        conf.push_str("    notify: site\n    acl: site\n");
    }
    Rendered {
        conf,
        zone,
        outside,
    }
}

/// The key, as both configurations declare it.
fn key_block(key: &TransferKey) -> String {
    format!(
        "key:\n\
         \x20 - id: {KEY_ID}\n\
         \x20   algorithm: hmac-sha256\n\
         \x20   secret: {}\n",
        key.0
    )
}

/// The house's half: the site as a remote to notify, and as the one address handed a
/// transfer, both with the key.
fn house_transfer(t: &Transfer) -> String {
    format!(
        "{key}\
         remote:\n\
         \x20 - id: site\n\
         \x20   address: {site}@{port}\n\
         \x20   key: {KEY_ID}\n\
         acl:\n\
         \x20 - id: site\n\
         \x20   address: {site}\n\
         \x20   key: {KEY_ID}\n\
         \x20   action: transfer\n",
        key = key_block(&t.key),
        site = t.site,
        port = t.port,
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

/// The site's whole configuration: a secondary of `apex`, transferring from whichever
/// house node runs Knot — tried in order — and taking a NOTIFY from any of them.
///
/// 🔴 `zonefile-load: none` and the journal holding everything: the zone survives a
/// restart without a file, and a file nobody wrote never replaces what was transferred.
pub fn site_conf(apex: &str, house: &[Ipv4Addr], key: &TransferKey) -> String {
    let at_port: Vec<String> = house.iter().map(|a| format!("{a}@{PORT}")).collect();
    let bare: Vec<String> = house.iter().map(|a| a.to_string()).collect();
    format!(
        "# Generated by Homelabus - do not edit by hand: hlb site sync\n\
         {base}\
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
         zone:\n\
         \x20 - domain: {apex}\n\
         \x20   master: house\n\
         \x20   acl: house\n\
         \x20   zonefile-sync: -1\n\
         \x20   zonefile-load: none\n\
         \x20   journal-content: all\n",
        base = BASE_CONF
            .strip_suffix(&format!("include: {DIR}/*.conf\n"))
            .unwrap_or(BASE_CONF),
        key = key_block(key),
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
/// files are checked by Knot's own tools before either is put in place, then Knot
/// reloads and the job waits for the zone to be signed; its last line is the SOA Knot
/// serves.
///
/// 🔴 A zone refused leaves the one served unchanged: nothing is renamed until both
/// checks pass, and the zone goes in before the configuration naming it.
pub fn writer_script(apex: &str) -> String {
    format!(
        "set -e\n\
         mkdir -p {DIR} {STORAGE}/run\n\
         kzonecheck -o '{apex}' {STAGED_ZONE}\n\
         knotc -c {STAGED_CHECK} conf-check\n\
         cp {STAGED_ZONE} {DIR}/.zone.next && mv {DIR}/.zone.next {DIR}/zone\n\
         cp {STAGED_CONF} {DIR}/.conf.next && mv {DIR}/.conf.next {DIR}/zone.conf\n\
         if [ ! -S {SOCKET} ]; then\n\
         \x20   echo 'Knot is not running: it reads the zone when it starts'\n\
         \x20   exit 0\n\
         fi\n\
         knotc -s {SOCKET} reload\n\
         i=0\n\
         until knotc -s {SOCKET} zone-read '{apex}' @ DNSKEY >/dev/null 2>&1; do\n\
         \x20   i=$((i + 1))\n\
         \x20   [ $i -lt 30 ] || {{ echo 'Knot did not sign the zone within 30 s' >&2; exit 1; }}\n\
         \x20   sleep 1\n\
         done\n\
         knotc -s {SOCKET} zone-read '{apex}' @ SOA\n"
    )
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
        assert!(writer_script("example.org").contains(&format!("{DIR}/.conf.next")));
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
        assert!(conf.ends_with("dnssec-policy: hlb\n    notify: site\n    acl: site\n"));
        assert!(
            !format!("{z:?}").contains(&key().0),
            "the key never reaches a log"
        );
    }

    #[test]
    fn the_site_transfers_from_every_house_node_and_keeps_what_it_got() {
        let house = [Ipv4Addr::new(10, 43, 0, 2), Ipv4Addr::new(10, 43, 0, 3)];
        let conf = site_conf("example.org", &house, &key());
        assert!(conf.contains("address: [ 10.43.0.2@10053, 10.43.0.3@10053 ]\n"));
        assert!(conf.contains("address: [ 10.43.0.2, 10.43.0.3 ]\n"));
        assert!(conf.contains("action: notify\n"));
        assert!(conf.contains("  - domain: example.org\n    master: house\n"));
        assert!(conf.contains("zonefile-load: none\n"));
        assert!(conf.contains("listen: [ 0.0.0.0@10053, ::@10053 ]\n"));
        assert!(
            !conf.contains("include:"),
            "the site writes no zone of its own"
        );
    }

    #[test]
    fn a_serial_is_read_from_either_tools_soa() {
        assert_eq!(
            soa_serial("[lab.test.] lab.test. 3600 SOA ns1.lab.test. hostmaster.lab.test. 1794989743 3600 900 1209600 300"),
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

    #[test]
    fn names_are_normalized_or_refused() {
        assert_eq!(normalize("Example.ORG.").as_deref(), Some("example.org"));
        for bad in ["org", "", "-a.org", "a..org", "a b.org", "a_b.org"] {
            assert_eq!(normalize(bad), None, "{bad}");
        }
    }
}
