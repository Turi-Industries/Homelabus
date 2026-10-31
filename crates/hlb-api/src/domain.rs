//! The house's domain, watched for the theft no machine sees: a registrar's support
//! talked into moving the name servers, a lock lifted, a transfer begun.
//!
//! A reading has two halves. The DNS's, from a public resolver — every TLD alike. The
//! registry's, from RDAP where the TLD has one: `.eu`, `.de`, `.io`, `.be` and `.ch`
//! have none (IANA's bootstrap, 2026-10-30), and `.eu`'s WHOIS shows no status at all,
//! so that half is said "not read" rather than guessed. The first reading accepted is
//! the baseline; each later one is compared with it.

use serde::{Deserialize, Serialize};

/// One reading of a zone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reading {
    /// The zone's apex: the first name holding NS, walking up from the exposure's
    /// domain.
    pub zone: String,
    /// Seconds since the epoch.
    pub read_at: i64,
    /// `Err` when no resolver could say.
    pub dns: Result<DnsSide, String>,
    pub registry: Registry,
    /// The CAA set governing the exposure's names. `None` when no resolver said, and
    /// in readings stored before it was read.
    #[serde(default)]
    pub caa_governing: Option<Governing>,
    /// The house's ACME accounts, judged against `caa_governing`. Only Let's
    /// Encrypt's production ones: a staging or private authority's are nobody's to pin.
    #[serde(default)]
    pub accounts: Vec<Account>,
}

/// The first CAA set found climbing from the exposure's domain to the zone, the one an
/// authority checks before issuing for a name below (RFC 8659 §3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Governing {
    /// Where it was found; `None` when no name up to the zone holds one.
    pub at: Option<String>,
    pub records: Vec<String>,
}

/// An ACME account that requests the house's certificates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Account {
    /// `Caddy`, `Stalwart`.
    pub who: String,
    /// The authority's CAA domain: `letsencrypt.org`.
    pub issuer: String,
    /// What a CAA `accounturi` names.
    pub uri: String,
    /// It also requests a wildcard, which an `issuewild` set governs when present.
    pub wildcard: bool,
}

/// What the internet resolves, normalised so two resolvers' answers compare equal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsSide {
    pub ns: Vec<String>,
    pub ds: Vec<String>,
    /// The resolver validated the chain (`AD`). False for a zone not signed too.
    pub validated: bool,
    pub caa: Vec<String>,
}

impl DnsSide {
    /// Each set sorted and deduplicated: resolvers reorder, and Google writes a DS
    /// digest in capitals where Cloudflare does not.
    pub fn new(ns: Vec<String>, ds: Vec<String>, validated: bool, caa: Vec<String>) -> Self {
        Self {
            ns: normalised(ns.iter().map(|n| host(n))),
            ds: normalised(ds.iter().map(|d| words(d).to_lowercase())),
            validated,
            caa: normalised(caa.iter().map(|c| words(c))),
        }
    }
}

/// What the registry says of the name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "read")]
pub enum Registry {
    /// Why: no RDAP for the TLD, or it did not answer.
    NotRead {
        why: String,
    },
    Read(RegistryRecord),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryRecord {
    /// The RDAP server asked.
    pub source: String,
    pub registrar: Option<String>,
    /// EPP statuses as RDAP spells them: `client transfer prohibited`…
    pub statuses: Vec<String>,
    /// The delegation the registry holds — what a resolver follows.
    pub nameservers: Vec<String>,
    /// Seconds since the epoch.
    pub expires: Option<i64>,
}

/// The RDAP base URL serving `tld`, from IANA's `dns.json`.
pub fn rdap_base(bootstrap: &serde_json::Value, tld: &str) -> Option<String> {
    let tld = tld.to_ascii_lowercase();
    bootstrap
        .get("services")?
        .as_array()?
        .iter()
        .find(|s| {
            s.get(0)
                .and_then(serde_json::Value::as_array)
                .is_some_and(|tlds| tlds.iter().any(|t| t.as_str() == Some(tld.as_str())))
        })?
        .get(1)?
        .as_array()?
        .iter()
        .filter_map(serde_json::Value::as_str)
        // Several are listed when a registry serves both; HTTPS first.
        .min_by_key(|u| !u.starts_with("https://"))
        .map(str::to_string)
}

/// A registry's RDAP answer for a domain. The expiry is left to the caller, which
/// parses dates.
pub fn parse_rdap(source: &str, body: &serde_json::Value) -> (RegistryRecord, Option<String>) {
    let strings = |v: Option<&serde_json::Value>| -> Vec<String> {
        v.and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(serde_json::Value::as_str)
            .map(str::to_string)
            .collect()
    };
    let statuses = normalised(
        strings(body.get("status"))
            .iter()
            .map(|s| words(s).to_lowercase()),
    );
    let nameservers = normalised(
        body.get("nameservers")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|n| n.get("ldhName").and_then(serde_json::Value::as_str))
            .map(host),
    );
    let registrar = body
        .get("entities")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .find(|e| strings(e.get("roles")).iter().any(|r| r == "registrar"))
        .and_then(|e| vcard_name(e).or_else(|| e.get("handle")?.as_str().map(str::to_string)));
    let expiry = body
        .get("events")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .find(|e| e.get("eventAction").and_then(serde_json::Value::as_str) == Some("expiration"))
        .and_then(|e| e.get("eventDate")?.as_str().map(str::to_string));
    (
        RegistryRecord {
            source: source.to_string(),
            registrar,
            statuses,
            nameservers,
            expires: None,
        },
        expiry,
    )
}

/// `fn` of a jCard: `["vcard", [["fn", {}, "text", "Name"], …]]`.
fn vcard_name(entity: &serde_json::Value) -> Option<String> {
    entity
        .get("vcardArray")?
        .get(1)?
        .as_array()?
        .iter()
        .find(|p| p.get(0).and_then(serde_json::Value::as_str) == Some("fn"))?
        .get(3)?
        .as_str()
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.trim().to_string())
}

/// What a drift is of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Moved {
    Ns,
    Ds,
    Validated,
    Caa,
    Registrar,
    Statuses,
    Delegation,
}

impl Moved {
    /// Stable, for the notification's key.
    pub fn key(self) -> &'static str {
        match self {
            Self::Ns => "ns",
            Self::Ds => "ds",
            Self::Validated => "validated",
            Self::Caa => "caa",
            Self::Registrar => "registrar",
            Self::Statuses => "statuses",
            Self::Delegation => "delegation",
        }
    }

    /// As a person reads it.
    pub fn label(self) -> &'static str {
        match self {
            Self::Ns => "name servers",
            Self::Ds => "DS at the parent",
            Self::Validated => "DNSSEC",
            Self::Caa => "CAA",
            Self::Registrar => "registrar",
            Self::Statuses => "registry statuses",
            Self::Delegation => "delegation the registry holds",
        }
    }
}

/// One thing that moved since the baseline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Drift {
    pub what: Moved,
    pub was: String,
    pub now: String,
}

/// What moved between the baseline and a reading. A half either could not read
/// compares nothing: a resolver down is not a theft. The expiry is not compared — a
/// renewal moves it.
pub fn drifts(baseline: &Reading, now: &Reading) -> Vec<Drift> {
    let mut out = Vec::new();
    let mut moved = |what: Moved, was: String, now: String| {
        if was != now {
            out.push(Drift { what, was, now });
        }
    };
    if let (Ok(b), Ok(n)) = (&baseline.dns, &now.dns) {
        moved(Moved::Ns, list(&b.ns), list(&n.ns));
        moved(Moved::Ds, list(&b.ds), list(&n.ds));
        moved(Moved::Validated, yes_no(b.validated), yes_no(n.validated));
        moved(Moved::Caa, list(&b.caa), list(&n.caa));
    }
    if let (Registry::Read(b), Registry::Read(n)) = (&baseline.registry, &now.registry) {
        moved(
            Moved::Registrar,
            b.registrar.clone().unwrap_or_else(|| "none named".into()),
            n.registrar.clone().unwrap_or_else(|| "none named".into()),
        );
        moved(Moved::Statuses, list(&b.statuses), list(&n.statuses));
        moved(
            Moved::Delegation,
            list(&b.nameservers),
            list(&n.nameservers),
        );
    }
    out
}

/// What is worth doing, said beside a reading and never alerted: these are how the
/// house is set up, not something that changed.
pub fn advice(r: &Reading, now: i64) -> Vec<String> {
    let mut out = Vec::new();
    if let Registry::Read(reg) = &r.registry {
        // `server transfer prohibited` alone is a registry lock, which counts.
        if !reg
            .statuses
            .iter()
            .any(|s| s.ends_with("transfer prohibited"))
        {
            out.push(
                "no transfer lock: ask the registrar to set one, or a registry lock where offered"
                    .into(),
            );
        }
        if let Some(expires) = reg.expires {
            let days = (expires - now).div_euclid(86_400);
            if days < 30 {
                out.push(format!(
                    "expires in {days} days: a name that lapses is anyone's"
                ));
            }
        }
    }
    if let Ok(dns) = &r.dns {
        if dns.ds.is_empty() {
            out.push("not signed: no DS at the parent, so no DNSSEC".into());
        } else if !dns.validated {
            out.push(
                "signed and NOT validating: a validating resolver refuses every name in it".into(),
            );
        }
        if dns.caa.is_empty() && r.accounts.is_empty() {
            out.push("no CAA: any certificate authority may issue for it".into());
        }
    }
    if let Some(pin) = pin_advice(r) {
        out.push(pin);
    }
    out
}

/// What a CAA set lets one account do (RFC 8659, and 8657's `accounturi`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// No `issue` governs: any authority, any account.
    Anyone,
    /// Its authority is named with no account: any account there may issue.
    AnyAccount,
    /// Only accounts named, its own among them.
    Pinned,
    /// Not allowed: every renewal fails, 30 days before the certificate ends.
    Refused,
}

impl Verdict {
    fn badness(self) -> u8 {
        match self {
            Self::Pinned => 0,
            Self::AnyAccount => 1,
            Self::Anyone => 2,
            Self::Refused => 3,
        }
    }
}

/// The tags RFC 8659 and its successors register. An unknown one marked critical
/// forbids every issuance (§4.1).
const KNOWN_TAGS: [&str; 7] = [
    "issue",
    "issuewild",
    "iodef",
    "issuemail",
    "issuevmc",
    "contactemail",
    "contactphone",
];

struct Caa {
    critical: bool,
    tag: String,
    /// The issuer domain, lower case; empty for `;`, which allows nobody.
    issuer: String,
    account: Option<String>,
}

/// `128 issue "letsencrypt.org; accounturi=https://…"`, as both resolvers answer.
fn parse_caa(record: &str) -> Option<Caa> {
    let mut parts = record.trim().splitn(3, char::is_whitespace);
    let flags: u8 = parts.next()?.parse().ok()?;
    let tag = parts.next()?.to_ascii_lowercase();
    let value = parts.next().unwrap_or("").trim();
    let value = value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .unwrap_or(value);
    let mut fields = value.split(';');
    let issuer = fields.next().unwrap_or("").trim().to_ascii_lowercase();
    let account = fields.find_map(|f| {
        let (k, v) = f.split_once('=')?;
        k.trim()
            .eq_ignore_ascii_case("accounturi")
            .then(|| v.trim().to_string())
    });
    Some(Caa {
        critical: flags & 0x80 != 0,
        tag,
        issuer,
        account,
    })
}

/// What `records` let `account` do — for a wildcard as well, when it requests one.
/// `validationmethods` (RFC 8657) is not judged: no account here says which
/// challenge its next renewal takes.
pub fn judge(records: &[String], account: &Account) -> Verdict {
    let caa: Vec<Caa> = records.iter().filter_map(|r| parse_caa(r)).collect();
    if caa
        .iter()
        .any(|c| c.critical && !KNOWN_TAGS.contains(&c.tag.as_str()))
    {
        return Verdict::Refused;
    }
    let under = |tag: &str| {
        let set: Vec<&Caa> = caa.iter().filter(|c| c.tag == tag).collect();
        if set.is_empty() {
            return Verdict::Anyone;
        }
        let ours: Vec<&&Caa> = set
            .iter()
            .filter(|c| c.issuer == account.issuer.to_ascii_lowercase())
            .collect();
        if !ours
            .iter()
            .any(|c| c.account.as_deref().is_none_or(|u| u == account.uri))
        {
            Verdict::Refused
        } else if ours.iter().any(|c| c.account.is_none()) {
            Verdict::AnyAccount
        } else {
            Verdict::Pinned
        }
    };
    let plain = under("issue");
    if !account.wildcard {
        return plain;
    }
    // With no `issuewild`, `issue` governs a wildcard too (§4.3).
    let wild = if caa.iter().any(|c| c.tag == "issuewild") {
        under("issuewild")
    } else {
        plain
    };
    if wild.badness() > plain.badness() {
        wild
    } else {
        plain
    }
}

/// The accounts the governing CAA refuses: critical, since their certificates stop
/// renewing and nothing else says why until they end.
pub fn refused(r: &Reading) -> Vec<&Account> {
    let Some(g) = &r.caa_governing else {
        return Vec::new();
    };
    r.accounts
        .iter()
        .filter(|a| judge(&g.records, a) == Verdict::Refused)
        .collect()
}

/// The lines that let the house's accounts alone issue, when the CAA lets others.
/// Every account in one piece of advice: a set pinning one of two refuses the other.
fn pin_advice(r: &Reading) -> Option<String> {
    let g = r.caa_governing.as_ref()?;
    let verdicts: Vec<Verdict> = r.accounts.iter().map(|a| judge(&g.records, a)).collect();
    if verdicts.is_empty() || verdicts.contains(&Verdict::Refused) {
        return None;
    }
    let why = if verdicts.contains(&Verdict::Anyone) {
        "no CAA names an authority: any may issue for the house's names"
    } else if verdicts.contains(&Verdict::AnyAccount) {
        "the CAA names no account: anyone's at the same authority may issue"
    } else {
        return None;
    };
    let wild_set = g
        .records
        .iter()
        .filter_map(|c| parse_caa(c))
        .any(|c| c.tag == "issuewild");
    let mut lines = Vec::new();
    for a in &r.accounts {
        lines.push(format!(
            "{}: 0 issue \"{}; accounturi={}\"",
            a.who, a.issuer, a.uri
        ));
        if a.wildcard && wild_set {
            lines.push(format!(
                "{}, its wildcard: 0 issuewild \"{}; accounturi={}\"",
                a.who, a.issuer, a.uri
            ));
        }
    }
    Some(format!(
        "{why}; these CAA records at {}, in place of its `issue` ones, let the house's \
         accounts alone:\n    {}",
        g.at.as_deref().unwrap_or(&r.zone),
        lines.join("\n    ")
    ))
}

/// A host name as compared: lower case, no final dot.
fn host(n: &str) -> String {
    n.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// Whitespace runs folded to one space.
fn words(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn normalised(items: impl Iterator<Item = String>) -> Vec<String> {
    let mut v: Vec<String> = items.filter(|s| !s.is_empty()).collect();
    v.sort();
    v.dedup();
    v
}

fn list(v: &[String]) -> String {
    if v.is_empty() {
        "none".into()
    } else {
        v.join(", ")
    }
}

fn yes_no(b: bool) -> String {
    if b { "validates" } else { "does not validate" }.into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reading(dns: DnsSide, registry: Registry) -> Reading {
        Reading {
            zone: "home.example".into(),
            read_at: 0,
            dns: Ok(dns),
            registry,
            caa_governing: None,
            accounts: Vec::new(),
        }
    }

    fn account(who: &str, n: u32, wildcard: bool) -> Account {
        Account {
            who: who.into(),
            issuer: "letsencrypt.org".into(),
            uri: format!("https://acme-v02.api.letsencrypt.org/acme/acct/{n}"),
            wildcard,
        }
    }

    fn records(r: &[&str]) -> Vec<String> {
        r.iter().map(|s| s.to_string()).collect()
    }

    fn signed() -> DnsSide {
        DnsSide::new(
            vec!["ns2.desec.org.".into(), "ns1.desec.io.".into()],
            vec!["53307 13 2 3F6A815A".into()],
            true,
            vec!["0 issue \"letsencrypt.org\"".into()],
        )
    }

    fn locked() -> Registry {
        Registry::Read(RegistryRecord {
            source: "https://rdap.example/".into(),
            registrar: Some("Gandi SAS".into()),
            statuses: vec!["client transfer prohibited".into()],
            nameservers: vec!["ns1.desec.io".into(), "ns2.desec.org".into()],
            expires: Some(400 * 86_400),
        })
    }

    #[test]
    fn two_resolvers_answering_in_their_own_order_and_case_read_the_same() {
        // Cloudflare's and Google's answers for desec.io, 2026-10-30.
        let cloudflare = DnsSide::new(
            vec!["ns1.desec.io.".into(), "ns2.desec.org.".into()],
            vec![
                "53307 13 2 3f6a815a28593ba6".into(),
                "53307 13 4 156e3dfc".into(),
            ],
            true,
            vec![],
        );
        let google = DnsSide::new(
            vec!["ns2.desec.org.".into(), "NS1.desec.io".into()],
            vec![
                "53307 13 4 156E3DFC".into(),
                "53307  13 2 3F6A815A28593BA6".into(),
            ],
            true,
            vec![],
        );
        assert_eq!(cloudflare, google);
    }

    #[test]
    fn name_servers_moved_away_are_a_drift_and_nothing_else_is() {
        let before = reading(signed(), locked());
        let mut after = before.clone();
        if let Ok(dns) = &mut after.dns {
            dns.ns = vec!["ns1.thief.example".into()];
        }
        let d = drifts(&before, &after);
        assert_eq!(d.len(), 1, "{d:?}");
        assert_eq!(d[0].what, Moved::Ns);
        assert_eq!(d[0].now, "ns1.thief.example");
    }

    #[test]
    fn a_lock_lifted_and_a_new_registrar_are_each_a_drift() {
        let before = reading(signed(), locked());
        let mut after = before.clone();
        if let Registry::Read(r) = &mut after.registry {
            r.statuses = vec!["pending transfer".into()];
            r.registrar = Some("Elsewhere Ltd".into());
        }
        let whats: Vec<_> = drifts(&before, &after).iter().map(|d| d.what).collect();
        assert_eq!(whats, [Moved::Registrar, Moved::Statuses]);
    }

    #[test]
    fn a_half_that_could_not_be_read_is_not_a_drift() {
        let before = reading(signed(), locked());
        let after = Reading {
            dns: Err("every resolver timed out".into()),
            registry: Registry::NotRead {
                why: "the RDAP server did not answer".into(),
            },
            ..before.clone()
        };
        assert!(drifts(&before, &after).is_empty());
    }

    #[test]
    fn a_renewal_moving_the_expiry_is_not_a_drift() {
        let before = reading(signed(), locked());
        let mut after = before.clone();
        if let Registry::Read(r) = &mut after.registry {
            r.expires = Some(800 * 86_400);
        }
        assert!(drifts(&before, &after).is_empty());
    }

    #[test]
    fn an_unlocked_unsigned_name_without_caa_is_advised_each_time() {
        let r = reading(
            DnsSide::new(vec!["ns1.example".into()], vec![], false, vec![]),
            Registry::Read(RegistryRecord {
                statuses: vec!["active".into()],
                expires: Some(10 * 86_400),
                ..match locked() {
                    Registry::Read(r) => r,
                    Registry::NotRead { .. } => unreachable!(),
                }
            }),
        );
        let a = advice(&r, 0).join("\n");
        for said in [
            "no transfer lock",
            "expires in 10 days",
            "not signed",
            "no CAA",
        ] {
            assert!(a.contains(said), "{said} missing from:\n{a}");
        }
        assert!(advice(&reading(signed(), locked()), 0).is_empty());
    }

    #[test]
    fn a_registry_lock_counts_as_a_transfer_lock() {
        let mut r = reading(signed(), locked());
        if let Registry::Read(reg) = &mut r.registry {
            reg.statuses = vec!["server transfer prohibited".into()];
        }
        assert!(advice(&r, 0).is_empty());
    }

    #[test]
    fn a_signed_zone_that_does_not_validate_is_said_so() {
        let mut dns = signed();
        dns.validated = false;
        let a = advice(&reading(dns, locked()), 0).join("\n");
        assert!(a.contains("signed and NOT validating"), "{a}");
    }

    #[test]
    fn the_bootstrap_names_a_tlds_server_and_none_for_one_without_rdap() {
        // The shape of IANA's dns.json.
        let b = serde_json::json!({
            "services": [
                [["com", "net"], ["https://rdap.verisign.com/com/v1/"]],
                [["fr"], ["http://rdap.nic.fr/", "https://rdap.nic.fr/"]],
            ]
        });
        assert_eq!(
            rdap_base(&b, "COM").as_deref(),
            Some("https://rdap.verisign.com/com/v1/")
        );
        assert_eq!(rdap_base(&b, "fr").as_deref(), Some("https://rdap.nic.fr/"));
        assert_eq!(rdap_base(&b, "eu"), None);
    }

    #[test]
    fn an_rdap_answer_gives_its_locks_registrar_delegation_and_expiry() {
        // Verisign's answer for a .com, cut to what is read.
        let body = serde_json::json!({
            "status": ["client transfer prohibited", "client delete prohibited"],
            "entities": [{
                "roles": ["registrar"],
                "handle": "292",
                "vcardArray": ["vcard", [["version", {}, "text", "4.0"],
                                         ["fn", {}, "text", "MarkMonitor Inc."]]],
            }],
            "nameservers": [{ "ldhName": "NS2.GOOGLE.COM" }, { "ldhName": "NS1.GOOGLE.COM" }],
            "events": [
                { "eventAction": "registration", "eventDate": "1997-09-15T04:00:00Z" },
                { "eventAction": "expiration", "eventDate": "2028-09-14T04:00:00Z" },
            ],
        });
        let (r, expiry) = parse_rdap("https://rdap.verisign.com/com/v1/", &body);
        assert_eq!(r.registrar.as_deref(), Some("MarkMonitor Inc."));
        assert_eq!(
            r.statuses,
            ["client delete prohibited", "client transfer prohibited"]
        );
        assert_eq!(r.nameservers, ["ns1.google.com", "ns2.google.com"]);
        assert_eq!(expiry.as_deref(), Some("2028-09-14T04:00:00Z"));
    }

    #[test]
    fn a_reading_survives_its_round_trip_through_the_state() {
        let r = reading(signed(), locked());
        let json = serde_json::to_string(&r).expect("written");
        assert_eq!(serde_json::from_str::<Reading>(&json).expect("read"), r);
    }

    #[test]
    fn desec_s_own_set_pins_its_account_and_refuses_any_other() {
        // Both resolvers' answer for desec.io, 2026-10-31.
        let set = records(&[
            "128 iodef \"mailto:input@desec.io\"",
            "128 issue \"letsencrypt.org;accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/1909605\"",
        ]);
        assert_eq!(
            judge(&set, &account("Caddy", 1909605, false)),
            Verdict::Pinned
        );
        assert_eq!(judge(&set, &account("Caddy", 7, false)), Verdict::Refused);
    }

    #[test]
    fn a_set_is_judged_by_its_issue_records_as_rfc_8659_reads_them() {
        let caddy = account("Caddy", 1, false);
        for (set, verdict) in [
            (vec![], Verdict::Anyone),
            (vec!["0 iodef \"mailto:a@b.example\""], Verdict::Anyone),
            (vec!["0 issue \"LetsEncrypt.org\""], Verdict::AnyAccount),
            (vec!["0 issue \"sectigo.com\""], Verdict::Refused),
            (vec!["0 issue \";\""], Verdict::Refused),
            (
                vec![
                    "0 issue \"letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/1\"",
                    "0 issue \"letsencrypt.org\"",
                ],
                Verdict::AnyAccount,
            ),
            (vec!["128 tbs \"x\""], Verdict::Refused),
            (vec!["0 tbs \"x\""], Verdict::Anyone),
        ] {
            assert_eq!(judge(&records(&set), &caddy), verdict, "{set:?}");
        }
    }

    #[test]
    fn a_wildcard_is_governed_by_issuewild_when_there_is_one() {
        let set = records(&[
            "0 issue \"letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/1\"",
            "0 issuewild \";\"",
        ]);
        assert_eq!(judge(&set, &account("Caddy", 1, false)), Verdict::Pinned);
        assert_eq!(judge(&set, &account("Caddy", 1, true)), Verdict::Refused);
        let issue_only = records(&[&set[0]]);
        assert_eq!(
            judge(&issue_only, &account("Caddy", 1, true)),
            Verdict::Pinned
        );
    }

    #[test]
    fn an_unpinned_set_is_advised_with_one_line_per_account() {
        let mut r = reading(signed(), locked());
        r.caa_governing = Some(Governing {
            at: Some("home.example".into()),
            records: records(&[
                "0 issue \"letsencrypt.org\"",
                "0 issuewild \"letsencrypt.org\"",
            ]),
        });
        r.accounts = vec![account("Caddy", 1, true), account("Stalwart", 2, false)];
        assert!(refused(&r).is_empty());
        let a = advice(&r, 0).join("\n");
        for line in [
            "Caddy: 0 issue \"letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/1\"",
            "Caddy, its wildcard: 0 issuewild \"letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/1\"",
            "Stalwart: 0 issue \"letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/2\"",
        ] {
            assert!(a.contains(line), "{line} missing from:\n{a}");
        }
        assert!(!a.contains("Stalwart, its wildcard"), "{a}");
    }

    #[test]
    fn a_set_pinning_one_account_of_two_refuses_the_other_and_advises_nothing() {
        let mut r = reading(signed(), locked());
        r.caa_governing = Some(Governing {
            at: Some("home.example".into()),
            records: records(&[
                "0 issue \"letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/1\"",
            ]),
        });
        r.accounts = vec![account("Caddy", 1, false), account("Stalwart", 2, false)];
        let who: Vec<&str> = refused(&r).iter().map(|a| a.who.as_str()).collect();
        assert_eq!(who, ["Stalwart"]);
        assert!(advice(&r, 0).is_empty(), "{:?}", advice(&r, 0));
    }

    #[test]
    fn no_caa_with_accounts_known_is_advised_as_the_lines_to_publish() {
        let mut dns = signed();
        dns.caa.clear();
        let mut r = reading(dns, locked());
        r.caa_governing = Some(Governing {
            at: None,
            records: vec![],
        });
        r.accounts = vec![account("Caddy", 1, false)];
        let a = advice(&r, 0);
        assert_eq!(a.len(), 1, "{a:?}");
        assert!(a[0].starts_with("no CAA names an authority"), "{a:?}");
        assert!(a[0].contains("records at home.example"), "{a:?}");
    }

    #[test]
    fn a_reading_stored_before_the_accounts_still_reads() {
        let mut json = serde_json::to_value(reading(signed(), locked())).expect("written");
        let o = json.as_object_mut().expect("an object");
        o.remove("caa_governing");
        o.remove("accounts");
        let r: Reading = serde_json::from_value(json).expect("read");
        assert!(r.accounts.is_empty() && r.caa_governing.is_none());
    }
}
