//! The house's domain, watched for the theft no machine sees: a registrar's support
//! talked into moving the name servers, a lock lifted, a transfer begun.
//!
//! A reading has two halves. The DNS's, from a public resolver — every TLD alike. The
//! registry's, from RDAP where the TLD has one, and from the registry's WHOIS where it
//! has none — `.eu`, `.de`, `.io`, `.be` and `.ch` (IANA's bootstrap, 2026-10-30). A
//! WHOIS says less, and each says it its own way: `.eu`'s shows no status at all, so
//! its statuses are unknown rather than empty; `.de`'s names no registrar; `.ch`'s
//! answers registrars only, and is said not read. The first reading accepted is the
//! baseline; each later one is compared with it.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[schema(as = CaaGoverning)]
pub struct Governing {
    /// Where it was found; `None` when no name up to the zone holds one.
    pub at: Option<String>,
    pub records: Vec<String>,
}

/// An ACME account that requests the house's certificates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[schema(as = AcmeAccount)]
pub struct Account {
    /// `Caddy`, `Stalwart`.
    pub who: String,
    /// The authority's CAA domain: `letsencrypt.org`.
    pub issuer: String,
    /// What a CAA `accounturi` names.
    pub uri: String,
    /// It also requests a wildcard, which an `issuewild` set governs when present.
    pub wildcard: bool,
    /// How its certificates are validated, one entry per kind. Empty in a reading
    /// stored before they were read: a CAA `validationmethods` is then not judged.
    #[serde(default)]
    pub validations: Vec<Validation>,
}

/// One kind of certificate an account requests, and the challenges that may validate
/// it — any one of them. An authority checks a CAA `validationmethods` (RFC 8657)
/// against the challenge taken.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[schema(as = AcmeValidation)]
pub struct Validation {
    /// A wildcard's: its `*.` name is governed by `issuewild` where there is one, its
    /// base name by `issue` like every other.
    pub wildcard: bool,
    /// RFC 8555's names: [`HTTP_01`], [`DNS_01`], [`TLS_ALPN_01`].
    pub methods: Vec<String>,
}

pub const HTTP_01: &str = "http-01";
pub const DNS_01: &str = "dns-01";
pub const TLS_ALPN_01: &str = "tls-alpn-01";

/// What the internet resolves, normalised so two resolvers' answers compare equal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[schema(as = DomainDns)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[schema(as = DomainRegistry)]
#[serde(rename_all = "snake_case", tag = "read")]
pub enum Registry {
    /// Why: no RDAP for the TLD, or it did not answer.
    NotRead {
        why: String,
    },
    Read(RegistryRecord),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[schema(as = DomainRegistryRecord)]
pub struct RegistryRecord {
    /// The RDAP server, or the WHOIS host, asked.
    pub source: String,
    pub registrar: Option<String>,
    /// EPP statuses as RDAP spells them: `client transfer prohibited`… `None`: the
    /// registry does not say (`.eu`'s WHOIS) — not a name without a lock.
    pub statuses: Option<Vec<String>>,
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
            statuses: Some(statuses),
            nameservers,
            expires: None,
        },
        expiry,
    )
}

/// The WHOIS host IANA names for a TLD: the `whois:` line of `whois.iana.org`'s answer.
pub fn whois_server(iana: &str) -> Option<String> {
    iana.lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        let v = v.trim().to_ascii_lowercase();
        // Read over plain TCP, so a host name and nothing else: whatever answered is
        // not trusted to name an address or a port.
        let host = !v.is_empty()
            && v.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-');
        (k.trim().eq_ignore_ascii_case("whois") && host).then_some(v)
    })
}

/// What to send `server` for `name`. DENIC answers a bare name with its status alone;
/// its name servers come with `-T dn,ace`.
pub fn whois_query(server: &str, name: &str) -> String {
    if server == "whois.denic.de" {
        format!("-T dn,ace {name}")
    } else {
        name.to_string()
    }
}

/// A WHOIS answer for one name.
#[derive(Debug, PartialEq, Eq)]
pub enum Whois {
    /// The expiry is left to the caller, which parses dates.
    Held(RegistryRecord, Option<String>),
    /// The registry holds no such name: a parent may be the registered one.
    NotHeld,
    /// An answer that is no record: a refusal, a limit, a shape not known. Its first
    /// line, said as the registry wrote it.
    Unread(String),
}

/// A WHOIS answer, in the two shapes measured (2026-11-01): `key: value` lines —
/// ICANN's (`.io`) and DENIC's — and EURid's and DNS Belgium's blocks, a heading
/// followed by indented lines. Statuses are spelled as RDAP spells them, so a TLD
/// gaining RDAP compares with the baseline WHOIS gave.
pub fn parse_whois(source: &str, text: &str) -> Whois {
    let mut domain = false;
    let mut registrar = None;
    let mut statuses: Option<Vec<String>> = None;
    let mut nameservers = Vec::new();
    let mut expiry = None;
    let mut section = String::new();
    let mut first = None;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty()
            || trimmed.starts_with('%')
            || trimmed.starts_with('#')
            || trimmed.starts_with(">>>")
        {
            continue;
        }
        first.get_or_insert(trimmed);
        let indented = line.starts_with([' ', '\t']);
        let (key, value) = match trimmed.split_once(':') {
            Some((k, v)) => (k.trim().to_ascii_lowercase(), v.trim()),
            None => (String::new(), trimmed),
        };
        if !indented {
            section = if value.is_empty() {
                key.clone()
            } else {
                String::new()
            };
        }
        let status = |statuses: &mut Option<Vec<String>>, v: &str| {
            statuses.get_or_insert_with(Vec::new).push(epp_words(v));
        };
        match (indented, section.as_str(), key.as_str()) {
            (false, _, "domain" | "domain name") => domain = true,
            (false, _, "status" | "domain status") => match value.to_ascii_lowercase().as_str() {
                "available" | "free" => return Whois::NotHeld,
                // DNS Belgium's: the name is taken, which is not an EPP status.
                "not available" => {}
                _ => status(&mut statuses, value),
            },
            (false, _, "registrar") if !value.is_empty() => registrar = Some(value.to_string()),
            (false, _, "name server" | "nserver") => nameservers.extend(first_word(value)),
            (false, _, "registry expiry date") => expiry = Some(value.to_string()),
            (true, "registrar", "name") => registrar = Some(value.to_string()),
            (true, "name servers" | "nameservers", _) => nameservers.extend(first_word(trimmed)),
            (true, "flags", _) => status(&mut statuses, trimmed),
            _ => {}
        }
    }
    if !domain {
        let first = first.unwrap_or("nothing");
        let lower = first.to_ascii_lowercase();
        return if lower.starts_with("domain not found") || lower.starts_with("no match") {
            Whois::NotHeld
        } else {
            Whois::Unread(first.to_string())
        };
    }
    Whois::Held(
        RegistryRecord {
            source: source.to_string(),
            registrar,
            statuses: statuses.map(|s| normalised(s.into_iter())),
            nameservers: normalised(nameservers.into_iter()),
            expires: None,
        },
        expiry,
    )
}

/// `ns1.example (192.0.2.1)` → `ns1.example`.
fn first_word(s: &str) -> Option<String> {
    s.split_whitespace().next().map(host)
}

/// `clientTransferProhibited https://icann.org/epp#…` → `client transfer prohibited`,
/// as RDAP spells it; `connect` stays.
fn epp_words(s: &str) -> String {
    let code = s.split_whitespace().next().unwrap_or("");
    let mut out = String::new();
    for c in code.chars() {
        if c.is_ascii_uppercase() && !out.is_empty() {
            out.push(' ');
        }
        out.push(c.to_ascii_lowercase());
    }
    out
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
#[schema(as = DomainChange)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[schema(as = DomainDrift)]
pub struct Drift {
    pub what: Moved,
    pub was: Side,
    pub now: Side,
}

/// One side of a drift, as a value: the interface words it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[schema(as = DomainDriftSide)]
pub enum Side {
    /// Name servers, DS, CAA, statuses, a delegation; a registrar, one or none named.
    Names {
        names: Vec<String>,
    },
    Validates {
        validates: bool,
    },
}

impl Drift {
    /// As the CLI and the notification print it.
    pub fn line(&self) -> String {
        let said = |s: &Side| match s {
            Side::Names { names } if names.is_empty() && self.what == Moved::Registrar => {
                "none named".to_string()
            }
            Side::Names { names } => list(names),
            Side::Validates { validates: true } => "validates".into(),
            Side::Validates { validates: false } => "does not validate".into(),
        };
        format!(
            "{}: was {}, now {}",
            self.what.label(),
            said(&self.was),
            said(&self.now)
        )
    }
}

/// What moved between the baseline and a reading. A half either could not read
/// compares nothing: a resolver down is not a theft. The expiry is not compared — a
/// renewal moves it.
pub fn drifts(baseline: &Reading, now: &Reading) -> Vec<Drift> {
    let mut out = Vec::new();
    let mut moved = |what: Moved, was: Side, now: Side| {
        if was != now {
            out.push(Drift { what, was, now });
        }
    };
    let names = |v: &[String]| Side::Names { names: v.to_vec() };
    if let (Ok(b), Ok(n)) = (&baseline.dns, &now.dns) {
        moved(Moved::Ns, names(&b.ns), names(&n.ns));
        moved(Moved::Ds, names(&b.ds), names(&n.ds));
        moved(
            Moved::Validated,
            Side::Validates {
                validates: b.validated,
            },
            Side::Validates {
                validates: n.validated,
            },
        );
        moved(Moved::Caa, names(&b.caa), names(&n.caa));
    }
    if let (Registry::Read(b), Registry::Read(n)) = (&baseline.registry, &now.registry) {
        moved(
            Moved::Registrar,
            names(b.registrar.as_slice()),
            names(n.registrar.as_slice()),
        );
        // A registry that does not say compares nothing, as a half not read.
        if let (Some(b), Some(n)) = (&b.statuses, &n.statuses) {
            moved(Moved::Statuses, names(b), names(n));
        }
        moved(
            Moved::Delegation,
            names(&b.nameservers),
            names(&n.nameservers),
        );
    }
    out
}

/// Something worth doing, said beside a reading and never alerted: how the house is
/// set up, not something that changed. A value, which the CLI and the interface word.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[schema(as = DomainAdvice)]
pub enum Advice {
    /// No transfer lock where the statuses are known.
    NoTransferLock,
    /// Lapsing within 30 days.
    Expires { days: i64 },
    /// No DS at the parent.
    NotSigned,
    /// A DS, and the chain does not validate: validating resolvers refuse the zone.
    SignedNotValidating,
    /// No CAA, and no account of the house read to pin.
    NoCaa,
    /// The CAA lets others issue: these records, at `at`, in place of its `issue`
    /// ones, let the house's accounts alone.
    Pin {
        why: PinWhy,
        at: String,
        records: Vec<PinRecord>,
    },
}

/// Why the CAA lets others issue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
#[schema(as = CaaPinWhy)]
pub enum PinWhy {
    /// No `issue` names an authority: any may issue.
    NoAuthority,
    /// Its authority is named with no account: anyone's there may issue.
    NoAccount,
}

/// One CAA record to publish, for one account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[schema(as = CaaPinRecord)]
pub struct PinRecord {
    pub who: String,
    /// For its wildcard: an `issuewild` record.
    pub wildcard: bool,
    pub record: String,
}

impl Advice {
    /// As the CLI prints it.
    pub fn line(&self) -> String {
        match self {
            Self::NoTransferLock => {
                "no transfer lock: ask the registrar to set one, or a registry lock where offered"
                    .into()
            }
            Self::Expires { days } => {
                format!("expires in {days} days: a name that lapses is anyone's")
            }
            Self::NotSigned => "not signed: no DS at the parent, so no DNSSEC".into(),
            Self::SignedNotValidating => {
                "signed and NOT validating: a validating resolver refuses every name in it".into()
            }
            Self::NoCaa => "no CAA: any certificate authority may issue for it".into(),
            Self::Pin { why, at, records } => {
                let why = match why {
                    PinWhy::NoAuthority => {
                        "no CAA names an authority: any may issue for the house's names"
                    }
                    PinWhy::NoAccount => {
                        "the CAA names no account: anyone's at the same authority may issue"
                    }
                };
                let lines: Vec<String> = records
                    .iter()
                    .map(|r| {
                        let who = if r.wildcard {
                            format!("{}, its wildcard", r.who)
                        } else {
                            r.who.clone()
                        };
                        format!("{who}: {}", r.record)
                    })
                    .collect();
                format!(
                    "{why}; these CAA records at {at}, in place of its `issue` ones, let the \
                     house's accounts alone:\n    {}",
                    lines.join("\n    ")
                )
            }
        }
    }
}

/// What is worth doing beside a reading.
pub fn advice(r: &Reading, now: i64) -> Vec<Advice> {
    let mut out = Vec::new();
    if let Registry::Read(reg) = &r.registry {
        // `server transfer prohibited` alone is a registry lock, which counts. Statuses
        // the registry does not show advise nothing: the lock may be there.
        if reg
            .statuses
            .as_ref()
            .is_some_and(|s| !s.iter().any(|s| s.ends_with("transfer prohibited")))
        {
            out.push(Advice::NoTransferLock);
        }
        if let Some(expires) = reg.expires {
            let days = (expires - now).div_euclid(86_400);
            if days < 30 {
                out.push(Advice::Expires { days });
            }
        }
    }
    if let Ok(dns) = &r.dns {
        if dns.ds.is_empty() {
            out.push(Advice::NotSigned);
        } else if !dns.validated {
            out.push(Advice::SignedNotValidating);
        }
        if dns.caa.is_empty() && r.accounts.is_empty() {
            out.push(Advice::NoCaa);
        }
    }
    if let Some(pin) = pin_advice(r) {
        out.push(pin);
    }
    out
}

/// What a CAA set lets one account do (RFC 8659, and 8657's `accounturi`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
#[schema(as = CaaVerdict)]
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
    /// `validationmethods`, lower case; `None` allows every one.
    methods: Option<Vec<String>>,
}

impl Caa {
    /// Lets `account` issue by one of `methods`; `None`: by whatever it takes, not
    /// known.
    fn allows(&self, account: &Account, methods: Option<&[String]>) -> bool {
        self.issuer == account.issuer.to_ascii_lowercase()
            && self.account.as_deref().is_none_or(|u| u == account.uri)
            && match (&self.methods, methods) {
                (Some(allowed), Some(taken)) => taken
                    .iter()
                    .any(|m| allowed.contains(&m.to_ascii_lowercase())),
                _ => true,
            }
    }
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
    let (mut account, mut methods) = (None, None);
    for f in fields {
        let Some((k, v)) = f.split_once('=') else {
            continue;
        };
        let k = k.trim();
        if k.eq_ignore_ascii_case("accounturi") {
            account = Some(v.trim().to_string());
        } else if k.eq_ignore_ascii_case("validationmethods") {
            methods = Some(
                v.split(',')
                    .map(|m| m.trim().to_ascii_lowercase())
                    .filter(|m| !m.is_empty())
                    .collect(),
            );
        }
    }
    Some(Caa {
        critical: flags & 0x80 != 0,
        tag,
        issuer,
        account,
        methods,
    })
}

/// What `records` let `account` do — for a wildcard as well, when it requests one —
/// by the challenges its certificates take. Each kind of certificate needs one of its
/// challenges allowed: one whose every challenge a `validationmethods` excludes is
/// refused at its next renewal.
pub fn judge(records: &[String], account: &Account) -> Verdict {
    let caa: Vec<Caa> = records.iter().filter_map(|r| parse_caa(r)).collect();
    if caa
        .iter()
        .any(|c| c.critical && !KNOWN_TAGS.contains(&c.tag.as_str()))
    {
        return Verdict::Refused;
    }
    let under = |(tag, methods): (&str, Option<&[String]>)| {
        let set: Vec<&Caa> = caa.iter().filter(|c| c.tag == tag).collect();
        if set.is_empty() {
            return Verdict::Anyone;
        }
        let allowing: Vec<&&Caa> = set.iter().filter(|c| c.allows(account, methods)).collect();
        if allowing.is_empty() {
            Verdict::Refused
        } else if allowing.iter().any(|c| c.account.is_none()) {
            Verdict::AnyAccount
        } else {
            Verdict::Pinned
        }
    };
    // With no `issuewild`, `issue` governs a wildcard too (§4.3).
    let wild_tag = if caa.iter().any(|c| c.tag == "issuewild") {
        "issuewild"
    } else {
        "issue"
    };
    let known = |wildcard_only: bool| -> Vec<Option<&[String]>> {
        let found: Vec<Option<&[String]>> = account
            .validations
            .iter()
            .filter(|v| v.wildcard || !wildcard_only)
            .map(|v| Some(v.methods.as_slice()))
            .collect();
        if found.is_empty() {
            vec![None]
        } else {
            found
        }
    };
    // A wildcard's base name is under `issue` like every other name.
    let mut checks: Vec<(&str, Option<&[String]>)> =
        known(false).into_iter().map(|m| ("issue", m)).collect();
    if account.wildcard {
        checks.extend(known(true).into_iter().map(|m| (wild_tag, m)));
    }
    checks
        .into_iter()
        .map(under)
        .max_by_key(|v| v.badness())
        .unwrap_or(Verdict::Anyone)
}

/// The methods to say again in a pin replacing the `tag` records that let `account`
/// issue: a restriction its owner wrote is not dropped by the advice. `None` when one
/// of those records allows every method.
fn kept_methods(records: &[String], tag: &str, account: &Account) -> Option<Vec<String>> {
    let mut kept = Vec::new();
    for c in records.iter().filter_map(|r| parse_caa(r)) {
        if c.tag != tag || !c.allows(account, None) {
            continue;
        }
        for m in c.methods? {
            if !kept.contains(&m) {
                kept.push(m);
            }
        }
    }
    (!kept.is_empty()).then_some(kept)
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

/// The records that let the house's accounts alone issue, when the CAA lets others.
/// Every account in one piece of advice: a set pinning one of two refuses the other.
fn pin_advice(r: &Reading) -> Option<Advice> {
    let g = r.caa_governing.as_ref()?;
    let verdicts: Vec<Verdict> = r.accounts.iter().map(|a| judge(&g.records, a)).collect();
    if verdicts.is_empty() || verdicts.contains(&Verdict::Refused) {
        return None;
    }
    let why = if verdicts.contains(&Verdict::Anyone) {
        PinWhy::NoAuthority
    } else if verdicts.contains(&Verdict::AnyAccount) {
        PinWhy::NoAccount
    } else {
        return None;
    };
    let wild_set = g
        .records
        .iter()
        .filter_map(|c| parse_caa(c))
        .any(|c| c.tag == "issuewild");
    let record = |tag: &str, a: &Account| {
        let methods = kept_methods(&g.records, tag, a)
            .map(|m| format!("; validationmethods={}", m.join(",")))
            .unwrap_or_default();
        format!("0 {tag} \"{}; accounturi={}{methods}\"", a.issuer, a.uri)
    };
    let mut records = Vec::new();
    for a in &r.accounts {
        records.push(PinRecord {
            who: a.who.clone(),
            wildcard: false,
            record: record("issue", a),
        });
        if a.wildcard && wild_set {
            records.push(PinRecord {
                who: a.who.clone(),
                wildcard: true,
                record: record("issuewild", a),
            });
        }
    }
    Some(Advice::Pin {
        why,
        at: g.at.clone().unwrap_or_else(|| r.zone.clone()),
        records,
    })
}

/// A certificate a Certificate Transparency log holds for the exposure's names, as Cert
/// Spotter reports it: a precertificate and its certificate are one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[schema(as = CtIssuance)]
pub struct Issuance {
    /// Cert Spotter's, rising: what the next reading starts after.
    pub id: String,
    pub names: Vec<String>,
    /// As Cert Spotter names it: `Let's Encrypt`.
    pub issuer: String,
    /// RFC 3339.
    pub not_before: String,
    /// The SHA-256 of its key's SPKI, hex: what says whether the house holds it.
    pub key: String,
}

/// Where the watch over the logs stands, kept between nights.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transparency {
    /// The last issuance judged; `None` until a baseline is accepted.
    pub after: Option<String>,
    /// Issuances for the house's names under a key it does not hold, alerted every
    /// night until accepted.
    pub foreign: Vec<Issuance>,
}

impl Transparency {
    /// After a night that read `found` and judged `foreign` of them: the next reading
    /// starts after the last one read, and the foreign ones join those kept, once each
    /// — the logs may give one again, and its alert is keyed by its id.
    pub fn advance(&mut self, found: &[Issuance], foreign: Vec<Issuance>) {
        if let Some(last) = found.last() {
            self.after = Some(last.id.clone());
        }
        for i in foreign {
            if !self.foreign.iter().any(|f| f.id == i.id) {
                self.foreign.push(i);
            }
        }
    }
}

/// One page of Cert Spotter's `/v1/issuances`, asked with `expand=dns_names` and
/// `expand=issuer`. An entry missing its id or its key is refused rather than
/// skipped: a skipped one would be an issuance nobody judged.
pub fn parse_issuances(body: &serde_json::Value) -> Result<Vec<Issuance>, String> {
    let entries = body
        .as_array()
        .ok_or("Cert Spotter answered something other than a list")?;
    entries
        .iter()
        .map(|e| {
            let text = |v: Option<&serde_json::Value>| v.and_then(|v| v.as_str()).map(String::from);
            let id = text(e.get("id")).ok_or("an issuance without its id")?;
            Ok(Issuance {
                key: text(e.get("pubkey_sha256"))
                    .map(|k| k.to_ascii_lowercase())
                    .ok_or_else(|| format!("issuance {id} without its key"))?,
                names: normalised(
                    e.get("dns_names")
                        .and_then(|n| n.as_array())
                        .into_iter()
                        .flatten()
                        .filter_map(|n| n.as_str())
                        .map(host),
                ),
                issuer: e
                    .get("issuer")
                    .and_then(|i| text(i.get("friendly_name")).or_else(|| text(i.get("name"))))
                    .unwrap_or_else(|| "an authority not named".into()),
                not_before: text(e.get("not_before")).unwrap_or_default(),
                id,
            })
        })
        .collect()
}

/// Whether two certificate names can be the same host: equal, or a wildcard covering
/// the other one label deep — either way, since a stranger's `*.home.example` serves
/// the house's `git.home.example`, and the house's wildcard every name below it.
pub fn names_meet(a: &str, b: &str) -> bool {
    let (a, b) = (host(a), host(b));
    let covers = |w: &str, n: &str| {
        w.strip_prefix("*.")
            .is_some_and(|base| n.split_once('.').is_some_and(|(_, parent)| parent == base))
    };
    a == b || covers(&a, &b) || covers(&b, &a)
}

/// Issuances judged against the keys the house holds and the names it serves.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Judged {
    /// Another key, for a name of the house: someone else can answer for it.
    pub foreign: Vec<Issuance>,
    /// Another key, for names the house does not serve: an owner's site elsewhere.
    pub elsewhere: Vec<Issuance>,
}

pub fn judge_issuances(issuances: &[Issuance], keys: &[String], names: &[String]) -> Judged {
    let mut out = Judged::default();
    for i in issuances {
        if keys.iter().any(|k| k.eq_ignore_ascii_case(&i.key)) {
            continue;
        }
        if i.names
            .iter()
            .any(|n| names.iter().any(|h| names_meet(n, h)))
        {
            out.foreign.push(i.clone());
        } else {
            out.elsewhere.push(i.clone());
        }
    }
    out
}

/// An issuance as a person reads it.
pub fn issuance_line(i: &Issuance) -> String {
    format!(
        "{} by {}, {} (Cert Spotter {})",
        list(&i.names),
        i.issuer,
        i.not_before.get(..10).unwrap_or(&i.not_before),
        i.id
    )
}

/// The domain as its screen shows it: what the night recorded, judged by the rules
/// the inbox and `hlb domain watch` say it with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "scope", rename_all = "snake_case")]
pub enum DomainView {
    /// No exposure: nothing is published by name.
    NoExposure,
    /// Served under the house's own root: no registry holds it, no public authority
    /// certifies it, nothing to watch.
    Internal {
        domain: String,
    },
    Public(Box<DomainPublic>),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct DomainPublic {
    /// The exposure's.
    pub domain: String,
    /// The reading's, or the exposure's domain before any.
    pub zone: String,
    /// `None`: never read.
    pub reading: Option<DomainSeen>,
    /// When the baseline was read; `None` while none was accepted for this zone.
    pub baseline_at: Option<i64>,
    /// What moved since the baseline; empty without one.
    pub drifts: Vec<Drift>,
    pub logs: CtWatch,
}

/// The last reading, judged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct DomainSeen {
    /// Seconds since the epoch.
    pub read_at: i64,
    /// Older than `STALE_AFTER_S`: what it said still stands, the silence since is
    /// said too.
    pub stale: bool,
    pub dns: DomainDnsRead,
    pub registry: Registry,
    pub caa_governing: Option<Governing>,
    pub accounts: Vec<AcmeAccountJudged>,
    pub advice: Vec<Advice>,
}

/// The DNS half: read, or why not.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case", tag = "read")]
pub enum DomainDnsRead {
    NotRead { why: String },
    Read(DnsSide),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct AcmeAccountJudged {
    pub account: Account,
    /// What the governing CAA lets it do; `None` when no resolver said which governs.
    pub verdict: Option<Verdict>,
}

/// Where the watch over the Certificate Transparency logs stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case", tag = "watch")]
pub enum CtWatch {
    /// Its record could not be read.
    Unread { why: String },
    /// No baseline accepted: nothing is judged yet.
    NotStarted,
    /// Issuances under a key the house does not hold, kept until accepted.
    Watched { foreign: Vec<Issuance> },
}

impl DomainPublic {
    /// Judges what the night recorded. `baseline` counts for its own zone only;
    /// `transparency` is `Err` when its record could not be read.
    pub fn judge(
        domain: &str,
        reading: Option<&Reading>,
        baseline: Option<&Reading>,
        transparency: Result<&Transparency, String>,
        now: i64,
    ) -> Self {
        let baseline = baseline.filter(|b| reading.is_none_or(|r| r.zone == b.zone));
        Self {
            domain: domain.to_string(),
            zone: reading.map_or_else(|| domain.to_string(), |r| r.zone.clone()),
            reading: reading.map(|r| DomainSeen {
                read_at: r.read_at,
                stale: now - r.read_at > crate::assertions::STALE_AFTER_S,
                dns: match &r.dns {
                    Ok(d) => DomainDnsRead::Read(d.clone()),
                    Err(why) => DomainDnsRead::NotRead { why: why.clone() },
                },
                registry: r.registry.clone(),
                caa_governing: r.caa_governing.clone(),
                accounts: r
                    .accounts
                    .iter()
                    .map(|a| AcmeAccountJudged {
                        account: a.clone(),
                        verdict: r.caa_governing.as_ref().map(|g| judge(&g.records, a)),
                    })
                    .collect(),
                advice: advice(r, now),
            }),
            baseline_at: baseline.map(|b| b.read_at),
            drifts: match (baseline, reading) {
                (Some(b), Some(r)) => drifts(b, r),
                _ => Vec::new(),
            },
            logs: match transparency {
                Err(why) => CtWatch::Unread { why },
                Ok(t) if t.after.is_none() => CtWatch::NotStarted,
                Ok(t) => CtWatch::Watched {
                    foreign: t.foreign.clone(),
                },
            },
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The advice as the CLI words it.
    fn said(r: &Reading) -> Vec<String> {
        advice(r, 0).iter().map(Advice::line).collect()
    }

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
            validations: Vec::new(),
        }
    }

    /// `account`, its certificates validated as `validations` say: `(wildcard, methods)`.
    fn validated(n: u32, validations: &[(bool, &[&str])]) -> Account {
        Account {
            wildcard: validations.iter().any(|(w, _)| *w),
            validations: validations
                .iter()
                .map(|(wildcard, methods)| Validation {
                    wildcard: *wildcard,
                    methods: methods.iter().map(|m| m.to_string()).collect(),
                })
                .collect(),
            ..account("Caddy", n, false)
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
            statuses: Some(vec!["client transfer prohibited".into()]),
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
        assert_eq!(
            d[0].now,
            Side::Names {
                names: vec!["ns1.thief.example".into()]
            }
        );
        assert_eq!(
            d[0].line(),
            format!(
                "name servers: was {}, now ns1.thief.example",
                list(&signed().ns)
            )
        );
    }

    #[test]
    fn a_lock_lifted_and_a_new_registrar_are_each_a_drift() {
        let before = reading(signed(), locked());
        let mut after = before.clone();
        if let Registry::Read(r) = &mut after.registry {
            r.statuses = Some(vec!["pending transfer".into()]);
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
                statuses: Some(vec!["active".into()]),
                expires: Some(10 * 86_400),
                ..match locked() {
                    Registry::Read(r) => r,
                    Registry::NotRead { .. } => unreachable!(),
                }
            }),
        );
        let a = said(&r).join("\n");
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
            reg.statuses = Some(vec!["server transfer prohibited".into()]);
        }
        assert!(advice(&r, 0).is_empty());
    }

    #[test]
    fn a_signed_zone_that_does_not_validate_is_said_so() {
        let mut dns = signed();
        dns.validated = false;
        let a = said(&reading(dns, locked())).join("\n");
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
            r.statuses.as_deref(),
            Some(
                &[
                    "client delete prohibited".to_string(),
                    "client transfer prohibited".into()
                ][..]
            )
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
    fn a_validationmethods_excluding_every_challenge_a_certificate_takes_refuses_it() {
        let set = |methods: &str| {
            records(&[&format!(
                "0 issue \"letsencrypt.org; validationmethods={methods}\""
            )])
        };
        // Stalwart takes one challenge; Caddy, with no DNS provider, either of two.
        let stalwart = validated(2, &[(false, &[HTTP_01])]);
        let caddy = validated(1, &[(false, &[HTTP_01, TLS_ALPN_01])]);
        for (methods, account, verdict) in [
            ("dns-01", &stalwart, Verdict::Refused),
            ("http-01", &stalwart, Verdict::AnyAccount),
            ("DNS-01, HTTP-01", &stalwart, Verdict::AnyAccount),
            ("dns-01", &caddy, Verdict::Refused),
            ("tls-alpn-01", &caddy, Verdict::AnyAccount),
        ] {
            assert_eq!(judge(&set(methods), account), verdict, "{methods}");
        }
        // Read before the challenges were: not judged on them.
        assert_eq!(
            judge(&set("dns-01"), &account("Stalwart", 2, false)),
            Verdict::AnyAccount
        );
    }

    #[test]
    fn a_wildcard_house_needs_its_dns_challenge_and_its_own_names_their_challenges() {
        let wildcard_only = validated(1, &[(true, &[DNS_01])]);
        let and_own_names = validated(1, &[(true, &[DNS_01]), (false, &[HTTP_01, TLS_ALPN_01])]);
        let dns_only = records(&["0 issue \"letsencrypt.org; validationmethods=dns-01\""]);
        assert_eq!(judge(&dns_only, &wildcard_only), Verdict::AnyAccount);
        // A name below the wildcard's reach gets a certificate of its own, over HTTP.
        assert_eq!(judge(&dns_only, &and_own_names), Verdict::Refused);
        // The wildcard's `*.` name under `issuewild`, its base name under `issue`.
        let http_wild = records(&[
            "0 issue \"letsencrypt.org\"",
            "0 issuewild \"letsencrypt.org; validationmethods=http-01\"",
        ]);
        assert_eq!(judge(&http_wild, &wildcard_only), Verdict::Refused);
        let http_issue = records(&[
            "0 issue \"letsencrypt.org; validationmethods=http-01\"",
            "0 issuewild \"letsencrypt.org\"",
        ]);
        assert_eq!(judge(&http_issue, &wildcard_only), Verdict::Refused);
    }

    #[test]
    fn a_record_restricting_the_challenge_does_not_hide_one_that_pins_the_account() {
        let stalwart = validated(2, &[(false, &[HTTP_01])]);
        let set = records(&[
            "0 issue \"letsencrypt.org; validationmethods=dns-01\"",
            "0 issue \"letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/2\"",
        ]);
        assert_eq!(judge(&set, &stalwart), Verdict::Pinned);
    }

    #[test]
    fn a_pin_says_again_the_challenges_its_owner_restricted() {
        let mut r = reading(signed(), locked());
        r.caa_governing = Some(Governing {
            at: Some("home.example".into()),
            records: records(&[
                "0 issue \"letsencrypt.org; validationmethods=dns-01,http-01\"",
                "0 issuewild \"letsencrypt.org; validationmethods=dns-01\"",
            ]),
        });
        r.accounts = vec![validated(1, &[(true, &[DNS_01])])];
        let a = said(&r).join("\n");
        for line in [
            "0 issue \"letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/1; validationmethods=dns-01,http-01\"",
            "0 issuewild \"letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/1; validationmethods=dns-01\"",
        ] {
            assert!(a.contains(line), "{line} missing from:\n{a}");
        }
        // The records the advice writes are judged as it says.
        let pinned: Vec<String> = match advice(&r, 0).pop() {
            Some(Advice::Pin { records, .. }) => records.into_iter().map(|p| p.record).collect(),
            other => panic!("no pin: {other:?}"),
        };
        assert_eq!(judge(&pinned, &r.accounts[0]), Verdict::Pinned);
    }

    #[test]
    fn an_account_stored_before_its_validations_reads_as_none() {
        let stored = r#"{"who":"Caddy","issuer":"letsencrypt.org","uri":"u","wildcard":true}"#;
        let a: Account = serde_json::from_str(stored).expect("read");
        assert!(a.validations.is_empty() && a.wildcard);
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
        let a = said(&r).join("\n");
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
        let a = said(&r);
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

    /// Two entries in the shape Cert Spotter answered for desec.io on 2026-10-31.
    fn page() -> serde_json::Value {
        serde_json::json!([
            {
                "id": "17742810616",
                "dns_names": ["www.desec.io", "desec.io", "get.desec.io"],
                "pubkey_sha256": "16E73877FF5B51995C9EA55DAFFB9AB38C8C8514C10B39688DB52FF54773573A",
                "issuer": { "friendly_name": "Let's Encrypt", "name": "C=US, O=Let's Encrypt, CN=R13" },
                "not_before": "2026-10-12T14:35:36Z",
            },
            {
                "id": "17743719754",
                "dns_names": ["insight.desec.io"],
                "pubkey_sha256": "aa",
                "issuer": { "name": "CN=Some CA" },
                "not_before": "2026-10-12T15:28:54Z",
            },
        ])
    }

    #[test]
    fn an_issuance_is_read_with_its_names_sorted_and_its_key_lower_case() {
        let got = parse_issuances(&page()).expect("read");
        assert_eq!(got[0].names, ["desec.io", "get.desec.io", "www.desec.io"]);
        assert_eq!(&got[0].key[..8], "16e73877");
        assert_eq!(got[0].issuer, "Let's Encrypt");
        assert_eq!(got[1].issuer, "CN=Some CA");
        assert_eq!(
            issuance_line(&got[0]),
            "desec.io, get.desec.io, www.desec.io by Let's Encrypt, 2026-10-12 (Cert Spotter 17742810616)"
        );
        assert_eq!(parse_issuances(&serde_json::json!([])), Ok(vec![]));
    }

    #[test]
    fn an_issuance_missing_its_key_refuses_the_page_rather_than_skipping_it() {
        let mut p = page();
        p[1].as_object_mut().expect("entry").remove("pubkey_sha256");
        let e = parse_issuances(&p).expect_err("refused");
        assert!(e.contains("17743719754"), "{e}");
        assert!(parse_issuances(&serde_json::json!({ "code": "rate_limited" })).is_err());
    }

    #[test]
    fn a_wildcard_meets_a_name_one_label_below_either_way() {
        assert!(names_meet("*.home.example", "git.home.example"));
        assert!(names_meet("git.home.example", "*.home.example"));
        assert!(names_meet("Home.Example.", "home.example"));
        assert!(!names_meet("*.home.example", "home.example"));
        assert!(!names_meet("*.home.example", "a.git.home.example"));
        assert!(!names_meet("blog.home.example", "git.home.example"));
    }

    #[test]
    fn only_a_key_the_house_does_not_hold_for_a_name_it_serves_is_foreign() {
        let got = parse_issuances(&page()).expect("read");
        let keys = ["16e73877ff5b51995c9ea55daffb9ab38c8c8514c10b39688db52ff54773573a".to_string()];
        let judged = judge_issuances(&got, &keys, &["*.desec.io".into()]);
        assert_eq!(judged.foreign.len(), 1);
        assert_eq!(judged.foreign[0].id, "17743719754");
        assert!(judged.elsewhere.is_empty());
        // The same issuance, for a name the house does not serve, is said, not alerted.
        let judged = judge_issuances(&got, &keys, &["desec.io".into()]);
        assert!(judged.foreign.is_empty());
        assert_eq!(judged.elsewhere.len(), 1);
        // Held, it is the house's whatever its names.
        let judged = judge_issuances(&got[1..], &["AA".into()], &["*.desec.io".into()]);
        assert_eq!(judged, Judged::default());
    }

    #[test]
    fn a_night_moves_the_cursor_and_keeps_what_was_foreign_until_accepted() {
        let got = parse_issuances(&page()).expect("read");
        let mut t = Transparency {
            after: Some("1".into()),
            foreign: vec![],
        };
        t.advance(&got, vec![got[1].clone()]);
        assert_eq!(t.after.as_deref(), Some("17743719754"));
        assert_eq!(t.foreign.len(), 1);
        // A night that read nothing keeps the cursor, and a foreign one given again is
        // kept once.
        t.advance(&[], vec![got[1].clone()]);
        assert_eq!(t.after.as_deref(), Some("17743719754"));
        assert_eq!(t.foreign.len(), 1);
    }

    fn ct(after: Option<&str>) -> Transparency {
        Transparency {
            after: after.map(String::from),
            foreign: Vec::new(),
        }
    }

    #[test]
    fn a_domain_never_read_shows_its_exposure_as_the_zone_and_nothing_judged() {
        let p = DomainPublic::judge("home.example", None, None, Ok(&ct(None)), 0);
        assert_eq!(p.zone, "home.example");
        assert_eq!(p.reading, None);
        assert_eq!(p.baseline_at, None);
        assert_eq!(p.logs, CtWatch::NotStarted);
    }

    #[test]
    fn the_view_carries_each_accounts_verdict_the_advice_and_the_drift() {
        let baseline = Reading {
            read_at: 10,
            ..reading(signed(), locked())
        };
        let mut now = Reading {
            read_at: 100,
            caa_governing: Some(Governing {
                at: None,
                records: records(&["0 issue \"letsencrypt.org\""]),
            }),
            accounts: vec![account("Caddy", 1, false)],
            ..reading(signed(), locked())
        };
        if let Ok(dns) = &mut now.dns {
            dns.ns = vec!["ns1.thief.example".into()];
        }
        let p = DomainPublic::judge(
            "home.example",
            Some(&now),
            Some(&baseline),
            Ok(&ct(Some("7"))),
            100,
        );
        assert_eq!(p.baseline_at, Some(10));
        assert_eq!(p.drifts, drifts(&baseline, &now));
        assert_eq!(p.drifts.len(), 1);
        let seen = p.reading.expect("read");
        assert!(!seen.stale);
        assert_eq!(seen.accounts[0].verdict, Some(Verdict::AnyAccount));
        assert_eq!(seen.advice, advice(&now, 100));
        assert!(
            matches!(seen.advice[..], [Advice::Pin { .. }]),
            "{:?}",
            seen.advice
        );
        assert_eq!(p.logs, CtWatch::Watched { foreign: vec![] });
    }

    #[test]
    fn a_baseline_of_another_zone_compares_nothing_and_an_old_reading_is_stale() {
        let other = Reading {
            zone: "elsewhere.example".into(),
            ..reading(signed(), locked())
        };
        let now = reading(
            DnsSide::new(vec!["ns1.thief.example".into()], vec![], false, vec![]),
            locked(),
        );
        let later = crate::assertions::STALE_AFTER_S + 1;
        let p = DomainPublic::judge(
            "home.example",
            Some(&now),
            Some(&other),
            Err("locked".into()),
            later,
        );
        assert_eq!(p.baseline_at, None);
        assert!(p.drifts.is_empty());
        assert!(p.reading.expect("read").stale);
        assert_eq!(
            p.logs,
            CtWatch::Unread {
                why: "locked".into()
            }
        );
    }

    #[test]
    fn a_dns_half_not_read_says_why_and_no_verdict_without_a_governing_set() {
        let r = Reading {
            dns: Err("every resolver timed out".into()),
            accounts: vec![account("Caddy", 1, false)],
            ..reading(signed(), locked())
        };
        let seen = DomainPublic::judge("home.example", Some(&r), None, Ok(&ct(None)), 0)
            .reading
            .expect("read");
        assert_eq!(
            seen.dns,
            DomainDnsRead::NotRead {
                why: "every resolver timed out".into()
            }
        );
        assert_eq!(seen.accounts[0].verdict, None);
    }

    /// Real answers, kept as the registries wrote them on 2026-11-01.
    fn whois(name: &str) -> &'static str {
        match name {
            "eu" => include_str!("../tests/whois/eu.txt"),
            "eu-free" => include_str!("../tests/whois/eu-free.txt"),
            "eu-subdomain" => include_str!("../tests/whois/eu-subdomain.txt"),
            "de" => include_str!("../tests/whois/de.txt"),
            "de-free" => include_str!("../tests/whois/de-free.txt"),
            "io" => include_str!("../tests/whois/io.txt"),
            "io-free" => include_str!("../tests/whois/io-free.txt"),
            "be" => include_str!("../tests/whois/be.txt"),
            "ch" => include_str!("../tests/whois/ch.txt"),
            "iana-eu" => include_str!("../tests/whois/iana-eu.txt"),
            other => panic!("no answer kept for {other}"),
        }
    }

    fn held(answer: &str, source: &str) -> (RegistryRecord, Option<String>) {
        match parse_whois(source, whois(answer)) {
            Whois::Held(r, e) => (r, e),
            other => panic!("{answer}: {other:?}"),
        }
    }

    #[test]
    fn iana_names_each_tld_s_whois_and_denic_is_asked_for_its_name_servers() {
        assert_eq!(whois_server(whois("iana-eu")).as_deref(), Some("whois.eu"));
        assert_eq!(whois_server("% nothing here"), None);
        assert_eq!(whois_server("whois: 192.0.2.1:8080"), None);
        assert_eq!(
            whois_query("whois.denic.de", "home.de"),
            "-T dn,ace home.de"
        );
        assert_eq!(whois_query("whois.eu", "home.eu"), "home.eu");
    }

    #[test]
    fn eurid_names_the_registrar_and_the_delegation_and_no_status() {
        let (r, expiry) = held("eu", "whois.eu");
        assert_eq!(r.registrar.as_deref(), Some("ClearMedia NV"));
        assert_eq!(r.statuses, None, "EURid shows none: unknown, not empty");
        assert!(r.nameservers.contains(&"ns1bru.europa.eu".to_string()));
        assert!(r.nameservers.contains(&"ans1.cw.net".to_string()));
        // Listed once per address, kept once.
        assert_eq!(
            r.nameservers
                .iter()
                .filter(|n| *n == "ns3bru.europa.eu")
                .count(),
            1
        );
        assert_eq!(expiry, None);
        let read = Reading {
            registry: Registry::Read(r),
            ..reading(signed(), locked())
        };
        assert!(
            !advice(&read, 0).contains(&Advice::NoTransferLock),
            "a lock nobody shows is not a lock missing"
        );
    }

    #[test]
    fn denic_gives_its_status_and_name_servers_and_no_registrar() {
        let (r, _) = held("de", "whois.denic.de");
        assert_eq!(r.registrar, None);
        assert_eq!(r.statuses, Some(vec!["connect".to_string()]));
        assert_eq!(
            r.nameservers,
            [
                "ns1.denic.de",
                "ns2.denic.de",
                "ns3.denic.de",
                "ns4.denic.net"
            ]
        );
    }

    #[test]
    fn icann_s_format_gives_the_locks_as_rdap_spells_them_and_the_expiry() {
        let (r, expiry) = held("io", "whois.nic.io");
        assert_eq!(
            r.statuses,
            Some(vec![
                "server delete prohibited".to_string(),
                "server transfer prohibited".into(),
                "server update prohibited".into()
            ])
        );
        assert_eq!(
            r.registrar.as_deref(),
            Some("Registry Operator acts as Registrar (9999)")
        );
        assert_eq!(expiry.as_deref(), Some("2027-05-01T00:00:02Z"));
        assert!(!r.nameservers.is_empty());
    }

    #[test]
    fn dns_belgium_s_flags_are_its_statuses_and_taken_is_not_one() {
        let (r, _) = held("be", "whois.dns.be");
        assert_eq!(r.registrar.as_deref(), Some("DNS BE vzw/asbl"));
        assert_eq!(
            r.statuses,
            Some(vec![
                "client transfer prohibited".to_string(),
                "server transfer prohibited".into()
            ])
        );
        assert_eq!(
            r.nameservers,
            ["ns1.dns.be", "ns2.dns.be", "ns3.dns.be", "ns5.dns.be"]
        );
    }

    #[test]
    fn a_free_name_is_not_held_and_a_refusal_is_said_as_written() {
        for free in ["eu-free", "de-free", "io-free"] {
            assert_eq!(parse_whois("x", whois(free)), Whois::NotHeld, "{free}");
        }
        assert_eq!(
            parse_whois("whois.nic.ch", whois("ch")),
            Whois::Unread(
                "Requests of this client are not permitted. Please use https://www.nic.ch/whois/ for queries."
                    .into()
            )
        );
        assert!(matches!(
            parse_whois("whois.eu", whois("eu-subdomain")),
            Whois::Unread(_)
        ));
    }

    #[test]
    fn statuses_a_registry_does_not_show_compare_nothing() {
        let before = reading(signed(), locked());
        let mut after = before.clone();
        if let Registry::Read(r) = &mut after.registry {
            r.statuses = None;
        }
        assert!(drifts(&before, &after).is_empty());
    }
}
