//! The DNS records the house's mail needs, judged against what the internet resolves.
//!
//! Stalwart computes every record of a domain it hosts (`Domain.dnsZoneFile`): the
//! zone is read from it, never written here, so a key it rotates or a name it is given
//! is what is expected the next night. Four are JUDGED — without them mail is refused
//! or filed as spam — and the rest (SRV, autoconfig, MTA-STS…) printed only.
//!
//! 🔴 A record is judged by what a public resolver answers, not the house's own: a
//! split-horizon zone can answer inside for a name Gmail never sees.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Why a record is needed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Purpose {
    /// A selector's public key: unpublished, every signature fails.
    Dkim,
    /// Which machines send for the domain — and for Stalwart's own name, which a
    /// receiver checks against `EHLO`, and alone for a bounce, sent with no sender.
    Spf,
    /// Where mail for the domain is delivered.
    Mx,
    /// What a receiver does when SPF and DKIM both fail.
    Dmarc,
}

impl Purpose {
    /// The value stored in `mail_records.purpose`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Dkim => "dkim",
            Self::Spf => "spf",
            Self::Mx => "mx",
            Self::Dmarc => "dmarc",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        [Self::Dkim, Self::Spf, Self::Mx, Self::Dmarc]
            .into_iter()
            .find(|p| p.as_str() == s)
    }

    /// The record type a resolver is asked for.
    pub fn record_type(self) -> &'static str {
        match self {
            Self::Mx => "MX",
            Self::Dkim | Self::Spf | Self::Dmarc => "TXT",
        }
    }
}

/// What a reading found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum RecordState {
    Published,
    /// 🔴 The name answers nothing of the kind.
    Missing,
    /// 🔴 Something is there and it is not what Stalwart needs: another DKIM key, an
    /// SPF that does not name how the house sends, two SPF or two DMARC records —
    /// which receivers treat as none.
    Differs,
    /// The resolver could not be asked. Not "fine".
    Unreadable,
}

impl RecordState {
    /// The value stored in `mail_records.state`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Published => "published",
            Self::Missing => "missing",
            Self::Differs => "differs",
            Self::Unreadable => "unreadable",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        [
            Self::Published,
            Self::Missing,
            Self::Differs,
            Self::Unreadable,
        ]
        .into_iter()
        .find(|v| v.as_str() == s)
    }
}

judged! {
    /// One record a mail domain needs, as last read.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct MailRecord {
        pub domain: String,
        /// The record's name, without the final dot.
        pub name: String,
        pub purpose: Purpose,
        /// The line to add, in zone-file form, as Stalwart computed it.
        pub expected: String,
        pub state: RecordState,
        /// What the resolver answered, or why it could not.
        pub observed: String,
        /// Seconds since the epoch.
        pub checked_at: i64,
    }

    rules {
        attention: crate::Attention = MailRecord::attention,
    }
}

impl MailRecord {
    /// A record missing loses mail or files it as spam; one not read, a look.
    pub fn attention(&self) -> crate::Attention {
        match self.state {
            RecordState::Published => crate::Attention::Ok,
            RecordState::Missing | RecordState::Differs => crate::Attention::Critical,
            RecordState::Unreadable => crate::Attention::Notice,
        }
    }
}

/// One line of the zone Stalwart computed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneRecord {
    /// Without the final dot.
    pub name: String,
    pub kind: String,
    /// The data, a TXT's strings joined.
    pub value: String,
    /// The line as Stalwart wrote it, for a person to paste.
    pub line: String,
}

/// The records of a zone file as Stalwart 0.16 writes it: `name. IN TYPE data`, a long
/// TXT split into quoted strings inside `( … )` over several lines.
pub fn parse_zone(zone: &str) -> Vec<ZoneRecord> {
    let mut out = Vec::new();
    let mut pending: Option<(String, String, String)> = None;
    for raw in zone.lines() {
        if let Some((name, kind, mut text)) = pending.take() {
            text.push('\n');
            text.push_str(raw);
            if raw.trim() == ")" {
                out.push(record(&name, &kind, &text));
            } else {
                pending = Some((name, kind, text));
            }
            continue;
        }
        let mut words = raw.split_whitespace();
        let (Some(name), Some("IN"), Some(kind)) = (words.next(), words.next(), words.next())
        else {
            continue;
        };
        if raw.trim_end().ends_with('(') {
            pending = Some((name.to_string(), kind.to_string(), raw.to_string()));
        } else {
            out.push(record(name, kind, raw));
        }
    }
    out
}

fn record(name: &str, kind: &str, line: &str) -> ZoneRecord {
    let data = line
        .split_once(&format!(" IN {kind} "))
        .map_or("", |(_, d)| d)
        .trim();
    let value = if kind == "TXT" {
        quoted_strings(data).concat()
    } else {
        data.to_string()
    };
    ZoneRecord {
        name: name.trim_end_matches('.').to_string(),
        kind: kind.to_string(),
        value,
        line: line.to_string(),
    }
}

/// The quoted strings of a TXT's data, in order, unescaped.
pub fn quoted_strings(data: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut chars = data.chars();
    while let Some(c) = chars.next() {
        if c != '"' {
            continue;
        }
        let mut s = String::new();
        while let Some(c) = chars.next() {
            match c {
                '\\' => {
                    if let Some(next) = chars.next() {
                        s.push(next);
                    }
                }
                '"' => break,
                c => s.push(c),
            }
        }
        out.push(s);
    }
    out
}

/// A TXT's value from a resolver's data: quoted strings joined — Cloudflare's form,
/// a long key in several —, or as is, Google's.
pub fn txt_value(data: &str) -> String {
    if data.trim_start().starts_with('"') {
        quoted_strings(data).concat()
    } else {
        data.to_string()
    }
}

/// The four kinds of record judged, out of a domain's zone. Every SPF line is: the
/// domain's, and the one Stalwart computes for its own name (`v=spf1 a -all`).
pub fn needed(domain: &str, zone: &[ZoneRecord]) -> Vec<(Purpose, ZoneRecord)> {
    let dmarc = format!("_dmarc.{domain}");
    zone.iter()
        .filter_map(|r| {
            let purpose = match r.kind.as_str() {
                "MX" if r.name == domain => Purpose::Mx,
                "TXT" if r.name.ends_with(&format!("._domainkey.{domain}")) => Purpose::Dkim,
                "TXT" if is_spf(&r.value) => Purpose::Spf,
                "TXT" if r.name == dmarc => Purpose::Dmarc,
                _ => return None,
            };
            Some((purpose, r.clone()))
        })
        .collect()
}

/// Is a line of the zone one a person can publish by hand and be helped by? `ports`
/// are those reaching Stalwart from outside — its published ones, and 443 when it has
/// a route.
///
/// Stalwart writes what it would publish ITSELF through a provider, keeping it in step
/// — offered by hand, most of it does harm. Two kinds only: an SRV on a port that
/// reaches it, and the TLS reports' address. Everything else is left out, counted, and
/// a kind Stalwart adds tomorrow with it:
///
/// - a CNAME (`autoconfig.`, `mta-sts.`…) names a host the ingress does not route, and
///   the TXT announcing it (`_mta-sts.`) points senders at a policy nobody serves;
/// - a TLSA pins today's key — 🔴 at the next renewal a sender enforcing DANE refuses
///   every message, and it needs DNSSEC besides;
/// - a CAA at the domain binds EVERY name under it to Stalwart's ACME account — 🔴 the
///   authority then refuses the ingress's certificates for the other apps —, and
///   `_validation-persist` grants that account the domain for good.
pub fn served(r: &ZoneRecord, ports: &[u16]) -> bool {
    match r.kind.as_str() {
        "SRV" => r
            .value
            .split_whitespace()
            .nth(2)
            .and_then(|p| p.parse::<u16>().ok())
            .is_some_and(|p| ports.contains(&p)),
        "TXT" => r.value.starts_with("v=TLSRPTv1"),
        _ => false,
    }
}

fn is_spf(txt: &str) -> bool {
    txt.to_ascii_lowercase().starts_with("v=spf1")
}

fn is_dmarc(txt: &str) -> bool {
    txt.to_ascii_uppercase().starts_with("V=DMARC1")
}

/// A record judged against the resolver's answer: TXT values with their strings
/// joined, MX as `priority host.`.
pub fn judge(
    purpose: Purpose,
    expected: &ZoneRecord,
    answer: &Result<Vec<String>, String>,
) -> (RecordState, String) {
    let found = match answer {
        Err(why) => return (RecordState::Unreadable, why.clone()),
        Ok(found) => found,
    };
    let observed = if found.is_empty() {
        "nothing".to_string()
    } else {
        found.join(" | ")
    };
    let state = match purpose {
        Purpose::Dkim => {
            let key = |t: &str| {
                t.split(';')
                    .map(str::trim)
                    .find_map(|tag| tag.strip_prefix("p="))
                    .map(|p| p.split_whitespace().collect::<String>())
            };
            let want = key(&expected.value);
            let keys: Vec<Option<String>> = found.iter().map(|t| key(t)).collect();
            if keys.iter().any(|k| k.is_some() && *k == want) {
                RecordState::Published
            } else if keys.iter().any(Option::is_some) {
                RecordState::Differs
            } else {
                RecordState::Missing
            }
        }
        Purpose::Spf => {
            let spf: Vec<&String> = found.iter().filter(|t| is_spf(t)).collect();
            match spf.as_slice() {
                [] => RecordState::Missing,
                [one] => {
                    let terms: Vec<String> = one
                        .split_whitespace()
                        .map(str::to_ascii_lowercase)
                        .collect();
                    // Every way Stalwart says the house sends — `mx`, an `include:` —
                    // must be there; the qualifier on `all` is the household's.
                    let covered = expected
                        .value
                        .split_whitespace()
                        .skip(1)
                        .map(str::to_ascii_lowercase)
                        .filter(|t| !t.trim_start_matches(['-', '~', '?', '+']).eq("all"))
                        .all(|t| terms.contains(&t));
                    if covered {
                        RecordState::Published
                    } else {
                        RecordState::Differs
                    }
                }
                _ => RecordState::Differs,
            }
        }
        Purpose::Mx => {
            let host = |mx: &str| {
                mx.split_whitespace()
                    .last()
                    .unwrap_or("")
                    .trim_end_matches('.')
                    .to_ascii_lowercase()
            };
            let want = host(&expected.value);
            // 🔴 A sender tries the LOWEST preference first: Stalwart's MX beside a
            // foreign one answering at a lower number (or the same, half the time)
            // was "published" while the mail went to the other server.
            let preference = |mx: &str| {
                mx.split_whitespace()
                    .next()
                    .and_then(|p| p.parse::<u16>().ok())
            };
            let ours = found
                .iter()
                .filter(|mx| host(mx) == want)
                .filter_map(|mx| preference(mx))
                .min();
            let first_foreign = found
                .iter()
                .filter(|mx| host(mx) != want)
                .map(|mx| preference(mx))
                .min_by_key(|p| p.unwrap_or(0));
            let first = match (ours, first_foreign) {
                (Some(_), None) => true,
                (Some(o), Some(Some(f))) => o < f,
                // An unreadable preference may be anything, the first included.
                (Some(_), Some(None)) | (None, _) => false,
            };
            if first {
                RecordState::Published
            } else if found.is_empty() {
                RecordState::Missing
            } else {
                RecordState::Differs
            }
        }
        Purpose::Dmarc => match found.iter().filter(|t| is_dmarc(t)).count() {
            0 => RecordState::Missing,
            1 => RecordState::Published,
            _ => RecordState::Differs,
        },
    };
    (state, observed)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Stalwart 0.16.26's own zone for `example.org`, named `mail.example.org`.
    const ZONE: &str = r#"v1-ed25519-20261019._domainkey.example.org. IN TXT "v=DKIM1; k=ed25519; h=sha256; p=WBPN5hINOKV4nmV3Bac24J7OaRYL/za1ojmsw5Dv7lQ="
v1-rsa-20261019._domainkey.example.org. IN TXT (
    "v=DKIM1; k=rsa; h=sha256; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApjfTAXunf"
    "ZJ+iTnTjRq7hKHVGM1RiiMBtBdRNZC2NlPeycSEV+/5EI//2/AMhIn/rCQZtYEq58d2a9+KHuIDAQAB"
)
mail.example.org. IN TXT "v=spf1 a -all"
example.org. IN TXT "v=spf1 mx -all"
example.org. IN MX 10 mail.example.org.
_dmarc.example.org. IN TXT "v=DMARC1; p=reject; rua=mailto:postmaster@example.org"
_imaps._tcp.example.org. IN SRV 0 1 993 mail.example.org.
mta-sts.example.org. IN CNAME mail.example.org.
"#;

    fn need(p: Purpose) -> ZoneRecord {
        needed("example.org", &parse_zone(ZONE))
            .into_iter()
            .find(|(q, r)| *q == p && !r.name.starts_with("mail."))
            .map(|(_, r)| r)
            .expect("in the zone")
    }

    fn ok(v: &[&str]) -> Result<Vec<String>, String> {
        Ok(v.iter().map(|s| s.to_string()).collect())
    }

    #[test]
    fn the_zone_is_read_whole_and_a_split_key_joined() {
        let zone = parse_zone(ZONE);
        assert_eq!(zone.len(), 8, "{zone:#?}");
        let rsa = zone
            .iter()
            .find(|r| r.name == "v1-rsa-20261019._domainkey.example.org")
            .expect("the RSA selector");
        assert!(
            rsa.value.ends_with("ApjfTAXunfZJ+iTnTjRq7hKHVGM1RiiMBtBdRNZC2NlPeycSEV+/5EI//2/AMhIn/rCQZtYEq58d2a9+KHuIDAQAB"),
            "{}",
            rsa.value
        );
        assert!(
            rsa.line.contains("(\n") && rsa.line.ends_with(')'),
            "pasteable: {}",
            rsa.line
        );
    }

    #[test]
    fn four_kinds_are_judged_and_the_helo_spf_with_them() {
        let n = needed("example.org", &parse_zone(ZONE));
        let names: Vec<(Purpose, &str)> = n.iter().map(|(p, r)| (*p, r.name.as_str())).collect();
        assert_eq!(
            names,
            [
                (Purpose::Dkim, "v1-ed25519-20261019._domainkey.example.org"),
                (Purpose::Dkim, "v1-rsa-20261019._domainkey.example.org"),
                (Purpose::Spf, "mail.example.org"),
                (Purpose::Spf, "example.org"),
                (Purpose::Mx, "example.org"),
                (Purpose::Dmarc, "_dmarc.example.org"),
            ]
        );
    }

    #[test]
    fn only_what_helps_published_by_hand_is_offered() {
        // Lines of its 0.16.26 zones — the lab's, under ACME —, ports as the catalog
        // publishes them.
        let zone = parse_zone(
            r#"_imaps._tcp.example.org. IN SRV 0 1 993 mail.example.org.
_pop3s._tcp.example.org. IN SRV 0 1 995 mail.example.org.
_jmap._tcp.example.org. IN SRV 0 1 443 mail.example.org.
mta-sts.example.org. IN CNAME mail.example.org.
_mta-sts.example.org. IN TXT "v=STSv1; id=138449342089700316"
_smtp._tls.example.org. IN TXT "v=TLSRPTv1; rua=mailto:postmaster@example.org"
autoconfig.example.org. IN CNAME mail.example.org.
_25._tcp.mail.example.org. IN TLSA 3 1 1 c1148245f35371be0898f3cd3e013419318f1e475170392dbfc6bf882508b39e
example.org. IN CAA 0 issue "letsencrypt.org;accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/1"
_validation-persist.example.org. IN TXT "letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/1"
"#,
        );
        assert_eq!(zone.len(), 10, "{zone:#?}");
        let kept: Vec<&str> = zone
            .iter()
            .filter(|r| served(r, &[25, 465, 993, 4190, 443]))
            .map(|r| r.name.as_str())
            .collect();
        assert_eq!(
            kept,
            [
                "_imaps._tcp.example.org",
                "_jmap._tcp.example.org",
                "_smtp._tls.example.org"
            ]
        );
        let jmap = zone
            .iter()
            .find(|r| r.name.starts_with("_jmap."))
            .expect("JMAP's SRV");
        assert!(!served(jmap, &[25, 465, 993, 4190]), "no route, no 443");
    }

    #[test]
    fn a_dkim_key_is_published_only_when_it_is_the_same_key() {
        let e = need(Purpose::Dkim);
        let mine = "v=DKIM1; k=ed25519; h=sha256; p=WBPN5hINOKV4nmV3Bac24J7OaRYL/za1ojmsw5Dv7lQ=";
        assert_eq!(
            judge(Purpose::Dkim, &e, &ok(&[mine])).0,
            RecordState::Published
        );
        assert_eq!(judge(Purpose::Dkim, &e, &ok(&[])).0, RecordState::Missing);
        assert_eq!(
            judge(Purpose::Dkim, &e, &ok(&["v=DKIM1; k=ed25519; p=AAAA"])).0,
            RecordState::Differs,
            "the key of a former install"
        );
    }

    #[test]
    fn an_spf_must_name_how_the_house_sends_and_be_alone() {
        let e = need(Purpose::Spf);
        for (txt, state) in [
            (vec!["v=spf1 mx -all"], RecordState::Published),
            (vec!["v=spf1 mx ~all"], RecordState::Published),
            (
                vec![
                    "v=spf1 mx include:_spf.google.com -all",
                    "google-site-verification=x",
                ],
                RecordState::Published,
            ),
            (
                vec!["v=spf1 include:_spf.google.com -all"],
                RecordState::Differs,
            ),
            (
                vec!["v=spf1 mx -all", "v=spf1 a -all"],
                RecordState::Differs,
            ),
            (vec!["google-site-verification=x"], RecordState::Missing),
        ] {
            assert_eq!(judge(Purpose::Spf, &e, &ok(&txt)).0, state, "{txt:?}");
        }
    }

    #[test]
    fn stalwarts_own_name_must_say_its_address_sends() {
        let helo = needed("example.org", &parse_zone(ZONE))
            .into_iter()
            .find(|(_, r)| r.name == "mail.example.org")
            .map(|(_, r)| r)
            .expect("the HELO SPF");
        for (txt, state) in [
            (vec!["v=spf1 a -all"], RecordState::Published),
            (vec![], RecordState::Missing),
            (vec!["v=spf1 mx -all"], RecordState::Differs),
        ] {
            assert_eq!(judge(Purpose::Spf, &helo, &ok(&txt)).0, state, "{txt:?}");
        }
    }

    #[test]
    fn an_mx_must_name_stalwart_and_a_resolver_down_is_not_a_verdict() {
        let e = need(Purpose::Mx);
        assert_eq!(
            judge(Purpose::Mx, &e, &ok(&["10 MAIL.example.org."])).0,
            RecordState::Published
        );
        assert_eq!(
            judge(Purpose::Mx, &e, &ok(&["1 smtp.google.com."])).0,
            RecordState::Differs
        );
        // A backup MX after Stalwart's is the household's choice; one before it, or
        // beside it, takes the mail.
        assert_eq!(
            judge(
                Purpose::Mx,
                &e,
                &ok(&["10 mail.example.org.", "20 backup.example.net."])
            )
            .0,
            RecordState::Published
        );
        for foreign_first in [
            ["5 smtp.google.com.", "10 mail.example.org."],
            ["10 smtp.google.com.", "10 mail.example.org."],
        ] {
            assert_eq!(
                judge(Purpose::Mx, &e, &ok(&foreign_first)).0,
                RecordState::Differs,
                "{foreign_first:?}"
            );
        }
        let (state, observed) = judge(Purpose::Mx, &e, &Err("timed out".into()));
        assert_eq!(
            (state, observed.as_str()),
            (RecordState::Unreadable, "timed out")
        );
    }

    #[test]
    fn two_dmarc_records_are_none() {
        let e = need(Purpose::Dmarc);
        assert_eq!(
            judge(Purpose::Dmarc, &e, &ok(&["v=DMARC1; p=none"])).0,
            RecordState::Published
        );
        assert_eq!(
            judge(
                Purpose::Dmarc,
                &e,
                &ok(&["v=DMARC1; p=none", "v=DMARC1; p=reject"])
            )
            .0,
            RecordState::Differs
        );
    }

    #[test]
    fn every_stored_value_reads_back() {
        for p in [Purpose::Dkim, Purpose::Spf, Purpose::Mx, Purpose::Dmarc] {
            assert_eq!(Purpose::parse(p.as_str()), Some(p));
        }
        for s in [
            RecordState::Published,
            RecordState::Missing,
            RecordState::Differs,
            RecordState::Unreadable,
        ] {
            assert_eq!(RecordState::parse(s.as_str()), Some(s));
        }
    }

    #[test]
    fn a_txt_reads_the_same_from_either_resolver() {
        let cloudflare = r#""v=DKIM1; k=rsa; p=MIIB" "IjAN""#;
        assert_eq!(txt_value(cloudflare), "v=DKIM1; k=rsa; p=MIIBIjAN");
        assert_eq!(txt_value("v=spf1 mx -all"), "v=spf1 mx -all");
    }

    #[test]
    fn a_quoted_string_keeps_its_escaped_quote() {
        assert_eq!(quoted_strings(r#""a\"b" "c""#), ["a\"b", "c"]);
    }
}
