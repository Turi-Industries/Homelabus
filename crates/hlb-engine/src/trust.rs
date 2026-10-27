//! The private roots, handed to the apps that verify a platform service themselves.
//!
//! Under `--internal`, or a private ACME authority, PocketID's certificate is signed by
//! a root no image trusts. The controller is given it; an app signing people in through
//! PocketID (`sso: native`) fetches the issuer's discovery document itself, and failed
//! on "certificate signed by unknown authority" — its sign-in button led nowhere. And an
//! app sending mail (`smtp`) meets Stalwart's submission port, served under
//! Homelabus's own root whatever the exposure (`crate::submission`).
//!
//! The root goes in a directory of its own, ADDED to what the image trusts, never in
//! place of it: an app also reaches the internet (avatars, updates, webhooks), and a
//! trust store holding the private root alone would refuse every public certificate.
//!
//! | Stack | What it reads |
//! |---|---|
//! | Go (Gitea, Vikunja, oauth2-proxy, Grafana) | every file of every `SSL_CERT_DIR` directory, after its system file |
//! | OpenSSL, `rustls-native-certs` (Vaultwarden) | `SSL_CERT_DIR`, files named `<subject hash>.<n>` only |
//! | Node (Immich, Termix) | `NODE_EXTRA_CA_CERTS`, added to its bundled roots |
//!
//! Hence the file is named the way `openssl rehash` names it, and `/etc/ssl/certs`
//! stays first in the list.

use sha1::{Digest, Sha1};

/// Where the root is mounted in the app's container.
pub const DIR: &str = "/run/hlb/trust";

/// Does this app fetch PocketID's issuer itself, and so need the root to trust it?
pub fn verifies_issuer(m: &hlb_types::Manifest) -> bool {
    m.spec.requires.iter().any(|c| {
        matches!(
            c,
            hlb_types::Capability::Sso {
                mode: hlb_types::SsoMode::Native,
                redirect_paths: _,
            }
        )
    })
}

/// Does this app reach Stalwart's submission port, and so need Homelabus's root?
pub fn sends_mail(m: &hlb_types::Manifest) -> bool {
    m.spec
        .requires
        .iter()
        .any(|c| matches!(c, hlb_types::Capability::Smtp { sender: _ }))
}

/// Where the roots are mounted for Node, which reads one file of several.
pub const BUNDLE: &str = "roots.pem";

/// What an app is given to trust `roots`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mount {
    /// `(path in the container, content)`.
    pub files: Vec<(String, String)>,
    /// The variables pointing its TLS stack there.
    pub env: Vec<(String, String)>,
}

/// Each root under its `openssl rehash` name, the same ones in one bundle, and the
/// variables naming them. `None` when no PEM holds a certificate this can read.
pub fn mount(roots: &[String]) -> Option<Mount> {
    let mut files: Vec<(String, String)> = Vec::new();
    let mut bundle = String::new();
    for root in roots {
        let Some(hash) = subject_hash(root) else {
            continue;
        };
        if files.iter().any(|(_, c)| c == root) {
            continue;
        }
        // Two roots of one subject share a hash: OpenSSL then looks at `.0`, `.1`…
        let n = files
            .iter()
            .filter(|(p, _)| p.starts_with(&format!("{DIR}/{hash}.")))
            .count();
        files.push((format!("{DIR}/{hash}.{n}"), root.clone()));
        bundle.push_str(root.trim_end());
        bundle.push('\n');
    }
    if files.is_empty() {
        return None;
    }
    files.push((format!("{DIR}/{BUNDLE}"), bundle));
    let env = vec![
        ("SSL_CERT_DIR".to_string(), format!("/etc/ssl/certs:{DIR}")),
        ("NODE_EXTRA_CA_CERTS".to_string(), format!("{DIR}/{BUNDLE}")),
    ];
    Some(Mount { files, env })
}

/// OpenSSL's subject hash (`openssl x509 -subject_hash`): the name `openssl rehash`
/// gives a certificate, and the only one OpenSSL looks it up by.
///
/// The first four bytes, little-endian, of the SHA-1 of the subject's CANONICAL form:
/// each string value as UTF-8, trimmed, its inner whitespace collapsed, ASCII lowered —
/// so `CN=Homelabus  Root` and `cn=homelabus root` share a file.
pub fn subject_hash(pem: &str) -> Option<String> {
    let der = rustls_pemfile::certs(&mut pem.as_bytes()).next()?.ok()?;
    let canon = canonical_subject(subject(der.as_ref())?)?;
    let digest = Sha1::digest(&canon);
    let first = u32::from_le_bytes([digest[0], digest[1], digest[2], digest[3]]);
    Some(format!("{first:08x}"))
}

/// One DER element: its tag, and its content.
fn element(der: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = der.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = if first < 0x80 {
        (first as usize, rest)
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 4 || rest.len() < n {
            return None;
        }
        let len = rest[..n]
            .iter()
            .fold(0usize, |acc, b| (acc << 8) | *b as usize);
        (len, &rest[n..])
    };
    (rest.len() >= len).then(|| (tag, &rest[..len], &rest[len..]))
}

/// The elements a constructed element contains.
fn children(mut content: &[u8]) -> Option<Vec<(u8, &[u8])>> {
    let mut out = Vec::new();
    while !content.is_empty() {
        let (tag, inner, rest) = element(content)?;
        out.push((tag, inner));
        content = rest;
    }
    Some(out)
}

/// The subject `Name`'s content: the sixth field of `tbsCertificate`, the fifth when
/// the version is left out.
fn subject(cert: &[u8]) -> Option<&[u8]> {
    let (_, cert, _) = element(cert)?;
    let (_, tbs, _) = element(cert)?;
    let fields = children(tbs)?;
    let skip = usize::from(fields.first()?.0 == 0xa0);
    let (tag, name) = *fields.get(skip + 4)?;
    (tag == 0x30).then_some(name)
}

/// `x509_name_canon`: every RDN set re-encoded with its strings canonical, one after
/// the other, without the outer SEQUENCE.
fn canonical_subject(name: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    for (tag, set) in children(name)? {
        if tag != 0x31 {
            return None;
        }
        let mut entries = Vec::new();
        for (tag, atv) in children(set)? {
            if tag != 0x30 {
                return None;
            }
            let parts = children(atv)?;
            let ((oid_tag, oid), (value_tag, value)) = (*parts.first()?, *parts.get(1)?);
            let mut body = encode(oid_tag, oid);
            match utf8(value_tag, value) {
                Some(s) => body.extend(encode(0x0c, canonical(&s).as_bytes())),
                None => body.extend(encode(value_tag, value)),
            }
            entries.push(encode(0x30, &body));
        }
        // DER sorts a SET OF by encoding.
        entries.sort();
        out.extend(encode(0x31, &entries.concat()));
    }
    Some(out)
}

/// A string value as UTF-8, for the types OpenSSL canonicalises (`ASN1_MASK_CANON`).
/// Any other type — NumericString among them — is kept as it is.
fn utf8(tag: u8, v: &[u8]) -> Option<String> {
    match tag {
        0x0c => String::from_utf8(v.to_vec()).ok(),
        // PrintableString, T61String, IA5String, VisibleString: one byte a character.
        0x13 | 0x14 | 0x16 | 0x1a => Some(v.iter().map(|b| *b as char).collect()),
        // BMPString: UCS-2, big-endian.
        0x1e => char::decode_utf16(
            v.chunks(2)
                .map(|c| u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)])),
        )
        .collect::<Result<String, _>>()
        .ok(),
        // UniversalString: UCS-4, big-endian.
        0x1c => v
            .chunks(4)
            .map(|c| {
                let mut b = [0u8; 4];
                b[..c.len()].copy_from_slice(c);
                char::from_u32(u32::from_be_bytes(b))
            })
            .collect(),
        _ => None,
    }
}

/// `asn1_string_canon`: trimmed, inner whitespace collapsed to one space, ASCII
/// lowered, every other byte kept.
fn canonical(s: &str) -> String {
    let space = |c: char| matches!(c, ' ' | '\t' | '\n' | '\x0b' | '\x0c' | '\r');
    let mut out = String::with_capacity(s.len());
    let mut in_space = false;
    for c in s.trim_matches(space).chars() {
        if space(c) {
            if !in_space {
                out.push(' ');
            }
            in_space = true;
        } else {
            out.push(c.to_ascii_lowercase());
            in_space = false;
        }
    }
    out
}

fn encode(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes: Vec<u8> = len
            .to_be_bytes()
            .into_iter()
            .skip_while(|b| *b == 0)
            .collect();
        out.push(0x80 | bytes.len() as u8);
        out.extend(bytes);
    }
    out.extend_from_slice(content);
    out
}

/// ISRG Root X1, which `openssl rehash` files as `4042bcee.0`.
#[cfg(test)]
pub(crate) const ISRG_ROOT_X1: &str = "-----BEGIN CERTIFICATE-----
MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTUwNjA0MTEwNDM4
WhcNMzUwNjA0MTEwNDM4WjBPMQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJu
ZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBY
MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK3oJHP0FDfzm54rVygc
h77ct984kIxuPOZXoHj3dcKi/vVqbvYATyjb3miGbESTtrFj/RQSa78f0uoxmyF+
0TM8ukj13Xnfs7j/EvEhmkvBioZxaUpmZmyPfjxwv60pIgbz5MDmgK7iS4+3mX6U
A5/TR5d8mUgjU+g4rk8Kb4Mu0UlXjIB0ttov0DiNewNwIRt18jA8+o+u3dpjq+sW
T8KOEUt+zwvo/7V3LvSye0rgTBIlDHCNAymg4VMk7BPZ7hm/ELNKjD+Jo2FR3qyH
B5T0Y3HsLuJvW5iB4YlcNHlsdu87kGJ55tukmi8mxdAQ4Q7e2RCOFvu396j3x+UC
B5iPNgiV5+I3lg02dZ77DnKxHZu8A/lJBdiB3QW0KtZB6awBdpUKD9jf1b0SHzUv
KBds0pjBqAlkd25HN7rOrFleaJ1/ctaJxQZBKT5ZPt0m9STJEadao0xAH0ahmbWn
OlFuhjuefXKnEgV4We0+UXgVCwOPjdAvBbI+e0ocS3MFEvzG6uBQE3xDk3SzynTn
jh8BCNAw1FtxNrQHusEwMFxIt4I7mKZ9YIqioymCzLq9gwQbooMDQaHWBfEbwrbw
qHyGO0aoSCqI3Haadr8faqU9GY/rOPNk3sgrDQoo//fb4hVC1CLQJ13hef4Y53CI
rU7m2Ys6xt0nUW7/vGT1M0NPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNV
HRMBAf8EBTADAQH/MB0GA1UdDgQWBBR5tFnme7bl5AFzgAiIyBpY9umbbjANBgkq
hkiG9w0BAQsFAAOCAgEAVR9YqbyyqFDQDLHYGmkgJykIrGF1XIpu+ILlaS/V9lZL
ubhzEFnTIZd+50xx+7LSYK05qAvqFyFWhfFQDlnrzuBZ6brJFe+GnY+EgPbk6ZGQ
3BebYhtF8GaV0nxvwuo77x/Py9auJ/GpsMiu/X1+mvoiBOv/2X/qkSsisRcOj/KK
NFtY2PwByVS5uCbMiogziUwthDyC3+6WVwW6LLv3xLfHTjuCvjHIInNzktHCgKQ5
ORAzI4JMPJ+GslWYHb4phowim57iaztXOoJwTdwJx4nLCgdNbOhdjsnvzqvHu7Ur
TkXWStAmzOVyyghqpZXjFaH3pO3JLF+l+/+sKAIuvtd7u+Nxe5AW0wdeRlN8NwdC
jNPElpzVmbUq4JUagEiuTDkHzsxHpFKVK7q4+63SM1N95R1NbdWhscdCb+ZAJzVc
oyi3B43njTOQ5yOf+1CceWxG1bQVs5ZufpsMljq4Ui0/1lvh+wjChP4kqKOJ2qxq
4RgqsahDYVvTH9w7jXbyLeiNdd8XM2w9U/t7y0Ff/9yi0GE44Za4rF2LN9d11TPA
mRGunUHBcnWEvgJBQl9nJEiU0Zsnvgc/ubhPgXRR4Xq37Z0j4r7g1SgEEzwxA57d
emyPxgcYxn/eR44/KJ4EBs+lVDR3veyJm+kXQ99b21/+jh5Xos1AnX5iItreGCc=
-----END CERTIFICATE-----
";

/// ISRG Root X2, ECDSA, filed as `0b9bc432.0`.
#[cfg(test)]
const ISRG_ROOT_X2: &str = "-----BEGIN CERTIFICATE-----
MIICGzCCAaGgAwIBAgIQQdKd0XLq7qeAwSxs6S+HUjAKBggqhkjOPQQDAzBPMQsw
CQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJuZXQgU2VjdXJpdHkgUmVzZWFyY2gg
R3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBYMjAeFw0yMDA5MDQwMDAwMDBaFw00
MDA5MTcxNjAwMDBaME8xCzAJBgNVBAYTAlVTMSkwJwYDVQQKEyBJbnRlcm5ldCBT
ZWN1cml0eSBSZXNlYXJjaCBHcm91cDEVMBMGA1UEAxMMSVNSRyBSb290IFgyMHYw
EAYHKoZIzj0CAQYFK4EEACIDYgAEzZvVn4CDCuwJSvMWSj5cz3es3mcFDR0HttwW
+1qLFNvicWDEukWVEYmO6gbf9yoWHKS5xcUy4APgHoIYOIvXRdgKam7mAHf7AlF9
ItgKbppbd9/w+kHsOdx1ymgHDB/qo0IwQDAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0T
AQH/BAUwAwEB/zAdBgNVHQ4EFgQUfEKWrt5LSDv6kviejM9ti6lyN5UwCgYIKoZI
zj0EAwMDaAAwZQIwe3lORlCEwkSHRhtFcP9Ymd70/aTSVaYgLXTWNLxBo1BfASdW
tL4ndQavEi51mI38AjEAi/V3bNTIZargCyzuFJ0nN6T5U6VR5CmD1/iQMVtCnwr1
/q4AaOeMSQ+2b1tbFfLn
-----END CERTIFICATE-----
";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_hash_is_the_name_openssl_files_a_root_under() {
        assert_eq!(subject_hash(ISRG_ROOT_X1).as_deref(), Some("4042bcee"));
    }

    #[test]
    fn strings_compare_as_openssl_compares_them() {
        assert_eq!(
            canonical("  Homelabus \t lab.HLB.test  "),
            "homelabus lab.hlb.test"
        );
        // Only ASCII is lowered: OpenSSL keeps every byte with its high bit set.
        assert_eq!(canonical("Électricité"), "Électricité");
    }

    #[test]
    fn the_root_is_added_beside_the_images_own() {
        let m = mount(&[ISRG_ROOT_X1.into()]).expect("a certificate");
        assert_eq!(
            m.files[0],
            ("/run/hlb/trust/4042bcee.0".into(), ISRG_ROOT_X1.into())
        );
        let get = |k: &str| m.env.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
        // The system directory first: replacing it would refuse every public site.
        assert_eq!(get("SSL_CERT_DIR"), Some("/etc/ssl/certs:/run/hlb/trust"));
        assert_eq!(get("NODE_EXTRA_CA_CERTS"), Some("/run/hlb/trust/roots.pem"));
    }

    #[test]
    fn two_roots_are_both_trusted_and_one_root_once() {
        // PocketID's under a private ACME authority, Stalwart's under Homelabus's own:
        // an app signing in AND sending mail needs both.
        let other = ISRG_ROOT_X2.to_string();
        let m = mount(&[ISRG_ROOT_X1.into(), other.clone(), ISRG_ROOT_X1.into()]).expect("roots");
        assert_eq!(m.files.len(), 3, "two roots and the bundle: {:?}", m.files);
        assert_eq!(m.files[1].0, "/run/hlb/trust/0b9bc432.0");
        let bundle = &m.files[2].1;
        assert!(bundle.contains(ISRG_ROOT_X1.trim_end()) && bundle.contains(other.trim_end()));
    }

    #[test]
    fn what_is_not_a_certificate_mounts_nothing() {
        assert_eq!(mount(&["hello".into()]), None);
        assert_eq!(mount(&[]), None);
        assert_eq!(subject_hash(""), None);
    }

    /// Every root of this machine's store is linked under the name computed here.
    /// The store also links each root under OpenSSL's OLD hash (MD5), so a name is
    /// looked up, not compared. Ignored: the store is the host's, and macOS has none
    /// in this shape.
    #[test]
    #[ignore = "reads the host's /etc/ssl/certs"]
    fn every_root_of_the_host_is_filed_under_its_hash() {
        let names: std::collections::BTreeSet<String> = std::fs::read_dir("/etc/ssl/certs")
            .expect("store")
            .filter_map(|e| e.ok()?.file_name().into_string().ok())
            .collect();
        let mut checked = 0;
        for name in names.iter().filter(|n| n.ends_with(".0")) {
            let pem = std::fs::read_to_string(format!("/etc/ssl/certs/{name}")).expect("pem");
            let hash = subject_hash(&pem).expect("a certificate");
            assert!(
                (0..10).any(|n| names.contains(&format!("{hash}.{n}"))),
                "{name}: no {hash}.n in the store"
            );
            checked += 1;
        }
        // A store that read as empty would pass on nothing.
        assert!(checked > 100, "only {checked} roots checked");
    }
}
