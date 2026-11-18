//! The router's certificate, pinned by its SHA-256.
//!
//! OPNsense serves its interface and API under a certificate it signed itself at first
//! boot: no authority a client trusts vouches for it, and accepting any certificate
//! would hand the API key to whoever answers at the router's address. Its console
//! prints the fingerprint (`HTTPS: SHA256 AB C1 …`), so a person can compare what
//! Homelabus read with what the machine itself says — and from then on only that
//! certificate is accepted.

use std::fmt;
use std::sync::{Arc, Mutex};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};

use crate::{Error, Result};

/// The SHA-256 of a certificate's DER, as OPNsense's console prints it.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Fingerprint([u8; 32]);

impl Fingerprint {
    pub fn of(der: &[u8]) -> Self {
        Self(Sha256::digest(der).into())
    }

    /// Hexadecimal in any case, with or without the spaces or colons the console and
    /// browsers separate it with.
    pub fn parse(text: &str) -> Option<Self> {
        let digits: Vec<u8> = text
            .bytes()
            .filter(|b| !matches!(b, b' ' | b':' | b'\t' | b'\n' | b'\r'))
            .collect();
        if digits.len() != 64 {
            return None;
        }
        let mut out = [0u8; 32];
        for (i, pair) in digits.chunks(2).enumerate() {
            let hi = (pair[0] as char).to_digit(16)?;
            let lo = (pair[1] as char).to_digit(16)?;
            out[i] = (hi * 16 + lo) as u8;
        }
        Some(Self(out))
    }

    /// The form kept in the state: 64 small letters and digits.
    pub fn hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }
}

/// Spaced and in capitals, as the router's console shows it.
impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let pairs: Vec<String> = self.0.iter().map(|b| format!("{b:02X}")).collect();
        f.write_str(&pairs.join(" "))
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fingerprint({})", self.hex())
    }
}

/// Accepts the one certificate pinned and nothing else — its name, its issuer and its
/// dates are not read: a self-signed certificate has nobody to vouch for them, and the
/// pin says more than they would. The handshake's signatures ARE checked, so a server
/// presenting the pinned certificate must hold its key.
#[derive(Debug)]
struct Pinned {
    /// `None` to read the certificate and refuse it: nothing is ever sent then.
    expected: Option<Fingerprint>,
    seen: Arc<Mutex<Option<Fingerprint>>>,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let presented = Fingerprint::of(end_entity.as_ref());
        if let Ok(mut seen) = self.seen.lock() {
            *seen = Some(presented);
        }
        match self.expected {
            Some(pin) if pin == presented => Ok(ServerCertVerified::assertion()),
            _ => Err(rustls::Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            )),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn client(
    expected: Option<Fingerprint>,
    seen: Arc<Mutex<Option<Fingerprint>>>,
) -> Result<reqwest::Client> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| Error::Tls(e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Pinned {
            expected,
            seen,
            provider,
        }))
        .with_no_client_auth();
    // 🔴 Never `unwrap_or_default()` here: the default client trusts the system's
    // authorities and not the pin, so a failed build would quietly drop it.
    reqwest::Client::builder()
        .tls_backend_preconfigured(config)
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| Error::Tls(e.to_string()))
}

/// A client that talks to the certificate `pin` and to no other.
pub fn pinned(pin: Fingerprint) -> Result<reqwest::Client> {
    client(Some(pin), Arc::default())
}

/// The certificate `url` presents, read during a handshake that is then refused: no
/// request is ever sent to a server not yet compared with its console.
pub async fn peek(url: &str) -> Result<Fingerprint> {
    let seen = Arc::new(Mutex::new(None));
    let http = client(None, seen.clone())?;
    let refused = http.get(url).send().await;
    let read = seen.lock().ok().and_then(|s| *s);
    match (read, refused) {
        (Some(f), _) => Ok(f),
        (None, Err(e)) => Err(Error::Http {
            source: e,
            context: format!("reading the certificate of {url}"),
        }),
        (None, Ok(_)) => Err(Error::Unexpected(format!(
            "{url} answered without TLS — the router's API is https"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONSOLE: &str = "AB C1 7B 69 48 3C DD 50 C5 FF 36 FC A0 1A 33 F1
               3D 31 DD 38 64 26 67 D0 DA A1 BC 13 07 32 C2 06";

    #[test]
    fn the_consoles_fingerprint_reads_as_printed() {
        let f = Fingerprint::parse(CONSOLE).expect("the console's form");
        assert_eq!(
            f.hex(),
            "abc17b69483cdd50c5ff36fca01a33f13d31dd38642667d0daa1bc130732c206"
        );
        assert_eq!(Fingerprint::parse(&f.hex()), Some(f));
        assert_eq!(Fingerprint::parse(&f.to_string()), Some(f));
        let colons = f.to_string().replace(' ', ":").to_lowercase();
        assert_eq!(Fingerprint::parse(&colons), Some(f));
    }

    #[test]
    fn a_fingerprint_of_the_wrong_length_or_alphabet_is_none() {
        assert_eq!(Fingerprint::parse("abcd"), None);
        assert_eq!(Fingerprint::parse(&"g".repeat(64)), None);
        assert_eq!(Fingerprint::parse(&"a".repeat(66)), None);
    }

    fn verify(expected: Option<Fingerprint>, der: &[u8]) -> (bool, Option<Fingerprint>) {
        let seen = Arc::new(Mutex::new(None));
        let v = Pinned {
            expected,
            seen: seen.clone(),
            provider: Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
        };
        let name = ServerName::try_from("10.77.0.3").expect("an address");
        let ok = v
            .verify_server_cert(&CertificateDer::from(der), &[], &name, &[], UnixTime::now())
            .is_ok();
        let read = *seen.lock().expect("not poisoned");
        (ok, read)
    }

    #[test]
    fn only_the_pinned_certificate_is_accepted() {
        let der = b"a certificate".as_slice();
        let pin = Fingerprint::of(der);
        assert_eq!(verify(Some(pin), der), (true, Some(pin)));
        let (ok, read) = verify(Some(pin), b"another certificate");
        assert!(!ok, "a certificate other than the pin is refused");
        assert_eq!(read, Some(Fingerprint::of(b"another certificate")));
    }

    #[test]
    fn a_peek_reads_the_certificate_and_refuses_it() {
        let der = b"a certificate".as_slice();
        assert_eq!(verify(None, der), (false, Some(Fingerprint::of(der))));
    }

    #[test]
    fn the_pinned_configuration_is_one_reqwest_takes() {
        // A rustls of another version than reqwest's is refused at build — the error
        // the client would otherwise meet only on a real router.
        pinned(Fingerprint::of(b"x")).expect("reqwest takes the configuration");
    }
}
