//! Vulnerability scanning and signature verification.
//!
//! ## What each one answers
//!
//! The two tools are often confused although they answer opposite questions:
//!
//! | | Question | What a failure means |
//! |---|---|---|
//! | **Trivy** | does the image contain known flaws? | the content is risky |
//! | **cosign** | does the image come from who it claims? | the image may be substituted |
//!
//! A signed image can be riddled with CVEs; a clean image can have been replaced. Both
//! are needed, and a signature failure is **always** more serious than a scan failure.
//!
//! ## 🔴 A missing tool is not a green light
//!
//! This module's central trap. If `trivy` is not installed and that is treated as "no
//! vulnerability found", every update passes while appearing to have been checked. That
//! is worse than not scanning at all, because you believe you are.
//!
//! So each result explicitly separates **"checked and clean"** from **"not checked"**,
//! and the caller must handle the two differently.

use crate::Result;
use hlb_types::ImageSigner;

/// A check's verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Check performed, nothing to report.
    Clean,
    /// Check performed, problems found.
    Findings {
        critical: usize,
        high: usize,
        detail: String,
    },
    /// 🔴 Check **not performed**. This is not a success.
    NotChecked { reason: String },
}

impl Verdict {
    /// Did the check actually happen?
    pub fn was_checked(&self) -> bool {
        !matches!(self, Self::NotChecked { .. })
    }

    /// Can we continue without a human decision?
    ///
    /// 🔴 `NotChecked` does not block - otherwise a homelab without `trivy` could never
    /// update again, and the user would disable the check entirely. But it does not
    /// count as "clean" either: `was_checked()` is what says so.
    pub fn blocks(&self) -> bool {
        matches!(self, Self::Findings { critical, .. } if *critical > 0)
    }

    pub fn describe(&self) -> String {
        match self {
            Self::Clean => "✓ no critical vulnerability".into(),
            Self::Findings {
                critical,
                high,
                detail,
            } => {
                format!("🔴 {critical} critical, {high} high - {detail}")
            }
            Self::NotChecked { reason } => {
                format!("⚠️  NOT CHECKED ({reason}) - which is not the same as \"clean\"")
            }
        }
    }
}

/// Scans an image with Trivy.
///
/// ⚠️ `--severity CRITICAL,HIGH`: with no filter, an ordinary Debian image reports
/// hundreds of low-severity vulnerabilities nobody will read. A report nobody reads
/// protects nothing.
///
/// `--ignore-unfixed`: a flaw with no available fix calls for no action. Reporting it
/// on every update trains people to ignore the report.
pub async fn scan_image(image: &str) -> Verdict {
    let out = tokio::process::Command::new("trivy")
        .args([
            "image",
            "--quiet",
            "--format",
            "json",
            "--severity",
            "CRITICAL,HIGH",
            "--ignore-unfixed",
            // Without this, a slow registry stalls the pipeline indefinitely.
            "--timeout",
            "5m",
            image,
        ])
        .output()
        .await;

    let out = match out {
        Ok(o) => o,
        Err(e) => {
            return Verdict::NotChecked {
                reason: format!("trivy unavailable: {e}"),
            }
        }
    };

    if !out.status.success() {
        return Verdict::NotChecked {
            reason: format!(
                "trivy failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ),
        };
    }

    parse_trivy(&String::from_utf8_lossy(&out.stdout))
}

/// Reads Trivy's JSON output.
pub fn parse_trivy(json: &str) -> Verdict {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(json) else {
        // 🔴 Unreadable output is NOT a clean image: the format may have changed
        // between versions, and reading it as a success would silently disable the
        // check.
        return Verdict::NotChecked {
            reason: "unreadable trivy output".into(),
        };
    };

    let mut critical = 0;
    let mut high = 0;
    let mut examples = Vec::new();

    for r in v
        .get("Results")
        .and_then(|r| r.as_array())
        .into_iter()
        .flatten()
    {
        for vuln in r
            .get("Vulnerabilities")
            .and_then(|x| x.as_array())
            .into_iter()
            .flatten()
        {
            match vuln.get("Severity").and_then(|s| s.as_str()) {
                Some("CRITICAL") => {
                    critical += 1;
                    if examples.len() < 3 {
                        if let Some(id) = vuln.get("VulnerabilityID").and_then(|x| x.as_str()) {
                            examples.push(id.to_string());
                        }
                    }
                }
                Some("HIGH") => high += 1,
                _ => {}
            }
        }
    }

    if critical == 0 && high == 0 {
        return Verdict::Clean;
    }
    Verdict::Findings {
        critical,
        high,
        detail: if examples.is_empty() {
            "see the full report".into()
        } else {
            examples.join(", ")
        },
    }
}

/// Verifies an image's signature with cosign.
///
/// `identity` and `issuer` describe WHO is allowed to have signed. Omitting them
/// amounts to accepting any valid signature - including that of an attacker who signed
/// their own image with their own account.
pub async fn verify_signature(
    image: &str,
    identity_regexp: Option<&str>,
    issuer: Option<&str>,
) -> Verdict {
    let (Some(identity), Some(issuer)) = (identity_regexp, issuer) else {
        // 🔴 With no expected identity, `cosign verify` accepts any valid signature.
        // An attacker signs their image with their own GitHub account and passes.
        // Refusing to verify is more honest than verifying anything.
        return Verdict::NotChecked {
            reason: "no signer identity declared - a verification without \
                     one accepts any signature"
                .into(),
        };
    };
    cosign_verify(image, identity, issuer, false).await
}

/// Verifies an image against the signer its manifest declares, if any.
///
/// A signed SLSA provenance counts: cosign 3.1.4's `verify` takes any Sigstore bundle
/// among the digest's OCI referrers, and Vaultwarden and Bulwark publish that
/// alone (measured 2026-11-01). A cosign that stopped doing so would refuse their
/// updates as unsigned — closed, and `hlb-catalog`'s `signatures` test says it first.
pub async fn verify_signed_by(image: &str, signer: Option<&ImageSigner>) -> Verdict {
    let Some(signer) = signer else {
        return Verdict::NotChecked {
            reason: "no signer declared for this image".into(),
        };
    };
    cosign_verify(image, &signer.identity_regexp(), ImageSigner::ISSUER, true).await
}

async fn cosign_verify(image: &str, identity: &str, issuer: &str, declared: bool) -> Verdict {
    let out = tokio::process::Command::new("cosign")
        .args([
            "verify",
            "--certificate-identity-regexp",
            identity,
            "--certificate-oidc-issuer",
            issuer,
            image,
        ])
        .output()
        .await;

    match out {
        Err(e) => Verdict::NotChecked {
            reason: format!("cosign unavailable: {e}"),
        },
        Ok(o) if o.status.success() => Verdict::Clean,
        Ok(o) => read_failure(&String::from_utf8_lossy(&o.stderr), declared),
    }
}

/// What a failed `cosign verify` means.
///
/// Separating "no signature" from "invalid signature": the first is common (most images
/// are unsigned), the second is a security alert. 🔴 Unless the manifest declares who
/// signs the image: its publisher signs every release, so a digest carrying no
/// signature is not theirs. cosign 3.1 says "no signatures found" for an unsigned image
/// and for a digest the registry does not hold alike, and "no matching attestations"
/// for one signed by someone else.
fn read_failure(stderr: &str, declared: bool) -> Verdict {
    let unsigned =
        stderr.contains("no matching signatures") || stderr.contains("no signatures found");
    if unsigned && !declared {
        return Verdict::NotChecked {
            reason: "unsigned image".into(),
        };
    }
    Verdict::Findings {
        critical: 1,
        high: 0,
        detail: if unsigned {
            "UNSIGNED, though its publisher signs every release".into()
        } else {
            format!("INVALID signature: {}", stderr.trim())
        },
    }
}

/// The combined result of both checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub image: String,
    pub vulnerabilities: Verdict,
    pub signature: Verdict,
}

impl Report {
    /// Must the update be refused without intervention?
    pub fn blocks(&self) -> bool {
        self.vulnerabilities.blocks() || self.signature.blocks()
    }

    /// How many checks did not happen.
    pub fn unchecked(&self) -> usize {
        usize::from(!self.vulnerabilities.was_checked())
            + usize::from(!self.signature.was_checked())
    }

    pub fn describe(&self) -> String {
        format!(
            "{}\n  vulnerabilities: {}\n  signature      : {}",
            self.image,
            self.vulnerabilities.describe(),
            match &self.signature {
                // `Verdict` speaks of vulnerabilities; a signature's finding is its detail.
                Verdict::Clean => "✓ signed by the expected signer".into(),
                Verdict::Findings { detail, .. } => format!("🔴 {detail}"),
                v @ Verdict::NotChecked { .. } => v.describe(),
            }
        )
    }
}

/// Full check of an image.
pub async fn audit(
    image: &str,
    identity_regexp: Option<&str>,
    issuer: Option<&str>,
) -> Result<Report> {
    Ok(Report {
        image: image.to_string(),
        vulnerabilities: scan_image(image).await,
        signature: verify_signature(image, identity_regexp, issuer).await,
    })
}

/// Full check of an image, against the signer its manifest declares.
pub async fn audit_signed_by(image: &str, signer: Option<&ImageSigner>) -> Result<Report> {
    Ok(Report {
        image: image.to_string(),
        vulnerabilities: scan_image(image).await,
        signature: verify_signed_by(image, signer).await,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_tool_is_never_a_pass() {
        // 🔴 The central trap. Treating "trivy absent" as "nothing found" would let
        // every update through while appearing to have been checked - worse than not
        // scanning at all.
        let v = Verdict::NotChecked {
            reason: "trivy unavailable".into(),
        };

        assert!(!v.was_checked());
        assert!(!v.blocks(), "but it must not block either");
        assert!(v.describe().contains("NOT CHECKED"), "{}", v.describe());
        assert!(
            v.describe().contains("not the same as"),
            "the message must say this is not \"clean\""
        );
    }

    #[test]
    fn a_clean_scan_and_an_unchecked_one_are_distinguishable() {
        assert!(Verdict::Clean.was_checked());
        assert!(!Verdict::NotChecked { reason: "x".into() }.was_checked());
        assert_ne!(Verdict::Clean, Verdict::NotChecked { reason: "x".into() });
    }

    #[test]
    fn only_critical_findings_block() {
        // High-severity flaws are reported, not blocking: blocking on them would stop
        // practically every Debian image update, and the user would end up disabling
        // the check.
        let high = Verdict::Findings {
            critical: 0,
            high: 12,
            detail: "x".into(),
        };
        assert!(!high.blocks());

        let crit = Verdict::Findings {
            critical: 1,
            high: 0,
            detail: "CVE-2026-1".into(),
        };
        assert!(crit.blocks());
    }

    #[test]
    fn trivy_output_is_parsed() {
        let json = r#"{"Results":[{"Target":"app","Vulnerabilities":[
            {"VulnerabilityID":"CVE-2026-1111","Severity":"CRITICAL"},
            {"VulnerabilityID":"CVE-2026-2222","Severity":"HIGH"},
            {"VulnerabilityID":"CVE-2026-3333","Severity":"HIGH"}]}]}"#;

        match parse_trivy(json) {
            Verdict::Findings {
                critical,
                high,
                detail,
            } => {
                assert_eq!(critical, 1);
                assert_eq!(high, 2);
                assert!(detail.contains("CVE-2026-1111"), "{detail}");
            }
            other => panic!("expected findings, got {other:?}"),
        }
    }

    #[test]
    fn an_empty_result_is_clean() {
        assert_eq!(parse_trivy(r#"{"Results":[]}"#), Verdict::Clean);
        // Trivy sometimes returns `null` rather than an empty array.
        assert_eq!(parse_trivy(r#"{"Results":null}"#), Verdict::Clean);
    }

    #[test]
    fn unreadable_output_is_not_clean() {
        // 🔴 Trivy's format changes between major versions. Reading it as a success
        // would silently disable the check.
        assert!(!parse_trivy("not json").was_checked());
        assert!(!parse_trivy("").was_checked());
    }

    #[tokio::test]
    async fn verification_without_a_declared_signer_is_refused() {
        // 🔴 `cosign verify` with no identity accepts ANY valid signature: an attacker
        // signs their image with their own account and passes the check.
        let v = verify_signature("alpine:3", None, None).await;
        assert!(!v.was_checked());
        assert!(v.describe().contains("identity"), "{}", v.describe());
    }

    #[test]
    fn an_unsigned_image_blocks_only_when_its_publisher_signs() {
        // cosign 3.1.4's own words, measured on gitea/gitea:28.2 (unsigned) and on
        // Vikunja 2.7 against another workflow.
        let unsigned = "Error: no signatures found\nerror during command execution: no \
                        signatures found\n";
        let other = "error during command execution: no matching attestations: failed to \
                     verify certificate identity: no matching CertificateIdentity found";
        assert!(!read_failure(unsigned, false).blocks());
        assert!(!read_failure(unsigned, false).was_checked());
        let substituted = read_failure(unsigned, true);
        assert!(substituted.blocks(), "{substituted:?}");
        assert!(substituted.describe().contains("UNSIGNED"));
        assert!(read_failure(other, false).blocks());
        assert!(read_failure(other, true).blocks());
    }

    #[tokio::test]
    async fn an_image_with_no_declared_signer_is_not_checked() {
        let v = verify_signed_by("alpine:3", None).await;
        assert!(!v.was_checked() && !v.blocks(), "{v:?}");
    }

    #[test]
    fn a_signature_is_described_as_a_signature() {
        // A verified signature read "✓ no critical vulnerability": the scan's words.
        let r = |signature| Report {
            image: "a/b:1".into(),
            vulnerabilities: Verdict::Clean,
            signature,
        };
        let signed = r(Verdict::Clean).describe();
        let line = signed.lines().last().expect("a signature line");
        assert!(line.contains("signed by the expected signer"), "{line}");
        assert!(!line.contains("vulnerab"), "{line}");
        let forged = r(read_failure("no signatures found", true)).describe();
        let line = forged.lines().last().expect("a signature line");
        assert!(
            line.contains("UNSIGNED") && !line.contains("critical"),
            "{line}"
        );
    }

    #[test]
    fn a_report_counts_what_it_could_not_check() {
        let r = Report {
            image: "a/b:1".into(),
            vulnerabilities: Verdict::Clean,
            signature: Verdict::NotChecked {
                reason: "unsigned image".into(),
            },
        };
        assert_eq!(r.unchecked(), 1);
        assert!(
            !r.blocks(),
            "an unsigned image does not block, it is reported"
        );
    }

    #[test]
    fn an_invalid_signature_blocks() {
        // Unsigned is not the same as badly signed. The second means someone tried
        // something.
        let r = Report {
            image: "a/b:1".into(),
            vulnerabilities: Verdict::Clean,
            signature: Verdict::Findings {
                critical: 1,
                high: 0,
                detail: "INVALID signature".into(),
            },
        };
        assert!(r.blocks());
    }
}
