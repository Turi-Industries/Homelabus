//! Which flaws in what runs are said aloud at once, and which wait for the weekly digest.
//!
//! An alert only when a fix exists, the flaw is exploited in the wild (KEV) or likely to
//! be (EPSS), and the app is reachable from the internet. Everything else is counted in
//! the digest; a flaw with no fix is never read at all (`grype` asks for fixed ones).
//! Measured 2026-11-08: PostgreSQL 17.6 carries 159 fixable flaws, and one of them passes
//! — an alert for each of the 159 is an alert nobody reads.

use std::collections::BTreeMap;

use hlb_state::Flaw;
use hlb_types::{ExposePolicy, Image, Manifest};

/// The chance of exploitation within thirty days past which a flaw is said at once. One
/// in ten: PostgreSQL's one alert (OpenSSL's CVE-2025-15467) reads 0.75, its next 0.03.
pub const EPSS_ALERT: f64 = 0.1;

/// The images an app runs: its own and its companions'. The daily pass reads each by
/// digest, and the inbox asks of each whether it was read lately — one list, or the two
/// would disagree on what "every image" means.
pub fn images(m: &Manifest) -> Vec<&Image> {
    std::iter::once(&m.spec.image)
        .chain(m.spec.companions.iter().map(|c| &c.image))
        .collect()
}

/// Does what `m` runs carry a flaw exploited in the wild, as the last good reading of each
/// of its images found? Its update then skips maturity and the manifest's reach
/// (`policy::decide`). Whether the move carries the fix is not known before it is
/// scanned: a release made in the days after a flaw is listed exploited is the likely
/// one, and maturity guards against a bad release — a smaller harm than a known attack.
pub async fn exploited(state: &hlb_state::State, m: &Manifest) -> hlb_state::Result<bool> {
    for d in images(m).iter().filter_map(|i| i.digest.as_ref()) {
        if state.image_flaws(d).await?.iter().any(|f| f.exploited) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Is `f` worth saying today?
pub fn alerting(f: &Flaw) -> bool {
    f.exploited || f.epss.is_some_and(|e| e >= EPSS_ALERT)
}

/// Can the internet reach the app? A public route, a port of its node published, or an
/// ingress never applied — 🔴 unknown is not closed.
pub fn exposed(app: &str, manifest: &Manifest, published: &[(String, String, bool)]) -> bool {
    let ports = !manifest.spec.security.published_ports.is_empty()
        || manifest
            .spec
            .companions
            .iter()
            .any(|c| !c.security.published_ports.is_empty());
    let routed = if published.is_empty() {
        // Never applied: what its manifest asks for is the best guess there is.
        manifest
            .spec
            .ingress
            .iter()
            .any(|i| i.expose != ExposePolicy::Private)
    } else {
        published.iter().any(|(_, a, public)| a == app && *public)
    };
    ports || routed
}

/// Each flaw once, at its worst: one CVE in `libssl3` and `openssl` is one flaw.
pub fn distinct(flaws: &[Flaw]) -> Vec<&Flaw> {
    let mut by_id: BTreeMap<&str, &Flaw> = BTreeMap::new();
    for f in flaws {
        by_id
            .entry(&f.id)
            .and_modify(|seen| {
                let worse = (f.exploited, f.epss.unwrap_or(0.0))
                    > (seen.exploited, seen.epss.unwrap_or(0.0));
                if worse {
                    *seen = f;
                }
            })
            .or_insert(f);
    }
    by_id.into_values().collect()
}

/// A flaw said in one line: `CVE-2025-15467 in openssl 3.0.17 (fixed in 3.0.18),
/// exploited`.
pub fn line(f: &Flaw) -> String {
    let why = match (f.exploited, f.epss) {
        (true, _) => "exploited in the wild".to_string(),
        (false, Some(e)) => format!("{:.0}% likely exploited within 30 days", e * 100.0),
        (false, None) => f.severity.to_lowercase(),
    };
    format!(
        "{} in {} {} (fixed in {}), {why}",
        f.id, f.package, f.version, f.fixed_in
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flaw(id: &str, exploited: bool, epss: Option<f64>) -> Flaw {
        Flaw {
            id: id.into(),
            package: "openssl".into(),
            severity: "High".into(),
            version: "3.0.17".into(),
            fixed_in: "3.0.18".into(),
            exploited,
            epss,
            first_seen: 0,
        }
    }

    #[test]
    fn exploited_or_likely_to_be_is_said_and_the_rest_waits() {
        assert!(alerting(&flaw("A", true, None)));
        assert!(alerting(&flaw("A", false, Some(0.75))));
        assert!(alerting(&flaw("A", false, Some(EPSS_ALERT))));
        assert!(!alerting(&flaw("A", false, Some(0.03))));
        assert!(!alerting(&flaw("A", false, None)), "unknown is not likely");
    }

    fn manifest(extra: &str) -> Manifest {
        serde_yaml_ng::from_str(&format!(
            r#"
apiVersion: hlb/v1
kind: App
metadata: {{ name: gitea }}
spec:
  image: {{ repo: gitea/gitea, tag: "1" }}
{extra}
"#
        ))
        .expect("manifest")
    }

    #[test]
    fn exposed_means_reachable_from_the_internet_or_not_known_to_be_closed() {
        let private = manifest("  ingress: [{ host: git, port: 3000 }]");
        let public = manifest("  ingress: [{ host: git, port: 3000, expose: public }]");
        let row = |public| vec![("git.example.org".to_string(), "gitea".to_string(), public)];
        assert!(!exposed("gitea", &private, &row(false)));
        assert!(
            exposed("gitea", &private, &row(true)),
            "what IS published wins"
        );
        assert!(!exposed("gitea", &public, &row(false)));
        // 🔴 Never applied: unknown, so the manifest's wish is taken.
        assert!(exposed("gitea", &public, &[]));
        assert!(!exposed("gitea", &private, &[]));
        let mail = manifest("  security: { publishedPorts: [25] }");
        assert!(exposed("gitea", &mail, &row(false)), "a port of its node");
    }

    #[tokio::test]
    async fn only_an_exploited_flaw_in_a_companion_or_the_app_makes_it_urgent() {
        let s = hlb_state::State::in_memory().await.expect("state");
        let m = manifest(
            r#"  companions:
    - name: cache
      image: { repo: valkey/valkey, tag: "8", digest: "sha256:cache" }"#,
        );
        assert!(!exploited(&s, &m).await.expect("read"), "never read");
        s.record_image_scan(
            "sha256:cache",
            "valkey",
            1,
            Ok(&[flaw("A", false, Some(0.9))]),
        )
        .await
        .expect("read");
        assert!(
            !exploited(&s, &m).await.expect("read"),
            "likely is not exploited"
        );
        s.record_image_scan("sha256:cache", "valkey", 2, Ok(&[flaw("A", true, None)]))
            .await
            .expect("read");
        assert!(exploited(&s, &m).await.expect("read"));
    }

    #[test]
    fn a_flaw_in_two_packages_is_counted_once_at_its_worst() {
        let mut b = flaw("A", true, None);
        b.package = "libssl3".into();
        let l = [flaw("A", false, Some(0.2)), b, flaw("B", false, None)];
        let d = distinct(&l);
        assert_eq!(d.len(), 2);
        assert!(d[0].exploited);
    }

    #[test]
    fn a_line_names_the_fix_and_why_it_is_said() {
        assert_eq!(
            line(&flaw("CVE-2025-15467", false, Some(0.748))),
            "CVE-2025-15467 in openssl 3.0.17 (fixed in 3.0.18), 75% likely exploited \
             within 30 days"
        );
        assert!(line(&flaw("X", true, Some(0.9))).ends_with("exploited in the wild"));
    }
}
