//! What an image carries, against the flaws known today: Syft lists its packages, Grype
//! reads the list.
//!
//! Both run as Swarm jobs from images pinned here, never as binaries the host may lack:
//! `trivy` was looked for on the PATH, found on no node of the lab, and every update
//! there read "not checked". The jobs land on the node `hlb` talks to, where two volumes
//! stay between runs — the vulnerability database (3.2 GB unpacked, measured 2026-11-08:
//! twice Trivy's, the price of KEV and EPSS in every match) and the package lists, one
//! per digest (6.5 MB for PostgreSQL 17), which a daily comparison reads without pulling
//! the image again.
//!
//! 🔴 A finding that cannot be read is never "nothing found": a job that failed, a log
//! cut short, a line that does not parse — each is `NotChecked`, said with its reason.

use std::collections::BTreeMap;

use hlb_orchestrator::{JobOutcome, Orchestrator, ServiceSpec};
use hlb_types::manifest::Bytes;
use hlb_types::{ImageSigner, Memory};

use crate::scan::{Report, Verdict};
use crate::Result;

/// Grype, the root image: the non-root one cannot write a fresh volume, which Docker
/// creates root's, 755.
pub const GRYPE_IMAGE: &str =
    "anchore/grype:v0.121.0@sha256:621d56d1d68106b787022c81546f7e0a36202a25d1239f0c20195fab8c16f7ea";
pub const SYFT_IMAGE: &str =
    "anchore/syft:v1.55.0@sha256:4cc92b64ca74ffca4c94d4c8fcc01f217731375300be14d0b6eeb2e82eaa110a";

/// Grype's database, kept between runs.
pub const DB_VOLUME: &str = "hlb-grype-db";
/// The package lists, one file per digest.
pub const SBOM_VOLUME: &str = "hlb-sbom";

const DB_DIR: &str = "/db";
const SBOM_DIR: &str = "/sbom";
const TEMPLATE_PATH: &str = "/hlb/report.tmpl";

/// A package list of the largest image is read in seconds; a pull of it, and the first
/// download of the database, take minutes.
const JOB_TIMEOUT_S: u64 = 1_200;

const MATCH: &str = "hlb-match";
const COUNT: &str = "hlb-matches";

/// One line per match, then their count: the job's log is its only output, cut at a
/// ceiling, and the count is how a cut one is told from a short one. JSON is not used:
/// pretty-printed, one match spans dozens of lines and PostgreSQL's 280 would not fit.
/// Field names checked against Grype 0.121's own output.
const TEMPLATE: &str = concat!(
    "{{- range .Matches -}}\n",
    "hlb-match\t{{.Vulnerability.ID}}\t{{.Vulnerability.Severity}}\t{{.Artifact.Name}}\t",
    "{{.Artifact.Version}}\t{{join \",\" .Vulnerability.Fix.Versions}}\t",
    "{{len .Vulnerability.KnownExploited}}\t",
    "{{range .Vulnerability.EPSS}}{{.EPSS}} {{end}}\n",
    "{{end -}}\n",
    "hlb-matches\t{{len .Matches}}\n",
);

/// How bad a flaw is, as its advisory says.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Unknown,
    Negligible,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    fn read(s: &str) -> Self {
        match s {
            "Critical" => Self::Critical,
            "High" => Self::High,
            "Medium" => Self::Medium,
            "Low" => Self::Low,
            "Negligible" => Self::Negligible,
            _ => Self::Unknown,
        }
    }
}

/// One flaw in one package. Only flaws a fix exists for are asked: one with none calls
/// for no action, and reporting it on every update trains people to ignore the report.
#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    pub id: String,
    pub severity: Severity,
    pub package: String,
    pub version: String,
    /// The versions that fix it.
    pub fixed_in: String,
    /// On CISA's list of flaws exploited in the wild (KEV).
    pub exploited: bool,
    /// The chance it is exploited within thirty days (EPSS), when known.
    pub epss: Option<f64>,
}

/// Reads a scan job's log. `Err` says why it is not a reading.
pub fn parse(lines: &[String]) -> std::result::Result<Vec<Finding>, String> {
    let mut found = Vec::new();
    let mut count = None;
    for line in lines {
        let fields: Vec<&str> = line.trim_end_matches(['\r', '\n']).split('\t').collect();
        match fields.as_slice() {
            [MATCH, id, severity, package, version, fixed_in, exploited, epss] => {
                found.push(Finding {
                    id: id.to_string(),
                    severity: Severity::read(severity),
                    package: package.to_string(),
                    version: version.to_string(),
                    fixed_in: fixed_in.to_string(),
                    exploited: exploited
                        .parse::<usize>()
                        .map_err(|_| format!("unreadable match: {line}"))?
                        > 0,
                    epss: epss
                        .split_whitespace()
                        .filter_map(|e| e.parse().ok())
                        .next(),
                });
            }
            [MATCH, ..] => return Err(format!("unreadable match: {line}")),
            [COUNT, n] => count = n.trim().parse::<usize>().ok(),
            _ => {}
        }
    }
    match count {
        None => Err(format!(
            "the scan did not say how many it found: {}",
            tail(lines)
        )),
        Some(n) if n != found.len() => Err(format!(
            "the report was cut: {} of {n} matches read",
            found.len()
        )),
        Some(_) => Ok(found),
    }
}

pub(crate) fn tail(lines: &[String]) -> String {
    let start = lines.len().saturating_sub(3);
    let said = lines[start..].join(" | ");
    if said.is_empty() {
        "it wrote nothing".into()
    } else {
        said
    }
}

/// The name of an image's package list: its digest. An image named by its tag alone has
/// none — a tag may name another build tomorrow, and its list would be read for it.
fn sbom_file(image: &str) -> Option<String> {
    let (_, hex) = image.split_once("@sha256:")?;
    (hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()))
        .then(|| format!("{SBOM_DIR}/{hex}.json"))
}

/// Where the scans run, and how they reach a registry.
pub struct Grype<'a> {
    pub orchestrator: &'a dyn Orchestrator,
    /// The overlay the jobs join: a job on none reaches no registry.
    pub network: &'a str,
}

fn job(kind: &str, image: &str, network: &str, node: Option<&str>) -> ServiceSpec {
    let hex = image
        .rsplit_once(':')
        .map(|(_, h)| h)
        .unwrap_or(image)
        .get(..12)
        .unwrap_or("image");
    let mut job = ServiceSpec::new(format!("hlb-{kind}-{hex}"), image_of(kind))
        .job()
        .network(network)
        .mount(SBOM_VOLUME, SBOM_DIR);
    if let Some(node) = node {
        // Both volumes stay where the last run left them.
        job = job.constraint(format!("node.id=={node}"));
    }
    // An image is unpacked in the container's own layer, which the job takes away:
    // in memory, Immich's would need gigabytes.
    job.hardening.read_only_rootfs = false;
    job
}

/// What a Syft job may take of the node it runs on: a quarter of it, a GiB when its size
/// is unknown. No reservation — it would only make the job wait for room Swarm thinks
/// is taken.
///
/// 🔴 Unbounded, Syft took the node down with it: listing `n8nio/n8n:3.0.0` needs more
/// than 2 GiB (killed at 2, done at 3 — `postgres:17` peaks at 660 MiB), and on the
/// lab's 4 GB manager it drove the whole house into the kernel's OOM killer for seven
/// minutes, Caddy and the daemon included, then froze it at the next pass (2026-11-10).
/// Killed at its own limit, the image is only "not checked", and says why.
pub(crate) fn syft_memory(node_mb: Option<u64>) -> Memory {
    const MIB: u64 = 1024 * 1024;
    Memory {
        reserve: Bytes(0),
        limit: Bytes(node_mb.map_or(1024, |mb| mb / 4) * MIB),
    }
}

/// Why a Syft job failed, a kill at its memory limit named as such: Swarm says only
/// "non-zero exit (137)", and a killed process writes nothing.
pub(crate) fn syft_failed(o: &JobOutcome, memory: &Memory) -> String {
    if o.output.iter().any(|l| l.contains("exit (137)")) {
        format!(
            "Syft failed: it needed more than the {} MiB it may take on this node",
            memory.limit.mib()
        )
    } else {
        format!("Syft failed: {}", tail(&o.output))
    }
}

fn sbom_job(
    image: &str,
    file: &str,
    network: &str,
    node: Option<&str>,
    memory: Memory,
) -> ServiceSpec {
    let mut job = job("sbom", image, network, node);
    job.memory = Some(memory);
    job.command([
        "/syft".to_string(),
        "scan".to_string(),
        format!("registry:{image}"),
        "-o".to_string(),
        format!("syft-json={file}"),
        "-q".to_string(),
    ])
}

fn scan_job(image: &str, file: &str, network: &str, node: Option<&str>) -> ServiceSpec {
    grype_reading(job("grype", image, network, node), &format!("sbom:{file}"))
}

/// Grype's reading of `input` (`sbom:<file>`, `purl:<file>`) in `job`, its database kept
/// in its volume — on the node `job` is held to, or it is fetched again.
pub(crate) fn grype_reading(job: ServiceSpec, input: &str) -> ServiceSpec {
    job.mount(DB_VOLUME, DB_DIR)
        .env(vec![("GRYPE_DB_CACHE_DIR".into(), DB_DIR.into())])
        .file(TEMPLATE_PATH, TEMPLATE)
        .command([
            "/grype".to_string(),
            input.to_string(),
            "--only-fixed".to_string(),
            "-o".to_string(),
            "template".to_string(),
            "-t".to_string(),
            TEMPLATE_PATH.to_string(),
            "-q".to_string(),
        ])
}

/// A Grype job's report, or why it is none.
pub(crate) fn report(o: &JobOutcome) -> std::result::Result<Vec<Finding>, String> {
    if o.succeeded {
        parse(&o.output)
    } else {
        Err(format!("Grype failed: {}", tail(&o.output)))
    }
}

impl Grype<'_> {
    pub(crate) async fn run(&self, spec: &ServiceSpec) -> std::result::Result<JobOutcome, String> {
        self.orchestrator
            .run_job(spec, JOB_TIMEOUT_S)
            .await
            .map_err(|e| e.to_string())
    }

    /// The flaws a fix exists for in `image`, which must name its digest. Its package
    /// list is read when one is kept, made first otherwise — or again, when the one kept
    /// cannot be read.
    pub async fn findings(&self, image: &str) -> std::result::Result<Vec<Finding>, String> {
        let Some(file) = sbom_file(image) else {
            return Err("no digest: the scan would read whatever the tag names today".into());
        };
        let node = self.orchestrator.local_node().await.ok().flatten();
        let node_mb = match &node {
            Some(id) => self
                .orchestrator
                .nodes()
                .await
                .ok()
                .and_then(|ns| ns.into_iter().find(|n| &n.id == id))
                .and_then(|n| n.memory_mb),
            None => None,
        };
        let node = node.as_deref();
        if let Ok(found) = report(
            &self
                .run(&scan_job(image, &file, self.network, node))
                .await?,
        ) {
            return Ok(found);
        }
        let memory = syft_memory(node_mb);
        let listed = self
            .run(&sbom_job(image, &file, self.network, node, memory))
            .await?;
        if !listed.succeeded {
            return Err(syft_failed(&listed, &memory));
        }
        report(
            &self
                .run(&scan_job(image, &file, self.network, node))
                .await?,
        )
    }

    /// `image` judged against the one it replaces, when it is known: the update's
    /// question is what the move brings, not what both carry.
    pub async fn vulnerabilities(&self, image: &str, replacing: Option<&str>) -> Verdict {
        let new = match self.findings(image).await {
            Ok(f) => f,
            Err(reason) => return Verdict::NotChecked { reason },
        };
        let old = match replacing {
            Some(r) => self.findings(r).await.map_err(|why| (r, why)),
            None => Err(("", "nothing runs before it".to_string())),
        };
        compare(&new, old.as_deref().map_err(|(r, w)| (*r, w.as_str())))
    }
}

fn image_of(kind: &str) -> &'static str {
    if kind == "sbom" {
        SYFT_IMAGE
    } else {
        GRYPE_IMAGE
    }
}

#[async_trait::async_trait]
impl crate::run::Scanner for Grype<'_> {
    async fn audit(
        &self,
        image: &str,
        signer: Option<&ImageSigner>,
        replacing: Option<&str>,
    ) -> Result<Report> {
        Ok(Report {
            image: image.to_string(),
            vulnerabilities: self.vulnerabilities(image, replacing).await,
            signature: crate::scan::verify_signed_by(image, signer).await,
        })
    }
}

/// Each flaw once, at its worst: a CVE in `libssl3` and `openssl` is one flaw.
fn by_id(found: &[Finding]) -> BTreeMap<&str, &Finding> {
    let mut ids: BTreeMap<&str, &Finding> = BTreeMap::new();
    for f in found {
        ids.entry(&f.id)
            .and_modify(|seen| {
                if (f.exploited, f.severity) > (seen.exploited, seen.severity) {
                    *seen = f;
                }
            })
            .or_insert(f);
    }
    ids
}

/// What blocks a move: a critical flaw, or one exploited in the wild, that the image it
/// replaces did not carry.
///
/// 🔴 Not every critical flaw. Measured 2026-11-08, PostgreSQL 17.6 carries 33 critical
/// matches a Debian update fixes, as does nearly every image built on a distribution:
/// blocking on them refuses the very update that may fix them, keeps the older image
/// running, and leads the owner to turn the scan off. With nothing to compare to, only
/// an exploited flaw blocks — said so.
///
/// ⚠️ A base past its end of life is read clean of what its distribution stopped
/// tracking: Alpine 3.18 → 3.20 "brought" three OpenSSL flaws 3.18 carries too. The
/// move off it is then refused until forced, which the audit log records.
pub fn compare(new: &[Finding], old: std::result::Result<&[Finding], (&str, &str)>) -> Verdict {
    let now = by_id(new);
    let blocking = |f: &Finding| f.exploited || f.severity == Severity::Critical;
    let (introduced, fixed, baseline): (Vec<&Finding>, usize, Option<String>) = match old {
        Ok(old) => {
            let before = by_id(old);
            (
                now.iter()
                    .filter(|(id, _)| !before.contains_key(*id))
                    .map(|(_, f)| *f)
                    .collect(),
                before.keys().filter(|id| !now.contains_key(*id)).count(),
                None,
            )
        }
        Err((image, why)) => (
            now.values().copied().collect(),
            0,
            Some(if image.is_empty() {
                why.to_string()
            } else {
                format!("{image} could not be read: {why}")
            }),
        ),
    };
    let stops: Vec<&Finding> = introduced
        .iter()
        .copied()
        .filter(|f| match baseline {
            None => blocking(f),
            Some(_) => f.exploited,
        })
        .collect();
    let high = introduced
        .iter()
        .filter(|f| f.severity >= Severity::High && !stops.contains(f))
        .count();
    let exploited_kept = now.values().filter(|f| f.exploited).count()
        - introduced.iter().filter(|f| f.exploited).count();

    if stops.is_empty() && high == 0 && exploited_kept == 0 && baseline.is_none() {
        return if now.is_empty() {
            Verdict::Clean
        } else {
            Verdict::Findings {
                critical: 0,
                high: 0,
                detail: carried(now.len(), fixed),
            }
        };
    }
    let mut detail: Vec<String> = Vec::new();
    if !stops.is_empty() {
        detail.push(format!(
            "brings {}",
            stops
                .iter()
                .take(3)
                .map(|f| named(f))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if exploited_kept > 0 {
        detail.push(format!(
            "{exploited_kept} exploited flaw(s) already running, still there"
        ));
    }
    match &baseline {
        Some(why) => detail.push(format!(
            "compared with nothing ({why}): only an exploited flaw blocks"
        )),
        None => detail.push(carried(now.len(), fixed)),
    }
    Verdict::Findings {
        critical: stops.len(),
        high,
        detail: detail.join("; "),
    }
}

fn named(f: &Finding) -> String {
    let mut s = format!("{} in {} {}", f.id, f.package, f.version);
    if f.exploited {
        s.push_str(" (exploited)");
    }
    s
}

fn carried(now: usize, fixed: usize) -> String {
    format!("{now} fixable flaw(s) carried, {fixed} fixed by this move")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(id: &str, sev: &str, pkg: &str, kev: u8) -> String {
        format!("{MATCH}\t{id}\t{sev}\t{pkg}\t1.0\t1.1\t{kev}\t0.5 ")
    }

    fn lines(l: &[String]) -> Vec<String> {
        let mut v = l.to_vec();
        v.push(format!("{COUNT}\t{}", l.len()));
        v
    }

    fn found(l: &[(&str, &str, u8)]) -> Vec<Finding> {
        let ls: Vec<String> = l.iter().map(|(i, s, k)| line(i, s, "p", *k)).collect();
        parse(&lines(&ls)).expect("a reading")
    }

    #[test]
    fn a_report_is_read_line_by_line() {
        // Grype 0.121's own output for httpd 2.4.49, two of its 248 lines.
        let out = vec![
            "hlb-match\tCVE-2024-38475\tCritical\thttpd\t2.4.49\t2.4.60\t1\t0.99957 ".into(),
            "hlb-match\tCVE-2023-6129\tMedium\tlibssl3\t3.1.0-r4\t3.1.4-r3\t0\t".into(),
            "hlb-matches\t2".into(),
        ];
        let f = parse(&out).expect("read");
        assert_eq!(f.len(), 2);
        assert_eq!(f[0].severity, Severity::Critical);
        assert!(f[0].exploited);
        assert_eq!(f[0].epss, Some(0.99957));
        assert_eq!(f[0].fixed_in, "2.4.60");
        assert!(!f[1].exploited);
        assert_eq!(f[1].epss, None);
    }

    #[test]
    fn a_report_cut_short_or_silent_is_no_reading() {
        // 🔴 The job's log has a ceiling: read as it is, a cut one is a short one.
        let cut = vec![line("CVE-1", "High", "p", 0), format!("{COUNT}\t280")];
        assert!(parse(&cut).expect_err("cut").contains("1 of 280"));
        assert!(parse(&[]).is_err(), "nothing said is not nothing found");
        assert!(parse(&["Error: failed to load vulnerability db".into()]).is_err());
        let mangled = vec![format!("{MATCH}\tCVE-1\tHigh"), format!("{COUNT}\t1")];
        assert!(parse(&mangled).is_err());
        assert_eq!(parse(&lines(&[])), Ok(Vec::new()));
    }

    #[test]
    fn only_what_the_move_brings_blocks_it() {
        let old = found(&[("CVE-A", "Critical", 0), ("CVE-B", "High", 0)]);
        // The same critical flaw on both sides: the move does not make it worse.
        let same = compare(&old, Ok(&old));
        assert!(!same.blocks(), "{same:?}");
        let fixes = compare(&found(&[("CVE-B", "High", 0)]), Ok(&old));
        assert!(!fixes.blocks());
        assert!(fixes.describe().contains("1 fixed"), "{}", fixes.describe());
        let brings = compare(
            &found(&[("CVE-A", "Critical", 0), ("CVE-C", "Critical", 0)]),
            Ok(&old),
        );
        assert!(brings.blocks());
        assert!(brings.describe().contains("CVE-C"), "{}", brings.describe());
        let exploited = compare(&found(&[("CVE-D", "Medium", 1)]), Ok(&[]));
        assert!(
            exploited.blocks(),
            "an exploited flaw blocks whatever its grade"
        );
    }

    #[test]
    fn with_nothing_to_compare_only_an_exploited_flaw_blocks() {
        let new = found(&[("CVE-A", "Critical", 0)]);
        let v = compare(&new, Err(("a/b:1@sha256:old", "Syft failed")));
        assert!(!v.blocks(), "{v:?}");
        assert!(
            v.describe().contains("compared with nothing"),
            "{}",
            v.describe()
        );
        let kev = found(&[("CVE-A", "Critical", 1)]);
        assert!(compare(&kev, Err(("", "nothing runs before it"))).blocks());
    }

    #[test]
    fn a_flaw_in_two_packages_is_one_flaw() {
        let l = vec![
            line("CVE-A", "Critical", "libssl3", 0),
            line("CVE-A", "Critical", "openssl", 0),
        ];
        let v = compare(&parse(&lines(&l)).expect("read"), Ok(&[]));
        assert!(v.blocks());
        assert!(matches!(v, Verdict::Findings { critical: 1, .. }), "{v:?}");
    }

    #[test]
    fn nothing_fixable_is_clean() {
        assert_eq!(compare(&[], Ok(&[])), Verdict::Clean);
    }

    #[test]
    fn a_package_list_is_named_by_its_digest_only() {
        let hex = "a".repeat(64);
        assert_eq!(
            sbom_file(&format!("postgres:17@sha256:{hex}")),
            Some(format!("/sbom/{hex}.json"))
        );
        assert_eq!(sbom_file("postgres:17"), None);
        assert_eq!(sbom_file("postgres:17@sha256:abc"), None);
    }

    #[test]
    fn the_jobs_keep_their_volumes_on_one_node_and_reach_a_registry() {
        let image = format!("postgres:17@sha256:{}", "b".repeat(64));
        let scan = scan_job(&image, "/sbom/x.json", "hlb_platform", Some("node1"));
        assert_eq!(scan.image, GRYPE_IMAGE);
        assert!(scan.constraints.contains(&"node.id==node1".to_string()));
        assert_eq!(scan.networks, ["hlb_platform"]);
        assert!(scan.mounts.contains(&(DB_VOLUME.into(), DB_DIR.into())));
        assert!(scan.command.contains(&"--only-fixed".to_string()));
        assert!(scan
            .files
            .iter()
            .any(|(p, t)| p == TEMPLATE_PATH && t == TEMPLATE));
        let sbom = sbom_job(
            &image,
            "/sbom/x.json",
            "hlb_platform",
            None,
            syft_memory(None),
        );
        assert_eq!(sbom.image, SYFT_IMAGE);
        assert!(sbom.command.contains(&format!("registry:{image}")));
        assert!(sbom.constraints.is_empty());
    }

    #[test]
    fn syft_takes_a_quarter_of_its_node_and_never_the_node() {
        let image = format!("n8nio/n8n:3.0.0@sha256:{}", "c".repeat(64));
        let sbom = sbom_job(&image, "/sbom/x.json", "n", None, syft_memory(Some(3_915)));
        let memory = sbom.memory.expect("bounded");
        assert_eq!(memory.limit.mib(), 978);
        // Reserved, it would wait for room Swarm counts as taken, and time out.
        assert_eq!(memory.reserve.0, 0);
        assert_eq!(syft_memory(None).limit.mib(), 1_024);
    }

    #[test]
    fn syft_killed_at_its_limit_says_so() {
        let memory = syft_memory(Some(4_096));
        let killed = JobOutcome {
            succeeded: false,
            output: vec!["task: non-zero exit (137)".into()],
        };
        assert_eq!(
            syft_failed(&killed, &memory),
            "Syft failed: it needed more than the 1024 MiB it may take on this node"
        );
        let refused = JobOutcome {
            succeeded: false,
            output: vec!["unauthorized".into()],
        };
        assert_eq!(syft_failed(&refused, &memory), "Syft failed: unauthorized");
    }
}
