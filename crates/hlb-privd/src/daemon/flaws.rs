//! Every image that runs, read against the flaws known today, once a day — without
//! pulling it again: Grype reads the package list Syft made of its digest once.
//!
//! What is said: at once, a flaw a fix exists for, exploited or likely to be, in an app
//! the internet reaches — once, until it is gone; weekly, the rest, counted per app, and
//! every image that could not be read. An image unread is never an image clean.

use std::collections::{BTreeMap, BTreeSet};

use hlb_notify::Notification;
use hlb_state::{Flaw, State};
use hlb_types::{Image, Manifest};
use hlb_updater::flaws::{alerting, distinct, exposed, line};
use hlb_updater::grype::{Finding, Grype};

/// How often the digest goes out.
pub const DIGEST_EVERY_S: i64 = 7 * 86_400;

/// What a reading of every image came to.
#[derive(Debug, Default, PartialEq)]
pub struct Read {
    /// Each app, with the flaws of the images it runs.
    pub apps: Vec<AppFlaws>,
    /// Images read, and those that could not be: `(image, why)`.
    pub read: usize,
    pub unread: Vec<(String, String)>,
}

#[derive(Debug, Default, PartialEq)]
pub struct AppFlaws {
    pub app: String,
    pub exposed: bool,
    /// Each flaw once, at its worst.
    pub flaws: Vec<Flaw>,
}

impl AppFlaws {
    /// What is said at once: worth it, and reachable.
    pub fn alerts(&self) -> Vec<&Flaw> {
        if !self.exposed {
            return Vec::new();
        }
        self.flaws.iter().filter(|f| alerting(f)).collect()
    }
}

/// The images an app runs, by digest: its own and its companions'. One running by its
/// tag alone has no digest to read, and is said so.
fn images(m: &Manifest) -> Vec<&Image> {
    std::iter::once(&m.spec.image)
        .chain(m.spec.companions.iter().map(|c| &c.image))
        .collect()
}

fn stored(f: Finding, at: i64) -> Flaw {
    Flaw {
        id: f.id,
        package: f.package,
        severity: format!("{:?}", f.severity),
        version: f.version,
        fixed_in: f.fixed_in,
        exploited: f.exploited,
        epss: f.epss,
        first_seen: at,
    }
}

/// Reads every image the installed apps run, records each reading, and gathers each
/// app's flaws from the last good reading of each of its images.
pub async fn read(state: &State, grype: &Grype<'_>, at: i64) -> hlb_state::Result<Read> {
    let mut manifests = BTreeMap::new();
    for (app, _) in state.installed_apps().await? {
        if let Ok(m) = state.app_manifest(&app).await {
            manifests.insert(app, m);
        }
    }
    let mut out = Read::default();
    let mut digests: BTreeMap<String, String> = BTreeMap::new();
    for m in manifests.values() {
        for i in images(m) {
            match &i.digest {
                Some(d) => {
                    digests.insert(d.clone(), i.reference());
                }
                None => out.unread.push((
                    i.reference(),
                    "runs by its tag alone: no digest to read".into(),
                )),
            }
        }
    }
    for (digest, image) in &digests {
        let reading = grype.findings(image).await;
        match reading {
            Ok(found) => {
                let flaws: Vec<Flaw> = found.into_iter().map(|f| stored(f, at)).collect();
                state
                    .record_image_scan(digest, image, at, Ok(&flaws))
                    .await?;
                out.read += 1;
            }
            Err(why) => {
                state
                    .record_image_scan(digest, image, at, Err(&why))
                    .await?;
                out.unread.push((image.clone(), why));
            }
        }
    }
    state
        .keep_image_scans(&digests.keys().cloned().collect())
        .await?;

    let published = state.published_ingress().await?;
    for (app, m) in &manifests {
        let mut all = Vec::new();
        for d in images(m).iter().filter_map(|i| i.digest.as_ref()) {
            all.extend(state.image_flaws(d).await?);
        }
        let flaws = distinct(&all).into_iter().cloned().collect();
        out.apps.push(AppFlaws {
            app: app.clone(),
            exposed: exposed(app, m, &published),
            flaws,
        });
    }
    Ok(out)
}

/// What to say of a reading: an alert per app with a flaw not said yet, and the digest
/// when a week has passed. Records what was said.
pub async fn judge(state: &State, r: &Read, at: i64) -> hlb_state::Result<Vec<Notification>> {
    let mut said = Vec::new();
    for a in &r.apps {
        let now: BTreeSet<String> = a.alerts().iter().map(|f| f.id.clone()).collect();
        let before = state.alerted_flaws(&a.app).await?;
        let new: Vec<&Flaw> = a
            .alerts()
            .into_iter()
            .filter(|f| !before.contains(&f.id))
            .collect();
        if let Some(n) = alert(&a.app, &new) {
            said.push(n);
        }
        state.set_alerted_flaws(&a.app, &now, at).await?;
    }
    state
        .keep_flaw_alerts(&r.apps.iter().map(|a| a.app.clone()).collect())
        .await?;
    let due = state
        .flaw_digest_sent()
        .await?
        .is_none_or(|sent| at - sent >= DIGEST_EVERY_S);
    if due {
        if let Some(n) = digest(r) {
            said.push(n);
        }
        state.set_flaw_digest_sent(at).await?;
    }
    Ok(said)
}

/// The alert for `app`'s new flaws, if any.
pub fn alert(app: &str, new: &[&Flaw]) -> Option<Notification> {
    if new.is_empty() {
        return None;
    }
    let lines: Vec<String> = new.iter().map(|f| format!("- {}", line(f))).collect();
    Some(Notification::important(
        &format!("flaw:{app}"),
        &format!("{app}: a flaw with a fix, exploited or likely to be"),
        &format!(
            "{app} is reachable from the internet and runs:\n{}\n\n\
             `hlb update check` says whether an update carries the fix; \
             `hlb update apply {app}` applies it.",
            lines.join("\n")
        ),
    ))
}

/// The weekly digest: each app's fixable flaws counted, what is worth an alert but not
/// reachable, and every image that could not be read. `None` when there is nothing.
pub fn digest(r: &Read) -> Option<Notification> {
    let mut lines = Vec::new();
    for a in r.apps.iter().filter(|a| !a.flaws.is_empty()) {
        let worth = a.flaws.iter().filter(|f| alerting(f)).count();
        let mut l = format!("- {}: {} fixable", a.app, a.flaws.len());
        if worth > 0 {
            l.push_str(&format!(
                ", {worth} exploited or likely to be{}",
                if a.exposed {
                    " (said when found)"
                } else {
                    ", not reachable from the internet"
                }
            ));
        }
        lines.push(l);
    }
    for (image, why) in &r.unread {
        lines.push(format!("- {image}: NOT READ ({why})"));
    }
    if lines.is_empty() {
        return None;
    }
    Some(Notification::important(
        "flaws-digest",
        "This week's flaws with a fix",
        &format!(
            "{} image(s) read.\n{}\n\nAn update usually carries the fix: \
             `hlb update check`.",
            r.read,
            lines.join("\n")
        ),
    ))
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

    fn app(name: &str, exposed: bool, flaws: Vec<Flaw>) -> AppFlaws {
        AppFlaws {
            app: name.into(),
            exposed,
            flaws,
        }
    }

    #[tokio::test]
    async fn an_alert_is_said_once_and_only_for_what_the_internet_reaches() {
        let s = State::in_memory().await.expect("state");
        let r = Read {
            apps: vec![
                app(
                    "gitea",
                    true,
                    vec![flaw("CVE-K", true, None), flaw("CVE-L", false, Some(0.01))],
                ),
                app("vikunja", false, vec![flaw("CVE-K", true, None)]),
            ],
            read: 2,
            unread: Vec::new(),
        };
        let said = judge(&s, &r, 1_000).await.expect("judge");
        let alerts: Vec<&str> = said
            .iter()
            .filter(|n| n.subject.starts_with("flaw:"))
            .map(|n| n.subject.as_str())
            .collect();
        assert_eq!(alerts, ["flaw:gitea"], "vikunja is not reachable");
        assert!(said[0].body.contains("CVE-K") && !said[0].body.contains("CVE-L"));
        assert!(
            said.iter().any(|n| n.subject == "flaws-digest"),
            "the first digest"
        );

        // The next day: nothing new, nothing said, no digest before a week.
        assert!(judge(&s, &r, 1_000 + 86_400)
            .await
            .expect("judge")
            .is_empty());
        let week = judge(&s, &r, 1_000 + DIGEST_EVERY_S).await.expect("judge");
        assert_eq!(week.len(), 1);
        assert!(week[0]
            .body
            .contains("vikunja: 1 fixable, 1 exploited or likely to be, not reachable"));
    }

    #[tokio::test]
    async fn a_flaw_gone_then_back_is_said_again() {
        let s = State::in_memory().await.expect("state");
        let with = |f: Vec<Flaw>| Read {
            apps: vec![app("gitea", true, f)],
            read: 1,
            unread: Vec::new(),
        };
        s.set_flaw_digest_sent(0).await.expect("sent");
        assert_eq!(
            judge(&s, &with(vec![flaw("A", true, None)]), 1)
                .await
                .expect("j")
                .len(),
            1
        );
        assert!(judge(&s, &with(vec![]), 2).await.expect("j").is_empty());
        assert_eq!(
            judge(&s, &with(vec![flaw("A", true, None)]), 3)
                .await
                .expect("j")
                .len(),
            1
        );
    }

    #[test]
    fn an_image_not_read_is_in_the_digest_never_clean() {
        let r = Read {
            apps: vec![app("gitea", true, vec![])],
            read: 0,
            unread: vec![(
                "gitea/gitea:1.25@sha256:x".into(),
                "Grype failed: no db".into(),
            )],
        };
        let d = digest(&r).expect("a digest");
        assert!(
            d.body.contains("NOT READ (Grype failed: no db)"),
            "{}",
            d.body
        );
        let nothing = Read {
            apps: vec![app("gitea", true, vec![])],
            read: 1,
            unread: Vec::new(),
        };
        assert_eq!(digest(&nothing), None, "nothing to say is said by nobody");
    }

    #[test]
    fn an_app_s_images_are_its_own_and_its_companions() {
        let m: Manifest = serde_yaml_ng::from_str(
            r#"
apiVersion: hlb/v1
kind: App
metadata: { name: immich }
spec:
  image: { repo: immich/server, tag: "2", digest: "sha256:a" }
  companions:
    - name: ml
      image: { repo: immich/ml, tag: "2" }
"#,
        )
        .expect("manifest");
        let i = images(&m);
        assert_eq!(i.len(), 2);
        assert_eq!(i[1].digest, None);
    }
}
