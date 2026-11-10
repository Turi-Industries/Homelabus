//! Undoing an app's last update: what it puts back, or why it cannot.
//!
//! Pure: the run and the running manifest in, the plan out. `hlb update undo` does the
//! restoring, from the copy the run kept, and the images, while the app is stopped.

use hlb_state::{UpdateRun, UpdateRunOutcome};
use hlb_types::{manifest::Spec, Image};

/// What undoing `app`'s last update puts back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Undo {
    /// The run undone.
    pub run: i64,
    pub ran_at: i64,
    /// What runs now, which the update moved to.
    pub now: String,
    /// The app's image before. `None`: the update moved its companions alone.
    pub image: Option<Image>,
    /// Each companion moved, with its image before, in the manifest's order.
    pub companions: Vec<Companion>,
    /// Every snapshot of the copy taken before the update: empty for an app owing none.
    pub copies: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Companion {
    pub name: String,
    pub service: String,
    pub image: Image,
}

/// Why nothing is undone. Nothing was touched.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    #[error("{app} has never been updated: there is nothing to undo")]
    NoRun { app: String },
    #[error("{app}'s last update was undone already: only the last one is undone")]
    AlreadyUndone { app: String },
    #[error(
        "{app}'s last update ended {outcome}, not applied: there is nothing of it to undo \
         — `hlb ps {app}` says what runs"
    )]
    NotApplied { app: String, outcome: &'static str },
    #[error(
        "{app}'s last update was recorded before undoing one was possible: nothing says \
         which copy it took — `hlb backup restore` puts one back by hand"
    )]
    NoMaterial { app: String },
    #[error(
        "{app} runs {now}, not {then} where its last update left it: it moved since, and \
         nothing is undone past that"
    )]
    MovedSince {
        app: String,
        then: String,
        now: String,
    },
    #[error("\"{image}\" cannot be read back as `repo:tag@digest`: nothing is deployed by tag")]
    Unreadable { image: String },
    #[error("{app}'s companion {name} is no longer installed: its image cannot go back")]
    CompanionGone { app: String, name: String },
}

/// What undoing `last`, `app`'s newest update run, puts back over `running`.
///
/// 🔴 The newest run only, whatever its outcome: an undo recorded refuses a second (the
/// copy it would restore predates the data the first one gave back), and a run that
/// rolled back left nothing to undo. And the app must still run what the run moved it
/// to — moved since, by hand, the copy is older than what that move found.
pub fn plan(app: &str, last: Option<&UpdateRun>, running: &Spec) -> Result<Undo, Refusal> {
    let app_s = || app.to_string();
    let Some(run) = last else {
        return Err(Refusal::NoRun { app: app_s() });
    };
    match run.outcome {
        UpdateRunOutcome::Applied => {}
        UpdateRunOutcome::Undone => return Err(Refusal::AlreadyUndone { app: app_s() }),
        o @ (UpdateRunOutcome::RolledBack
        | UpdateRunOutcome::Paused
        | UpdateRunOutcome::Inconclusive) => {
            return Err(Refusal::NotApplied {
                app: app_s(),
                outcome: o.as_str(),
            })
        }
    }
    let Some(material) = &run.undo else {
        return Err(Refusal::NoMaterial { app: app_s() });
    };
    let now = running.image.reference();
    if now != run.to_image {
        return Err(Refusal::MovedSince {
            app: app_s(),
            then: run.to_image.clone(),
            now,
        });
    }
    // A move of companions alone records the app's image unchanged on both sides.
    let image = if run.from_image == run.to_image {
        None
    } else {
        Some(parse(&run.from_image, &running.image)?)
    };
    let mut companions = Vec::new();
    for c in &running.companions {
        if let Some(before) = material.companions.get(&c.name) {
            companions.push(Companion {
                name: c.name.clone(),
                service: c.service(app),
                image: parse(before, &c.image)?,
            });
        }
    }
    if let Some(gone) = material
        .companions
        .keys()
        .find(|n| !running.companions.iter().any(|c| &c.name == *n))
    {
        return Err(Refusal::CompanionGone {
            app: app_s(),
            name: gone.clone(),
        });
    }
    Ok(Undo {
        run: run.id,
        ran_at: run.ran_at,
        now,
        image,
        companions,
        copies: material.copies.clone(),
    })
}

/// `repo:tag@digest` back into an image, what only the running one says carried over
/// when it is the same repository.
///
/// ⚠️ A registry's port is a `:` too (`registry:5000/app:1.2@sha256:…`): the tag is
/// after the LAST `:` with no `/` after it.
fn parse(reference: &str, running: &Image) -> Result<Image, Refusal> {
    let unreadable = || Refusal::Unreadable {
        image: reference.to_string(),
    };
    let (named, digest) = reference.split_once('@').ok_or_else(unreadable)?;
    let (repo, tag) = named
        .rsplit_once(':')
        .filter(|(r, t)| !r.is_empty() && !t.is_empty() && !t.contains('/'))
        .ok_or_else(unreadable)?;
    if digest.is_empty() {
        return Err(unreadable());
    }
    let same = repo == running.repo;
    Ok(Image {
        repo: repo.to_string(),
        tag: tag.to_string(),
        digest: Some(digest.to_string()),
        built_here: same && running.built_here,
        signed_by: running.signed_by.clone().filter(|_| same),
    })
}

/// Would `to_digest` put back on `app` what a person undid? Then the automatic pass
/// leaves it to a person: an undo is a decision about that very image.
pub fn undone(last: Option<&UpdateRun>, to_digest: &str) -> bool {
    last.is_some_and(|r| {
        r.outcome == UpdateRunOutcome::Undone
            && r.from_image
                .split_once('@')
                .is_some_and(|(_, d)| d == to_digest)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hlb_state::UpdateUndo;

    fn spec() -> Spec {
        let m: hlb_types::Manifest = serde_yaml_ng::from_str(
            r#"
apiVersion: hlb/v1
kind: App
metadata: { name: immich }
spec:
  image: { repo: ghcr.io/immich-app/immich-server, tag: v3.3.0, digest: "sha256:new" }
  companions:
    - name: ml
      image: { repo: ghcr.io/immich-app/immich-machine-learning, tag: v3.3.0, digest: "sha256:mlnew" }
"#,
        )
        .expect("manifest");
        m.spec
    }

    fn run(outcome: UpdateRunOutcome, undo: Option<UpdateUndo>) -> UpdateRun {
        UpdateRun {
            id: 7,
            app: "immich".into(),
            ran_at: 100,
            from_image: "ghcr.io/immich-app/immich-server:v3.1.0@sha256:old".into(),
            to_image: "ghcr.io/immich-app/immich-server:v3.3.0@sha256:new".into(),
            outcome,
            detail: String::new(),
            undo,
        }
    }

    fn material() -> UpdateUndo {
        UpdateUndo {
            copies: vec!["a1".into(), "b2".into()],
            companions: [(
                "ml".to_string(),
                "ghcr.io/immich-app/immich-machine-learning:v3.1.0@sha256:mlold".to_string(),
            )]
            .into(),
        }
    }

    #[test]
    fn an_applied_update_goes_back_to_its_images_and_its_copy() {
        let u = plan(
            "immich",
            Some(&run(UpdateRunOutcome::Applied, Some(material()))),
            &spec(),
        )
        .expect("undoable");
        let image = u.image.expect("the app's image moves");
        assert_eq!(
            image.reference(),
            "ghcr.io/immich-app/immich-server:v3.1.0@sha256:old"
        );
        assert_eq!(u.companions.len(), 1);
        assert_eq!(u.companions[0].service, "immich-ml");
        assert_eq!(u.companions[0].image.tag, "v3.1.0");
        assert_eq!(u.copies, ["a1", "b2"]);
        assert_eq!(u.run, 7);
    }

    #[test]
    fn only_an_applied_last_update_is_undone() {
        let s = spec();
        assert_eq!(
            plan("immich", None, &s),
            Err(Refusal::NoRun {
                app: "immich".into()
            })
        );
        assert!(matches!(
            plan("immich", Some(&run(UpdateRunOutcome::Undone, None)), &s),
            Err(Refusal::AlreadyUndone { .. })
        ));
        for o in [
            UpdateRunOutcome::RolledBack,
            UpdateRunOutcome::Paused,
            UpdateRunOutcome::Inconclusive,
        ] {
            assert!(matches!(
                plan("immich", Some(&run(o, Some(material()))), &s),
                Err(Refusal::NotApplied { .. })
            ));
        }
        // Recorded before the copy's ids were kept: no guessing which snapshots.
        assert!(matches!(
            plan("immich", Some(&run(UpdateRunOutcome::Applied, None)), &s),
            Err(Refusal::NoMaterial { .. })
        ));
    }

    #[test]
    fn an_app_moved_since_its_update_is_not_undone() {
        let mut s = spec();
        s.image.digest = Some("sha256:newer".into());
        assert!(matches!(
            plan(
                "immich",
                Some(&run(UpdateRunOutcome::Applied, Some(material()))),
                &s
            ),
            Err(Refusal::MovedSince { .. })
        ));
    }

    #[test]
    fn a_companion_no_longer_installed_refuses_the_undo() {
        let mut s = spec();
        s.companions.clear();
        assert!(matches!(
            plan(
                "immich",
                Some(&run(UpdateRunOutcome::Applied, Some(material()))),
                &s
            ),
            Err(Refusal::CompanionGone { .. })
        ));
    }

    #[test]
    fn a_move_of_companions_alone_leaves_the_app_s_image() {
        let mut r = run(UpdateRunOutcome::Applied, Some(material()));
        r.from_image = r.to_image.clone();
        let u = plan("immich", Some(&r), &spec()).expect("undoable");
        assert_eq!(u.image, None);
        assert_eq!(u.companions.len(), 1);
    }

    #[test]
    fn an_image_is_read_back_past_a_registry_s_port() {
        let running = Image {
            repo: "registry:5000/team/app".into(),
            tag: "2".into(),
            digest: None,
            built_here: true,
            signed_by: None,
        };
        let i = parse("registry:5000/team/app:1.2@sha256:abc", &running).expect("read");
        assert_eq!(
            (i.repo.as_str(), i.tag.as_str(), i.digest.as_deref()),
            ("registry:5000/team/app", "1.2", Some("sha256:abc"))
        );
        assert!(i.built_here, "the same repository keeps what only it says");
        // By tag alone, or a port mistaken for a tag: refused, never deployed so.
        for bad in [
            "registry:5000/team/app:1.2",
            "registry:5000/team/app@sha256:abc",
            "app:1.2@",
        ] {
            assert!(parse(bad, &running).is_err(), "{bad}");
        }
        let other = parse("elsewhere/app:1@sha256:x", &running).expect("read");
        assert!(!other.built_here);
    }

    #[test]
    fn the_image_a_person_undid_waits_for_a_person() {
        let undone_run = UpdateRun {
            outcome: UpdateRunOutcome::Undone,
            // An undo records the way back: from what ran to what it put back.
            from_image: "x:2@sha256:new".into(),
            to_image: "x:1@sha256:old".into(),
            ..run(UpdateRunOutcome::Undone, None)
        };
        assert!(undone(Some(&undone_run), "sha256:new"));
        assert!(!undone(Some(&undone_run), "sha256:newer"));
        let applied = run(UpdateRunOutcome::Applied, None);
        assert!(!undone(Some(&applied), "sha256:new"));
        assert!(!undone(None, "sha256:new"));
    }
}
