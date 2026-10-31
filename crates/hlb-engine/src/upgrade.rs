//! Bringing an installed app to its catalog manifest.
//!
//! An installation runs the manifest frozen when it was installed, and rerunning the
//! install skipped every deployment already done: Vikunja kept two replicas over a
//! local volume long after the catalog had gone to one (found on a real cluster).
//! `hlb upgrade` applies the catalog's manifest — except its images, which move through
//! `hlb update`: that path backs up first, and an image is where a migration hides.

use hlb_types::{Capability, Manifest};

/// The manifest an upgrade installs: the catalog's, running the images installed now.
pub fn next(frozen: &Manifest, catalog: &Manifest) -> Manifest {
    let mut next = catalog.clone();
    next.spec.image = frozen.spec.image.clone();
    for companion in &mut next.spec.companions {
        if let Some(installed) = frozen
            .spec
            .companions
            .iter()
            .find(|f| f.name == companion.name)
        {
            companion.image = installed.image.clone();
        }
    }
    next
}

/// What changes, one line per field: `spec.swarm.replicas: 2 → 1`.
pub fn changes(frozen: &Manifest, next: &Manifest) -> Vec<String> {
    let (Ok(before), Ok(after)) = (serde_json::to_value(frozen), serde_json::to_value(next)) else {
        return vec!["the manifests could not be compared".to_string()];
    };
    let mut out = Vec::new();
    diff("", &before, &after, &mut out);
    out
}

fn diff(path: &str, before: &serde_json::Value, after: &serde_json::Value, out: &mut Vec<String>) {
    use serde_json::Value;
    if before == after {
        return;
    }
    if let (Value::Object(b), Value::Object(a)) = (before, after) {
        let mut keys: Vec<&String> = b.keys().chain(a.keys()).collect();
        keys.sort();
        keys.dedup();
        for k in keys {
            let p = if path.is_empty() {
                k.clone()
            } else {
                format!("{path}.{k}")
            };
            diff(
                &p,
                b.get(k).unwrap_or(&Value::Null),
                a.get(k).unwrap_or(&Value::Null),
                out,
            );
        }
        return;
    }
    // Element by element when the length holds: one tier changed in `requires` reads
    // as that one field, not as the whole list printed twice.
    if let (Value::Array(b), Value::Array(a)) = (before, after) {
        if a.len() == b.len() {
            for (i, (x, y)) in b.iter().zip(a).enumerate() {
                diff(&format!("{path}[{i}]"), x, y, out);
            }
            return;
        }
    }
    out.push(format!("{path}: {before} → {after}"));
}

/// What the catalog changed in the images, which an upgrade leaves to `hlb update`.
pub fn image_notes(frozen: &Manifest, catalog: &Manifest) -> Vec<String> {
    let mut notes = Vec::new();
    let mut note = |what: &str, installed: &hlb_types::Image, wanted: &hlb_types::Image| {
        if installed.repo != wanted.repo || installed.tag != wanted.tag {
            notes.push(format!(
                "{what}: the catalog has {}:{}, this installation runs {}:{} — \
                 `hlb update` changes images, after its backup",
                wanted.repo, wanted.tag, installed.repo, installed.tag
            ));
        }
    };
    note("image", &frozen.spec.image, &catalog.spec.image);
    for c in &catalog.spec.companions {
        if let Some(f) = frozen.spec.companions.iter().find(|f| f.name == c.name) {
            note(&format!("companion {}", c.name), &f.image, &c.image);
        }
    }
    notes
}

/// What an upgrade cannot do on its own. Empty: it may proceed.
///
/// Each moves or abandons data a deployment cannot move: an existing volume keeps the
/// backing it was created with, a database or a bucket renamed is a new, empty one,
/// and a companion dropped from the catalog would keep running, managed by nobody.
pub fn refusals(frozen: &Manifest, next: &Manifest) -> Vec<String> {
    let mut out = Vec::new();
    for c in &frozen.spec.requires {
        // Every capability, named: one added tomorrow must be decided on here.
        match c {
            Capability::Storage {
                name,
                path: _,
                tier,
                backup: _,
                sqlite: _,
                // How the pass copies it moves nothing: the next pass reads the new one.
                copy: _,
                owner,
            } => match storage(next, name) {
                Some((_, o)) if o != *owner => out.push(format!(
                    "volume \"{name}\" changes hands ({} → {}): the data stays with the \
                     volume it is in — remove and install the app",
                    owner.as_deref().unwrap_or("its own"),
                    o.as_deref().unwrap_or("its own")
                )),
                Some((t, _)) if t != *tier => out.push(format!(
                    "volume \"{name}\" moves from {tier:?} to {t:?}: an existing volume keeps \
                     the backing it was created with, and its data does not move — copy it, \
                     then remove and install the app"
                )),
                Some(_) => {}
                // 🔴 Removing and installing Stalwart is losing the house's mail: 1.0
                // opens a new store, which only its migration fills.
                None if crate::stalwart_migrate::crossing(frozen, next) => out.push(format!(
                    "volume \"{name}\" gives way to \"{}\": Stalwart 1.0 cannot open a 0.16 \
                     store. `hlb mail migrate --apply` copies the mail into the new one, then \
                     switches — the old volume is kept",
                    crate::stalwart_migrate::TO_STORAGE
                )),
                None => out.push(format!(
                    "volume \"{name}\" is no longer declared: the app would stop using its \
                     data. Remove and install the app once the data is saved elsewhere"
                )),
            },
            Capability::Database {
                engine,
                name,
                extensions: _,
            } => {
                // Matched by name: Seafile has three, and against the catalog's first
                // one each of the other two read as renamed — its upgrade was refused.
                let theirs = databases(next);
                let found = theirs.iter().find(|(_, n)| *n == name).or_else(|| {
                    match (databases(frozen).len(), theirs.as_slice()) {
                        (1, [only]) => Some(only),
                        _ => None,
                    }
                });
                match found {
                    Some((e, _)) if *e != engine => out.push(format!(
                        "the database moves from {engine:?} to {e:?}: nothing converts \
                         one into the other"
                    )),
                    // A name left out is the app's own: `None` → `Some("vikunja")` for
                    // vikunja names the same database, and refusing it stranded nothing
                    // but the upgrade.
                    Some((_, n)) if effective(n, frozen) != effective(name, frozen) => {
                        out.push(format!(
                            "the database is renamed ({name:?} → {n:?}): the app would \
                         reconnect to a new, empty one"
                        ))
                    }
                    Some(_) => {}
                    None => out.push(format!(
                        "the database {:?} is no longer declared: the app would stop \
                         reading its data. Remove and install the app once the data is \
                         saved elsewhere",
                        name.as_deref().unwrap_or(&frozen.metadata.name)
                    )),
                }
            }
            Capability::ObjectStorage {
                bucket,
                backup: _,
                expire_after_days: _,
            } => match bucket_in(next, frozen, bucket) {
                Some(b) if effective(&b, next) != effective(bucket, frozen) => out.push(format!(
                    "the bucket is renamed ({bucket:?} → {b:?}): the app would write \
                         to a new, empty one"
                )),
                Some(_) => {}
                // Gone from the catalog, the app would stop reading what it stored: the
                // same as a volume or a database no longer declared.
                None => out.push(format!(
                    "the bucket {:?} is no longer declared: the app would stop reading \
                     its objects. Remove and install the app once they are saved elsewhere",
                    effective(bucket, frozen)
                )),
            },
            // Re-provisioned in place by the plan: a cache holds nothing to keep, an
            // OIDC client and a mailbox are updated, not replaced.
            Capability::Cache {
                engine: _,
                dedicated: _,
            }
            | Capability::Sso {
                mode: _,
                redirect_paths: _,
            }
            | Capability::Smtp { sender: _ }
            | Capability::MailAccount {
                quota_bytes: _,
                aliases: _,
            } => {}
        }
    }
    for f in &frozen.spec.companions {
        if !next.spec.companions.iter().any(|c| c.name == f.name) {
            out.push(format!(
                "companion \"{}\" is no longer in the catalog: its service would keep \
                 running, managed by nobody — remove and install the app",
                f.name
            ));
        }
    }
    out
}

fn storage(m: &Manifest, volume: &str) -> Option<(hlb_types::StorageTier, Option<String>)> {
    m.spec.requires.iter().find_map(|c| match c {
        Capability::Storage {
            name,
            path: _,
            tier,
            backup: _,
            sqlite: _,
            copy: _,
            owner,
        } if name == volume => Some((*tier, owner.clone())),
        _ => None,
    })
}

fn databases(m: &Manifest) -> Vec<(&hlb_types::DbEngine, &Option<String>)> {
    m.spec
        .requires
        .iter()
        .filter_map(|c| match c {
            Capability::Database {
                engine,
                name,
                extensions: _,
            } => Some((engine, name)),
            _ => None,
        })
        .collect()
}

/// A database's or a bucket's name as provisioned: one left out is the app's own.
fn effective<'a>(name: &'a Option<String>, m: &'a Manifest) -> &'a str {
    name.as_deref().unwrap_or(&m.metadata.name)
}

fn buckets(m: &Manifest) -> Vec<Option<String>> {
    m.spec
        .requires
        .iter()
        .filter_map(|c| match c {
            Capability::ObjectStorage {
                bucket,
                backup: _,
                expire_after_days: _,
            } => Some(bucket.clone()),
            _ => None,
        })
        .collect()
}

/// `frozen`'s bucket `name` in `next`: by its name, as databases are — Fluxer has four,
/// and against the catalog's first each of the others would read as renamed. One on
/// each side is the same bucket whatever it is called.
fn bucket_in(next: &Manifest, frozen: &Manifest, name: &Option<String>) -> Option<Option<String>> {
    let theirs = buckets(next);
    theirs
        .iter()
        .find(|b| effective(b, next) == effective(name, frozen))
        .cloned()
        .or_else(|| match (buckets(frozen).len(), theirs.as_slice()) {
            (1, [only]) => Some(only.clone()),
            _ => None,
        })
}

/// How an upgrade's run ended, once the state is made to say it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Settled {
    /// Every action done: the new manifest is what runs.
    Finished,
    /// Done but for actions recorded as unimplemented: the new spec was deployed, so
    /// the new manifest stays, the app `partial`.
    Partial,
    /// Stopped before any service was redeployed: the previous manifest and status are
    /// back, as if nothing had been tried.
    Reverted,
    /// Stopped after a service was redeployed on the new spec: the new manifest stays —
    /// it is what runs —, the status the app had is back, and the next upgrade runs the
    /// plan again.
    Interrupted,
}

/// Brings the state in line with what an upgrade's run did, from its journal.
///
/// 🔴 Two ways it lied before. A run leaving only unimplemented actions — an OIDC
/// client with no PocketID key — put the previous manifest back while the services ran
/// the new spec, so reconciliation and the next upgrade compared against a manifest
/// nothing ran. And a failed run left the app `failed`, which takes its route away: an
/// upgrade that stopped halfway made a working app unreachable.
pub async fn settle(
    state: &hlb_state::State,
    app: &str,
    previous: &Manifest,
    previous_status: &str,
    domain: Option<&str>,
) -> crate::Result<Settled> {
    use hlb_state::ActionStatus;
    let journal = state.plan_actions(app).await?;
    let open = journal
        .iter()
        .any(|a| matches!(a.status, ActionStatus::Failed | ActionStatus::Pending));
    if !journal.is_empty() && !open {
        let partial = journal
            .iter()
            .any(|a| a.status == ActionStatus::Unimplemented);
        return Ok(if partial {
            Settled::Partial
        } else {
            Settled::Finished
        });
    }
    let deployed = journal
        .iter()
        .any(|a| a.kind == "DeployService" && a.status == ActionStatus::Done);
    if !deployed {
        state.upsert_app(app, previous, domain).await?;
    }
    state.set_app_status(app, previous_status).await?;
    Ok(if deployed {
        Settled::Interrupted
    } else {
        Settled::Reverted
    })
}

/// Did the app's last run stop before its end — an upgrade [`Settled::Interrupted`]
/// keeps the manifest it deployed, and its catalog no longer differs from it?
pub async fn interrupted(state: &hlb_state::State, app: &str) -> crate::Result<bool> {
    Ok(state
        .plan_actions(app)
        .await?
        .iter()
        .any(|a| a.status == hlb_state::ActionStatus::Failed))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(extra: &str) -> Manifest {
        serde_yaml_ng::from_str(&format!(
            "apiVersion: hlb/v1\nkind: App\nmetadata: {{ name: vikunja }}\nspec:\n  \
             image: {{ repo: vikunja/vikunja, tag: \"0.24\" }}\n{extra}"
        ))
        .expect("test manifest")
    }

    #[test]
    fn the_catalogs_change_is_applied_and_the_installed_image_kept() {
        let mut frozen = manifest("  swarm:\n    replicas: 2\n");
        frozen.spec.image.digest = Some("sha256:running".into());
        let catalog = manifest("  swarm:\n    replicas: 1\n");
        let n = next(&frozen, &catalog);
        assert_eq!(n.spec.swarm.replicas, 1);
        assert_eq!(n.spec.image.digest.as_deref(), Some("sha256:running"));
        assert_eq!(
            changes(&frozen, &n),
            vec!["spec.swarm.replicas: 2 → 1".to_string()]
        );
        assert!(refusals(&frozen, &n).is_empty());
    }

    #[test]
    fn a_new_image_is_named_and_left_to_update() {
        let frozen = manifest("");
        let mut catalog = manifest("");
        catalog.spec.image.tag = "0.25".into();
        assert!(changes(&frozen, &next(&frozen, &catalog)).is_empty());
        let notes = image_notes(&frozen, &catalog);
        assert!(
            notes.len() == 1 && notes[0].contains("hlb update"),
            "{notes:?}"
        );
    }

    #[test]
    fn a_volume_that_changes_tier_or_disappears_is_refused() {
        let vol = |tier: &str| {
            format!(
                "  requires:\n    - kind: storage\n      name: files\n      path: /files\n      \
                 tier: {tier}\n"
            )
        };
        let frozen = manifest(&vol("local"));
        let moved = next(&frozen, &manifest(&vol("nfs")));
        assert!(refusals(&frozen, &moved)[0].contains("does not move"));
        assert_eq!(
            changes(&frozen, &moved),
            vec![r#"spec.requires[0].tier: "local" → "nfs""#.to_string()]
        );
        let gone = next(&frozen, &manifest(""));
        assert!(refusals(&frozen, &gone)[0].contains("no longer declared"));
    }

    #[test]
    fn several_databases_are_matched_by_name() {
        let dbs = |names: &[&str]| {
            let mut s = String::from("  requires:\n");
            for n in names {
                s.push_str(&format!(
                    "    - kind: database\n      engine: mariadb\n      name: {n}\n"
                ));
            }
            s
        };
        let frozen = manifest(&dbs(&["seafile_db", "seahub_db", "ccnet_db"]));
        let reordered = next(
            &frozen,
            &manifest(&dbs(&["ccnet_db", "seafile_db", "seahub_db"])),
        );
        assert_eq!(refusals(&frozen, &reordered), Vec::<String>::new());

        let dropped = next(&frozen, &manifest(&dbs(&["ccnet_db", "seafile_db"])));
        let r = refusals(&frozen, &dropped);
        assert!(
            r.len() == 1 && r[0].contains("\"seahub_db\" is no longer declared"),
            "{r:?}"
        );

        // One database on each side is still read as a rename.
        let single = manifest(&dbs(&["vikunja"]));
        let renamed = next(&single, &manifest(&dbs(&["tasks"])));
        assert!(refusals(&single, &renamed)[0].contains("renamed"));
    }

    #[test]
    fn a_bucket_no_longer_declared_is_refused() {
        let frozen = manifest("  requires:\n    - kind: object-storage\n");
        let gone = next(&frozen, &manifest(""));
        let r = refusals(&frozen, &gone);
        assert!(
            r.len() == 1 && r[0].contains("\"vikunja\" is no longer declared"),
            "{r:?}"
        );
    }

    #[test]
    fn several_buckets_are_matched_by_name() {
        let four = |last: &str| {
            manifest(&format!(
                "  requires:\n    - {{ kind: object-storage, backup: false, bucket: a }}\n    \
                 - {{ kind: object-storage, backup: false, bucket: b }}\n    \
                 - {{ kind: object-storage, backup: false, bucket: {last} }}\n"
            ))
        };
        let frozen = four("c");
        // The same three, whatever their order: nothing to refuse.
        assert_eq!(
            refusals(&frozen, &next(&frozen, &four("c"))),
            Vec::<String>::new()
        );
        // One gone: that one, by its name.
        let r = refusals(&frozen, &next(&frozen, &four("d")));
        assert!(
            r.len() == 1 && r[0].contains("\"c\"") && r[0].contains("no longer declared"),
            "{r:?}"
        );
    }

    #[test]
    fn naming_the_database_the_app_already_had_is_not_a_rename() {
        let frozen = manifest("  requires:\n    - kind: database\n      engine: postgres\n");
        let named = next(
            &frozen,
            &manifest(
                "  requires:\n    - kind: database\n      engine: postgres\n      name: vikunja\n",
            ),
        );
        assert_eq!(refusals(&frozen, &named), Vec::<String>::new());
        let bucket = manifest("  requires:\n    - kind: object-storage\n");
        let named = next(
            &bucket,
            &manifest("  requires:\n    - kind: object-storage\n      bucket: vikunja\n"),
        );
        assert_eq!(refusals(&bucket, &named), Vec::<String>::new());
    }

    async fn upgraded(
        statuses: &[(&str, hlb_state::ActionStatus)],
    ) -> (hlb_state::State, Manifest) {
        let s = hlb_state::State::in_memory().await.expect("state");
        let before = manifest("  swarm:\n    replicas: 2\n");
        s.upsert_app("vikunja", &before, Some("tasks.example.org"))
            .await
            .expect("app");
        s.set_app_status("vikunja", "running")
            .await
            .expect("status");
        // The upgrade: the catalog's manifest frozen, its plan run.
        let after = manifest("  swarm:\n    replicas: 1\n");
        s.upsert_app("vikunja", &after, Some("tasks.example.org"))
            .await
            .expect("frozen");
        let records: Vec<(String, String)> = statuses
            .iter()
            .map(|(kind, _)| (kind.to_string(), format!("{kind} vikunja")))
            .collect();
        s.record_plan("vikunja", &records).await.expect("plan");
        for (seq, (_, status)) in statuses.iter().enumerate() {
            s.set_action_status("vikunja", seq, *status, None)
                .await
                .expect("status");
        }
        (s, before)
    }

    async fn status(s: &hlb_state::State) -> String {
        s.installed_apps()
            .await
            .expect("apps")
            .into_iter()
            .find(|(n, _)| n == "vikunja")
            .map(|(_, st)| st)
            .expect("recorded")
    }

    #[tokio::test]
    async fn an_upgrade_left_unimplemented_keeps_the_manifest_it_deployed() {
        use hlb_state::ActionStatus::*;
        let (s, before) =
            upgraded(&[("DeployService", Done), ("CreateOidcClient", Unimplemented)]).await;
        s.set_app_status("vikunja", "partial")
            .await
            .expect("status");
        let settled = settle(&s, "vikunja", &before, "running", Some("tasks.example.org"))
            .await
            .expect("settle");
        assert_eq!(settled, Settled::Partial);
        assert_eq!(
            s.app_manifest("vikunja")
                .await
                .expect("m")
                .spec
                .swarm
                .replicas,
            1,
            "the services run the new spec: the state says so"
        );
        assert_eq!(status(&s).await, "partial");
    }

    #[tokio::test]
    async fn an_upgrade_failing_before_any_deployment_puts_everything_back() {
        use hlb_state::ActionStatus::*;
        let (s, before) = upgraded(&[("GenerateSecret", Failed), ("DeployService", Pending)]).await;
        s.set_app_status("vikunja", "failed").await.expect("status");
        let settled = settle(&s, "vikunja", &before, "running", Some("tasks.example.org"))
            .await
            .expect("settle");
        assert_eq!(settled, Settled::Reverted);
        assert_eq!(
            s.app_manifest("vikunja")
                .await
                .expect("m")
                .spec
                .swarm
                .replicas,
            2
        );
        assert_eq!(status(&s).await, "running", "its route must not go");
        assert_eq!(
            s.app_domain("vikunja").await.expect("d").as_deref(),
            Some("tasks.example.org")
        );
    }

    #[tokio::test]
    async fn an_upgrade_failing_after_a_deployment_keeps_what_runs_and_its_route() {
        use hlb_state::ActionStatus::*;
        let (s, before) = upgraded(&[("DeployService", Done), ("WaitHealthy", Failed)]).await;
        s.set_app_status("vikunja", "failed").await.expect("status");
        let settled = settle(&s, "vikunja", &before, "running", Some("tasks.example.org"))
            .await
            .expect("settle");
        assert_eq!(settled, Settled::Interrupted);
        assert_eq!(
            s.app_manifest("vikunja")
                .await
                .expect("m")
                .spec
                .swarm
                .replicas,
            1
        );
        assert_eq!(status(&s).await, "running");
        assert!(interrupted(&s, "vikunja").await.expect("read"));
    }
}
