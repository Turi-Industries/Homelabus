//! The state, as the coverage calculation reads it.
//!
//! `hlb_backup::coverage_of` needs to read the state, and `hlb-state` cannot implement
//! its trait — `hlb-backup` depends on `hlb-updater`, which depends on `hlb-state`. The
//! adapter lives here, beside the pass that writes what it reads: the CLI and the
//! controller each had their own, and the CLI's had kept the reading of ages across
//! every kind after the controller's moved on.

use hlb_backup::{Class, CoverageSource, Destination};
use hlb_state::{backup_kind, State};

/// The [`backup_kind`]s a pass writes for `class`.
///
/// 🔴 What makes a destination's age honest: read across kinds, the dump every pass
/// records made a destination whose volumes were backed up once read "fresh" forever.
pub fn kinds_of(class: Class) -> &'static [&'static str] {
    match class {
        Class::Critical => &[backup_kind::SQLITE, backup_kind::SQL_DUMP],
        Class::Bulky => &[backup_kind::VOLUME, backup_kind::BUCKET],
    }
}

/// The class whose destinations receive `kind`; `None` for a kind no app's coverage
/// counts — Homelabus's own state, a base backup.
pub fn class_of(kind: &str) -> Option<Class> {
    [Class::Critical, Class::Bulky]
        .into_iter()
        .find(|c| kinds_of(*c).contains(&kind))
}

/// Adapts the state to what the coverage calculation needs.
pub struct StateSource<'a>(pub &'a State);

impl StateSource<'_> {
    /// What `app` holds of `class`, as kinds. ⚠️ A read error reads as the class's
    /// every kind: owed and never backed up is the safe direction.
    async fn kinds(&self, app: &str, class: Class) -> Vec<&'static str> {
        let all = kinds_of(class);
        match self.0.backup_kinds(app).await {
            Ok(held) => all.iter().copied().filter(|k| held.contains(k)).collect(),
            Err(_) => all.to_vec(),
        }
    }
}

impl CoverageSource for StateSource<'_> {
    async fn destinations(&self) -> Vec<Destination> {
        // ⚠️ A read error returns an EMPTY list, so zero up-to-date copies, so an alert.
        // That is the safe direction: an unreadable database must not translate into
        // "all is well".
        crate::load_destinations(self.0).await.unwrap_or_default()
    }

    async fn route(&self, app: &str, class: Class) -> Vec<String> {
        self.0.route(app, class.name()).await.unwrap_or_default()
    }

    async fn classes(&self, app: &str) -> Vec<Class> {
        let mut out = Vec::new();
        for c in [Class::Critical, Class::Bulky] {
            if !self.kinds(app, c).await.is_empty() {
                out.push(c);
            }
        }
        out
    }

    async fn age_of(&self, app: &str, destination: &str, class: Class) -> Option<i64> {
        let kinds = self.kinds(app, class).await;
        if kinds.is_empty() {
            return None;
        }
        self.0
            .seconds_since_last_success_of(app, &kinds, Some(destination))
            .await
            .ok()
            .flatten()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_kind_an_app_holds_has_a_class() {
        for kind in [
            backup_kind::VOLUME,
            backup_kind::SQLITE,
            backup_kind::SQL_DUMP,
            backup_kind::BUCKET,
        ] {
            assert!(class_of(kind).is_some(), "{kind}");
        }
        assert_eq!(class_of(backup_kind::STATE), None);
    }

    fn manifest(yaml: &str) -> hlb_types::Manifest {
        serde_yaml_ng::from_str(yaml).expect("test manifest")
    }

    #[tokio::test]
    async fn a_destination_is_as_old_as_the_oldest_kind_it_holds_of_an_app() {
        // 🔴 Found by review: a dump every pass, a volume backed up once — and the
        // destination receiving both was "fresh", read across kinds.
        let s = State::in_memory().await.expect("state");
        s.upsert_app(
            "gitea",
            &manifest(
                "apiVersion: hlb/v1\nkind: App\nmetadata: { name: gitea }\n\
                 spec:\n  image: { repo: a/b, tag: \"1\" }\n  \
                 requires:\n    - kind: database\n      engine: postgres\n",
            ),
            None,
        )
        .await
        .expect("app");
        s.add_volume("gitea", "gitea-data", "/data", true, false)
            .await
            .expect("volume");
        s.upsert_destination("nas", "/mnt/nas", "critical,bulky", None)
            .await
            .expect("destination");
        s.record_backup_to("gitea", "volume", "nas", Some("v1"), None)
            .await
            .expect("volume");
        s.backdate_backup("gitea", "nas", 20 * 86_400)
            .await
            .expect("three weeks ago");
        s.record_backup_to("gitea", "sql-dump", "nas", Some("d1"), None)
            .await
            .expect("dump");

        let c = hlb_backup::coverage_of(&StateSource(&s), "gitea", 12 * 3_600).await;
        assert!(
            matches!(
                c.per_destination.as_slice(),
                [(n, hlb_backup::DestinationState::Stale { age_s })]
                    if n == "nas" && *age_s >= 20 * 86_400
            ),
            "{c:?}"
        );
    }

    #[tokio::test]
    async fn an_app_holding_nothing_needs_no_backup() {
        let s = State::in_memory().await.expect("state");
        s.upsert_app(
            "valkey",
            &manifest(
                "apiVersion: hlb/v1\nkind: App\nmetadata: { name: valkey }\n\
                 spec:\n  image: { repo: a/b, tag: \"1\" }\n",
            ),
            None,
        )
        .await
        .expect("app");
        s.upsert_destination("nas", "/mnt/nas", "critical,bulky", None)
            .await
            .expect("destination");
        let c = hlb_backup::coverage_of(&StateSource(&s), "valkey", 12 * 3_600).await;
        assert!(!c.needs_backup(), "{c:?}");
    }
}
