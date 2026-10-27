//! Multiple backup destinations and their routing.
//!
//! ## The problem this solves
//!
//! A single repository was enough as long as there was only a NAS. As soon as you want
//! the 3-2-1 rule — a fast copy on the LAN, an off-site copy against fire and
//! ransomware — you need several, and **not all data can go everywhere**.
//!
//! This is not a question of importance: everything is important. It is a question of
//! **volume and pipe**. A few gigabytes of SQL dumps cross any domestic connection;
//! several hundred gigabytes of photos do not, and the first backup would never catch
//! up. Hence routing by data class, decided at install time and not in the catalog — it
//! is each person's connection and budget that decide, not a manifest's author.
//!
//! ## 🔴 The central invariant: a fresh destination never masks a stale one
//!
//! This is the trap that would drain the whole thing of its meaning.
//! `seconds_since_last_success` took the maximum **across all destinations**: with a NAS
//! backed up every four hours and an off-site failing for three weeks, the answer stayed
//! "backed up 2 h ago". You would believe the 3-2-1 rule held while only one copy was
//! left, on the same machines.
//!
//! Freshness is therefore measured **per destination**, and [`State::worst`] always keeps
//! the worst case.
//!
//! ## 🔴 Credentials never travel through a plan nor through a log
//!
//! An S3 key lives in the vault and only appears in the restic container's environment,
//! at execution time. A displayed destination shows its endpoint, never its keys — see
//! [`Destination::describe`].

use crate::{Error, Result};

/// A class of data to back up.
///
/// 🔴 The distinction is not "important / not important" — everything is. It separates
/// what **fits through a domestic connection** from what does not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Class {
    /// SQL dumps, state, secrets, manifests. A few gigabytes at most.
    ///
    /// This is what must go off-site first: without the database the volumes are
    /// useless; without the secrets the backups themselves are unreadable.
    Critical,
    /// Application volumes: photos, files, media. No upper bound.
    Bulky,
}

impl Class {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::Bulky => "bulky",
        }
    }

    /// ⚠️ `name()` writes these words into `backup_destinations.classes`. Changing one
    /// makes every destination already configured accept NOTHING: still listed, still
    /// looking configured, quietly never written to again. The spare spellings are
    /// there so a hand-typed `--classes` does not have to be exact.
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "critical" | "dumps" => Some(Self::Critical),
            "bulky" | "volumes" | "bulk" => Some(Self::Bulky),
            _ => None,
        }
    }
}

/// Where a backup goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Destination {
    /// Short identifier: `nas`, `garage`, `offsite`.
    pub name: String,
    /// restic location. A path, or an `s3:…` URL.
    pub location: String,
    /// What this destination accepts. Empty = nothing, and it is said so.
    pub classes: Vec<Class>,
    /// Name of the secret carrying `access_key:secret_key`, for S3 destinations.
    pub credentials_secret: Option<String>,
}

impl Destination {
    /// Is this an S3 repository?
    ///
    /// 🔴 Decides everything else: an S3 repository is **not mounted** into the restic
    /// container, it is reached over the network. Mounting it would create an empty
    /// directory and restic would answer "repository does not exist", naming a local
    /// path unrelated to the real destination.
    pub fn is_s3(&self) -> bool {
        let l = self.location.trim_start();
        l.starts_with("s3:") || l.starts_with("s3s:")
    }

    /// Is this repository reached over the network — S3, or a restic REST server?
    ///
    /// 🔴 What a volume on ANOTHER node can be backed up to. A path names a directory on
    /// whichever machine restic runs on: run where the volume lives, it would have
    /// started a second repository on that machine's own disk, nobody watching it.
    pub fn is_remote(&self) -> bool {
        self.is_s3() || self.location.trim_start().starts_with("rest:")
    }

    pub fn accepts(&self, c: Class) -> bool {
        self.classes.contains(&c)
    }

    /// The location, with credentials masked.
    ///
    /// ⚠️ An S3 URL can carry credentials (`s3:https://key:secret@host/bucket`). We
    /// truncate before the `@`: otherwise `hlb backup dest list` would publish the key in
    /// the terminal, then in the shell history, then in a screenshot.
    ///
    /// ⚠️ Extracted from `describe` rather than copied: two divergent maskings would end
    /// up leaving one that is not a masking at all, and an access key would go out into a
    /// terminal or onto a printed page.
    pub fn masked_location(&self) -> String {
        match self.location.split_once('@') {
            Some((before, after)) if before.contains("://") => {
                let schema = before.split_once("://").map(|(s, _)| s).unwrap_or("s3");
                format!("{schema}://••••@{after}")
            }
            _ => self.location.clone(),
        }
    }

    pub fn describe(&self) -> String {
        let location = self.masked_location();

        let classes: Vec<&str> = self.classes.iter().map(|c| c.name()).collect();
        if classes.is_empty() {
            // 🔴 A destination that accepts nothing receives nothing. Say it, because it
            // otherwise looks like a configured destination.
            format!(
                "{} -> {location}  ⚠️ accepts NO class: nothing will be sent there",
                self.name
            )
        } else {
            format!("{} -> {location}  [{}]", self.name, classes.join(", "))
        }
    }

    /// The environment variables to hand restic.
    ///
    /// `credentials` is the secret's content, in `access_key:secret_key` form.
    ///
    /// 🔴 Through the environment, never through the command line: that one is readable
    /// by every user of the machine through `ps`.
    pub fn env(&self, credentials: Option<&str>) -> Result<Vec<(String, String)>> {
        let mut v = Vec::new();

        if !self.is_s3() {
            return Ok(v);
        }

        let Some(id) = credentials else {
            return Err(Error::Unexpected(format!(
                "destination \"{}\": S3 repository with no credentials. Store them with \
                 \"hlb backup dest add {} --location … --access-key …\"",
                self.name, self.name
            )));
        };

        let Some((key, secret)) = id.split_once(':') else {
            return Err(Error::Unexpected(format!(
                "destination \"{}\": unreadable credentials, expected format \
                 \"access_key:secret_key\"",
                self.name
            )));
        };

        v.push(("AWS_ACCESS_KEY_ID".into(), key.to_string()));
        v.push(("AWS_SECRET_ACCESS_KEY".into(), secret.to_string()));
        Ok(v)
    }
}

impl Destination {
    /// The container runner and the repository path to hand restic.
    ///
    /// 🔴 The whole difference between local and S3 sits here, and it is easy to miss: a
    /// local repository is **mounted** and restic sees it at `/repo`; an S3 repository
    /// is **reached over the network** and restic receives the URL as is. Mounting a URL
    /// would create an empty directory, and restic would answer "repository does not
    /// exist", naming a local path unrelated to the real destination.
    ///
    /// `network` serves S3 repositories hosted INSIDE the cluster (Garage): without it,
    /// the restic container does not resolve `garage`.
    pub fn runner(&self, network: Option<&str>) -> (crate::runner::ContainerRunner, String) {
        let mut r = crate::runner::ContainerRunner::default();

        if self.is_remote() {
            if let Some(n) = network {
                r = r.network(n);
            }
            (r, self.location.clone())
        } else {
            (r.mount(&self.location, "/repo"), "/repo".to_string())
        }
    }
}

/// A destination's freshness for one app.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum State {
    /// 🔴 NOTHING has ever arrived there.
    ///
    /// Distinct from "behind", for the same reason `NeverSucceeded` is distinct from
    /// `Stale` in the UI: a destination that never received anything never protected
    /// anything. Confusing it with a delay would send you looking for a recent failure,
    /// when the routing may never have been wired up.
    Never,
    Fresh {
        age_s: i64,
    },
    /// Behind, past the threshold.
    Stale {
        age_s: i64,
    },
}

impl State {
    pub fn judge(age_s: Option<i64>, threshold_s: i64) -> Self {
        match age_s {
            None => Self::Never,
            Some(a) if a > threshold_s => Self::Stale { age_s: a },
            Some(a) => Self::Fresh { age_s: a },
        }
    }

    pub fn is_alarming(&self) -> bool {
        !matches!(self, Self::Fresh { .. })
    }
}

/// An app's state across all its destinations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Coverage {
    pub app: String,
    /// `(destination name, state)`.
    pub per_destination: Vec<(String, State)>,
    /// What the app has to back up. Empty: nothing — see [`Coverage::needs_backup`].
    pub classes: Vec<Class>,
}

impl Coverage {
    /// Does the app hold anything to back up?
    ///
    /// 🔴 Valkey, LibreSpeed and Anubis keep nothing: counted, each was "never backed
    /// up" forever — a critical alert, and the inbox line, nobody could ever clear, and
    /// a rule already firing for them never notified the real loss that came later.
    pub fn needs_backup(&self) -> bool {
        !self.classes.is_empty()
    }

    /// 🔴 The worst case, never the best.
    ///
    /// This is THE rule of this module. Taking the most recent — what
    /// `seconds_since_last_success` did by aggregating every destination — would let a
    /// fresh NAS mask an off-site dead for three weeks. You would believe the 3-2-1 rule
    /// held while only one copy was left, on the same machines.
    pub fn worst(&self) -> Option<&State> {
        self.per_destination
            .iter()
            .map(|(_, e)| e)
            .max_by_key(|e| match e {
                // Never received is the worst case, whatever the age of the others.
                State::Never => i64::MAX,
                State::Stale { age_s } => *age_s,
                State::Fresh { age_s } => -*age_s,
            })
    }

    /// The destinations that are a problem.
    pub fn alarming(&self) -> Vec<&(String, State)> {
        self.per_destination
            .iter()
            .filter(|(_, e)| e.is_alarming())
            .collect()
    }

    /// How many copies are really up to date?
    ///
    /// 🔴 This is the number that counts for 3-2-1, and it is NOT derived from the
    /// number of configured destinations: a failing destination is a configured
    /// destination that protects nothing.
    pub fn up_to_date_copies(&self) -> usize {
        self.per_destination
            .iter()
            .filter(|(_, e)| matches!(e, State::Fresh { .. }))
            .count()
    }
}

/// What must be known of the state in order to compute a coverage.
///
/// ## Why a trait rather than a `&State`
///
/// `hlb-backup` does not depend on `hlb-state` and must not start: this crate is
/// testable without a database or a server, and that is what allows the whole backup
/// logic to be exercised in memory. The trait inverts the dependency — the caller
/// supplies the facts, the calculation lives here.
///
/// That was **the** defect: `Coverage` was only built in the CLI. The controller
/// therefore could not emit `hlb_backup_copies`, and the `single-copy` alert rule — the
/// one guarding 3-2-1 — never fired once.
#[allow(async_fn_in_trait)]
pub trait CoverageSource {
    /// The declared destinations.
    async fn destinations(&self) -> Vec<Destination>;

    /// The destinations explicitly routed for this app and this class.
    /// Empty = no explicit route, we fall back on what each destination accepts.
    async fn route(&self, app: &str, class: Class) -> Vec<String>;

    /// The classes of data the app holds. Empty: nothing to back up.
    async fn classes(&self, app: &str) -> Vec<Class>;

    /// Age of the last success of `class` on this destination, in seconds — of the
    /// OLDEST of what the class holds for this app: a fresh dump never makes a stale
    /// SQLite snapshot younger.
    /// `None` = never succeeded — which is not "a very long time ago".
    async fn age_of(&self, app: &str, destination: &str, class: Class) -> Option<i64>;
}

/// The destinations that must receive this class for this app.
///
/// An explicit route wins; otherwise we fall back on what each destination accepts
/// globally. That is what lets you say "Immich's bulky data goes off-site" without
/// sending every other app's along with it.
pub async fn destinations_for<S: CoverageSource>(
    source: &S,
    app: &str,
    class: Class,
) -> Vec<Destination> {
    let all_of_them = source.destinations().await;
    let explicit = source.route(app, class).await;

    if explicit.is_empty() {
        return all_of_them
            .into_iter()
            .filter(|d| d.accepts(class))
            .collect();
    }
    all_of_them
        .into_iter()
        .filter(|d| explicit.contains(&d.name))
        .collect()
}

/// An app's real coverage: where its data is, and from when.
///
/// 🔴 **Per destination, never aggregated.** A `MAX(finished_at)` across every
/// destination makes an off-site dead for three weeks look like a two-hour-old backup,
/// because the NAS is running. You believe 3-2-1 holds while only one copy is left, on
/// the same machines.
///
/// 🔴 **Per class, the oldest deciding.** A destination receiving an app's dumps every
/// pass and its volumes once is as old as the volumes: read across kinds, the dumps made
/// it look fresh while the files went unprotected.
pub async fn coverage_of<S: CoverageSource>(source: &S, app: &str, threshold_s: i64) -> Coverage {
    let classes = source.classes(app).await;
    // Sorted by name: a coverage whose order changed from one call to the next would
    // make displays unstable and snapshot tests useless. `None` inside: never served.
    let mut ages: std::collections::BTreeMap<String, Option<i64>> = Default::default();
    for &c in &classes {
        for d in destinations_for(source, app, c).await {
            let age = source.age_of(app, &d.name, c).await;
            let worst = match ages.get(&d.name) {
                None => age,
                Some(seen) => seen.zip(age).map(|(a, b)| a.max(b)),
            };
            ages.insert(d.name, worst);
        }
    }

    Coverage {
        app: app.to_string(),
        per_destination: ages
            .into_iter()
            .map(|(n, age)| (n, State::judge(age, threshold_s)))
            .collect(),
        classes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An in-memory source: the whole point of having inverted the dependency.
    struct InMemorySource {
        destinations: Vec<Destination>,
        routes: Vec<(String, Class, Vec<String>)>,
        /// `(app, destination, age)`, whatever the class.
        ages: Vec<(String, String, Option<i64>)>,
    }

    /// Like [`InMemorySource`], with what each app holds and an age per class.
    struct ByClass {
        destinations: Vec<Destination>,
        classes: Vec<Class>,
        ages: Vec<(String, Class, Option<i64>)>,
    }

    impl CoverageSource for ByClass {
        async fn destinations(&self) -> Vec<Destination> {
            self.destinations.clone()
        }
        async fn route(&self, _: &str, _: Class) -> Vec<String> {
            Vec::new()
        }
        async fn classes(&self, _: &str) -> Vec<Class> {
            self.classes.clone()
        }
        async fn age_of(&self, _: &str, destination: &str, class: Class) -> Option<i64> {
            self.ages
                .iter()
                .find(|(d, c, _)| d == destination && *c == class)
                .and_then(|(_, _, age)| *age)
        }
    }

    impl CoverageSource for InMemorySource {
        async fn destinations(&self) -> Vec<Destination> {
            self.destinations.clone()
        }
        async fn route(&self, app: &str, class: Class) -> Vec<String> {
            self.routes
                .iter()
                .find(|(a, c, _)| a == app && *c == class)
                .map(|(_, _, d)| d.clone())
                .unwrap_or_default()
        }
        async fn classes(&self, _: &str) -> Vec<Class> {
            vec![Class::Critical, Class::Bulky]
        }
        async fn age_of(&self, app: &str, destination: &str, _: Class) -> Option<i64> {
            self.ages
                .iter()
                .find(|(a, d, _)| a == app && d == destination)
                .and_then(|(_, _, age)| *age)
        }
    }

    fn dest(name: &str, classes: Vec<Class>) -> Destination {
        Destination {
            name: name.into(),
            location: format!("/mnt/{name}"),
            classes,
            credentials_secret: None,
        }
    }

    #[tokio::test]
    async fn a_fresh_destination_never_hides_a_dead_one() {
        // 🔴 THE freshness trap, now computable outside the CLI. The NAS is running, the
        // off-site has been dead for weeks: an aggregate would make that look like a
        // two-hour-old backup, and you would believe 3-2-1 held.
        let s = InMemorySource {
            destinations: vec![
                dest("nas", vec![Class::Critical, Class::Bulky]),
                dest("offsite", vec![Class::Critical]),
            ],
            routes: Vec::new(),
            ages: vec![
                ("immich".into(), "nas".into(), Some(7_200)),
                ("immich".into(), "offsite".into(), Some(21 * 86_400)),
            ],
        };

        let c = coverage_of(&s, "immich", 12 * 3_600).await;
        assert_eq!(c.per_destination.len(), 2);
        assert_eq!(c.up_to_date_copies(), 1, "only one copy really protects");
        assert!(
            c.worst().is_some_and(|e| e.is_alarming()),
            "the summary must show the WORST case, not the best"
        );
    }

    #[tokio::test]
    async fn an_explicit_route_overrides_what_a_destination_accepts() {
        // "Immich's bulky data goes off-site" without sending the others' along.
        let s = InMemorySource {
            destinations: vec![
                dest("nas", vec![Class::Critical, Class::Bulky]),
                dest("offsite", vec![Class::Critical]),
            ],
            routes: vec![("immich".into(), Class::Bulky, vec!["offsite".into()])],
            ages: Vec::new(),
        };

        let v = destinations_for(&s, "immich", Class::Bulky).await;
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].name, "offsite", "the explicit route wins");

        // Another app keeps the default behaviour.
        let v = destinations_for(&s, "gitea", Class::Bulky).await;
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].name, "nas");
    }

    #[tokio::test]
    async fn an_app_never_backed_up_has_zero_copies() {
        // "Configured is not protected": two declared destinations, zero copies.
        let s = InMemorySource {
            destinations: vec![
                dest("nas", vec![Class::Critical]),
                dest("offsite", vec![Class::Critical]),
            ],
            routes: Vec::new(),
            ages: Vec::new(),
        };
        let c = coverage_of(&s, "seafile", 12 * 3_600).await;
        assert_eq!(
            c.per_destination.len(),
            2,
            "the destinations really are declared"
        );
        assert_eq!(c.up_to_date_copies(), 0, "and protect nothing");
    }

    #[tokio::test]
    async fn coverage_order_is_stable() {
        // An order that varied would make displays unstable and snapshot tests
        // useless.
        let s = InMemorySource {
            destinations: vec![
                dest("zzz", vec![Class::Critical]),
                dest("aaa", vec![Class::Critical]),
                dest("mmm", vec![Class::Critical]),
            ],
            routes: Vec::new(),
            ages: Vec::new(),
        };
        let c = coverage_of(&s, "app", 3_600).await;
        let names: Vec<&str> = c.per_destination.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, vec!["aaa", "mmm", "zzz"]);
    }

    #[tokio::test]
    async fn a_fresh_dump_never_makes_a_stale_volume_fresh() {
        // 🔴 Found by review: dumps succeed every pass, volumes went unbacked — and the
        // destination receiving both read "fresh" because ages were read across kinds.
        let s = ByClass {
            destinations: vec![dest("nas", vec![Class::Critical, Class::Bulky])],
            classes: vec![Class::Critical, Class::Bulky],
            ages: vec![
                ("nas".into(), Class::Critical, Some(600)),
                ("nas".into(), Class::Bulky, Some(20 * 86_400)),
            ],
        };
        let c = coverage_of(&s, "gitea", 12 * 3_600).await;
        assert_eq!(
            c.per_destination,
            vec![("nas".to_string(), State::Stale { age_s: 20 * 86_400 })]
        );

        // A class never received there: the destination never protected that data.
        let s = ByClass {
            ages: vec![("nas".into(), Class::Critical, Some(600))],
            ..s
        };
        let c = coverage_of(&s, "gitea", 12 * 3_600).await;
        assert_eq!(c.per_destination, vec![("nas".to_string(), State::Never)]);
    }

    #[tokio::test]
    async fn an_app_with_nothing_to_back_up_is_expected_nowhere() {
        // Valkey keeps nothing: it is not "never backed up" on every destination.
        let s = ByClass {
            destinations: vec![dest("nas", vec![Class::Critical, Class::Bulky])],
            classes: Vec::new(),
            ages: Vec::new(),
        };
        let c = coverage_of(&s, "valkey", 12 * 3_600).await;
        assert!(!c.needs_backup());
        assert!(c.per_destination.is_empty());

        // An app with volumes and only a critical destination is still owed a copy.
        let s = ByClass {
            destinations: vec![dest("offsite", vec![Class::Critical])],
            classes: vec![Class::Bulky],
            ages: Vec::new(),
        };
        let c = coverage_of(&s, "immich", 12 * 3_600).await;
        assert!(c.needs_backup() && c.per_destination.is_empty());
    }

    fn d(name: &str, location: &str, classes: Vec<Class>) -> Destination {
        Destination {
            name: name.into(),
            location: location.into(),
            classes,
            credentials_secret: None,
        }
    }

    #[test]
    fn a_fresh_destination_never_masks_a_stale_one() {
        // 🔴 The module's invariant. With a NAS backed up every 4 h and an off-site
        // failing for three weeks, the old aggregation answered "backed up 2 h ago". You
        // believed 3-2-1 held while only one copy was left, on the same machines.
        let c = Coverage {
            app: "immich".into(),
            per_destination: vec![
                ("nas".into(), State::Fresh { age_s: 7_200 }),
                ("offsite".into(), State::Stale { age_s: 1_814_400 }),
            ],
            classes: vec![Class::Critical, Class::Bulky],
        };

        assert_eq!(c.worst(), Some(&State::Stale { age_s: 1_814_400 }));
        assert_eq!(c.alarming().len(), 1);
        assert_eq!(c.up_to_date_copies(), 1, "only one copy really protects");
    }

    #[test]
    fn never_received_outranks_any_delay() {
        // A destination that has NEVER received anything is worse than one very far
        // behind: it never protected anything, and the cause is different — the routing
        // has probably never been wired up.
        let c = Coverage {
            app: "immich".into(),
            per_destination: vec![
                ("offsite".into(), State::Stale { age_s: 10_000_000 }),
                ("garage".into(), State::Never),
            ],
            classes: vec![Class::Critical, Class::Bulky],
        };
        assert_eq!(c.worst(), Some(&State::Never));
    }

    #[test]
    fn configured_is_not_protected() {
        // 🔴 The number of configured destinations says nothing about the number of
        // copies. Three destinations with two failing is not 3-2-1.
        let c = Coverage {
            app: "immich".into(),
            per_destination: vec![
                ("nas".into(), State::Fresh { age_s: 100 }),
                ("garage".into(), State::Never),
                ("offsite".into(), State::Stale { age_s: 999_999 }),
            ],
            classes: vec![Class::Critical, Class::Bulky],
        };
        assert_eq!(c.per_destination.len(), 3);
        assert_eq!(c.up_to_date_copies(), 1);
    }

    #[test]
    fn an_s3_repository_is_recognised_and_never_mounted() {
        // 🔴 A mounted S3 repository would create an empty directory, and restic would
        // answer "repository does not exist", naming a local path unrelated to the real
        // destination.
        assert!(d("o", "s3:https://s3.example.com/depot", vec![]).is_s3());
        assert!(d("o", "s3:http://garage:3900/backups", vec![]).is_s3());
        assert!(!d("n", "/mnt/nas/restic", vec![]).is_s3());
        assert!(!d("n", "hlb-repo", vec![]).is_s3());
    }

    #[test]
    fn credentials_never_reach_the_command_line() {
        // Through the environment only: a command line is readable by every user of the
        // machine through `ps`.
        let dest = d(
            "offsite",
            "s3:https://s3.example.com/depot",
            vec![Class::Critical],
        );
        let env = dest.env(Some("AKIA123:secret456")).expect("credentials");

        assert_eq!(env.len(), 2);
        assert_eq!(env[0], ("AWS_ACCESS_KEY_ID".into(), "AKIA123".into()));
        assert_eq!(env[1], ("AWS_SECRET_ACCESS_KEY".into(), "secret456".into()));
    }

    #[test]
    fn an_s3_destination_without_credentials_fails_loudly() {
        // 🔴 Without keys, restic would fail on an S3 authorization error that does not
        // say the secret was never stored. Better to refuse here, with the command to
        // type.
        let dest = d(
            "offsite",
            "s3:https://s3.example.com/depot",
            vec![Class::Critical],
        );
        let e = dest.env(None).expect_err("must refuse").to_string();
        assert!(e.contains("no credentials"), "{e}");
        assert!(
            e.contains("hlb backup dest add"),
            "the error must say what to do: {e}"
        );
    }

    #[test]
    fn the_secret_name_is_never_mistaken_for_its_value() {
        // 🔴 `credentials_secret` is the NAME of the secret in the vault, not its value.
        // Passing it through would send "backup-dest-offsite" as the access key, and S3
        // would answer "invalid signature" — an error that points nowhere.
        //
        // A secret name contains no ":", so `env()` refuses it. This test locks that
        // safeguard.
        let dest = Destination {
            name: "offsite".into(),
            location: "s3:https://s3.ext/depot".into(),
            classes: vec![Class::Critical],
            credentials_secret: Some("backup-dest-offsite".into()),
        };

        let e = dest
            .env(Some("backup-dest-offsite"))
            .expect_err("a secret name is not a key:secret pair")
            .to_string();
        assert!(e.contains("access_key:secret_key"), "{e}");
    }

    #[test]
    fn a_local_destination_needs_no_credentials() {
        let dest = d("nas", "/mnt/nas/restic", vec![Class::Bulky]);
        assert!(dest.env(None).expect("no credentials required").is_empty());
    }

    #[test]
    fn a_url_never_shows_its_credentials() {
        // ⚠️ Otherwise `hlb backup dest list` would publish the key in the terminal,
        // then in the shell history, then in a screenshot.
        let dest = d(
            "offsite",
            "s3:https://AKIA123:tressecret@s3.example.com/depot",
            vec![Class::Critical],
        );
        let s = dest.describe();
        assert!(!s.contains("tressecret"), "{s}");
        assert!(!s.contains("AKIA123"), "{s}");
        assert!(
            s.contains("s3.example.com/depot"),
            "the location stays readable: {s}"
        );
    }

    #[test]
    fn a_destination_accepting_nothing_says_so() {
        // It otherwise looks like a configured destination, and you would believe the
        // backups were covered.
        let s = d("garage", "s3:http://garage:3900/b", vec![]).describe();
        assert!(s.contains("NO class"), "{s}");
    }

    #[test]
    fn routing_separates_by_volume_not_by_importance() {
        // The real split of a domestic installation: everything goes to the NAS, the
        // critical class also goes off-site, and the bulky class only goes off-site for
        // the apps you choose — because a domestic connection cannot swallow it.
        let nas = d(
            "nas",
            "/mnt/nas/restic",
            vec![Class::Critical, Class::Bulky],
        );
        let garage = d("garage", "s3:http://garage:3900/b", vec![Class::Critical]);
        let offsite = d(
            "offsite",
            "s3:https://s3.ext/d",
            vec![Class::Critical, Class::Bulky],
        );

        assert!(nas.accepts(Class::Bulky));
        assert!(garage.accepts(Class::Critical));
        assert!(
            !garage.accepts(Class::Bulky),
            "Garage lives on the cluster's disks: putting the photos there would double \
             their footprint"
        );
        assert!(offsite.accepts(Class::Bulky));
    }

    #[test]
    fn class_names_are_read_from_several_spellings() {
        assert_eq!(Class::parse("critical"), Some(Class::Critical));
        assert_eq!(Class::parse("dumps"), Some(Class::Critical));
        assert_eq!(Class::parse("VOLUMES"), Some(Class::Bulky));
        assert_eq!(Class::parse(" bulky "), Some(Class::Bulky));
        assert_eq!(Class::parse("anything at all"), None);
    }

    #[test]
    fn an_s3_repository_is_passed_as_a_url_not_a_mount() {
        // 🔴 Mounting a URL would create an empty directory, and restic would answer
        // "repository does not exist", naming a local path unrelated to the real
        // destination — the diagnosis would go the wrong way.
        let s3 = d("offsite", "s3:https://s3.ext/depot", vec![Class::Critical]);
        let (_, path) = s3.runner(None);
        assert_eq!(path, "s3:https://s3.ext/depot");

        let local = d("nas", "/mnt/nas/restic", vec![Class::Critical]);
        let (_, path) = local.runner(None);
        assert_eq!(
            path, "/repo",
            "a local repository is mounted and seen at /repo"
        );
    }

    #[test]
    fn a_rest_server_is_reached_from_any_node_and_a_path_from_its_own() {
        let rest = d("nas", "rest:http://nas.lan:8000/", vec![Class::Bulky]);
        assert!(
            rest.is_remote() && !rest.is_s3(),
            "no S3 credentials asked for"
        );
        assert_eq!(rest.runner(None).1, "rest:http://nas.lan:8000/");
        assert_eq!(rest.env(None).expect("no credentials needed"), vec![]);
        assert!(d("o", "s3:https://s3.ext/b", vec![]).is_remote());
        assert!(!d("nas", "/srv/restic", vec![]).is_remote());
    }

    #[test]
    fn a_never_backed_up_app_is_alarming_on_every_destination() {
        let c = Coverage {
            app: "brand-new".into(),
            per_destination: vec![
                ("nas".into(), State::Never),
                ("offsite".into(), State::Never),
            ],
            classes: vec![Class::Critical, Class::Bulky],
        };
        assert_eq!(c.up_to_date_copies(), 0);
        assert_eq!(c.alarming().len(), 2);
    }

    #[test]
    fn the_threshold_decides_stale_from_fresh() {
        assert_eq!(State::judge(None, 100), State::Never);
        assert_eq!(State::judge(Some(50), 100), State::Fresh { age_s: 50 });
        assert_eq!(State::judge(Some(100), 100), State::Fresh { age_s: 100 });
        assert_eq!(State::judge(Some(101), 100), State::Stale { age_s: 101 });
    }
}
