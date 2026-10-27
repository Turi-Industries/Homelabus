//! A controller populated with plausible data, without Docker or a cluster (batch 2.6).
//!
//! ## Why this exists
//!
//! The interface has some twenty screens to write. Without a demo mode, every visual
//! iteration demands a real installation: a Swarm, deployed apps, backups several days
//! old, an account whose creation failed. You do not reproduce that to adjust a margin.
//! You do not reproduce that to adjust a margin.
//!
//! And above all: the cases you need to *see* are the ones you never have to hand. An
//! app never backed up, an off-site stale for three weeks, an expired alias still
//! receiving, a node at 96 % disk, a half-created account. They are exactly the ones
//! whose display must be right, and exactly the ones you do not run into while
//! developing.
//!
//! ## 🔴 What this mode must never do
//!
//! Touch a real database. It opens **`State::in_memory()`** and nothing else: the
//! `--state` path is ignored, and saying so at startup avoids the misunderstanding of
//! believing you lost your data.
//!
//! Nor does it write into Docker: no orchestrator is wired in, no reconciliation loop
//! runs.

use std::collections::BTreeMap;

use hlb_agent::disk::DiskUsage;
use hlb_agent::report::NodeReport;
use hlb_state::State;

use crate::agents::AgentStatus;

/// The demonstration's administrator, whom every request of `--demo` acts for.
pub const ADMIN: &str = "lena";

/// A dataset that covers the interesting cases.
///
/// Each entry is there for a precise display state, noted in a comment — without which
/// the set drifts towards "three apps that are fine", that is, towards the only case
/// that does not need checking.
pub async fn seed(state: &State) -> Result<(), Box<dyn std::error::Error>> {
    seed_from(state, None).await
}

/// The same, freezing the catalog's own manifests where it has the app.
///
/// 🔴 The hand-written stubs below differ from the catalog's: compared to it, every
/// application of the demonstration read as "changed by the catalog" — a line no real
/// installation would show, since an install freezes the catalog's manifest.
pub async fn seed_from(
    state: &State,
    catalog: Option<&hlb_catalog::Catalog>,
) -> Result<(), Box<dyn std::error::Error>> {
    let now = crate::auth::now();
    let manifest = |name: &str| match catalog.and_then(|c| c.get(name).ok()) {
        Some(entry) => Ok(entry.manifest.clone()),
        None => manifest(name),
    };

    // --- A muted alert, stored where a real mute is ---------------------------
    for m in mutes(now) {
        state.mute_alert(&m).await?;
    }

    // --- Applications, one per attention state --------------------------------
    for (name, status, domain) in [
        ("gitea", "running", Some("git.home.example")),
        ("vikunja", "running", Some("tasks.home.example")),
        ("immich", "running", Some("photos.home.example")),
        ("vaultwarden", "running", Some("vault.home.example")),
        ("jellyfin", "partial", Some("media.home.example")),
        ("n8n", "failed", Some("flows.home.example")),
        ("seafile", "running", Some("files.home.example")),
        ("postgres", "running", None),
        // 🔴 The generated runbook revealed its absence: gitea declares SSO, so the
        // dependency graph requires "pocket-id". Without it, the restart order could
        // not be computed — a real gap, not a display defect.
        ("pocket-id", "running", Some("id.home.example")),
        // Likewise: Immich declares object storage, so Garage must exist.
        ("garage", "running", None),
        ("valkey", "running", None),
        ("stalwart", "running", Some("mail.home.example")),
    ] {
        state.upsert_app(name, &manifest(name)?, domain).await?;
        state.set_app_status(name, status).await?;
    }
    // What the lab found: Vikunja installed when the catalog ran it twice over a local
    // volume. Its frozen manifest keeps that and the catalog has moved on — the case
    // `hlb upgrade` is for, so that its inbox line and its button are on these screens.
    let mut vikunja = manifest("vikunja")?;
    vikunja.spec.swarm.replicas = 2;
    state
        .upsert_app("vikunja", &vikunja, Some("tasks.home.example"))
        .await?;

    // --- Assertions, as last night's pass read them -----------------------------
    // Gitea's first door found open — the critical line and its red mark —, Seafile
    // never read — the `unknown` one —, the rest holding.
    for (app, _) in state.installed_apps().await? {
        if app == "seafile" {
            continue;
        }
        let m = state.app_manifest(&app).await?;
        let results: Vec<_> = hlb_guide::assertions::declared(&m)
            .into_iter()
            .enumerate()
            .map(|(i, a)| {
                let open = app == "gitea" && i == 0;
                hlb_api::assertions::AssertionResult {
                    id: a.id,
                    holds: a.holds,
                    verdict: if open {
                        hlb_api::assertions::Verdict::Broken
                    } else {
                        hlb_api::assertions::Verdict::Holds
                    },
                    observed: if open {
                        "the page does not say “Registration is disabled”".into()
                    } else {
                        "as the manifest says".into()
                    },
                    checked_at: now - 5 * 3_600,
                    fix: a.fix.filter(|_| open),
                }
            })
            .collect();
        state.record_assertions(&app, &results).await?;
    }

    // --- Mail records: the RSA key never published, the rest in place ------------
    {
        use hlb_api::mail_dns::{MailRecord, Purpose, RecordState};
        let record = |name: &str, purpose, state, observed: &str| MailRecord {
            domain: "home.example".into(),
            name: name.into(),
            purpose,
            expected: format!("{name}. IN TXT \"…\""),
            state,
            observed: observed.into(),
            checked_at: now - 5 * 3_600,
        };
        state
            .record_mail_records(&[
                record(
                    "v1-ed25519-20261019._domainkey.home.example",
                    Purpose::Dkim,
                    RecordState::Published,
                    "v=DKIM1; k=ed25519; h=sha256; p=…",
                ),
                record(
                    "v1-rsa-20261019._domainkey.home.example",
                    Purpose::Dkim,
                    RecordState::Missing,
                    "nothing",
                ),
                record(
                    "home.example",
                    Purpose::Spf,
                    RecordState::Published,
                    "v=spf1 mx -all",
                ),
                record(
                    "home.example",
                    Purpose::Mx,
                    RecordState::Published,
                    "10 mail.home.example.",
                ),
                record(
                    "_dmarc.home.example",
                    Purpose::Dmarc,
                    RecordState::Published,
                    "v=DMARC1; p=quarantine",
                ),
            ])
            .await?;
    }

    // --- Mail queue: one message to Gmail stuck behind a closed port 25 ----------
    state
        .record_mail_queue(&[hlb_api::mail_queue::Waiting {
            message_id: "demo-queued-1".into(),
            recipient: "grand-mere@gmail.com".into(),
            since: now - 3 * 3_600,
            attempts: 7,
            next_retry: now + 1_800,
            expires_at: Some(now - 3 * 3_600 + 3 * 86_400),
            error: Some(
                "gmail-smtp-in.l.google.com: I/O error: Connection timed out (os error 110)".into(),
            ),
            read_at: now - 300,
        }])
        .await?;

    // --- Scheduled jobs: each declared one ran fine two days ago ------------------
    for (app, _) in state.installed_apps().await? {
        let m = state.app_manifest(&app).await?;
        for j in &m.spec.jobs {
            state
                .record_job_run(&hlb_state::JobRun {
                    app: app.clone(),
                    job: j.id.clone(),
                    ran_at: now - 2 * 86_400,
                    succeeded: true,
                    output: String::new(),
                })
                .await?;
        }
    }

    // The volumes, with the two cases that carry a trap: a volume NOT backed up and a
    // SQLite database that cannot be copied hot.
    // And a volume kept for each app whose backup case the screens show, whatever
    // manifest it froze: an app holding nothing is owed no backup, and its case would
    // fall off every screen.
    for (app, name, path, backup, sqlite) in [
        ("gitea", "gitea-data", "/data", true, false),
        ("immich", "immich-cache", "/cache", false, false),
        ("immich", "immich-upload", "/upload", true, false),
        ("vaultwarden", "vaultwarden-data", "/data", true, true),
        ("jellyfin", "jellyfin-config", "/config", true, false),
        ("n8n", "n8n-data", "/data", true, false),
        ("vikunja", "vikunja-files", "/files", true, false),
        ("seafile", "seafile-data", "/shared", true, false),
    ] {
        state.add_volume(app, name, path, backup, sqlite).await?;
    }

    // --- Backups: the four cases that count -----------------------------------
    state
        .upsert_destination("nas", "/mnt/nas/restic", "critical,bulky", None)
        .await?;
    state
        .upsert_destination(
            "offsite",
            "s3:s3.eu-central.example/hlb",
            "critical",
            Some("backup-dest-offsite"),
        )
        .await?;

    // Fresh everywhere: the nominal case.
    for dest in ["nas", "offsite"] {
        backed_up(state, "gitea", dest, "a1b2c3d4").await?;
        backed_up(state, "vaultwarden", dest, "e5f6a7b8").await?;
    }

    // 🔴 The freshness trap: the NAS is running, the off-site is dead. A summary taking the
    // MAX would pass that off as a two-hour-old backup, when only one copy is left, on
    // the same machines.
    backed_up(state, "immich", "nas", "c9d0e1f2").await?;
    for _ in 0..4 {
        state
            .record_backup_to(
                "immich",
                hlb_state::backup_kind::SQL_DUMP,
                "offsite",
                None,
                Some("connection refused"),
            )
            .await?;
    }

    // Backed up and fresh, but partially deployed: that is what produces a `Notice`.
    // ⚠️ Without this line, jellyfin fell back to `Critical` — an app never backed up
    // outweighs its status, and the demonstration set then showed NO intermediate case.
    // The test caught it.
    for dest in ["nas", "offsite"] {
        backed_up(state, "jellyfin", dest, "11aa22bb").await?;
        backed_up(state, "n8n", dest, "33cc44dd").await?;
        // Backed up, but NOT FOR 30 HOURS: the app runs, the dashboard shows a green
        // tick next to the status, and yet nothing goes out any more. That is a third
        // `Critical`, of a different cause from the other two.
        backed_up(state, "vikunja", dest, "55ee66ff").await?;
    }

    // 🔴 The system's worst state: the app runs perfectly and has NO backup. It is the
    // one that looks healthiest on a dashboard.
    // (seafile deliberately has no backup row at all.)

    // 🔴 VARIED ages, not all "just now". A two-hour-old backup and a thirty-hour-old
    // one do not display the same — the second is overdue — and it is exactly
    // that difference in display we want to be able to check.
    for (app, dest, age_s) in [
        ("gitea", "nas", 2 * 3_600),
        ("gitea", "offsite", 9 * 3_600),
        ("vaultwarden", "nas", 40 * 60),
        ("vaultwarden", "offsite", 5 * 3_600),
        // ⚠️ jellyfin keeps a FRESH backup: it is its `partial` status that must produce
        // a `Notice`. Backdating it would tip it into `Critical`, and the demonstration
        // set would no longer have any intermediate case — the test caught it twice.
        // caught it twice.
        ("jellyfin", "nas", 50 * 60),
        ("jellyfin", "offsite", 3 * 3_600),
        // Overdue: more than 24 h, so `Critical` despite an app that runs fine.
        ("vikunja", "nas", 30 * 3_600),
        ("vikunja", "offsite", 31 * 3_600),
        ("n8n", "nas", 3 * 3_600),
        ("n8n", "offsite", 6 * 3_600),
        ("immich", "nas", 7 * 3_600),
    ] {
        state.backdate_backup(app, dest, age_s).await?;
    }

    // 🔴 The exposure REALLY published, as an "hlb ingress --apply" would have recorded
    // it. Three cases at once: compliant, published when it should not be, and a route
    // surviving a removed app.
    state
        .record_ingress(&[
            ("git.home.example".into(), "gitea".into(), true),
            // 🔴 Immich is declared PRIVATE in its manifest and nevertheless answers
            // from the internet. It is the app published by mistake, today invisible.
            ("photos.home.example".into(), "immich".into(), true),
            // And the route of an app that no longer exists: it appears in no manifest,
            // therefore in no walk over the installed apps.
            ("cloud.home.example".into(), "nextcloud".into(), true),
        ])
        .await?;

    // Gitea is the app whose restore was VERIFIED: without it, the demo would never
    // show the only case where a backup can really be trusted.
    state
        .record_verification("gitea", "a1b2c3d4", true, Some("1,284 files read back"))
        .await?;
    // And Immich the one whose verification FAILED: an app can have fresh copies and a
    // read-back that fails, which is the most misleading case.
    state
        .record_verification("immich", "e5f6a7b8", false, Some("3 blocs illisibles"))
        .await?;
    state
        .record_drill("postgres", true, Some(42), 187, "sandbox restore")
        .await?;

    // --- Actions manuelles en attente ----------------------------------------
    state
        .add_guide(
            "n8n",
            "first-admin",
            "Create the administrator account",
            true,
        )
        .await?;
    state
        .add_guide("jellyfin", "libraries", "Declare the libraries", false)
        .await?;

    // --- Secrets: names and purposes, never values ----------------------------
    for (name, usage) in [
        ("gitea-db-password", "PostgreSQL password"),
        ("gitea-oidc-secret", "client OIDC PocketID"),
        ("restic-repo-password", "restic repository encryption"),
        ("backup-dest-offsite", "backup S3 credentials"),
        ("immich-s3-secret", "Immich's Garage key"),
    ] {
        // ⚠️ A fake value, never a credible one: this mode is a demonstration, and a
        // realistic-looking secret would end up copied somewhere.
        state
            .store_secret_if_absent(name, b"(mode demonstration)", usage)
            .await?;
    }

    // --- Roles, and the apps each one enters ------------------------------------
    // The three a new installation starts with, and two of the household's own: the
    // operator who runs things, and a family whose photos have a quota.
    let mut operators = hlb_users::RoleDef::new(
        "operators",
        hlb_types::Role::Operator,
        hlb_users::MailLimits::standard(),
    );
    operators.name = "Operators".into();
    state.put_role(&operators, "lena").await?;
    let mut family = hlb_users::RoleDef::new(
        "family",
        hlb_types::Role::User,
        hlb_users::MailLimits::standard(),
    );
    family.name = "Family".into();
    state.put_role(&family, "lena").await?;
    state
        .set_role_quota("family", "immich", Some(200 << 30))
        .await?;
    state
        .set_role_quota("standard", "immich", Some(50 << 30))
        .await?;
    for (app, roles) in [
        ("gitea", &["admin", "operators", "family"][..]),
        ("vikunja", &["admin", "operators", "family", "standard"]),
        ("immich", &["admin", "family", "standard"]),
        ("vaultwarden", &["admin", "operators", "family", "standard"]),
        // Seafile lets nobody in: the closed case, on the screens.
    ] {
        for role in roles {
            state.allow_role(app, role, "lena").await?;
        }
    }

    // --- Accounts humains ------------------------------------------------------
    state.upsert_user("lena", "admin", Some("pid-lena")).await?;
    state
        .add_mailbox("lena", "lena", "home.example", true)
        .await?;
    // A second mailbox, so "my default mailbox" is a choice on the demonstration.
    state
        .add_mailbox("lena", "contact", "home.example", false)
        .await?;
    state
        .set_user_role("lena", "admin", Some("bootstrap"))
        .await?;
    // Devices signed in, so "my sessions" has something to close. The demonstration
    // authenticates nobody by cookie: these values open nothing.
    for (cookie, ago, agent) in [
        ("demo-laptop", 120, Some("Firefox 131 on Linux")),
        ("demo-phone", 3 * 3_600, Some("Safari on iPhone")),
        ("demo-unknown", 9 * 3_600, None),
    ] {
        state
            .open_session(cookie, "lena", None, now - ago, 12 * 3_600, agent)
            .await?;
    }

    state
        .upsert_user("camille", "standard", Some("pid-camille"))
        .await?;
    state
        .add_mailbox("camille", "camille", "home.example", true)
        .await?;
    state
        .set_user_role("camille", "operators", Some("lena"))
        .await?;

    // 🔴 A HALF-created account: identity in place, no mailbox. The person signs in
    // everywhere and their address receives nothing — it only shows on the first lost
    // email, often a password reset.
    state
        .upsert_user("dominique", "family", Some("pid-dominique"))
        .await?;

    // 🔴 And the reverse: mailbox created, no identity.
    state.upsert_user("sacha", "guest", None).await?;
    state
        .add_mailbox("sacha", "sacha", "home.example", true)
        .await?;

    // --- Aliases: the four states of `alias::State` -----------------------------
    let day = 86_400;
    // Permanent.
    state
        .add_alias(
            "lena",
            "lena",
            "taxes-k3m9x2",
            None,
            Some("taxes"),
            Some("tax office"),
        )
        .await?;
    // Temporary, still valid.
    state
        .add_alias(
            "lena",
            "lena",
            "contest-p7t4nz",
            Some(now + 20 * day),
            Some("contest"),
            Some("prize draw"),
        )
        .await?;
    // 🔴 Expired AND STILL ACTIVE: the purge has not run, the address still receives.
    // It is the only state that betrays the promise made to the user.
    state
        .add_alias(
            "lena",
            "lena",
            "newsletter-w2r8kd",
            Some(now - 3 * day),
            Some("newsletter"),
            Some("the supplier's newsletter"),
        )
        .await?;
    // Expired and removed: the nominal state after a purge.
    state
        .add_alias(
            "lena",
            "lena",
            "trial-b6h1qc",
            Some(now - 30 * day),
            Some("trial"),
            None,
        )
        .await?;
    state.deactivate_alias("lena", "trial-b6h1qc").await?;

    // ⚠️ Three distinct values for the sorting folder: `NULL` (nothing decided, we
    // propose a default), `""` (an explicit choice NOT to sort) and a chosen folder.
    // Confusing them would re-impose a folder on every regeneration.
    state
        .set_alias_folder("lena", "taxes-k3m9x2", Some("Admin/Taxes"))
        .await?;
    state
        .set_alias_folder("lena", "contest-p7t4nz", Some(""))
        .await?;

    state
        .add_alias(
            "camille",
            "camille",
            "amazon-r4j8mv",
            None,
            Some("amazon"),
            Some("amazon.fr"),
        )
        .await?;

    // --- Announcements: the four levels, one of them a FOLLOWED incident -------
    //
    // 🔴 An incident without its thread would not show what makes the system valuable:
    // the chronology you re-read afterwards.
    let incident = state
        .publish_announcement(
            "Photos are slow",
            "Immich has been slow since 9 a.m. We are looking.",
            hlb_api::AnnouncementLevel::Incident,
            true,
            None,
            "lena",
            None,
        )
        .await?;
    state
        .follow_announcement(
            incident,
            "Cause identified: small-01's disk is 96 % full.",
            "lena",
        )
        .await?;
    state
        .follow_announcement(
            incident,
            "Purged under way. The photos already imported are not affected.",
            "camille",
        )
        .await?;

    state
        .publish_announcement(
            "Database maintenance on Tuesday",
            "PostgreSQL restarts Tuesday at 3 a.m. About ten minutes of downtime.",
            hlb_api::AnnouncementLevel::Maintenance,
            false,
            // ⚠️ Reserved for operations: the portal user has nothing to do with it, and
            // flooding them would make them stop reading the announcements.
            Some(hlb_types::Role::Operator),
            "lena",
            None,
        )
        .await?;

    state
        .publish_announcement(
            "New webmail",
            "Bulwark is available at mail.home.example. Roundcube stays reachable.",
            hlb_api::AnnouncementLevel::Info,
            false,
            None,
            "lena",
            None,
        )
        .await?;

    // An EXPIRED announcement: it has left the portal and stays in the history.
    state
        .publish_announcement(
            "Network outage of 12 August",
            "Resolved: cable unplugged in the basement.",
            hlb_api::AnnouncementLevel::Incident,
            false,
            None,
            "lena",
            Some(now - 86_400),
        )
        .await?;

    // --- Audit log ------------------------------------------------------------
    //
    // 🔴 The last field is the AGE in seconds. Without it, every event carries the same
    // minute, and the timeline — whose only point is to bring "the app went down" next
    // to "the update was applied" — shows nothing at all. It is the screen that made
    // the defect visible.
    for (actor, role, action, target, issue, detail, age) in [
        (
            "lena",
            hlb_types::Role::Admin,
            "install",
            "immich",
            "ok",
            None,
            6 * 86_400,
        ),
        // The pair that tells a story: the update, then the failure two
        // minutes plus tard.
        (
            "camille",
            hlb_types::Role::Operator,
            "update",
            "gitea",
            "ok",
            Some("1.23 to 1.24"),
            3_720,
        ),
        (
            "lena",
            hlb_types::Role::Admin,
            "backup-run",
            "immich",
            "failed",
            Some("off-site unreachable"),
            3_600,
        ),
        (
            "camille",
            hlb_types::Role::Operator,
            "purge",
            "vikunja",
            "refused",
            Some("insufficient role"),
            2 * 86_400,
        ),
        (
            "lena",
            hlb_types::Role::Admin,
            "user-role",
            "camille",
            "ok",
            Some("user to operator"),
            26 * 3_600,
        ),
        (
            "bitwarden",
            hlb_types::Role::Operator,
            "alias-create",
            "lena",
            "ok",
            None,
            900,
        ),
    ] {
        state
            .audit(actor, role, action, target, issue, detail)
            .await?;
        // The id of the row we have just written: the most recent one.
        if let Some(last) = state.audit_trail(1).await?.first() {
            state.backdate_audit(last.id, age).await?;
        }
    }

    Ok(())
}

/// How much the demonstration holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum Scale {
    /// Every case once: a dozen applications, four accounts, four machines.
    #[default]
    Household,
    /// The household, plus what a list has to survive. Four accounts cannot show what
    /// a thousand cost — a screen of cards reads fine at four and is unusable at 1,000.
    Large,
}

/// What [`Scale::Large`] adds. Not more applications: an installation runs what the
/// catalogue holds, and it holds 22 manifests.
pub const LARGE_ACCOUNTS: usize = 1_000;
pub const LARGE_INVITATIONS: usize = 300;
pub const LARGE_AUDIT: usize = 5_000;
pub const LARGE_MACHINES: usize = 8;

/// The demonstration at a scale.
pub async fn seed_at(
    state: &State,
    scale: Scale,
    catalog: Option<&hlb_catalog::Catalog>,
) -> Result<(), Box<dyn std::error::Error>> {
    seed_from(state, catalog).await?;
    if scale == Scale::Large {
        grow(state).await?;
    }
    Ok(())
}

/// The machines at a scale.
pub fn nodes_at(now: u64, scale: Scale) -> BTreeMap<String, AgentStatus> {
    let mut m = nodes(now);
    if scale == Scale::Large {
        for i in 0..LARGE_MACHINES {
            // Spread over the range rather than all alike: a list of identical gauges
            // hides whether the eye can find the one that is filling up.
            let used = 20 + (i as u64 * 37) % 75;
            m.insert(
                format!("10.0.1.{}:8421", i + 1),
                AgentStatus::Reporting(Box::new(NodeReport {
                    hostname: format!("rack-{:02}", i + 1),
                    at: now,
                    disks: vec![disk("/", 400_000, 400_000 * used / 100)],
                    memory_total_mb: Some(8_192),
                    memory_available_mb: Some(8_192 * (100 - used) / 100),
                    agent_version: "0.2.0".into(),
                    protocol: 2,
                    cpu_cores: Some(4),
                    cpu_busy: Some(used as f64 / 100.0),
                    ..Default::default()
                })),
            );
        }
    }
    m
}

/// A thousand people, named the way people are — never `user-0042`, which would hide
/// how a list of real names sorts, wraps and searches.
fn people() -> impl Iterator<Item = String> {
    const FIRST: [&str; 40] = [
        "alex",
        "andrea",
        "ariel",
        "camille",
        "charlie",
        "claude",
        "dominique",
        "eden",
        "elie",
        "gael",
        "jo",
        "jules",
        "kim",
        "lou",
        "maxime",
        "morgan",
        "noa",
        "pascal",
        "sacha",
        "sam",
        "yann",
        "alix",
        "ange",
        "celian",
        "emery",
        "lior",
        "marion",
        "nour",
        "robin",
        "swann",
        "tal",
        "yael",
        "ilan",
        "mael",
        "noe",
        "sasha",
        "teo",
        "val",
        "zoe",
        "leo",
    ];
    const LAST: [&str; 25] = [
        "martin", "bernard", "dubois", "thomas", "robert", "richard", "lambert", "durand", "leroy",
        "moreau", "simon", "laurent", "lefebvre", "michel", "garcia", "david", "bertrand", "roux",
        "vincent", "fournier", "morel", "girard", "andre", "mercier", "blanc",
    ];
    LAST.iter()
        .flat_map(|last| FIRST.iter().map(move |first| format!("{first}.{last}")))
}

/// What [`Scale::Large`] adds to the household.
async fn grow(state: &State) -> Result<(), Box<dyn std::error::Error>> {
    let now = crate::auth::now();

    // The household's broken cases, at the rate a thousand people would produce them:
    // a list that is all healthy never shows whether the broken few can be found.
    for (i, name) in people().take(LARGE_ACCOUNTS).enumerate() {
        let identity = (i % 53 != 7).then(|| format!("pid-{name}"));
        let role = match i % 50 {
            0 => "operators",
            _ if i % 9 == 0 => "guest",
            _ if i % 3 == 0 => "family",
            _ => "standard",
        };
        state.upsert_user(&name, role, identity.as_deref()).await?;
        if i % 37 != 5 {
            state
                .add_mailbox(&name, &name, "home.example", true)
                .await?;
        }
        state.set_user_role(&name, role, Some("lena")).await?;
    }

    for i in 0..LARGE_INVITATIONS {
        let age = i as i64 * 3_600;
        state
            .create_invitation(
                &format!("demonstration-invitation-{i}"),
                "lena",
                "standard",
                now - age,
                7 * 86_400,
                // A few widely open links among the single-use ones: those are the
                // ones a long list must not bury.
                if i % 25 == 0 { 5 } else { 1 },
                None,
            )
            .await?;
    }

    let names: Vec<String> = people().take(LARGE_ACCOUNTS).collect();
    for i in 0..LARGE_AUDIT {
        let person = names[(i * 7) % names.len()].as_str();
        let app = [
            "gitea",
            "immich",
            "vaultwarden",
            "jellyfin",
            "n8n",
            "vikunja",
        ][i % 6];
        // The verbs the controller really writes: a demonstration that invents its own
        // teaches a convention nothing else follows.
        use hlb_types::Role::{Admin, User};
        let (actor, role, action, target, outcome) = match i % 5 {
            0 => ("lena", Admin, "alias-disable", person, "ok"),
            1 => ("lena", Admin, "user-role", person, "ok"),
            2 => (
                "lena",
                Admin,
                "backup-run",
                app,
                if i % 45 == 2 { "failed" } else { "ok" },
            ),
            3 => ("lena", Admin, "alias-purge", person, "ok"),
            _ => (person, User, "signin", person, "ok"),
        };
        state
            .audit(actor, role, action, target, outcome, None)
            .await?;
        if let Some(last) = state.audit_trail(1).await?.first() {
            // Ten minutes apart: five thousand entries cover a month, as they would.
            state
                .backdate_audit(last.id, ((LARGE_AUDIT - i) * 600) as i64)
                .await?;
        }
    }
    Ok(())
}

/// The topology, as a real cluster would return it.
///
/// 🔴 Built with **the anti-affinity trap inside**: two VMs on the same hardware, and a
/// service whose two replicas are both on it. Without that case, the screen that
/// justifies the interface's existence would have nothing to show — and we would not
/// know whether it shows it well.
pub fn topology() -> hlb_api::Topology {
    let node = |id: &str, host: &str, tier: &str, reachable: bool, services: &[&str]| {
        hlb_api::NodeInDomain {
            id: id.into(),
            hostname: host.into(),
            tier: Some(tier.into()),
            reachable,
            services: services.iter().map(|s| s.to_string()).collect(),
        }
    };

    hlb_api::Topology {
        total_nodes: 4,
        // Two managers on the SAME hardware: losing "big-01" takes the quorum on top of
        // the apps. That is the case the simulator must make legible.
        managers: vec!["n-heavy".into(), "n-mail".into(), "n-small1".into()],
        domains: vec![
            // 🔴 THE case: two Swarm nodes, a single physical server. The command line
            // shows two and lets you believe in redundancy.
            hlb_api::DomainSummary {
                name: Some("big-01 (one machine)".into()),
                concentrated: true,
                nodes: vec![
                    node(
                        "n-heavy",
                        "swarm-heavy",
                        "heavy",
                        true,
                        &["postgres", "valkey", "gitea", "immich"],
                    ),
                    node("n-mail", "mail-vm", "light", true, &["stalwart", "gitea"]),
                ],
            },
            hlb_api::DomainSummary {
                name: Some("small-01".into()),
                concentrated: false,
                nodes: vec![node("n-small1", "small-01", "light", true, &["vikunja"])],
            },
            // A node with no declared domain: we do NOT KNOW whether it shares hardware.
            hlb_api::DomainSummary {
                name: None,
                concentrated: false,
                nodes: vec![node("n-small2", "small-02", "light", false, &[])],
            },
        ],
        violations: vec![hlb_api::ViolationSummary {
            service: "gitea".into(),
            domain: Some("big-01 (one machine)".into()),
            replicas: 2,
            total: 2,
            total_violation: true,
            explanation: "gitea: its 2 replicas are ALL on domain \
                              \"big-01 (single machine)\" — the redundancy is an illusion"
                .into(),
        }],
    }
}

/// The demo's mutes, stored by `seed` in the table a real mute lives in.
pub fn mutes(now: i64) -> Vec<hlb_api::AlertMute> {
    vec![hlb_api::AlertMute {
        rule: "disk-full".into(),
        until: now + 4 * 3_600,
        by: "lena".into(),
        reason: "purge of small-01 under way".into(),
    }]
}

/// The active alerts, as the loop would produce them.
///
/// 🔴 Fabricated, because the demonstration mode has no VictoriaMetrics: without them
/// the alerts screen would be empty and could not be written. And it is precisely the
/// screen whose display must be right — a badly rendered alert is an alert you will not
/// see on the day.
///
/// The set covers the four cases that display differently: critical, important,
/// **non-evaluable** (collection is down, that is not "all is well"), and a **muted**
/// alert that must stay visible.
pub fn alerts(_now: i64) -> Vec<hlb_api::ActiveAlert> {
    vec![
        hlb_api::ActiveAlert {
            rule: "backup-absent".into(),
            level: hlb_api::AlertLevel::Critical,
            explanation: "applications have NEVER been backed up".into(),
            value: Some(4.0),
            threshold: 0.0,
            // Three days: an alert that lasts has been ignored, or its remedy does not
            // work. That is not handled like an alert that has just appeared.
            since_s: 3 * 86_400,
            muted_until: None,
            muted_by: None,
            mute_reason: None,
        },
        hlb_api::ActiveAlert {
            rule: "single-copy".into(),
            level: hlb_api::AlertLevel::Critical,
            explanation: "an application has only ONE up-to-date copy left".into(),
            value: Some(1.0),
            threshold: 2.0,
            since_s: 9 * 3_600,
            muted_until: None,
            muted_by: None,
            mute_reason: None,
        },
        hlb_api::ActiveAlert {
            rule: "disk-full".into(),
            level: hlb_api::AlertLevel::Important,
            explanation: "a filesystem is above 85 % usage".into(),
            value: Some(0.96),
            threshold: 0.85,
            since_s: 2 * 3_600,
            // 🔴 Muted — by `seed`, in the table, the way a person would — and it must
            // STAY visible: making it vanish would give a green dashboard for a known,
            // unresolved problem.
            muted_until: None,
            muted_by: None,
            mute_reason: None,
        },
        hlb_api::ActiveAlert {
            rule: "verification-stale".into(),
            level: hlb_api::AlertLevel::Unknown,
            explanation: "the rule can no longer be evaluated: no more data".into(),
            // 🔴 No value: we do not know. Putting 0 would say "threshold respected".
            value: None,
            threshold: 31.0,
            since_s: 40 * 60,
            muted_until: None,
            muted_by: None,
            mute_reason: None,
        },
    ]
}

/// The nodes as an agent would report them.
///
/// Separate from the state because these reports do not live in the database: they are
/// in memory, in `LastPoll`, and the loop → API sharing is what we want to exercise.
pub fn nodes(now: u64) -> BTreeMap<String, AgentStatus> {
    let mut m = BTreeMap::new();

    m.insert(
        "10.0.0.1:8421".to_string(),
        AgentStatus::Reporting(Box::new(NodeReport {
            hostname: "swarm-heavy".into(),
            at: now,
            disks: vec![
                disk("/", 500_000, 210_000),
                disk("/var/lib/docker", 200_000, 96_000),
            ],
            memory_total_mb: Some(16_384),
            memory_available_mb: Some(4_900),
            agent_version: "0.2.0".into(),
            protocol: 2,
            cpu_cores: Some(8),
            load: Some(hlb_agent::system::LoadAverage {
                one_min: 3.2,
                five_min: 2.8,
                fifteen_min: 2.4,
            }),
            cpu_busy: Some(0.41),
            swap_total_mb: Some(4_096),
            swap_used_mb: Some(120),
            interfaces: vec![hlb_agent::system::Interface {
                name: "eth0".into(),
                rx_bytes: 91_284_733_912,
                tx_bytes: 42_119_884_004,
            }],
            system: Some(hlb_agent::system::System {
                kernel: Some("6.1.0-18-amd64".into()),
                distro: Some("Debian GNU/Linux 12 (bookworm)".into()),
                uptime_s: Some(41 * 86_400),
            }),
            reboot_required: Some(false),
        })),
    );

    // 🔴 A node under pressure: /var/lib/docker at 96 %. A half-empty `/` is no
    // consolation — the WORST filesystem decides.
    m.insert(
        "10.0.0.2:8421".to_string(),
        AgentStatus::Reporting(Box::new(NodeReport {
            hostname: "small-01".into(),
            at: now,
            disks: vec![
                disk("/", 100_000, 30_000),
                disk("/var/lib/docker", 50_000, 48_000),
            ],
            memory_total_mb: Some(4_096),
            memory_available_mb: Some(890),
            agent_version: "0.2.0".into(),
            protocol: 2,
            cpu_cores: Some(4),
            // 🔴 Load per core above 1: the machine is overloaded.
            load: Some(hlb_agent::system::LoadAverage {
                one_min: 6.1,
                five_min: 5.4,
                fifteen_min: 4.9,
            }),
            cpu_busy: Some(0.93),
            swap_total_mb: Some(2_048),
            // 🔴 The swap IS being used: an early signal, the machine slows without
            // having fallen over yet. That is the case you need to see on screen.
            swap_used_mb: Some(1_450),
            interfaces: vec![hlb_agent::system::Interface {
                name: "eth0".into(),
                rx_bytes: 12_884_901_888,
                tx_bytes: 3_221_225_472,
            }],
            system: Some(hlb_agent::system::System {
                kernel: Some("6.1.0-18-arm64".into()),
                distro: Some("Debian GNU/Linux 12 (bookworm)".into()),
                // Rebooted twenty minutes ago: that often explains a lot, and nobody
                // thinks of it.
                uptime_s: Some(1_200),
            }),
            // A kernel waiting for its reboot: the demonstration shows the cause.
            reboot_required: Some(true),
        })),
    );

    // 🔴 An unreachable node. Distinct from a healthy node: its data is no longer
    // backed up, and showing it as "no problem reported" would be the lie this whole
    // project seeks to avoid.
    m.insert(
        "10.0.0.3:8421".to_string(),
        AgentStatus::Unreachable {
            detail: "connection refused (agent stopped?)".into(),
        },
    );

    // An agent MUTE for a long time: it answered once, not since. So the report exists,
    // but it is old — and it is up to the interface not to pass it off
    // as fresh.
    m.insert(
        "10.0.0.4:8421".to_string(),
        AgentStatus::Reporting(Box::new(NodeReport {
            hostname: "small-02".into(),
            at: now.saturating_sub(3_600),
            disks: vec![disk("/", 100_000, 19_000)],
            memory_total_mb: Some(4_096),
            memory_available_mb: Some(2_600),
            // ⚠️ Left on protocol 1: a mismatched fleet. Its system measurements
            // are absent — and must display as "unknown", not "0 %".
            agent_version: "0.1.0".into(),
            protocol: 1,
            ..Default::default()
        })),
    );

    m
}

fn disk(path: &str, total_mb: u64, used_mb: u64) -> DiskUsage {
    DiskUsage {
        path: path.into(),
        total_mb,
        used_mb,
        free_mb: total_mb - used_mb,
    }
}

/// A demonstration manifest, as RICH as the catalog's.
///
/// 🔴 A minimal manifest would give an empty detail screen: no capabilities, no volumes,
/// no variables. So we would never write the display of those sections — and they are
/// precisely the ones that carry the traps (a volume not backed up, a SQLite database
/// that cannot be copied hot, a secret token that must stay literal).
///
/// ⚠️ Returns a `Result` rather than unwrapping: `expect` is forbidden in production in
/// this repository, and this module is part of it — it is compiled into the binary.
fn manifest(name: &str) -> Result<hlb_types::Manifest, Box<dyn std::error::Error>> {
    let y = match name {
        "gitea" => r#"
apiVersion: hlb/v1
kind: App
metadata: { name: gitea, displayName: Gitea, category: development }
spec:
  image: { repo: gitea/gitea, tag: "1.24" }
  requires:
    - kind: database
      engine: postgres
    - kind: sso
      mode: native
      redirectPaths: ["/user/oauth2/PocketID/callback"]
    - kind: storage
      name: data
      path: /data
      backup: true
  env:
    GITEA__database__DB_TYPE: postgres
    GITEA__database__HOST: "{{ db.host }}:{{ db.port }}"
    GITEA__database__NAME: "{{ db.name }}"
    GITEA__database__USER: "{{ db.user }}"
    GITEA__database__PASSWD: "{{ db.password }}"
    GITEA__server__ROOT_URL: "https://{{ domain }}/"
  ingress:
    - host: "{{ domain }}"
      port: 3000
      expose: after-guide
"#
        .to_string(),
        "immich" => r#"
apiVersion: hlb/v1
kind: App
metadata: { name: immich, displayName: Immich, category: media }
spec:
  image: { repo: ghcr.io/immich-app/immich-server, tag: "v1.119" }
  requires:
    - kind: database
      engine: postgres
      extensions: ["vector", "vchord"]
    - kind: object-storage
      bucket: immich
      backup: false
    - kind: storage
      name: cache
      path: /cache
      backup: false
  env:
    DB_HOSTNAME: "{{ db.host }}"
    DB_PASSWORD: "{{ db.password }}"
    S3_ACCESS_KEY: "{{ s3.access_key }}"
  ingress:
    - host: "{{ domain }}"
      port: 2283
      expose: private
"#
        .to_string(),
        "vaultwarden" => r#"
apiVersion: hlb/v1
kind: App
metadata: { name: vaultwarden, displayName: Vaultwarden, category: security }
spec:
  image: { repo: vaultwarden/server, tag: "1.32" }
  requires:
    - kind: storage
      name: data
      path: /data
      backup: true
      sqlite: true
    - kind: smtp
  env:
    DOMAIN: "https://{{ domain }}"
    SMTP_PASSWORD: "{{ smtp.password }}"
"#
        .to_string(),
        other => format!(
            "apiVersion: hlb/v1\nkind: App\nmetadata: {{ name: {other} }}\n\
             spec:\n  image: {{ repo: exemple/{other}, tag: \"1.0\" }}\n"
        ),
    };
    Ok(serde_yaml_ng::from_str(&y)?)
}

/// Records a success of every kind `app` holds on `dest`, as a pass would.
///
/// ⚠️ An app's age is the OLDEST of its kinds: one kind left unrecorded would make the
/// app "never backed up" whatever the others say.
async fn backed_up(
    state: &State,
    app: &str,
    dest: &str,
    snapshot: &str,
) -> Result<(), hlb_state::Error> {
    for kind in state.backup_kinds(app).await? {
        state
            .record_backup_to(app, kind, dest, Some(snapshot), None)
            .await?;
    }
    Ok(())
}

/// The fleet reduced to tier and available memory, for the capacity budget.
///
/// 🔴 Consistent with `nodes()` and `topology()`: `small-01` is the protected 4 GB
/// machine, of which almost nothing is left. It is the one that must trigger the
/// warning, and not an absence of information.
pub fn fleet_per_tier() -> Vec<(Option<String>, Option<u64>)> {
    vec![
        (Some("heavy".into()), Some(11_800)),
        (Some("light".into()), Some(890)),
        // The mute node: the budget becomes a lower bound, and says so.
        (Some("light".into()), None),
    ]
}

/// An app's Swarm tasks, fabricated for the demonstration.
///
/// 🔴 They carry the cases you never have to hand at the right moment: the failure
/// Swarm gives a reason for, the failure it does not explain, and the service running
/// half-way. That is what makes the causal chain visible without a cluster.
pub fn tasks(app: &str) -> Vec<hlb_api::TaskSummary> {
    let t = |id: &str, node: &str, alive: bool, err: Option<&str>| hlb_api::TaskSummary {
        id: id.into(),
        service: app.into(),
        slot: Some(1),
        node: Some(node.into()),
        state: if alive {
            "running".into()
        } else {
            "failed".into()
        },
        desired_state: "running".into(),
        alive,
        failed: !alive,
        explanation: err.map(str::to_string),
        image: None,
    };

    match app {
        // The full chain: Swarm says why, the node is short of space, the rule flagged
        // it.
        "n8n" => vec![t(
            "tk-n8n-1",
            // ⚠️ The node UNDER PRESSURE: that is what closes the chain. Placing the
            // task on a healthy machine would give "unknown cause", which is the second
            // case — carried by seafile just below.
            "small-01",
            false,
            Some("no space left on device"),
        )],
        // 🔴 The failure nothing explains. It is the case the diagnosis must refuse to
        // invent: it stops at "unknown cause" rather than accuse the first node that
        // comes along.
        "seafile" => vec![t("tk-seafile-1", "swarm-heavy", false, Some("exit code 1"))],
        "immich" => vec![t("tk-immich-1", "swarm-heavy", true, None)],
        "gitea" => vec![
            t("tk-gitea-1", "swarm-heavy", true, None),
            t("tk-gitea-2", "mail-vm", true, None),
        ],
        _ => Vec::new(),
    }
}

/// Every demo app's tasks placed on `node` (a hostname, as `tasks`'s own fixtures use
/// — "small-01", "swarm-heavy", "mail-vm") — the SAME fabricated placements `tasks`
/// already returns, filtered by node instead of by app. Used by the per-node detail
/// endpoint's own demo branch, the same "no orchestrator, fabricate" precedent as
/// `tasks` itself.
pub fn node_tasks(node: &str) -> Vec<hlb_api::TaskSummary> {
    ["n8n", "seafile", "immich", "gitea"]
        .into_iter()
        .flat_map(tasks)
        .filter(|t| t.node.as_deref() == Some(node))
        .collect()
}

/// The Swarm side of a demo node, found by hostname in [`topology`].
///
/// 🔴 It reads `topology()` rather than carrying a second list: the demonstration's
/// cluster is described once, and a node that gains a failure domain there must not
/// keep an old identifier here.
///
/// ⚠️ `small-01` is reported as **drained** on purpose. Every other demo node is
/// active, so both halves of the availability control — "drain this node" and "put it
/// back into service" — are visible in the one mode this project recommends for
/// looking at the interface. A demonstration where every node is in the same state
/// shows one of the two buttons and hides the other.
pub fn swarm_node(hostname: Option<&str>) -> Option<hlb_api::SwarmNode> {
    let hostname = hostname?;
    topology()
        .domains
        .iter()
        .flat_map(|d| &d.nodes)
        .find(|n| n.hostname == hostname)
        .map(|n| hlb_api::SwarmNode {
            id: n.id.clone(),
            availability: if n.hostname == "small-01" {
                "drain".into()
            } else {
                "active".into()
            },
        })
}

/// The reconciliation gaps, fabricated for the demonstration.
///
/// 🔴 Without an orchestrator the loop does not run — and the screen that makes the
/// non-actions legible would be empty, therefore impossible to write. Both families are
/// there: what will be corrected, and what was deliberately left alone.
pub fn drifts() -> Vec<hlb_api::DriftSummary> {
    use hlb_engine::reconcile::Drift;

    // ⚠️ We go through the REAL `Drift` values rather than write the sentences by hand:
    // a demonstration that invents its own text ends up showing a screen the code never
    // produces.
    [
        Drift::ReplicasDiverged {
            app: "vikunja".into(),
            desired: 2,
            actual: 1,
        },
        Drift::OrphanService {
            name: "old-nextcloud".into(),
        },
        Drift::Converging {
            app: "immich".into(),
            running: 1,
            desired: 2,
        },
    ]
    .iter()
    .map(|d| hlb_api::DriftSummary {
        target: d.app().to_string(),
        description: d.to_string(),
        corrigible: d.is_correctable(),
        refusal: d.refusal().map(str::to_string),
    })
    .collect()
}

/// A day of measurements for the demonstration's machines, every five minutes, ending on
/// what each reports now: the curves the home draws, which an installation fills by
/// itself one minute at a time.
///
/// Deterministic, like the rest of the demonstration: busier in the evening, a disk that
/// fills faster when it is already nearly full, the network quiet at night, and an
/// application that stopped running three hours ago.
pub fn history(
    nodes: &BTreeMap<String, AgentStatus>,
    apps_running: usize,
    now: i64,
) -> Vec<hlb_state::Sample> {
    use hlb_api::Metric;
    const STEP: i64 = 300;
    let end = now - now.rem_euclid(60);
    let times: Vec<i64> = (0..=86_400 / STEP).rev().map(|k| end - k * STEP).collect();
    // The time of day, as a wave: -1 at four in the morning, 1 at four in the afternoon.
    let day = |t: i64| {
        ((t.rem_euclid(86_400) as f64 / 86_400.0 - 4.0 / 24.0) * std::f64::consts::TAU
            - std::f64::consts::FRAC_PI_2)
            .sin()
    };
    // Reproducible noise in [-1, 1], one value per subject, metric and moment.
    let noise = |seed: &str, t: i64| {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for b in seed.bytes().chain(t.to_le_bytes()) {
            h = (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3);
        }
        (h % 2_001) as f64 / 1_000.0 - 1.0
    };
    let mut out = Vec::new();
    let mut curve = |metric: String, subject: &str, values: &mut dyn FnMut(i64) -> f64| {
        for &t in &times {
            out.push(hlb_state::Sample {
                at: t,
                subject: subject.to_string(),
                metric: metric.clone(),
                value: values(t),
            });
        }
    };

    for (address, status) in nodes {
        let Some(r) = status.report() else { continue };
        let now_wave = day(end);
        // Each curve ends on today's value, wherever the wave is now.
        let around = |current: f64, swing: f64, jitter: f64, key: &str| {
            let key = format!("{address}{key}");
            move |t: i64| {
                let shift = if t == end {
                    0.0
                } else {
                    swing * (day(t) - now_wave) + jitter * noise(&key, t)
                };
                (current + shift).clamp(0.0, 1.0)
            }
        };
        if let Some(c) = r.cpu_busy {
            curve(
                Metric::Cpu.key().into(),
                address,
                &mut around(c, 0.25, 0.08, "cpu"),
            );
        }
        if let Some(m) = r.memory_used() {
            curve(
                Metric::Memory.key().into(),
                address,
                &mut around(m, 0.06, 0.02, "memory"),
            );
        }
        if let (Some(t), Some(u)) = (r.swap_total_mb, r.swap_used_mb) {
            if t > 0 {
                curve(
                    Metric::Swap.key().into(),
                    address,
                    &mut around(u as f64 / t as f64, 0.03, 0.01, "swap"),
                );
            }
        }
        if let Some(l) = r.load_per_core() {
            let key = format!("{address}load");
            curve(Metric::Load.key().into(), address, &mut |t| {
                if t == end {
                    l
                } else {
                    (l * (1.0 + 0.4 * (day(t) - now_wave)) + 0.1 * noise(&key, t)).max(0.0)
                }
            });
        }
        for d in &r.disks {
            let used = d.used_percent() / 100.0;
            // A nearly full disk got there quickly: it fills four times as fast.
            let per_day = if used > 0.9 { 0.08 } else { 0.02 };
            curve(
                format!("{}{}", Metric::Disk.key(), d.path),
                address,
                &mut |t| (used - per_day * (end - t) as f64 / 86_400.0).max(0.0),
            );
        }
        if !r.interfaces.is_empty() {
            for (metric, total, base) in [
                (
                    Metric::NetIn,
                    r.interfaces.iter().map(|i| i.rx_bytes as f64).sum::<f64>(),
                    400_000.0,
                ),
                (
                    Metric::NetOut,
                    r.interfaces.iter().map(|i| i.tx_bytes as f64).sum::<f64>(),
                    120_000.0,
                ),
            ] {
                // Walked back from today's counter: what each five minutes carried.
                let key = format!("{address}{}", metric.key());
                let mut counter = total;
                let mut by_time = BTreeMap::new();
                for &t in times.iter().rev() {
                    by_time.insert(t, counter);
                    let rate = base * (1.2 + day(t)) * (1.0 + 0.3 * noise(&key, t));
                    counter = (counter - rate * STEP as f64).max(0.0);
                }
                curve(metric.key().into(), address, &mut |t| by_time[&t]);
            }
        }
    }

    let running = apps_running as f64;
    curve(Metric::AppsRunning.key().into(), "", &mut |t| {
        let ago = end - t;
        if (14 * 3_600..14 * 3_600 + 1_200).contains(&ago) {
            running // a restart: one application down for twenty minutes
        } else if ago > 3 * 3_600 {
            running + 1.0
        } else {
            running
        }
    });
    out
}
#[cfg(test)]
mod tests {
    use super::*;
    use hlb_api::Attention;

    /// Every alert the demo shows names a rule that `hlb-metrics` really emits.
    ///
    /// 🔴 It showed `disk-plein` while the rule was `disque-plein`: a French-to-English
    /// pass rewrote the demo's copy of the name and not the rule's — a rule name is a
    /// string, and a rename is compiler-verified only for identifiers. The one that
    /// drifted was the muted alert, whose whole reason for being in this set is that
    /// muting must not hide it.
    ///
    /// Derived from `alerts()` itself rather than from a second list of names — the two
    /// lists is the shape that let this one drift.
    #[test]
    fn every_rule_the_diagnostic_waits_for_exists() {
        // `hlb-api` cannot depend on `hlb-metrics`, so the two names its diagnostic
        // looks for are strings; this crate sees both sides.
        let known: Vec<&str> = hlb_metrics::rules::default_rules()
            .iter()
            .map(|r| r.name)
            .collect();
        for name in [
            hlb_api::diagnostic::NODE_RULE,
            hlb_api::diagnostic::DISK_RULE,
        ] {
            assert!(known.contains(&name), "no rule named \"{name}\": {known:?}");
        }
    }

    /// The demo's alerts as `/api/alerts` serves them: with the stored mutes applied.
    fn muted_alerts(now: i64) -> Vec<hlb_api::ActiveAlert> {
        let mutes = mutes(now);
        let mut a = alerts(now);
        a.iter_mut().for_each(|x| x.apply_mutes(&mutes));
        a
    }

    #[test]
    fn every_demo_mute_names_an_alert_the_demo_shows() {
        // A mute on a name nothing shows silences nothing, and the muted case — the one
        // in the set to prove muting does not hide an alert — would never render.
        let shown: Vec<String> = alerts(0).into_iter().map(|a| a.rule).collect();
        for m in mutes(0) {
            assert!(
                shown.contains(&m.rule),
                "the demo mutes `{}`, which it does not show",
                m.rule
            );
        }
    }

    #[test]
    fn every_demo_alert_names_a_rule_that_exists() {
        let known: std::collections::BTreeSet<&str> = hlb_metrics::rules::default_rules()
            .iter()
            .map(|r| r.name)
            .collect();

        let shown = alerts(0);
        // The floor under the derivation: a set built from an empty vector passes every
        // assertion below it.
        assert!(
            shown.len() >= 4,
            "only {} demo alerts — that reads as a set which stopped being built, \
             not one that shrank",
            shown.len()
        );
        for a in &shown {
            assert!(
                known.contains(a.rule.as_str()),
                "the demo shows `{}`, which no rule in hlb-metrics emits — known: {known:?}",
                a.rule
            );
        }
    }

    #[tokio::test]
    async fn the_demo_manifests_are_rich_enough_to_render_a_detail_screen() {
        // 🔴 A minimal manifest would give an EMPTY detail screen: no capabilities, no
        // variables. So we would never write the display of those sections — and they
        // are the ones that carry the traps.
        let s = State::in_memory().await.expect("state");
        seed(&s).await.expect("seeding");

        let m = s.app_manifest("gitea").await.expect("manifest");
        assert!(!m.spec.requires.is_empty(), "no capability to display");
        assert!(!m.spec.env.is_empty(), "no variable to display");

        // And the secret tokens are there, LITERAL: that is what the screen must show
        // without ever resolving them.
        assert!(
            m.spec.env.values().any(|v| v.contains("{{ db.password }}")),
            "no secret token: the literal display would not be exercised"
        );
    }

    #[tokio::test]
    async fn the_large_demo_holds_a_thousand_people_and_their_broken_few() {
        let s = State::in_memory().await.expect("state");
        seed_at(&s, Scale::Large, None).await.expect("seeding");

        let people = s.users_with_roles().await.expect("users");
        assert_eq!(people.len(), 4 + LARGE_ACCOUNTS);
        // The point of a thousand: whether the half-created few can be FOUND among them.
        let mut broken = 0;
        for h in &people {
            let account = s.account(&h.user).await.expect("account");
            if account.coherence() != hlb_users::Coherence::Complete {
                broken += 1;
            }
        }
        assert!((20..100).contains(&broken), "{broken} broken accounts");

        assert_eq!(
            nodes_at(0, Scale::Large).len(),
            nodes(0).len() + LARGE_MACHINES
        );
    }

    #[tokio::test]
    async fn the_demo_has_an_unbacked_volume_and_a_sqlite_one() {
        // The two cases that carry a trap: a volume you believe protected and that is
        // not, and a SQLite database that cannot be copied hot.
        let s = State::in_memory().await.expect("state");
        seed(&s).await.expect("seeding");

        let immich = s.app_volumes("immich").await.expect("volumes");
        assert!(
            immich.iter().any(|(_, _, backup, _)| !backup),
            "no unbacked-up volume"
        );

        let vw = s.app_volumes("vaultwarden").await.expect("volumes");
        assert!(
            vw.iter().any(|(_, _, _, sqlite)| *sqlite),
            "no SQLite volume"
        );
    }

    #[tokio::test]
    async fn the_demo_covers_every_attention_level() {
        // 🔴 A dataset showing only healthy apps is of no use: the screens that need
        // checking are the ones for the cases you never have to hand.
        let s = State::in_memory().await.expect("state");
        seed(&s).await.expect("seeding");

        let apps = s.installed_apps().await.expect("apps");
        assert!(apps.len() >= 8);

        let mut seen = std::collections::BTreeSet::new();
        for (name, status) in &apps {
            let a = hlb_api::AppSummary {
                name: name.clone(),
                status: status.clone(),
                image: String::new(),
                domain: None,
                last_backup_secs: s.backup_age(name).await.expect("backup"),
                holds_data: !s.backup_kinds(name).await.expect("kinds").is_empty(),
                last_verification_secs: None,
                blocking_guides: s.unverified_blocking(name).await.expect("guides") as i64,
            };
            seen.insert(a.attention());
        }

        for level in [Attention::Ok, Attention::Notice, Attention::Critical] {
            assert!(
                seen.contains(&level),
                "the demonstration set has no {level:?} case"
            );
        }
    }

    #[tokio::test]
    async fn the_demo_shows_all_three_causes_of_a_critical_app() {
        // 🔴 "Critical" covers three situations that are repaired differently: never
        // backed up, stale backup, service failed. A set showing only one would leave
        // the other two displays unchecked.
        let s = State::in_memory().await.expect("state");
        seed(&s).await.expect("seeding");

        assert_eq!(
            s.backup_age("seafile").await.expect("never"),
            None,
            "no \"never backed up\" case"
        );
        assert!(
            s.backup_age("vikunja").await.expect("stale").unwrap_or(0) > 86_400,
            "no \"stale backup\" case"
        );
        assert!(
            s.installed_apps()
                .await
                .expect("apps")
                .iter()
                .any(|(_, st)| st == "failed"),
            "no \"service failed\" case"
        );
    }

    #[tokio::test]
    async fn the_demo_shows_a_fresh_destination_masking_a_dead_one() {
        // The freshness trap: `MAX(finished_at)` across every destination passes an off-site
        // dead for weeks off as a two-hour-old backup.
        let s = State::in_memory().await.expect("state");
        seed(&s).await.expect("seeding");

        let immich = crate::coverage::all_of_them(&s, crate::api::STALENESS_THRESHOLD_S)
            .await
            .into_iter()
            .find(|c| c.app == "immich")
            .expect("immich holds data");
        let at = |d: &str| {
            immich
                .per_destination
                .iter()
                .find(|(n, _)| n == d)
                .map(|(_, st)| st.clone())
        };
        assert!(
            matches!(at("nas"), Some(hlb_backup::DestinationState::Fresh { .. })),
            "the NAS received: {immich:?}"
        );
        assert_eq!(
            at("offsite"),
            Some(hlb_backup::DestinationState::Never),
            "the off-site has NEVER received anything, and that must show"
        );
        assert!(
            s.consecutive_failures_on("immich", "offsite")
                .await
                .expect("failures")
                >= 4,
            "the repeated failures must show before the staleness threshold"
        );
    }

    #[tokio::test]
    async fn the_demo_has_an_app_that_looks_healthy_and_is_not() {
        // The system's worst state: the app runs and has NO backup. It is the one that
        // looks healthiest, so the one the display must catch.
        let s = State::in_memory().await.expect("state");
        seed(&s).await.expect("seeding");

        assert_eq!(s.backup_age("seafile").await.expect("backup"), None);
    }

    #[tokio::test]
    async fn the_demo_has_a_half_created_account_in_both_directions() {
        // Identity with no mailbox AND mailbox with no identity: the two halves show
        // differently and are repaired differently.
        let s = State::in_memory().await.expect("state");
        seed(&s).await.expect("seeding");

        use hlb_users::Coherence;
        assert_eq!(
            s.account("lena").await.expect("account").coherence(),
            Coherence::Complete
        );
        assert_eq!(
            s.account("dominique").await.expect("account").coherence(),
            Coherence::WithoutMailbox
        );
        assert_eq!(
            s.account("sacha").await.expect("account").coherence(),
            Coherence::WithoutIdentity
        );
    }

    #[tokio::test]
    async fn the_demo_has_an_expired_alias_that_still_receives() {
        // 🔴 The third state, the one that only exists because a mail server cannot
        // expire an alias: expired, and STILL active.
        let s = State::in_memory().await.expect("state");
        seed(&s).await.expect("seeding");

        let c = s.account("lena").await.expect("account");
        let broken = c.broken_promises(crate::auth::now());
        assert!(!broken.is_empty(), "no alias betrays its promise");
        assert!(broken
            .iter()
            .any(|(_, a)| a.local.starts_with("newsletter")));
    }

    #[tokio::test]
    async fn the_demo_distinguishes_no_folder_from_no_sorting() {
        // `NULL` = nothing was decided (we propose a default); `""` = I do NOT want
        // sorting. Confusing them re-imposes a folder on every regeneration.
        let s = State::in_memory().await.expect("state");
        seed(&s).await.expect("seeding");

        let rules = s.alias_rules("lena", "lena").await.expect("rules");
        let folder = |alias: &str| {
            rules
                .iter()
                .find(|(a, ..)| a.starts_with(alias))
                .map(|(_, d, _)| d.clone())
                .expect("alias present")
        };
        assert_eq!(folder("taxes").as_deref(), Some("Admin/Taxes"));
        assert_eq!(
            folder("contest").as_deref(),
            Some(""),
            "refusal explicite de trier"
        );
        assert_eq!(folder("newsletter"), None, "nothing decided");
    }

    #[test]
    fn the_demo_has_a_node_still_speaking_the_old_protocol() {
        // 🔴 A mismatched fleet: it is the NORMAL state during an update. Without
        // it in the demonstration set, we would never write the "unknown measurement"
        // display — and a `0 %` would end up slipping in.
        let n = nodes(1_000_000);
        let old = n
            .values()
            .filter_map(|s| s.report())
            .find(|r| r.protocol < 2)
            .expect("no agent on protocol 1");
        assert_eq!(old.cpu_busy, None);
        assert!(old.interfaces.is_empty());
        // But what it does send stays usable.
        assert!(old.memory_used().is_some());
    }

    #[test]
    fn the_demo_shows_a_machine_that_has_started_swapping() {
        // A swap in use is a signal BEFORE the failure: the machine slows without having
        // fallen over yet. That is the case we want to be able to look at on screen.
        let n = nodes(1_000_000);
        assert!(
            n.values()
                .filter_map(|s| s.report())
                .any(|r| r.swap_on_disk()),
            "no node is swapping to disk"
        );
    }

    #[test]
    fn the_demo_shows_a_machine_over_one_load_per_core() {
        // The only figure comparable across heterogeneous machines.
        let n = nodes(1_000_000);
        let overload = n
            .values()
            .filter_map(|s| s.report())
            .filter_map(|r| r.load_per_core())
            .any(|c| c > 1.0);
        assert!(overload, "no overloaded node");
    }

    #[test]
    fn the_demo_topology_contains_the_trap_it_exists_to_show() {
        // 🔴 Without two VMs on the same hardware, the screen that justifies the
        // interface's existence would have nothing to show — and we would not know it.
        let t = topology();
        assert_eq!(t.attention(), hlb_api::Attention::Critical);
        assert!(
            matches!(t.verdict(), hlb_api::TopologyVerdict::RedundancyIllusion { services } if services > 0),
            "{:?}",
            t.verdict()
        );

        let concentrated = t
            .domains
            .iter()
            .find(|d| d.concentrated)
            .expect("no concentrated domain");
        assert!(
            concentrated.nodes.len() >= 2,
            "one piece of hardware must carry several nodes"
        );

        assert!(
            t.domains.iter().any(|d| d.name.is_none()),
            "no undeclared domain: the \"we do not know\" case would not be displayed"
        );
        assert!(
            t.domains
                .iter()
                .flat_map(|d| &d.nodes)
                .any(|n| !n.reachable),
            "no unreachable node in the topology"
        );
    }

    #[tokio::test]
    async fn the_demo_has_a_followed_incident() {
        // 🔴 An incident without its thread would not show what makes the system
        // valuable: the chronology you re-read afterwards.
        let s = State::in_memory().await.expect("state");
        seed(&s).await.expect("seeding");

        let v = s
            .announcements(hlb_types::Role::Admin, crate::auth::now(), false)
            .await
            .expect("announcements");
        let incident = v
            .iter()
            .find(|a| a.open_incident())
            .expect("no open incident");
        assert!(
            incident.follow_ups.len() >= 2,
            "an incident with no follow-up thread"
        );
        assert_ne!(
            incident.last_update(),
            incident.body,
            "the last update must differ from the original message"
        );
    }

    #[tokio::test]
    async fn the_demo_shows_the_portal_filtering_at_work() {
        // ⚠️ Without an operations-only announcement, we would never write the filtered
        // display — and a maintenance announcement would end up on the portal.
        let s = State::in_memory().await.expect("state");
        seed(&s).await.expect("seeding");
        let now = crate::auth::now();

        let portal = s
            .announcements(hlb_types::Role::User, now, false)
            .await
            .expect("announcements");
        let admin = s
            .announcements(hlb_types::Role::Admin, now, false)
            .await
            .expect("announcements");

        assert!(
            admin.len() > portal.len(),
            "no reserved announcement: the filtering would not be exercised"
        );
    }

    #[tokio::test]
    async fn the_demo_keeps_an_expired_announcement_in_the_record() {
        let s = State::in_memory().await.expect("state");
        seed(&s).await.expect("seeding");
        let now = crate::auth::now();

        let active = s
            .announcements(hlb_types::Role::Admin, now, false)
            .await
            .expect("a");
        let all_of_them = s
            .announcements(hlb_types::Role::Admin, now, true)
            .await
            .expect("a");
        assert!(
            all_of_them.len() > active.len(),
            "no expired announcement in the history"
        );
    }

    #[test]
    fn the_demo_alerts_cover_every_display_case() {
        // 🔴 Each displays differently, and each is the one you will fail to see on
        // the day it matters if it renders badly.
        let a = muted_alerts(1_000_000);

        assert!(a.iter().any(|x| x.level == hlb_api::AlertLevel::Critical));
        assert!(a.iter().any(|x| x.level == hlb_api::AlertLevel::Important));
        assert!(
            a.iter().any(|x| x.level == hlb_api::AlertLevel::Unknown),
            "\"non-evaluable\" is missing: it is the case confused with \"all is well\""
        );
        assert!(
            a.iter().any(|x| x.is_muted(1_000_000)),
            "no muted alert: the matching display would never be written"
        );
        // A non-evaluable alert has NO value: putting 0 would say "threshold
        // respected", the exact opposite.
        let unknown = a
            .iter()
            .find(|x| x.level == hlb_api::AlertLevel::Unknown)
            .expect("an unknown one");
        assert_eq!(unknown.value, None);
    }

    #[test]
    fn a_demo_silenced_alert_still_shows_its_reason() {
        let a = muted_alerts(1_000_000);
        let muted = a
            .iter()
            .find(|x| x.is_muted(1_000_000))
            .expect("a muted alert");
        let mute = muted.mute(1_000_000).expect("a mute in force");
        assert_eq!(mute.by.as_deref(), Some("lena"), "who muted it must show");
        assert!(mute.reason.is_some(), "why it was muted must show");
        assert!(!muted.explanation.is_empty(), "the reason stays visible");
    }

    #[test]
    fn the_demo_nodes_cover_reachable_saturated_and_silent() {
        let n = nodes(1_000_000);
        assert_eq!(n.len(), 4);

        let thresholds = hlb_agent::disk::Thresholds::default();
        let saturated = n
            .values()
            .filter_map(|s| s.report())
            .any(|r| !r.allows_deploy(&thresholds));
        assert!(
            saturated,
            "no node under pressure: the critical case is not shown"
        );

        let unreachable = n
            .values()
            .any(|s| matches!(s, AgentStatus::Unreachable { .. }));
        assert!(unreachable, "an unreachable node is not a healthy node");

        let silent = n
            .values()
            .filter_map(|s| s.report())
            .any(|r| r.is_stale(1_000_000, 120));
        assert!(silent, "a mute agent must be represented");
    }

    #[test]
    fn the_demonstration_has_a_day_behind_it_ending_on_today() {
        let now = 1_800_000_000;
        let nodes = nodes_at(now as u64, Scale::Household);
        let samples = history(&nodes, 9, now);
        let end = now - now % 60;
        let mut checked = 0;
        for (address, status) in &nodes {
            let Some(r) = status.report() else {
                // 🔴 An unreachable machine has no past invented for it.
                assert!(!samples.iter().any(|x| &x.subject == address), "{address}");
                continue;
            };
            // The processor is unknown on an agent's first reading: then it has no curve.
            let Some(busy) = r.cpu_busy else { continue };
            let cpu: Vec<_> = samples
                .iter()
                .filter(|x| &x.subject == address && x.metric == "cpu")
                .collect();
            assert_eq!(
                cpu.len(),
                289,
                "a day every five minutes, both ends included"
            );
            assert_eq!(cpu.last().map(|x| (x.at, x.value)), Some((end, busy)));
            checked += 1;
        }
        assert!(checked >= 2, "{checked} machines had a processor curve");
        for x in &samples {
            if ["cpu", "memory", "swap"].contains(&x.metric.as_str())
                || x.metric.starts_with("disk:")
            {
                assert!((0.0..=1.0).contains(&x.value), "{x:?}");
            }
        }
        // A counter never runs backwards inside the day it was walked back from.
        let rx: Vec<f64> = samples
            .iter()
            .filter(|x| x.metric == "net_rx" && Some(&x.subject) == nodes.keys().next())
            .map(|x| x.value)
            .collect();
        assert!(rx.windows(2).all(|w| w[0] <= w[1]));
    }

    #[tokio::test]
    async fn the_demonstration_acts_for_an_administrator_it_seeds() {
        // Acting for an account it never created, every preference would fail on the
        // foreign key — the 500 a token bound to a missing account answers.
        for scale in [Scale::Household, Scale::Large] {
            let s = State::in_memory().await.expect("state");
            seed_at(&s, scale, None).await.expect("seed");
            assert_eq!(
                s.user_role(ADMIN).await.expect("role"),
                hlb_types::Role::Admin
            );
            s.set_home_of(ADMIN, Some(&[]))
                .await
                .expect("a preference can be stored");
        }
    }
}
