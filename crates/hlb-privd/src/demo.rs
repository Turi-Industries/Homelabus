//! The demonstration's data, written into an in-memory state at startup.
//!
//! The daemon seeds it: it alone writes the state. The web side fabricates the views
//! that have no table (machines, tasks, the curves) itself.
//!
//! ## 🔴 What this must never do
//!
//! Touch a real database. The demonstration opens **`State::in_memory()`** and nothing
//! else: the `--state` path is ignored, and saying so at startup avoids the
//! misunderstanding of believing you lost your data.

use hlb_state::State;

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
    let now = crate::now();
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

    // --- Flaws, as this morning's pass read them ----------------------------------
    // Jellyfin, public, running OpenSSL's exploited flaw — the critical line —,
    // Seafile's images never read — the `unknown` one —, the rest read and quiet.
    for (app, _) in state.installed_apps().await? {
        if app == "seafile" {
            continue;
        }
        let m = state.app_manifest(&app).await?;
        let flaws: Vec<hlb_state::Flaw> = (app == "jellyfin")
            .then(|| hlb_state::Flaw {
                id: "CVE-2025-15467".into(),
                package: "libssl3".into(),
                severity: "High".into(),
                version: "3.0.17-1~deb12u2".into(),
                fixed_in: "3.0.18-1~deb12u1".into(),
                exploited: true,
                epss: Some(0.75),
                first_seen: now - 6 * 3_600,
            })
            .into_iter()
            .collect();
        for i in hlb_updater::flaws::images(&m) {
            let digest = i
                .digest
                .clone()
                .unwrap_or_else(|| format!("sha256:{:0<64}", app.len()));
            state
                .record_image_scan(&digest, &i.reference(), now - 6 * 3_600, Ok(&flaws))
                .await?;
        }
        let said: std::collections::BTreeSet<String> = flaws.iter().map(|f| f.id.clone()).collect();
        state
            .set_alerted_flaws(&app, &said, now - 6 * 3_600)
            .await?;
    }

    // The machines: one quiet, one running the kernel's exploited flaw, one whose
    // system Grype holds no advisories for — never read, so never clean.
    let kernel = hlb_state::Flaw {
        id: "CVE-2024-1086".into(),
        package: "linux-image-6.1.0-18-amd64".into(),
        severity: "High".into(),
        version: "6.1.76-1".into(),
        fixed_in: "6.1.85-1".into(),
        exploited: true,
        epss: Some(0.82),
        first_seen: now - 6 * 3_600,
    };
    for (host, system, read) in [
        (
            "swarm-heavy",
            "Debian GNU/Linux 12 (bookworm)",
            Ok(Vec::new()),
        ),
        (
            "small-01",
            "Debian GNU/Linux 12 (bookworm)",
            Ok(vec![kernel]),
        ),
        (
            "small-02",
            "Arch Linux",
            Err("Grype holds no advisories for Arch Linux: its packages would read clean"),
        ),
    ] {
        let key = hlb_state::host_key(host);
        let said: std::collections::BTreeSet<String> = match &read {
            Ok(flaws) => flaws.iter().map(|f| f.id.clone()).collect(),
            Err(_) => Default::default(),
        };
        state
            .record_image_scan(
                &key,
                system,
                now - 6 * 3_600,
                read.as_deref().map_err(|e| *e),
            )
            .await?;
        state
            .set_alerted_flaws(&key, &said, now - 6 * 3_600)
            .await?;
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

    // --- Updates waiting, one per thing a person may be asked ------------------------
    updates(state, now).await?;

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

    // A plan filed for a quiet hour, so the plans screen has one to preview again:
    // Vikunja is the app the catalog has changed.
    state
        .save_named_plan(
            "vikunja-sunday",
            "POST",
            "/api/apps/vikunja/upgrade",
            "",
            "upgrade vikunja to the catalog's manifest",
            "lena",
            Some("on Sunday morning, nobody uses it then"),
        )
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
    let now = crate::now();

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

/// The demo's mutes, stored by `seed` in the table a real mute lives in.
pub fn mutes(now: i64) -> Vec<hlb_api::AlertMute> {
    vec![hlb_api::AlertMute {
        rule: "disk-full".into(),
        until: now + 4 * 3_600,
        by: "lena".into(),
        reason: "purge of small-01 under way".into(),
    }]
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

/// One update per answer the updates page gives: a click with its notes, a major by
/// hand, a patch going on alone, one approved, one rolled back while nobody was there.
/// Each moves from the tag its frozen manifest runs, so a catalog moving on moves them.
async fn updates(state: &State, now: i64) -> Result<(), Box<dyn std::error::Error>> {
    use hlb_api::updates::{
        ReleaseNote, UpdateJump, UpdateMove, UpdateReach, UpdateRefusal, UpdateWho, UpdateWhy,
    };
    let beyond = |jump, reach| UpdateWhy::BeyondReach {
        jump,
        reach,
        by_house: false,
    };
    let cases = [
        (
            "gitea",
            1,
            UpdateWho::OneClick,
            Some(beyond(UpdateJump::Minor, UpdateReach::Patch)),
            true,
        ),
        (
            "immich",
            0,
            UpdateWho::Manual,
            Some(UpdateWhy::Major),
            false,
        ),
        ("jellyfin", 1, UpdateWho::Automatic, None, false),
        (
            "vaultwarden",
            2,
            UpdateWho::OneClick,
            Some(beyond(UpdateJump::Patch, UpdateReach::None)),
            false,
        ),
        (
            "seafile",
            2,
            UpdateWho::OneClick,
            Some(beyond(UpdateJump::Patch, UpdateReach::None)),
            false,
        ),
    ];
    for (app, at, who, why, notes) in cases {
        let from = state.app_manifest(app).await?.spec.image.tag;
        let to = bump(&from, at);
        // GitHub's shape for a release page; gitea's manifest names no source today.
        let notes = notes.then(|| {
            vec![ReleaseNote {
                tag: format!("v{}", to.trim_start_matches('v')),
                url: format!(
                    "https://github.com/go-gitea/gitea/releases/tag/v{}",
                    to.trim_start_matches('v')
                ),
            }]
        });
        state
            .record_update_decision(&hlb_state::UpdateDecision {
                app: app.into(),
                digest: format!("sha256:{:0<64}", app.len()),
                from_tag: from,
                kind: UpdateMove::Version.as_stored().into(),
                to_tag: Some(to),
                who: who.as_stored().into(),
                why: why.map(|w| serde_json::to_string(&w)).transpose()?,
                notes: notes.map(|n| serde_json::to_string(&n)).transpose()?,
                decided_at: now - 1_200,
                refused: None,
                refused_at: None,
                approved_by: None,
                approved_at: None,
            })
            .await?;
    }
    let digest = |app: &str| format!("sha256:{:0<64}", app.len());
    state
        .approve_update("vaultwarden", &digest("vaultwarden"), ADMIN, now - 3_600)
        .await?;
    state
        .approve_update("seafile", &digest("seafile"), ADMIN, now - 2 * 86_400)
        .await?;
    let rolled = UpdateRefusal::RolledBack {
        reason: "task: non-zero exit (1)".into(),
    };
    state
        .refuse_update(
            "seafile",
            &digest("seafile"),
            &serde_json::to_string(&rolled)?,
            now - 86_400,
        )
        .await?;
    Ok(())
}

/// `tag` with its `at`-th number moved on and the ones after it zeroed: `28.2` at 1 is
/// `28.3`, `v3.3.1` at 0 is `v4.0.0`. A tag that is no version stays as it is.
fn bump(tag: &str, at: usize) -> String {
    let (v, rest) = match tag.strip_prefix('v') {
        Some(r) => ("v", r),
        None => ("", tag),
    };
    let Ok(mut parts) = rest
        .split('.')
        .map(str::parse::<u64>)
        .collect::<Result<Vec<_>, _>>()
    else {
        return tag.to_string();
    };
    let Some(n) = parts.get_mut(at) else {
        return tag.to_string();
    };
    *n += 1;
    for p in parts.iter_mut().skip(at + 1) {
        *p = 0;
    }
    let joined: Vec<String> = parts.iter().map(u64::to_string).collect();
    format!("{v}{}", joined.join("."))
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_demo_update_moves_the_number_it_names() {
        assert_eq!(super::bump("28.2", 1), "28.3");
        assert_eq!(super::bump("v3.3.1", 0), "v4.0.0");
        assert_eq!(super::bump("14.0.9", 2), "14.0.10");
        assert_eq!(super::bump("latest", 0), "latest");
        assert_eq!(super::bump("12.4", 2), "12.4");
    }
}
