//! The printable runbook.
//!
//! ## 🔴 Why it is GENERATED, and never written by hand
//!
//! The runbook is printed, on paper. Written by hand, it is wrong on the day you
//! need it: nodes change, destinations move, apps are added. A reassuring, stale
//! document is worse than no document — you follow it.
//!
//! This one is produced from the real state, at the moment you ask for it. It carries
//! its generation date, because once printed it starts ageing too.
//!
//! ## ⚠️ It contains NO secret
//!
//! A runbook is meant to be printed and stored elsewhere — that is its whole point, and
//! exactly why it must carry no secret value. It says **where things are**, not what
//! they are worth.

use hlb_state::State;

/// The runbook, in Markdown: readable as is, and printable from anything.
pub async fn generate(state: &State, nodes: &[hlb_api::NodeSummary], now: i64) -> String {
    let mut s = String::new();

    s.push_str("# Runbook Homelabus\n\n");
    s.push_str(
        "Generated automatically from the real state. Once printed, this document \
         starts ageing: regenerate it after any infrastructure change.\n\n",
    );

    // --- What you need to hand ------------------------------------------------
    s.push_str("## Before anything: the master key\n\n");
    s.push_str(
        "Without it the vault's secrets are permanently unusable, and NO restore will \
         give you a working system: the databases will restore, the apps will not be \
         able to connect to them.\n\n\
         - Default location: `~/.config/hlb/master.key`\n\
         - It must exist OUTSIDE the cluster, on media that does not depend on \
           it.\n\n",
    );
    // 🔴 We do not say where it really is: the runbook is printed and stored, and
    // naming a key's exact location on a piece of paper is a risk in itself.

    // --- The restart order ------------------------------------------------------
    s.push_str("## Restart order\n\n");
    s.push_str(
        "Docker Swarm has no `depends_on`: it starts everything in parallel, and an \
         app launched before its database crash-loops. This order comes from the \
         capability graph, not from a hand-maintained list.\n\n",
    );
    match startup_order(state).await {
        Ok(order) if !order.is_empty() => {
            for (i, app) in order.iter().enumerate() {
                s.push_str(&format!("{}. `{app}`\n", i + 1));
            }
        }
        // ⚠️ An order we cannot compute is not replaced by a plausible one: following
        // the wrong order at the worst moment is exactly what we want to avoid. And the
        // REASON is printed — "postgres is missing" can be fixed, "the order could not
        // be computed" cannot.
        Ok(_) => s.push_str("*No application installed.*\n"),
        Err(reason) => s.push_str(&format!(
            "*The order could not be computed: {reason}.*\n\n\
             *In the meantime, start the platform services (postgres, valkey, garage) \
             BEFORE the applications, and check each one before moving on to the \
             next.*\n"
        )),
    }
    s.push('\n');

    // --- The nodes ---------------------------------------------------------------
    s.push_str("## Nodes\n\n");
    if nodes.is_empty() {
        s.push_str(
            "*No known node: Docker is unreachable, or no agent \
                    answers.*\n\n",
        );
    } else {
        s.push_str("| Name | Address | Reachable |\n|---|---|---|\n");
        for n in nodes {
            s.push_str(&format!(
                "| {} | `{}` | {} |\n",
                n.hostname.as_deref().unwrap_or("(unknown)"),
                n.address,
                // ⚠️ The state at generation time, not a property of the node. A printed
                // runbook freezes it: that is exactly why it carries its date.
                if n.reachable { "yes" } else { "NO" }
            ));
        }
        s.push('\n');
    }

    // --- The backup destinations --------------------------------------------------
    s.push_str("## Backup destinations\n\n");
    let dests = state.destinations().await.unwrap_or_default();
    if dests.is_empty() {
        s.push_str("🔴 **NO destination declared.** There is nothing to restore.\n\n");
    } else {
        s.push_str("| Name | Location | Classes |\n|---|---|---|\n");
        for (name, location, classes, _secret) in &dests {
            // ⚠️ `location` can hold S3 credentials in a URL. We go through
            // `hlb-backup`'s masking rather than print an access key on a piece of
            // paper that will sit in a drawer.
            s.push_str(&format!(
                "| {name} | `{}` | {classes} |\n",
                hlb_backup::Destination {
                    name: name.clone(),
                    location: location.clone(),
                    classes: Vec::new(),
                    credentials_secret: None,
                }
                .masked_location()
            ));
        }
        s.push('\n');
    }

    // --- The procedure ------------------------------------------------------------
    s.push_str("## Disaster recovery\n\n");
    s.push_str(
        "1. Check the master key is available. **Without it, stop here** and find it \
         again.\n\
         2. `hlb dr status` — says whether the switchover is possible, and what is \
         missing otherwise.\n\
         3. `hlb backup verify <app>` — verify BEFORE destroying anything.\n\
         4. `hlb dr promote <node> --apply` — the assisted switchover.\n\
         5. `hlb reconcile --apply` — bring the real state back in line with the \
         desired one.\n\
         6. `hlb ingress --apply` — republish the routes: without this, nothing is \
         reachable.\n\n",
    );

    s.push_str("## If you can no longer sign in\n\n");
    s.push_str(
        "PocketID is the single point of failure on ACCESS: if it is down, you can no \
         longer get into Homelabus, so you can no longer drive its restore.\n\n\
         - PocketID's single-use sign-in codes (printed separately).\n\
         - Vaultwarden's local sign-in, which depends on no other service.\n\
         - An `admin` API token lets you drive everything from the command line \
           without going through SSO.\n\n",
    );

    s.push_str(&format!(
        "---\n\nGenerated on {} (UTC). The figures and lists above date from that \
         instant.\n",
        readable_timestamp(now)
    ));

    s
}

/// "2026-08-19 07:12", in UTC.
///
/// ⚠️ No local timezone: the server does not know the reader's, and a date shown in the
/// wrong timezone compares badly against the logs, which are in UTC.
fn readable_timestamp(t: i64) -> String {
    let days = t.div_euclid(86_400);
    let remaining = t.rem_euclid(86_400);

    // The civil-days algorithm (Howard Hinnant), the inverse of the timeline's.
    let z = days + 719_468;
    let ere = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - ere * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + ere * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}",
        remaining / 3_600,
        (remaining % 3_600) / 60
    )
}

/// The topological order of the installed apps.
///
/// The error is SURFACED, not swallowed: `MissingDependency` names the missing service,
/// which is far more useful information than a missing order.
async fn startup_order(state: &State) -> Result<Vec<String>, String> {
    let mut manifests = Vec::new();
    let apps = state
        .installed_apps()
        .await
        .map_err(|e| format!("unreadable state ({e})"))?;
    for (name, status) in apps {
        if status == "failed" {
            continue;
        }
        if let Ok(m) = state.app_manifest(&name).await {
            manifests.push(m);
        }
    }
    // ⚠️ The SAME topological sort as the deployment's: an order written separately
    // would diverge as soon as a capability changed, and that is the worst moment to
    // notice.
    hlb_resolver::graph::DependencyGraph::from_manifests(&manifests)
        .deployment_order()
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_runbook_never_carries_a_secret_value() {
        // 🔴 A runbook is meant to be PRINTED and stored elsewhere. Putting a secret
        // value in it puts it on paper, outside any access control.
        let s = State::in_memory().await.expect("state");
        s.store_secret_if_absent("gitea-db-password", b"tres-secret", "password")
            .await
            .expect("secret");

        let r = generate(&s, &[], 1_787_097_600).await;
        assert!(!r.contains("tres-secret"), "a secret value leaked");
    }

    #[tokio::test]
    async fn an_installation_with_no_backup_destination_says_so_loudly() {
        // The runbook you read at the worst moment must say straight away that there
        // is nothing to restore, rather than unroll a pointless procedure.
        let s = State::in_memory().await.expect("state");
        let r = generate(&s, &[], 1_787_097_600).await;
        assert!(r.contains("NO destination declared"), "{r}");
    }

    #[tokio::test]
    async fn the_generation_date_is_printed_because_paper_goes_stale() {
        let s = State::in_memory().await.expect("state");
        let r = generate(&s, &[], 1_787_097_600).await;
        assert!(r.contains("2026-08-19"), "{r}");
        assert!(r.contains("starts ageing"));
    }

    #[tokio::test]
    async fn an_uncomputable_order_prints_the_reason_not_just_the_failure() {
        // ⚠️ "The order could not be computed" cannot be fixed; "gitea needs postgres,
        // which is not in the catalog" can. And following an invented order at the
        // worst moment is exactly what we want to avoid.
        let s = State::in_memory().await.expect("state");
        let m: hlb_types::Manifest = serde_yaml_ng::from_str(
            "apiVersion: hlb/v1\nkind: App\nmetadata: { name: gitea }\n\
             spec:\n  image: { repo: a/b, tag: \"1\" }\n  requires:\n\
             \x20   - kind: database\n      engine: postgres\n",
        )
        .expect("manifest");
        s.upsert_app("gitea", &m, None).await.expect("app");

        let r = generate(&s, &[], 1_787_097_600).await;
        assert!(
            r.contains("postgres"),
            "the reason must name what is missing: {r}"
        );
        assert!(r.contains("BEFORE the applications"));
    }

    #[tokio::test]
    async fn an_empty_installation_says_so_rather_than_blaming_a_calculation() {
        // 🔴 "The order could not be computed" on an empty installation would send you
        // looking for an outage where there is simply nothing.
        let s = State::in_memory().await.expect("state");
        let r = generate(&s, &[], 1_787_097_600).await;
        assert!(r.contains("No application installed"), "{r}");
    }
}

#[cfg(test)]
mod timestamp_tests {
    use super::readable_timestamp;

    #[test]
    fn the_civil_date_matches_known_epochs() {
        // The computation is done by hand (no date dependency in this crate): a
        // one-day error would date the runbook yesterday, and you would believe you
        // had regenerated a document you had not.
        assert_eq!(readable_timestamp(0), "1970-01-01 00:00");
        assert_eq!(readable_timestamp(946_684_800), "2000-01-01 00:00");
        assert_eq!(readable_timestamp(1_787_097_600), "2026-08-19 00:00");
        assert_eq!(
            readable_timestamp(1_787_097_600 + 11_520),
            "2026-08-19 03:12"
        );
    }
}
