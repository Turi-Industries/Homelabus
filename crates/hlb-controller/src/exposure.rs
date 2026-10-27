//! Declared exposure against real exposure (batch 9.10).
//!
//! ## 🔴 The point: "it is easy to get this wrong"
//!
//! The manifest declares `expose`; `hlb-ingress` renders the Caddy configuration. Both
//! pieces of information exist, and nobody puts them side by side: an app published by
//! mistake is **invisible**.
//!
//! ## 🔴 What we compare AGAINST
//!
//! A first attempt compared the manifests… to `routes_from_manifest` applied to those
//! same manifests. Both sides came from the same function: the comparison could **never**
//! fail, and the screen would have shown "compliant" whatever happened. Worse than
//! absent: it would have attested to a verification that never took place.
//!
//! So the comparison is against what was REALLY published at the last application of the
//! ingress configuration (`published_ingress`), versus what the manifests ask for today.
//! That is the dangerous, real case: an app installed or changed without reapplying the
//! ingress, or an app removed whose route stays open.
//!
//! ⚠️ No recorded application does NOT amount to "compliant": we know nothing, and the
//! screen must say so.

use hlb_api::issues::Cause;
use hlb_state::State;

/// Every route — the orphans first — with the cause the inbox files a divergence under,
/// decided in the branch that writes the divergence.
pub async fn findings(state: &State) -> Vec<(hlb_api::ExposureSummary, Option<Cause>)> {
    // 🔴 The orphan routes FIRST: a removed app whose route still answers appears in no
    // manifest, therefore in no walk over the installed apps. That is exactly the one
    // you never see.
    let mut out = orphans(state).await;
    out.append(&mut everything(state).await);
    out
}

/// The exposure of every installed app.
async fn everything(state: &State) -> Vec<(hlb_api::ExposureSummary, Option<Cause>)> {
    let mut out = Vec::new();

    let published = state.published_ingress().await.unwrap_or_default();
    // ⚠️ Never applied: distinct from "nothing is published". Confusing the two would
    // announce a closed cluster when we know nothing about it.
    let never_applied = published.is_empty();

    let apps = state.installed_apps().await.unwrap_or_default();
    for (name, _status) in apps {
        let Ok(m) = state.app_manifest(&name).await else {
            continue;
        };
        let domain = state.app_domain(&name).await.ok().flatten();

        // The route only opens once the blocking manual actions are handled.
        // This is exactly the CLI's calculation.
        let released = state.unverified_blocking(&name).await.unwrap_or(1) == 0;
        let routes = hlb_ingress::routes_from_manifest(&m, domain.as_deref(), released);

        for (i, r) in routes.iter().enumerate() {
            let declared = m
                .spec
                .ingress
                .get(i)
                .map(|ing| match ing.expose {
                    hlb_types::ExposePolicy::Private => "private",
                    hlb_types::ExposePolicy::AfterGuide => "after-guide",
                    hlb_types::ExposePolicy::Public => "public",
                })
                .unwrap_or("private");

            let real = published.iter().find(|(h, ..)| h == &r.host);

            let (public, divergence, cause) = match (never_applied, real) {
                (true, _) => (
                    r.public,
                    Some(format!(
                        "{}: the ingress configuration has never been applied — what \
                         is really reachable is UNKNOWN.",
                        r.host
                    )),
                    Some(Cause::ExposureUnknown),
                ),
                // 🔴 The dangerous case: open on the internet when nothing asked for
                // it.
                (false, Some((_, _, true))) if !r.public => (
                    true,
                    Some(format!(
                        "{} is published on the internet while the manifest wants it \
                         \"{declared}\".",
                        r.host
                    )),
                    Some(Cause::ExposedAgainstManifest),
                ),
                (false, Some((_, _, false))) if r.public => (
                    false,
                    Some(format!(
                        "{} should be published and is not: the ingress configuration \
                         predates this change.",
                        r.host
                    )),
                    Some(Cause::NotPublished),
                ),
                (false, None) => (
                    false,
                    Some(format!(
                        "{} has no route published: \"hlb ingress --apply\" has not \
                         been re-run since the install.",
                        r.host
                    )),
                    Some(Cause::RouteNotApplied),
                ),
                (false, Some((_, _, public))) => (*public, None, None),
            };

            out.push((
                hlb_api::ExposureSummary {
                    app: name.clone(),
                    installed: true,
                    host: r.host.clone(),
                    declared: declared.to_string(),
                    public,
                    divergence,
                    cause: cause.clone(),
                },
                cause,
            ));
        }
    }

    // The interface's own route: published by the ingress once the controller runs as a
    // service, and wanted public — invitations are opened from outside. It belongs to
    // no manifest, so the walk above never meets it.
    if let Some(host) = interface_host(state).await {
        if let Some((_, _, public)) = published.iter().find(|(h, ..)| h == &host) {
            out.push((
                hlb_api::ExposureSummary {
                    app: hlb_engine::ingress::CONTROLLER_SERVICE.into(),
                    // No application page: it is Homelabus itself.
                    installed: false,
                    host,
                    declared: "public".into(),
                    public: *public,
                    divergence: None,
                    cause: None,
                },
                None,
            ));
        }
    }

    // What is open comes first: across twenty rows, the one that is a problem would get
    // lost in the middle of an alphabetical sort.
    out.sort_by(|(a, _), (b, _)| {
        b.attention()
            .cmp(&a.attention())
            .then_with(|| a.host.cmp(&b.host))
    });
    out
}

/// The routes published that no manifest asks for any more.
///
/// 🔴 This is the half a walk over installed apps can NOT see: a removed app whose route
/// stays open appears in no manifest, therefore in no loop over the apps. It nevertheless
/// keeps answering on the internet.
async fn orphans(state: &State) -> Vec<(hlb_api::ExposureSummary, Option<Cause>)> {
    let published = state.published_ingress().await.unwrap_or_default();
    let mut expected_items = std::collections::BTreeSet::new();

    for (name, _) in state.installed_apps().await.unwrap_or_default() {
        let Ok(m) = state.app_manifest(&name).await else {
            continue;
        };
        let domain = state.app_domain(&name).await.ok().flatten();
        let released = state.unverified_blocking(&name).await.unwrap_or(1) == 0;
        for r in hlb_ingress::routes_from_manifest(&m, domain.as_deref(), released) {
            expected_items.insert(r.host);
        }
    }
    // The interface's route is wanted by the exposure, not by a manifest: without it
    // here it read as a removed app's route still answering — critical, and false.
    expected_items.extend(interface_host(state).await);

    published
        .into_iter()
        .filter(|(host, ..)| !expected_items.contains(host))
        .map(|(host, app, public)| {
            (
                hlb_api::ExposureSummary {
                    declared: "none (the app is no longer installed)".into(),
                    divergence: Some(format!(
                        "{host} still answers{} while {app} is no longer installed.",
                        if public {
                            " from the internet"
                        } else {
                            " from the VPN"
                        }
                    )),
                    host,
                    app,
                    installed: false,
                    public,
                    cause: Some(Cause::OrphanRoute),
                },
                Some(Cause::OrphanRoute),
            )
        })
        .collect()
}

/// Where the interface is published, once the exposure is configured.
async fn interface_host(state: &State) -> Option<String> {
    state
        .exposure()
        .await
        .ok()
        .flatten()
        .map(|e| e.controller_host())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_interface_s_route_is_no_orphan() {
        let state = State::in_memory().await.expect("state");
        state
            .set_exposure(&hlb_state::Exposure {
                domain: "example.org".into(),
                certificates: hlb_state::Certificates::Internal,
                acme_email: None,
                dns_provider: None,
                staging: false,
                controller_host: None,
                acme_ca: None,
                acme_ca_root: None,
            })
            .await
            .expect("exposure");
        state
            .record_ingress(&[("hlb.example.org".into(), "hlb-controller".into(), true)])
            .await
            .expect("ingress");
        assert!(
            orphans(&state).await.is_empty(),
            "the interface read as an orphan"
        );
        let rows = findings(&state).await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].0.host, "hlb.example.org");
        assert_eq!(rows[0].1, None, "nothing to fix about it");
    }

    #[tokio::test]
    async fn a_route_that_outlived_its_app_says_the_app_is_gone() {
        let state = State::in_memory().await.expect("state");
        state
            .record_ingress(&[("cloud.example".into(), "nextcloud".into(), true)])
            .await
            .expect("ingress");
        let rows = orphans(&state).await;
        assert_eq!(rows.len(), 1);
        // The interface links an installed app to its page; this one has none.
        assert!(!rows[0].0.installed);
        assert_eq!(rows[0].1, Some(Cause::OrphanRoute));
    }
}
