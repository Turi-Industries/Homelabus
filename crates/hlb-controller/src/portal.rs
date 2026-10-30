//! The portal: what someone with an account and nothing else sees (batch 7).
//!
//! ## 🔴 What Homelabus does not grant
//!
//! The portal **announces** the available applications; it does not grant access. That
//! comes from PocketID and forward-auth. The distinction is not theoretical: showing an
//! app as "available" does not make it reachable, and letting people believe otherwise
//! would send them looking for an outage where an authorization is missing.
//!
//! The screen says so, rather than leaving it to be guessed.
//!
//! ## And an announcement that does not concern its reader is noise
//!
//! Flooding them with operational messages makes them stop reading — at the precise
//! moment one of them will matter. Hence audience by role.

use std::sync::Arc;

use crate::extract::{Json, Path, Query};
use axum::extract::State as AxumState;
use axum::http::StatusCode;
use hlb_api::{ActionResult, ActionStep, StepState};

use crate::actions::ActionQuery;
use crate::api::AppState;
use crate::auth::{Authorized, CanPublish, CanReadSelf};
use crate::error::{ActionReply, ApiError, ApiResult};

/// The announcements meant for whoever is looking.
#[utoipa::path(
    get,
    path = "/api/announcements",
    responses(
        (status = 200, body = Vec<hlb_api::Announcement>)
    ),
    extensions(
        ("x-hlb-requires" = json!("read-self"))
    )
)]
pub async fn announcements(
    auth: Authorized<CanReadSelf>,
    AxumState(s): AxumState<Arc<AppState>>,
) -> Json<Vec<hlb_api::Announcement>> {
    Json(
        s.state
            .announcements(auth.identity().role, crate::auth::now(), false)
            .await
            .unwrap_or_default(),
    )
}

/// What the portal displays.
#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct Portal {
    /// The exposed applications, with their address.
    pub apps: Vec<PortalApp>,
    pub announcements: Vec<hlb_api::Announcement>,
    /// The account, if there is one.
    pub account: Option<String>,
    #[serde(default)]
    pub mailboxes: Vec<hlb_api::MailboxBrief>,
}

#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct PortalApp {
    pub name: String,
    pub display_name: String,
    pub domain: Option<String>,
    pub category: Option<String>,
    /// 🔴 Is the app running **right now**?
    ///
    /// Showing a link to a stopped app leads to an error page, and you believe it is
    /// your own access that is broken.
    pub available: bool,
}

/// One person's portal.
#[utoipa::path(
    get,
    path = "/api/portal",
    responses(
        (status = 200, body = Portal)
    ),
    extensions(
        ("x-hlb-requires" = json!("read-self"))
    )
)]
pub async fn portal(
    auth: Authorized<CanReadSelf>,
    AxumState(s): AxumState<Arc<AppState>>,
) -> Json<Portal> {
    let i = auth.identity();
    let account = i.actor.for_account().map(str::to_string);

    let installed = s.state.installed_apps().await.unwrap_or_default();
    let mut apps = Vec::new();

    for (name, status) in installed {
        // ⚠️ Only apps that have a domain are shown: the platform services (postgres,
        // valkey) have nothing to offer a user, and listing them would send people
        // looking for a link that does not exist.
        let Ok(Some(domain)) = s.state.app_domain(&name).await else {
            continue;
        };

        let display_name = s
            .state
            .app_manifest(&name)
            .await
            .ok()
            .and_then(|m| m.metadata.display_name.clone())
            .unwrap_or_else(|| name.clone());
        let category = s
            .state
            .app_manifest(&name)
            .await
            .ok()
            .and_then(|m| m.metadata.category.clone());

        apps.push(PortalApp {
            name,
            display_name,
            domain: Some(domain),
            category,
            available: status == "running",
        });
    }
    apps.sort_by(|a, b| a.display_name.cmp(&b.display_name));

    let mailboxes = match &account {
        Some(c) => s
            .state
            .mailboxes(c)
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|(local, domain, default)| hlb_api::MailboxBrief {
                address: format!("{local}@{domain}"),
                default,
            })
            .collect(),
        None => Vec::new(),
    };

    Json(Portal {
        apps,
        announcements: s
            .state
            .announcements(i.role, crate::auth::now(), false)
            .await
            .unwrap_or_default(),
        account,
        mailboxes,
    })
}

/// The themes shipped by the interface.
///
/// 🔴 The list lives HERE and not in the interface: if each had its own, a removed theme
/// would keep being offered until the next interface deploy, and choosing it would give
/// a default theme with no explanation. The interface reads it from the API.
/// Re-exported so existing callers keep working; the list lives in `hlb_api`.
pub use hlb_api::THEMES;

/// The display preferences of the signed-in person.
#[utoipa::path(
    get,
    path = "/api/preferences",
    responses(
        (status = 200, body = hlb_api::Preferences)
    ),
    extensions(
        ("x-hlb-requires" = json!("read-self"))
    )
)]
pub async fn preferences(
    auth: Authorized<CanReadSelf>,
    AxumState(s): AxumState<Arc<AppState>>,
) -> Json<hlb_api::Preferences> {
    let (theme, home, density) = match auth.actor().for_account() {
        Some(c) => (
            s.state.theme_of(c).await.unwrap_or(None),
            s.state.home_of(c).await.unwrap_or(None),
            s.state.density_of(c).await.unwrap_or_default(),
        ),
        // A service token has no preference: it belongs to nobody.
        None => (None, None, hlb_api::Density::default()),
    };

    Json(hlb_api::Preferences {
        theme,
        available: offered(&s),
        default: s.state.brand().await.ok().and_then(|m| m.default_theme),
        home,
        home_default: hlb_api::HomeTile::DEFAULT.to_vec(),
        home_offered: hlb_api::HomeWidget::ALL
            .map(hlb_api::HomeWidget::tile)
            .to_vec(),
        density,
    })
}

#[derive(Debug, serde::Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct DensityRequest {
    pub density: hlb_api::Density,
}

/// Sets how tightly the signed-in person's lists are set.
///
/// ⚠️ No preview, for the reason a theme has none: it changes what one person sees,
/// and is undone in one click.
#[utoipa::path(
    put,
    path = "/api/preferences/density",
    request_body = DensityRequest,
    responses(
        (status = 204, description = "Set")
    ),
    extensions(
        ("x-hlb-requires" = json!("act-on-self")),
        ("x-hlb-preview" = json!(false))
    )
)]
pub async fn change_density(
    auth: Authorized<crate::auth::CanActOnSelf>,
    AxumState(s): AxumState<Arc<AppState>>,
    Json(d): Json<DensityRequest>,
) -> Result<StatusCode, ApiError> {
    let Some(account) = auth.actor().for_account() else {
        return Err(ApiError::Forbidden(
            "a service token has no preferences: it belongs to nobody".into(),
        ));
    };
    let asked = hlb_api::intent::SetDensity {
        user: account.to_string(),
        density: d.density,
    };
    s.record(asked).await.map_err(ApiError::Internal)?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Default, serde::Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct HomeRequest {
    /// The tiles, in order. `null` = back to the default.
    #[serde(default)]
    pub home: Option<Vec<hlb_api::HomeTile>>,
}

/// Arranges the signed-in person's home.
///
/// ⚠️ No preview, for the reason a theme has none: it changes what one person sees,
/// and is undone in one click. A name `HomeWidget` does not know is refused by the
/// body's own parsing — never stored, then silently missing from the home.
#[utoipa::path(
    put,
    path = "/api/preferences/home",
    request_body = HomeRequest,
    responses(
        (status = 204, description = "Arranged")
    ),
    extensions(
        ("x-hlb-requires" = json!("act-on-self")),
        ("x-hlb-preview" = json!(false))
    )
)]
pub async fn arrange_home(
    auth: Authorized<crate::auth::CanActOnSelf>,
    AxumState(s): AxumState<Arc<AppState>>,
    Json(d): Json<HomeRequest>,
) -> Result<StatusCode, ApiError> {
    let Some(account) = auth.actor().for_account() else {
        return Err(ApiError::Forbidden(
            "a service token has no preferences: it belongs to nobody".into(),
        ));
    };
    let home = d.home.as_deref().unwrap_or_default();
    // A card twice is a layout the interface cannot have produced, and would draw two
    // copies of the same figures.
    let twice = home.iter().enumerate().find_map(|(i, t)| {
        home[..i]
            .iter()
            .any(|u| u.widget == t.widget)
            .then_some(t.widget)
    });
    if let Some(w) = twice {
        return Err(ApiError::Unprocessable(format!("{w:?} is pinned twice")));
    }
    // Refused, not trimmed to fit: stored as asked, the home would draw another size
    // than the one chosen and nothing would say why.
    if let Some(t) = home.iter().find(|t| !t.fits()) {
        return Err(ApiError::Unprocessable(format!(
            "{:?} is {} × {}: a tile is 1 to {} columns wide and 1 to {} rows tall",
            t.widget,
            t.w,
            t.h,
            hlb_api::TILE_W_MAX,
            hlb_api::TILE_H_MAX
        )));
    }
    let asked = hlb_api::intent::SetHome {
        user: account.to_string(),
        home: d.home.clone(),
    };
    s.record(asked).await.map_err(ApiError::Internal)?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Default, serde::Deserialize, utoipa::ToSchema)]
pub struct ThemeRequest {
    /// The theme's name. `null` = go back to the installation's.
    #[serde(default)]
    pub theme: Option<String>,
}

/// Changes the signed-in person's theme.
///
/// ⚠️ No preview: choosing a theme is immediate, reversible in one click, and has no
/// effect on anyone else. Forcing a round trip would train people to confirm twice —
/// which would drain the protection of its meaning where it counts.
#[utoipa::path(
    put,
    path = "/api/preferences/theme",
    request_body = Option<ThemeRequest>,
    responses(
        (status = 204, description = "Chosen")
    ),
    extensions(
        ("x-hlb-requires" = json!("act-on-self")),
        ("x-hlb-preview" = json!(false))
    )
)]
pub async fn change_theme(
    auth: Authorized<crate::auth::CanActOnSelf>,
    AxumState(s): AxumState<Arc<AppState>>,
    body: Option<Json<ThemeRequest>>,
) -> Result<StatusCode, ApiError> {
    let d = body.map(|Json(d)| d).unwrap_or_default();

    let Some(account) = auth.actor().for_account() else {
        return Err(ApiError::Forbidden(
            "a service token has no preferences: it belongs to nobody".into(),
        ));
    };

    // 🔴 An unknown theme is REFUSED, not silently accepted: accepted, it would be
    // stored, would fall back to the default on display, and you would think the choice
    // was lost to an interface bug.
    if let Some(t) = &d.theme {
        let known = offered(&s);
        if !known.iter().any(|k| k.eq_ignore_ascii_case(t)) {
            return Err(ApiError::Unprocessable(format!(
                "unknown theme \"{t}\". Available: {}",
                known.join(", ")
            )));
        }
    }

    let asked = hlb_api::intent::SetTheme {
        user: account.to_string(),
        theme: d.theme.clone(),
    };
    s.record(asked).await.map_err(ApiError::Internal)?;
    Ok(StatusCode::NO_CONTENT)
}

/// The status page.
///
/// ## 🔴 Private by default
///
/// It is served behind authentication as long as `--status-public` is not set. A public
/// status page reveals the list of what runs at your place and the calendar of your
/// outages — a legitimate choice, but one that gets decided.
///
/// ⚠️ When it is public, it shows only the **exposed** services and the incidents: never
/// the nodes, never the backups, never the accounts.
#[utoipa::path(
    get,
    path = "/status",
    responses(
        (status = 200, body = hlb_api::StatusPage)
    ),
    extensions(
        ("x-hlb-public" = json!(true))
    )
)]
pub async fn status(AxumState(s): AxumState<Arc<AppState>>) -> ApiResult<hlb_api::StatusPage> {
    if !s.public_status {
        // The refusal says HOW to open the page, so it is not read as an outage.
        return Err(ApiError::NotFound(
            "status page not published. An administrator can open it: \
             --status-public when starting the controller."
                .into(),
        ));
    }
    Ok(Json(build_status(&s).await))
}

/// The same page, for whoever is already authenticated.
///
/// Always available: seeing the services' state is part of normal reading.
#[utoipa::path(
    get,
    path = "/api/status",
    responses(
        (status = 200, body = hlb_api::StatusPage)
    ),
    extensions(
        ("x-hlb-requires" = json!("read-self"))
    )
)]
pub async fn private_status(
    _auth: Authorized<CanReadSelf>,
    AxumState(s): AxumState<Arc<AppState>>,
) -> Json<hlb_api::StatusPage> {
    Json(build_status(&s).await)
}

/// How many days of history the status page's uptime bar covers.
const UPTIME_WINDOW_DAYS: i64 = 90;

async fn build_status(s: &AppState) -> hlb_api::StatusPage {
    let now = crate::auth::now();

    // Incident- and maintenance-level announcements, open AND past: `Announcement`
    // already IS the incident history (never deleted, `expires_at` marks it closed).
    // Historical / realtime / scheduled is derived by the reader from `level` and
    // `active()` — no separate field, no new storage.
    let incidents: Vec<hlb_api::Announcement> = s
        .state
        .announcements(hlb_types::Role::User, now, true)
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|a| {
            matches!(
                a.level,
                hlb_api::AnnouncementLevel::Incident | hlb_api::AnnouncementLevel::Maintenance
            )
        })
        .collect();

    let en_maintenance = s.state.maintenance_titles(now).await;

    let mut services = Vec::new();
    for (name, status) in s.state.installed_apps().await.unwrap_or_default() {
        // ⚠️ Only the EXPOSED apps: the platform services do not face outward, and
        // listing them on a public page would draw up the inventory of
        // the installation.
        let Ok(Some(domain)) = s.state.app_domain(&name).await else {
            continue;
        };

        let announced = en_maintenance.iter().any(|t| t.contains(&name));
        let uptime = s
            .state
            .uptime_history(&name, UPTIME_WINDOW_DAYS)
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|(day, state)| hlb_api::UptimeSample { day, state })
            .collect();

        services.push(hlb_api::ServiceStatus {
            state: hlb_api::ServiceState::of(&status, announced),
            name,
            domain: Some(domain),
            uptime,
        });
    }
    services.sort_by(|a, b| {
        b.state
            .attention()
            .cmp(&a.state.attention())
            .then_with(|| a.name.cmp(&b.name))
    });

    hlb_api::StatusPage {
        services,
        incidents,
        public: s.public_status,
    }
}

#[derive(Debug, Default, serde::Deserialize, utoipa::ToSchema)]
pub struct AnnouncementRequest {
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub body: Option<String>,
    #[serde(default)]
    pub level: Option<String>,
    #[serde(default)]
    pub pinned: bool,
    /// Minimum role to see it. Absent = everyone.
    #[serde(default)]
    pub audience: Option<String>,
    /// Visibility duration in seconds. Absent = permanent.
    #[serde(default)]
    pub duration_s: Option<i64>,
}

/// Publishes an announcement.
#[utoipa::path(
    post,
    path = "/api/announcements",
    params(crate::actions::ActionQuery),
    request_body = Option<AnnouncementRequest>,
    responses(
        (status = 200, body = hlb_api::ActionResult),
        (status = 422, description = "Nothing could be planned: the body's `blockers` say why", body = hlb_api::ActionResult)
    ),
    extensions(
        ("x-hlb-requires" = json!("publish")),
        ("x-hlb-preview" = json!(true))
    )
)]
pub async fn publish(
    auth: Authorized<CanPublish>,
    AxumState(s): AxumState<Arc<AppState>>,
    Query(q): Query<ActionQuery>,
    body: Option<Json<AnnouncementRequest>>,
) -> ActionReply {
    let d = body.map(|Json(d)| d).unwrap_or_default();
    let mut blockers = Vec::new();
    let mut warnings = Vec::new();

    let title = d.title.clone().unwrap_or_default();
    let text = d.body.clone().unwrap_or_default();
    if title.trim().is_empty() {
        blockers.push("title missing".to_string());
    }
    if text.trim().is_empty() {
        blockers.push("body missing — an announcement with no text announces nothing".to_string());
    }

    let level = hlb_api::AnnouncementLevel::parse(d.level.as_deref().unwrap_or("info"));
    let audience = d.audience.as_deref().and_then(hlb_types::Role::parse);

    // 🔴 An incident with no deadline stays open indefinitely, and that is INTENDED:
    // silence must not pass for a resolution. But you have to know it.
    if level == hlb_api::AnnouncementLevel::Incident && d.duration_s.is_none() {
        warnings.push(
            "this incident will stay displayed until someone closes it — that is \
             intended: an outage that vanishes from the screen on its own makes people \
             believe it is fixed"
                .to_string(),
        );
    }

    if audience.is_none() && level == hlb_api::AnnouncementLevel::Maintenance {
        warnings.push(
            "with no audience, this maintenance will be visible to everyone, including \
             people who only have a mailbox"
                .to_string(),
        );
    }

    let applied = q.apply && blockers.is_empty();
    let mut step = ActionStep {
        description: format!("publish \"{title}\" ({})", level.label()),
        state: StepState::Planned,
        error: None,
    };

    if applied {
        let expire = d.duration_s.map(|s| crate::auth::now().saturating_add(s));
        let asked = hlb_api::intent::PublishAnnouncement {
            title: title.clone(),
            body: text.clone(),
            level,
            pinned: d.pinned,
            audience,
            author: auth.actor().name().to_string(),
            expires_at: expire,
        };
        match s.record(asked).await {
            Ok(_) => step.state = StepState::Done,
            Err(e) => {
                step.state = StepState::Failed;
                step.error = Some(e.to_string());
            }
        }
    }

    let r = ActionResult {
        applied,
        summary: format!("publish \"{title}\""),
        steps: vec![step],
        cli_command: format!(
            "hlb announcement publish \"{title}\" \"…\" --level {}{}{} --apply",
            level.as_str(),
            if d.pinned { " --pinned" } else { "" },
            audience
                .map(|a| format!(" --audience {}", a.as_str()))
                .unwrap_or_default()
        ),
        blockers,
        warnings,
        confirmation_required: None,
    };

    respond(&s, auth.identity(), "announcement", &title, r).await
}

#[derive(Debug, Default, serde::Deserialize, utoipa::ToSchema)]
pub struct FollowUpRequest {
    #[serde(default)]
    pub body: Option<String>,
}

/// Adds an update to an incident's thread.
#[utoipa::path(
    post,
    path = "/api/announcements/{id}/follow_ups",
    params(crate::actions::ActionQuery),
    request_body = Option<FollowUpRequest>,
    responses(
        (status = 200, body = hlb_api::ActionResult),
        (status = 422, description = "Nothing could be planned: the body's `blockers` say why", body = hlb_api::ActionResult)
    ),
    extensions(
        ("x-hlb-requires" = json!("publish")),
        ("x-hlb-preview" = json!(true))
    )
)]
pub async fn follow_up(
    auth: Authorized<CanPublish>,
    AxumState(s): AxumState<Arc<AppState>>,
    Path(id): Path<i64>,
    Query(q): Query<ActionQuery>,
    body: Option<Json<FollowUpRequest>>,
) -> ActionReply {
    let d = body.map(|Json(d)| d).unwrap_or_default();
    let text = d.body.clone().unwrap_or_default();
    let mut blockers = Vec::new();

    if text.trim().is_empty() {
        blockers.push("text missing".to_string());
    }

    let applied = q.apply && blockers.is_empty();
    let mut step = ActionStep {
        // ⚠️ The word "add" is deliberate: an update is ADDED to the thread, it does not
        // replace the original message. It is the chronology you re-read afterwards.
        description: format!("add an update to the thread of announcement {id}"),
        state: StepState::Planned,
        error: None,
    };

    if applied {
        let asked = hlb_api::intent::FollowAnnouncement {
            announcement: id,
            body: text.clone(),
            author: auth.actor().name().to_string(),
        };
        match s.record(asked).await {
            Ok(()) => step.state = StepState::Done,
            Err(e) => {
                step.state = StepState::Failed;
                step.error = Some(e.to_string());
            }
        }
    }

    let r = ActionResult {
        applied,
        summary: format!("follow-up on announcement {id}"),
        steps: vec![step],
        cli_command: format!("hlb announcement follow {id} \"…\" --apply"),
        blockers,
        warnings: Vec::new(),
        confirmation_required: None,
    };

    respond(
        &s,
        auth.identity(),
        "announcement-follow_ups",
        &id.to_string(),
        r,
    )
    .await
}

/// Removes an announcement.
#[utoipa::path(
    delete,
    path = "/api/announcements/{id}",
    params(crate::actions::ActionQuery),
    responses(
        (status = 200, body = hlb_api::ActionResult),
        (status = 422, description = "Nothing could be planned: the body's `blockers` say why", body = hlb_api::ActionResult)
    ),
    extensions(
        ("x-hlb-requires" = json!("publish")),
        ("x-hlb-preview" = json!(true))
    )
)]
pub async fn remove(
    auth: Authorized<CanPublish>,
    AxumState(s): AxumState<Arc<AppState>>,
    Path(id): Path<i64>,
    Query(q): Query<ActionQuery>,
) -> ActionReply {
    let applied = q.apply;
    let mut step = ActionStep {
        description: format!("remove announcement {id}"),
        state: StepState::Planned,
        error: None,
    };

    if applied {
        match s.record(hlb_api::intent::RemoveAnnouncement { id }).await {
            Ok(true) => step.state = StepState::Done,
            Ok(false) => {
                step.state = StepState::Failed;
                step.error = Some(format!("no announcement {id}"));
            }
            Err(e) => {
                step.state = StepState::Failed;
                step.error = Some(e.to_string());
            }
        }
    }

    let r = ActionResult {
        applied,
        summary: format!("remove announcement {id}"),
        steps: vec![step],
        cli_command: format!("hlb announcement remove {id} --apply"),
        blockers: Vec::new(),
        // ⚠️ Removing erases the follow-up thread along with the announcement. For a
        // closed incident, prefer letting it expire: the history can be re-read.
        warnings: vec![
            "removing also erases the follow-up thread — for a closed incident, let it \
             expire instead: the history stays consultable"
                .to_string(),
        ],
        confirmation_required: None,
    };

    respond(
        &s,
        auth.identity(),
        "announcement-remove",
        &id.to_string(),
        r,
    )
    .await
}

async fn respond(
    s: &AppState,
    identity: &crate::auth::Identity,
    action: &str,
    target: &str,
    r: ActionResult,
) -> ActionReply {
    let issue = if !r.applied {
        "preview"
    } else if r.succeeded() {
        "ok"
    } else {
        "failed"
    };
    let _ = s
        .append_audit(
            identity.actor.name(),
            identity.role,
            action,
            target,
            issue,
            Some(&r.verdict()),
        )
        .await;
    Ok(Json(r))
}

/// Every theme a person may choose: the shipped ones, plus whatever this installation
/// declared in files.
///
/// 🔴 One function, used by BOTH the list that is offered and the check that refuses.
/// Two expressions of "which themes exist" is how a theme comes to be offered by one
/// half of the system and rejected by the other — and the person then believes their
/// choice was lost to a bug.
fn offered(s: &std::sync::Arc<crate::api::AppState>) -> Vec<String> {
    THEMES
        .iter()
        .map(|t| t.to_string())
        .chain(s.custom_themes.iter().map(|t| t.name.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn an_announced_maintenance_overrides_a_running_status() {
        assert_eq!(
            hlb_api::ServiceState::of("running", true),
            hlb_api::ServiceState::Maintenance
        );
        assert_eq!(
            hlb_api::ServiceState::of("running", false),
            hlb_api::ServiceState::Operational
        );
        assert_eq!(
            hlb_api::ServiceState::of("partial", false),
            hlb_api::ServiceState::Degraded
        );
        assert_eq!(
            hlb_api::ServiceState::of("failed", false),
            hlb_api::ServiceState::Unavailable
        );
        // An unrecognised status string is not silently "fine": it reads the same as
        // "failed", never a default that could pass for healthy.
        assert_eq!(
            hlb_api::ServiceState::of("anything-else", false),
            hlb_api::ServiceState::Unavailable
        );
    }

    #[tokio::test]
    async fn maintenance_titles_only_returns_the_maintenance_level() {
        let st = hlb_state::State::in_memory().await.expect("state");
        st.publish_announcement(
            "Maintenance on gitea",
            "body",
            hlb_api::AnnouncementLevel::Maintenance,
            false,
            None,
            "admin",
            None,
        )
        .await
        .expect("announcement");
        st.publish_announcement(
            "gitea is down",
            "body",
            hlb_api::AnnouncementLevel::Incident,
            false,
            None,
            "admin",
            None,
        )
        .await
        .expect("announcement");

        let titles = st.maintenance_titles(crate::auth::now()).await;
        assert_eq!(titles, vec!["maintenance on gitea".to_string()]);
    }

    #[tokio::test]
    async fn an_expired_maintenance_no_longer_overrides_the_live_status() {
        // 🔴 `maintenance_titles` decides the LIVE per-app state — unlike
        // `build_status`'s incident-history list, which deliberately widens to include
        // the past, this one must stay narrow: a maintenance window that ended must
        // not keep painting the service as "planned maintenance" forever.
        let st = hlb_state::State::in_memory().await.expect("state");
        let now = crate::auth::now();
        st.publish_announcement(
            "Maintenance on gitea",
            "body",
            hlb_api::AnnouncementLevel::Maintenance,
            false,
            None,
            "admin",
            Some(now - 3_600),
        )
        .await
        .expect("announcement");

        assert!(st.maintenance_titles(now).await.is_empty());
    }
}
