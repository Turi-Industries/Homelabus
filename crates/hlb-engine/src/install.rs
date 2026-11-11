//! What an install runs from, and when it is recorded.
//!
//! One answer for `hlb install` and the interface's install: an app is recorded — its
//! manifest frozen, its domain kept — only by a run that applies, and a run over an app
//! already recorded resumes it rather than freezing the catalog's manifest again.

use hlb_state::State;
use hlb_types::{Guide, Manifest};

/// Where a catalog entry came from: its source — `None` the official catalog — and
/// the counter of the signed index it came in and its version there, if one.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Origin<'a> {
    pub source: Option<&'a str>,
    pub index: Option<u64>,
    pub version: Option<&'a str>,
}

impl Origin<'_> {
    /// What is frozen with the install, and moved by an upgrade.
    pub fn release(&self) -> hlb_state::Release {
        hlb_state::Release {
            index: self.index,
            version: self.version.map(str::to_string),
        }
    }
}

/// What an install of an app plans and freezes.
#[derive(Debug, Clone)]
pub struct Basis {
    /// The catalog source it is installed from, `None` for the official one.
    pub source: Option<String>,
    /// The signed index it is installed from, and its version there.
    pub release: hlb_state::Release,
    pub manifest: Manifest,
    /// The guide it plans with, frozen beside the manifest.
    pub guide: Guide,
    pub domain: Option<String>,
    pub mail_domain: Option<String>,
    /// The app is recorded already: this run resumes it.
    pub resumed: Option<String>,
}

/// The basis of an install of `app`, read without writing.
///
/// A new app takes the catalog's manifest and guide and the domains asked for. One
/// already recorded keeps the manifest and guide frozen at its install — its resolved
/// digests included — and the domains it took.
///
/// 🔴 Frozen again from the catalog, a rerun replaced what an earlier run had resolved
/// (an image built here lost its digest, and the deployment stayed refused as
/// unpinned) and skipped `hlb upgrade`'s refusals of what strands data. A catalog
/// change reaches a recorded app through `hlb upgrade`.
///
/// `Err` is a refusal to say: a domain that is not a domain name, one another app or
/// the platform answers at already, one asked for that is not the one the app has, or
/// an app of that name installed from another catalog source.
///
/// 🔴 `community/foo` installs as `foo` — its service, volumes and databases keep the
/// bare name — so it never sits beside an official `foo`: the second would take over
/// the first's volumes and database. `origin` is the catalog entry's.
pub async fn basis(
    state: &State,
    app: &str,
    origin: Origin<'_>,
    catalog: &Manifest,
    catalog_guide: &Guide,
    domain: Option<String>,
    mail_domain: Option<String>,
) -> crate::Result<std::result::Result<Basis, String>> {
    let (domain, mail_domain) = match (canonical(domain), canonical(mail_domain)) {
        (Ok(d), Ok(m)) => (d, m),
        (Err(refusal), _) | (_, Err(refusal)) => return Ok(Err(refusal)),
    };
    let Some((_, status)) = state
        .installed_apps()
        .await?
        .into_iter()
        .find(|(n, _)| n == app)
    else {
        if let Some(d) = &domain {
            if let Some(refusal) = taken(state, app, catalog, d).await? {
                return Ok(Err(refusal));
            }
        }
        return Ok(Ok(Basis {
            source: origin.source.map(str::to_string),
            release: origin.release(),
            manifest: catalog.clone(),
            guide: catalog_guide.clone(),
            domain,
            mail_domain,
            resumed: None,
        }));
    };
    let source = origin.source;
    let installed_from = state.app_source(app).await?;
    if installed_from.as_deref() != source {
        let from = |s: Option<&str>| match s {
            Some(s) => format!("the source \"{s}\""),
            None => "the official catalog".to_string(),
        };
        return Ok(Err(format!(
            "\"{app}\" is installed from {} — {} has an app of the same name, and the two \
             would share its services, volumes and databases: remove one before installing \
             the other",
            from(installed_from.as_deref()),
            from(source)
        )));
    }
    let recorded = state.app_domain(app).await?;
    if let Some(asked) = domain
        .as_deref()
        .filter(|d| recorded.as_deref() != Some(*d))
    {
        return Ok(Err(format!(
            "\"{app}\" is installed at {} — an install resumes it there, and does not \
             move it to {asked}",
            recorded.as_deref().unwrap_or("no domain")
        )));
    }
    Ok(Ok(Basis {
        source: installed_from,
        release: state.app_release(app).await?,
        manifest: state.app_manifest(app).await?,
        guide: installed_guide(state, app, || Some(catalog_guide.clone())).await?,
        domain: recorded,
        mail_domain: state.app_mail_domain(app).await?.or(mail_domain),
        resumed: Some(status),
    }))
}

/// The guide an app follows: the one frozen with its manifest, else — an app recorded
/// before guides were frozen, or not recorded yet — the catalog's, which `catalog` reads.
///
/// 🔴 Read from today's catalog, an acknowledgement, a nightly re-check or a restore
/// followed steps the running manifest was never deployed with, and found none once
/// the app left the catalog.
pub async fn installed_guide(
    state: &State,
    app: &str,
    catalog: impl FnOnce() -> Option<Guide>,
) -> crate::Result<Guide> {
    match state.app_guide(app).await {
        Ok(Some(frozen)) => Ok(frozen),
        Ok(None) | Err(hlb_state::Error::UnknownApp(_)) => Ok(catalog().unwrap_or_default()),
        // Unreadable is said, never replaced by the catalog's.
        Err(e) => Err(e.into()),
    }
}

fn canonical(d: Option<String>) -> std::result::Result<Option<String>, String> {
    d.map(|d| hlb_types::domain::parse(&d)).transpose()
}

/// Why a new app may not answer at `domain`: a name it would serve is another app's,
/// or the interface's.
///
/// 🔴 The Caddyfile keeps ONE site per name, and which of two apps keeps it follows
/// their order: an app installed at PocketID's name could have taken every sign-in.
async fn taken(
    state: &State,
    app: &str,
    manifest: &Manifest,
    domain: &str,
) -> crate::Result<Option<String>> {
    let hosts = |m: &Manifest, d: Option<&str>| -> Vec<String> {
        let mut h: Vec<String> = hlb_ingress::routes_from_manifest(m, d, true)
            .into_iter()
            .map(|r| r.host)
            .collect();
        h.extend(d.map(str::to_string));
        h
    };
    let wanted = hosts(manifest, Some(domain));
    if let Some(e) = state.exposure().await? {
        let interface = e.controller_host();
        if wanted.contains(&interface) {
            return Ok(Some(format!(
                "{interface} is where the interface answers — choose another domain"
            )));
        }
    }
    for (other, _) in state.installed_apps().await? {
        if other == app {
            continue;
        }
        let d = state.app_domain(&other).await?;
        let theirs = hosts(&state.app_manifest(&other).await?, d.as_deref());
        if let Some(h) = wanted.iter().find(|h| theirs.contains(h)) {
            return Ok(Some(format!(
                "{h} is where \"{other}\" answers — choose another domain"
            )));
        }
    }
    Ok(None)
}

/// Records the app — only by a run that applies, right before it executes: recording
/// first is what makes the run resumable if it stops halfway.
pub async fn record(state: &State, app: &str, basis: &Basis) -> crate::Result<()> {
    if basis.resumed.is_none() {
        state
            .upsert_app(app, &basis.manifest, basis.domain.as_deref())
            .await?;
        state.set_app_guide(app, Some(&basis.guide)).await?;
        state
            .set_app_source(app, basis.source.as_deref(), &basis.release)
            .await?;
    }
    state
        .set_app_mail_domain(app, basis.mail_domain.as_deref())
        .await?;
    Ok(())
}

/// Whether a vital app's databases are placed on the vital server: it is recorded —
/// the graph reads the same, and recording it pinned every older database where it is.
pub async fn vital_postgres(state: &State) -> crate::Result<bool> {
    Ok(state
        .installed_apps()
        .await?
        .iter()
        .any(|(name, _)| name == hlb_types::VITAL_POSTGRES))
}

/// The mail domain an app's plan is resolved with again — an upgrade, a redeployment:
/// one named now, else the one its install took, else the exposure's.
pub async fn mail_domain(
    state: &State,
    app: &str,
    named: Option<String>,
) -> crate::Result<Option<String>> {
    if let Some(named) = named {
        return hlb_types::domain::parse(&named)
            .map(Some)
            .map_err(crate::Error::Domain);
    }
    if let Some(kept) = state.app_mail_domain(app).await? {
        return Ok(Some(kept));
    }
    Ok(state.exposure().await?.map(|e| e.domain))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(name: &str) -> Manifest {
        serde_yaml_ng::from_str(&format!(
            "apiVersion: hlb/v1\nkind: App\nmetadata: {{ name: {name} }}\nspec:\n  \
             image: {{ repo: x/{name}, tag: \"1\" }}\n  ingress:\n    \
             - host: \"{{{{ domain }}}}\"\n      port: 80\n"
        ))
        .expect("test manifest")
    }

    async fn refusal(state: &State, app: &str, domain: &str, mail: Option<&str>) -> String {
        basis(
            state,
            app,
            Origin::default(),
            &manifest(app),
            &Default::default(),
            Some(domain.into()),
            mail.map(str::to_string),
        )
        .await
        .expect("state")
        .expect_err("refused")
    }

    #[tokio::test]
    async fn a_vital_app_is_placed_on_the_vital_server_once_it_is_recorded() {
        let state = State::in_memory().await.expect("state");
        state
            .upsert_app("gitea", &manifest("gitea"), None)
            .await
            .expect("upsert");
        assert!(!vital_postgres(&state).await.expect("read"));
        let vital = hlb_types::VITAL_POSTGRES;
        state
            .upsert_app(vital, &manifest(vital), None)
            .await
            .expect("upsert");
        assert!(vital_postgres(&state).await.expect("read"));
    }

    #[tokio::test]
    async fn a_domain_that_would_write_caddyfile_directives_is_refused() {
        let state = State::in_memory().await.expect("state");
        let r = refusal(
            &state,
            "gitea",
            "git.example.org {\n\tfile_server\n}\nx.example.org",
            None,
        )
        .await;
        assert!(r.contains("not a domain name"), "{r}");
        let r = refusal(&state, "gitea", "git.example.org", Some("example.org}")).await;
        assert!(r.contains("not a domain name"), "{r}");
    }

    #[tokio::test]
    async fn a_domain_another_app_answers_at_is_refused() {
        let state = State::in_memory().await.expect("state");
        state
            .upsert_app("pocket-id", &manifest("pocket-id"), Some("id.example.org"))
            .await
            .expect("app");
        let r = refusal(&state, "gitea", "ID.example.org.", None).await;
        assert!(r.contains("pocket-id"), "{r}");
    }

    #[tokio::test]
    async fn the_interfaces_name_is_refused() {
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
        let r = refusal(&state, "gitea", "hlb.example.org", None).await;
        assert!(r.contains("interface"), "{r}");
    }

    #[tokio::test]
    async fn a_free_domain_is_taken_canonical() {
        let state = State::in_memory().await.expect("state");
        let b = basis(
            &state,
            "gitea",
            Origin::default(),
            &manifest("gitea"),
            &Default::default(),
            Some(" Git.Example.org ".into()),
            Some("Example.org".into()),
        )
        .await
        .expect("state")
        .expect("accepted");
        assert_eq!(b.domain.as_deref(), Some("git.example.org"));
        assert_eq!(b.mail_domain.as_deref(), Some("example.org"));
    }

    #[tokio::test]
    async fn an_install_freezes_the_catalogs_guide_and_a_resume_keeps_it() {
        let state = State::in_memory().await.expect("state");
        let guide = |id: &str| -> Guide {
            serde_yaml_ng::from_str(&format!("steps:\n  - {{ id: {id}, title: T }}\n"))
                .expect("guide")
        };
        let ids = |g: &Guide| g.steps.iter().map(|s| s.id.clone()).collect::<Vec<_>>();
        let first = basis(
            &state,
            "gitea",
            Origin::default(),
            &manifest("gitea"),
            &guide("dns"),
            None,
            None,
        )
        .await
        .expect("state")
        .expect("accepted");
        record(&state, "gitea", &first).await.expect("recorded");
        let frozen = state
            .app_guide("gitea")
            .await
            .expect("read")
            .expect("frozen");
        assert_eq!(ids(&frozen), ["dns"]);

        // The catalog's guide changed since: a resume plans with the one installed.
        let again = basis(
            &state,
            "gitea",
            Origin::default(),
            &manifest("gitea"),
            &guide("other"),
            None,
            None,
        )
        .await
        .expect("state")
        .expect("resumable");
        assert_eq!(ids(&again.guide), ["dns"]);
    }

    #[tokio::test]
    async fn an_upgrades_mail_domain_is_checked_too() {
        let state = State::in_memory().await.expect("state");
        assert!(mail_domain(&state, "gitea", Some("a b".into()))
            .await
            .is_err());
    }
}
