//! Tests against a real PocketID instance.
//!
//! PocketID publishes no OpenAPI specification: the shape of its API was established
//! by probing it. These tests are therefore the only guarantee the client stays correct
//! - a stub written from my own assumptions would prove nothing.
//!
//! ## Bootstrapping
//!
//! PocketID is *passkey-only*: nobody can sign in to create an API key in a test. The
//! key is the one the catalog's manifest sets at install (`STATIC_API_KEY`, v2.2+), so
//! these tests prove that bootstrap too — and they run the image the catalog names, so
//! a manifest moving to another version moves them with it.
//!
//! ```sh
//! export DOCKER_HOST=$(docker context inspect -f '{{.Endpoints.docker.Host}}')
//! cargo test -p hlb-identity -- --ignored --test-threads=1 --nocapture
//! ```

#![allow(clippy::expect_used, clippy::unwrap_used)]

use hlb_identity::PocketId;

const CONTAINER: &str = "hlb-test-pocketid";
const PORT: u16 = 11412;
/// PocketID refuses to start on a static key shorter than 16 characters.
const API_KEY: &str = "plaintext-test-key-0123456789";

/// The image and the environment variables the catalog's manifest gives PocketID.
fn manifest() -> hlb_types::manifest::Manifest {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../catalog/_platform/pocket-id/manifest.yaml"
    );
    serde_yaml_ng::from_str(&std::fs::read_to_string(path).expect("manifest")).expect("parsed")
}

fn docker(args: &[&str]) -> std::process::Output {
    std::process::Command::new("docker")
        .args(args)
        .output()
        .expect("docker reachable (DOCKER_HOST ?)")
}

fn start() -> PocketId {
    let _ = docker(&["rm", "-f", CONTAINER]);
    let url = format!("http://localhost:{PORT}");
    let m = manifest();
    let env = &m.spec.env;
    assert_eq!(
        env.get("STATIC_API_KEY").map(String::as_str),
        Some("{{ secret.api-key }}"),
        "the key Homelabus calls PocketID with is the one the manifest sets"
    );

    let mut args = vec![
        "run".to_string(),
        "-d".into(),
        "--name".into(),
        CONTAINER.into(),
        "-p".into(),
        format!("{PORT}:1411"),
    ];
    // Every variable the manifest sets, its templates filled the way an install would.
    for (k, v) in env {
        let v = match k.as_str() {
            "APP_URL" => url.clone(),
            "STATIC_API_KEY" => API_KEY.to_string(),
            "ENCRYPTION_KEY" => "test-encryption-key-0123456789".to_string(),
            _ => {
                assert!(
                    !v.contains("{{"),
                    "{k}={v}: a template this test does not fill"
                );
                v.clone()
            }
        };
        args.extend(["-e".to_string(), format!("{k}={v}")]);
    }
    args.push(m.spec.image.reference());
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let out = docker(&args);
    assert!(
        out.status.success(),
        "startup: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Wait for the service to answer and the schema to be migrated.
    let mut ready = false;
    for _ in 0..60 {
        let c = std::process::Command::new("curl")
            .args([
                "-s",
                "-o",
                "/dev/null",
                "-w",
                "%{http_code}",
                &format!("{url}/healthz"),
            ])
            .output()
            .expect("curl");
        if String::from_utf8_lossy(&c.stdout) == "204" {
            ready = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(2));
    }
    assert!(ready, "PocketID did not start in time");

    PocketId::new(url, API_KEY)
}

/// An administrator, created as `/setup` would: [`PocketId::create_user`] never makes
/// one, and an administrator is the account a careless update would demote.
async fn administrator() -> String {
    let created: serde_json::Value = reqwest::Client::new()
        .post(format!("http://localhost:{PORT}/api/users"))
        .header("X-API-KEY", API_KEY)
        .json(&serde_json::json!({
            "username": "hlbtest", "email": "hlb@example.invalid", "firstName": "HLB",
            "lastName": "Test", "displayName": "HLB", "isAdmin": true,
        }))
        .send()
        .await
        .expect("created")
        .error_for_status()
        .expect("accepted")
        .json()
        .await
        .expect("json");
    created["id"].as_str().expect("id").to_string()
}

fn stop() {
    let _ = docker(&["rm", "-f", CONTAINER]);
}

#[tokio::test]
#[ignore = "needs Docker"]
async fn the_whole_client_lifecycle_works() {
    let p = start();

    // The API key is accepted, and the instance is empty.
    assert_eq!(p.ping().await.expect("ping"), 0);
    println!("✓ API key accepted, instance empty");

    // Creation with the URIs computed from the chosen domain.
    let urls = vec!["https://git.example.fr/user/oauth2/PocketID/callback".to_string()];
    let c = p.create("gitea", &urls, true).await.expect("creation");
    assert_eq!(c.name, "gitea");
    assert_eq!(
        c.callback_urls, urls,
        "the callback URIs must be registered"
    );
    assert!(c.pkce_enabled);
    assert!(!c.is_public, "a server-side app keeps its secret");
    println!("✓ client created: {}", c.id);

    // The secret arrives through a separate call.
    let secret = p.regenerate_secret(&c.id).await.expect("secret");
    assert!(
        secret.len() >= 24,
        "suspiciously short secret: {}",
        secret.len()
    );
    println!("✓ secret obtained ({} characters)", secret.len());

    // Search by name.
    let found = p.find_by_name("gitea").await.expect("search");
    assert_eq!(found.expect("present").id, c.id);

    // Deletion: no orphan client left after an uninstall.
    p.delete(&c.id).await.expect("deletion");
    assert!(p.find_by_name("gitea").await.expect("search").is_none());
    println!("client deleted, no orphan left");

    stop();
}

#[tokio::test]
#[ignore = "needs Docker"]
async fn ensure_never_regenerates_an_existing_secret() {
    // 🔴 The most important test in this module.
    //
    // Before v2.15 every call to /secret invalidates the previous one: if `ensure`
    // regenerated, rerunning an install would break the SSO of an app already in
    // service. From v2.15 each call adds an active secret nobody holds.
    let p = start();
    let urls = vec!["https://tasks.example.fr/auth/openid/pocketid".to_string()];

    let first = p
        .ensure("vikunja", &urls, true)
        .await
        .expect("first ensure");
    let secret = first.client_secret.expect("secret at creation");
    println!("✓ first call: client created with a secret");

    let second = p
        .ensure("vikunja", &urls, true)
        .await
        .expect("second ensure");
    assert_eq!(second.client_id, first.client_id, "same client");
    assert!(
        second.client_secret.is_none(),
        "no new secret must be generated for an existing client"
    );
    println!("✓ second call: client reused, secret intact");

    // And the first secret still works: it was not invalidated.
    assert!(!secret.is_empty());
    // The secret creation answered with is the only one: asking for another on top
    // would leave an active secret nobody holds.
    let secrets: serde_json::Value = reqwest::Client::new()
        .get(format!(
            "http://localhost:{PORT}/api/oidc/clients/{}/secrets",
            first.client_id
        ))
        .header("X-API-KEY", API_KEY)
        .send()
        .await
        .expect("secrets")
        .json()
        .await
        .expect("json");
    let active = secrets
        .as_array()
        .or_else(|| secrets["data"].as_array())
        .expect("a list")
        .iter()
        .filter(|s| s["isActive"] == true)
        .count();
    assert_eq!(active, 1, "{secrets}");
    assert_eq!(p.list(None).await.expect("list").len(), 1, "no duplicate");

    stop();
}

#[tokio::test]
#[ignore = "needs Docker"]
async fn a_partial_name_does_not_match_the_wrong_client() {
    // `search` does a partial match: without exact filtering, "gitea" would also find
    // "gitea-runner" and the wrong one's configuration would be overwritten.
    let p = start();
    let urls = vec!["https://x.fr/cb".to_string()];

    p.create("gitea-runner", &urls, false)
        .await
        .expect("creation");

    assert!(
        p.find_by_name("gitea").await.expect("search").is_none(),
        "\"gitea\" must NOT match \"gitea-runner\""
    );
    assert!(p
        .find_by_name("gitea-runner")
        .await
        .expect("search")
        .is_some());
    println!("✓ the match is exact, not partial");

    stop();
}

#[tokio::test]
#[ignore = "needs Docker"]
async fn a_bad_api_key_is_reported_as_such() {
    let _ = start();
    let p = PocketId::new(format!("http://localhost:{PORT}"), "wrong-key");

    let err = p.list(None).await.unwrap_err();
    assert!(
        matches!(err, hlb_identity::Error::Unauthorized),
        "unexpected error: {err}"
    );
    println!("✓ key refused, typed error: {err}");

    stop();
}

#[tokio::test]
#[ignore = "needs Docker"]
async fn a_person_changes_their_names_without_losing_their_rights() {
    // The update overwrites `isAdmin` with whatever it is sent, so an administrator
    // is the account a careless body would demote.
    let p = start();
    let id = administrator().await;

    let after = p
        .update_user(
            &id,
            &hlb_identity::UserChange::Names {
                first: "Léna".into(),
                last: "Martin".into(),
                display: "Léna M.".into(),
            },
        )
        .await
        .expect("names changed");
    assert_eq!(after.display_name, "Léna M.");
    assert_eq!(after.last_name.as_deref(), Some("Martin"));
    assert!(after.is_admin, "a name change demoted an administrator");
    assert_eq!(after.username, "hlbtest");

    let after = p
        .update_user(
            &id,
            &hlb_identity::UserChange::Email("contact@example.invalid".into()),
        )
        .await
        .expect("address changed");
    assert_eq!(after.email.as_deref(), Some("contact@example.invalid"));
    assert_eq!(
        after.display_name, "Léna M.",
        "the address change kept the names"
    );

    let read = p.user(&id).await.expect("read back");
    assert_eq!(read, after);
    println!("✓ names and address changed, administrator still an administrator");

    stop();
}

#[tokio::test]
#[ignore = "needs Docker"]
async fn a_callback_is_added_and_nothing_else_moves() {
    // The portal's client collects one callback per protected app. An update that sent
    // only the URLs would reset PKCE or turn the client public — and nothing would say
    // so until a sign-in failed.
    let p = start();
    let first = vec!["https://auth.example.fr/oauth2/callback".to_string()];
    let c = p
        .create("oauth2-proxy", &first, true)
        .await
        .expect("creation");

    let added = p
        .add_callback_url("oauth2-proxy", "https://wiki.example.fr/oauth2/callback")
        .await
        .expect("add");
    assert!(added);
    let again = p
        .add_callback_url("oauth2-proxy", "https://wiki.example.fr/oauth2/callback")
        .await
        .expect("add twice");
    assert!(!again, "a second add must change nothing");

    let after = p
        .find_by_name("oauth2-proxy")
        .await
        .expect("read")
        .expect("present");
    assert_eq!(after.id, c.id);
    assert_eq!(
        after.callback_urls,
        vec![
            "https://auth.example.fr/oauth2/callback".to_string(),
            "https://wiki.example.fr/oauth2/callback".to_string(),
        ]
    );
    assert!(after.pkce_enabled, "PKCE survived the update");
    assert!(!after.is_public, "the client stayed confidential");
    println!("✓ callback added, the rest of the client unchanged");
    stop();
}

#[tokio::test]
#[ignore = "needs Docker"]
async fn a_new_person_gets_a_link_that_signs_them_in_once() {
    // 🔴 The first thing an invited person receives. Sent with the person in the path
    // only, PocketID 1.16 answered 500 on a foreign key: no enrolment link had ever been
    // obtained from a real server.
    let p = start();
    let u = p
        .create_user("camille", Some("camille@example.invalid"), "Camille", &[])
        .await
        .expect("created");
    let token = p.one_time_token(&u.id, "12h").await.expect("a token");
    assert!(!token.is_empty());

    // Exchanged once, it signs in as that person; twice, it is refused.
    let http = reqwest::Client::new();
    let url = format!("http://localhost:{PORT}/api/one-time-access-token/{token}");
    let first = http.post(&url).send().await.expect("exchange");
    assert!(first.status().is_success(), "{}", first.status());
    let who: serde_json::Value = first.json().await.expect("json");
    assert_eq!(who["username"], "camille", "{who}");
    let again = http.post(&url).send().await.expect("exchange");
    assert!(
        !again.status().is_success(),
        "a single-use link was used twice"
    );
    println!("✓ an enrolment link, exchanged once for that person");

    stop();
}

/// What the client's app would read for this person — PocketID's own preview of the
/// ID token, which refuses as the sign-in does when they may not enter.
async fn id_token(client: &str, user: &str) -> Result<serde_json::Value, u16> {
    let r = reqwest::Client::new()
        .get(format!(
            "http://localhost:{PORT}/api/oidc/clients/{client}/preview/{user}?scopes=openid%20profile%20groups"
        ))
        .header("X-API-KEY", API_KEY)
        .send()
        .await
        .expect("preview");
    if !r.status().is_success() {
        return Err(r.status().as_u16());
    }
    Ok(r.json::<serde_json::Value>().await.expect("json")["idToken"].clone())
}

#[tokio::test]
#[ignore = "needs Docker"]
async fn a_role_is_a_group_whose_claims_reach_its_members_tokens() {
    use std::collections::{BTreeMap, BTreeSet};
    let pid = start();
    let lena = pid
        .create_user("lena", Some("lena@example.org"), "Léna", &[])
        .await
        .expect("lena");
    let sacha = pid
        .create_user("sacha", Some("sacha@example.org"), "Sacha", &[])
        .await
        .expect("sacha");
    let gitea = pid
        .create("gitea", &["https://g.example.org/cb".into()], false)
        .await
        .expect("client");

    // Before any restriction: everyone gets in. That is PocketID's default, and why
    // an app is always written restricted.
    assert!(id_token(&gitea.id, &sacha.id).await.is_ok());

    let family = pid
        .create_group("hlb-family", "Family")
        .await
        .expect("group");
    pid.set_members(&family, &BTreeSet::from([lena.id.clone()]))
        .await
        .expect("members");
    let claims = BTreeMap::from([
        ("hlb_gitea".to_string(), serde_json::json!("admin")),
        ("immich_quota".to_string(), serde_json::json!(50)),
        ("as_text".to_string(), serde_json::json!("5")),
        (
            "vikunja_groups".to_string(),
            serde_json::json!([{ "name": "Family", "oidcID": "hlb-family" }]),
        ),
    ]);
    pid.set_group_claims(&family, &claims)
        .await
        .expect("claims");
    let read = pid.group(&family).await.expect("group");
    assert_eq!(read.members, BTreeSet::from([lena.id.clone()]));
    assert_eq!(read.claims, claims, "each claim comes back as written");
    assert_eq!(
        pid.groups("hlb-").await.expect("list").len(),
        1,
        "found by its prefix"
    );

    pid.restrict_client(&gitea.id, &BTreeSet::from([family.clone()]))
        .await
        .expect("restricted");
    assert_eq!(
        pid.client_groups(&gitea.id).await.expect("read"),
        (true, BTreeSet::from([family.clone()]))
    );
    let token = id_token(&gitea.id, &lena.id).await.expect("lena enters");
    assert_eq!(token["hlb_gitea"], "admin");
    assert_eq!(token["immich_quota"], 50);
    assert_eq!(token["as_text"], "5", "a string stays a string");
    assert_eq!(token["vikunja_groups"][0]["oidcID"], "hlb-family");
    assert_eq!(token["groups"], serde_json::json!(["hlb-family"]));
    assert!(
        id_token(&gitea.id, &sacha.id).await.is_err(),
        "someone in no allowed group is refused"
    );

    // A person's own claim beats their group's: a quota given to one person.
    pid.set_user_claims(
        &lena.id,
        &BTreeMap::from([("immich_quota".to_string(), serde_json::json!(200))]),
    )
    .await
    .expect("own claim");
    assert_eq!(
        id_token(&gitea.id, &lena.id).await.expect("token")["immich_quota"],
        200
    );
    assert_eq!(
        pid.user_claims(&lena.id).await.expect("read")["immich_quota"],
        200
    );

    // Restricted to no group: nobody, not even lena.
    pid.restrict_client(&gitea.id, &BTreeSet::new())
        .await
        .expect("closed");
    assert!(
        id_token(&gitea.id, &lena.id).await.is_err(),
        "closed is closed"
    );

    pid.rename_group(&family, "hlb-family", "Family and friends")
        .await
        .expect("renamed");
    assert_eq!(
        pid.group(&family).await.expect("group").friendly_name,
        "Family and friends"
    );
    pid.delete_group(&family).await.expect("deleted");
    assert!(pid.groups("hlb-").await.expect("list").is_empty());
    stop();
    println!("✓ a role's group, its members, its claims and the client it opens");
}
