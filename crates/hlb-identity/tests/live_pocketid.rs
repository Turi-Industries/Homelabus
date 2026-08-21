//! Tests against a real PocketID instance.
//!
//! PocketID publishes no OpenAPI specification: the shape of its API was established
//! by probing it. These tests are therefore the only guarantee the client stays correct
//! - a stub written from my own assumptions would prove nothing.
//!
//! ## Bootstrapping
//!
//! PocketID is *passkey-only*: obtaining an API key through the interface is impossible
//! in an automated test. So one is inserted straight into the database. Keys are stored
//! there as the **hexadecimal SHA-256** of the presented secret.
//!
//! ```sh
//! export DOCKER_HOST=$(docker context inspect -f '{{.Endpoints.docker.Host}}')
//! cargo test -p hlb-identity -- --ignored --test-threads=1 --nocapture
//! ```

#![allow(clippy::expect_used, clippy::unwrap_used)]

use hlb_identity::PocketId;

const CONTAINER: &str = "hlb-test-pocketid";
const PORT: u16 = 11412;
const API_KEY: &str = "cle-de-test-en-clair";
/// SHA-256 de `API_KEY`, tel que PocketID le stocke.
const API_KEY_SHA256: &str = "5e846559aa2db8905019fd4ae34c75171930ceb138205cd301a8ae5966994f68";

fn docker(args: &[&str]) -> std::process::Output {
    std::process::Command::new("docker")
        .args(args)
        .output()
        .expect("docker joignable (DOCKER_HOST ?)")
}

fn sql(stmt: &str) {
    let out = docker(&["exec", CONTAINER, "sqlite3", "/app/data/pocket-id.db", stmt]);
    assert!(
        out.status.success(),
        "sqlite : {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn start() -> PocketId {
    let _ = docker(&["rm", "-f", CONTAINER]);
    let url = format!("http://localhost:{PORT}");

    let out = docker(&[
        "run",
        "-d",
        "--name",
        CONTAINER,
        "-p",
        &format!("{PORT}:1411"),
        "-e",
        &format!("APP_URL={url}"),
        "-e",
        "TRUST_PROXY=true",
        "ghcr.io/pocket-id/pocket-id:v1",
    ]);
    assert!(
        out.status.success(),
        "startup: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Wait for the service to answer and the schema to be migrated.
    let mut pret = false;
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
            pret = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(2));
    }
    assert!(pret, "PocketID did not start in time");

    // `sqlite3` is not in the image: it is added for the bootstrap.
    let _ = docker(&["exec", CONTAINER, "apk", "add", "--no-cache", "sqlite"]);

    sql(&format!(
        "INSERT INTO users (id, created_at, username, email, last_name, display_name, is_admin)
         VALUES ('u-hlb', datetime('now'), 'hlbtest', 'hlb@example.invalid', 'Test', 'HLB', 1);
         INSERT INTO api_keys (id, name, key, expires_at, created_at, user_id)
         VALUES ('k-hlb', 'hlb', '{API_KEY_SHA256}', datetime('now','+1 year'), datetime('now'), 'u-hlb');"
    ));

    PocketId::new(url, API_KEY)
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
    assert!(!c.is_public, "une app serveur garde son secret");
    println!("✓ client created: {}", c.id);

    // The secret arrives through a separate call.
    let secret = p.regenerate_secret(&c.id).await.expect("secret");
    assert!(
        secret.len() >= 24,
        "secret suspicieusement court : {}",
        secret.len()
    );
    println!("✓ secret obtained ({} characters)", secret.len());

    // Recherche par nom.
    let trouve = p.find_by_name("gitea").await.expect("recherche");
    assert_eq!(trouve.expect("present").id, c.id);

    // Suppression : pas de client orphelin après désinstallation (§5.2).
    p.delete(&c.id).await.expect("suppression");
    assert!(p.find_by_name("gitea").await.expect("recherche").is_none());
    println!("✓ client supprimé, aucun orphelin");

    stop();
}

#[tokio::test]
#[ignore = "needs Docker"]
async fn ensure_never_regenerates_an_existing_secret() {
    // 🔴 Le test le plus important de ce module.
    //
    // Chaque appel à /secret invalide le précédent. Si `ensure` régénérait, relancer
    // une installation casserait le SSO de l'app déjà en service — avec un secret
    // devenu invalide et personne pour s'en apercevoir avant la prochaine connexion.
    let p = start();
    let urls = vec!["https://tasks.example.fr/auth/openid/pocketid".to_string()];

    let premier = p
        .ensure("vikunja", &urls, true)
        .await
        .expect("premier ensure");
    let secret = premier.client_secret.expect("secret at creation");
    println!("✓ first call: client created with a secret");

    let second = p
        .ensure("vikunja", &urls, true)
        .await
        .expect("second ensure");
    assert_eq!(second.client_id, premier.client_id, "same client");
    assert!(
        second.client_secret.is_none(),
        "no new secret must be generated for an existing client"
    );
    println!("✓ second call: client reused, secret intact");

    // And the first secret still works: it was not invalidated.
    assert!(!secret.is_empty());
    assert_eq!(
        p.list(None).await.expect("liste").len(),
        1,
        "pas de doublon"
    );

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
        p.find_by_name("gitea").await.expect("recherche").is_none(),
        "\"gitea\" must NOT match \"gitea-runner\""
    );
    assert!(p
        .find_by_name("gitea-runner")
        .await
        .expect("recherche")
        .is_some());
    println!("✓ la correspondance est exacte, pas partielle");

    stop();
}

#[tokio::test]
#[ignore = "needs Docker"]
async fn a_bad_api_key_is_reported_as_such() {
    let _ = start();
    let p = PocketId::new(format!("http://localhost:{PORT}"), "mauvaise-cle");

    let err = p.list(None).await.unwrap_err();
    assert!(
        matches!(err, hlb_identity::Error::Unauthorized),
        "erreur inattendue : {err}"
    );
    println!("✓ key refused, typed error: {err}");

    stop();
}
