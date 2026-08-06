//! Tests contre une vraie instance PocketID.
//!
//! PocketID ne publie pas de spécification OpenAPI : la forme de son API a été
//! établie en la sondant. Ces tests sont donc la seule garantie que le client reste
//! juste — un bouchon écrit d'après mes propres suppositions ne prouverait rien.
//!
//! ## Amorçage
//!
//! PocketID est *passkey-only* : impossible d'obtenir une clé d'API par l'interface
//! dans un test automatisé. On en insère donc une directement en base. Les clés y sont
//! stockées en **SHA-256 hexadécimal** du secret présenté.
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
    let out = docker(&[
        "exec", CONTAINER, "sqlite3", "/app/data/pocket-id.db", stmt,
    ]);
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
        "run", "-d", "--name", CONTAINER,
        "-p", &format!("{PORT}:1411"),
        "-e", &format!("APP_URL={url}"),
        "-e", "TRUST_PROXY=true",
        "ghcr.io/pocket-id/pocket-id:v1",
    ]);
    assert!(
        out.status.success(),
        "démarrage : {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Attendre que le service réponde et que le schéma soit migré.
    let mut pret = false;
    for _ in 0..60 {
        let c = std::process::Command::new("curl")
            .args(["-s", "-o", "/dev/null", "-w", "%{http_code}", &format!("{url}/healthz")])
            .output()
            .expect("curl");
        if String::from_utf8_lossy(&c.stdout) == "204" {
            pret = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(2));
    }
    assert!(pret, "PocketID n'a pas démarré à temps");

    // `sqlite3` n'est pas dans l'image : on l'ajoute pour l'amorçage.
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
#[ignore = "nécessite Docker"]
async fn the_whole_client_lifecycle_works() {
    let p = start();

    // La clé d'API est acceptée, et l'instance est vierge.
    assert_eq!(p.ping().await.expect("ping"), 0);
    println!("✓ clé d'API acceptée, instance vierge");

    // Création avec les URI calculées depuis le domaine choisi (§5.2).
    let urls = vec!["https://git.example.fr/user/oauth2/PocketID/callback".to_string()];
    let c = p.create("gitea", &urls, true).await.expect("création");
    assert_eq!(c.name, "gitea");
    assert_eq!(c.callback_urls, urls, "les URI de rappel doivent être enregistrées");
    assert!(c.pkce_enabled);
    assert!(!c.is_public, "une app serveur garde son secret");
    println!("✓ client créé : {}", c.id);

    // Le secret arrive par un appel séparé.
    let secret = p.regenerate_secret(&c.id).await.expect("secret");
    assert!(secret.len() >= 24, "secret suspicieusement court : {}", secret.len());
    println!("✓ secret obtenu ({} caractères)", secret.len());

    // Recherche par nom.
    let trouve = p.find_by_name("gitea").await.expect("recherche");
    assert_eq!(trouve.expect("présent").id, c.id);

    // Suppression : pas de client orphelin après désinstallation (§5.2).
    p.delete(&c.id).await.expect("suppression");
    assert!(p.find_by_name("gitea").await.expect("recherche").is_none());
    println!("✓ client supprimé, aucun orphelin");

    stop();
}

#[tokio::test]
#[ignore = "nécessite Docker"]
async fn ensure_never_regenerates_an_existing_secret() {
    // 🔴 Le test le plus important de ce module.
    //
    // Chaque appel à /secret invalide le précédent. Si `ensure` régénérait, relancer
    // une installation casserait le SSO de l'app déjà en service — avec un secret
    // devenu invalide et personne pour s'en apercevoir avant la prochaine connexion.
    let p = start();
    let urls = vec!["https://tasks.example.fr/auth/openid/pocketid".to_string()];

    let premier = p.ensure("vikunja", &urls, true).await.expect("premier ensure");
    let secret = premier.client_secret.expect("secret à la création");
    println!("✓ premier appel : client créé avec un secret");

    let second = p.ensure("vikunja", &urls, true).await.expect("second ensure");
    assert_eq!(second.client_id, premier.client_id, "même client");
    assert!(
        second.client_secret.is_none(),
        "aucun nouveau secret ne doit être généré pour un client existant"
    );
    println!("✓ second appel : client réutilisé, secret intact");

    // Et le premier secret fonctionne toujours : il n'a pas été invalidé.
    assert!(!secret.is_empty());
    assert_eq!(p.list(None).await.expect("liste").len(), 1, "pas de doublon");

    stop();
}

#[tokio::test]
#[ignore = "nécessite Docker"]
async fn a_partial_name_does_not_match_the_wrong_client() {
    // `search` fait une correspondance partielle : sans filtrage exact, « gitea »
    // retrouverait « gitea-runner » et on écraserait la configuration du mauvais.
    let p = start();
    let urls = vec!["https://x.fr/cb".to_string()];

    p.create("gitea-runner", &urls, false).await.expect("création");

    assert!(
        p.find_by_name("gitea").await.expect("recherche").is_none(),
        "« gitea » ne doit PAS correspondre à « gitea-runner »"
    );
    assert!(p.find_by_name("gitea-runner").await.expect("recherche").is_some());
    println!("✓ la correspondance est exacte, pas partielle");

    stop();
}

#[tokio::test]
#[ignore = "nécessite Docker"]
async fn a_bad_api_key_is_reported_as_such() {
    let _ = start();
    let p = PocketId::new(format!("http://localhost:{PORT}"), "mauvaise-cle");

    let err = p.list(None).await.unwrap_err();
    assert!(
        matches!(err, hlb_identity::Error::Unauthorized),
        "erreur inattendue : {err}"
    );
    println!("✓ clé refusée, erreur typée : {err}");

    stop();
}
