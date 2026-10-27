//! The roles' sync against a real PocketID, and a real Seafile's quota.
//!
//! What PocketID gives an app is read back the way the app gets it — PocketID's own
//! preview of the ID token, which also refuses as the sign-in does — so a claim written
//! but never reaching a token, or a restriction set and not obeyed, fails here.
//!
//! ```sh
//! cargo test -p hlb-engine --test live_roles -- --ignored --test-threads=1 --nocapture
//! ```

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeMap;

use async_trait::async_trait;
use hlb_engine::roles::{Outcome, Report, RoleSync};
use hlb_identity::PocketId;
use hlb_orchestrator::{Orchestrator, ServiceSpec, ServiceStatus};
use hlb_secrets::Vault;
use hlb_state::State;

const POCKETID: &str = "hlb-test-roles-pocketid";
const PORT: u16 = 11413;
const KEY: &str = "plaintext-test-key-0123456789";

fn docker(args: &[&str]) -> std::process::Output {
    std::process::Command::new("docker")
        .args(args)
        .output()
        .expect("docker reachable")
}

fn catalog(path: &str) -> hlb_types::Manifest {
    let p = format!(
        "{}/../../catalog/{path}/manifest.yaml",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_yaml_ng::from_str(&std::fs::read_to_string(p).expect("manifest")).expect("parsed")
}

fn wait_for(url: &str, code: &str) {
    for _ in 0..90 {
        let c = std::process::Command::new("curl")
            .args(["-s", "-o", "/dev/null", "-w", "%{http_code}", url])
            .output()
            .expect("curl");
        if String::from_utf8_lossy(&c.stdout) == code {
            return;
        }
        std::thread::sleep(std::time::Duration::from_secs(2));
    }
    panic!("{url} never answered {code}");
}

/// PocketID on the catalog's image, at the key Homelabus would have generated.
fn pocketid() -> PocketId {
    let _ = docker(&["rm", "-f", POCKETID]);
    let url = format!("http://localhost:{PORT}");
    let image = catalog("_platform/pocket-id").spec.image.reference();
    let out = docker(&[
        "run",
        "-d",
        "--name",
        POCKETID,
        "-p",
        &format!("{PORT}:1411"),
        "-e",
        &format!("APP_URL={url}"),
        "-e",
        "TRUST_PROXY=true",
        "-e",
        "ENCRYPTION_KEY=test-encryption-key-0123456789",
        "-e",
        &format!("STATIC_API_KEY={KEY}"),
        &image,
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    wait_for(&format!("{url}/healthz"), "204");
    PocketId::new(url, KEY)
}

/// The ID token an app would get for this person, or the refusal.
async fn token(client: &str, user: &str) -> Result<serde_json::Value, u16> {
    let r = reqwest::Client::new()
        .get(format!(
            "http://localhost:{PORT}/api/oidc/clients/{client}/preview/{user}?scopes=openid%20profile%20email%20groups"
        ))
        .header("X-API-KEY", KEY)
        .send()
        .await
        .expect("preview");
    if !r.status().is_success() {
        return Err(r.status().as_u16());
    }
    Ok(r.json::<serde_json::Value>().await.expect("json")["idToken"].clone())
}

/// Writes a person's address as PocketID's own account page would leave it.
async fn set_address(user: &str, email: &str, verified: bool) {
    let url = format!("http://localhost:{PORT}/api/users/{user}");
    let http = reqwest::Client::new();
    let mut body: serde_json::Value = http
        .get(&url)
        .header("X-API-KEY", KEY)
        .send()
        .await
        .expect("read")
        .json()
        .await
        .expect("json");
    body["email"] = email.into();
    body["emailVerified"] = verified.into();
    if body["lastName"].is_null() {
        body["lastName"] = "".into();
    }
    let r = http
        .put(&url)
        .header("X-API-KEY", KEY)
        .json(&body)
        .send()
        .await
        .expect("write");
    assert!(r.status().is_success(), "{}", r.text().await.unwrap());
}

/// An orchestrator whose `exec` enters a container on this machine by name.
#[derive(Default)]
struct Local {
    containers: BTreeMap<String, String>,
}

#[async_trait]
impl Orchestrator for Local {
    async fn ping(&self) -> hlb_orchestrator::Result<String> {
        Ok("local".into())
    }
    async fn deploy(&self, _: &ServiceSpec) -> hlb_orchestrator::Result<String> {
        unreachable!()
    }
    async fn update_image(&self, _: &str, _: &str) -> hlb_orchestrator::Result<()> {
        unreachable!()
    }
    async fn scale(&self, _: &str, _: u64) -> hlb_orchestrator::Result<()> {
        unreachable!()
    }
    async fn enable_autolock(&self) -> hlb_orchestrator::Result<String> {
        unreachable!()
    }
    async fn autolock_enabled(&self) -> hlb_orchestrator::Result<bool> {
        Ok(false)
    }
    async fn cluster_init(&self, _: &str) -> hlb_orchestrator::Result<String> {
        unreachable!()
    }
    async fn join_tokens(&self) -> hlb_orchestrator::Result<hlb_orchestrator::JoinTokens> {
        unreachable!()
    }
    async fn nodes(&self) -> hlb_orchestrator::Result<Vec<hlb_orchestrator::NodeInfo>> {
        Ok(Vec::new())
    }
    async fn label_node(&self, _: &str, _: &str, _: &str) -> hlb_orchestrator::Result<()> {
        unreachable!()
    }
    async fn set_node_availability(&self, _: &str, _: &str) -> hlb_orchestrator::Result<()> {
        unreachable!()
    }
    async fn exec_in_service(
        &self,
        name: &str,
        cmd: &[String],
    ) -> hlb_orchestrator::Result<hlb_orchestrator::ExecOutput> {
        let container = self
            .containers
            .get(name)
            .expect("a container for the service");
        let mut args = vec!["exec".to_string(), container.clone()];
        args.extend(cmd.iter().cloned());
        let out = std::process::Command::new("docker")
            .args(&args)
            .output()
            .expect("docker exec");
        Ok(hlb_orchestrator::ExecOutput {
            exit_code: i64::from(out.status.code().unwrap_or(-1)),
            stdout: String::from_utf8_lossy(&out.stdout).into(),
            stderr: String::from_utf8_lossy(&out.stderr).into(),
        })
    }
    async fn ensure_network(&self, _: &str) -> hlb_orchestrator::Result<bool> {
        unreachable!()
    }
    async fn create_volume(
        &self,
        _: &hlb_orchestrator::VolumeSpec,
    ) -> hlb_orchestrator::Result<hlb_orchestrator::VolumeInfo> {
        unreachable!()
    }
    async fn inspect_volume(
        &self,
        _: &str,
    ) -> hlb_orchestrator::Result<hlb_orchestrator::VolumeInfo> {
        unreachable!()
    }
    async fn status(&self, n: &str) -> hlb_orchestrator::Result<ServiceStatus> {
        Err(hlb_orchestrator::Error::NotFound(n.into()))
    }
    async fn list(&self) -> hlb_orchestrator::Result<Vec<ServiceStatus>> {
        Ok(Vec::new())
    }
    async fn remove(&self, _: &str) -> hlb_orchestrator::Result<()> {
        unreachable!()
    }
    async fn wait_healthy(&self, _: &str, _: u64) -> hlb_orchestrator::Result<ServiceStatus> {
        unreachable!()
    }
    async fn tasks(
        &self,
        _: Option<&str>,
    ) -> hlb_orchestrator::Result<Vec<hlb_orchestrator::TaskInfo>> {
        Ok(Vec::new())
    }
    async fn logs(
        &self,
        _: &str,
        _: u32,
    ) -> hlb_orchestrator::Result<Vec<hlb_orchestrator::LogLine>> {
        Ok(Vec::new())
    }
}

struct Lab {
    state: State,
    vault: Vault,
    orch: Local,
    _dir: tempfile::TempDir,
}

impl Lab {
    async fn new(orch: Local) -> Self {
        let dir = tempfile::tempdir().expect("tmp");
        let vault = Vault::init(dir.path().join("k.key")).expect("vault");
        let state = State::in_memory().await.expect("state");
        Self {
            state,
            vault,
            orch,
            _dir: dir,
        }
    }

    async fn secret(&self, name: &str, value: &str) {
        self.state
            .store_secret_if_absent(name, &self.vault.encrypt(value).expect("enc"), "test")
            .await
            .expect("stored");
    }

    async fn sync(&self, apply: bool) -> Report {
        let reach = |u: &str| {
            u.replace("http://pocket-id:1411", &format!("http://localhost:{PORT}"))
                .replace("@postgres:5432/", &format!("@localhost:{PG_PORT}/"))
        };
        let r = RoleSync {
            state: &self.state,
            vault: &self.vault,
            orchestrator: &self.orch,
            reach: &reach,
            now: 1_000_000,
        }
        .run(apply)
        .await
        .expect("sync");
        for l in &r.lines {
            println!("  {:?} {}: {}", l.outcome, l.subject, l.change);
        }
        r
    }
}

#[tokio::test]
#[ignore = "needs Docker"]
async fn the_roles_reach_pocketid_and_the_tokens_its_apps_get() {
    let pid = pocketid();
    let lab = Lab::new(Local::default()).await;
    lab.secret(hlb_engine::access::POCKETID_KEY_SECRET, KEY)
        .await;

    // Two people, an administrator and a family member, known to PocketID.
    let mut family = hlb_users::RoleDef::new(
        "family",
        hlb_types::Role::User,
        hlb_users::MailLimits::standard(),
    );
    family.name = "Family".into();
    lab.state.put_role(&family, "test").await.expect("role");
    let mut subs = BTreeMap::new();
    for (name, role) in [("lena", "admin"), ("sacha", "family")] {
        let u = pid
            .create_user(name, Some(&format!("{name}@example.org")), name, &[])
            .await
            .expect("person");
        lab.state
            .upsert_user(name, role, Some(&u.id))
            .await
            .expect("account");
        lab.state
            .add_mailbox(name, name, "example.org", true)
            .await
            .expect("mailbox");
        subs.insert(name, u.id);
    }

    // Gitea and Termix as the catalog has them, each with its PocketID client.
    let mut clients = BTreeMap::new();
    for (app, path) in [("gitea", "gitea"), ("termix", "termix")] {
        lab.state
            .upsert_app(app, &catalog(path), Some(&format!("{app}.example.org")))
            .await
            .expect("installed");
        let c = pid
            .create(app, &[format!("https://{app}.example.org/cb")], false)
            .await
            .expect("client");
        lab.secret(&format!("{app}-oidc-client-id"), &c.id).await;
        clients.insert(app, c.id);
        for role in ["admin", "family"] {
            lab.state
                .allow_role(app, role, "test")
                .await
                .expect("allowed");
        }
    }

    // Before any sync: PocketID lets everyone into everything.
    assert!(token(&clients["termix"], &subs["sacha"]).await.is_ok());

    let preview = lab.sync(false).await;
    assert!(
        preview.lines.iter().all(|l| l.outcome == Outcome::ToDo),
        "a preview writes nothing"
    );
    assert!(
        pid.groups("hlb-").await.expect("groups").is_empty(),
        "nothing written"
    );
    assert!(
        preview
            .notes
            .iter()
            .any(|n| n.contains("termix") && n.contains("family")),
        "family is below Termix's floor, and said to be: {:?}",
        preview.notes
    );

    let applied = lab.sync(true).await;
    assert!(!applied.failed(), "{applied:?}");
    assert!(applied.lines.iter().all(|l| l.outcome == Outcome::Done));

    let lena_gitea = token(&clients["gitea"], &subs["lena"])
        .await
        .expect("lena enters gitea");
    assert_eq!(lena_gitea["hlb_gitea"], "admin");
    assert_eq!(lena_gitea["groups"], serde_json::json!(["hlb-admin"]));
    let sacha_gitea = token(&clients["gitea"], &subs["sacha"])
        .await
        .expect("sacha enters gitea");
    assert_eq!(
        sacha_gitea["hlb_gitea"], "user",
        "a member, not an administrator"
    );
    assert_eq!(
        token(&clients["termix"], &subs["lena"])
            .await
            .expect("lena enters termix")["hlb_termix"],
        "admin"
    );
    assert!(
        token(&clients["termix"], &subs["sacha"]).await.is_err(),
        "🔴 Termix holds every machine's SSH access: a family member is refused"
    );

    let again = lab.sync(true).await;
    assert!(
        again.lines.is_empty(),
        "nothing moved, nothing written: {again:?}"
    );
    assert!(again.unchanged > 0);

    // Taken out of Gitea: refused at once, by PocketID.
    lab.state
        .deny_role("gitea", "family")
        .await
        .expect("denied");
    lab.sync(true).await;
    assert!(token(&clients["gitea"], &subs["sacha"]).await.is_err());

    // A group edited by hand in PocketID is put back.
    let admin = pid
        .groups("hlb-admin")
        .await
        .expect("groups")
        .into_iter()
        .find(|g| g.name == "hlb-admin")
        .expect("group");
    pid.set_members(&admin.id, &Default::default())
        .await
        .expect("emptied");
    let repaired = lab.sync(true).await;
    assert!(
        repaired.lines.iter().any(|l| l.change.contains("+ lena")),
        "{repaired:?}"
    );
    assert!(token(&clients["gitea"], &subs["lena"]).await.is_ok());

    // An own mailbox PocketID holds unverified is said verified — Fluxer refuses the
    // sign-in otherwise —, and an address typed in PocketID is left as it is.
    set_address(&subs["lena"], "lena@example.org", false).await;
    lab.sync(true).await;
    assert_eq!(
        token(&clients["gitea"], &subs["lena"]).await.expect("in")["email_verified"],
        true
    );
    set_address(&subs["lena"], "lena@elsewhere.net", false).await;
    let left = lab.sync(true).await;
    assert!(!left.lines.iter().any(|l| l.subject == "lena"), "{left:?}");
    assert_eq!(
        token(&clients["gitea"], &subs["lena"]).await.expect("in")["email_verified"],
        false,
        "🔴 nobody's mailbox: Homelabus vouches for nothing it did not make"
    );

    // No role left: Gitea closes for everyone, lena included.
    lab.state.deny_role("gitea", "admin").await.expect("denied");
    lab.sync(true).await;
    assert!(
        token(&clients["gitea"], &subs["lena"]).await.is_err(),
        "closed is closed"
    );

    let _ = docker(&["rm", "-f", POCKETID]);
    println!("✓ roles, groups, claims and restrictions, read from the tokens the apps get");
}

const MARIADB: &str = "hlb-test-roles-mariadb";
const VALKEY: &str = "hlb-test-roles-valkey";
const SEAFILE: &str = "hlb-test-roles-seafile";
const NETWORK: &str = "hlb-test-roles";

/// Seafile as the catalog runs it — its quota script included — over a MariaDB.
fn seafile() {
    for c in [SEAFILE, MARIADB, VALKEY] {
        let _ = docker(&["rm", "-f", c]);
    }
    let _ = docker(&["network", "create", NETWORK]);
    let m = catalog("seafile");
    let mariadb = catalog("_platform/mariadb").spec.image.reference();
    let valkey = catalog("_platform/valkey").spec.image.reference();
    assert!(docker(&[
        "run",
        "-d",
        "--name",
        MARIADB,
        "--network",
        NETWORK,
        "-e",
        "MARIADB_ROOT_PASSWORD=rootpw",
        &mariadb,
    ])
    .status
    .success());
    assert!(
        docker(&["run", "-d", "--name", VALKEY, "--network", NETWORK, &valkey])
            .status
            .success()
    );
    // Until MariaDB takes connections: Seafile's first start gives up otherwise.
    for _ in 0..60 {
        if docker(&[
            "exec", MARIADB, "mariadb", "-uroot", "-prootpw", "-e", "SELECT 1",
        ])
        .status
        .success()
        {
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(2));
    }
    let dir = tempfile::tempdir().expect("tmp").keep();
    let script = m
        .spec
        .files
        .iter()
        .find(|f| f.path == "/run/hlb/seafile-quota.sh")
        .expect("the catalog's quota script");
    std::fs::write(dir.join("seafile-quota.sh"), &script.content).expect("script");
    let out = docker(&[
        "run",
        "-d",
        "--name",
        SEAFILE,
        "--network",
        NETWORK,
        "-p",
        "11581:80",
        "-v",
        &format!(
            "{}:/run/hlb/seafile-quota.sh:ro",
            dir.join("seafile-quota.sh").display()
        ),
        "-e",
        &format!("SEAFILE_MYSQL_DB_HOST={MARIADB}"),
        "-e",
        "SEAFILE_MYSQL_DB_PORT=3306",
        "-e",
        "SEAFILE_MYSQL_DB_USER=seafile",
        "-e",
        "SEAFILE_MYSQL_DB_PASSWORD=sfpw",
        "-e",
        "INIT_SEAFILE_MYSQL_ROOT_PASSWORD=rootpw",
        "-e",
        "SEAFILE_MYSQL_DB_CCNET_DB_NAME=ccnet_db",
        "-e",
        "SEAFILE_MYSQL_DB_SEAFILE_DB_NAME=seafile_db",
        "-e",
        "SEAFILE_MYSQL_DB_SEAHUB_DB_NAME=seahub_db",
        "-e",
        "JWT_PRIVATE_KEY=0123456789abcdef0123456789abcdef0123",
        "-e",
        "CACHE_PROVIDER=redis",
        "-e",
        &format!("REDIS_HOST={VALKEY}"),
        "-e",
        "REDIS_PORT=6379",
        "-e",
        "SEAFILE_SERVER_HOSTNAME=files.example.org",
        "-e",
        "SEAFILE_SERVER_PROTOCOL=http",
        "-e",
        "ENABLE_GO_FILESERVER=true",
        "-e",
        "INIT_SEAFILE_ADMIN_EMAIL=lena@example.org",
        "-e",
        "INIT_SEAFILE_ADMIN_PASSWORD=Adminpw123",
        "-e",
        "NON_ROOT=false",
        &m.spec.image.reference(),
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    wait_for("http://localhost:11581/api2/ping/", "200");
}

/// The quota Seafile holds for this account, in bytes; -2 is none.
fn seafile_quota(user: &str) -> i64 {
    let py =
        format!("from seaserv import seafile_api; print(seafile_api.get_user_quota('{user}'))");
    let i = "/opt/seafile/seafile-server-latest";
    let out = docker(&[
        "exec",
        "-e",
        "SEAFILE_CENTRAL_CONF_DIR=/opt/seafile/conf",
        "-e",
        "SEAFILE_CONF_DIR=/opt/seafile/seafile-data",
        "-e",
        &format!("SEAFILE_RPC_PIPE_PATH={i}/runtime"),
        "-e",
        &format!("PYTHONPATH={i}/seafile/lib/python3/site-packages"),
        SEAFILE,
        "python3",
        "-c",
        &py,
    ]);
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse()
        .expect("a quota")
}

#[tokio::test]
#[ignore = "needs Docker, and pulls Seafile"]
async fn a_role_s_quota_and_a_person_s_reach_seafile() {
    seafile();
    let lab = Lab::new(Local {
        containers: [("seafile".to_string(), SEAFILE.to_string())].into(),
    })
    .await;
    lab.state
        .upsert_app("seafile", &catalog("seafile"), Some("files.example.org"))
        .await
        .expect("installed");
    let mut family = hlb_users::RoleDef::new(
        "family",
        hlb_types::Role::User,
        hlb_users::MailLimits::standard(),
    );
    family.name = "Family".into();
    lab.state.put_role(&family, "test").await.expect("role");
    lab.state
        .set_role_quota("family", "seafile", Some(100 << 30))
        .await
        .expect("quota");
    lab.state
        .allow_role("seafile", "family", "test")
        .await
        .expect("allowed");
    for (name, sub) in [
        ("lena", "sub-lena"),
        ("sacha", "sub-sacha"),
        ("dominique", "sub-dominique"),
    ] {
        lab.state
            .upsert_user(name, "family", Some(sub))
            .await
            .expect("account");
    }
    lab.state
        .set_person_quota("lena", "seafile", Some(Some(200 << 30)), "test")
        .await
        .expect("own quota");
    lab.state
        .set_person_quota("sacha", "seafile", Some(None), "test")
        .await
        .expect("none");
    // Signed in to Seafile, as seahub records a PocketID sign-in: lena is the image's
    // first administrator, sacha an account of their own. Dominique never came.
    for (user, sub) in [
        ("lena@example.org", "sub-lena"),
        ("sacha@auth.local", "sub-sacha"),
    ] {
        let q = format!(
            "INSERT INTO social_auth_usersocialauth (username, provider, uid, extra_data) \
             VALUES ('{user}', 'pocket-id', '{sub}', '')"
        );
        assert!(docker(&[
            "exec",
            MARIADB,
            "mariadb",
            "-uroot",
            "-prootpw",
            "seahub_db",
            "-e",
            &q
        ])
        .status
        .success());
    }

    let r = lab.sync(true).await;
    let of = |who: &str| {
        r.lines
            .iter()
            .find(|l| l.subject == format!("{who} in seafile"))
            .map(|l| l.outcome.clone())
            .expect("a line")
    };
    assert_eq!(of("lena"), Outcome::Done);
    assert_eq!(of("sacha"), Outcome::Done);
    assert!(
        matches!(of("dominique"), Outcome::Waiting(_)),
        "never signed in: retried, not failed"
    );
    assert_eq!(
        seafile_quota("lena@example.org"),
        200 << 30,
        "their own beats their role's"
    );
    assert_eq!(seafile_quota("sacha@auth.local"), -2, "none at all");

    let again = lab.sync(true).await;
    assert!(
        again
            .lines
            .iter()
            .filter(|l| l.subject.ends_with("in seafile"))
            .all(|l| l.subject.starts_with("dominique")),
        "a quota set today is not set again: {again:?}"
    );

    for c in [SEAFILE, MARIADB, VALKEY] {
        let _ = docker(&["rm", "-f", c]);
    }
    let _ = docker(&["network", "rm", NETWORK]);
    println!("✓ quotas by role and by person, set inside a real Seafile");
}

const PG: &str = "hlb-test-roles-postgres";
const PG_PORT: u16 = 11582;
const IMMICH: &str = "hlb-test-roles-immich";

fn psql(query: &str) -> String {
    let out = docker(&[
        "exec", PG, "psql", "-U", "postgres", "-d", "immich", "-tAc", query,
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

#[tokio::test]
#[ignore = "needs Docker, and pulls Immich"]
async fn an_immich_account_s_quota_follows_its_role_after_its_creation() {
    // The claim is read when Immich creates the account only: after, the statement
    // is what moves it — run here against the schema Immich v3.1.0 migrates itself.
    for c in [IMMICH, PG, VALKEY] {
        let _ = docker(&["rm", "-f", c]);
    }
    let _ = docker(&["network", "create", NETWORK]);
    let pg = catalog("_platform/postgres").spec.image.reference();
    assert!(docker(&[
        "run",
        "-d",
        "--name",
        PG,
        "--network",
        NETWORK,
        "-p",
        &format!("{PG_PORT}:5432"),
        "-e",
        "POSTGRES_PASSWORD=pgpw",
        "-e",
        "POSTGRES_DB=immich",
        &pg,
    ])
    .status
    .success());
    let valkey = catalog("_platform/valkey").spec.image.reference();
    assert!(
        docker(&["run", "-d", "--name", VALKEY, "--network", NETWORK, &valkey])
            .status
            .success()
    );
    for _ in 0..60 {
        if docker(&["exec", PG, "pg_isready", "-U", "postgres"])
            .status
            .success()
        {
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(2));
    }
    let m = catalog("immich");
    assert!(docker(&[
        "run",
        "-d",
        "--name",
        IMMICH,
        "--network",
        NETWORK,
        "-p",
        "11583:2283",
        "-e",
        &format!("DB_HOSTNAME={PG}"),
        "-e",
        "DB_USERNAME=postgres",
        "-e",
        "DB_PASSWORD=pgpw",
        "-e",
        "DB_DATABASE_NAME=immich",
        "-e",
        &format!("REDIS_HOSTNAME={VALKEY}"),
        "-e",
        "IMMICH_MACHINE_LEARNING_ENABLED=false",
        &m.spec.image.reference(),
    ])
    .status
    .success());
    wait_for("http://localhost:11583/api/server/ping", "200");
    let created = reqwest::Client::new()
        .post("http://localhost:11583/api/auth/admin-sign-up")
        .json(&serde_json::json!({ "email": "lena@example.org", "password": "Pw-0123456789", "name": "Lena" }))
        .send()
        .await
        .expect("sign-up");
    assert!(
        created.status().is_success(),
        "{}",
        created.text().await.unwrap_or_default()
    );
    // As an OIDC sign-in links it.
    psql("UPDATE \"user\" SET \"oauthId\" = 'sub-lena' WHERE email = 'lena@example.org'");

    let lab = Lab::new(Local::default()).await;
    lab.secret("postgres-admin-password", "pgpw").await;
    lab.state
        .upsert_app("immich", &m, Some("photos.example.org"))
        .await
        .expect("installed");
    let mut family = hlb_users::RoleDef::new(
        "family",
        hlb_types::Role::User,
        hlb_users::MailLimits::standard(),
    );
    family.name = "Family".into();
    lab.state.put_role(&family, "test").await.expect("role");
    lab.state
        .set_role_quota("family", "immich", Some(50 << 30))
        .await
        .expect("quota");
    lab.state
        .allow_role("immich", "family", "test")
        .await
        .expect("allowed");
    for (name, sub) in [("lena", "sub-lena"), ("dominique", "sub-dominique")] {
        lab.state
            .upsert_user(name, "family", Some(sub))
            .await
            .expect("account");
    }

    let r = lab.sync(true).await;
    assert!(
        r.lines
            .iter()
            .any(|l| l.subject == "lena in immich" && l.outcome == Outcome::Done),
        "{r:?}"
    );
    assert!(r
        .lines
        .iter()
        .any(|l| l.subject == "dominique in immich" && matches!(l.outcome, Outcome::Waiting(_))));
    assert_eq!(
        psql("SELECT \"quotaSizeInBytes\" FROM \"user\" WHERE \"oauthId\" = 'sub-lena'"),
        (50_u64 << 30).to_string()
    );

    lab.state
        .set_person_quota("lena", "immich", Some(None), "test")
        .await
        .expect("none");
    lab.sync(true).await;
    assert_eq!(
        psql("SELECT coalesce(\"quotaSizeInBytes\"::text, 'none') FROM \"user\" WHERE \"oauthId\" = 'sub-lena'"),
        "none",
        "no quota is NULL, never 0"
    );

    for c in [IMMICH, PG, VALKEY] {
        let _ = docker(&["rm", "-f", c]);
    }
    let _ = docker(&["network", "rm", NETWORK]);
    println!("✓ an Immich account's quota, moved after its creation");
}
