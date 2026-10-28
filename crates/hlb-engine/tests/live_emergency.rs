//! The emergency vault against a real Vaultwarden on PostgreSQL — the catalog's image —
//! from an empty organisation to a password rotated, every key on the owner's side made
//! by `hlb_bitwarden::crypto` the way an owner's client makes it: the account, the
//! organisation and its collections, the confirmation.
//!
//! The manifest's two SQL assertions are read against the same database, so a query
//! naming a column Vaultwarden does not have fails here and not every night.
//!
//! ```sh
//! cargo test -p hlb-engine --test live_emergency -- --ignored --nocapture
//! ```

#![allow(clippy::expect_used, clippy::unwrap_used)]

use hlb_bitwarden::client::{Server, Session, SignIn};
use hlb_bitwarden::crypto::{seal, Kdf, KeyPair, MasterKey, SymmetricKey};
use hlb_bitwarden::emergency::Verdict;
use hlb_engine::emergency::{EmergencyVault, Report};
use hlb_engine::roles::Outcome;
use hlb_secrets::Vault;
use hlb_state::State;
use hlb_types::access::{EmergencyPart, Members};
use serde_json::{json, Value};

const NETWORK: &str = "hlb-test-emergency";
const POSTGRES: &str = "hlb-test-emergency-pg";
const VAULTWARDEN: &str = "hlb-test-emergency-vw";
const PORT: u16 = 11586;
const OWNER: &str = "owner@owner.example.org";
const OWNER_PASSWORD: &str = "correct horse battery staple";
const SERVICE: &str = "homelabus@example.org";
const KDF: Kdf = Kdf::Pbkdf2 {
    iterations: 600_000,
};

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

fn base() -> String {
    format!("http://localhost:{PORT}")
}

fn clean() {
    let _ = docker(&["rm", "-f", VAULTWARDEN, POSTGRES]);
    let _ = docker(&["network", "rm", NETWORK]);
}

fn run(args: &[&str]) {
    let out = docker(args);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// The value an SQL assertion of the catalog's manifest reads, as the controller's
/// reader would: the first column of the first row.
fn assertion(id: &str) -> String {
    let m = catalog("vaultwarden");
    let a = m
        .spec
        .assertions
        .iter()
        .find(|a| a.id == id)
        .expect("the assertion");
    let hlb_types::Check::Sql { query, .. } = &a.check else {
        panic!("{id} is no SQL assertion");
    };
    let out = docker(&[
        "exec",
        POSTGRES,
        "psql",
        "-U",
        "postgres",
        "-d",
        "vaultwarden",
        "-tAc",
        query,
    ]);
    assert!(
        out.status.success(),
        "{id}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

async fn start() {
    clean();
    run(&["network", "create", NETWORK]);
    run(&[
        "run",
        "-d",
        "--name",
        POSTGRES,
        "--network",
        NETWORK,
        "-e",
        "POSTGRES_PASSWORD=pw",
        "-e",
        "POSTGRES_DB=vaultwarden",
        "postgres:17-alpine",
    ]);
    for _ in 0..60 {
        if docker(&["exec", POSTGRES, "pg_isready", "-U", "postgres"])
            .status
            .success()
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    run(&[
        "run",
        "-d",
        "--name",
        VAULTWARDEN,
        "--network",
        NETWORK,
        "-p",
        &format!("{PORT}:80"),
        "-e",
        &format!("DOMAIN={}", base()),
        "-e",
        &format!("DATABASE_URL=postgresql://postgres:pw@{POSTGRES}/vaultwarden"),
        "-e",
        "SIGNUPS_ALLOWED=false",
        "-e",
        "I_REALLY_WANT_VOLATILE_STORAGE=true",
        // The owner comes in through PocketID or an admin's invitation in real life;
        // here their domain is let in, and the invited account's.
        "-e",
        "SIGNUPS_DOMAINS_WHITELIST=owner.example.org,example.org",
        &catalog("vaultwarden").spec.image.reference(),
    ]);
    let http = reqwest::Client::new();
    for _ in 0..90 {
        if http
            .get(format!("{}/alive", base()))
            .send()
            .await
            .is_ok_and(|r| r.status().is_success())
        {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    panic!("Vaultwarden did not start");
}

/// An account registered the way the web vault registers one.
async fn register(email: &str, password: &str) {
    let master = MasterKey::derive(password, email, KDF).expect("master key");
    let key = SymmetricKey::generate();
    let pair = KeyPair::generate().expect("pair");
    let http = reqwest::Client::new();
    // 🔴 Two steps since 1.37.4, which answers 404 on the one-step `register`: without
    // mail configured, the first hands back the token the mail would have carried, as
    // bare text.
    let verification: String = http
        .post(format!(
            "{}/identity/accounts/register/send-verification-email",
            base()
        ))
        .json(&json!({ "email": email, "name": email }))
        .send()
        .await
        .expect("verification")
        .text()
        .await
        .expect("a token");
    let resp = http
        .post(format!("{}/identity/accounts/register/finish", base()))
        .json(&json!({
            "email": email, "name": email, "emailVerificationToken": verification,
            "masterPasswordHash": master.password_hash(password),
            "masterPasswordHint": null,
            "userSymmetricKey": master.stretch().expect("stretched").encrypt(&key.to_bytes()),
            "kdf": 0, "kdfIterations": 600000,
            "userAsymmetricKeys": { "publicKey": pair.public().expect("public"),
                      "encryptedPrivateKey": pair.wrap(&key).expect("wrapped") },
        }))
        .send()
        .await
        .expect("register");
    assert!(
        resp.status().is_success(),
        "{email}: {}",
        resp.text().await.unwrap_or_default()
    );
}

async fn sign_in(email: &str, password: &str) -> Session {
    let hash = MasterKey::derive(password, email, KDF)
        .expect("master key")
        .password_hash(password);
    match Server::new(&base())
        .sign_in(email, &hash, None)
        .await
        .expect("signed in")
    {
        SignIn::Done(s) => s,
        SignIn::SecondFactor => panic!("{email} asked for a second factor"),
    }
}

/// What the owner's client does, with the keys it holds.
struct Owner {
    session: Session,
    org: String,
    key: SymmetricKey,
    server: String,
    family: String,
}

impl Owner {
    async fn new() -> Self {
        register(OWNER, OWNER_PASSWORD).await;
        let session = sign_in(OWNER, OWNER_PASSWORD).await;
        let me = session.unlock(OWNER, OWNER_PASSWORD).expect("unlocked");
        let key = SymmetricKey::generate();
        let org_pair = KeyPair::generate().expect("pair");
        let org = session
            .post(
                "/api/organizations",
                &json!({
                    "name": "Household", "billingEmail": OWNER,
                    "collectionName": key.encrypt_str("Default collection"),
                    "key": seal(&me.pair.public().unwrap(), &key).unwrap(),
                    "keys": { "publicKey": org_pair.public().unwrap(),
                              "encryptedPrivateKey": org_pair.wrap(&key).unwrap() },
                    "planType": 0,
                }),
            )
            .await
            .expect("organisation")["id"]
            .as_str()
            .unwrap()
            .to_string();
        let collection = |name: &str| {
            let (session, key, org) = (&session, &key, &org);
            let name = key.encrypt_str(name);
            async move {
                session
                    .post(
                        &format!("/api/organizations/{org}/collections"),
                        &json!({ "name": name, "groups": [], "users": [] }),
                    )
                    .await
                    .expect("collection")["id"]
                    .as_str()
                    .unwrap()
                    .to_string()
            }
        };
        let server = collection("Server").await;
        let family = collection("Family").await;
        Self {
            session,
            org,
            key,
            server,
            family,
        }
    }

    fn access(&self, ids: &[&str]) -> Value {
        Value::Array(
            ids.iter()
                .map(|id| json!({ "id": id, "readOnly": false, "hidePasswords": false, "manage": false }))
                .collect(),
        )
    }

    async fn invite(&self) {
        self.session
            .post(
                &format!("/api/organizations/{}/users/invite", self.org),
                &json!({
                    "emails": [SERVICE], "type": 2, "accessAll": false, "permissions": {},
                    "groups": [], "collections": self.access(&[&self.server]),
                }),
            )
            .await
            .expect("invited");
    }

    async fn member(&self) -> Value {
        let members = self
            .session
            .get(&format!("/api/organizations/{}/users", self.org))
            .await
            .expect("members");
        members["data"]
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m["email"] == SERVICE)
            .expect("the account is a member")
            .clone()
    }

    async fn confirm(&self) {
        let m = self.member().await;
        let public = self
            .session
            .get(&format!(
                "/api/users/{}/public-key",
                m["userId"].as_str().unwrap()
            ))
            .await
            .expect("public key");
        self.session
            .post(
                &format!(
                    "/api/organizations/{}/users/{}/confirm",
                    self.org,
                    m["id"].as_str().unwrap()
                ),
                &json!({ "key": seal(public["publicKey"].as_str().unwrap(), &self.key).unwrap() }),
            )
            .await
            .expect("confirmed");
    }

    async fn require_two_step(&self) {
        self.session
            .put(
                &format!("/api/organizations/{}/policies/0", self.org),
                &json!({ "policy": { "enabled": true, "data": null } }),
            )
            .await
            .expect("policy");
    }

    async fn give(&self, collections: &[&str]) {
        let m = self.member().await;
        self.session
            .put(
                &format!(
                    "/api/organizations/{}/users/{}",
                    self.org,
                    m["id"].as_str().unwrap()
                ),
                &json!({ "type": 2, "accessAll": false, "permissions": {}, "groups": [],
                         "collections": self.access(collections) }),
            )
            .await
            .expect("access changed");
    }

    /// The Server collection's items, decrypted with the organisation's key — what an
    /// owner opening Vaultwarden on the bad day reads.
    async fn items(&self) -> Vec<Value> {
        let sync = self.session.sync().await.expect("sync");
        let k = &self.key;
        let text = |v: &Value| v.as_str().map(|e| k.decrypt_str(e).expect("decrypted"));
        sync["ciphers"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|c| {
                c["collectionIds"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|i| i == &self.server)
            })
            .map(|c| {
                json!({
                    "name": text(&c["name"]),
                    "username": text(&c["login"]["username"]),
                    "password": text(&c["login"]["password"]),
                    "uri": text(&c["login"]["uris"][0]["uri"]),
                    "history": c["passwordHistory"].as_array().map(|h| h.iter()
                        .map(|p| text(&p["password"])).collect::<Vec<_>>()),
                })
            })
            .collect()
    }
}

fn verdicts(r: &Report) -> Vec<(String, &'static str)> {
    r.checks
        .iter()
        .map(|c| {
            (
                c.what.clone(),
                match c.verdict {
                    Verdict::Holds => "holds",
                    Verdict::Missing(_) => "missing",
                    Verdict::Wrong(_) => "wrong",
                },
            )
        })
        .collect()
}

fn outcomes(r: &Report) -> Vec<(String, String, &'static str)> {
    r.lines
        .iter()
        .map(|l| {
            (
                l.subject.clone(),
                l.change.clone(),
                match l.outcome {
                    Outcome::ToDo => "to do",
                    Outcome::Done => "done",
                    Outcome::Waiting(_) => "waiting",
                    Outcome::NotConfigured(_) => "not configured",
                    Outcome::Failed(_) => "failed",
                },
            )
        })
        .collect()
}

async fn secret(state: &State, vault: &Vault, name: &str) -> Option<String> {
    state
        .secret(name)
        .await
        .expect("state")
        .map(|ct| vault.decrypt(&ct).expect("decrypted"))
}

#[tokio::test]
#[ignore = "needs Docker"]
async fn the_emergency_vault_holds_every_recovery_sign_in_once_verified() {
    start().await;
    let state = State::in_memory().await.expect("state");
    let vault = Vault::ephemeral();
    for (app, domain) in [
        ("vaultwarden", "vault.example.org"),
        ("grafana", "grafana.example.org"),
    ] {
        let path = if app == "grafana" {
            "_platform/grafana"
        } else {
            app
        };
        state
            .upsert_app(app, &catalog(path), Some(domain))
            .await
            .expect("recorded");
        state
            .set_app_status(app, "installed")
            .await
            .expect("status");
    }
    state
        .store_secret_if_absent(
            "grafana-admin-password",
            &vault.encrypt("G-admin-1").unwrap(),
            "generated",
        )
        .await
        .expect("secret");
    let reach = |u: &str| u.replace("http://vaultwarden:80", &base());
    let now = || {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    };
    let ev = |t: i64| EmergencyVault {
        state: &state,
        vault: &vault,
        reach: &reach,
        now: t,
    };

    // Nothing to deposit into yet: an owner's organisation first.
    let r = ev(now()).run(None, false).await.expect("ran");
    assert!(
        r.stopped
            .as_deref()
            .unwrap_or_default()
            .contains("no organisation"),
        "{r:?}"
    );
    let owner = Owner::new().await;
    state
        .store_secret_if_absent(
            &Members::organization_id_secret("vaultwarden"),
            &vault.encrypt(&owner.org).unwrap(),
            "organization",
        )
        .await
        .expect("org id");
    assert_eq!(
        assertion("two-step-required"),
        "Household",
        "not required yet"
    );

    // The address, previewed: nothing kept.
    let r = ev(now()).run(Some(SERVICE), false).await.expect("ran");
    assert_eq!(
        outcomes(&r),
        [
            ("account".into(), format!("its address: {SERVICE}"), "to do"),
            (
                "account".into(),
                "its master password, generated".into(),
                "to do"
            ),
        ]
    );
    let email_secret = Members::emergency_secret("vaultwarden", EmergencyPart::Email);
    assert_eq!(
        secret(&state, &vault, &email_secret).await,
        None,
        "a preview keeps nothing"
    );

    // Applied: kept and generated — and no account answers to them yet.
    let r = ev(now()).run(Some(SERVICE), true).await.expect("ran");
    assert!(
        r.stopped
            .as_deref()
            .unwrap_or_default()
            .contains("Invite member"),
        "{r:?}"
    );
    let password = secret(
        &state,
        &vault,
        &Members::emergency_secret("vaultwarden", EmergencyPart::Password),
    )
    .await
    .expect("generated");

    // The owner invites it; whoever opens the invitation registers with that password.
    owner.invite().await;
    register(SERVICE, &password).await;

    // Homelabus gives it a second factor and an API key — BEFORE an owner confirms it:
    // a confirmed member signing in by password without one is revoked by the policy.
    let r = ev(now()).run(None, true).await.expect("ran");
    assert_eq!(
        outcomes(&r),
        [
            ("account".into(), "its own second factor".into(), "done"),
            (
                "account".into(),
                "its API key, kept in the vault".into(),
                "done"
            ),
        ],
        "{r:?}"
    );
    assert_eq!(
        verdicts(&r),
        [("a confirmed member of the organisation".into(), "missing")]
    );
    assert!(secret(
        &state,
        &vault,
        &Members::emergency_secret("vaultwarden", EmergencyPart::Totp)
    )
    .await
    .is_some());
    assert!(!r.verified());

    // Confirmed, the policy still off: nothing deposited, and nothing proved.
    owner.confirm().await;
    let r = ev(now()).run(None, true).await.expect("ran");
    assert_eq!(
        verdicts(&r).last().cloned(),
        Some(("two-step login required of every member".into(), "missing"))
    );
    assert!(r.lines.is_empty(), "nothing written: {r:?}");
    assert!(state.breakglass().await.unwrap().is_empty());

    // The policy on: verified, and the deposit previewed, then made.
    owner.require_two_step().await;
    assert_eq!(assertion("two-step-required"), "");
    // The owner has no second factor, and the policy exempts owners: read all the same.
    assert_eq!(assertion("every-account-has-a-second-factor"), OWNER);
    let r = ev(now()).run(None, false).await.expect("ran");
    assert!(r.verified(), "{:?}", verdicts(&r));
    assert_eq!(
        outcomes(&r),
        [(
            "grafana/admin-password".into(),
            "deposit, as \"Grafana — admin\"".into(),
            "to do"
        )]
    );
    assert!(owner.items().await.is_empty(), "a preview writes nothing");
    let r = ev(now()).run(None, true).await.expect("ran");
    assert!(!r.failed(), "{r:?}");
    assert_eq!(
        owner.items().await,
        [json!({
            "name": "Grafana — admin", "username": "admin", "password": "G-admin-1",
            "uri": "https://grafana.example.org/login", "history": [],
        })]
    );
    assert_eq!(
        state.breakglass().await.unwrap()[0].0,
        hlb_api::breakglass::EMERGENCY_VAULT,
        "the safeguard proved"
    );

    // A rotation reaches the item, the former password kept in its history.
    state
        .rotate_secret(
            "grafana-admin-password",
            &vault.encrypt("G-admin-2").unwrap(),
        )
        .await
        .expect("rotated");
    let r = ev(now()).run(None, true).await.expect("ran");
    assert_eq!(
        outcomes(&r),
        [(
            "grafana/admin-password".into(),
            "update its password".into(),
            "done"
        )]
    );
    let items = owner.items().await;
    assert_eq!(items[0]["password"], "G-admin-2");
    assert_eq!(items[0]["history"], json!(["G-admin-1"]));
    let r = ev(now()).run(None, true).await.expect("ran");
    assert_eq!((r.lines.len(), r.unchanged), (0, 1), "{r:?}");

    // 🔴 Given another collection, the account would hand it to a compromised
    // controller: refused, and the safeguard withdrawn at once.
    owner.give(&[&owner.server, &owner.family]).await;
    let r = ev(now()).run(None, true).await.expect("ran");
    assert!(
        verdicts(&r).contains(&("no other collection".into(), "wrong")),
        "{r:?}"
    );
    assert!(r.lines.is_empty());
    assert!(state.breakglass().await.unwrap().is_empty(), "withdrawn");

    clean();
    println!(
        "✓ the emergency vault: set up, verified, deposited, rotated, refused when over-given"
    );
}
