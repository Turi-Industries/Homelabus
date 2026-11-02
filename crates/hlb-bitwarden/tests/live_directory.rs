//! A Bitwarden organisation's members, written through the Directory Connector's route
//! of a real Vaultwarden — the catalog's image.
//!
//! The organisation is made the way an owner's client makes it, its keys opaque: the
//! server stores them and decrypts nothing, which is also why Homelabus can invite and
//! remove but never confirm.
//!
//! ```sh
//! cargo test -p hlb-bitwarden --test live_directory -- --ignored --nocapture
//! ```

#![allow(clippy::expect_used, clippy::unwrap_used)]

use hlb_bitwarden::directory::{Directory, Group, Member};

const CONTAINER: &str = "hlb-test-vaultwarden";
const PORT: u16 = 11585;
const OWNER: &str = "owner@example.org";
/// What a client sends as the master password's hash; the server hashes it again.
const HASH: &str = "aGFzaA==";
const OPAQUE: &str = "2.AAAA|BBBB|CCCC";

fn docker(args: &[&str]) -> std::process::Output {
    std::process::Command::new("docker")
        .args(args)
        .output()
        .expect("docker reachable")
}

fn image() -> String {
    let p = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../catalog/apps/vaultwarden/manifest.yaml"
    );
    let m: hlb_types::manifest::Manifest =
        serde_yaml_ng::from_str(&std::fs::read_to_string(p).expect("manifest")).expect("parsed");
    m.spec.image.reference()
}

fn base() -> String {
    format!("http://localhost:{PORT}")
}

async fn owner_token(http: &reqwest::Client) -> String {
    let v: serde_json::Value = http
        .post(format!("{}/identity/connect/token", base()))
        .form(&[
            ("grant_type", "password"),
            ("username", OWNER),
            ("password", HASH),
            ("scope", "api offline_access"),
            ("client_id", "web"),
            ("deviceType", "10"),
            ("deviceIdentifier", "11111111-1111-1111-1111-111111111111"),
            ("deviceName", "test"),
        ])
        .send()
        .await
        .expect("token")
        .json()
        .await
        .expect("json");
    v["access_token"].as_str().expect("token").to_string()
}

/// The members' addresses, sorted, and whether each carries an external id.
async fn members(http: &reqwest::Client, token: &str, org: &str) -> Vec<(String, bool)> {
    let v: serde_json::Value = http
        .get(format!("{}/api/organizations/{org}/users", base()))
        .bearer_auth(token)
        .send()
        .await
        .expect("members")
        .json()
        .await
        .expect("json");
    let mut out: Vec<(String, bool)> = v["data"]
        .as_array()
        .expect("data")
        .iter()
        .map(|m| {
            (
                m["email"].as_str().unwrap_or_default().to_string(),
                m["externalId"].as_str().is_some_and(|e| !e.is_empty()),
            )
        })
        .collect();
    out.sort();
    out
}

/// Each group's external id and how many members it holds.
async fn groups(http: &reqwest::Client, token: &str, org: &str) -> Vec<(String, usize)> {
    let v: serde_json::Value = http
        .get(format!("{}/api/organizations/{org}/groups", base()))
        .bearer_auth(token)
        .send()
        .await
        .expect("groups")
        .json()
        .await
        .expect("json");
    let mut out = Vec::new();
    for g in v["data"].as_array().expect("data") {
        let id = g["id"].as_str().expect("id");
        let users: serde_json::Value = http
            .get(format!(
                "{}/api/organizations/{org}/groups/{id}/users",
                base()
            ))
            .bearer_auth(token)
            .send()
            .await
            .expect("group users")
            .json()
            .await
            .expect("json");
        out.push((
            g["externalId"].as_str().unwrap_or_default().to_string(),
            users.as_array().map_or(0, Vec::len),
        ));
    }
    out.sort();
    out
}

#[tokio::test]
#[ignore = "needs Docker"]
async fn the_roles_people_are_invited_and_removed_and_hand_added_ones_kept() {
    let _ = docker(&["rm", "-f", CONTAINER]);
    let out = docker(&[
        "run",
        "-d",
        "--name",
        CONTAINER,
        "-p",
        &format!("{PORT}:80"),
        "-e",
        &format!("DOMAIN={}", base()),
        "-e",
        "SIGNUPS_ALLOWED=true",
        "-e",
        "I_REALLY_WANT_VOLATILE_STORAGE=true",
        "-e",
        "ORG_GROUPS_ENABLED=true",
        &image(),
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let http = reqwest::Client::new();
    for _ in 0..60 {
        if http
            .get(format!("{}/alive", base()))
            .send()
            .await
            .is_ok_and(|r| r.status().is_success())
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }

    // The owner, and their organisation, as an owner's client makes them.
    // 🔴 Two steps since 1.37.4, which answers 404 on the one-step `register`: without
    // mail configured, the first hands back the token the mail would have carried, as
    // bare text.
    let verification: String = http
        .post(format!(
            "{}/identity/accounts/register/send-verification-email",
            base()
        ))
        .json(&serde_json::json!({ "email": OWNER, "name": "Owner" }))
        .send()
        .await
        .expect("verification")
        .text()
        .await
        .expect("a token");
    let registered = http
        .post(format!("{}/identity/accounts/register/finish", base()))
        .json(&serde_json::json!({
            "email": OWNER, "name": "Owner", "emailVerificationToken": verification,
            "masterPasswordHash": HASH, "masterPasswordHint": null,
            "userSymmetricKey": OPAQUE, "kdf": 0, "kdfIterations": 600000,
            "userAsymmetricKeys": { "publicKey": "pub", "encryptedPrivateKey": OPAQUE },
        }))
        .send()
        .await
        .expect("register");
    assert!(
        registered.status().is_success(),
        "{}",
        registered.text().await.unwrap_or_default()
    );
    let token = owner_token(&http).await;
    let org: serde_json::Value = http
        .post(format!("{}/api/organizations", base()))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "name": "Household", "billingEmail": OWNER, "collectionName": OPAQUE,
            "key": "4.AAAA", "keys": { "publicKey": "pub", "encryptedPrivateKey": OPAQUE },
            "planType": 0,
        }))
        .send()
        .await
        .expect("organisation")
        .json()
        .await
        .expect("json");
    let org = org["id"].as_str().expect("id").to_string();
    let key: serde_json::Value = http
        .post(format!("{}/api/organizations/{org}/api-key", base()))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "masterPasswordHash": HASH }))
        .send()
        .await
        .expect("api key")
        .json()
        .await
        .expect("json");
    let key = key["apiKey"].as_str().expect("key");

    let wrong = Directory::new(&base(), &org, "not-the-key");
    let refused = wrong
        .import(&[], &[])
        .await
        .expect_err("a wrong key is refused");
    assert!(
        !refused.to_string().contains("not-the-key"),
        "never echoed: {refused}"
    );

    let dir = Directory::new(&base(), &org, key);
    let member = |who: &str| Member {
        email: format!("{who}@example.org"),
        external_id: who.to_string(),
        deleted: false,
    };
    let group = |role: &str, who: &[&str]| Group {
        name: role.to_string(),
        external_id: format!("hlb-{role}"),
        member_external_ids: who.iter().map(|w| w.to_string()).collect(),
    };
    dir.import(
        &[member("lena"), member("sacha")],
        &[group("family", &["lena"]), group("guests", &["sacha"])],
    )
    .await
    .expect("imported");
    assert_eq!(
        groups(&http, &token, &org).await,
        [("hlb-family".to_string(), 1), ("hlb-guests".to_string(), 1)],
        "a group per role, each with its people"
    );
    assert_eq!(
        members(&http, &token, &org).await,
        [
            ("lena@example.org".to_string(), true),
            ("owner@example.org".to_string(), false),
            ("sacha@example.org".to_string(), true),
        ],
        "both invited, the owner untouched"
    );

    // Sacha's role no longer lets them in: removed. The owner, added by no import,
    // stays — and so would anyone an owner invited by hand.
    // Their role is gone too: its group is sent once more, empty — the import removes
    // no group, and one not sent would keep what its collections give.
    dir.import(
        &[member("lena")],
        &[group("family", &["lena"]), group("guests", &[])],
    )
    .await
    .expect("imported");
    assert_eq!(
        groups(&http, &token, &org).await,
        [("hlb-family".to_string(), 1), ("hlb-guests".to_string(), 0)]
    );
    assert_eq!(
        members(&http, &token, &org).await,
        [
            ("lena@example.org".to_string(), true),
            ("owner@example.org".to_string(), false),
        ]
    );
    dir.import(&[member("lena")], &[group("family", &["lena"])])
        .await
        .expect("again: nothing moves");
    assert_eq!(members(&http, &token, &org).await.len(), 2);

    let _ = docker(&["rm", "-f", CONTAINER]);
    println!(
        "✓ an organisation's members follow the roles, through the Directory Connector's route"
    );
}
