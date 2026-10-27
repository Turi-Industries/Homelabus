//! The pass, against a real restic: a volume and the state database reach a declared
//! destination, under the paths every older snapshot uses.
//!
//! ```sh
//! cargo test -p hlb-backup-run --test pass -- --ignored --nocapture
//! ```

#![allow(clippy::expect_used, clippy::unwrap_used)]

use hlb_backup_run::{Event, Pass};

fn docker(args: &[&str]) -> std::process::Output {
    std::process::Command::new("docker")
        .args(args)
        .output()
        .expect("docker reachable")
}

#[tokio::test]
#[ignore = "needs Docker"]
async fn a_pass_sends_volumes_and_state_to_the_declared_destination() {
    let dir = tempfile::tempdir().expect("tmp");
    let state_path = dir.path().join("hlb.db");
    let state = hlb_state::State::open(&state_path).await.expect("state");
    let vault = hlb_secrets::Vault::open_or_init(dir.path().join("k.key")).expect("vault");

    let (data, repo) = ("hlb-pass-data", "hlb-pass-repo");
    for v in [data, repo] {
        let _ = docker(&["volume", "rm", "-f", v]);
        docker(&["volume", "create", v]);
    }
    let w = docker(&[
        "run",
        "--rm",
        "-v",
        &format!("{data}:/d"),
        "alpine:3",
        "sh",
        "-c",
        "echo precious > /d/file.txt",
    ]);
    assert!(w.status.success());

    let manifest: hlb_types::Manifest = serde_yaml_ng::from_str(
        "apiVersion: hlb/v1\nkind: App\nmetadata: { name: demo }\n\
         spec:\n  image: { repo: a/b, tag: \"1\" }\n",
    )
    .expect("manifest");
    state
        .upsert_app("demo", &manifest, None)
        .await
        .expect("app");
    state
        .add_volume("demo", data, "/unused", true, false)
        .await
        .expect("volume");
    state
        .upsert_destination("nas", repo, "critical,bulky", None)
        .await
        .expect("destination");

    let pass = Pass {
        state: &state,
        vault: &vault,
        state_path: &state_path,
        fallback_repo: None,
        network: "bridge",
        postgres_admin: None,
        mariadb_admin: None,
        schedule: hlb_backup::Schedule::default(),
        force: true,
        only: None,
        orchestrator: None,
        s3_endpoint: None,
    };
    let mut events = Vec::new();
    let sum = pass.run(&mut |e| events.push(e)).await.expect("pass");
    for e in &events {
        println!("{e:?}");
    }
    assert_eq!(sum.failed, 0, "{events:?}");
    let done: Vec<&str> = events
        .iter()
        .filter_map(|e| match e {
            Event::Done {
                what, destination, ..
            } if destination == "nas" => Some(what.as_str()),
            _ => None,
        })
        .collect();
    assert!(done.contains(&"demo volumes"), "{done:?}");
    assert!(done.contains(&"hlb state"), "{done:?}");

    // The paths inside the snapshot are the frozen ones.
    let password = hlb_backup_run::restic_password(&state, &vault)
        .await
        .expect("pw");
    let ls = docker(&[
        "run",
        "--rm",
        "-v",
        &format!("{repo}:/repo"),
        "-e",
        &format!("RESTIC_PASSWORD={password}"),
        "restic/restic:latest",
        "-r",
        "/repo",
        "snapshots",
        "--json",
    ]);
    let out = String::from_utf8_lossy(&ls.stdout);
    assert!(out.contains(&format!("/donnees/{data}")), "{out}");

    for v in [data, repo] {
        let _ = docker(&["volume", "rm", "-f", v]);
    }
}
