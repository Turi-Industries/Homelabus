//! The weekly upkeep against real REST servers: proved again, pruned to the retention
//! policy where the destination can be erased anyway, left whole where it cannot — and
//! pruned there by its owner, running the script `hlb backup dest prune-script` prints.
//!
//! ```sh
//! cargo test -p hlb-backup-run --test upkeep -- --ignored --nocapture
//! ```

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::process::Command;

use hlb_backup::{Destination, RetentionPolicy};
use hlb_backup_run::upkeep::{self, Retention};

const REST_SERVER: &str = "restic/rest-server:0.13.0@sha256:8668c235a932745585fef5cabbab9eccb501035f90138085a6e74963dcd1a71f";

fn docker(args: &[&str]) -> std::process::Output {
    Command::new("docker").args(args).output().expect("docker")
}

struct Stand(String);

impl Drop for Stand {
    fn drop(&mut self) {
        for c in ["rest-ao", "rest-open", "rest-owner"] {
            let _ = docker(&["rm", "-f", &format!("{}-{c}", self.0)]);
        }
        let _ = docker(&["network", "rm", &self.0]);
    }
}

#[tokio::test]
#[ignore = "needs Docker"]
async fn an_erasable_destination_is_pruned_and_one_out_of_reach_is_left_whole() {
    let net = format!("hlb-upkeep-{}", std::process::id());
    let _stand = Stand(net.clone());
    assert!(docker(&["network", "create", &net]).status.success());
    for (name, options) in [("rest-ao", "--append-only"), ("rest-open", "")] {
        let out = docker(&[
            "run",
            "-d",
            "--name",
            &format!("{net}-{name}"),
            "--network",
            &net,
            "-e",
            "DISABLE_AUTHENTICATION=1",
            "-e",
            &format!("OPTIONS={options}"),
            REST_SERVER,
        ]);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    std::thread::sleep(std::time::Duration::from_secs(2));

    let dir = tempfile::tempdir().expect("tmp");
    let state = hlb_state::State::open(dir.path().join("hlb.db"))
        .await
        .expect("state");
    let vault = hlb_secrets::Vault::open_or_init(dir.path().join("k.key")).expect("vault");
    let password = hlb_backup_run::restic_password(&state, &vault)
        .await
        .expect("password");
    let mut count = Vec::new();
    for name in ["rest-ao", "rest-open"] {
        let location = format!("rest:http://{net}-{name}:8000/r");
        state
            .upsert_destination(name, &location, "critical,bulky", None)
            .await
            .expect("destination");
        let d = Destination {
            name: name.into(),
            location: location.clone(),
            classes: vec![hlb_backup::Class::Critical],
            credentials_secret: None,
        };
        let (runner, location) = d.runner(Some(&net));
        let repo = hlb_backup::Repository::new(runner, location, password.clone());
        repo.init().await.expect("init");
        // Four snapshots within one hour. The policy keeps the hour's newest — and,
        // while a bucket is not full, restic 0.19 keeps the OLDEST too, reaching back as
        // far as it can ("oldest hourly snapshot"): two stay.
        for _ in 0..4 {
            // Not the proof's witness's `/etc/hostname`: restic groups by host and
            // paths, and a witness kept beside them would take one of the hour's places.
            repo.backup("/etc/os-release", &["app:test"])
                .await
                .expect("backup");
        }
        count.push((name, repo));
    }

    let reach = |u: &str| u.to_string();
    // The proof is dated by the clock: the pass is asked at the same time.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs() as i64;
    let lines = upkeep::run(
        &state,
        &vault,
        &net,
        &reach,
        &RetentionPolicy::default(),
        now,
    )
    .await
    .expect("upkeep");
    for l in &lines {
        println!(
            "{}: {} — {:?}",
            l.destination,
            l.proof.describe(),
            l.retention
        );
    }
    let of = |n: &str| lines.iter().find(|l| l.destination == n).expect(n);
    assert_eq!(of("rest-open").retention, Retention::Applied);
    assert!(matches!(of("rest-ao").retention, Retention::Left(_)));
    for (name, repo) in &count {
        let left = repo.snapshots(Some("app:test")).await.expect("list").len();
        let want = if *name == "rest-open" { 2 } else { 4 };
        assert_eq!(left, want, "{name}");
    }

    // Proved within the week: not proved again, nothing touched.
    let again = upkeep::run(
        &state,
        &vault,
        &net,
        &reach,
        &RetentionPolicy::default(),
        now + 3_600,
    )
    .await
    .expect("upkeep");
    assert!(again.is_empty(), "{again:?}");
    println!("✓ pruned where erasable, whole where not, once a week");

    // The owner's view of the append-only repository: the same files, served by a
    // server that deletes. The script runs as printed, its two variables set.
    let Retention::Left(why) = &of("rest-ao").retention else {
        panic!("rest-ao was pruned")
    };
    assert!(
        why.contains("hlb backup dest prune-script rest-ao"),
        "{why}"
    );
    let out = docker(&[
        "run",
        "-d",
        "--name",
        &format!("{net}-rest-owner"),
        "--network",
        &net,
        "--volumes-from",
        &format!("{net}-rest-ao"),
        "-e",
        "DISABLE_AUTHENTICATION=1",
        REST_SERVER,
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    std::thread::sleep(std::time::Duration::from_secs(2));
    let d = Destination {
        name: "rest-ao".into(),
        location: format!("rest:http://{net}-rest-ao:8000/r"),
        classes: vec![hlb_backup::Class::Critical],
        credentials_secret: None,
    };
    let script = upkeep::owner_script(&d, &RetentionPolicy::default()).expect("script");
    let out = Command::new("docker")
        .args([
            "run",
            "--rm",
            "--network",
            &net,
            "-e",
            &format!("RESTIC_REPOSITORY=rest:http://{net}-rest-owner:8000/r"),
            "-e",
            "RESTIC_PASSWORD",
            "--entrypoint",
            "sh",
            hlb_backup::images::RESTIC,
            "-c",
            &script,
        ])
        .env("RESTIC_PASSWORD", &password)
        .output()
        .expect("docker");
    println!("{}", String::from_utf8_lossy(&out.stdout));
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let (_, ao) = count
        .iter()
        .find(|(n, _)| *n == "rest-ao")
        .expect("rest-ao");
    assert_eq!(ao.snapshots(Some("app:test")).await.expect("list").len(), 2);
    println!("✓ the owner's script prunes what Homelabus could not");
}
