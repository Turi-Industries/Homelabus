//! What an app's volume holds is data, never what the app runs or how it is set up.
//!
//! A restore writes back whatever the backup holds, and after an intrusion the backup
//! is the intruder's. Filtering the restore guards one way in; reading nothing
//! executable from the volume guards them all — `hlb backup restore`, a recovery on a
//! new machine, restic by hand in the middle of an outage. Each test forges a volume
//! the way an intruder would, starts the catalog's image on it with the manifest's own
//! settings, and checks the forgery changed nothing.
//!
//! ```sh
//! cargo test -p hlb-catalog --test volume_decides_nothing -- --ignored --nocapture
//! ```

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::process::Command;

use hlb_types::Manifest;

fn manifest(name: &str) -> Manifest {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../../catalog");
    let catalog = hlb_catalog::Catalog::load(root).expect("catalog");
    catalog.get(name).expect("in the catalog").manifest.clone()
}

fn run(program: &str, args: &[&str]) -> String {
    let out = Command::new(program).args(args).output().expect(program);
    assert!(
        out.status.success(),
        "{program} {}: {}",
        args.join(" "),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// `docker exec`, its output whatever its status.
fn exec(container: &str, script: &str) -> String {
    let out = Command::new("docker")
        .args(["exec", container, "sh", "-c", script])
        .output()
        .expect("docker");
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// The status an HTTP request got, `0` when nothing answered.
fn status(args: &[&str]) -> u16 {
    let mut all = vec!["-s", "-o", "/dev/null", "-w", "%{http_code}"];
    all.extend(args);
    let out = Command::new("curl").args(&all).output().expect("curl");
    String::from_utf8_lossy(&out.stdout)
        .parse()
        .unwrap_or_default()
}

fn wait_for(url: &str) {
    for _ in 0..90 {
        if status(&[url]) == 200 {
            return;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    panic!("{url} never answered");
}

/// Removes what a test started, whatever happens to it.
struct Stand {
    containers: Vec<String>,
    volume: String,
}

impl Drop for Stand {
    fn drop(&mut self) {
        for c in &self.containers {
            let _ = Command::new("docker").args(["rm", "-f", c]).output();
        }
        let _ = Command::new("docker")
            .args(["volume", "rm", &self.volume])
            .output();
    }
}

#[test]
#[ignore = "needs Docker, curl and git"]
fn a_forged_gitea_volume_runs_none_of_its_code() {
    let m = manifest("gitea");
    let image = m.spec.image.reference();
    let script = &m
        .spec
        .files
        .iter()
        .find(|f| f.path == "/run/hlb/gitea-start.sh")
        .expect("the start script")
        .content;
    // Rebuilt at every start, app.ini holds only what the environment gives it: the
    // keys that encrypt must be there, or Gitea falls back on a constant. Each is a
    // file the environment names, the vault's — given here as the test's own.
    let keys = [
        (
            "GITEA__security__SECRET_KEY",
            "Abcdefgh1234567890abcdefXYZ12345",
        ),
        (
            "GITEA__security__INTERNAL_TOKEN",
            "Zyxwvut0987654321zyxwvutABCDE123",
        ),
        (
            "GITEA__oauth2__JWT_SECRET",
            "Xz0LAn7SZbPUVMuj6SbTMNPtCt1Z-VzuOK2IM95esLk",
        ),
        (
            "GITEA__server__LFS_JWT_SECRET",
            "r5apulnCltEBzBNOXSMGU2T9LY9VDWqnOXdpSA-X2Sc",
        ),
    ];
    let secret_files: Vec<(String, String, &str)> = keys
        .iter()
        .map(|(key, value)| {
            let name = format!("{key}__FILE");
            let path = m.spec.env.get(&name).unwrap_or_else(|| panic!("{name}"));
            assert!(
                m.spec
                    .files
                    .iter()
                    .any(|f| &f.path == path && f.content.contains("{{ secret.")),
                "{key} is not from the vault"
            );
            (name, path.clone(), *value)
        })
        .collect();

    let tag = std::process::id();
    let container = format!("hlb-gitea-vol-{tag}");
    let mut stand = Stand {
        containers: Vec::new(),
        volume: format!("hlb-gitea-vol-{tag}"),
    };
    let dir = tempfile::tempdir().expect("a directory");
    let start = dir.path().join("start.sh");
    std::fs::write(&start, script).expect("written");
    let mount = format!("{}:/run/hlb/gitea-start.sh:ro", start.display());
    let mut secrets: Vec<String> = Vec::new();
    for (i, (name, path, value)) in secret_files.iter().enumerate() {
        let local = dir.path().join(format!("secret-{i}"));
        std::fs::write(&local, value).expect("written");
        secrets.extend([
            "-e".to_string(),
            format!("{name}={path}"),
            "-v".to_string(),
            format!("{}:{path}:ro", local.display()),
        ]);
    }
    let volume = format!("{}:/data", stand.volume);
    let start_gitea = |stand: &mut Stand| {
        let _ = Command::new("docker")
            .args(["rm", "-f", &container])
            .output();
        let mut args: Vec<&str> = vec![
            "run",
            "-d",
            "--name",
            &container,
            "-p",
            "127.0.0.1::3000",
            "-e",
            "GITEA__security__INSTALL_LOCK=true",
            "-e",
            "GITEA__database__DB_TYPE=sqlite3",
            "-e",
            "HLB_OIDC_ISSUER=http://nowhere.invalid",
            "-e",
            "HLB_OIDC_CLIENT_ID=x",
            "-v",
            &volume,
            "-v",
            &mount,
        ];
        args.extend(secrets.iter().map(String::as_str));
        args.extend([
            image.as_str(),
            "/usr/bin/entrypoint",
            "bash",
            "/run/hlb/gitea-start.sh",
        ]);
        run("docker", &args);
        if !stand.containers.contains(&container) {
            stand.containers.push(container.clone());
        }
        let port = run("docker", &["port", &container, "3000/tcp"])
            .rsplit(':')
            .next()
            .expect("a port")
            .to_string();
        wait_for(&format!("http://127.0.0.1:{port}/api/healthz"));
        port
    };

    // A repository, as Gitea makes it.
    let port = start_gitea(&mut stand);
    // The keys came in through their files, and none through the environment.
    for (name, _, value) in &secret_files {
        let key = name.rsplit("__").nth(1).expect("a key");
        assert_eq!(
            exec(
                &container,
                &format!("grep -c '^{key} *= *{value}$' /data/gitea/conf/app.ini")
            ),
            "1",
            "{name}"
        );
    }
    let password = "Pa55word-long!";
    Command::new("docker")
        .args([
            "exec",
            "-u",
            "git",
            &container,
            "gitea",
            "admin",
            "user",
            "create",
            "--username",
            "tester",
            "--password",
            password,
            "--email",
            "t@x.test",
            "--must-change-password=false",
        ])
        .output()
        .expect("a user");
    let auth = format!("tester:{password}");
    assert_eq!(
        status(&[
            "-u",
            &auth,
            "-H",
            "Content-Type: application/json",
            "-d",
            r#"{"name":"demo","auto_init":true}"#,
            &format!("http://127.0.0.1:{port}/api/v1/user/repos"),
        ]),
        201
    );
    run("docker", &["stop", &container]);

    // The intruder's backup: a command in app.ini, a page template, a hook beside
    // Gitea's, git told to take its hooks and config elsewhere, and a key to log in.
    let r = "/data/git/repositories/tester/demo.git";
    run(
        "docker",
        &[
            "run",
            "--rm",
            "-v",
            &volume,
            "--entrypoint",
            "sh",
            &image,
            "-c",
            &format!(
                "set -e
                 printf '[markup.evil]\\nENABLED = true\\nFILE_EXTENSIONS = .x\\nRENDER_COMMAND = touch /tmp/pwned-markup\\n' >> /data/gitea/conf/app.ini
                 mkdir -p /data/gitea/templates/custom /data/evil
                 echo '<script>steal()</script>' > /data/gitea/templates/custom/header.tmpl
                 printf '#!/bin/sh\\ntouch /tmp/pwned-hook\\n' > {r}/hooks/post-receive.d/evil
                 printf '#!/bin/sh\\ntouch /tmp/pwned-path\\n' > /data/evil/post-receive
                 chmod +x {r}/hooks/post-receive.d/evil /data/evil/post-receive
                 chown -R 1000:1000 {r}/hooks /data/evil
                 printf '[core]\\n\\thooksPath = /data/evil\\n[include]\\n\\tpath = /data/evil/cfg\\n' >> {r}/config
                 echo /data/evil > {r}/commondir
                 echo 'ssh-ed25519 AAAAforged intruder' >> /data/git/.ssh/authorized_keys
                 ln -s /data/evil /data/git/repositories/tester/linked.git"
            ),
        ],
    );

    let port = start_gitea(&mut stand);
    let logs = Command::new("docker")
        .args(["logs", &container])
        .output()
        .expect("logs");
    let logs = String::from_utf8_lossy(&logs.stderr).to_string();
    for removed in [
        "custom/templates",
        "linked.git (a link)",
        "demo.git/commondir",
        "hooks/post-receive.d/evil",
        "core.hookspath include.path",
    ] {
        assert!(
            logs.contains(removed),
            "{removed} was not said removed:\n{logs}"
        );
    }
    assert_eq!(
        exec(&container, "grep -c markup /data/gitea/conf/app.ini"),
        "0"
    );
    assert!(!exec(&container, "cat /data/git/.ssh/authorized_keys").contains("forged"));

    // A push still reaches Gitea — its own hooks were written again — and runs
    // nothing of the intruder's.
    let clone = dir.path().join("demo");
    let url = format!("http://{auth}@127.0.0.1:{port}/tester/demo.git");
    run(
        "git",
        &["clone", "-q", &url, clone.to_str().expect("a path")],
    );
    std::fs::write(clone.join("f"), "pushed").expect("written");
    let git = |args: &[&str]| {
        let mut all = vec![
            "-C",
            clone.to_str().expect("a path"),
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@x.test",
        ];
        all.extend(args);
        run("git", &all)
    };
    git(&["add", "f"]);
    git(&["commit", "-qm", "after the restore"]);
    git(&["push", "-q", "origin", "HEAD"]);
    let head = git(&["rev-parse", "HEAD"]);
    let branch = run(
        "curl",
        &[
            "-s",
            "-u",
            &auth,
            &format!("http://127.0.0.1:{port}/api/v1/repos/tester/demo/branches/main"),
        ],
    );
    assert!(
        branch.contains(&head),
        "Gitea did not hear of the push: {branch}"
    );
    assert_eq!(exec(&container, "ls /tmp | grep pwned || true"), "");
}

#[test]
#[ignore = "needs Docker and curl"]
fn a_forged_vaultwarden_config_opens_nothing() {
    let m = manifest("vaultwarden");
    let image = m.spec.image.reference();
    let env = |k: &str| m.spec.env.get(k).cloned().unwrap_or_default();
    let config = env("CONFIG_FILE");
    let templates = env("TEMPLATES_FOLDER");
    // Outside the data volume, or the forgery below is what Vaultwarden reads.
    for path in [&config, &templates] {
        assert!(
            path.starts_with("/run/hlb/"),
            "\"{path}\" — Vaultwarden reads it from its volume"
        );
    }

    let tag = std::process::id();
    let container = format!("hlb-vw-vol-{tag}");
    let stand = Stand {
        containers: vec![container.clone()],
        volume: format!("hlb-vw-vol-{tag}"),
    };
    let volume = format!("{}:/data", stand.volume);
    // What the admin page writes, and beats every variable: its own token, sign-ups
    // open to anyone.
    run(
        "docker",
        &[
            "run",
            "--rm",
            "-v",
            &volume,
            "--entrypoint",
            "sh",
            &image,
            "-c",
            "echo '{\"signups_allowed\": true, \"admin_token\": \"forged\"}' > /data/config.json
             mkdir -p /data/templates/email",
        ],
    );
    let config = format!("CONFIG_FILE={config}");
    let templates = format!("TEMPLATES_FOLDER={templates}");
    run(
        "docker",
        &[
            "run",
            "-d",
            "--name",
            &container,
            "-p",
            "127.0.0.1::80",
            "-e",
            "SIGNUPS_ALLOWED=false",
            "-e",
            "DOMAIN=http://localhost",
            "-e",
            &config,
            "-e",
            &templates,
            "-v",
            &volume,
            &image,
        ],
    );
    let port = run("docker", &["port", &container, "80/tcp"])
        .rsplit(':')
        .next()
        .expect("a port")
        .to_string();
    let base = format!("http://127.0.0.1:{port}");
    wait_for(&format!("{base}/alive"));

    let admin = run("curl", &["-s", &format!("{base}/admin")]);
    assert!(
        admin.contains("disabled"),
        "the admin page opened on the volume's token"
    );
    // A sign-up's first step: 200 and its token when sign-ups are open, 400 closed.
    // 🔴 1.37.4 dropped the one-step `/identity/accounts/register` — a 404 there proves
    // nothing, and this test waited on it in vain.
    assert_eq!(
        status(&[
            "-H",
            "Content-Type: application/json",
            "-d",
            r#"{"email":"a@b.test","name":"a"}"#,
            &format!("{base}/identity/accounts/register/send-verification-email"),
        ]),
        400,
        "a sign-up passed"
    );
    drop(stand);
}
