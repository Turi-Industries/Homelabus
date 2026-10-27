//! A destination's proof, against the real servers: a REST server with and without
//! `--append-only`, Garage, and a versioned S3 reached with a credential that may or may
//! not delete a version. Each must come out as what it is — above all, nothing erasable
//! may come out "kept".
//!
//! ```sh
//! cargo test -p hlb-backup-run --test erasure -- --ignored --nocapture
//! ```

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::process::Command;

use hlb_backup::erasure::Erasure;
use hlb_backup::{Class, Destination};

const REST_SERVER: &str = "restic/rest-server:0.13.0@sha256:8668c235a932745585fef5cabbab9eccb501035f90138085a6e74963dcd1a71f";
// The project's own images stopped being published to Docker Hub in 2025.
const MINIO: &str =
    "chainguard/minio@sha256:709099319add48dfb44aa596a7070d3ddd8dd04d7ae881765719aec29df9e510";
const MC: &str = "chainguard/minio-client@sha256:3d0109d854f045c0158637d6ad0d44fd8a3aef9f0b62082096eb1854c2df8b31";

fn docker(args: &[&str]) -> String {
    let out = Command::new("docker").args(args).output().expect("docker");
    assert!(
        out.status.success(),
        "docker {}: {}",
        args.join(" "),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// Removes what the test started, whatever happens to it.
struct Stand {
    network: String,
    containers: Vec<String>,
}

impl Stand {
    fn run(&mut self, name: &str, args: &[&str]) {
        let name = format!("{}-{name}", self.network);
        let mut all = vec!["run", "-d", "--name", &name, "--network", &self.network];
        all.extend(args);
        docker(&all);
        self.containers.push(name);
    }

    fn port(&self, name: &str, port: &str) -> String {
        let out = docker(&["port", &format!("{}-{name}", self.network), port]);
        out.lines()
            .next()
            .and_then(|l| l.rsplit(':').next())
            .expect("a port")
            .to_string()
    }
}

impl Drop for Stand {
    fn drop(&mut self) {
        for c in &self.containers {
            let _ = Command::new("docker").args(["rm", "-f", c]).output();
        }
        let _ = Command::new("docker")
            .args(["network", "rm", &self.network])
            .output();
    }
}

fn wait(what: &str, mut ready: impl FnMut() -> bool) {
    for _ in 0..60 {
        if ready() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    panic!("{what} never came up");
}

#[tokio::test]
#[ignore = "needs Docker"]
async fn each_destination_is_proven_as_what_it_is() {
    let mut stand = Stand {
        network: format!("hlb-erasure-{}", std::process::id()),
        containers: Vec::new(),
    };
    docker(&["network", "create", &stand.network]);
    let net = stand.network.clone();

    // Two REST servers: one keeps what it is given, one does not.
    stand.run(
        "rest-ao",
        &[
            "-e",
            "DISABLE_AUTHENTICATION=1",
            "-e",
            "OPTIONS=--append-only",
            REST_SERVER,
        ],
    );
    stand.run(
        "rest-open",
        &["-e", "DISABLE_AUTHENTICATION=1", REST_SERVER],
    );

    // MinIO: a bucket without versions, a versioned one, and a credential on it that
    // may do everything but delete a version.
    stand.run(
        "minio",
        &[
            "-p",
            "127.0.0.1::9000",
            "-e",
            "MINIO_ROOT_USER=rootuser",
            "-e",
            "MINIO_ROOT_PASSWORD=rootpassword",
            MINIO,
            "server",
            "/tmp/data",
        ],
    );
    // The client image has no shell: its alias through the environment, the policy
    // through a mounted file.
    let dir = tempfile::tempdir().expect("tmp");
    let host = format!("MC_HOST_m=http://rootuser:rootpassword@{net}-minio:9000");
    let files = format!("{}:/w:ro", dir.path().display());
    let mc = |args: &[&str]| {
        let mut all = vec![
            "run",
            "--rm",
            "--network",
            &net,
            "-e",
            &host,
            "-v",
            &files,
            MC,
        ];
        all.extend(args);
        Command::new("docker").args(&all).output().expect("docker")
    };
    wait("minio", || mc(&["ls", "m"]).status.success());
    // What a backup needs, deleting included — restic removes its locks. Leaving
    // s3:DeleteObjectVersion OUT of it is the lesson AWS teaches; MinIO deletes a
    // version with s3:DeleteObject alone, and only a Deny stops it.
    let allow = r#"{"Effect":"Allow","Action":["s3:GetBucketLocation","s3:GetBucketVersioning","s3:ListBucket","s3:ListBucketVersions","s3:GetObject","s3:GetObjectVersion","s3:PutObject","s3:DeleteObject"],"Resource":["arn:aws:s3:::kept","arn:aws:s3:::kept/*"]}"#;
    let deny = r#"{"Effect":"Deny","Action":["s3:DeleteObjectVersion"],"Resource":["arn:aws:s3:::kept/*"]}"#;
    std::fs::write(
        dir.path().join("omit.json"),
        format!(r#"{{"Version":"2012-10-17","Statement":[{allow}]}}"#),
    )
    .expect("policy");
    std::fs::write(
        dir.path().join("deny.json"),
        format!(r#"{{"Version":"2012-10-17","Statement":[{allow},{deny}]}}"#),
    )
    .expect("policy");
    for step in [
        &["mb", "m/plain"][..],
        &["mb", "--with-versioning", "m/kept"],
        &["admin", "policy", "create", "m", "omit", "/w/omit.json"],
        &["admin", "policy", "create", "m", "deny", "/w/deny.json"],
        &["admin", "user", "add", "m", "omitter", "omitterpassword"],
        &["admin", "user", "add", "m", "writer", "writerpassword"],
        &[
            "admin", "policy", "attach", "m", "omit", "--user", "omitter",
        ],
        &["admin", "policy", "attach", "m", "deny", "--user", "writer"],
    ] {
        let out = mc(step);
        assert!(
            out.status.success(),
            "mc {step:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let s3 = format!("http://127.0.0.1:{}", stand.port("minio", "9000/tcp"));

    // Garage, as the catalog runs it.
    std::fs::write(
        dir.path().join("garage.toml"),
        "metadata_dir = \"/tmp/meta\"\ndata_dir = \"/tmp/data\"\ndb_engine = \"lmdb\"\n\
         replication_factor = 1\nrpc_bind_addr = \"[::]:3901\"\n\
         [s3_api]\ns3_region = \"garage\"\napi_bind_addr = \"[::]:3900\"\n\
         [admin]\napi_bind_addr = \"[::]:3903\"\n",
    )
    .expect("garage.toml");
    let garage_image = {
        let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../../catalog");
        hlb_catalog_image(root, "garage")
    };
    let mount = format!(
        "{}:/etc/garage.toml:ro",
        dir.path().join("garage.toml").display()
    );
    stand.run(
        "garage",
        &[
            "-p",
            "127.0.0.1::3900",
            "-e",
            "GARAGE_RPC_SECRET=0000000000000000000000000000000000000000000000000000000000000001",
            "-e",
            "GARAGE_ADMIN_TOKEN=admin",
            "-v",
            &mount,
            &garage_image,
        ],
    );
    let garage = format!("{net}-garage");
    let g = |args: &[&str]| {
        let mut all = vec!["exec", garage.as_str(), "/garage"];
        all.extend(args);
        docker(&all)
    };
    wait("garage", || {
        Command::new("docker")
            .args(["exec", &garage, "/garage", "status"])
            .output()
            .is_ok_and(|o| o.status.success())
    });
    let node = g(&["node", "id", "-q"]);
    let node = node.split('@').next().expect("an id").to_string();
    g(&["layout", "assign", "-z", "dc1", "-c", "1G", &node]);
    g(&["layout", "apply", "--version", "1"]);
    g(&["bucket", "create", "backups"]);
    let key = g(&["key", "create", "backups-key"]);
    let field = |name: &str| {
        key.lines()
            .find_map(|l| l.trim().strip_prefix(name).map(|v| v.trim().to_string()))
            .expect(name)
    };
    let (garage_id, garage_secret) = (field("Key ID:"), field("Secret key:"));
    g(&[
        "bucket",
        "allow",
        "--read",
        "--write",
        "backups",
        "--key",
        "backups-key",
    ]);
    let garage_s3 = format!("http://127.0.0.1:{}", stand.port("garage", "3900/tcp"));

    // The installation.
    let state = hlb_state::State::open(dir.path().join("hlb.db"))
        .await
        .expect("state");
    let vault = hlb_secrets::Vault::open_or_init(dir.path().join("k.key")).expect("vault");
    let add_destination = |name: &str, location: String, creds: Option<String>| {
        let state = &state;
        let vault = &vault;
        let name = name.to_string();
        async move {
            let secret = match creds {
                Some(c) => {
                    let n = format!("backup-dest-{name}");
                    state
                        .store_secret_if_absent(&n, &vault.encrypt(&c).expect("sealed"), "test")
                        .await
                        .expect("secret");
                    Some(n)
                }
                None => None,
            };
            state
                .upsert_destination(&name, &location, "critical,bulky", secret.as_deref())
                .await
                .expect("destination");
            Destination {
                name: name.clone(),
                location,
                classes: vec![Class::Critical, Class::Bulky],
                credentials_secret: secret,
            }
        }
    };
    let cases = [
        (
            add_destination("nas", "/mnt/nas/restic".into(), None).await,
            "erasable",
        ),
        (
            add_destination(
                "rest-open",
                format!("rest:http://{net}-rest-open:8000/r"),
                None,
            )
            .await,
            "erasable",
        ),
        (
            add_destination("rest-ao", format!("rest:http://{net}-rest-ao:8000/r"), None).await,
            "kept",
        ),
        (
            add_destination(
                "garage",
                format!("s3:{garage_s3}/backups"),
                Some(format!("{garage_id}:{garage_secret}")),
            )
            .await,
            "erasable",
        ),
        (
            add_destination(
                "plain",
                format!("s3:{s3}/plain/restic"),
                Some("rootuser:rootpassword".into()),
            )
            .await,
            "erasable",
        ),
        (
            add_destination(
                "versioned-root",
                format!("s3:{s3}/kept/restic"),
                Some("rootuser:rootpassword".into()),
            )
            .await,
            "erasable",
        ),
        (
            add_destination(
                "versioned-omitted",
                format!("s3:{s3}/kept/restic"),
                Some("omitter:omitterpassword".into()),
            )
            .await,
            "erasable",
        ),
        (
            add_destination(
                "versioned",
                format!("s3:{s3}/kept/restic"),
                Some("writer:writerpassword".into()),
            )
            .await,
            "kept",
        ),
    ];

    let reach = |url: &str| url.to_string();
    let mut wrong = Vec::new();
    for (d, expected) in &cases {
        let found = hlb_backup_run::erasure::prove(&state, &vault, &net, &reach, d).await;
        println!("{}: {}", d.name, found.describe());
        if found.verdict() != *expected {
            wrong.push(format!("{}: {found:?}, expected {expected}", d.name));
        }
        let stored = state
            .destination_proof(&d.name, &d.location)
            .await
            .expect("read")
            .expect("recorded");
        assert_eq!(Erasure::from_stored(&stored.0, &stored.1), found);
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}

/// The catalog's image for `name`, by its digest.
fn hlb_catalog_image(root: &str, name: &str) -> String {
    let text = std::fs::read_to_string(format!("{root}/_platform/{name}/manifest.yaml"))
        .expect("manifest");
    let m: hlb_types::Manifest = serde_yaml_ng::from_str(&text).expect("parsed");
    m.spec.image.reference()
}
