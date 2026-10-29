//! Termix given the nodes, end to end, against the catalog's Termix image and two real
//! `sshd`s standing for nodes — Debian's and Alpine's. The orchestrator is a stand-in
//! whose jobs run in those containers: what a node's job does is what the script does
//! there.
//!
//! From an administrator's key to Homelabus's own account; the nodes' accounts, hosts
//! and shares; a member of the role reading the key Termix holds and opening a node
//! with it from the allowed address only; a rotation; a node leaving.
//!
//! ```sh
//! cargo test -p hlb-engine --test live_termix -- --ignored --nocapture
//! ```

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::Mutex;

use async_trait::async_trait;
use hlb_engine::roles::Outcome;
use hlb_engine::termix::{NodeAccess, ACCOUNT};
use hlb_orchestrator::{
    JobOutcome, NodeInfo, NodeRole, Orchestrator, ServiceSpec, ServiceStatus, TaskInfo,
};
use hlb_secrets::Vault;
use hlb_state::State;
use hlb_types::access::Nodes;
use serde_json::{json, Value};

const NET: &str = "hlb-test-termix";
const SUBNET: &str = "172.31.252.0/24";
const TERMIX: &str = "hlb-test-termix-app";
const PORT: u16 = 11587;
/// Termix's connections, as the stand-in's `docker_gwbridge` reports them.
const ALLOWED: &str = "172.31.252.20";
const OTHER: &str = "172.31.252.30";
const NODES: [(&str, &str, &str, &str); 2] = [
    (
        "n1-aaaaaaaaaaaaaaaaaaaa",
        "deb1",
        "172.31.252.11",
        "debian:bookworm-slim",
    ),
    (
        "n2-bbbbbbbbbbbbbbbbbbbb",
        "alp1",
        "172.31.252.12",
        "alpine:3",
    ),
];

fn docker(args: &[&str]) -> std::process::Output {
    std::process::Command::new("docker")
        .args(args)
        .output()
        .expect("docker reachable")
}

fn run(args: &[&str]) {
    let out = docker(args);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn container(node: &str) -> String {
    format!("hlb-test-termix-{node}")
}

fn clean() {
    let mut names = vec![TERMIX.to_string()];
    names.extend(NODES.iter().map(|n| container(n.1)));
    for n in names {
        let _ = docker(&["rm", "-f", &n]);
    }
    let _ = docker(&["network", "rm", NET]);
}

/// Removes the containers and the network however the test ends — a panic included.
struct Cleanup;

impl Drop for Cleanup {
    fn drop(&mut self) {
        clean();
    }
}

fn catalog() -> hlb_types::Manifest {
    let p = format!(
        "{}/../../catalog/termix/manifest.yaml",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_yaml_ng::from_str(&std::fs::read_to_string(p).expect("manifest")).expect("parsed")
}

/// Swarm, as far as the node sync reads it; its jobs run in the nodes' containers.
struct Stand {
    nodes: Mutex<Vec<NodeInfo>>,
    jobs: Mutex<Vec<String>>,
}

impl Stand {
    fn new() -> Self {
        Self {
            nodes: Mutex::new(
                NODES
                    .iter()
                    .map(|(id, host, addr, _)| NodeInfo {
                        id: (*id).into(),
                        hostname: (*host).into(),
                        role: NodeRole::Manager,
                        status: "ready".into(),
                        availability: "active".into(),
                        tier: None,
                        protection: None,
                        is_leader: false,
                        memory_mb: None,
                        failure_domain: None,
                        data: Vec::new(),
                        ingress: false,
                        addr: Some((*addr).into()),
                    })
                    .collect(),
            ),
            jobs: Mutex::new(Vec::new()),
        }
    }
}

#[async_trait]
impl Orchestrator for Stand {
    async fn ping(&self) -> hlb_orchestrator::Result<String> {
        Ok("stand".into())
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
    async fn nodes(&self) -> hlb_orchestrator::Result<Vec<NodeInfo>> {
        Ok(self.nodes.lock().unwrap().clone())
    }
    async fn label_node(&self, _: &str, _: &str, _: &str) -> hlb_orchestrator::Result<()> {
        unreachable!()
    }
    async fn set_node_availability(&self, _: &str, _: &str) -> hlb_orchestrator::Result<()> {
        unreachable!()
    }
    async fn exec_in_service(
        &self,
        _: &str,
        _: &[String],
    ) -> hlb_orchestrator::Result<hlb_orchestrator::ExecOutput> {
        unreachable!()
    }
    async fn run_job(&self, spec: &ServiceSpec, _: u64) -> hlb_orchestrator::Result<JobOutcome> {
        self.jobs.lock().unwrap().push(spec.name.clone());
        let node = spec
            .constraints
            .iter()
            .find_map(|c| c.strip_prefix("node.id=="))
            .expect("a job placed on a node");
        // `docker network inspect docker_gwbridge`: where Termix's connections come
        // from, here the one address a test client takes.
        if spec.command.first().map(String::as_str) == Some("docker") {
            return Ok(JobOutcome {
                succeeded: true,
                output: vec![format!("{ALLOWED}/32 ")],
            });
        }
        assert_eq!(
            spec.command[..4],
            ["chroot", "/host", "/bin/sh", "-c"],
            "{:?}",
            spec.command
        );
        let host = NODES
            .iter()
            .find(|n| n.0 == node)
            .map(|n| container(n.1))
            .expect("a known node");
        // A preview's job mounts the host read-only: a write there would fail, which is
        // what this assertion stands for.
        let read_only = spec
            .binds
            .iter()
            .any(|b| b.target == "/host" && b.read_only);
        let out = docker(&["exec", &host, "/bin/sh", "-c", &spec.command[4]]);
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        if read_only {
            assert!(text.contains("HLB-END"), "{text}");
        }
        Ok(JobOutcome {
            succeeded: out.status.success(),
            output: text.lines().map(str::to_string).collect(),
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
    /// Termix runs on the first node.
    async fn tasks(&self, service: Option<&str>) -> hlb_orchestrator::Result<Vec<TaskInfo>> {
        assert_eq!(service, Some("termix"));
        Ok(vec![TaskInfo {
            id: "t1".into(),
            service: "termix".into(),
            slot: Some(1),
            node_id: Some(NODES[0].0.into()),
            desired_state: "running".into(),
            state: "running".into(),
            image: "ghcr.io/lukegus/termix:2.9.2".into(),
            message: None,
            err: None,
            updated_at: None,
        }])
    }
    async fn logs(
        &self,
        _: &str,
        _: u32,
    ) -> hlb_orchestrator::Result<Vec<hlb_orchestrator::LogLine>> {
        Ok(Vec::new())
    }
}

fn base() -> String {
    format!("http://127.0.0.1:{PORT}")
}

/// A raw call, for what Homelabus never does itself: a person's session, a member.
async fn call(method: reqwest::Method, path: &str, token: &str, body: Option<Value>) -> Value {
    let mut req = reqwest::Client::new()
        .request(method, format!("{}{path}", base()))
        .bearer_auth(token);
    if let Some(b) = body {
        req = req.json(&b);
    }
    let resp = req.send().await.expect("sent");
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    assert!(status.is_success(), "{path}: {status} {text}");
    serde_json::from_str(&text).unwrap_or(Value::Null)
}

async fn start() {
    clean();
    run(&["network", "create", "--subnet", SUBNET, NET]);
    // Registration open in this container only: its first account stands for the
    // administrator who signed in through PocketID.
    run(&[
        "run",
        "-d",
        "--name",
        TERMIX,
        "--network",
        NET,
        "-p",
        &format!("127.0.0.1:{PORT}:8080"),
        "-e",
        "ALLOW_REGISTRATION=true",
        "-e",
        "ENABLE_TELEMETRY=false",
        &format!("{}:{}", catalog().spec.image.repo, catalog().spec.image.tag),
    ]);
    for (_, host, addr, image) in NODES {
        let start = if image.starts_with("alpine") {
            "apk add -q openssh && ssh-keygen -A && exec /usr/sbin/sshd -D -e"
        } else {
            "apt-get update -qq && apt-get install -y -qq openssh-server >/dev/null && \
             mkdir -p /run/sshd && exec /usr/sbin/sshd -D -e"
        };
        run(&[
            "run",
            "-d",
            "--name",
            &container(host),
            "--network",
            NET,
            "--ip",
            addr,
            image,
            "sh",
            "-c",
            start,
        ]);
    }
    let client = reqwest::Client::new();
    for _ in 0..120 {
        let termix = client
            .get(format!("{}/users/registration-allowed", base()))
            .send()
            .await
            .is_ok_and(|r| r.status().is_success());
        let sshd = NODES.iter().all(|n| {
            docker(&[
                "exec",
                &container(n.1),
                "sh",
                "-c",
                "grep -q ':0016 00000000:0000 0A' /proc/net/tcp",
            ])
            .status
            .success()
        });
        if termix && sshd {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    panic!("Termix or an sshd never came up");
}

/// An administrator, signed in, and the key they make for Homelabus.
async fn administrator_key() -> String {
    let client = reqwest::Client::new();
    let made = client
        .post(format!("{}/users/create", base()))
        .json(&json!({ "username": "camille", "password": "Camille-pass-1" }))
        .send()
        .await
        .expect("registered");
    assert!(made.status().is_success());
    let login = client
        .post(format!("{}/users/login", base()))
        .json(&json!({ "username": "camille", "password": "Camille-pass-1" }))
        .send()
        .await
        .expect("signed in");
    let jwt = login
        .headers()
        .get_all("set-cookie")
        .iter()
        .find_map(|c| {
            c.to_str()
                .ok()?
                .strip_prefix("jwt=")?
                .split(';')
                .next()
                .map(str::to_string)
        })
        .expect("a session");
    let me = call(reqwest::Method::GET, "/users/me", &jwt, None).await;
    let key = call(
        reqwest::Method::POST,
        "/users/api-keys",
        &jwt,
        Some(json!({ "name": "for homelabus", "userId": me["userId"] })),
    )
    .await;
    key["token"].as_str().expect("a token").to_string()
}

/// Where Termix reaches a node from: on its own node, the bridge's subnet (here the
/// one address [`ALLOWED`]); on every other, its node's address — the client then runs
/// in the first node's own network.
fn termix_source(node: &str) -> String {
    if node == NODES[0].1 {
        ALLOWED.to_string()
    } else {
        format!("container:{}", container(NODES[0].1))
    }
}

/// `id -un` on a node through `key`, from `from` — an address on the test network, or
/// `container:<name>` for that container's own. Termix hands a key back without its
/// final newline, and `ssh` refuses one without ("error in libcrypto"): it is put back.
fn ssh(from: &str, node: &str, key: &str) -> (bool, String) {
    let script = format!(
        "apk add -q openssh-client >/dev/null && umask 077 && printf '%s\\n' \"$KEY\" > /k && \
         ssh -i /k -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=10 \
         hlb-termix@{node} id -un"
    );
    let key = format!("KEY={key}");
    let mut args = vec!["run", "--rm", "--network"];
    match from.strip_prefix("container:") {
        Some(_) => args.push(from),
        None => args.extend([NET, "--ip", from]),
    }
    args.extend(["-e", &key, "alpine:3", "sh", "-c", &script]);
    let out = docker(&args);
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (
        out.status.success() && text.lines().any(|l| l.trim() == "hlb-termix"),
        text,
    )
}

fn failures(r: &hlb_engine::termix::Report) -> Vec<String> {
    r.lines
        .iter()
        .filter_map(|l| match &l.outcome {
            Outcome::Failed(w) | Outcome::NotConfigured(w) | Outcome::Waiting(w) => {
                Some(format!("{}: {} — {w}", l.subject, l.change))
            }
            _ => None,
        })
        .collect()
}

#[tokio::test]
#[ignore = "needs Docker and the network"]
async fn termix_holds_every_node_through_its_own_account() {
    let _cleanup = Cleanup;
    start().await;
    let state = State::in_memory().await.expect("state");
    let vault = Vault::ephemeral();
    state
        .upsert_app("termix", &catalog(), Some("termix.example.org"))
        .await
        .expect("recorded");
    state
        .set_app_status("termix", "installed")
        .await
        .expect("status");
    let stand = Stand::new();
    let reach = |u: &str| u.replace("http://termix:8080", &base());
    let access = NodeAccess {
        state: &state,
        vault: &vault,
        orchestrator: &stand,
        reach: &reach,
    };

    // Not let in yet: the run says how, and touches nothing.
    let r = access.run(true).await.expect("ran");
    assert!(
        r.stopped
            .as_deref()
            .is_some_and(|s| s.contains("hlb termix connect")),
        "{r:?}"
    );
    assert!(stand.jobs.lock().unwrap().is_empty());

    // An administrator's key becomes Homelabus's own account and key; theirs is gone.
    let given = administrator_key().await;
    let preview = access.connect(&given, false).await.expect("previewed");
    assert!(
        preview.lines.iter().all(|l| l.outcome == Outcome::ToDo),
        "{preview:?}"
    );
    assert!(state
        .secret(&Nodes::api_key_secret("termix"))
        .await
        .unwrap()
        .is_none());
    let connected = access.connect(&given, true).await.expect("connected");
    assert!(
        connected.stopped.is_none() && !connected.failed(),
        "{connected:?}"
    );
    let own = vault
        .decrypt(
            &state
                .secret(&Nodes::api_key_secret("termix"))
                .await
                .unwrap()
                .expect("kept"),
        )
        .unwrap();
    let me = call(reqwest::Method::GET, "/users/me", &own, None).await;
    assert_eq!(me["username"], ACCOUNT);
    assert_eq!(me["is_admin"], true);
    let gone = reqwest::Client::new()
        .get(format!("{}/users/me", base()))
        .bearer_auth(&given)
        .send()
        .await
        .unwrap();
    assert_eq!(
        gone.status(),
        401,
        "the administrator's key outlived the connection"
    );

    // A preview reads every node and writes none of them.
    let preview = access.run(false).await.expect("previewed");
    assert!(failures(&preview).is_empty(), "{:?}", failures(&preview));
    assert!(!preview.lines.is_empty());
    for (_, host, ..) in NODES {
        let id = docker(&["exec", &container(host), "id", "hlb-termix"]);
        assert!(!id.status.success(), "{host}: a preview made the account");
    }

    // Applied: every node's account, Termix's credential, role, hosts and shares.
    let r = access.run(true).await.expect("ran");
    assert!(failures(&r).is_empty(), "{:?}", failures(&r));
    assert_eq!(r.host_keys.len(), 2, "{r:?}");
    let again = access.run(true).await.expect("ran again");
    assert!(
        again.lines.is_empty(),
        "a second run changed: {:?}",
        again.lines
    );
    assert!(again.unchanged > 0);

    let hosts = call(reqwest::Method::GET, "/host/db/host", &own, None).await;
    let names: Vec<&str> = hosts
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|h| h["name"].as_str())
        .collect();
    assert_eq!(names.len(), 2, "{hosts}");
    for (_, host, addr, _) in NODES {
        let h = hosts
            .as_array()
            .unwrap()
            .iter()
            .find(|h| h["name"] == host)
            .expect("a host per node");
        assert_eq!(h["ip"], addr);
        assert_eq!(h["username"], "hlb-termix");
        assert_eq!(h["shareSshAuth"], true);
    }

    // A member of the role the sign-in gives: the node opens with what Termix hands
    // them, from Termix's address and from no other.
    call(
        reqwest::Method::POST,
        "/users/admin-create",
        &own,
        Some(json!({ "username": "dominique", "password": "Dominique-pass-1" })),
    )
    .await;
    let users = call(reqwest::Method::GET, "/users/list", &own, None).await;
    let member = users["users"]
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["username"] == "dominique")
        .expect("made")["userId"]
        .clone();
    let roles = call(reqwest::Method::GET, "/rbac/roles", &own, None).await;
    let role = roles["roles"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["name"] == "homelabus-nodes")
        .expect("the role OIDC_ROLE_MAP names")["id"]
        .clone();
    call(
        reqwest::Method::POST,
        &format!("/rbac/users/{}/roles", member.as_str().unwrap()),
        &own,
        Some(json!({ "roleId": role })),
    )
    .await;
    let member_key = call(
        reqwest::Method::POST,
        "/users/api-keys",
        &own,
        Some(json!({ "name": "member", "userId": member })),
    )
    .await["token"]
        .as_str()
        .unwrap()
        .to_string();
    let shared = call(
        reqwest::Method::GET,
        "/rbac/shared-hosts",
        &member_key,
        None,
    )
    .await;
    let deb1 = shared["sharedHosts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|h| h["name"] == NODES[0].1)
        .expect("the member sees the node")["id"]
        .as_i64()
        .unwrap();
    let handed = |id: i64| {
        let k = member_key.clone();
        async move {
            call(
                reqwest::Method::GET,
                &format!("/host/db/host/{id}/local-connection-auth"),
                &k,
                None,
            )
            .await["key"]
                .as_str()
                .expect("the shared key")
                .to_string()
        }
    };
    let key = handed(deb1).await;
    for (_, host, addr, _) in NODES {
        let (ok, out) = ssh(&termix_source(host), addr, &key);
        assert!(ok, "{host}: {out}");
        let (ok, out) = ssh(OTHER, addr, &key);
        assert!(!ok, "{host}: the key opened from elsewhere: {out}");
    }
    // 🔴 Every node's bridge has the same subnet: on any node but Termix's, a container
    // of that node must not open its own host with the key.
    let (ok, out) = ssh(ALLOWED, NODES[1].2, &key);
    assert!(!ok, "the bridge's subnet opened another node: {out}");

    // A rotation: every node and Termix move to a new key, the former opens nothing.
    let before = state
        .secret(&Nodes::node_key_secret("termix"))
        .await
        .unwrap();
    let r = access.rotate(true).await.expect("rotated");
    assert!(failures(&r).is_empty(), "{:?}", failures(&r));
    assert!(state
        .secret(&Nodes::next_node_key_secret("termix"))
        .await
        .unwrap()
        .is_none());
    assert_ne!(
        state
            .secret(&Nodes::node_key_secret("termix"))
            .await
            .unwrap(),
        before
    );
    let rotated = handed(deb1).await;
    assert_ne!(
        rotated, key,
        "the member's share still hands the former key"
    );
    for (_, host, addr, _) in NODES {
        assert!(
            ssh(&termix_source(host), addr, &rotated).0,
            "{host}: the new key"
        );
        assert!(
            !ssh(&termix_source(host), addr, &key).0,
            "{host}: the former key still opens"
        );
    }

    // The emergency vault would hold the key Termix holds now.
    let (wanted, _) = hlb_engine::emergency::wanted(&state, &vault)
        .await
        .expect("wanted");
    let item = wanted
        .iter()
        .find(|w| w.marker == "termix/node-key")
        .expect("the nodes' key, deposited");
    assert_eq!(item.username, "hlb-termix");
    // The same key — not the same text: each serialisation draws its check words.
    assert_eq!(
        hlb_termix::NodeKey::from_openssh(&item.password).expect("a key"),
        hlb_termix::NodeKey::from_openssh(&rotated).expect("a key")
    );

    // A node leaving the cluster takes its host with it.
    stand.nodes.lock().unwrap().pop();
    let r = access.run(true).await.expect("ran");
    assert!(
        r.lines
            .iter()
            .any(|l| l.subject == NODES[1].1 && l.change.contains("removed")),
        "{r:?}"
    );
    let hosts = call(reqwest::Method::GET, "/host/db/host", &own, None).await;
    assert_eq!(hosts.as_array().unwrap().len(), 1, "{hosts}");
}
