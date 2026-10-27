//! The demonstration, against the real binary: what it promises about the disk and
//! about real systems is decided in `main`, where no router test reaches.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::process::{Command, Stdio};
use std::time::Duration;

/// The controller, with none of the caller's `HLB_*` variables: a developer's
/// `HLB_MASTER_KEY` or `HLB_BACKUP_REPO` would decide the outcome otherwise.
fn controller(dir: &std::path::Path) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_hlb-controller"));
    c.env_clear().current_dir(dir).stdout(Stdio::null());
    c
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .expect("a free port")
        .port()
}

struct Killed(std::process::Child);

impl Drop for Killed {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn the_demonstration_writes_nothing_where_it_is_started() {
    let dir = tempfile::tempdir().expect("temp dir");
    let port = free_port();
    // The default `--master-key` is relative: started here, the demonstration used to
    // create `hlb-master.key` in this directory — and open the real one at the root.
    let child = controller(dir.path())
        .args(["--demo", "--listen", &format!("127.0.0.1:{port}")])
        .stderr(Stdio::null())
        .spawn()
        .expect("controller start");
    let _guard = Killed(child);

    let mut up = false;
    for _ in 0..100 {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            up = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(up, "the demonstration did not listen in time");

    let written: Vec<_> = std::fs::read_dir(dir.path())
        .expect("read dir")
        .map(|e| e.expect("entry").file_name())
        .collect();
    assert!(written.is_empty(), "the demonstration wrote {written:?}");
}

/// What the controller said on its way out, or `None` if it was still running: an
/// accepted flag starts a server, which would hold `output()` forever.
fn refused(mut cmd: Command) -> Option<String> {
    let mut child = Killed(
        cmd.stderr(Stdio::piped())
            .spawn()
            .expect("controller start"),
    );
    for _ in 0..50 {
        if child.0.try_wait().expect("wait").is_some() {
            let mut stderr = String::new();
            std::io::Read::read_to_string(&mut child.0.stderr.take()?, &mut stderr).ok()?;
            return Some(stderr);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    None
}

#[test]
fn the_demonstration_refuses_a_flag_that_reaches_a_real_system() {
    let dir = tempfile::tempdir().expect("temp dir");
    // Through the environment as well: that is how a deployment sets them, and a demo
    // started from the same shell inherits them.
    for (flag, env) in [
        ("--backup-repo", "HLB_BACKUP_REPO"),
        ("--postgres-admin", "HLB_POSTGRES_ADMIN"),
        ("--git-mirror", "HLB_GIT_MIRROR"),
    ] {
        let mut by_flag = controller(dir.path());
        by_flag.args(["--demo", flag, "somewhere"]);
        let mut by_env = controller(dir.path());
        by_env.arg("--demo").env(env, "somewhere");
        for cmd in [by_flag, by_env] {
            let stderr =
                refused(cmd).unwrap_or_else(|| panic!("{flag} was accepted beside --demo"));
            assert!(stderr.contains("cannot be used with"), "{flag}: {stderr}");
        }
    }
}
