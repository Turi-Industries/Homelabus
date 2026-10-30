//! The kit split among relatives, end to end through the binary: split where the state
//! is, then combined from the printed sheets where there is none — the relatives'
//! machine is not the cluster.

#![allow(clippy::expect_used)]

use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

fn owner(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_hlb"))
        .current_dir(dir)
        .env("HLB_STATE", dir.join("hlb.db"))
        .env("HLB_MASTER_KEY", dir.join("master.age"))
        .args(args)
        .output()
        .expect("hlb runs")
}

/// `hlb emergency combine`, as a relative runs it: elsewhere, no state, no vault.
fn relative(dir: &Path, args: &[&str], typed: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_hlb"))
        .current_dir(dir)
        .env_remove("HLB_STATE")
        .env_remove("HLB_MASTER_KEY")
        .args(["emergency", "combine"])
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("hlb runs");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(typed.as_bytes())
        .expect("typed");
    child.wait_with_output().expect("hlb ends")
}

/// A share's lines, as a relative reads them off the sheet — two lines, as printed.
fn typed_from(sheet: &Path) -> String {
    let text = std::fs::read_to_string(sheet).expect("sheet");
    let mut lines = text
        .lines()
        .skip_while(|l| !l.starts_with("The share"))
        .skip(1)
        .skip_while(|l| l.is_empty())
        .take_while(|l| !l.is_empty())
        .map(|l| format!("{}\n", l.trim()))
        .collect::<String>();
    assert!(lines.lines().count() == 2, "a share on two lines:\n{text}");
    lines.push('\n');
    lines
}

#[test]
fn three_relatives_open_the_kit_without_the_cluster_and_two_cannot() {
    let house = tempfile::tempdir().expect("house");
    let away = tempfile::tempdir().expect("away");
    let family = house.path().join("family");
    let made = owner(
        house.path(),
        &[
            "emergency",
            "split",
            "--out",
            family.to_str().expect("utf-8"),
        ],
    );
    assert!(made.status.success(), "{made:?}");
    let plain = owner(house.path(), &["emergency", "kit"]);
    assert!(plain.status.success(), "{plain:?}");
    let kit = String::from_utf8(plain.stdout).expect("kit");
    let master = kit
        .lines()
        .map(str::trim)
        .find(|l| l.starts_with("AGE-SECRET-KEY-"))
        .expect("the master key is on the kit");

    std::fs::copy(family.join("kit.age"), away.path().join("kit.age")).expect("sent");
    let three: String = [1, 4, 5]
        .iter()
        .map(|i| typed_from(&family.join(format!("share-{i}.txt"))))
        .collect::<String>()
        .replace("\n\n", "\n")
        + "\n";

    let opened = relative(away.path(), &["--kit", "kit.age"], &three);
    assert!(opened.status.success(), "{opened:?}");
    assert!(
        String::from_utf8_lossy(&opened.stdout).contains(master),
        "the opened kit carries the master key"
    );
    // Nothing was made where it ran: no state, no vault.
    let left: Vec<_> = std::fs::read_dir(away.path())
        .expect("dir")
        .map(|e| e.expect("entry").file_name())
        .collect();
    assert_eq!(left, vec![std::ffi::OsString::from("kit.age")]);

    let two: String = typed_from(&family.join("share-2.txt"))
        .trim_end()
        .to_string()
        + "\n"
        + &typed_from(&family.join("share-3.txt"));
    let refused = relative(away.path(), &["--kit", "kit.age"], &two);
    assert!(!refused.status.success());
    assert!(refused.stdout.is_empty(), "nothing of the kit is shown");
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("2 given"),
        "{refused:?}"
    );

    // The kit sealed again after the split opens with the same shares.
    let resealed = house.path().join("kit-again.age");
    let again = owner(
        house.path(),
        &[
            "emergency",
            "kit",
            "--sealed",
            "--out",
            resealed.to_str().expect("utf-8"),
        ],
    );
    assert!(again.status.success(), "{again:?}");
    std::fs::copy(&resealed, away.path().join("again.age")).expect("sent");
    let reopened = relative(away.path(), &["--kit", "again.age"], &three);
    assert!(reopened.status.success(), "{reopened:?}");
    assert!(String::from_utf8_lossy(&reopened.stdout).contains(master));

    // A second split is refused unless asked for: the shares are in people's drawers.
    let second = owner(house.path(), &["emergency", "split", "--out", "elsewhere"]);
    assert!(!second.status.success());
    assert!(!house.path().join("elsewhere").exists());
}
