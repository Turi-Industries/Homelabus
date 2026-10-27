//! Replacing the running binary.
//!
//! ## 🔴 The paradox: a program replacing itself
//!
//! Under Unix you **cannot** write into the file of a running executable: the kernel
//! answers `ETXTBSY` ("Text file busy"). So `cp new /usr/local/bin/hlb` fails, and the
//! message says nothing useful to anyone who does not know that code.
//!
//! But you **can** rename or delete it: the process keeps its inode alive as long as it
//! runs. So the switch is:
//!
//! ```text
//! 1. write the new binary NEXT TO it, never over it, and flush it to the disk
//! 2. link the old one     hlb → hlb.previous   (a second name, nothing moves)
//! 3. rename the new one   hlb.new → hlb        (atomic, replaces in one step)
//! 4. flush the directory, so the renames survive a power cut
//! ```
//!
//! ⚠️ Renaming the old one aside first left a moment with NO `hlb` at the path, and a
//! crash in it left none at all. `rename` over an existing name replaces it atomically:
//! the path always names a whole binary, the old or the new.
//!
//! ⚠️ Both renames must be **on the same filesystem**. A `/tmp` on another volume turns
//! the `rename` into a non-atomic copy, and an interruption at the wrong moment leaves a
//! truncated binary where the tool used to repair things should be.
//!
//! ## 🔴 The old binary is KEPT
//!
//! Not archived elsewhere, not re-downloadable: placed right next to it. The day you
//! need a rollback is usually a day when something is wrong - and the network can be
//! part of it.

use std::path::{Path, PathBuf};

/// What can prevent the switch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SwapError {
    /// The directory is not writable.
    NotWritable { path: PathBuf, detail: String },
    /// 🔴 The new binary is not executable.
    NotExecutable { path: PathBuf },
    /// 🔴 The downloaded file is not an executable at all.
    NotABinary { detail: String },
    /// A file operation failed.
    Io { step: String, detail: String },
}

impl SwapError {
    pub fn describe(&self) -> String {
        match self {
            Self::NotWritable { path, detail } => format!(
                "🔴 {} is not writable ({detail}).\n\
                 The switch renames files INSIDE that directory: write permission on \
                 it is needed, not just on the binary.",
                path.display()
            ),
            Self::NotExecutable { path } => format!(
                "🔴 {} has no execute bit. After the switch nothing would start - and \
                 there would be no tool left to repair with.",
                path.display()
            ),
            Self::NotABinary { detail } => format!(
                "🔴 the downloaded file is not an executable ({detail}). An HTML \
                 error page served instead of the binary? An unfollowed redirect?"
            ),
            Self::Io { step, detail } => format!("failed during \"{step}\": {detail}"),
        }
    }
}

/// Where the files go during the switch.
#[derive(Debug, Clone)]
pub struct Paths {
    /// The binary currently in service.
    pub current: PathBuf,
}

impl Paths {
    pub fn new(current: impl Into<PathBuf>) -> Self {
        Self {
            current: current.into(),
        }
    }

    /// The new binary, before the switch.
    ///
    /// ⚠️ **Next to the target binary**, not in `/tmp`: both must sit on the same
    /// filesystem for the `rename` to be atomic.
    pub fn incoming(&self) -> PathBuf {
        self.with_suffix(".new")
    }

    /// The old binary, kept for the rollback.
    pub fn previous(&self) -> PathBuf {
        self.with_suffix(".previous")
    }

    fn with_suffix(&self, suffix: &str) -> PathBuf {
        let mut name = self
            .current
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "hlb".into());
        name.push_str(suffix);
        self.current.with_file_name(name)
    }
}

/// Does a file look like a native executable?
///
/// 🔴 The check that catches the most common case: a server answering an HTML error
/// page with a 200, or an unfollowed redirect. Without it, `<!DOCTYPE html>` would be
/// installed instead of the binary - and nothing would be left to repair with.
pub fn looks_like_binary(data: &[u8]) -> Result<(), SwapError> {
    if data.len() < 4 {
        return Err(SwapError::NotABinary {
            detail: format!("{} bytes only", data.len()),
        });
    }

    let magic = &data[..4];
    let known = matches!(
        magic,
        // ELF : Linux, BSD.
        [0x7f, b'E', b'L', b'F']
            // Mach-O 64-bit, native and byte-swapped.
            | [0xcf, 0xfa, 0xed, 0xfe]
            | [0xfe, 0xed, 0xfa, 0xcf]
            // Mach-O universel.
            | [0xca, 0xfe, 0xba, 0xbe]
    );

    if known {
        return Ok(());
    }

    // The likely cause is named rather than dumping raw bytes.
    let start = String::from_utf8_lossy(&data[..16.min(data.len())]).to_lowercase();
    let detail = if start.contains("<!doctype") || start.contains("<html") {
        "an HTML page received instead of the binary".to_string()
    } else if start.starts_with("#!") {
        "a script, not a native executable".to_string()
    } else {
        format!("unknown signature: {:02x?}", magic)
    };

    Err(SwapError::NotABinary { detail })
}

/// Checks the switch will be possible, **before** downloading.
///
/// 🔴 Discovering the directory is not writable after downloading and verifying a
/// binary is wasted time; discovering it after renaming the old one would leave the
/// system with no binary at all.
pub fn preflight(paths: &Paths) -> Result<(), SwapError> {
    let folder = paths
        .current
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));

    // Write permission is tested by actually creating a file: permission bits lie
    // (read-only mount, ACLs, SELinux).
    let probe = folder.join(".hlb-write-probe");
    match std::fs::write(&probe, b"") {
        Ok(()) => {
            let _ = std::fs::remove_file(&probe);
            Ok(())
        }
        Err(e) => Err(SwapError::NotWritable {
            path: folder,
            detail: e.to_string(),
        }),
    }
}

/// Installs the new binary, keeping the old one.
///
/// Returns the path of the old binary, to keep for a possible rollback.
pub fn swap(paths: &Paths, binary: &[u8]) -> Result<PathBuf, SwapError> {
    looks_like_binary(binary)?;
    preflight(paths)?;

    let incoming_path = paths.incoming();
    let previous_path = paths.previous();

    // 1. Write next to it, never over it: the kernel would refuse (ETXTBSY) and the
    //    "Text file busy" message helps nobody. Flushed: a rename can reach the disk
    //    before the data it names, and a power cut then leaves an empty `hlb`.
    write_synced(&incoming_path, binary)?;

    // 2. The execute bit, BEFORE the switch. Afterwards it would be too late: nothing
    //    would start and there would be no tool left to repair with.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&incoming_path, std::fs::Permissions::from_mode(0o755)).map_err(
            |e| SwapError::Io {
                step: "setting the execute bit".into(),
                detail: e.to_string(),
            },
        )?;
    }
    check_executable(&incoming_path)?;

    // 3. Keep the old one under a second name. A hard link moves nothing: the path
    //    keeps naming the running binary until the rename below replaces it.
    let _ = std::fs::remove_file(&previous_path);
    if std::fs::hard_link(&paths.current, &previous_path).is_err() {
        // A filesystem without hard links: a copy keeps it just as well, slower.
        std::fs::copy(&paths.current, &previous_path).map_err(|e| SwapError::Io {
            step: "keeping the old binary".into(),
            detail: e.to_string(),
        })?;
    }

    // 4. Put the new one in place. Atomic: at no instant is the path absent to an
    //    outside observer, and a failure leaves the old one where it was.
    std::fs::rename(&incoming_path, &paths.current).map_err(|e| SwapError::Io {
        step: "putting the new binary in place (old one untouched)".into(),
        detail: e.to_string(),
    })?;
    sync_directory(&paths.current);

    Ok(previous_path)
}

/// Puts the old binary back.
pub fn rollback(paths: &Paths) -> Result<(), SwapError> {
    let previous_path = paths.previous();
    if !previous_path.exists() {
        return Err(SwapError::Io {
            step: "rollback".into(),
            detail: format!(
                "{} is missing - nothing to restore",
                previous_path.display()
            ),
        });
    }

    // The current one is kept under another name rather than deleted: if the rollback
    // is itself a mistake, going forward again must stay possible.
    let set_aside = paths.current.with_extension("failed");
    let _ = std::fs::remove_file(&set_aside);
    let _ = std::fs::rename(&paths.current, &set_aside);

    std::fs::rename(&previous_path, &paths.current).map_err(|e| SwapError::Io {
        step: "restoring the old binary".into(),
        detail: e.to_string(),
    })
}

fn write_synced(path: &Path, data: &[u8]) -> Result<(), SwapError> {
    use std::io::Write;
    let io = |e: std::io::Error| SwapError::Io {
        step: "writing the new binary".into(),
        detail: e.to_string(),
    };
    let mut f = std::fs::File::create(path).map_err(io)?;
    f.write_all(data).map_err(io)?;
    f.sync_all().map_err(io)
}

/// Flushes the directory holding `path`, where a rename is recorded. Best effort: the
/// binary is already in place, and some filesystems refuse to open a directory so.
fn sync_directory(path: &Path) {
    if let Some(dir) = path.parent() {
        let dir = if dir.as_os_str().is_empty() {
            Path::new(".")
        } else {
            dir
        };
        if let Ok(d) = std::fs::File::open(dir) {
            let _ = d.sync_all();
        }
    }
}

#[cfg(unix)]
fn check_executable(p: &Path) -> Result<(), SwapError> {
    use std::os::unix::fs::PermissionsExt;
    let m = std::fs::metadata(p).map_err(|e| SwapError::Io {
        step: "reading the permissions".into(),
        detail: e.to_string(),
    })?;
    if m.permissions().mode() & 0o111 == 0 {
        return Err(SwapError::NotExecutable {
            path: p.to_path_buf(),
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_executable(_p: &Path) -> Result<(), SwapError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal ELF: the four signature bytes are enough for our checks.
    fn fake_binary() -> Vec<u8> {
        let mut v = vec![0x7f, b'E', b'L', b'F'];
        v.extend_from_slice(&[0u8; 60]);
        v
    }

    #[test]
    fn the_incoming_file_sits_next_to_the_target() {
        // ⚠️ On the SAME filesystem: a /tmp on another volume turns the rename into a
        // non-atomic copy.
        let p = Paths::new("/usr/local/bin/hlb");
        assert_eq!(p.incoming(), PathBuf::from("/usr/local/bin/hlb.new"));
        assert_eq!(p.previous(), PathBuf::from("/usr/local/bin/hlb.previous"));
        assert_eq!(p.incoming().parent(), p.current.parent());
    }

    #[test]
    fn an_html_page_is_never_installed() {
        // 🔴 The most common case: a server answering an error page with a 200, or an
        // unfollowed redirect. Without this check, HTML would be installed instead of
        // the binary - and nothing would be left to repair with.
        let e = looks_like_binary(b"<!DOCTYPE html><html>404</html>").unwrap_err();
        assert!(e.describe().contains("HTML page"), "{}", e.describe());
    }

    #[test]
    fn a_shell_script_is_refused() {
        let e = looks_like_binary(b"#!/bin/sh\necho coucou\n").unwrap_err();
        assert!(e.describe().contains("script"), "{}", e.describe());
    }

    #[test]
    fn a_truncated_download_is_refused() {
        let e = looks_like_binary(b"EL").unwrap_err();
        assert!(e.describe().contains("2 bytes"), "{}", e.describe());
    }

    #[test]
    fn elf_and_mach_o_are_both_accepted() {
        // The project targets Linux, and is developed on macOS.
        assert!(looks_like_binary(&fake_binary()).is_ok());
        assert!(looks_like_binary(&[0xcf, 0xfa, 0xed, 0xfe, 0, 0, 0, 0]).is_ok());
        assert!(looks_like_binary(&[0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 0]).is_ok());
    }

    #[test]
    fn a_real_swap_keeps_the_old_binary() {
        let d = tempfile::tempdir().expect("temp dir");
        let target = d.path().join("hlb");
        std::fs::write(&target, b"ANCIEN").expect("binary initial");

        let p = Paths::new(&target);
        let kept = swap(&p, &fake_binary()).expect("swap");

        // The new one is in place…
        assert_eq!(&std::fs::read(&target).expect("read")[..4], b"\x7fELF");
        // ...and the old one is right beside it, not lost.
        assert_eq!(std::fs::read(&kept).expect("read"), b"ANCIEN");
        assert_eq!(kept, p.previous());
    }

    #[test]
    fn the_path_always_names_a_binary_during_the_switch() {
        // 🔴 Renamed aside first, the old binary left the path empty between two
        // renames: a crash there left no `hlb` at all. Watched from another thread over
        // many switches, the path is never missing.
        let d = tempfile::tempdir().expect("temp dir");
        let target = d.path().join("hlb");
        std::fs::write(&target, fake_binary()).expect("initial");
        let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let watcher = {
            let (target, done) = (target.clone(), done.clone());
            std::thread::spawn(move || {
                let mut missing = 0u32;
                while !done.load(std::sync::atomic::Ordering::Relaxed) {
                    if std::fs::symlink_metadata(&target).is_err() {
                        missing += 1;
                    }
                }
                missing
            })
        };
        let p = Paths::new(&target);
        for _ in 0..2000 {
            swap(&p, &fake_binary()).expect("swap");
        }
        done.store(true, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(watcher.join().expect("watcher"), 0, "the path went missing");
    }

    #[test]
    fn the_new_binary_is_executable() {
        // 🔴 Without the execute bit nothing starts after the switch - and there is no
        // tool left to repair with.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let d = tempfile::tempdir().expect("temp dir");
            let target = d.path().join("hlb");
            std::fs::write(&target, b"ANCIEN").expect("initial");

            swap(&Paths::new(&target), &fake_binary()).expect("swap");
            let m = std::fs::metadata(&target).expect("stat");
            assert_ne!(m.permissions().mode() & 0o111, 0);
        }
    }

    #[test]
    fn a_rollback_puts_the_old_binary_back() {
        let d = tempfile::tempdir().expect("temp dir");
        let target = d.path().join("hlb");
        std::fs::write(&target, b"ANCIEN").expect("initial");

        let p = Paths::new(&target);
        swap(&p, &fake_binary()).expect("swap");
        rollback(&p).expect("rollback");

        assert_eq!(std::fs::read(&target).expect("read"), b"ANCIEN");
    }

    #[test]
    fn a_rollback_keeps_the_failed_version() {
        // If the rollback is itself a mistake, going forward again must stay possible:
        // the file is moved aside, not deleted.
        let d = tempfile::tempdir().expect("temp dir");
        let target = d.path().join("hlb");
        std::fs::write(&target, b"ANCIEN").expect("initial");

        let p = Paths::new(&target);
        swap(&p, &fake_binary()).expect("swap");
        rollback(&p).expect("return_to");

        assert!(
            target.with_extension("failed").exists(),
            "the set-aside version must stay available"
        );
    }

    #[test]
    fn a_rollback_without_a_previous_version_says_so() {
        let d = tempfile::tempdir().expect("temp dir");
        let target = d.path().join("hlb");
        std::fs::write(&target, b"X").expect("initial");

        let e = rollback(&Paths::new(&target)).unwrap_err();
        assert!(
            e.describe().contains("nothing to restore"),
            "{}",
            e.describe()
        );
    }

    #[test]
    fn a_read_only_directory_is_detected_before_anything_moves() {
        // 🔴 Discovering it after renaming the old one would leave the system with no
        // binary at all.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let d = tempfile::tempdir().expect("temp dir");
            let target = d.path().join("hlb");
            std::fs::write(&target, b"ANCIEN").expect("initial");
            std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o555))
                .expect("read-only");

            let p = Paths::new(&target);
            let r = swap(&p, &fake_binary());

            // Permissions are restored so the temp directory can clean itself up.
            let _ = std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o755));

            assert!(matches!(r, Err(SwapError::NotWritable { .. })), "{r:?}");
            // And the old binary has not moved.
            assert_eq!(std::fs::read(&target).expect("read"), b"ANCIEN");
        }
    }

    #[test]
    fn nothing_moves_when_the_download_is_not_a_binary() {
        let d = tempfile::tempdir().expect("temp dir");
        let target = d.path().join("hlb");
        std::fs::write(&target, b"ANCIEN").expect("initial");

        let p = Paths::new(&target);
        assert!(swap(&p, b"<!DOCTYPE html>").is_err());

        assert_eq!(std::fs::read(&target).expect("read"), b"ANCIEN");
        assert!(!p.previous().exists(), "nothing should have been moved");
    }
}
