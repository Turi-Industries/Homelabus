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
//! 1. write the new binary NEXT TO it, never over it
//! 2. rename the old one   hlb → hlb.previous   (the process keeps running)
//! 3. rename the new one   hlb.new → hlb        (atomic)
//! ```
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
                "🔴 {} n'est pas modifiable ({detail}).\n\
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
                 error page served instead of the binary? An unfollowed \
                 suivie ?"
            ),
            Self::Io { step, detail } => format!("failed during \"{step}\": {detail}"),
        }
    }
}

/// Where the files go during the switch.
#[derive(Debug, Clone)]
pub struct Paths {
    /// Le binary en service.
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
        self.with_suffix(".nouveau")
    }

    /// The old binary, kept for the rollback.
    pub fn previous(&self) -> PathBuf {
        self.with_suffix(".previous_path")
    }

    fn with_suffix(&self, suffix: &str) -> PathBuf {
        let mut nom = self
            .current
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "hlb".into());
        nom.push_str(suffix);
        self.current.with_file_name(nom)
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
            detail: format!("{} octets seulement", data.len()),
        });
    }

    let magie = &data[..4];
    let connu = matches!(
        magie,
        // ELF : Linux, BSD.
        [0x7f, b'E', b'L', b'F']
            // Mach-O 64-bit, native and byte-swapped.
            | [0xcf, 0xfa, 0xed, 0xfe]
            | [0xfe, 0xed, 0xfa, 0xcf]
            // Mach-O universel.
            | [0xca, 0xfe, 0xba, 0xbe]
    );

    if connu {
        return Ok(());
    }

    // The likely cause is named rather than dumping raw bytes.
    let debut = String::from_utf8_lossy(&data[..16.min(data.len())]).to_lowercase();
    let detail = if debut.contains("<!doctype") || debut.contains("<html") {
        "an HTML page received instead of the binary".to_string()
    } else if debut.starts_with("#!") {
        "a script, not a native executable".to_string()
    } else {
        format!("signature inconnue : {:02x?}", magie)
    };

    Err(SwapError::NotABinary { detail })
}

/// Checks the switch will be possible, **before** downloading.
///
/// 🔴 Discovering the directory is not writable after downloading and verifying a
/// binary is wasted time; discovering it after renaming the old one would leave the
/// system with no binary at all.
pub fn preflight(paths: &Paths) -> Result<(), SwapError> {
    let dossier = paths
        .current
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));

    // Write permission is tested by actually creating a file: permission bits lie
    // (read-only mount, ACLs, SELinux).
    let sonde = dossier.join(".hlb-sonde-ecriture");
    match std::fs::write(&sonde, b"") {
        Ok(()) => {
            let _ = std::fs::remove_file(&sonde);
            Ok(())
        }
        Err(e) => Err(SwapError::NotWritable {
            path: dossier,
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

    let entrant = paths.incoming();
    let previous_path = paths.previous();

    // 1. Write next to it, never over it: the kernel would refuse (ETXTBSY) and the
    //    "Text file busy" message helps nobody.
    std::fs::write(&entrant, binary).map_err(|e| SwapError::Io {
        step: "writing the new binary".into(),
        detail: e.to_string(),
    })?;

    // 2. The execute bit, BEFORE the switch. Afterwards it would be too late: nothing
    //    would start and there would be no tool left to repair with.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&entrant, std::fs::Permissions::from_mode(0o755)).map_err(
            |e| SwapError::Io {
                step: "setting the execute bit".into(),
                detail: e.to_string(),
            },
        )?;
    }
    verifier_executable(&entrant)?;

    // 3. Move the old one aside. The running process keeps going: its inode stays
    //    alive until it exits.
    let _ = std::fs::remove_file(&previous_path);
    std::fs::rename(&paths.current, &previous_path).map_err(|e| SwapError::Io {
        step: "moving the old binary aside".into(),
        detail: e.to_string(),
    })?;

    // 4. Put the new one in place. Atomic: at no instant is the path absent to an
    //    outside observer.
    if let Err(e) = std::fs::rename(&entrant, &paths.current) {
        // 🔴 Put the old one back: without this there is NO binary at the expected
        // path, and nothing left to repair with.
        let _ = std::fs::rename(&previous_path, &paths.current);
        return Err(SwapError::Io {
            step: "putting the new binary in place (old one restored)".into(),
            detail: e.to_string(),
        });
    }

    Ok(previous_path)
}

/// Remet l'ancien binary en place.
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
    let ecarte = paths.current.with_extension("echoue");
    let _ = std::fs::remove_file(&ecarte);
    let _ = std::fs::rename(&paths.current, &ecarte);

    std::fs::rename(&previous_path, &paths.current).map_err(|e| SwapError::Io {
        step: "restauration de l'ancien binary".into(),
        detail: e.to_string(),
    })
}

#[cfg(unix)]
fn verifier_executable(p: &Path) -> Result<(), SwapError> {
    use std::os::unix::fs::PermissionsExt;
    let m = std::fs::metadata(p).map_err(|e| SwapError::Io {
        step: "lecture des permissions".into(),
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
fn verifier_executable(_p: &Path) -> Result<(), SwapError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal ELF: the four signature bytes are enough for our checks.
    fn faux_binaire() -> Vec<u8> {
        let mut v = vec![0x7f, b'E', b'L', b'F'];
        v.extend_from_slice(&[0u8; 60]);
        v
    }

    #[test]
    fn the_incoming_file_sits_next_to_the_target() {
        // ⚠️ On the SAME filesystem: a /tmp on another volume turns the rename into a
        // non-atomic copy.
        let p = Paths::new("/usr/local/bin/hlb");
        assert_eq!(p.incoming(), PathBuf::from("/usr/local/bin/hlb.nouveau"));
        assert_eq!(
            p.previous(),
            PathBuf::from("/usr/local/bin/hlb.previous_path")
        );
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
        assert!(e.describe().contains("2 octets"), "{}", e.describe());
    }

    #[test]
    fn elf_and_mach_o_are_both_accepted() {
        // The project targets Linux, and is developed on macOS.
        assert!(looks_like_binary(&faux_binaire()).is_ok());
        assert!(looks_like_binary(&[0xcf, 0xfa, 0xed, 0xfe, 0, 0, 0, 0]).is_ok());
        assert!(looks_like_binary(&[0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 0]).is_ok());
    }

    #[test]
    fn a_real_swap_keeps_the_old_binary() {
        let d = tempfile::tempdir().expect("temp dir");
        let cible = d.path().join("hlb");
        std::fs::write(&cible, b"ANCIEN").expect("binary initial");

        let p = Paths::new(&cible);
        let garde = swap(&p, &faux_binaire()).expect("bascule");

        // Le nouveau est en place…
        assert_eq!(&std::fs::read(&cible).expect("lecture")[..4], b"\x7fELF");
        // ...and the old one is right beside it, not lost.
        assert_eq!(std::fs::read(&garde).expect("lecture"), b"ANCIEN");
        assert_eq!(garde, p.previous());
    }

    #[test]
    fn the_new_binary_is_executable() {
        // 🔴 Without the execute bit nothing starts after the switch - and there is no
        // tool left to repair with.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let d = tempfile::tempdir().expect("temp dir");
            let cible = d.path().join("hlb");
            std::fs::write(&cible, b"ANCIEN").expect("initial");

            swap(&Paths::new(&cible), &faux_binaire()).expect("bascule");
            let m = std::fs::metadata(&cible).expect("stat");
            assert_ne!(m.permissions().mode() & 0o111, 0);
        }
    }

    #[test]
    fn a_rollback_puts_the_old_binary_back() {
        let d = tempfile::tempdir().expect("temp dir");
        let cible = d.path().join("hlb");
        std::fs::write(&cible, b"ANCIEN").expect("initial");

        let p = Paths::new(&cible);
        swap(&p, &faux_binaire()).expect("bascule");
        rollback(&p).expect("rollback");

        assert_eq!(std::fs::read(&cible).expect("lecture"), b"ANCIEN");
    }

    #[test]
    fn a_rollback_keeps_the_failed_version() {
        // If the rollback is itself a mistake, going forward again must stay possible:
        // the file is moved aside, not deleted.
        let d = tempfile::tempdir().expect("temp dir");
        let cible = d.path().join("hlb");
        std::fs::write(&cible, b"ANCIEN").expect("initial");

        let p = Paths::new(&cible);
        swap(&p, &faux_binaire()).expect("bascule");
        rollback(&p).expect("retour");

        assert!(
            cible.with_extension("echoue").exists(),
            "the set-aside version must stay available"
        );
    }

    #[test]
    fn a_rollback_without_a_previous_version_says_so() {
        let d = tempfile::tempdir().expect("temp dir");
        let cible = d.path().join("hlb");
        std::fs::write(&cible, b"X").expect("initial");

        let e = rollback(&Paths::new(&cible)).unwrap_err();
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
            let cible = d.path().join("hlb");
            std::fs::write(&cible, b"ANCIEN").expect("initial");
            std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o555))
                .expect("lecture seule");

            let p = Paths::new(&cible);
            let r = swap(&p, &faux_binaire());

            // Permissions are restored so the temp directory can clean itself up.
            let _ = std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o755));

            assert!(matches!(r, Err(SwapError::NotWritable { .. })), "{r:?}");
            // And the old binary has not moved.
            assert_eq!(std::fs::read(&cible).expect("lecture"), b"ANCIEN");
        }
    }

    #[test]
    fn nothing_moves_when_the_download_is_not_a_binary() {
        let d = tempfile::tempdir().expect("temp dir");
        let cible = d.path().join("hlb");
        std::fs::write(&cible, b"ANCIEN").expect("initial");

        let p = Paths::new(&cible);
        assert!(swap(&p, b"<!DOCTYPE html>").is_err());

        assert_eq!(std::fs::read(&cible).expect("lecture"), b"ANCIEN");
        assert!(!p.previous().exists(), "nothing should have been moved");
    }
}
