//! Remplacement du binaire en cours d'exécution (§7bis).
//!
//! ## 🔴 Le paradoxe : le programme qui se remplace lui-même
//!
//! Sous Unix, on **ne peut pas** écrire dans le fichier d'un exécutable en cours :
//! le noyau répond `ETXTBSY` (« Text file busy »). Un `cp nouveau /usr/local/bin/hlb`
//! échoue donc, et le message ne dit rien d'utile à qui ne connaît pas ce code.
//!
//! Mais on **peut** le renommer ou le supprimer : le processus garde son inode
//! vivant tant qu'il tourne. La bascule est donc :
//!
//! ```text
//! 1. écrire le nouveau binaire À CÔTÉ, jamais par-dessus
//! 2. renommer l'ancien   hlb → hlb.precedent   (le processus continue de tourner)
//! 3. renommer le nouveau hlb.nouveau → hlb     (atomique)
//! ```
//!
//! ⚠️ Les deux renommages doivent être **sur le même système de fichiers**. Un
//! `/tmp` sur un autre volume transforme le `rename` en copie non atomique, et une
//! coupure au mauvais moment laisse un binaire tronqué à la place de l'outil qui
//! sert à réparer.
//!
//! ## 🔴 L'ancien binaire est CONSERVÉ
//!
//! Pas archivé ailleurs, pas retéléchargeable : posé juste à côté. Le jour où l'on a
//! besoin d'un retour arrière, c'est souvent parce que quelque chose ne va pas — et
//! le réseau peut en faire partie.

use std::path::{Path, PathBuf};

/// Ce qui peut empêcher la bascule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SwapError {
    /// Le répertoire n'est pas accessible en écriture.
    NotWritable { path: PathBuf, detail: String },
    /// 🔴 Le nouveau binaire n'est pas exécutable.
    NotExecutable { path: PathBuf },
    /// 🔴 Le fichier téléchargé n'est pas un exécutable du tout.
    NotABinary { detail: String },
    /// Échec d'une opération de fichier.
    Io { step: String, detail: String },
}

impl SwapError {
    pub fn describe(&self) -> String {
        match self {
            Self::NotWritable { path, detail } => format!(
                "🔴 {} n'est pas modifiable ({detail}).\n\
                 La bascule renomme des fichiers DANS ce répertoire : il faut le droit \
                 d'écriture dessus, pas seulement sur le binaire.",
                path.display()
            ),
            Self::NotExecutable { path } => format!(
                "🔴 {} n'a pas le bit d'exécution. Après bascule, plus rien ne \
                 démarrerait — et il n'y aurait plus d'outil pour réparer.",
                path.display()
            ),
            Self::NotABinary { detail } => format!(
                "🔴 le fichier téléchargé n'est pas un exécutable ({detail}). \
                 Page d'erreur HTML servie à la place du binaire ? Redirection non \
                 suivie ?"
            ),
            Self::Io { step, detail } => format!("échec pendant « {step} » : {detail}"),
        }
    }
}

/// Où vont les fichiers pendant la bascule.
#[derive(Debug, Clone)]
pub struct Paths {
    /// Le binaire en service.
    pub current: PathBuf,
}

impl Paths {
    pub fn new(current: impl Into<PathBuf>) -> Self {
        Self {
            current: current.into(),
        }
    }

    /// Le nouveau binaire, avant bascule.
    ///
    /// ⚠️ **À côté du binaire cible**, pas dans `/tmp` : les deux doivent être sur le
    /// même système de fichiers pour que le `rename` soit atomique.
    pub fn incoming(&self) -> PathBuf {
        self.with_suffix(".nouveau")
    }

    /// L'ancien binaire, conservé pour le retour arrière.
    pub fn previous(&self) -> PathBuf {
        self.with_suffix(".precedent")
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

/// Un fichier ressemble-t-il à un exécutable natif ?
///
/// 🔴 Le contrôle qui attrape le cas le plus courant : un serveur qui répond une page
/// d'erreur HTML avec un code 200, ou une redirection non suivie. Sans lui, on
/// installerait `<!DOCTYPE html>` à la place du binaire — et il n'y aurait plus rien
/// pour réparer.
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
            // Mach-O 64 bits, natif et inversé.
            | [0xcf, 0xfa, 0xed, 0xfe]
            | [0xfe, 0xed, 0xfa, 0xcf]
            // Mach-O universel.
            | [0xca, 0xfe, 0xba, 0xbe]
    );

    if connu {
        return Ok(());
    }

    // On nomme la cause probable plutôt que d'afficher des octets bruts.
    let debut = String::from_utf8_lossy(&data[..16.min(data.len())]).to_lowercase();
    let detail = if debut.contains("<!doctype") || debut.contains("<html") {
        "page HTML reçue à la place du binaire".to_string()
    } else if debut.starts_with("#!") {
        "script, pas un exécutable natif".to_string()
    } else {
        format!("signature inconnue : {:02x?}", magie)
    };

    Err(SwapError::NotABinary { detail })
}

/// Vérifie que la bascule pourra avoir lieu, **avant** de télécharger.
///
/// 🔴 Découvrir que le répertoire n'est pas modifiable après avoir téléchargé et
/// vérifié un binaire est du temps perdu ; le découvrir après avoir renommé l'ancien
/// laisserait le système sans binaire du tout.
pub fn preflight(paths: &Paths) -> Result<(), SwapError> {
    let dossier = paths
        .current
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));

    // On teste le droit d'écriture en créant réellement un fichier : les bits de
    // permission mentent (montage en lecture seule, ACL, SELinux).
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

/// Installe le nouveau binaire, en conservant l'ancien.
///
/// Renvoie le chemin de l'ancien binaire, à garder pour un éventuel retour arrière.
pub fn swap(paths: &Paths, binary: &[u8]) -> Result<PathBuf, SwapError> {
    looks_like_binary(binary)?;
    preflight(paths)?;

    let entrant = paths.incoming();
    let precedent = paths.previous();

    // 1. Écrire à côté, jamais par-dessus : le noyau refuserait (ETXTBSY) et le
    //    message « Text file busy » n'aide personne.
    std::fs::write(&entrant, binary).map_err(|e| SwapError::Io {
        step: "écriture du nouveau binaire".into(),
        detail: e.to_string(),
    })?;

    // 2. Le bit d'exécution, AVANT la bascule. Après, il serait trop tard : plus
    //    rien ne démarrerait et il n'y aurait plus d'outil pour réparer.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&entrant, std::fs::Permissions::from_mode(0o755)).map_err(
            |e| SwapError::Io {
                step: "pose du bit d'exécution".into(),
                detail: e.to_string(),
            },
        )?;
    }
    verifier_executable(&entrant)?;

    // 3. Écarter l'ancien. Le processus en cours continue de tourner : son inode
    //    reste vivant tant qu'il n'a pas rendu la main.
    let _ = std::fs::remove_file(&precedent);
    std::fs::rename(&paths.current, &precedent).map_err(|e| SwapError::Io {
        step: "mise de côté de l'ancien binaire".into(),
        detail: e.to_string(),
    })?;

    // 4. Mettre le nouveau en place. Atomique : à aucun instant le chemin n'est
    //    absent pour un observateur extérieur.
    if let Err(e) = std::fs::rename(&entrant, &paths.current) {
        // 🔴 Remettre l'ancien : sans ça, il n'y a plus AUCUN binaire au chemin
        // attendu, et plus rien pour réparer.
        let _ = std::fs::rename(&precedent, &paths.current);
        return Err(SwapError::Io {
            step: "mise en place du nouveau binaire (ancien restauré)".into(),
            detail: e.to_string(),
        });
    }

    Ok(precedent)
}

/// Remet l'ancien binaire en place.
pub fn rollback(paths: &Paths) -> Result<(), SwapError> {
    let precedent = paths.previous();
    if !precedent.exists() {
        return Err(SwapError::Io {
            step: "retour arrière".into(),
            detail: format!("{} absent — rien à restaurer", precedent.display()),
        });
    }

    // On garde l'actuel sous un autre nom plutôt que de le supprimer : si le retour
    // arrière lui-même est une erreur, il faut pouvoir revenir en avant.
    let ecarte = paths.current.with_extension("echoue");
    let _ = std::fs::remove_file(&ecarte);
    let _ = std::fs::rename(&paths.current, &ecarte);

    std::fs::rename(&precedent, &paths.current).map_err(|e| SwapError::Io {
        step: "restauration de l'ancien binaire".into(),
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

    /// Un ELF minimal : les quatre octets de signature suffisent à nos contrôles.
    fn faux_binaire() -> Vec<u8> {
        let mut v = vec![0x7f, b'E', b'L', b'F'];
        v.extend_from_slice(&[0u8; 60]);
        v
    }

    #[test]
    fn the_incoming_file_sits_next_to_the_target() {
        // ⚠️ Sur le MÊME système de fichiers : un /tmp sur un autre volume
        // transforme le rename en copie non atomique.
        let p = Paths::new("/usr/local/bin/hlb");
        assert_eq!(p.incoming(), PathBuf::from("/usr/local/bin/hlb.nouveau"));
        assert_eq!(p.previous(), PathBuf::from("/usr/local/bin/hlb.precedent"));
        assert_eq!(p.incoming().parent(), p.current.parent());
    }

    #[test]
    fn an_html_page_is_never_installed() {
        // 🔴 Le cas le plus courant : serveur qui répond une page d'erreur en 200,
        // ou redirection non suivie. Sans ce contrôle on installerait du HTML à la
        // place du binaire — et il n'y aurait plus rien pour réparer.
        let e = looks_like_binary(b"<!DOCTYPE html><html>404</html>").unwrap_err();
        assert!(e.describe().contains("page HTML"), "{}", e.describe());
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
        // Le projet cible Linux, et se développe sur macOS.
        assert!(looks_like_binary(&faux_binaire()).is_ok());
        assert!(looks_like_binary(&[0xcf, 0xfa, 0xed, 0xfe, 0, 0, 0, 0]).is_ok());
        assert!(looks_like_binary(&[0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 0]).is_ok());
    }

    #[test]
    fn a_real_swap_keeps_the_old_binary() {
        let d = tempfile::tempdir().expect("répertoire");
        let cible = d.path().join("hlb");
        std::fs::write(&cible, b"ANCIEN").expect("binaire initial");

        let p = Paths::new(&cible);
        let garde = swap(&p, &faux_binaire()).expect("bascule");

        // Le nouveau est en place…
        assert_eq!(&std::fs::read(&cible).expect("lecture")[..4], b"\x7fELF");
        // …et l'ancien est juste à côté, pas perdu.
        assert_eq!(std::fs::read(&garde).expect("lecture"), b"ANCIEN");
        assert_eq!(garde, p.previous());
    }

    #[test]
    fn the_new_binary_is_executable() {
        // 🔴 Sans le bit d'exécution, plus rien ne démarre après bascule — et il n'y
        // a plus d'outil pour réparer.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let d = tempfile::tempdir().expect("répertoire");
            let cible = d.path().join("hlb");
            std::fs::write(&cible, b"ANCIEN").expect("initial");

            swap(&Paths::new(&cible), &faux_binaire()).expect("bascule");
            let m = std::fs::metadata(&cible).expect("stat");
            assert_ne!(m.permissions().mode() & 0o111, 0);
        }
    }

    #[test]
    fn a_rollback_puts_the_old_binary_back() {
        let d = tempfile::tempdir().expect("répertoire");
        let cible = d.path().join("hlb");
        std::fs::write(&cible, b"ANCIEN").expect("initial");

        let p = Paths::new(&cible);
        swap(&p, &faux_binaire()).expect("bascule");
        rollback(&p).expect("retour arrière");

        assert_eq!(std::fs::read(&cible).expect("lecture"), b"ANCIEN");
    }

    #[test]
    fn a_rollback_keeps_the_failed_version() {
        // Si le retour arrière est lui-même une erreur, il faut pouvoir revenir en
        // avant : on écarte, on ne supprime pas.
        let d = tempfile::tempdir().expect("répertoire");
        let cible = d.path().join("hlb");
        std::fs::write(&cible, b"ANCIEN").expect("initial");

        let p = Paths::new(&cible);
        swap(&p, &faux_binaire()).expect("bascule");
        rollback(&p).expect("retour");

        assert!(
            cible.with_extension("echoue").exists(),
            "la version écartée doit rester disponible"
        );
    }

    #[test]
    fn a_rollback_without_a_previous_version_says_so() {
        let d = tempfile::tempdir().expect("répertoire");
        let cible = d.path().join("hlb");
        std::fs::write(&cible, b"X").expect("initial");

        let e = rollback(&Paths::new(&cible)).unwrap_err();
        assert!(e.describe().contains("rien à restaurer"), "{}", e.describe());
    }

    #[test]
    fn a_read_only_directory_is_detected_before_anything_moves() {
        // 🔴 Le découvrir après avoir renommé l'ancien laisserait le système sans
        // binaire du tout.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let d = tempfile::tempdir().expect("répertoire");
            let cible = d.path().join("hlb");
            std::fs::write(&cible, b"ANCIEN").expect("initial");
            std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o555))
                .expect("lecture seule");

            let p = Paths::new(&cible);
            let r = swap(&p, &faux_binaire());

            // On remet les droits pour que le répertoire temporaire se nettoie.
            let _ = std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o755));

            assert!(matches!(r, Err(SwapError::NotWritable { .. })), "{r:?}");
            // Et l'ancien binaire n'a pas bougé.
            assert_eq!(std::fs::read(&cible).expect("lecture"), b"ANCIEN");
        }
    }

    #[test]
    fn nothing_moves_when_the_download_is_not_a_binary() {
        let d = tempfile::tempdir().expect("répertoire");
        let cible = d.path().join("hlb");
        std::fs::write(&cible, b"ANCIEN").expect("initial");

        let p = Paths::new(&cible);
        assert!(swap(&p, b"<!DOCTYPE html>").is_err());

        assert_eq!(std::fs::read(&cible).expect("lecture"), b"ANCIEN");
        assert!(!p.previous().exists(), "rien n'aurait dû être déplacé");
    }
}
