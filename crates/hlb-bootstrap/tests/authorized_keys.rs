//! Manipulation réelle d'`authorized_keys` (§2ter phase 0bis).
//!
//! 🔴 C'est le fichier qui, mal écrit, enferme dehors définitivement. Les tests
//! unitaires vérifient le calcul des lignes ; ceux-ci vérifient que le **script**
//! exécuté sur la machine fait bien ce qu'il annonce — permissions comprises, car
//! `sshd` ignore silencieusement un fichier trop permissif.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use hlb_bootstrap::access::{self, ManagedKey};
use hlb_bootstrap::LocalRunner;

const HUMAINE: &str = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQ remy@portable";

fn cle() -> ManagedKey {
    ManagedKey::new(
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHLB homelabus@hlb",
        "hlb",
    )
}

/// Un faux `$HOME` avec un `authorized_keys` préexistant.
fn home_avec(contenu: &str) -> tempfile::TempDir {
    let d = tempfile::tempdir().expect("répertoire");
    let ssh = d.path().join(".ssh");
    std::fs::create_dir_all(&ssh).expect("mkdir");
    std::fs::write(ssh.join("authorized_keys"), contenu).expect("écriture");
    d
}

fn lire(d: &tempfile::TempDir) -> String {
    std::fs::read_to_string(d.path().join(".ssh/authorized_keys")).expect("lecture")
}

#[tokio::test]
async fn a_real_grant_preserves_the_human_key() {
    let d = home_avec(&format!("{HUMAINE}\n"));
    let home = d.path().to_string_lossy().to_string();
    let r = LocalRunner;

    let avant = access::read_authorized_keys(&r, &home)
        .await
        .expect("lecture");
    assert!(avant.contains(HUMAINE));

    let (apres, ch) = access::grant(&avant, &cle());
    access::write_authorized_keys(&r, &home, &apres, &avant)
        .await
        .expect("écriture");

    let final_ = lire(&d);
    assert!(
        final_.contains(HUMAINE),
        "🔴 clé humaine perdue :\n{final_}"
    );
    assert!(final_.contains("homelabus-managed:hlb"), "{final_}");
    assert_eq!(ch.kept, 1);
}

#[tokio::test]
async fn permissions_are_what_sshd_demands() {
    // ⚠️ sshd ignore authorized_keys SANS RIEN DIRE s'il est lisible par le groupe,
    // ou si ~/.ssh l'est. C'est le mode d'échec le plus déroutant de SSH.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let d = home_avec("");
        let home = d.path().to_string_lossy().to_string();
        let r = LocalRunner;

        // On dégrade volontairement les droits avant l'écriture.
        std::fs::set_permissions(
            d.path().join(".ssh"),
            std::fs::Permissions::from_mode(0o777),
        )
        .expect("chmod");

        let (apres, _) = access::grant("", &cle());
        access::write_authorized_keys(&r, &home, &apres, "")
            .await
            .expect("écriture");

        let m_dir = std::fs::metadata(d.path().join(".ssh")).expect("stat");
        let m_f = std::fs::metadata(d.path().join(".ssh/authorized_keys")).expect("stat");

        assert_eq!(
            m_dir.permissions().mode() & 0o777,
            0o700,
            "~/.ssh doit être 700"
        );
        assert_eq!(
            m_f.permissions().mode() & 0o777,
            0o600,
            "le fichier doit être 600"
        );
    }
}

#[tokio::test]
async fn an_empty_write_over_a_populated_file_is_refused() {
    // 🔴 Le garde-fou de dernier recours. Quel que soit le bug en amont, on ne doit
    // pas pouvoir couper tous les accès à une machine.
    let d = home_avec(&format!("{HUMAINE}\n"));
    let home = d.path().to_string_lossy().to_string();

    let r = access::write_authorized_keys(&LocalRunner, &home, "", HUMAINE).await;

    assert!(r.is_err(), "une écriture vide doit être REFUSÉE");
    let m = r.unwrap_err().to_string();
    assert!(m.contains("couperait tous les accès"), "{m}");

    // Et le fichier est intact.
    assert!(lire(&d).contains(HUMAINE));
}

#[tokio::test]
async fn a_grant_then_revoke_round_trip_leaves_no_trace() {
    let d = home_avec(&format!("{HUMAINE}\n"));
    let home = d.path().to_string_lossy().to_string();
    let r = LocalRunner;

    let avant = access::read_authorized_keys(&r, &home)
        .await
        .expect("lecture");
    let (avec, _) = access::grant(&avant, &cle());
    access::write_authorized_keys(&r, &home, &avec, &avant)
        .await
        .expect("pose");

    let relu = access::read_authorized_keys(&r, &home)
        .await
        .expect("relecture");
    let (sans, ch) = access::revoke(&relu, &cle());
    access::write_authorized_keys(&r, &home, &sans, &relu)
        .await
        .expect("retrait");

    let final_ = lire(&d);
    assert_eq!(ch.removed, 1);
    assert!(
        final_.contains(HUMAINE),
        "la clé humaine survit au cycle complet"
    );
    assert!(!final_.contains("homelabus-managed"), "{final_}");
}

#[tokio::test]
async fn a_missing_file_is_not_an_error() {
    // Une machine neuve n'a jamais eu de clé : ce n'est pas une panne.
    let d = tempfile::tempdir().expect("répertoire");
    let home = d.path().to_string_lossy().to_string();

    let c = access::read_authorized_keys(&LocalRunner, &home)
        .await
        .expect("pas d'erreur sur fichier absent");
    assert!(c.trim().is_empty());
}

#[tokio::test]
async fn exotic_content_survives_the_heredoc() {
    // Le contenu traverse un heredoc shell. Sans délimiteur entre quotes, `$`, les
    // backticks et les guillemets seraient interprétés — et une clé publique est du
    // base64 aléatoire, donc tôt ou tard elle contient de quoi tout casser.
    let piege = "command=\"echo $HOME `id`\" ssh-rsa AAAA'B$C`d` piege@x";
    let d = home_avec(&format!("{piege}\n"));
    let home = d.path().to_string_lossy().to_string();
    let r = LocalRunner;

    let avant = access::read_authorized_keys(&r, &home)
        .await
        .expect("lecture");
    let (apres, _) = access::grant(&avant, &cle());
    access::write_authorized_keys(&r, &home, &apres, &avant)
        .await
        .expect("écriture");

    assert!(lire(&d).contains(piege), "contenu altéré :\n{}", lire(&d));
}
