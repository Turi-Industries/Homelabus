//! Vérification de restauration (§8.3).
//!
//! > « Un backup non testé n'est pas un backup. »
//!
//! Le piège est de croire qu'on a vérifié quelque chose alors qu'on n'a rien prouvé :
//!
//! | Ce qu'on fait souvent | Ce que ça prouve |
//! |---|---|
//! | L'instantané a un identifiant | restic a répondu |
//! | `restic check` passe | les métadonnées sont cohérentes |
//! | `restic check --read-data` passe | les blocs sont lisibles et non corrompus |
//! | **On restaure et on compare** | **les données reviennent réellement** |
//!
//! Seule la dernière ligne répond à la question qu'on se pose vraiment. C'est donc
//! celle-ci qu'on implémente : restaurer dans un espace jetable, puis comparer le
//! contenu obtenu à ce que l'instantané prétend contenir.

use crate::restic::{Repository, Runner};
use crate::Result;

/// Ce qu'une vérification a établi.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verification {
    pub snapshot_id: String,
    /// Nombre de fichiers effectivement restaurés.
    pub files_restored: u64,
    /// Octets effectivement restaurés.
    pub bytes_restored: u64,
    /// Ce que l'instantané annonçait.
    pub files_expected: u64,
    pub bytes_expected: u64,
}

impl Verification {
    /// La restauration correspond-elle à ce que l'instantané annonçait ?
    pub fn matches(&self) -> bool {
        self.files_restored == self.files_expected && self.bytes_restored == self.bytes_expected
    }

    pub fn describe(&self) -> String {
        if self.matches() {
            format!(
                "{} fichiers / {} octets restaurés, conformes à l'instantané",
                self.files_restored, self.bytes_restored
            )
        } else {
            format!(
                "ÉCART — restauré {} fichiers / {} octets, l'instantané en annonçait \
                 {} / {}",
                self.files_restored,
                self.bytes_restored,
                self.files_expected,
                self.bytes_expected
            )
        }
    }
}

/// Statistiques d'un instantané, telles que restic les rapporte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stats {
    pub files: u64,
    pub bytes: u64,
}

impl<R: Runner> Repository<R> {
    /// Ce que l'instantané prétend contenir : **fichiers réguliers seulement**.
    ///
    /// ⚠️ On n'utilise pas `restic stats` : son `total_file_count` compte aussi les
    /// répertoires (une sauvegarde de 2 fichiers dans 2 niveaux en annonce 4). Une
    /// vérification bâtie dessus comparerait des choux et des carottes.
    ///
    /// `restic ls --json` distingue les types, ce qui donne un décompte comparable à
    /// ce qu'on trouve réellement sur le disque après restauration.
    pub async fn stats(&self, snapshot: &str) -> Result<Stats> {
        let out = self.exec_public(&["ls", snapshot, "--json"]).await?;

        let mut s = Stats { files: 0, bytes: 0 };
        // Sortie en JSON par ligne : un objet par entrée.
        for line in out.stdout.lines() {
            let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
                continue;
            };
            if v.get("type").and_then(|t| t.as_str()) == Some("file") {
                s.files += 1;
                s.bytes += v.get("size").and_then(|x| x.as_u64()).unwrap_or(0);
            }
        }
        Ok(s)
    }

    /// Vérifie l'intégrité **et la lisibilité réelle** d'un sous-ensemble des données.
    ///
    /// `restic check` seul ne lit que les métadonnées : un bloc corrompu sur le disque
    /// passerait inaperçu. `--read-data-subset` en relit un échantillon, ce qui
    /// attrape la corruption silencieuse sans relire tout le dépôt à chaque fois.
    pub async fn check_data(&self, subset: &str) -> Result<()> {
        self.exec_public(&["check", "--read-data-subset", subset]).await?;
        Ok(())
    }
}

/// Restaure un instantané dans un espace jetable et compare au contenu annoncé.
///
/// `count_target` doit renvoyer `(fichiers, octets)` réellement présents à
/// l'emplacement restauré — c'est l'appelant qui sait inspecter cet espace (volume
/// Docker, chemin local, montage distant).
pub async fn verify_by_restore<R, F, Fut>(
    repo: &Repository<R>,
    snapshot: &str,
    scratch: &str,
    count_target: F,
) -> Result<Verification>
where
    R: Runner,
    F: FnOnce(String) -> Fut,
    Fut: std::future::Future<Output = Result<(u64, u64)>>,
{
    let expected = repo.stats(snapshot).await?;

    repo.restore(snapshot, scratch).await?;
    let (files, bytes) = count_target(scratch.to_string()).await?;

    let v = Verification {
        snapshot_id: snapshot.to_string(),
        files_restored: files,
        bytes_restored: bytes,
        files_expected: expected.files,
        bytes_expected: expected.bytes,
    };

    if v.matches() {
        tracing::info!(snapshot, "{}", v.describe());
    } else {
        // Ne jamais passer sous silence : c'est exactement le cas où on croyait
        // avoir une sauvegarde et où on n'en a pas.
        tracing::error!(snapshot, "{}", v.describe());
    }
    Ok(v)
}

/// L'image utilisée pour la vérification.
///
/// La même que pour les sauvegardes, délibérément : elle est déjà présente sur la
/// machine, elle embarque busybox (`find`, `stat`, `awk`), et n'ajoute donc aucun
/// téléchargement à une opération déjà lente.
const IMAGE: &str = "restic/restic:latest";

/// Vérifie un instantané de bout en bout : restauration réelle puis comparaison.
///
/// ## 🔴 Pourquoi un volume Docker et pas un dossier temporaire
///
/// Sur macOS (colima, Docker Desktop), le dossier temporaire de l'hôte **n'est pas
/// partagé avec la VM Docker**. Un `tempfile::tempdir()` monté dans le conteneur y
/// apparaîtrait vide : restic écrirait dans la VM, l'hôte ne verrait rien, le
/// décompte tomberait à zéro et l'on conclurait à une sauvegarde vide — sur une
/// sauvegarde parfaitement saine.
///
/// L'espace jetable est donc un **volume Docker**, et le comptage se fait dans un
/// conteneur, du même côté de la frontière que les fichiers restaurés.
pub async fn verify_snapshot(
    repo_location: &str,
    password: &str,
    snapshot: &str,
) -> Result<Verification> {
    // Nom unique : deux vérifications concurrentes ne doivent pas se mélanger, et un
    // volume réutilisé porterait les restes de la précédente — ce qui gonflerait le
    // décompte et ferait passer une sauvegarde incomplète.
    let volume = format!("hlb-verif-{}", jeton());
    docker(&["volume", "create", &volume]).await?;

    let resultat = verifier_dans(&volume, repo_location, password, snapshot).await;

    // Nettoyage inconditionnel : un échec ne doit pas laisser derrière lui un volume
    // portant une copie en clair des données.
    if let Err(e) = docker(&["volume", "rm", "-f", &volume]).await {
        tracing::warn!(volume, "volume de vérification non supprimé : {e}");
    }
    resultat
}

async fn verifier_dans(
    volume: &str,
    repo_location: &str,
    password: &str,
    snapshot: &str,
) -> Result<Verification> {
    use crate::runner::ContainerRunner;

    let runner = ContainerRunner::new(IMAGE)
        .mount(repo_location, "/depot")
        .mount(volume, "/verif");
    let repo = Repository::new(runner, "/depot", password.to_string());

    let vol = volume.to_string();
    verify_by_restore(&repo, snapshot, "/verif", move |_| async move {
        compter_dans_volume(&vol).await
    })
    .await
}

/// Compte les fichiers réguliers restaurés, depuis l'intérieur d'un conteneur.
async fn compter_dans_volume(volume: &str) -> Result<(u64, u64)> {
    // `-exec ... +` groupe les arguments : un `\;` lancerait un `stat` par fichier,
    // ce qui rendrait la vérification d'un gros volume interminable.
    let script = "find /verif -type f -exec stat -c %s {} + 2>/dev/null \
                  | awk '{s+=$1} END {print NR, s+0}'";

    let out = docker(&[
        "run", "--rm", "--entrypoint", "sh",
        "-v", &format!("{volume}:/verif"),
        IMAGE, "-c", script,
    ])
    .await?;

    parse_count(&out)
}

/// Analyse la sortie « <fichiers> <octets> » du script de comptage.
fn parse_count(sortie: &str) -> Result<(u64, u64)> {
    let derniere = sortie.lines().rfind(|l| !l.trim().is_empty()).unwrap_or("");

    let mut it = derniere.split_whitespace();
    match (
        it.next().and_then(|v| v.parse::<u64>().ok()),
        it.next().and_then(|v| v.parse::<u64>().ok()),
    ) {
        (Some(f), Some(o)) => Ok((f, o)),
        // 🔴 Jamais (0, 0) par défaut : un comptage illisible n'est pas un volume
        // vide. Les confondre transformerait une panne d'outillage en « sauvegarde
        // vide », et inversement masquerait une vraie sauvegarde vide.
        _ => Err(crate::Error::Unexpected(format!(
            "comptage illisible : « {} »",
            sortie.trim()
        ))),
    }
}

async fn docker(args: &[&str]) -> Result<String> {
    let out = tokio::process::Command::new("docker")
        .args(args)
        .output()
        .await
        .map_err(|e| crate::Error::ResticMissing(format!("docker introuvable : {e}")))?;

    if !out.status.success() {
        return Err(crate::Error::Restic {
            command: format!("docker {}", args.first().unwrap_or(&"")),
            stderr: String::from_utf8_lossy(&out.stderr).trim().to_string(),
        });
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

/// Un suffixe unique, sans dépendance de génération aléatoire.
///
/// ⚠️ L'horodatage **seul** ne suffit pas : sur macOS, `SystemTime::now()` n'a pas la
/// résolution nanoseconde annoncée par son type, et deux appels rapprochés renvoient
/// la même valeur. Deux vérifications lancées ensemble partageraient alors le même
/// volume — et se compteraient mutuellement leurs fichiers.
///
/// Le compteur règle le cas dans un processus, le PID celui de deux processus lancés
/// dans le même tic d'horloge.
fn jeton() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);

    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);

    format!(
        "{t:x}-{:x}-{:x}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verification(restored: (u64, u64), expected: (u64, u64)) -> Verification {
        Verification {
            snapshot_id: "abc".into(),
            files_restored: restored.0,
            bytes_restored: restored.1,
            files_expected: expected.0,
            bytes_expected: expected.1,
        }
    }

    #[test]
    fn an_exact_restore_matches() {
        assert!(verification((12, 4096), (12, 4096)).matches());
    }

    #[test]
    fn a_missing_file_is_detected() {
        // Le cas qui compte : la restauration « a marché » mais il manque des données.
        let v = verification((11, 4096), (12, 4096));
        assert!(!v.matches());
        assert!(v.describe().contains("ÉCART"), "{}", v.describe());
    }

    #[test]
    fn a_truncated_file_is_detected() {
        // Même nombre de fichiers, mais du contenu manquant.
        assert!(!verification((12, 2048), (12, 4096)).matches());
    }

    #[test]
    fn an_empty_restore_is_never_a_success() {
        // 🔴 Une restauration qui ne produit rien ne doit surtout pas passer.
        let v = verification((0, 0), (12, 4096));
        assert!(!v.matches());
        assert!(v.describe().contains("ÉCART"));
    }

    #[test]
    fn the_description_is_readable_in_both_cases() {
        assert!(verification((3, 100), (3, 100)).describe().contains("conformes"));
        assert!(verification((3, 100), (4, 100)).describe().contains("annonçait"));
    }

    #[test]
    fn a_count_output_is_parsed() {
        assert_eq!(parse_count("2 17\n").expect("analysable"), (2, 17));
        assert_eq!(parse_count("0 0\n").expect("analysable"), (0, 0));
        // Une ligne de bruit avant le résultat ne doit pas gêner.
        assert_eq!(parse_count("attention: bla\n5 4096\n").expect("analysable"), (5, 4096));
    }

    #[test]
    fn an_unreadable_count_is_never_taken_for_an_empty_volume() {
        // 🔴 Retourner (0, 0) sur une sortie illisible transformerait une panne
        // d'outillage en « sauvegarde vide » — et masquerait une vraie sauvegarde
        // vide le jour où il y en a une.
        assert!(parse_count("").is_err());
        assert!(parse_count("docker: command not found").is_err());
        assert!(parse_count("2").is_err(), "un seul champ ne suffit pas");
    }

    #[test]
    fn scratch_volumes_never_collide() {
        // 🔴 Un volume réutilisé porterait les restes de la vérification précédente.
        // L'horodatage seul ne suffit PAS : sur macOS, deux appels rapprochés à
        // `SystemTime::now()` renvoient la même valeur — ce test l'a montré.
        let jetons: std::collections::BTreeSet<String> = (0..100).map(|_| jeton()).collect();
        assert_eq!(jetons.len(), 100, "collision entre jetons rapprochés");
    }



}
