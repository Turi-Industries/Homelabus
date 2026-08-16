//! Sauvegarde cohérente des bases SQLite (§3.4).
//!
//! ## 🔴 Copier un fichier SQLite à chaud ne le sauvegarde pas
//!
//! C'est la panne la plus traître de tout le système de sauvegarde, parce qu'elle ne
//! se manifeste **qu'au moment de la restauration**.
//!
//! Une base SQLite en mode WAL n'est pas un fichier, c'est trois :
//!
//! | Fichier | Contenu |
//! |---|---|
//! | `base.db` | les pages déjà intégrées |
//! | `base.db-wal` | les transactions récentes, pas encore intégrées |
//! | `base.db-shm` | l'index partagé du WAL |
//!
//! `restic` les copie l'un après l'autre. Entre la copie du premier et celle du
//! deuxième, l'application écrit. Le jeu obtenu est **incohérent** : SQLite refuse de
//! l'ouvrir, ou pire, l'ouvre en ayant silencieusement perdu les transactions du WAL.
//!
//! Et rien ne le signale au moment de la sauvegarde. L'instantané a un identifiant,
//! sa taille est plausible, `restic check` passe. On découvre le problème le jour où
//! l'on restaure.
//!
//! ## `VACUUM INTO` plutôt que la copie
//!
//! `VACUUM INTO 'chemin'` (SQLite 3.27+, 2019) produit une base **complète et
//! cohérente** dans un fichier neuf, en une seule transaction, pendant que
//! l'application continue d'écrire. C'est le mécanisme officiel pour exactement ce
//! besoin.
//!
//! Deux avantages sur l'ancien `.backup` du client `sqlite3` :
//!
//! - il ne demande **aucun binaire externe** — on passe par la même bibliothèque
//!   SQLite que le reste du projet ;
//! - le fichier produit est défragmenté, donc plus petit à sauvegarder.
//!
//! ⚠️ Il refuse d'écrire par-dessus un fichier existant. C'est voulu : écraser un
//! instantané pendant qu'on le sauvegarde donnerait à restic un fichier qui change
//! sous ses pieds.

use std::path::{Path, PathBuf};

use crate::{Error, Result};

/// Les extensions qui trahissent une base SQLite.
///
/// ⚠️ Il n'y a pas de convention unique : Vaultwarden utilise `db.sqlite3`, PocketID
/// `pocket-id.db`, d'autres `.sqlite`. Manquer un fichier voudrait dire le sauvegarder
/// à chaud sans le savoir.
const EXTENSIONS: &[&str] = &["db", "sqlite", "sqlite3"];

/// Un fichier annexe du moteur, jamais une base à part entière.
///
/// 🔴 Les instantanier séparément produirait des fichiers inutilisables **et**
/// donnerait l'illusion d'avoir sauvegardé plus de bases qu'il n'y en a.
fn is_sidecar(name: &str) -> bool {
    name.ends_with("-wal") || name.ends_with("-shm") || name.ends_with("-journal")
}

/// Une base SQLite trouvée dans un volume.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Found {
    pub path: PathBuf,
    /// Nom du fichier d'instantané à produire.
    pub snapshot_name: String,
}

/// Repère les bases SQLite sous un chemin.
pub fn discover(root: &Path) -> std::io::Result<Vec<Found>> {
    let mut out = Vec::new();
    let mut pile = vec![root.to_path_buf()];

    while let Some(p) = pile.pop() {
        for e in std::fs::read_dir(&p)? {
            let e = e?;
            let m = e.metadata()?;
            if m.is_dir() {
                pile.push(e.path());
                continue;
            }
            if !m.is_file() {
                continue;
            }

            let nom = e.file_name().to_string_lossy().to_string();
            if is_sidecar(&nom) {
                continue;
            }

            let ext = e
                .path()
                .extension()
                .map(|x| x.to_string_lossy().to_lowercase())
                .unwrap_or_default();

            if EXTENSIONS.contains(&ext.as_str()) && looks_like_sqlite(&e.path())? {
                out.push(Found {
                    path: e.path(),
                    snapshot_name: format!("{nom}.snapshot"),
                });
            }
        }
    }

    // Déterministe : l'ordre du système de fichiers ne l'est pas, et un instantané
    // qui change d'ordre rendrait les journaux illisibles.
    out.sort();
    Ok(out)
}

/// Le fichier commence-t-il par l'en-tête SQLite ?
///
/// ⚠️ L'extension ne suffit pas : `.db` sert à tout et n'importe quoi. Lancer un
/// `VACUUM INTO` sur un fichier qui n'est pas une base échouerait à chaque
/// sauvegarde, et le vrai problème serait noyé dans le bruit.
fn looks_like_sqlite(p: &Path) -> std::io::Result<bool> {
    use std::io::Read;

    // Les 16 premiers octets d'un fichier SQLite sont toujours « SQLite format 3\0 ».
    const MAGIE: &[u8] = b"SQLite format 3\0";
    let mut f = std::fs::File::open(p)?;
    let mut tete = [0u8; 16];

    match f.read_exact(&mut tete) {
        Ok(()) => Ok(tete == MAGIE),
        // Un fichier plus court que l'en-tête n'est pas une base.
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(false),
        Err(e) => Err(e),
    }
}

/// Produit un instantané cohérent d'une base.
///
/// Le fichier de destination ne doit pas exister : `VACUUM INTO` refuse d'écraser, et
/// c'est une protection qu'on ne contourne pas.
pub async fn snapshot(source: &Path, destination: &Path) -> Result<u64> {
    if destination.exists() {
        return Err(Error::Unexpected(format!(
            "{} existe déjà — VACUUM INTO refuse d'écraser, et écraser un instantané \
             pendant sa sauvegarde donnerait à restic un fichier qui change sous ses pieds",
            destination.display()
        )));
    }

    // Lecture seule : une sauvegarde ne doit en aucun cas pouvoir modifier la base
    // de production, même par accident de configuration.
    let opts = sqlx::sqlite::SqliteConnectOptions::new()
        .filename(source)
        .read_only(true)
        .create_if_missing(false);

    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(opts)
        .await
        .map_err(|e| Error::Unexpected(format!("ouverture de {} : {e}", source.display())))?;

    // Le chemin ne peut pas être un paramètre lié dans un VACUUM.
    let dest = destination.to_string_lossy().replace('\'', "''");
    sqlx::query(&format!("VACUUM INTO '{dest}'"))
        .execute(&pool)
        .await
        .map_err(|e| Error::Unexpected(format!("instantané de {} : {e}", source.display())))?;

    pool.close().await;

    let taille = std::fs::metadata(destination)
        .map_err(|e| Error::Unexpected(format!("instantané illisible : {e}")))?
        .len();

    // 🔴 Un instantané vide n'est jamais normal : même une base sans table fait
    // plusieurs kilo-octets d'en-tête et de schéma.
    if taille == 0 {
        return Err(Error::Unexpected(format!(
            "instantané de {} vide — la base est-elle lisible ?",
            source.display()
        )));
    }

    tracing::info!(
        source = %source.display(),
        octets = taille,
        "instantané SQLite cohérent produit"
    );
    Ok(taille)
}

/// Instantanie toutes les bases d'un volume dans un répertoire de transit.
pub async fn snapshot_all(root: &Path, staging: &Path) -> Result<Vec<PathBuf>> {
    let bases = discover(root)
        .map_err(|e| Error::Unexpected(format!("exploration de {} : {e}", root.display())))?;

    if bases.is_empty() {
        // 🔴 Signalé, pas silencieux : un volume déclaré `sqlite: true` où l'on ne
        // trouve aucune base veut dire que le chemin est faux, ou que le nom du
        // fichier ne suit aucune convention connue. Le taire ferait croire à une
        // sauvegarde faite.
        return Err(Error::Unexpected(format!(
            "aucune base SQLite trouvée sous {} alors que le volume est déclaré \
             « sqlite: true » — chemin erroné, ou extension inhabituelle ?",
            root.display()
        )));
    }

    let mut produits = Vec::new();
    for b in bases {
        let dest = staging.join(&b.snapshot_name);
        snapshot(&b.path, &dest).await?;
        produits.push(dest);
    }
    Ok(produits)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Crée une vraie base SQLite avec du contenu.
    async fn base(chemin: &Path, lignes: usize) {
        let opts = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(chemin)
            .create_if_missing(true)
            // Le mode WAL est celui qui rend la copie à chaud dangereuse : on teste
            // dans les conditions du problème.
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal);

        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(opts)
            .await
            .expect("base de test");

        sqlx::query("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)")
            .execute(&pool)
            .await
            .expect("table");
        for i in 0..lignes {
            sqlx::query("INSERT INTO t (v) VALUES (?1)")
                .bind(format!("valeur-{i}"))
                .execute(&pool)
                .await
                .expect("insertion");
        }
        pool.close().await;
    }

    #[tokio::test]
    async fn a_snapshot_contains_every_row() {
        // 🔴 LE test : l'instantané doit contenir les données, y compris celles
        // encore dans le WAL au moment où on le prend.
        let d = tempfile::tempdir().expect("répertoire");
        let src = d.path().join("app.db");
        base(&src, 500).await;

        let dest = d.path().join("app.db.snapshot");
        let taille = snapshot(&src, &dest).await.expect("instantané");
        assert!(taille > 0);

        // On relit l'instantané et on compte.
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect(&format!("sqlite://{}", dest.display()))
            .await
            .expect("relecture");

        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM t")
            .fetch_one(&pool)
            .await
            .expect("comptage");
        assert_eq!(n, 500, "l'instantané doit contenir toutes les lignes");
    }

    #[tokio::test]
    async fn the_source_is_never_modified() {
        // Une sauvegarde qui écrit dans la base de production serait pire que pas de
        // sauvegarde du tout.
        let d = tempfile::tempdir().expect("répertoire");
        let src = d.path().join("app.db");
        base(&src, 10).await;

        let avant = std::fs::metadata(&src).expect("stat").len();
        snapshot(&src, &d.path().join("s.db")).await.expect("instantané");
        let apres = std::fs::metadata(&src).expect("stat").len();

        assert_eq!(avant, apres, "la base source ne doit pas bouger");
    }

    #[tokio::test]
    async fn overwriting_an_existing_snapshot_is_refused() {
        // Écraser pendant que restic lit donnerait un fichier qui change sous ses pieds.
        let d = tempfile::tempdir().expect("répertoire");
        let src = d.path().join("app.db");
        base(&src, 5).await;

        let dest = d.path().join("s.db");
        snapshot(&src, &dest).await.expect("premier");
        let e = snapshot(&src, &dest).await.unwrap_err().to_string();
        assert!(e.contains("existe déjà"), "{e}");
    }

    #[tokio::test]
    async fn databases_are_discovered_by_content_not_extension() {
        // ⚠️ `.db` sert à tout : un VACUUM INTO sur un fichier qui n'est pas une base
        // échouerait à chaque sauvegarde et noierait le vrai problème.
        let d = tempfile::tempdir().expect("répertoire");
        base(&d.path().join("vraie.db"), 3).await;
        std::fs::write(d.path().join("fausse.db"), b"pas une base du tout").expect("écriture");
        std::fs::write(d.path().join("court.db"), b"ab").expect("écriture");

        let v = discover(d.path()).expect("exploration");
        assert_eq!(v.len(), 1, "{v:?}");
        assert!(v[0].path.ends_with("vraie.db"));
    }

    #[tokio::test]
    async fn wal_and_shm_files_are_never_treated_as_databases() {
        // 🔴 Les instantanier séparément produirait des fichiers inutilisables ET
        // ferait croire à plus de bases qu'il n'y en a.
        assert!(is_sidecar("app.db-wal"));
        assert!(is_sidecar("app.db-shm"));
        assert!(is_sidecar("app.db-journal"));
        assert!(!is_sidecar("app.db"));

        let d = tempfile::tempdir().expect("répertoire");
        base(&d.path().join("app.db"), 3).await;
        // Le mode WAL a pu laisser un -wal ; on en pose un explicitement.
        std::fs::write(d.path().join("app.db-wal"), b"SQLite format 3\0xxxx").expect("wal");

        let v = discover(d.path()).expect("exploration");
        assert_eq!(v.len(), 1, "{v:?}");
    }

    #[tokio::test]
    async fn nested_directories_are_explored() {
        let d = tempfile::tempdir().expect("répertoire");
        let sous = d.path().join("data").join("db");
        std::fs::create_dir_all(&sous).expect("arborescence");
        base(&sous.join("profonde.sqlite3"), 2).await;

        let v = discover(d.path()).expect("exploration");
        assert_eq!(v.len(), 1, "{v:?}");
        assert_eq!(v[0].snapshot_name, "profonde.sqlite3.snapshot");
    }

    #[tokio::test]
    async fn a_volume_declared_sqlite_but_empty_is_an_error() {
        // 🔴 Le taire ferait croire à une sauvegarde faite. Un volume déclaré
        // « sqlite: true » sans base veut dire que le chemin est faux.
        let d = tempfile::tempdir().expect("répertoire");
        let staging = tempfile::tempdir().expect("transit");
        std::fs::write(d.path().join("notes.txt"), b"rien").expect("écriture");

        let e = snapshot_all(d.path(), staging.path()).await.unwrap_err().to_string();
        assert!(e.contains("aucune base SQLite"), "{e}");
        assert!(e.contains("chemin erroné"), "l'erreur doit orienter : {e}");
    }

    #[tokio::test]
    async fn every_database_of_a_volume_is_snapshotted() {
        let d = tempfile::tempdir().expect("répertoire");
        let staging = tempfile::tempdir().expect("transit");
        base(&d.path().join("a.db"), 4).await;
        base(&d.path().join("b.sqlite"), 7).await;

        let v = snapshot_all(d.path(), staging.path()).await.expect("instantanés");
        assert_eq!(v.len(), 2, "{v:?}");
        for p in &v {
            assert!(p.exists(), "{} manquant", p.display());
            assert!(std::fs::metadata(p).expect("stat").len() > 0);
        }
    }

    #[tokio::test]
    async fn a_missing_source_fails_clearly() {
        let d = tempfile::tempdir().expect("répertoire");
        let e = snapshot(&d.path().join("absente.db"), &d.path().join("s.db"))
            .await
            .unwrap_err()
            .to_string();
        assert!(e.contains("ouverture"), "{e}");
    }
}

/// Réplication continue vers S3 (§8.1).
///
/// ## Ce que Litestream ajoute à l'instantané
///
/// L'instantané `VACUUM INTO` est cohérent, mais il date du dernier passage de la
/// boucle de sauvegarde — quatre heures dans la configuration par défaut. Perdre le
/// disque à 15 h 55 coûte donc jusqu'à quatre heures de travail.
///
/// Litestream réplique le WAL en continu : le retard tombe à quelques secondes. C'est
/// le pendant exact du PITR pour PostgreSQL.
///
/// ## 🔴 Les deux ne se remplacent pas
///
/// | | Ce que ça protège | Ce que ça NE protège pas |
/// |---|---|---|
/// | Instantané + restic | perte de disque, corruption, **suppression accidentelle** | les 4 dernières heures |
/// | Litestream | perte de disque, les dernières secondes | **une suppression répliquée en 2 s** |
///
/// Une table effacée par erreur est répliquée immédiatement vers S3. Litestream garde
/// un historique (`retention`), mais court : c'est l'instantané qui reste le filet
/// pour les erreurs humaines. On garde donc les deux.
pub mod litestream {
    /// Où répliquer.
    #[derive(Debug, Clone)]
    pub struct Replica {
        /// Seau S3 (ou compatible : MinIO, Garage, Backblaze…).
        pub bucket: String,
        /// Chemin dans le seau.
        pub path: String,
        /// Point de terminaison, pour un S3 non-Amazon.
        pub endpoint: Option<String>,
        /// Durée de conservation de l'historique.
        pub retention: String,
    }

    impl Default for Replica {
        fn default() -> Self {
            Self {
                bucket: "homelabus".into(),
                path: "litestream".into(),
                endpoint: None,
                // 🔴 72 h et non 24 : une suppression accidentelle un vendredi soir
                // doit rester rattrapable le lundi matin. Avec 24 h, elle ne l'est
                // plus — et c'est le week-end qu'on regarde le moins ses journaux.
                retention: "72h".into(),
            }
        }
    }

    /// Rend le `litestream.yml` pour un ensemble de bases.
    ///
    /// ⚠️ Litestream veut le chemin de la base **vivante**, pas de l'instantané : il
    /// lit le WAL au fil de l'eau. Lui donner l'instantané ne répliquerait rien, et
    /// il n'émettrait aucune erreur — il attendrait des écritures qui n'arrivent
    /// jamais sur un fichier figé.
    pub fn render(databases: &[std::path::PathBuf], replica: &Replica) -> String {
        let mut s = String::from(
            "# Généré par HomelabUS (§8.1) — ne pas éditer à la main.\n\
             #\n\
             # ⚠️ Litestream ne REMPLACE pas les instantanés restic : une table\n\
             # effacée par erreur est répliquée en quelques secondes. C'est\n\
             # l'instantané qui reste le filet contre les erreurs humaines.\n\
             \ndbs:\n",
        );

        for d in databases {
            s.push_str(&format!("  - path: {}\n", d.display()));
            s.push_str("    replicas:\n");
            s.push_str("      - type: s3\n");
            s.push_str(&format!("        bucket: {}\n", replica.bucket));
            s.push_str(&format!(
                "        path: {}/{}\n",
                replica.path.trim_end_matches('/'),
                d.file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_else(|| "base".into())
            ));
            if let Some(e) = &replica.endpoint {
                s.push_str(&format!("        endpoint: {e}\n"));
                // ⚠️ Indispensable hors d'Amazon : sans ça, Litestream construit des
                // URL de style `bucket.endpoint`, que MinIO et Garage ne servent pas.
                s.push_str("        force-path-style: true\n");
            }
            s.push_str(&format!("        retention: {}\n", replica.retention));
            // Une vérification périodique attrape une réplication qui a divergé
            // silencieusement — le mode d'échec propre à la réplication continue.
            s.push_str("        validation-interval: 12h\n");
        }

        if databases.is_empty() {
            // Un fichier avec `dbs:` vide fait démarrer Litestream sans rien répliquer,
            // et sans le dire. Autant que le fichier le crie.
            s.push_str("# 🔴 AUCUNE base déclarée : Litestream démarrera sans rien répliquer.\n");
        }
        s
    }
}

#[cfg(test)]
mod tests_litestream {
    use super::litestream::*;
    use std::path::PathBuf;

    #[test]
    fn the_live_database_is_replicated_not_the_snapshot() {
        // ⚠️ Litestream lit le WAL au fil de l'eau. Sur un instantané figé, il
        // n'émettrait AUCUNE erreur et ne répliquerait jamais rien.
        let y = render(&[PathBuf::from("/data/app.db")], &Replica::default());
        assert!(y.contains("path: /data/app.db"), "{y}");
        assert!(!y.contains(".snapshot"), "{y}");
    }

    #[test]
    fn retention_survives_a_weekend() {
        // 🔴 24 h ne suffit pas : une suppression du vendredi soir doit rester
        // rattrapable le lundi matin, et c'est le week-end qu'on regarde le moins.
        assert_eq!(Replica::default().retention, "72h");
    }

    #[test]
    fn a_non_amazon_endpoint_forces_path_style() {
        // ⚠️ Sans ça, Litestream construit des URL « bucket.endpoint » que MinIO et
        // Garage ne servent pas — l'erreur parle de DNS, pas de style d'URL.
        let r = Replica {
            endpoint: Some("https://minio.example.fr".into()),
            ..Replica::default()
        };
        let y = render(&[PathBuf::from("/data/app.db")], &r);
        assert!(y.contains("force-path-style: true"), "{y}");
    }

    #[test]
    fn amazon_needs_no_endpoint_line() {
        let y = render(&[PathBuf::from("/data/app.db")], &Replica::default());
        assert!(!y.contains("endpoint:"), "{y}");
        assert!(!y.contains("force-path-style"), "{y}");
    }

    #[test]
    fn each_database_gets_its_own_path() {
        // Deux bases répliquées au même chemin s'écraseraient mutuellement.
        let y = render(
            &[PathBuf::from("/d/a.db"), PathBuf::from("/d/b.db")],
            &Replica::default(),
        );
        assert!(y.contains("litestream/a.db"), "{y}");
        assert!(y.contains("litestream/b.db"), "{y}");
    }

    #[test]
    fn an_empty_configuration_says_it_replicates_nothing() {
        // Litestream démarrerait normalement, sans rien répliquer et sans le dire.
        let y = render(&[], &Replica::default());
        assert!(y.contains("AUCUNE base"), "{y}");
    }

    #[test]
    fn the_file_says_it_does_not_replace_snapshots() {
        // Le piège de fond : croire que la réplication continue suffit. Une table
        // effacée par erreur est répliquée en quelques secondes.
        let y = render(&[PathBuf::from("/d/a.db")], &Replica::default());
        assert!(y.contains("ne REMPLACE pas"), "{y}");
    }
}
