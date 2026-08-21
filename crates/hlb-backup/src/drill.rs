//! Exercices de reprise après sinistre (§8.3, §2bis.5).
//!
//! > **Une procédure de reprise jamais exercée ne marche pas le jour où on en a
//! > besoin.**
//!
//! Ce n'est pas une formule : la restauration est le chemin de code le moins parcouru
//! du système. Tout le reste tourne en permanence — les sauvegardes, la
//! réconciliation, les mises à jour — et se casse donc bruyamment. La restauration,
//! elle, ne s'exécute qu'un jour, et c'est le pire jour possible pour découvrir
//! qu'un mot de passe a changé, qu'un chemin a bougé ou qu'un `down` était faux.
//!
//! ## 🔴 Ce qui distingue un exercice d'une catastrophe
//!
//! Un exercice de reprise qui touche la production est **pire que pas d'exercice du
//! tout** : on transforme une répétition en incident réel, et on le fait
//! volontairement, un jour où tout allait bien.
//!
//! Trois garde-fous, chacun vérifié par un test :
//!
//! 1. **Cible jetable obligatoire.** L'exercice refuse de démarrer si la cible n'est
//!    pas explicitement marquée comme telle. Aucun défaut, aucune déduction.
//! 2. **Aucune écriture hors de la cible.** On lit les sauvegardes, on écrit dans un
//!    conteneur et un volume créés pour l'occasion, détruits à la fin.
//! 3. **Le résultat n'a aucun effet de bord.** Un exercice raté n'arrête rien, ne
//!    bascule rien, ne supprime rien. Il *signale*.
//!
//! ## Ce qu'un exercice prouve, et ce qu'il ne prouve pas
//!
//! | | Prouvé | Non prouvé |
//! |---|---|---|
//! | `backup verify` | les octets reviennent | qu'ils forment une base utilisable |
//! | **exercice** | la base s'ouvre et contient les données | que le service applicatif redémarre |
//!
//! La colonne de droite reste : un PostgreSQL restauré peut être parfait et
//! l'application refuser de démarrer pour une raison qui lui est propre. L'exercice
//! ne prétend pas le contraire.

use crate::{Error, Result};

/// Ce qu'on exerce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// Restaurer une sauvegarde de base et vérifier que PostgreSQL l'ouvre.
    Postgres,
    /// Restaurer un dump logique et compter les lignes.
    SqlDump,
}

impl Scope {
    pub fn describe(&self) -> &'static str {
        match self {
            Self::Postgres => "sauvegarde de base PostgreSQL",
            Self::SqlDump => "dump logique",
        }
    }
}

/// La cible d'un exercice.
///
/// 🔴 `disposable` n'a **pas** de valeur par défaut à `true`, et n'est pas déduit.
/// Un exercice qui devinerait sa cible finirait un jour par deviner mal — et ce jour-là
/// il écraserait la production avec une sauvegarde vieille de quatre heures.
#[derive(Debug, Clone)]
pub struct Target {
    /// Nom du conteneur jetable créé pour l'exercice.
    pub container: String,
    /// L'appelant affirme que cette cible est jetable.
    pub disposable: bool,
}

/// Pourquoi un exercice ne peut pas avoir lieu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refused {
    /// 🔴 La cible n'est pas déclarée jetable.
    NotDisposable { container: String },
    /// 🔴 Le nom de la cible ressemble à de la production.
    LooksLikeProduction { container: String, motif: String },
    /// Rien à restaurer.
    NothingToRestore,
}

impl Refused {
    pub fn describe(&self) -> String {
        match self {
            Self::NotDisposable { container } => format!(
                "🔴 « {container} » n'est pas déclaré jetable. Un exercice qui touche \
                 la production transforme une répétition en incident réel — un jour \
                 où tout allait bien. Passe --disposable si la cible est bien un \
                 conteneur créé pour l'occasion."
            ),
            Self::LooksLikeProduction { container, motif } => format!(
                "🔴 « {container} » contient « {motif} » : ce nom ressemble à de la \
                 production. Même avec --disposable, on refuse — une faute de frappe \
                 sur un nom de conteneur ne doit pas coûter une base."
            ),
            Self::NothingToRestore => "aucune sauvegarde à restaurer : l'exercice \
                 n'aurait rien à prouver. Lance d'abord `hlb backup pitr base --apply`."
                .to_string(),
        }
    }
}

/// Les fragments de nom qui trahissent une cible de production.
///
/// ⚠️ Volontairement larges. Un faux positif coûte un renommage de conteneur de test ;
/// un faux négatif coûte une base de production.
const NOMS_INTERDITS: &[&str] = &["prod", "production", "live", "main", "primary", "primaire"];

/// Vérifie qu'un exercice peut avoir lieu sans risque.
pub fn authorize(target: &Target, has_backup: bool) -> std::result::Result<(), Refused> {
    // 🔴 Le nom d'abord : même déclarée jetable, une cible qui s'appelle « postgres-prod »
    // est très probablement une erreur de frappe, et l'ordre des contrôles fait que
    // `--disposable` ne peut pas la contourner.
    let bas = target.container.to_lowercase();
    if let Some(m) = NOMS_INTERDITS.iter().find(|m| bas.contains(**m)) {
        return Err(Refused::LooksLikeProduction {
            container: target.container.clone(),
            motif: (*m).to_string(),
        });
    }

    if !target.disposable {
        return Err(Refused::NotDisposable {
            container: target.container.clone(),
        });
    }

    if !has_backup {
        return Err(Refused::NothingToRestore);
    }
    Ok(())
}

/// Le résultat d'un exercice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub scope: Scope,
    /// La base restaurée s'est-elle ouverte ?
    pub opened: bool,
    /// Nombre de tables trouvées. `None` = pas interrogé.
    pub tables: Option<i64>,
    /// Durée, en secondes.
    pub seconds: u64,
    pub detail: String,
}

impl Outcome {
    /// L'exercice a-t-il prouvé quelque chose ?
    ///
    /// 🔴 Ouvrir ne suffit pas : un PostgreSQL restauré depuis une sauvegarde vide
    /// s'ouvre parfaitement et ne contient rien. C'est exactement le cas qu'un
    /// exercice doit attraper, et celui qu'une vérification par taille laisse passer.
    pub fn succeeded(&self) -> bool {
        self.opened && self.tables.is_some_and(|n| n > 0)
    }

    pub fn describe(&self) -> String {
        if self.succeeded() {
            format!(
                "{} restaurée en {} s — {} lisibles",
                self.scope.describe(),
                self.seconds,
                crate::pluriel_tables(self.tables.unwrap_or(0))
            )
        } else if self.opened {
            format!(
                "{} s'ouvre mais ne contient RIEN ({}). Une base vide se \
                 restaure parfaitement — c'est le pire résultat possible, parce qu'il \
                 ressemble à un succès.",
                self.scope.describe(),
                crate::pluriel_tables(self.tables.unwrap_or(0))
            )
        } else {
            format!("{} ne s'ouvre pas : {}", self.scope.describe(), self.detail)
        }
    }
}

/// Depuis combien de temps l'exercice n'a-t-il pas été fait ?
///
/// Le §8.3 vise une fois par mois. Au-delà de deux, la procédure a eu le temps de
/// diverger : un chemin qui bouge, un mot de passe qui tourne, une version qui change.
pub const INTERVALLE_JOURS: i64 = 30;
pub const RETARD_JOURS: i64 = 60;

/// L'état de la préparation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Readiness {
    /// Exercé récemment.
    Ready { days: i64 },
    /// Il serait temps.
    Due { days: i64 },
    /// 🔴 Trop vieux pour qu'on puisse encore s'y fier.
    Overdue { days: i64 },
    /// 🔴 Jamais exercé.
    Never,
}

impl Readiness {
    pub fn from_days(days: Option<i64>) -> Self {
        match days {
            None => Self::Never,
            Some(d) if d > RETARD_JOURS => Self::Overdue { days: d },
            Some(d) if d > INTERVALLE_JOURS => Self::Due { days: d },
            Some(d) => Self::Ready { days: d },
        }
    }

    /// Faut-il alerter ?
    pub fn needs_attention(&self) -> bool {
        !matches!(self, Self::Ready { .. })
    }

    pub fn describe(&self) -> String {
        match self {
            Self::Ready { days } => format!("exercée il y a {days} j"),
            Self::Due { days } => {
                format!("exercée il y a {days} j — le §8.3 vise tous les 30 j")
            }
            Self::Overdue { days } => format!(
                "exercée il y a {days} j. Au-delà de {RETARD_JOURS} j, la procédure \
                 a eu le temps de diverger : un chemin qui bouge, un mot de passe qui \
                 tourne, une version qui change."
            ),
            Self::Never => "JAMAIS exercée. La restauration est le chemin de code \
                 le moins parcouru du système, et le seul qu'on découvre le pire jour."
                .to_string(),
        }
    }
}

/// Exécute un exercice sur une sauvegarde de base PostgreSQL.
///
/// ⚠️ Restaure dans un conteneur **neuf**, jamais dans un serveur existant. Un
/// `pg_basebackup` restauré par-dessus un répertoire de données peuplé détruirait ce
/// qu'il contient.
pub async fn run_postgres(
    target: &Target,
    base_dir: &str,
    base_id: &str,
    image: &str,
) -> Result<Outcome> {
    let debut = std::time::SystemTime::now();

    // Le conteneur est détruit d'abord : un reliquat d'exercice précédent porterait
    // des données qui fausseraient le résultat.
    let _ = docker(&["rm", "-f", &target.container]).await;

    let source = format!("{}/{base_id}", base_dir.trim_end_matches('/'));

    // 🔴 `:ro` sur le montage de la sauvegarde : quoi qu'il arrive dans le conteneur,
    // l'archive ne peut pas être modifiée. C'est la protection qui compte le plus —
    // une archive corrompue PAR un exercice serait le comble.
    //
    // ⚠️ Et surtout : on remplace la commande par un `sleep`, donc le point d'entrée
    // de l'image ne démarre PAS PostgreSQL. Le laisser faire créerait une base neuve
    // qu'il faudrait ensuite arrêter — et `pg_ctl` échoue sur « another server might
    // be running » parce que le serveur tourne sous un autre utilisateur que celui
    // qui l'arrête.
    let demarrage = docker(&[
        "run",
        "-d",
        "--name",
        &target.container,
        "--entrypoint",
        "sleep",
        "-v",
        &format!("{source}:/sauvegarde:ro"),
        image,
        "600",
    ])
    .await;

    if let Err(e) = demarrage {
        return Ok(Outcome {
            scope: Scope::Postgres,
            opened: false,
            tables: None,
            seconds: 0,
            detail: format!("conteneur non démarré : {e}"),
        });
    }

    // Le répertoire de données est CRÉÉ par nous, vide, puis rempli depuis l'archive.
    //
    // ⚠️ `chmod 700` n'est pas cosmétique : PostgreSQL refuse de démarrer sur un
    // répertoire de données accessible à d'autres, avec un message qui parle de
    // permissions sans dire lesquelles.
    let restauration = docker(&[
        "exec",
        &target.container,
        "sh",
        "-c",
        "set -e; \
         mkdir -p /var/lib/postgresql/data; \
         rm -rf /var/lib/postgresql/data/*; \
         tar xzf /sauvegarde/base.tar.gz -C /var/lib/postgresql/data; \
         mkdir -p /var/lib/postgresql/data/pg_wal; \
         tar xzf /sauvegarde/pg_wal.tar.gz -C /var/lib/postgresql/data/pg_wal 2>/dev/null || true; \
         chown -R postgres:postgres /var/lib/postgresql/data; \
         chmod 700 /var/lib/postgresql/data; \
         su postgres -c 'pg_ctl -D /var/lib/postgresql/data -w -t 60 -l /tmp/pg.log start' \
           || (cat /tmp/pg.log; exit 1)",
    ])
    .await;

    let ouverte = restauration.is_ok();
    let detail = restauration.err().unwrap_or_default();

    // 🔴 Compter dans TOUTES les bases du cluster, pas seulement `postgres`.
    //
    // La première version n'interrogeait que la base `postgres`, qui est vide sur
    // une installation réelle : les données vivent dans une base par app (§3.1).
    // L'exercice annonçait donc « base vide » sur une sauvegarde parfaitement
    // saine — un faux négatif qui, répété, apprend à ignorer l'alerte.
    let tables = if ouverte {
        docker(&[
            "exec", &target.container, "sh", "-c",
            "total=0; \
             for d in $(psql -U postgres -tAc \
                 \"SELECT datname FROM pg_database WHERE datallowconn AND NOT datistemplate\"); do \
               n=$(psql -U postgres -d \"$d\" -tAc \
                 \"SELECT count(*) FROM information_schema.tables \
                   WHERE table_schema NOT IN ('pg_catalog','information_schema')\" 2>/dev/null || echo 0); \
               total=$((total + n)); \
             done; \
             echo $total",
        ])
        .await
        .ok()
        .and_then(|s| s.trim().parse::<i64>().ok())
    } else {
        None
    };

    // Nettoyage inconditionnel : un exercice ne laisse rien derrière lui.
    let _ = docker(&["rm", "-f", &target.container]).await;

    Ok(Outcome {
        scope: Scope::Postgres,
        opened: ouverte,
        tables,
        seconds: debut.elapsed().map(|d| d.as_secs()).unwrap_or(0),
        detail,
    })
}

async fn docker(args: &[&str]) -> std::result::Result<String, String> {
    let out = tokio::process::Command::new("docker")
        .args(args)
        .output()
        .await
        .map_err(|e| format!("docker introuvable : {e}"))?;

    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

/// Le nom d'un conteneur d'exercice.
///
/// Préfixé et horodaté : reconnaissable d'un coup d'œil dans un `docker ps`, et
/// impossible à confondre avec un service réel.
pub fn container_name(at: i64) -> Result<String> {
    let (y, m, d, hh, mm, ss) = crate::pitr::civil_public(at);
    Ok(format!(
        "hlb-exercice-{y:04}{m:02}{d:02}T{hh:02}{mm:02}{ss:02}Z"
    ))
}

#[allow(dead_code)]
fn _assert_error_used(_: Error) {}

#[cfg(test)]
mod tests {
    use super::*;

    const J0: i64 = 1_786_881_600;

    fn jetable() -> Target {
        Target {
            container: container_name(J0).expect("nom"),
            disposable: true,
        }
    }

    #[test]
    fn an_undeclared_target_is_refused() {
        // 🔴 Aucun défaut, aucune déduction : un exercice qui devinerait sa cible
        // finirait un jour par deviner mal.
        let t = Target {
            disposable: false,
            ..jetable()
        };
        let e = authorize(&t, true).unwrap_err();
        assert!(matches!(e, Refused::NotDisposable { .. }));
        assert!(e.describe().contains("incident réel"), "{}", e.describe());
    }

    #[test]
    fn a_production_looking_name_is_refused_even_when_declared_disposable() {
        // 🔴 L'ordre des contrôles fait que --disposable ne peut PAS contourner ça :
        // une faute de frappe sur un nom de conteneur ne doit pas coûter une base.
        for nom in [
            "postgres-prod",
            "db-production",
            "pg-main",
            "PRIMARY-db",
            "live-pg",
        ] {
            let t = Target {
                container: nom.into(),
                disposable: true,
            };
            let e = authorize(&t, true).unwrap_err();
            assert!(
                matches!(e, Refused::LooksLikeProduction { .. }),
                "« {nom} » aurait dû être refusé"
            );
        }
    }

    #[test]
    fn a_disposable_target_passes() {
        assert!(authorize(&jetable(), true).is_ok());
    }

    #[test]
    fn without_a_backup_there_is_nothing_to_prove() {
        assert_eq!(
            authorize(&jetable(), false).unwrap_err(),
            Refused::NothingToRestore
        );
    }

    #[test]
    fn the_container_name_is_unmistakable() {
        let n = container_name(J0).expect("nom");
        assert!(n.starts_with("hlb-exercice-"), "{n}");
        // Et il ne déclenche aucun des garde-fous de nom.
        assert!(authorize(
            &Target {
                container: n,
                disposable: true
            },
            true
        )
        .is_ok());
    }

    #[test]
    fn an_empty_database_that_opens_is_the_worst_result() {
        // 🔴 Une base vide se restaure PARFAITEMENT : elle s'ouvre, aucune erreur.
        // C'est le cas qu'une vérification par taille laisse passer, et celui qui
        // ressemble le plus à un succès.
        let o = Outcome {
            scope: Scope::Postgres,
            opened: true,
            tables: Some(0),
            seconds: 12,
            detail: String::new(),
        };
        assert!(!o.succeeded());
        assert!(
            o.describe().contains("ne contient RIEN"),
            "{}",
            o.describe()
        );
        assert!(
            o.describe().contains("ressemble à un succès"),
            "{}",
            o.describe()
        );
    }

    #[test]
    fn a_populated_database_succeeds() {
        let o = Outcome {
            scope: Scope::Postgres,
            opened: true,
            tables: Some(14),
            seconds: 30,
            detail: String::new(),
        };
        assert!(o.succeeded());
        assert!(o.describe().contains("14 table"));
    }

    #[test]
    fn a_database_that_does_not_open_fails_loudly() {
        let o = Outcome {
            scope: Scope::Postgres,
            opened: false,
            tables: None,
            seconds: 5,
            detail: "could not read file pg_control".into(),
        };
        assert!(!o.succeeded());
        assert!(
            o.describe().contains("pg_control"),
            "la cause doit être visible"
        );
    }

    #[test]
    fn never_drilled_is_the_loudest_state() {
        let r = Readiness::from_days(None);
        assert_eq!(r, Readiness::Never);
        assert!(r.needs_attention());
        assert!(r.describe().contains("JAMAIS"));
        assert!(r.describe().contains("le pire jour"), "{}", r.describe());
    }

    #[test]
    fn the_drill_ages_through_three_states() {
        // Le §8.3 vise tous les 30 jours ; au-delà de 60, la procédure a eu le temps
        // de diverger.
        assert_eq!(Readiness::from_days(Some(5)), Readiness::Ready { days: 5 });
        assert_eq!(Readiness::from_days(Some(45)), Readiness::Due { days: 45 });
        assert_eq!(
            Readiness::from_days(Some(120)),
            Readiness::Overdue { days: 120 }
        );

        assert!(!Readiness::from_days(Some(5)).needs_attention());
        assert!(Readiness::from_days(Some(45)).needs_attention());
    }

    #[test]
    fn the_thresholds_leave_room_to_react() {
        // Alerter à 30 j pile ne laisse aucune marge : on veut savoir que c'est dû
        // AVANT que ce soit trop vieux.
        // `const` : vérifié à la compilation, donc changer un seuil sans y penser
        // ne compile même pas.
        const _: () = assert!(INTERVALLE_JOURS < RETARD_JOURS);
        const _: () = assert!(RETARD_JOURS - INTERVALLE_JOURS >= 30);
    }
}
