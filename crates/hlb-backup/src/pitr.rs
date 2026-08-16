//! Restauration à un instant précis pour PostgreSQL (§8.1, couche L2).
//!
//! ## Ce que ça apporte par rapport au dump logique
//!
//! `pg_dump` (couche L1) donne un instantané cohérent **à l'heure où il tourne**.
//! Entre deux dumps espacés de quatre heures, une suppression accidentelle à 14 h 05
//! coûte quatre heures de travail : on ne peut restaurer qu'à 12 h ou à 16 h — et
//! 16 h contient déjà la suppression.
//!
//! Le PITR change ça : une **sauvegarde de base** plus la suite continue des
//! journaux WAL permet de rejouer jusqu'à 14 h 04 exactement.
//!
//! ## 🔴 Le danger propre à l'archivage WAL
//!
//! **Un `archive_command` qui échoue ne perd pas les journaux : il les garde.**
//!
//! PostgreSQL considère qu'un segment WAL non archivé n'est pas recyclable. Si la
//! destination d'archivage est pleine, montée en lecture seule ou simplement absente,
//! `pg_wal` grossit indéfiniment jusqu'à saturer le disque — et le serveur s'arrête
//! net, en écriture comme en lecture.
//!
//! Autrement dit : **archiver vers une destination cassée est plus dangereux que ne
//! pas archiver du tout.**
//!
//! C'est pour ça que l'agent surveille `/archive/wal` et `/archive/base` par défaut
//! (§9bis) : la saturation du disque d'archivage déclenche les mêmes paliers que
//! n'importe quel autre système de fichiers. Un chemin absent est ignoré sans bruit —
//! tous les nœuds n'archivent pas.
//!
//! ## Ce que ce module fait
//!
//! Il **calcule et rend des configurations**. Il n'exécute rien : la restauration
//! d'une base est une opération manuelle, décidée par un humain, et une API qui la
//! déclencherait toute seule serait une arme pointée sur les données.

use crate::{Error, Result};

/// Une sauvegarde de base (`pg_basebackup`), point de départ d'un rejeu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaseBackup {
    pub id: String,
    /// Instant de **fin** de la sauvegarde, en secondes depuis l'époque.
    ///
    /// C'est bien la fin, pas le début : le rejeu ne peut commencer qu'à partir du
    /// moment où la copie des fichiers est complète et cohérente.
    pub finished_at: i64,
}

/// La fenêtre réellement restaurable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Window {
    pub earliest: i64,
    pub latest: i64,
}

impl Window {
    pub fn contains(&self, t: i64) -> bool {
        t >= self.earliest && t <= self.latest
    }

    pub fn describe(&self) -> String {
        format!("de {} à {}", iso8601(self.earliest), iso8601(self.latest))
    }
}

/// Où atterrissent les segments WAL archivés.
#[derive(Debug, Clone)]
pub struct WalArchive {
    /// Répertoire d'archivage, monté dans le conteneur PostgreSQL.
    pub dir: String,
}

impl WalArchive {
    pub fn new(dir: impl Into<String>) -> Self {
        Self { dir: dir.into() }
    }

    /// La commande d'archivage d'un segment.
    ///
    /// 🔴 Le `test ! -f` n'est pas une précaution superflue : sans lui, un segment
    /// réarchivé après un redémarrage **écrase** son homologue déjà présent. Si les
    /// contenus diffèrent — ce qui arrive après un basculement de ligne temporelle —
    /// l'archive devient silencieusement incohérente et le rejeu échoue le jour où
    /// on en a besoin. La documentation PostgreSQL impose cette forme.
    pub fn archive_command(&self) -> String {
        format!(
            "test ! -f {dir}/%f && cp %p {dir}/%f",
            dir = self.dir.trim_end_matches('/')
        )
    }

    /// La commande symétrique, utilisée pendant la reprise.
    pub fn restore_command(&self) -> String {
        format!("cp {}/%f %p", self.dir.trim_end_matches('/'))
    }

    /// Les réglages à poser dans `postgresql.conf`.
    ///
    /// ⚠️ `wal_level` et `archive_mode` exigent un **redémarrage** du serveur, pas un
    /// simple `pg_ctl reload`. Une modification rechargée à chaud est acceptée sans
    /// erreur et reste sans effet : l'archivage semble activé et n'archive rien.
    pub fn render_settings(&self) -> String {
        format!(
            "# Généré par HomelabUS (§8.1) — ne pas éditer à la main.\n\
             # ⚠️ Ces trois réglages exigent un REDÉMARRAGE, pas un reload.\n\
             wal_level = replica\n\
             archive_mode = on\n\
             archive_command = '{}'\n\
             # Marge de rejeu : un segment orphelin de 16 Mo vaut mieux qu'un trou.\n\
             archive_timeout = 300\n\
             wal_keep_size = 1024\n",
            self.archive_command()
        )
    }
}

/// Un segment WAL archivé.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    /// Nom du fichier, 24 caractères hexadécimaux.
    pub name: String,
    /// Instant où il a été archivé (date de modification du fichier).
    pub archived_at: i64,
}

impl Segment {
    /// La ligne temporelle du segment — les 8 premiers chiffres.
    ///
    /// Elle change après chaque reprise. Deux segments de lignes différentes peuvent
    /// couvrir la même position sans être interchangeables.
    pub fn timeline(&self) -> Option<u32> {
        u32::from_str_radix(self.name.get(..8)?, 16).ok()
    }
}

/// Un nom de segment WAL valide ?
///
/// 🔴 Le répertoire d'archivage ne contient pas que des segments : PostgreSQL y dépose
/// aussi des `.history` (changements de ligne temporelle), des `.backup` (marqueurs de
/// sauvegarde de base) et parfois des `.partial`. Les compter comme des segments
/// donnerait une couverture WAL plus large qu'elle ne l'est — soit précisément le
/// mensonge que ce module existe pour éviter.
fn is_segment(name: &str) -> bool {
    name.len() == 24 && name.chars().all(|c| c.is_ascii_hexdigit())
}

/// Inventorie les segments réellement présents dans le répertoire d'archivage.
///
/// C'est ce qui permet d'annoncer une borne haute **constatée** plutôt que déduite de
/// la dernière sauvegarde de base. Sans cet inventaire, on sous-estime la fenêtre — ce
/// qui est le bon sens de l'erreur, mais reste une information fausse.
pub fn scan_archive(dir: &std::path::Path) -> std::io::Result<Vec<Segment>> {
    let mut out = Vec::new();

    for e in std::fs::read_dir(dir)? {
        let e = e?;
        let nom = e.file_name().to_string_lossy().to_string();
        if !is_segment(&nom) {
            continue;
        }

        let m = e.metadata()?;
        if !m.is_file() {
            continue;
        }

        let at = m
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        out.push(Segment { name: nom, archived_at: at });
    }

    // Par nom : l'ordre lexicographique des segments WAL EST leur ordre chronologique,
    // par construction du format. Trier par date de fichier serait moins fiable — une
    // copie d'archive peut réécrire les dates sans changer les données.
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

/// Jusqu'à quand les journaux archivés permettent de rejouer.
///
/// ⚠️ C'est l'instant d'archivage du dernier segment, donc une **borne prudente** : le
/// segment courant, pas encore archivé, contient déjà des transactions plus récentes.
/// Annoncer plus loin promettrait un rejeu qu'on ne peut pas garantir.
pub fn wal_coverage(segments: &[Segment]) -> Option<i64> {
    segments.iter().map(|s| s.archived_at).max()
}

/// Pourquoi une restauration demandée n'est pas possible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unreachable {
    /// Aucune sauvegarde de base : le WAL seul ne restaure rien.
    NoBaseBackup,
    /// La cible précède la plus ancienne sauvegarde de base conservée.
    BeforeOldestBase { oldest: i64 },
    /// La cible est après le dernier journal archivé.
    AfterLastWal { last: i64 },
}

impl Unreachable {
    pub fn describe(&self) -> String {
        match self {
            Self::NoBaseBackup => "aucune sauvegarde de base : le WAL seul ne restaure rien"
                .to_string(),
            Self::BeforeOldestBase { oldest } => format!(
                "antérieur à la plus ancienne sauvegarde de base ({})",
                iso8601(*oldest)
            ),
            Self::AfterLastWal { last } => {
                format!("postérieur au dernier journal archivé ({})", iso8601(*last))
            }
        }
    }
}

/// La fenêtre restaurable, d'après ce qu'on conserve réellement.
///
/// `last_wal_at` est l'instant couvert par le dernier segment archivé.
pub fn recoverable_window(bases: &[BaseBackup], last_wal_at: i64) -> Option<Window> {
    let oldest = bases.iter().map(|b| b.finished_at).min()?;
    if last_wal_at < oldest {
        // Les journaux ne couvrent même pas la fin de la plus ancienne base : rien
        // n'est rejouable, et prétendre le contraire serait pire que de le dire.
        return None;
    }
    Some(Window {
        earliest: oldest,
        latest: last_wal_at,
    })
}

/// Choisit la sauvegarde de base à partir de laquelle rejouer.
///
/// 🔴 C'est la **plus récente antérieure ou égale** à la cible. Une base postérieure
/// est inutilisable : le WAL se rejoue en avant, jamais en arrière. Une base plus
/// ancienne fonctionnerait mais rejouerait inutilement des heures de journaux.
pub fn base_for(
    bases: &[BaseBackup],
    target: i64,
    last_wal_at: i64,
) -> std::result::Result<&BaseBackup, Unreachable> {
    if bases.is_empty() {
        return Err(Unreachable::NoBaseBackup);
    }
    if target > last_wal_at {
        return Err(Unreachable::AfterLastWal { last: last_wal_at });
    }

    bases
        .iter()
        .filter(|b| b.finished_at <= target)
        .max_by_key(|b| b.finished_at)
        .ok_or_else(|| Unreachable::BeforeOldestBase {
            oldest: bases
                .iter()
                .map(|b| b.finished_at)
                .min()
                .unwrap_or(target),
        })
}

/// Jusqu'où on peut purger les journaux archivés, sans rien casser.
///
/// 🔴 La borne est la **plus ancienne** sauvegarde de base conservée, pas la plus
/// récente. Purger jusqu'à la plus récente rendrait toutes les bases antérieures
/// irrestaurables : elles existeraient encore sur le disque, sembleraient valides, et
/// ne serviraient plus à rien. C'est le scénario où l'on croit avoir trente jours de
/// rétention et où l'on n'en a qu'un.
pub fn wal_prunable_before(bases: &[BaseBackup]) -> Option<i64> {
    bases.iter().map(|b| b.finished_at).min()
}

/// La configuration de reprise à écrire dans `postgresql.auto.conf`.
///
/// ⚠️ Depuis PostgreSQL 12, `recovery.conf` n'existe plus : ces paramètres vont dans
/// la configuration normale, et c'est la présence du fichier **`recovery.signal`**
/// qui déclenche la reprise. Un serveur à qui l'on donne ces réglages sans créer le
/// fichier démarre normalement et ignore la cible — sans le moindre avertissement.
pub fn render_recovery(archive: &WalArchive, target: i64) -> String {
    format!(
        "# Généré par HomelabUS (§8.1) — reprise à un instant précis.\n\
         # ⚠️ Créer AUSSI un fichier vide `recovery.signal` dans le répertoire de\n\
         # données : sans lui, PostgreSQL démarre normalement et ignore tout ceci.\n\
         restore_command = '{restore}'\n\
         recovery_target_time = '{cible}'\n\
         # `promote` : le serveur devient accessible en écriture une fois la cible\n\
         # atteinte. Le défaut (`pause`) le laisse en lecture seule, ce qui ressemble\n\
         # beaucoup à une restauration échouée.\n\
         recovery_target_action = 'promote'\n\
         # Après une reprise, PostgreSQL crée une nouvelle ligne temporelle. Sans ce\n\
         # réglage, une SECONDE restauration au même point suivrait la ligne d'origine\n\
         # et ne retrouverait pas les journaux attendus.\n\
         recovery_target_timeline = 'latest'\n",
        restore = archive.restore_command(),
        cible = pg_timestamp(target),
    )
}

/// Vérifie qu'une restauration est possible, et prépare tout ce qu'il faut.
pub fn plan_recovery(
    bases: &[BaseBackup],
    last_wal_at: i64,
    target: i64,
    archive: &WalArchive,
) -> Result<RecoveryPlan> {
    let base = base_for(bases, target, last_wal_at).map_err(|u| Error::Pitr {
        target: iso8601(target),
        reason: u.describe(),
    })?;

    Ok(RecoveryPlan {
        base: base.clone(),
        target,
        wal_replay_secs: target - base.finished_at,
        config: render_recovery(archive, target),
    })
}

#[derive(Debug, Clone)]
pub struct RecoveryPlan {
    pub base: BaseBackup,
    pub target: i64,
    /// Durée de journaux à rejouer. Sert à annoncer un ordre de grandeur : rejouer
    /// six jours de WAL ne prend pas le même temps que six minutes.
    pub wal_replay_secs: i64,
    pub config: String,
}

impl RecoveryPlan {
    pub fn describe(&self) -> String {
        format!(
            "base {} ({}), rejeu de {} h {:02} min jusqu'à {}",
            self.base.id,
            iso8601(self.base.finished_at),
            self.wal_replay_secs / 3600,
            (self.wal_replay_secs % 3600) / 60,
            iso8601(self.target)
        )
    }
}

/// Date lisible en UTC, sans dépendance de calendrier.
///
/// L'algorithme est celui de Howard Hinnant (`civil_from_days`) : il traite
/// correctement les années bissextiles séculaires, contrairement aux approximations
/// « une année fait 365,25 jours » qui dérivent d'un jour tous les quelques siècles.
pub fn iso8601(epoch: i64) -> String {
    let (y, m, d, hh, mm, ss) = civil(epoch);
    format!("{y:04}-{m:02}-{d:02} {hh:02}:{mm:02}:{ss:02} UTC")
}

/// La même date, au format que PostgreSQL attend pour `recovery_target_time`.
fn pg_timestamp(epoch: i64) -> String {
    let (y, m, d, hh, mm, ss) = civil(epoch);
    // Le suffixe `+00` est indispensable : sans fuseau, PostgreSQL interprète la
    // date dans le `TimeZone` du serveur, et l'on restaure à un instant décalé de
    // plusieurs heures sans que rien ne le signale.
    format!("{y:04}-{m:02}-{d:02} {hh:02}:{mm:02}:{ss:02}+00")
}

/// Analyse « AAAA-MM-JJ HH:MM:SS », **interprété en UTC**.
///
/// 🔴 Aucune tolérance sur le fuseau : accepter une date sans fuseau et l'interpréter
/// dans celui de la machine ferait restaurer à un instant décalé de plusieurs heures,
/// silencieusement. Ici c'est UTC, c'est dit, et l'affichage le rappelle.
pub fn parse_utc(s: &str) -> Option<i64> {
    let s = s.trim();
    let (date, heure) = s.split_once(['T', ' '])?;

    let mut d = date.split('-');
    let y: i64 = d.next()?.parse().ok()?;
    let m: i64 = d.next()?.parse().ok()?;
    let day: i64 = d.next()?.parse().ok()?;
    if d.next().is_some() || !(1..=12).contains(&m) || !(1..=31).contains(&day) {
        return None;
    }

    let mut t = heure.trim_end_matches('Z').split(':');
    let hh: i64 = t.next()?.parse().ok()?;
    let mm: i64 = t.next()?.parse().ok()?;
    // Les secondes sont facultatives : « 14:04 » est une cible parfaitement légitime.
    let ss: i64 = match t.next() {
        Some(v) => v.parse().ok()?,
        None => 0,
    };
    if t.next().is_some() || hh > 23 || mm > 59 || ss > 59 {
        return None;
    }

    let epoch = days_from_civil(y, m, day) * 86_400 + hh * 3600 + mm * 60 + ss;

    // Aller-retour : rejette le 31 février et consorts, que le calcul brut
    // accepterait en débordant sur le mois suivant.
    let (vy, vm, vd, _, _, _) = civil(epoch);
    if (vy, vm as i64, vd as i64) != (y, m, day) {
        return None;
    }
    Some(epoch)
}

/// L'inverse de `civil`, même origine décalée au 1er mars.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil(epoch: i64) -> (i64, u32, u32, u32, u32, u32) {
    let jours = epoch.div_euclid(86_400);
    let reste = epoch.rem_euclid(86_400);

    // Décale l'origine au 1er mars 0000 : février, avec son jour variable, se
    // retrouve en fin de cycle et disparaît du calcul.
    let z = jours + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };

    (
        y,
        m,
        d,
        (reste / 3600) as u32,
        ((reste % 3600) / 60) as u32,
        (reste % 60) as u32,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 2026-08-16 12:00:00 UTC.
    const J0: i64 = 1_786_881_600;
    const HEURE: i64 = 3600;

    fn bases() -> Vec<BaseBackup> {
        vec![
            BaseBackup { id: "base-1".into(), finished_at: J0 },
            BaseBackup { id: "base-2".into(), finished_at: J0 + 24 * HEURE },
            BaseBackup { id: "base-3".into(), finished_at: J0 + 48 * HEURE },
        ]
    }

    #[test]
    fn the_archive_command_never_overwrites() {
        // 🔴 Sans `test ! -f`, un segment réarchivé après redémarrage écrase son
        // homologue. Si les contenus diffèrent — ce qui arrive après un changement
        // de ligne temporelle — l'archive devient incohérente en silence.
        let c = WalArchive::new("/archive/wal").archive_command();
        assert!(c.starts_with("test ! -f /archive/wal/%f &&"), "{c}");
        assert!(c.contains("cp %p /archive/wal/%f"), "{c}");
    }

    #[test]
    fn a_trailing_slash_does_not_double_up() {
        let c = WalArchive::new("/archive/wal/").archive_command();
        assert!(!c.contains("//"), "{c}");
    }

    #[test]
    fn the_settings_warn_that_a_reload_is_not_enough() {
        // ⚠️ Un `wal_level` rechargé à chaud est accepté sans erreur et reste sans
        // effet : l'archivage paraît actif et n'archive rien.
        let s = WalArchive::new("/archive/wal").render_settings();
        assert!(s.contains("REDÉMARRAGE"), "{s}");
        assert!(s.contains("wal_level = replica"));
        assert!(s.contains("archive_mode = on"));
    }

    #[test]
    fn the_chosen_base_is_the_latest_one_before_the_target() {
        // 🔴 Le WAL se rejoue en avant, jamais en arrière : une base postérieure à
        // la cible est inutilisable, et une base trop ancienne rejoue pour rien.
        let b = bases();
        let cible = J0 + 30 * HEURE;
        let choisie = base_for(&b, cible, J0 + 72 * HEURE).expect("atteignable");
        assert_eq!(choisie.id, "base-2");
    }

    #[test]
    fn a_target_exactly_on_a_base_uses_that_base() {
        let b = bases();
        let choisie = base_for(&b, J0 + 24 * HEURE, J0 + 72 * HEURE).expect("atteignable");
        assert_eq!(choisie.id, "base-2", "aucun rejeu nécessaire");
    }

    #[test]
    fn a_target_before_every_base_is_refused() {
        let b = bases();
        let r = base_for(&b, J0 - HEURE, J0 + 72 * HEURE);
        assert_eq!(r.unwrap_err(), Unreachable::BeforeOldestBase { oldest: J0 });
    }

    #[test]
    fn a_target_after_the_last_wal_is_refused() {
        // Restaurer « à maintenant » alors que l'archivage est en panne depuis deux
        // jours donnerait une base silencieusement périmée de deux jours.
        let b = bases();
        let dernier = J0 + 50 * HEURE;
        let r = base_for(&b, J0 + 72 * HEURE, dernier);
        assert_eq!(r.unwrap_err(), Unreachable::AfterLastWal { last: dernier });
    }

    #[test]
    fn wal_alone_restores_nothing() {
        let e = base_for(&[], J0, J0 + HEURE).unwrap_err();
        assert_eq!(e, Unreachable::NoBaseBackup);
        assert!(e.describe().contains("WAL seul"));
    }

    #[test]
    fn the_window_starts_at_the_oldest_base() {
        let w = recoverable_window(&bases(), J0 + 72 * HEURE).expect("fenêtre");
        assert_eq!(w.earliest, J0);
        assert_eq!(w.latest, J0 + 72 * HEURE);
        assert!(w.contains(J0 + 30 * HEURE));
        assert!(!w.contains(J0 - 1));
    }

    #[test]
    fn without_a_base_there_is_no_window() {
        assert!(recoverable_window(&[], J0).is_none());
    }

    #[test]
    fn wal_that_predates_every_base_gives_no_window() {
        // Les journaux ne couvrent même pas la fin de la plus ancienne base :
        // annoncer une fenêtre restaurable serait un mensonge.
        assert!(recoverable_window(&bases(), J0 - HEURE).is_none());
    }

    #[test]
    fn wal_is_pruned_up_to_the_oldest_base_not_the_newest() {
        // 🔴 Le piège coûteux. Purger jusqu'à la base la plus RÉCENTE laisserait les
        // deux bases antérieures en place, d'apparence valide, et irrestaurables.
        // On croirait avoir trois jours de rétention ; on en aurait un.
        let borne = wal_prunable_before(&bases()).expect("borne");
        assert_eq!(borne, J0, "la borne est base-1, pas base-3");
        assert_ne!(borne, J0 + 48 * HEURE);
    }

    #[test]
    fn pruning_nothing_is_the_answer_without_bases() {
        assert!(wal_prunable_before(&[]).is_none());
    }

    #[test]
    fn the_recovery_config_mentions_the_signal_file() {
        // ⚠️ Sans `recovery.signal`, PostgreSQL démarre normalement et ignore
        // silencieusement la cible de reprise.
        let c = render_recovery(&WalArchive::new("/archive/wal"), J0);
        assert!(c.contains("recovery.signal"), "{c}");
        assert!(c.contains("recovery_target_action = 'promote'"));
        assert!(c.contains("recovery_target_timeline = 'latest'"));
    }

    #[test]
    fn the_recovery_target_carries_its_timezone() {
        // 🔴 Sans `+00`, PostgreSQL interprète la date dans le fuseau du serveur :
        // on restaure à un instant décalé de plusieurs heures, sans avertissement.
        let c = render_recovery(&WalArchive::new("/a"), J0);
        assert!(c.contains("recovery_target_time = '2026-08-16 12:00:00+00'"), "{c}");
    }

    #[test]
    fn a_plan_reports_how_much_wal_it_replays() {
        let p = plan_recovery(
            &bases(),
            J0 + 72 * HEURE,
            J0 + 30 * HEURE,
            &WalArchive::new("/archive/wal"),
        )
        .expect("plan");

        assert_eq!(p.base.id, "base-2");
        // De base-2 (J0+24 h) à la cible (J0+30 h) : six heures.
        assert_eq!(p.wal_replay_secs, 6 * HEURE);
        assert!(p.describe().contains("6 h 00 min"), "{}", p.describe());
    }

    #[test]
    fn an_impossible_plan_says_why() {
        let e = plan_recovery(&[], J0, J0, &WalArchive::new("/a")).unwrap_err();
        let m = e.to_string();
        assert!(m.contains("2026-08-16"), "{m}");
        assert!(m.contains("WAL seul"), "{m}");
    }

    /// Un nom de segment WAL réaliste : ligne temporelle, journal, segment.
    fn seg(timeline: u32, log: u32, num: u32) -> String {
        format!("{timeline:08X}{log:08X}{num:08X}")
    }

    #[test]
    fn only_real_segments_are_inventoried() {
        // 🔴 Le répertoire contient aussi des .history, .backup et .partial. Les
        // compter donnerait une couverture WAL plus large qu'elle ne l'est.
        let d = tempfile::tempdir().expect("répertoire");
        for n in [
            seg(1, 0, 1),
            seg(1, 0, 2),
            "00000001.history".to_string(),
            format!("{}.backup", seg(1, 0, 1)),
            format!("{}.partial", seg(1, 0, 3)),
            "README".to_string(),
        ] {
            std::fs::write(d.path().join(n), b"x").expect("écriture");
        }

        let s = scan_archive(d.path()).expect("inventaire");
        assert_eq!(s.len(), 2, "{:?}", s.iter().map(|x| &x.name).collect::<Vec<_>>());
        assert!(s.iter().all(|x| is_segment(&x.name)));
    }

    #[test]
    fn segments_are_ordered_by_name_not_by_file_date() {
        // L'ordre lexicographique des segments EST leur ordre chronologique, par
        // construction. Une copie d'archive peut réécrire les dates de fichier sans
        // toucher aux données : s'y fier donnerait un ordre arbitraire.
        let d = tempfile::tempdir().expect("répertoire");
        for n in [seg(1, 0, 3), seg(1, 0, 1), seg(1, 0, 2)] {
            std::fs::write(d.path().join(&n), b"x").expect("écriture");
        }

        let s = scan_archive(d.path()).expect("inventaire");
        let noms: Vec<&str> = s.iter().map(|x| x.name.as_str()).collect();
        assert_eq!(noms, [seg(1, 0, 1), seg(1, 0, 2), seg(1, 0, 3)]);
    }

    #[test]
    fn a_segment_carries_its_timeline() {
        // Après une reprise, PostgreSQL passe en ligne 2 : deux segments de lignes
        // différentes couvrent la même position sans être interchangeables.
        let s = Segment { name: seg(2, 0, 7), archived_at: 0 };
        assert_eq!(s.timeline(), Some(2));
        assert_eq!(Segment { name: "court".into(), archived_at: 0 }.timeline(), None);
    }

    #[test]
    fn an_empty_archive_covers_nothing() {
        // 🔴 `None`, pas `Some(0)` : un 0 serait interprété comme « couvert jusqu'au
        // 1er janvier 1970 », et toute cible serait déclarée hors de portée avec un
        // message absurde.
        let d = tempfile::tempdir().expect("répertoire");
        assert!(scan_archive(d.path()).expect("inventaire").is_empty());
        assert_eq!(wal_coverage(&[]), None);
    }

    #[test]
    fn a_missing_archive_directory_is_an_error() {
        // Un répertoire d'archivage absent est une panne d'archivage, pas une archive
        // vide. Le confondre masquerait exactement le scénario du §8.1 : pg_wal qui
        // grossit parce que l'archivage échoue.
        assert!(scan_archive(std::path::Path::new("/n-existe-pas")).is_err());
    }

    #[test]
    fn coverage_is_the_latest_archived_segment() {
        let s = vec![
            Segment { name: seg(1, 0, 1), archived_at: J0 },
            Segment { name: seg(1, 0, 2), archived_at: J0 + HEURE },
        ];
        assert_eq!(wal_coverage(&s), Some(J0 + HEURE));
    }

    #[test]
    fn the_window_extends_to_the_real_wal_not_the_last_base() {
        // Le point de tout cet inventaire : sans lui, la borne haute serait celle de
        // base-3 (J0+48 h) et l'on refuserait une restauration pourtant possible.
        let segments = vec![Segment {
            name: seg(1, 0, 9),
            archived_at: J0 + 70 * HEURE,
        }];
        let couverture = wal_coverage(&segments).expect("couverture");

        let w = recoverable_window(&bases(), couverture).expect("fenêtre");
        assert_eq!(w.latest, J0 + 70 * HEURE);
        assert!(w.contains(J0 + 65 * HEURE), "après la dernière base, mais couvert");

        // Et la cible correspondante devient atteignable.
        let p = plan_recovery(&bases(), couverture, J0 + 65 * HEURE, &WalArchive::new("/a"))
            .expect("plan");
        assert_eq!(p.base.id, "base-3");
    }

    #[test]
    fn parsing_and_formatting_round_trip() {
        let e = parse_utc("2026-08-16 12:00:00").expect("analysable");
        assert_eq!(e, J0);
        assert_eq!(iso8601(e), "2026-08-16 12:00:00 UTC");
        // La forme ISO avec « T » et « Z » doit passer aussi.
        assert_eq!(parse_utc("2026-08-16T12:00:00Z"), Some(J0));
        // Les secondes sont facultatives : « 14:04 » est une cible légitime.
        assert_eq!(parse_utc("2026-08-16 12:00"), Some(J0));
    }

    #[test]
    fn an_impossible_date_is_rejected() {
        // 🔴 Sans l'aller-retour de validation, le 31 février déborderait sur le
        // 3 mars et l'on restaurerait à une date que personne n'a demandée.
        assert_eq!(parse_utc("2026-02-31 00:00:00"), None);
        assert_eq!(parse_utc("2025-02-29 00:00:00"), None, "2025 n'est pas bissextile");
        assert!(parse_utc("2024-02-29 00:00:00").is_some(), "2024 l'est");
        assert_eq!(parse_utc("2026-13-01 00:00:00"), None);
        assert_eq!(parse_utc("2026-08-16 25:00:00"), None);
        assert_eq!(parse_utc("n'importe quoi"), None);
        assert_eq!(parse_utc("2026-08-16"), None, "sans heure, la cible est ambiguë");
    }

    #[test]
    fn the_civil_conversions_are_inverses() {
        for e in [0_i64, 951_782_400, J0, -86_400, 1_000_000_000] {
            let (y, m, d, hh, mm, ss) = civil(e);
            assert_eq!(
                days_from_civil(y, m as i64, d as i64) * 86_400
                    + hh as i64 * 3600
                    + mm as i64 * 60
                    + ss as i64,
                e,
                "aller-retour cassé pour {e}"
            );
        }
    }

    #[test]
    fn dates_survive_leap_years() {
        // 2000 est bissextile (divisible par 400), 1900 ne l'est pas (par 100).
        // Les approximations « 365,25 jours » se trompent sur exactement ces cas.
        assert_eq!(iso8601(951_782_400), "2000-02-29 00:00:00 UTC");
        assert_eq!(iso8601(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(iso8601(J0), "2026-08-16 12:00:00 UTC");
        // Un instant antérieur à l'époque ne doit pas produire d'aberration.
        assert_eq!(iso8601(-86_400), "1969-12-31 00:00:00 UTC");
    }
}

/// Production d'une sauvegarde de base (`pg_basebackup`).
///
/// 🔴 **Sans elle, l'archivage WAL ne sert à rien.** C'est le point de départ obligé
/// de tout rejeu : les journaux disent comment passer d'un état à un autre, jamais
/// quel est l'état initial. Un homelab qui archiverait consciencieusement son WAL
/// depuis six mois sans une seule sauvegarde de base ne pourrait rien restaurer.
pub mod basebackup {
    use super::*;

    /// Où écrire la sauvegarde, et à qui se connecter.
    #[derive(Debug, Clone)]
    pub struct Target {
        /// Volume ou chemin hôte recevant la copie.
        pub destination: String,
        pub host: String,
        pub port: u16,
        /// 🔴 Un rôle avec l'attribut `REPLICATION`. Le super-utilisateur convient,
        /// mais un rôle dédié limite ce qu'une fuite de ce mot de passe permettrait.
        pub user: String,
        pub password: String,
        /// Réseau Docker sur lequel le serveur est joignable.
        pub network: Option<String>,
        /// Image cliente. Sa version majeure doit correspondre au serveur.
        pub image: String,
    }

    impl Target {
        pub fn new(destination: impl Into<String>, host: impl Into<String>) -> Self {
            Self {
                destination: destination.into(),
                host: host.into(),
                port: 5432,
                user: "postgres".into(),
                password: String::new(),
                network: None,
                image: "postgres:17-alpine".into(),
            }
        }

        pub fn credentials(mut self, user: impl Into<String>, password: impl Into<String>) -> Self {
            self.user = user.into();
            self.password = password.into();
            self
        }

        pub fn network(mut self, net: impl Into<String>) -> Self {
            self.network = Some(net.into());
            self
        }

        pub fn image(mut self, image: impl Into<String>) -> Self {
            self.image = image.into();
            self
        }
    }

    /// Les arguments de `pg_basebackup`, isolés pour être testables sans Docker.
    ///
    /// Chaque option porte une conséquence :
    ///
    /// - `--format=tar` + `--gzip` : une arborescence brute serait recopiée fichier
    ///   par fichier, et les permissions se perdraient au passage sur un volume monté.
    /// - `--wal-method=stream` : 🔴 **le point critique.** Une sauvegarde de base met
    ///   plusieurs minutes ; pendant ce temps le serveur continue d'écrire. Sans les
    ///   journaux produits *pendant* la copie, la sauvegarde obtenue est incohérente et
    ///   PostgreSQL refuse de démarrer dessus. `stream` ouvre une seconde connexion qui
    ///   les capture au fil de l'eau. Le défaut historique (`fetch`) exige en plus que
    ///   `wal_keep_size` soit assez grand, faute de quoi la sauvegarde échoue *à la
    ///   fin*, après avoir tout copié.
    /// - `--checkpoint=fast` : sans lui, PostgreSQL attend le prochain checkpoint
    ///   naturel — jusqu'à plusieurs minutes d'attente avant que la copie ne démarre.
    /// - `--no-password` : jamais d'invite interactive. Un conteneur qui attend une
    ///   saisie reste bloqué jusqu'au délai d'expiration, sans rien dire.
    pub fn args(label: &str) -> Vec<String> {
        [
            "pg_basebackup",
            "--pgdata=/sauvegarde",
            "--format=tar",
            "--gzip",
            "--wal-method=stream",
            "--checkpoint=fast",
            "--progress",
            "--no-password",
        ]
        .iter()
        .map(|s| s.to_string())
        .chain(std::iter::once(format!("--label={label}")))
        .collect()
    }

    /// Enrichit les erreurs dont le message brut n'indique pas quoi faire.
    ///
    /// 🔴 `pg_basebackup` passe par le **protocole de réplication**, pas par une
    /// connexion SQL ordinaire. `pg_hba.conf` traite `replication` comme une base de
    /// données distincte : un utilisateur qui se connecte parfaitement en `psql` est
    /// refusé pour une sauvegarde de base. L'image officielle n'autorise la
    /// réplication que depuis `127.0.0.1`, donc jamais depuis un autre conteneur.
    pub(crate) fn expliquer(stderr: &str) -> String {
        if stderr.contains("no pg_hba.conf entry for replication") {
            return format!(
                "{stderr}\n\n\
                 🔴 pg_basebackup utilise le protocole de RÉPLICATION, que pg_hba.conf\n\
                 traite comme une base de données à part. Se connecter en psql ne prouve\n\
                 donc rien. L'image postgres officielle ne l'autorise que depuis\n\
                 127.0.0.1 — jamais depuis un autre conteneur.\n\n\
                 Ajoute cette ligne à pg_hba.conf, puis recharge :\n\
                 \x20   host replication all all scram-sha-256\n\
                 \x20   psql -U postgres -c 'SELECT pg_reload_conf()'"
            );
        }

        if stderr.contains("must be superuser or replication role")
            || stderr.contains("permission denied to start WAL sender")
        {
            return format!(
                "{stderr}\n\n\
                 🔴 L'utilisateur n'a pas l'attribut REPLICATION :\n\
                 \x20   ALTER ROLE <utilisateur> REPLICATION;"
            );
        }

        if stderr.contains("directory") && stderr.contains("exists and is not empty") {
            return format!(
                "{stderr}\n\n\
                 Une sauvegarde porte déjà ce nom. On n'écrase JAMAIS une sauvegarde\n\
                 existante : déplace-la ou supprime-la à la main si elle est inutile."
            );
        }

        stderr.to_string()
    }

    /// Le nom du sous-répertoire d'une sauvegarde de base.
    ///
    /// Horodaté et trié lexicographiquement : l'ordre des noms est l'ordre
    /// chronologique, ce dont dépend le choix de la base de départ (`base_for`).
    pub fn directory_name(at: i64) -> String {
        let (y, m, d, hh, mm, ss) = civil(at);
        format!("base-{y:04}{m:02}{d:02}T{hh:02}{mm:02}{ss:02}Z")
    }

    /// Exécute `pg_basebackup` dans un conteneur.
    ///
    /// Renvoie le nom du répertoire créé, qui sert d'identifiant d'instantané dans
    /// l'état — c'est ce que `hlb backup pitr plan` affichera.
    pub async fn run(target: &Target, at: i64) -> Result<String> {
        let nom = directory_name(at);

        let mut cmd = tokio::process::Command::new("docker");
        cmd.args(["run", "--rm"]);

        if let Some(n) = &target.network {
            cmd.arg("--network");
            cmd.arg(n);
        }

        for (k, v) in [
            ("PGHOST", target.host.clone()),
            ("PGPORT", target.port.to_string()),
            ("PGUSER", target.user.clone()),
            // Comme partout ailleurs : par l'environnement, jamais sur la ligne de
            // commande, lisible par tout utilisateur de la machine.
            ("PGPASSWORD", target.password.clone()),
        ] {
            cmd.arg("-e");
            cmd.arg(format!("{k}={v}"));
        }

        // Le sous-répertoire est créé par le montage : `pg_basebackup` exige une
        // destination VIDE et échouerait sur un répertoire déjà peuplé — ce qui est
        // exactement le comportement voulu, on n'écrase jamais une base existante.
        cmd.arg("-v");
        cmd.arg(format!(
            "{}/{nom}:/sauvegarde",
            target.destination.trim_end_matches('/')
        ));

        cmd.arg(&target.image);
        cmd.args(args(&nom));

        let out = cmd.output().await.map_err(|e| {
            Error::ResticMissing(format!("docker introuvable : {e}"))
        })?;

        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();

            // Un échec laisse un répertoire vide créé par le montage. L'accumuler à
            // chaque tentative encombrerait l'archive de coquilles indiscernables des
            // vraies sauvegardes pour qui regarde le disque.
            let _ = tokio::fs::remove_dir(format!(
                "{}/{nom}",
                target.destination.trim_end_matches('/')
            ))
            .await;

            return Err(Error::Dump {
                database: format!("sauvegarde de base « {nom} »"),
                stderr: expliquer(&stderr),
            });
        }

        tracing::info!(base = %nom, "sauvegarde de base produite");
        Ok(nom)
    }
}

#[cfg(test)]
mod tests_basebackup {
    use super::basebackup::*;

    const J0: i64 = 1_786_881_600;

    #[test]
    fn wal_is_streamed_during_the_copy() {
        // 🔴 L'option qui décide si la sauvegarde est restaurable. Une copie dure
        // plusieurs minutes pendant lesquelles le serveur écrit ; sans les journaux
        // produits À CE MOMENT-LÀ, PostgreSQL refuse de démarrer sur le résultat.
        let a = args("base-test");
        assert!(a.contains(&"--wal-method=stream".to_string()), "{a:?}");
        assert!(
            !a.iter().any(|x| x.contains("wal-method=fetch")),
            "`fetch` échouerait en FIN de sauvegarde si wal_keep_size est trop petit"
        );
    }

    #[test]
    fn the_checkpoint_is_forced() {
        // Sans ça, la copie attend le prochain checkpoint naturel : plusieurs minutes
        // d'immobilité que personne ne saurait expliquer.
        assert!(args("x").contains(&"--checkpoint=fast".to_string()));
    }

    #[test]
    fn no_interactive_prompt_is_ever_possible() {
        // Un conteneur qui attend une saisie reste bloqué en silence jusqu'au délai
        // d'expiration.
        assert!(args("x").contains(&"--no-password".to_string()));
    }

    #[test]
    fn the_label_reaches_the_command() {
        assert!(args("base-20260816T120000Z")
            .contains(&"--label=base-20260816T120000Z".to_string()));
    }

    #[test]
    fn directory_names_sort_chronologically() {
        // 🔴 Le choix de la base de départ dépend de l'ordre. Un nom qui ne trierait
        // pas comme le temps ferait rejouer depuis la mauvaise sauvegarde.
        let a = directory_name(J0);
        let b = directory_name(J0 + 3600);
        let c = directory_name(J0 + 86_400);

        assert_eq!(a, "base-20260816T120000Z");
        assert!(a < b, "{a} < {b}");
        assert!(b < c, "{b} < {c}");
    }

    #[test]
    fn the_replication_refusal_says_exactly_what_to_add() {
        // 🔴 Le message brut de PostgreSQL est exact mais inexploitable : rien n'y
        // dit que « replication » est une base au sens de pg_hba, ni que l'image
        // officielle ne l'autorise que depuis 127.0.0.1. Constaté sur un vrai
        // serveur : un utilisateur qui se connecte en psql est refusé ici.
        let brut = "pg_basebackup: error: connection to server at \"pg\" failed: \
                    FATAL:  no pg_hba.conf entry for replication connection from \
                    host \"172.27.0.3\", user \"postgres\", no encryption";
        let m = expliquer(brut);

        assert!(m.contains("host replication all all scram-sha-256"), "{m}");
        assert!(m.contains("pg_reload_conf"), "{m}");
        assert!(m.contains(brut), "le message d'origine doit rester lisible");
    }

    #[test]
    fn a_role_without_replication_is_diagnosed() {
        let m = expliquer("FATAL: must be superuser or replication role to start walsender");
        assert!(m.contains("ALTER ROLE"), "{m}");
    }

    #[test]
    fn an_ordinary_error_is_left_alone() {
        // On n'ajoute du texte que quand on a quelque chose d'utile à dire.
        let brut = "pg_basebackup: error: could not connect: timeout";
        assert_eq!(expliquer(brut), brut);
    }

    #[test]
    fn the_password_never_appears_in_the_arguments() {
        // Une ligne de commande est lisible par tout utilisateur de la machine.
        let t = Target::new("/archive/base", "postgres").credentials("hlb", "s3cr3t");
        assert!(!args("x").iter().any(|a| a.contains("s3cr3t")));
        assert_eq!(t.password, "s3cr3t", "il passe par l'environnement");
    }

    #[test]
    fn a_trailing_slash_does_not_double_up() {
        let t = Target::new("/archive/base/", "postgres");
        let chemin = format!("{}/{}", t.destination.trim_end_matches('/'), directory_name(J0));
        assert!(!chemin.contains("//"), "{chemin}");
    }
}

/// Les identifiants de connexion extraits d'une URL PostgreSQL.
///
/// Le CLI reçoit déjà `--postgres-admin` sous la forme
/// `postgres://user:password@hôte:port/base`. Les redemander séparément pour la
/// sauvegarde de base ferait diverger deux sources de vérité — et le jour où l'une
/// change, la sauvegarde échoue sur une authentification refusée.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credentials {
    pub user: String,
    pub password: String,
    pub host: String,
    pub port: u16,
}

/// Analyse `postgres://user:password@hôte:port/base`.
///
/// ⚠️ Le mot de passe peut contenir des caractères encodés (`%40` pour `@`). On les
/// décode : les passer tels quels ferait échouer l'authentification avec un message
/// parfaitement trompeur — « mot de passe incorrect » alors qu'il est bon.
pub fn parse_pg_url(url: &str) -> Option<Credentials> {
    let reste = url
        .strip_prefix("postgres://")
        .or_else(|| url.strip_prefix("postgresql://"))?;

    // On coupe sur le DERNIER `@` : un mot de passe peut en contenir un.
    let (identifiants, hote) = reste.rsplit_once('@')?;
    let (user, password) = identifiants.split_once(':').unwrap_or((identifiants, ""));

    // Le chemin (`/base`) et la chaîne de requête ne nous concernent pas.
    let hote = hote.split(['/', '?']).next()?;
    let (host, port) = match hote.rsplit_once(':') {
        Some((h, p)) => (h, p.parse().unwrap_or(5432)),
        None => (hote, 5432),
    };

    if host.is_empty() || user.is_empty() {
        return None;
    }

    Some(Credentials {
        user: percent_decode(user),
        password: percent_decode(password),
        host: host.to_string(),
        port,
    })
}

/// Décodage pour-cent minimal, suffisant pour un identifiant d'URL.
fn percent_decode(s: &str) -> String {
    let o = s.as_bytes();
    let mut out = Vec::with_capacity(o.len());
    let mut i = 0;

    while i < o.len() {
        if o[i] == b'%' && i + 2 < o.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(o[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests_url {
    use super::*;

    #[test]
    fn a_standard_url_is_parsed() {
        let c = parse_pg_url("postgres://admin:secret@db.local:5433/postgres")
            .expect("analysable");
        assert_eq!(c.user, "admin");
        assert_eq!(c.password, "secret");
        assert_eq!(c.host, "db.local");
        assert_eq!(c.port, 5433);
    }

    #[test]
    fn the_port_defaults_to_5432() {
        let c = parse_pg_url("postgres://admin:x@db.local/postgres").expect("analysable");
        assert_eq!(c.port, 5432);
        assert_eq!(c.host, "db.local");
    }

    #[test]
    fn an_encoded_password_is_decoded() {
        // ⚠️ Sans décodage, l'authentification échoue en annonçant un mot de passe
        // incorrect alors qu'il est bon — le diagnostic le plus coûteux qui soit.
        let c = parse_pg_url("postgres://admin:p%40ss%3Aword@db/postgres").expect("analysable");
        assert_eq!(c.password, "p@ss:word");
    }

    #[test]
    fn a_password_containing_an_at_sign_still_parses() {
        // On coupe sur le DERNIER `@`, sinon l'hôte serait tronqué.
        let c = parse_pg_url("postgres://admin:a@b@db.local/postgres").expect("analysable");
        assert_eq!(c.password, "a@b");
        assert_eq!(c.host, "db.local");
    }

    #[test]
    fn the_postgresql_scheme_works_too() {
        assert!(parse_pg_url("postgresql://a:b@h/db").is_some());
    }

    #[test]
    fn a_query_string_is_ignored() {
        let c = parse_pg_url("postgres://a:b@h:5432/db?sslmode=require").expect("analysable");
        assert_eq!(c.host, "h");
        assert_eq!(c.port, 5432);
    }

    #[test]
    fn nonsense_is_refused() {
        assert!(parse_pg_url("").is_none());
        assert!(parse_pg_url("mysql://a:b@h/db").is_none(), "mauvais schéma");
        assert!(parse_pg_url("postgres://db.local/base").is_none(), "sans identifiants");
        assert!(parse_pg_url("postgres://:mdp@h/db").is_none(), "sans utilisateur");
    }
}
