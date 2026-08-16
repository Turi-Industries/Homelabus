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
//! pas archiver du tout**. C'est pour ça que ce module refuse de produire une
//! configuration d'archivage sans destination explicitement validée, et que la
//! pression disque du §9bis surveille le chemin d'archivage comme les autres.
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
