//! The flaws found in the images that run, as the daily scan read them, and what was said
//! about them.
//!
//! Stored per DIGEST, not per app: PostgreSQL's image serves several apps' databases and
//! is read once. An app's flaws are those of the digests its frozen manifest runs.

use std::collections::BTreeSet;

use sqlx::Row;

use crate::{Result, State};

/// One flaw in one package of an image, a fix known.
#[derive(Debug, Clone, PartialEq)]
pub struct Flaw {
    pub id: String,
    pub package: String,
    /// As the advisory grades it: `Critical`, `High`…
    pub severity: String,
    pub version: String,
    pub fixed_in: String,
    /// On CISA's list of flaws exploited in the wild.
    pub exploited: bool,
    /// The chance it is exploited within thirty days, when known.
    pub epss: Option<f64>,
    /// When a reading of this digest first found it.
    pub first_seen: i64,
}

/// The last reading of one image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageScan {
    pub digest: String,
    pub image: String,
    /// The last reading that succeeded: `None`, never read.
    pub read_at: Option<i64>,
    /// The last that failed, and why — kept beside an older good reading, never in its
    /// place.
    pub failed_at: Option<i64>,
    pub error: Option<String>,
}

impl ImageScan {
    /// The flaws stored are today's: read, and not failed since.
    pub fn is_current(&self) -> bool {
        match (self.read_at, self.failed_at) {
            (Some(r), Some(f)) => r >= f,
            (Some(_), None) => true,
            (None, _) => false,
        }
    }
}

impl State {
    /// Records a reading of `digest`. Its flaws replace the last reading's, each keeping
    /// when it was first seen; a failure keeps them, and says when and why.
    pub async fn record_image_scan(
        &self,
        digest: &str,
        image: &str,
        at: i64,
        reading: std::result::Result<&[Flaw], &str>,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "INSERT INTO image_scans (digest, image) VALUES (?1, ?2)
             ON CONFLICT (digest) DO UPDATE SET image = excluded.image",
        )
        .bind(digest)
        .bind(image)
        .execute(&mut *tx)
        .await?;
        match reading {
            Err(why) => {
                sqlx::query("UPDATE image_scans SET failed_at = ?2, error = ?3 WHERE digest = ?1")
                    .bind(digest)
                    .bind(at)
                    .bind(why)
                    .execute(&mut *tx)
                    .await?;
            }
            Ok(flaws) => {
                let seen: Vec<(String, String, i64)> = sqlx::query_as(
                    "SELECT id, package, first_seen FROM image_flaws WHERE digest = ?1",
                )
                .bind(digest)
                .fetch_all(&mut *tx)
                .await?;
                sqlx::query("DELETE FROM image_flaws WHERE digest = ?1")
                    .bind(digest)
                    .execute(&mut *tx)
                    .await?;
                for f in flaws {
                    let first = seen
                        .iter()
                        .find(|(i, p, _)| *i == f.id && *p == f.package)
                        .map_or(at, |(_, _, t)| *t);
                    sqlx::query(
                        "INSERT OR IGNORE INTO image_flaws (digest, id, package, severity, version,
                             fixed_in, exploited, epss, first_seen)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                    )
                    .bind(digest)
                    .bind(&f.id)
                    .bind(&f.package)
                    .bind(&f.severity)
                    .bind(&f.version)
                    .bind(&f.fixed_in)
                    .bind(f.exploited)
                    .bind(f.epss)
                    .bind(first)
                    .execute(&mut *tx)
                    .await?;
                }
                sqlx::query(
                    "UPDATE image_scans SET read_at = ?2, failed_at = NULL, error = NULL
                     WHERE digest = ?1",
                )
                .bind(digest)
                .bind(at)
                .execute(&mut *tx)
                .await?;
            }
        }
        tx.commit().await?;
        Ok(())
    }

    /// The last reading of `digest`, if one was ever tried.
    pub async fn image_scan(&self, digest: &str) -> Result<Option<ImageScan>> {
        let row = sqlx::query(
            "SELECT digest, image, read_at, failed_at, error FROM image_scans WHERE digest = ?1",
        )
        .bind(digest)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|r| {
            Ok(ImageScan {
                digest: r.try_get("digest")?,
                image: r.try_get("image")?,
                read_at: r.try_get("read_at")?,
                failed_at: r.try_get("failed_at")?,
                error: r.try_get("error")?,
            })
        })
        .transpose()
    }

    /// The flaws the last good reading of `digest` found.
    pub async fn image_flaws(&self, digest: &str) -> Result<Vec<Flaw>> {
        let rows = sqlx::query(
            "SELECT id, package, severity, version, fixed_in, exploited, epss, first_seen
             FROM image_flaws WHERE digest = ?1 ORDER BY id, package",
        )
        .bind(digest)
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|r| {
                Ok(Flaw {
                    id: r.try_get("id")?,
                    package: r.try_get("package")?,
                    severity: r.try_get("severity")?,
                    version: r.try_get("version")?,
                    fixed_in: r.try_get("fixed_in")?,
                    exploited: r.try_get::<i64, _>("exploited")? != 0,
                    epss: r.try_get("epss")?,
                    first_seen: r.try_get("first_seen")?,
                })
            })
            .collect()
    }

    /// Forgets the readings of every image but `running`: one no app runs any more has
    /// nothing left to say.
    pub async fn keep_image_scans(&self, running: &BTreeSet<String>) -> Result<()> {
        let all: Vec<String> = sqlx::query_scalar("SELECT digest FROM image_scans")
            .fetch_all(&self.pool)
            .await?;
        for d in all.iter().filter(|d| !running.contains(*d)) {
            sqlx::query("DELETE FROM image_scans WHERE digest = ?1")
                .bind(d)
                .execute(&self.pool)
                .await?;
        }
        Ok(())
    }

    /// The flaws already said aloud for `app`.
    pub async fn alerted_flaws(&self, app: &str) -> Result<BTreeSet<String>> {
        let ids: Vec<String> = sqlx::query_scalar("SELECT id FROM flaw_alerts WHERE app = ?1")
            .bind(app)
            .fetch_all(&self.pool)
            .await?;
        Ok(ids.into_iter().collect())
    }

    /// `app`'s alerts now: those of `ids` not said yet are recorded at `at`, and those no
    /// longer among them forgotten — gone, so said again should they come back.
    pub async fn set_alerted_flaws(
        &self,
        app: &str,
        ids: &BTreeSet<String>,
        at: i64,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        let before: Vec<String> = sqlx::query_scalar("SELECT id FROM flaw_alerts WHERE app = ?1")
            .bind(app)
            .fetch_all(&mut *tx)
            .await?;
        for gone in before.iter().filter(|i| !ids.contains(*i)) {
            sqlx::query("DELETE FROM flaw_alerts WHERE app = ?1 AND id = ?2")
                .bind(app)
                .bind(gone)
                .execute(&mut *tx)
                .await?;
        }
        for id in ids {
            sqlx::query(
                "INSERT OR IGNORE INTO flaw_alerts (app, id, alerted_at) VALUES (?1, ?2, ?3)",
            )
            .bind(app)
            .bind(id)
            .bind(at)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Forgets the alerts of every app but `installed`.
    pub async fn keep_flaw_alerts(&self, installed: &BTreeSet<String>) -> Result<()> {
        let apps: Vec<String> = sqlx::query_scalar("SELECT DISTINCT app FROM flaw_alerts")
            .fetch_all(&self.pool)
            .await?;
        for a in apps.iter().filter(|a| !installed.contains(*a)) {
            sqlx::query("DELETE FROM flaw_alerts WHERE app = ?1")
                .bind(a)
                .execute(&self.pool)
                .await?;
        }
        Ok(())
    }

    /// When the weekly digest was last sent.
    pub async fn flaw_digest_sent(&self) -> Result<Option<i64>> {
        Ok(
            sqlx::query_scalar("SELECT sent_at FROM flaw_digest WHERE one = 1")
                .fetch_optional(&self.pool)
                .await?,
        )
    }

    pub async fn set_flaw_digest_sent(&self, at: i64) -> Result<()> {
        sqlx::query(
            "INSERT INTO flaw_digest (one, sent_at) VALUES (1, ?1)
             ON CONFLICT (one) DO UPDATE SET sent_at = excluded.sent_at",
        )
        .bind(at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flaw(id: &str, package: &str) -> Flaw {
        Flaw {
            id: id.into(),
            package: package.into(),
            severity: "High".into(),
            version: "1.0".into(),
            fixed_in: "1.1".into(),
            exploited: false,
            epss: Some(0.2),
            first_seen: 0,
        }
    }

    #[tokio::test]
    async fn a_flaw_keeps_when_it_was_first_seen_across_readings() {
        let s = State::in_memory().await.expect("state");
        let d = "sha256:pg";
        s.record_image_scan(
            d,
            "postgres:17@sha256:pg",
            100,
            Ok(&[flaw("CVE-1", "libssl3")]),
        )
        .await
        .expect("first");
        s.record_image_scan(
            d,
            "postgres:17@sha256:pg",
            200,
            Ok(&[flaw("CVE-1", "libssl3"), flaw("CVE-2", "perl")]),
        )
        .await
        .expect("second");
        let f = s.image_flaws(d).await.expect("read");
        assert_eq!(
            f.iter()
                .map(|f| (f.id.as_str(), f.first_seen))
                .collect::<Vec<_>>(),
            [("CVE-1", 100), ("CVE-2", 200)]
        );
        assert_eq!(f[0].epss, Some(0.2));
    }

    #[tokio::test]
    async fn a_failed_reading_keeps_the_last_good_one_and_says_it_failed() {
        let s = State::in_memory().await.expect("state");
        let d = "sha256:pg";
        assert_eq!(s.image_scan(d).await.expect("read"), None);
        s.record_image_scan(d, "pg", 100, Ok(&[flaw("CVE-1", "p")]))
            .await
            .expect("read");
        assert!(s.image_scan(d).await.expect("r").expect("one").is_current());
        s.record_image_scan(d, "pg", 200, Err("Grype failed"))
            .await
            .expect("failed");
        let scan = s.image_scan(d).await.expect("r").expect("one");
        assert!(!scan.is_current(), "{scan:?}");
        assert_eq!(scan.read_at, Some(100));
        assert_eq!(scan.error.as_deref(), Some("Grype failed"));
        assert_eq!(s.image_flaws(d).await.expect("r").len(), 1);
        // Never read at all is not current either.
        s.record_image_scan("sha256:new", "x", 1, Err("no"))
            .await
            .expect("failed");
        assert!(!s
            .image_scan("sha256:new")
            .await
            .expect("r")
            .expect("one")
            .is_current());
    }

    #[tokio::test]
    async fn an_image_nobody_runs_is_forgotten_with_its_flaws() {
        let s = State::in_memory().await.expect("state");
        for d in ["sha256:a", "sha256:b"] {
            s.record_image_scan(d, d, 1, Ok(&[flaw("CVE-1", "p")]))
                .await
                .expect("read");
        }
        s.keep_image_scans(&["sha256:a".to_string()].into())
            .await
            .expect("tidy");
        assert!(s.image_scan("sha256:b").await.expect("r").is_none());
        assert!(s.image_flaws("sha256:b").await.expect("r").is_empty());
        assert_eq!(s.image_flaws("sha256:a").await.expect("r").len(), 1);
    }

    #[tokio::test]
    async fn an_alert_is_said_once_and_again_only_once_gone() {
        let s = State::in_memory().await.expect("state");
        let ids = |l: &[&str]| l.iter().map(|s| s.to_string()).collect::<BTreeSet<_>>();
        s.set_alerted_flaws("gitea", &ids(&["CVE-1"]), 10)
            .await
            .expect("set");
        s.set_alerted_flaws("gitea", &ids(&["CVE-1", "CVE-2"]), 20)
            .await
            .expect("set");
        assert_eq!(
            s.alerted_flaws("gitea").await.expect("r"),
            ids(&["CVE-1", "CVE-2"])
        );
        s.set_alerted_flaws("gitea", &ids(&["CVE-2"]), 30)
            .await
            .expect("set");
        assert_eq!(s.alerted_flaws("gitea").await.expect("r"), ids(&["CVE-2"]));
        s.keep_flaw_alerts(&BTreeSet::new()).await.expect("tidy");
        assert!(s.alerted_flaws("gitea").await.expect("r").is_empty());
        assert_eq!(s.flaw_digest_sent().await.expect("r"), None);
        s.set_flaw_digest_sent(5).await.expect("sent");
        s.set_flaw_digest_sent(7).await.expect("sent");
        assert_eq!(s.flaw_digest_sent().await.expect("r"), Some(7));
    }
}
