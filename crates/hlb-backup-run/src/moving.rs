//! A database moved to another server of its engine: the vital apps' own PostgreSQL,
//! installed with a site, and back.
//!
//! The copy taken here is the move: dumped from the server it lives on, archived and
//! recorded as one of the schedule's dumps — the newest a restore takes unasked, since
//! it is what the database holds — then put back on the other server by the restore
//! `hlb backup restore` runs. Its order is the caller's: the app stopped before the
//! copy, the server recorded only once the copy is in, the old database dropped only
//! once the app answers on the new one.

use hlb_backup::pgdump::DUMP_KIND;
use hlb_types::DbEngine;

use crate::lifeboat::Brought;
use crate::restore::{Database, Restore};

impl Restore<'_> {
    /// `db` as `admin_url`'s server holds it, archived to `app`'s first critical
    /// destination and recorded. ⚠️ The app must be stopped: a write after the copy
    /// would stay on the old server.
    pub async fn database_copy(
        &self,
        app: &str,
        db: &Database<'_>,
        admin_url: &str,
    ) -> Result<Brought, String> {
        let dest = crate::effective_destinations(
            self.state,
            app,
            hlb_backup::Class::Critical,
            self.fallback_repo,
        )
        .await
        .map_err(|e| e.to_string())?
        .into_iter()
        .next()
        .ok_or_else(|| format!("no destination accepts {app}'s dumps"))?;
        // 🔴 Exhaustive: an engine added must say how it is copied.
        let dump = match db.engine {
            DbEngine::Postgres => crate::pg_dump(self.network, app, db.name, admin_url).await,
            DbEngine::Mariadb => crate::maria_dump(self.network, app, db.name, admin_url).await,
        }
        .map_err(|e| format!("{} could not be dumped: {e}", db.name))?;
        self.archived(app, db, &dest, &dump, DUMP_KIND).await
    }
}
