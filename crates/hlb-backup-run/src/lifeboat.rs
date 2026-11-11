//! What the house's backups hold of an app, sent to its site's own daemon — and, once
//! the site has served it, what it wrote there brought back into those backups.
//!
//! 🔴 **Read here, never there.** One restic password encrypts every app's snapshots:
//! the house restores, and the site receives the files and the dump of the apps it
//! carries, nothing it could read the others with.
//!
//! What comes home goes through the backups rather than straight onto the house's
//! volumes: the restores already know where each volume lives and back up what it holds
//! before replacing it, and the site's copy stays restorable once the site is wiped.

use std::path::Path;

use hlb_backup::restic::Node;
use hlb_backup::Snapshot;
use hlb_orchestrator::tar::{self, Attrs, Kind};
use hlb_orchestrator::SwarmOrchestrator;
use hlb_types::DbEngine;
use tokio::io::AsyncWriteExt as _;

use crate::restore::{sqlite_of_pass, Database, Restore, Source};
use crate::{restic_password, volume_path};

/// What the site wrote, archived on its way home. 🔴 A stored value: the restore that
/// follows names it by id, and a person reading the snapshots tells it apart by this.
pub const FROM_SITE: &str = "kind:from-site";

/// What one restore sent the site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sent {
    /// The snapshot it was read from.
    pub snapshot: String,
    /// Bytes shipped: the archive's, or the dump's.
    pub bytes: u64,
    /// The SQLite databases put back from the pass's consistent copies.
    pub sqlite: Vec<String>,
}

/// The site's daemon, and how its free space is asked before an archive is sent.
pub struct Site<'a> {
    pub docker: &'a SwarmOrchestrator,
    /// The site daemon's socket, bridged here: the client tools run there.
    pub socket: &'a Path,
    /// The overlay the site's PostgreSQL answers on.
    pub network: &'a str,
}

/// The site's PostgreSQL: its image, which the client tools run from, and its own
/// administrator — never the house's.
pub struct Server<'a> {
    pub image: &'a str,
    pub admin_password: &'a str,
}

impl<'a> Server<'a> {
    /// Its administrator, reading off the site's `postgres`.
    pub fn reader(&self) -> Reader<'a> {
        Reader {
            image: self.image,
            host: "postgres",
            user: "postgres",
            password: self.admin_password,
        }
    }
}

/// Who reads a database off the site, and where: the server's service, and an account
/// that may dump the database — on the vital server's standby, promoted, the app's own
/// role, whose password the site was always given.
pub struct Reader<'a> {
    /// The server's image, which the client tools run from.
    pub image: &'a str,
    pub host: &'a str,
    pub user: &'a str,
    pub password: &'a str,
}

/// The decision on whether an archive of `bytes` fits in what the site has free:
/// a tenth of its disk always left, as a verification leaves the house's.
pub fn fits(bytes: u64, free: u64, total: u64) -> Result<(), String> {
    let floor = total / 10;
    if free.saturating_sub(bytes) < floor {
        return Err(format!(
            "{} MB to send, {} MB free on the site: a tenth of its disk must stay free",
            bytes.div_ceil(1 << 20),
            free >> 20
        ));
    }
    Ok(())
}

fn attrs(n: &Node) -> Attrs {
    Attrs {
        uid: n.uid,
        gid: n.gid,
        mode: n.mode,
        mtime: u64::try_from(n.mtime).unwrap_or(0),
    }
}

/// An error and every cause under it: a request cut on the way says only "client
/// error (SendRequest)", and why — a pipe broken, the daemon's early answer — is below.
fn causes(e: &dyn std::error::Error) -> String {
    let mut out = e.to_string();
    let mut next = e.source();
    while let Some(c) = next {
        let c_text = c.to_string();
        if !out.contains(&c_text) {
            out.push_str(": ");
            out.push_str(&c_text);
        }
        next = c.source();
    }
    out
}

/// A file streamed to Docker in chunks, read from the start.
fn stream(
    file: tokio::fs::File,
) -> impl futures::Stream<Item = std::io::Result<bytes::Bytes>> + Send + 'static {
    futures::stream::try_unfold(file, |mut f| async move {
        use tokio::io::AsyncReadExt as _;
        let mut buf = vec![0u8; 1 << 16];
        let n = f.read(&mut buf).await?;
        if n == 0 {
            return Ok(None);
        }
        buf.truncate(n);
        Ok(Some((bytes::Bytes::from(buf), f)))
    })
}

/// An archive written here and read back to send. 🔴 Not `File::create`: write-only,
/// and the read that streams it fails "Bad file descriptor" — which reached the client
/// as nothing but "client error (SendRequest)".
async fn scratch_file(path: &Path) -> Result<tokio::fs::File, String> {
    tokio::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .await
        .map_err(|e| format!("{}: {e}", path.display()))
}

async fn rewound(mut f: tokio::fs::File) -> Result<(tokio::fs::File, u64), String> {
    use tokio::io::AsyncSeekExt as _;
    f.flush().await.map_err(|e| e.to_string())?;
    let size = f
        .seek(std::io::SeekFrom::End(0))
        .await
        .map_err(|e| e.to_string())?;
    f.rewind().await.map_err(|e| e.to_string())?;
    Ok((f, size))
}

/// The archive putting an empty [`wal_ship::STANDBY_SIGNAL`], the server's user's, into
/// the data directory mounted at `root`. No entry for the directory: its own owner and
/// mode, the base's, stay as restored.
///
/// [`wal_ship::STANDBY_SIGNAL`]: hlb_backup::wal_ship::STANDBY_SIGNAL
pub fn standby_signal(root: &str) -> Result<Vec<u8>, String> {
    use hlb_backup::wal_ship::{POSTGRES_UID, STANDBY_SIGNAL};
    let mtime = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let a = Attrs {
        uid: POSTGRES_UID,
        gid: POSTGRES_UID,
        mode: 0o600,
        mtime,
    };
    let path = format!("{}/{STANDBY_SIGNAL}", root.trim_start_matches('/'));
    let mut out = tar::header(&path, Kind::File(0), &a)?.to_vec();
    out.extend_from_slice(&tar::end());
    Ok(out)
}

/// `volume` on the site, a PostgreSQL directory a base backup filled, made to start as a
/// standby. `image` is the server's, which the site has pulled already.
pub async fn mark_standby(site: &Site<'_>, image: &str, volume: &str) -> Result<(), String> {
    let root = volume_path(volume);
    let tar = bytes::Bytes::from(standby_signal(&root)?);
    site.docker
        .put_archive(
            image,
            volume,
            &root,
            futures::stream::once(async move { Ok::<_, std::io::Error>(tar) }),
        )
        .await
        .map_err(|e| format!("{volume} on the site: {}", causes(&e)))
}

impl Restore<'_> {
    fn repository(
        &self,
        source: &Source,
        password: &str,
        env: Vec<(String, String)>,
    ) -> hlb_backup::Repository<hlb_backup::ContainerRunner> {
        let (runner, location) = source.destination.runner(Some(self.network));
        hlb_backup::Repository::new(runner, location, password).extra_env(env)
    }

    /// Fills `volume` on the site with its latest snapshot, then its SQLite databases
    /// from the consistent copies the same pass took. `image` unpacks it — the
    /// service's own, which the site pulls anyway. `free` answers the site's free and
    /// total bytes, asked before the archive leaves.
    ///
    /// The archive is written to `scratch` first: Docker reads it at its own pace, and
    /// restic's dump cannot wait.
    pub async fn volume_to_site<F, Fut>(
        &self,
        app: &str,
        volume: &str,
        site: &Site<'_>,
        image: &str,
        scratch: &Path,
        free: F,
    ) -> Result<Sent, String>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Result<(u64, u64), String>>,
    {
        let source = self.find(app, volume, None, None).await?;
        let password = restic_password(self.state, self.vault)
            .await
            .map_err(|e| e.to_string())?;
        let env = self.env(&source.destination).await?;
        let repo = self.repository(&source, &password, env);
        let id = &source.snapshot.id;
        let root = volume_path(volume);

        // 🔴 restic's archive of a directory holds everything under it and not the
        // directory: unpacked so, the volume's root keeps the mount point's owner and
        // mode, and an app dropping its privileges cannot write into its own volume.
        let node = repo
            .node(id, &root)
            .await
            .map_err(|e| e.to_string())?
            .filter(|n| n.kind == "dir")
            .ok_or_else(|| format!("snapshot {} holds no directory {root}", &id[..8]))?;
        let path = scratch.join(format!("{volume}.tar"));
        let mut file = scratch_file(&path).await?;
        let head = tar::header(root.trim_start_matches('/'), Kind::Dir, &attrs(&node))?;
        file.write_all(&head).await.map_err(|e| e.to_string())?;
        repo.dump(id, &root, &mut file)
            .await
            .map_err(|e| format!("{volume}: {e}"))?;
        let (file, size) = rewound(file).await?;
        let (free_now, total) = free().await?;
        fits(size, free_now, total)?;
        site.docker
            .put_archive(image, volume, &root, stream(file))
            .await
            .map_err(|e| format!("{volume} on the site: {}", causes(&e)))?;
        let _ = tokio::fs::remove_file(&path).await;

        let sqlite = self
            .sqlite_to_site(app, volume, site, image, scratch, &source, &repo)
            .await?;
        Ok(Sent {
            snapshot: id.clone(),
            bytes: size,
            sqlite,
        })
    }

    /// Each SQLite database of `volume`, from the copy the pass of `source` took, over
    /// what restic read of it live. Its files only, at their own paths, owned as they
    /// were: the copy's own directories are the staging's, root's.
    #[allow(clippy::too_many_arguments)]
    async fn sqlite_to_site(
        &self,
        app: &str,
        volume: &str,
        site: &Site<'_>,
        image: &str,
        scratch: &Path,
        source: &Source,
        repo: &hlb_backup::Repository<hlb_backup::ContainerRunner>,
    ) -> Result<Vec<String>, String> {
        let taken = self
            .state
            .snapshots_taken(app)
            .await
            .map_err(|e| e.to_string())?;
        let all: Vec<Snapshot> = repo
            .snapshots(Some(&format!("app:{app}")))
            .await
            .map_err(|e| e.to_string())?;
        let mut back = Vec::new();
        for (db, s) in sqlite_of_pass(&all, volume, &source.snapshot, &taken) {
            // A database is named by its path in the volume (`data/app.db`): its slashes
            // would name directories the scratch does not have.
            let path = scratch.join(format!("{volume}-{}.tar", db.replace('/', "_")));
            let mut file = scratch_file(&path).await?;
            for p in &s.paths {
                let node = repo
                    .node(&s.id, p)
                    .await
                    .map_err(|e| e.to_string())?
                    .filter(|n| n.kind == "file")
                    .ok_or_else(|| format!("{db}: snapshot {} holds no file {p}", s.short_id()))?;
                let head = tar::header(
                    p.trim_start_matches('/'),
                    Kind::File(node.size),
                    &attrs(&node),
                )?;
                file.write_all(&head).await.map_err(|e| e.to_string())?;
                let mut counted = Counted {
                    inner: &mut file,
                    n: 0,
                };
                repo.dump(&s.id, p, &mut counted)
                    .await
                    .map_err(|e| format!("{db}: {e}"))?;
                // A header announcing a size the content does not have shifts every
                // entry after it: the archive would unpack garbage.
                if counted.n != node.size {
                    return Err(format!(
                        "{db}: {p} read back as {} bytes, {} recorded",
                        counted.n, node.size
                    ));
                }
                let rest = (node.size as usize).next_multiple_of(tar::BLOCK) - node.size as usize;
                file.write_all(&vec![0u8; rest])
                    .await
                    .map_err(|e| e.to_string())?;
            }
            file.write_all(&tar::end())
                .await
                .map_err(|e| e.to_string())?;
            let (file, _) = rewound(file).await?;
            site.docker
                .put_archive(image, volume, &volume_path(volume), stream(file))
                .await
                .map_err(|e| format!("{db} on the site: {}", causes(&e)))?;
            let _ = tokio::fs::remove_file(&path).await;
            back.push(db);
        }
        Ok(back)
    }

    /// Recreates `db` on the site's PostgreSQL from its latest dump: the app's role
    /// with the password the app is given, its database as provisioning makes it,
    /// the extensions it declares, then the dump restored as that role.
    ///
    pub async fn database_to_site(
        &self,
        app: &str,
        db: &Database<'_>,
        role_password: &str,
        connection_limit: Option<u32>,
        site: &Site<'_>,
        server: &Server<'_>,
    ) -> Result<Sent, String> {
        if db.engine != DbEngine::Postgres {
            return Err(format!("{}: the site runs PostgreSQL only", db.name));
        }
        let source = self.find_dump(app, db.engine, db.name, None, None).await?;
        let password = restic_password(self.state, self.vault)
            .await
            .map_err(|e| e.to_string())?;
        let env = self.env(&source.destination).await?;
        let repo = self.repository(&source, &password, env);
        let id = source.snapshot.short_id();
        let [path] = source.snapshot.paths.as_slice() else {
            return Err(format!("snapshot {id} holds more than one dump"));
        };
        let mut dump = Vec::new();
        repo.dump(&source.snapshot.id, path, &mut dump)
            .await
            .map_err(|e| format!("the dump could not be read back: {e}"))?;
        if !dump.starts_with(b"PGDMP") {
            return Err(format!("snapshot {id} is not a PostgreSQL dump"));
        }

        let e = |e: hlb_platform::Error| e.to_string();
        let mut script = vec![hlb_platform::role_statement(db.role, role_password).map_err(e)?];
        if let Some(n) = connection_limit {
            script.push(hlb_platform::connection_limit_statement(db.role, n).map_err(e)?);
        }
        script.extend(hlb_platform::database_statements(db.name, db.role).map_err(e)?);
        let extensions = db
            .extensions
            .iter()
            .map(|x| hlb_platform::extension_statement(x).map(|s| format!("{s};\n")))
            .collect::<Result<String, _>>()
            .map_err(e)?;

        let dumper = hlb_backup::PgDumper::new(
            hlb_backup::PgContainerRunner::new(server.image)
                .network(site.network)
                .docker_socket(site.socket),
        );
        let at = |database: &str| hlb_backup::PgTarget {
            host: "postgres".into(),
            port: 5432,
            database: database.to_string(),
            user: "postgres".into(),
            password: server.admin_password.to_string(),
        };
        let err = |e: hlb_backup::Error| e.to_string();
        dumper
            .psql_script(&at("postgres"), &format!("{};\n", script.join(";\n")))
            .await
            .map_err(err)?;
        if !extensions.is_empty() {
            dumper
                .psql_script(&at(db.name), &extensions)
                .await
                .map_err(err)?;
        }
        dumper
            .restore_as(&at(db.name), &dump, db.role, db.extensions)
            .await
            .map_err(err)?;
        Ok(Sent {
            snapshot: source.snapshot.id.clone(),
            bytes: dump.len() as u64,
            sqlite: Vec::new(),
        })
    }
}

impl Restore<'_> {
    /// `volume` as the site holds it, archived to `app`'s first bulky destination and
    /// recorded: the source a [`Restore::in_place`] then puts back over the house's.
    ///
    /// Read from the site's daemon into `scratch`, unpacked into a Docker volume of this
    /// machine's, backed up from there at the volume's own path — the path every
    /// restore looks under. ⚠️ The site's services writing it must be stopped.
    pub async fn volume_from_site(
        &self,
        app: &str,
        volume: &str,
        site: &Site<'_>,
        image: &str,
        scratch: &Path,
    ) -> Result<Brought, String> {
        let dest = crate::effective_destinations(
            self.state,
            app,
            hlb_backup::Class::Bulky,
            self.fallback_repo,
        )
        .await
        .map_err(|e| e.to_string())?
        .into_iter()
        .next()
        .ok_or_else(|| format!("no destination accepts {app}'s volumes"))?;
        let path = scratch.join(format!("{volume}.home.tar"));
        let mut file = scratch_file(&path).await?;
        let bytes = site
            .docker
            .get_archive(image, volume, &volume_path(volume), &mut file)
            .await
            .map_err(|e| format!("{volume} on the site: {}", causes(&e)))?;
        let (file, _) = rewound(file).await?;

        // Its entries are `<volume>/…`, the root first: unpacked under `/<volume>`, the
        // volume's own owner and mode come with it.
        let here = hlb_orchestrator::SwarmOrchestrator::connect()
            .await
            .map_err(|e| format!("this machine's Docker: {e}"))?;
        let staging = format!("hlb-home-{volume}");
        here.remove_volume(&staging).await.ok();
        let staged = here
            .put_archive(
                hlb_backup::images::RESTIC,
                &staging,
                &format!("/{volume}"),
                stream(file),
            )
            .await
            .map_err(|e| format!("{volume} unpacked here: {}", causes(&e)));
        let _ = tokio::fs::remove_file(&path).await;
        let taken = match staged {
            Ok(()) => self.back_up_staged(app, volume, &staging, &dest).await,
            Err(e) => Err(e),
        };
        here.remove_volume(&staging).await.ok();
        let id = taken?;
        let source = self.find(app, volume, Some(&dest.name), Some(&id)).await?;
        Ok(Brought { source, bytes })
    }

    async fn back_up_staged(
        &self,
        app: &str,
        volume: &str,
        staging: &str,
        dest: &hlb_backup::Destination,
    ) -> Result<String, String> {
        let password = restic_password(self.state, self.vault)
            .await
            .map_err(|e| e.to_string())?;
        let env = self.env(dest).await?;
        let (runner, location) = dest.runner(Some(self.network));
        let repo = hlb_backup::Repository::new(
            runner.mount(staging, volume_path(volume)),
            location,
            password,
        )
        .extra_env(env);
        // Copied with what writes it stopped: a restore does not warn of a live copy.
        crate::snapshot(
            &repo,
            (self.state, &dest.name),
            app,
            &[volume_path(volume)],
            &[FROM_SITE, crate::STOPPED_TAG],
        )
        .await
    }

    /// `db` dumped on the site's PostgreSQL, archived to `app`'s first critical
    /// destination and recorded: the source a [`Restore::database_in_place`] then puts
    /// back over the house's. ⚠️ The site's app must be stopped.
    pub async fn database_from_site(
        &self,
        app: &str,
        db: &Database<'_>,
        site: &Site<'_>,
        reader: &Reader<'_>,
    ) -> Result<Brought, String> {
        use hlb_backup::pgdump::scheduled;
        if db.engine != DbEngine::Postgres {
            return Err(format!("{}: the site runs PostgreSQL only", db.name));
        }
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
        let dumper = hlb_backup::PgDumper::new(
            hlb_backup::PgContainerRunner::new(reader.image)
                .network(site.network)
                .docker_socket(site.socket),
        );
        let target = hlb_backup::PgTarget {
            host: reader.host.into(),
            port: 5432,
            database: db.name.to_string(),
            user: reader.user.into(),
            password: reader.password.to_string(),
        };
        let dump = scheduled::produce(&dumper, app, &target, crate::now())
            .await
            .map_err(|e| format!("{} on the site: {e}", db.name))?;
        self.archived(app, db, &dest, &dump, FROM_SITE).await
    }

    /// `dump` of `db` archived to `dest` tagged `kind`, recorded, and found again as
    /// the source a restore reads.
    pub(crate) async fn archived(
        &self,
        app: &str,
        db: &Database<'_>,
        dest: &hlb_backup::Destination,
        dump: &hlb_backup::pgdump::scheduled::Dump,
        kind: &str,
    ) -> Result<Brought, String> {
        use hlb_backup::pgdump::scheduled;
        let password = restic_password(self.state, self.vault)
            .await
            .map_err(|e| e.to_string())?;
        let creds = crate::credentials(self.state, self.vault, dest)
            .await
            .map_err(|e| e.to_string())?;
        let id = scheduled::archive_as(
            dest,
            creds.as_deref(),
            Some(self.network),
            &password,
            dump,
            kind,
        )
        .await
        .map_err(|e| format!("{} archived: {e}", db.name))?;
        self.state
            .record_snapshot(app, &dest.name, &id)
            .await
            .map_err(|e| format!("snapshot {id} taken, but not recorded: {e}"))?;
        let source = self
            .find_dump(app, db.engine, db.name, Some(&dest.name), Some(&id))
            .await?;
        Ok(Brought {
            source,
            bytes: dump.bytes.len() as u64,
        })
    }
}

/// What the site wrote, now a snapshot of the house's.
#[derive(Debug, Clone)]
pub struct Brought {
    pub source: Source,
    /// Bytes read off the site.
    pub bytes: u64,
}

/// A writer counting what goes through it.
struct Counted<'a, W> {
    inner: &'a mut W,
    n: u64,
}

impl<W: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for Counted<'_, W> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = &mut *self;
        let r = std::pin::Pin::new(&mut *this.inner).poll_write(cx, buf);
        if let std::task::Poll::Ready(Ok(n)) = r {
            this.n += n as u64;
        }
        r
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut *self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut *self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_archive_leaves_a_tenth_of_the_site_s_disk() {
        let gib = 1u64 << 30;
        assert!(fits(gib, 10 * gib, 20 * gib).is_ok());
        let refused = fits(9 * gib, 10 * gib, 20 * gib).expect_err("past the floor");
        assert!(refused.contains("a tenth"), "{refused}");
        assert!(
            fits(11 * gib, 10 * gib, 20 * gib).is_err(),
            "more than is free"
        );
    }

    #[test]
    fn the_standby_signal_is_postgres_s_file_and_leaves_the_directory_alone() {
        use std::io::Write as _;
        let archive = standby_signal("/donnees/postgres-vital-data").expect("archive");
        let mut tar = std::process::Command::new("tar")
            .args(["--numeric-owner", "-tvf", "-"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("tar");
        tar.stdin
            .take()
            .expect("stdin")
            .write_all(&archive)
            .expect("written");
        let out = tar.wait_with_output().expect("listed");
        assert!(out.status.success(), "{out:?}");
        let listed = String::from_utf8_lossy(&out.stdout);
        let lines: Vec<&str> = listed.lines().collect();
        assert_eq!(lines.len(), 1, "one entry, no directory's: {listed}");
        assert!(lines[0].starts_with("-rw-------"), "{listed}");
        assert!(lines[0].contains("999/999"), "{listed}");
        assert!(
            lines[0].ends_with("donnees/postgres-vital-data/standby.signal"),
            "{listed}"
        );
    }
}
