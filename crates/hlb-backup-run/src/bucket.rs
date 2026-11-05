//! A bucket backed up as one archive, and put back from it.
//!
//! Its objects are read through the app's own key, in the order the bucket lists them,
//! and streamed into restic as a tar (`hlb_backup::tarball`): no copy of the bucket on
//! any disk, and an unchanged bucket adds nothing to the repository.
//!
//! 🔴 Garage's blocks are protected by its replication, and a house with one storage
//! node has none: what Fluxer keeps there — attachments, avatars, emoji — exists once
//! until the pass reads it.

use std::collections::HashSet;

use hlb_backup::restic::Runner;
use hlb_backup::tarball::{self, Entry, Reader, Writer};
use hlb_backup::Repository;
use hlb_objstore::s3;
use hlb_secrets::Vault;
use hlb_state::State;
use tokio::io::{AsyncWrite, AsyncWriteExt};

/// The archive's name in its snapshot. ⚠️ A stored value: every snapshot of a bucket
/// holds its archive under it, and a restore looks for it there.
pub fn archive_name(bucket: &str) -> String {
    format!("bucket-{bucket}.tar")
}

/// The archive's path in its snapshot, as restic lists it.
pub fn archive_path(bucket: &str) -> String {
    format!("/{}", archive_name(bucket))
}

/// Garage's S3 API as the overlay names it: where the controller, on the overlay, reads.
pub use hlb_objstore::S3_URL;

/// The tag every bucket snapshot carries. ⚠️ A stored value.
pub const BUCKET_TAG: &str = "kind:bucket";

/// An app's own S3 key: its id and its secret. Read and write, never owner.
pub struct S3Key {
    id: String,
    secret: String,
}

/// `app`'s S3 key, out of the vault.
pub async fn key(state: &State, vault: &Vault, app: &str) -> Result<S3Key, String> {
    let (id_name, secret_name) = hlb_types::capability::s3_key_secrets(app);
    let read = |name: String| async move {
        match state.secret(&name).await.map_err(|e| e.to_string())? {
            Some(ct) => vault.decrypt(&ct).map(Some).map_err(|e| e.to_string()),
            None => Ok(None),
        }
    };
    let (Some(id), Some(secret)) = (read(id_name).await?, read(secret_name).await?) else {
        return Err(format!(
            "{app}'s S3 key is not in the vault: its buckets were never provisioned here"
        ));
    };
    Ok(S3Key { id, secret })
}

/// `bucket`, reached with `key` at `endpoint`.
pub async fn at(endpoint: &str, bucket: &str, key: &S3Key) -> Result<s3::Bucket, String> {
    let at = s3::Location {
        endpoint: endpoint.to_string(),
        bucket: bucket.to_string(),
        prefix: String::new(),
    };
    s3::Bucket::connect(at, &key.id, &key.secret)
        .await
        .map_err(|e| e.to_string())
}

/// `bucket`, reached with `app`'s own key at `endpoint`.
pub async fn open(
    state: &State,
    vault: &Vault,
    endpoint: &str,
    app: &str,
    bucket: &str,
) -> Result<s3::Bucket, String> {
    at(endpoint, bucket, &key(state, vault, app).await?).await
}

/// Every object of `b` into `out`, as an archive ending with its trailer. The count.
///
/// An error leaves the archive unfinished, never closed: the pipe then breaks rather
/// than ending, and restic saves nothing of it.
pub async fn write_archive<W: AsyncWrite + Unpin>(b: &s3::Bucket, out: W) -> Result<u64, String> {
    let objects = b.list().await.map_err(|e| e.to_string())?;
    let mut w = Writer::new(out);
    for o in &objects {
        let mut d = b.open(&o.key).await.map_err(|e| e.to_string())?;
        w.start(&Entry {
            path: o.key.clone(),
            size: d.size,
            mtime: o.modified,
            headers: d.headers.clone(),
        })
        .await
        .map_err(|e| format!("{}: {e}", o.key))?;
        while let Some(chunk) = d.chunk().await.map_err(|e| e.to_string())? {
            w.write(&chunk)
                .await
                .map_err(|e| format!("{}: {e}", o.key))?;
        }
        w.end_entry().await.map_err(|e| format!("{}: {e}", o.key))?;
    }
    w.finish().await.map_err(|e| e.to_string())
}

/// Backs `bucket` up to `repo` with `tags`. The snapshot's id.
pub async fn back_up<R: Runner>(
    repo: &Repository<R>,
    b: &s3::Bucket,
    bucket: &str,
    tags: &[&str],
) -> Result<String, String> {
    let (sink, mut source) = tarball::pipe();
    let name = archive_name(bucket);
    let (written, saved) = tokio::join!(
        write_archive(b, sink),
        repo.backup_stdin(&name, tags, &mut source)
    );
    match (written, saved) {
        (Ok(_), Ok(id)) => Ok(id),
        // The read failed and restic still saved something: what it saved is part of a
        // bucket, and goes.
        (Err(e), Ok(id)) => {
            let _ = repo.forget_snapshot(&id).await;
            Err(format!("{bucket}: {e}"))
        }
        (Err(e), Err(_)) => Err(format!("{bucket}: {e}")),
        (Ok(_), Err(e)) => Err(format!("{bucket}: {e}")),
    }
}

/// What a restore put back.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Restored {
    pub written: u64,
    /// Written since the snapshot, and deleted: a restore is exact, as a volume's is.
    pub deleted: u64,
}

/// Puts `bucket` back as `snapshot` holds it.
///
/// ⚠️ The app must be stopped. Objects are rewritten as the archive is read, and the
/// ones it does not hold are deleted only once its trailer said it is whole: an archive
/// that breaks halfway leaves the bucket partly restored and nothing deleted — undone
/// by restoring the copy taken before.
pub async fn restore<R: Runner>(
    repo: &Repository<R>,
    snapshot: &str,
    b: &s3::Bucket,
    bucket: &str,
) -> Result<Restored, String> {
    let (mut w, r) = tokio::io::duplex(1 << 20);
    let path = archive_path(bucket);
    let dumping = async {
        let d = repo.dump(snapshot, &path, &mut w).await;
        let _ = w.shutdown().await;
        d.map_err(|e| e.to_string())
    };
    let (dumped, written) = tokio::join!(dumping, write_back(Reader::new(r), b));
    dumped?;
    let (written, kept) = written?;

    let mut deleted = 0;
    for o in b.list().await.map_err(|e| e.to_string())? {
        if !kept.contains(&o.key) {
            let r = b.delete(&o.key, None).await.map_err(|e| e.to_string())?;
            if !(200..300).contains(&r.status) {
                return Err(format!("{}: deleting it answered {}", o.key, r.status));
            }
            deleted += 1;
        }
    }
    Ok(Restored { written, deleted })
}

/// What an archive held when read to its end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Read {
    pub objects: u64,
    pub bytes: u64,
}

/// Reads `bucket`'s archive to its end and writes it nowhere: its trailer is what says it
/// is whole, and restoring it would need the app stopped.
pub async fn read<R: Runner>(
    repo: &Repository<R>,
    snapshot: &str,
    bucket: &str,
) -> Result<Read, String> {
    let (mut w, r) = tokio::io::duplex(1 << 20);
    let path = archive_path(bucket);
    let dumping = async {
        let d = repo.dump(snapshot, &path, &mut w).await;
        let _ = w.shutdown().await;
        d.map_err(|e| e.to_string())
    };
    let (dumped, read) = tokio::join!(dumping, read_archive(Reader::new(r)));
    // The reader's complaint first: a dump stopped by a closed pipe says only that.
    let read = read?;
    dumped?;
    Ok(read)
}

async fn read_archive<R: tokio::io::AsyncRead + Unpin>(
    mut archive: Reader<R>,
) -> Result<Read, String> {
    let mut seen = Read {
        objects: 0,
        bytes: 0,
    };
    let mut buf = vec![0u8; 256 * 1024];
    while archive.next().await.map_err(|e| e.to_string())?.is_some() {
        seen.objects += 1;
        loop {
            match archive.read(&mut buf).await.map_err(|e| e.to_string())? {
                0 => break,
                n => seen.bytes += n as u64,
            }
        }
    }
    archive.drain().await.map_err(|e| e.to_string())?;
    Ok(seen)
}

/// Every object of the archive written into `b`. Their count, and their keys.
async fn write_back<R: tokio::io::AsyncRead + Unpin>(
    mut archive: Reader<R>,
    b: &s3::Bucket,
) -> Result<(u64, HashSet<String>), String> {
    let mut keys = HashSet::new();
    while let Some(e) = archive.next().await.map_err(|e| e.to_string())? {
        let (tx, rx) = tokio::sync::mpsc::channel::<std::io::Result<Vec<u8>>>(4);
        let body = reqwest_body(rx);
        let pump = async {
            // Owned here: once the object is read, the body it feeds ends with it.
            let tx = tx;
            let mut buf = vec![0u8; 256 * 1024];
            loop {
                match archive.read(&mut buf).await {
                    Ok(0) => return Ok(()),
                    Ok(n) => {
                        if tx.send(Ok(buf[..n].to_vec())).await.is_err() {
                            return Err("the write stopped taking the object".to_string());
                        }
                    }
                    Err(err) => {
                        let _ = tx.send(Err(std::io::Error::other(err.to_string()))).await;
                        return Err(err.to_string());
                    }
                }
            }
        };
        let (pumped, put) = tokio::join!(pump, b.put_stream(&e.path, e.size, &e.headers, body));
        pumped.map_err(|err| format!("{}: {err}", e.path))?;
        put.map_err(|err| format!("{}: {err}", e.path))?;
        keys.insert(e.path);
    }
    archive.drain().await.map_err(|e| e.to_string())?;
    Ok((keys.len() as u64, keys))
}

fn reqwest_body(
    rx: tokio::sync::mpsc::Receiver<std::io::Result<Vec<u8>>>,
) -> hlb_objstore::reqwest::Body {
    let stream = futures::stream::unfold(rx, |mut rx| async move {
        rx.recv().await.map(|item| (item, rx))
    });
    hlb_objstore::reqwest::Body::wrap_stream(stream)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn archive(objects: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut w = tarball::Writer::new(&mut out);
        for (path, body) in objects {
            w.start(&Entry {
                path: path.to_string(),
                size: body.len() as u64,
                mtime: 0,
                headers: Vec::new(),
            })
            .await
            .expect("start");
            w.write(body).await.expect("write");
            w.end_entry().await.expect("end");
        }
        w.finish().await.expect("finish");
        out
    }

    // `restic dump` writes the tar's end after the trailer the reader stops at. Reader
    // gone, the dump failed on a closed pipe, and a whole bucket read as a failed one.
    #[tokio::test]
    async fn the_end_of_the_archive_after_its_trailer_is_read_too() {
        let mut bytes = archive(&[("a", b"hello")]).await;
        bytes.extend(std::iter::repeat_n(0u8, 20 * 1024));
        let (mut w, r) = tokio::io::duplex(64);
        let writing = async {
            let wrote = tokio::io::AsyncWriteExt::write_all(&mut w, &bytes).await;
            let _ = w.shutdown().await;
            wrote
        };
        let (wrote, read) = tokio::join!(writing, read_archive(Reader::new(r)));
        assert_eq!(read.expect("whole").objects, 1);
        wrote.expect("the writer must reach its end");
    }

    #[tokio::test]
    async fn an_archive_is_read_to_its_end_and_one_cut_short_fails() {
        let bytes = archive(&[("a", b"hello"), ("b/c", b"world!")]).await;
        let read = read_archive(Reader::new(bytes.as_slice()))
            .await
            .expect("whole");
        assert_eq!(
            read,
            Read {
                objects: 2,
                bytes: 11
            }
        );

        // 🔴 A truncated archive is still a valid tar: only its trailer says otherwise.
        let cut = &bytes[..1024];
        assert!(read_archive(Reader::new(cut)).await.is_err());
        assert!(read_archive(Reader::new(&[][..])).await.is_err());
    }

    #[test]
    fn a_buckets_archive_has_a_path_of_its_own() {
        // Distinct from every volume's (`/donnees/…`): a restore picking by path can
        // never take one for the other.
        assert_eq!(archive_path("fluxer"), "/bucket-fluxer.tar");
        assert!(!archive_path("x").starts_with(&crate::volume_path("")));
    }
}
