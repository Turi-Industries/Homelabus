//! A bucket as one stream: a POSIX tar (pax), written object after object as they are
//! read, and read back the same way — never a copy of the bucket on a disk.
//!
//! restic chunks the stream by its content: an archive whose objects come in the same
//! order deduplicates against the last one (measured on 1 GB: 25 MiB of new objects
//! among the old ones added 31 MiB to the repository, an unchanged bucket nothing).
//!
//! 🔴 **A truncated archive is still a valid tar.** Cut short by a read that failed
//! halfway, it would restore a bucket missing every object after the cut, without an
//! error — the trap of a MariaDB dump without its last line. So an archive ENDS with
//! [`TRAILER`], which counts what came before it, and the reader refuses one without it,
//! or whose count does not match.

use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};

use crate::{Error, Result};

/// A pipe from the archive being written to restic reading it, whose end counts only
/// when the writer CLOSED it: through a plain pipe, a writer that failed and was
/// dropped reads as a clean end — and restic would save the half it got.
pub fn pipe() -> (Sink, Source) {
    let (w, r) = tokio::io::duplex(1 << 20);
    let closed = Arc::new(AtomicBool::new(false));
    (
        Sink {
            w,
            closed: closed.clone(),
        },
        Source { r, closed },
    )
}

/// The writing end; [`Writer::finish`] closes it.
pub struct Sink {
    w: DuplexStream,
    closed: Arc<AtomicBool>,
}

/// The reading end: an end the writer did not close is an error.
pub struct Source {
    r: DuplexStream,
    closed: Arc<AtomicBool>,
}

impl AsyncWrite for Sink {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        b: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().w).poll_write(cx, b)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().w).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let me = self.get_mut();
        // Before the end reaches the reader, or it would read an end not yet said.
        me.closed.store(true, Ordering::SeqCst);
        Pin::new(&mut me.w).poll_shutdown(cx)
    }
}

impl AsyncRead for Source {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let me = self.get_mut();
        let before = buf.filled().len();
        match Pin::new(&mut me.r).poll_read(cx, buf) {
            Poll::Ready(Ok(()))
                if buf.filled().len() == before && !me.closed.load(Ordering::SeqCst) =>
            {
                Poll::Ready(Err(std::io::Error::other(
                    "the archive's writer stopped before it finished it",
                )))
            }
            other => other,
        }
    }
}

const BLOCK: usize = 512;

/// The last entry of a whole archive; its content is the number of objects before it.
/// ⚠️ A stored value: every bucket archive ends with it.
pub const TRAILER: &str = ".homelabus-complete";

/// The pax records an object's headers travel in, by their lower-case name.
/// ⚠️ A stored value too.
const HEADER: &str = "HOMELABUS.header.";

/// The ustar size field holds eleven octal digits: past that, the size goes in pax.
const USTAR_MAX: u64 = 0o77_777_777_777;

/// One object of an archive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Its key, whole.
    pub path: String,
    pub size: u64,
    /// Seconds since the epoch: when it was last written.
    pub mtime: i64,
    /// What the store said of it — `content-type`, `cache-control`… — lower-case names.
    pub headers: Vec<(String, String)>,
}

/// A pax record: `"<length> <key>=<value>\n"`, where the length counts itself.
fn record(key: &str, value: &str) -> Vec<u8> {
    let rest = format!(" {key}={value}\n");
    let mut n = rest.len() + 1;
    while n.to_string().len() + rest.len() != n {
        n += 1;
    }
    format!("{n}{rest}").into_bytes()
}

fn octal(field: &mut [u8], value: u64) {
    let digits = field.len() - 1;
    let s = format!("{value:0digits$o}");
    let s = &s[s.len().saturating_sub(digits)..];
    field[..digits].copy_from_slice(s.as_bytes());
    field[digits] = 0;
}

/// A ustar header block: `name` cut to what the field holds — the whole name is in the
/// pax record before it.
fn ustar(name: &str, size: u64, mtime: i64, kind: u8) -> [u8; BLOCK] {
    let mut h = [0u8; BLOCK];
    let short: String = name
        .chars()
        .filter(char::is_ascii)
        .take(99)
        .collect::<String>();
    h[..short.len()].copy_from_slice(short.as_bytes());
    octal(&mut h[100..108], 0o644);
    octal(&mut h[108..116], 0);
    octal(&mut h[116..124], 0);
    octal(&mut h[124..136], size.min(USTAR_MAX));
    octal(&mut h[136..148], mtime.max(0) as u64);
    h[156] = kind;
    h[257..263].copy_from_slice(b"ustar\0");
    h[263..265].copy_from_slice(b"00");
    // The checksum is computed with its own field read as spaces.
    h[148..156].copy_from_slice(b"        ");
    let sum: u32 = h.iter().map(|b| u32::from(*b)).sum();
    let s = format!("{sum:06o}\0 ");
    h[148..156].copy_from_slice(s.as_bytes());
    h
}

fn padding(size: u64) -> usize {
    (BLOCK - (size % BLOCK as u64) as usize) % BLOCK
}

/// Writes an archive into `W`, object by object.
pub struct Writer<W> {
    out: W,
    count: u64,
    /// Bytes still owed to the entry being written.
    owed: u64,
    size: u64,
}

impl<W: AsyncWrite + Unpin> Writer<W> {
    pub fn new(out: W) -> Self {
        Self {
            out,
            count: 0,
            owed: 0,
            size: 0,
        }
    }

    /// Opens an entry; its `size` bytes follow through [`Writer::write`].
    pub async fn start(&mut self, e: &Entry) -> Result<()> {
        if self.owed != 0 {
            return Err(Error::Unexpected(format!(
                "archive: {} bytes still owed to the previous object",
                self.owed
            )));
        }
        if e.path == TRAILER {
            return Err(Error::Unexpected(format!(
                "archive: an object named {TRAILER} would read as the archive's end"
            )));
        }
        let mut pax = record("path", &e.path);
        if e.size > USTAR_MAX {
            pax.extend(record("size", &e.size.to_string()));
        }
        for (k, v) in &e.headers {
            pax.extend(record(&format!("{HEADER}{k}"), v));
        }
        self.out
            .write_all(&ustar("PaxHeader", pax.len() as u64, e.mtime, b'x'))
            .await?;
        self.out.write_all(&pax).await?;
        self.out
            .write_all(&[0u8; BLOCK][..padding(pax.len() as u64)])
            .await?;
        self.out
            .write_all(&ustar(&e.path, e.size, e.mtime, b'0'))
            .await?;
        self.owed = e.size;
        self.size = e.size;
        Ok(())
    }

    /// Part of the open entry's content. More than it said it holds is refused: the
    /// object changed under the read, and the archive would be unreadable after it.
    pub async fn write(&mut self, chunk: &[u8]) -> Result<()> {
        if chunk.len() as u64 > self.owed {
            return Err(Error::Unexpected(
                "archive: the object is longer than its size — it changed while read".into(),
            ));
        }
        self.out.write_all(chunk).await?;
        self.owed -= chunk.len() as u64;
        Ok(())
    }

    /// Closes the open entry, every byte of it written.
    pub async fn end_entry(&mut self) -> Result<()> {
        if self.owed != 0 {
            return Err(Error::Unexpected(format!(
                "archive: the object ended {} bytes short of its size",
                self.owed
            )));
        }
        self.out
            .write_all(&[0u8; BLOCK][..padding(self.size)])
            .await?;
        self.count += 1;
        Ok(())
    }

    /// The trailer, then the end of the archive. Never called on a failed read: an
    /// archive without its trailer is refused, which is the point.
    pub async fn finish(mut self) -> Result<u64> {
        let count = self.count.to_string();
        self.out
            .write_all(&ustar(TRAILER, count.len() as u64, 0, b'0'))
            .await?;
        self.out.write_all(count.as_bytes()).await?;
        self.out
            .write_all(&[0u8; BLOCK][..padding(count.len() as u64)])
            .await?;
        self.out.write_all(&[0u8; 2 * BLOCK]).await?;
        self.out.flush().await?;
        self.out.shutdown().await?;
        Ok(self.count)
    }
}

/// Reads an archive out of `R`, object by object.
pub struct Reader<R> {
    input: R,
    /// Content bytes of the current entry not read yet, then its padding.
    left: u64,
    pad: usize,
    count: u64,
}

impl<R: AsyncRead + Unpin> Reader<R> {
    pub fn new(input: R) -> Self {
        Self {
            input,
            left: 0,
            pad: 0,
            count: 0,
        }
    }

    /// Reads what follows the trailer, once [`Self::next`] has said the archive is whole.
    ///
    /// 🔴 A tar ends with blocks of zeros after the last entry. A reader gone at the trailer
    /// closes its pipe on the writer still sending them: `restic dump` then fails on a
    /// bucket that is whole, depending on how far it had got.
    pub async fn drain(&mut self) -> Result<()> {
        tokio::io::copy(&mut self.input, &mut tokio::io::sink())
            .await
            .map_err(|e| Error::Unexpected(format!("reading the archive's end: {e}")))?;
        Ok(())
    }

    async fn block(&mut self) -> Result<[u8; BLOCK]> {
        let mut b = [0u8; BLOCK];
        match self.input.read_exact(&mut b).await {
            Ok(_) => Ok(b),
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Err(incomplete()),
            Err(e) => Err(e.into()),
        }
    }

    async fn skip(&mut self, mut n: u64) -> Result<()> {
        let mut buf = [0u8; 8192];
        while n > 0 {
            let want = n.min(buf.len() as u64) as usize;
            let got = self.input.read(&mut buf[..want]).await?;
            if got == 0 {
                return Err(incomplete());
            }
            n -= got as u64;
        }
        Ok(())
    }

    /// The next object, its content read through [`Reader::read`]; `None` at the
    /// trailer, once its count agrees with the objects read.
    pub async fn next(&mut self) -> Result<Option<Entry>> {
        // What the caller left of the previous object is skipped, not misread.
        let rest = self.left + self.pad as u64;
        self.skip(rest).await?;
        self.left = 0;
        self.pad = 0;

        let mut pax: Vec<(String, String)> = Vec::new();
        loop {
            let h = self.block().await?;
            if h.iter().all(|b| *b == 0) {
                return Err(incomplete());
            }
            let size = parse_octal(&h[124..136])?;
            let mtime = parse_octal(&h[136..148])? as i64;
            match h[156] {
                b'x' => {
                    let mut body = vec![0u8; size as usize];
                    self.input
                        .read_exact(&mut body)
                        .await
                        .map_err(|_| incomplete())?;
                    self.skip(padding(size) as u64).await?;
                    pax = parse_pax(&body)?;
                }
                b'0' | 0 => {
                    let name = String::from_utf8_lossy(&h[..100])
                        .trim_end_matches('\0')
                        .to_string();
                    let path = pax
                        .iter()
                        .find(|(k, _)| k == "path")
                        .map_or(name, |(_, v)| v.clone());
                    let size = pax
                        .iter()
                        .find(|(k, _)| k == "size")
                        .and_then(|(_, v)| v.parse().ok())
                        .unwrap_or(size);
                    if path == TRAILER {
                        let mut body = vec![0u8; size.min(32) as usize];
                        self.input
                            .read_exact(&mut body)
                            .await
                            .map_err(|_| incomplete())?;
                        let said: u64 = String::from_utf8_lossy(&body)
                            .trim()
                            .parse()
                            .map_err(|_| incomplete())?;
                        if said != self.count {
                            return Err(Error::Unexpected(format!(
                                "archive: its trailer counts {said} objects, {} were read",
                                self.count
                            )));
                        }
                        return Ok(None);
                    }
                    let headers = pax
                        .into_iter()
                        .filter_map(|(k, v)| k.strip_prefix(HEADER).map(|h| (h.to_string(), v)))
                        .collect();
                    self.left = size;
                    self.pad = padding(size);
                    self.count += 1;
                    return Ok(Some(Entry {
                        path,
                        size,
                        mtime,
                        headers,
                    }));
                }
                other => {
                    return Err(Error::Unexpected(format!(
                        "archive: an entry of type {:?}, which no bucket archive holds",
                        other as char
                    )))
                }
            }
        }
    }

    /// Part of the current object's content; `0` once it is all read.
    pub async fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if self.left == 0 {
            return Ok(0);
        }
        let want = self.left.min(buf.len() as u64) as usize;
        let got = self.input.read(&mut buf[..want]).await?;
        if got == 0 {
            return Err(incomplete());
        }
        self.left -= got as u64;
        Ok(got)
    }
}

fn incomplete() -> Error {
    Error::Unexpected(format!(
        "archive: it ends before its {TRAILER} — a bucket read that failed halfway, \
         which would restore without the objects after the cut"
    ))
}

fn parse_octal(field: &[u8]) -> Result<u64> {
    let s: String = field
        .iter()
        .take_while(|b| **b != 0 && **b != b' ')
        .map(|b| *b as char)
        .collect();
    if s.is_empty() {
        return Ok(0);
    }
    u64::from_str_radix(s.trim(), 8)
        .map_err(|_| Error::Unexpected(format!("archive: unreadable number {s:?}")))
}

fn parse_pax(body: &[u8]) -> Result<Vec<(String, String)>> {
    let mut out = Vec::new();
    let mut rest = body;
    while !rest.is_empty() && rest[0] != 0 {
        let space = rest
            .iter()
            .position(|b| *b == b' ')
            .ok_or_else(|| Error::Unexpected("archive: unreadable pax record".into()))?;
        let n: usize = std::str::from_utf8(&rest[..space])
            .ok()
            .and_then(|s| s.parse().ok())
            .filter(|n| *n > space && *n <= rest.len())
            .ok_or_else(|| Error::Unexpected("archive: unreadable pax length".into()))?;
        let rec = std::str::from_utf8(&rest[space + 1..n - 1])
            .map_err(|_| Error::Unexpected("archive: a pax record is not UTF-8".into()))?;
        if let Some((k, v)) = rec.split_once('=') {
            out.push((k.to_string(), v.to_string()));
        }
        rest = &rest[n..];
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(path: &str, size: usize) -> Entry {
        Entry {
            path: path.into(),
            size: size as u64,
            mtime: 1_793_000_000,
            headers: vec![("content-type".into(), "image/png".into())],
        }
    }

    async fn archive(objects: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut w = Writer::new(&mut out);
        for (path, body) in objects {
            w.start(&entry(path, body.len())).await.expect("start");
            for chunk in body.chunks(700) {
                w.write(chunk).await.expect("write");
            }
            w.end_entry().await.expect("end");
        }
        assert_eq!(w.finish().await.expect("finish"), objects.len() as u64);
        out
    }

    #[tokio::test]
    async fn an_archive_reads_back_whole_its_keys_and_headers_intact() {
        let long = format!("attachments/{}/é tête.png", "x".repeat(150));
        let objects = [
            ("emoji/1.webp", vec![7u8; 1500]),
            (long.as_str(), (0..=255u8).cycle().take(4096).collect()),
            ("empty", Vec::new()),
        ];
        let bytes = archive(&objects).await;
        assert_eq!(bytes.len() % BLOCK, 0);

        let mut r = Reader::new(bytes.as_slice());
        for (path, body) in &objects {
            let e = r.next().await.expect("read").expect("an object");
            assert_eq!(e.path, *path);
            assert_eq!(
                e.headers,
                [("content-type".to_string(), "image/png".to_string())]
            );
            let mut got = Vec::new();
            let mut buf = [0u8; 300];
            loop {
                let n = r.read(&mut buf).await.expect("body");
                if n == 0 {
                    break;
                }
                got.extend_from_slice(&buf[..n]);
            }
            assert_eq!(&got, body);
        }
        assert_eq!(r.next().await.expect("the trailer"), None);
    }

    #[tokio::test]
    async fn the_system_tar_reads_what_is_written() {
        // Not a format of our own: GNU tar lists it, the whole key included.
        let long = format!("a/{}", "k".repeat(120));
        let bytes = archive(&[("one", b"1".to_vec()), (long.as_str(), b"22".to_vec())]).await;
        let dir = tempfile::tempdir().expect("tmp");
        let file = dir.path().join("b.tar");
        std::fs::write(&file, &bytes).expect("written");
        let Ok(out) = std::process::Command::new("tar")
            .arg("-tf")
            .arg(&file)
            .output()
        else {
            return; // no tar on this machine
        };
        let listed = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(
            listed.lines().collect::<Vec<_>>(),
            ["one", long.as_str(), TRAILER]
        );
    }

    #[tokio::test]
    async fn an_archive_cut_short_is_refused_wherever_it_is_cut() {
        let bytes = archive(&[("a", vec![1; 2000]), ("b", vec![2; 10])]).await;
        // Cut anywhere before the trailer's end — even on a block boundary, where a
        // tar reader would see a clean end.
        for cut in [BLOCK, 3 * BLOCK, 5 * BLOCK, bytes.len() - 3 * BLOCK] {
            let mut r = Reader::new(&bytes[..cut]);
            let mut result = Ok(Some(entry("", 0)));
            while let Ok(Some(_)) = result {
                result = r.next().await;
            }
            let e = result.expect_err(&format!("cut at {cut}"));
            assert!(e.to_string().contains(TRAILER), "{e}");
        }
        // Zeros where the trailer should be: the end of a tar, not of our archive.
        let mut early = bytes[..bytes.len() - 4 * BLOCK].to_vec();
        early.extend_from_slice(&[0u8; 2 * BLOCK]);
        let mut r = Reader::new(early.as_slice());
        while let Ok(Some(_)) = r.next().await {}
        assert!(r.next().await.is_err());
    }

    #[tokio::test]
    async fn an_object_that_changed_while_read_is_refused() {
        let mut out = Vec::new();
        let mut w = Writer::new(&mut out);
        w.start(&entry("a", 3)).await.expect("start");
        assert!(w.write(b"four").await.is_err(), "longer than said");
        let mut w = Writer::new(Vec::new());
        w.start(&entry("a", 3)).await.expect("start");
        w.write(b"ab").await.expect("write");
        assert!(w.end_entry().await.is_err(), "shorter than said");
        let mut w = Writer::new(Vec::new());
        assert!(
            w.start(&entry(TRAILER, 1)).await.is_err(),
            "an object named as the end"
        );
    }

    #[tokio::test]
    async fn a_writer_dropped_halfway_breaks_the_pipe_rather_than_ending_it() {
        let (sink, mut source) = pipe();
        let writing = async move {
            let mut w = Writer::new(sink);
            w.start(&entry("a", 10)).await.expect("start");
            w.write(b"12345").await.expect("half");
            // The read of the object fails here: the writer is dropped, never finished.
        };
        let mut got = Vec::new();
        let (_, read) = tokio::join!(writing, source.read_to_end(&mut got));
        assert!(read.is_err(), "a writer that failed read as a clean end");

        let (sink, mut source) = pipe();
        let writing = async move {
            let w = Writer::new(sink);
            w.finish().await.expect("finished")
        };
        let mut got = Vec::new();
        let (_, read) = tokio::join!(writing, source.read_to_end(&mut got));
        assert!(read.is_ok(), "{read:?}");
    }

    #[test]
    fn a_pax_record_counts_its_own_length() {
        for value in ["", "x", &"y".repeat(93), &"z".repeat(994)] {
            let r = record("path", value);
            let said: usize = std::str::from_utf8(&r)
                .expect("utf8")
                .split(' ')
                .next()
                .and_then(|n| n.parse().ok())
                .expect("length");
            assert_eq!(said, r.len(), "{value:?}");
        }
    }
}
