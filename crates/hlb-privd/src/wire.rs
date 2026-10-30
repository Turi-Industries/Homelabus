//! The socket between the web side and the daemon.
//!
//! One intent per connection: the web side writes it as one line of JSON, the daemon
//! answers one line and closes. A Unix socket costs nothing to open, and a connection
//! that carries one exchange cannot leave a half-read answer for the next caller.
//!
//! 🔴 **The peer is checked, not the path.** Whoever can reach the socket file would
//! otherwise speak for the web side — install, sign up, open a session. The daemon reads
//! the connecting process's uid from the kernel (`SO_PEERCRED`) and answers only the one
//! uid the web side runs as; anyone else gets a refusal and nothing is read.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use hlb_api::intent::Intent;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

use crate::{Error, Privd};

/// The largest intent read: a logo travels in one, and nothing else comes near.
const MAX_INTENT: u64 = 16 * 1024 * 1024;

/// What travels back: the answer, or why there is none.
type Reply = Result<serde_json::Value, String>;

/// The web side's end: where the daemon listens.
#[derive(Debug, Clone)]
pub struct Remote {
    socket: PathBuf,
}

impl Remote {
    pub fn new(socket: impl Into<PathBuf>) -> Self {
        Self {
            socket: socket.into(),
        }
    }

    /// Asks one intent and returns its answer as it travelled.
    pub async fn answer(&self, intent: &Intent) -> Result<serde_json::Value, Error> {
        let transport =
            |e: std::io::Error| Error::Transport(format!("{}: {e}", self.socket.display()));
        let mut stream = UnixStream::connect(&self.socket).await.map_err(transport)?;
        let mut line = serde_json::to_vec(intent)?;
        line.push(b'\n');
        stream.write_all(&line).await.map_err(transport)?;
        stream.shutdown().await.map_err(transport)?;
        let mut reply = String::new();
        BufReader::new(stream)
            .take(MAX_INTENT)
            .read_line(&mut reply)
            .await
            .map_err(transport)?;
        if reply.is_empty() {
            return Err(Error::Transport(format!(
                "{}: the daemon closed without answering",
                self.socket.display()
            )));
        }
        let reply: Reply = serde_json::from_str(&reply)?;
        reply.map_err(Error::Refused)
    }
}

/// Listens at `socket`, replacing a file a previous run left there.
pub fn listen(socket: &Path) -> std::io::Result<UnixListener> {
    match std::fs::remove_file(socket) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    UnixListener::bind(socket)
}

/// Answers every connection from the web side's uid, until shutdown.
pub async fn serve(
    listener: UnixListener,
    privd: Arc<Privd>,
    web_uid: u32,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => {
                    let privd = privd.clone();
                    tokio::spawn(async move { one(stream, &privd, web_uid).await });
                }
                // A loop never panics: a failed accept is logged, the next one tried.
                Err(e) => tracing::warn!("the privileged socket refused a connection: {e}"),
            },
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    return;
                }
            }
        }
    }
}

/// One exchange. The peer is checked BEFORE the intent is read.
async fn one(mut stream: UnixStream, privd: &Privd, web_uid: u32) {
    let reply: Reply = match stream.peer_cred() {
        Ok(cred) if cred.uid() == web_uid => read_and_answer(&mut stream, privd).await,
        Ok(cred) => {
            tracing::warn!(
                uid = cred.uid(),
                "privileged socket: a stranger was refused"
            );
            Err(format!("uid {} is not the web side's", cred.uid()))
        }
        Err(e) => Err(format!("the peer could not be identified: {e}")),
    };
    let Ok(mut line) = serde_json::to_vec(&reply) else {
        return;
    };
    line.push(b'\n');
    let _ = stream.write_all(&line).await;
    let _ = stream.shutdown().await;
}

async fn read_and_answer(stream: &mut UnixStream, privd: &Privd) -> Reply {
    let mut line = String::new();
    BufReader::new(&mut *stream)
        .take(MAX_INTENT)
        .read_line(&mut line)
        .await
        .map_err(|e| format!("the intent could not be read: {e}"))?;
    // `deny_unknown_fields` on every intent: a field the daemon does not know is refused
    // here, never silently dropped.
    let intent: Intent =
        serde_json::from_str(&line).map_err(|e| format!("not an intent this daemon knows: {e}"))?;
    privd.answer(intent).await.map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A daemon answering `web_uid` (computed from this process's own uid), and the
    /// sender that would stop it, kept alive by the caller.
    async fn served(
        web_uid: impl FnOnce(u32) -> u32,
    ) -> (tempfile::TempDir, Remote, tokio::sync::watch::Sender<bool>) {
        let (a, _b) = UnixStream::pair().expect("pair");
        let mine = a.peer_cred().expect("cred").uid();
        let dir = tempfile::tempdir().expect("dir");
        let socket = dir.path().join("privd.sock");
        let listener = listen(&socket).expect("listen");
        let state = Arc::new(hlb_state::State::in_memory().await.expect("state"));
        let (tx, rx) = tokio::sync::watch::channel(false);
        tokio::spawn(serve(
            listener,
            Arc::new(Privd::new(state)),
            web_uid(mine),
            rx,
        ));
        (dir, Remote::new(socket), tx)
    }

    #[tokio::test]
    async fn the_web_side_s_uid_is_answered() {
        let (_dir, remote, _stop) = served(|mine| mine).await;
        let answer = remote
            .answer(&Intent::Drifts(hlb_api::intent::Drifts {}))
            .await
            .expect("answered");
        assert_eq!(answer, serde_json::json!([]));
    }

    #[tokio::test]
    async fn any_other_uid_is_refused_before_the_intent_is_read() {
        let (_dir, remote, _stop) = served(|mine| mine.wrapping_add(1)).await;
        match remote
            .answer(&Intent::Drifts(hlb_api::intent::Drifts {}))
            .await
        {
            Err(Error::Refused(why)) => assert!(why.contains("not the web side"), "{why}"),
            other => panic!("a stranger was answered: {other:?}"),
        }
    }

    #[tokio::test]
    async fn an_unknown_field_is_refused_not_dropped() {
        let (dir, _, _stop) = served(|mine| mine).await;
        let mut s = UnixStream::connect(dir.path().join("privd.sock"))
            .await
            .expect("connect");
        s.write_all(b"{\"intent\":\"drifts\",\"all\":true}\n")
            .await
            .expect("write");
        s.shutdown().await.expect("shutdown");
        let mut reply = String::new();
        s.read_to_string(&mut reply).await.expect("read");
        let reply: Reply = serde_json::from_str(&reply).expect("a reply");
        assert!(reply.is_err(), "{reply:?}");
    }

    #[tokio::test]
    async fn no_daemon_is_a_transport_error_naming_the_socket() {
        let remote = Remote::new("/nonexistent/privd.sock");
        match remote
            .answer(&Intent::Drifts(hlb_api::intent::Drifts {}))
            .await
        {
            Err(Error::Transport(why)) => assert!(why.contains("/nonexistent/privd.sock")),
            other => panic!("{other:?}"),
        }
    }
}
