//! Reaching the platform's services from a host.
//!
//! Their admin URLs name what the overlay resolves — `postgres`, `mariadb`, `garage` —
//! and a host resolves none of them: run from a manager, `hlb install` recorded every
//! database as unimplemented and `hlb replication status` could not connect. Where a
//! name does not resolve, a relay container on the platform network forwards its port
//! to 127.0.0.1, for this command only. Inside the overlay — the controller — the name
//! resolves and nothing is opened.
//!
//! Only for connections `hlb` makes itself: a URL handed to a container on the overlay
//! (`pg_dump`, `pg_basebackup`) must keep the service's name, which 127.0.0.1 is not
//! there.

use std::io::Read as _;
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Mutex;
use std::time::Duration;

/// The relay. Pinned: a tag that moves is an image nobody reviewed.
pub const IMAGE: &str =
    "alpine/socat:1.8.0.3@sha256:beb4a68d9e4fe6b0f21ea774a0fde6c31f580dde6368939ed70100c5385b015e";

/// A relay left by an `hlb` that was killed stops on its own after this.
const LIFETIME_S: u32 = 6 * 3600;

/// The relays this command opened: `(container, host, port, local port)`.
///
/// 🔴 Reused, never opened twice: the container is named after the process, and a
/// command running two plans — moving the ingress redeploys Caddy, then CrowdSec —
/// asked Docker for the same name again, was refused, and provisioned nothing.
#[allow(clippy::type_complexity)]
static OPENED: Mutex<Vec<(String, String, u16, u16)>> = Mutex::new(Vec::new());

/// Where to connect to `url` from here: itself when its host resolves, else through a
/// relay. A relay that cannot be opened leaves the URL as it is, and says why — the
/// connection then fails where it always did, with its own message.
pub fn reach(url: &str, network: &str) -> String {
    let Some((host, port)) = target(url) else {
        return url.to_string();
    };
    if (host.as_str(), port)
        .to_socket_addrs()
        .is_ok_and(|mut a| a.next().is_some())
    {
        return url.to_string();
    }
    match open(&host, port, network) {
        Ok(local) => through(url, local).unwrap_or_else(|| url.to_string()),
        Err(e) => {
            eprintln!(
                "⚠️  {host} does not resolve here, and no relay could be opened on {network}: {e}"
            );
            url.to_string()
        }
    }
}

/// Removes every relay this command opened.
pub fn close_all() {
    let names = match OPENED.lock() {
        Ok(mut n) => std::mem::take(&mut *n),
        Err(_) => return,
    };
    for (name, ..) in names {
        let _ = std::process::Command::new("docker")
            .args(["rm", "-f", &name])
            .output();
    }
}

/// The host and port a URL connects to, its scheme's default port included.
fn target(url: &str) -> Option<(String, u16)> {
    let u = reqwest::Url::parse(url).ok()?;
    let host = u.host_str()?.to_string();
    let port = u.port_or_known_default().or(match u.scheme() {
        "postgres" | "postgresql" => Some(5432),
        "mysql" | "mariadb" => Some(3306),
        _ => None,
    })?;
    Some((host, port))
}

/// The same URL, pointed at the relay's local port.
fn through(url: &str, local_port: u16) -> Option<String> {
    let mut u = reqwest::Url::parse(url).ok()?;
    u.set_host(Some("127.0.0.1")).ok()?;
    u.set_port(Some(local_port)).ok()?;
    let mut out = u.to_string();
    // The parser writes a root path the original did not have: a client appending
    // `/v1/…` to it would ask for `//v1/…`.
    if u.path() == "/" && !url.ends_with('/') && out.ends_with('/') {
        out.pop();
    }
    Some(out)
}

fn open(host: &str, port: u16, network: &str) -> Result<u16, String> {
    if let Some(local) = OPENED.lock().ok().and_then(|o| {
        o.iter()
            .find(|(_, h, p, l)| h == host && *p == port && *l != 0)
            .map(|(.., l)| *l)
    }) {
        return Ok(local);
    }
    let name = format!("hlb-relay-{host}-{port}-{}", std::process::id());
    let docker = |args: &[&str]| {
        std::process::Command::new("docker")
            .args(args)
            .output()
            .map_err(|e| format!("docker: {e}"))
            .and_then(|o| {
                if o.status.success() {
                    Ok(String::from_utf8_lossy(&o.stdout).trim().to_string())
                } else {
                    Err(String::from_utf8_lossy(&o.stderr).trim().to_string())
                }
            })
    };
    let lifetime = LIFETIME_S.to_string();
    let listen = format!("TCP-LISTEN:{port},fork,reuseaddr");
    let forward = format!("TCP:{host}:{port}");
    // Published on 127.0.0.1 only: the relay must not open the database to the LAN.
    let publish = format!("127.0.0.1::{port}");
    docker(&[
        "run",
        "-d",
        "--rm",
        "--name",
        &name,
        "--network",
        network,
        "-p",
        &publish,
        "--entrypoint",
        "timeout",
        IMAGE,
        &lifetime,
        "socat",
        &listen,
        &forward,
    ])?;
    let bound = docker(&["port", &name, &format!("{port}/tcp")]);
    let local: Result<u16, String> = bound.and_then(|b| {
        b.lines()
            .next()
            .and_then(|l| l.rsplit(':').next())
            .and_then(|p| p.parse().ok())
            .ok_or_else(|| format!("no local port in \"{b}\""))
    });
    // Recorded whatever the port reads, so `close_all` removes it either way.
    if let Ok(mut opened) = OPENED.lock() {
        opened.push((
            name.clone(),
            host.to_string(),
            port,
            *local.as_ref().unwrap_or(&0),
        ));
    }
    let local = local?;
    wait_listening(local);
    Ok(local)
}

/// Docker's proxy accepts on the published port before socat listens behind it, then
/// closes: a first connection made too early is cut, and reads as the service being
/// down. Listening shows as a connection that stays open — these services wait for the
/// client to speak first.
fn wait_listening(port: u16) {
    for _ in 0..30 {
        if let Ok(mut s) = TcpStream::connect(("127.0.0.1", port)) {
            let _ = s.set_read_timeout(Some(Duration::from_millis(200)));
            let mut byte = [0u8; 1];
            match s.read(&mut byte) {
                Ok(0) => {}
                Ok(_) => return,
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    return
                }
                Err(_) => {}
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_url_is_read_with_its_schemes_default_port() {
        assert_eq!(
            target("postgres://postgres:pw@postgres/postgres"),
            Some(("postgres".into(), 5432))
        );
        assert_eq!(
            target("mysql://root:pw@mariadb:3306/mysql"),
            Some(("mariadb".into(), 3306))
        );
        assert_eq!(target("http://garage:3903"), Some(("garage".into(), 3903)));
    }

    #[test]
    fn the_relayed_url_keeps_everything_but_where_it_connects() {
        assert_eq!(
            through(
                "postgres://postgres:p%40ss@postgres:5432/postgres?sslmode=disable",
                49170
            )
            .as_deref(),
            Some("postgres://postgres:p%40ss@127.0.0.1:49170/postgres?sslmode=disable")
        );
        assert_eq!(
            through("http://garage:3903", 49171).as_deref(),
            Some("http://127.0.0.1:49171")
        );
    }

    #[test]
    fn a_host_that_resolves_is_reached_directly() {
        // No relay, no docker call: the controller, on the overlay, takes this path.
        assert_eq!(
            reach("http://127.0.0.1:3903", "unused"),
            "http://127.0.0.1:3903"
        );
    }
}
