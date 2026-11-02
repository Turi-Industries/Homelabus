//! Fetching a catalog source's signed index over the network into its cache, for
//! `hlb catalog source` and the controller's nightly pass alike.
//!
//! The network is here and never in `hlb-catalog`: `hlb_catalog::index` says whether
//! what was downloaded is what the source's key signed, and fetches nothing itself.

use std::path::{Path, PathBuf};

use hlb_catalog::index;
use hlb_state::{CatalogSource, State};
use hlb_types::index::{Index, FILE, SIGNATURE_FILE};

/// The most one response may weigh. An index and an app's files are text: a source
/// serving more is broken or hostile, and is not given the disk to fill.
const MOST_BYTES: usize = 8 << 20;

/// Whether `location` is an address, and the refusal if it is one not to fetch from.
/// Plain HTTP is accepted on this machine only — a mirror beside it, or a test: the
/// signature would catch a changed file, but not a network withholding the fresh index.
pub fn address(location: &str) -> Option<std::result::Result<String, String>> {
    if !location.contains("://") {
        return None;
    }
    let url = match reqwest::Url::parse(location) {
        Ok(u) => u,
        Err(e) => return Some(Err(format!("{location}: {e}"))),
    };
    let loopback = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    Some(match url.scheme() {
        "https" => Ok(location.trim_end_matches('/').to_string()),
        "http" if loopback => Ok(location.trim_end_matches('/').to_string()),
        _ => Err(format!(
            "{location}: a source is fetched over https:// (plain http only from this machine)"
        )),
    })
}

async fn get(client: &reqwest::Client, url: &str) -> std::result::Result<Vec<u8>, String> {
    let mut r = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("{url}: {e}"))?;
    if !r.status().is_success() {
        return Err(format!("{url}: HTTP {}", r.status().as_u16()));
    }
    let mut body = Vec::new();
    while let Some(chunk) = r.chunk().await.map_err(|e| format!("{url}: {e}"))? {
        body.extend_from_slice(&chunk);
        if body.len() > MOST_BYTES {
            return Err(format!("{url}: over {} MiB, refused", MOST_BYTES >> 20));
        }
    }
    Ok(body)
}

/// The signed index served under `url`, refused unless `key` signed it for `name` and
/// it is no older than `seen` — before a single file it names is downloaded.
pub async fn signed_index(
    client: &reqwest::Client,
    url: &str,
    name: &str,
    key: &str,
    seen: Option<u64>,
) -> std::result::Result<(Index, Vec<u8>, String), String> {
    let bytes = get(client, &format!("{url}/{FILE}")).await?;
    let sig = get(client, &format!("{url}/{SIGNATURE_FILE}")).await?;
    let sig = String::from_utf8_lossy(&sig).into_owned();
    let idx = index::accept(&bytes, &sig, name, key, seen).map_err(|e| e.to_string())?;
    Ok((idx, bytes, sig))
}

/// What a fetch did: the index read, and the files downloaded and kept.
pub struct Staged {
    pub index: Index,
    pub downloaded: usize,
    pub kept: usize,
}

/// Writes the index into `staged`, every file it names copied from `cache` when the
/// cache holds it already, downloaded otherwise. Nothing here is trusted yet:
/// `index::swap_in` checks it whole before it replaces the cache.
pub async fn stage(
    client: &reqwest::Client,
    url: &str,
    (idx, bytes, sig): (Index, Vec<u8>, String),
    cache: &Path,
    staged: &Path,
) -> std::result::Result<Staged, String> {
    let io = |p: &Path| {
        let p = p.display().to_string();
        move |e: std::io::Error| format!("{p}: {e}")
    };
    if staged.exists() {
        // A fetch that stopped halfway: nothing in it was ever read.
        std::fs::remove_dir_all(staged).map_err(io(staged))?;
    }
    std::fs::create_dir_all(staged).map_err(io(staged))?;
    std::fs::write(staged.join(FILE), &bytes).map_err(io(staged))?;
    std::fs::write(staged.join(SIGNATURE_FILE), &sig).map_err(io(staged))?;
    // A packaging fix is a new version directory whose files are mostly the last
    // one's: found by digest, not by path. `holds` reads each again, so the cache's
    // index, unverified here, can only point at a file, never vouch for one.
    let mut held = std::collections::HashMap::new();
    if let Ok(old) = index::read(&cache.join(FILE)) {
        for (rel, digest) in index::files(&old).unwrap_or_default() {
            held.entry(digest).or_insert(rel);
        }
    }
    let (mut downloaded, mut kept) = (0, 0);
    for (rel, digest) in index::files(&idx).map_err(|e| e.to_string())? {
        let to = staged.join(&rel);
        if let Some(parent) = to.parent() {
            std::fs::create_dir_all(parent).map_err(io(parent))?;
        }
        let from = [Some(&rel), held.get(&digest)]
            .into_iter()
            .flatten()
            .find(|r| index::holds(cache, r, &digest));
        if let Some(from) = from {
            std::fs::copy(cache.join(from), &to).map_err(io(&to))?;
            kept += 1;
        } else {
            let body = get(client, &format!("{url}/{rel}")).await?;
            std::fs::write(&to, body).map_err(io(&to))?;
            downloaded += 1;
        }
    }
    Ok(Staged {
        index: idx,
        downloaded,
        kept,
    })
}

pub fn client() -> std::result::Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .map_err(|e| e.to_string())
}

/// What a fetch of one source did.
#[derive(Debug)]
pub struct Fetched {
    pub index: Index,
    /// The files downloaded and kept from the cache; `None` when the index served is
    /// the one held already.
    pub files: Option<(usize, usize)>,
    /// The apps installed from this source that run a version it revoked:
    /// `(app, version, why)`.
    pub revoked: Vec<(String, String, String)>,
}

/// Fetches `src` into its cache, if it is served over the network — `None` for a
/// directory, read as it is. The counter rises in the state and the fetch is audited
/// for `actor` when a new index replaced the cache.
pub async fn fetch(
    state: &State,
    src: &CatalogSource,
    actor: &str,
    role: hlb_types::Role,
) -> std::result::Result<Option<Fetched>, String> {
    let Some(signed) = &src.signed else {
        return Ok(None);
    };
    let (name, key, url) = (&src.name, &signed.key, &signed.url);
    let cache = PathBuf::from(&src.directory);
    let client = client()?;
    let fetched = signed_index(&client, url, name, key, signed.counter).await?;
    let counter = fetched.0.counter;
    let unchanged = Some(counter) == signed.counter
        && index::verify(&cache, name, key).is_ok_and(|held| held.counter == counter);
    let e = |e: hlb_state::Error| e.to_string();
    let (idx, files) = if unchanged {
        (fetched.0, None)
    } else {
        let staged = cache.with_extension("new");
        let swapped = match stage(&client, url, fetched, &cache, &staged).await {
            Ok(s) => index::swap_in(&staged, &cache, name, key)
                .map(|_| s)
                .map_err(|e| e.to_string()),
            Err(e) => Err(e),
        };
        // What did not verify is not left lying beside the cache.
        let s = swapped.inspect_err(|_| {
            let _ = std::fs::remove_dir_all(&staged);
        })?;
        state
            .raise_catalog_source_counter(name, counter)
            .await
            .map_err(e)?;
        state
            .audit(
                actor,
                role,
                "catalog-source-fetch",
                name,
                "ok",
                Some(&format!("index {counter}")),
            )
            .await
            .map_err(e)?;
        (s.index, Some((s.downloaded, s.kept)))
    };
    // 🔴 A revoked version keeps running until someone moves it: said where the
    // revocation arrives, and every day after in the inbox.
    let mut revoked = Vec::new();
    for (app, _) in state.installed_apps().await.map_err(e)? {
        if state.app_source(&app).await.map_err(e)?.as_deref() != Some(name.as_str()) {
            continue;
        }
        let Some(version) = state.app_release(&app).await.map_err(e)?.version else {
            continue;
        };
        if let Some(why) = idx.revocation(&app, &version) {
            let why = why.to_string();
            revoked.push((app, version, why));
        }
    }
    Ok(Some(Fetched {
        index: idx,
        files,
        revoked,
    }))
}

/// Fetches every source served over the network. One unreachable never keeps the
/// others stale: each has its own outcome.
pub async fn fetch_all(
    state: &State,
    actor: &str,
    role: hlb_types::Role,
) -> hlb_state::Result<Vec<(String, std::result::Result<Fetched, String>)>> {
    let mut out = Vec::new();
    for src in state.catalog_sources().await? {
        if let Some(r) = fetch(state, &src, actor, role).await.transpose() {
            out.push((src.name.clone(), r));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const SEED: [u8; 32] = [9; 32];

    /// Serves `dir` over plain HTTP on the loopback, as a mirror beside the house would.
    async fn serve(dir: PathBuf) -> String {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = l.local_addr().expect("addr").port();
        tokio::spawn(async move {
            while let Ok((mut c, _)) = l.accept().await {
                let dir = dir.clone();
                tokio::spawn(async move {
                    let mut head = Vec::new();
                    let mut b = [0u8; 1024];
                    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                        match c.read(&mut b).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => head.extend_from_slice(&b[..n]),
                        }
                    }
                    let line = String::from_utf8_lossy(&head).into_owned();
                    let path = line
                        .split(' ')
                        .nth(1)
                        .unwrap_or("/")
                        .trim_start_matches('/');
                    let answer = match std::fs::read(dir.join(path)) {
                        Ok(body) => [
                            format!(
                                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                body.len()
                            )
                            .into_bytes(),
                            body,
                        ]
                        .concat(),
                        Err(_) => b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
                    };
                    let _ = c.write_all(&answer).await;
                });
            }
        });
        format!("http://127.0.0.1:{port}")
    }

    fn now() -> i64 {
        chrono::Utc::now().timestamp()
    }

    /// A catalog holding a copy of one official app.
    fn catalog() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("catalog");
        let official = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../catalog/librespeed");
        let ok = std::process::Command::new("cp")
            .arg("-r")
            .arg(official)
            .arg(dir.path())
            .status()
            .expect("cp")
            .success();
        assert!(ok);
        dir
    }

    #[tokio::test]
    async fn a_fetch_takes_a_new_index_once_and_names_a_revoked_install() {
        let cat = catalog();
        let served = tempfile::tempdir().expect("served");
        let one = index::build(cat.path(), "community", None, served.path(), now()).expect("built");
        index::sign(served.path(), &SEED, None, now()).expect("signed");
        let url = serve(served.path().to_path_buf()).await;

        let home = tempfile::tempdir().expect("home");
        let state = State::in_memory().await.expect("state");
        let src = |counter| CatalogSource {
            name: "community".into(),
            directory: home.path().join("community").display().to_string(),
            signed: Some(hlb_state::SignedSource {
                url: url.clone(),
                key: index::public_key(&SEED),
                counter,
            }),
        };
        assert!(state.add_catalog_source(&src(None)).await.expect("added"));

        let f = fetch(&state, &src(None), "test", hlb_types::Role::Admin)
            .await
            .expect("fetched")
            .expect("a signed source");
        assert_eq!(f.index.counter, 1);
        assert!(matches!(f.files, Some((n, 0)) if n > 0), "{:?}", f.files);
        let mut c = hlb_catalog::Catalog::default();
        c.add_signed_source(
            "community",
            &src(None).directory,
            &index::public_key(&SEED),
            now(),
        )
        .expect("the cache reads");
        assert!(c.get("community/librespeed").is_ok());

        // Fetched again, it is the index held: nothing downloaded.
        let again = fetch(&state, &src(Some(1)), "test", hlb_types::Role::Admin)
            .await
            .expect("fetched")
            .expect("signed");
        assert!(again.files.is_none(), "{:?}", again.files);

        // Installed from it, then revoked by its owner: the next fetch names it.
        let version = one.apps["librespeed"][0].version.clone();
        let manifest = hlb_catalog::Catalog::load(cat.path())
            .expect("catalog")
            .get("librespeed")
            .expect("librespeed")
            .manifest
            .clone();
        state
            .upsert_app("librespeed", &manifest, None)
            .await
            .expect("app");
        state
            .set_app_source(
                "librespeed",
                Some("community"),
                &hlb_state::Release {
                    index: Some(1),
                    version: Some(version.clone()),
                },
            )
            .await
            .expect("source");
        std::fs::write(
            cat.path().join(index::REVOKED_FILE),
            format!("librespeed: [ {{ version: \"{version}\", why: leaks }} ]\n"),
        )
        .expect("revoked");
        // The index published before, files and all: its versions are carried.
        let previous = tempfile::tempdir().expect("previous");
        let copied = std::process::Command::new("cp")
            .arg("-r")
            .arg(format!("{}/.", served.path().display()))
            .arg(previous.path())
            .status()
            .expect("cp")
            .success();
        assert!(copied);
        std::fs::remove_dir_all(served.path()).expect("cleared");
        index::build(
            cat.path(),
            "community",
            Some(previous.path()),
            served.path(),
            now(),
        )
        .expect("built");
        index::sign(served.path(), &SEED, Some(&one), now()).expect("signed");
        let counter = state
            .catalog_sources()
            .await
            .expect("sources")
            .into_iter()
            .find_map(|s| s.signed.and_then(|s| s.counter));
        assert_eq!(counter, Some(1), "the first fetch raised it");
        let third = fetch(&state, &src(counter), "test", hlb_types::Role::Admin)
            .await
            .expect("fetched")
            .expect("signed");
        assert_eq!(third.index.counter, 2);
        assert_eq!(
            third.revoked,
            vec![("librespeed".to_string(), version, "leaks".to_string())]
        );
    }
}
