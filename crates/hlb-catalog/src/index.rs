//! Building, signing and verifying a source's `index.json` (`hlb_types::index`).
//!
//! No network here: what fetches a source writes a directory, and this says whether
//! that directory is what the source's key signed. CI builds an index, the owner signs
//! it on their own machine — neither GitHub nor Sigstore can publish an app.

use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hlb_types::index::{self, AppVersion, Index};

use crate::Catalog;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("{path}: {source}")]
    Json {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },

    #[error(transparent)]
    Catalog(#[from] crate::Error),

    #[error(
        "🔴 the index served is number {counter}, older than the {seen} already read: a \
         replay, refused"
    )]
    Replayed { seen: u64, counter: u64 },

    #[error(
        "\"{app}\" cannot be read by the hlb building the index ({why}) — build with the newest"
    )]
    Unreadable { app: String, why: String },

    #[error("\"{0}\" declares no `metadata.hlb`: an index says which hlb each version runs on")]
    NoRange(String),

    #[error("{0} is not empty: an index is built into a directory of its own")]
    OutNotEmpty(PathBuf),

    #[error("the index is for the source \"{found}\", not \"{expected}\"")]
    WrongSource { expected: String, found: String },

    #[error(
        "counter {counter} does not rise above the published index's {published}: signed, \
         it would read as a replay — build it again from the published one"
    )]
    NotRising { published: u64, counter: u64 },

    #[error("the index expired {ago} s ago — build it again")]
    Expired { ago: i64 },

    #[error(
        "the index expires {ahead} s from now, past the {} s an index is valid",
        index::VALIDITY_SECS
    )]
    TooLong { ahead: i64 },

    #[error("{0} is not a public key: 64 hexadecimal characters")]
    BadKey(String),

    #[error("🔴 the signature does not match: index.json was changed, or signed with another key")]
    BadSignature,

    #[error("🔴 {path} is not the file the index signed")]
    FileChanged { path: String },

    #[error("🔴 {path}: a path in the index leaves its directory")]
    PathEscapes { path: String },
}

pub type Result<T> = std::result::Result<T, Error>;

/// Builds the index of the catalog in `catalog_dir` into `out`, an empty directory.
///
/// `previous` is the directory of the index published before: its versions are kept,
/// files included, so an older `hlb` keeps the last version its range accepts, and its
/// counter is the one this index rises above. An app whose files are the same as its
/// last version's gets no new version; one whose image tag stayed and files moved is a
/// packaging fix, `<tag>~hlbN`.
pub fn build(
    catalog_dir: &Path,
    source: &str,
    previous: Option<&Path>,
    out: &Path,
    now: i64,
) -> Result<Index> {
    let catalog = Catalog::load(catalog_dir)?;
    // An index built by an hlb that sets an app aside would leave it out silently.
    if let Some((app, why)) = catalog.left_out().next() {
        return Err(Error::Unreadable {
            app: app.to_string(),
            why: why.to_string(),
        });
    }
    if out.exists() {
        let mut entries = std::fs::read_dir(out).map_err(|source| Error::Io {
            path: out.to_path_buf(),
            source,
        })?;
        if entries.next().is_some() {
            return Err(Error::OutNotEmpty(out.to_path_buf()));
        }
    }
    let before = match previous {
        Some(dir) => {
            let idx = read(&dir.join(index::FILE))?;
            if idx.source != source {
                return Err(Error::WrongSource {
                    expected: source.to_string(),
                    found: idx.source,
                });
            }
            check_files(&idx, dir)?;
            Some((idx, dir))
        }
        None => None,
    };

    let mut apps = BTreeMap::new();
    for e in catalog.entries() {
        let m = &e.manifest;
        let app = &m.metadata.name;
        let range = m
            .metadata
            .hlb
            .clone()
            .ok_or_else(|| Error::NoRange(app.clone()))?;
        let dir = e.path.parent().unwrap_or(Path::new("."));
        let files = hashed(dir)?;
        let mut versions: Vec<AppVersion> = before
            .as_ref()
            .and_then(|(idx, _)| idx.apps.get(app).cloned())
            .unwrap_or_default();
        for v in &versions {
            if let Some((_, from)) = &before {
                copy_version(&from.join(index::version_dir(app, &v.version)), out, app, v)?;
            }
        }
        if versions.last().map(|v| &v.files) != Some(&files) {
            let images = std::iter::once(&m.spec.image)
                .chain(m.spec.companions.iter().map(|c| &c.image))
                .map(hlb_types::Image::reference)
                .collect();
            let v = AppVersion {
                version: next_version(&m.spec.image.tag, &versions),
                hlb: range,
                files,
                images,
            };
            copy_version(dir, out, app, &v)?;
            versions.push(v);
        }
        apps.insert(app.clone(), versions);
    }

    let idx = Index {
        source: source.to_string(),
        counter: before.map_or(1, |(i, _)| i.counter + 1),
        expires: now + index::VALIDITY_SECS,
        apps,
    };
    let mut text = serde_json::to_string_pretty(&idx).map_err(|source| Error::Json {
        path: out.join(index::FILE),
        source,
    })?;
    text.push('\n');
    write(&out.join(index::FILE), text.as_bytes())?;
    Ok(idx)
}

/// Signs the index in `dir` with `seed`, writing `index.json.sig` beside it.
///
/// 🔴 Refused unless the counter rises above `published`'s — the index the source
/// serves today — and the expiry is ahead and within an index's validity: a signature
/// is what makes a replay or a frozen mirror detectable, so the signer is where both
/// are checked. Every file is checked against its digest first: what is signed is what
/// will be served.
pub fn sign(dir: &Path, seed: &[u8; 32], published: Option<&Index>, now: i64) -> Result<Index> {
    let path = dir.join(index::FILE);
    let bytes = std::fs::read(&path).map_err(|source| Error::Io {
        path: path.clone(),
        source,
    })?;
    let idx = parse(&bytes, &path)?;
    if let Some(p) = published {
        if p.source != idx.source {
            return Err(Error::WrongSource {
                expected: p.source.clone(),
                found: idx.source,
            });
        }
        if idx.counter <= p.counter {
            return Err(Error::NotRising {
                published: p.counter,
                counter: idx.counter,
            });
        }
    }
    current(&idx, now)?;
    // A clock a little ahead of the builder's is no reason to refuse.
    let ahead = idx.expires - now;
    if ahead > index::VALIDITY_SECS + 3600 {
        return Err(Error::TooLong { ahead });
    }
    check_files(&idx, dir)?;
    let sig = SigningKey::from_bytes(seed).sign(&bytes);
    write(
        &dir.join(index::SIGNATURE_FILE),
        format!("{}\n", hex(&sig.to_bytes())).as_bytes(),
    )?;
    Ok(idx)
}

/// The public key a seed signs for, as a source is given it.
pub fn public_key(seed: &[u8; 32]) -> String {
    hex(SigningKey::from_bytes(seed).verifying_key().as_bytes())
}

/// The index in `dir`, if `key` signed it for `source` and every file is the one it
/// signed. Expiry is not judged here: an expired index still says what the apps
/// installed from it are — `current` says whether anything new may come from it.
pub fn verify(dir: &Path, source: &str, key: &str) -> Result<Index> {
    let path = dir.join(index::FILE);
    let bytes = std::fs::read(&path).map_err(|e| Error::Io {
        path: path.clone(),
        source: e,
    })?;
    let sig_path = dir.join(index::SIGNATURE_FILE);
    let sig = std::fs::read_to_string(&sig_path).map_err(|e| Error::Io {
        path: sig_path,
        source: e,
    })?;
    let idx = signed(&bytes, &sig, source, key, &path)?;
    check_files(&idx, dir)?;
    Ok(idx)
}

/// A freshly downloaded index, before any file it names is fetched: signed by `key`
/// for `source`, and never older than `seen`, the highest counter already read — a
/// mirror serving an older index is replaying it.
pub fn accept(
    bytes: &[u8],
    sig: &str,
    source: &str,
    key: &str,
    seen: Option<u64>,
) -> Result<Index> {
    let idx = signed(bytes, sig, source, key, Path::new(index::FILE))?;
    if let Some(seen) = seen.filter(|s| idx.counter < *s) {
        return Err(Error::Replayed {
            seen,
            counter: idx.counter,
        });
    }
    Ok(idx)
}

fn signed(bytes: &[u8], sig: &str, source: &str, key: &str, path: &Path) -> Result<Index> {
    let key = parse_key(key)?;
    let sig = unhex(sig.trim())
        .and_then(|b| <[u8; 64]>::try_from(b).ok())
        .map(|b| Signature::from_bytes(&b))
        .ok_or(Error::BadSignature)?;
    key.verify(bytes, &sig).map_err(|_| Error::BadSignature)?;
    let idx = parse(bytes, path)?;
    if idx.source != source {
        return Err(Error::WrongSource {
            expected: source.to_string(),
            found: idx.source,
        });
    }
    Ok(idx)
}

/// Every file an index names, `(path under its directory, SHA-256)` — each held inside
/// it, for a fetch to download.
pub fn files(idx: &Index) -> Result<Vec<(String, String)>> {
    let mut out = Vec::new();
    for (app, versions) in &idx.apps {
        for v in versions {
            let base = index::version_dir(app, &v.version);
            for (rel, digest) in &v.files {
                let path = format!("{base}/{rel}");
                if contained(Path::new(""), &base, rel).is_none() {
                    return Err(Error::PathEscapes { path });
                }
                out.push((path, digest.clone()));
            }
        }
    }
    Ok(out)
}

/// Whether `dir` holds `rel` with that digest already: a fetch downloads what moved.
pub fn holds(dir: &Path, rel: &str, digest: &str) -> bool {
    std::fs::read(dir.join(rel)).is_ok_and(|b| hlb_types::token::sha256_hex(&b) == digest)
}

/// Puts `staged` in the place of `cache` once it verifies whole, so a fetch that
/// stopped halfway, or a file that arrived changed, leaves the source as it was.
pub fn swap_in(staged: &Path, cache: &Path, source: &str, key: &str) -> Result<Index> {
    let idx = verify(staged, source, key)?;
    let io = |path: &Path| {
        let path = path.to_path_buf();
        move |source| Error::Io { path, source }
    };
    let old = cache.with_extension("old");
    if old.exists() {
        std::fs::remove_dir_all(&old).map_err(io(&old))?;
    }
    if cache.exists() {
        std::fs::rename(cache, &old).map_err(io(cache))?;
    }
    std::fs::rename(staged, cache).map_err(io(staged))?;
    if old.exists() {
        std::fs::remove_dir_all(&old).map_err(io(&old))?;
    }
    Ok(idx)
}

/// Whether anything new may be installed from the index at `now`.
pub fn current(idx: &Index, now: i64) -> Result<()> {
    if idx.expires <= now {
        return Err(Error::Expired {
            ago: now - idx.expires,
        });
    }
    Ok(())
}

/// Reads an index, signed or not — what a build starts from.
pub fn read(path: &Path) -> Result<Index> {
    let bytes = std::fs::read(path).map_err(|source| Error::Io {
        path: path.to_path_buf(),
        source,
    })?;
    parse(&bytes, path)
}

fn parse(bytes: &[u8], path: &Path) -> Result<Index> {
    serde_json::from_slice(bytes).map_err(|source| Error::Json {
        path: path.to_path_buf(),
        source,
    })
}

fn parse_key(key: &str) -> Result<VerifyingKey> {
    unhex(key.trim())
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .and_then(|b| VerifyingKey::from_bytes(&b).ok())
        .ok_or_else(|| Error::BadKey(key.to_string()))
}

/// Every file of every version against its digest.
fn check_files(idx: &Index, dir: &Path) -> Result<()> {
    for (app, versions) in &idx.apps {
        for v in versions {
            let base = index::version_dir(app, &v.version);
            for (rel, digest) in &v.files {
                let shown = format!("{base}/{rel}");
                let path = contained(dir, &base, rel).ok_or_else(|| Error::PathEscapes {
                    path: shown.clone(),
                })?;
                let bytes = std::fs::read(&path).map_err(|source| Error::Io { path, source })?;
                if &hlb_types::token::sha256_hex(&bytes) != digest {
                    return Err(Error::FileChanged { path: shown });
                }
            }
        }
    }
    Ok(())
}

/// `dir/base/rel`, if neither part can climb out of `dir`: the app and version names
/// and the file paths all come from the index.
fn contained(dir: &Path, base: &str, rel: &str) -> Option<PathBuf> {
    let joined = Path::new(base).join(rel);
    joined
        .components()
        .all(|c| matches!(c, Component::Normal(_)))
        .then(|| dir.join(joined))
}

/// Every file under an app's directory, by its path there, and its SHA-256 — walked,
/// so an icon or a file added tomorrow is carried without anyone listing it.
fn hashed(dir: &Path) -> Result<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    walk(dir, dir, &mut out)?;
    Ok(out)
}

fn walk(root: &Path, dir: &Path, out: &mut BTreeMap<String, String>) -> Result<()> {
    let io = |path: &Path| {
        let path = path.to_path_buf();
        move |source| Error::Io { path, source }
    };
    for entry in std::fs::read_dir(dir).map_err(io(dir))? {
        let path = entry.map_err(io(dir))?.path();
        if path.is_dir() {
            walk(root, &path, out)?;
        } else {
            let bytes = std::fs::read(&path).map_err(io(&path))?;
            let rel = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");
            out.insert(rel, hlb_types::token::sha256_hex(&bytes));
        }
    }
    Ok(())
}

/// Copies a version's files from `src_base` — an app's directory in the catalog, or
/// its version's in a published index — to where `out` serves them.
fn copy_version(src_base: &Path, out: &Path, app: &str, v: &AppVersion) -> Result<()> {
    let base = index::version_dir(app, &v.version);
    for rel in v.files.keys() {
        let to = contained(out, &base, rel).ok_or_else(|| Error::PathEscapes {
            path: format!("{base}/{rel}"),
        })?;
        let src = src_base.join(rel);
        let bytes = std::fs::read(&src).map_err(|source| Error::Io { path: src, source })?;
        write(&to, &bytes)?;
    }
    Ok(())
}

fn write(path: &Path, bytes: &[u8]) -> Result<()> {
    let io = |source| Error::Io {
        path: path.to_path_buf(),
        source,
    };
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(io)?;
    }
    std::fs::write(path, bytes).map_err(io)
}

/// `tag` for its first packaging, `tag~hlbN` for the Nth.
fn next_version(tag: &str, versions: &[AppVersion]) -> String {
    let packagings = versions
        .iter()
        .filter_map(|v| match v.version.split_once("~hlb") {
            None if v.version == tag => Some(1),
            Some((t, n)) if t == tag => n.parse::<u32>().ok(),
            _ => None,
        })
        .max();
    match packagings {
        None => tag.to_string(),
        Some(n) => format!("{tag}~hlb{}", n + 1),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !s.is_ascii() {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: [u8; 32] = [7; 32];
    const NOW: i64 = 1_800_000_000;

    /// A catalog holding copies of two of the official apps.
    fn catalog() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        let official = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../catalog");
        for app in ["librespeed", "mealie"] {
            let ok = std::process::Command::new("cp")
                .arg("-r")
                .arg(official.join(app))
                .arg(dir.path())
                .status()
                .expect("cp")
                .success();
            assert!(ok);
        }
        dir
    }

    fn built(cat: &Path, previous: Option<&Path>) -> (tempfile::TempDir, Index) {
        let out = tempfile::tempdir().expect("out");
        let idx = build(cat, "community", previous, out.path(), NOW).expect("built");
        (out, idx)
    }

    #[test]
    fn a_signed_index_verifies_and_anything_changed_after_does_not() {
        let cat = catalog();
        let (out, idx) = built(cat.path(), None);
        assert_eq!(idx.counter, 1);
        assert_eq!(idx.expires, NOW + index::VALIDITY_SECS);
        let v = &idx.apps["librespeed"][0];
        assert_eq!(v.version, "6.3.1-alpine");
        assert_eq!(v.hlb, ">=0.4.0");
        // Walked: the icon is carried with the manifest and the guide.
        assert_eq!(
            v.files.keys().map(String::as_str).collect::<Vec<_>>(),
            ["guide.yaml", "icon.png", "manifest.yaml"]
        );
        assert!(v.images[0].contains("@sha256:"), "{:?}", v.images);

        sign(out.path(), &SEED, None, NOW).expect("signed");
        let key = public_key(&SEED);
        assert_eq!(
            verify(out.path(), "community", &key).expect("verified"),
            idx
        );

        // Signed for another source, under the same key.
        assert!(matches!(
            verify(out.path(), "other", &key),
            Err(Error::WrongSource { .. })
        ));
        // Another key.
        let theirs = public_key(&[9; 32]);
        assert!(matches!(
            verify(out.path(), "community", &theirs),
            Err(Error::BadSignature)
        ));
        // A file the index names, changed by whoever serves it.
        let guide = out.path().join("apps/librespeed/6.3.1-alpine/guide.yaml");
        let original = std::fs::read(&guide).expect("guide");
        std::fs::write(&guide, b"steps: []\n").expect("changed");
        assert!(
            matches!(
                verify(out.path(), "community", &key),
                Err(Error::FileChanged { ref path }) if path.ends_with("guide.yaml")
            ),
            "a changed file passed"
        );
        std::fs::write(&guide, original).expect("put back");
        // The index itself.
        let path = out.path().join(index::FILE);
        let text = std::fs::read_to_string(&path).expect("index");
        std::fs::write(&path, text.replace("\"counter\": 1", "\"counter\": 9")).expect("changed");
        assert!(matches!(
            verify(out.path(), "community", &key),
            Err(Error::BadSignature)
        ));
    }

    #[test]
    fn signing_refuses_a_replay_and_an_expiry_behind_or_too_far() {
        let cat = catalog();
        let (first, published) = built(cat.path(), None);
        sign(first.path(), &SEED, None, NOW).expect("signed");

        // Built from the published one, it rises.
        let (next, idx) = built(cat.path(), Some(first.path()));
        assert_eq!(idx.counter, 2);
        sign(next.path(), &SEED, Some(&published), NOW).expect("rises");
        // 🔴 Signed again over what is published, the old one would replay.
        let same = sign(first.path(), &SEED, Some(&published), NOW);
        assert!(
            matches!(
                same,
                Err(Error::NotRising {
                    published: 1,
                    counter: 1
                })
            ),
            "{same:?}"
        );
        // Signed after it expired, or set to last past an index's validity.
        let late = NOW + index::VALIDITY_SECS + 1;
        assert!(matches!(
            sign(next.path(), &SEED, Some(&published), late),
            Err(Error::Expired { .. })
        ));
        let early = NOW - 2 * 3600;
        assert!(matches!(
            sign(next.path(), &SEED, Some(&published), early),
            Err(Error::TooLong { .. })
        ));
        assert!(current(&idx, NOW).is_ok());
        assert!(current(&idx, idx.expires).is_err());
    }

    #[test]
    fn a_rebuild_keeps_every_version_and_counts_a_packaging_fix() {
        let cat = catalog();
        let (one, _) = built(cat.path(), None);

        // Nothing moved: no new version, the counter rises all the same.
        let (two, idx) = built(cat.path(), Some(one.path()));
        assert_eq!(idx.apps["mealie"].len(), 1);
        assert_eq!(idx.counter, 2);

        // The guide alone changed: a packaging fix of the same tag.
        let guide = cat.path().join("mealie/guide.yaml");
        let text = std::fs::read_to_string(&guide).expect("guide");
        std::fs::write(&guide, format!("{text}\n# fixed\n")).expect("fixed");
        let (three, idx) = built(cat.path(), Some(two.path()));
        let tag = &idx.apps["mealie"][0].version;
        let versions: Vec<&str> = idx.apps["mealie"]
            .iter()
            .map(|v| v.version.as_str())
            .collect();
        assert_eq!(versions, [tag.clone(), format!("{tag}~hlb2")]);
        assert_eq!(idx.apps["librespeed"].len(), 1);

        // And again: the third packaging.
        std::fs::write(&guide, format!("{text}\n# fixed twice\n")).expect("fixed");
        let (four, idx) = built(cat.path(), Some(three.path()));
        assert_eq!(idx.apps["mealie"][2].version, format!("{tag}~hlb3"));

        // Every version's files are still served, as signed.
        sign(four.path(), &SEED, None, NOW).expect("signed");
        let read = verify(four.path(), "community", &public_key(&SEED)).expect("verified");
        assert_eq!(read.apps["mealie"].len(), 3);
        assert!(four
            .path()
            .join(format!("apps/mealie/{tag}/guide.yaml"))
            .is_file());

        // An app gone from the catalog is gone from the index: it is offered no more.
        std::fs::remove_dir_all(cat.path().join("librespeed")).expect("removed");
        let (_, idx) = built(cat.path(), Some(four.path()));
        assert!(!idx.apps.contains_key("librespeed"));
    }

    #[test]
    fn a_build_never_mixes_with_what_a_directory_holds() {
        let cat = catalog();
        let out = tempfile::tempdir().expect("out");
        std::fs::write(out.path().join("stale"), b"x").expect("stale");
        assert!(matches!(
            build(cat.path(), "community", None, out.path(), NOW),
            Err(Error::OutNotEmpty(_))
        ));
        // From another source's index.
        let (other, _) = {
            let o = tempfile::tempdir().expect("o");
            let i = build(cat.path(), "other", None, o.path(), NOW).expect("built");
            (o, i)
        };
        let fresh = tempfile::tempdir().expect("fresh");
        assert!(matches!(
            build(
                cat.path(),
                "community",
                Some(other.path()),
                fresh.path(),
                NOW
            ),
            Err(Error::WrongSource { .. })
        ));
    }

    #[test]
    fn a_path_in_the_index_never_leaves_its_directory() {
        // Signed or not, the names come from the index: `../` would read — and a build
        // would write — outside the source's directory.
        let dir = tempfile::tempdir().expect("dir");
        for (app, version, file) in [
            ("..", "1", "manifest.yaml"),
            ("app", "../../x", "manifest.yaml"),
            ("app", "1", "../../../etc/passwd"),
            ("app", "1", "/etc/passwd"),
        ] {
            let idx = Index {
                source: "community".into(),
                counter: 1,
                expires: NOW,
                apps: [(
                    app.to_string(),
                    vec![AppVersion {
                        version: version.into(),
                        hlb: ">=0.4.0".into(),
                        files: [(file.to_string(), "00".to_string())].into(),
                        images: vec![],
                    }],
                )]
                .into(),
            };
            assert!(
                matches!(
                    check_files(&idx, dir.path()),
                    Err(Error::PathEscapes { .. })
                ),
                "{app}/{version}/{file} read"
            );
        }
    }

    #[test]
    fn a_signed_source_offers_the_newest_version_this_hlb_runs() {
        let cat = catalog();
        let (one, _) = built(cat.path(), None);
        let guide = cat.path().join("mealie/guide.yaml");
        let text = std::fs::read_to_string(&guide).expect("guide");
        std::fs::write(&guide, format!("{text}\n# for a later hlb\n")).expect("fixed");
        let (two, _) = built(cat.path(), Some(one.path()));
        // Its second packaging is for an hlb to come.
        let path = two.path().join(index::FILE);
        let mut idx = read(&path).expect("index");
        let later = idx.apps.get_mut("mealie").expect("mealie");
        later[1].hlb = ">=9.0.0".into();
        let first = later[0].version.clone();
        std::fs::write(&path, serde_json::to_string_pretty(&idx).expect("json")).expect("written");
        sign(two.path(), &SEED, None, NOW).expect("signed");
        let key = public_key(&SEED);

        let mut c = Catalog::default();
        c.add_signed_source("community", two.path(), &key, NOW)
            .expect("added");
        let e = c.get("community/mealie").expect("mealie");
        assert_eq!(e.index, Some(2), "the index it came from");
        assert!(
            e.path
                .ends_with(format!("apps/mealie/{first}/manifest.yaml")),
            "{}",
            e.path.display()
        );
        assert!(!e.guide.steps.is_empty());

        // 🔴 Expired, nothing new comes from it — and it says how to fetch a fresh one.
        let mut c = Catalog::default();
        c.add_signed_source("community", two.path(), &key, NOW + index::VALIDITY_SECS)
            .expect("added");
        let why = c
            .get("community/mealie")
            .expect_err("set aside")
            .to_string();
        assert!(why.contains("out of date") && why.contains("fresh index"), "{why}");
        assert!(c.is_empty());

        // Another key: the source is not read at all.
        let mut c = Catalog::default();
        assert!(c
            .add_signed_source("community", two.path(), &public_key(&[9; 32]), NOW)
            .is_err());
    }

    #[test]
    fn a_fetch_refuses_a_replay_and_keeps_the_cache_until_a_whole_index_verifies() {
        let cat = catalog();
        let (one, _) = built(cat.path(), None);
        sign(one.path(), &SEED, None, NOW).expect("signed");
        let key = public_key(&SEED);
        let bytes = std::fs::read(one.path().join(index::FILE)).expect("index");
        let sig = std::fs::read_to_string(one.path().join(index::SIGNATURE_FILE)).expect("sig");

        assert!(accept(&bytes, &sig, "community", &key, None).is_ok());
        assert!(
            accept(&bytes, &sig, "community", &key, Some(1)).is_ok(),
            "the same one"
        );
        assert!(matches!(
            accept(&bytes, &sig, "community", &key, Some(2)),
            Err(Error::Replayed {
                seen: 2,
                counter: 1
            })
        ));
        let idx = accept(&bytes, &sig, "community", &key, None).expect("accepted");
        let wanted = files(&idx).expect("files");
        assert!(
            wanted.iter().all(|(p, d)| holds(one.path(), p, d)),
            "every file is where the index says"
        );

        // A staged copy with one file changed in transit leaves the cache as it was.
        let root = tempfile::tempdir().expect("root");
        let cache = root.path().join("community");
        let copy = |to: &Path| {
            assert!(std::process::Command::new("cp")
                .arg("-r")
                .arg(one.path())
                .arg(to)
                .status()
                .expect("cp")
                .success());
        };
        copy(&cache);
        let staged = root.path().join("community.new");
        copy(&staged);
        let (rel, _) = &wanted[0];
        std::fs::write(staged.join(rel), b"changed").expect("changed");
        assert!(matches!(
            swap_in(&staged, &cache, "community", &key),
            Err(Error::FileChanged { .. })
        ));
        assert!(
            verify(&cache, "community", &key).is_ok(),
            "the cache is untouched"
        );

        std::fs::remove_dir_all(&staged).expect("cleared");
        copy(&staged);
        swap_in(&staged, &cache, "community", &key).expect("swapped");
        assert!(!staged.exists() && !cache.with_extension("old").exists());
        assert!(verify(&cache, "community", &key).is_ok());
    }
}
