//! Every image a program runs is pinned by its digest.
//!
//! The catalog's images are held by `catalog validate`. The ones Homelabus starts
//! itself — restic for every backup, the PostgreSQL and MariaDB clients for every dump,
//! a `docker` CLI on every node, the relay `hlb` opens to reach the overlay — sit in the
//! sources as string literals, and `restic/restic:latest` was four of them: every backup
//! ran whatever restic Docker Hub served that day, each node its own. The images built
//! here are pinned by what they are built from, the `Dockerfile`'s bases.
//!
//! The literals are found by their SHAPE, from every source walked: a list of the
//! constants would be one more list in this repository to drift.

mod scan;

use std::path::Path;

use scan::{crates_root, rust_files, short, split};

/// Literals of an image's shape that are not images, each with why.
const NOT_IMAGES: &[(&str, &str)] = &[("ec_paramgen_curve:P-256", "an openssl option")];

/// restic's snapshot tags are `kind:<what>` (`kind:pre-update`, `kind:sql-dump`…): a
/// shape of their own, not an image named `kind`.
fn restic_tag(s: &str) -> bool {
    s.starts_with("kind:")
}

/// A digest alone (`sha256:<hex>`, compared against what an installed app runs) has
/// the shape of an image named `sha256`, and is no image.
fn bare_digest(s: &str) -> bool {
    s.strip_prefix("sha256:")
        .is_some_and(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// Is this literal shaped like an image reference — `name:tag`, with or without a
/// registry and a path — rather than a URL or a `host:port`?
fn image_shaped(s: &str) -> bool {
    let name = |p: &str| {
        !p.is_empty()
            && p.split(['.', '_', '-']).all(|w| {
                !w.is_empty()
                    && w.bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
            })
    };
    let (body, digest) = match s.split_once('@') {
        Some((b, d)) => (b, Some(d)),
        None => (s, None),
    };
    if digest.is_some_and(|d| !d.starts_with("sha256:")) {
        return false;
    }
    let Some((path, tag)) = body.rsplit_once(':') else {
        return false;
    };
    let tag_ok = !tag.is_empty()
        && tag
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        // A port is digits alone.
        && !tag.bytes().all(|b| b.is_ascii_digit());
    let mut segments = path.split('/');
    let first = segments.next().unwrap_or_default();
    let registry = first.contains('.') && path.contains('/');
    tag_ok && segments.all(name) && (registry || name(first))
}

fn pinned(s: &str) -> bool {
    s.split_once("@sha256:")
        .is_some_and(|(_, h)| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()))
}

#[test]
fn every_image_a_program_runs_is_pinned() {
    let mut found = 0;
    let mut unpinned: Vec<String> = Vec::new();
    for file in rust_files(&crates_root()) {
        if file.components().any(|c| c.as_os_str() == "tests") {
            continue;
        }
        let source = std::fs::read_to_string(&file).unwrap_or_default();
        let production = source.split("\n#[cfg(test)]").next().unwrap_or("");
        for value in split(production).1 {
            if !image_shaped(&value)
                || restic_tag(&value)
                || bare_digest(&value)
                || NOT_IMAGES.iter().any(|(n, _)| *n == value)
            {
                continue;
            }
            found += 1;
            if !pinned(&value) {
                unpinned.push(format!("{}: {value}", short(&file)));
            }
        }
    }
    // Restic, the two dump clients, the Docker CLI, the relay and the SMTP trial: a
    // scan that stopped recognising them would pass on nothing.
    assert!(found >= 6, "only {found} images found in the sources");
    unpinned.sort();
    assert!(
        unpinned.is_empty(),
        "images run by their tag alone — `repo:tag@sha256:…`, the digest the tag names \
         today:\n  {}",
        unpinned.join("\n  ")
    );
}

#[test]
fn every_base_an_image_is_built_from_is_pinned() {
    let root = crates_root()
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_default();
    let dockerfile = std::fs::read_to_string(root.join("Dockerfile")).expect("the Dockerfile");
    let mut stages: Vec<String> = Vec::new();
    let mut bases = 0;
    let mut unpinned = Vec::new();
    for line in dockerfile.lines() {
        let words: Vec<&str> = line.split_whitespace().collect();
        let (image, stage) = match words.as_slice() {
            ["FROM", image, "AS", stage] => (*image, Some(*stage)),
            ["FROM", image, ..] => (*image, None),
            ["COPY", from, ..] if from.starts_with("--from=") => (&from["--from=".len()..], None),
            _ => continue,
        };
        // A stage of this file, built above it.
        if !stages.iter().any(|s| s == image) {
            bases += 1;
            if !pinned(image) {
                unpinned.push(line.trim().to_string());
            }
        }
        stages.extend(stage.map(str::to_string));
    }
    assert!(bases >= 5, "only {bases} bases read in the Dockerfile");
    assert!(
        unpinned.is_empty(),
        "bases by their tag alone:\n  {}",
        unpinned.join("\n  ")
    );
}

#[test]
fn the_shape_tells_an_image_from_its_neighbours() {
    for image in [
        "postgres:17-alpine",
        "restic/restic:0.19.1",
        "ghcr.io/immich-app/postgres:17-vectorchord0.4.3-pgvector0.8.0",
        "curlimages/curl:8.11.1@sha256:c1fe1679c34d9784c1b0d1e5f62ac0a79fca01fb6377cdd33e90473c6f9f9a69",
    ] {
        assert!(image_shaped(image), "{image}");
    }
    for other in [
        "postgres:5432",
        "https://ghcr.io/v2/",
        "{}:{}",
        "a b:c",
        "Content-Type:text",
    ] {
        assert!(!image_shaped(other), "{other}");
    }
}
