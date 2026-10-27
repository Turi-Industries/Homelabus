#!/usr/bin/env bash
#
# Give a worktree its own `target/`, seeded from the main checkout's by reflink.
#
# 🔴 Why never share one: cargo names a workspace crate's artifacts by a hash of its path
# RELATIVE to the workspace, so two checkouts write the same files — and it judges a
# path crate fresh by mtimes, so whichever checkout built last silently supplies the
# other's crates. On 2026-10-27 a worktree's `hlb-guide` compiled against the main
# checkout's newer `hlb-api` ("missing field `fix`"); the reverse, a test suite passing
# on another checkout's code, says nothing at all.
#
# Why a reflink: `target/` is 84 GB on a disk 87 % full. A reflink copy shares the blocks
# until one side rewrites them, so the copy costs metadata, the third-party crates are
# reused as built, and only this checkout's own crates take new space. `incremental/` is
# left behind — 56 GB of caches that only speed the first rebuild.
#
# On a filesystem without reflinks nothing is copied: the first build is cold, and big.
#
# Usage: scripts/worktree-target.sh [worktree]   (idempotent; the main checkout is a no-op)

set -uo pipefail

tree=$(git -C "${1:-.}" rev-parse --show-toplevel) || exit 1
main=$(git -C "$tree" rev-parse --path-format=absolute --git-common-dir) || exit 1
main=${main%/.git}
[[ $tree != "$main" ]] || exit 0

# A symlink to the main checkout's target is the shared setup this replaces.
[[ -L $tree/target ]] && rm "$tree/target"
[[ -e $tree/target ]] && exit 0
[[ -d $main/target/debug ]] || exit 0

mkdir -p "$tree/target/debug"
for part in deps build .fingerprint; do
    [[ -e $main/target/debug/$part ]] || continue
    if ! cp -a --reflink=always "$main/target/debug/$part" "$tree/target/debug/" 2>/dev/null; then
        rm -rf "$tree/target"
        mkdir -p "$tree/target"
        echo "worktree-target: this filesystem cannot reflink; $tree/target starts empty, and its first build is a full one" >&2
        exit 0
    fi
done

# The copied artifacts are the main checkout's crates. Make this checkout's sources newer
# than all of them, so each workspace crate is rebuilt from its own code once.
for krate in "$tree"/crates/*/; do
    for root in src/lib.rs src/main.rs; do
        [[ -f $krate$root ]] && touch "$krate$root"
    done
done
echo "worktree-target: $tree/target seeded by reflink from the main checkout's"
