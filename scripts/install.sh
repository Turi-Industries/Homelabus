#!/bin/sh
#
# Installs `hlb` from a release, and runs nothing it downloaded before checking it:
#
#   curl -fsSL https://github.com/Turi-Industries/Homelabus/releases/latest/download/install.sh | sh
#
# 1. cosign, itself checked against the checksum written below, verifies the keyless
#    signature of SHA256SUMS: made by this repository's release workflow, on a version
#    tag, through GitHub's identity — there is no signing key anyone could lose or leak.
# 2. The binary is checked against SHA256SUMS.
# Only then is it installed.
#
#   HLB_VERSION=v0.3.0         a given release rather than the latest
#   HLB_INSTALL_DIR=~/.local/bin   where it goes (default /usr/local/bin)
#   HLB_RELEASE_URL=…          where the release's files are, for a mirror or a test;
#                              the signature is still required to be this repository's
#
# Published with each release by `.github/workflows/release.yml`, which tries it.

set -eu

REPO=Turi-Industries/Homelabus
VERSION=${HLB_VERSION:-latest}
DIR=${HLB_INSTALL_DIR:-/usr/local/bin}

# Moving cosign is moving the trust anchor: take the new checksums from the release's
# `cosign_checksums.txt`, and its build must be a week old like any image here.
COSIGN_VERSION=v3.1.4
COSIGN_SHA256_amd64=424e2c97d0b45fd7a6b608a87f090f35633f4c23ece5f092d48bba11aaf4bbfa
COSIGN_SHA256_arm64=ade83b7aac62e131cacfe96d958948b2150cc9efec46a570a2649b8e27dedad2

# The workflow's path and a `v` tag, not any workflow of the repository: a branch's run
# of another file could otherwise sign a binary.
IDENTITY="^https://github\.com/$REPO/\.github/workflows/release\.yml@refs/tags/v"
ISSUER=https://token.actions.githubusercontent.com

die() {
    echo "hlb install: $*" >&2
    exit 1
}

[ "$(uname -s)" = Linux ] || die "Linux only: $(uname -s) has no release build"
case "$(uname -m)" in
    x86_64 | amd64) target=x86_64-unknown-linux-musl cosign_arch=amd64 ;;
    aarch64 | arm64) target=aarch64-unknown-linux-musl cosign_arch=arm64 ;;
    *) die "no release build for $(uname -m)" ;;
esac
command -v curl >/dev/null || die "curl is needed"

if command -v sha256sum >/dev/null; then
    sha256() { sha256sum "$1" | cut -d' ' -f1; }
elif command -v shasum >/dev/null; then
    sha256() { shasum -a 256 "$1" | cut -d' ' -f1; }
else
    die "sha256sum or shasum is needed"
fi

if [ -n "${HLB_RELEASE_URL:-}" ]; then
    base=$HLB_RELEASE_URL
elif [ "$VERSION" = latest ]; then
    base=https://github.com/$REPO/releases/latest/download
else
    base=https://github.com/$REPO/releases/download/$VERSION
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM
fetch() {
    curl -fsSL --retry 3 -o "$tmp/$2" "$1" || die "could not download $1"
}

fetch "https://github.com/sigstore/cosign/releases/download/$COSIGN_VERSION/cosign-linux-$cosign_arch" cosign
eval "expected=\$COSIGN_SHA256_$cosign_arch"
[ "$(sha256 "$tmp/cosign")" = "$expected" ] || die "cosign does not match its checksum: refusing to use it"
chmod +x "$tmp/cosign"

fetch "$base/SHA256SUMS" SHA256SUMS
fetch "$base/SHA256SUMS.sigstore.json" SHA256SUMS.sigstore.json
"$tmp/cosign" verify-blob \
    --bundle "$tmp/SHA256SUMS.sigstore.json" \
    --certificate-identity-regexp "$IDENTITY" \
    --certificate-oidc-issuer "$ISSUER" \
    "$tmp/SHA256SUMS" >/dev/null 2>"$tmp/cosign.log" ||
    die "SHA256SUMS is not signed by $REPO's release workflow: $(cat "$tmp/cosign.log")"

fetch "$base/hlb-$target" hlb
expected=$(awk -v f="hlb-$target" '$2 == f || $2 == "*" f { print $1 }' "$tmp/SHA256SUMS")
[ -n "$expected" ] || die "SHA256SUMS names no hlb-$target"
[ "$(sha256 "$tmp/hlb")" = "$expected" ] || die "hlb-$target does not match SHA256SUMS: refusing to install it"
chmod +x "$tmp/hlb"

mkdir -p "$DIR" 2>/dev/null || true
[ -w "$DIR" ] || die "$DIR is not writable: run it with sudo, or set HLB_INSTALL_DIR"
mv "$tmp/hlb" "$DIR/hlb"
echo "hlb installed in $DIR, its signature and checksum verified: $("$DIR/hlb" --version)"
