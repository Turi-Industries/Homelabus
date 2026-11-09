# The node agent, the controller and the ingress, built from this repository.
#
#   docker build --target agent      -t <registry>/hlb-agent:<version> .
#   docker build --target controller -t <registry>/hlb-controller:<version> .
#   docker build --target caddy      -t <registry>/hlb-caddy:<version> .
#
# Then `hlb fleet agent --image …` and `hlb fleet controller --image …`; the ingress is
# the catalog's `caddy`, installed like any platform service.
#
# Every base by its digest: these images carry no digest of their own until a release
# has built them (`builtHere` in the catalog), so what pins them is what they are built
# from. The tag stays beside it, for whoever reads which version it is.

# Caddy with the DNS modules a wildcard certificate needs, the CrowdSec bouncer, and the
# rate limit an app's `authRoutes` are held to: a standard image refuses to start on
# `dns <provider>`, `crowdsec` or `rate_limit`. Every provider
# `hlb_ingress::dns::PROVIDERS` offers is compiled in here, and a test holds the two
# together — a provider offered and not built would be refused by Caddy at reload.
FROM caddy:2.11.7-builder-alpine@sha256:95a5e7e2692b5eb9545aadc5b90a39f6f509bee59c9508a493f83ee902eaef63 AS caddy-build
RUN xcaddy build v2.11.4 \
    --with github.com/caddy-dns/cloudflare@v0.2.4 \
    --with github.com/caddy-dns/desec@v1.1.0 \
    --with github.com/caddy-dns/duckdns@v0.5.0 \
    --with github.com/caddy-dns/gandi@v1.1.0 \
    --with github.com/caddy-dns/hetzner/v2@v2.0.1 \
    --with github.com/caddy-dns/ovh@v1.1.0 \
    --with github.com/caddy-dns/porkbun@v0.3.1 \
    --with github.com/hslatman/caddy-crowdsec-bouncer/http@v0.14.1 \
    --with github.com/mholt/caddy-ratelimit@v0.1.0

FROM caddy:2.11.7-alpine@sha256:eb4d35b7452d1ab6171fbdbe8d9275b2301dad6dad92115d91e19fb9b24d510f AS caddy
COPY --from=caddy-build /usr/bin/caddy /usr/bin/caddy

FROM rust:1.99-bookworm@sha256:48b7f435b8fc6378ce43b44f15e3a47fd8919b2825f835c39bd4bd3da50af5b8 AS build
WORKDIR /src
COPY . .
# The commit the interface's source link names (AGPL §13); unset, this version's tag.
ARG HLB_SOURCE
RUN cargo build --release --locked -p hlb-agent -p hlb-controller -p hlb-cli

# The same Bun as the lockfile was written with: an older one refuses the format.
FROM oven/bun:1.4.4@sha256:1d22548f177f4ff38e0c15baa3c2c46c6c2060ba2d1bc573bb4720b407548f1d AS web
WORKDIR /src/web
COPY web/ ./
RUN bun install --frozen-lockfile && bun run build

FROM debian:bookworm-slim@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8 AS base
# ca-certificates for the registries and S3; coreutils (`df`) ships with the image.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*

FROM base AS agent
COPY --from=build /src/target/release/hlb-agent /usr/local/bin/hlb-agent
# Unprivileged: the host's root is mounted read-only, and everything the agent reads
# there — /proc, df, os-release, hostname — is world-readable.
USER 65534:65534
ENTRYPOINT ["hlb-agent"]

FROM base AS controller
# openssl: the controller issues the fleet's mTLS leaves again before they end
# (`hlb_engine::pki`), through the same tool `hlb` made them with.
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssl \
 && rm -rf /var/lib/apt/lists/*
# The Docker CLI: backups and dumps run in containers it starts. A static binary,
# taken from Docker's own image rather than a distribution's lagging package.
COPY --from=docker:29.9-cli@sha256:5e6baf67325a79f64ed3bed6863954d5e05d0f3d4e57cbdb14809346814bbfdb /usr/local/bin/docker /usr/local/bin/docker
COPY --from=build /src/target/release/hlb-controller /usr/local/bin/hlb-controller
# The daemon, run from the same image: `hlb fleet controller` gives its service the
# command `hlb-privd`, and the web side's the entrypoint below.
COPY --from=build /src/target/release/hlb-privd /usr/local/bin/hlb-privd
COPY --from=web /src/web/build /usr/share/hlb/ui
# The catalog it installs from: without it the interface says installing is unavailable.
COPY catalog /usr/share/hlb/catalog
ENV HLB_UI_DIR=/usr/share/hlb/ui \
    HLB_CATALOG=/usr/share/hlb/catalog \
    HLB_LISTEN=0.0.0.0:8420
ENTRYPOINT ["hlb-controller"]
