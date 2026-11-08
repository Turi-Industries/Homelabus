# NUT's server with its dummy driver, for `tests/live_nut.rs`: a UPS whose status the
# test sets (`upsrw`, the `admin` account below — the test's, never Homelabus's, which
# only reads), and `monitor`, the account a node's upsmon signs in with.
#
#   docker build -t hlb-nut-dummy:test crates/hlb-engine/tests/data/nut
#   docker run -d --name hlb-nut -p 127.0.0.1:13493:3493 hlb-nut-dummy:test
FROM debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587
RUN apt-get update && apt-get install -y --no-install-recommends nut-server nut-client \
 && rm -rf /var/lib/apt/lists/*
# ⚠️ NUT 2.8's dummy-ups reads its .dev file ONCE: a status changes through upsrw.
RUN printf 'MODE=netserver\n' > /etc/nut/nut.conf \
 && printf '[house]\n  driver = dummy-ups\n  port = house.dev\n  desc = "dummy"\n' > /etc/nut/ups.conf \
 && printf 'LISTEN 0.0.0.0 3493\n' > /etc/nut/upsd.conf \
 && printf '[admin]\n  password = adminpw\n  actions = SET\n[monitor]\n  password = mon-pass.2\n  upsmon secondary\n' > /etc/nut/upsd.users \
 && printf 'ups.status: OL\nbattery.charge: 100\nbattery.runtime: 1800\nups.mfr: Dummy\n' > /etc/nut/house.dev \
 && chown -R nut:nut /etc/nut
CMD ["sh", "-c", "/usr/sbin/upsdrvctl start && /usr/sbin/upsd && sleep infinity"]
