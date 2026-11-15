# The lab

One privileged container, `hlb-lab`, holding the house's network and its VMs, and a
VPS on the Docker network `hlb-internet` — the internet the house reaches through NAT.
The drills (`scripts/drills/`) drive it through `/lab/vm.sh` and `/lab/vps.sh`.

```
host 10.99.0.1 ── hlb-internet 10.99.0.0/24 ── vps1 10.99.0.40
                        │
                  hlb-lab 10.99.0.2  (NAT, dnsmasq)
                        │
                  br0 10.77.0.0/24 ── deb1 .11, deb2 .12
```

From the house's side only replies come in, and the ACME authority on deb2 (`:9000`),
which plays Let's Encrypt for the VPS.

## The machines

```sh
export HLB_LAB_DIR=/path/with/space        # disks and the lab's key; ~/.local/share/hlb-lab
scripts/lab/lab.sh up                      # image, network, container, br0
docker exec hlb-lab /lab/vps.sh up vps1 40 4096
docker exec hlb-lab /lab/vm.sh up deb1 11 debian-12 4096 2
docker exec hlb-lab /lab/vm.sh up deb2 12 debian-12 4096 2
scripts/lab/lab.sh off                     # every VM powered off, then the container
scripts/lab/lab.sh boot                    # later: vps1 first, then the house
```

The container mounts the whole repository, read-only: a container made before
2026-11-15 mounts `scripts/lab` alone, which a checkout without it leaves stale — `lab.sh
off`, `docker rm hlb-lab`, `lab.sh build`, `lab.sh boot` (the disks stay in
`HLB_LAB_DIR`). Until then, `docker cp scripts/lab/. hlb-lab:/lab/src-copy` and point
`/lab/vm.sh` and `/lab/vps.sh` at the copy.

## The house, as it was rebuilt on 2026-11-15

`hlb` built for Debian 12 (`rust:1.99-bookworm`, `cargo build --release -p hlb-cli`),
installed as `/usr/local/bin/hlb` on deb1 and deb2. On deb1, `/root/hlb.sh` runs it on
the lab's state (`HLB_STATE=/var/lib/homelabus/hlb.db`,
`HLB_MASTER_KEY=/etc/homelabus/hlb-master.key`); deb1's SSH key is authorised on deb2
and vps1.

```sh
hlb cluster init --endpoint 10.77.0.11 --apply
hlb node add 10.77.0.12 --identity /root/.ssh/id_ed25519 --apply
hlb node tier deb1 --set heavy --apply; hlb node tier deb2 --set heavy --apply
# deb2: /root/step-ca-run.sh — smallstep/step-ca on :9000, ACME provisioner `acme`,
# each name of /root/step-ca-hosts pinned with --add-host (to the door, 10.99.0.40)
hlb config exposure --domain lab.test --email owner@lab.test --dns none --node deb1 \
    --acme-ca https://10.77.0.12:9000/acme/acme/directory --acme-ca-root /root/root_ca.crt --apply
hlb install caddy --apply; hlb install postgres --apply; hlb install stalwart --apply
hlb install pocket-id --apply
hlb ack vaultwarden/dns-record --force; hlb install vaultwarden --apply
# a restic rest-server on deb1, 10.77.0.11:8000
hlb backup dest add rest --location rest:http://10.77.0.11:8000/ --classes critical,bulky
hlb backup run
hlb site add 10.99.0.40 --identity /root/.ssh/id_ed25519 --apply
hlb site sync --apply
hlb site lifeboat --apply
```

⚠️ Vaultwarden's catalog manifest cannot declare `lifeboat` until a release reads it, so
the lifeboat refuses it. The lab runs a copy of the catalog (`HLB_CATALOG=/root/lab-catalog`
on deb1) where it declares `lifeboat: { returns: whole }` with `hlb: ">=0.4.9"`, taken
by `hlb upgrade vaultwarden`.

⚠️ After each boot of vps1: `ip route replace 10.77.0.12/32 via 10.99.0.2` (`lab.sh
boot` does it), or the site's Caddy reaches no authority when promoted.
