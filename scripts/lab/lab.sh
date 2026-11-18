#!/usr/bin/env bash
#
# The lab, from the host: the `hlb-lab` container and the `hlb-internet` network it plays
# the internet on. The VMs inside are scripts/lab/vm.sh's.
#
#   scripts/lab/lab.sh up      build the image if missing, start the container, its network
#   scripts/lab/lab.sh boot    up, then the router (opn1), the VPS (vps1) and the house
#   scripts/lab/lab.sh off     every VM powered off cleanly, then the container stopped
#   scripts/lab/lab.sh build   rebuild the image (the scripts are mounted: edits need none)
#
# HLB_LAB_DIR (default ~/.local/share/hlb-lab) holds the disks, the base images and the
# lab's SSH key, outside the container: the lab was lost once with a reinstalled Docker,
# and with it every VM. Recreating the container keeps them.

set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")"

dir=${HLB_LAB_DIR:-$HOME/.local/share/hlb-lab}
lab() { docker exec -i hlb-lab "$@"; }

build() { docker build -q -t hlb-lab . >/dev/null; }

up() {
    docker image inspect hlb-lab >/dev/null 2>&1 || build
    docker network inspect hlb-internet >/dev/null 2>&1 ||
        docker network create --subnet 10.99.0.0/24 --gateway 10.99.0.1 hlb-internet >/dev/null
    if ! docker container inspect hlb-lab >/dev/null 2>&1; then
        mkdir -p "$dir"
        # --init: qemu daemonizes, and its zombies would otherwise outlive every VM.
        # --dns: Docker's default forwards to the host's resolver, which a host may serve
        # on docker0 only; the lab's internet asks the internet's.
        docker run -d --name hlb-lab --hostname hlb-lab --init --privileged \
            --device /dev/kvm --network hlb-internet --ip 10.99.0.2 \
            --dns 1.1.1.1 --dns 9.9.9.9 \
            -v "$dir:/vms" -v "$(git rev-parse --show-toplevel):/lab/repo:ro" hlb-lab >/dev/null
    else
        docker start hlb-lab >/dev/null
    fi
    lab /lab/vm.sh net
}

boot() {
    up
    # The router before all: once made, it is the house's way out.
    if lab test -f /vms/opn1/bootstrapped; then lab /lab/router.sh up; fi
    # The VPS next: deb1's site guard runs 30 s after boot, and a link that never
    # handshook stops the vital apps until it does.
    lab /lab/vps.sh up vps1 2>/dev/null || echo "vps1 not made yet: /lab/vps.sh up vps1 40 4096"
    lab /lab/vm.sh up deb1 2>/dev/null || echo "deb1 not made yet"
    lab /lab/vm.sh up deb2 2>/dev/null || echo "deb2 not made yet"
    local vm
    for vm in vps1 deb1 deb2; do lab test -f "/vms/$vm/vm.conf" && lab /lab/vm.sh wait "$vm" 300; done
    # Lost at each of its boots: the VPS reaches the lab's ACME authority as it would
    # reach Let's Encrypt.
    lab /lab/vm.sh ssh vps1 ip route replace 10.77.0.12/32 via 10.99.0.2 2>/dev/null || true
}

off() {
    docker container inspect hlb-lab >/dev/null 2>&1 || return 0
    local vm
    for vm in $(lab /lab/vm.sh ls | awk '$3 == "up" {print $1}'); do lab /lab/vm.sh down "$vm"; done
    # Not in vm.sh's list, and a router killed with the container does not boot again.
    lab /lab/router.sh down
    docker stop hlb-lab >/dev/null
}

case ${1:-} in
    up) up ;;
    boot) boot ;;
    off) off ;;
    build) build ;;
    *) sed -n '3,9p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
