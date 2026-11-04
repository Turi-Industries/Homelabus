#!/usr/bin/env bash
#
# Goal 3, as a theft: what a node's disk gives up away from the house, on the lab's two
# encrypted nodes. enc2 is at level B and enc3 at A, each bound to its TPM AND a Tang on
# deb1, deb2 or the other one. It writes these rows of docs/measures.tsv:
#
#   stolen-<node>-no-tang      closed|OPEN   no Tang reachable, its own TPM
#   stolen-enc2-other-tpm      closed|OPEN   Tangs reachable, another TPM
#   stolen-reopen-seconds      seconds for enc2 to open once one Tang is back
#   node-levels                how many nodes `hlb cluster status` reads at each level
#
# 🔴 Each node first opens at home, and enc2 opens again once a Tang returns. Without
# those a dead VM, a wrong IP or a broken SSH key would all read as "closed".
#
# A virtual machine always reads level D, so node-levels stays there on the lab however
# strong its disk's binding is. It is the theft rows that say what the binding gives.
#
# Not here: enc3 booted through GRUB instead of its signed image, which takes the
# firmware's menu by key presses and was proven by hand on 2026-10-29.
#
# Usage: scripts/drills/stolen.sh [--no-record]    with deb1 and deb2 up, enc2 and enc3 off

set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

record=1
[[ ${1:-} == --no-record ]] && record=0

hlb_on_deb1=${LAB_HLB:-/root/lab-044/hlb}
enc2=10.77.0.19
enc3=10.77.0.17
wait_closed=120
wait_open=240

lab() { docker exec -i hlb-lab "$@"; }
now() { date +%s; }

tangs() {
    lab /lab/vm.sh ssh deb1 "systemctl $1 tangd.socket"
    lab /lab/vm.sh ssh deb2 "systemctl $1 tangd.socket"
}

# The system's own SSH only: the initrd's is on 2222, and answers while the disk is shut.
opened() { lab /lab/vm.sh ssh "$1" cat /proc/uptime >/dev/null 2>&1; }

waits_for() {
    local ip=$1 limit=$2 start
    start=$(now)
    while (($(now) - start < limit)); do
        if opened "$ip"; then
            echo $(($(now) - start))
            return 0
        fi
        sleep 4
    done
    return 1
}

running() { lab sh -c "[ -f /vms/$1/qemu.pid ] && ps -o stat= -p \$(cat /vms/$1/qemu.pid) 2>/dev/null | grep -qv Z"; }

# A power cut: a node waiting at its prompt has no system left to shut it down cleanly.
cut_power() {
    lab sh -c "echo quit | socat - UNIX-CONNECT:/vms/$1/monitor.sock" >/dev/null 2>&1 || true
    for _ in $(seq 1 15); do running "$1" || return 0; sleep 1; done
    echo "$1 still runs after a power cut" >&2
    exit 1
}

shut_down() {
    lab /lab/vm.sh ssh "$2" systemctl poweroff >/dev/null 2>&1 || true
    for _ in $(seq 1 60); do running "$1" || return 0; sleep 2; done
    cut_power "$1"
}

boot_enc2() {
    lab sh -c 'ip tuntap add dev tap19 mode tap 2>/dev/null; true'
    lab sh "/lab/enc/${1:-boot-enc2.sh}"
}
# The IOMMU the node was verified with: without it `verify-boot` warns, and the drill
# would be testing another machine than the one proven.
boot_enc3() { lab env QEMU_EXTRA="-machine kernel-irqchip=split -device intel-iommu,intremap=on" sh /lab/enc/uefi.sh boot; }

# Whatever stopped the drill, the house gets its Tangs back: its nodes need them to boot.
trap 'tangs start || true' EXIT

running enc2 && { echo "enc2 is running: this drill boots it" >&2; exit 1; }
running enc3 && { echo "enc3 is running: this drill boots it" >&2; exit 1; }
tangs start

# enc2 ----------------------------------------------------------------------------------
echo "enc2 at home"
boot_enc2
at_home=$(waits_for "$enc2" "$wait_open") || { echo "enc2 did not open at home: the drill proves nothing" >&2; exit 1; }
echo "  opened alone in ${at_home} s"
shut_down enc2 "$enc2"

echo "enc2 on another TPM, the Tangs reachable"
lab sh -c 'rm -rf /vms/enc2/tpm-other; mkdir /vms/enc2/tpm-other'
boot_enc2 boot-enc2-other-tpm.sh
if waits_for "$enc2" "$wait_closed" >/dev/null; then other_tpm=OPEN; else other_tpm=closed; fi
echo "  after ${wait_closed} s: $other_tpm"
cut_power enc2
lab rm -rf /vms/enc2/tpm-other

echo "enc2 with no Tang"
tangs stop
boot_enc2
if waits_for "$enc2" "$wait_closed" >/dev/null; then enc2_no_tang=OPEN; else enc2_no_tang=closed; fi
echo "  after ${wait_closed} s: $enc2_no_tang"
tangs start
reopen=$(waits_for "$enc2" "$wait_open") || { echo "enc2 did not open once a Tang returned" >&2; exit 1; }
echo "  a Tang back: opened in ${reopen} s"
shut_down enc2 "$enc2"

# enc3 ----------------------------------------------------------------------------------
echo "enc3 at home"
boot_enc3
at_home3=$(waits_for "$enc3" "$wait_open") || { echo "enc3 did not open at home: the drill proves nothing" >&2; exit 1; }
echo "  opened alone in ${at_home3} s"
shut_down enc3 "$enc3"

echo "enc3 with no Tang"
tangs stop
boot_enc3
if waits_for "$enc3" "$wait_closed" >/dev/null; then enc3_no_tang=OPEN; else enc3_no_tang=closed; fi
echo "  after ${wait_closed} s: $enc3_no_tang"
cut_power enc3
tangs start

# Levels --------------------------------------------------------------------------------
version=$(lab /lab/vm.sh ssh deb1 "$hlb_on_deb1 --version" | awk '{print $2}')
levels=$(lab /lab/vm.sh ssh deb1 "cd /root; HLB_STATE=/var/lib/homelabus/hlb.db HLB_MASTER_KEY=/root/hlb-master.key $hlb_on_deb1 cluster status" \
    | awk '$2 ~ /^(manager|worker)$/ || $3 ~ /^(manager|worker)$/ {
               for (i = 2; i < NF; i++) if ($i ~ /^[A-D]$/ && $(i+1) ~ /^[0-9?]/) n[$i]++
           }
           END { for (l in n) printf "%s:%d ", l, n[l] }')
levels=${levels% }
[[ -n $levels ]] || { echo "no level read from cluster status" >&2; exit 1; }

echo
echo "hlb $version: enc2 no Tang $enc2_no_tang, other TPM $other_tpm; enc3 no Tang $enc3_no_tang; reopened in ${reopen} s; levels $levels"
if ((record)); then
    scripts/measure.sh stolen-enc2-no-tang "$enc2_no_tang" "$version" "level B node; ${wait_closed} s; opened alone at home first"
    scripts/measure.sh stolen-enc2-other-tpm "$other_tpm" "$version" "Tangs reachable; ${wait_closed} s"
    scripts/measure.sh stolen-enc3-no-tang "$enc3_no_tang" "$version" "level A node; ${wait_closed} s; opened alone at home first"
    scripts/measure.sh stolen-reopen-seconds "$reopen" "$version" "enc2, one Tang back"
    scripts/measure.sh node-levels "$levels" "$version" "lab: virtual machines read D by design"
fi
