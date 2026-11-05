#!/usr/bin/env bash
#
# Goal 6, as far as it can be counted today: how long the lab's updates took from first seen
# to applied, and what still waits. It reads `hlb update lag` and applies nothing. One row of
# docs/measures.tsv:
#
#   updates-lag   "<n> applied, the slowest in <d> d; <n> waiting, the oldest for <d> d"
#
# ⚠️ Every update, not a security fix's: nothing here knows which is one before phase 5
# brings CVE data. And the lab applies what someone tells it to, so what it says is how long
# a person took, the automatic path of phase 5 not existing yet.
#
# Usage: scripts/drills/updates.sh [--no-record]    with deb1 and deb2 up

set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

record=1
[[ ${1:-} == --no-record ]] && record=0

hlb_on_deb1=${LAB_HLB:-/root/lab-046/hlb}
hlb() {
    docker exec -i hlb-lab /lab/vm.sh ssh deb1 \
        "cd /root; HLB_STATE=/var/lib/homelabus/hlb.db HLB_MASTER_KEY=/root/hlb-master.key $hlb_on_deb1 $*"
}

version=$(hlb --version | awk '{print $2}')
lag=$(hlb update lag | tail -1)
# 🔴 A changed report must stop here: recorded, it would read as a measure.
[[ $lag =~ ^[0-9]+\ applied,\ the\ slowest\ in\ [0-9]+\ d\;\ [0-9]+\ waiting,\ the\ oldest\ for\ [0-9]+\ d$ ]] ||
    { echo "unreadable: $lag" >&2; exit 1; }

echo "hlb $version: $lag"
if ((record)); then
    scripts/measure.sh updates-lag "$lag" "$version" "the lab, every update and not a fix's, applied by a person"
fi
