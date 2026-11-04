#!/usr/bin/env bash
#
# Goal 2, as the house sees it: how many of the lab's apps had their backups read back,
# and read good, in the last 30 days. It reads `hlb backup status` and starts nothing: what
# it counts is what the daemon did, or what someone ran. One row of docs/measures.tsv:
#
#   restores-read-back   "<read> of <holding data>"
#
# ⚠️ Read back means restored and counted, never started: a store copied live passes.
#
# Usage: scripts/drills/restores.sh [--no-record]    with deb1 and deb2 up

set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

record=1
[[ ${1:-} == --no-record ]] && record=0

hlb_on_deb1=${LAB_HLB:-/root/lab-045/hlb}
hlb() {
    docker exec -i hlb-lab /lab/vm.sh ssh deb1 \
        "cd /root; HLB_STATE=/var/lib/homelabus/hlb.db HLB_MASTER_KEY=/root/hlb-master.key $hlb_on_deb1 $*"
}

version=$(hlb --version | awk '{print $2}')
# Columns are at least two spaces apart, and an age holds one: "12 min". An app line starts
# in the first column; a destination's detail below it is indented.
read -r good held < <(hlb backup status | awk -F'  +' '
    /^[a-z]/ && NR > 1 {
        if ($2 == "-" && $3 == "-") next
        held++
        split($3, age, " ")
        recent = (age[2] == "s" || age[2] == "min" || age[2] == "h" || (age[2] == "d" && age[1] <= 30))
        if (recent) good++
    }
    END { print good + 0, held + 0 }')
# 🔴 Nothing read is not "0 of 0": a change of the table's shape would pass as an empty house.
((held > 0)) || { echo "no app with data read from backup status" >&2; exit 1; }

echo "hlb $version: $good of $held read back in the last 30 days"
if ((record)); then
    scripts/measure.sh restores-read-back "$good of $held" "$version" "the lab's own backups; restored and counted, never started"
fi
