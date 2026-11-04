#!/usr/bin/env bash
#
# Appends one result to docs/measures.tsv, which `scripts/scorecard.sh` reads. Only the
# drills call this: a figure typed by hand is a claim, and a figure with no release
# beside it cannot say it has gone stale.
#
# Usage: scripts/measure.sh <measure> <value> <hlb version> [note]

set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

[[ $# -ge 3 ]] || { echo "usage: $0 <measure> <value> <hlb version> [note]" >&2; exit 2; }
# A tab or a newline in a note would shift every later column of the row.
note=$(tr '\t\n' '  ' <<<"${4:-}")
printf '%s\t%s\t%s\t%s\t%s\n' "$(date +%F)" "$3" "$1" "$2" "${note% }" >>docs/measures.tsv
