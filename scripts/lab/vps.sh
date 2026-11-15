#!/usr/bin/env bash
#
# The lab's VPS: a Debian 12 VM on `hlb-internet`, the rented server phase 4 builds on.
#
#   vps.sh up <name> <octet> <MB>     made at 10.99.0.<octet>, 2 vCPU
#   vps.sh up <name>                  booted as it was made
#
# Anything else is vm.sh's (`vps.sh ssh vps1 …`, `vps.sh down vps1`).

set -euo pipefail
here=$(dirname "$(readlink -f "$0")")

if [[ ${1:-} == up && $# -eq 4 ]]; then
    exec "$here/vm.sh" up "$2" "$3" debian-12 "$4" 2 internet
fi
exec "$here/vm.sh" "$@"
