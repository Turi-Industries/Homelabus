#!/usr/bin/env bash
#
# Goal 5, phase 4's gate: the moving-house drill. The house's line is cut; how long until
# the vital apps answer from the VPS, and, the line back, how long until they answer from
# home again. Three rows of docs/measures.tsv:
#
#   available-alert-seconds    the cut → the site's Gatus firing its first alert
#   available-promote-seconds  the cut → every vital name answered by the site's own Caddy
#   available-return-seconds   the line back → every vital name answered by the house again
#
# The promotion runs the moment the alert fires, over SSH on the VPS as the owner would:
# their reaction is not counted. The visitor stands on the lab's internet (this machine,
# on `hlb-internet`) and tells who answers by the certificate's serial — the house's Caddy
# and the site's hold different ones, both from the lab's authority.
#
# ⚠️ The lab's ACME authority (step-ca on deb2) plays Let's Encrypt, a service of the
# internet: the cut spares it, and the VPS is given a route to it. Its view of every
# vital name must be the door (`--add-host <name>:10.99.0.40`, deb2 `/root/step-ca-run.sh`):
# a name it resolves to the house leaves that app without a certificate on the site.
#
# Usage: scripts/drills/available.sh [--no-record]
#        with deb1, deb2 and vps1 up (`/lab/vps.sh up`), the site added, its lifeboat
#        declaring the vital apps. LAB_HLB: a command on deb1 running hlb on the lab's state.

set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

record=1
[[ ${1:-} == --no-record ]] && record=0

door=10.99.0.40
hlb_on_deb1=${LAB_HLB:-/root/p6s.sh}
hlb() { docker exec -i hlb-lab /lab/vm.sh ssh deb1 "$hlb_on_deb1 $*"; }
vps() { docker exec -i hlb-lab ssh -i /lab/id_ed25519 -o BatchMode=yes "root@$door" "$@"; }
now() { date +%s; }

# The house cut as a dead box would: nothing between br0 and the outside, but the authority.
cut() {
    docker exec hlb-lab sh -c '
        iptables -N HLB-CUT 2>/dev/null || iptables -F HLB-CUT
        iptables -A HLB-CUT -p tcp -d 10.77.0.12 --dport 9000 -j RETURN
        iptables -A HLB-CUT -p tcp -s 10.77.0.12 --sport 9000 -j RETURN
        iptables -A HLB-CUT -p tcp -s 10.77.0.12 -d '"$door"' -m multiport --dports 80,443 -j RETURN
        iptables -A HLB-CUT -p tcp -d 10.77.0.12 -s '"$door"' -m multiport --sports 80,443 -j RETURN
        iptables -A HLB-CUT -i br0 ! -o br0 -j DROP
        iptables -A HLB-CUT -o br0 ! -i br0 -j DROP
        iptables -C FORWARD -j HLB-CUT 2>/dev/null || iptables -I FORWARD 1 -j HLB-CUT'
}
mend() { docker exec hlb-lab sh -c 'iptables -D FORWARD -j HLB-CUT 2>/dev/null; iptables -F HLB-CUT 2>/dev/null; true'; }
# 🔴 A drill stopped halfway must not leave the house cut off.
trap mend EXIT

# "<code> <serial>" for a name through the door; "000 -" when nothing answers.
ask() {
    local code serial
    code=$(curl -sk -m 3 -o /dev/null -w '%{http_code}' --resolve "$1:443:$door" "https://$1/" || true)
    serial=$(timeout 3 openssl s_client -connect "$door:443" -servername "$1" </dev/null 2>/dev/null |
        openssl x509 -noout -serial 2>/dev/null || true)
    echo "${code:-000} ${serial#serial=}"
}
# Every name answered (below 500) with a serial that is (=) or is not (!=) the house's.
all_answer() {
    local op=$1 name code serial
    for name in "${names[@]}"; do
        read -r code serial < <(ask "$name")
        [[ $code =~ ^[1-4] && -n $serial ]] || return 1
        if [[ $op == "=" ]]; then [[ $serial == "${house[$name]}" ]] || return 1
        else [[ $serial != "${house[$name]}" ]] || return 1; fi
    done
}
wait_for() { # <limit seconds> <command...>
    local limit=$1 start; shift; start=$(now)
    until "$@"; do (($(now) - start < limit)) || return 1; sleep 1; done
}

version=$(hlb --version | awk '{print $2}')
mend
# The VPS reaches the authority as it would reach Let's Encrypt: lost at each of its boots.
vps ip route replace 10.77.0.12/32 via 10.99.0.2

echo "Lifeboat, as each night:"
hlb site lifeboat --apply | tail -2
read -ra names < <(vps "sed -n 's/^NAMES=\"\(.*\)\"$/\1/p' /usr/local/sbin/hlb-site-promote")
((${#names[@]})) || { echo "the site has no promotion: no vital app carried" >&2; exit 1; }
declare -A house
for name in "${names[@]}"; do
    read -r code serial < <(ask "$name")
    [[ $code =~ ^[1-4] && -n $serial ]] || { echo "$name does not answer from home: $code" >&2; exit 1; }
    house[$name]=$serial
done
echo "Vital names: ${names[*]}"

cut_at=$(now)
since=$(date -u -d "@$cut_at" +%Y-%m-%dT%H:%M:%SZ)
cut
echo "$(date +%T) the house cut"
alerted() { vps "docker service logs --since $since hlb-site-gatus 2>&1 | grep -q 'has been TRIGGERED'"; }
wait_for 900 alerted || { echo "no alert 15 minutes after the cut" >&2; exit 1; }
alert=$(($(now) - cut_at))
echo "$(date +%T) alerted after $alert s; promoting"
vps /usr/local/sbin/hlb-site-promote --apply
wait_for 900 all_answer "!=" || { echo "the site does not answer every vital name 15 minutes after the cut" >&2; exit 1; }
promote=$(($(now) - cut_at))
echo "$(date +%T) every vital name answered from the VPS, $promote s after the cut"

back_at=$(now)
mend
echo "$(date +%T) the line back"
hlb site return --apply | tail -2
wait_for 300 all_answer "=" || { echo "the house does not answer every vital name after the return" >&2; exit 1; }
back=$(($(now) - back_at))
echo "$(date +%T) every vital name answered from home, $back s after the line came back"

if ((record)); then
    lab="lab: 4 GB VPS on hlb-internet, house deb1+deb2; ${names[*]}"
    scripts/measure.sh available-alert-seconds "$alert" "$version" "$lab; Gatus every minute, 3 failures"
    scripts/measure.sh available-promote-seconds "$promote" "$version" "$lab; promoted over SSH at the alert, the owner's reaction not counted"
    scripts/measure.sh available-return-seconds "$back" "$version" "$lab; hlb site return at once, the site's writes brought home"
fi
