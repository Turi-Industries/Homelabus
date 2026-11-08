#!/usr/bin/env bash
#
# Goal 2, to its end: the house is gone, a bare machine and the emergency kit are left.
# Everything the kit says, then every app of the lab started on its restored copy and asked
# whether it holds what its manifest promises. Two rows of docs/measures.tsv:
#
#   recovery-started   "<running with its assertions read good> of <apps holding data>"
#   recovery-content   what the house's tables and volumes held that the new machine holds
#
# 🔴 An assertion reads an app's settings: a database restored empty passes every one of them.
# So the house is read first (`witness.sh`), then a pass taken, so what was read is in it. A
# table with rows must have rows after, not as many: an app restarted cleans its sessions.
#
# ⚠️ Each restore backs up what it overwrites first, so `rest` receives a small copy of each
# empty volume, tagged `kind:pre-restore`: no restore takes one unless named. The daemon is
# never run: no pass writes to a destination, and no app's job runs.
#
# Needs the lab, its lease through the session's hook, a build that copies the state at the
# end of a pass (0.4.6), or the newest pass is refused, and deb1 up: `rest` lives there. The
# VM takes 8 GB, so deb2 goes down, and it cannot reach deb1 or deb2 but for
# `rest`: what comes back depends on nothing of the house.
#
# 🔴 deb1 is paused first, and stays so: with deb2 down Swarm moves its services onto deb1,
# whose images filled its disk (17 to 19 GB of containerd in minutes), and `rest`, on the same
# disk, answered restores 507. Afterwards boot deb2, wait until `docker node ls` reads it
# Ready, then `docker node update --availability active deb1`: active first, what ran on deb2
# lands on deb1, and Stalwart, pinned there by its data, finds no memory left to reserve.
#
# Usage: scripts/drills/recovery.sh [--no-record]

set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

record=1
[[ ${1:-} == --no-record ]] && record=0

# .13 is the lab's: dnsmasq pins .11 to .19 by MAC, and .13 holds no mesh peer.
vm=drill
ip=10.77.0.13
hlb_on_deb1=${LAB_HLB:-/root/lab-048/hlb}
state=/var/lib/homelabus/hlb.db
key=/var/lib/homelabus/hlb-master.key
kit=/root/drill-kit.txt
# Where the lab's Immich and Jellyfin keep their share: the state does not say, a person does.
nfs=/srv/hlb-nfs
nfs_owner=10000

lab() { docker exec -i hlb-lab "$@"; }
deb1() { lab /lab/vm.sh ssh deb1 "$@"; }
on() { lab /lab/vm.sh ssh "$ip" "$@"; }

clean() {
    set +e
    deb1 "rm -f $kit"
    on systemctl poweroff 2>/dev/null
    for _ in {1..30}; do
        lab test -e "/vms/$vm/qemu.pid" || break
        sleep 2
    done
    lab rm -rf "/vms/$vm"
}
trap clean EXIT

lab test ! -e "/vms/$vm" || { echo "/vms/$vm exists: an earlier drill's" >&2; trap - EXIT; exit 1; }

# What the house holds, then the pass that copies it ---------------------------------------
house=$(mktemp)
after=$(mktemp)
for node in deb1 deb2; do
    lab /lab/vm.sh ssh "$node" 'bash -s -- $(docker volume ls -q)' <scripts/drills/witness.sh >>"$house"
done
deb1 "cd /root; HLB_STATE=/var/lib/homelabus/hlb.db HLB_MASTER_KEY=/root/hlb-master.key \
    $hlb_on_deb1 backup run --force" | tail -1

deb1 'docker node update --availability pause deb1' >/dev/null
lab /lab/vm.sh ssh deb2 systemctl poweroff 2>/dev/null || true
lab /lab/vm.sh up "$vm" 13 debian-12 8192 4
for _ in {1..60}; do
    on true 2>/dev/null && break
    sleep 2
done

# The binary and the two lines of the kit: through pipes, never argv, never on screen ---
deb1 "cat $hlb_on_deb1" | on 'install -d /root/d; cat > /root/hlb; chmod +x /root/hlb'
version=$(on /root/hlb --version | awk '{print $2}')
deb1 "cd /root; HLB_STATE=/var/lib/homelabus/hlb.db HLB_MASTER_KEY=/root/hlb-master.key \
    $hlb_on_deb1 emergency kit --out $kit >/dev/null 2>&1"
# 🔴 By their shape, so a sheet laid out anew stops here rather than handing a wrong line
# over. Only the verdict comes back.
deb1 "awk 'NR==11 && /^ *AGE-SECRET-KEY-/ {a=1} NR==15 && length(\$1)==32 {b=1} END {exit !(a && b)}' $kit" ||
    { echo "the kit's key and password are not on lines 11 and 15" >&2; exit 1; }
deb1 "awk 'NR==11 {print \$1}' $kit" |
    on "install -d -m 755 /var/lib/homelabus; umask 077; cat > $key"
deb1 "awk 'NR==15 {print \$1}' $kit" | on 'umask 077; cat > /root/d/restic-pw'
deb1 "rm -f $kit"

# What runs on the VM, as one script: it lives through a dropped connection to the lab ----
on 'cat > /root/d/recover.sh; chmod +x /root/d/recover.sh' <<EOF
#!/usr/bin/env bash
set -uo pipefail
trap '[[ -n \${finished:-} ]] || echo "NOT RECOVERED"' EXIT
export HLB_STATE=$state HLB_MASTER_KEY=$key
export DEBIAN_FRONTEND=noninteractive
cd /root/d

quiet() { grep -vE '^ *\$|does not resolve|^Run .docker' | cut -c1-200; }

apt-get -qq update >/dev/null 2>&1
apt-get -qq install -y nftables restic nfs-kernel-server >/dev/null 2>&1

# Nothing of the house but the destination.
nft -f - <<NFT
table inet drill {
    chain output {
        type filter hook output priority 0;
        ip daddr 10.77.0.11 tcp dport 8000 accept
        ip daddr { 10.77.0.11, 10.77.0.12 } reject
    }
}
NFT

# The kit's step 4, as printed.
RESTIC_PASSWORD_FILE=/root/d/restic-pw restic -r rest:http://10.77.0.11:8000/ \\
    dump latest --tag app:hlb,db:state /staging/hlb-state.snapshot > $state || exit 1

/root/hlb cluster init --no-mesh --advertise-addr $ip --apply 2>&1 | tail -2
/root/hlb node tier $vm --set heavy --apply 2>&1 | tail -1
/root/hlb config exposure --node $vm --apply 2>&1 | tail -1
/root/hlb catalog source fetch 2>&1 | tail -1

# Served as \`hlb storage export\` serves it: the lab's share is on deb2, out of reach.
install -d /etc/exports.d
for v in immich/data jellyfin/media; do install -d -o $nfs_owner -g $nfs_owner $nfs/\$v; done
echo "$nfs $ip(rw,sync,no_subtree_check,crossmnt,all_squash,anonuid=$nfs_owner,anongid=$nfs_owner)" \\
    > /etc/exports.d/hlb.exports
systemctl restart nfs-server && exportfs -ra

# An install refuses to move an app, and says where it is: the state's answer, not a choice.
install_app() {
    local a=\$1 out at
    case \$a in
    immich|jellyfin) set -- --nfs-server $ip --nfs-export $nfs ;;
    *) set -- ;;
    esac
    out=\$(/root/hlb install "\$a" "\$@" --apply 2>&1)
    case \$out in
    *"is installed at "*)
        at=\${out#*is installed at }
        at=\${at%% *}
        out=\$(/root/hlb install "\$a" --domain "\$at" "\$@" --apply 2>&1)
        ;;
    esac
    echo "\$out" | quiet | tail -3
}

# Each volume and bucket of an app, the preview naming them when it has several.
restore_app() {
    local a=\$1 out v
    # Between two crashes a task can be on no node for an instant: what a person retries.
    for _ in {1..12}; do
        out=\$(/root/hlb backup restore "\$a" --from rest 2>&1)
        [[ \$out == *"runs nowhere"* ]] || break
        sleep 5
    done
    case \$out in
    *"backs up no"*) return 1 ;;
    *"Which of"*)
        for v in \$(sed -n 's/^Which of [^?]*? //p' <<<"\$out" | head -1 | tr -d ,); do
            restore_one "\$a" "\$v"
        done
        ;;
    *) restore_one "\$a" ;;
    esac
    return 0
}

# 🔴 Each said restored, or the app does not count: Caddy has no assertion, and restored from
# a full destination it started empty and read as recovered (13 of 14, the first full run).
unrestored=""
restore_one() {
    local out
    out=\$(/root/hlb backup restore "\$@" --from rest --apply 2>&1)
    echo "\$out" | quiet | grep -E '^✓ .* restored|^🔴'
    sed -nE 's/^✓ ([^ ]+) restored.*/\1/p' <<<"\$out" >> /root/d/restored
    grep -q '^✓ .* restored' <<<"\$out" || unrestored="\$unrestored \$1"
}

# Running, every service of the app and its companions, and every assertion read good. A
# slow first start is not a failure: an app gets five minutes.
started() {
    local a=\$1 out="no assertion read: a service stayed at 0"
    for _ in {1..30}; do
        if ! docker service ls --format '{{.Name}} {{.Replicas}}' | grep -E "^\$a(-[a-z-]+)? " |
            grep -qE ' 0/[0-9]'; then
            out=\$(/root/hlb assert "\$a" 2>&1)
            if ! grep -qE '^ *(✗|\?|🔴)' <<<"\$out"; then
                echo "\$out" | quiet
                return 0
            fi
        fi
        sleep 10
    done
    echo "\$out" | quiet
    return 1
}

# The order the house would deploy in, of what it holds.
installed=\$(/root/hlb backup status 2>/dev/null | awk '/^[a-z]/ && NR > 1 {print \$1}')
good=0 held=0
for a in \$(/root/hlb order | sed -nE 's/^ *[0-9]+\. ([a-z0-9-]+).*/\1/p'); do
    grep -qx "\$a" <<<"\$installed" || continue
    echo "--- \$a \$(date +%T)"
    install_app "\$a"
    [[ \$a == garage ]] && /root/hlb garage init --apply 2>&1 | quiet | tail -1
    restore_app "\$a" || continue
    held=\$((held + 1))
    # An install stopped on a slow first start, over an empty volume, resumes.
    install_app "\$a"
    if [[ " \$unrestored " == *" \$a "* ]]; then
        echo "NOT RESTORED: \$a"
    elif started "\$a"; then
        good=\$((good + 1))
    else
        echo "NOT STARTED: \$a"
    fi
done
finished=1
echo "RESULT \$good \$held"
EOF
on 'nohup /root/d/recover.sh > /root/d/recover.log 2>&1 < /dev/null &'
until on 'grep -q "^RESULT\|^NOT RECOVERED" /root/d/recover.log'; do
    on 'tail -n1 /root/d/recover.log' | cut -c1-120 || true
    sleep 30
done
on cat /root/d/recover.log
read -r _ good held < <(on 'grep "^RESULT" /root/d/recover.log')
# 🔴 Nothing read is not "0 of 0": an empty listing would pass as an empty house.
((held > 0)) || { echo "no app with data was recovered" >&2; exit 1; }

echo "hlb $version: $good of $held started on their restored copy"

# What came back ---------------------------------------------------------------------------
# A volume is judged only if restored here: the house holds caches no pass takes. A node's
# leftovers are the larger of the two, and read the same way: a volume holding files.
restored=$(on 'sort -u /root/d/restored' | tr '\n' ' ')
on "bash -s -- $restored" <scripts/drills/witness.sh >"$after"
read -r tables volumes < <(awk -v restored="$restored" '
    BEGIN { n = split(restored, r, " "); for (i = 1; i <= n; i++) back[r[i]] = 1 }
    NR == FNR { if ($3 > held[$1 " " $2]) held[$1 " " $2] = $3; next }
    { now[$1 " " $2] = $3 }
    END {
        for (k in held) {
            if (held[k] == 0) continue
            split(k, w, " ")
            if (w[1] == "volume" && !(w[2] in back)) continue
            total[w[1]]++
            if (now[k] > 0) kept[w[1]]++
            else print "LOST " k " held " held[k] > "/dev/stderr"
        }
        printf "%d/%d %d/%d\n", kept["table"], total["table"], kept["volume"], total["volume"]
    }' "$house" "$after")
rm -f "$house" "$after"
# 🔴 Nothing read is not "0 of 0": a reader broken on both sides would pass as nothing lost.
[[ $tables != */0 && $volumes != */0 ]] || { echo "the house read as holding nothing" >&2; exit 1; }
content="${tables%/*} of ${tables#*/} tables and ${volumes%/*} of ${volumes#*/} volumes"
echo "hlb $version: $content holding data still hold it"
if ((record)); then
    scripts/measure.sh recovery-started "$good of $held" "$version" \
        "a bare VM, the kit and rest alone; each volume and bucket said restored, its services up, every assertion it declares read good"
    scripts/measure.sh recovery-content "$content" "$version" \
        "read on the house before the pass, then on the bare VM: each still holding rows or files"
fi
