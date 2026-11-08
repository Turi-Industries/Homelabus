#!/usr/bin/env bash
#
# Goal 1, timed: a bare machine to a first app, by the published release and nothing
# else, on two throwaway VMs of the lab. It writes four rows of docs/measures.tsv.
#
#   deploy-os-seconds        the netinst, from `hlb node preseed`'s file to its power-off
#   deploy-first-app-seconds download to a first app with no dependency (librespeed)
#   deploy-full-app-seconds  download to an app with a database and sign-in (Vikunja)
#   deploy-answers           what the person had to decide on the way
#
# Each answer goes through `ask`, so the count is what the path really demanded: a new
# required question stops the drill until it is answered here, and raises the figure.
#
# Needs the lab (the `hlb-lab` container, its `/lab/vm.sh`), and takes its lease through
# the session's hook. It leaves deb1 and deb2 alone: the VMs make a Swarm of their own.
#
# Usage: scripts/drills/deploy.sh [--no-record]

set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

record=1
[[ ${1:-} == --no-record ]] && record=0

# .13 and .14 are the lab's: dnsmasq pins .11 to .19 by MAC, and .13 and .14 hold no peer.
vm=drill
ip=10.77.0.13
memory=4096
domain=drill.test

lab() { docker exec -i hlb-lab "$@"; }
on() { lab /lab/vm.sh ssh "$ip" "$@"; }
now() { date +%s; }

answers=0
# Sets its variable rather than printing: a `$(ask …)` would count in a subshell, and
# the figure would stay at zero.
ask() {
    answers=$((answers + 1))
    printf -v "$1" '%s' "$3"
    echo "  answer $answers: $2 = $3"
}

# The netinst ---------------------------------------------------------------------------
os_install() {
    local d=/vms/drill-os
    lab sh -euc "
        rm -rf $d /tmp/drill-hlb; mkdir -p $d /tmp/drill-hlb
        cd /tmp/drill-hlb
        curl -fsSL https://github.com/Turi-Industries/Homelabus/releases/latest/download/install.sh \
            | HLB_INSTALL_DIR=/tmp/drill-hlb sh >/dev/null
        # A state of its own: this file is rendered before any house exists.
        ./hlb --state ./hlb.db --master-key ./k.key node preseed drill-os \
            --disk /dev/disk/by-id/virtio-drill-os-system \
            --ssh-key \"\$(cat /lab/id_ed25519.pub)\" > /vms/www/drill-os.cfg
        cp /vms/nas02/vmlinuz /vms/nas02/initrd.gz $d/
        qemu-img create -q -f qcow2 $d/sys.qcow2 20G
        ip tuntap add dev tap14 mode tap 2>/dev/null || true
        ip link set tap14 master br0 up
    "
    # Detached, or `docker exec` waits on its streams for as long as the server lives.
    lab sh -c 'ss -ltn | grep -q "10.77.0.1:8000" || setsid socat TCP-LISTEN:8000,bind=10.77.0.1,fork,reuseaddr EXEC:"sh /lab/enc/serve.sh" >/dev/null 2>&1 </dev/null &'

    local start end
    start=$(now)
    lab qemu-system-x86_64 -enable-kvm -cpu host -m 2048 -smp 2 -name drill-os \
        -drive "file=$d/sys.qcow2,if=none,id=d0" -device virtio-blk-pci,drive=d0,serial=drill-os-system \
        -netdev tap,id=n0,ifname=tap14,script=no,downscript=no \
        -device virtio-net-pci,netdev=n0,mac=52:54:00:77:00:14 \
        -drive file=/vms/base/netinst.iso,media=cdrom,readonly=on \
        -kernel "$d/vmlinuz" -initrd "$d/initrd.gz" \
        -append "auto=true priority=critical url=http://10.77.0.1:8000/drill-os.cfg console=ttyS0,115200n8" \
        -no-reboot -display none -serial "file:$d/install.log" -daemonize -pidfile "$d/qemu.pid"
    # hlb-lab's PID 1 reaps nothing: a finished qemu stays a zombie, so /proc alone
    # would wait for ever.
    while lab sh -c "[ -f $d/qemu.pid ] && ps -o stat= -p \$(cat $d/qemu.pid) 2>/dev/null | grep -qv Z"; do
        sleep 5
        (($(now) - start < 1500)) || { echo "the netinst did not finish in 25 min" >&2; exit 1; }
    done
    end=$(now)
    # An installer that stopped early also powers off: only its last lines tell them apart.
    lab tail -c 2000 "$d/install.log" | grep -qiE 'Requesting system (reboot|poweroff)|reboot: (Restarting|Power down)' \
        || { echo "the netinst stopped without finishing: $d/install.log" >&2; exit 1; }
    os_seconds=$((end - start))
    echo "netinst: ${os_seconds} s"
    lab rm -rf "$d" /vms/www/drill-os.cfg /tmp/drill-hlb
}

# The release, on a bare machine --------------------------------------------------------
boot() {
    lab sh -c "[ -f /vms/$vm/qemu.pid ] && kill \$(cat /vms/$vm/qemu.pid) 2>/dev/null; rm -rf /vms/$vm"
    lab /lab/vm.sh up "$vm" 13 debian-13 "$memory" 2 >/dev/null
    for _ in $(seq 1 60); do on true 2>/dev/null && return; sleep 3; done
    echo "the VM never answered" >&2
    exit 1
}

# One step, its time, its output kept: a failure must show what it said.
step() {
    local name=$1
    shift
    local started=$(now)
    if ! on "mkdir -p /root/d && cd /root/d && $* > $name.log 2>&1"; then
        echo "FAILED: $name" >&2
        on "tail -20 /root/d/$name.log" >&2
        exit 1
    fi
    echo "  $name: $(($(now) - started)) s"
}

# An app's DNS record is a question for the person, once per app it stops. Attested before
# the first apply, so no refusal is part of the path. `--force` because drill.test resolves
# nowhere.
install_attesting() {
    local app=$1 attest
    ask attest "$app's DNS record exists" "--force"
    step "$app-attest" "hlb ack $app/dns-record $attest"
    step "$app" "hlb install $app --apply"
}

path() {
    local start endpoint exposed ingress source tier
    ask endpoint "the address other nodes reach" "$ip"
    ask exposed "the house's domain" "$domain"
    ask ingress "the node the router forwards to" "$vm"
    ask source "where certificates come from" "--internal"

    start=$(now)
    step download "curl -fsSL https://github.com/Turi-Industries/Homelabus/releases/latest/download/install.sh | sh"
    version=$(on "hlb --version" | awk '{print $2}')
    step init "hlb cluster init --endpoint $endpoint --apply"
    step exposure "hlb config exposure --domain $exposed $source --node $ingress --apply"
    step caddy "hlb install caddy --apply"
    install_attesting librespeed
    first_app_seconds=$(($(now) - start))

    # Below 8 GB a node is "light", and PostgreSQL, Stalwart and PocketID refuse it.
    ask tier "a node under 8 GB carrying a database anyway" "--set heavy"
    step tier "hlb node tier $vm $tier --apply"
    step postgres "hlb install postgres --apply"
    step stalwart "hlb install stalwart --apply"
    step pocket "hlb install pocket-id --apply"
    install_attesting vikunja
    step assert "hlb assert vikunja"
    full_app_seconds=$(($(now) - start))
}

os_install
boot
path
lab sh -c "kill \$(cat /vms/$vm/qemu.pid) 2>/dev/null; rm -rf /vms/$vm"

echo
echo "hlb $version: netinst ${os_seconds} s, first app ${first_app_seconds} s, full app ${full_app_seconds} s, ${answers} answers"
if ((record)); then
    note="lab VM, ${memory} MB, 2 vCPU, Debian 13 cloud image"
    scripts/measure.sh deploy-os-seconds "$os_seconds" "$version" "netinst by preseed, no encryption, lab VM"
    scripts/measure.sh deploy-first-app-seconds "$first_app_seconds" "$version" "$note; librespeed behind Caddy"
    scripts/measure.sh deploy-full-app-seconds "$full_app_seconds" "$version" "$note; Vikunja, PostgreSQL, Stalwart, PocketID"
    scripts/measure.sh deploy-answers "$answers" "$version" "the drill's ask calls"
fi
