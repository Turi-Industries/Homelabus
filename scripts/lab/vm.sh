#!/usr/bin/env bash
#
# The lab's VMs, run inside the `hlb-lab` container (scripts/lab/lab.sh starts it).
#
#   vm.sh net                                       br0, DHCP, NAT, the internet bridge
#   vm.sh up <name> <octet> <image> <MB> <cpus> [house|internet]
#   vm.sh up <name>                                 boot an existing VM as it was made
#   vm.sh wait <name> [seconds]                     until SSH answers
#   vm.sh ssh <name|ip> [command...]                stdin passes through
#   vm.sh down <name>                               ACPI power-off, then kill after 2 min
#   vm.sh ls
#
# <image> is debian-12 or debian-13, Debian's generic cloud image. A VM on the house sits
# at 10.77.0.<octet> (dnsmasq pins it by MAC); one on the internet at 10.99.0.<octet>,
# static, reaching the house only through NAT. A VM's disk is an overlay on its image,
# kept under /vms/<name> across container rebuilds: `up` on an existing VM never
# reinstalls it.

set -euo pipefail

VMS=/vms
KEY=$VMS/keys/id_ed25519
HOUSE=10.77.0
INET=10.99.0

die() { echo "vm.sh: $*" >&2; exit 1; }

running() {
    local pid
    [[ -f $VMS/$1/qemu.pid ]] || return 1
    pid=$(cat "$VMS/$1/qemu.pid")
    # A finished qemu lingers as a zombie when PID 1 does not reap it.
    ps -o stat= -p "$pid" 2>/dev/null | grep -qv Z
}

# The house's gateway: the router once it is made (router.sh), the container before.
gateway() {
    if [[ -f $VMS/opn1/bootstrapped ]]; then echo "$HOUSE.3"; else echo "$HOUSE.1"; fi
}

net() {
    sysctl -qw net.ipv4.ip_forward=1
    mkdir -p "$VMS/keys" "$VMS/base" "$VMS/www"
    [[ -f $KEY ]] || ssh-keygen -q -t ed25519 -N '' -C hlb-lab -f "$KEY"

    if ! ip link show br0 >/dev/null 2>&1; then
        ip link add br0 type bridge
        ip addr add "$HOUSE.1/24" dev br0
        ip link set br0 up
    fi

    # The internet: eth0 (the container on `hlb-internet`) moved into a bridge, so a VPS
    # sits on the same segment as the host. The bridge keeps eth0's MAC: a bridge takes
    # its lowest port's, and a VPS's tap would otherwise change it under the host's ARP.
    if ! ip link show brinet >/dev/null 2>&1; then
        local mac addr gw
        mac=$(cat /sys/class/net/eth0/address)
        addr=$(ip -4 -o addr show dev eth0 | awk '{print $4}')
        gw=$(ip route show default | awk '{print $3; exit}')
        ip link add brinet type bridge
        ip link set brinet address "$mac"
        ip addr flush dev eth0
        ip link set eth0 master brinet
        ip addr add "$addr" dev brinet
        ip link set brinet up
        ip route replace default via "$gw" dev brinet
    fi

    if ! pgrep -f dnsmasq-hlb-lab >/dev/null; then
        # Every octet pinned by MAC: a VM's address is its name's, whatever the lease file
        # remembers from an earlier VM.
        local pins=() n
        for n in $(seq 2 99); do pins+=("--dhcp-host=52:54:00:77:00:$(printf %02d "$n"),$HOUSE.$n"); done
        dnsmasq --conf-file=/dev/null --pid-file=/run/dnsmasq-hlb-lab.pid \
            --interface=br0 --bind-interfaces \
            --dhcp-range="$HOUSE.100,$HOUSE.199,12h" --dhcp-option=option:router,"$(gateway)" \
            --dhcp-option=option:dns-server,"$HOUSE.1" "${pins[@]}" \
            --dhcp-leasefile="$VMS/dnsmasq.leases" --log-facility="$VMS/dnsmasq.log" \
            --dhcp-authoritative
    fi

    # The house goes out by NAT, as behind a box. Nothing from the internet enters it but
    # replies, and the lab's ACME authority on deb2 (:9000), which plays Let's Encrypt.
    iptables -t nat -C POSTROUTING -s "$HOUSE.0/24" ! -d "$HOUSE.0/24" -j MASQUERADE 2>/dev/null ||
        iptables -t nat -A POSTROUTING -s "$HOUSE.0/24" ! -d "$HOUSE.0/24" -j MASQUERADE
    if ! iptables -C FORWARD -o br0 -j HLB-HOUSE-IN 2>/dev/null; then
        iptables -N HLB-HOUSE-IN 2>/dev/null || iptables -F HLB-HOUSE-IN
        iptables -A HLB-HOUSE-IN -i br0 -j RETURN
        iptables -A HLB-HOUSE-IN -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
        iptables -A HLB-HOUSE-IN -p tcp -d "$HOUSE.12" --dport 9000 -j RETURN
        iptables -A HLB-HOUSE-IN -j DROP
        iptables -A FORWARD -o br0 -j HLB-HOUSE-IN
    fi
    # The VPS reaches that authority through the container, not the house's router: deb2's
    # reply would leave by its gateway, reach a router that never saw the request, and be
    # dropped. The container stands as the client, on deb2's own link.
    iptables -t nat -C POSTROUTING -o br0 -p tcp -d "$HOUSE.12" --dport 9000 -j MASQUERADE 2>/dev/null ||
        iptables -t nat -A POSTROUTING -o br0 -p tcp -d "$HOUSE.12" --dport 9000 -j MASQUERADE
    echo "net: br0 $HOUSE.1/24, brinet $(ip -4 -o addr show dev brinet | awk '{print $4}')"
}

image() {
    local name=$1 file=$VMS/base/$1.qcow2 url
    [[ -f $file ]] && return
    case $name in
        debian-12) url=https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-generic-amd64.qcow2 ;;
        debian-13) url=https://cloud.debian.org/images/cloud/trixie/latest/debian-13-generic-amd64.qcow2 ;;
        *) die "unknown image $name (debian-12, debian-13)" ;;
    esac
    echo "fetching $name" >&2
    curl -fL --retry 3 -o "$file.part" "$url"
    mv "$file.part" "$file"
}

seed() { # <dir> <name> <ip> <segment>
    local dir=$1 name=$2 ip=$3 segment=$4 pub
    pub=$(cat "$KEY.pub")
    cat >"$dir/user-data" <<EOF
#cloud-config
hostname: $name
manage_etc_hosts: true
disable_root: false
ssh_pwauth: false
write_files:
  - path: /root/.ssh/authorized_keys
    permissions: "0600"
    content: |
      $pub
EOF
    if [[ $segment == internet ]]; then
        cat >"$dir/network-config" <<EOF
version: 2
ethernets:
  nic:
    match: {macaddress: "$(mac "$4" "${ip##*.}")"}
    addresses: [$ip/24]
    routes: [{to: default, via: $INET.1}]
    nameservers: {addresses: [1.1.1.1, 9.9.9.9]}
EOF
        cloud-localds -N "$dir/network-config" "$dir/seed.iso" "$dir/user-data"
    else
        cloud-localds "$dir/seed.iso" "$dir/user-data"
    fi
}

mac() { # <segment> <octet>
    if [[ $1 == internet ]]; then printf '52:54:00:99:00:%02d' "$2"; else printf '52:54:00:77:00:%02d' "$2"; fi
}

up() {
    local name=$1 dir=$VMS/$1 octet image_name memory cpus segment bridge tap ip
    if (($# == 1)); then
        [[ -f $dir/vm.conf ]] || die "$name was never made: vm.sh up $name <octet> <image> <MB> <cpus>"
        # shellcheck source=/dev/null
        . "$dir/vm.conf"
    else
        (($# >= 5)) || die "usage: vm.sh up <name> <octet> <image> <MB> <cpus> [house|internet]"
        octet=$2 image_name=$3 memory=$4 cpus=$5 segment=${6:-house}
    fi
    running "$name" && { echo "$name already running"; return; }
    ip link show br0 >/dev/null 2>&1 || net >/dev/null

    if [[ $segment == internet ]]; then bridge=brinet ip=$INET.$octet tap=tapi$octet
    else bridge=br0 ip=$HOUSE.$octet tap=tap$octet; fi

    mkdir -p "$dir"
    if [[ ! -f $dir/disk.qcow2 ]]; then
        image "$image_name"
        qemu-img create -q -f qcow2 -b "$VMS/base/$image_name.qcow2" -F qcow2 "$dir/disk.qcow2" 40G
        seed "$dir" "$name" "$ip" "$segment"
    fi
    printf 'octet=%s\nimage_name=%s\nmemory=%s\ncpus=%s\nsegment=%s\nip=%s\n' \
        "$octet" "$image_name" "$memory" "$cpus" "$segment" "$ip" >"$dir/vm.conf"
    echo "$ip" >"$dir/ip"

    ip tuntap add dev "$tap" mode tap 2>/dev/null || true
    ip link set "$tap" master "$bridge" up
    rm -f "$dir/qmp.sock"
    qemu-system-x86_64 -enable-kvm -cpu host -m "$memory" -smp "$cpus" -name "$name" \
        -drive "file=$dir/disk.qcow2,if=none,id=d0,discard=unmap" \
        -device "virtio-blk-pci,drive=d0,serial=$name-system" \
        -drive "file=$dir/seed.iso,media=cdrom,readonly=on" \
        -netdev "tap,id=n0,ifname=$tap,script=no,downscript=no" \
        -device "virtio-net-pci,netdev=n0,mac=$(mac "$segment" "$octet")" \
        -device virtio-rng-pci \
        -qmp "unix:$dir/qmp.sock,server,nowait" \
        -display none -serial "file:$dir/console.log" -daemonize -pidfile "$dir/qemu.pid"
    echo "$name up at $ip"
}

target() { # a name or an address → an address
    if [[ -f $VMS/$1/ip ]]; then cat "$VMS/$1/ip"; else echo "$1"; fi
}

ssh_to() {
    local host
    host=$(target "$1")
    shift
    exec ssh -i "$KEY" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o LogLevel=ERROR -o ConnectTimeout=5 -o ServerAliveInterval=15 "root@$host" "$@"
}

wait_for() {
    local name=$1 limit=${2:-300} start=$SECONDS
    until "$0" ssh "$name" true </dev/null 2>/dev/null; do
        ((SECONDS - start < limit)) || die "$name did not answer in $limit s"
        sleep 3
    done
    echo "$name answers ($((SECONDS - start)) s)"
}

down() {
    local name=$1 dir=$VMS/$1 i
    running "$name" || { echo "$name not running"; return; }
    printf '{"execute":"qmp_capabilities"}\n{"execute":"system_powerdown"}\n' |
        socat - "UNIX-CONNECT:$dir/qmp.sock" >/dev/null 2>&1 || true
    for i in $(seq 1 60); do running "$name" || { echo "$name off"; return; }; sleep 2; done
    echo "$name ignored ACPI: killed" >&2
    kill "$(cat "$dir/qemu.pid")"
}

ls_vms() {
    local dir name
    for dir in "$VMS"/*/vm.conf; do
        [[ -f $dir ]] || continue
        dir=${dir%/vm.conf} name=${dir##*/}
        printf '%-8s %-12s %s\n' "$name" "$(cat "$dir/ip")" "$(running "$name" && echo up || echo off)"
    done
}

cmd=${1:-}
(($#)) && shift
case $cmd in
    net) net ;;
    up) (($#)) || die "usage: vm.sh up <name> ..."; up "$@" ;;
    wait) wait_for "$@" ;;
    ssh) (($#)) || die "usage: vm.sh ssh <name|ip> [command...]"; ssh_to "$@" ;;
    down) down "$1" ;;
    ls) ls_vms ;;
    *) sed -n '3,12p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
