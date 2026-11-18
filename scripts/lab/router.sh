#!/usr/bin/env bash
#
# The lab's router: OPNsense on a VM of its own, run inside the `hlb-lab` container.
#
#   router.sh up       made on first use (image fetched and checked), booted otherwise
#   router.sh key      an API key for root, written to /vms/opn1/apikey.txt — the file
#                      `hlb router connect` reads, as the interface would download it
#   router.sh down     powered off
#   router.sh console  the serial console (Ctrl-] then q to leave... socat: Ctrl-C)
#
# Its LAN (vtnet0) is on the house's bridge at 10.77.0.3, its WAN (vtnet1) on the
# internet's at 10.99.0.3: the house's gateway and public address, as a box's would be.
# `up` addresses it, and points the house's DHCP and its running nodes at the router —
# the house has no way out while it is down. 🔴 OPNsense's own DHCP is turned off before its LAN ever
# reaches br0: it serves 192.168.1.0/24 out of the box, and a node rebooting would take
# the first offer — the lab's dnsmasq stays the house's DHCP. Reached over SSH by the
# lab's key (`vm.sh ssh opn1`), root/opnsense on the console.
#
# 🔴 A hard stop of the host leaves its disk UNBOOTABLE: twice on 2026-11-18 (Docker
# restarted, then the host rebooted) the loader read garbage for /boot.config ("No
# accep") — nano's UFS does not survive a killed QEMU, where the Debian VMs' ext4 does.
# Nothing on the console says so; a screendump over QMP shows it. `router.sh down`
# before stopping the lab; otherwise move disk.qcow2 and bootstrapped aside and `up`
# rebuilds it, with a new certificate — `hlb router connect` again.

set -euo pipefail

VMS=/vms
NAME=opn1
DIR=$VMS/$NAME
KEY=$VMS/keys/id_ed25519
LAN=10.77.0.3
WAN=10.99.0.3
RELEASE=26.7
# From the release's checksums file (pkg.opnsense.org/releases/26.7/), the same as the
# announcement's: the image is refused unless it matches.
SHA256=28d5e2f37e40d87468a924e3006ef10e2ddc6de485b85333d9e3958c84d0cb9d
IMAGE=$VMS/base/opnsense-$RELEASE.img

die() { echo "router.sh: $*" >&2; exit 1; }

running() {
    [[ -f $DIR/qemu.pid ]] || return 1
    ps -o stat= -p "$(cat "$DIR/qemu.pid")" 2>/dev/null | grep -qv Z
}

ssh_opn() {
    ssh -i "$KEY" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o LogLevel=ERROR -o ConnectTimeout=3 "root@$LAN" "$@"
}

image() {
    [[ -f $IMAGE ]] && return
    local part=$VMS/base/opnsense-$RELEASE.img.bz2.part
    echo "fetching OPNsense $RELEASE" >&2
    curl -fL --retry 3 -o "$part" \
        "https://pkg.opnsense.org/releases/$RELEASE/OPNsense-$RELEASE-nano-amd64.img.bz2"
    echo "$SHA256  $part" | sha256sum -c --quiet || { rm -f "$part"; die "checksum mismatch"; }
    bunzip2 -c "$part" >"$IMAGE.part"
    mv "$IMAGE.part" "$IMAGE"
    rm -f "$part"
}

# Types lines on the serial console, one connection for all: separate connections lost
# the password typed while `login` was still starting.
console_type() { # <seconds to wait after> <line>...
    local wait=$1
    shift
    { sleep 0.5; for l in "$@"; do printf '%s\r' "$l"; sleep 2; done; sleep "$wait"; } |
        socat - "UNIX-CONNECT:$DIR/console.sock" >/dev/null
}

# The first boot's configuration, fetched by the router over a bridge of its own: typed
# on the console, a long line wraps at 80 columns and breaks.
bootstrap() {
    local pub
    pub=$(base64 -w0 "$KEY.pub")
    cat >"$DIR/setup.sh" <<EOF
set -e
c=/conf/config.xml
[ -f /conf/config.xml.lab-orig ] || cp \$c /conf/config.xml.lab-orig
sed -i "" -e "s|<ipaddr>192.168.1.1</ipaddr>|<ipaddr>$LAN</ipaddr>|" \$c
sed -i "" -e "/<dnsmasq /,/<\/dnsmasq>/ s|<enable>1</enable>|<enable>0</enable>|" \$c
grep -q "<permitrootlogin>" \$c || sed -i "" -e "s|<ssh>|<ssh><enabled>enabled</enabled><permitrootlogin>1</permitrootlogin>|" \$c
sed -i "" -e "/<name>root<\/name>/,/<\/user>/ s|<authorizedkeys/>|<authorizedkeys>$pub</authorizedkeys>|" \$c
EOF
    printf '#!/bin/sh\nprintf "HTTP/1.0 200 OK\\r\\n\\r\\n"\ncat %s\n' "$DIR/setup.sh" >"$DIR/serve"
    chmod +x "$DIR/serve"

    ip link show bropn >/dev/null 2>&1 || {
        ip link add bropn type bridge
        ip addr add 192.168.1.2/24 dev bropn
        ip link set bropn up
    }
    ip link set tap3 master bropn
    socat TCP-LISTEN:8000,bind=192.168.1.2,reuseaddr EXEC:"$DIR/serve" &
    local server=$!

    echo "waiting for the first boot's login prompt" >&2
    local i
    for i in $(seq 1 120); do grep -qa 'login:' "$DIR/console.log" 2>/dev/null && break; sleep 5; done
    console_type 3 root opnsense 8 'fetch -qo - http://192.168.1.2:8000/ | sh && reboot'
    kill "$server" 2>/dev/null || true

    ip link set tap3 master br0
    ip link del bropn
    touch "$DIR/bootstrapped"
}

up() {
    if running; then
        wan
        echo "$NAME already running, the house's gateway at $WAN"
        return
    fi
    ip link show br0 >/dev/null 2>&1 || /lab/vm.sh net >/dev/null
    mkdir -p "$DIR"
    if [[ ! -f $DIR/disk.qcow2 ]]; then
        image
        qemu-img create -q -f qcow2 -b "$IMAGE" -F raw "$DIR/disk.qcow2" 8G
    fi
    echo "$LAN" >"$DIR/ip"
    local t
    for t in tap3:br0 tapi3:brinet; do
        ip tuntap add dev "${t%%:*}" mode tap 2>/dev/null || true
        ip link set "${t%%:*}" master "${t##*:}" up
    done
    # Kept off the house until its DHCP is off: see the header.
    [[ -f $DIR/bootstrapped ]] || ip link set tap3 nomaster
    rm -f "$DIR/qmp.sock" "$DIR/console.sock"
    qemu-system-x86_64 -enable-kvm -cpu host -m 2048 -smp 2 -name "$NAME" \
        -drive "file=$DIR/disk.qcow2,if=none,id=d0" -device virtio-blk-pci,drive=d0 \
        -netdev tap,id=n0,ifname=tap3,script=no,downscript=no \
        -device virtio-net-pci,netdev=n0,mac=52:54:00:77:00:03 \
        -netdev tap,id=n1,ifname=tapi3,script=no,downscript=no \
        -device virtio-net-pci,netdev=n1,mac=52:54:00:99:00:03 \
        -device virtio-rng-pci -qmp "unix:$DIR/qmp.sock,server,nowait" -display none \
        -chardev "socket,id=c0,path=$DIR/console.sock,server=on,wait=off,logfile=$DIR/console.log,logappend=on" \
        -serial chardev:c0 -daemonize -pidfile "$DIR/qemu.pid"
    [[ -f $DIR/bootstrapped ]] || bootstrap

    local start=$SECONDS
    until ssh_opn true </dev/null 2>/dev/null; do
        ((SECONDS - start < 300)) || die "$NAME did not answer SSH in 300 s"
        sleep 5
    done
    wan
    echo "$NAME up at https://$LAN ($(ssh_opn opnsense-version </dev/null)), the house's gateway at $WAN"
    grep -a -A1 'HTTPS: SHA256' "$DIR/console.log" | tail -2
}

# The WAN addressed through the router's own models, then the house sent through it.
# Private sources are not blocked on it: the lab's internet is 10.99.0.0/24, and a WAN
# refusing them would refuse every client.
wan() {
    if ! ssh_opn "grep -q '<ipaddr>$WAN</ipaddr>' /conf/config.xml" </dev/null; then
        cat >"$DIR/wan.php" <<EOF
<?php
require_once("script/load_phalcon.php");
use OPNsense\Core\Config;
Config::getInstance()->lock();
\$gws = new OPNsense\Routing\Gateways();
\$have = false;
foreach (\$gws->gateway_item->iterateItems() as \$g) { \$have = \$have || (string)\$g->name == "WAN_GW"; }
if (!\$have) {
    \$gws->gateway_item->Add()->setNodes(["name" => "WAN_GW", "interface" => "wan",
        "ipprotocol" => "inet", "gateway" => "10.99.0.1", "defaultgw" => "1"]);
    \$gws->serializeToConfig(false, true);
}
\$w = Config::getInstance()->object()->interfaces->wan;
\$w->ipaddr = "$WAN"; \$w->subnet = "24"; \$w->gateway = "WAN_GW"; \$w->ipaddrv6 = "";
unset(\$w->blockpriv, \$w->blockbogons);
Config::getInstance()->save();
EOF
        ssh_opn 'cat > /tmp/wan.php' <"$DIR/wan.php"
        ssh_opn "sh -c 'cd /usr/local/opnsense/mvc && php /tmp/wan.php && rm /tmp/wan.php && /usr/local/etc/rc.reload_all'" \
            </dev/null >/dev/null
    fi
    ssh_opn "netstat -rn -f inet | grep -q '^default  *10.99.0.1 '" </dev/null ||
        die "$NAME's WAN has no default route through 10.99.0.1"

    # dnsmasq reads the gateway once, at start: `vm.sh net` starts it again with this one.
    if ! pgrep -af dnsmasq-hlb-lab | grep -q "option:router,$LAN"; then
        pkill -f dnsmasq-hlb-lab || true
        while pgrep -f dnsmasq-hlb-lab >/dev/null; do sleep 0.2; done
        /lab/vm.sh net >/dev/null
    fi
    # A running node would renew its lease only in hours: its route is changed now.
    local vm
    for vm in $(/lab/vm.sh ls | awk '$2 ~ /^10\.77\./ && $3 == "up" {print $1}'); do
        /lab/vm.sh ssh "$vm" ip route replace default via "$LAN" dev ens4 proto dhcp metric 100 </dev/null
    done
}

# The router's own model makes the key, as its interface does: the secret is shown
# once and the router keeps only its hash.
key() {
    cat >"$DIR/key.php" <<'EOF'
<?php
require_once("script/load_phalcon.php");
use OPNsense\Core\Config;
Config::getInstance()->lock();
$mdl = new OPNsense\Auth\User();
$k = $mdl->getUserByName("root")->apikeys->add();
$mdl->serializeToConfig(false, true);
Config::getInstance()->save();
echo "key=" . $k["key"] . "\nsecret=" . $k["secret"] . "\n";
EOF
    ssh_opn 'cat > /tmp/key.php' <"$DIR/key.php"
    (umask 077 && ssh_opn "sh -c 'cd /usr/local/opnsense/mvc && php /tmp/key.php; rm /tmp/key.php'" \
        </dev/null >"$DIR/apikey.txt")
    echo "root's API key in $DIR/apikey.txt"
}

down() {
    running || { echo "$NAME not running"; return; }
    printf '{"execute":"qmp_capabilities"}\n{"execute":"system_powerdown"}\n' |
        socat - "UNIX-CONNECT:$DIR/qmp.sock" >/dev/null 2>&1 || true
    local i
    for i in $(seq 1 60); do running || { echo "$NAME off"; return; }; sleep 2; done
    echo "$NAME ignored ACPI: killed" >&2
    kill "$(cat "$DIR/qemu.pid")"
}

case ${1:-} in
    up) up ;;
    key) key ;;
    down) down ;;
    console) exec socat -,raw,echo=0,escape=0x1d "UNIX-CONNECT:$DIR/console.sock" ;;
    *) sed -n '3,10p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
