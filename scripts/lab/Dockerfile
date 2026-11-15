# The lab: one privileged container holding the house's network (br0, 10.77.0.0/24) and
# its VMs, and bridging a VPS onto the Docker network `hlb-internet`. Built and run by
# scripts/lab/lab.sh; the scripts are mounted, not copied, so an edit needs no rebuild.
FROM debian:bookworm

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        bash ca-certificates cloud-image-utils curl dnsmasq-base iproute2 iptables \
        openssh-client ovmf procps qemu-system-x86 qemu-utils socat swtpm swtpm-tools \
        tcpdump wireguard-tools \
    && rm -rf /var/lib/apt/lists/*

# The drills name these paths. The key lives with the disks, so a rebuilt container
# still reaches VMs that were given it.
RUN mkdir -p /lab \
    && ln -s src/vm.sh /lab/vm.sh \
    && ln -s src/vps.sh /lab/vps.sh \
    && ln -s /vms/keys/id_ed25519 /lab/id_ed25519 \
    && ln -s /vms/keys/id_ed25519.pub /lab/id_ed25519.pub

CMD ["sleep", "infinity"]
