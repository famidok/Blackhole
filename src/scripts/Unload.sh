#!/bin/bash

BPF_DIR="/sys/fs/bpf/xdp/globals"

echo "------------------------------------------------"
echo "  XDP UNLOADER & MAP CLEANER"
echo "------------------------------------------------"

INTERFACES=$(ip -o link show | awk -F': ' '{print $2}' | grep -v "lo")

echo "Available interfaces:"
select INTERFACE in $INTERFACES "Cancel"; do
    if [ "$INTERFACE" == "Cancel" ]; then
        echo "Operation cancelled."
        exit 0
    elif [ -n "$INTERFACE" ]; then
        echo "Selected interface: $INTERFACE"
        break
    else
        echo "Invalid selection. Please try again."
    fi
done

echo "Unloading XDP program from $INTERFACE..."
sudo ip link set dev $INTERFACE xdpgeneric off 2>/dev/null

echo "Removing pinned eBPF maps from $BPF_DIR..."

MAPS=(
    "three_tuples"
    "ip_pairs"
    "source_ips"
    "destination_ips"
    "dst_ports"
    "interfaces"
    "protocols"
    "ipv4_lpm_map"
)

for MAP in "${MAPS[@]}"; do
    if [ -f "$BPF_DIR/$MAP" ]; then
        sudo rm "$BPF_DIR/$MAP"
        echo "[+] Deleted: $MAP"
    else
        echo "[-] Not found: $MAP"
    fi
done

echo "------------------------------------------------"
echo "  Unload process complete."
echo "------------------------------------------------"