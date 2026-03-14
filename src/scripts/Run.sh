#!/bin/bash

BLACKLIST_O="build/blacklist.o"
BLACKLIST_CONFIG_WRITER="build/blacklist_config_writer"
BLACKLIST_MAP="build/blacklist_map"

if [ "$EUID" -ne 0 ]; then
  echo "Error: Please run as root (use sudo)"
  exit 1
fi

check_files() {
    local files=("$BLACKLIST_O" "$BLACKLIST_CONFIG_WRITER" "$BLACKLIST_MAP")
    for file in "${files[@]}"; do
        if [ ! -f "$file" ]; then
            echo "Error: $file not found! Run 'make' first."
            exit 1
        fi
    done
}

select_interface() {
    local interfaces=$(ip -o link show | awk -F': ' '{print $2}' | grep -v "lo")
    echo "Available network interfaces:"
    select opt in $interfaces "Exit"; do
        if [ "$opt" == "Exit" ]; then
            exit 0
        elif [ -n "$opt" ]; then
            IFACE=$opt
            break
        else
            echo "Invalid selection."
        fi
    done
}

check_files
select_interface

echo "------------------------------------------------"
echo "Step 1: Loading XDP program onto $IFACE..."
ip link set "$IFACE" xdpgeneric obj "$BLACKLIST_O" sec prog
if [ $? -ne 0 ]; then
    echo "FAILED: Could not load $BLACKLIST_O"
    exit 1
fi
echo "SUCCESS: XDP program loaded."

echo "------------------------------------------------"
echo "Step 2: Starting Configuration Writer..."
./"$BLACKLIST_CONFIG_WRITER"
if [ $? -ne 0 ]; then
    echo "FAILED: Configuration writer exited with error."
    exit 1
fi

echo "------------------------------------------------"
echo "Step 3: Populating eBPF Maps..."
./"$BLACKLIST_MAP"
if [ $? -ne 0 ]; then
    echo "FAILED: Map loader (blacklist_map) failed."
    exit 1
fi

echo "------------------------------------------------"
echo "DEPLOYMENT COMPLETE"
echo "Interface: $IFACE"
echo "Status: Active"
echo "------------------------------------------------"