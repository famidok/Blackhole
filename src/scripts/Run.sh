#!/bin/bash

read -p "Enter the interface name (e.g., enp0s1): " IFACE

BLACKLIST_O="../build/blacklist.o"
BLACKLIST_CONFIG_WRITER="../build/blacklist_config_writer"
BLACKLIST_MAP="../build/blacklist_map"

if [ ! -f "$BLACKLIST_O" ]; then
    echo "Error: $BLACKLIST_O not found!"
    exit 1
fi

if [ ! -f "$BLACKLIST_CONFIG_WRITER" ]; then
    echo "Error: $BLACKLIST_CONFIG_WRITER not found!"
    exit 1
fi

if [ ! -f "$BLACKLIST_MAP" ]; then
    echo "Error: $BLACKLIST_MAP not found!"
    exit 1
fi

echo "Loading blacklist.o object requires sudo privileges..."
sudo ip link set "$IFACE" xdpgeneric obj "$BLACKLIST_O" sec prog
if [ $? -ne 0 ]; then
    echo "Failed to load blacklist.o!"
    exit 1
fi

echo "Running blacklist_config_writer..."
"$BLACKLIST_CONFIG_WRITER"
if [ $? -ne 0 ]; then
    echo "blacklist_config_writer failed!"
    exit 1
fi

echo "Running blacklist_map with sudo..."
sudo "$BLACKLIST_MAP"
if [ $? -ne 0 ]; then
    echo "blacklist_map failed!"
    exit 1
fi

echo "All operations completed successfully."
