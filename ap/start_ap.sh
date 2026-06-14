#!/bin/bash

echo "[AP] Starting WPA2 Access Point..."
echo "[AP] Using interface: $IFACE"

ip link set $IFACE up
sed -i "s/interface=wlan0/interface=$IFACE/" /etc/hostapd/hostapd.conf

tcpdump -i $IFACE -w /shared/capture.pcap "ether proto 0x888e" &
echo "[AP] tcpdump capturing on $IFACE..."

sleep 2

echo "[AP] Launching hostapd..."
hostapd /etc/hostapd/hostapd.conf

echo "[AP] Done"
