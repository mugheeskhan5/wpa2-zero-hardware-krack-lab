#!/bin/bash
#
# PROTO env var selects which config to run:
#   PROTO=wpa2 (default) -> hostapd.conf       (WPA2-PSK)
#   PROTO=wpa3           -> hostapd_wpa3.conf   (WPA3-SAE)
#
PROTO="${PROTO:-wpa2}"

if [ "$PROTO" = "wpa3" ]; then
    CONF_SRC="/etc/hostapd/hostapd_wpa3.conf"
    LABEL="WPA3-SAE"
else
    CONF_SRC="/etc/hostapd/hostapd.conf"
    LABEL="WPA2-PSK"
fi

echo "[AP] Starting $LABEL Access Point..."
echo "[AP] Using interface: $IFACE"
echo "[AP] Using config: $CONF_SRC"

ip link set $IFACE up
sed -i "s/interface=wlan0/interface=$IFACE/" "$CONF_SRC"

tcpdump -i $IFACE -w /shared/capture.pcap "ether proto 0x888e" &
echo "[AP] tcpdump capturing on $IFACE..."

sleep 2

echo "[AP] Launching hostapd ($LABEL)..."
hostapd "$CONF_SRC"

echo "[AP] Done"
