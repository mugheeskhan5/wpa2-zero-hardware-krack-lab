#!/bin/bash
#
# PROTO env var selects which config to run:
#   PROTO=wpa2 (default) -> wpa_supplicant.conf      (WPA2-PSK)
#   PROTO=wpa3           -> wpa_supplicant_wpa3.conf  (WPA3-SAE)
#
PROTO="${PROTO:-wpa2}"

if [ "$PROTO" = "wpa3" ]; then
    CONF_SRC="/etc/wpa_supplicant/wpa_supplicant_wpa3.conf"
    LABEL="WPA3-SAE"
else
    CONF_SRC="/etc/wpa_supplicant/wpa_supplicant.conf"
    LABEL="WPA2-PSK"
fi

echo "[CLIENT] Starting $LABEL Client..."
echo "[CLIENT] Using interface: $IFACE"
echo "[CLIENT] Using config: $CONF_SRC"

ip link set $IFACE up

killall wpa_supplicant 2>/dev/null
sleep 1

echo "[CLIENT] Waiting for AP to be ready..."
sleep 8

echo "[CLIENT] Launching wpa_supplicant ($LABEL)..."
wpa_supplicant -i $IFACE \
    -D nl80211 \
    -c "$CONF_SRC" \
    -d 2>&1 | tee /shared/client_log.txt

echo "[CLIENT] Done"
