#!/bin/bash
set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/lib_common.sh"

N="${1:-50}"
WINDOW_S="${2:-45}"
CSV_PATH="$RESULTS_DIR/krack_trials.csv"
KRACK_DIR="${KRACK_DIR:-$HOME/krackattacks/krackattack}"
CLIENT_CONF="/tmp/krack_client.conf"

csv_init "$CSV_PATH" "trial,timestamp_utc,msg1_count,msg3_replay_count,msg4_response_count,reinstall_detected,verdict_line,capture_window_s,pcap_path"

if [ ! -d "$KRACK_DIR" ]; then
    echo "[-] krackattacks-scripts not found at $KRACK_DIR"
    exit 1
fi

if [ ! -f "$CLIENT_CONF" ]; then
    sudo tee "$CLIENT_CONF" > /dev/null << 'EOF'
ctrl_interface=/var/run/wpa_supplicant
network={
    ssid="testnetwork"
    psk="abcdefgh"
    key_mgmt=WPA-PSK
    proto=RSN
    pairwise=CCMP
    group=CCMP
}
EOF
fi

echo "[*] KRACK replay resilience experiment"
echo "    Trials         : $N"
echo "    Capture window : ${WINDOW_S}s per trial"
echo "    CSV            : $CSV_PATH"
echo "    pcaps kept in  : $KRACK_CAPTURES_DIR"
echo ""
sudo -v

trap 'echo "[!] Interrupted - cleaning up"; \
      sudo pkill -f krack-test-client.py 2>/dev/null; \
      sudo pkill wpa_supplicant 2>/dev/null; \
      sudo pkill tcpdump 2>/dev/null; \
      dc down >/dev/null 2>&1' INT TERM

for trial in $(seq 1 "$N"); do
    print_progress "$trial" "$N" "KRACK trial"

    ts=$(now_iso)
    pcap_dest=$(unique_filename "$KRACK_CAPTURES_DIR" trial "$trial" pcap)
    krack_log="/tmp/krack_trial_${trial}.log"
    tcpdump_pid=""

    # ── Clean slate ────────────────────────────────────────────────────
    dc down >/dev/null 2>&1
    sudo pkill wpa_supplicant 2>/dev/null
    sudo pkill -f krack-test-client.py 2>/dev/null
    sudo pkill tcpdump 2>/dev/null
    sleep 1

    # Full hwsim reload — destroys monwlan2 and all residual state
    sudo modprobe -r mac80211_hwsim 2>/dev/null || true
    sleep 1
    sudo modprobe mac80211_hwsim radios=3
    sudo ip link set wlan0 up
    sudo ip link set wlan1 up
    sudo ip link set wlan2 up
    sudo ip link set hwsim0 up
    sleep 2

    # ── Step 1: Start victim AP (Terminal 1 equivalent) ────────────────
    echo "    Starting victim AP..."
    dc up -d ap >/dev/null 2>&1
    for i in $(seq 1 15); do
        if docker logs wpa2_ap 2>/dev/null | grep -q "AP-ENABLED"; then
            echo "    Victim AP enabled"
            break
        fi
        sleep 1
    done

    # ── Step 2: Start tcpdump (Terminal 2 equivalent) ──────────────────
    # Must start BEFORE KRACK script — matches manual procedure order
    sudo -v
    sudo tcpdump -i wlan2 -w "$pcap_dest" >/dev/null 2>&1 &
    tcpdump_pid=$!
    sleep 2
    echo "    tcpdump capturing on hwsim0 (pid=$tcpdump_pid)"

    # ── Step 3: Start KRACK rogue AP (Terminal 3 equivalent) ───────────
    (
        cd "$KRACK_DIR"
        source venv/bin/activate
        sudo -E "$(which python3)" -u krack-test-client.py
    ) > "$krack_log" 2>/dev/null &
    krack_pid=$!

    echo "    Waiting for rogue AP to be ready..."
    ready=0
    for i in $(seq 1 30); do
        if grep -q "Ready. Connect" "$krack_log" 2>/dev/null; then
            ready=1
            break
        fi
        sleep 1
    done

    if [ "$ready" = "0" ]; then
        echo "    -> SKIP: rogue AP did not become ready within 30s"
        sudo kill "$krack_pid" 2>/dev/null
        sudo kill -SIGINT "$tcpdump_pid" 2>/dev/null
        wait "$tcpdump_pid" 2>/dev/null
        dc down >/dev/null 2>&1
        csv_row "$CSV_PATH" "$trial,$ts,0,0,0,unknown,rogue AP did not become ready,$WINDOW_S,$pcap_dest"
        continue
    fi

    # ── Step 4: Connect victim client (Terminal 4 equivalent) ──────────
    echo "    Rogue AP ready — connecting victim client..."
    sudo killall wpa_supplicant 2>/dev/null
    sleep 1
    sudo wpa_supplicant -i wlan1 -D nl80211 -c "$CLIENT_CONF" >/dev/null 2>&1 &
    client_pid=$!

    # Wait for actual association before starting window
    echo "    Waiting for client to associate..."
    for i in $(seq 1 20); do
        if sudo iw dev wlan1 link 2>/dev/null | grep -q "Connected"; then
            echo "    Client associated — capture window starts (${WINDOW_S}s)..."
            break
        fi
        sleep 1
    done

    # ── Capture window — replays happen here ───────────────────────────
    sleep "$WINDOW_S"

    # ── Tear down ──────────────────────────────────────────────────────
    sudo kill "$client_pid" 2>/dev/null
    sudo kill "$krack_pid" 2>/dev/null
    sudo pkill -f krack-test-client.py 2>/dev/null
    sleep 0.5
    sudo kill -SIGINT "$tcpdump_pid" 2>/dev/null
    wait "$tcpdump_pid" 2>/dev/null
    sudo chmod 644 "$pcap_dest" 2>/dev/null
    dc down >/dev/null 2>&1

    # ── Parse results ──────────────────────────────────────────────────
      msg1_count=$(tshark -r "$pcap_dest" -Y "eapol" 2>/dev/null | grep -c "Message 1 of 4")
      msg3_count=$(tshark -r "$pcap_dest" -Y "eapol" 2>/dev/null | grep -c "Message 3 of 4")
      msg4_count=$(tshark -r "$pcap_dest" -Y "eapol" 2>/dev/null | grep -c "Message 4 of 4")
    [ -z "$msg1_count" ] && msg1_count=0
    [ -z "$msg3_count" ] && msg3_count=0
    [ -z "$msg4_count" ] && msg4_count=0

    verdict="no verdict line captured in window"
    reinstall_detected="unknown"
    if grep -q "DOESN'T reinstall the pairwise key" "$krack_log" 2>/dev/null; then
        verdict="client DOES NOT reinstall pairwise key (patched)"
        reinstall_detected="false"
    elif grep -qi "reinstall" "$krack_log" 2>/dev/null; then
        verdict=$(grep -i "reinstall" "$krack_log" | head -1)
        reinstall_detected="true"
    fi

    csv_row "$CSV_PATH" "$trial,$ts,$msg1_count,$msg3_count,$msg4_count,$reinstall_detected,$(csv_escape "$verdict"),$WINDOW_S,$pcap_dest"
    echo "    -> MSG3 replays=$msg3_count MSG4 responses=$msg4_count reinstall=$reinstall_detected"

    rm -f "$krack_log"
done

trap - INT TERM
echo ""
echo "[+] Done. $N trials -> $CSV_PATH"
echo "[+] All pcaps -> $KRACK_CAPTURES_DIR"
