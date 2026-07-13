#!/bin/bash
#
# trial_handshake.sh
#
# Handshake reliability/latency experiment for WPA2-PSK or WPA3-SAE.
#
# Usage:
#   ./trial_handshake.sh [N] [timeout_seconds] [proto]
#
#   N               number of trials (default 100)
#   timeout_seconds  per-trial handshake wait timeout (default 15)
#   proto            wpa2 (default) or wpa3
#
# Design:
#   - Restart-only per trial (no rebuild) -- isolates handshake reliability
#     from build reliability (measured by trial_container_build.sh).
#   - CSV row written for every trial: success, failure, and timeout.
#   - pcap kept only on failure/timeout; deleted on success.
#   - PROTO passed into containers via docker-compose env substitution.
#   - Analyzer called with matching --proto flag.
#   - 0.3s settle delay after handshake log line before stopping tcpdump,
#     closing the race between hostapd logging completion and tcpdump
#     flushing the last frame to disk.
#
set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/lib_common.sh"

N="${1:-100}"
TIMEOUT_S="${2:-15}"
PROTO="${3:-wpa2}"

if [ "$PROTO" != "wpa2" ] && [ "$PROTO" != "wpa3" ]; then
    echo "[-] proto must be 'wpa2' or 'wpa3', got: $PROTO" >&2
    exit 1
fi

export PROTO

CSV_PATH="$RESULTS_DIR/handshake_trials_${PROTO}.csv"
CAPTURE_SRC="$LAB_DIR/shared/capture.pcap"
FAIL_DIR="$FAIL_HANDSHAKE_DIR/$PROTO"
mkdir -p "$FAIL_DIR"

csv_init "$CSV_PATH" "trial,timestamp_utc,proto,up_to_complete_s,eapol_frames_found,mic_verification,msg2_mic_valid,msg3_mic_valid,msg4_mic_valid,result,error,pcap_path"

echo "[*] Handshake reliability experiment"
echo "    Protocol : $PROTO"
echo "    Trials   : $N"
echo "    Timeout  : ${TIMEOUT_S}s per trial"
echo "    CSV      : $CSV_PATH"
echo ""

echo "[*] Ensuring images are built (one-time)..."
dc build

trap 'echo ""; echo "[!] Interrupted"; dc down >/dev/null 2>&1' INT TERM

for trial in $(seq 1 "$N"); do
    print_progress "$trial" "$N" "handshake trial ($PROTO)"

    ts=$(now_iso)

    dc down >/dev/null 2>&1
    rm -f "$CAPTURE_SRC"

    sudo -n true 2>/dev/null || sudo -v
    sudo tcpdump -i hwsim0 -w "$CAPTURE_SRC" "ether proto 0x888e" >/dev/null 2>&1 &
    tcpdump_pid=$!
    sleep 1

    t_start=$(now_epoch)
    dc up -d >/dev/null 2>&1

    wait_status=$(wait_for_handshake "$TIMEOUT_S")
    t_end=$(now_epoch)
    duration=$(elapsed_s "$t_start" "$t_end")

    # Settle: give tcpdump time to flush the last frame before SIGINT
    sleep 0.3
    sudo kill -SIGINT "$tcpdump_pid" 2>/dev/null
    wait "$tcpdump_pid" 2>/dev/null
    sudo chmod 644 "$CAPTURE_SRC" 2>/dev/null

    dc down >/dev/null 2>&1

    if [ "$wait_status" = "TIMEOUT" ]; then
        pcap_dest=$(unique_filename "$FAIL_DIR" trial "$trial" pcap)
        cp "$CAPTURE_SRC" "$pcap_dest" 2>/dev/null
        mic_v="performed"; [ "$PROTO" = "wpa3" ] && mic_v="not_applicable"
        csv_row "$CSV_PATH" "$trial,$ts,$PROTO,$duration,0,$mic_v,,,,timeout,$(csv_escape "handshake did not complete within ${TIMEOUT_S}s"),$pcap_dest"
        echo "    -> TIMEOUT (${duration}s) - pcap: $pcap_dest"
        continue
    fi

    json=$(python3 "$LAB_DIR/scripts/analyzer.py" --proto "$PROTO" --json "$CAPTURE_SRC" 2>/dev/null)

    parsed=$(echo "$json" | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
except Exception as e:
    print(f'error|parse failed: {e}|0|unknown|||')
    sys.exit(0)
print('|'.join([
    str(d.get('result','error')),
    str(d.get('error') or ''),
    str(d.get('eapol_frames_found',0)),
    str(d.get('mic_verification','unknown')),
    str(d.get('msg2_mic_valid','')),
    str(d.get('msg3_mic_valid','')),
    str(d.get('msg4_mic_valid','')),
]))
" 2>/dev/null)

    [ -z "$parsed" ] && parsed="error|analyzer produced no output|0|unknown|||"

    IFS='|' read -r result error frames mic_v m2 m3 m4 <<< "$parsed"

    if [ "$result" = "verified" ]; then
        rm -f "$CAPTURE_SRC"
        csv_row "$CSV_PATH" "$trial,$ts,$PROTO,$duration,$frames,$mic_v,$m2,$m3,$m4,success,,"
        echo "    -> SUCCESS (${duration}s)"
    else
        pcap_dest=$(unique_filename "$FAIL_DIR" trial "$trial" pcap)
        cp "$CAPTURE_SRC" "$pcap_dest" 2>/dev/null
        csv_row "$CSV_PATH" "$trial,$ts,$PROTO,$duration,$frames,$mic_v,$m2,$m3,$m4,$result,$(csv_escape "$error"),$pcap_dest"
        echo "    -> FAIL ($result, ${duration}s) - pcap: $pcap_dest"
    fi
done

trap - INT TERM
echo ""
echo "[+] Done. $N trials ($PROTO) -> $CSV_PATH"
echo "[+] Failure pcaps (if any) -> $FAIL_DIR"
