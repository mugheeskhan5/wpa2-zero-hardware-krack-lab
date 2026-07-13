#!/bin/bash
#
# trial_container_build.sh
#
# Container reliability experiment: N full cold-rebuild cycles.
#
# Usage:
#   ./trial_container_build.sh [N] [timeout_seconds]
#
#   N               number of trials (default 20)
#   timeout_seconds  per-trial handshake wait timeout (default 15)
#
# Design:
#   - Each trial: down -> build --no-cache (timed) -> up -d (timed) ->
#     wait for handshake completion (timed) -> tear down.
#   - --no-cache is mandatory: without it Docker's layer cache makes
#     runs 2-20 artificially fast (~3s vs ~50s), stopping the experiment
#     from measuring what it claims to (cold build reliability).
#   - Build time and up-to-completion time are recorded separately.
#   - CSV row written for every trial regardless of outcome.
#   - Failed build logs kept in failures/container_build/.
#   - At ~50s/cycle, N=20 takes ~17 minutes total.
#
set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/lib_common.sh"

N="${1:-20}"
TIMEOUT_S="${2:-15}"
CSV_PATH="$RESULTS_DIR/container_build_trials.csv"
CAPTURE_SRC="$LAB_DIR/shared/capture.pcap"

csv_init "$CSV_PATH" "trial,timestamp_utc,build_time_s,up_to_complete_s,total_cycle_s,build_result,handshake_result,error"

echo "[*] Container reliability experiment (cold rebuild each trial)"
echo "    Trials  : $N"
echo "    Timeout : ${TIMEOUT_S}s handshake wait per trial"
echo "    Est.    : ~$((N * 50 / 60)) minutes total at ~50s/cycle"
echo "    CSV     : $CSV_PATH"
echo ""

trap 'echo ""; echo "[!] Interrupted"; dc down >/dev/null 2>&1' INT TERM

for trial in $(seq 1 "$N"); do
    print_progress "$trial" "$N" "container build trial"

    ts=$(now_iso)
    build_result="success"
    handshake_result="not_attempted"
    error=""

    dc down >/dev/null 2>&1
    rm -f "$CAPTURE_SRC"

    # ── Timed: cold build ──────────────────────────────────────────────
    t_build_start=$(now_epoch)
    if ! dc build --no-cache > "/tmp/build_trial_${trial}.log" 2>&1; then
        build_result="fail"
        error="docker-compose build --no-cache failed"
    fi
    t_build_end=$(now_epoch)
    build_time=$(elapsed_s "$t_build_start" "$t_build_end")

    if [ "$build_result" = "fail" ]; then
        log_dest=$(unique_filename "$FAIL_BUILD_DIR" trial "$trial" log)
        cp "/tmp/build_trial_${trial}.log" "$log_dest" 2>/dev/null
        csv_row "$CSV_PATH" "$trial,$ts,$build_time,,,$build_result,$handshake_result,$(csv_escape "$error")"
        echo "    -> BUILD FAILED (${build_time}s) - log: $log_dest"
        rm -f "/tmp/build_trial_${trial}.log"
        dc down >/dev/null 2>&1
        continue
    fi

    # ── Timed: up + handshake ──────────────────────────────────────────
    sudo -n true 2>/dev/null || sudo -v
    sudo tcpdump -i hwsim0 -w "$CAPTURE_SRC" "ether proto 0x888e" >/dev/null 2>&1 &
    tcpdump_pid=$!
    sleep 1

    t_up_start=$(now_epoch)
    dc up -d >/dev/null 2>&1
    wait_status=$(wait_for_handshake "$TIMEOUT_S")
    t_up_end=$(now_epoch)
    up_time=$(elapsed_s "$t_up_start" "$t_up_end")
    total_cycle=$(elapsed_s "$t_build_start" "$t_up_end")

    sleep 0.3
    sudo kill -SIGINT "$tcpdump_pid" 2>/dev/null
    wait "$tcpdump_pid" 2>/dev/null

    dc down >/dev/null 2>&1
    rm -f "$CAPTURE_SRC" "/tmp/build_trial_${trial}.log"

    if [ "$wait_status" = "TIMEOUT" ]; then
        handshake_result="timeout"
        error="handshake did not complete within ${TIMEOUT_S}s after successful build"
    else
        handshake_result="success"
    fi

    csv_row "$CSV_PATH" "$trial,$ts,$build_time,$up_time,$total_cycle,$build_result,$handshake_result,$(csv_escape "$error")"
    echo "    -> build=${build_time}s up_to_complete=${up_time}s total=${total_cycle}s handshake=$handshake_result"
done

trap - INT TERM
echo ""
echo "[+] Done. $N trials -> $CSV_PATH"
echo "[+] Failed build logs (if any) -> $FAIL_BUILD_DIR"
