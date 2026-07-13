#!/bin/bash
#
# lib_common.sh — shared helpers for all trial harness scripts.
# Source this file: source "$(dirname "$0")/lib_common.sh"
#

HARNESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(cd "$HARNESS_DIR/.." && pwd)"
RESULTS_DIR="$HARNESS_DIR/results"
FAIL_HANDSHAKE_DIR="$RESULTS_DIR/failures/handshake"
FAIL_BUILD_DIR="$RESULTS_DIR/failures/container_build"
KRACK_CAPTURES_DIR="$RESULTS_DIR/krack_captures"

mkdir -p "$RESULTS_DIR" \
         "$FAIL_HANDSHAKE_DIR/wpa2" \
         "$FAIL_HANDSHAKE_DIR/wpa3" \
         "$FAIL_BUILD_DIR" \
         "$KRACK_CAPTURES_DIR"

# ── Timestamps ─────────────────────────────────────────────────────────────

now_iso() {
    date -u +"%Y-%m-%dT%H:%M:%SZ"
}

now_compact() {
    date -u +"%Y%m%d_%H%M%S"
}

now_epoch() {
    date +%s.%N
}

elapsed_s() {
    local start="$1" end="$2"
    awk -v s="$start" -v e="$end" 'BEGIN { printf "%.3f", (e - s) }'
}

# ── Unique filenames ───────────────────────────────────────────────────────
# unique_filename <dir> <prefix> <trial_num> <ext>
unique_filename() {
    local dir="$1" prefix="$2" trial_num="$3" ext="$4"
    local padded
    padded=$(printf "%03d" "$trial_num")
    echo "${dir}/${prefix}_${padded}_$(now_compact).${ext}"
}

# ── CSV helpers ────────────────────────────────────────────────────────────

# csv_init <path> <header>
# Writes header only if file does not already exist (so repeated runs append)
csv_init() {
    local path="$1" header="$2"
    if [ ! -f "$path" ]; then
        echo "$header" > "$path"
    fi
}

csv_row() {
    local path="$1" row="$2"
    echo "$row" >> "$path"
}

# csv_escape <field> — wraps in quotes if field contains comma/quote/newline
csv_escape() {
    local field="$1"
    if [[ "$field" == *,* || "$field" == *\"* || "$field" == *$'\n'* ]]; then
        field="${field//\"/\"\"}"
        echo "\"${field}\""
    else
        echo "$field"
    fi
}

# ── Docker helpers ─────────────────────────────────────────────────────────

dc() {
    (cd "$LAB_DIR" && docker-compose "$@")
}

# wait_for_handshake <timeout_seconds>
#
# Blocks until EAPOL_4WAY_HS_COMPLETED appears in wpa2_ap logs, or timeout.
# Uses `docker logs -f | grep -q -m1` (no poll loop, no re-scanning buffer).
# Echoes COMPLETED or TIMEOUT. Caller owns container teardown.
wait_for_handshake() {
    local timeout_s="${1:-15}"
    if timeout "$timeout_s" docker logs -f wpa2_ap 2>&1 \
        | grep -q -m1 "EAPOL-4WAY-HS-COMPLETED"; then
        echo "COMPLETED"
    else
        echo "TIMEOUT"
    fi
}

# ── Misc ───────────────────────────────────────────────────────────────────

print_progress() {
    local current="$1" total="$2" label="$3"
    echo "[*] [$current/$total] $label"
}
