#!/usr/bin/env python3
"""
WPA2/WPA3 4-Way Handshake Analyzer

--proto wpa2 (default): extracts ANonce/SNonce/MACs, re-derives PMK/PTK/
KCK/KEK/TK from the known passphrase+SSID, and cryptographically verifies
the MIC of MSG2/MSG3/MSG4.

--proto wpa3: completion-detection only. WPA3-SAE's PMK is the output of
the SAE Dragonfly exchange (random per-session scalars, never transmitted),
not a static function of password+SSID, so the WPA2 MIC re-derivation path
does not apply. This mode counts EAPOL-Key frames and reports whether all 4
are present, with mic_verification=not_applicable in the result dict.

Usage:
    python3 analyzer.py [--proto wpa2|wpa3] [--quiet|--json] [pcap_path]
"""

import argparse
import json
import struct
import hashlib
import hmac
import sys
import os
from binascii import hexlify

SSID     = "LabNet_01"
PASSWORD = "LabPassphrase2024!"
SSID_WPA3     = "LabNet_WPA3"
PASSWORD_WPA3 = "LabPassphrase2024!"

DEFAULT_PCAP = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "shared", "capture.pcap"
)


def pmk_derive(password, ssid):
    return hashlib.pbkdf2_hmac("sha1", password.encode(), ssid.encode(), 4096, 32)


def prf512(key, label, data):
    result = b""
    for i in range(4):
        result += hmac.new(key, label + b"\x00" + data + bytes([i]), "sha1").digest()
    return result[:64]


def ptk_derive(pmk, anonce, snonce, ap_mac, cli_mac):
    macs   = min(ap_mac, cli_mac) + max(ap_mac, cli_mac)
    nonces = min(anonce, snonce)  + max(anonce, snonce)
    return prf512(pmk, b"Pairwise key expansion", macs + nonces)


def verify_mic(kck, eapol_frame):
    mic_received = eapol_frame[81:97]
    frame_zeroed = eapol_frame[:81] + b"\x00" * 16 + eapol_frame[97:]
    mic_computed = hmac.new(kck, frame_zeroed, "sha1").digest()[:16]
    return mic_received, mic_computed, mic_received == mic_computed


def read_pcap(filename):
    packets = []
    with open(filename, "rb") as f:
        magic = f.read(4)
        endian = "<" if magic == b"\xd4\xc3\xb2\xa1" else ">"
        f.read(20)
        while True:
            hdr = f.read(16)
            if len(hdr) < 16:
                break
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(endian + "IIII", hdr)
            packets.append((ts_sec, ts_usec, f.read(incl_len)))
    return packets


def find_eapol(packet_data):
    idx = packet_data.find(b"\x88\x8e")
    if idx == -1:
        return None
    return packet_data[idx + 2:]


def extract_eapol_fields(eapol):
    if len(eapol) < 99:
        return None
    fields = {
        "key_info":     struct.unpack("!H", eapol[5:7])[0],
        "key_length":   struct.unpack("!H", eapol[7:9])[0],
        "replay":       struct.unpack("!Q", eapol[9:17])[0],
        "nonce":        eapol[17:49],
        "mic":          eapol[81:97],
        "key_data_len": struct.unpack("!H", eapol[97:99])[0],
        "raw":          eapol,
    }
    ki = fields["key_info"]
    fields["mic_flag"]     = bool(ki & 0x0100)
    fields["install_flag"] = bool(ki & 0x0040)
    fields["ack_flag"]     = bool(ki & 0x0080)
    fields["secure_flag"]  = bool(ki & 0x0200)
    return fields


def extract_macs(packet_data):
    try:
        radiotap_len = struct.unpack("<H", packet_data[2:4])[0]
        dot11 = packet_data[radiotap_len:]
        return dot11[10:16], dot11[4:10]
    except Exception:
        return None, None


def analyze(pcap_path, verbose=True, proto="wpa2"):
    if proto not in ("wpa2", "wpa3"):
        raise ValueError(f"proto must be 'wpa2' or 'wpa3', got {proto!r}")

    out = {
        "pcap": pcap_path,
        "proto": proto,
        "result": "error",
        "error": None,
        "mic_verification": "performed" if proto == "wpa2" else "not_applicable",
    }

    if not os.path.exists(pcap_path):
        out["error"] = f"file not found: {pcap_path}"
        if verbose:
            print(f"[-] File not found: {pcap_path}")
        return out

    if verbose:
        label = "WPA2 4-WAY HANDSHAKE" if proto == "wpa2" else "WPA3-SAE (completion check only)"
        print("=" * 60)
        print(f"   {label} ANALYZER")
        print("=" * 60)
        print(f"\n[1] Reading pcap: {pcap_path}")

    packets = read_pcap(pcap_path)
    if verbose:
        print(f"    Packets found: {len(packets)}")
        print("\n[2] Extracting EAPOL frames...")

    eapol_frames, mac_pairs = [], []
    for _, _, data in packets:
        eapol = find_eapol(data)
        if eapol:
            fields = extract_eapol_fields(eapol)
            if fields:
                src, dst = extract_macs(data)
                eapol_frames.append(fields)
                mac_pairs.append((src, dst))
                if verbose:
                    n = len(eapol_frames)
                    print(f"    MSG{n} - Key Info: 0x{fields['key_info']:04x} "
                          f"| MIC: {'YES' if fields['mic_flag'] else 'NO'} "
                          f"| ACK: {'YES' if fields['ack_flag'] else 'NO'}")

    out["eapol_frames_found"] = len(eapol_frames)

    if len(eapol_frames) < 4:
        out["result"] = "incomplete"
        out["error"] = f"only {len(eapol_frames)} EAPOL frames found, need 4"
        if verbose:
            print(f"[-] {out['error']}")
        return out

    if verbose:
        print("    All 4 EAPOL frames found")

    # WPA3: completion detection only — stop here
    if proto == "wpa3":
        out["result"] = "verified"
        if verbose:
            print("\n[3] WPA3-SAE: skipping MIC verification (SAE-derived PMK)")
            print("\n" + "=" * 60)
            print("   RESULT: 4-WAY HANDSHAKE COMPLETED (WPA3-SAE)")
            print("   MIC verification: NOT APPLICABLE")
            print("=" * 60)
        return out

    # WPA2: full PMK/PTK/MIC path
    if verbose:
        print("\n[3] Extracting MACs and Nonces...")

    ap_mac  = mac_pairs[0][0]
    cli_mac = mac_pairs[0][1]
    anonce  = eapol_frames[0]["nonce"]
    snonce  = eapol_frames[1]["nonce"]

    if verbose:
        print(f"    AP  MAC : {hexlify(ap_mac).decode()}")
        print(f"    CLI MAC : {hexlify(cli_mac).decode()}")
        print(f"    ANonce  : {hexlify(anonce).decode()}")
        print(f"    SNonce  : {hexlify(snonce).decode()}")
        print("\n[4] Deriving PMK...")

    pmk = pmk_derive(PASSWORD, SSID)
    if verbose:
        print(f"    PMK: {hexlify(pmk).decode()}")
        print("\n[5] Deriving PTK...")

    ptk = ptk_derive(pmk, anonce, snonce, ap_mac, cli_mac)
    kck, kek, tk = ptk[:16], ptk[16:32], ptk[32:48]
    if verbose:
        print(f"    PTK: {hexlify(ptk).decode()}")
        print(f"    KCK: {hexlify(kck).decode()}")
        print(f"    KEK: {hexlify(kek).decode()}")
        print(f"    TK : {hexlify(tk).decode()}")

    if verbose:
        print("\n[6] Verifying MICs...")

    r2, c2, v2 = verify_mic(kck, eapol_frames[1]["raw"])
    r3, c3, v3 = verify_mic(kck, eapol_frames[2]["raw"])
    r4, c4, v4 = verify_mic(kck, eapol_frames[3]["raw"])

    if verbose:
        for n, rv, cv, valid in [(2, r2, c2, v2), (3, r3, c3, v3), (4, r4, c4, v4)]:
            print(f"    MSG{n} MIC received : {hexlify(rv).decode()}")
            print(f"    MSG{n} MIC computed : {hexlify(cv).decode()}")
            print(f"    MSG{n} STATUS       : {'VALID' if valid else 'INVALID'}")

    all_valid = v2 and v3 and v4
    out.update({
        "result":          "verified" if all_valid else "mic_invalid",
        "error":           None if all_valid else "one or more MICs did not verify",
        "ap_mac":          hexlify(ap_mac).decode(),
        "client_mac":      hexlify(cli_mac).decode(),
        "pmk":             hexlify(pmk).decode(),
        "ptk":             hexlify(ptk).decode(),
        "kck":             hexlify(kck).decode(),
        "kek":             hexlify(kek).decode(),
        "tk":              hexlify(tk).decode(),
        "msg2_mic_valid":  v2,
        "msg3_mic_valid":  v3,
        "msg4_mic_valid":  v4,
    })

    if verbose:
        print("\n" + "=" * 60)
        print("   FINAL SUMMARY")
        print("=" * 60)
        print(f"   SSID     : {SSID}")
        print(f"   PMK      : {hexlify(pmk).decode()[:32]}...")
        print(f"   KCK      : {hexlify(kck).decode()}")
        print(f"   TK       : {hexlify(tk).decode()}")
        print(f"   MSG2 MIC : {'VALID' if v2 else 'INVALID'}")
        print(f"   MSG3 MIC : {'VALID' if v3 else 'INVALID'}")
        print(f"   MSG4 MIC : {'VALID' if v4 else 'INVALID'}")
        print(f"   RESULT   : {'COMPLETE AND VERIFIED' if all_valid else 'FAILED'}")
        print("=" * 60)

    return out


def main():
    parser = argparse.ArgumentParser(description="WPA2/WPA3 handshake pcap analyzer")
    parser.add_argument("pcap", nargs="?", default=DEFAULT_PCAP)
    parser.add_argument("--proto", choices=["wpa2", "wpa3"], default="wpa2")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--quiet", action="store_true",
                      help="suppress output, exit 0/1 for pass/fail")
    mode.add_argument("--json", action="store_true",
                      help="print one-line JSON result, always exit 0")
    args = parser.parse_args()

    verbose = not (args.quiet or args.json)
    result = analyze(args.pcap, verbose=verbose, proto=args.proto)

    if args.json:
        print(json.dumps(result))
        sys.exit(0)

    if args.quiet:
        if result["result"] != "verified":
            print(f"ERROR: {result['result']}: {result['error']}", file=sys.stderr)
            sys.exit(1)
        sys.exit(0)

    if result["result"] != "verified":
        sys.exit(1)


if __name__ == "__main__":
    main()
