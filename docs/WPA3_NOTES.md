# WPA3-SAE Implementation and Feasibility Notes

This document covers the WPA3-SAE configuration used in this testbed,
the feasibility research performed before implementation, known
limitations of the mac80211_hwsim simulation substrate for SAE, and
guidance on running and interpreting the WPA3 trial experiments.

---

## Protocol Configuration

### AP side — `ap/hostapd_wpa3.conf`

| Parameter | Value | Reason |
|---|---|---|
| `wpa_key_mgmt` | `SAE` | WPA3-Personal mode |
| `sae_password` | `LabPassphrase2024!` | Replaces `wpa_passphrase` for SAE |
| `sae_groups` | `19` | NIST P-256 — mandatory group, universally supported |
| `sae_pwe` | `2` | Accept both hunting-and-pecking and H2E |
| `ieee80211w` | `2` | MFP required — WPA3 mandates this |
| `rsn_pairwise` | `CCMP` | AES-128, same as WPA2 |
| `disable_pmksa_caching` | `1` | Forces full SAE exchange per trial |

### Client side — `client/wpa_supplicant_wpa3.conf`

All settings mirror the AP. The critical ones:
- `key_mgmt=SAE` — selects SAE key management
- `sae_pwe=2` — must match the AP exactly; mismatch causes silent
  connection failure
- `ieee80211w=2` — must match the AP's required MFP setting

### Why SAE group 19 only

Groups 20 (P-384) and 21 (P-521) are optional and heavier. The upstream
`hostap` test suite (`tests/hwsim/test_sae.py`) explicitly notes:

> "mac80211_hwsim does not support SAE offload, so accept both a
> successful connection and association rejection."

Heavier optional groups are exactly where this lack of offload causes
non-deterministic timeouts in hwsim, independent of hostapd/wpa_supplicant
correctness. Group 19 is the well-tested, CI-validated path. Pinning
to group 19 eliminates this source of non-determinism from the
reliability experiment.

### Why sae_pwe=2

`sae_pwe` controls the Password Element derivation method:
- `0` = hunting-and-pecking only (older, timing side-channel risk)
- `1` = hash-to-element (H2E) only (newer, constant-time)
- `2` = accept both

H2E became the default in some hostapd/wpa_supplicant versions after
the Dragonblood disclosure (CVE-2019-9494). Setting `sae_pwe=2` on
both sides prevents version-mismatch failures when the AP and client
have different defaults, which would otherwise cause silent connection
failures with no useful error message.

### Why ieee80211w=2 is mandatory for WPA3

WPA3-Personal requires Management Frame Protection (MFP). If the AP
sets `ieee80211w=2` (required) and the client sets `ieee80211w=1`
(optional) or `ieee80211w=0` (disabled), the association is rejected.
Both sides must be set to `2`. This differs from the WPA2 configuration
in this testbed which uses `ieee80211w=1` (optional) to match common
deployment practice.

---

## How Protocol Selection Works

The `PROTO` environment variable controls which config is used at
runtime without rebuilding images:

```bash
# WPA2-PSK (default)
docker-compose up -d

# WPA3-SAE
PROTO=wpa3 docker-compose up -d
```

The startup scripts (`ap/start_ap.sh` and `client/start_client.sh`)
read `$PROTO` and select the appropriate config file:

```
PROTO=wpa2 → /etc/hostapd/hostapd.conf
PROTO=wpa3 → /etc/hostapd/hostapd_wpa3.conf
```

This means the same container images handle both protocols. The
images only need to be rebuilt if the Dockerfiles change, not when
switching between WPA2 and WPA3.

---

## Key Difference from WPA2: PMK Derivation

This is the most important technical distinction for understanding
the analyzer's behaviour.

**WPA2-PSK:**
```
PMK = PBKDF2-SHA1(password, SSID, 4096 iterations, 32 bytes)
```
This is a static, deterministic function of the password and SSID.
Anyone who knows both can recompute the PMK offline — which is what
`analyzer.py` does to verify handshake MICs independently.

**WPA3-SAE:**
The PMK is the output of the SAE (Dragonfly) commit/confirm exchange.
It depends on random private scalars generated fresh per session by
both the AP and client. These scalars are never transmitted and are
not present in any pcap file. The PMK therefore cannot be recomputed
from a capture alone.

**Consequence for the analyzer:**
`analyzer.py` runs in `--proto wpa3` mode for WPA3 trials. In this
mode it performs completion detection only — confirming that all four
EAPOL-Key frames are present — and reports
`mic_verification=not_applicable` rather than attempting MIC
verification with the wrong formula. Attempting WPA2 MIC verification
on a WPA3 capture would silently produce `mic_invalid` for every
trial, which would be a misleading false negative.

---

## Running WPA3 Trials

### Pilot run first (always)

Before committing to N=100, run 5 trials to confirm SAE works on
your specific kernel/hwsim combination:

```bash
./scripts/setup_interfaces.sh 3
./harness/trial_handshake.sh 5 15 wpa3
cat harness/results/handshake_trials_wpa3.csv
```

All 5 should show `result=success`. If you see a high timeout rate,
check the troubleshooting section below before running the full
experiment.

### Full run

```bash
./harness/trial_handshake.sh 100 15 wpa3
```

Results are written to `harness/results/handshake_trials_wpa3.csv`.
The `mic_verification` column will show `not_applicable` for all WPA3
rows — this is correct and expected, not an error.

### Comparing WPA2 and WPA3

Run both experiments and compare the two CSVs:

```bash
./harness/trial_handshake.sh 100 15 wpa2
./harness/trial_handshake.sh 100 15 wpa3

# Quick comparison
python3 - << 'PYEOF'
import pandas as pd
wpa2 = pd.read_csv('harness/results/handshake_trials_wpa2.csv')
wpa3 = pd.read_csv('harness/results/handshake_trials_wpa3.csv')
for name, df in [('WPA2', wpa2), ('WPA3', wpa3)]:
    s = df[df['result']=='success']['up_to_complete_s']
    print(f"{name}: {len(s)}/100 success, mean={s.mean():.3f}s, std={s.std():.3f}s")
PYEOF
```

---

## Known Limitations

### mac80211_hwsim SAE offload

mac80211_hwsim does not implement SAE offload. The upstream hostap
project's own automated test suite acknowledges this explicitly in
`tests/hwsim/test_sae.py`. In practice this means:

- Basic SAE with group 19 works reliably — this is what the trial
  harness uses and what the upstream CI validates continuously.
- Heavier optional groups (20, 21) can trigger non-deterministic
  association rejections on newer kernels, unrelated to
  hostapd/wpa_supplicant correctness.
- WPA3 timeout failures observed in experiments are attributable to
  this hwsim limitation, not to protocol instability.

### MIC verification not available for WPA3

As described above, the SAE-derived PMK is not recoverable from a
pcap. WPA3 trials therefore report completion (4 EAPOL frames
present) rather than cryptographic correctness. The handshake is
still a genuine WPA3-SAE exchange — only the offline independent
verification step differs from WPA2.

### Latency metric includes container overhead

The reported latency (from `docker-compose up -d` to
`EAPOL_4WAY_HS_COMPLETED`) includes container startup time, interface
initialization, wpa_supplicant scan, and the full authentication
sequence. It is an end-to-end framework startup metric rather than
a pure SAE protocol timing measurement. Both WPA2 and WPA3 are
measured under identical conditions so the relative comparison
is valid, but the absolute values should not be compared to
measurements taken on physical hardware.

---

## Dragonblood Context

Vanhoef and Ronen (IEEE S&P 2020) disclosed that WPA3-SAE
implementations in multiple vendors were vulnerable to:

- **CVE-2019-9494** — timing side-channel on the SAE hunting-and-
  pecking loop, enabling offline dictionary attacks.
- **CVE-2019-9495** — cache-based side-channel on the same loop.
- **Denial-of-service** — commit frame flooding causing AP resource
  exhaustion.

These were mitigated through:
1. The SAE hash-to-element (H2E) derivation method (constant-time,
   no loop), specified in IEEE 802.11-2020 and enabled by
   `sae_pwe=1` or `sae_pwe=2`.
2. Anti-clogging tokens for the DoS vector.

The `sae_pwe=2` setting in this testbed accepts both H&P and H2E,
allowing the AP and client to negotiate H2E when both support it
(which hostapd/wpa_supplicant v2.10 does), providing the
Dragonblood mitigations by default.

---

## References

- M. Vanhoef and E. Ronen, "Dragonblood: Analyzing the Dragonfly
  Handshake of WPA3 and EAP-pwd," IEEE S&P 2020.
- D. Harkins, "Dragonfly Key Exchange," RFC 7664, IETF, 2015.
- IEEE Std 802.11-2020 (SAE-H2E specification).
- J. Malinen, mac80211_hwsim kernel documentation:
  https://www.kernel.org/doc/html/latest/networking/mac80211_hwsim/
