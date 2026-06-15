## WPA2-Lab-Zero-Hardware: Containerized 4-Way Handshake & KRACK Attack Simulation
<img width="482" height="406" alt="ezgif com-animated-gif-maker (1)" src="https://github.com/user-attachments/assets/8ca77c1d-271f-4d6e-9e47-f290990e9d58" />






A fully containerized WPA2 security lab that demonstrates the IEEE 802.11i 4-way handshake using real `hostapd` and `wpa_supplicant` binaries running in isolated Docker containers, communicating over virtual 802.11 radios provided by `mac80211_hwsim`. The lab also includes a KRACK (CVE-2017-13077) attack demonstration using Mathy Vanhoef's original proof-of-concept scripts.

This replaces a previous approach that ran `mac80211_hwsim` directly on the host, which caused interface conflicts and was difficult to reproduce. Using Docker containers gives full process isolation, reproducible builds, and clean teardown.

---

## What This Lab Demonstrates

- A complete WPA2 4-way handshake between two Docker containers (`wpa2_ap` and `wpa2_client`)
- Capture of all 4 EAPOL frames in a Wireshark-readable `.pcap` file
- Independent cryptographic verification of PMK, PTK, KCK, KEK and TK using a custom Python analyzer
- Mathematical verification of all 3 handshake MICs (HMAC-SHA1)
- A working KRACK (Key Reinstallation Attack) demonstration using Mathy Vanhoef's `krackattacks-scripts`
- Confirmation that modern patched `wpa_supplicant` (v2.10) correctly rejects PTK reinstallation

---

## Architecture

```
┌─────────────────────────────┐        ┌─────────────────────────────┐
│      wpa2_ap container       │        │     wpa2_client container    │
│  hostapd v2.10 (WPA2-PSK)     │        │  wpa_supplicant v2.10         │
│  interface: wlan0             │◄──────►│  interface: wlan1             │
│  SSID: LabNet_01               │        │  PSK: LabPassphrase2024!       │
└──────────────┬────────────────┘        └──────────────┬────────────────┘
               │                                          │
               └──────────────┬───────────────────────────┘
                               │
                  mac80211_hwsim (virtual 802.11 radios)
                               │
                         hwsim0 (monitor interface)
                               │
                          tcpdump / Wireshark
```

For the KRACK demo, a third virtual radio `wlan2` is used by Mathy Vanhoef's modified `hostapd` to replay MSG3 of the 4-way handshake.

---

## Repository Structure

```
.
├── README.md                  This file
├── docker-compose.yml          Defines the AP and client containers
├── ap/
│   ├── Dockerfile
│   ├── hostapd.conf
│   └── start_ap.sh
├── client/
│   ├── Dockerfile
│   ├── wpa_supplicant.conf
│   └── start_client.sh
├── scripts/
│   ├── analyzer.py              Python MIC/PTK/PMK verification tool
│   ├── setup_interfaces.sh       Reload mac80211_hwsim and bring interfaces up
│   ├── run_handshake.sh          Run the full handshake capture
│   └── run_krack_demo.sh         Run the KRACK attack demonstration
├── shared/                       Output directory for captures and logs (gitignored)
└── docs/
    ├── REPRODUCTION_GUIDE.md     Full step-by-step reproduction guide
    └── KRACK_NOTES.md             KRACK attack background and result interpretation
```

---

## Prerequisites

- Ubuntu 22.04 LTS (tested on kernel 6.17, VM or bare metal)
- Docker + Docker Compose v2
- `mac80211_hwsim` kernel module support
- `wireshark`, `tcpdump`, `git`, `build-essential`

See [`docs/REPRODUCTION_GUIDE.md`](docs/REPRODUCTION_GUIDE.md) for full dependency installation steps.

---

## Quick Start

### 1. Clone and install dependencies

```bash
git clone https://github.com/mughees/wpa2-zero-hardware-krack-lab.git
cd wpa2-zero-hardware-krack-lab
sudo apt update && sudo apt install -y docker.io wireshark tcpdump git build-essential \
    libnl-3-dev libnl-genl-3-dev pkg-config libssl-dev net-tools sysfsutils python3-venv iw
sudo usermod -aG docker $USER && newgrp docker
sudo usermod -aG wireshark $USER && newgrp wireshark
```

### 2. Set up virtual radios

```bash
./scripts/setup_interfaces.sh
```

### 3. Run the handshake capture

```bash
./scripts/run_handshake.sh
```

This builds and starts both containers, captures the 4-way handshake to `shared/capture.pcap`, and prints the AP logs.

### 4. Verify with the Python analyzer

```bash
python3 scripts/analyzer.py
```

Expected output ends with:
```
MSG2 MIC : VALID
MSG3 MIC : VALID
MSG4 MIC : VALID
RESULT   : COMPLETE AND VERIFIED
```

### 5. Open the capture in Wireshark

```bash
wireshark shared/capture.pcap &
```

Apply the filter `eapol` to see all 4 handshake messages.

---

## KRACK Attack Demonstration

The KRACK demo requires Mathy Vanhoef's `krackattacks-scripts` repository (not included here — cloned separately due to its own build process).

NOTE:The KRACK demo requires modifications to your host system's hardware cryptography settings and **will require a system reboot**. 

```bash
git clone https://github.com/vanhoefm/krackattacks-scripts.git ~/krackattacks
cd ~/krackattacks/krackattack
./build.sh && ./pysetup.sh
source venv/bin/activate
pip install pycryptodome
sudo ./disable-hwcrypto.sh && sudo reboot
```

After reboot, follow [`docs/KRACK_NOTES.md`](docs/KRACK_NOTES.md) for the full 4-terminal procedure, or run:

```bash
./scripts/run_krack_demo.sh
```

**Expected result on a patched system (wpa_supplicant 2.7+):**
```
client DOESN'T reinstall the pairwise key in the 4-way handshake (this is good)
```

This confirms the attack infrastructure successfully replays MSG3 multiple times, but the patched client correctly refuses to reinstall the PTK — demonstrating the 2017 KRACK patches are effective.

---

## Cryptographic Background

| Key | Size | Derivation | Purpose |
|---|---|---|---|
| PSK | 8-63 ASCII | User password | Never transmitted |
| PMK | 256 bits | PBKDF2-SHA1(PSK, SSID, 4096 iters) | Pairwise Master Key |
| PTK | 512 bits | PRF-512(PMK, nonces, MACs) | Session key |
| KCK | 128 bits | PTK[0:16] | Computes handshake MICs |
| KEK | 128 bits | PTK[16:32] | Encrypts GTK in MSG3 |
| TK | 128 bits | PTK[32:48] | AES-CCMP data encryption |
| GTK | 128/256 bits | Random, AP-generated | Broadcast traffic key |

---

## Cleanup

```bash
docker-compose down
sudo modprobe -r mac80211_hwsim
sudo systemctl start NetworkManager
```

If you ran the KRACK demo, also re-enable hardware crypto:
```bash
sudo ~/krackattacks/krackattack/reenable-hwcrypto.sh
```

---

## Author

**Mughees**

---

## Ethics & Legal Notice

This lab is intended strictly for educational use in isolated, authorized environments. All traffic is generated between virtual interfaces created by `mac80211_hwsim` and never touches real Wi-Fi networks. Do not use these tools or techniques against networks you do not own or have explicit authorization to test.

---

## References

- Vanhoef, M. & Piessens, F. (2017). *Key Reinstallation Attacks: Forcing Nonce Reuse in WPA2*. CCS 2017.
- IEEE Standard 802.11i-2004
- [hostapd / wpa_supplicant documentation](https://w1.fi/)
- [krackattacks-scripts](https://github.com/vanhoefm/krackattacks-scripts)
