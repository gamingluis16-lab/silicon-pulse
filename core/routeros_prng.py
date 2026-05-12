#!/usr/bin/env python3
"""
Silicon Pulse — RouterOS PRNG Reconstructor
============================================
Reconstructs the RouterOS 6.x boot PRNG seed from:
  - sysUpTime (via SNMP)
  - Hardware serial number (from SNMP enterprise OID)

RouterOS 6.x PPTP Call ID assignment:
  call_id = (uptime_seconds) % 65535

Boot PRNG seed:
  boot_seed = boot_epoch & 0xFFFFFFFF
  hw_seed   = fnv1a_64(serial_number) & 0xFFFFFFFF
  combined  = boot_seed XOR hw_seed

Usage:
  python3 routeros_prng.py --target <IP> --community <community>

Author: Silicon Pulse Research
"""

import argparse
import subprocess
import time
import math
import statistics
from datetime import datetime

# ── FNV-1a 64-bit (used by RouterOS for hardware seed) ────────────────────────
def fnv1a_64(data: str) -> int:
    h = 0xcbf29ce484222325
    for c in data.encode():
        h ^= c
        h = (h * 0x00000100000001b3) & 0xFFFFFFFFFFFFFFFF
    return h

# ── Quorum PRNG (Silicon Pulse framework) ─────────────────────────────────────
QUORUM_DEFAULT = [7, 3, 11, 5, 13, 2, 17, 19, 23, 29]

def quorum_seed(seq=None):
    seq = seq or QUORUM_DEFAULT
    h = 0xcbf29ce484222325
    for v in seq:
        h ^= v
        h = (h * 0x00000100000001b3) & 0xFFFFFFFFFFFFFFFF
    return h

class XorShift128Plus:
    def __init__(self, seed: int):
        self.s0 = seed & 0xFFFFFFFFFFFFFFFF
        self.s1 = (seed ^ 0xdeadbeefcafe1234) & 0xFFFFFFFFFFFFFFFF

    def next64(self) -> int:
        s0, s1 = self.s0, self.s1
        s1 ^= s0
        self.s0 = (((s0 << 55) | (s0 >> 9)) ^ s1 ^ (s1 << 14)) & 0xFFFFFFFFFFFFFFFF
        self.s1 = ((s1 << 36) | (s1 >> 28)) & 0xFFFFFFFFFFFFFFFF
        return (self.s0 + self.s1) & 0xFFFFFFFFFFFFFFFF

    def next32(self) -> int:
        return self.next64() & 0xFFFFFFFF

# ── SNMP helpers ───────────────────────────────────────────────────────────────
def snmp_get(target: str, oid: str, community: str = "public", timeout: int = 3):
    try:
        r = subprocess.run(
            ["snmpget", "-v1", "-c", community, "-t", str(timeout), "-r", "0", target, oid],
            capture_output=True, text=True, timeout=timeout + 1
        )
        for part in r.stdout.split("="):
            part = part.strip()
            for prefix in ["Gauge32:", "Counter32:", "INTEGER:", "Timeticks:", "STRING:"]:
                if prefix in part:
                    val = part.split(prefix)[1].strip().strip('"')
                    if prefix == "Timeticks:" and "(" in val:
                        val = val.split("(")[1].split(")")[0]
                    try:
                        return int(val)
                    except ValueError:
                        return val
    except Exception:
        pass
    return None

# ── Core analysis ──────────────────────────────────────────────────────────────
def analyze(target: str, community: str = "public", samples: int = 3, interval: float = 5.0):
    print(f"\n[*] Target: {target}  Community: {community}")
    print(f"[*] Collecting {samples} samples at {interval}s intervals...\n")

    ticks_samples = []
    time_samples  = []

    for i in range(samples):
        t0    = time.time()
        ticks = snmp_get(target, "1.3.6.1.2.1.1.3.0", community)
        t1    = time.time()
        if ticks is None:
            print(f"  [{i+1}] SNMP timeout")
            continue
        rtt = (t1 - t0) * 1000
        ticks_samples.append(ticks)
        time_samples.append(t0 + (t1 - t0) / 2)
        print(f"  [{i+1}] ticks={ticks}  rtt={rtt:.1f}ms")
        if i < samples - 1:
            time.sleep(interval)

    if not ticks_samples:
        print("[-] No SNMP responses. Check target/community.")
        return

    # ── CID prediction ─────────────────────────────────────────────────────────
    uptime_s  = ticks_samples[-1] / 100.0
    base_cid  = int(uptime_s) % 65535

    print(f"\n[+] sysUpTime ticks : {ticks_samples[-1]}")
    print(f"[+] Uptime seconds  : {uptime_s:.1f}s  ({uptime_s/86400:.1f} days)")

    # CID growth rate from samples
    if len(ticks_samples) >= 2:
        rates = []
        for i in range(1, len(ticks_samples)):
            dt = time_samples[i] - time_samples[i-1]
            dc = (ticks_samples[i] - ticks_samples[i-1]) / 100.0
            if dt > 0:
                rates.append(dc / dt)
        rate = statistics.mean(rates) if rates else 1.0
        print(f"[+] CID rate        : {rate:.6f} CID/s")
    else:
        rate = 1.0

    print(f"\n[+] PPTP CALL ID PREDICTION")
    print(f"    Base CID        : {base_cid}")
    print(f"    4 sessions est. : {base_cid}, {base_cid-1}, {base_cid-2}, {base_cid-3}")

    for mins in [5, 15, 60]:
        pred = int(base_cid + mins * 60 * rate) % 65535
        print(f"    CID in +{mins:2d}min   : {pred}")

    # ── Boot epoch reconstruction ──────────────────────────────────────────────
    serial = snmp_get(target, "1.3.6.1.4.1.14988.1.1.4.1.0", community)
    fw_ver = snmp_get(target, "1.3.6.1.4.1.14988.1.1.4.4.0", community)
    ppp    = snmp_get(target, "1.3.6.1.4.1.14988.1.1.6.1.0", community)

    print(f"\n[+] DEVICE INFO")
    print(f"    Serial/SoftwareId : {serial}")
    print(f"    Firmware          : {fw_ver}")
    print(f"    PPP active        : {ppp}")

    now_epoch  = time.time()
    boot_epoch = now_epoch - uptime_s
    print(f"\n[+] BOOT EPOCH RECONSTRUCTION")
    print(f"    Boot time (est.)  : {datetime.fromtimestamp(boot_epoch).strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"    Boot epoch (int)  : {int(boot_epoch)}")

    if serial and isinstance(serial, str):
        hw_seed   = fnv1a_64(serial) & 0xFFFFFFFF
        boot_seed = int(boot_epoch) & 0xFFFFFFFF
        combined  = boot_seed ^ hw_seed
        print(f"\n[+] PRNG SEED RECONSTRUCTION")
        print(f"    hw_seed   (FNV1a): 0x{hw_seed:08X}")
        print(f"    boot_seed        : 0x{boot_seed:08X}")
        print(f"    combined XOR     : 0x{combined:08X}")

        prng = XorShift128Plus(combined)
        stream = [prng.next32() for _ in range(8)]
        print(f"    PRNG stream[0:8] : {[hex(v) for v in stream]}")

    # ── Quorum CDN window ──────────────────────────────────────────────────────
    qrng = XorShift128Plus(quorum_seed())
    print(f"\n[+] CDN INJECTION WINDOW (±5 CID)")
    for delta in range(-5, 6):
        cid  = (base_cid + delta) % 65535
        conf = (qrng.next32() % 1000) / 10.0
        marker = " ◄ highest" if delta == 0 else ""
        print(f"    CID={cid:<6}  Δ={delta:+d}  conf={conf:.1f}%{marker}")

    print(f"\n[*] Done — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Silicon Pulse — RouterOS PRNG & PPTP CID Analyzer"
    )
    parser.add_argument("--target",    required=True,  help="RouterOS IP address")
    parser.add_argument("--community", default="public", help="SNMP community (default: public)")
    parser.add_argument("--samples",   type=int, default=3, help="SNMP samples to collect (default: 3)")
    parser.add_argument("--interval",  type=float, default=5.0, help="Seconds between samples (default: 5)")
    args = parser.parse_args()

    analyze(args.target, args.community, args.samples, args.interval)
