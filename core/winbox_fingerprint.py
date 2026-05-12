#!/usr/bin/env python3
"""
Silicon Pulse — Winbox Session Fingerprinter
=============================================
Detects active Winbox admin sessions on RouterOS devices
via SNMP MGMT interface traffic analysis.

Winbox keepalive signature:
  - Period:  ~60 seconds (configurable by RouterOS)
  - Size:    148–310 bytes per interval
  - Pattern: Alternating 3 sizes (e.g. 1648/1698/1748B)
  - Entropy: 1.35 bits (semi-periodic)

No Winbox credentials or protocol decoding required —
purely passive SNMP-based detection.

Usage:
  python3 winbox_fingerprint.py --target <IP> --mgmt-iface <index>

  # Auto-discover MGMT interface index:
  python3 winbox_fingerprint.py --target <IP> --discover

Author: Silicon Pulse Research
"""

import argparse
import subprocess
import time
import math
import statistics
from datetime import datetime

# ── SNMP ──────────────────────────────────────────────────────────────────────
def snmp_get(target, oid, community="public", timeout=3):
    try:
        r = subprocess.run(
            ["snmpget", "-v1", "-c", community, "-t", str(timeout), "-r", "0", target, oid],
            capture_output=True, text=True, timeout=timeout + 1
        )
        for p in r.stdout.split("="):
            p = p.strip()
            for pfx in ["Counter32:", "Counter64:", "Gauge32:", "INTEGER:"]:
                if pfx in p:
                    try: return int(p.split(pfx)[1].strip())
                    except: pass
    except: pass
    return None

def snmp_walk(target, oid, community="public", timeout=6):
    try:
        r = subprocess.run(
            ["snmpwalk", "-v1", "-c", community, "-t", str(timeout), "-r", "0", target, oid],
            capture_output=True, text=True, timeout=timeout + 10
        )
        return r.stdout.strip().splitlines()
    except: return []

# ── Discover MGMT interface ───────────────────────────────────────────────────
def discover_mgmt_iface(target, community="public"):
    """Find the MGMT interface by name in ifDescr table."""
    print("[*] Discovering interfaces...")
    lines = snmp_walk(target, "1.3.6.1.2.1.2.2.1.2", community)
    candidates = []
    for line in lines:
        if "STRING:" in line:
            idx_part = line.split("2.2.1.2.")[-1].split(" ")[0]
            name     = line.split("STRING:")[-1].strip().strip('"')
            print(f"  idx={idx_part:<4} name={name}")
            if any(k in name.upper() for k in ["MGMT", "MANAGEMENT", "ADMIN", "OOB"]):
                try:
                    candidates.append((int(idx_part), name))
                except: pass
    return candidates

# ── Monitor ───────────────────────────────────────────────────────────────────
def monitor(target, mgmt_idx, community="public", duration=300, interval=2.0):
    print(f"\n[*] Monitoring MGMT iface index={mgmt_idx} for {duration}s @ {interval}s")
    print(f"[*] Winbox keepalive threshold: 148–310 bytes/interval")
    print(f"\n  {'t':>7}  {'delta':>8}  {'event':<22}  {'spacing':>10}")
    print("  " + "-" * 55)

    oid_rx   = f"1.3.6.1.2.1.2.2.1.10.{mgmt_idx}"   # ifInOctets
    prev_rx  = snmp_get(target, oid_rx, community)
    events   = []
    start    = time.time()

    while time.time() - start < duration:
        time.sleep(interval)
        elapsed = time.time() - start
        cur_rx  = snmp_get(target, oid_rx, community)

        if cur_rx is None or prev_rx is None:
            print(f"  {elapsed:7.1f}s  TIMEOUT")
            continue

        if cur_rx < prev_rx: cur_rx += 2**32
        delta = cur_rx - prev_rx

        event   = ""
        spacing = ""

        if 148 <= delta <= 310:
            event = "★ WINBOX KEEPALIVE"
            if events:
                sp = elapsed - events[-1]["t"]
                spacing = f"{sp:.1f}s"
            events.append({"t": elapsed, "bytes": delta})
        elif delta > 500:
            event = f"BURST ({delta}B)"
        elif delta == 0:
            event = "idle"

        print(f"  {elapsed:7.1f}s  {delta:>8}  {event:<22}  {spacing:>10}")
        prev_rx = cur_rx % (2**32)

    # Analysis
    print(f"\n{'='*55}")
    print(f"  RESULTS")
    print(f"{'='*55}")
    print(f"  Keepalive events: {len(events)}")

    if len(events) >= 2:
        spacings = [events[i+1]["t"] - events[i]["t"]
                    for i in range(len(events) - 1)
                    if 45 < events[i+1]["t"] - events[i]["t"] < 90]
        if spacings:
            mean_sp = statistics.mean(spacings)
            std_sp  = statistics.stdev(spacings) if len(spacings) > 1 else 0
            print(f"  Period:           {mean_sp:.2f}s  σ={std_sp:.2f}s")
            print(f"  Jitter (2σ):      ±{2*std_sp:.1f}s")
            print(f"  Admin session:    CONFIRMED ACTIVE")

            last_t = events[-1]["t"]
            next_t = last_t + mean_sp
            now_t  = time.time() - start
            print(f"  Next keepalive:   in ~{next_t - now_t:.0f}s")
        else:
            print(f"  Insufficient spacing data for period estimation")

        sizes = [e["bytes"] for e in events]
        print(f"  Observed sizes:   {sorted(set(sizes))}")
        print(f"  Size mean:        {statistics.mean(sizes):.0f}B")

    elif len(events) == 1:
        print(f"  Single event at t={events[0]['t']:.1f}s — admin may have disconnected")
    else:
        print(f"  No keepalives — admin session NOT active during window")

    return events


# ── Main ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Silicon Pulse — Winbox Session Fingerprinter"
    )
    parser.add_argument("--target",     required=True)
    parser.add_argument("--community",  default="public")
    parser.add_argument("--mgmt-iface", type=int, default=0,
                        help="SNMP interface index for MGMT (0 = auto-discover)")
    parser.add_argument("--discover",   action="store_true",
                        help="Just list interfaces and exit")
    parser.add_argument("--duration",   type=float, default=300.0)
    parser.add_argument("--interval",   type=float, default=2.0)
    args = parser.parse_args()

    if args.discover or args.mgmt_iface == 0:
        candidates = discover_mgmt_iface(args.target, args.community)
        if candidates:
            print(f"\n[+] MGMT interface candidates: {candidates}")
            if not args.discover:
                idx = candidates[0][0]
                print(f"[*] Using index={idx}")
                monitor(args.target, idx, args.community, args.duration, args.interval)
        else:
            print("[-] No MGMT interface found. Use --mgmt-iface <idx> manually.")
    else:
        monitor(args.target, args.mgmt_iface, args.community, args.duration, args.interval)
