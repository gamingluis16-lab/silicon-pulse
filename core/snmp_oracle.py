#!/usr/bin/env python3
"""
Silicon Pulse — SNMP Network Oracle
=====================================
Continuous SNMP monitoring for RouterOS devices.
Builds a time-series model of:
  - Interface traffic (with Counter64 support)
  - PPP/VPN session count and changes
  - Winbox keepalive fingerprinting (MGMT interface)
  - Traffic entropy and correlation analysis
  - Call ID prediction from uptime ticks

Usage:
  # Run once (snapshot):
  python3 snmp_oracle.py --target <IP> --mode snapshot

  # Continuous monitoring (60s intervals):
  python3 snmp_oracle.py --target <IP> --mode monitor --interval 60

  # Install as cron (every minute):
  python3 snmp_oracle.py --target <IP> --mode install-cron

  # Analyze collected data:
  python3 snmp_oracle.py --target <IP> --mode analyze

Author: Silicon Pulse Research
"""

import argparse
import json
import math
import os
import statistics
import subprocess
import time
from datetime import datetime

DEFAULT_DB = "/tmp/sp_oracle_{target}.json"

# ── SNMP ──────────────────────────────────────────────────────────────────────
def snmp_get(target, oid, community="public", timeout=3):
    try:
        r = subprocess.run(
            ["snmpget", "-v1", "-c", community, "-t", str(timeout), "-r", "0", target, oid],
            capture_output=True, text=True, timeout=timeout + 1
        )
        for p in r.stdout.split("="):
            p = p.strip()
            for pfx in ["Gauge32:", "Counter32:", "Counter64:", "INTEGER:", "Timeticks:"]:
                if pfx in p:
                    v = p.split(pfx)[1].strip()
                    if pfx == "Timeticks:" and "(" in v:
                        v = v.split("(")[1].split(")")[0]
                    try: return int(v)
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

# ── DB ────────────────────────────────────────────────────────────────────────
def db_path(target):
    return DEFAULT_DB.format(target=target.replace(".", "_"))

def load_db(target):
    path = db_path(target)
    if os.path.exists(path):
        try:
            with open(path) as f: return json.load(f)
        except: pass
    return {
        "target": target,
        "samples": [],
        "call_id_history": [],
        "keepalive": {"period": 60.0, "last_t": None, "events": []},
        "created": datetime.now().isoformat()
    }

def save_db(db, target):
    with open(db_path(target), "w") as f:
        json.dump(db, f, indent=2)

# ── Collect ───────────────────────────────────────────────────────────────────
def collect_snapshot(target, community="public", iface_map=None):
    """Collect a single SNMP snapshot from target."""
    if iface_map is None:
        iface_map = {}

    now  = time.time()
    snap = {"t": now, "iso": datetime.now().isoformat()}

    snap["ticks"] = snmp_get(target, "1.3.6.1.2.1.1.3.0",              community)
    snap["ppp"]   = snmp_get(target, "1.3.6.1.4.1.14988.1.1.6.1.0",   community)
    snap["cpu"]   = snmp_get(target, "1.3.6.1.2.1.25.3.3.1.2.1",       community)

    snap["ifaces"] = {}
    for name, idx in iface_map.items():
        rx = snmp_get(target, f"1.3.6.1.2.1.31.1.1.1.6.{idx}",  community)
        tx = snmp_get(target, f"1.3.6.1.2.1.31.1.1.1.10.{idx}", community)
        snap["ifaces"][name] = {"rx": rx, "tx": tx}

    if snap["ticks"]:
        snap["base_cid"] = int(snap["ticks"] / 100) % 65535

    # ARP table
    arp_lines  = snmp_walk(target, "1.3.6.1.2.1.4.22.1.3", community, timeout=4)
    snap["arp"] = [l.split("IpAddress:")[-1].strip()
                   for l in arp_lines if "IpAddress:" in l]
    return snap

# ── Update models ─────────────────────────────────────────────────────────────
def update_models(db, snap):
    samples = db["samples"]

    if len(samples) >= 1:
        prev = samples[-1]
        dt   = snap["t"] - prev["t"]
        if dt > 0:
            snap["deltas"] = {}
            for name in snap.get("ifaces", {}):
                prev_rx  = prev.get("ifaces", {}).get(name, {}).get("rx") or 0
                curr_rx  = snap["ifaces"][name].get("rx") or 0
                if curr_rx < prev_rx: curr_rx += 2**64
                delta = curr_rx - prev_rx
                snap["deltas"][name] = {
                    "bytes": delta,
                    "bps":   round(delta * 8 / dt, 1)
                }

    # Keepalive detection on MGMT interface
    mgmt_delta = snap.get("deltas", {}).get("MGMT", {}).get("bytes", 0)
    ka = db["keepalive"]
    if 150 <= mgmt_delta <= 310:
        t_now = snap["t"]
        ka["events"].append({"t": t_now, "bytes": mgmt_delta, "iso": snap["iso"]})
        ka["events"] = ka["events"][-200:]
        if ka["last_t"]:
            sp = t_now - ka["last_t"]
            if 45 <= sp <= 90:
                alpha = 0.3
                ka["period"] = alpha * sp + (1 - alpha) * ka["period"]
        ka["last_t"]       = t_now
        ka["next_predicted"] = t_now + ka["period"]

    # CID history
    if "base_cid" in snap:
        db["call_id_history"].append({
            "t": snap["t"], "base_cid": snap["base_cid"],
            "ticks": snap["ticks"], "ppp": snap.get("ppp")
        })
        db["call_id_history"] = db["call_id_history"][-2880:]

    # Traffic entropy
    if "deltas" in snap:
        vals = [v["bytes"] for v in snap["deltas"].values() if v["bytes"] > 0]
        if vals:
            total = sum(vals)
            ent   = -sum((v/total) * math.log2(v/total) for v in vals)
            snap["entropy"] = round(ent, 4)

    return db

# ── Analyze ───────────────────────────────────────────────────────────────────
def run_analysis(db):
    samples  = db["samples"]
    cid_hist = db["call_id_history"]
    ka       = db["keepalive"]

    print(f"\n{'='*60}")
    print(f"  SILICON PULSE ORACLE — ANALYSIS")
    print(f"  Samples: {len(samples)}  CID history: {len(cid_hist)}")
    print(f"{'='*60}\n")

    # CID model
    if len(cid_hist) >= 2:
        times = [c["t"]        for c in cid_hist]
        cids  = [c["base_cid"] for c in cid_hist]
        rates = []
        for i in range(1, len(cids)):
            dt = times[i] - times[i-1]
            dc = (cids[i] - cids[i-1]) % 65535
            if 0 < dt < 200: rates.append(dc / dt)
        if rates:
            r   = statistics.mean(rates)
            sd  = statistics.stdev(rates) if len(rates) > 1 else 0
            now = time.time()
            dt  = now - cid_hist[-1]["t"]
            cur = int(cid_hist[-1]["base_cid"] + dt * r) % 65535
            print(f"[ CID MODEL ]")
            print(f"  Rate: {r:.6f} CID/s  σ={sd:.6f}")
            print(f"  Current CID: {cur}")
            print(f"  Sessions:    {cur}, {cur-1}, {cur-2}, {cur-3}")
            print(f"  ±1h accuracy: ±{sd*3600:.0f} CID\n")

    # Keepalive
    if ka["events"]:
        print(f"[ WINBOX KEEPALIVE ]")
        print(f"  Period: {ka['period']:.2f}s  Events: {len(ka['events'])}")
        if ka["next_predicted"]:
            secs = ka["next_predicted"] - time.time()
            print(f"  Next KA in: {secs:.0f}s\n")

    # Traffic stats
    ifaces = set()
    for s in samples:
        ifaces |= set(s.get("deltas", {}).keys())
    if ifaces:
        print(f"[ TRAFFIC STATS (bytes/sample) ]")
        for name in sorted(ifaces):
            vals = [s["deltas"][name]["bytes"]
                    for s in samples if name in s.get("deltas", {})]
            if vals:
                mu  = statistics.mean(vals)
                mx  = max(vals)
                bps = mu * 8 / 60
                print(f"  {name:<14}: avg={mu/1e6:.1f}MB  max={mx/1e6:.1f}MB  ~{bps/1e6:.1f}Mbps")

    # PPP events
    ppp_events = db.get("sessions", {}).get("ppp_events", [])
    if ppp_events:
        print(f"\n[ PPP EVENTS ]")
        for ev in ppp_events[-5:]:
            print(f"  {ev['iso'][:19]}: {ev['from']}→{ev['to']} sessions")


# ── Main ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Silicon Pulse SNMP Oracle")
    parser.add_argument("--target",    required=True)
    parser.add_argument("--community", default="public")
    parser.add_argument("--mode",      default="snapshot",
                        choices=["snapshot", "monitor", "analyze"])
    parser.add_argument("--interval",  type=float, default=60.0)
    parser.add_argument("--duration",  type=float, default=3600.0,
                        help="Monitor duration in seconds (default 3600)")
    parser.add_argument("--ifaces",    default="",
                        help="Comma-separated name:index pairs, e.g. WAN:3,LAN:4")
    args = parser.parse_args()

    # Parse interface map
    iface_map = {}
    if args.ifaces:
        for pair in args.ifaces.split(","):
            if ":" in pair:
                n, idx = pair.split(":", 1)
                iface_map[n.strip()] = int(idx.strip())

    db = load_db(args.target)

    if args.mode == "snapshot":
        snap = collect_snapshot(args.target, args.community, iface_map)
        db   = update_models(db, snap)
        db["samples"].append(snap)
        save_db(db, args.target)
        print(f"[+] {snap['iso'][:19]}  ticks={snap.get('ticks')}  "
              f"ppp={snap.get('ppp')}  cid={snap.get('base_cid')}")
        if "deltas" in snap:
            for k, v in snap["deltas"].items():
                print(f"    {k:<14}: {v['bytes']:>12,}B  {v['bps']/1e6:.2f} Mbps")

    elif args.mode == "monitor":
        print(f"[*] Monitoring {args.target} every {args.interval}s "
              f"for {args.duration/3600:.1f}h")
        end = time.time() + args.duration
        while time.time() < end:
            snap = collect_snapshot(args.target, args.community, iface_map)
            db   = update_models(db, snap)
            db["samples"].append(snap)
            db["samples"] = db["samples"][-2880:]
            save_db(db, args.target)
            ppp = snap.get("ppp", "?")
            cid = snap.get("base_cid", "?")
            ent = snap.get("entropy", "?")
            print(f"[{snap['iso'][11:19]}] ppp={ppp}  cid={cid}  "
                  f"entropy={ent}  arp={len(snap.get('arp',[]))}")
            time.sleep(args.interval)

    elif args.mode == "analyze":
        run_analysis(db)
