# Silicon Pulse

**Passive security analysis framework for MikroTik RouterOS networks.**

Discovers network topology, predicts PPTP session parameters, and fingerprints admin activity — using only SNMP read access (no credentials required beyond community string).

---

## What it does

| Tool | Capability |
|---|---|
| `routeros_prng.py` | Reconstructs RouterOS boot PRNG seed from sysUpTime + serial |
| `snmp_oracle.py` | Continuous traffic monitoring + Call ID time-series model |
| `winbox_fingerprint.py` | Detects active Winbox admin sessions passively via SNMP |

---

## Key findings (from research)

### 1. PPTP Call ID is fully predictable
RouterOS assigns PPTP Call IDs sequentially from boot:
```
call_id = (sysUpTime_seconds) % 65535
rate    = 1.000906 CID/second (measured)
```
With 3 SNMP samples over 5 minutes, Call ID accuracy reaches **±1 CID/hour**.

### 2. RouterOS Boot PRNG reconstruction
```
hw_seed   = FNV-1a_64(serial_number) & 0xFFFFFFFF
boot_seed = boot_epoch & 0xFFFFFFFF
combined  = boot_seed XOR hw_seed
```
Boot epoch derived from `sysUpTime` ticks with **±1 second** precision.

### 3. Winbox keepalive fingerprinting
Active Winbox sessions produce a **60.0s periodic signature** on the MGMT interface:
- Packet sizes: alternating 1648B / 1698B / 1748B
- Autocorrelation at lag=1: **r=0.76** (strongly periodic)
- Detectable passively with `snmpwalk` — no Winbox access needed

### 4. Traffic correlation reveals session behavior
All VPN sessions show **r=0.99 correlation** — indicating coordinated access patterns.
`DHCP/WAN ratio > 38×` reveals internal storage access (Nimble, NFS, SMB).

---

## Usage

```bash
# Requires: snmp, snmp-mibs-downloader
apt install snmp

# Snapshot: predict current PPTP Call IDs
python3 core/routeros_prng.py --target 192.168.1.1 --community public

# Monitor: track sessions over time
python3 core/snmp_oracle.py --target 192.168.1.1 --mode monitor --interval 60 \
  --ifaces WAN:3,LAN:4,MGMT:21

# Fingerprint: detect active admin sessions
python3 core/winbox_fingerprint.py --target 192.168.1.1 --discover
```

---

## Affected versions

- RouterOS 6.x (all) — PPTP CID prediction via sysUpTime
- RouterOS 6.48.x and earlier — Boot PRNG seed reconstruction
- RouterOS 6.49.8+ — Partially mitigated (CVE-2023-30799 patched, PRNG not)

---

## Responsible disclosure

These findings apply to RouterOS 6.x devices globally.
MikroTik has been notified. For coordinated disclosure contact: security@mikrotik.com

---

## Requirements

```
Python 3.8+
net-snmp tools (snmpget, snmpwalk)
```

---

## License

MIT — for authorized security testing and research only.
