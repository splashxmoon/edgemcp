# edgedefense-core

Shared network discovery, identification and scoring engine for EdgeDefense.

This package contains **no user interface and no product surface**. It is the
detection layer, imported by:

- [`edgedefense-mcp`](../mcp-server) — the free, open-source MCP server
- the EdgeDefense Core/Home application (future, closed-source)

Both consume this package the same way. Neither reimplements anything in it.
Keeping detection logic in one place is the entire point of this folder: the
alternative — two codebases that slowly diverge — is expensive to unwind later.

## Two guarantees

Every module here upholds both:

**No outbound network calls.** Nothing in this package contacts a remote
service, for any purpose. Vendor lookups read a bundled CSV
(`data/oui.csv`), not an API. There is no telemetry and no analytics. This is
load-bearing for the product's premise, not an implementation detail — do not
add a remote fallback anywhere in this package.

**Tier 0 needs no elevated privileges.** `scan`, `discovery`, `classify`,
`findings` and `scoring` all run as an ordinary user on Windows, macOS and
Linux. Only the opt-in `tier1` subpackage needs more, and it asks first.

## What is deliberately not here

The trained ML detection pipeline behind the paid product is **not** part of
this package and must never be imported into it. `mcp-server/` is public, and
anything reachable from it is public by extension. `tier1/heuristics.py`
contains two transparent statistical rules and nothing more.

This boundary is a hard architectural constraint, not a future TODO.

## Layout

```
src/edgedefense_core/
├── models.py           Device, Finding, TrustScore, ScanResult
├── netinfo.py          Local IP, subnet and gateway detection
├── scan.py             Orchestrator — the entry point consumers call
├── vendor.py           Offline MAC → manufacturer lookup
├── classify.py         Best-guess device typing, with confidence levels
├── findings.py         Observations → findings, plus all explanation copy
├── scoring.py          The 0–100 trust score
├── storage.py          Local SQLite persistence
├── util.py             Small shared formatting helpers
├── data/oui.csv        Bundled vendor database
├── discovery/
│   ├── arp.py          ARP table reading + UDP sweep to populate it
│   ├── mdns.py         Dependency-free mDNS client and DNS parser
│   └── ports.py        TCP connect fingerprinting
└── tier1/
    ├── consent.py      Capability detection and the opt-in gate
    ├── capture.py      Passive capture (scapy, optional)
    └── heuristics.py   DNS-bypass and volume-outlier detection
```

## Usage

```python
import asyncio
from edgedefense_core import run_scan, compute_trust_score, Storage

async def main():
    storage = Storage()
    result = await run_scan(scan_depth="quick", storage=storage)
    score = compute_trust_score(result.devices, result.findings)

    print(f"{len(result.devices)} devices, trust score {score.score}/100")
    for finding in result.findings:
        print(f"  [{finding.severity}] {finding.summary}")

asyncio.run(main())
```

## How discovery works

Three independent methods, run concurrently. Any one can fail without aborting
the scan; a failure reduces detail and is reported as a warning.

1. **ARP sweep.** Sends one empty UDP datagram to port 9 (discard) on each
   address in the local subnet, which causes the kernel to ARP-resolve them,
   then reads the OS address table. Roughly 254 packets of 42 bytes on a /24 —
   less than loading a single web page, and confined to the local link.
2. **mDNS.** Queries the standard service types over multicast from an
   ephemeral port with the QU (unicast response) bit set, so responders reply
   directly. Binding port 5353 is attempted opportunistically for better
   coverage; failing to (because Bonjour or Avahi owns it) is expected and
   non-fatal.
3. **TCP fingerprinting.** Ordinary `connect()` calls to 12 ports (quick) or 42
   ports (full). No payload is sent and the socket closes immediately.

Evidence is then merged per address and weighted, most reliable first:
mDNS service types → hostname keywords → open ports → vendor name.

## Scoring calibration

The score starts at 100 and subtracts capped, per-category deductions. It is
tuned so a normal, well-configured home network lands in the 90s.

That calibration is intentional and worth preserving. The score is designed to
be screenshot-friendly, which creates a standing pull toward inflating findings
so the number looks dramatic. If a typical network scored 42, the number would
mean nothing and the tool would deserve to be distrusted. Every deduction
traces to a finding the user can read in full.

## Tests

```bash
pip install -e ".[dev]"
pytest
```

The suite covers parsing, classification, scoring calibration and the Tier 1
heuristics against synthetic fixtures — no live network required.

## Licence

MIT.
