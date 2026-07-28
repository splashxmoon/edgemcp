"""EdgeDefense core engine.

Shared network discovery, identification and scoring logic. This package is
imported by the MCP server and, in future, by the paid Core/Home application.
Neither should reimplement anything found here.

Two guarantees hold for every module in this package:

* **No outbound network calls.** Nothing here contacts a remote service, for
  any purpose, including vendor lookups and analytics. The OUI database is
  bundled on disk for exactly this reason.

  There is exactly one exception, and it is deliberate:
  :mod:`edgedefense_core.perf.speedtest` fetches real bytes from an internet
  server, because throughput cannot be measured any other way. It is confined
  to that one module, never runs as part of a scan, and only executes when a
  caller invokes it by name. It is not imported by anything else here.
* **No elevated privileges.** Everything under ``scan``, ``discovery``,
  ``classify``, ``findings``, ``scoring`` and ``perf`` runs as an ordinary user.

The trained ML detection pipeline behind the paid product is deliberately NOT
part of this package and must never be imported into it.
"""

from __future__ import annotations

from .changes import ChangeReport, compare_scans
from .classify import classify_device, friendly_type
from .findings import build_findings, find_by_id, sort_findings
from .models import Device, Finding, ScanResult, TrustScore
from .netinfo import describe_local_network
from .perf import (
    InterfaceReport,
    LatencyReport,
    SpeedTestResult,
    WifiReport,
    collect_wifi,
    run_latency_check,
    run_speed_test,
    sample_interfaces,
)
from .scan import run_scan, scan_result_from_dict
from .scoring import compute_trust_score
from .storage import Storage, default_data_dir
from .vendor import lookup_vendor, oui_database_size

__version__ = "0.1.0"

__all__ = [
    "ChangeReport",
    "Device",
    "Finding",
    "InterfaceReport",
    "LatencyReport",
    "ScanResult",
    "SpeedTestResult",
    "Storage",
    "TrustScore",
    "WifiReport",
    "__version__",
    "build_findings",
    "classify_device",
    "collect_wifi",
    "compare_scans",
    "compute_trust_score",
    "default_data_dir",
    "describe_local_network",
    "find_by_id",
    "friendly_type",
    "lookup_vendor",
    "oui_database_size",
    "run_latency_check",
    "run_scan",
    "run_speed_test",
    "sample_interfaces",
    "scan_result_from_dict",
    "sort_findings",
]
