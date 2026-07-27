"""EdgeDefense core engine.

Shared network discovery, identification and scoring logic. This package is
imported by the MCP server and, in future, by the paid Core/Home application.
Neither should reimplement anything found here.

Two guarantees hold for every module in this package:

* **No outbound network calls.** Nothing here contacts a remote service, for
  any purpose, including vendor lookups and analytics. The OUI database is
  bundled on disk for exactly this reason.
* **No elevated privileges for Tier 0.** Everything under ``scan``,
  ``discovery``, ``classify``, ``findings`` and ``scoring`` runs as an ordinary
  user. Only the opt-in ``tier1`` subpackage needs more, and it asks first.

The trained ML detection pipeline behind the paid product is deliberately NOT
part of this package and must never be imported into it.
"""

from __future__ import annotations

from .classify import classify_device, friendly_type
from .findings import build_findings, find_by_id, sort_findings
from .models import Device, Finding, ScanResult, TrustScore
from .netinfo import describe_local_network
from .scan import run_scan, scan_result_from_dict
from .scoring import compute_trust_score
from .storage import Storage, default_data_dir
from .vendor import lookup_vendor, oui_database_size

__version__ = "0.1.0"

__all__ = [
    "Device",
    "Finding",
    "ScanResult",
    "Storage",
    "TrustScore",
    "__version__",
    "build_findings",
    "classify_device",
    "compute_trust_score",
    "default_data_dir",
    "describe_local_network",
    "find_by_id",
    "friendly_type",
    "lookup_vendor",
    "oui_database_size",
    "run_scan",
    "scan_result_from_dict",
    "sort_findings",
]
