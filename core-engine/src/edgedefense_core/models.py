"""Core data models shared by every consumer of the engine.

These types are deliberately plain (dataclasses + primitives) so that the MCP
server, the future paid app, and the test-suite can all serialise them without
agreeing on a heavier framework.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

# --------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------

#: Severity ordering, lowest to highest. Used for sorting findings.
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3}

#: Device type slugs the classifier can emit.
DEVICE_TYPES = (
    "router",
    "computer",
    "phone_or_tablet",
    "tv_or_streaming",
    "smart_speaker",
    "camera",
    "printer",
    "smart_home",
    "nas_or_server",
    "game_console",
    "iot_generic",
    "unknown",
)

_MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")


def normalise_mac(raw: Optional[str]) -> Optional[str]:
    """Return a MAC as lowercase colon-separated, or None if unparseable.

    Accepts the separator styles produced by ``arp`` on Windows (``-``),
    Linux/macOS (``:``), and Cisco-style (``.``).
    """
    if not raw:
        return None

    # Separated form first, so unpadded octets survive: macOS `arp` prints
    # "0:40:9d:74:16:5e", which collapses to 11 hex characters if the
    # separators are simply stripped.
    groups = re.split(r"[:\-]", raw.strip())
    if len(groups) == 6 and all(re.fullmatch(r"[0-9a-fA-F]{1,2}", g) for g in groups):
        return ":".join(g.rjust(2, "0").lower() for g in groups)

    cleaned = re.sub(r"[^0-9a-fA-F]", "", raw)
    if len(cleaned) != 12:
        return None
    cleaned = cleaned.lower()
    mac = ":".join(cleaned[i : i + 2] for i in range(0, 12, 2))
    return mac if _MAC_RE.match(mac) else None


def is_randomised_mac(mac: Optional[str]) -> bool:
    """True if the MAC has the locally-administered bit set.

    Modern phones and laptops rotate a locally-administered MAC per network for
    privacy. Such a device is *expected* to be unidentifiable by vendor, so the
    scorer must not treat it as suspicious.
    """
    if not mac:
        return False
    try:
        first_octet = int(mac.split(":")[0], 16)
    except (ValueError, IndexError):
        return False
    return bool(first_octet & 0b10) and not bool(first_octet & 0b1)


def is_multicast_mac(mac: Optional[str]) -> bool:
    """True for broadcast/multicast MACs, which are not real devices."""
    if not mac:
        return False
    if mac == "ff:ff:ff:ff:ff:ff":
        return True
    try:
        return bool(int(mac.split(":")[0], 16) & 0b1)
    except (ValueError, IndexError):
        return False


# --------------------------------------------------------------------------
# Models
# --------------------------------------------------------------------------


@dataclass
class Device:
    """A single host observed on the local network."""

    device_id: str
    ip: str
    mac: Optional[str] = None
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    device_type: str = "unknown"
    #: How much to trust ``device_type``: "high" | "medium" | "low" | "none".
    type_confidence: str = "none"
    open_ports: List[int] = field(default_factory=list)
    services: Dict[int, str] = field(default_factory=dict)
    mdns_services: List[str] = field(default_factory=list)
    randomised_mac: bool = False
    is_gateway: bool = False
    is_self: bool = False
    #: Which discovery methods saw this device, e.g. ["arp", "mdns"].
    sources: List[str] = field(default_factory=list)
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None

    def label(self) -> str:
        """Best human-facing name for this device."""
        if self.hostname:
            return self.hostname
        if self.vendor:
            return f"{self.vendor} device"
        return f"Unidentified device ({self.ip})"

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        # JSON object keys must be strings; port numbers are ints internally.
        data["services"] = {str(k): v for k, v in self.services.items()}
        data["label"] = self.label()
        return data


@dataclass
class Finding:
    """Something worth telling the user about.

    ``finding_id`` is deterministic across scans of the same network so that a
    user can ask about a finding in a later turn and still get an answer.
    """

    finding_id: str
    code: str
    severity: str
    title: str
    summary: str
    #: Longer plain-English explanation, surfaced by ``explain_finding``.
    detail: str
    what_to_do: str
    tier: int = 0
    device_id: Optional[str] = None
    #: Honest statement of what this detection can and cannot know.
    limitations: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TrustScore:
    """The shareable 0-100 headline number and its justification."""

    score: int
    grade: str
    #: 2-3 plain-language bullet points explaining the number.
    reasons: List[str] = field(default_factory=list)
    #: Per-category point deductions, for transparency.
    deductions: Dict[str, int] = field(default_factory=dict)
    tier1_included: bool = False
    device_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResult:
    """Everything one scan produced."""

    started_at: str
    finished_at: str
    scan_depth: str
    subnet: Optional[str]
    devices: List[Device] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    #: Non-fatal problems, e.g. "mDNS socket unavailable".
    warnings: List[str] = field(default_factory=list)
    tier1_included: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "scan_depth": self.scan_depth,
            "subnet": self.subnet,
            "tier1_included": self.tier1_included,
            "devices": [d.to_dict() for d in self.devices],
            "findings": [f.to_dict() for f in self.findings],
            "warnings": list(self.warnings),
        }
