"""Tier 1 capability detection and the opt-in gate.

Tier 1 is the only part of this tool that needs elevated privileges, and it is
never enabled implicitly. The user must be shown exactly what the elevated
access is used for, and must then explicitly confirm, before any capture runs.

The consent text lives here rather than in the MCP layer so that every product
built on this engine asks the same question in the same words.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, asdict
from typing import Any, Dict, Optional

from ..storage import Storage, utc_now

#: Settings key recording that the user opted in, and when.
CONSENT_KEY = "tier1_consent_granted_at"

#: Shown verbatim before the first capture. Deliberately specific about what is
#: captured, what is not, and where it goes -- vague reassurance is worse than
#: no reassurance for a tool asking for packet-level access.
CONSENT_TEXT = """\
Tier 1 traffic analysis needs elevated (administrator/root) privileges. Here is
exactly what that is used for, and what it is not.

WHAT IT DOES
  - Reads packet headers on your local network interface for a fixed, short
    window that you choose (10-300 seconds).
  - Records, per device: which addresses it contacted, how many bytes it moved,
    and which DNS lookups it made.
  - Uses that to detect two things: devices connecting to addresses that were
    never looked up through your network's DNS, and devices moving far more
    data than their peers.

WHAT IT DOES NOT DO
  - It does not store packet contents. Only headers and counters are kept.
  - It does not decrypt anything.
  - It does not send any data anywhere. Results are written to a local SQLite
    file on this machine and nowhere else. This tool has no network client and
    no analytics of any kind.
  - It does not run continuously. Each capture is a one-off for the duration
    you specify, and stops on its own.

WHY IT NEEDS ELEVATED ACCESS
  Reading packets from a network interface requires raw socket access, which
  every operating system restricts to privileged processes. There is no way to
  do passive traffic analysis without it. This is also why it is optional:
  everything in Tier 0 works with no special permissions at all.

WHAT YOU SHOULD KNOW BEFORE AGREEING
  If other people share this network, their traffic metadata will be visible to
  the capture too. Only enable this on a network you are responsible for.

To proceed, confirm explicitly. To keep using the tool without it, simply do
not - every other feature continues to work.\
"""


@dataclass
class Tier1Capability:
    """Whether Tier 1 can run here, and whether the user has agreed to it."""

    consent_granted: bool
    consent_granted_at: Optional[str]
    has_privileges: bool
    has_capture_backend: bool
    backend_hint: str
    platform: str

    @property
    def ready(self) -> bool:
        """True only when consent, privileges, and a backend are all present."""
        return self.consent_granted and self.has_privileges and self.has_capture_backend

    def blocking_reason(self) -> Optional[str]:
        """The single most relevant reason Tier 1 cannot run right now."""
        if not self.consent_granted:
            return "consent_required"
        if not self.has_capture_backend:
            return "backend_missing"
        if not self.has_privileges:
            return "privileges_missing"
        return None

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["ready"] = self.ready
        data["blocking_reason"] = self.blocking_reason()
        return data


def has_elevated_privileges() -> bool:
    """Best-effort check for the privileges raw packet capture requires."""
    if sys.platform == "win32":
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        except Exception:
            return False

    if hasattr(os, "geteuid"):
        if os.geteuid() == 0:
            return True
        # On Linux a non-root process can still capture if it has been granted
        # CAP_NET_RAW, which is the recommended way to avoid running as root.
        return _has_net_raw_capability()

    return False


def _has_net_raw_capability() -> bool:
    """Check for CAP_NET_RAW in the process's effective capability set."""
    try:
        with open("/proc/self/status", "r", encoding="utf-8") as handle:
            for line in handle:
                if line.startswith("CapEff:"):
                    effective = int(line.split()[1], 16)
                    return bool(effective & (1 << 13))  # CAP_NET_RAW == 13
    except (OSError, ValueError, IndexError):
        return False
    return False


def has_capture_backend() -> bool:
    """True if scapy is importable, which is what the capture layer uses."""
    try:
        import scapy.all  # noqa: F401
    except Exception:
        return False
    return True


def backend_hint() -> str:
    """Actionable guidance for whatever is currently missing."""
    if not has_capture_backend():
        return (
            "The capture backend is not installed. Install it with: "
            "pip install 'edgedefense-mcp[tier1]'  (this adds scapy). On Windows you "
            "will also need Npcap installed; on macOS and Linux libpcap is normally "
            "already present."
        )
    if not has_elevated_privileges():
        if sys.platform == "win32":
            return (
                "Traffic capture needs an elevated process. Close your MCP client, "
                "restart it from an Administrator terminal, and try again."
            )
        return (
            "Traffic capture needs root or the CAP_NET_RAW capability. Either run the "
            "server with sudo, or grant the capability once with: "
            "sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))"
        )
    return "Ready."


def get_capability(storage: Storage) -> Tier1Capability:
    """Assemble the current Tier 1 status."""
    granted_at = storage.get_setting(CONSENT_KEY)
    return Tier1Capability(
        consent_granted=bool(granted_at),
        consent_granted_at=granted_at,
        has_privileges=has_elevated_privileges(),
        has_capture_backend=has_capture_backend(),
        backend_hint=backend_hint(),
        platform=sys.platform,
    )


def grant_consent(storage: Storage) -> str:
    """Record the user's explicit opt-in. Returns the timestamp stored."""
    timestamp = utc_now()
    storage.set_setting(CONSENT_KEY, timestamp)
    return timestamp


def revoke_consent(storage: Storage) -> None:
    """Withdraw Tier 1 consent. The next capture will require opting in again."""
    storage.set_setting(CONSENT_KEY, "")
