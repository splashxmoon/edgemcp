"""Zero-privilege device discovery methods.

Each module here is independently useful and independently failable: the
orchestrator in :mod:`edgedefense_core.scan` runs them together and tolerates
any one of them returning nothing.
"""

from __future__ import annotations

from . import arp, mdns, ports

__all__ = ["arp", "mdns", "ports"]
