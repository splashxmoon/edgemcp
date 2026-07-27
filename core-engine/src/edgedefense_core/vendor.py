"""Offline MAC-to-vendor lookup.

The OUI database is bundled with the package and read from disk. This module
performs no network I/O of any kind -- that is a deliberate product guarantee,
not an implementation detail. Do not add a remote fallback here.
"""

from __future__ import annotations

import re
from functools import lru_cache
from typing import Dict, Optional

try:  # Python 3.9+
    from importlib.resources import files as _resource_files
except ImportError:  # pragma: no cover - only on very old interpreters
    _resource_files = None  # type: ignore[assignment]

_PREFIX_RE = re.compile(r"^[0-9A-F]{6}$")


@lru_cache(maxsize=1)
def _load_oui() -> Dict[str, str]:
    """Parse the bundled OUI CSV into a prefix -> vendor mapping.

    Cached for the process lifetime; the file is a few tens of kilobytes.
    """
    table: Dict[str, str] = {}

    if _resource_files is None:  # pragma: no cover
        return table

    try:
        handle = _resource_files("edgedefense_core.data").joinpath("oui.csv")
        content = handle.read_text(encoding="utf-8")
    except (FileNotFoundError, ModuleNotFoundError, OSError):
        return table

    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("prefix,"):
            continue
        prefix, _, vendor = line.partition(",")
        prefix = prefix.strip().upper()
        vendor = vendor.strip()
        if vendor and _PREFIX_RE.match(prefix):
            table[prefix] = vendor

    return table


def oui_database_size() -> int:
    """Number of vendor prefixes available locally. Useful for diagnostics."""
    return len(_load_oui())


def lookup_vendor(mac: Optional[str]) -> Optional[str]:
    """Return the manufacturer for a MAC address, or None if unknown.

    Returns None for locally-administered (randomised) MACs, because the OUI in
    such an address is meaningless -- reporting a vendor there would be wrong,
    not merely imprecise.
    """
    if not mac:
        return None

    hex_only = re.sub(r"[^0-9a-fA-F]", "", mac).upper()
    if len(hex_only) < 6:
        return None

    # Bit 1 of the first octet marks a locally-administered address.
    try:
        if int(hex_only[:2], 16) & 0b10:
            return None
    except ValueError:
        return None

    return _load_oui().get(hex_only[:6])
