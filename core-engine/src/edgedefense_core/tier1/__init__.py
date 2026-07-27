"""Tier 1: opt-in passive traffic analysis.

This subpackage is the only part of the engine that requires elevated
privileges, and it is never reached without explicit user consent recorded via
:func:`edgedefense_core.tier1.consent.grant_consent`.

Importing this package is safe with or without the optional ``scapy``
dependency installed; the capture layer reports a clear, actionable error at
call time instead of failing at import.
"""

from __future__ import annotations

from .consent import (
    CONSENT_TEXT,
    Tier1Capability,
    get_capability,
    grant_consent,
    has_capture_backend,
    has_elevated_privileges,
    revoke_consent,
)

__all__ = [
    "CONSENT_TEXT",
    "Tier1Capability",
    "analyse_capture",
    "capture_summary",
    "capture_traffic",
    "get_capability",
    "grant_consent",
    "has_capture_backend",
    "has_elevated_privileges",
    "revoke_consent",
]


def __getattr__(name: str):
    """Defer capture/heuristics imports until they are actually used.

    Keeps ``import edgedefense_core.tier1`` cheap and scapy-free for the common
    case where the user only ever runs Tier 0.
    """
    if name in ("capture_traffic", "CaptureUnavailable", "CaptureResult"):
        from . import capture

        return getattr(capture, name)
    if name in ("analyse_capture", "capture_summary", "detect_dns_bypass",
                "detect_volume_outliers"):
        from . import heuristics

        return getattr(heuristics, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
