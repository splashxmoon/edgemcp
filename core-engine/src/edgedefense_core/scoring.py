"""The 0-100 network trust score.

Design constraints, in priority order:

1. **Accuracy over drama.** The score is meant to be screenshot-friendly, which
   creates a standing temptation to inflate findings so the number looks
   dramatic. It is deliberately resisted: a normal home network with a router,
   some phones and a TV should land in the 90s, because that network really is
   fine. If most users saw a 42, the number would mean nothing.
2. **Derived from findings, never independent of them.** Every point deducted
   traces to a finding the user can read. The score and the explanation cannot
   drift apart because they come from the same source.
3. **Capped per category.** Ten devices with SMB open is not ten times the
   problem of one, so each category saturates.
"""

from __future__ import annotations

from typing import Dict, Iterable, List, Tuple

from .models import Device, Finding, TrustScore
from .util import plural

#: Points deducted per occurrence of each finding code.
_WEIGHTS: Dict[str, int] = {
    # Exposed services
    "telnet_exposed": 14,
    "adb_exposed": 14,
    "default_credential_risk": 12,
    "vnc_exposed": 8,
    "ftp_exposed": 6,
    "database_exposed": 6,
    "tr069_exposed": 3,
    "rdp_exposed": 4,
    "smb_exposed": 2,
    # Attack surface
    "many_open_ports": 4,
    # Identification
    "unidentified_device": 4,
    "private_address_device": 0,  # expected modern behaviour; never scored
    # Tier 1
    "dns_bypass": 7,
    "data_volume_outlier": 3,
}

#: Which category each code rolls up into, and the maximum any one category may
#: subtract. Caps stop a single class of issue from zeroing the score.
_CATEGORIES: Dict[str, str] = {
    "telnet_exposed": "exposed_services",
    "adb_exposed": "exposed_services",
    "default_credential_risk": "exposed_services",
    "vnc_exposed": "exposed_services",
    "ftp_exposed": "exposed_services",
    "database_exposed": "exposed_services",
    "tr069_exposed": "exposed_services",
    "rdp_exposed": "exposed_services",
    "smb_exposed": "exposed_services",
    "many_open_ports": "attack_surface",
    "unidentified_device": "unidentified_devices",
    "private_address_device": "unidentified_devices",
    "dns_bypass": "tier1_anomalies",
    "data_volume_outlier": "tier1_anomalies",
}

_CATEGORY_CAPS: Dict[str, int] = {
    "exposed_services": 45,
    "attack_surface": 12,
    "unidentified_devices": 16,
    "tier1_anomalies": 24,
}

_CATEGORY_LABELS: Dict[str, str] = {
    "exposed_services": "exposed services",
    "attack_surface": "unnecessary open ports",
    "unidentified_devices": "unidentified devices",
    "tier1_anomalies": "traffic anomalies",
}


def _grade(score: int) -> str:
    """Map a score onto a word, so the headline reads as a judgement not a stat."""
    if score >= 90:
        return "Strong"
    if score >= 75:
        return "Good"
    if score >= 60:
        return "Fair"
    if score >= 40:
        return "Needs attention"
    return "At risk"


def _reasons(
    findings: List[Finding],
    devices: List[Device],
    category_totals: Dict[str, int],
) -> List[str]:
    """Build the 2-3 plain-language bullets shown under the number.

    Ordered by how much each thing actually cost, so the top reason is always
    the one most worth acting on.
    """
    reasons: List[str] = []
    ranked = sorted(category_totals.items(), key=lambda pair: -pair[1])

    for category, points in ranked:
        if points <= 0:
            continue

        # Every scored finding in this category. The device count must be
        # derived from the whole category, not from one code within it -- the
        # points quoted are the category total, so attributing them to a single
        # code's device count would overstate what that one device cost.
        in_category = [
            f
            for f in findings
            if _CATEGORIES.get(f.code) == category and _WEIGHTS.get(f.code, 0) > 0
        ]
        if not in_category:
            continue

        affected = {f.device_id for f in in_category if f.device_id}
        count = len(affected) or len(in_category)
        worst = max(in_category, key=lambda f: _WEIGHTS.get(f.code, 0))

        if category == "exposed_services":
            verb = "exposes" if count == 1 else "expose"
            reasons.append(
                f"{plural(count, 'device')} {verb} a risky service - most serious: "
                f"{worst.title} (-{points} points)."
            )
        elif category == "unidentified_devices":
            reasons.append(
                f"{plural(count, 'device')} could not be identified at all "
                f"(-{points} points)."
            )
        elif category == "attack_surface":
            verb = "listens" if count == 1 else "listen"
            reasons.append(
                f"{plural(count, 'device')} {verb} on more ports than a home device "
                f"usually needs (-{points} points)."
            )
        else:
            reasons.append(
                f"Traffic analysis flagged "
                f"{plural(len(in_category), 'anomaly', 'anomalies')} (-{points} points)."
            )

        if len(reasons) >= 3:
            break

    if not reasons:
        identified = sum(1 for d in devices if d.device_type != "unknown")
        reasons.append(
            f"No risky services were found on any of the {len(devices)} devices detected."
        )
        if identified:
            reasons.append(
                f"{identified} of {len(devices)} devices were identified by type and manufacturer."
            )

    return reasons[:3]


def compute_trust_score(
    devices: Iterable[Device],
    findings: Iterable[Finding],
    tier1_included: bool = False,
) -> TrustScore:
    """Compute the shareable trust score from a completed scan.

    Args:
        devices: Every device discovered.
        findings: Findings produced by :mod:`edgedefense_core.findings`.
        tier1_included: Whether traffic-analysis findings are part of the input.
            Recorded on the result so the output can say what the score is
            based on rather than implying a depth of analysis that did not run.

    Returns:
        A :class:`~edgedefense_core.models.TrustScore`.
    """
    device_list = list(devices)
    finding_list = list(findings)

    raw_totals: Dict[str, int] = {}
    for finding in finding_list:
        weight = _WEIGHTS.get(finding.code, 0)
        if weight <= 0:
            continue
        category = _CATEGORIES.get(finding.code, "attack_surface")
        raw_totals[category] = raw_totals.get(category, 0) + weight

    capped_totals = {
        category: min(total, _CATEGORY_CAPS.get(category, total))
        for category, total in raw_totals.items()
    }

    score = 100 - sum(capped_totals.values())

    # An empty scan is not a perfect network -- it is a failed scan. Saying so
    # is more useful than reporting 100.
    if not device_list:
        return TrustScore(
            score=0,
            grade="No data",
            reasons=[
                "No devices were discovered, so no score could be calculated.",
                "This usually means the scan could not reach the local network - "
                "check that you are connected to wifi or ethernet rather than only a VPN.",
            ],
            deductions={},
            tier1_included=tier1_included,
            device_count=0,
        )

    score = max(0, min(100, score))

    return TrustScore(
        score=score,
        grade=_grade(score),
        reasons=_reasons(finding_list, device_list, capped_totals),
        deductions={_CATEGORY_LABELS.get(k, k): v for k, v in capped_totals.items()},
        tier1_included=tier1_included,
        device_count=len(device_list),
    )


def score_breakdown(findings: Iterable[Finding]) -> List[Tuple[str, int]]:
    """Per-finding point costs, for users who want to audit the number."""
    return [
        (f.finding_id, _WEIGHTS.get(f.code, 0))
        for f in findings
        if _WEIGHTS.get(f.code, 0) > 0
    ]
