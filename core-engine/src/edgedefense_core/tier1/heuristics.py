"""Tier 1 anomaly detection: simple, explainable heuristics.

Nothing here is machine learning, and nothing here pretends to be. These are
two deliberately transparent rules whose false-positive modes are known and
stated in every finding they produce.

The trained detection pipeline is a separate, private package. It is not
imported here and must never be: this repository is public.
"""

from __future__ import annotations

from statistics import median
from typing import Dict, Iterable, List, Optional

from ..findings import (
    EXPLANATIONS,
    bare_name,
    make_finding_id,
    name_with_ip,
    sentence_name,
)
from ..models import Device, Finding
from ..util import human_bytes
from .capture import CaptureResult

#: A device must contact at least this many unresolved addresses before we say
#: anything. One or two is background noise on almost every device.
_BYPASS_MIN_ADDRESSES = 3

#: Outlier detection needs a peer group to compare against.
_OUTLIER_MIN_DEVICES = 4

#: A device must exceed both a relative and an absolute threshold to be called
#: an outlier, so a quiet network does not manufacture one.
_OUTLIER_RATIO = 4.0
_OUTLIER_FLOOR_BYTES = 5 * 1024 * 1024


def _device_lookup(devices: Iterable[Device]) -> Dict[str, Device]:
    """Index devices by IP so capture data can be attributed to real names."""
    return {device.ip: device for device in devices}


def detect_dns_bypass(
    capture: CaptureResult,
    devices: Iterable[Device],
) -> List[Finding]:
    """Flag devices connecting to addresses never resolved via network DNS.

    The rule: collect every address that appeared in a DNS answer anywhere on
    the network during the window, then look for devices contacting public
    addresses outside that set.

    Comparing against DNS answers seen from *any* device (rather than only the
    device in question) is deliberate. It is the conservative choice: it
    suppresses findings whenever a name was resolved by anyone, which loses some
    true positives but avoids flooding the user with false ones.
    """
    findings: List[Finding] = []
    by_ip = _device_lookup(devices)
    resolved = set(capture.resolved_ips)

    for ip, traffic in capture.per_device.items():
        unresolved = sorted(traffic.contacted_ips - resolved)
        if len(unresolved) < _BYPASS_MIN_ADDRESSES:
            continue

        device = by_ip.get(ip)
        device_id = device.device_id if device else f"ip-{ip}"
        name = bare_name(device) if device else f"the device at {ip}"
        sentence = sentence_name(device) if device else f"The device at {ip}"
        where = name_with_ip(device) if device else f"The device at {ip}"

        findings.append(
            Finding(
                finding_id=make_finding_id("dns_bypass", device_id),
                code="dns_bypass",
                severity="medium",
                title=f"{where} connected to addresses that were never looked up",
                summary=(
                    f"{where} contacted {len(unresolved)} internet addresses with no "
                    f"matching DNS lookup during the {int(capture.duration_seconds)}-second "
                    f"capture. It made {traffic.dns_query_count} DNS queries in the same window."
                ),
                detail=EXPLANATIONS["dns_bypass"]["detail"].format(
                    name=name, Name=sentence, ip=ip, count=len(unresolved)
                ),
                what_to_do=EXPLANATIONS["dns_bypass"]["what_to_do"].format(name=name, Name=sentence),
                limitations=EXPLANATIONS["dns_bypass"]["limitations"],
                tier=1,
                device_id=device_id,
                evidence={
                    # Capped: the point is to show a sample, not dump a flow log.
                    "unresolved_addresses": unresolved[:10],
                    "unresolved_count": len(unresolved),
                    "dns_queries_made": traffic.dns_query_count,
                    "capture_seconds": int(capture.duration_seconds),
                },
            )
        )

    return findings


def detect_volume_outliers(
    capture: CaptureResult,
    devices: Iterable[Device],
) -> List[Finding]:
    """Flag devices moving far more data than their peers during the window."""
    findings: List[Finding] = []
    by_ip = _device_lookup(devices)

    totals = {ip: t.total_bytes for ip, t in capture.per_device.items() if t.total_bytes > 0}
    if len(totals) < _OUTLIER_MIN_DEVICES:
        return findings

    values = sorted(totals.values())
    typical = median(values)
    if typical <= 0:
        return findings

    for ip, total in totals.items():
        if total < _OUTLIER_FLOOR_BYTES or total < typical * _OUTLIER_RATIO:
            continue

        device = by_ip.get(ip)
        device_id = device.device_id if device else f"ip-{ip}"
        name = bare_name(device) if device else f"the device at {ip}"
        sentence = sentence_name(device) if device else f"The device at {ip}"
        where = name_with_ip(device) if device else f"The device at {ip}"

        findings.append(
            Finding(
                finding_id=make_finding_id("data_volume_outlier", device_id),
                code="data_volume_outlier",
                severity="low",
                title=f"{where} moved much more data than other devices",
                summary=(
                    f"{where} transferred {human_bytes(total)} during the capture, "
                    f"against a typical device's {human_bytes(typical)}."
                ),
                detail=EXPLANATIONS["data_volume_outlier"]["detail"].format(
                    name=name,
                    Name=sentence,
                    ip=ip,
                    bytes_human=human_bytes(total),
                    median_human=human_bytes(typical),
                ),
                what_to_do=EXPLANATIONS["data_volume_outlier"]["what_to_do"].format(name=name, Name=sentence),
                limitations=EXPLANATIONS["data_volume_outlier"]["limitations"],
                tier=1,
                device_id=device_id,
                evidence={
                    "total_bytes": total,
                    "median_bytes": int(typical),
                    "ratio": round(total / typical, 1),
                },
            )
        )

    return findings


def analyse_capture(
    capture: CaptureResult,
    devices: Iterable[Device],
) -> List[Finding]:
    """Run every Tier 1 heuristic and return the combined findings."""
    device_list = list(devices)
    findings = detect_dns_bypass(capture, device_list)
    findings.extend(detect_volume_outliers(capture, device_list))

    from ..findings import sort_findings

    return sort_findings(findings)


def capture_summary(capture: CaptureResult, devices: Optional[Iterable[Device]] = None) -> Dict:
    """Human-facing summary stats for a completed capture."""
    by_ip = _device_lookup(devices or [])
    busiest = sorted(
        capture.per_device.values(), key=lambda t: t.total_bytes, reverse=True
    )[:5]

    return {
        "duration_seconds": round(capture.duration_seconds, 1),
        "packets_seen": capture.packets_seen,
        "devices_with_traffic": len(capture.per_device),
        "names_resolved": len(capture.resolved_ips),
        "busiest_devices": [
            {
                "ip": t.ip,
                "label": by_ip[t.ip].label() if t.ip in by_ip else f"Device at {t.ip}",
                "total": human_bytes(t.total_bytes),
                "total_bytes": t.total_bytes,
            }
            for t in busiest
        ],
    }
