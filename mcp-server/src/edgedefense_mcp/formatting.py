"""Markdown rendering for tool output.

The product framing is "ask a question, get an answer", so Markdown is the
default and JSON is opt-in. Two rules govern everything here:

* **Say what is uncertain.** A low-confidence device type is rendered as a
  guess, not a fact.
* **Do not pad.** Every line must earn its place; a wall of text is as unusable
  as a raw JSON dump, just slower to read.
"""

from __future__ import annotations

import json
from typing import Any, Dict, Iterable, List, Optional

from edgedefense_core.changes import ChangeReport, compare_scans
from edgedefense_core.classify import friendly_type, summarise_types, type_count_label
from edgedefense_core.discovery.ports import describe_port
from edgedefense_core.findings import name_with_ip
from edgedefense_core.local_checks import LocalSecurityReport
from edgedefense_core.models import Device, Finding, ScanResult, TrustScore
from edgedefense_core.util import plural

#: Severity -> the marker shown in lists. Text rather than colour so it survives
#: being copied into any client.
_SEVERITY_MARK = {
    "high": "**HIGH**",
    "medium": "**MEDIUM**",
    "low": "LOW",
    "info": "INFO",
}

_CONFIDENCE_PHRASE = {
    "high": "",
    "medium": " (probably)",
    "low": " (best guess)",
    "none": "",
}


def to_json(payload: Any) -> str:
    """Serialise a payload for the JSON response format."""
    return json.dumps(payload, indent=2, default=str)


def device_line(device: Device, index: Optional[int] = None) -> str:
    """One device rendered as a single list entry."""
    prefix = f"{index}. " if index is not None else "- "
    type_label = friendly_type(device.device_type)
    hedge = _CONFIDENCE_PHRASE.get(device.type_confidence, "")

    bits: List[str] = [f"**{device.label()}** - {type_label}{hedge}"]
    detail = [device.ip]
    if device.vendor:
        detail.append(device.vendor)
    if device.is_gateway:
        detail.append("this is your router")
    if device.is_self:
        detail.append("this computer")
    if device.randomised_mac:
        detail.append("private address")
    if device.open_ports:
        detail.append(plural(len(device.open_ports), "open port"))

    # A plain separator rather than a middle dot: this text is copied into
    # terminals and clients with a wide range of encodings.
    bits.append(f"  {' | '.join(detail)}")
    return prefix + "\n".join(bits)


def format_scan_summary(result: ScanResult, score: TrustScore) -> str:
    """The first thing a new user sees. Answers 'what is on my network?'."""
    lines: List[str] = ["# Network scan complete", ""]

    device_count = len(result.devices)
    if device_count == 0:
        lines.append("No devices were found on the local network.")
        lines.extend(_warning_block(result.warnings))
        return "\n".join(lines)

    lines.append(
        f"Found **{plural(device_count, 'device')}** on `{result.subnet or 'your network'}`."
    )
    lines.append("")

    # What kinds of things are here.
    type_counts = summarise_types([d.device_type for d in result.devices])
    breakdown = ", ".join(
        type_count_label(device_type, count) for device_type, count in type_counts
    )
    lines.append(f"**What's connected:** {breakdown}")
    lines.append("")

    # Headline score.
    lines.append(f"**Trust score: {score.score}/100 ({score.grade})**")
    for reason in score.reasons:
        lines.append(f"- {reason}")
    lines.append("")

    # Findings, most severe first, capped so the summary stays a summary.
    actionable = [f for f in result.findings if f.severity in ("high", "medium")]
    if actionable:
        lines.append(f"## Worth your attention ({len(actionable)})")
        lines.append("")
        for finding in actionable[:5]:
            mark = _SEVERITY_MARK.get(finding.severity, finding.severity.upper())
            lines.append(f"- {mark} {finding.summary}")
            lines.append(f"  _Ask about `{finding.finding_id}` for the full explanation._")
        if len(actionable) > 5:
            lines.append(f"- ...and {len(actionable) - 5} more.")
        lines.append("")
    else:
        lines.append("## Worth your attention")
        lines.append("")
        lines.append(
            "Nothing significant. No device is exposing a service that carries real risk."
        )
        lines.append("")

    # Device list.
    lines.append("## Devices")
    lines.append("")
    for device in result.devices:
        lines.append(device_line(device))
    lines.append("")

    lines.extend(_warning_block(result.warnings))
    lines.append(
        f"_Scan depth: {result.scan_depth}. All results stayed on this machine._"
    )
    return "\n".join(lines)


def format_device_list(devices: List[Device], filter_type: str, total: int) -> str:
    """Render a filtered device list."""
    heading = {
        "all": "All devices",
        "unknown": "Unidentified devices",
        "flagged": "Devices with findings",
    }.get(filter_type, "Devices")

    lines: List[str] = [f"# {heading}", ""]

    if not devices:
        if filter_type == "unknown":
            lines.append("Every device on the network was identified. Nothing unknown.")
        elif filter_type == "flagged":
            lines.append("No device has an outstanding finding against it.")
        else:
            lines.append("No devices found. Run a scan first.")
        return "\n".join(lines)

    lines.append(f"Showing {len(devices)} of {plural(total, 'device')}.")
    lines.append("")
    for index, device in enumerate(devices, start=1):
        lines.append(device_line(device, index=index))
    lines.append("")
    lines.append("_Ask about any device by its IP or name for more detail._")
    return "\n".join(lines)


def format_device_detail(
    device: Device,
    findings: List[Finding],
) -> str:
    """Everything known about one device."""
    lines: List[str] = [f"# {device.label()}", ""]

    type_label = friendly_type(device.device_type)
    confidence = device.type_confidence
    if confidence in ("high", ""):
        lines.append(f"**Type:** {type_label}")
    elif confidence == "none":
        lines.append(
            "**Type:** could not be determined - the device revealed nothing "
            "identifying about itself."
        )
    else:
        lines.append(f"**Type:** {type_label} _(confidence: {confidence})_")

    lines.append(f"**Address:** {device.ip}")
    lines.append(f"**Hardware address:** {device.mac or 'not visible'}")

    if device.randomised_mac:
        lines.append(
            "**Note:** this device uses a randomised hardware address for privacy, "
            "so its manufacturer cannot be identified. That is normal for modern "
            "phones and laptops."
        )
    else:
        lines.append(f"**Manufacturer:** {device.vendor or 'not in the local vendor database'}")

    if device.hostname:
        lines.append(f"**Name it reports:** {device.hostname}")
    if device.user_label:
        lines.append(f"**Your name for it:** {device.user_label}")
    if device.is_gateway:
        lines.append("**Role:** this is your router - the device connecting you to the internet.")
    if device.is_self:
        lines.append("**Role:** this is the computer running the scan.")
    if device.first_seen:
        lines.append(f"**First seen:** {device.first_seen}")
    if device.last_seen:
        lines.append(f"**Last seen:** {device.last_seen}")
    if device.sources:
        lines.append(f"**Detected via:** {', '.join(device.sources)}")

    lines.append("")

    if device.open_ports:
        lines.append(f"## Open ports ({len(device.open_ports)})")
        lines.append("")
        for port in device.open_ports:
            lines.append(f"- **{port}** - {device.services.get(port, 'unknown service')}")
        lines.append("")
    else:
        lines.append("## Open ports")
        lines.append("")
        lines.append("None of the ports checked were open. This device is not offering "
                     "any services to the network.")
        lines.append("")

    if device.mdns_services:
        lines.append("## Services it advertises")
        lines.append("")
        for service in device.mdns_services:
            lines.append(f"- `{service}`")
        lines.append("")

    if findings:
        lines.append(f"## Findings ({len(findings)})")
        lines.append("")
        for finding in findings:
            mark = _SEVERITY_MARK.get(finding.severity, finding.severity.upper())
            lines.append(f"- {mark} {finding.title}")
            lines.append(f"  {finding.summary}")
            lines.append(f"  _Full explanation: `{finding.finding_id}`_")
        lines.append("")
    else:
        lines.append("## Findings")
        lines.append("")
        lines.append("Nothing flagged on this device.")
        lines.append("")

    return "\n".join(lines)


def format_trust_score(score: TrustScore, result: ScanResult) -> str:
    """The shareable score. Designed to be screenshotted, so: short."""
    lines: List[str] = [
        "# Network Trust Score",
        "",
        f"# {score.score}/100 - {score.grade}",
        "",
    ]

    if score.device_count:
        lines.append(f"Across {plural(score.device_count, 'device')} on this network.")
        lines.append("")

    for reason in score.reasons:
        lines.append(f"- {reason}")
    lines.append("")

    if score.deductions:
        lines.append("**Where the points went:**")
        for label, points in sorted(score.deductions.items(), key=lambda kv: -kv[1]):
            lines.append(f"- {label}: -{points}")
        lines.append("")

    basis = "Based on device discovery and port checks."
    lines.append(f"_{basis}_")
    lines.append("")
    lines.append(
        "_Scored by EdgeDefense. Runs locally, sends nothing anywhere, needs no account._"
    )
    return "\n".join(lines)


def format_finding_explanation(finding: Finding, device: Optional[Device]) -> str:
    """The AI-escalation surface: a flagged issue turned into plain English."""
    lines: List[str] = [f"# {finding.title}", ""]

    severity_sentence = {
        "high": "This is worth acting on.",
        "medium": "This is worth understanding, and probably worth changing.",
        "low": "This is minor - useful to know, not urgent.",
        "info": "This is informational. Nothing is wrong.",
    }.get(finding.severity, "")

    lines.append(f"**Severity:** {finding.severity.upper()}. {severity_sentence}")
    if device:
        lines.append(f"**Device:** {name_with_ip(device)}")
    lines.append("")

    lines.append("## What this means")
    lines.append("")
    lines.append(finding.detail)
    lines.append("")

    lines.append("## What to do about it")
    lines.append("")
    lines.append(finding.what_to_do)
    lines.append("")

    if finding.limitations:
        lines.append("## What this check cannot tell you")
        lines.append("")
        lines.append(finding.limitations)
        lines.append("")

    return "\n".join(lines)


def format_changes(report: ChangeReport) -> str:
    """Render what changed between the two most recent scans."""
    lines: List[str] = ["# What changed on your network", ""]
    lines.append(
        f"Comparing the scan at **{report.current_finished_at}** "
        f"with the one before it (**{report.previous_finished_at}**)."
    )
    lines.append("")

    if not report.has_changes:
        lines.append(
            "Nothing changed. Same devices, same open ports. "
            "Run another scan later to catch new arrivals."
        )
        return "\n".join(lines)

    if report.new_devices:
        lines.append(f"## New devices ({len(report.new_devices)})")
        lines.append("")
        for device in report.new_devices:
            lines.append(device_line(device))
        lines.append("")

    if report.vanished_devices:
        lines.append(f"## No longer seen ({len(report.vanished_devices)})")
        lines.append("")
        for device in report.vanished_devices:
            lines.append(device_line(device))
        lines.append(
            "_Devices that were asleep or off-network may show up here. "
            "They often reappear on the next scan._"
        )
        lines.append("")

    if report.port_changes:
        lines.append(f"## Port changes ({len(report.port_changes)})")
        lines.append("")
        for change in report.port_changes:
            lines.append(f"**{change.label}** ({change.ip})")
            if change.opened:
                opened = ", ".join(
                    f"{p} ({describe_port(p)})" for p in change.opened
                )
                lines.append(f"- Opened: {opened}")
            if change.closed:
                closed = ", ".join(
                    f"{p} ({describe_port(p)})" for p in change.closed
                )
                lines.append(f"- Closed: {closed}")
            lines.append("")

    return "\n".join(lines)


def _warning_block(warnings: Iterable[str]) -> List[str]:
    """Render scan warnings, or nothing at all if there were none."""
    warnings = list(warnings)
    if not warnings:
        return []
    lines = ["## Notes", ""]
    lines.extend(f"- {warning}" for warning in warnings)
    lines.append("")
    return lines


def format_local_security(report: LocalSecurityReport) -> str:
    """Format the local security checks report."""
    lines: List[str] = ["# Local Security Configuration", ""]
    
    # Wi-Fi Status
    lines.append("## Wi-Fi Security")
    lines.append("")
    if report.wifi_secure is None:
        lines.append("Could not determine Wi-Fi security status.")
    else:
        status = "**Secure**" if report.wifi_secure else "**INSECURE** (Open Network)"
        lines.append(f"Status: {status}")
        if report.wifi_ssid:
            lines.append(f"Network: {report.wifi_ssid}")
        if report.wifi_auth_type:
            lines.append(f"Authentication: {report.wifi_auth_type}")
    lines.append("")

    # DNS Configuration
    lines.append("## DNS Configuration")
    lines.append("")
    if not report.dns_servers:
        lines.append("No DNS servers could be detected.")
    else:
        lines.append(f"Using {len(report.dns_servers)} DNS server(s):")
        for dns in report.dns_servers:
            lines.append(f"- {dns}")
    lines.append("")

    # Local Port Exposure
    lines.append("## Local Network Exposure")
    lines.append("")
    lines.append("Ports listening on `0.0.0.0` (accessible to anyone on your network):")
    lines.append("")
    if not report.listening_ports:
        lines.append("No exposed ports detected. Good!")
    else:
        for p in report.listening_ports:
            lines.append(f"- **Port {p['port']}** ({p['protocol'].upper()})")
    lines.append("")

    lines.extend(_warning_block(report.warnings))
    return "\n".join(lines)
