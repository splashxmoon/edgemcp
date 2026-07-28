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
from edgedefense_core.perf.interfaces import InterfaceReport, InterfaceStats
from edgedefense_core.perf.latency import LatencyReport
from edgedefense_core.perf.speedtest import SpeedTestResult
from edgedefense_core.perf.wifi import WifiReport
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


# --------------------------------------------------------------------------
# Performance
# --------------------------------------------------------------------------


def human_rate(bits_per_second: Optional[float]) -> str:
    """Render a throughput figure at whatever scale keeps it readable."""
    if bits_per_second is None:
        return "unknown"
    if bits_per_second < 1_000:
        return f"{bits_per_second:.0f} bps"
    if bits_per_second < 1_000_000:
        return f"{bits_per_second / 1_000:.1f} Kbps"
    if bits_per_second < 1_000_000_000:
        return f"{bits_per_second / 1_000_000:.1f} Mbps"
    return f"{bits_per_second / 1_000_000_000:.2f} Gbps"


def human_bytes(count: Optional[int]) -> str:
    """Render a byte total the way a person would say it."""
    if count is None:
        return "unknown"
    value = float(count)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            return f"{value:.1f} {unit}" if unit != "B" else f"{value:.0f} B"
        value /= 1024
    return f"{value:.1f} TB"


def _interface_block(iface: InterfaceStats) -> List[str]:
    """One adapter, rendered as a short paragraph."""
    lines: List[str] = [f"**{iface.name}**" + (f" - {iface.description}" if iface.description else "")]

    facts: List[str] = []
    if iface.link_speed_mbps:
        facts.append(f"link {human_rate(iface.link_speed_mbps * 1_000_000)}")
    if iface.mtu:
        facts.append(f"MTU {iface.mtu}")
    facts.append("up" if iface.is_up else "down")
    lines.append(f"- {' | '.join(facts)}")

    if iface.recv_rate_bps is not None or iface.send_rate_bps is not None:
        lines.append(
            f"- Right now: {human_rate(iface.recv_rate_bps)} down, "
            f"{human_rate(iface.send_rate_bps)} up"
        )

    lines.append(
        f"- Since boot: {human_bytes(iface.bytes_recv)} received, "
        f"{human_bytes(iface.bytes_sent)} sent"
    )

    rate = iface.error_rate()
    if rate is None:
        pass  # The platform did not expose error counters; say nothing rather than "0%".
    elif rate > 0.01:
        lines.append(
            f"- **{rate * 100:.2f}% of packets errored or were dropped.** Above about 1% "
            "this is a real fault - a failing cable, a dying port, or a marginal "
            "wireless link."
        )
    elif rate > 0:
        lines.append(f"- Error rate {rate * 100:.3f}% (normal)")
    else:
        lines.append("- No packet errors or drops")

    return lines


def format_network_stats(
    interfaces: InterfaceReport,
    wifi: Optional[WifiReport],
) -> str:
    """Render adapter throughput and Wi-Fi link quality as one report."""
    lines: List[str] = ["# Network status", ""]

    active = interfaces.active()
    if not active:
        lines.append(
            "No active network adapter reported any traffic. Either this machine is "
            "offline, or the counters could not be read."
        )
        lines.extend(_warning_block(interfaces.warnings))
        return "\n".join(lines)

    if interfaces.sample_seconds:
        lines.append(
            f"Live rates measured over {interfaces.sample_seconds:.1f} seconds."
        )
        lines.append("")

    lines.append("## Adapters")
    lines.append("")
    for iface in active:
        lines.extend(_interface_block(iface))
        lines.append("")

    idle = [
        iface
        for iface in interfaces.interfaces
        if iface not in active and not iface.is_virtual and iface.is_up
    ]
    if idle:
        lines.append(
            f"_{plural(len(idle), 'other adapter')} up but idle: "
            f"{', '.join(iface.name for iface in idle)}._"
        )
        lines.append("")

    if wifi is not None:
        lines.extend(_wifi_section(wifi))

    lines.extend(_warning_block(interfaces.warnings))
    lines.append("_All of this was read from local counters. Nothing left this machine._")
    return "\n".join(lines)


def _wifi_section(report: WifiReport) -> List[str]:
    """The Wi-Fi half of the status report."""
    lines: List[str] = ["## Wi-Fi", ""]
    link = report.link

    if link is None:
        lines.append(
            "Not connected by Wi-Fi. On a wired connection that is expected, and it is "
            "the better situation of the two."
        )
        lines.append("")
        lines.extend(_warning_block(report.warnings))
        return lines

    lines.append(f"**Network:** {link.ssid or 'unknown'}")

    quality = link.quality()
    if link.signal_dbm is not None:
        percent = f" ({link.signal_percent}%)" if link.signal_percent is not None else ""
        lines.append(
            f"**Signal:** {link.signal_dbm:.0f} dBm{percent}"
            + (f" - {quality}" if quality else "")
        )
    elif link.signal_percent is not None:
        lines.append(f"**Signal:** {link.signal_percent}%")

    if link.band or link.channel:
        band = link.band or "unknown band"
        channel = f", channel {link.channel}" if link.channel else ""
        lines.append(f"**Radio:** {band}{channel}")
    if link.radio_type:
        lines.append(f"**Standard:** {link.radio_type}")
    if link.rx_rate_mbps or link.tx_rate_mbps:
        lines.append(
            f"**Negotiated rate:** {link.rx_rate_mbps or 0:.0f} Mbps down, "
            f"{link.tx_rate_mbps or 0:.0f} Mbps up"
        )
        lines.append(
            "_This is what the radio negotiated, not what your internet connection "
            "delivers. It is a ceiling, and usually a generous one._"
        )
    lines.append("")

    usage = report.channel_usage()
    if usage:
        crowded = report.congestion()
        if crowded is not None:
            lines.append(
                f"**Channel {link.channel}:** shared with {plural(crowded, 'other network')}."
            )
        busiest = ", ".join(
            f"ch {channel} ({count})" for channel, count in usage[:5]
        )
        lines.append(f"**Busiest channels nearby:** {busiest}")
        lines.append(f"**Networks in range:** {len(report.nearby)}")
        lines.append("")

    advice = report.advice()
    if advice:
        lines.append("### Worth doing")
        lines.append("")
        for tip in advice:
            lines.append(f"- {tip}")
        lines.append("")

    lines.extend(_warning_block(report.warnings))
    return lines


def format_latency(report: LatencyReport) -> str:
    """Render gateway round trips and resolver timings."""
    lines: List[str] = ["# Latency and name resolution", ""]

    gateway = report.gateway
    lines.append("## Hop to your router")
    lines.append("")
    if gateway is None:
        lines.append("The default gateway could not be determined, so this was skipped.")
    elif gateway.error:
        lines.append(gateway.error)
    elif not gateway.samples_ms:
        lines.append(
            f"`{gateway.host}` did not answer any of {plural(gateway.sent, 'ping')}. "
            "Plenty of routers are configured not to reply to pings, so this alone is "
            "not evidence of a problem."
        )
    else:
        lines.append(f"**{gateway.host}** - {gateway.received}/{gateway.sent} replied")
        lines.append(
            f"- Round trip: {gateway.min_ms:.1f} ms min, "
            f"**{gateway.avg_ms:.1f} ms average**, {gateway.max_ms:.1f} ms max"
        )
        if gateway.jitter_ms is not None:
            lines.append(f"- Jitter: {gateway.jitter_ms:.1f} ms")
        loss = gateway.loss_percent
        if loss:
            lines.append(f"- **Packet loss: {loss:.0f}%**")
    lines.append("")

    if report.dns:
        lines.append("## DNS resolvers")
        lines.append("")
        for entry in report.dns:
            if entry.avg_ms is None:
                lines.append(f"- **{entry.server}** - {entry.error or 'no reply'}")
            else:
                suffix = f" ({entry.failures} query failed)" if entry.failures else ""
                lines.append(f"- **{entry.server}** - {entry.avg_ms:.0f} ms average{suffix}")
        lines.append("")
        lines.append(
            f"_Measured by resolving `{report.dns[0].query}`, which every resolver will "
            "have cached. This reflects the lookup a browser actually makes._"
        )
        lines.append("")

    verdict = report.verdict()
    if verdict:
        lines.append("## What this means")
        lines.append("")
        for line in verdict:
            lines.append(f"- {line}")
        lines.append("")

    lines.extend(_warning_block(report.warnings))
    lines.append(
        "_Packets went only to your own router and to the DNS servers this machine is "
        "already configured to use._"
    )
    return "\n".join(lines)


def format_speed_test(result: SpeedTestResult) -> str:
    """Render the throughput result, headline number first."""
    lines: List[str] = ["# Internet speed test", ""]

    if result.download_mbps is None and result.upload_mbps is None:
        lines.append("The test could not complete.")
        lines.append("")
        lines.extend(_warning_block(result.warnings))
        return "\n".join(lines)

    down = f"{result.download_mbps:.1f}" if result.download_mbps is not None else "?"
    up = f"{result.upload_mbps:.1f}" if result.upload_mbps is not None else "not measured"
    lines.append(f"# {down} Mbps down / {up} Mbps up")
    lines.append("")

    if result.idle_latency_ms is not None:
        latency_line = f"**Latency:** {result.idle_latency_ms:.0f} ms idle"
        if result.jitter_ms is not None:
            latency_line += f", {result.jitter_ms:.0f} ms jitter"
        lines.append(latency_line)

    grade = result.bufferbloat_grade()
    if grade and result.bufferbloat_ms is not None:
        lines.append(
            f"**Under load:** {result.loaded_latency_ms:.0f} ms "
            f"(+{result.bufferbloat_ms:.0f} ms) - bufferbloat grade **{grade}**"
        )

    if result.server_location or result.server_colo:
        where = result.server_location or ""
        colo = f" [{result.server_colo}]" if result.server_colo else ""
        lines.append(f"**Measured against:** {where}{colo}")
    lines.append("")

    notes = result.capability_notes()
    if notes:
        lines.append("## What that gets you")
        lines.append("")
        for note in notes:
            lines.append(f"- {note}")
        lines.append("")

    lines.append("## How it was measured")
    lines.append("")
    lines.append(
        f"- {human_bytes(result.bytes_downloaded)} pulled over "
        f"{plural(result.download_streams, 'parallel connection')}"
    )
    if result.bytes_uploaded:
        lines.append(
            f"- {human_bytes(result.bytes_uploaded)} pushed over "
            f"{plural(result.upload_streams, 'parallel connection')}"
        )
    if result.duration_seconds:
        lines.append(f"- Took {result.duration_seconds:.0f} seconds in total")
    lines.append("")

    lines.extend(_warning_block(result.warnings))
    lines.append(
        f"_This test contacted `{result.endpoint}` - the one part of EdgeDefense that "
        "leaves your machine, and only when you ask for it. No identifying information "
        "was attached, and your public IP address was deliberately left out of this "
        "result. A speed test is a rough measure: other devices using the connection "
        "during the test will drag the numbers down._"
    )
    return "\n".join(lines)
