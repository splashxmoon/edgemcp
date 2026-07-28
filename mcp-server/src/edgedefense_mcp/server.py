#!/usr/bin/env python3
"""EdgeDefense MCP server.

Answers questions about the local network in plain language. Everything runs on
the machine that hosts the server: there is no account, no cloud component, and
no outbound request of any kind, including analytics.

All tools work without elevated privileges. Device naming is the only tool
that writes locally — everything else is read-only.

Tool parameters are declared flat (rather than wrapped in a single Pydantic
model) so the generated JSON schema has no nesting for callers to get wrong.
Validation is unchanged -- FastMCP builds the same constraints from the
annotations.
"""

from __future__ import annotations

import asyncio
from enum import Enum
from typing import Annotated, Any, Dict, List, Optional

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from edgedefense_core import __version__ as core_version
from edgedefense_core.changes import compare_scans
from edgedefense_core.classify import classify_device
from edgedefense_core.findings import find_by_id, sort_findings
from edgedefense_core.models import Device, Finding, ScanResult
from edgedefense_core.scan import run_scan, scan_result_from_dict
from edgedefense_core.scoring import compute_trust_score
from edgedefense_core.storage import Storage
from edgedefense_core.vendor import oui_database_size

from .formatting import (
    format_changes,
    format_device_detail,
    format_device_list,
    format_finding_explanation,
    format_latency,
    format_local_security,
    format_network_stats,
    format_scan_summary,
    format_speed_test,
    format_trust_score,
    to_json,
)

__version__ = "0.1.0"


def _disable_dotenv_loading() -> None:
    """Stop FastMCP reading a .env file from whatever directory we start in.

    FastMCP's ``Settings`` is a pydantic-settings model declared with
    ``env_file=".env"``, so merely constructing it parses whichever .env
    happens to sit in the working directory the MCP client launched us from --
    typically the user's home directory, which we do not control.

    If that file is not valid UTF-8, parsing raises and the server dies during
    import, before it can serve anything. The client reports only "Connection
    closed", which is close to undiagnosable from the user's side. A .env
    written by PowerShell's default redirection is UTF-16, which triggers this
    exactly.

    This server takes no configuration of its own, so it has no reason to read
    a .env at all. Disabling it removes a whole class of startup failure whose
    trigger lives outside this project. Real ``FASTMCP_*`` environment
    variables still work; only the file is ignored.
    """
    try:
        from mcp.server.fastmcp.server import Settings

        Settings.model_config["env_file"] = None
    except Exception:
        # Hardening must never itself prevent startup. If a future SDK layout
        # makes this unreachable, test_startup_isolation.py will catch it.
        pass


_disable_dotenv_loading()

mcp = FastMCP(
    "edgedefense_mcp",
    instructions=(
        "Answers questions about the user's home network: what is connected, what each "
        "device is, what looks unusual, and what any finding actually means.\n\n"
        "Start with edgedefense_scan_network - the other tools read the results of the "
        "most recent scan. Findings are referenced by a stable finding_id; pass that to "
        "edgedefense_explain_finding for a plain-English explanation. Use "
        "edgedefense_whats_changed to compare the latest scan with the previous one.\n\n"
        "It also answers performance questions. For 'why is my network slow', prefer "
        "edgedefense_network_stats (adapter throughput, Wi-Fi signal, channel "
        "congestion) and edgedefense_latency_check (round trip to the router, DNS "
        "timing) - both are local and fast. Reach for edgedefense_speed_test only when "
        "the user actually wants a throughput number in Mbps.\n\n"
        "This server runs locally and requires no account, no telemetry and no "
        "elevated privileges. Exactly one tool leaves the machine: "
        "edgedefense_speed_test contacts a public speed test service, because "
        "measuring download speed is impossible without doing so. Every other tool "
        "reads local state or talks only to the user's own network."
    ),
)


# --------------------------------------------------------------------------
# Enums
# --------------------------------------------------------------------------


class ResponseFormat(str, Enum):
    """Output format for tool responses."""

    MARKDOWN = "markdown"
    JSON = "json"


class ScanDepth(str, Enum):
    """How thorough a scan to run."""

    QUICK = "quick"
    FULL = "full"


class DeviceFilter(str, Enum):
    """Which subset of devices to list."""

    ALL = "all"
    UNKNOWN = "unknown"
    FLAGGED = "flagged"


# --------------------------------------------------------------------------
# Shared state
# --------------------------------------------------------------------------

_storage: Optional[Storage] = None
#: The most recent scan, kept in memory so follow-up questions are instant.
_last_result: Optional[ScanResult] = None
#: Serialises scans; two concurrent sweeps would interfere with each other.
_scan_lock = asyncio.Lock()

_NO_SCAN_MESSAGE = (
    "No scan results are available yet. Run edgedefense_scan_network first - it takes "
    "about ten seconds and needs no special permissions."
)


def get_storage() -> Storage:
    """Lazily open the local database so import never touches the filesystem."""
    global _storage
    if _storage is None:
        _storage = Storage()
    return _storage


def _apply_user_label(device: Device, label: str) -> Device:
    """Re-classify a device after the user assigns a name."""
    device_type, confidence = classify_device(
        hostname=device.hostname,
        user_label=label,
        vendor=device.vendor,
        open_ports=device.open_ports,
        mdns_services=device.mdns_services,
        is_gateway=device.is_gateway,
        is_self=device.is_self,
    )
    device.user_label = label
    device.device_type = device_type
    device.type_confidence = confidence
    return device


def _current_result() -> Optional[ScanResult]:
    """Return the most recent scan, falling back to the stored one."""
    global _last_result
    if _last_result is not None:
        return _last_result

    stored = get_storage().load_latest_scan()
    if stored:
        _last_result = scan_result_from_dict(stored)
    return _last_result


def _resolve_device(result: ScanResult, identifier: str) -> Optional[Device]:
    """Find a device by id, IP, MAC or hostname.

    Deliberately forgiving: the user will type whatever they saw in the last
    response, and rejecting a valid-looking identifier over formatting would be
    a poor experience.
    """
    needle = identifier.strip().lower()
    if not needle:
        return None

    for device in result.devices:
        if device.device_id.lower() == needle:
            return device
    for device in result.devices:
        if device.ip == needle or (device.mac or "").lower() == needle:
            return device
    for device in result.devices:
        if (device.hostname or "").lower() == needle:
            return device
    # Last resort: "ip-192.168.1.4" typed as "192.168.1.4" and vice versa.
    stripped = needle[3:] if needle.startswith("ip-") else needle
    for device in result.devices:
        if device.ip == stripped:
            return device
    return None


# --------------------------------------------------------------------------
# Reusable parameter annotations
# --------------------------------------------------------------------------

FormatParam = Annotated[
    ResponseFormat,
    Field(description="'markdown' for readable prose, 'json' for structured data"),
]


# --------------------------------------------------------------------------
# Tools
# --------------------------------------------------------------------------


@mcp.tool(
    name="edgedefense_scan_network",
    annotations={
        "title": "Scan the local network",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": False,
    },
)
async def edgedefense_scan_network(
    scan_depth: Annotated[
        ScanDepth,
        Field(
            description=(
                "'quick' (default, ~10 seconds, checks 12 common ports) or 'full' "
                "(~30 seconds, checks 42 ports and listens longer for device announcements)"
            )
        ),
    ] = ScanDepth.QUICK,
    response_format: FormatParam = ResponseFormat.MARKDOWN,
) -> str:
    """Discover every device on the local network and summarise what is there.

    This is the entry point: the other tools read the results of the most recent
    scan, so call this first. Discovery uses the system address table, device
    self-announcements (mDNS), and a check of common ports. It requires no
    elevated privileges and makes no outbound internet requests.

    Args:
        scan_depth (ScanDepth): 'quick' (~10s) or 'full' (~30s). Default 'quick'.
        response_format (ResponseFormat): 'markdown' or 'json'. Default 'markdown'.

    Returns:
        str: In markdown mode, a readable summary: device count, a breakdown by
        device type, the trust score with reasons, notable findings, and the
        full device list.

        In json mode, an object with this schema:
        {
            "started_at": str,          # ISO-8601 UTC
            "finished_at": str,
            "scan_depth": str,          # "quick" | "full"
            "subnet": str | null,       # e.g. "192.168.1.0/24"
            "devices": [
                {
                    "device_id": str,       # MAC, or "ip-<address>" if no MAC
                    "ip": str,
                    "mac": str | null,
                    "hostname": str | null,
                    "vendor": str | null,
                    "device_type": str,     # e.g. "router", "phone_or_tablet"
                    "type_confidence": str, # "high"|"medium"|"low"|"none"
                    "open_ports": [int],
                    "services": {str: str}, # port -> service description
                    "mdns_services": [str],
                    "randomised_mac": bool,
                    "is_gateway": bool,
                    "is_self": bool,
                    "sources": [str],       # "arp" | "mdns" | "self"
                    "first_seen": str | null,
                    "last_seen": str | null,
                    "label": str
                }
            ],
            "findings": [
                {
                    "finding_id": str,      # stable; pass to explain_finding
                    "code": str,
                    "severity": str,        # "high"|"medium"|"low"|"info"
                    "title": str,
                    "summary": str,
                    "detail": str,
                    "what_to_do": str,
                    "limitations": str,
                    "device_id": str | null,
                    "evidence": object
                }
            ],
            "warnings": [str],
            "trust_score": {"score": int, "grade": str, "reasons": [str], ...}
        }

    Examples:
        - Use when: "What's on my network?" -> defaults
        - Use when: "Do a thorough scan" -> scan_depth='full'
        - Don't use when: results already exist and the user is asking a
          follow-up question - use edgedefense_list_devices or
          edgedefense_get_device_detail instead, which do not re-scan

    Error Handling:
        Never raises for network conditions. If discovery is partially blocked
        (VPN active, mDNS port unavailable), the scan still returns whatever was
        found and explains the gap under "Notes" / "warnings".
    """
    global _last_result

    async with _scan_lock:
        result = await run_scan(scan_depth=scan_depth.value, storage=get_storage())
        _last_result = result

    score = compute_trust_score(result.devices, result.findings)

    if response_format == ResponseFormat.JSON:
        payload = result.to_dict()
        payload["trust_score"] = score.to_dict()
        return to_json(payload)

    return format_scan_summary(result, score)


@mcp.tool(
    name="edgedefense_list_devices",
    annotations={
        "title": "List discovered devices",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def edgedefense_list_devices(
    filter_type: Annotated[
        DeviceFilter,
        Field(
            description=(
                "'all' for every device, 'unknown' for devices that could not be "
                "identified, 'flagged' for devices with at least one finding against them"
            )
        ),
    ] = DeviceFilter.ALL,
    response_format: FormatParam = ResponseFormat.MARKDOWN,
) -> str:
    """List devices found by the most recent scan, optionally filtered.

    Reads cached results and does not re-scan, so it is fast and repeatable.

    Args:
        filter_type (DeviceFilter): 'all', 'unknown', or 'flagged'. Default 'all'.
        response_format (ResponseFormat): 'markdown' or 'json'. Default 'markdown'.

    Returns:
        str: In markdown mode, a numbered list with each device's name, type,
        address, manufacturer and open-port count.

        In json mode:
        {
            "filter": str,              # the filter applied
            "total_devices": int,       # total discovered, before filtering
            "count": int,               # devices in this response
            "devices": [ ... ]          # same device schema as scan_network
        }

    Examples:
        - Use when: "List everything on my network" -> filter_type='all'
        - Use when: "Which devices couldn't you identify?" -> filter_type='unknown'
        - Use when: "What has problems?" -> filter_type='flagged'
        - Don't use when: no scan has run yet - call edgedefense_scan_network first

    Error Handling:
        Returns a message directing the user to run a scan if none has been run.
    """
    result = _current_result()
    if result is None:
        return _NO_SCAN_MESSAGE

    findings = result.findings
    flagged_ids = {f.device_id for f in findings if f.device_id and f.severity != "info"}

    if filter_type == DeviceFilter.UNKNOWN:
        devices = [d for d in result.devices if d.device_type == "unknown"]
    elif filter_type == DeviceFilter.FLAGGED:
        devices = [d for d in result.devices if d.device_id in flagged_ids]
    else:
        devices = list(result.devices)

    if response_format == ResponseFormat.JSON:
        return to_json(
            {
                "filter": filter_type.value,
                "total_devices": len(result.devices),
                "count": len(devices),
                "devices": [d.to_dict() for d in devices],
            }
        )

    return format_device_list(devices, filter_type.value, len(result.devices))


@mcp.tool(
    name="edgedefense_get_device_detail",
    annotations={
        "title": "Inspect one device",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def edgedefense_get_device_detail(
    device_id: Annotated[
        str,
        Field(
            description=(
                "Which device to look up. Accepts the device_id from a previous response "
                "(e.g. 'a4:cf:12:34:56:78' or 'ip-192.168.1.40'), a plain IP address "
                "(e.g. '192.168.1.40'), a MAC address, or the device's hostname"
            ),
            min_length=1,
            max_length=200,
        ),
    ],
    response_format: FormatParam = ResponseFormat.MARKDOWN,
) -> str:
    """Show everything known about a single device.

    Covers device type and how confident that guess is, manufacturer, hostname,
    open ports with what each one does, advertised services, when it was first
    seen on this network, and any findings against it.

    Args:
        device_id (str): device_id, IP address, MAC address, or hostname.
        response_format (ResponseFormat): 'markdown' or 'json'. Default 'markdown'.

    Returns:
        str: In markdown mode, a full profile of the device.

        In json mode:
        {
            "device": { ... },          # same device schema as scan_network
            "findings": [ ... ]         # findings referencing this device
        }

    Examples:
        - Use when: "What is 192.168.1.40?" -> device_id='192.168.1.40'
        - Use when: "Tell me about that unknown device" -> pass its device_id
        - Don't use when: the user wants an overview - use edgedefense_list_devices

    Error Handling:
        If the identifier does not match, returns a message listing the
        addresses that are available, so the correct one can be chosen without
        another round trip.
    """
    result = _current_result()
    if result is None:
        return _NO_SCAN_MESSAGE

    device = _resolve_device(result, device_id)
    if device is None:
        available = ", ".join(d.ip for d in result.devices[:15])
        more = "" if len(result.devices) <= 15 else f" (and {len(result.devices) - 15} more)"
        return (
            f"No device matching '{device_id}' was found in the most recent scan.\n\n"
            f"Devices currently known: {available}{more}.\n\n"
            "You can pass an IP address, a MAC address, a hostname, or the device_id "
            "shown in an earlier response. If the device is new, run "
            "edgedefense_scan_network again to pick it up."
        )

    device_findings = [f for f in result.findings if f.device_id == device.device_id]

    if response_format == ResponseFormat.JSON:
        return to_json(
            {
                "device": device.to_dict(),
                "findings": [f.to_dict() for f in device_findings],
            }
        )

    return format_device_detail(device, device_findings)


@mcp.tool(
    name="edgedefense_get_trust_score",
    annotations={
        "title": "Get the network trust score",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": False,
    },
)
async def edgedefense_get_trust_score(
    response_format: FormatParam = ResponseFormat.MARKDOWN,
) -> str:
    """Compute the 0-100 network trust score with the reasons behind it.

    The score starts at 100 and subtracts points for exposed risky services,
    unidentified devices, and unusually broad attack surface. Each category is
    capped so no single issue dominates. Every deduction traces to a finding
    the user can read.

    The scoring is deliberately calibrated so that an ordinary, well-configured
    home network scores in the 90s. A low score means something real.

    Args:
        response_format (ResponseFormat): 'markdown' or 'json'. Default 'markdown'.

    Returns:
        str: In markdown mode, a short screenshot-friendly card: the headline
        number and grade, two to three plain-language reasons, and the per-
        category point breakdown.

        In json mode:
        {
            "score": int,               # 0-100
            "grade": str,               # "Strong"|"Good"|"Fair"|"Needs attention"|"At risk"
            "reasons": [str],
            "deductions": {str: int},   # category label -> points subtracted
            "device_count": int
        }

    Examples:
        - Use when: "What's my network trust score?" -> defaults
        - Use when: "How secure is my network out of 100?" -> defaults
        - Don't use when: the user wants the detail behind one issue - use
          edgedefense_explain_finding

    Error Handling:
        Returns a message directing the user to scan first if no scan has run.
        If a scan found no devices at all, reports that explicitly rather than
        returning a perfect score for an empty result.
    """
    result = _current_result()
    if result is None:
        return _NO_SCAN_MESSAGE

    score = compute_trust_score(result.devices, result.findings)

    if response_format == ResponseFormat.JSON:
        return to_json(score.to_dict())

    return format_trust_score(score, result)


@mcp.tool(
    name="edgedefense_explain_finding",
    annotations={
        "title": "Explain a finding in plain English",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def edgedefense_explain_finding(
    finding_id: Annotated[
        str,
        Field(
            description=(
                "The finding_id from a previous response, e.g. "
                "'telnet_exposed:a4:cf:12:34:56:78'. Every scan response includes these"
            ),
            min_length=1,
            max_length=300,
        ),
    ],
    response_format: FormatParam = ResponseFormat.MARKDOWN,
) -> str:
    """Explain what a flagged issue means, why it matters, and what to do.

    Every explanation also states what the check genuinely cannot determine --
    for example, that detecting an open Telnet port does not prove the password
    is still the factory default.

    Args:
        finding_id (str): the id from a previous response.
        response_format (ResponseFormat): 'markdown' or 'json'. Default 'markdown'.

    Returns:
        str: In markdown mode: severity, the affected device, what the finding
        means, what to do about it, and the limits of the check.

        In json mode:
        {
            "finding": { ... },         # same finding schema as scan_network
            "device": { ... } | null    # the affected device, if any
        }

    Examples:
        - Use when: "Why is that a problem?" after a scan flagged something
        - Use when: "Explain telnet_exposed:a4:cf:12:34:56:78"
        - Don't use when: the user wants the device overview - use
          edgedefense_get_device_detail

    Error Handling:
        If the id does not match, returns the list of currently available
        finding ids so the right one can be selected immediately.
    """
    result = _current_result()
    if result is None:
        return _NO_SCAN_MESSAGE

    findings = result.findings
    finding = find_by_id(findings, finding_id)

    if finding is None:
        if not findings:
            return (
                f"No finding with id '{finding_id}' exists, and the most recent scan "
                "produced no findings at all - nothing was flagged on this network."
            )
        available = "\n".join(f"- `{f.finding_id}` - {f.title}" for f in findings[:15])
        more = "" if len(findings) <= 15 else f"\n- ...and {len(findings) - 15} more."
        return (
            f"No finding with id '{finding_id}' was found.\n\n"
            f"Available findings:\n{available}{more}"
        )

    device = _resolve_device(result, finding.device_id) if finding.device_id else None

    if response_format == ResponseFormat.JSON:
        return to_json(
            {
                "finding": finding.to_dict(),
                "device": device.to_dict() if device else None,
            }
        )

    return format_finding_explanation(finding, device)


@mcp.tool(
    name="edgedefense_local_security",
    annotations={
        "title": "Check local machine security",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def edgedefense_local_security(
    response_format: FormatParam = ResponseFormat.MARKDOWN,
) -> str:
    """Run security and configuration checks on the computer running the scan.

    Checks Wi-Fi encryption (warns if connected to an open network), DNS configuration,
    and lists local ports that are exposed to the network (listening on 0.0.0.0).

    Args:
        response_format (ResponseFormat): 'markdown' or 'json'. Default 'markdown'.

    Returns:
        str: In markdown mode, a formatted report of the local security posture.

        In json mode:
        {
            "wifi_secure": bool | null,
            "wifi_ssid": str | null,
            "wifi_auth_type": str | null,
            "dns_servers": [ ... ],
            "listening_ports": [ {"protocol": str, "port": int, "address": str} ],
            "warnings": [ ... ]
        }
    """
    from edgedefense_core.local_checks import run_local_checks
    report = await run_local_checks()

    if response_format == ResponseFormat.JSON:
        return to_json(report.to_dict())

    return format_local_security(report)


@mcp.tool(
    name="edgedefense_whats_changed",
    annotations={
        "title": "What changed on the network",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def edgedefense_whats_changed(
    response_format: FormatParam = ResponseFormat.MARKDOWN,
) -> str:
    """Compare the most recent scan with the one before it to find changes.

    Reports new devices that appeared, devices that vanished, and any ports that
    opened or closed on devices that were present in both scans.

    Args:
        response_format (ResponseFormat): 'markdown' or 'json'. Default 'markdown'.

    Returns:
        str: In markdown mode, a formatted summary of all changes.

        In json mode:
        {
            "current_finished_at": str,
            "previous_finished_at": str,
            "new_devices": [ ... ],
            "vanished_devices": [ ... ],
            "port_changes": [ ... ],
            "has_changes": bool
        }

    Examples:
        - Use when: "What changed since yesterday?"
        - Use when: "Anything new on my network?"
    """
    storage = get_storage()
    current_payload = storage.load_latest_scan()
    previous_payload = storage.load_previous_scan()

    if not current_payload:
        return _NO_SCAN_MESSAGE

    if not previous_payload:
        return (
            "Only one scan has been run so far. Run another scan later to see what "
            "has changed."
        )

    current = scan_result_from_dict(current_payload)
    previous = scan_result_from_dict(previous_payload)
    
    report = compare_scans(current, previous)

    if response_format == ResponseFormat.JSON:
        return to_json(report.to_dict())

    return format_changes(report)


@mcp.tool(
    name="edgedefense_name_device",
    annotations={
        "title": "Name a device",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def edgedefense_name_device(
    device_id: Annotated[
        str,
        Field(
            description=(
                "Which device to name. Accepts the device_id from a previous response, "
                "or a plain IP or MAC address."
            ),
        ),
    ],
    label: Annotated[
        str,
        Field(
            description="The friendly name to assign to the device (e.g. 'SimpliSafe base station').",
        ),
    ],
) -> str:
    """Assign a persistent friendly name to a device.

    This name will be saved locally and applied to the device in all future scans.
    It helps turn unidentified devices into a network you understand. This is a
    write operation.

    Args:
        device_id (str): The device identifier (device_id, IP, MAC).
        label (str): The name to assign.

    Returns:
        str: Confirmation message.
    """
    global _last_result

    result = _current_result()
    if result is None:
        return _NO_SCAN_MESSAGE

    device = _resolve_device(result, device_id)
    if device is None:
        return f"No device matching '{device_id}' was found in the most recent scan."

    storage = get_storage()
    storage.set_user_label(device.device_id, label)
    
    # Update in memory
    _apply_user_label(device, label)

    return f"Device {device.ip} ({device.mac or 'no MAC'}) has been named '{label}'."


# --------------------------------------------------------------------------
# Performance tools
# --------------------------------------------------------------------------


@mcp.tool(
    name="edgedefense_network_stats",
    annotations={
        "title": "Network adapter and Wi-Fi status",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": False,
    },
)
async def edgedefense_network_stats(
    sample_seconds: Annotated[
        float,
        Field(
            description=(
                "How long to watch traffic to compute the live throughput rate. "
                "2 seconds is a good default; longer is steadier but slower"
            ),
            ge=0.5,
            le=30.0,
        ),
    ] = 2.0,
    include_wifi: Annotated[
        bool,
        Field(
            description=(
                "Also report Wi-Fi signal strength, band, channel and how many nearby "
                "networks share that channel. Adds a few seconds"
            )
        ),
    ] = True,
    response_format: FormatParam = ResponseFormat.MARKDOWN,
) -> str:
    """Report how each network adapter is performing right now.

    Covers current upload and download throughput per adapter, cumulative
    traffic, link speed, MTU, and packet error and drop rates. With Wi-Fi
    included, it also reports signal strength in dBm, the band and channel in
    use, the negotiated radio rate, and how many neighbouring networks are
    competing for the same channel.

    This is the right first stop for "my internet is slow", because it
    distinguishes a weak or crowded Wi-Fi link from an actual problem with the
    internet connection. Those have completely different fixes, and a speed
    test alone cannot tell them apart.

    Everything here is read from counters the operating system already keeps.
    Nothing is transmitted.

    Args:
        sample_seconds (float): seconds to watch traffic for the live rate.
            Default 2.0.
        include_wifi (bool): include Wi-Fi link quality and channel congestion.
            Default True.
        response_format (ResponseFormat): 'markdown' or 'json'. Default 'markdown'.

    Returns:
        str: In markdown mode, a report of each active adapter's current and
        cumulative traffic and error rate, followed by the Wi-Fi link and any
        specific, measured advice about it.

        In json mode:
        {
            "interfaces": {
                "sample_seconds": float,
                "interfaces": [
                    {
                        "name": str,
                        "description": str | null,
                        "is_up": bool,
                        "mac": str | null,
                        "mtu": int | null,
                        "link_speed_mbps": float | null,
                        "bytes_sent": int | null,
                        "bytes_recv": int | null,
                        "packets_sent": int | null,
                        "packets_recv": int | null,
                        "errors_in": int | null,
                        "errors_out": int | null,
                        "drops_in": int | null,
                        "drops_out": int | null,
                        "error_rate": float | null,   # 0.0-1.0, null if unknown
                        "is_virtual": bool,
                        "send_rate_bps": float | null,
                        "recv_rate_bps": float | null
                    }
                ],
                "warnings": [str]
            },
            "wifi": {
                "link": {
                    "ssid": str | null,
                    "bssid": str | null,
                    "band": str | null,           # "2.4 GHz" | "5 GHz" | "6 GHz"
                    "channel": int | null,
                    "signal_percent": int | null,
                    "signal_dbm": float | null,
                    "signal_quality": str | null, # "excellent".."very weak"
                    "rx_rate_mbps": float | null,
                    "tx_rate_mbps": float | null,
                    "radio_type": str | null,
                    "authentication": str | null
                } | null,
                "nearby_count": int,
                "nearby": [ {"ssid": str, "channel": int, "band": str, "signal_percent": int} ],
                "channel_usage": [ {"channel": int, "networks": int} ],
                "same_channel_networks": int | null,
                "advice": [str],
                "warnings": [str]
            } | null
        }

    Examples:
        - Use when: "Why is my network slow?" -> defaults
        - Use when: "How strong is my Wi-Fi signal?" -> defaults
        - Use when: "What's using my bandwidth right now?" -> sample_seconds=5
        - Don't use when: the user wants a speed in Mbps against the internet -
          use edgedefense_speed_test

    Error Handling:
        Never raises for network conditions. A machine on Ethernet reports no
        Wi-Fi link, which is a normal result rather than an error. Platforms
        that do not expose a given counter report null for it rather than zero,
        so a missing counter is never mistaken for a healthy one.
    """
    from edgedefense_core.perf.interfaces import sample_interfaces
    from edgedefense_core.perf.wifi import collect_wifi

    interfaces = await sample_interfaces(sample_seconds)
    wifi = await collect_wifi(include_nearby=True) if include_wifi else None

    if response_format == ResponseFormat.JSON:
        return to_json(
            {
                "interfaces": interfaces.to_dict(),
                "wifi": wifi.to_dict() if wifi else None,
            }
        )

    return format_network_stats(interfaces, wifi)


@mcp.tool(
    name="edgedefense_latency_check",
    annotations={
        "title": "Measure latency and DNS response time",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": False,
    },
)
async def edgedefense_latency_check(
    count: Annotated[
        int,
        Field(
            description="How many pings to send to the router. More is steadier",
            ge=1,
            le=20,
        ),
    ] = 5,
    include_dns: Annotated[
        bool,
        Field(
            description=(
                "Also time a name lookup against each DNS server this machine is "
                "configured to use"
            )
        ),
    ] = True,
    response_format: FormatParam = ResponseFormat.MARKDOWN,
) -> str:
    """Measure the round trip to your router, and how fast names resolve.

    Reports minimum, average and maximum round-trip time to the default
    gateway, jitter between consecutive packets, and packet loss. With DNS
    included, it times a lookup against each configured resolver.

    These two numbers separate the two common causes of "everything feels
    slow". High latency to your own router is a local wireless problem. Fast
    router latency with slow DNS is a resolver problem, and shows up as a pause
    before every new site loads while everything already open stays fast.

    Packets go only to your own gateway and to the DNS servers this machine
    already uses. No third-party service is contacted.

    Args:
        count (int): pings to send to the gateway. Default 5.
        include_dns (bool): also time DNS lookups. Default True.
        response_format (ResponseFormat): 'markdown' or 'json'. Default 'markdown'.

    Returns:
        str: In markdown mode, the round-trip figures, per-resolver timings, and
        a short plain-language reading of what those numbers imply.

        In json mode:
        {
            "gateway": {
                "host": str,
                "sent": int,
                "received": int,
                "loss_percent": float | null,
                "min_ms": float | null,
                "avg_ms": float | null,
                "max_ms": float | null,
                "jitter_ms": float | null,
                "samples_ms": [float],
                "error": str | null
            } | null,
            "dns": [
                {
                    "server": str,
                    "query": str,
                    "avg_ms": float | null,
                    "min_ms": float | null,
                    "max_ms": float | null,
                    "failures": int,
                    "error": str | null
                }
            ],
            "verdict": [str],
            "warnings": [str]
        }

    Examples:
        - Use when: "Why do my video calls keep stuttering?" -> count=10
        - Use when: "Is my DNS slow?" -> defaults
        - Use when: "Is the problem my Wi-Fi or my ISP?" -> defaults, then read
          the gateway figures
        - Don't use when: the user wants throughput in Mbps - use
          edgedefense_speed_test

    Error Handling:
        Never raises. Many routers are configured not to answer pings; that is
        reported as an inconclusive result rather than as a fault, because it
        genuinely is not one.
    """
    from edgedefense_core.perf.latency import run_latency_check

    report = await run_latency_check(count=count, include_dns=include_dns)

    if response_format == ResponseFormat.JSON:
        return to_json(report.to_dict())

    return format_latency(report)


@mcp.tool(
    name="edgedefense_speed_test",
    annotations={
        "title": "Internet speed test (contacts an external service)",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": False,
        # The only tool in this server for which this is true. Clients use this
        # to decide whether an action reaches beyond the local machine.
        "openWorldHint": True,
    },
)
async def edgedefense_speed_test(
    duration: Annotated[
        float,
        Field(
            description=(
                "Seconds to spend on each of the download and upload phases. "
                "6 is enough for an accurate reading on most connections"
            ),
            ge=2.0,
            le=30.0,
        ),
    ] = 6.0,
    include_upload: Annotated[
        bool,
        Field(
            description="Measure upload as well as download. Roughly doubles the runtime"
        ),
    ] = True,
    streams: Annotated[
        int,
        Field(
            description=(
                "Parallel connections. A single connection cannot fill a fast link, so "
                "lowering this will under-report gigabit connections"
            ),
            ge=1,
            le=16,
        ),
    ] = 4,
    response_format: FormatParam = ResponseFormat.MARKDOWN,
) -> str:
    """Measure real download and upload speed, latency, and bufferbloat.

    **This is the only tool in EdgeDefense that contacts the internet.** Every
    other tool reads local state or talks only to the user's own network. This
    one has to transfer real data to and from Cloudflare's public speed test
    service, because throughput cannot be measured any other way. It needs no
    account or API key, and no identifying information is attached beyond what
    any HTTPS request unavoidably reveals. The user's public IP address is
    deliberately excluded from the result.

    It transfers a meaningful amount of data - typically tens to hundreds of
    megabytes - so it is worth avoiding on a metered or capped connection.

    Alongside throughput it measures bufferbloat: how much latency rises while
    the connection is saturated. That number, not the download figure, is
    usually what explains a call breaking up when someone else starts a
    download, and it is fixed in the router rather than by buying more speed.

    Args:
        duration (float): seconds per phase. Default 6.0.
        include_upload (bool): measure upload too. Default True.
        streams (int): parallel connections. Default 4.
        response_format (ResponseFormat): 'markdown' or 'json'. Default 'markdown'.

    Returns:
        str: In markdown mode, the headline speeds, latency under load with a
        bufferbloat grade, what the measured connection can realistically
        support, and how the measurement was taken.

        In json mode:
        {
            "download_mbps": float | null,
            "upload_mbps": float | null,
            "idle_latency_ms": float | null,
            "jitter_ms": float | null,
            "loaded_latency_ms": float | null,
            "bufferbloat_ms": float | null,
            "bufferbloat_grade": str | null,   # "A+" .. "F"
            "bytes_downloaded": int,
            "bytes_uploaded": int,
            "download_streams": int,
            "upload_streams": int,
            "server_location": str | null,
            "server_colo": str | null,
            "endpoint": str,
            "duration_seconds": float | null,
            "capability_notes": [str],
            "warnings": [str]
        }

    Examples:
        - Use when: "How fast is my internet?" -> defaults
        - Use when: "Am I getting the speed I pay for?" -> defaults
        - Use when: "Why do calls break up when someone downloads?" ->
          defaults, then read bufferbloat_grade
        - Don't use when: the user asked why the network feels slow without
          asking for a number - edgedefense_network_stats and
          edgedefense_latency_check diagnose that locally, in less time, and
          without sending anything

    Error Handling:
        Never raises for network conditions. If the endpoint is unreachable the
        result comes back with null speeds and an explanation in warnings,
        rather than an exception. A phase that fails does not prevent the
        others from being reported.
    """
    from edgedefense_core.perf.speedtest import run_speed_test

    result = await run_speed_test(
        duration=duration,
        streams=streams,
        include_upload=include_upload,
    )

    if response_format == ResponseFormat.JSON:
        return to_json(result.to_dict())

    return format_speed_test(result)


# --------------------------------------------------------------------------
# Resources
# --------------------------------------------------------------------------


@mcp.resource("edgedefense://privacy")
def privacy_statement() -> str:
    """The tool's privacy guarantees, and where its data lives."""
    from edgedefense_core.perf.speedtest import DEFAULT_ENDPOINT as speed_endpoint

    storage_info: Dict[str, Any] = get_storage().describe()
    return (
        "# EdgeDefense privacy\n\n"
        "- No analytics, no telemetry, no crash reporting, no account.\n"
        "- Manufacturer lookups use a vendor database bundled on disk "
        f"({oui_database_size()} entries), never a remote API.\n"
        "- Scan results are stored locally at:\n"
        f"  `{storage_info['database_path']}`\n"
        f"- Devices remembered: {storage_info['devices_known']}; "
        f"scans stored: {storage_info['scans_stored']}.\n"
        "- Deleting that file erases all history. Nothing is retained elsewhere.\n\n"
        "## What leaves this machine\n\n"
        "One tool, and only when you invoke it:\n\n"
        f"- **edgedefense_speed_test** transfers data to and from `{speed_endpoint}` "
        "to measure throughput. There is no way to measure download speed without "
        "doing this. No account, no API key, and nothing identifying is attached "
        "beyond what any HTTPS request unavoidably reveals. The service sees the "
        "requesting IP address, as every server does; that address is deliberately "
        "left out of the result the tool returns.\n\n"
        "Everything else is local:\n\n"
        "- Discovery, classification, scoring and the local security checks read "
        "state this machine already holds, or listen for announcements devices "
        "broadcast on the LAN.\n"
        "- **edgedefense_latency_check** sends packets, but only to your own router "
        "and to the DNS servers this machine is already configured to use.\n"
        "- **edgedefense_network_stats** transmits nothing at all; it reads operating "
        "system counters and the wireless radio's view of the air around it.\n\n"
        f"Engine version {core_version}, server version {__version__}.\n"
    )


def main() -> None:
    """Run the server over stdio. This is a local tool, not a hosted service."""
    mcp.run()


if __name__ == "__main__":
    main()
