#!/usr/bin/env python3
"""EdgeDefense MCP server.

Answers questions about the local network in plain language. Everything runs on
the machine that hosts the server: there is no account, no cloud component, and
no outbound request of any kind, including analytics.

All Tier 0 tools work without elevated privileges. The single Tier 1 tool asks
for explicit consent, in writing, before it requests anything more.

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
from edgedefense_core.findings import find_by_id, sort_findings
from edgedefense_core.models import Device, Finding, ScanResult
from edgedefense_core.scan import run_scan, scan_result_from_dict
from edgedefense_core.scoring import compute_trust_score
from edgedefense_core.storage import Storage
from edgedefense_core.tier1 import consent as tier1_consent
from edgedefense_core.vendor import oui_database_size

from .formatting import (
    format_capture_result,
    format_device_detail,
    format_device_list,
    format_finding_explanation,
    format_scan_summary,
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
        "edgedefense_explain_finding for a plain-English explanation.\n\n"
        "This server runs entirely locally. It makes no outbound network requests, "
        "collects no telemetry, and requires no account. Tier 0 needs no elevated "
        "privileges; Tier 1 traffic analysis is opt-in and asks for consent first."
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
#: Tier 1 findings from the most recent capture, merged into score and lookups.
_tier1_findings: List[Finding] = []
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


def _all_findings(result: ScanResult) -> List[Finding]:
    """Tier 0 findings plus any Tier 1 findings from the latest capture."""
    return sort_findings(list(result.findings) + list(_tier1_findings))


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
            "tier1_included": bool,
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
                    "tier": int,
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
    global _last_result, _tier1_findings

    async with _scan_lock:
        result = await run_scan(scan_depth=scan_depth.value, storage=get_storage())
        _last_result = result
        # Traffic findings describe a window that has passed; a fresh scan
        # invalidates them rather than silently carrying them forward.
        _tier1_findings = []

    score = compute_trust_score(result.devices, result.findings, tier1_included=False)

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

    findings = _all_findings(result)
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

    device_findings = [f for f in _all_findings(result) if f.device_id == device.device_id]

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
    unidentified devices, unusually broad attack surface, and (if traffic
    analysis has run) traffic anomalies. Each category is capped so no single
    issue dominates. Every deduction traces to a finding the user can read.

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
            "tier1_included": bool,
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

    findings = _all_findings(result)
    score = compute_trust_score(
        result.devices, findings, tier1_included=bool(_tier1_findings)
    )

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

    findings = _all_findings(result)
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
    name="edgedefense_tier1_status",
    annotations={
        "title": "Check traffic-analysis availability",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def edgedefense_tier1_status(
    response_format: FormatParam = ResponseFormat.MARKDOWN,
) -> str:
    """Report whether opt-in traffic analysis (Tier 1) can run on this machine.

    Checks three things independently: whether the user has consented, whether
    the optional capture dependency is installed, and whether the process has
    the privileges raw packet capture requires. Reports what is missing and how
    to fix it. Reading this status never requests any permission.

    Args:
        response_format (ResponseFormat): 'markdown' or 'json'. Default 'markdown'.

    Returns:
        str: In markdown mode, a readable status with next steps.

        In json mode:
        {
            "consent_granted": bool,
            "consent_granted_at": str | null,
            "has_privileges": bool,
            "has_capture_backend": bool,
            "backend_hint": str,        # actionable guidance
            "platform": str,
            "ready": bool,
            "blocking_reason": str | null  # "consent_required"|"backend_missing"|
                                           # "privileges_missing"|null
        }

    Examples:
        - Use when: "Can you analyse my traffic?" -> defaults
        - Use when: "Why isn't traffic analysis working?" -> defaults
        - Don't use when: the user wants to actually run it - use
          edgedefense_analyze_traffic

    Error Handling:
        Never fails. Missing capabilities are reported as status, not errors.
    """
    capability = tier1_consent.get_capability(get_storage())

    if response_format == ResponseFormat.JSON:
        return to_json(capability.to_dict())

    def check(ok: bool) -> str:
        return "yes" if ok else "no"

    lines = ["# Traffic analysis (Tier 1) status", ""]
    lines.append(f"- **User has opted in:** {check(capability.consent_granted)}")
    lines.append(f"- **Capture backend installed:** {check(capability.has_capture_backend)}")
    lines.append(f"- **Process has required privileges:** {check(capability.has_privileges)}")
    lines.append("")

    if capability.ready:
        lines.append("Traffic analysis is ready to run.")
    elif capability.blocking_reason() == "consent_required":
        lines.append(
            "**Not enabled.** Traffic analysis is off by default and requires explicit "
            "consent. Calling `edgedefense_analyze_traffic` will show exactly what "
            "elevated access is used for, so the user can decide."
        )
    else:
        lines.append(f"**Not available.** {capability.backend_hint}")

    lines.append("")
    lines.append(
        "_Everything in Tier 0 - device discovery, identification, port checks, the trust "
        "score - works without any of this._"
    )
    return "\n".join(lines)


@mcp.tool(
    name="edgedefense_analyze_traffic",
    annotations={
        "title": "Analyse network traffic (opt-in, elevated)",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": False,
    },
)
async def edgedefense_analyze_traffic(
    consent_confirmed: Annotated[
        bool,
        Field(
            description=(
                "Must be true to run a capture. Leave false (the default) on the first "
                "call: the tool then returns the full consent notice explaining what "
                "elevated access is used for, which MUST be shown to the user so they can "
                "decide. Only set true after the user has seen that notice and explicitly "
                "agreed. Never set it on their behalf"
            )
        ),
    ] = False,
    duration_seconds: Annotated[
        int,
        Field(
            description="How long to capture for, 10-300 seconds. Stops on its own",
            ge=10,
            le=300,
        ),
    ] = 60,
    interface: Annotated[
        Optional[str],
        Field(
            description="Optional network interface name. Auto-detected when omitted",
            max_length=100,
        ),
    ] = None,
    response_format: FormatParam = ResponseFormat.MARKDOWN,
) -> str:
    """Passively observe network traffic for a fixed window and flag anomalies.

    OPT-IN AND ELEVATED. This is the only tool that needs administrator/root
    privileges. Call it first with consent_confirmed=false (the default): it
    returns the full consent notice, which MUST be shown to the user verbatim.
    Only call again with consent_confirmed=true after the user has read that
    notice and explicitly agreed. Do not set that flag on the user's behalf.

    Detects two things: devices connecting to internet addresses that were never
    resolved through the network's DNS, and devices moving far more data than
    their peers. Both heuristics have well-understood false-positive modes,
    which each finding states.

    Only packet headers and counters are retained. No packet contents are
    stored, nothing is decrypted, and nothing is transmitted anywhere.

    Args:
        consent_confirmed (bool): must be true to capture; false returns the
            consent notice. Default false.
        duration_seconds (int): 10-300. Default 60.
        interface (Optional[str]): interface name, auto-detected if omitted.
        response_format (ResponseFormat): 'markdown' or 'json'. Default 'markdown'.

    Returns:
        str: With consent_confirmed=false, the consent notice plus current
        capability status.

        With consent granted, in markdown mode: capture statistics, any
        anomalies found with their finding ids, the busiest devices, and the
        updated trust score.

        In json mode:
        {
            "consent_required": bool,       # true only if consent is still needed
            "capture": {
                "duration_seconds": float,
                "packets_seen": int,
                "devices_with_traffic": int,
                "names_resolved": int,
                "busiest_devices": [ {"ip": str, "label": str, "total": str,
                                      "total_bytes": int} ]
            },
            "findings": [ ... ],            # same finding schema, with tier=1
            "trust_score": { ... }
        }

    Examples:
        - Use when: "Is anything on my network behaving oddly?" -> start with
          consent_confirmed=false, show the notice, then re-call if they agree
        - Use when: the user has already opted in and asks to re-check traffic
        - Don't use when: the user only wants to know what is connected - Tier 0
          answers that with no special permissions

    Error Handling:
        Returns a clear message rather than raising when: no scan has been run,
        the capture dependency is missing, or privileges are insufficient. Each
        case explains the specific next step.
    """
    global _tier1_findings

    storage = get_storage()
    capability = tier1_consent.get_capability(storage)

    # --- Consent gate --------------------------------------------------
    if not consent_confirmed:
        if response_format == ResponseFormat.JSON:
            return to_json(
                {
                    "consent_required": True,
                    "consent_text": tier1_consent.CONSENT_TEXT,
                    "capability": capability.to_dict(),
                }
            )
        return (
            "# Traffic analysis requires your explicit consent\n\n"
            f"{tier1_consent.CONSENT_TEXT}\n\n"
            "---\n\n"
            f"**Current status on this machine:** {capability.backend_hint}\n\n"
            "If you want to proceed, say so and this tool will be called again with your "
            "consent recorded. If you would rather not, everything else keeps working "
            "exactly as it does now."
        )

    # --- Capability checks ---------------------------------------------
    if not capability.has_capture_backend or not capability.has_privileges:
        return (
            "# Traffic analysis cannot start\n\n"
            f"{capability.backend_hint}\n\n"
            "Your consent has not been recorded, because there is nothing to consent to "
            "until this is resolved. Tier 0 features are unaffected."
        )

    result = _current_result()
    if result is None:
        return (
            "Run edgedefense_scan_network first. Traffic analysis attributes activity to "
            "specific devices, which needs the device list from a scan."
        )

    # Consent is recorded only now: the user agreed AND the capture can happen.
    if not capability.consent_granted:
        tier1_consent.grant_consent(storage)

    from edgedefense_core.tier1.capture import CaptureUnavailable, capture_traffic
    from edgedefense_core.tier1.heuristics import analyse_capture, capture_summary

    try:
        capture = await capture_traffic(
            duration_seconds=duration_seconds, interface=interface
        )
    except CaptureUnavailable as exc:
        return f"# Traffic analysis could not run\n\n{exc}"

    findings = analyse_capture(capture, result.devices)
    _tier1_findings = findings

    summary = capture_summary(capture, result.devices)
    score = compute_trust_score(result.devices, _all_findings(result), tier1_included=True)

    if response_format == ResponseFormat.JSON:
        return to_json(
            {
                "consent_required": False,
                "capture": summary,
                "findings": [f.to_dict() for f in findings],
                "trust_score": score.to_dict(),
            }
        )

    return format_capture_result(summary, findings, score)


# --------------------------------------------------------------------------
# Resources
# --------------------------------------------------------------------------


@mcp.resource("edgedefense://privacy")
def privacy_statement() -> str:
    """The tool's privacy guarantees, and where its data lives."""
    storage_info: Dict[str, Any] = get_storage().describe()
    return (
        "# EdgeDefense privacy\n\n"
        "- No outbound network requests are made by this tool, for any purpose.\n"
        "- No analytics, no telemetry, no crash reporting, no account.\n"
        "- Manufacturer lookups use a vendor database bundled on disk "
        f"({oui_database_size()} entries), never a remote API.\n"
        "- Scan results are stored locally at:\n"
        f"  `{storage_info['database_path']}`\n"
        f"- Devices remembered: {storage_info['devices_known']}; "
        f"scans stored: {storage_info['scans_stored']}.\n"
        "- Deleting that file erases all history. Nothing is retained elsewhere.\n\n"
        f"Engine version {core_version}, server version {__version__}.\n"
    )


def main() -> None:
    """Run the server over stdio. This is a local tool, not a hosted service."""
    mcp.run()


if __name__ == "__main__":
    main()
