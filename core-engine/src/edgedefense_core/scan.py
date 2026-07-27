"""Scan orchestration: the single entry point both the MCP server and the
future paid app call into.

Consumers should not reach into the discovery modules directly. Everything they
need -- discovery, identification, scoring, persistence -- happens here, so that
improving detection improves every product at once.
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional, Tuple

from .classify import classify_device
from .discovery import arp as arp_discovery
from .discovery import mdns as mdns_discovery
from .discovery import ports as port_discovery
from .findings import build_findings
from .models import Device, Finding, ScanResult, is_randomised_mac
from .netinfo import LocalNetwork, describe_local_network
from .storage import Storage, utc_now
from .vendor import lookup_vendor

#: Tunables per scan depth. "quick" is the default because a first-time user
#: should get an answer in the time they are willing to wait for one.
_DEPTH_SETTINGS: Dict[str, Dict[str, Any]] = {
    "quick": {
        "mdns_seconds": 2.5,
        "arp_settle": 1.2,
        "ports": port_discovery.QUICK_PORTS,
        "port_timeout": 0.6,
        "host_concurrency": 32,
    },
    "full": {
        "mdns_seconds": 6.0,
        "arp_settle": 2.5,
        "ports": port_discovery.FULL_PORTS,
        "port_timeout": 1.0,
        "host_concurrency": 24,
    },
}


def _device_id_for(ip: str, mac: Optional[str]) -> str:
    """Stable, human-readable identifier for a device.

    The MAC is preferred because it survives DHCP handing out a different IP.
    Readable ids matter here: the user will be typing them back to us.
    """
    return mac if mac else f"ip-{ip}"


async def _resolve_hostnames(ips: List[str]) -> Dict[str, str]:
    """Reverse-resolve many addresses in parallel, tolerating failures."""

    async def one(ip: str) -> Tuple[str, Optional[str]]:
        name = await asyncio.to_thread(arp_discovery.resolve_hostname, ip)
        return ip, name

    results = await asyncio.gather(*(one(ip) for ip in ips))
    return {ip: name for ip, name in results if name}


async def run_scan(
    scan_depth: str = "quick",
    storage: Optional[Storage] = None,
    network: Optional[LocalNetwork] = None,
) -> ScanResult:
    """Run a Tier 0 scan: discovery, identification, scoring inputs.

    Requires no elevated privileges. Every step degrades gracefully -- a failure
    in one discovery method reduces detail rather than aborting the scan.

    Args:
        scan_depth: "quick" (default, ~10s) or "full" (~30s, more ports).
        storage: Optional store for first-seen tracking and result caching.
        network: Optional pre-computed network facts, mainly for testing.

    Returns:
        A populated :class:`~edgedefense_core.models.ScanResult`.
    """
    depth = scan_depth if scan_depth in _DEPTH_SETTINGS else "quick"
    settings = _DEPTH_SETTINGS[depth]
    started_at = utc_now()
    warnings: List[str] = []

    net = network or await asyncio.to_thread(describe_local_network)
    hosts = net.hosts()

    if not net.local_ip:
        warnings.append(
            "Could not determine this machine's network address. The scan may be "
            "incomplete - check that a network interface is up."
        )
    if not hosts and net.local_ip:
        warnings.append(
            "Could not determine the size of the local subnet, so the address sweep was "
            "skipped. Only devices already in the system's ARP table will appear."
        )

    # ARP sweep and mDNS listening are independent, so overlap them: mDNS
    # responses often arrive while the sweep is still running.
    arp_task = asyncio.create_task(
        arp_discovery.discover_via_arp(
            hosts, warm=bool(hosts), settle_seconds=settings["arp_settle"]
        )
    )
    mdns_task = asyncio.create_task(
        mdns_discovery.discover_via_mdns(duration=settings["mdns_seconds"])
    )

    arp_map: Dict[str, str] = {}
    mdns_hosts: Dict[str, mdns_discovery.MdnsHost] = {}

    try:
        arp_map = await arp_task
    except Exception as exc:  # discovery must never take the whole scan down
        warnings.append(f"Address-table discovery failed: {type(exc).__name__}.")

    try:
        mdns_hosts, mdns_warnings = await mdns_task
        warnings.extend(mdns_warnings)
    except Exception as exc:
        warnings.append(f"mDNS discovery failed: {type(exc).__name__}.")

    # Union of everything any method saw.
    all_ips = sorted(
        set(arp_map) | set(mdns_hosts) | ({net.local_ip} if net.local_ip else set()),
        key=lambda ip: tuple(int(part) for part in ip.split(".")),
    )

    if not all_ips:
        finished_at = utc_now()
        warnings.append(
            "No devices were found. If you are connected through a VPN, the local network "
            "may be unreachable while it is active."
        )
        return ScanResult(
            started_at=started_at,
            finished_at=finished_at,
            scan_depth=depth,
            subnet=net.cidr,
            devices=[],
            findings=[],
            warnings=warnings,
        )

    # Port scan and reverse-DNS in parallel across all discovered hosts.
    port_task = asyncio.create_task(
        port_discovery.scan_many(
            all_ips,
            settings["ports"],
            timeout=settings["port_timeout"],
            host_concurrency=settings["host_concurrency"],
        )
    )
    hostname_task = asyncio.create_task(_resolve_hostnames(all_ips))

    try:
        open_ports_map = await port_task
    except Exception as exc:
        open_ports_map = {}
        warnings.append(f"Port fingerprinting failed: {type(exc).__name__}.")

    try:
        hostname_map = await hostname_task
    except Exception:
        hostname_map = {}

    # Evidence from previous scans, so a device that happens to stay quiet
    # during this mDNS window keeps the identity it already earned.
    memory: Dict[str, Dict[str, Any]] = {}
    if storage is not None:
        try:
            memory = storage.load_device_memory()
        except Exception:
            memory = {}

    devices = _assemble_devices(
        all_ips=all_ips,
        arp_map=arp_map,
        mdns_hosts=mdns_hosts,
        open_ports_map=open_ports_map,
        hostname_map=hostname_map,
        net=net,
        memory=memory,
    )

    if storage is not None:
        try:
            first_seen_map = storage.record_devices(devices)
            for device in devices:
                device.first_seen = first_seen_map.get(device.device_id)
        except Exception as exc:
            warnings.append(f"Could not write to local history: {type(exc).__name__}.")

    findings = build_findings(devices)

    result = ScanResult(
        started_at=started_at,
        finished_at=utc_now(),
        scan_depth=depth,
        subnet=net.cidr,
        devices=devices,
        findings=findings,
        warnings=warnings,
    )

    if storage is not None:
        try:
            storage.save_scan(result.to_dict())
        except Exception:
            # History is a convenience; failing to write it must not fail the scan.
            pass

    return result


def _assemble_devices(
    *,
    all_ips: List[str],
    arp_map: Dict[str, str],
    mdns_hosts: Dict[str, "mdns_discovery.MdnsHost"],
    open_ports_map: Dict[str, List[int]],
    hostname_map: Dict[str, str],
    net: LocalNetwork,
    memory: Optional[Dict[str, Dict[str, Any]]] = None,
) -> List[Device]:
    """Merge every evidence source into one Device per address."""
    devices: List[Device] = []
    memory = memory or {}
    now = utc_now()

    for ip in all_ips:
        mac = arp_map.get(ip)
        mdns_entry = mdns_hosts.get(ip)
        open_ports = open_ports_map.get(ip, [])
        device_id = _device_id_for(ip, mac)
        remembered = memory.get(device_id, {})

        hostname = hostname_map.get(ip)
        if mdns_entry and mdns_entry.hostname:
            hostname = mdns_entry.hostname  # mDNS names are friendlier than PTR
        if not hostname:
            hostname = remembered.get("hostname")

        # Union with what this device advertised on previous scans.
        seen_services = set(mdns_entry.services) if mdns_entry else set()
        seen_services.update(remembered.get("mdns_services") or [])
        mdns_services = sorted(seen_services)
        txt_hints = dict(mdns_entry.txt_hints) if mdns_entry else {}

        is_self = bool(net.local_ip and ip == net.local_ip)
        is_gateway = bool(net.gateway and ip == net.gateway)

        vendor = lookup_vendor(mac)
        device_type, confidence = classify_device(
            hostname=hostname,
            vendor=vendor,
            open_ports=open_ports,
            mdns_services=mdns_services,
            txt_hints=txt_hints,
            is_gateway=is_gateway,
            is_self=is_self,
        )

        sources: List[str] = []
        if ip in arp_map:
            sources.append("arp")
        if mdns_entry:
            sources.append("mdns")
        if is_self:
            sources.append("self")

        devices.append(
            Device(
                device_id=device_id,
                ip=ip,
                mac=mac,
                hostname=hostname,
                vendor=vendor,
                device_type=device_type,
                type_confidence=confidence,
                open_ports=open_ports,
                services={p: port_discovery.describe_port(p) for p in open_ports},
                mdns_services=mdns_services,
                randomised_mac=is_randomised_mac(mac),
                is_gateway=is_gateway,
                is_self=is_self,
                sources=sources,
                last_seen=now,
            )
        )

    return devices


def scan_result_from_dict(payload: Dict[str, Any]) -> ScanResult:
    """Rehydrate a stored scan so follow-up questions work without re-scanning."""
    devices = [
        Device(
            device_id=d["device_id"],
            ip=d["ip"],
            mac=d.get("mac"),
            hostname=d.get("hostname"),
            vendor=d.get("vendor"),
            device_type=d.get("device_type", "unknown"),
            type_confidence=d.get("type_confidence", "none"),
            open_ports=list(d.get("open_ports") or []),
            services={int(k): v for k, v in (d.get("services") or {}).items()},
            mdns_services=list(d.get("mdns_services") or []),
            randomised_mac=bool(d.get("randomised_mac")),
            is_gateway=bool(d.get("is_gateway")),
            is_self=bool(d.get("is_self")),
            sources=list(d.get("sources") or []),
            first_seen=d.get("first_seen"),
            last_seen=d.get("last_seen"),
        )
        for d in payload.get("devices", [])
    ]

    findings = [
        Finding(
            finding_id=f["finding_id"],
            code=f["code"],
            severity=f.get("severity", "info"),
            title=f.get("title", ""),
            summary=f.get("summary", ""),
            detail=f.get("detail", ""),
            what_to_do=f.get("what_to_do", ""),
            tier=int(f.get("tier", 0)),
            device_id=f.get("device_id"),
            limitations=f.get("limitations", ""),
            evidence=dict(f.get("evidence") or {}),
        )
        for f in payload.get("findings", [])
    ]

    return ScanResult(
        started_at=payload.get("started_at", ""),
        finished_at=payload.get("finished_at", ""),
        scan_depth=payload.get("scan_depth", "quick"),
        subnet=payload.get("subnet"),
        devices=devices,
        findings=findings,
        warnings=list(payload.get("warnings") or []),
        tier1_included=bool(payload.get("tier1_included")),
    )
