"""TCP port fingerprinting via ordinary connect() calls.

A full TCP handshake to a port requires no privileges anywhere -- it is exactly
what a browser does. We never send a payload, and we close immediately, so this
is a connectivity check rather than a vulnerability probe.
"""

from __future__ import annotations

import asyncio
from typing import Dict, List, Optional, Tuple

#: Ports checked on a "quick" scan: the ones that actually distinguish device
#: types on a home network, plus the few that carry real risk.
QUICK_PORTS: Tuple[int, ...] = (
    21, 22, 23, 53, 80, 139, 443, 445, 554, 3389, 5000, 8080,
)

#: Additional ports checked on a "full" scan.
FULL_PORTS: Tuple[int, ...] = QUICK_PORTS + (
    25, 111, 135, 515, 631, 873, 993, 1400, 1883, 1900, 2049, 2323,
    3000, 3306, 5001, 5060, 5432, 5555, 5900, 6379, 7000, 7547,
    8000, 8081, 8123, 8443, 8888, 9000, 9100, 9200, 27017, 32400,
)

#: Human-readable service names. Keeping this local avoids depending on the
#: system services file, which varies wildly across platforms.
SERVICE_NAMES: Dict[int, str] = {
    21: "FTP (file transfer)",
    22: "SSH (remote shell)",
    23: "Telnet (unencrypted remote login)",
    25: "SMTP (mail)",
    53: "DNS",
    80: "HTTP (web interface)",
    111: "RPC portmapper",
    135: "Windows RPC",
    139: "NetBIOS file sharing",
    443: "HTTPS (secure web interface)",
    445: "SMB file sharing",
    515: "Line printer daemon",
    554: "RTSP (video stream)",
    631: "IPP (printing)",
    873: "rsync",
    993: "IMAPS (mail)",
    1400: "Sonos control",
    1883: "MQTT (IoT messaging)",
    1900: "UPnP discovery",
    2049: "NFS file sharing",
    2323: "Telnet (alternate port)",
    3000: "HTTP (development server)",
    3306: "MySQL database",
    3389: "RDP (Windows remote desktop)",
    5000: "HTTP (UPnP/app server)",
    5001: "HTTP (app server)",
    5060: "SIP (VoIP)",
    5432: "PostgreSQL database",
    5555: "ADB (Android debug bridge)",
    5900: "VNC (remote desktop)",
    6379: "Redis database",
    7000: "HTTP (AirPlay/app server)",
    7547: "TR-069 (ISP router management)",
    8000: "HTTP (alternate)",
    8080: "HTTP (alternate web interface)",
    8081: "HTTP (alternate)",
    8123: "Home Assistant",
    8443: "HTTPS (alternate)",
    8888: "HTTP (alternate)",
    9000: "HTTP (app server)",
    9100: "Raw printing (JetDirect)",
    9200: "Elasticsearch",
    27017: "MongoDB database",
    32400: "Plex media server",
}


def describe_port(port: int) -> str:
    """Return a plain-language name for a port number."""
    return SERVICE_NAMES.get(port, f"unknown service (port {port})")


async def _probe(ip: str, port: int, timeout: float) -> Optional[int]:
    """Return ``port`` if a TCP connection succeeds, else None."""
    writer = None
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        return port
    except (asyncio.TimeoutError, OSError):
        return None
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except (OSError, asyncio.TimeoutError):
                pass


async def scan_ports(
    ip: str,
    ports: Tuple[int, ...],
    timeout: float = 0.8,
    concurrency: int = 64,
) -> List[int]:
    """Return the sorted list of open TCP ports on one host."""
    semaphore = asyncio.Semaphore(concurrency)

    async def guarded(port: int) -> Optional[int]:
        async with semaphore:
            return await _probe(ip, port, timeout)

    results = await asyncio.gather(*(guarded(p) for p in ports))
    return sorted(p for p in results if p is not None)


async def scan_many(
    ips: List[str],
    ports: Tuple[int, ...],
    timeout: float = 0.8,
    host_concurrency: int = 24,
) -> Dict[str, List[int]]:
    """Port-scan several hosts concurrently, bounded so we stay a good neighbour."""
    semaphore = asyncio.Semaphore(host_concurrency)

    async def guarded(ip: str) -> Tuple[str, List[int]]:
        async with semaphore:
            return ip, await scan_ports(ip, ports, timeout=timeout)

    pairs = await asyncio.gather(*(guarded(ip) for ip in ips))
    return dict(pairs)
