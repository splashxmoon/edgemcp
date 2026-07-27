"""Passive traffic capture (Tier 1, opt-in, requires elevated privileges).

Only packet *headers* and counters are retained. Payloads are read solely to
parse DNS answers -- which is what makes DNS-bypass detection possible -- and
are never stored. Nothing here writes to disk or opens an outbound connection.

scapy is an optional dependency; every entry point degrades to a clear error
message when it is absent rather than raising an import error at module load.
"""

from __future__ import annotations

import asyncio
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from ..netinfo import is_private_ip

#: Hard bounds on capture length. A capture is a deliberate, bounded action --
#: this tool never sniffs continuously in the background.
MIN_DURATION = 10
MAX_DURATION = 300


class CaptureUnavailable(RuntimeError):
    """Raised when capture cannot start, with a message safe to show the user."""


@dataclass
class DeviceTraffic:
    """Per-device counters accumulated during one capture."""

    ip: str
    bytes_sent: int = 0
    bytes_received: int = 0
    packets: int = 0
    #: Public addresses this device opened connections to.
    contacted_ips: Set[str] = field(default_factory=set)
    #: Names this device asked DNS to resolve.
    dns_queries: Set[str] = field(default_factory=set)
    dns_query_count: int = 0

    @property
    def total_bytes(self) -> int:
        return self.bytes_sent + self.bytes_received


@dataclass
class CaptureResult:
    """Everything one capture window observed."""

    duration_seconds: float
    packets_seen: int
    started_at: str
    interface: Optional[str] = None
    #: Every IP that appeared in a DNS answer, mapped to the names that
    #: resolved to it. This is the reference set for bypass detection.
    resolved_ips: Dict[str, Set[str]] = field(default_factory=lambda: defaultdict(set))
    per_device: Dict[str, DeviceTraffic] = field(default_factory=dict)
    truncated: bool = False

    def device(self, ip: str) -> DeviceTraffic:
        entry = self.per_device.get(ip)
        if entry is None:
            entry = DeviceTraffic(ip=ip)
            self.per_device[ip] = entry
        return entry

    def to_dict(self) -> Dict[str, Any]:
        return {
            "duration_seconds": self.duration_seconds,
            "packets_seen": self.packets_seen,
            "started_at": self.started_at,
            "interface": self.interface,
            "resolved_ip_count": len(self.resolved_ips),
            "devices": {
                ip: {
                    "bytes_sent": t.bytes_sent,
                    "bytes_received": t.bytes_received,
                    "total_bytes": t.total_bytes,
                    "packets": t.packets,
                    "contacted_ip_count": len(t.contacted_ips),
                    "dns_query_count": t.dns_query_count,
                }
                for ip, t in self.per_device.items()
            },
        }


def _import_scapy():
    """Import scapy lazily, converting any failure into CaptureUnavailable."""
    try:
        from scapy.all import DNS, DNSRR, IP, TCP, UDP, sniff  # type: ignore

        return {"DNS": DNS, "DNSRR": DNSRR, "IP": IP, "TCP": TCP, "UDP": UDP, "sniff": sniff}
    except Exception as exc:  # ImportError, or a libpcap/Npcap loading failure
        raise CaptureUnavailable(
            "The traffic-capture backend could not be loaded. Install it with "
            "`pip install 'edgedefense-mcp[tier1]'`. On Windows, Npcap must also be "
            f"installed. (Underlying error: {type(exc).__name__}: {exc})"
        ) from exc


def _capture_blocking(
    duration: int,
    interface: Optional[str],
    started_at: str,
) -> CaptureResult:
    """Run the capture. Blocking; callers should use :func:`capture_traffic`."""
    scapy = _import_scapy()
    DNS, DNSRR, IP, TCP, UDP = (
        scapy["DNS"],
        scapy["DNSRR"],
        scapy["IP"],
        scapy["TCP"],
        scapy["UDP"],
    )

    result = CaptureResult(
        duration_seconds=float(duration),
        packets_seen=0,
        started_at=started_at,
        interface=interface,
    )

    def handle(packet: Any) -> None:
        if IP not in packet:
            return

        result.packets_seen += 1
        ip_layer = packet[IP]
        src, dst = ip_layer.src, ip_layer.dst
        size = int(getattr(ip_layer, "len", 0) or len(packet))

        src_local = is_private_ip(src)
        dst_local = is_private_ip(dst)

        # Attribute traffic to whichever end is a device on this network.
        if src_local:
            entry = result.device(src)
            entry.bytes_sent += size
            entry.packets += 1
            if not dst_local:
                entry.contacted_ips.add(dst)
        if dst_local:
            entry = result.device(dst)
            entry.bytes_received += size
            entry.packets += 1

        # DNS: record both the question (who asked) and the answers (which
        # addresses are legitimately reachable by name).
        if UDP in packet and DNS in packet:
            dns_layer = packet[DNS]

            if getattr(dns_layer, "qr", 0) == 0 and src_local:
                question = getattr(dns_layer, "qd", None)
                if question is not None and getattr(question, "qname", None):
                    name = _decode_name(question.qname)
                    asker = result.device(src)
                    asker.dns_query_count += 1
                    if name:
                        asker.dns_queries.add(name)

            answer_count = int(getattr(dns_layer, "ancount", 0) or 0)
            for index in range(answer_count):
                try:
                    record = dns_layer.an[index]
                except (IndexError, TypeError, AttributeError):
                    break
                if not isinstance(record, DNSRR):
                    continue
                # A (1) and AAAA (28) records are the ones that yield addresses.
                if getattr(record, "type", None) in (1, 28):
                    address = str(getattr(record, "rdata", "") or "")
                    if address:
                        result.resolved_ips[address].add(_decode_name(record.rrname))

    sniff_kwargs: Dict[str, Any] = {
        "prn": handle,
        "store": False,
        "timeout": duration,
        # Only IPv4 traffic; keeps the parsing path simple and the volume down.
        "filter": "ip",
    }
    if interface:
        sniff_kwargs["iface"] = interface

    try:
        scapy["sniff"](**sniff_kwargs)
    except PermissionError as exc:
        raise CaptureUnavailable(
            "Permission denied opening the network interface. Traffic capture requires "
            "administrator/root privileges."
        ) from exc
    except OSError as exc:
        raise CaptureUnavailable(
            f"Could not start capture on the network interface: {exc}. If you specified an "
            "interface name, check that it is correct."
        ) from exc

    return result


def _decode_name(raw: Any) -> str:
    """Normalise a DNS name from scapy's bytes into a plain string."""
    if raw is None:
        return ""
    if isinstance(raw, bytes):
        text = raw.decode("utf-8", errors="replace")
    else:
        text = str(raw)
    return text.rstrip(".")


async def capture_traffic(
    duration_seconds: int = 60,
    interface: Optional[str] = None,
) -> CaptureResult:
    """Capture traffic for a bounded window and return per-device summaries.

    Args:
        duration_seconds: How long to listen, clamped to 10-300 seconds.
        interface: Optional interface name. Auto-detected when omitted.

    Returns:
        A :class:`CaptureResult`.

    Raises:
        CaptureUnavailable: If the backend is missing or privileges are absent.
            The message is written to be shown directly to the user.
    """
    duration = max(MIN_DURATION, min(MAX_DURATION, int(duration_seconds)))
    from ..storage import utc_now

    started_at = utc_now()
    started_monotonic = time.monotonic()

    result = await asyncio.to_thread(_capture_blocking, duration, interface, started_at)
    result.duration_seconds = time.monotonic() - started_monotonic
    return result
