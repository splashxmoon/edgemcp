"""Latency, jitter, packet loss, and how fast name lookups resolve.

Separates the two halves of "the internet feels slow": the hop to your own
router, and the resolver that turns names into addresses. A user whose gateway
latency is 40 ms has a Wi-Fi problem; a user whose gateway is 2 ms but whose
DNS takes 300 ms has a resolver problem. The fixes share nothing.

Packets go only to the default gateway and to the DNS servers this machine is
already configured to use. Nothing here contacts a third-party service.
"""

from __future__ import annotations

import asyncio
import random
import socket
import struct
import sys
import time
from dataclasses import dataclass, field
from statistics import mean
from typing import Any, Dict, List, Optional

from ..local_checks import get_dns_servers
from ..netinfo import describe_local_network
from ._proc import run

#: A name that every resolver will have cached. Using a random subdomain would
#: measure a cold lookup, which is a worse model of what the user experiences.
_PROBE_NAME = "cloudflare.com"

#: Windows prints "time<1ms" instead of a number below its 1 ms resolution.
#: Half a millisecond is the honest midpoint of what that means.
_SUB_MS = 0.5


@dataclass
class PingResult:
    """Round-trip times to one host."""

    host: str
    label: str = ""
    sent: int = 0
    received: int = 0
    samples_ms: List[float] = field(default_factory=list)
    error: Optional[str] = None

    @property
    def loss_percent(self) -> Optional[float]:
        if not self.sent:
            return None
        return 100.0 * (self.sent - self.received) / self.sent

    @property
    def min_ms(self) -> Optional[float]:
        return min(self.samples_ms) if self.samples_ms else None

    @property
    def avg_ms(self) -> Optional[float]:
        return mean(self.samples_ms) if self.samples_ms else None

    @property
    def max_ms(self) -> Optional[float]:
        return max(self.samples_ms) if self.samples_ms else None

    @property
    def jitter_ms(self) -> Optional[float]:
        """Mean absolute difference between consecutive round trips.

        This is the RFC 3550 style of jitter rather than a standard deviation:
        what degrades a call is variation between one packet and the next, not
        spread around the average.
        """
        if len(self.samples_ms) < 2:
            return None
        deltas = [
            abs(later - earlier)
            for earlier, later in zip(self.samples_ms, self.samples_ms[1:])
        ]
        return mean(deltas)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "host": self.host,
            "label": self.label,
            "sent": self.sent,
            "received": self.received,
            "loss_percent": self.loss_percent,
            "min_ms": self.min_ms,
            "avg_ms": self.avg_ms,
            "max_ms": self.max_ms,
            "jitter_ms": self.jitter_ms,
            "samples_ms": self.samples_ms,
            "error": self.error,
        }


@dataclass
class DnsResult:
    """How one resolver performed."""

    server: str
    query: str = _PROBE_NAME
    samples_ms: List[float] = field(default_factory=list)
    failures: int = 0
    error: Optional[str] = None

    @property
    def avg_ms(self) -> Optional[float]:
        return mean(self.samples_ms) if self.samples_ms else None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "server": self.server,
            "query": self.query,
            "avg_ms": self.avg_ms,
            "min_ms": min(self.samples_ms) if self.samples_ms else None,
            "max_ms": max(self.samples_ms) if self.samples_ms else None,
            "failures": self.failures,
            "error": self.error,
        }


@dataclass
class LatencyReport:
    """Everything the latency check measured."""

    gateway: Optional[PingResult] = None
    dns: List[DnsResult] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def verdict(self) -> List[str]:
        """Plain-language conclusions, each tied to a number that was measured."""
        lines: List[str] = []
        gateway = self.gateway

        if gateway and gateway.samples_ms:
            avg = gateway.avg_ms or 0.0
            jitter = gateway.jitter_ms
            loss = gateway.loss_percent or 0.0

            if avg < 5:
                lines.append(
                    f"The hop to your router averages {avg:.1f} ms, which is what a "
                    "healthy wired or strong Wi-Fi link looks like."
                )
            elif avg < 20:
                lines.append(
                    f"The hop to your router averages {avg:.1f} ms. That is normal for "
                    "Wi-Fi, though a wired connection would be several times faster."
                )
            else:
                lines.append(
                    f"The hop to your router averages {avg:.1f} ms, which is high for a "
                    "link inside your own home. Weak signal or a congested channel is "
                    "the usual cause - the internet connection itself is not involved."
                )

            if jitter is not None and jitter > 10:
                lines.append(
                    f"Round-trip time varies by {jitter:.1f} ms between packets. That "
                    "instability is what makes calls stutter, even when the average "
                    "looks fine."
                )
            if loss > 0:
                lines.append(
                    f"{loss:.0f}% of packets to your own router were lost. Inside a home "
                    "network that should be zero, and it points at the wireless link "
                    "rather than at your provider."
                )
        elif gateway:
            lines.append(
                "The router did not answer any pings. Many routers are configured not "
                "to reply, so this on its own does not mean anything is wrong."
            )

        answered = [entry for entry in self.dns if entry.samples_ms]
        if answered:
            slowest = max(answered, key=lambda entry: entry.avg_ms or 0.0)
            fastest = min(answered, key=lambda entry: entry.avg_ms or 0.0)
            if (slowest.avg_ms or 0) > 100:
                lines.append(
                    f"DNS lookups via {slowest.server} take {slowest.avg_ms:.0f} ms. "
                    "Every new site visit waits on that before a single byte of the "
                    "page is requested, so it reads as general slowness."
                )
            elif len(answered) > 1 and (slowest.avg_ms or 0) > 4 * max(fastest.avg_ms or 0.1, 1):
                lines.append(
                    f"Your resolvers disagree sharply: {fastest.server} answers in "
                    f"{fastest.avg_ms:.0f} ms but {slowest.server} takes "
                    f"{slowest.avg_ms:.0f} ms. Whichever one a lookup lands on is luck."
                )
            else:
                lines.append(
                    f"Name lookups resolve in {fastest.avg_ms:.0f} ms, which is fine."
                )

        return lines

    def to_dict(self) -> Dict[str, Any]:
        return {
            "gateway": self.gateway.to_dict() if self.gateway else None,
            "dns": [entry.to_dict() for entry in self.dns],
            "verdict": self.verdict(),
            "warnings": self.warnings,
        }


# --------------------------------------------------------------------------
# ICMP, via the system ping tool
# --------------------------------------------------------------------------

#: Raw ICMP sockets need root, and this project's whole premise is that it does
#: not ask for that. The system ping binary is setuid precisely so unprivileged
#: users can do this, so shelling out is the correct call, not a shortcut.


def _ping_args(host: str, count: int) -> List[str]:
    if sys.platform == "win32":
        return ["ping", "-n", str(count), "-w", "1500", host]
    if sys.platform == "darwin":
        return ["ping", "-c", str(count), "-t", str(max(2, count * 2)), host]
    return ["ping", "-c", str(count), "-W", "2", host]


def parse_ping(text: str, host: str, sent: int) -> PingResult:
    """Extract per-reply round trips from ping output on any platform.

    Only the individual reply lines are parsed; the summary block that ping
    prints is worded differently on every platform and in every locale, whereas
    ``time=1.23 ms`` is stable across all of them.
    """
    result = PingResult(host=host, sent=sent)

    for line in text.splitlines():
        lowered = line.lower()
        if "time" not in lowered:
            continue
        # "time=1.23 ms", "time=1ms", "tiempo=1ms" - anchor on the operator.
        index = lowered.find("time")
        if index < 0:
            continue
        fragment = lowered[index:]
        if "<" in fragment[:8]:
            result.samples_ms.append(_SUB_MS)
            continue
        equals = fragment.find("=")
        if equals < 0 or equals > 8:
            continue
        number: List[str] = []
        for char in fragment[equals + 1 :].strip():
            if char.isdigit() or char == ".":
                number.append(char)
            else:
                break
        try:
            result.samples_ms.append(float("".join(number)))
        except ValueError:
            continue

    result.received = len(result.samples_ms)
    return result


async def ping_host(host: str, count: int = 5, label: str = "") -> PingResult:
    """Ping a host and summarise the round trips."""
    count = max(1, min(int(count), 20))
    output = await run(_ping_args(host, count), timeout=5.0 + 2.0 * count)
    if not output.strip():
        return PingResult(
            host=host,
            label=label,
            sent=count,
            error="The system ping tool produced no output, so latency could not be measured.",
        )
    result = parse_ping(output, host, count)
    result.label = label
    return result


# --------------------------------------------------------------------------
# DNS, over a hand-built query
# --------------------------------------------------------------------------


def build_dns_query(name: str, transaction_id: Optional[int] = None) -> bytes:
    """Build a minimal DNS A-record query.

    Hand-rolled rather than pulled from a library because the core engine has
    no dependencies, and because ``socket.gethostbyname`` cannot be pointed at
    a specific resolver - which is the entire point of this measurement.
    """
    if transaction_id is None:
        transaction_id = random.randint(0, 0xFFFF)
    # Flags 0x0100: standard query, recursion desired. One question, no answers.
    header = struct.pack(">HHHHHH", transaction_id, 0x0100, 1, 0, 0, 0)

    encoded = b"".join(
        bytes([len(label)]) + label.encode("idna" if not label.isascii() else "ascii")
        for label in name.rstrip(".").split(".")
        if label
    )
    question = encoded + b"\x00" + struct.pack(">HH", 1, 1)  # QTYPE=A, QCLASS=IN
    return header + question


def _query_once(server: str, payload: bytes, transaction_id: int, timeout: float) -> float:
    """Send one query and return the round trip in milliseconds.

    Raises on timeout or socket error; the caller counts those as failures.
    """
    family = socket.AF_INET6 if ":" in server else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        started = time.perf_counter()
        sock.sendto(payload, (server, 53))
        while True:
            data, _ = sock.recvfrom(2048)
            # Ignore anything that is not the answer we asked for; a stray
            # datagram would otherwise be timed as if it were.
            if len(data) >= 2 and struct.unpack(">H", data[:2])[0] == transaction_id:
                return (time.perf_counter() - started) * 1000.0
    finally:
        sock.close()


def _time_resolver(server: str, samples: int, timeout: float) -> DnsResult:
    """Time several lookups against one resolver."""
    result = DnsResult(server=server)
    for _ in range(samples):
        transaction_id = random.randint(0, 0xFFFF)
        payload = build_dns_query(_PROBE_NAME, transaction_id)
        try:
            result.samples_ms.append(_query_once(server, payload, transaction_id, timeout))
        except (socket.timeout, OSError):
            result.failures += 1
    if not result.samples_ms and result.failures:
        result.error = "No reply. The resolver is unreachable or is refusing queries."
    return result


async def time_dns_servers(
    servers: Optional[List[str]] = None,
    samples: int = 3,
    timeout: float = 2.0,
) -> List[DnsResult]:
    """Measure lookup time against each configured resolver.

    Args:
        servers: resolvers to test. Defaults to the ones this machine is
            already configured to use.
        samples: queries per resolver.
        timeout: seconds to wait for each reply.
    """
    if servers is None:
        servers = await get_dns_servers()
    if not servers:
        return []

    samples = max(1, min(int(samples), 10))
    # Sequential per resolver but concurrent across them: the point is to
    # compare resolvers, and running them in series would let a slow one push
    # the whole check past a sensible runtime.
    return list(
        await asyncio.gather(
            *(
                asyncio.to_thread(_time_resolver, server, samples, timeout)
                for server in servers
            )
        )
    )


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------


async def run_latency_check(count: int = 5, include_dns: bool = True) -> LatencyReport:
    """Measure the hop to the router and, optionally, resolver response time.

    Args:
        count: how many pings to send to the gateway.
        include_dns: also time lookups against each configured DNS server.

    Returns:
        A report. Never raises for network conditions: an unreachable gateway
        or a silent resolver is recorded as such and explained.
    """
    report = LatencyReport()

    try:
        network = await asyncio.to_thread(describe_local_network)
    except Exception as exc:  # noqa: BLE001
        report.warnings.append(f"Could not determine the default gateway: {exc}")
        network = None

    if network and network.gateway:
        report.gateway = await ping_host(network.gateway, count=count, label="your router")
    else:
        report.warnings.append(
            "No default gateway was found, so the hop to your router could not be "
            "measured. This is expected on a machine with no active network."
        )

    if include_dns:
        try:
            report.dns = await time_dns_servers()
        except Exception as exc:  # noqa: BLE001
            report.warnings.append(f"DNS timing failed: {exc}")
        if not report.dns:
            report.warnings.append(
                "No DNS servers were configured or reachable, so lookup time was not "
                "measured."
            )

    return report
