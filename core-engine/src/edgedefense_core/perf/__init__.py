"""Network performance measurement: throughput, latency, link quality.

Where the rest of the engine answers "what is on my network and is it safe",
this package answers "is my network actually working well". The two questions
share a user but almost no code.

One deliberate exception to the package-wide no-outbound-traffic rule lives
here. :mod:`edgedefense_core.perf.speedtest` contacts an internet server,
because measuring download speed cannot be done any other way. It is isolated
in its own module, never runs as part of a scan, and is only reachable when a
caller asks for it by name. Everything else in this package reads local
counters or talks to the local gateway and the machine's own DNS resolvers.
"""

from __future__ import annotations

from .interfaces import (
    InterfaceReport,
    InterfaceStats,
    collect_interfaces,
    sample_interfaces,
)
from .latency import (
    DnsResult,
    LatencyReport,
    PingResult,
    ping_host,
    run_latency_check,
    time_dns_servers,
)
from .speedtest import DEFAULT_ENDPOINT, SpeedTestResult, run_speed_test
from .wifi import NearbyNetwork, WifiLink, WifiReport, collect_wifi

__all__ = [
    "DEFAULT_ENDPOINT",
    "DnsResult",
    "InterfaceReport",
    "InterfaceStats",
    "LatencyReport",
    "NearbyNetwork",
    "PingResult",
    "SpeedTestResult",
    "WifiLink",
    "WifiReport",
    "collect_interfaces",
    "collect_wifi",
    "ping_host",
    "run_latency_check",
    "run_speed_test",
    "sample_interfaces",
    "time_dns_servers",
]
