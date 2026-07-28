"""The synthetic network the evaluation questions are asked against.

Evaluation answers have to be stable and verifiable, which a real network can
never be -- devices come and go between runs. This fixture is a deliberately
ordinary home network with one genuinely bad device on it, so every question in
``evaluation.xml`` has exactly one correct answer.
"""

from __future__ import annotations

from edgedefense_core.findings import build_findings
from edgedefense_core.models import Device, ScanResult

#: (ip, mac, hostname, device_type, confidence, open_ports, mdns, gateway)
_SPEC = [
    ("192.168.1.1", "70:3a:cb:00:00:01", None, [53, 80], [], True),
    ("192.168.1.15", "f0:18:98:aa:bb:cc", "macbook-pro", [], [], False),
    ("192.168.1.22", "00:00:5e:00:53:01", None, [23, 554], [], False),
    ("192.168.1.30", "94:9f:3e:11:22:33", None, [], ["_sonos._tcp.local"], False),
    ("192.168.1.35", "2c:76:8a:11:22:33", None, [9100, 515, 631], [], False),
    ("192.168.1.40", "b8:27:eb:aa:bb:cc", "pibridge", [22, 8123], [], False),
    ("192.168.1.55", "de:ad:be:ef:00:01", None, [], [], False),
    ("192.168.1.60", "00:1a:2b:3c:4d:5e", None, [], [], False),
    ("192.168.1.70", "a4:cf:12:00:00:01", "tasmota_000001", [80], [], False),
]


def build_fixture_result() -> ScanResult:
    """Construct the fixture scan, classifying devices with the real engine."""
    from edgedefense_core.classify import classify_device
    from edgedefense_core.discovery.ports import describe_port
    from edgedefense_core.models import is_randomised_mac
    from edgedefense_core.vendor import lookup_vendor

    devices = []
    for ip, mac, hostname, ports, mdns, is_gateway in _SPEC:
        vendor = lookup_vendor(mac)
        device_type, confidence = classify_device(
            hostname=hostname,
            vendor=vendor,
            open_ports=ports,
            mdns_services=mdns,
            is_gateway=is_gateway,
        )
        devices.append(
            Device(
                device_id=mac,
                ip=ip,
                mac=mac,
                hostname=hostname,
                vendor=vendor,
                device_type=device_type,
                type_confidence=confidence,
                open_ports=list(ports),
                services={p: describe_port(p) for p in ports},
                mdns_services=list(mdns),
                randomised_mac=is_randomised_mac(mac),
                is_gateway=is_gateway,
                sources=["arp"],
                first_seen="2026-07-20T09:00:00+00:00",
                last_seen="2026-07-27T10:00:11+00:00",
            )
        )

    return ScanResult(
        started_at="2026-07-27T10:00:00+00:00",
        finished_at="2026-07-27T10:00:11+00:00",
        scan_depth="quick",
        subnet="192.168.1.0/24",
        devices=devices,
        findings=build_findings(devices),
    )


def install_fixture() -> ScanResult:
    """Load the fixture into the server's cache so tools answer from it."""
    from edgedefense_mcp import server as srv

    result = build_fixture_result()
    srv._last_result = result
    return result
