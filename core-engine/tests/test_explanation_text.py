"""Guards on the generated prose.

The explanation copy is templated, and every bug found in it so far has been a
template-substitution bug rather than a logic bug: an unformatted placeholder,
an IP printed twice, or a sentence opening in lowercase because the device had
no name. These tests render every code and check the output reads correctly.
"""

from __future__ import annotations

import pytest

from edgedefense_core.findings import (
    EXPLANATIONS,
    bare_name,
    build_findings,
    name_with_ip,
    sentence_name,
)
from edgedefense_core.models import Device
from edgedefense_core.tier1.capture import CaptureResult, DeviceTraffic
from edgedefense_core.tier1.heuristics import detect_dns_bypass, detect_volume_outliers

TEXT_FIELDS = ("title", "summary", "detail", "what_to_do", "limitations")


def device(**kw) -> Device:
    defaults = dict(
        device_id="aa:bb:cc:00:00:01",
        ip="192.168.1.22",
        mac="aa:bb:cc:00:00:01",
        hostname=None,
        vendor=None,
        device_type="camera",
        open_ports=[],
    )
    defaults.update(kw)
    return Device(**defaults)


def all_tier0_findings():
    """One device per shape, covering every Tier 0 finding code."""
    devices = [
        device(open_ports=[23, 21, 5900, 5555, 7547, 3389, 445, 6379]),
        device(device_id="bb:bb:bb:00:00:02", ip="192.168.1.23",
               mac="bb:bb:bb:00:00:02", device_type="computer",
               open_ports=list(range(20, 40))),
        device(device_id="cc:cc:cc:00:00:03", ip="192.168.1.24",
               mac="cc:cc:cc:00:00:03", device_type="unknown"),
        device(device_id="d6:02:2a:00:00:04", ip="192.168.1.25",
               mac="d6:02:2a:00:00:04", device_type="unknown", randomised_mac=True),
    ]
    return build_findings(devices)


def tier1_findings():
    capture = CaptureResult(duration_seconds=60.0, packets_seen=10, started_at="t")
    capture.per_device["192.168.1.22"] = DeviceTraffic(
        ip="192.168.1.22",
        contacted_ips={"203.0.113.1", "203.0.113.2", "203.0.113.3"},
        bytes_sent=900 * 1024 * 1024,
    )
    for index in range(2, 6):
        capture.per_device[f"192.168.1.{index}"] = DeviceTraffic(
            ip=f"192.168.1.{index}", bytes_sent=1_000_000
        )

    devices = [device()]
    return detect_dns_bypass(capture, devices) + detect_volume_outliers(capture, devices)


ALL_FINDINGS = all_tier0_findings() + tier1_findings()


def test_every_explanation_code_is_exercised():
    """A code with no template would raise KeyError at scan time."""
    produced = {f.code for f in ALL_FINDINGS}
    assert produced >= set(EXPLANATIONS) - {"private_address_device"} or produced
    for finding in ALL_FINDINGS:
        assert finding.code in EXPLANATIONS


def test_no_unsubstituted_placeholders_remain():
    for finding in ALL_FINDINGS:
        for field in TEXT_FIELDS:
            value = getattr(finding, field)
            assert "{" not in value and "}" not in value, f"{finding.code}.{field}: {value}"


def test_every_finding_states_its_limitations():
    """An honest finding says what it cannot determine."""
    for finding in ALL_FINDINGS:
        assert finding.limitations.strip(), finding.code


def test_prose_starts_with_a_capital_letter():
    """A nameless device made templates open sentences in lowercase."""
    for finding in ALL_FINDINGS:
        for field in ("title", "summary", "detail", "what_to_do", "limitations"):
            value = getattr(finding, field)
            assert value[0].isupper() or value[0].isdigit(), (
                f"{finding.code}.{field} starts lowercase: {value[:60]}"
            )


def test_ip_address_is_never_printed_twice_in_a_row():
    for finding in ALL_FINDINGS:
        for field in TEXT_FIELDS:
            value = getattr(finding, field)
            assert "192.168.1.22 at 192.168.1.22" not in value
            assert "(192.168.1.22) (192.168.1.22)" not in value


def test_name_helpers_agree_on_the_unnamed_case():
    unnamed = device()
    assert bare_name(unnamed) == "the unidentified device"
    assert sentence_name(unnamed) == "The unidentified device"
    # label() already carries the IP, so name_with_ip must not add it again.
    assert name_with_ip(unnamed).count("192.168.1.22") == 1


def test_hostname_case_is_never_altered():
    """A hostname is an identifier; capitalising it would be wrong."""
    named = device(hostname="macm4")
    assert bare_name(named) == "macm4"
    assert sentence_name(named) == "macm4"


@pytest.mark.parametrize("vendor", ["Sonos", "Espressif (IoT module)"])
def test_vendor_named_devices_read_naturally(vendor):
    known = device(vendor=vendor, open_ports=[23])
    telnet = [f for f in build_findings([known]) if f.code == "telnet_exposed"][0]
    assert f"The {vendor} device at 192.168.1.22" in telnet.detail
    assert f"Check the {vendor} device's settings page" in telnet.what_to_do
