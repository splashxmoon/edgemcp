"""Local persistence, evidence accumulation, and the Tier 1 opt-in gate."""

from __future__ import annotations

import pytest

from edgedefense_core.models import Device
from edgedefense_core.storage import Storage
from edgedefense_core.tier1 import consent as tier1_consent
from edgedefense_core.tier1.capture import CaptureResult, DeviceTraffic
from edgedefense_core.tier1.heuristics import detect_dns_bypass, detect_volume_outliers


@pytest.fixture()
def storage(tmp_path) -> Storage:
    """A throwaway database, so tests never touch the user's real history."""
    return Storage(data_dir=tmp_path)


def make_device(device_id="aa:bb:cc:11:22:33", ip="192.168.1.50", **kw) -> Device:
    defaults = dict(mac=device_id, hostname="thing", vendor="Acme")
    defaults.update(kw)
    return Device(device_id=device_id, ip=ip, **defaults)


# --------------------------------------------------------------------------
# Storage
# --------------------------------------------------------------------------


def test_first_seen_survives_later_scans(storage):
    """"This device appeared today" is only trustworthy if this holds."""
    device = make_device()
    original = storage.record_devices([device])[device.device_id]

    device.ip = "192.168.1.99"  # DHCP moved it
    again = storage.record_devices([device])[device.device_id]

    assert again == original


def test_device_memory_accumulates_mdns_evidence(storage):
    """mDNS is lossy; a device that stays quiet must keep its identity."""
    noisy = make_device(mdns_services=["_rfb._tcp.local", "_airplay._tcp.local"])
    storage.record_devices([noisy])

    memory = storage.load_device_memory()
    assert set(memory[noisy.device_id]["mdns_services"]) == {
        "_rfb._tcp.local",
        "_airplay._tcp.local",
    }
    assert memory[noisy.device_id]["hostname"] == "thing"


def test_stored_hostname_is_not_erased_by_a_silent_scan(storage):
    named = make_device(hostname="macm4")
    storage.record_devices([named])

    silent = make_device(hostname=None)
    storage.record_devices([silent])

    assert storage.load_device_memory()[named.device_id]["hostname"] == "macm4"


def test_scan_history_round_trips(storage):
    assert storage.load_latest_scan() is None
    storage.save_scan({"finished_at": "2026-01-01T00:00:00+00:00", "devices": []})
    assert storage.load_latest_scan()["finished_at"] == "2026-01-01T00:00:00+00:00"


def test_purge_clears_everything(storage):
    storage.record_devices([make_device()])
    storage.save_scan({"finished_at": "x", "devices": []})

    storage.purge_all()

    assert storage.known_device_count() == 0
    assert storage.load_latest_scan() is None


def test_describe_states_nothing_is_transmitted(storage):
    assert storage.describe()["transmitted_anywhere"] is False


# --------------------------------------------------------------------------
# Tier 1 consent
# --------------------------------------------------------------------------


def test_tier1_is_off_until_consent_is_granted(storage):
    assert tier1_consent.get_capability(storage).consent_granted is False
    assert tier1_consent.get_capability(storage).blocking_reason() == "consent_required"

    tier1_consent.grant_consent(storage)
    assert tier1_consent.get_capability(storage).consent_granted is True

    tier1_consent.revoke_consent(storage)
    assert tier1_consent.get_capability(storage).consent_granted is False


def test_consent_text_states_what_it_does_and_does_not_do():
    """The notice is the whole basis for asking; it must stay specific."""
    text = tier1_consent.CONSENT_TEXT
    assert "does not store packet contents" in text
    assert "does not send any data anywhere" in text
    assert "elevated" in text.lower()


def test_capability_is_never_ready_without_all_three_conditions(storage):
    capability = tier1_consent.get_capability(storage)
    if not capability.consent_granted:
        assert capability.ready is False


# --------------------------------------------------------------------------
# Tier 1 heuristics
# --------------------------------------------------------------------------


def build_capture(per_device, resolved=None, duration=60.0) -> CaptureResult:
    capture = CaptureResult(duration_seconds=duration, packets_seen=100, started_at="t")
    for ip, traffic in per_device.items():
        capture.per_device[ip] = traffic
    for ip in resolved or []:
        capture.resolved_ips[ip].add("example.com")
    return capture


def test_dns_bypass_needs_several_unresolved_addresses():
    """One or two is background noise on almost every device."""
    quiet = DeviceTraffic(ip="192.168.1.50", contacted_ips={"8.8.8.8", "1.1.1.1"})
    capture = build_capture({"192.168.1.50": quiet})
    assert detect_dns_bypass(capture, [make_device()]) == []


def test_dns_bypass_flags_a_device_with_many_unresolved_addresses():
    talker = DeviceTraffic(
        ip="192.168.1.50",
        contacted_ips={"203.0.113.1", "203.0.113.2", "203.0.113.3", "203.0.113.4"},
        dns_query_count=0,
    )
    capture = build_capture({"192.168.1.50": talker})
    findings = detect_dns_bypass(capture, [make_device()])

    assert len(findings) == 1
    assert findings[0].code == "dns_bypass"
    assert findings[0].tier == 1
    # Honest about DNS-over-HTTPS looking identical.
    assert "DNS-over-HTTPS" in findings[0].limitations
    # Evidence is a capped sample, not a full flow log.
    assert len(findings[0].evidence["unresolved_addresses"]) <= 10


def test_addresses_resolved_by_anyone_suppress_the_finding():
    contacted = {"203.0.113.1", "203.0.113.2", "203.0.113.3"}
    talker = DeviceTraffic(ip="192.168.1.50", contacted_ips=set(contacted))
    capture = build_capture({"192.168.1.50": talker}, resolved=contacted)
    assert detect_dns_bypass(capture, [make_device()]) == []


def test_volume_outlier_needs_a_peer_group():
    """With too few devices there is nothing to be an outlier against."""
    hog = DeviceTraffic(ip="192.168.1.50", bytes_sent=500 * 1024 * 1024)
    capture = build_capture({"192.168.1.50": hog})
    assert detect_volume_outliers(capture, [make_device()]) == []


def test_volume_outlier_requires_both_a_ratio_and_an_absolute_floor():
    """A quiet network must not manufacture an outlier out of a few kilobytes."""
    per_device = {f"192.168.1.{i}": DeviceTraffic(ip=f"192.168.1.{i}", bytes_sent=1000)
                  for i in range(1, 5)}
    per_device["192.168.1.1"].bytes_sent = 100_000  # 100x the others, still tiny
    capture = build_capture(per_device)
    assert detect_volume_outliers(capture, []) == []


def test_volume_outlier_flags_a_genuine_hog():
    per_device = {f"192.168.1.{i}": DeviceTraffic(ip=f"192.168.1.{i}", bytes_sent=1_000_000)
                  for i in range(1, 5)}
    per_device["192.168.1.1"].bytes_sent = 900 * 1024 * 1024
    capture = build_capture(per_device)

    findings = detect_volume_outliers(capture, [])
    assert len(findings) == 1
    assert findings[0].code == "data_volume_outlier"
    assert findings[0].severity == "low"  # high volume alone is weak evidence
