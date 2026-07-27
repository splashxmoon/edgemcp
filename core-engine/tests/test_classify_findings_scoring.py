"""Classification precedence, finding generation, and score calibration.

The scoring tests are the ones worth defending: they pin the calibration that
keeps a normal home network in the 90s. If a change makes those fail, the
question to answer is whether the network really got worse or whether the
scoring just got louder.
"""

from __future__ import annotations

from edgedefense_core.classify import classify_device, friendly_type, type_count_label
from edgedefense_core.findings import build_findings, find_by_id
from edgedefense_core.models import Device
from edgedefense_core.scoring import compute_trust_score


def make_device(**overrides) -> Device:
    """A plain, unremarkable device that tests can perturb one field at a time."""
    defaults = dict(
        device_id="aa:bb:cc:11:22:33",
        ip="192.168.1.50",
        mac="aa:bb:cc:11:22:33",
        hostname="thing",
        vendor="Acme",
        device_type="smart_home",
        type_confidence="high",
        open_ports=[],
        services={},
    )
    defaults.update(overrides)
    return Device(**defaults)


# --------------------------------------------------------------------------
# Classification
# --------------------------------------------------------------------------


def test_gateway_and_self_short_circuit_all_other_evidence():
    """Both are known facts, so weaker evidence must not override them."""
    assert classify_device(hostname="printer", is_gateway=True) == ("router", "high")
    assert classify_device(hostname="printer", is_self=True) == ("computer", "high")


def test_mdns_beats_vendor():
    device_type, confidence = classify_device(
        vendor="Hewlett Packard",                        # weak: HP makes everything
        mdns_services=["_googlecast._tcp.local"],        # strong: it says it is a Chromecast
    )
    assert (device_type, confidence) == ("tv_or_streaming", "high")


def test_screen_sharing_identifies_a_computer_over_ambiguous_airplay():
    """A Mac advertises AirPlay too; only _rfb distinguishes it from a TV."""
    device_type, confidence = classify_device(
        hostname="macm4",
        mdns_services=["_airplay._tcp.local", "_raop._tcp.local", "_rfb._tcp.local"],
    )
    assert (device_type, confidence) == ("computer", "high")


def test_airplay_audio_without_video_reads_as_a_speaker():
    device_type, _ = classify_device(
        hostname="living-room-speaker",
        mdns_services=["_airplay._tcp.local", "_raop._tcp.local"],
    )
    assert device_type == "smart_speaker"


def test_printer_identified_by_port_signature():
    device_type, confidence = classify_device(open_ports=[9100, 515])
    assert (device_type, confidence) == ("printer", "high")


def test_unknown_when_there_is_no_evidence():
    assert classify_device() == ("unknown", "none")


def test_plural_labels_are_written_out_not_suffixed():
    """Appending "s" produced "17 unidentifieds" and "3 TV or streaming devices"."""
    assert type_count_label("unknown", 17) == "17 unidentified devices"
    assert type_count_label("unknown", 1) == "1 unidentified device"
    assert type_count_label("tv_or_streaming", 3) == "3 TVs and streaming devices"
    assert type_count_label("phone_or_tablet", 1) == "1 phone or tablet"
    assert friendly_type("nas_or_server") == "Server or NAS"


# --------------------------------------------------------------------------
# Findings
# --------------------------------------------------------------------------


def test_telnet_produces_a_high_severity_finding_with_a_stable_id():
    device = make_device(open_ports=[23], services={23: "Telnet"})
    findings = build_findings([device])
    telnet = find_by_id(findings, "telnet_exposed:aa:bb:cc:11:22:33")
    assert telnet is not None
    assert telnet.severity == "high"
    assert telnet.limitations  # every finding must state what it cannot know


def test_smb_reported_once_even_though_two_ports_match():
    device = make_device(open_ports=[139, 445])
    codes = [f.code for f in build_findings([device])]
    assert codes.count("smb_exposed") == 1


def test_unidentified_device_summary_does_not_repeat_the_ip():
    """label() already embeds the IP when there is no better name."""
    device = make_device(
        hostname=None, vendor=None, device_type="unknown", open_ports=[23]
    )
    telnet = [f for f in build_findings([device]) if f.code == "telnet_exposed"][0]
    assert telnet.summary.count("192.168.1.50") == 1
    assert telnet.title.count("192.168.1.50") == 1
    # The detail template renders "{name} at {ip}", so the name must be bare.
    assert "192.168.1.50 at 192.168.1.50" not in telnet.detail


def test_default_credential_pattern_needs_an_appliance_device_type():
    appliance = make_device(device_type="camera", open_ports=[23])
    computer = make_device(device_type="computer", open_ports=[23])

    assert any(f.code == "default_credential_risk" for f in build_findings([appliance]))
    assert not any(f.code == "default_credential_risk" for f in build_findings([computer]))


def test_randomised_mac_is_informational_not_a_deduction():
    """Penalising this would penalise every modern phone."""
    phone = make_device(
        device_id="de:ad:be:ef:00:01",
        mac="de:ad:be:ef:00:01",
        hostname=None,
        vendor=None,
        device_type="unknown",
        randomised_mac=True,
    )
    findings = build_findings([phone])
    codes = {f.code for f in findings}
    assert "private_address_device" in codes
    assert "unidentified_device" not in codes

    score = compute_trust_score([phone], findings)
    assert score.score == 100


def test_findings_are_sorted_most_severe_first():
    device = make_device(device_type="computer", open_ports=[23, 445])
    severities = [f.severity for f in build_findings([device])]
    assert severities[0] == "high"


# --------------------------------------------------------------------------
# Scoring
# --------------------------------------------------------------------------


def test_ordinary_home_network_scores_in_the_nineties():
    """The calibration guarantee. A router, a phone, a TV and a laptop is fine."""
    devices = [
        make_device(device_id="r", ip="192.168.1.1", device_type="router", is_gateway=True),
        make_device(device_id="p", ip="192.168.1.2", device_type="phone_or_tablet"),
        make_device(device_id="t", ip="192.168.1.3", device_type="tv_or_streaming"),
        make_device(device_id="l", ip="192.168.1.4", device_type="computer", open_ports=[445]),
    ]
    findings = build_findings(devices)
    score = compute_trust_score(devices, findings)
    assert score.score >= 90, f"clean network scored {score.score}: calibration drifted"
    assert score.grade == "Strong"


def test_clean_network_scores_a_hundred_with_positive_reasons():
    devices = [make_device(device_id=str(i), ip=f"192.168.1.{i}") for i in range(1, 5)]
    score = compute_trust_score(devices, build_findings(devices))
    assert score.score == 100
    assert score.reasons and "No risky services" in score.reasons[0]


def test_exposed_service_deductions_are_capped():
    """Twenty compromised devices is bad, but the score must not go negative."""
    devices = [
        make_device(device_id=f"d{i}", ip=f"192.168.1.{i}", device_type="camera",
                    open_ports=[23, 21, 5900])
        for i in range(1, 21)
    ]
    findings = build_findings(devices)
    score = compute_trust_score(devices, findings)
    assert score.deductions["exposed services"] == 45  # the category cap
    assert 0 <= score.score <= 100


def test_score_reason_device_count_matches_the_points_quoted():
    """The reason quotes a category total, so its count must span the category.

    Reporting one code's device count next to the whole category's points read
    as "1 device ... (-24 points)" when two devices were involved.
    """
    devices = [
        make_device(device_id="a", ip="192.168.1.10", device_type="computer",
                    open_ports=[23, 21]),
        make_device(device_id="b", ip="192.168.1.11", device_type="computer",
                    open_ports=[445]),
    ]
    findings = build_findings(devices)
    score = compute_trust_score(devices, findings)
    exposure_reason = next(r for r in score.reasons if "risky service" in r)
    assert exposure_reason.startswith("2 devices expose")


def test_singular_reason_uses_singular_verb():
    device = make_device(device_type="computer", open_ports=[23])
    score = compute_trust_score([device], build_findings([device]))
    assert "1 device exposes" in score.reasons[0]


def test_empty_scan_reports_no_data_rather_than_a_perfect_score():
    score = compute_trust_score([], [])
    assert score.score == 0
    assert score.grade == "No data"
    assert score.device_count == 0


def test_tier1_flag_is_recorded_on_the_score():
    device = make_device()
    assert compute_trust_score([device], [], tier1_included=True).tier1_included is True
    assert compute_trust_score([device], [], tier1_included=False).tier1_included is False
