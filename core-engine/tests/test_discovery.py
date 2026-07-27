"""ARP output parsing, mDNS wire-format handling, and port descriptions."""

from __future__ import annotations

from edgedefense_core.discovery.arp import _parse_arp_output
from edgedefense_core.discovery.mdns import (
    _SERVICE_TYPE_RE,
    _parse_txt,
    _read_name,
    _encode_name,
    build_query,
)
from edgedefense_core.discovery.ports import QUICK_PORTS, SERVICE_NAMES, describe_port

# --------------------------------------------------------------------------
# ARP
# --------------------------------------------------------------------------

WINDOWS_ARP = """
Interface: 192.168.1.39 --- 0xe
  Internet Address      Physical Address      Type
  192.168.1.1          70-3a-cb-00-00-01     dynamic
  192.168.1.22         00-00-5e-00-53-01     dynamic
  192.168.1.255        ff-ff-ff-ff-ff-ff     static
  224.0.0.251           01-00-5e-00-00-fb     static
"""

LINUX_ARP = """
192.168.1.1 dev wlan0 lladdr 70:3a:cb:00:00:01 REACHABLE
192.168.1.22 dev wlan0 lladdr 00:00:5e:00:53:01 STALE
192.168.1.90 dev wlan0  FAILED
"""

MACOS_ARP = """
? (192.168.1.1) at 70:3a:cb:0:0:1 on en0 ifscope [ethernet]
? (192.168.1.22) at 0:0:5e:0:53:1 on en0 ifscope [ethernet]
? (192.168.1.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]
"""


def test_parses_windows_arp_and_drops_broadcast():
    entries = {e.ip: e.mac for e in _parse_arp_output(WINDOWS_ARP)}
    assert entries["192.168.1.1"] == "70:3a:cb:00:00:01"
    assert entries["192.168.1.22"] == "00:00:5e:00:53:01"
    # Broadcast and multicast rows are not real devices.
    assert "192.168.1.255" not in entries
    assert "224.0.0.251" not in entries


def test_parses_linux_neighbour_table():
    entries = {e.ip: e.mac for e in _parse_arp_output(LINUX_ARP)}
    assert entries == {
        "192.168.1.1": "70:3a:cb:00:00:01",
        "192.168.1.22": "00:00:5e:00:53:01",
    }
    # A FAILED entry has no address and must not appear.
    assert "192.168.1.90" not in entries


def test_parses_macos_arp_including_shortened_octets():
    entries = {e.ip: e.mac for e in _parse_arp_output(MACOS_ARP)}
    # macOS drops leading zeros, printing "0:0:1" rather than "00:00:01".
    assert entries["192.168.1.1"] == "70:3a:cb:00:00:01"
    assert entries["192.168.1.22"] == "00:00:5e:00:53:01"
    assert "192.168.1.255" not in entries


def test_arp_parsing_is_resilient_to_junk():
    assert _parse_arp_output("") == []
    assert _parse_arp_output("no addresses here at all") == []


# --------------------------------------------------------------------------
# mDNS
# --------------------------------------------------------------------------


def test_name_round_trip():
    encoded = _encode_name("_airplay._tcp.local")
    name, offset = _read_name(encoded, 0)
    assert name == "_airplay._tcp.local"
    assert offset == len(encoded)


def test_read_name_follows_compression_pointer():
    # "local" at offset 0, then a name whose final label is a pointer to it.
    data = _encode_name("local") + b"\x04test\xc0\x00"
    name, _ = _read_name(data, len(_encode_name("local")))
    assert name == "test.local"


def test_read_name_survives_pointer_loop():
    """A self-referential pointer must terminate rather than hang."""
    data = b"\xc0\x00"
    name, _ = _read_name(data, 0)
    assert isinstance(name, str)


def test_build_query_sets_unicast_response_bit():
    packet = build_query(("_airplay._tcp.local",), unicast_response=True)
    # Header is 12 bytes; qdcount lives at offset 4-6.
    assert packet[4:6] == b"\x00\x01"
    # The class field is the last two bytes, with the QU bit (0x8000) set.
    assert packet[-2:] == b"\x80\x01"

    plain = build_query(("_airplay._tcp.local",), unicast_response=False)
    assert plain[-2:] == b"\x00\x01"


def test_parse_txt_extracts_key_values():
    # Each chunk is length-prefixed: "model=J105" is 10 bytes, "md=Nest" is 7.
    payload = b"\x0amodel=J105\x07md=Nest\x04junk"
    parsed = _parse_txt(payload)
    assert parsed["model"] == "J105"
    assert parsed["md"] == "Nest"
    # A chunk with no "=" is not a key/value pair and is skipped.
    assert "junk" not in parsed


def test_service_type_extraction_handles_awkward_instance_names():
    """Instance labels routinely contain dots and colons.

    Splitting on the first dot mangled Amazon Whisperplay names, which is what
    this anchored match replaced.
    """
    awkward = (
        "dmgr:22D4B650FA0934F9CC983B633D65FA85:xnVDMM+4u1:938025._amzn-wplay._tcp.local"
    )
    assert _SERVICE_TYPE_RE.search(awkward).group(1) == "_amzn-wplay._tcp.local"

    simple = "Living Room._airplay._tcp.local"
    assert _SERVICE_TYPE_RE.search(simple).group(1) == "_airplay._tcp.local"

    udp = "abc._matterc._udp.local"
    assert _SERVICE_TYPE_RE.search(udp).group(1) == "_matterc._udp.local"

    assert _SERVICE_TYPE_RE.search("hostname.local") is None


# --------------------------------------------------------------------------
# Ports
# --------------------------------------------------------------------------


def test_every_quick_port_has_a_plain_language_name():
    for port in QUICK_PORTS:
        assert port in SERVICE_NAMES, f"port {port} has no description"


def test_describe_port_falls_back_gracefully():
    assert "Telnet" in describe_port(23)
    assert "12345" in describe_port(12345)
