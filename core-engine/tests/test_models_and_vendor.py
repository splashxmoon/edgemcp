"""MAC normalisation, randomised-address detection, and offline vendor lookup."""

from __future__ import annotations

import pytest

from edgedefense_core.models import (
    is_multicast_mac,
    is_randomised_mac,
    normalise_mac,
)
from edgedefense_core.vendor import lookup_vendor, oui_database_size


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("A4:CF:12:34:56:78", "a4:cf:12:34:56:78"),
        ("a4-cf-12-34-56-78", "a4:cf:12:34:56:78"),   # Windows arp style
        ("a4cf.1234.5678", "a4:cf:12:34:56:78"),       # Cisco style
        ("a4cf12345678", "a4:cf:12:34:56:78"),
        ("  A4:CF:12:34:56:78  ", "a4:cf:12:34:56:78"),
    ],
)
def test_normalise_mac_accepts_every_platform_format(raw, expected):
    assert normalise_mac(raw) == expected


@pytest.mark.parametrize("raw", [None, "", "not-a-mac", "a4:cf:12:34:56", "zz:zz:zz:zz:zz:zz"])
def test_normalise_mac_rejects_garbage(raw):
    assert normalise_mac(raw) is None


def test_randomised_mac_detection():
    # Locally-administered bit (0x02) set, unicast -> a privacy address.
    assert is_randomised_mac("de:ad:be:ef:00:01") is True
    assert is_randomised_mac("a2:27:eb:11:22:33") is True
    # Globally-unique vendor address.
    assert is_randomised_mac("b8:27:eb:00:00:01") is False
    assert is_randomised_mac(None) is False


def test_multicast_mac_detection():
    assert is_multicast_mac("ff:ff:ff:ff:ff:ff") is True
    assert is_multicast_mac("01:00:5e:00:00:fb") is True   # IPv4 multicast
    assert is_multicast_mac("b8:27:eb:00:00:01") is False


def test_vendor_database_is_bundled():
    # Guards against the data file being dropped from the wheel.
    assert oui_database_size() > 500


def test_vendor_lookup_hits_known_prefixes():
    assert lookup_vendor("b8:27:eb:00:00:01") == "Raspberry Pi"
    assert lookup_vendor("A4:CF:12:00:00:01") == "Espressif (IoT module)"
    assert "Apple" == lookup_vendor("f0:18:98:11:22:33")


def test_vendor_lookup_returns_none_for_randomised_mac():
    """A randomised MAC's OUI is meaningless -- naming a vendor would be wrong.

    0xa2 has the locally-administered bit set, and its first three octets
    happen to collide with a real Espressif prefix.
    """
    assert lookup_vendor("a2:cf:12:cd:56:13") is None


def test_vendor_lookup_handles_unknown_and_invalid():
    assert lookup_vendor("00:00:01:02:03:04") is None
    assert lookup_vendor(None) is None
    assert lookup_vendor("junk") is None
