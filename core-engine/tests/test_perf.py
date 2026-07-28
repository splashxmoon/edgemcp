"""Tests for the performance modules.

These exercise the parsers against real console output captured from each
platform, so the suite is meaningful on any one machine. Nothing here touches
the network: the speed test is covered through its pure logic (grading,
capability notes) rather than by transferring bytes.
"""

from __future__ import annotations

import asyncio
import struct

import pytest

from edgedefense_core.perf import interfaces, latency, speedtest, wifi


def run(coro):
    """Drive a coroutine to completion, matching the convention used elsewhere."""
    return asyncio.run(coro)


# --------------------------------------------------------------------------
# Interfaces
# --------------------------------------------------------------------------


PROC_NET_DEV = """\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 12345      100    0    0    0     0          0         0    12345      100    0    0    0     0       0          0
  eth0: 900000     5000    2    3    0     0          0        10   400000     2500    0    1    0     0       0          0
"""


def test_linux_counters_parsed_from_proc(monkeypatch, tmp_path):
    """/proc/net/dev fields land in the right slots, receive before transmit."""
    (tmp_path / "net_dev").write_text(PROC_NET_DEV)

    real_open = open

    def fake_open(path, *args, **kwargs):
        if str(path) == "/proc/net/dev":
            return real_open(tmp_path / "net_dev", *args, **kwargs)
        raise OSError("not available in test")

    monkeypatch.setattr("builtins.open", fake_open)

    found = {iface.name: iface for iface in interfaces._collect_linux()}

    assert set(found) == {"lo", "eth0"}
    eth = found["eth0"]
    assert eth.bytes_recv == 900000
    assert eth.packets_recv == 5000
    assert eth.errors_in == 2
    assert eth.drops_in == 3
    assert eth.bytes_sent == 400000
    assert eth.packets_sent == 2500
    assert eth.errors_out == 0
    assert eth.drops_out == 1
    assert found["lo"].is_virtual


def test_error_rate_is_none_when_counters_absent():
    """A platform that reports no error counters must not read as 'no errors'."""
    without = interfaces.InterfaceStats(name="en0", packets_recv=100, packets_sent=100)
    assert without.error_rate() is None

    with_counters = interfaces.InterfaceStats(
        name="en0", packets_recv=100, packets_sent=100, errors_in=2, drops_in=0
    )
    assert with_counters.error_rate() == pytest.approx(0.01)


def test_virtual_adapters_recognised():
    assert interfaces.looks_virtual("lo")
    assert interfaces.looks_virtual("vEthernet (Default Switch)")
    assert interfaces.looks_virtual("Ethernet 2", "Hyper-V Virtual Ethernet Adapter")
    assert not interfaces.looks_virtual("Wi-Fi", "Intel(R) Wi-Fi 6 AX201")


def test_rate_rejects_counter_rollback():
    """A counter that went backwards means a reset, not negative throughput."""
    assert interfaces._rate(1000, 500, 2.0) is None
    assert interfaces._rate(1000, 2000, 2.0) == pytest.approx(4000.0)
    assert interfaces._rate(None, 2000, 2.0) is None


MACOS_NETSTAT = """\
Name  Mtu   Network       Address            Ipkts Ierrs     Ibytes    Opkts Oerrs     Obytes  Coll
lo0   16384 <Link#1>                          1000     0     100000     1000     0     100000     0
en0   1500  <Link#5>    a4:83:e7:11:22:33     50000     4   90000000    25000     1   40000000     0
en0   1500  192.168.1     192.168.1.40        50000     -   90000000    25000     -   40000000     -
"""


def test_macos_counters_mapped_by_header(monkeypatch):
    """Columns are located by name, so a shifted layout cannot misread them."""
    async def fake_run(args, timeout=10.0):
        return MACOS_NETSTAT

    monkeypatch.setattr(interfaces, "run", fake_run)
    found = {iface.name: iface for iface in run(interfaces._collect_macos())}

    assert set(found) == {"lo0", "en0"}
    en0 = found["en0"]
    assert en0.bytes_recv == 90000000
    assert en0.bytes_sent == 40000000
    assert en0.errors_in == 4
    assert en0.errors_out == 1
    assert en0.mac == "a4:83:e7:11:22:33"
    assert en0.mtu == 1500


# --------------------------------------------------------------------------
# Wi-Fi
# --------------------------------------------------------------------------


NETSH_INTERFACES = """
There is 1 interface on the system:

    Name                   : Wi-Fi
    Description            : Intel(R) Wi-Fi 6 AX201 160MHz
    State                  : connected
    SSID                   : Foxglove
    BSSID                  : a4:cf:12:34:56:78
    Network type           : Infrastructure
    Radio type             : 802.11ax
    Authentication         : WPA2-Personal
    Cipher                 : CCMP
    Connection mode        : Profile
    Band                   : 5 GHz
    Channel                : 44
    Receive rate (Mbps)    : 1201
    Transmit rate (Mbps)   : 1201
    Signal                 : 84%
"""


def test_netsh_link_parsed_with_dbm_conversion():
    link = wifi.parse_netsh_interfaces(NETSH_INTERFACES)

    assert link is not None
    assert link.ssid == "Foxglove"
    assert link.bssid == "a4:cf:12:34:56:78"
    assert link.channel == 44
    assert link.band == "5 GHz"
    assert link.signal_percent == 84
    assert link.signal_dbm == pytest.approx(-58.0)
    assert link.quality() == "good"
    assert link.rx_rate_mbps == pytest.approx(1201.0)
    assert link.radio_type == "802.11ax"


def test_netsh_disconnected_reports_no_link():
    text = "    Name : Wi-Fi\n    State : disconnected\n"
    assert wifi.parse_netsh_interfaces(text) is None


NETSH_NETWORKS = """
Interface name : Wi-Fi
There are 3 networks currently visible.

SSID 1 : Foxglove
    Network type            : Infrastructure
    Authentication          : WPA2-Personal
    Encryption              : CCMP
    BSSID 1                 : a4:cf:12:34:56:78
         Signal             : 84%
         Radio type         : 802.11ax
         Channel            : 44
    BSSID 2                 : a4:cf:12:34:56:79
         Signal             : 70%
         Radio type         : 802.11n
         Channel            : 6

SSID 2 : Neighbour
    Network type            : Infrastructure
    BSSID 1                 : b0:11:22:33:44:55
         Signal             : 45%
         Channel            : 6
"""


def test_netsh_networks_counts_each_radio_separately():
    """A dual-band router occupies two channels and must count as two."""
    networks = wifi.parse_netsh_networks(NETSH_NETWORKS)

    assert len(networks) == 3
    assert [n.channel for n in networks] == [44, 6, 6]
    assert networks[0].ssid == "Foxglove"
    assert networks[2].ssid == "Neighbour"
    assert networks[0].band == "5 GHz"
    assert networks[1].band == "2.4 GHz"


def test_congestion_excludes_our_own_access_point():
    """The scan sees the AP we are joined to; counting it inflates every reading."""
    report = wifi.WifiReport(
        link=wifi.WifiLink(ssid="Foxglove", bssid="a4:cf:12:34:56:78", channel=44),
        nearby=[
            wifi.NearbyNetwork(ssid="Foxglove", bssid="A4:CF:12:34:56:78", channel=44),
            wifi.NearbyNetwork(ssid="Neighbour", bssid="b0:11:22:33:44:55", channel=44),
        ],
    )
    assert report.congestion() == 1


def test_congestion_counts_other_mesh_radios_on_our_own_network():
    """A second mesh node shares our name but contends for airtime regardless."""
    report = wifi.WifiReport(
        link=wifi.WifiLink(ssid="Foxglove", bssid="a4:cf:12:34:56:78", channel=44),
        nearby=[
            wifi.NearbyNetwork(ssid="Foxglove", bssid="a4:cf:12:34:56:78", channel=44),
            wifi.NearbyNetwork(ssid="Foxglove", bssid="a4:cf:12:34:56:99", channel=44),
        ],
    )
    assert report.congestion() == 1


def test_netsh_networks_capture_bssid():
    networks = wifi.parse_netsh_networks(NETSH_NETWORKS)
    assert networks[0].bssid == "a4:cf:12:34:56:78"
    assert networks[2].bssid == "b0:11:22:33:44:55"


def test_channel_congestion_and_advice():
    report = wifi.WifiReport(
        link=wifi.WifiLink(
            ssid="Foxglove", band="2.4 GHz", channel=6, signal_percent=40,
            signal_dbm=-80.0,
        ),
        nearby=[
            wifi.NearbyNetwork(ssid="A", channel=6),
            wifi.NearbyNetwork(ssid="B", channel=6),
            wifi.NearbyNetwork(ssid="C", channel=6),
            wifi.NearbyNetwork(ssid="D", channel=11),
        ],
    )

    assert report.congestion() == 3
    assert report.channel_usage()[0] == (6, 3)

    advice = " ".join(report.advice())
    assert "share channel 6" in advice
    # -80 dBm is weak, and weak signal advice must fire before channel advice
    # matters at all.
    assert "weak" in advice
    # Channel 6 is one of the clean three, so no overlap warning.
    assert "overlaps" not in advice


def test_advice_flags_overlapping_24ghz_channel():
    report = wifi.WifiReport(
        link=wifi.WifiLink(band="2.4 GHz", channel=3, signal_dbm=-45.0),
        nearby=[],
    )
    advice = " ".join(report.advice())
    assert "overlaps" in advice
    assert "5 GHz" in advice


def test_band_from_channel():
    assert wifi.band_for_channel(1) == "2.4 GHz"
    assert wifi.band_for_channel(11) == "2.4 GHz"
    assert wifi.band_for_channel(44) == "5 GHz"
    assert wifi.band_for_channel(157) == "5 GHz"
    assert wifi.band_for_channel(213) == "6 GHz"
    assert wifi.band_for_channel(None) is None


AIRPORT_INFO = """\
     agrCtlRSSI: -55
     agrExtRSSI: 0
    agrCtlNoise: -92
          state: running
        op mode: station
      lastTxRate: 400
         maxRate: 866
    lastAssocStatus: 0
      802.11 auth: open
        link auth: wpa2-psk
            BSSID: a4:cf:12:34:56:78
             SSID: Foxglove
              MCS: 9
          channel: 44,80
"""


def test_airport_info_parsed():
    link = wifi.parse_airport_info(AIRPORT_INFO)

    assert link is not None
    assert link.ssid == "Foxglove"
    assert link.channel == 44  # The ",80" is the width, not part of the channel.
    assert link.signal_dbm == pytest.approx(-55.0)
    assert link.quality() == "good"
    assert link.tx_rate_mbps == pytest.approx(400.0)


NMCLI = r"""yes:Foxglove:A4\:CF\:12\:34\:56\:78:44:84:540 Mbit/s
no:Neighbour:B0\:11\:22\:33\:44\:55:6:45:270 Mbit/s
"""


def test_nmcli_unescapes_bssid_colons():
    link, nearby = wifi.parse_nmcli(NMCLI)

    assert link is not None
    assert link.ssid == "Foxglove"
    assert link.bssid == "A4:CF:12:34:56:78"
    assert link.channel == 44
    assert len(nearby) == 2
    assert nearby[1].ssid == "Neighbour"
    assert nearby[1].channel == 6


# --------------------------------------------------------------------------
# Latency
# --------------------------------------------------------------------------


WINDOWS_PING = """
Pinging 192.168.1.1 with 32 bytes of data:
Reply from 192.168.1.1: bytes=32 time=3ms TTL=64
Reply from 192.168.1.1: bytes=32 time<1ms TTL=64
Reply from 192.168.1.1: bytes=32 time=5ms TTL=64
Request timed out.

Ping statistics for 192.168.1.1:
    Packets: Sent = 4, Received = 3, Lost = 1 (25% loss),
"""

LINUX_PING = """
PING 192.168.1.1 (192.168.1.1) 56(84) bytes of data.
64 bytes from 192.168.1.1: icmp_seq=1 ttl=64 time=1.23 ms
64 bytes from 192.168.1.1: icmp_seq=2 ttl=64 time=4.56 ms
64 bytes from 192.168.1.1: icmp_seq=3 ttl=64 time=2.00 ms

--- 192.168.1.1 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2003ms
rtt min/avg/max/mdev = 1.230/2.596/4.560/1.383 ms
"""


def test_windows_ping_parsed_including_sub_millisecond():
    result = latency.parse_ping(WINDOWS_PING, "192.168.1.1", sent=4)

    assert result.received == 3
    assert result.samples_ms == [3.0, 0.5, 5.0]
    assert result.loss_percent == pytest.approx(25.0)
    assert result.min_ms == 0.5
    assert result.max_ms == 5.0


def test_linux_ping_parsed():
    result = latency.parse_ping(LINUX_PING, "192.168.1.1", sent=3)

    assert result.samples_ms == [1.23, 4.56, 2.0]
    assert result.loss_percent == pytest.approx(0.0)
    assert result.avg_ms == pytest.approx(2.596666, rel=1e-3)


def test_jitter_measures_packet_to_packet_variation():
    """Jitter is consecutive variation, not spread about the mean."""
    steady = latency.PingResult(host="h", sent=4, received=4, samples_ms=[10, 10, 10, 10])
    assert steady.jitter_ms == pytest.approx(0.0)

    # Same min, max and average as a smooth ramp, but alternating wildly.
    erratic = latency.PingResult(host="h", sent=4, received=4, samples_ms=[5, 15, 5, 15])
    assert erratic.jitter_ms == pytest.approx(10.0)


def test_ping_with_no_replies_has_no_stats():
    result = latency.parse_ping("Request timed out.\nRequest timed out.\n", "h", sent=2)
    assert result.received == 0
    assert result.avg_ms is None
    assert result.jitter_ms is None
    assert result.loss_percent == pytest.approx(100.0)


def test_dns_query_is_well_formed():
    """The hand-built packet must be a valid A query the resolver will answer."""
    query = latency.build_dns_query("cloudflare.com", transaction_id=0xBEEF)

    transaction_id, flags, questions, answers, authority, additional = struct.unpack(
        ">HHHHHH", query[:12]
    )
    assert transaction_id == 0xBEEF
    assert flags == 0x0100  # Standard query, recursion desired.
    assert questions == 1
    assert (answers, authority, additional) == (0, 0, 0)

    # Labels are length-prefixed and terminated by a zero byte.
    assert query[12:] == b"\x0acloudflare\x03com\x00" + struct.pack(">HH", 1, 1)


def test_latency_verdict_names_the_actual_cause():
    report = latency.LatencyReport(
        gateway=latency.PingResult(
            host="192.168.1.1", sent=5, received=4, samples_ms=[40, 55, 38, 60]
        )
    )
    verdict = " ".join(report.verdict())

    assert "high for a link inside your own home" in verdict
    assert "internet connection itself is not involved" in verdict
    # 20% loss to your own router deserves its own line.
    assert "20% of packets" in verdict


def test_latency_verdict_handles_silent_router():
    report = latency.LatencyReport(
        gateway=latency.PingResult(host="192.168.1.1", sent=5, received=0)
    )
    verdict = " ".join(report.verdict())
    assert "configured not to reply" in verdict


# --------------------------------------------------------------------------
# Speed test (pure logic only - no bytes are transferred)
# --------------------------------------------------------------------------


def test_bufferbloat_grades():
    def grade(increase):
        return speedtest.SpeedTestResult(bufferbloat_ms=increase).bufferbloat_grade()

    assert grade(2) == "A+"
    assert grade(20) == "A"
    assert grade(45) == "B"
    assert grade(150) == "C"
    assert grade(300) == "D"
    assert grade(900) == "F"
    assert grade(None) is None


def test_capability_notes_scale_with_measured_speed():
    fast = speedtest.SpeedTestResult(download_mbps=450.0, upload_mbps=40.0)
    assert "several 4K streams" in " ".join(fast.capability_notes())

    slow = speedtest.SpeedTestResult(download_mbps=6.0, upload_mbps=1.0)
    notes = " ".join(slow.capability_notes())
    assert "below what a single HD stream" in notes
    # A weak uplink is called out separately, since the headline number hides it.
    assert "Upload is 1.0 Mbps" in notes


def test_bufferbloat_note_only_for_bad_grades():
    good = speedtest.SpeedTestResult(download_mbps=100.0, bufferbloat_ms=10.0)
    assert not any("bufferbloat" in note for note in good.capability_notes())

    bad = speedtest.SpeedTestResult(download_mbps=100.0, bufferbloat_ms=250.0)
    assert any("bufferbloat" in note for note in bad.capability_notes())


def test_mbps_conversion_and_guards():
    assert speedtest._mbps(12_500_000, 1.0) == pytest.approx(100.0)
    assert speedtest._mbps(0, 5.0) is None
    assert speedtest._mbps(1000, 0) is None


TRACE_RESPONSE = """\
fl=386f142
h=speed.cloudflare.com
ip=203.0.113.45
ts=1785266230.000
visit_scheme=https
colo=EWR
loc=US
tls=TLSv1.3
"""


def test_meta_parsing_keeps_location_and_drops_the_client_ip():
    """The trace response carries the caller's public IP; it must not survive."""
    fields = {}
    for line in TRACE_RESPONSE.splitlines():
        key, separator, value = line.partition("=")
        if separator and key in speedtest._META_KEEP:
            fields[key] = value.strip()

    assert fields == {"colo": "EWR", "loc": "US"}
    assert "ip" not in fields
    assert "203.0.113.45" not in str(fields)


def test_non_success_status_is_reported_not_counted():
    """A 403 body is still bytes. Counting it would report a fake slow link."""

    class Response:
        status = 403
        reason = "Forbidden"

    problem = speedtest._rejected(Response())
    assert problem is not None
    assert "403" in problem

    class Ok:
        status = 200
        reason = "OK"

    assert speedtest._rejected(Ok()) is None


def test_download_chunk_stays_within_the_endpoint_limit():
    """Cloudflare answers 403 above roughly 100 MB; the request must stay under."""
    assert speedtest._MAX_DOWNLOAD_CHUNK <= 50 * 1024 * 1024


def test_result_dict_never_exposes_a_public_ip():
    """The endpoint reports the caller's IP; it must not reach the output."""
    result = speedtest.SpeedTestResult(
        download_mbps=100.0, server_location="London, GB", server_colo="LHR"
    )
    payload = result.to_dict()

    assert "ip" not in payload
    assert not any("ip" == key.lower() for key in payload)
    assert payload["server_location"] == "London, GB"
