"""Tool contract tests for the MCP server.

These exercise the tool layer against a synthetic scan result, so they never
touch the real network or the user's stored history.
"""

from __future__ import annotations

import asyncio
import json

import pytest

from edgedefense_core.findings import build_findings
from edgedefense_core.models import Device, ScanResult
from edgedefense_mcp import server as srv


def make_devices():
    """A small network with one genuinely risky device."""
    router = Device(
        device_id="70:3a:cb:00:00:01",
        ip="192.168.1.1",
        mac="70:3a:cb:00:00:01",
        hostname=None,
        vendor="Google",
        device_type="router",
        type_confidence="high",
        is_gateway=True,
        open_ports=[53, 80],
        services={53: "DNS", 80: "HTTP (web interface)"},
    )
    camera = Device(
        device_id="00:00:5e:00:53:01",
        ip="192.168.1.22",
        mac="00:00:5e:00:53:01",
        hostname=None,
        vendor=None,
        device_type="camera",
        type_confidence="medium",
        open_ports=[23, 554],
        services={23: "Telnet (unencrypted remote login)", 554: "RTSP (video stream)"},
    )
    laptop = Device(
        device_id="f0:18:98:11:22:33",
        ip="192.168.1.40",
        mac="f0:18:98:11:22:33",
        hostname="macbook",
        vendor="Apple",
        device_type="computer",
        type_confidence="high",
        open_ports=[],
    )
    mystery = Device(
        device_id="aa:bb:cc:dd:ee:ff",
        ip="192.168.1.77",
        mac="aa:bb:cc:dd:ee:ff",
        hostname=None,
        vendor=None,
        device_type="unknown",
        type_confidence="none",
        open_ports=[],
    )
    return [router, camera, laptop, mystery]


@pytest.fixture(autouse=True)
def fake_scan(tmp_path, monkeypatch):
    """Install a synthetic scan result and a throwaway database."""
    from edgedefense_core.storage import Storage

    devices = make_devices()
    result = ScanResult(
        started_at="2026-07-27T10:00:00+00:00",
        finished_at="2026-07-27T10:00:11+00:00",
        scan_depth="quick",
        subnet="192.168.1.0/24",
        devices=devices,
        findings=build_findings(devices),
    )

    monkeypatch.setattr(srv, "_storage", Storage(data_dir=tmp_path))
    monkeypatch.setattr(srv, "_last_result", result)
    yield result
    monkeypatch.setattr(srv, "_last_result", None)


async def call(name: str, args: dict | None = None) -> str:
    """Invoke a tool the way a client would, and return its text output."""
    raw = await srv.mcp.call_tool(name, args or {})
    blocks = raw[0] if isinstance(raw, tuple) else raw
    return blocks[0].text


def run(coro):
    return asyncio.run(coro)


# --------------------------------------------------------------------------
# Registration
# --------------------------------------------------------------------------


def test_every_tool_is_registered_read_only():
    """No tool may modify the network."""
    tools = run(srv.mcp.list_tools())
    assert len(tools) == 11
    for tool in tools:
        if tool.name == "edgedefense_name_device":
            assert tool.annotations.readOnlyHint is False, tool.name
        else:
            assert tool.annotations.readOnlyHint is True, tool.name
        assert tool.annotations.destructiveHint is False, tool.name


def test_only_the_speed_test_reaches_outside_this_machine():
    """The privacy claim, expressed as an assertion.

    Measuring throughput genuinely requires transferring data with an internet
    server, so one tool is exempt. That exemption is the entire cost of the
    feature, and it must not silently spread: openWorldHint is how a client
    tells the user an action leaves their machine.
    """
    tools = run(srv.mcp.list_tools())
    outward = {tool.name for tool in tools if tool.annotations.openWorldHint}
    assert outward == {"edgedefense_speed_test"}


def test_no_destructive_tool_exists():
    """Blocking is a paid-product capability, deliberately absent here."""
    names = {t.name for t in run(srv.mcp.list_tools())}
    assert not any(
        word in name for name in names for word in ("block", "disconnect", "kick", "delete")
    )


def test_tool_schemas_are_flat():
    """A nested `params` wrapper is a common source of malformed tool calls."""
    for tool in run(srv.mcp.list_tools()):
        assert "params" not in tool.inputSchema.get("properties", {}), tool.name


# --------------------------------------------------------------------------
# Listing and detail
# --------------------------------------------------------------------------


def test_list_devices_returns_everything_by_default():
    out = run(call("edgedefense_list_devices"))
    assert "192.168.1.1" in out and "192.168.1.40" in out


def test_list_devices_unknown_filter():
    out = run(call("edgedefense_list_devices", {"filter_type": "unknown"}))
    assert "192.168.1.77" in out
    assert "192.168.1.40" not in out  # the identified laptop is excluded


def test_list_devices_flagged_filter_only_includes_devices_with_findings():
    out = run(call("edgedefense_list_devices", {"filter_type": "flagged"}))
    assert "192.168.1.22" in out   # telnet
    assert "192.168.1.40" not in out


def test_list_devices_json_shape():
    payload = json.loads(
        run(call("edgedefense_list_devices", {"response_format": "json"}))
    )
    assert payload["total_devices"] == 4
    assert payload["count"] == 4
    assert {d["ip"] for d in payload["devices"]} == {
        "192.168.1.1", "192.168.1.22", "192.168.1.40", "192.168.1.77"
    }


def test_device_detail_resolves_by_ip_mac_and_hostname():
    for identifier in ("192.168.1.40", "f0:18:98:11:22:33", "macbook"):
        out = run(call("edgedefense_get_device_detail", {"device_id": identifier}))
        assert "macbook" in out, identifier


def test_device_detail_reports_no_open_ports_explicitly():
    out = run(call("edgedefense_get_device_detail", {"device_id": "192.168.1.40"}))
    assert "not offering" in out


def test_device_detail_unknown_id_lists_valid_options():
    out = run(call("edgedefense_get_device_detail", {"device_id": "10.0.0.1"}))
    assert "No device matching" in out
    assert "192.168.1.1" in out  # tells the caller what it could have asked for


# --------------------------------------------------------------------------
# Score and explanations
# --------------------------------------------------------------------------


def test_trust_score_json_is_well_formed():
    score = json.loads(run(call("edgedefense_get_trust_score", {"response_format": "json"})))
    assert 0 <= score["score"] <= 100
    assert score["grade"]
    assert score["reasons"]


def test_explain_finding_covers_meaning_action_and_limits():
    out = run(
        call("edgedefense_explain_finding",
             {"finding_id": "telnet_exposed:00:00:5e:00:53:01"})
    )
    assert "What this means" in out
    assert "What to do about it" in out
    assert "cannot tell you" in out


def test_explain_finding_is_case_insensitive():
    out = run(
        call("edgedefense_explain_finding",
             {"finding_id": "TELNET_EXPOSED:00:00:5E:00:53:01"})
    )
    assert "What this means" in out


def test_explain_unknown_finding_lists_available_ids():
    out = run(call("edgedefense_explain_finding", {"finding_id": "nope"}))
    assert "No finding with id" in out
    assert "telnet_exposed" in out


# --------------------------------------------------------------------------
# No-scan behaviour
# --------------------------------------------------------------------------


def test_tools_direct_the_user_to_scan_when_nothing_is_cached(monkeypatch, tmp_path):
    from edgedefense_core.storage import Storage

    monkeypatch.setattr(srv, "_last_result", None)
    monkeypatch.setattr(srv, "_storage", Storage(data_dir=tmp_path / "empty"))

    for tool in ("edgedefense_list_devices", "edgedefense_get_trust_score"):
        assert "edgedefense_scan_network" in run(call(tool))


# --------------------------------------------------------------------------
# Performance tools
# --------------------------------------------------------------------------
#
# These stub the measurement layer. The point under test is the tool contract --
# schema, formatting, JSON shape -- not the network, which the core engine's
# own suite covers against captured console output.


def test_network_stats_reports_live_rates_and_wifi(monkeypatch):
    from edgedefense_core.perf import interfaces as core_interfaces
    from edgedefense_core.perf import wifi as core_wifi

    report = core_interfaces.InterfaceReport(
        sample_seconds=2.0,
        interfaces=[
            core_interfaces.InterfaceStats(
                name="Wi-Fi",
                description="Intel(R) Wi-Fi 6 AX201",
                is_up=True,
                link_speed_mbps=866.0,
                mtu=1500,
                bytes_recv=90_000_000,
                bytes_sent=40_000_000,
                packets_recv=50_000,
                packets_sent=25_000,
                errors_in=0,
                errors_out=0,
                drops_in=0,
                drops_out=0,
                recv_rate_bps=24_000_000.0,
                send_rate_bps=1_500_000.0,
            )
        ],
    )
    radio = core_wifi.WifiReport(
        link=core_wifi.WifiLink(
            ssid="Foxglove", band="5 GHz", channel=44, signal_dbm=-58.0,
            signal_percent=84, rx_rate_mbps=866.0, tx_rate_mbps=866.0,
        ),
        nearby=[core_wifi.NearbyNetwork(ssid="Neighbour", channel=44)],
    )

    async def fake_sample(seconds):
        return report

    async def fake_wifi(include_nearby=True):
        return radio

    monkeypatch.setattr(core_interfaces, "sample_interfaces", fake_sample)
    monkeypatch.setattr(core_wifi, "collect_wifi", fake_wifi)

    out = run(call("edgedefense_network_stats"))
    assert "24.0 Mbps down" in out
    assert "1.5 Mbps up" in out
    assert "Foxglove" in out
    assert "-58 dBm" in out
    assert "No packet errors" in out


def test_network_stats_json_shape(monkeypatch):
    from edgedefense_core.perf import interfaces as core_interfaces
    from edgedefense_core.perf import wifi as core_wifi

    async def fake_sample(seconds):
        return core_interfaces.InterfaceReport(
            sample_seconds=1.0,
            interfaces=[core_interfaces.InterfaceStats(name="eth0", is_up=True)],
        )

    async def fake_wifi(include_nearby=True):
        return core_wifi.WifiReport()

    monkeypatch.setattr(core_interfaces, "sample_interfaces", fake_sample)
    monkeypatch.setattr(core_wifi, "collect_wifi", fake_wifi)

    payload = json.loads(
        run(call("edgedefense_network_stats", {"response_format": "json"}))
    )
    assert payload["interfaces"]["interfaces"][0]["name"] == "eth0"
    assert payload["wifi"]["link"] is None


def test_network_stats_can_skip_wifi(monkeypatch):
    """include_wifi=False must not run the radio scan at all."""
    from edgedefense_core.perf import interfaces as core_interfaces
    from edgedefense_core.perf import wifi as core_wifi

    async def fake_sample(seconds):
        return core_interfaces.InterfaceReport(interfaces=[])

    def explode(**kwargs):
        raise AssertionError("Wi-Fi was scanned despite include_wifi=False")

    monkeypatch.setattr(core_interfaces, "sample_interfaces", fake_sample)
    monkeypatch.setattr(core_wifi, "collect_wifi", explode)

    out = run(call("edgedefense_network_stats", {"include_wifi": False}))
    assert "No active network adapter" in out


def test_latency_check_renders_round_trips(monkeypatch):
    from edgedefense_core.perf import latency as core_latency

    async def fake_check(count=5, include_dns=True):
        return core_latency.LatencyReport(
            gateway=core_latency.PingResult(
                host="192.168.1.1", label="your router", sent=5, received=5,
                samples_ms=[1.2, 1.4, 1.1, 1.5, 1.3],
            ),
            dns=[core_latency.DnsResult(server="192.168.1.1", samples_ms=[8.0, 9.0])],
        )

    monkeypatch.setattr(core_latency, "run_latency_check", fake_check)

    out = run(call("edgedefense_latency_check"))
    assert "192.168.1.1" in out
    assert "1.3 ms average" in out
    assert "healthy wired or strong Wi-Fi link" in out


def test_speed_test_output_states_that_it_left_the_machine(monkeypatch):
    """The one outbound tool must say so in its own output, every time."""
    from edgedefense_core.perf import speedtest as core_speedtest

    async def fake_test(duration=6.0, streams=4, include_upload=True):
        return core_speedtest.SpeedTestResult(
            download_mbps=412.5,
            upload_mbps=38.2,
            idle_latency_ms=9.0,
            jitter_ms=1.0,
            loaded_latency_ms=310.0,
            bufferbloat_ms=301.0,
            bytes_downloaded=310_000_000,
            bytes_uploaded=29_000_000,
            download_streams=4,
            upload_streams=3,
            server_location="London, GB",
            server_colo="LHR",
            duration_seconds=14.0,
        )

    monkeypatch.setattr(core_speedtest, "run_speed_test", fake_test)

    out = run(call("edgedefense_speed_test"))
    assert "412.5 Mbps down / 38.2 Mbps up" in out
    assert "speed.cloudflare.com" in out
    assert "leaves your machine" in out
    # A 301 ms rise under load is grade D and must be explained, not buried.
    assert "grade **D**" in out
    assert "bufferbloat" in out.lower()


def test_speed_test_reports_failure_without_raising(monkeypatch):
    from edgedefense_core.perf import speedtest as core_speedtest

    async def fake_test(duration=6.0, streams=4, include_upload=True):
        return core_speedtest.SpeedTestResult(
            warnings=["The endpoint did not respond, so no measurement could be taken."]
        )

    monkeypatch.setattr(core_speedtest, "run_speed_test", fake_test)

    out = run(call("edgedefense_speed_test"))
    assert "could not complete" in out
    assert "did not respond" in out


def test_speed_test_json_never_carries_a_public_ip(monkeypatch):
    from edgedefense_core.perf import speedtest as core_speedtest

    async def fake_test(duration=6.0, streams=4, include_upload=True):
        return core_speedtest.SpeedTestResult(
            download_mbps=100.0, server_location="London, GB", server_colo="LHR"
        )

    monkeypatch.setattr(core_speedtest, "run_speed_test", fake_test)

    payload = json.loads(run(call("edgedefense_speed_test", {"response_format": "json"})))
    assert payload["download_mbps"] == 100.0
    assert "ip" not in {key.lower() for key in payload}
