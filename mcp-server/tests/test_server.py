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
    """Nothing in the free tier may modify the network."""
    tools = run(srv.mcp.list_tools())
    assert len(tools) == 8
    for tool in tools:
        if tool.name == "edgedefense_name_device":
            assert tool.annotations.readOnlyHint is False, tool.name
        else:
            assert tool.annotations.readOnlyHint is True, tool.name
        assert tool.annotations.destructiveHint is False, tool.name
        # Everything runs locally; nothing reaches an external service.
        assert tool.annotations.openWorldHint is False, tool.name


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
