"""Permanent endpoint configuration and credential handling."""

import importlib.util
from pathlib import Path
from unittest.mock import Mock
from urllib.error import HTTPError

import pytest


@pytest.fixture
def supervisor(monkeypatch, tmp_path):
    path = Path(__file__).resolve().parents[2] / "scripts" / "serve_forever.py"
    spec = importlib.util.spec_from_file_location("serve_forever", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "SERVER_LOG", tmp_path / "server.log")
    for name in ("EDGEDEFENSE_TUNNEL_HOSTNAME", "EDGEDEFENSE_TUNNEL_ID",
                 "EDGEDEFENSE_PASSPHRASE"):
        monkeypatch.delenv(name, raising=False)
    return module


def test_named_tunnel_uses_identity_not_public_hostname(supervisor, monkeypatch, tmp_path):
    popen = Mock()
    monkeypatch.setattr(supervisor.subprocess, "Popen", popen)
    monkeypatch.setattr(supervisor, "TUNNEL_LOG", tmp_path / "tunnel.log")
    supervisor.start_tunnel("cloudflared", 8765, "edgedefense-mcp")
    command = popen.call_args.args[0]
    assert command[-1] == "edgedefense-mcp"
    assert "run" in command
    assert "http://127.0.0.1:8765" in command


def test_oauth_launch_uses_public_origin_and_keeps_secret_out_of_arguments(supervisor, monkeypatch):
    popen = Mock()
    monkeypatch.setattr(supervisor.subprocess, "Popen", popen)
    supervisor.start_server(8765, "private-passphrase", "mcp.edgedefenseai.com", True)
    command = popen.call_args.args[0]
    assert command[command.index("--public-url") + 1] == "https://mcp.edgedefenseai.com"
    assert command[command.index("--allow-host") + 1] == "mcp.edgedefenseai.com"
    assert "--oauth" in command
    assert "private-passphrase" not in command
    assert popen.call_args.kwargs["env"]["EDGEDEFENSE_PASSPHRASE"] == "private-passphrase"


def test_legacy_token_mode_still_requires_secret(supervisor, monkeypatch):
    popen = Mock()
    monkeypatch.setattr(supervisor.subprocess, "Popen", popen)
    supervisor.start_server(8765, "private-token")
    assert "--oauth" not in popen.call_args.args[0]
    assert popen.call_args.kwargs["env"]["EDGEDEFENSE_TOKEN"] == "private-token"


def test_generated_passphrase_survives_restart(supervisor, tmp_path):
    path = tmp_path / "passphrase"
    first = supervisor.load_or_create_token(path)
    assert len(first) >= 32
    assert supervisor.load_or_create_token(path) == first


@pytest.mark.parametrize("args", [
    ["--oauth"],
    ["--hostname", "mcp.edgedefenseai.com"],
    ["--tunnel", "edgedefense-mcp"],
    ["--hostname", "https://mcp.edgedefenseai.com/mcp", "--tunnel", "edgedefense-mcp"],
])
def test_incomplete_configuration_fails_before_starting(supervisor, monkeypatch, args):
    launch = Mock()
    monkeypatch.setattr(supervisor, "start_server", launch)
    monkeypatch.setattr(supervisor.sys, "argv", ["serve_forever.py", *args])
    with pytest.raises(SystemExit) as exc:
        supervisor.main()
    assert exc.value.code == 2
    launch.assert_not_called()


def test_http_error_is_not_healthy(supervisor, monkeypatch):
    monkeypatch.setattr(supervisor.time, "time", Mock(side_effect=[0, 0, 2]))
    monkeypatch.setattr(supervisor.time, "sleep", Mock())
    monkeypatch.setattr(supervisor.urllib.request, "urlopen", Mock(
        side_effect=HTTPError("http://localhost/healthz", 503, "unavailable", {}, None)))
    assert not supervisor.wait_for_health(8765, timeout=1)
