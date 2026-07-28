"""The server must start regardless of what sits in its working directory.

MCP clients launch stdio servers with a working directory the server does not
choose -- usually the user's home directory. FastMCP's Settings model is
declared with ``env_file=".env"``, so anything unparseable there killed the
process during import, and the client surfaced only "Connection closed".

That happened in the wild: a UTF-16 .env in the home directory (PowerShell's
default redirection encoding) raised UnicodeDecodeError before a single
request could be served. These tests pin the fix.

Each runs in a subprocess because the failure occurs at import time and the
working directory is process-global.
"""

from __future__ import annotations

import json
import subprocess
import sys

import pytest

#: Content written in encodings that are not valid UTF-8.
_ENV_BODY = "SOME_KEY=value\nANOTHER_KEY=thing\n"

ENCODINGS = [
    pytest.param("utf-16", id="utf-16-le-bom"),       # PowerShell's default
    pytest.param("utf-16-be", id="utf-16-be"),
    pytest.param("latin-1", id="latin-1-high-bytes"),
]


def _write_env(directory, encoding: str) -> None:
    payload = _ENV_BODY if encoding != "latin-1" else "KEY=caf\xe9 na\xefve\n"
    (directory / ".env").write_bytes(payload.encode(encoding))


def _import_server_in(cwd) -> subprocess.CompletedProcess:
    """Import the server with `cwd` as the working directory."""
    return subprocess.run(
        [sys.executable, "-c",
         "from edgedefense_mcp.server import mcp; print('IMPORT_OK')"],
        cwd=str(cwd), capture_output=True, text=True, timeout=120,
    )


@pytest.mark.parametrize("encoding", ENCODINGS)
def test_imports_despite_unparseable_dotenv(tmp_path, encoding):
    """A .env the server never asked for must not prevent startup."""
    _write_env(tmp_path, encoding)

    result = _import_server_in(tmp_path)

    assert "IMPORT_OK" in result.stdout, (
        f"server failed to import with a {encoding} .env present:\n{result.stderr}"
    )
    assert "UnicodeDecodeError" not in result.stderr


def test_serves_requests_from_a_directory_with_a_broken_dotenv(tmp_path):
    """Full handshake, not just import -- the client's first real interaction."""
    _write_env(tmp_path, "utf-16")

    proc = subprocess.Popen(
        [sys.executable, "-X", "utf8", "-m", "edgedefense_mcp"],
        cwd=str(tmp_path), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, text=True, encoding="utf-8", bufsize=1,
    )
    try:
        proc.stdin.write(json.dumps({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                       "clientInfo": {"name": "test", "version": "1"}},
        }) + "\n")
        proc.stdin.flush()
        response = json.loads(proc.stdout.readline())

        assert response["result"]["serverInfo"]["name"] == "edgedefense_mcp"

        proc.stdin.write(json.dumps(
            {"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
        proc.stdin.write(json.dumps(
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}) + "\n")
        proc.stdin.flush()
        tools = json.loads(proc.stdout.readline())["result"]["tools"]

        assert len(tools) == 11
    finally:
        proc.stdin.close()
        proc.terminate()


def test_dotenv_loading_is_actually_disabled():
    """Pins the mechanism, so an SDK change that re-enables it fails loudly."""
    from edgedefense_mcp import server  # noqa: F401  (applies the hardening)
    from mcp.server.fastmcp.server import Settings

    assert Settings.model_config.get("env_file") is None, (
        "FastMCP is reading .env again; the working directory can break startup"
    )


def test_a_valid_dotenv_is_also_ignored(tmp_path):
    """We take no configuration, so a readable .env must not change behaviour."""
    (tmp_path / ".env").write_text("FASTMCP_PORT=9999\n", encoding="utf-8")

    result = subprocess.run(
        [sys.executable, "-c",
         "from edgedefense_mcp.server import mcp; print(mcp.settings.port)"],
        cwd=str(tmp_path), capture_output=True, text=True, timeout=120,
    )

    assert result.stdout.strip() == "8000", (
        f"a .env in the working directory changed our settings: {result.stdout!r}"
    )
