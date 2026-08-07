"""Runs at home: bridges the real MCP server to the cloud relay.

Two things happen here:

* ``run_mcp_server`` starts the actual EdgeDefense MCP server -- the same
  ``edgedefense_mcp.server:mcp`` that the tunnel deployment uses, with real
  device discovery, real scoring, real findings. There is deliberately no
  second implementation of the tools in this package; ``mcp_tools.py`` used to
  duplicate them with hardcoded fake data (a trust score that was always
  "80 (Fair)" regardless of what was on the network) and has been removed.
* ``run_http_bridge`` dials OUT to the cloud relay over HTTP long polling, so
  nothing has to listen for inbound connections at home -- no port forwarding,
  no tunnel, no changing hostname.

The relay endpoints require a bearer token (see main.py). EDGEDEFENSE_RELAY_TOKEN
must be set to the same value the relay was configured with, or every request
here is rejected with 401.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import urllib.error
import urllib.request

RELAY_BASE = os.environ.get("EDGEDEFENSE_RELAY_URL", "https://www.edgedefenseai.com")
POLL_URL = f"{RELAY_BASE}/relay/poll"
SEND_URL = f"{RELAY_BASE}/relay/send"

#: Windows' console codepage means stray non-ASCII bytes in a scan result
#: (a device's advertised hostname, say) would otherwise crash the print
#: below with a UnicodeEncodeError -- turning a cosmetic logging line into a
#: reason the bridge silently stops relaying.
def _safe_print(prefix: str, text: str) -> None:
    print(f"{prefix} {text}".encode("ascii", errors="replace").decode("ascii"))


def run_mcp_server() -> None:
    """Run the real MCP server over stdio, as a subprocess of the bridge."""
    from edgedefense_mcp.server import mcp

    mcp.run(transport="stdio")


def _require_token() -> str:
    token = os.environ.get("EDGEDEFENSE_RELAY_TOKEN")
    if not token:
        print(
            "EDGEDEFENSE_RELAY_TOKEN is not set. The relay rejects every request "
            "without it -- set it to the same value configured on the relay "
            "(Render) before running this.",
            file=sys.stderr,
        )
        raise SystemExit(1)
    return token


async def run_http_bridge() -> None:
    """Connect to the cloud relay and pipe messages to/from the local MCP server."""
    token = _require_token()
    auth_headers = {"Authorization": f"Bearer {token}", "User-Agent": "EdgeDefense-Agent/1.0"}

    print(f"Connecting to cloud relay at {POLL_URL} ...")

    proc = await asyncio.create_subprocess_exec(
        sys.executable, __file__, "--mcp",
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
    )

    async def poll_to_proc() -> None:
        while True:
            try:
                def _poll():
                    req = urllib.request.Request(POLL_URL, method="GET", headers=auth_headers)
                    with urllib.request.urlopen(req, timeout=35) as res:
                        return json.loads(res.read().decode("utf-8"))

                data = await asyncio.to_thread(_poll)
                if data and data.get("message"):
                    msg = data["message"]
                    _safe_print("[Relay -> Local]", msg)
                    proc.stdin.write(msg.encode("utf-8") + b"\n")
                    await proc.stdin.drain()
            except urllib.error.HTTPError as exc:
                if exc.code == 401:
                    print(
                        "Relay rejected this token (401). EDGEDEFENSE_RELAY_TOKEN "
                        "does not match what the relay is configured with.",
                        file=sys.stderr,
                    )
                else:
                    print(f"Poll HTTP error {exc.code}: {exc.read().decode(errors='ignore')}")
                await asyncio.sleep(3)
            except urllib.error.URLError as exc:
                if "timeout" not in str(exc).lower():
                    print(f"Poll error: {exc.reason}")
                    await asyncio.sleep(2)
            except Exception as exc:  # noqa: BLE001 - a bad poll must not kill the bridge
                print(f"Poll error: {exc}")
                await asyncio.sleep(2)

    async def proc_to_send() -> None:
        while True:
            try:
                line = await proc.stdout.readline()
                if not line:
                    break
                _safe_print("[Local -> Relay]", line.decode("utf-8", errors="replace").strip())

                def _send(data: bytes) -> None:
                    req = urllib.request.Request(
                        SEND_URL, data=data, method="POST",
                        headers={**auth_headers, "Content-Type": "application/json"},
                    )
                    urllib.request.urlopen(req, timeout=10)

                await asyncio.to_thread(_send, line)
            except Exception as exc:  # noqa: BLE001
                print(f"Error sending response: {exc}")

    await asyncio.gather(poll_to_proc(), proc_to_send())


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--mcp":
        run_mcp_server()
    else:
        asyncio.run(run_http_bridge())
