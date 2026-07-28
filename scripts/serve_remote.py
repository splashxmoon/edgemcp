#!/usr/bin/env python3
"""Start the MCP server plus a Cloudflare quick tunnel, and print the URL to paste.

A quick tunnel gets a new hostname every run, so the connector URL has to be
re-pasted after each restart. This script removes the rest of the ceremony:
one command, and it prints the finished URL.

    python scripts/serve_remote.py

The token is generated once and kept in .edgedefense-token beside this repo, so
the URL stays the same across restarts even though the hostname changes. That
file is gitignored and should stay that way -- it is the credential.

Requires cloudflared: https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/
"""

from __future__ import annotations

import argparse
import os
import re
import secrets
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
TOKEN_FILE = REPO_ROOT / ".edgedefense-token"
TUNNEL_URL_RE = re.compile(r"https://[a-z0-9-]+\.trycloudflare\.com")

#: Where winget puts cloudflared on Windows when it is not yet on PATH.
_WINDOWS_FALLBACKS = (
    r"%LOCALAPPDATA%\Microsoft\WinGet\Links\cloudflared.exe",
    r"%LOCALAPPDATA%\Microsoft\WinGet\Packages"
    r"\Cloudflare.cloudflared_Microsoft.Winget.Source_8wekyb3d8bbwe\cloudflared.exe",
)


def find_cloudflared() -> str | None:
    """Locate cloudflared, tolerating a PATH that has not been refreshed."""
    found = shutil.which("cloudflared")
    if found:
        return found
    if sys.platform == "win32":
        for candidate in _WINDOWS_FALLBACKS:
            expanded = Path(os.path.expandvars(candidate))
            if expanded.exists():
                return str(expanded)
    return None


def load_or_create_token() -> str:
    """Reuse the existing token so the connector URL survives restarts."""
    if TOKEN_FILE.exists():
        token = TOKEN_FILE.read_text(encoding="utf-8").strip()
        if token:
            return token

    token = secrets.token_urlsafe(32)
    TOKEN_FILE.write_text(token, encoding="utf-8")
    try:
        os.chmod(TOKEN_FILE, 0o600)
    except OSError:
        pass  # best effort; Windows ACLs do not map cleanly
    print(f"Generated a new token and saved it to {TOKEN_FILE.name}")
    return token


def wait_for_health(port: int, timeout: float = 40.0) -> bool:
    """Block until the server answers, so the tunnel never starts too early."""
    import urllib.error
    import urllib.request

    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=2):
                return True
        except urllib.error.HTTPError:
            return True  # answering at all is enough
        except Exception:
            time.sleep(0.5)
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--port", type=int, default=8765, help="local port (default 8765)")
    args = parser.parse_args()

    cloudflared = find_cloudflared()
    if not cloudflared:
        print(
            "cloudflared was not found. Install it with:\n"
            "  winget install --id Cloudflare.cloudflared --source winget   (Windows)\n"
            "  brew install cloudflared                                     (macOS)\n"
            "then run this again.",
            file=sys.stderr,
        )
        return 1

    token = load_or_create_token()

    # Loopback only. The tunnel reaches the server locally, so there is no
    # reason to expose the port to the rest of the network as well.
    server = subprocess.Popen(
        [sys.executable, "-m", "edgedefense_mcp", "--http",
         "--port", str(args.port), "--allow-host", "*"],
        env={**os.environ, "EDGEDEFENSE_TOKEN": token},
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )

    tunnel = None
    try:
        print(f"Starting server on 127.0.0.1:{args.port} ...")
        if not wait_for_health(args.port):
            print("Server did not come up. Is the port already in use?", file=sys.stderr)
            return 1

        print("Opening tunnel ...")
        tunnel = subprocess.Popen(
            [cloudflared, "tunnel", "--url", f"http://127.0.0.1:{args.port}",
             "--no-autoupdate"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding="utf-8", errors="replace", bufsize=1,
        )

        public = None
        deadline = time.time() + 60
        while time.time() < deadline and tunnel.poll() is None:
            line = tunnel.stdout.readline()
            if not line:
                continue
            match = TUNNEL_URL_RE.search(line)
            if match:
                public = match.group(0)
                break

        if not public:
            print("Tunnel did not report a URL. Is cloudflared able to reach the "
                  "internet?", file=sys.stderr)
            return 1

        print()
        print("  Paste this into your MCP client:")
        print()
        print(f"    {public}/t/{token}/mcp")
        print()
        print("  Leave any OAuth fields empty. Treat the URL as a password -- it")
        print("  grants a full inventory of this network.")
        print()
        print("  Ctrl+C to stop.")

        # Keep both children alive until interrupted.
        while tunnel.poll() is None and server.poll() is None:
            time.sleep(1)
        return 0

    except KeyboardInterrupt:
        print("\nStopping ...")
        return 0
    finally:
        for process in (tunnel, server):
            if process and process.poll() is None:
                try:
                    process.send_signal(signal.SIGTERM)
                    process.wait(timeout=8)
                except Exception:
                    process.kill()


if __name__ == "__main__":
    raise SystemExit(main())
