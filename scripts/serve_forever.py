#!/usr/bin/env python3
"""Keep the remote MCP server running, and pick up new commits without
changing the URL people have already saved.

This is the supervised version of ``serve_remote.py``. That script is fine for
a one-off demo, but it has two properties that make it unsuitable for an
endpoint other people rely on:

* **Stopping the server stops the tunnel.** Both children are torn down
  together, so restarting to pick up new code hands you a brand-new tunnel
  hostname, which breaks whatever is pointing at the old one.
* **A quick tunnel's hostname is random.** Even a clean restart changes it.

Both are fixed here. The tunnel is started once and deliberately left alone;
only the server is restarted when new code lands. With ``--hostname`` the
tunnel is a *named* one, whose address never changes at all -- at which point
the public URL is genuinely permanent and nothing downstream needs updating,
ever.

Typical use, after the one-time named-tunnel setup described in the README:

    python scripts/serve_forever.py --hostname mcp-tunnel.example.com

Without ``--hostname`` it falls back to a quick tunnel, prints the address, and
warns that the address will change if the tunnel is ever restarted.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
TOKEN_FILE = REPO_ROOT / ".edgedefense-token"
TUNNEL_LOG = REPO_ROOT / ".cloudflared-tunnel.log"
URL_FILE = REPO_ROOT / ".edgedefense-public-url"
TUNNEL_URL_RE = re.compile(r"https://[a-z0-9-]+\.trycloudflare\.com")

_WINDOWS_FALLBACKS = (
    r"%LOCALAPPDATA%\Microsoft\WinGet\Links\cloudflared.exe",
    r"%LOCALAPPDATA%\Microsoft\WinGet\Packages"
    r"\Cloudflare.cloudflared_Microsoft.Winget.Source_8wekyb3d8bbwe\cloudflared.exe",
)


def find_cloudflared() -> Optional[str]:
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
    """Reuse the saved token so the URL survives restarts."""
    import secrets

    if TOKEN_FILE.exists():
        token = TOKEN_FILE.read_text(encoding="utf-8").strip()
        if token:
            return token
    token = secrets.token_urlsafe(32)
    TOKEN_FILE.write_text(token, encoding="utf-8")
    try:
        os.chmod(TOKEN_FILE, 0o600)
    except OSError:
        pass
    return token


def git(*args: str) -> str:
    """Run a git command in the repo, returning stdout or ""."""
    try:
        proc = subprocess.run(
            ["git", *args],
            cwd=REPO_ROOT,
            capture_output=True,
            timeout=120,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return proc.stdout.decode(errors="replace").strip()


def current_commit() -> str:
    return git("rev-parse", "HEAD")


def pull_if_updated(branch: str) -> bool:
    """Fetch and fast-forward. True if new code arrived.

    Deliberately ``--ff-only``: a supervisor that silently creates merge
    commits on a machine nobody is watching is a way to lose work. If the
    branch has diverged, this reports it and keeps serving the current code
    rather than trying to be clever.
    """
    before = current_commit()
    git("fetch", "origin", branch)

    remote = git("rev-parse", f"origin/{branch}")
    if not remote or remote == before:
        return False

    merged = subprocess.run(
        ["git", "merge", "--ff-only", f"origin/{branch}"],
        cwd=REPO_ROOT,
        capture_output=True,
    )
    if merged.returncode != 0:
        log(
            "New commits exist upstream but the local branch has diverged, so "
            "they were not applied. Resolve it by hand; still serving the "
            "current code."
        )
        return False

    after = current_commit()
    if after != before:
        log(f"Updated {before[:8]} -> {after[:8]}")
        return True
    return False


def wait_for_health(port: int, timeout: float = 40.0) -> bool:
    """Block until the server answers on /healthz."""
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


def start_server(port: int, token: str) -> subprocess.Popen:
    """Launch the MCP server.

    ``--json-response`` is not optional behind a tunnel and a serverless proxy:
    streamed responses get buffered somewhere in that chain, and stateful
    sessions break when two requests land on different proxy instances.
    """
    return subprocess.Popen(
        [
            sys.executable, "-m", "edgedefense_mcp", "--http",
            "--port", str(port), "--allow-host", "*", "--json-response",
        ],
        cwd=REPO_ROOT,
        env={**os.environ, "EDGEDEFENSE_TOKEN": token},
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def start_tunnel(cloudflared: str, port: int, hostname: Optional[str]) -> subprocess.Popen:
    """Launch cloudflared, named if a hostname was configured.

    cloudflared logs continuously, so its output goes to a file rather than a
    pipe. Reading only the first few lines of a pipe and leaving the rest
    unread eventually fills the OS buffer, at which point cloudflared blocks on
    write and quietly stops serving while still looking alive.
    """
    if hostname:
        args = [cloudflared, "tunnel", "run", "--url", f"http://127.0.0.1:{port}", hostname]
    else:
        args = [cloudflared, "tunnel", "--url", f"http://127.0.0.1:{port}", "--no-autoupdate"]

    handle = open(TUNNEL_LOG, "w", encoding="utf-8")
    return subprocess.Popen(args, stdout=handle, stderr=subprocess.STDOUT, cwd=REPO_ROOT)


def read_quick_tunnel_url(process: subprocess.Popen, timeout: float = 60.0) -> Optional[str]:
    """Poll the log for the hostname a quick tunnel was assigned."""
    deadline = time.time() + timeout
    while time.time() < deadline and process.poll() is None:
        try:
            match = TUNNEL_URL_RE.search(TUNNEL_LOG.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            match = None
        if match:
            return match.group(0)
        time.sleep(1)
    return None


def stop(process: Optional[subprocess.Popen], timeout: float = 8.0) -> None:
    """Stop one child without touching any other."""
    if process is None or process.poll() is not None:
        return
    try:
        process.send_signal(signal.SIGTERM)
        process.wait(timeout=timeout)
    except Exception:
        try:
            process.kill()
        except Exception:
            pass


def log(message: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {message}", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument(
        "--hostname",
        default=os.environ.get("EDGEDEFENSE_TUNNEL_HOSTNAME"),
        help=(
            "Named-tunnel hostname, e.g. mcp-tunnel.example.com. Without this a "
            "quick tunnel is used, whose address changes on every restart."
        ),
    )
    parser.add_argument("--branch", default="main", help="branch to track (default main)")
    parser.add_argument(
        "--check-every",
        type=float,
        default=300.0,
        help="seconds between update checks (default 300; 0 disables updating)",
    )
    args = parser.parse_args()

    cloudflared = find_cloudflared()
    if not cloudflared:
        print("cloudflared was not found. Install it and try again.", file=sys.stderr)
        return 1

    token = load_or_create_token()

    server = start_server(args.port, token)
    if not wait_for_health(args.port):
        print("Server did not come up. Is the port already in use?", file=sys.stderr)
        stop(server)
        return 1
    log(f"Server up on 127.0.0.1:{args.port} at {current_commit()[:8]}")

    tunnel = start_tunnel(cloudflared, args.port, args.hostname)

    if args.hostname:
        public = f"https://{args.hostname}"
        log(f"Named tunnel: {public} (stable across restarts)")
    else:
        public = read_quick_tunnel_url(tunnel) or ""
        if not public:
            print("Tunnel did not report a URL.", file=sys.stderr)
            stop(tunnel)
            stop(server)
            return 1
        log(f"Quick tunnel: {public}")
        log("This address CHANGES if the tunnel restarts. Use --hostname for a "
            "permanent one.")

    url = f"{public}/t/{token}/mcp"
    URL_FILE.write_text(url, encoding="utf-8")
    print()
    print(f"  Upstream origin (set EDGEDEFENSE_UPSTREAM to this): {public}")
    print(f"  Direct MCP URL:                                     {url}")
    print()
    print("  Treat the URL as a password: it grants a full inventory of this network.")
    print("  Ctrl+C to stop.")
    print()

    last_check = time.time()
    try:
        while True:
            time.sleep(2)

            # The tunnel is restarted only if it actually died. Leaving a
            # healthy tunnel alone is the entire point: its address is what
            # everything downstream is pointing at.
            if tunnel.poll() is not None:
                log("Tunnel exited; restarting it.")
                tunnel = start_tunnel(cloudflared, args.port, args.hostname)
                if not args.hostname:
                    fresh = read_quick_tunnel_url(tunnel)
                    if fresh and fresh != public:
                        public = fresh
                        url = f"{public}/t/{token}/mcp"
                        URL_FILE.write_text(url, encoding="utf-8")
                        log(f"NEW quick-tunnel address: {public}")
                        log("EDGEDEFENSE_UPSTREAM must be updated to match, or the "
                            "public URL stays broken.")

            if server.poll() is not None:
                log("Server exited; restarting it.")
                server = start_server(args.port, token)
                wait_for_health(args.port)

            if args.check_every and time.time() - last_check >= args.check_every:
                last_check = time.time()
                if pull_if_updated(args.branch):
                    # Restart the server alone. The tunnel keeps running, so the
                    # public address -- and every saved connector URL -- survives.
                    log("Restarting server to pick up new code (tunnel untouched).")
                    stop(server)
                    server = start_server(args.port, token)
                    if wait_for_health(args.port):
                        log("Back up. Same URL, new code.")
                    else:
                        log("Server did not come back up after the update.")

    except KeyboardInterrupt:
        print()
        log("Stopping ...")
        return 0
    finally:
        stop(tunnel)
        stop(server)


if __name__ == "__main__":
    raise SystemExit(main())
