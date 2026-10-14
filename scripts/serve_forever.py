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
only the server is restarted when new code lands. With ``--hostname`` and
``--tunnel`` the tunnel is a *named* one, whose address never changes -- at which point
the public URL is genuinely permanent and nothing downstream needs updating,
ever.

Typical use, after the one-time named-tunnel setup described in the README:

    python scripts/serve_forever.py --hostname mcp.edgedefenseai.com --tunnel edgedefense-mcp --oauth

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
PASSPHRASE_FILE = REPO_ROOT / ".edgedefense-passphrase"
TUNNEL_LOG = REPO_ROOT / ".cloudflared-tunnel.log"
SERVER_LOG = REPO_ROOT / ".edgedefense-server.log"
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


def load_or_create_token(path: Optional[Path] = None) -> str:
    """Reuse the saved token so the URL survives restarts."""
    import secrets

    path = path or TOKEN_FILE
    if path.exists():
        token = path.read_text(encoding="utf-8").strip()
        if token:
            return token
    token = secrets.token_urlsafe(32)
    path.write_text(token, encoding="utf-8")
    try:
        os.chmod(path, 0o600)
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
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=2) as response:
                if response.status == 200:
                    return True
        except Exception:
            time.sleep(0.5)
    return False


def start_server(port: int, token: str, hostname: Optional[str] = None,
                 oauth: bool = False) -> subprocess.Popen:
    """Launch the MCP server.

    ``--json-response`` is not optional behind a tunnel and a serverless proxy:
    streamed responses get buffered somewhere in that chain, and stateful
    sessions break when two requests land on different proxy instances.
    """
    command = [
        sys.executable, "-m", "edgedefense_mcp", "--http",
        "--port", str(port), "--allow-host", hostname or "*", "--json-response",
    ]
    env = dict(os.environ)
    if oauth:
        command.extend(["--oauth", "--public-url", f"https://{hostname}"])
        env["EDGEDEFENSE_PASSPHRASE"] = token
    else:
        env["EDGEDEFENSE_TOKEN"] = token
    with open(SERVER_LOG, "a", encoding="utf-8") as handle:
        return subprocess.Popen(
            command, cwd=REPO_ROOT, env=env,
            stdout=subprocess.DEVNULL, stderr=handle,
        )


def start_tunnel(cloudflared: str, port: int, tunnel: Optional[str]) -> subprocess.Popen:
    """Launch cloudflared, named if a hostname was configured.

    cloudflared logs continuously, so its output goes to a file rather than a
    pipe. Reading only the first few lines of a pipe and leaving the rest
    unread eventually fills the OS buffer, at which point cloudflared blocks on
    write and quietly stops serving while still looking alive.
    """
    if tunnel:
        args = [cloudflared, "tunnel", "run", "--url", f"http://127.0.0.1:{port}", tunnel]
    else:
        args = [cloudflared, "tunnel", "--url", f"http://127.0.0.1:{port}", "--no-autoupdate"]

    with open(TUNNEL_LOG, "w", encoding="utf-8") as handle:
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


UPSTREAM_RE = re.compile(r"(export const UPSTREAM_FALLBACK = ')([^']*)(';)")


def publish_upstream(site_repo: Path, origin: str) -> bool:
    """Write the tunnel origin into the site repo and push it.

    This closes the loop for quick tunnels. The site's MCP proxy has to know
    the current tunnel hostname; that hostname is only knowable here, on the
    machine the tunnel points at; and it changes without warning. So the
    machine that knows publishes it, and the site redeploys itself.

    Only that one file is committed. Whatever else is in the site working tree
    is somebody's work in progress and is none of this script's business.
    """
    target = site_repo / "app" / "mcp" / "upstream.js"
    if not target.is_file():
        log(f"No upstream.js at {target}; skipping publish.")
        return False

    text = target.read_text(encoding="utf-8")
    match = UPSTREAM_RE.search(text)
    if not match:
        log("upstream.js does not have the expected shape; leaving it alone.")
        return False
    if match.group(2) == origin:
        return False  # Already correct; an empty commit would just be noise.

    target.write_text(UPSTREAM_RE.sub(rf"\g<1>{origin}\g<3>", text, count=1), encoding="utf-8")

    def run(*args: str) -> int:
        return subprocess.run(args, cwd=site_repo, capture_output=True).returncode

    if run("git", "add", "app/mcp/upstream.js") != 0:
        log("Could not stage upstream.js.")
        return False
    if run("git", "commit", "-m", f"Point the MCP proxy at {origin}") != 0:
        log("Nothing to commit, or the commit failed.")
        return False
    if run("git", "push", "origin", "HEAD") != 0:
        log("Push failed -- check credentials for the site repo.")
        return False

    log("Published the new upstream to the site repo; a redeploy should follow.")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument(
        "--hostname",
        default=os.environ.get("EDGEDEFENSE_TUNNEL_HOSTNAME"),
        help=(
            "Public hostname, e.g. mcp.edgedefenseai.com. Without this a "
            "quick tunnel is used, whose address changes on every restart."
        ),
    )
    parser.add_argument(
        "--tunnel", default=os.environ.get("EDGEDEFENSE_TUNNEL_ID"),
        help="Cloudflare tunnel name or UUID (separate from the public hostname)",
    )
    parser.add_argument(
        "--oauth", action="store_true",
        help="browser sign-in at /mcp; requires a named tunnel and hostname",
    )
    parser.add_argument("--branch", default="main", help="branch to track (default main)")
    parser.add_argument(
        "--site-repo",
        default=os.environ.get("EDGEDEFENSE_SITE_REPO"),
        help=(
            "Path to the website repo. When a quick tunnel changes address, the "
            "new origin is committed to app/mcp/upstream.js and pushed, so the "
            "proxy redeploys pointing at the right place. Unnecessary with "
            "--hostname, whose address never changes."
        ),
    )
    parser.add_argument(
        "--check-every",
        type=float,
        default=300.0,
        help="seconds between update checks (default 300; 0 disables updating)",
    )
    args = parser.parse_args()

    if bool(args.hostname) != bool(args.tunnel):
        parser.error("--hostname and --tunnel must be supplied together")
    if args.oauth and not args.hostname:
        parser.error("--oauth requires --hostname and --tunnel")
    if args.hostname and not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?", args.hostname):
        parser.error("--hostname must be a DNS hostname, without a scheme, port or path")

    cloudflared = find_cloudflared()
    if not cloudflared:
        print("cloudflared was not found. Install it and try again.", file=sys.stderr)
        return 1

    if args.oauth:
        token = os.environ.get("EDGEDEFENSE_PASSPHRASE") or load_or_create_token(PASSPHRASE_FILE)
    else:
        token = load_or_create_token()

    server = start_server(args.port, token, args.hostname, args.oauth)
    if not wait_for_health(args.port):
        print("Server did not come up. Is the port already in use?", file=sys.stderr)
        stop(server)
        return 1
    log(f"Server up on 127.0.0.1:{args.port} at {current_commit()[:8]}")

    tunnel = start_tunnel(cloudflared, args.port, args.tunnel)

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

    url = f"{public}/mcp" if args.oauth else f"{public}/t/{token}/mcp"
    URL_FILE.write_text(url, encoding="utf-8")

    site_repo = Path(args.site_repo).expanduser() if args.site_repo else None
    if site_repo and not args.hostname:
        publish_upstream(site_repo, public)
    print()
    print(f"  Upstream origin (set EDGEDEFENSE_UPSTREAM to this): {public}")
    print(f"  Direct MCP URL:                                     {url}")
    print()
    if args.oauth:
        print("  Connect using browser sign-in. Leave client OAuth fields empty.")
        if not os.environ.get("EDGEDEFENSE_PASSPHRASE"):
            print(f"  Sign-in passphrase is stored locally in: {PASSPHRASE_FILE}")
    else:
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
                tunnel = start_tunnel(cloudflared, args.port, args.tunnel)
                if not args.hostname:
                    fresh = read_quick_tunnel_url(tunnel)
                    if fresh and fresh != public:
                        public = fresh
                        url = f"{public}/t/{token}/mcp"
                        URL_FILE.write_text(url, encoding="utf-8")
                        log(f"NEW quick-tunnel address: {public}")
                        if site_repo:
                            publish_upstream(site_repo, public)
                        else:
                            log("Nothing points at this yet. Pass --site-repo to have "
                                "the new address published automatically, or update "
                                "EDGEDEFENSE_UPSTREAM by hand.")

            if server.poll() is not None:
                log("Server exited; restarting it.")
                server = start_server(args.port, token, args.hostname, args.oauth)
                wait_for_health(args.port)

            if args.check_every and time.time() - last_check >= args.check_every:
                last_check = time.time()
                if pull_if_updated(args.branch):
                    # Restart the server alone. The tunnel keeps running, so the
                    # public address -- and every saved connector URL -- survives.
                    log("Restarting server to pick up new code (tunnel untouched).")
                    stop(server)
                    server = start_server(args.port, token, args.hostname, args.oauth)
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
