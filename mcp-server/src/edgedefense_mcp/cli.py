"""Command line entry point.

``edgedefense-mcp`` with no arguments is stdio, which is what every local
client expects and what the README documents. HTTP mode exists for remote
connectors -- clients that take a URL rather than spawning a process -- and is
opt-in precisely because it turns a local-only tool into a listening service.
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import List, Optional

from . import __version__
from .http_app import (
    MCP_PATH,
    build_app,
    describe_endpoints,
    generate_token,
    is_loopback,
    warn,
)

DEFAULT_PORT = 8765

#: Read when --token is not passed, so the secret need not appear in shell history.
TOKEN_ENV_VAR = "EDGEDEFENSE_TOKEN"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="edgedefense-mcp",
        description=(
            "EdgeDefense MCP server. Answers questions about the local network. "
            "Defaults to stdio, which is what Claude Code, Claude Desktop, Cursor, "
            "Codex and VS Code use."
        ),
        epilog=(
            "HTTP mode serves a remote MCP connector. The server still only ever sees "
            "the network of the machine it runs on, so it must run at home -- hosting "
            "it elsewhere would scan that host's network instead."
        ),
    )
    parser.add_argument("--version", action="version", version=f"edgedefense-mcp {__version__}")

    transport = parser.add_argument_group("transport")
    transport.add_argument(
        "--http",
        action="store_true",
        help="serve Streamable HTTP instead of stdio (for remote connectors)",
    )
    transport.add_argument(
        "--host",
        default="127.0.0.1",
        help="address to bind in HTTP mode (default: 127.0.0.1, loopback only)",
    )
    transport.add_argument(
        "--port", type=int, default=DEFAULT_PORT,
        help=f"port to bind in HTTP mode (default: {DEFAULT_PORT})",
    )

    security = parser.add_argument_group("security")
    security.add_argument(
        "--token",
        default=None,
        help=(
            "shared secret required to reach the server. Read from "
            f"${TOKEN_ENV_VAR} when omitted. Generated automatically, and printed, "
            "if the bind address is reachable from the network"
        ),
    )
    security.add_argument(
        "--allow-host", action="append", default=[], metavar="HOST",
        help=(
            "hostname to accept in DNS-rebinding checks; repeatable. Pass the "
            "hostname clients will use, e.g. mcp.edgedefenseai.com. Use '*' to "
            "disable host checking, which is only sensible behind a token"
        ),
    )
    security.add_argument(
        "--insecure-no-token", action="store_true",
        help="permit a network-reachable bind with no token. Not advisable",
    )
    return parser


def resolve_token(args: argparse.Namespace) -> Optional[str]:
    """Decide the shared secret, generating one when exposure demands it."""
    token = args.token or os.environ.get(TOKEN_ENV_VAR) or None

    if token or is_loopback(args.host):
        return token

    if args.insecure_no_token:
        warn(
            "WARNING: serving on a network-reachable address with no token. Anyone "
            "who can reach this port can enumerate every device on your network."
        )
        return None

    token = generate_token()
    warn("No token supplied for a network-reachable bind, so one was generated.")
    return token


def run_http(args: argparse.Namespace) -> int:
    """Serve Streamable HTTP. Returns a process exit code."""
    try:
        import uvicorn
    except ImportError:
        warn(
            "HTTP mode needs uvicorn, which normally ships with the MCP SDK. "
            "Install it with: pip install uvicorn"
        )
        return 1

    from .server import mcp

    token = resolve_token(args)
    allowed: List[str] = list(args.allow_host)
    if not allowed:
        allowed = [
            f"{args.host}:{args.port}", args.host,
            f"localhost:{args.port}", "localhost",
            f"127.0.0.1:{args.port}", "127.0.0.1",
        ]

    app = build_app(mcp, token=token, allowed_hosts=allowed)

    warn("")
    warn("EdgeDefense MCP - HTTP mode")
    warn(describe_endpoints(args.host, args.port, token))
    if token:
        warn("  Treat the URL as a password: it grants a full inventory of this network.")
    if not is_loopback(args.host):
        warn("  Bound to a network-reachable address.")
    warn("  Scans still cover only this machine's network. Nothing is uploaded.")
    warn("")

    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    if args.http:
        return run_http(args)

    # stdio: the default path, unchanged and dependency-free.
    from .server import mcp

    mcp.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
