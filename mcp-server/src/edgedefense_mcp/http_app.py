"""Streamable HTTP transport, for use as a remote MCP connector.

Read this before deploying: it changes the tool's security posture.

In stdio mode the server is reachable only by the process that launched it.
Over HTTP it is reachable by anything that can route to the port, and what it
exposes is a full inventory of the devices on your home network. That is
exactly the information an attacker would want first. So HTTP mode is opt-in,
binds to loopback by default, and refuses to listen on a routable address
without a token.

Authentication is a shared secret, accepted two ways:

* ``Authorization: Bearer <token>`` -- for clients that can set headers.
* ``/t/<token>/mcp`` in the URL path -- for clients that cannot. Claude's
  "Add custom connector" dialog takes only a URL, so this is the form that
  works there. The token is then as sensitive as a password: anyone with the
  link has the same access you do.

This is a capability URL, not a substitute for real authorization. It is
appropriate for a personal tunnel to your own machine and nothing more.
"""

from __future__ import annotations

import hmac
import ipaddress
import secrets
import sys
from typing import Any, Callable, List, Optional

#: Where the MCP endpoint lives beneath any token prefix.
MCP_PATH = "/mcp"

#: Prefix used for the in-URL token form.
TOKEN_PATH_PREFIX = "/t/"


def generate_token() -> str:
    """A token with enough entropy to sit in a public URL."""
    return secrets.token_urlsafe(32)


def is_loopback(host: str) -> bool:
    """True if binding to ``host`` keeps the server off the network."""
    if host in ("localhost", ""):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class TokenAuthMiddleware:
    """ASGI middleware enforcing the shared secret before anything else runs.

    Rejects unauthenticated requests at the edge, so an unauthorised caller
    never reaches the MCP session layer and cannot learn whether a session
    exists, which tools are registered, or anything about the network.
    """

    def __init__(self, app: Any, token: Optional[str]) -> None:
        self.app = app
        self.token = token
        self._prefix = f"{TOKEN_PATH_PREFIX}{token}" if token else None

    async def __call__(self, scope: dict, receive: Callable, send: Callable) -> None:
        if scope["type"] != "http" or not self.token:
            await self.app(scope, receive, send)
            return

        path: str = scope.get("path", "")

        # Unauthenticated liveness probe. Deliberately says nothing beyond
        # "something is listening" -- useful for checking a tunnel is up
        # without handing an anonymous caller any detail about the host.
        if path == "/healthz":
            await _plain_response(send, 200, b'{"status":"ok"}', b"application/json")
            return

        if self._authorised_by_path(path):
            scope = dict(scope)
            remainder = path[len(self._prefix) :] or "/"
            scope["path"] = remainder
            # Starlette routes on raw_path when present, so it must agree.
            if scope.get("raw_path"):
                scope["raw_path"] = remainder.encode()
        elif not self._authorised_by_header(scope):
            await _plain_response(
                send,
                401,
                b'{"error":"unauthorized",'
                b'"detail":"Supply the token as an Authorization: Bearer header, '
                b'or use the /t/<token>/mcp URL form."}',
                b"application/json",
            )
            return

        await self.app(scope, receive, send)

    def _authorised_by_path(self, path: str) -> bool:
        if not self._prefix:
            return False
        if not (path == self._prefix or path.startswith(self._prefix + "/")):
            return False
        # Compare the supplied segment in constant time even though the prefix
        # check above already matched: keeps the comparison uniform.
        supplied = path[len(TOKEN_PATH_PREFIX) :].split("/", 1)[0]
        return hmac.compare_digest(supplied, self.token or "")

    def _authorised_by_header(self, scope: dict) -> bool:
        for key, value in scope.get("headers", []):
            if key.lower() != b"authorization":
                continue
            raw = value.decode("latin-1").strip()
            prefix = "bearer "
            if raw.lower().startswith(prefix):
                return hmac.compare_digest(raw[len(prefix) :].strip(), self.token or "")
        return False


async def _plain_response(send: Callable, status: int, body: bytes, media: bytes) -> None:
    """Emit a complete ASGI response without depending on a framework."""
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", media),
                (b"content-length", str(len(body)).encode()),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


def build_app(
    mcp_server: Any,
    token: Optional[str],
    allowed_hosts: Optional[List[str]] = None,
) -> Any:
    """Wrap the FastMCP streamable-HTTP app with authentication.

    Args:
        mcp_server: The configured :class:`FastMCP` instance.
        token: Shared secret, or None to serve unauthenticated (loopback only).
        allowed_hosts: Hostnames permitted by DNS-rebinding protection. Use
            ``["*"]`` to disable that check, which is only reasonable when a
            token is set -- a tunnel presents its own hostname, which cannot be
            known in advance.

    Returns:
        An ASGI application.
    """
    from mcp.server.transport_security import TransportSecuritySettings

    hosts = list(allowed_hosts or [])
    if "*" in hosts:
        # A tunnel's hostname is not knowable ahead of time. The token is the
        # control that matters in that deployment; host checking is not.
        security = TransportSecuritySettings(enable_dns_rebinding_protection=False)
    else:
        security = TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=hosts,
            allowed_origins=[f"http://{h}" for h in hosts] + [f"https://{h}" for h in hosts],
        )

    mcp_server.settings.transport_security = security
    mcp_server.settings.streamable_http_path = MCP_PATH

    return TokenAuthMiddleware(mcp_server.streamable_http_app(), token)


def describe_endpoints(host: str, port: int, token: Optional[str]) -> str:
    """The exact URL to paste into a client, printed at startup."""
    base = f"http://{host}:{port}"
    if not token:
        return (
            f"  Endpoint : {base}{MCP_PATH}\n"
            "  Auth     : none (loopback only)\n"
        )
    return (
        f"  Endpoint : {base}{TOKEN_PATH_PREFIX}{token}{MCP_PATH}\n"
        f"  Or header: Authorization: Bearer {token}\n"
        f"  Health   : {base}/healthz\n"
    )


def warn(message: str) -> None:
    """Startup diagnostics go to stderr, never stdout."""
    print(message, file=sys.stderr)
