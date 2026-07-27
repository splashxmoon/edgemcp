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
from contextlib import asynccontextmanager
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


def build_oauth_app(
    mcp_server: Any,
    passphrase: str,
    public_url: str,
    allowed_hosts: Optional[List[str]] = None,
) -> Any:
    """Build the app with a full OAuth 2.1 flow in front of the MCP endpoint.

    This is the path a URL-only client such as Claude's custom connector takes:
    it registers itself, sends the browser to ``/login`` on this server's own
    public URL, and receives a revocable token. The authorization server runs
    in this process -- there is no hosted identity service involved.
    """
    from mcp.server.auth.routes import create_auth_routes
    from mcp.server.auth.settings import ClientRegistrationOptions
    from pydantic import AnyHttpUrl
    from starlette.applications import Starlette
    from starlette.responses import HTMLResponse, RedirectResponse
    from starlette.routing import Mount, Route

    from .login_page import render_done, render_login
    from .oauth import SCOPE, EdgeDefenseAuthProvider

    provider = EdgeDefenseAuthProvider(passphrase=passphrase, public_url=public_url)
    issuer = AnyHttpUrl(public_url)

    _configure_security(mcp_server, allowed_hosts)
    mcp_server.settings.streamable_http_path = MCP_PATH

    async def login_form(request):
        txn_id = request.query_params.get("txn", "")
        txn = provider.transaction(txn_id)
        if txn is None:
            return HTMLResponse(
                render_login("", request.url.hostname or "",
                             error="This sign-in link has expired. Start again from your client."),
                status_code=400,
            )
        client = await provider.get_client(txn.client_id)
        name = getattr(client, "client_name", None) if client else None
        return HTMLResponse(render_login(txn_id, request.url.hostname or "", name))

    async def login_submit(request):
        form = await request.form()
        txn_id = str(form.get("txn", ""))
        supplied = str(form.get("passphrase", ""))

        txn = provider.transaction(txn_id)
        if txn is None:
            return HTMLResponse(
                render_login("", request.url.hostname or "",
                             error="This sign-in link has expired. Start again from your client."),
                status_code=400,
            )

        if not provider.check_passphrase(supplied):
            client = await provider.get_client(txn.client_id)
            return HTMLResponse(
                render_login(txn_id, request.url.hostname or "",
                             getattr(client, "client_name", None) if client else None,
                             error="That passphrase is not correct."),
                status_code=401,
            )

        redirect_to = provider.complete_login(txn_id)
        if not redirect_to:
            return HTMLResponse(render_done())
        return RedirectResponse(redirect_to, status_code=302)

    async def health(_request):
        from starlette.responses import JSONResponse

        return JSONResponse({"status": "ok"})

    routes = [
        Route("/login", login_form, methods=["GET"]),
        Route("/login", login_submit, methods=["POST"]),
        Route("/healthz", health, methods=["GET"]),
    ]
    routes.extend(
        create_auth_routes(
            provider=provider,
            issuer_url=issuer,
            client_registration_options=ClientRegistrationOptions(
                enabled=True, valid_scopes=[SCOPE], default_scopes=[SCOPE]
            ),
        )
    )

    # RFC 9728. This is how a client discovers which authorization server
    # guards this resource, so the flow can start from the MCP URL alone --
    # which is all the connector dialog is given.
    async def resource_metadata(_request):
        from starlette.responses import JSONResponse

        return JSONResponse(
            {
                "resource": f"{public_url}{MCP_PATH}",
                "authorization_servers": [public_url],
                "scopes_supported": [SCOPE],
                "bearer_methods_supported": ["header"],
            }
        )

    # Clients differ on whether the resource path is appended, so serve both.
    routes.insert(0, Route("/.well-known/oauth-protected-resource",
                           resource_metadata, methods=["GET"]))
    routes.insert(1, Route(f"/.well-known/oauth-protected-resource{MCP_PATH}",
                           resource_metadata, methods=["GET"]))

    # Bearer validation is done here rather than through FastMCP's auth
    # settings: those are wired during FastMCP construction, and this server's
    # instance is built at import time with tools attached by decorator. Doing
    # it in middleware keeps the check explicit and independently testable.
    protected = BearerAuthMiddleware(
        mcp_server.streamable_http_app(),
        provider,
        resource_metadata_url=f"{public_url}/.well-known/oauth-protected-resource",
    )
    routes.append(Mount("/", app=protected))

    # Starlette does not run a mounted sub-application's lifespan, and the
    # streamable-HTTP session manager is started there. Without this the OAuth
    # routes work, the token is accepted, and then every authenticated MCP
    # request fails inside an unstarted session manager.
    @asynccontextmanager
    async def lifespan(_app):
        async with mcp_server.session_manager.run():
            yield

    app = Starlette(routes=routes, lifespan=lifespan)
    app.state.oauth_provider = provider
    return app


class BearerAuthMiddleware:
    """Require a valid OAuth access token before reaching the MCP endpoint.

    On rejection it emits ``WWW-Authenticate`` naming the resource metadata
    document, which is what lets a client that was handed only the MCP URL
    discover where to authenticate and begin the flow.
    """

    def __init__(self, app: Any, provider: Any, resource_metadata_url: str) -> None:
        self.app = app
        self.provider = provider
        self.resource_metadata_url = resource_metadata_url

    async def __call__(self, scope: dict, receive: Callable, send: Callable) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        token = _bearer_token(scope)
        record = await self.provider.load_access_token(token) if token else None

        if record is None:
            body = (
                b'{"error":"invalid_token",'
                b'"error_description":"Authenticate to reach this MCP server."}'
            )
            await send(
                {
                    "type": "http.response.start",
                    "status": 401,
                    "headers": [
                        (b"content-type", b"application/json"),
                        (b"content-length", str(len(body)).encode()),
                        (
                            b"www-authenticate",
                            f'Bearer resource_metadata="{self.resource_metadata_url}"'.encode(),
                        ),
                    ],
                }
            )
            await send({"type": "http.response.body", "body": body})
            return

        await self.app(scope, receive, send)


def _bearer_token(scope: dict) -> Optional[str]:
    """Extract a bearer token from the Authorization header, if present."""
    for key, value in scope.get("headers", []):
        if key.lower() == b"authorization":
            raw = value.decode("latin-1").strip()
            if raw.lower().startswith("bearer "):
                return raw[7:].strip()
    return None


def _configure_security(mcp_server: Any, allowed_hosts: Optional[List[str]]) -> None:
    """Apply DNS-rebinding settings shared by both HTTP modes."""
    from mcp.server.transport_security import TransportSecuritySettings

    hosts = list(allowed_hosts or [])
    if "*" in hosts:
        security = TransportSecuritySettings(enable_dns_rebinding_protection=False)
    else:
        security = TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=hosts,
            allowed_origins=[f"http://{h}" for h in hosts] + [f"https://{h}" for h in hosts],
        )
    mcp_server.settings.transport_security = security


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
