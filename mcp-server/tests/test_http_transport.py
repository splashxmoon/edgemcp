"""HTTP transport: authentication, and the defaults that keep it safe.

Over HTTP this server hands out a complete inventory of a home network, so the
tests that matter most are the ones proving an unauthenticated caller gets
nothing at all -- not a tool list, not a session, not an error that reveals
whether a session exists.

The middleware is exercised directly through the ASGI interface rather than
through a web framework, which keeps these fast and free of test-only deps.
"""

from __future__ import annotations

import json

import pytest

from edgedefense_mcp.cli import build_parser, resolve_token
from edgedefense_mcp.http_app import (
    TokenAuthMiddleware,
    generate_token,
    is_loopback,
)

TOKEN = "s3cret-token-value"


class StubApp:
    """Records whether it was reached, and with what path."""

    def __init__(self) -> None:
        self.called = False
        self.seen_path: str | None = None

    async def __call__(self, scope, receive, send):
        self.called = True
        self.seen_path = scope.get("path")
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"reached"})


async def _invoke(middleware, path: str, headers=None):
    """Drive an ASGI app and collect its response."""
    scope = {
        "type": "http",
        "path": path,
        "raw_path": path.encode(),
        "method": "POST",
        "headers": [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()],
    }
    messages = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        messages.append(message)

    await middleware(scope, receive, send)
    status = next((m["status"] for m in messages if m["type"] == "http.response.start"), None)
    body = b"".join(m.get("body", b"") for m in messages if m["type"] == "http.response.body")
    return status, body


def run(coro):
    import asyncio

    return asyncio.run(coro)


# --------------------------------------------------------------------------
# Authentication
# --------------------------------------------------------------------------


def test_request_without_credentials_is_rejected():
    stub = StubApp()
    status, body = run(_invoke(TokenAuthMiddleware(stub, TOKEN), "/mcp"))

    assert status == 401
    assert stub.called is False, "unauthenticated request reached the MCP layer"
    assert b"unauthorized" in body


@pytest.mark.parametrize(
    "path,headers",
    [
        ("/t/wrong-token/mcp", None),
        ("/mcp", {"Authorization": "Bearer wrong-token"}),
        ("/mcp", {"Authorization": "Basic " + TOKEN}),      # wrong scheme
        ("/mcp", {"Authorization": TOKEN}),                  # no scheme
        ("/t/" + TOKEN[:-1] + "/mcp", None),                 # near-miss token
    ],
    ids=["bad-path-token", "bad-bearer", "wrong-scheme", "no-scheme", "near-miss"],
)
def test_bad_credentials_are_rejected(path, headers):
    stub = StubApp()
    status, _ = run(_invoke(TokenAuthMiddleware(stub, TOKEN), path, headers))

    assert status == 401
    assert stub.called is False


def test_token_in_url_path_authenticates_and_prefix_is_stripped():
    """Claude's connector dialog accepts only a URL, so this form must work."""
    stub = StubApp()
    status, body = run(_invoke(TokenAuthMiddleware(stub, TOKEN), f"/t/{TOKEN}/mcp"))

    assert status == 200
    assert body == b"reached"
    # The wrapped app must see the real endpoint, not the token-bearing path.
    assert stub.seen_path == "/mcp"


def test_bearer_header_authenticates():
    stub = StubApp()
    status, _ = run(
        _invoke(TokenAuthMiddleware(stub, TOKEN), "/mcp",
                {"Authorization": f"Bearer {TOKEN}"})
    )

    assert status == 200
    assert stub.seen_path == "/mcp"


def test_bearer_scheme_is_case_insensitive():
    stub = StubApp()
    status, _ = run(
        _invoke(TokenAuthMiddleware(stub, TOKEN), "/mcp",
                {"Authorization": f"bearer {TOKEN}"})
    )
    assert status == 200


def test_health_endpoint_needs_no_credentials_and_leaks_nothing():
    """Useful for checking a tunnel is up; must not describe the host."""
    stub = StubApp()
    status, body = run(_invoke(TokenAuthMiddleware(stub, TOKEN), "/healthz"))

    assert status == 200
    assert json.loads(body) == {"status": "ok"}
    assert stub.called is False


def test_no_token_configured_means_no_gate():
    """Loopback-only mode stays frictionless."""
    stub = StubApp()
    status, _ = run(_invoke(TokenAuthMiddleware(stub, None), "/mcp"))

    assert status == 200
    assert stub.called is True


# --------------------------------------------------------------------------
# Defaults that decide exposure
# --------------------------------------------------------------------------


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "::1", ""])
def test_loopback_addresses_recognised(host):
    assert is_loopback(host) is True


@pytest.mark.parametrize("host", ["0.0.0.0", "192.168.1.10", "edgedefenseai.com"])
def test_routable_addresses_recognised(host):
    assert is_loopback(host) is False


def test_binding_to_the_network_generates_a_token_when_none_given():
    """Exposing an inventory of the network unauthenticated must not be the default."""
    args = build_parser().parse_args(["--http", "--host", "0.0.0.0"])
    token = resolve_token(args)

    assert token, "a network-reachable bind was left unauthenticated"
    assert len(token) >= 32


def test_loopback_bind_stays_tokenless():
    args = build_parser().parse_args(["--http"])
    assert resolve_token(args) is None


def test_explicit_token_is_respected():
    args = build_parser().parse_args(["--http", "--host", "0.0.0.0", "--token", "mine"])
    assert resolve_token(args) == "mine"


def test_token_can_come_from_the_environment(monkeypatch):
    """Keeps the secret out of shell history and process listings."""
    monkeypatch.setenv("EDGEDEFENSE_TOKEN", "from-env")
    args = build_parser().parse_args(["--http", "--host", "0.0.0.0"])
    assert resolve_token(args) == "from-env"


def test_opting_out_of_the_token_is_possible_but_explicit():
    args = build_parser().parse_args(
        ["--http", "--host", "0.0.0.0", "--insecure-no-token"]
    )
    assert resolve_token(args) is None


def test_generated_tokens_are_unique_and_url_safe():
    tokens = {generate_token() for _ in range(50)}
    assert len(tokens) == 50
    for token in tokens:
        assert "/" not in token and "?" not in token and "#" not in token


# --------------------------------------------------------------------------
# CLI contract
# --------------------------------------------------------------------------


def test_stdio_remains_the_default():
    """Every documented local client spawns us with no arguments."""
    args = build_parser().parse_args([])
    assert args.http is False


def test_http_defaults_to_loopback():
    args = build_parser().parse_args(["--http"])
    assert args.host == "127.0.0.1"
    assert args.port == 8765
