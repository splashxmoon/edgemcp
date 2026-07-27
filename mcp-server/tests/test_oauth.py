"""OAuth 2.1 authorization server: the flow, and the properties that secure it.

The valuable tests here are the negative ones. This flow stands between the
public internet and a complete inventory of a home network, so what matters is
that a wrong passphrase, a replayed code, a forged token or an expired link all
fail closed.
"""

from __future__ import annotations

import asyncio
import time
from urllib.parse import parse_qs, urlparse

import pytest
from mcp.server.auth.provider import AuthorizationParams
from mcp.shared.auth import OAuthClientInformationFull

from edgedefense_mcp.cli import build_parser, main as cli_main
from edgedefense_mcp.http_app import BearerAuthMiddleware
from edgedefense_mcp.login_page import render_login
from edgedefense_mcp.oauth import LOGIN_TXN_TTL, EdgeDefenseAuthProvider

PASSPHRASE = "open-sesame-please"
PUBLIC = "https://mcp.edgedefenseai.com"
REDIRECT = "https://claude.ai/api/mcp/auth_callback"


def run(coro):
    return asyncio.run(coro)


@pytest.fixture()
def provider() -> EdgeDefenseAuthProvider:
    return EdgeDefenseAuthProvider(passphrase=PASSPHRASE, public_url=PUBLIC)


@pytest.fixture()
def client() -> OAuthClientInformationFull:
    return OAuthClientInformationFull(
        client_id="client-123",
        client_name="Claude",
        redirect_uris=[REDIRECT],
        grant_types=["authorization_code", "refresh_token"],
        response_types=["code"],
    )


def make_params(state: str = "state-abc") -> AuthorizationParams:
    return AuthorizationParams(
        state=state,
        scopes=["edgedefense"],
        code_challenge="challenge-value",
        redirect_uri=REDIRECT,
        redirect_uri_provided_explicitly=True,
    )


async def _authorize(provider, client, params=None):
    await provider.register_client(client)
    url = await provider.authorize(client, params or make_params())
    return parse_qs(urlparse(url).query)["txn"][0]


# --------------------------------------------------------------------------
# Passphrase
# --------------------------------------------------------------------------


def test_correct_passphrase_accepted(provider):
    assert provider.check_passphrase(PASSPHRASE) is True


@pytest.mark.parametrize("wrong", ["", "nope", PASSPHRASE + "x", PASSPHRASE[:-1], None])
def test_wrong_passphrase_rejected(provider, wrong):
    assert provider.check_passphrase(wrong) is False


def test_provider_refuses_to_start_without_a_passphrase():
    """An empty passphrase would let anyone who finds the page connect."""
    with pytest.raises(ValueError):
        EdgeDefenseAuthProvider(passphrase="", public_url=PUBLIC)


# --------------------------------------------------------------------------
# Authorization
# --------------------------------------------------------------------------


def test_authorize_sends_the_browser_to_our_own_login_page(provider, client):
    """The whole point: sign-in happens on the operator's domain."""
    run(provider.register_client(client))
    url = run(provider.authorize(client, make_params()))

    assert url.startswith(f"{PUBLIC}/login?")
    assert "txn=" in url


def test_login_issues_a_code_and_preserves_state(provider, client):
    txn = run(_authorize(provider, client))
    redirect = provider.complete_login(txn)

    query = parse_qs(urlparse(redirect).query)
    assert redirect.startswith(REDIRECT)
    assert query["code"][0]
    # Losing state would break the client's CSRF protection.
    assert query["state"] == ["state-abc"]


def test_a_login_transaction_is_single_use(provider, client):
    txn = run(_authorize(provider, client))
    assert provider.complete_login(txn) is not None
    assert provider.complete_login(txn) is None


def test_expired_login_link_is_refused(provider, client, monkeypatch):
    """A sign-in link left open for hours must not still mint a token."""
    txn = run(_authorize(provider, client))
    # Advance wall-clock time past the transaction TTL. It has to be the epoch
    # clock the provider uses -- monotonic() is seconds since boot and would
    # move the clock backwards.
    later = time.time() + LOGIN_TXN_TTL + 60
    monkeypatch.setattr(time, "time", lambda: later)

    assert provider.transaction(txn) is None
    assert provider.complete_login(txn) is None


def test_unknown_transaction_is_refused(provider):
    assert provider.transaction("never-issued") is None
    assert provider.complete_login("never-issued") is None


# --------------------------------------------------------------------------
# Codes and tokens
# --------------------------------------------------------------------------


def test_code_exchanges_for_access_and_refresh_tokens(provider, client):
    txn = run(_authorize(provider, client))
    code_value = parse_qs(urlparse(provider.complete_login(txn)).query)["code"][0]

    code = run(provider.load_authorization_code(client, code_value))
    assert code is not None
    token = run(provider.exchange_authorization_code(client, code))

    assert token.access_token and token.refresh_token
    assert token.token_type == "Bearer"


def test_authorization_code_cannot_be_replayed(provider, client):
    """A leaked code must not yield a second token."""
    txn = run(_authorize(provider, client))
    code_value = parse_qs(urlparse(provider.complete_login(txn)).query)["code"][0]

    code = run(provider.load_authorization_code(client, code_value))
    run(provider.exchange_authorization_code(client, code))

    assert run(provider.load_authorization_code(client, code_value)) is None


def test_a_code_belongs_to_the_client_that_requested_it(provider, client):
    txn = run(_authorize(provider, client))
    code_value = parse_qs(urlparse(provider.complete_login(txn)).query)["code"][0]

    other = OAuthClientInformationFull(
        client_id="someone-else", redirect_uris=[REDIRECT],
        grant_types=["authorization_code"], response_types=["code"],
    )
    assert run(provider.load_authorization_code(other, code_value)) is None


def test_issued_access_token_validates(provider, client):
    txn = run(_authorize(provider, client))
    code_value = parse_qs(urlparse(provider.complete_login(txn)).query)["code"][0]
    code = run(provider.load_authorization_code(client, code_value))
    token = run(provider.exchange_authorization_code(client, code))

    record = run(provider.load_access_token(token.access_token))
    assert record is not None and record.client_id == client.client_id


@pytest.mark.parametrize("forged", ["forged", "", "Bearer x", "a" * 43])
def test_forged_access_tokens_are_rejected(provider, forged):
    assert run(provider.load_access_token(forged)) is None


def test_refresh_rotates_and_retires_the_old_token(provider, client):
    txn = run(_authorize(provider, client))
    code_value = parse_qs(urlparse(provider.complete_login(txn)).query)["code"][0]
    code = run(provider.load_authorization_code(client, code_value))
    first = run(provider.exchange_authorization_code(client, code))

    refresh = run(provider.load_refresh_token(client, first.refresh_token))
    second = run(provider.exchange_refresh_token(client, refresh, ["edgedefense"]))

    assert second.access_token != first.access_token
    # The redeemed refresh token must not work twice.
    assert run(provider.load_refresh_token(client, first.refresh_token)) is None


def test_revoking_a_token_invalidates_it(provider, client):
    txn = run(_authorize(provider, client))
    code_value = parse_qs(urlparse(provider.complete_login(txn)).query)["code"][0]
    code = run(provider.load_authorization_code(client, code_value))
    token = run(provider.exchange_authorization_code(client, code))

    record = run(provider.load_access_token(token.access_token))
    run(provider.revoke_token(record))

    assert run(provider.load_access_token(token.access_token)) is None


# --------------------------------------------------------------------------
# Bearer middleware
# --------------------------------------------------------------------------


class StubApp:
    def __init__(self):
        self.called = False

    async def __call__(self, scope, receive, send):
        self.called = True
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})


async def _invoke(mw, headers=None):
    scope = {"type": "http", "path": "/mcp", "method": "POST",
             "headers": [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()]}
    out = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(m):
        out.append(m)

    await mw(scope, receive, send)
    start = next(m for m in out if m["type"] == "http.response.start")
    return start["status"], {k.decode(): v.decode() for k, v in start["headers"]}


def test_unauthenticated_mcp_request_is_rejected_before_reaching_the_server(provider):
    stub = StubApp()
    mw = BearerAuthMiddleware(stub, provider, f"{PUBLIC}/.well-known/oauth-protected-resource")

    status, _ = run(_invoke(mw))

    assert status == 401
    assert stub.called is False


def test_rejection_advertises_where_to_authenticate(provider):
    """RFC 9728: this is how a client given only the MCP URL finds the flow."""
    mw = BearerAuthMiddleware(StubApp(), provider,
                              f"{PUBLIC}/.well-known/oauth-protected-resource")
    _, headers = run(_invoke(mw))

    assert "resource_metadata" in headers["www-authenticate"]
    assert PUBLIC in headers["www-authenticate"]


def test_valid_token_passes_through(provider, client):
    txn = run(_authorize(provider, client))
    code_value = parse_qs(urlparse(provider.complete_login(txn)).query)["code"][0]
    code = run(provider.load_authorization_code(client, code_value))
    token = run(provider.exchange_authorization_code(client, code))

    stub = StubApp()
    mw = BearerAuthMiddleware(stub, provider, f"{PUBLIC}/.well-known/oauth-protected-resource")
    status, _ = run(_invoke(mw, {"Authorization": f"Bearer {token.access_token}"}))

    assert status == 200
    assert stub.called is True


# --------------------------------------------------------------------------
# Login page
# --------------------------------------------------------------------------


def test_login_page_escapes_the_client_supplied_name():
    """client_name arrives via dynamic registration and is attacker-controlled."""
    page = render_login("txn1", "mcp.edgedefenseai.com", '<script>alert(1)</script>')

    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;" in page


def test_login_page_states_what_is_being_granted():
    page = render_login("txn1", "mcp.edgedefenseai.com", "Claude")
    assert "read-only" in page.lower()
    assert "Nothing is uploaded" in page


def test_login_page_has_no_external_requests():
    """A passphrase page must not fetch anything from a third party."""
    page = render_login("txn1", "mcp.edgedefenseai.com", "Claude")
    for marker in ("http://", "https://", "src=", "@import"):
        assert marker not in page, f"login page references {marker}"


# --------------------------------------------------------------------------
# CLI guards
# --------------------------------------------------------------------------


def test_oauth_requires_a_public_url(capsys, monkeypatch):
    monkeypatch.delenv("EDGEDEFENSE_PASSPHRASE", raising=False)
    assert cli_main(["--http", "--oauth", "--passphrase", "x"]) == 2
    assert "--public-url" in capsys.readouterr().err


def test_oauth_requires_a_passphrase(capsys, monkeypatch):
    monkeypatch.delenv("EDGEDEFENSE_PASSPHRASE", raising=False)
    assert cli_main(["--http", "--oauth", "--public-url", PUBLIC]) == 2
    assert "passphrase" in capsys.readouterr().err


def test_passphrase_can_come_from_the_environment(monkeypatch):
    monkeypatch.setenv("EDGEDEFENSE_PASSPHRASE", "from-env")
    args = build_parser().parse_args(["--http", "--oauth", "--public-url", PUBLIC])
    assert args.passphrase is None  # supplied via environment instead
