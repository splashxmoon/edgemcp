"""Auth-boundary tests for the cloud relay.

The relay forwards commands to a machine that can scan someone's home
network, so "every message-moving endpoint requires the token, no
exceptions" is the one property that must never regress silently. This
module exists because that property regressed once already: the original
version had a complete OAuth dance that never actually gated anything.
"""

from __future__ import annotations

import base64
import hashlib
import secrets

import pytest
from fastapi.testclient import TestClient

TOKEN = "test-relay-secret-do-not-use-in-prod"


@pytest.fixture
def client(monkeypatch):
    """A configured relay, isolated per test so global state cannot leak."""
    monkeypatch.setenv("EDGEDEFENSE_RELAY_TOKEN", TOKEN)

    import importlib

    from edgedefense_relay import main as relay_main

    importlib.reload(relay_main)  # re-read RELAY_TOKEN from the env just set
    with TestClient(relay_main.app) as test_client:
        yield test_client


@pytest.fixture
def unconfigured_client(monkeypatch):
    """A relay with no token set at all -- the out-of-the-box state."""
    monkeypatch.delenv("EDGEDEFENSE_RELAY_TOKEN", raising=False)

    import importlib

    from edgedefense_relay import main as relay_main

    importlib.reload(relay_main)
    with TestClient(relay_main.app) as test_client:
        yield test_client


AUTH = {"Authorization": f"Bearer {TOKEN}"}

# Every endpoint that moves a real message toward or away from the home
# agent. If a new one is added and forgotten here, that is exactly the class
# of bug this file exists to catch.
PROTECTED_GET = ["/relay/poll", "/mcp/connect"]
PROTECTED_POST = ["/relay/send", "/mcp/messages?session_id=abc"]


class TestUnauthenticatedRequestsAreRejected:
    def test_get_endpoints_reject_no_header(self, client):
        for path in PROTECTED_GET:
            response = client.get(path)
            assert response.status_code == 401, path

    def test_post_endpoints_reject_no_header(self, client):
        for path in PROTECTED_POST:
            response = client.post(path, content=b"{}")
            assert response.status_code == 401, path

    def test_wrong_token_is_rejected(self, client):
        bad = {"Authorization": "Bearer not-the-real-token"}
        assert client.get("/relay/poll", headers=bad).status_code == 401

    def test_malformed_header_is_rejected(self, client):
        # No "Bearer " prefix -- a client sending the raw token would fail
        # exactly like a client sending nothing, not silently succeed.
        bad = {"Authorization": TOKEN}
        assert client.get("/relay/poll", headers=bad).status_code == 401


class TestServerRefusesToRunUnconfigured:
    """A missing token must read as 'not configured', never as 'open'."""

    def test_protected_endpoints_503_without_a_configured_token(self, unconfigured_client):
        response = unconfigured_client.get("/relay/poll")
        assert response.status_code == 503

    def test_generate_code_503_without_a_configured_token(self, unconfigured_client):
        response = unconfigured_client.post(
            "/oauth/generate_code",
            json={"passphrase": "anything", "code_challenge": "x", "redirect_uri": "https://x"},
        )
        assert response.status_code == 503


class TestCorrectTokenIsAccepted:
    def test_relay_poll_accepts_the_real_token(self, client):
        # 30s long-poll with nothing queued would hang the test; this only
        # proves the auth gate passes, not the polling behaviour itself.
        response = client.get("/relay/poll", headers=AUTH)
        assert response.status_code == 200

    def test_relay_send_accepts_the_real_token(self, client):
        response = client.post("/relay/send", headers=AUTH, content=b'{"ok":true}')
        assert response.status_code == 202


class TestLoginNoLongerIssuesFreeTokens:
    """The bug this whole file exists to prevent from coming back.

    The original /oauth/generate_code accepted whatever `token` the browser
    supplied and handed it straight back as an access_token -- meaning
    anonymous sign-in (proving nothing) was sufficient to obtain a working
    credential. The fix is that a code is only ever minted for RELAY_TOKEN
    itself, and only after the caller demonstrates they know it.
    """

    def _pkce_pair(self):
        verifier = secrets.token_urlsafe(32)
        digest = hashlib.sha256(verifier.encode("ascii")).digest()
        challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
        return verifier, challenge

    def test_wrong_passphrase_is_rejected(self, client):
        _, challenge = self._pkce_pair()
        response = client.post(
            "/oauth/generate_code",
            json={
                "passphrase": "guessing",
                "code_challenge": challenge,
                "redirect_uri": "https://claude.ai/api/mcp/auth_callback",
            },
        )
        assert response.status_code == 401

    def test_correct_passphrase_yields_a_code_that_exchanges_for_the_real_token(self, client):
        verifier, challenge = self._pkce_pair()
        generated = client.post(
            "/oauth/generate_code",
            json={
                "passphrase": TOKEN,
                "code_challenge": challenge,
                "redirect_uri": "https://claude.ai/api/mcp/auth_callback",
            },
        )
        assert generated.status_code == 200
        code = generated.json()["code"]

        exchanged = client.post(
            "/oauth/token",
            json={"grant_type": "authorization_code", "code": code, "code_verifier": verifier},
        )
        assert exchanged.status_code == 200
        # This is the property that matters: no matter what a client claims
        # during login, the credential it ends up with is always the one true
        # secret -- never a value the client itself supplied.
        assert exchanged.json()["access_token"] == TOKEN

    def test_generated_access_token_actually_works_against_protected_endpoints(self, client):
        verifier, challenge = self._pkce_pair()
        code = client.post(
            "/oauth/generate_code",
            json={"passphrase": TOKEN, "code_challenge": challenge, "redirect_uri": "https://x"},
        ).json()["code"]
        access_token = client.post(
            "/oauth/token",
            json={"grant_type": "authorization_code", "code": code, "code_verifier": verifier},
        ).json()["access_token"]

        response = client.get(
            "/relay/poll", headers={"Authorization": f"Bearer {access_token}"}
        )
        assert response.status_code == 200

    def test_pkce_mismatch_is_rejected(self, client):
        _, challenge = self._pkce_pair()
        code = client.post(
            "/oauth/generate_code",
            json={"passphrase": TOKEN, "code_challenge": challenge, "redirect_uri": "https://x"},
        ).json()["code"]

        wrong_verifier, _ = self._pkce_pair()
        response = client.post(
            "/oauth/token",
            json={
                "grant_type": "authorization_code",
                "code": code,
                "code_verifier": wrong_verifier,
            },
        )
        assert response.status_code == 400


class TestNoDebugLeak:
    def test_debug_logs_endpoint_no_longer_exists(self, client):
        """It used to expose every session id and message body, unauthenticated."""
        response = client.get("/mcp/debug_logs")
        assert response.status_code == 404


class TestHealthNeedsNoAuth:
    def test_health_is_reachable_without_a_token(self, client):
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "ok"
