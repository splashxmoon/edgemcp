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
EMAIL = "owner@example.com"
PASSWORD = "correct horse battery staple"


@pytest.fixture
def client(monkeypatch):
    """A fully configured relay, isolated per test so global state cannot leak."""
    monkeypatch.setenv("EDGEDEFENSE_RELAY_TOKEN", TOKEN)
    monkeypatch.setenv("EDGEDEFENSE_LOGIN_EMAIL", EMAIL)
    monkeypatch.setenv("EDGEDEFENSE_LOGIN_PASSWORD", PASSWORD)

    import importlib

    from edgedefense_relay import main as relay_main

    importlib.reload(relay_main)  # re-read the env vars just set
    with TestClient(relay_main.app) as test_client:
        yield test_client


@pytest.fixture
def unconfigured_client(monkeypatch):
    """A relay with none of the three secrets set -- the out-of-the-box state."""
    for var in ("EDGEDEFENSE_RELAY_TOKEN", "EDGEDEFENSE_LOGIN_EMAIL", "EDGEDEFENSE_LOGIN_PASSWORD"):
        monkeypatch.delenv(var, raising=False)

    import importlib

    from edgedefense_relay import main as relay_main

    importlib.reload(relay_main)
    with TestClient(relay_main.app) as test_client:
        yield test_client


@pytest.fixture
def missing_login_client(monkeypatch):
    """RELAY_TOKEN is set but the login credentials are not -- a partial setup."""
    monkeypatch.setenv("EDGEDEFENSE_RELAY_TOKEN", TOKEN)
    monkeypatch.delenv("EDGEDEFENSE_LOGIN_EMAIL", raising=False)
    monkeypatch.delenv("EDGEDEFENSE_LOGIN_PASSWORD", raising=False)

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

    def test_generate_code_503_without_any_config(self, unconfigured_client):
        response = unconfigured_client.post(
            "/oauth/generate_code",
            json={"email": "x", "password": "x", "code_challenge": "x", "redirect_uri": "https://x"},
        )
        assert response.status_code == 503

    def test_generate_code_503_when_login_credentials_are_unset(self, missing_login_client):
        """A relay token with no login credentials is still not safe to serve.

        Otherwise the failure mode of "I set one env var but forgot the other
        two" is a relay that answers requests it should be refusing.
        """
        response = missing_login_client.post(
            "/oauth/generate_code",
            json={"email": "x", "password": "x", "code_challenge": "x", "redirect_uri": "https://x"},
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
    itself, and only after the caller's email and password are checked
    against the ones configured on the relay -- two credentials, and neither
    of them is the token that ends up being issued.
    """

    def _pkce_pair(self):
        verifier = secrets.token_urlsafe(32)
        digest = hashlib.sha256(verifier.encode("ascii")).digest()
        challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
        return verifier, challenge

    def _generate_code(self, client, email, password, challenge):
        return client.post(
            "/oauth/generate_code",
            json={
                "email": email,
                "password": password,
                "code_challenge": challenge,
                "redirect_uri": "https://claude.ai/api/mcp/auth_callback",
            },
        )

    def test_wrong_password_is_rejected(self, client):
        _, challenge = self._pkce_pair()
        response = self._generate_code(client, EMAIL, "guessing", challenge)
        assert response.status_code == 401

    def test_wrong_email_is_rejected(self, client):
        _, challenge = self._pkce_pair()
        response = self._generate_code(client, "someone-else@example.com", PASSWORD, challenge)
        assert response.status_code == 401

    def test_email_comparison_is_case_insensitive(self, client):
        """A typed-in email shouldn't fail over capitalization."""
        _, challenge = self._pkce_pair()
        response = self._generate_code(client, EMAIL.upper(), PASSWORD, challenge)
        assert response.status_code == 200

    def test_correct_credentials_yield_a_code_that_exchanges_for_the_relay_token(self, client):
        verifier, challenge = self._pkce_pair()
        generated = self._generate_code(client, EMAIL, PASSWORD, challenge)
        assert generated.status_code == 200
        code = generated.json()["code"]

        exchanged = client.post(
            "/oauth/token",
            json={"grant_type": "authorization_code", "code": code, "code_verifier": verifier},
        )
        assert exchanged.status_code == 200
        # This is the property that matters: no matter what a client claims
        # during login, the credential it ends up with is always the one real
        # RELAY_TOKEN -- never the email or password themselves, and never a
        # value the client supplied.
        assert exchanged.json()["access_token"] == TOKEN
        assert exchanged.json()["access_token"] not in (EMAIL, PASSWORD)

    def test_generated_access_token_actually_works_against_protected_endpoints(self, client):
        verifier, challenge = self._pkce_pair()
        code = self._generate_code(client, EMAIL, PASSWORD, challenge).json()["code"]
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
        code = self._generate_code(client, EMAIL, PASSWORD, challenge).json()["code"]

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
