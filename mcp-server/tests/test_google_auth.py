"""Google sign-in: claim validation and the allowlist.

Signing in with Google proves who someone is. It says nothing about whether
they may read this network, and conflating the two would let any Google account
on earth connect. Most of these tests exist to keep those separate.

No network is touched: the token exchange is the only part that talks to
Google, and the claim checks it feeds are tested directly.
"""

from __future__ import annotations

import base64
import json
import time

import pytest

from edgedefense_mcp.google_auth import (
    STATE_TTL,
    GoogleAuthError,
    GoogleAuthenticator,
    _decode_jwt_payload,
)

CLIENT_ID = "test-client.apps.googleusercontent.com"
ALLOWED = "owner@example.com"


@pytest.fixture()
def google() -> GoogleAuthenticator:
    return GoogleAuthenticator(
        client_id=CLIENT_ID,
        client_secret="secret",
        redirect_uri="https://mcp.edgedefenseai.com/auth/google/callback",
        allowed_emails=[ALLOWED, "Second.Person@Example.com"],
    )


def make_claims(**overrides) -> dict:
    claims = {
        "iss": "https://accounts.google.com",
        "aud": CLIENT_ID,
        "exp": time.time() + 3600,
        "email": ALLOWED,
        "email_verified": True,
    }
    claims.update(overrides)
    return claims


def encode(claims: dict) -> str:
    body = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    return f"header.{body}.signature"


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------


def test_allowlist_is_mandatory():
    """Without it, "signed in with Google" would mean "anyone at all"."""
    with pytest.raises(ValueError, match="allowed email"):
        GoogleAuthenticator(CLIENT_ID, "secret", "https://x/cb", allowed_emails=[])


def test_credentials_are_mandatory():
    with pytest.raises(ValueError):
        GoogleAuthenticator("", "", "https://x/cb", allowed_emails=[ALLOWED])


# --------------------------------------------------------------------------
# Authorisation, as distinct from authentication
# --------------------------------------------------------------------------


def test_allowed_address_is_permitted(google):
    assert google.is_allowed(ALLOWED) is True


def test_allowlist_ignores_case_and_whitespace(google):
    """Google addresses are not case sensitive; a config typo should not lock you out."""
    assert google.is_allowed("Owner@Example.COM") is True
    assert google.is_allowed("  second.person@example.com  ") is True


@pytest.mark.parametrize(
    "email",
    ["stranger@example.com", "", None, "owner@example.com.evil.com", "owner@evil.com"],
)
def test_other_addresses_are_refused(google, email):
    assert google.is_allowed(email) is False


# --------------------------------------------------------------------------
# Claim validation
# --------------------------------------------------------------------------


def test_valid_claims_accepted(google):
    google._validate(make_claims())  # must not raise


def test_token_for_another_application_is_refused(google):
    """Stops a token minted for a different app being replayed here."""
    with pytest.raises(GoogleAuthError, match="different application"):
        google._validate(make_claims(aud="someone-elses-client-id"))


def test_token_from_another_issuer_is_refused(google):
    with pytest.raises(GoogleAuthError, match="did not come from Google"):
        google._validate(make_claims(iss="https://accounts.evil.com"))


def test_expired_token_is_refused(google):
    with pytest.raises(GoogleAuthError, match="expired"):
        google._validate(make_claims(exp=time.time() - 10))


def test_missing_expiry_is_refused(google):
    with pytest.raises(GoogleAuthError):
        google._validate(make_claims(exp=None))


def test_unverified_email_is_refused(google):
    """An unverified address proves nothing about who is signing in."""
    with pytest.raises(GoogleAuthError, match="not verified"):
        google._validate(make_claims(email_verified=False))


def test_missing_email_is_refused(google):
    with pytest.raises(GoogleAuthError, match="email"):
        google._validate(make_claims(email=""))


def test_google_issuer_variants_both_accepted(google):
    google._validate(make_claims(iss="accounts.google.com"))
    google._validate(make_claims(iss="https://accounts.google.com"))


# --------------------------------------------------------------------------
# Token decoding
# --------------------------------------------------------------------------


def test_claims_decode_including_unpadded_base64():
    claims = make_claims(email="someone@example.com")
    assert _decode_jwt_payload(encode(claims))["email"] == "someone@example.com"


@pytest.mark.parametrize("bad", ["", "not-a-jwt", "a.b", "a.!!!.c"])
def test_malformed_tokens_raise_a_clear_error(bad):
    with pytest.raises(GoogleAuthError):
        _decode_jwt_payload(bad)


# --------------------------------------------------------------------------
# CSRF state
# --------------------------------------------------------------------------


def test_start_returns_a_google_url_carrying_state(google):
    url = google.start("txn-1")

    assert url.startswith("https://accounts.google.com/o/oauth2/v2/auth?")
    assert "state=" in url
    assert "openid+email+profile" in url or "openid%20email%20profile" in url


def test_state_round_trips_to_the_original_transaction(google):
    url = google.start("txn-42")
    state = url.split("state=")[1].split("&")[0]

    assert google.consume_state(state) == "txn-42"


def test_state_is_single_use(google):
    url = google.start("txn-1")
    state = url.split("state=")[1].split("&")[0]

    assert google.consume_state(state) == "txn-1"
    assert google.consume_state(state) is None


def test_forged_state_is_refused(google):
    """A forged callback must not be able to complete a pending authorization."""
    google.start("txn-1")
    assert google.consume_state("forged-state") is None


def test_expired_state_is_refused(google, monkeypatch):
    url = google.start("txn-1")
    state = url.split("state=")[1].split("&")[0]

    later = time.time() + STATE_TTL + 60
    monkeypatch.setattr(time, "time", lambda: later)

    assert google.consume_state(state) is None


def test_each_sign_in_gets_a_distinct_state(google):
    states = {google.start(f"txn-{i}").split("state=")[1].split("&")[0] for i in range(25)}
    assert len(states) == 25


def test_offline_access_is_never_requested(google):
    """We only need identity, so no refresh token should ever be issued to us."""
    assert "access_type=online" in google.start("txn-1")
