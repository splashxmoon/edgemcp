"""Optional "Sign in with Google" for the browser sign-in flow.

This is the one place in the project that talks to a third party, and only
while somebody is signing in. Scanning still makes no outbound request of any
kind. That distinction is worth keeping straight, and is stated in the README
rather than left for someone to discover.

Access is decided by an explicit email allowlist. Google tells us *who* is
signing in; it does not decide *whether* they may. Without an allowlist any
Google account on earth would satisfy the "signed in" test, so an empty
allowlist is a configuration error rather than a permissive default.
"""

from __future__ import annotations

import base64
import json
import secrets
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlencode

GOOGLE_AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
GOOGLE_ISSUERS = ("https://accounts.google.com", "accounts.google.com")

#: A sign-in round trip should not stay valid for long.
STATE_TTL = 600


class GoogleAuthError(Exception):
    """Raised with a message safe to render on the sign-in page."""


@dataclass
class _PendingSignIn:
    """A Google round trip in flight, tied back to an MCP authorization."""

    txn_id: str
    created_at: float = field(default_factory=time.time)

    def expired(self) -> bool:
        return time.time() - self.created_at > STATE_TTL


def _decode_jwt_payload(token: str) -> Dict:
    """Read an ID token's claims.

    The signature is deliberately not re-verified. This token is not accepted
    from the browser: it is fetched by this server directly from Google's token
    endpoint over TLS, in exchange for a code, using the client secret. OpenID
    Connect Core section 3.1.3.7 explicitly permits skipping signature checks
    when the token arrives that way, because TLS plus client authentication
    already establishes both origin and integrity. The claims below are still
    validated.
    """
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception as exc:
        raise GoogleAuthError("Google returned a malformed sign-in token.") from exc


class GoogleAuthenticator:
    """Runs the Google side of the sign-in and enforces the allowlist."""

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        allowed_emails: List[str],
    ) -> None:
        if not client_id or not client_secret:
            raise ValueError("Google sign-in needs a client ID and secret")
        if not allowed_emails:
            raise ValueError(
                "Google sign-in needs at least one allowed email address. Without one, "
                "any Google account could connect."
            )

        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        # Case-insensitive: Google addresses are not case sensitive.
        self.allowed_emails = {e.strip().lower() for e in allowed_emails if e.strip()}
        self._pending: Dict[str, _PendingSignIn] = {}

    # -- outbound -------------------------------------------------------

    def start(self, txn_id: str) -> str:
        """Return the Google URL to send the browser to."""
        self._sweep()
        state = secrets.token_urlsafe(24)
        self._pending[state] = _PendingSignIn(txn_id=txn_id)

        query = {
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "response_type": "code",
            "scope": "openid email profile",
            "state": state,
            # We only need identity, so never ask for offline access.
            "access_type": "online",
            "prompt": "select_account",
        }
        return f"{GOOGLE_AUTH_ENDPOINT}?{urlencode(query)}"

    def consume_state(self, state: str) -> Optional[str]:
        """Validate the CSRF state and return the MCP transaction it belongs to."""
        pending = self._pending.pop(state, None)
        if pending is None or pending.expired():
            return None
        return pending.txn_id

    # -- inbound --------------------------------------------------------

    async def exchange(self, code: str) -> Tuple[str, Dict]:
        """Swap the code for an ID token and return (email, claims)."""
        import httpx

        try:
            async with httpx.AsyncClient(timeout=20.0) as http:
                response = await http.post(
                    GOOGLE_TOKEN_ENDPOINT,
                    data={
                        "code": code,
                        "client_id": self.client_id,
                        "client_secret": self.client_secret,
                        "redirect_uri": self.redirect_uri,
                        "grant_type": "authorization_code",
                    },
                )
        except Exception as exc:
            raise GoogleAuthError(
                "Could not reach Google to complete sign-in. Check this machine's "
                "internet connection and try again."
            ) from exc

        if response.status_code != 200:
            raise GoogleAuthError(
                "Google rejected the sign-in. Check that the client ID, secret and "
                "redirect URI in Google Cloud Console match this server exactly."
            )

        id_token = response.json().get("id_token")
        if not id_token:
            raise GoogleAuthError("Google did not return an identity token.")

        claims = _decode_jwt_payload(id_token)
        self._validate(claims)
        return claims.get("email", "").lower(), claims

    def _validate(self, claims: Dict) -> None:
        """Check the claims that decide whether this sign-in counts."""
        if claims.get("iss") not in GOOGLE_ISSUERS:
            raise GoogleAuthError("Sign-in token did not come from Google.")

        # Guards against a token minted for a different application being
        # replayed here.
        if claims.get("aud") != self.client_id:
            raise GoogleAuthError("Sign-in token was issued for a different application.")

        expires = claims.get("exp")
        if not expires or float(expires) < time.time():
            raise GoogleAuthError("Sign-in token has expired. Please try again.")

        if not claims.get("email"):
            raise GoogleAuthError("Google did not share an email address.")

        # An unverified address proves nothing about who is signing in.
        if claims.get("email_verified") not in (True, "true"):
            raise GoogleAuthError("That Google account's email address is not verified.")

    def is_allowed(self, email: str) -> bool:
        """Authorisation, as distinct from authentication."""
        return (email or "").strip().lower() in self.allowed_emails

    def _sweep(self) -> None:
        for state, pending in list(self._pending.items()):
            if pending.expired():
                self._pending.pop(state, None)
