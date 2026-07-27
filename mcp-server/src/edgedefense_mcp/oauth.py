"""A self-contained OAuth 2.1 authorization server for the MCP endpoint.

Why this exists: MCP clients that take a URL rather than a command -- Claude's
"Add custom connector" among them -- can perform an OAuth flow, which is a far
better experience than pasting a secret URL. Clicking connect opens a browser,
you sign in on your own domain, and the client holds a revocable token
afterwards.

Why it is *local*: the authorization server runs inside the same process as the
MCP server, on your machine. There is no hosted identity service, no account,
and no third party in the loop. That matters because the whole product premise
is that nothing about your network leaves your machine -- adding a cloud login
to reach a local network scanner would trade the premise away for nothing.

The trust model is therefore deliberately small: one operator, one passphrase.
This is not multi-tenant identity and does not pretend to be. It exists to stop
anyone who finds the URL from enumerating your network, and to give the client
a credential you can revoke by restarting.
"""

from __future__ import annotations

import hmac
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    OAuthAuthorizationServerProvider,
    RefreshToken,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

#: Access tokens are short-lived; refresh tokens carry the session.
ACCESS_TOKEN_TTL = 3600
REFRESH_TOKEN_TTL = 30 * 24 * 3600
#: A login must be completed promptly once started.
LOGIN_TXN_TTL = 600
AUTH_CODE_TTL = 300

#: The single scope this server understands.
SCOPE = "edgedefense"


@dataclass
class _LoginTransaction:
    """An authorization request parked while the operator signs in."""

    client_id: str
    params: AuthorizationParams
    created_at: float = field(default_factory=time.time)

    def expired(self) -> bool:
        return time.time() - self.created_at > LOGIN_TXN_TTL


class EdgeDefenseAuthProvider(
    OAuthAuthorizationServerProvider[AuthorizationCode, RefreshToken, AccessToken]
):
    """OAuth 2.1 provider backed by a single operator passphrase.

    Dynamic client registration is accepted because MCP clients register
    themselves on first connect; there is no console for pre-provisioning one.
    Registration alone grants nothing -- a client still cannot obtain a token
    without the passphrase.
    """

    def __init__(self, passphrase: str, public_url: str) -> None:
        if not passphrase:
            raise ValueError("OAuth mode requires a passphrase")
        self._passphrase = passphrase
        self.public_url = public_url.rstrip("/")

        self._clients: Dict[str, OAuthClientInformationFull] = {}
        self._transactions: Dict[str, _LoginTransaction] = {}
        self._codes: Dict[str, AuthorizationCode] = {}
        self._access: Dict[str, AccessToken] = {}
        self._refresh: Dict[str, RefreshToken] = {}

    # -- passphrase ------------------------------------------------------

    def check_passphrase(self, supplied: str) -> bool:
        """Constant-time comparison, so timing cannot reveal the passphrase."""
        return hmac.compare_digest(supplied or "", self._passphrase)

    # -- client registration ---------------------------------------------

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        self._clients[client_info.client_id] = client_info

    async def get_client(self, client_id: str) -> Optional[OAuthClientInformationFull]:
        return self._clients.get(client_id)

    # -- authorization ----------------------------------------------------

    async def authorize(
        self, client: OAuthClientInformationFull, params: AuthorizationParams
    ) -> str:
        """Park the request and send the browser to our own login page.

        Returning a URL here is what produces the "opens in the browser"
        behaviour: the SDK redirects, the operator sees a page on their own
        domain, and only afterwards is an authorization code minted.
        """
        self._sweep()
        txn_id = secrets.token_urlsafe(24)
        self._transactions[txn_id] = _LoginTransaction(
            client_id=client.client_id, params=params
        )
        return f"{self.public_url}/login?{urlencode({'txn': txn_id})}"

    def transaction(self, txn_id: str) -> Optional[_LoginTransaction]:
        txn = self._transactions.get(txn_id)
        if txn and txn.expired():
            self._transactions.pop(txn_id, None)
            return None
        return txn

    def complete_login(self, txn_id: str) -> Optional[str]:
        """Consume a transaction and return the client's redirect URL.

        Called only after the passphrase has been verified.
        """
        txn = self._transactions.pop(txn_id, None)
        if txn is None or txn.expired():
            return None

        params = txn.params
        code_value = secrets.token_urlsafe(32)
        self._codes[code_value] = AuthorizationCode(
            code=code_value,
            scopes=params.scopes or [SCOPE],
            expires_at=time.time() + AUTH_CODE_TTL,
            client_id=txn.client_id,
            code_challenge=params.code_challenge,
            redirect_uri=params.redirect_uri,
            redirect_uri_provided_explicitly=params.redirect_uri_provided_explicitly,
            resource=params.resource,
            subject="operator",
        )

        query = {"code": code_value}
        if params.state:
            query["state"] = params.state
        separator = "&" if "?" in str(params.redirect_uri) else "?"
        return f"{params.redirect_uri}{separator}{urlencode(query)}"

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> Optional[AuthorizationCode]:
        code = self._codes.get(authorization_code)
        if code is None or code.client_id != client.client_id:
            return None
        if code.expires_at < time.time():
            self._codes.pop(authorization_code, None)
            return None
        return code

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        # Single use: a replayed code must not yield a second token.
        self._codes.pop(authorization_code.code, None)
        return self._issue(client.client_id, authorization_code.scopes,
                           resource=authorization_code.resource)

    # -- tokens -----------------------------------------------------------

    def _issue(
        self, client_id: str, scopes: List[str], resource: Optional[str] = None
    ) -> OAuthToken:
        access_value = secrets.token_urlsafe(32)
        refresh_value = secrets.token_urlsafe(32)
        now = time.time()

        self._access[access_value] = AccessToken(
            token=access_value, client_id=client_id, scopes=scopes,
            expires_at=int(now + ACCESS_TOKEN_TTL), resource=resource,
            subject="operator",
        )
        self._refresh[refresh_value] = RefreshToken(
            token=refresh_value, client_id=client_id, scopes=scopes,
            expires_at=int(now + REFRESH_TOKEN_TTL), subject="operator",
        )
        return OAuthToken(
            access_token=access_value,
            token_type="Bearer",
            expires_in=ACCESS_TOKEN_TTL,
            scope=" ".join(scopes),
            refresh_token=refresh_value,
        )

    async def load_access_token(self, token: str) -> Optional[AccessToken]:
        record = self._access.get(token)
        if record is None:
            return None
        if record.expires_at and record.expires_at < time.time():
            self._access.pop(token, None)
            return None
        return record

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> Optional[RefreshToken]:
        record = self._refresh.get(refresh_token)
        if record is None or record.client_id != client.client_id:
            return None
        if record.expires_at and record.expires_at < time.time():
            self._refresh.pop(refresh_token, None)
            return None
        return record

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: List[str],
    ) -> OAuthToken:
        # Rotate: the presented refresh token is retired as it is redeemed.
        self._refresh.pop(refresh_token.token, None)
        return self._issue(client.client_id, scopes or refresh_token.scopes)

    async def revoke_token(self, token: Any) -> None:
        value = getattr(token, "token", None)
        if value:
            self._access.pop(value, None)
            self._refresh.pop(value, None)

    # -- housekeeping ------------------------------------------------------

    def _sweep(self) -> None:
        """Drop expired transactions and codes so memory cannot grow unbounded."""
        now = time.time()
        for key, txn in list(self._transactions.items()):
            if txn.expired():
                self._transactions.pop(key, None)
        for key, code in list(self._codes.items()):
            if code.expires_at < now:
                self._codes.pop(key, None)
