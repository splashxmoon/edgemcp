"""EdgeDefense cloud relay.

Sits between Claude (which speaks MCP over HTTP/SSE) and the home agent
(which dials out over HTTP long polling), so the home agent never has to
accept an inbound connection. This process never scans anything itself --
every JSON-RPC message it handles is opaque text it forwards in one direction
or the other.

Because it forwards commands to a machine that can scan someone's home
network, every endpoint that moves a message -- /relay/poll, /relay/send,
/mcp/connect, /mcp/messages -- requires the same bearer token the home agent
was configured with. There is no tier of these endpoints that is safe to
leave open: even /relay/send, which only carries responses *back* toward
Claude, would let anyone who found the URL inject fabricated scan results
into a real session.

EDGEDEFENSE_RELAY_TOKEN must be set before this will serve authenticated
traffic. Without it, the protected endpoints answer 503 rather than silently
accepting every request -- a missing token must never be indistinguishable
from an intentionally open server.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import os
import time
import uuid
from contextlib import asynccontextmanager
from typing import Dict, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel
from sse_starlette.sse import EventSourceResponse

#: Constructed once uvicorn's event loop is actually running. asyncio.Queue no
#: longer strictly needs a running loop to build on modern Python, but binding
#: it inside the app's own lifespan is the version-independent way to get that
#: right rather than depending on an implementation detail.
active_agent_queue: Optional[asyncio.Queue] = None


@asynccontextmanager
async def lifespan(_app: FastAPI):
    global active_agent_queue
    active_agent_queue = asyncio.Queue()
    yield


app = FastAPI(title="EdgeDefense Relay Server (Cloud)", lifespan=lifespan)

#: The one secret this whole deployment turns on. Same value goes on the home
#: agent (EDGEDEFENSE_RELAY_TOKEN) and is what a visitor must type into the
#: login page to get a working connector.
RELAY_TOKEN: Optional[str] = os.environ.get("EDGEDEFENSE_RELAY_TOKEN")


def require_relay_token(authorization: Optional[str] = Header(None)) -> None:
    """FastAPI dependency guarding every endpoint that moves a real message.

    Compared with hmac.compare_digest rather than ==, which is not a
    theoretical concern for a token that is also usable as a login
    passphrase: a timing side-channel here would let an attacker recover it
    one character at a time.
    """
    if not RELAY_TOKEN:
        raise HTTPException(
            status_code=503,
            detail="Relay is not configured: EDGEDEFENSE_RELAY_TOKEN is not set.",
        )
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token.")
    supplied = authorization[len("Bearer ") :]
    if not hmac.compare_digest(supplied, RELAY_TOKEN):
        raise HTTPException(status_code=401, detail="Invalid token.")


# --------------------------------------------------------------------------
# OAuth: proves the browser knows the relay token before minting an
# access_token a client can use against the protected endpoints above.
# --------------------------------------------------------------------------

oauth_clients: Dict[str, str] = {}
oauth_codes: Dict[str, dict] = {}


class RegisterReq(BaseModel):
    client_name: str
    redirect_uris: list[str]


@app.post("/oauth/register")
async def oauth_register(reg: RegisterReq):
    client_id = str(uuid.uuid4())
    oauth_clients[client_id] = reg.redirect_uris[0] if reg.redirect_uris else ""
    return {
        "client_id": client_id,
        "client_secret": str(uuid.uuid4()),
        "client_id_issued_at": int(time.time()),
        "redirect_uris": reg.redirect_uris,
    }


@app.get("/oauth/authorize")
async def oauth_authorize(
    client_id: str,
    redirect_uri: str,
    state: str,
    code_challenge: str,
    code_challenge_method: str = "S256",
):
    params = f"?client_id={client_id}&redirect_uri={redirect_uri}&state={state}&code_challenge={code_challenge}"
    return RedirectResponse(url=f"https://www.edgedefenseai.com/login{params}")


class GenerateCodeReq(BaseModel):
    #: What the visitor typed into the login page. This is what makes "login"
    #: mean something -- it used to accept a client-supplied `token` from an
    #: anonymous session and echo it straight back as an access_token, which
    #: authenticated nothing: anyone could self-issue a session with zero
    #: credentials. Now the code is only ever minted for RELAY_TOKEN itself,
    #: and only after the passphrase is checked against it here.
    passphrase: str
    code_challenge: str
    redirect_uri: str


@app.post("/oauth/generate_code")
async def oauth_generate_code(req: GenerateCodeReq):
    if not RELAY_TOKEN:
        raise HTTPException(status_code=503, detail="Relay is not configured.")
    if not hmac.compare_digest(req.passphrase, RELAY_TOKEN):
        raise HTTPException(status_code=401, detail="Incorrect passphrase.")

    code = str(uuid.uuid4())
    oauth_codes[code] = {
        "token": RELAY_TOKEN,
        "code_challenge": req.code_challenge,
        "redirect_uri": req.redirect_uri,
        "expires_at": time.time() + 300,
    }
    return {"code": code}


@app.get("/.well-known/oauth-authorization-server")
async def oauth_metadata():
    return {
        "issuer": "https://www.edgedefenseai.com",
        "authorization_endpoint": "https://www.edgedefenseai.com/oauth/authorize",
        "token_endpoint": "https://www.edgedefenseai.com/oauth/token",
        "registration_endpoint": "https://www.edgedefenseai.com/oauth/register",
        "scopes_supported": ["mcp"],
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "code_challenge_methods_supported": ["S256"],
    }


@app.post("/oauth/token")
async def oauth_token(request: Request):
    content_type = request.headers.get("content-type", "")
    if "application/json" in content_type:
        data = await request.json()
        grant_type = data.get("grant_type")
        code = data.get("code")
        code_verifier = data.get("code_verifier")
    else:
        form = await request.form()
        grant_type = form.get("grant_type")
        code = form.get("code")
        code_verifier = form.get("code_verifier")

    if grant_type != "authorization_code":
        raise HTTPException(status_code=400, detail="unsupported_grant_type")

    code_data = oauth_codes.get(code)
    if not code_data:
        raise HTTPException(status_code=400, detail="invalid_grant")

    if time.time() > code_data["expires_at"]:
        del oauth_codes[code]
        raise HTTPException(status_code=400, detail="invalid_grant expired")

    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    expected_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

    if not hmac.compare_digest(expected_challenge, code_data["code_challenge"]):
        raise HTTPException(status_code=400, detail="invalid_grant pkce mismatch")

    token = code_data["token"]
    del oauth_codes[code]

    return {
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": 31536000,
        "refresh_token": token,
    }


# --------------------------------------------------------------------------
# The relay itself
# --------------------------------------------------------------------------

active_sse_queues: Dict[str, asyncio.Queue] = {}


@app.get("/health")
async def health_check():
    connected = active_agent_queue is not None and not active_agent_queue.empty()
    return {"status": "ok", "cloud_mcp": True, "agent_connected": connected}


@app.get("/relay/poll", dependencies=[Depends(require_relay_token)])
async def relay_poll():
    """The home agent long-polls this to receive commands from Claude."""
    try:
        msg = await asyncio.wait_for(active_agent_queue.get(), timeout=30.0)
        return JSONResponse(status_code=200, content={"message": msg})
    except asyncio.TimeoutError:
        return JSONResponse(status_code=200, content={"message": None})


@app.post("/relay/send", dependencies=[Depends(require_relay_token)])
async def relay_send(request: Request):
    """The home agent POSTs responses here; forwarded to whoever is listening."""
    body = await request.body()
    data = body.decode("utf-8")
    for q in active_sse_queues.values():
        await q.put(data)
    return JSONResponse(status_code=202, content="Accepted")


@app.get("/mcp/connect", dependencies=[Depends(require_relay_token)])
async def mcp_connect(request: Request):
    """Claude connects here over SSE."""
    session_id = str(uuid.uuid4())
    q: asyncio.Queue = asyncio.Queue()
    active_sse_queues[session_id] = q

    async def event_generator():
        try:
            endpoint_url = f"https://www.edgedefenseai.com/mcp/messages?session_id={session_id}"
            yield {"event": "endpoint", "data": endpoint_url}
            while True:
                msg = await q.get()
                yield {"event": "message", "data": msg}
        except asyncio.CancelledError:
            pass
        finally:
            active_sse_queues.pop(session_id, None)

    return EventSourceResponse(event_generator())


@app.post("/mcp/messages", dependencies=[Depends(require_relay_token)])
async def mcp_messages(request: Request):
    """Claude POSTs JSON-RPC messages here; queued for the home agent."""
    session_id = request.query_params.get("session_id")
    if not session_id:
        raise HTTPException(status_code=400, detail="session_id required")

    body = await request.body()
    try:
        await active_agent_queue.put(body.decode("utf-8"))
        return JSONResponse(status_code=202, content="Accepted")
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=str(exc)) from exc


def run() -> None:
    import uvicorn

    uvicorn.run("edgedefense_relay.main:app", host="0.0.0.0", port=8000, reload=False)


if __name__ == "__main__":
    run()
