from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.responses import JSONResponse, RedirectResponse
from sse_starlette.sse import EventSourceResponse
import uuid
import time
import json
import asyncio
from typing import Dict

app = FastAPI(title="EdgeDefense Relay Server (Cloud)")

# --- OAuth Mock Logic (Keeping this intact) ---
oauth_clients: Dict[str, str] = {}
oauth_codes: Dict[str, dict] = {}

from pydantic import BaseModel
import hashlib
import base64

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
        "redirect_uris": reg.redirect_uris
    }

@app.get("/oauth/authorize")
async def oauth_authorize(
    client_id: str, 
    redirect_uri: str, 
    state: str, 
    code_challenge: str, 
    code_challenge_method: str = "S256"
):
    params = f"?client_id={client_id}&redirect_uri={redirect_uri}&state={state}&code_challenge={code_challenge}"
    return RedirectResponse(url=f"https://www.edgedefenseai.com/login{params}")

class GenerateCodeReq(BaseModel):
    token: str
    code_challenge: str
    redirect_uri: str

@app.post("/oauth/generate_code")
async def oauth_generate_code(req: GenerateCodeReq):
    code = str(uuid.uuid4())
    oauth_codes[code] = {
        "token": req.token,
        "code_challenge": req.code_challenge,
        "redirect_uri": req.redirect_uri,
        "expires_at": time.time() + 300 
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
        "code_challenge_methods_supported": ["S256"]
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
    
    digest = hashlib.sha256(code_verifier.encode('ascii')).digest()
    expected_challenge = base64.urlsafe_b64encode(digest).rstrip(b'=').decode('ascii')
    
    if expected_challenge != code_data["code_challenge"]:
        raise HTTPException(status_code=400, detail="invalid_grant pkce mismatch")
    
    token = code_data["token"]
    del oauth_codes[code] 
    
    return {
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": 31536000,
        "refresh_token": token
    }

@app.get("/health")
async def health_check():
    return {"status": "ok", "cloud_mcp": True, "agent_connected": not active_agent_queue.empty()}


# --- Relay Architecture (HTTP Long Polling) ---

# State
active_agent_queue: asyncio.Queue = asyncio.Queue()
active_sse_queues: Dict[str, asyncio.Queue] = {}

@app.get("/relay/poll")
async def relay_poll():
    """Edge Agent long-polls this endpoint to receive commands from Claude"""
    try:
        # Wait up to 30 seconds for a message
        msg = await asyncio.wait_for(active_agent_queue.get(), timeout=30.0)
        return JSONResponse(status_code=200, content={"message": msg})
    except asyncio.TimeoutError:
        return JSONResponse(status_code=200, content={"message": None})

@app.post("/relay/send")
async def relay_send(request: Request):
    """Edge Agent POSTs responses here, which are forwarded to Claude's SSE"""
    body = await request.body()
    data = body.decode("utf-8")
    for q in active_sse_queues.values():
        await q.put(data)
    return JSONResponse(status_code=202, content="Accepted")

@app.get("/mcp/connect")
async def mcp_connect(request: Request):
    """Claude Desktop connects here."""
    session_id = str(uuid.uuid4())
    q = asyncio.Queue()
    active_sse_queues[session_id] = q

    async def event_generator():
        try:
            # Send the endpoint URL so Claude knows where to POST messages
            yield {
                "event": "endpoint",
                "data": f"https://www.edgedefenseai.com/mcp/messages?session_id={session_id}"
            }
            # Read from queue and yield events
            while True:
                msg = await q.get()
                yield {
                    "event": "message",
                    "data": msg
                }
        except asyncio.CancelledError:
            pass
        finally:
            active_sse_queues.pop(session_id, None)

    return EventSourceResponse(event_generator())

@app.post("/mcp/messages")
async def mcp_messages(request: Request):
    """Claude Desktop POSTs JSON-RPC messages here."""
    session_id = request.query_params.get("session_id")
    if not session_id:
        raise HTTPException(status_code=400, detail="session_id required")
        
    body = await request.body()
    try:
        # Queue the message for the Edge Agent to pick up
        await active_agent_queue.put(body.decode("utf-8"))
        return JSONResponse(status_code=202, content="Accepted")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


def run():
    import uvicorn
    uvicorn.run("edgedefense_relay.main:app", host="0.0.0.0", port=8000, reload=False)

if __name__ == "__main__":
    run()
