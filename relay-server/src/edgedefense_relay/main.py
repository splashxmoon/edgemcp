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

@app.post("/oauth/token")
async def oauth_token(request: Request):
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
        "expires_in": 31536000 
    }

@app.get("/health")
async def health_check():
    return {"status": "ok", "cloud_mcp": True, "agent_connected": active_agent_ws is not None}


# --- Relay Architecture ---

# State
active_agent_ws: WebSocket = None
active_sse_queues: Dict[str, asyncio.Queue] = {}

@app.websocket("/ws/agent")
async def websocket_agent_endpoint(websocket: WebSocket):
    global active_agent_ws
    await websocket.accept()
    active_agent_ws = websocket
    print("Edge Agent connected to Cloud Relay!")
    try:
        while True:
            data = await websocket.receive_text()
            # The agent sends responses. We forward them to the SSE queues.
            # In a multi-client setup, we'd route by session_id.
            # Here we broadcast to all active SSE connections (usually just Claude Desktop)
            for q in active_sse_queues.values():
                await q.put(data)
    except WebSocketDisconnect:
        print("Edge Agent disconnected.")
        active_agent_ws = None

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
                "data": f"/mcp/messages?session_id={session_id}"
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
    
    if not active_agent_ws:
        raise HTTPException(status_code=503, detail="No Edge Agent connected to Relay")
        
    body = await request.body()
    try:
        # Forward directly to the Edge Agent over WebSocket
        await active_agent_ws.send_text(body.decode("utf-8"))
        return JSONResponse(status_code=202, content="Accepted")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


def run():
    import uvicorn
    uvicorn.run("edgedefense_relay.main:app", host="0.0.0.0", port=8000, reload=False)

if __name__ == "__main__":
    run()
