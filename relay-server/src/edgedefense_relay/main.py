import asyncio
import json
import logging
from typing import Dict, Any, Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, Depends, HTTPException, status
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel
import time
import uuid
import hashlib
import base64
from sse_starlette.sse import EventSourceResponse

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="EdgeDefense Relay Server")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory registries
# Maps user_id -> active WebSocket connection
active_uplinks: Dict[str, WebSocket] = {}

# Maps user_id -> asyncio.Queue for SSE messages going to Claude
active_sse_queues: Dict[str, asyncio.Queue] = {}


import os
from supabase import create_client, Client

# --- Authentication ---
# Connect to Supabase to verify the JWT token
async def get_user_id(token: str) -> str:
    if not token:
        raise HTTPException(status_code=401, detail="Token required")
    
    supabase_url = os.getenv("SUPABASE_URL")
    supabase_key = os.getenv("SUPABASE_KEY")
    
    if not supabase_url or not supabase_key:
        logger.warning("SUPABASE_URL or SUPABASE_KEY missing. Falling back to mock auth.")
        return token
        
    try:
        supabase: Client = create_client(supabase_url, supabase_key)
        user_response = supabase.auth.get_user(token)
        
        if user_response and user_response.user:
            return user_response.user.id
    except Exception as e:
        logger.error(f"Supabase auth failed: {e}")
        
    raise HTTPException(status_code=401, detail="Invalid token")

async def get_user_id_from_header(request: Request) -> str:
    auth = request.headers.get("Authorization")
    if not auth or not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Bearer token required")
    token = auth.split(" ")[1]
    return await get_user_id(token)


# --- 1. Uplink (WebSocket) for Local Client ---
@app.websocket("/relay/uplink")
async def websocket_uplink(websocket: WebSocket, token: str):
    user_id = await get_user_id(token)
    await websocket.accept()
    
    # Register this uplink
    active_uplinks[user_id] = websocket
    logger.info(f"Uplink connected for user {user_id}")
    
    try:
        while True:
            # Receive JSON-RPC message from the local client
            data = await websocket.receive_text()
            logger.debug(f"Received from uplink ({user_id}): {data}")
            
            # Forward the message to Claude via SSE if Claude is connected
            queue = active_sse_queues.get(user_id)
            if queue:
                await queue.put(data)
            else:
                logger.warning(f"No active SSE connection for user {user_id} to receive message.")
    except WebSocketDisconnect:
        logger.info(f"Uplink disconnected for user {user_id}")
    finally:
        if active_uplinks.get(user_id) == websocket:
            del active_uplinks[user_id]


# --- 2. SSE Endpoint for Claude.ai ---
@app.get("/mcp/connect")
async def mcp_connect_get_no_token():
    """Fallback if the user omits the token in the URL"""
    raise HTTPException(status_code=401, detail="Missing token. Please use the full URL from the EdgeDefenseAI authorization page.")

@app.get("/mcp/connect/{token}")
async def mcp_connect_get(token: str, request: Request):
    """Claude.ai connects here to receive SSE messages."""
    user_id = await get_user_id(token)
    logger.info(f"SSE connection opened for user {user_id}")
    
    # Create a new queue for this SSE connection
    queue = asyncio.Queue()
    active_sse_queues[user_id] = queue

    async def event_generator():
        try:
            # Send the endpoint event as required by MCP HTTP transport
            # We need to tell the client where to send POST requests
            yield {
                "event": "endpoint",
                "data": f"/mcp/connect/{token}"
            }
            
            while True:
                # Wait for a message from the uplink
                message = await queue.get()
                yield {
                    "data": message
                }
        except asyncio.CancelledError:
            logger.info(f"SSE connection cancelled for user {user_id}")
            raise
        finally:
            if active_sse_queues.get(user_id) == queue:
                del active_sse_queues[user_id]

    return EventSourceResponse(event_generator())


# --- 3. POST Endpoint for Claude.ai ---
@app.post("/mcp/connect")
async def mcp_connect_post_no_token():
    """Fallback if the user omits the token in the URL"""
    raise HTTPException(status_code=401, detail="Missing token. Please use the full URL from the EdgeDefenseAI authorization page.")

@app.post("/mcp/connect/{token}")
async def mcp_connect_post(token: str, request: Request):
    """Claude.ai posts JSON-RPC messages here."""
    user_id = await get_user_id(token)
    
    # Read the raw JSON-RPC payload
    body = await request.body()
    payload = body.decode("utf-8")
    logger.debug(f"Received from Claude ({user_id}): {payload}")
    
    # Find the active uplink for this user
    uplink = active_uplinks.get(user_id)
    if not uplink:
        logger.error(f"No active uplink found for user {user_id}")
        return JSONResponse(status_code=502, content={"error": "Local EdgeDefense client is not connected. Make sure the app is running."})
    
    try:
        # Forward the JSON-RPC message down to the local client
        await uplink.send_text(payload)
        return JSONResponse(status_code=202, content="Accepted")
    except Exception as e:
        logger.error(f"Error forwarding to uplink: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})

# --- 4. OAuth 2.1 Identity Provider for Claude Desktop ---

# In-memory stores for OAuth flow
oauth_clients: Dict[str, str] = {}
oauth_codes: Dict[str, dict] = {}

class ClientRegistration(BaseModel):
    client_name: Optional[str] = None
    redirect_uris: list[str] = []

@app.get("/.well-known/oauth-authorization-server")
async def oauth_metadata():
    base_url = "https://www.edgedefenseai.com"
    return {
        "issuer": base_url,
        "authorization_endpoint": f"{base_url}/oauth/authorize",
        "token_endpoint": f"{base_url}/oauth/token",
        "registration_endpoint": f"{base_url}/oauth/register",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "code_challenge_methods_supported": ["S256"]
    }

@app.post("/oauth/register")
async def oauth_register(reg: ClientRegistration):
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


def run():
    import uvicorn
    uvicorn.run("edgedefense_relay.main:app", host="0.0.0.0", port=8000, reload=True)

if __name__ == "__main__":
    run()
