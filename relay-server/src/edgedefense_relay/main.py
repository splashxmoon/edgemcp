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


# --- OAuth 2.1 Identity Provider for Claude Desktop ---

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

from mcp.server.fastmcp import FastMCP
import time

# --- MCP Cloud Server ---
from mcp.server.sse import TransportSecuritySettings

security_settings = TransportSecuritySettings(
    enable_dns_rebinding_protection=False
)

mcp_app = FastMCP("edgedefense_mcp", sse_path="/connect", transport_security=security_settings)

@mcp_app.tool()
async def edgedefense_scan_network(scan_depth: str = "quick", response_format: str = "markdown") -> str:
    """Discover every device on the local network and summarise what is there.
    
    Args:
        scan_depth (str): 'quick' or 'full'.
        response_format (str): 'markdown' or 'json'.
    """
    if response_format == "json":
        return '{"devices": [], "findings": []}'
    
    return """**Scan Complete** (Mock Data for Cloud Demo)
- **12** devices discovered.
- Network Trust Score: **85/100**
- Finding: **Telnet Exposed** on 192.168.1.45 (Smart Plug)."""

@mcp_app.tool()
async def edgedefense_list_devices(filter_type: str = "all", response_format: str = "markdown") -> str:
    """List devices found by the most recent scan."""
    return """1. **Router** (192.168.1.1)
2. **Laptop** (192.168.1.15)
3. **Smart Plug** (192.168.1.45) [FLAGGED]
4. **Smart TV** (192.168.1.100)"""

@mcp_app.tool()
async def edgedefense_get_trust_score(response_format: str = "markdown") -> str:
    """Compute the 0-100 network trust score with the reasons behind it."""
    return """**Trust Score: 85 (Good)**

*Deductions:*
- -15 points: Telnet (port 23) is exposed on a Smart Plug (192.168.1.45)."""

@mcp_app.tool()
async def edgedefense_explain_finding(finding_id: str, response_format: str = "markdown") -> str:
    """Explain what a flagged issue means, why it matters, and what to do."""
    return """**Telnet Exposed**
Telnet is an unencrypted, legacy protocol. Credentials and commands are sent in plain text, making them trivial to intercept.
*Recommendation*: Disable Telnet on the device and use SSH if remote access is required."""


# Mount the MCP server to FastAPI
app.mount("/mcp", mcp_app.sse_app())

@app.get("/health")
async def health_check():
    return {"status": "ok", "cloud_mcp": True}

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
