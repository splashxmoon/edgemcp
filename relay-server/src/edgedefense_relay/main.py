import asyncio
import json
import logging
from typing import Dict, Any, Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, Depends, HTTPException, status
from fastapi.responses import JSONResponse
from sse_starlette.sse import EventSourceResponse

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="EdgeDefense Relay Server")

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
async def mcp_connect_get(request: Request, user_id: str = Depends(get_user_id_from_header)):
    """Claude.ai connects here to receive SSE messages."""
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
                "data": "/mcp/connect"
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
async def mcp_connect_post(request: Request, user_id: str = Depends(get_user_id_from_header)):
    """Claude.ai posts JSON-RPC messages here."""
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


def run():
    import uvicorn
    uvicorn.run("edgedefense_relay.main:app", host="0.0.0.0", port=8000, reload=True)

if __name__ == "__main__":
    run()
