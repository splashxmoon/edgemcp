import argparse
import asyncio
import math
import os
import sys
from typing import Optional

import anyio
import websockets
import websockets.client
from pydantic import TypeAdapter

from mcp.types import JSONRPCMessage
from .server import mcp
from .cli import warn

UPLINK_TOKEN_ENV_VAR = "EDGEDEFENSE_UPLINK_TOKEN"


async def uplink_transport(url: str, token: str) -> None:
    """
    Connects to the relay server via WebSocket and pipes JSON-RPC
    messages into FastMCP using memory streams.
    """
    client_send, server_receive = anyio.create_memory_object_stream(math.inf)
    server_send, client_receive = anyio.create_memory_object_stream(math.inf)

    opts = mcp._mcp_server.create_initialization_options()
    
    # Append the token to the URL query string
    separator = "&" if "?" in url else "?"
    uri = f"{url}{separator}token={token}"
    
    warn(f"Connecting to uplink relay at {url} ...")
    
    async with websockets.client.connect(uri) as ws:
        warn("Connected to uplink relay successfully. Ready for incoming requests.")
        
        async def read_ws():
            adapter = TypeAdapter(JSONRPCMessage)
            try:
                async for message_str in ws:
                    try:
                        msg = adapter.validate_json(message_str)
                        await client_send.send(msg)
                    except Exception as e:
                        warn(f"Failed to parse incoming message: {e}")
            except Exception as e:
                warn(f"WebSocket read failed: {e}")
            finally:
                await client_send.aclose()

        async def write_ws():
            try:
                async for msg in client_receive:
                    payload = msg.model_dump_json(by_alias=True, exclude_none=True)
                    await ws.send(payload)
            except Exception as e:
                warn(f"WebSocket write failed: {e}")
            finally:
                await client_receive.aclose()

        async with anyio.create_task_group() as tg:
            tg.start_soon(read_ws)
            tg.start_soon(write_ws)
            
            # Start FastMCP on the memory streams
            await mcp._mcp_server.run(server_receive, server_send, opts)


def run_uplink(args: argparse.Namespace) -> int:
    token = args.uplink_token or os.environ.get(UPLINK_TOKEN_ENV_VAR)
    if not token:
        warn(f"Error: --uplink-token or {UPLINK_TOKEN_ENV_VAR} is required for uplink mode.")
        return 1

    try:
        asyncio.run(uplink_transport(args.uplink, token))
    except KeyboardInterrupt:
        warn("Uplink disconnected.")
    except Exception as e:
        warn(f"Uplink error: {e}")
        return 1
    return 0
