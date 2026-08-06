import sys
import asyncio
import websockets

def run_mcp_server():
    """Runs the FastMCP server over standard input/output"""
    from mcp.server.fastmcp import FastMCP
    from edgedefense_relay.mcp_tools import register_tools
    
    mcp = FastMCP("EdgeDefense Local Scanner")
    register_tools(mcp)
    
    # Run the server using stdio transport
    mcp.run(transport="stdio")


async def run_websocket_bridge():
    """Connects to the cloud relay and bridges WebSocket to the local MCP server"""
    uri = "wss://www.edgedefenseai.com/relay/ws/agent"
    print(f"Connecting to Cloud Relay at {uri}...")
    
    while True:
        try:
            async with websockets.connect(uri) as ws:
                print("✅ Connected to Cloud Relay! Waiting for commands...")
                
                # Spawn the MCP server as a subprocess
                proc = await asyncio.create_subprocess_exec(
                    sys.executable, __file__, "--mcp",
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE
                )
                
                async def ws_to_proc():
                    try:
                        async for msg in ws:
                            # Forward WebSocket messages (from Claude) to MCP stdin
                            proc.stdin.write(msg.encode('utf-8') + b'\n')
                            await proc.stdin.drain()
                    except Exception as e:
                        print(f"WebSocket to Process error: {e}")
                
                async def proc_to_ws():
                    try:
                        while True:
                            line = await proc.stdout.readline()
                            if not line:
                                break
                            # Forward MCP stdout (to Claude) back through the WebSocket
                            await ws.send(line.decode('utf-8').strip())
                    except Exception as e:
                        print(f"Process to WebSocket error: {e}")
                
                # Run both directions concurrently
                await asyncio.gather(ws_to_proc(), proc_to_ws())
                
                # If we get here, either process exited or connection dropped
                if proc.returncode is None:
                    proc.terminate()
                    
        except Exception as e:
            print(f"Connection lost or failed: {e}. Retrying in 5 seconds...")
            await asyncio.sleep(5)

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--mcp":
        run_mcp_server()
    else:
        asyncio.run(run_websocket_bridge())
