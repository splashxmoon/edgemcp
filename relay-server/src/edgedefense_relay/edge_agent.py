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


import json
import urllib.request
import urllib.error

async def run_http_bridge():
    """Connects to the cloud relay via HTTP long polling"""
    poll_url = "https://www.edgedefenseai.com/relay/poll"
    send_url = "https://www.edgedefenseai.com/relay/send"
    print(f"Connecting to Cloud Relay at {poll_url}...")
    
    # Spawn the MCP server as a subprocess
    proc = await asyncio.create_subprocess_exec(
        sys.executable, __file__, "--mcp",
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE
    )
    
    async def poll_to_proc():
        while True:
            try:
                # Run the blocking urllib request in a thread
                def _poll():
                    req = urllib.request.Request(poll_url, method="GET")
                    with urllib.request.urlopen(req, timeout=35) as res:
                        return json.loads(res.read().decode('utf-8'))
                        
                data = await asyncio.to_thread(_poll)
                if data and data.get("message"):
                    msg = data["message"]
                    print(f"[Relay -> Local] {msg}")
                    proc.stdin.write(msg.encode('utf-8') + b'\n')
                    await proc.stdin.drain()
            except urllib.error.URLError as e:
                # Timeout is normal, just loop
                if not isinstance(e.reason, TimeoutError) and "timeout" not in str(e).lower():
                    await asyncio.sleep(2)
            except Exception as e:
                print(f"Poll error: {e}")
                await asyncio.sleep(2)
                
    async def proc_to_send():
        while True:
            try:
                line = await proc.stdout.readline()
                if not line:
                    break
                
                print(f"[Local -> Relay] {line.decode('utf-8').strip()}")
                # Send back to relay
                def _send(data):
                    req = urllib.request.Request(send_url, data=data, method="POST", headers={"Content-Type": "application/json"})
                    urllib.request.urlopen(req, timeout=10)
                
                await asyncio.to_thread(_send, line)
            except Exception as e:
                print(f"Error sending response: {e}")
                
    # Run both directions concurrently
    await asyncio.gather(poll_to_proc(), proc_to_send())

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--mcp":
        run_mcp_server()
    else:
        asyncio.run(run_http_bridge())
