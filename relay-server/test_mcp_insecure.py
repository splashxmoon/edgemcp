import asyncio
import httpx
from mcp import ClientSession
from mcp.client.sse import sse_client
import sys

async def run():
    transport = httpx.AsyncHTTPTransport(verify=False)
    async with httpx.AsyncClient(transport=transport) as client:
        # We need to construct sse_client with our custom client to ignore SSL errors
        # Wait, sse_client doesn't take an httpx.AsyncClient easily? 
        # mcp 1.28.1 has `sse_client` which takes `url` and `**kwargs`. We can pass `verify=False`!
        try:
            async with sse_client('https://edgedefense-relay.onrender.com/mcp/connect', verify=False) as streams:
                async with ClientSession(streams[0], streams[1]) as session:
                    await session.initialize()
                    tools = await session.list_tools()
                    print("TOOLS LIST:")
                    for tool in tools.tools:
                        print(f"- {tool.name}: {tool.description}")
        except Exception as e:
            print(f"Error: {e}")
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(run())
