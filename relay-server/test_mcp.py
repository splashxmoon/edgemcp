import asyncio
from mcp import ClientSession
from mcp.client.sse import sse_client
import sys

async def run():
    try:
        async with sse_client('https://edgedefense-relay.onrender.com/mcp/connect') as streams:
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
