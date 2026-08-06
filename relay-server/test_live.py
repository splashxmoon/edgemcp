import asyncio
import httpx
import json

async def run():
    async with httpx.AsyncClient(timeout=10.0) as client:
        print("Connecting to SSE...")
        async with client.stream("GET", "https://edgedefense-relay.onrender.com/mcp/connect", headers={"Accept": "text/event-stream"}) as response:
            print(f"Connected: {response.status_code}")
            endpoint_url = None
            async for line in response.aiter_lines():
                if line.startswith("data: "):
                    data = line[6:]
                    try:
                        event_data = json.loads(data)
                        if event_data.get("event") == "endpoint":
                            endpoint_url = event_data.get("data")
                            print(f"Got endpoint: {endpoint_url}")
                            break
                    except Exception as e:
                        print("Error parsing JSON:", e)
            
            if not endpoint_url:
                print("No endpoint received.")
                return

            print("Sending tools/list...")
            if endpoint_url.startswith("/"):
                post_url = f"https://edgedefense-relay.onrender.com{endpoint_url}"
            else:
                post_url = endpoint_url
                
            res = await client.post(
                post_url,
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/list",
                    "params": {}
                }
            )
            print("POST response:", res.status_code, res.text)

if __name__ == "__main__":
    asyncio.run(run())
