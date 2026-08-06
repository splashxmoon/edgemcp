from fastapi import FastAPI
from mcp.server.fastmcp import FastMCP
from starlette.testclient import TestClient

app = FastAPI()
mcp_app = FastMCP("edgedefense")

@mcp_app.tool()
def mock_tool() -> str:
    return "mock"

# FastMCP might have something like .sse_app or .create_starlette_app()
# Let's inspect the signature of m.sse_app
import inspect
print("sse_app signature:", inspect.signature(mcp_app.sse_app))

app.mount("/mcp", mcp_app.sse_app())

client = TestClient(app)
res = client.get("/mcp/sse", headers={"Accept": "text/event-stream"})
print("/mcp/sse Status:", res.status_code)
print("Headers:", res.headers)
