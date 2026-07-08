# 9b_mcp_server/server.py — naive MCP server baseline (deliberately vulnerable)
# No auth, no JSON Schema with additionalProperties:false, no per-user scope,
# string-interpolated SQL. This is the BEFORE state.

from mcp.server import Server
from mcp.types import Tool, TextContent
import sqlite3

app = Server("pillar-2-mcp")
db  = sqlite3.connect("db/customers.sqlite")


@app.list_tools()
async def tools():
    return [Tool(
        name="lookup_customer",
        description="Look up a customer by ID. Returns full row.",
        inputSchema={
            "type": "object",
            "properties": {
                # No pattern regex — any string is accepted
                "customer_id": {"type": "string"}
            }
            # No additionalProperties: false — mass assignment possible
        },
    )]


@app.call_tool()
async def call_tool(name: str, args: dict):
    if name != "lookup_customer":
        return [TextContent(type="text", text="unknown tool")]

    # Direct string interpolation — SQL injection on purpose (baseline)
    row = db.execute(
        f"SELECT * FROM customers WHERE id = '{args['customer_id']}'"
    ).fetchone()

    return [TextContent(type="text", text=str(row))]

# Vulnerabilities in this baseline:
# 1. No authentication — any caller can invoke any tool
# 2. String-interpolated SQL — SQL injection via customer_id
# 3. No WHERE owner_user_id = ? — any caller can read any row
# 4. inputSchema missing additionalProperties:false — mass assignment
