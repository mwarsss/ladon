"""MCP mode: an outside assistant gets the same protection as the built-in one."""

import asyncio
import sys

from mcp import Client, StdioServerParameters

from ladon.mcp_server import build_gateway, create_server


def text(result):
    return result.content[0].text


def test_mcp_client_is_blocked_from_paying_the_scammer(tmp_path):
    async def scenario():
        server = create_server(build_gateway("b_protected_defense", "protected", tmp_path / "audit.jsonl"))
        async with Client(server) as client:
            names = {t.name for t in (await client.list_tools()).tools}
            assert {"read_inbox", "read_email", "make_payment", "send_email"} <= names
            await client.call_tool("read_inbox", {})
            for msg_id in ("msg-101", "msg-102", "msg-103"):
                await client.call_tool("read_email", {"id": msg_id})
            scam = await client.call_tool("make_payment", {"to": "ACC-99281", "amount": 8450, "reference": "APEX-992"})
            real = await client.call_tool("make_payment", {"to": "ACC-55210", "amount": 3200, "reference": "INV-402"})
            return scam, real

    scam, real = asyncio.run(scenario())
    assert scam.is_error and "BLOCKED by Ladon" in text(scam) and "Red flags" in text(scam)
    assert not real.is_error and "payment_executed" in text(real)
    assert (tmp_path / "audit.jsonl").read_text().count("make_payment") >= 2  # both calls are in the signed log


def test_mcp_server_runs_over_stdio(tmp_path):
    async def scenario():
        params = StdioServerParameters(command=sys.executable, args=[
            "-m", "ladon.mcp_server", "--audit-log", str(tmp_path / "audit.jsonl")])
        async with Client(params) as client:
            return await client.call_tool("read_inbox", {})

    result = asyncio.run(scenario())
    assert not result.is_error and "msg-101" in text(result)
