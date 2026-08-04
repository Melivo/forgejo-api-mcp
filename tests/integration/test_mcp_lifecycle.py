from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

PROJECT_ROOT = Path(__file__).resolve().parents[2]

MOCKED_SERVER_BOOTSTRAP = """
import httpx

from forgejo_api_mcp import server as server_module


def handle_request(request):
    return httpx.Response(
        200,
        json={"full_name": "octo/sample", "method": request.method},
        request=request,
    )


server_module.client = server_module.ForgejoClient(
    server_module.catalog,
    "https://forgejo.invalid",
    "integration-test-token",
    transport=httpx.MockTransport(handle_request),
)
server_module.main()
"""


def _child_environment() -> dict[str, str]:
    environment = os.environ.copy()
    environment.pop("FORGEJO_ACCESS_TOKEN", None)
    source_path = str(PROJECT_ROOT / "src")
    environment["PYTHONPATH"] = os.pathsep.join(
        part for part in (source_path, environment.get("PYTHONPATH")) if part
    )
    return environment


@pytest.mark.asyncio
async def test_stdio_protocol_lifecycle_with_mocked_http() -> None:
    parameters = StdioServerParameters(
        command=sys.executable,
        args=["-c", MOCKED_SERVER_BOOTSTRAP],
        cwd=PROJECT_ROOT,
        env=_child_environment(),
    )

    async with (
        stdio_client(parameters) as (read_stream, write_stream),
        ClientSession(read_stream, write_stream) as session,
    ):
        initialized = await session.initialize()
        assert initialized.server_info.name == "forgejo-api"
        assert initialized.server_info.version == "0.1.0"

        listed = await session.list_tools()
        assert {tool.name for tool in listed.tools} == {
            "list_operations",
            "get_operation",
            "invoke_operation",
        }

        successful = await session.call_tool(
            "invoke_operation",
            {
                "operation_id": "repoGet",
                "path_params": {"owner": "octo", "repo": "sample"},
            },
        )
        assert successful.is_error is False
        assert successful.structured_content == {
            "operation_id": "repoGet",
            "status_code": 200,
            "ok": True,
            "content_type": "application/json",
            "body": {"full_name": "octo/sample", "method": "GET"},
        }

        rejected = await session.call_tool(
            "invoke_operation",
            {"operation_id": "repoGet", "path_params": {"owner": "octo"}},
        )
        assert rejected.is_error is True
        error_text = "\n".join(
            item.text for item in rejected.content if getattr(item, "type", None) == "text"
        )
        assert "requires path parameters" in error_text
        assert "integration-test-token" not in json.dumps(rejected.model_dump(by_alias=True))

    # Exiting both context managers performs the protocol close and waits for clean child exit.
