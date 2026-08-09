from __future__ import annotations

import httpx
import pytest

from forgejo_api_mcp.catalog import OperationCatalog
from forgejo_api_mcp.client import ForgejoClient
from forgejo_api_mcp.credentials import (
    CRED_PERSIST_LOCAL_MACHINE,
    TARGET_NAME,
    CredentialRecord,
)


@pytest.mark.asyncio
async def test_rotation_requires_reconstructing_the_startup_client() -> None:
    seen_authorization: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_authorization.append(request.headers["authorization"])
        return httpx.Response(200, request=request)

    catalog = OperationCatalog.bundled()
    transport = httpx.MockTransport(handler)
    store_record = CredentialRecord(
        TARGET_NAME, "forgejo-api-mcp", "snapshot-a", CRED_PERSIST_LOCAL_MACHINE
    )
    running_client = ForgejoClient(
        catalog, "https://forgejo.example", store_record.credential_blob, transport=transport
    )

    store_record = CredentialRecord(
        TARGET_NAME, "forgejo-api-mcp", "snapshot-b", CRED_PERSIST_LOCAL_MACHINE
    )
    await running_client.probe_auth()
    restarted_client = ForgejoClient(
        catalog, "https://forgejo.example", store_record.credential_blob, transport=transport
    )
    await restarted_client.probe_auth()

    assert seen_authorization == ["token snapshot-a", "token snapshot-b"]
