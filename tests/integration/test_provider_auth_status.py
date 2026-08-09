from __future__ import annotations

import httpx
import pytest

from forgejo_api_mcp.catalog import OperationCatalog
from forgejo_api_mcp.client import ForgejoClient


@pytest.fixture
def catalog() -> OperationCatalog:
    return OperationCatalog.bundled()


def _client(
    catalog: OperationCatalog,
    token: str | None,
    handler,
    *,
    base_url: str = "https://forgejo.example",
    allow_insecure: bool = False,
) -> ForgejoClient:
    return ForgejoClient(
        catalog,
        base_url,
        token,
        transport=httpx.MockTransport(handler),
        allow_insecure_localhost=allow_insecure,
    )


@pytest.mark.asyncio
async def test_probe_auth_authenticated_through_full_client(catalog: OperationCatalog) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/v1/user"
        assert request.headers["authorization"] == "token good"
        return httpx.Response(200, json={"login": "alice"}, request=request)

    client = _client(catalog, "good", handler)
    result = await client.probe_auth()

    assert result == {
        "usesStartupSnapshot": True,
        "restartRequiredAfterRotation": True,
        "snapshotStatus": "authenticated",
        "status_code": 200,
        "detail": "token authenticated",
    }
    assert "token good" not in str(result)


@pytest.mark.asyncio
async def test_probe_auth_credential_rejected_on_401(catalog: OperationCatalog) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, request=request)

    client = _client(catalog, "stale-secret", handler)
    result = await client.probe_auth()

    assert result["snapshotStatus"] == "credential_rejected"
    assert result["status_code"] == 401
    assert result["restartRequiredAfterRotation"] is True
    assert "stale-secret" not in str(result)
    assert "token stale-secret" not in str(result)


@pytest.mark.asyncio
async def test_probe_auth_unconfigured_without_token(catalog: OperationCatalog) -> None:
    client = ForgejoClient(catalog, "https://forgejo.example", None)
    result = await client.probe_auth()

    assert result["snapshotStatus"] == "unconfigured"
    assert result["restartRequiredAfterRotation"] is True
    assert "login" not in result


@pytest.mark.asyncio
async def test_probe_auth_transport_failure_classified(catalog: OperationCatalog) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down", request=request)

    client = _client(catalog, "good", handler)
    result = await client.probe_auth()

    assert result["snapshotStatus"] == "transport"
    assert result["restartRequiredAfterRotation"] is True


@pytest.mark.asyncio
async def test_probe_auth_insecure_base_url_makes_no_request(catalog: OperationCatalog) -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, request=request)

    client = _client(
        catalog,
        "candidate",
        handler,
        base_url="http://localhost:3000",
        allow_insecure=True,
    )
    result = await client.probe_auth()

    assert result["snapshotStatus"] == "insecure_base_url"
    assert result["status_code"] == 0
    assert result["restartRequiredAfterRotation"] is True
    assert requests == []
