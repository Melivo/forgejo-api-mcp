from __future__ import annotations

from typing import Any

import httpx
import pytest

from forgejo_api_mcp.catalog import OperationCatalog
from forgejo_api_mcp.client import ForgejoClient
from forgejo_api_mcp.errors import InputValidationError
from forgejo_api_mcp.provider_auth import (
    AUTHENTICATED,
    CREDENTIAL_REJECTED,
    DEFAULT_TIMEOUT_SECONDS,
    FORBIDDEN,
    INSECURE_BASE_URL,
    PROVIDER_ERROR,
    TIMEOUT,
    TRANSPORT,
    classify_invoke_result,
    classify_token,
)


class NeverReadStream(httpx.AsyncByteStream):
    def __init__(self) -> None:
        self.closed = False

    async def __aiter__(self):
        raise AssertionError("response body must never be consumed")
        yield b"unreachable"

    async def aclose(self) -> None:
        self.closed = True


@pytest.mark.asyncio
async def test_classify_token_rejects_insecure_url_without_request() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, request=request)

    result = await classify_token(
        "candidate", base_url="http://forgejo.example", transport=httpx.MockTransport(handler)
    )
    assert result.status == INSECURE_BASE_URL
    assert result.status_code == 0
    assert requests == []


@pytest.mark.asyncio
async def test_classify_token_is_status_only_and_closes_unread_stream() -> None:
    stream = NeverReadStream()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, stream=stream, request=request)

    result = await classify_token(
        "candidate", base_url=BASE_URL, transport=httpx.MockTransport(handler)
    )
    assert result.status == AUTHENTICATED
    assert stream.closed is True
    assert "login" not in result.to_dict()


@pytest.mark.asyncio
async def test_classify_token_honors_injected_absolute_deadline() -> None:
    import asyncio
    import time

    async def handler(request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(0.2)
        return httpx.Response(200, request=request)

    started = time.monotonic()
    result = await classify_token(
        "candidate", base_url=BASE_URL, transport=httpx.MockTransport(handler), timeout=0.02
    )
    elapsed = time.monotonic() - started
    assert result.status == TIMEOUT
    assert elapsed < 0.15


def test_default_auth_deadline_is_30_seconds() -> None:
    assert DEFAULT_TIMEOUT_SECONDS == 30.0

BASE_URL = "https://forgejo.example/api/v1"


def _client(token: str, transport: httpx.AsyncBaseTransport) -> ForgejoClient:
    return ForgejoClient(
        OperationCatalog.bundled(),
        "https://forgejo.example",
        token,
        transport=transport,
    )


@pytest.mark.asyncio
async def test_classify_token_authenticated_does_not_parse_login() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["authorization"] == "token good"
        assert request.url.path == "/api/v1/user"
        return httpx.Response(200, json={"login": "alice"}, request=request)

    result = await classify_token("good", base_url=BASE_URL, transport=httpx.MockTransport(handler))
    assert result.status == AUTHENTICATED
    assert result.status_code == 200
    assert "login" not in result.to_dict()


@pytest.mark.asyncio
async def test_classify_token_401_is_credential_rejected() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"message": "bad credentials"}, request=request)

    result = await classify_token("stale", base_url=BASE_URL, transport=httpx.MockTransport(handler))
    assert result.status == CREDENTIAL_REJECTED
    assert result.status_code == 401
    assert "login" not in result.to_dict()
    assert "stale" not in result.detail


@pytest.mark.asyncio
async def test_classify_token_403_is_forbidden() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, request=request)

    result = await classify_token("scoped", base_url=BASE_URL, transport=httpx.MockTransport(handler))
    assert result.status == FORBIDDEN
    assert result.status_code == 403


@pytest.mark.asyncio
async def test_classify_token_500_is_provider_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, request=request)

    result = await classify_token("good", base_url=BASE_URL, transport=httpx.MockTransport(handler))
    assert result.status == PROVIDER_ERROR
    assert result.status_code == 500


@pytest.mark.asyncio
async def test_classify_token_timeout_is_timeout() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("slow", request=request)

    result = await classify_token("good", base_url=BASE_URL, transport=httpx.MockTransport(handler))
    assert result.status == TIMEOUT


@pytest.mark.asyncio
async def test_classify_token_transport_error_is_transport() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down", request=request)

    result = await classify_token("good", base_url=BASE_URL, transport=httpx.MockTransport(handler))
    assert result.status == TRANSPORT


@pytest.mark.asyncio
async def test_classify_token_does_not_follow_redirects() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "https://evil.example/"}, request=request)

    result = await classify_token("good", base_url=BASE_URL, transport=httpx.MockTransport(handler))
    assert result.status == PROVIDER_ERROR
    assert result.status_code == 302


@pytest.mark.asyncio
async def test_classify_token_appends_user_when_base_has_no_api_path() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(200, json={"login": "alice"}, request=request)

    await classify_token("good", base_url="https://forgejo.example", transport=httpx.MockTransport(handler))
    assert seen == ["https://forgejo.example/api/v1/user"]


@pytest.mark.asyncio
async def test_classify_token_result_to_dict_has_no_secret() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"login": "alice"}, request=request)

    result = await classify_token(
        "super-secret-value", base_url=BASE_URL, transport=httpx.MockTransport(handler)
    )
    dumped = result.to_dict()
    assert "super-secret-value" not in str(dumped)


@pytest.mark.asyncio
async def test_classify_token_rejects_empty_or_multiline_token() -> None:
    with pytest.raises(InputValidationError):
        await classify_token("", base_url=BASE_URL)
    with pytest.raises(InputValidationError):
        await classify_token("with\nnewline", base_url=BASE_URL)


@pytest.mark.asyncio
async def test_classify_invoke_result_maps_client_success() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"login": "alice"}, request=request)

    client = _client("good", httpx.MockTransport(handler))
    result = classify_invoke_result(await client.invoke("userGetCurrent"))
    assert result.status == AUTHENTICATED
    assert "login" not in result.to_dict()


@pytest.mark.asyncio
async def test_classify_invoke_result_maps_client_401() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, request=request)

    client = _client("stale", httpx.MockTransport(handler))
    result = classify_invoke_result(await client.invoke("userGetCurrent"))
    assert result.status == CREDENTIAL_REJECTED
    assert result.status_code == 401
    assert "stale" not in str(result.to_dict())


@pytest.mark.asyncio
async def test_classify_invoke_result_maps_timeout_and_transport() -> None:
    def timeout_handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow", request=request)

    client = _client("good", httpx.MockTransport(timeout_handler))
    result = classify_invoke_result(await client.invoke("userGetCurrent"))
    assert result.status == TIMEOUT

    def transport_handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down", request=request)

    client2 = _client("good", httpx.MockTransport(transport_handler))
    result2 = classify_invoke_result(await client2.invoke("userGetCurrent"))
    assert result2.status == TRANSPORT


def test_classify_invoke_result_maps_failure_status_only() -> None:
    result = classify_invoke_result(
        {"ok": False, "status_code": 500, "error": {"kind": "http", "message": "boom"}}
    )
    assert result.status == PROVIDER_ERROR
    assert result.status_code == 500


@pytest.mark.asyncio
async def test_result_dict_never_contains_token_across_branches() -> None:
    secret = "tok-abc-123-secret"

    def handler_factory(code: int) -> Any:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(code, request=request)

        return handler

    for code in (200, 401, 403, 500):
        result = await classify_token(
            secret, base_url=BASE_URL, transport=httpx.MockTransport(handler_factory(code))
        )
        assert secret not in str(result.to_dict()), code
