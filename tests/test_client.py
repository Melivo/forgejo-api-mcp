from __future__ import annotations

import asyncio
import base64
import json
from copy import deepcopy
from importlib.resources import files
from typing import Any
from urllib.parse import parse_qs

import httpx
import pytest

from forgejo_api_mcp.catalog import OperationCatalog
from forgejo_api_mcp.client import (
    MAX_BASE64_FILE_UPLOAD_CHARS,
    MAX_FILE_UPLOAD_BYTES,
    MAX_HTTPX_URL_LENGTH,
    MAX_PARAMETER_INPUT_BYTES,
    MAX_REQUEST_BODY_BYTES,
    TRUNCATION_MARKER,
    ForgejoClient,
)
from forgejo_api_mcp.errors import ConfigurationError, InputValidationError


class RecordingTransport(httpx.AsyncBaseTransport):
    def __init__(self, response: httpx.Response | Exception | None = None) -> None:
        self.calls = 0
        self.request: httpx.Request | None = None
        self.response = response

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.calls += 1
        self.request = request
        await request.aread()
        if isinstance(self.response, Exception):
            raise self.response
        if self.response is not None:
            self.response.request = request
            return self.response
        return httpx.Response(200, json={"ok": True}, request=request)


@pytest.fixture
def catalog() -> OperationCatalog:
    return OperationCatalog.bundled()


def make_client(
    catalog: OperationCatalog,
    transport: httpx.AsyncBaseTransport,
    **kwargs: Any,
) -> ForgejoClient:
    return ForgejoClient(
        catalog,
        "https://forgejo.example",
        "runtime-test-token",
        transport=transport,
        **kwargs,
    )


def test_base_url_is_https_locked_and_api_path_is_normalized_once(
    catalog: OperationCatalog,
) -> None:
    assert ForgejoClient(catalog, "https://forgejo.example", None).base_url == (
        "https://forgejo.example/api/v1"
    )
    assert ForgejoClient(catalog, "https://forgejo.example/api/v1/", None).base_url == (
        "https://forgejo.example/api/v1"
    )
    assert ForgejoClient(catalog, "https://forgejo.example/api/v1/api/v1", None).base_url == (
        "https://forgejo.example/api/v1"
    )
    assert ForgejoClient(catalog, "https://forgejo.example/forgejo", None).base_url == (
        "https://forgejo.example/forgejo/api/v1"
    )

    with pytest.raises(ConfigurationError, match="must use HTTPS"):
        ForgejoClient(catalog, "http://forgejo.example", None)
    with pytest.raises(ConfigurationError, match="only for localhost"):
        ForgejoClient(
            catalog,
            "http://forgejo.example",
            None,
            allow_insecure_localhost=True,
        )
    assert ForgejoClient(
        catalog,
        "http://127.0.0.1:3000",
        None,
        allow_insecure_localhost=True,
    ).base_url == "http://127.0.0.1:3000/api/v1"


@pytest.mark.asyncio
async def test_validation_rejects_bad_parameters_and_body_before_io(
    catalog: OperationCatalog,
) -> None:
    transport = RecordingTransport()
    client = make_client(catalog, transport)

    with pytest.raises(InputValidationError, match="requires path parameters"):
        await client.invoke("repoGet", path_params={"owner": "octo"})
    with pytest.raises(InputValidationError, match="does not accept query parameters"):
        await client.invoke(
            "repoGet",
            path_params={"owner": "octo", "repo": "example"},
            query_params={"host": "attacker.example"},
        )
    with pytest.raises(InputValidationError, match="body: requires properties.*ref"):
        await client.invoke(
            "ActionsDispatchWorkflow",
            path_params={"owner": "octo", "repo": "example", "workflow_id": "build.yml"},
            body={"inputs": {}},
        )
    with pytest.raises(InputValidationError, match="body.inputs.flag: must be a string"):
        await client.invoke(
            "ActionsDispatchWorkflow",
            path_params={"owner": "octo", "repo": "example", "workflow_id": "build.yml"},
            body={"ref": "main", "inputs": {"flag": 3}},
        )

    assert transport.calls == 0


@pytest.mark.asyncio
async def test_invalid_email_is_rejected_before_io(catalog: OperationCatalog) -> None:
    transport = RecordingTransport()
    client = make_client(catalog, transport)

    with pytest.raises(InputValidationError, match="body.email: must be a valid email"):
        await client.invoke(
            "adminCreateUser",
            body={"username": "invalid-email", "email": "@"},
        )

    assert transport.calls == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("operation_id", "path_params", "query_params", "error"),
    [
        (
            "orgListActivityFeeds",
            {"org": "octo"},
            {"date": "20260731"},
            "query.date: must be a valid date",
        ),
        (
            "notifyGetList",
            {},
            {"since": "20260731T000000+0000"},
            "query.since: must be a valid date-time",
        ),
    ],
)
async def test_basic_iso_dates_are_rejected_before_io(
    catalog: OperationCatalog,
    operation_id: str,
    path_params: dict[str, Any],
    query_params: dict[str, Any],
    error: str,
) -> None:
    transport = RecordingTransport()
    client = make_client(catalog, transport)

    with pytest.raises(InputValidationError, match=error):
        await client.invoke(
            operation_id,
            path_params=path_params,
            query_params=query_params,
        )

    assert transport.calls == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "value",
    [
        "2026-07-31T00:00:00Z",
        "2026-07-31T09:30:00+09:30",
        "2026-07-31T16:00:00.123456-08:00",
    ],
)
async def test_rfc3339_timezone_forms_remain_valid(
    catalog: OperationCatalog,
    value: str,
) -> None:
    transport = RecordingTransport()
    client = make_client(catalog, transport)

    await client.invoke("notifyGetList", query_params={"since": value})

    assert transport.calls == 1


@pytest.mark.asyncio
async def test_serialized_request_bodies_are_bounded_before_io(
    catalog: OperationCatalog,
) -> None:
    transport = RecordingTransport()
    client = make_client(catalog, transport)
    oversized = "x" * (MAX_REQUEST_BODY_BYTES + 1)

    with pytest.raises(InputValidationError, match="Serialized request body exceeds"):
        await client.invoke("renderMarkdownRaw", body=oversized)
    with pytest.raises(InputValidationError, match="Serialized request body exceeds"):
        await client.invoke(
            "ActionsDispatchWorkflow",
            path_params={"owner": "octo", "repo": "sample", "workflow_id": "build.yml"},
            body={"ref": oversized},
        )

    assert transport.calls == 0


@pytest.mark.asyncio
async def test_aggregate_parameter_input_is_bounded_before_io(
    catalog: OperationCatalog,
) -> None:
    transport = RecordingTransport()
    client = make_client(catalog, transport)

    with pytest.raises(InputValidationError, match="Aggregate parameter input exceeds"):
        await client.invoke(
            "repoGet",
            path_params={
                "owner": "x" * MAX_PARAMETER_INPUT_BYTES,
                "repo": "one-byte-too-many",
            },
        )

    assert transport.calls == 0


@pytest.mark.asyncio
async def test_oversized_serialized_path_and_query_are_rejected_before_io(
    catalog: OperationCatalog,
) -> None:
    transport = RecordingTransport()
    client = make_client(catalog, transport)

    with pytest.raises(InputValidationError, match="Serialized request URL exceeds"):
        await client.invoke(
            "repoGet",
            path_params={"owner": "x" * MAX_HTTPX_URL_LENGTH, "repo": "sample"},
        )
    with pytest.raises(InputValidationError, match="Serialized request URL exceeds"):
        await client.invoke(
            "repoSearch",
            query_params={"q": "x" * MAX_HTTPX_URL_LENGTH},
        )

    repeated_values = [""] * (MAX_HTTPX_URL_LENGTH // len("status-types=&") + 1)
    with pytest.raises(InputValidationError, match="Serialized request URL exceeds"):
        await client.invoke(
            "notifyGetList",
            query_params={"status-types": repeated_values},
        )

    assert transport.calls == 0


@pytest.mark.asyncio
async def test_additional_properties_false_is_enforced_before_io() -> None:
    raw = files("forgejo_api_mcp").joinpath("openapi.json").read_text(encoding="utf-8")
    document = json.loads(raw)
    operation = deepcopy(document["paths"]["/markdown/raw"]["post"])
    operation["operationId"] = "closedBody"
    operation["parameters"][0]["schema"] = {
        "type": "object",
        "properties": {"name": {"type": "string"}},
        "additionalProperties": False,
    }
    document["paths"] = {"/closed": {"post": operation}}
    transport = RecordingTransport()
    client = make_client(OperationCatalog(document), transport)

    with pytest.raises(InputValidationError, match="does not allow properties.*extra"):
        await client.invoke("closedBody", body={"name": "ok", "extra": True})
    assert transport.calls == 0


@pytest.mark.asyncio
async def test_values_are_typed_and_multi_arrays_are_serialized(
    catalog: OperationCatalog,
) -> None:
    transport = RecordingTransport()
    client = make_client(catalog, transport)

    with pytest.raises(InputValidationError, match="query.page: must be an integer"):
        await client.invoke("repoSearch", query_params={"page": "1"})
    with pytest.raises(InputValidationError, match="query.since: must be a valid date-time"):
        await client.invoke("notifyGetList", query_params={"since": "yesterday"})
    await client.invoke(
        "notifyGetList",
        query_params={"status-types": ["read", "pinned"], "all": True},
    )

    assert transport.request is not None
    query = parse_qs(transport.request.url.query.decode())
    assert query["status-types"] == ["read", "pinned"]
    assert query["all"] == ["true"]


@pytest.mark.asyncio
async def test_path_values_cannot_change_the_resolved_host(catalog: OperationCatalog) -> None:
    transport = RecordingTransport()
    client = make_client(catalog, transport)

    await client.invoke(
        "repoGet",
        path_params={"owner": "//attacker.example", "repo": "sample?redirect=true"},
    )

    assert transport.request is not None
    assert transport.request.url.host == "forgejo.example"
    assert transport.request.url.raw_path.endswith(
        b"/%2F%2Fattacker.example/sample%3Fredirect%3Dtrue"
    )


@pytest.mark.asyncio
async def test_multipart_file_descriptor_is_validated_and_serialized(
    catalog: OperationCatalog,
) -> None:
    transport = RecordingTransport()
    client = make_client(catalog, transport)
    params = {"owner": "octo", "repo": "sample", "index": 1}

    with pytest.raises(InputValidationError, match="does not accept file parameters"):
        await client.invoke(
            "issueCreateIssueAttachment",
            path_params=params,
            file_params={"unknown": {"content_base64": "YQ=="}},
        )
    with pytest.raises(InputValidationError, match="must be valid base64"):
        await client.invoke(
            "issueCreateIssueAttachment",
            path_params=params,
            file_params={"attachment": {"content_base64": "not-base64"}},
        )
    assert transport.calls == 0

    await client.invoke(
        "issueCreateIssueAttachment",
        path_params=params,
        file_params={
            "attachment": {
                "content_base64": base64.b64encode(b"hello").decode(),
                "filename": "hello.txt",
                "content_type": "text/plain",
            }
        },
    )
    assert transport.request is not None
    assert transport.request.headers["content-type"].startswith("multipart/form-data; boundary=")
    assert b'filename="hello.txt"' in transport.request.content
    assert b"hello" in transport.request.content


def test_base64_file_upload_accepts_exact_decoded_size_boundary(
    catalog: OperationCatalog,
) -> None:
    client = make_client(catalog, RecordingTransport())
    content = b"x" * MAX_FILE_UPLOAD_BYTES
    encoded = base64.b64encode(content).decode("ascii")

    decoded, _, _ = client._decode_file(
        {"content_base64": encoded}, "file_params.attachment"
    )

    assert len(encoded) == MAX_BASE64_FILE_UPLOAD_CHARS
    assert decoded == content


def test_certainly_oversized_base64_file_is_rejected_before_decoding(
    catalog: OperationCatalog,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = make_client(catalog, RecordingTransport())
    decode_called = False

    def record_decode(*args: Any, **kwargs: Any) -> bytes:
        nonlocal decode_called
        decode_called = True
        return b""

    monkeypatch.setattr(base64, "b64decode", record_decode)

    with pytest.raises(InputValidationError, match="exceeds.*upload limit"):
        client._decode_file(
            {"content_base64": "A" * (MAX_BASE64_FILE_UPLOAD_CHARS + 1)},
            "file_params.attachment",
        )

    assert decode_called is False


def test_decoded_file_size_bound_is_retained(catalog: OperationCatalog) -> None:
    client = make_client(catalog, RecordingTransport())
    encoded = base64.b64encode(b"x" * (MAX_FILE_UPLOAD_BYTES + 1)).decode("ascii")

    assert len(encoded) == MAX_BASE64_FILE_UPLOAD_CHARS
    with pytest.raises(InputValidationError, match="exceeds.*upload limit"):
        client._decode_file({"content_base64": encoded}, "file_params.attachment")


@pytest.mark.parametrize("field", ["filename", "content_type"])
@pytest.mark.parametrize("control_code", [*range(32), 127])
def test_multipart_metadata_rejects_every_c0_and_del_character(
    catalog: OperationCatalog,
    field: str,
    control_code: int,
) -> None:
    transport = RecordingTransport()
    client = make_client(catalog, transport)
    descriptor = {
        "content_base64": "YQ==",
        "filename": "safe.txt",
        "content_type": "text/plain",
    }
    descriptor[field] += chr(control_code)

    with pytest.raises(InputValidationError, match="C0 or DEL control characters"):
        client._decode_file(descriptor, "file_params.attachment")

    assert transport.calls == 0


@pytest.mark.asyncio
async def test_multipart_content_type_requires_strict_media_type_before_io(
    catalog: OperationCatalog,
) -> None:
    transport = RecordingTransport()
    client = make_client(catalog, transport)
    params = {"owner": "octo", "repo": "sample", "index": 1}

    for content_type in ("text", "text/", "/plain", "text/plain, application/json"):
        with pytest.raises(InputValidationError, match="valid media type"):
            await client.invoke(
                "issueCreateIssueAttachment",
                path_params=params,
                file_params={
                    "attachment": {
                        "content_base64": "YQ==",
                        "filename": "safe.txt",
                        "content_type": content_type,
                    }
                },
            )

    with pytest.raises(InputValidationError, match="C0 or DEL control characters"):
        await client.invoke(
            "issueCreateIssueAttachment",
            path_params=params,
            file_params={
                "attachment": {
                    "content_base64": "YQ==",
                    "filename": "safe.txt",
                    "content_type": "text/plain\x00",
                }
            },
        )

    assert transport.calls == 0


@pytest.mark.asyncio
async def test_parameterized_multipart_media_type_remains_valid(
    catalog: OperationCatalog,
) -> None:
    transport = RecordingTransport()
    client = make_client(catalog, transport)

    await client.invoke(
        "issueCreateIssueAttachment",
        path_params={"owner": "octo", "repo": "sample", "index": 1},
        file_params={
            "attachment": {
                "content_base64": "YQ==",
                "filename": "safe.txt",
                "content_type": 'text/plain; charset="utf-8"',
            }
        },
    )

    assert transport.calls == 1
    assert transport.request is not None
    assert b'Content-Type: text/plain; charset="utf-8"' in transport.request.content


@pytest.mark.asyncio
async def test_timeout_and_transport_errors_are_structured_and_token_safe(
    catalog: OperationCatalog,
) -> None:
    timeout_transport = RecordingTransport(httpx.ReadTimeout("runtime-test-token leaked"))
    timeout = await make_client(catalog, timeout_transport).invoke(
        "repoGet", path_params={"owner": "octo", "repo": "sample"}
    )
    transport_error = RecordingTransport(httpx.ConnectError("runtime-test-token leaked"))
    failed = await make_client(catalog, transport_error).invoke(
        "repoGet", path_params={"owner": "octo", "repo": "sample"}
    )

    assert timeout["error"]["kind"] == "timeout"
    assert failed["error"]["kind"] == "transport"
    assert "runtime-test-token" not in json.dumps([timeout, failed])


@pytest.mark.asyncio
async def test_total_request_time_is_bounded(catalog: OperationCatalog) -> None:
    class SlowTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            await asyncio.sleep(0.05)
            return httpx.Response(200, json={"ok": True}, request=request)

    result = await make_client(catalog, SlowTransport(), timeout=0.01).invoke(
        "repoGet", path_params={"owner": "octo", "repo": "sample"}
    )

    assert result["error"] == {"kind": "timeout", "message": "Forgejo request timed out"}


@pytest.mark.asyncio
async def test_auth_header_is_sent_but_never_returned(catalog: OperationCatalog) -> None:
    transport = RecordingTransport(
        httpx.Response(403, json={"message": "echoed runtime-test-token"})
    )
    result = await make_client(catalog, transport).invoke(
        "repoGet", path_params={"owner": "octo", "repo": "sample"}
    )

    assert transport.request is not None
    assert transport.request.headers["authorization"] == "token runtime-test-token"
    assert result["status_code"] == 403
    assert result["error"] == {"kind": "http", "message": "Forgejo returned HTTP 403"}
    assert "runtime-test-token" not in json.dumps(result)


@pytest.mark.asyncio
async def test_http_error_omits_remote_body_with_token_and_request_secrets(
    catalog: OperationCatalog,
) -> None:
    password = "request-password-value"
    token = "runtime-test-token"
    sensitive_values = {
        token,
        base64.b64encode(token.encode()).decode(),
        password,
        base64.b64encode(password.encode()).decode(),
    }
    transport = RecordingTransport(
        httpx.Response(422, json={"remote_details": sorted(sensitive_values)})
    )

    result = await make_client(catalog, transport).invoke(
        "adminCreateUser",
        body={"username": "secret-test", "email": "qa@example.invalid", "password": password},
    )

    assert result == {
        "operation_id": "adminCreateUser",
        "status_code": 422,
        "ok": False,
        "error": {"kind": "http", "message": "Forgejo returned HTTP 422"},
    }
    serialized_result = json.dumps(result)
    assert all(secret not in serialized_result for secret in sensitive_values)


@pytest.mark.asyncio
async def test_binary_response_cannot_echo_access_token(catalog: OperationCatalog) -> None:
    transport = RecordingTransport(
        httpx.Response(
            200,
            content=b"prefix-runtime-test-token-suffix",
            headers={"content-type": "application/octet-stream"},
        )
    )

    result = await make_client(catalog, transport).invoke(
        "repoGetRawFile",
        path_params={"owner": "octo", "repo": "sample", "filepath": "archive.bin"},
    )
    decoded = base64.b64decode(result["body"]["data"])

    assert b"runtime-test-token" not in decoded
    assert len(decoded) == len(b"prefix-runtime-test-token-suffix")


@pytest.mark.asyncio
@pytest.mark.parametrize("status_code", [200, 422])
async def test_upstream_content_type_cannot_echo_access_token(
    catalog: OperationCatalog,
    status_code: int,
) -> None:
    transport = RecordingTransport(
        httpx.Response(
            status_code,
            content=b"response",
            headers={"content-type": "application/runtime-test-token"},
        )
    )

    result = await make_client(catalog, transport).invoke(
        "repoGetRawFile",
        path_params={"owner": "octo", "repo": "sample", "filepath": "archive.bin"},
    )

    assert "runtime-test-token" not in json.dumps(result)
    if status_code == 200:
        assert result["content_type"] == "application/******************"
        assert result["body"]["content_type"] == result["content_type"]


@pytest.mark.asyncio
async def test_truncation_redacts_token_crossing_response_boundary(
    catalog: OperationCatalog,
) -> None:
    token = "boundary-token-that-is-longer-than-the-visible-slice"
    prefix = b"safe-prefix"
    limit = len(prefix) + 12
    transport = RecordingTransport(
        httpx.Response(
            200,
            content=prefix + token.encode() + b"-suffix",
            headers={"content-type": "application/octet-stream"},
        )
    )
    client = ForgejoClient(
        catalog,
        "https://forgejo.example",
        token,
        transport=transport,
        max_binary_bytes=limit,
    )

    result = await client.invoke(
        "repoGetRawFile",
        path_params={"owner": "octo", "repo": "sample", "filepath": "archive.bin"},
    )
    decoded = base64.b64decode(result["body"]["data"])

    assert result["truncated"] is True
    assert decoded == prefix + (b"*" * 12)
    assert all(token[:length].encode() not in decoded for length in range(1, len(token) + 1))


@pytest.mark.asyncio
async def test_json_and_text_responses_are_bounded_with_marker(
    catalog: OperationCatalog,
) -> None:
    json_transport = RecordingTransport(httpx.Response(200, json={"name": "sample"}))
    parsed = await make_client(catalog, json_transport).invoke(
        "repoGet", path_params={"owner": "octo", "repo": "sample"}
    )
    text_transport = RecordingTransport(
        httpx.Response(200, content=b"a" * 40, headers={"content-type": "text/plain"})
    )
    truncated = await make_client(catalog, text_transport, max_text_bytes=32).invoke(
        "renderMarkdownRaw", body="hello"
    )

    assert parsed["body"] == {"name": "sample"}
    assert truncated["truncated"] is True
    assert truncated["body"].endswith(TRUNCATION_MARKER)
    assert len(truncated["body"].encode()) <= 32


@pytest.mark.asyncio
async def test_binary_responses_are_bounded_base64(catalog: OperationCatalog) -> None:
    transport = RecordingTransport(
        httpx.Response(
            200,
            content=b"0123456789",
            headers={"content-type": "application/octet-stream"},
        )
    )
    result = await make_client(catalog, transport, max_binary_bytes=5).invoke(
        "repoGetRawFile",
        path_params={"owner": "octo", "repo": "sample", "filepath": "archive.bin"},
    )

    assert result["truncated"] is True
    assert result["body"] == {
        "data": base64.b64encode(b"01234").decode(),
        "content_type": "application/octet-stream",
        "encoding": "base64",
        "bytes_included": 5,
        "truncated": True,
    }


def test_timeout_and_response_limits_cannot_exceed_safety_bounds(
    catalog: OperationCatalog,
) -> None:
    with pytest.raises(ConfigurationError, match="timeout must be between"):
        ForgejoClient(catalog, "https://forgejo.example", None, timeout=31)
    with pytest.raises(ConfigurationError, match="max_text_bytes must be between"):
        ForgejoClient(catalog, "https://forgejo.example", None, max_text_bytes=1_000_001)
