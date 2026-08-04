from __future__ import annotations

import base64
import json
from collections.abc import Mapping
from email import policy
from email.parser import BytesParser
from typing import Any
from urllib.parse import quote

import httpx
import pytest

from forgejo_api_mcp.catalog import Operation, OperationCatalog
from forgejo_api_mcp.client import ForgejoClient

SUPPORTED_PARAMETER_LOCATIONS = {"path", "query", "header", "body", "formData"}
SUPPORTED_REQUEST_MEDIA = {
    "application/json",
    "text/plain",
    "multipart/form-data",
    "application/octet-stream",
}
SUPPORTED_RESPONSE_MEDIA = {
    "application/json",
    "text/html",
    "text/plain",
    "application/octet-stream",
}


def _schema_value(schema: Mapping[str, Any]) -> Any:
    if schema.get("enum"):
        return schema["enum"][0]

    schema_type = schema.get("type")
    if schema_type == "object" or (
        schema_type is None and ("properties" in schema or "additionalProperties" in schema)
    ):
        properties = schema.get("properties", {})
        return {
            name: _schema_value(properties[name])
            for name in schema.get("required", [])
            if name in properties
        }
    if schema_type == "array":
        count = max(1, int(schema.get("minItems", 0)))
        return [_schema_value(schema.get("items", {})) for _ in range(count)]
    if schema_type == "integer":
        value = int(schema.get("minimum", 1))
        if schema.get("exclusiveMinimum"):
            value += 1
        multiple = schema.get("multipleOf")
        if multiple:
            value = max(value, int(multiple))
            remainder = value % int(multiple)
            if remainder:
                value += int(multiple) - remainder
        return value
    if schema_type == "number":
        value = float(schema.get("minimum", 1.0))
        if schema.get("exclusiveMinimum"):
            value += 1.0
        return value
    if schema_type == "boolean":
        return True
    if schema_type == "string":
        value_format = schema.get("format")
        if value_format == "date-time":
            return "2026-07-31T00:00:00+00:00"
        if value_format == "date":
            return "2026-07-31"
        if value_format == "email":
            return "qa@example.invalid"
        if value_format in {"uri", "url"}:
            return "https://example.invalid/resource"
        if value_format == "uuid":
            return "00000000-0000-4000-8000-000000000000"
        if value_format == "byte":
            return "cWE="
        minimum = max(1, int(schema.get("minLength", 0)))
        return "x" * minimum
    if schema_type == "file":
        return {"content_base64": "cWE=", "filename": "qa.txt", "content_type": "text/plain"}
    return {}


def _invocation_arguments(operation: Operation) -> dict[str, Any]:
    arguments: dict[str, Any] = {
        "path_params": {},
        "query_params": {},
        "header_params": {},
        "form_params": {},
        "file_params": {},
    }
    groups = {
        "path": arguments["path_params"],
        "query": arguments["query_params"],
        "header": arguments["header_params"],
        "formData": arguments["form_params"],
    }
    for parameter in operation.parameters:
        location = str(parameter["in"])
        if location == "body":
            continue
        name = str(parameter["name"])
        value = _schema_value(parameter)
        if location == "formData" and parameter.get("type") == "file":
            arguments["file_params"][name] = value
        else:
            groups[location][name] = value
    if operation.request_body_schema is not None:
        arguments["body"] = _schema_value(operation.request_body_schema)
    return arguments


def _response_for(media_type: str, request: httpx.Request) -> httpx.Response:
    if media_type == "application/json":
        return httpx.Response(200, json={"contract": "ok"}, request=request)
    if media_type.startswith("text/"):
        return httpx.Response(
            200,
            text="contract ok",
            headers={"content-type": media_type},
            request=request,
        )
    return httpx.Response(
        200,
        content=b"contract-binary",
        headers={"content-type": media_type},
        request=request,
    )


def _serialized_parameter(value: Any, collection_format: str | None) -> list[str] | str:
    values = value if isinstance(value, list | tuple) else None
    if values is None:
        if isinstance(value, bool):
            return "true" if value else "false"
        return str(value)
    serialized = ["true" if item is True else "false" if item is False else str(item) for item in values]
    if collection_format == "multi":
        return serialized
    separator = {"ssv": " ", "tsv": "\t", "pipes": "|"}.get(collection_format, ",")
    return separator.join(serialized)


def _expected_path(operation: Operation, arguments: dict[str, Any]) -> bytes:
    path = operation.path
    for parameter in operation.parameters:
        if parameter["in"] != "path":
            continue
        name = str(parameter["name"])
        serialized = _serialized_parameter(
            arguments["path_params"][name], parameter.get("collectionFormat")
        )
        if isinstance(serialized, list):
            serialized = ",".join(serialized)
        path = path.replace(f"{{{name}}}", quote(serialized, safe=""))
    return f"/api/v1{path}".encode()


def _expected_pairs(
    operation: Operation, arguments: dict[str, Any], location: str
) -> list[tuple[str, str]]:
    argument_name = {
        "query": "query_params",
        "header": "header_params",
        "formData": "form_params",
    }[location]
    values = arguments[argument_name]
    pairs: list[tuple[str, str]] = []
    for parameter in operation.parameters:
        if parameter["in"] != location or parameter.get("type") == "file":
            continue
        name = str(parameter["name"])
        serialized = _serialized_parameter(values[name], parameter.get("collectionFormat"))
        if isinstance(serialized, list):
            pairs.extend((name, item) for item in serialized)
        else:
            pairs.append((name, serialized))
    return pairs


def _assert_multipart_mapping(
    request: httpx.Request, operation: Operation, arguments: dict[str, Any]
) -> None:
    content_type = request.headers["content-type"]
    message = BytesParser(policy=policy.default).parsebytes(
        f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n".encode()
        + request.content
    )
    actual_parts = []
    for part in message.iter_parts():
        actual_parts.append(
            (
                part.get_param("name", header="content-disposition"),
                part.get_filename(),
                part.get_payload(decode=True),
                part.get_content_type(),
            )
        )

    expected_parts = [
        (name, None, value.encode(), "text/plain")
        for name, value in _expected_pairs(operation, arguments, "formData")
    ]
    for parameter in operation.parameters:
        if parameter["in"] != "formData" or parameter.get("type") != "file":
            continue
        name = str(parameter["name"])
        descriptor = arguments["file_params"][name]
        expected_parts.append(
            (
                name,
                descriptor["filename"],
                base64.b64decode(descriptor["content_base64"]),
                descriptor["content_type"],
            )
        )
    assert actual_parts == expected_parts, operation.operation_id


def _assert_request_mapping(
    request: httpx.Request, operation: Operation, arguments: dict[str, Any]
) -> None:
    assert request.method == operation.method, operation.operation_id
    assert request.url.raw_path.split(b"?", 1)[0] == _expected_path(
        operation, arguments
    ), operation.operation_id
    assert list(request.url.params.multi_items()) == _expected_pairs(
        operation, arguments, "query"
    ), operation.operation_id

    for name, value in _expected_pairs(operation, arguments, "header"):
        assert request.headers[name] == value, operation.operation_id
    assert request.headers["authorization"] == "token contract-test-token", operation.operation_id
    assert request.headers["accept-encoding"] == "identity", operation.operation_id
    assert request.headers["accept"] == operation.produces[0], operation.operation_id

    if arguments["file_params"] or arguments["form_params"]:
        assert request.headers["content-type"].startswith(
            "multipart/form-data; boundary="
        ), operation.operation_id
        _assert_multipart_mapping(request, operation, arguments)
    elif "body" in arguments:
        if operation.consumes == ("text/plain",):
            assert request.headers["content-type"] == "text/plain", operation.operation_id
            assert request.content == arguments["body"].encode(), operation.operation_id
        else:
            assert request.headers["content-type"] == "application/json", operation.operation_id
            assert json.loads(request.content) == arguments["body"], operation.operation_id
    else:
        assert request.content == b"", operation.operation_id


@pytest.mark.asyncio
async def test_all_467_operations_conform_to_catalog_and_adapter_mappings() -> None:
    catalog = OperationCatalog.bundled()
    operations = catalog.list()
    assert len(operations) == 467
    assert len({operation.operation_id for operation in operations}) == 467

    exercised_locations: set[str] = set()
    exercised_request_media: set[str] = set()
    exercised_response_media: set[str] = set()

    for operation in operations:
        locations = {str(parameter["in"]) for parameter in operation.parameters}
        assert locations <= SUPPORTED_PARAMETER_LOCATIONS, operation.operation_id
        assert set(operation.consumes) <= SUPPORTED_REQUEST_MEDIA, operation.operation_id
        assert set(operation.response_content_types) <= SUPPORTED_RESPONSE_MEDIA, operation.operation_id
        assert operation.response_content_types, operation.operation_id
        if "formData" in locations:
            assert "multipart/form-data" in operation.consumes, operation.operation_id
        if "body" in locations:
            assert operation.request_body_schema is not None, operation.operation_id

        exercised_locations.update(locations)
        exercised_request_media.update(operation.consumes)
        arguments = _invocation_arguments(operation)

        for media_type in operation.response_content_types:
            captured: dict[str, httpx.Request] = {}

            async def handler(
                request: httpx.Request,
                response_media: str = media_type,
                requests: dict[str, httpx.Request] = captured,
            ) -> httpx.Response:
                await request.aread()
                requests["request"] = request
                return _response_for(response_media, request)

            transport = httpx.MockTransport(handler)
            client = ForgejoClient(
                catalog,
                "https://forgejo.invalid",
                "contract-test-token",
                transport=transport,
            )
            result = await client.invoke(operation.operation_id, **arguments)

            _assert_request_mapping(captured["request"], operation, arguments)
            assert result["ok"] is True, operation.operation_id
            assert result["status_code"] == 200, operation.operation_id
            assert result["content_type"] == media_type, operation.operation_id
            if media_type == "application/json":
                assert result["body"] == {"contract": "ok"}, operation.operation_id
            elif media_type.startswith("text/"):
                assert result["body"] == "contract ok", operation.operation_id
            else:
                assert result["body"]["encoding"] == "base64", operation.operation_id
                assert result["body"]["content_type"] == media_type, operation.operation_id
            exercised_response_media.add(media_type)

    assert exercised_locations == {"path", "query", "body", "formData"}
    assert exercised_request_media == SUPPORTED_REQUEST_MEDIA
    assert exercised_response_media == SUPPORTED_RESPONSE_MEDIA
