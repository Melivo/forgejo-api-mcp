from __future__ import annotations

from typing import Any

import httpx
import pytest

from forgejo_api_mcp import server as server_module


@pytest.mark.asyncio
async def test_server_registers_discovery_detail_invocation_and_status_tools() -> None:
    tools = {tool.name: tool for tool in await server_module.server.list_tools()}

    assert set(tools) == {
        "list_operations",
        "get_operation",
        "invoke_operation",
        "provider_auth_status",
    }
    assert tools["list_operations"].annotations.read_only_hint is True
    assert tools["get_operation"].annotations.read_only_hint is True
    assert tools["invoke_operation"].annotations.destructive_hint is True
    assert tools["provider_auth_status"].annotations.read_only_hint is True
    assert tools["provider_auth_status"].annotations.idempotent_hint is True
    assert tools["provider_auth_status"].annotations.destructive_hint is False
    assert "explicit user confirmation" in tools["invoke_operation"].description


@pytest.mark.asyncio
async def test_invoke_operation_schema_exposes_every_separated_input_group() -> None:
    tools = {tool.name: tool for tool in await server_module.server.list_tools()}
    schema = tools["invoke_operation"].input_schema

    assert schema["required"] == ["operation_id"]
    assert set(schema["properties"]) == {
        "operation_id",
        "path_params",
        "query_params",
        "header_params",
        "body",
        "form_params",
        "file_params",
    }


@pytest.mark.asyncio
async def test_list_and_get_operation_include_media_and_mutation_contracts() -> None:
    listed = await server_module.list_operations(query="ActionsDispatchWorkflow", tag="repository")
    detail = await server_module.get_operation("ActionsDispatchWorkflow")

    assert listed["count"] == 1
    assert listed["operations"][0]["is_mutating"] is True
    assert listed["operations"][0]["is_destructive"] is False
    assert detail["request_body_schema"]["properties"]["inputs"]["additionalProperties"] == {
        "type": "string"
    }
    assert detail["consumes"] == ["application/json", "text/plain"]
    assert detail["response_content_types"] == ["application/json"]


@pytest.mark.asyncio
async def test_invoke_tool_delegates_all_argument_groups(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    class StubClient:
        async def invoke(self, **kwargs: Any) -> dict[str, Any]:
            captured.update(kwargs)
            return {"ok": True}

    monkeypatch.setattr(server_module, "client", StubClient())
    result = await server_module.invoke_operation(
        "sampleOperation",
        path_params={"path": "value"},
        query_params={"query": 1},
        header_params={"header": "value"},
        body={"body": True},
        form_params={"form": "value"},
        file_params={"file": {"content_base64": ""}},
    )

    assert result == {"ok": True}
    assert captured == {
        "operation_id": "sampleOperation",
        "path_params": {"path": "value"},
        "query_params": {"query": 1},
        "header_params": {"header": "value"},
        "body": {"body": True},
        "form_params": {"form": "value"},
        "file_params": {"file": {"content_base64": ""}},
    }


@pytest.mark.asyncio
async def test_server_retains_initial_base_url_after_environment_changes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests: list[httpx.Request] = []

    def handle_request(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"ok": True}, request=request)

    monkeypatch.setenv("FORGEJO_BASE_URL", "https://initial.example/forgejo")
    retained_client = server_module.ForgejoClient.from_environment(server_module.catalog)
    retained_client._transport = httpx.MockTransport(handle_request)
    monkeypatch.setattr(server_module, "client", retained_client)

    monkeypatch.setenv("FORGEJO_BASE_URL", "https://changed.example")
    result = await server_module.invoke_operation(
        "repoGet",
        path_params={"owner": "octo", "repo": "sample"},
    )

    assert result["ok"] is True
    assert len(requests) == 1
    assert requests[0].url.host == "initial.example"
    assert requests[0].url.path.startswith("/forgejo/api/v1/")


def test_main_runs_stdio_only(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    def fake_run(*, transport: str, **kwargs: Any) -> None:
        captured["transport"] = transport
        captured["kwargs"] = kwargs

    monkeypatch.setattr(server_module.server, "run", fake_run)
    server_module.main()

    assert captured == {"transport": "stdio", "kwargs": {}}


@pytest.mark.asyncio
async def test_provider_auth_status_reports_authenticated_for_200(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def handle_request(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/v1/user"
        return httpx.Response(200, json={"login": "alice"}, request=request)

    probe_client = server_module.ForgejoClient.from_environment(server_module.catalog)
    probe_client._transport = httpx.MockTransport(handle_request)
    probe_client._token = "good"
    probe_client._token_bytes = b"good"
    monkeypatch.setattr(server_module, "client", probe_client)

    result = await server_module.provider_auth_status()

    assert result["snapshotStatus"] == "authenticated"
    assert "login" not in result
    assert result["usesStartupSnapshot"] is True
    assert result["restartRequiredAfterRotation"] is True
    assert "restartRequired" not in result
    assert "good" not in str(result)


@pytest.mark.asyncio
async def test_provider_auth_status_classifies_401_as_credential_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def handle_request(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, request=request)

    probe_client = server_module.ForgejoClient.from_environment(server_module.catalog)
    probe_client._transport = httpx.MockTransport(handle_request)
    probe_client._token = "stale"
    probe_client._token_bytes = b"stale"
    monkeypatch.setattr(server_module, "client", probe_client)

    result = await server_module.provider_auth_status()

    assert result["snapshotStatus"] == "credential_rejected"
    assert result["status_code"] == 401
    assert result["restartRequiredAfterRotation"] is True
    assert "stale" not in str(result)


@pytest.mark.asyncio
async def test_provider_auth_status_reports_unconfigured_without_a_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    probe_client = server_module.ForgejoClient(
        server_module.catalog, "https://forgejo.example", None
    )
    monkeypatch.setattr(server_module, "client", probe_client)

    result = await server_module.provider_auth_status()

    assert result["snapshotStatus"] == "unconfigured"
    assert result["usesStartupSnapshot"] is True
    assert result["restartRequiredAfterRotation"] is True
    assert "login" not in result


@pytest.mark.asyncio
async def test_provider_auth_status_rejects_insecure_base_without_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests: list[httpx.Request] = []

    def handle_request(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, request=request)

    probe_client = server_module.ForgejoClient(
        server_module.catalog,
        "http://localhost:3000",
        "candidate",
        allow_insecure_localhost=True,
        transport=httpx.MockTransport(handle_request),
    )
    monkeypatch.setattr(server_module, "client", probe_client)

    result = await server_module.provider_auth_status()

    assert result["snapshotStatus"] == "insecure_base_url"
    assert result["status_code"] == 0
    assert result["restartRequiredAfterRotation"] is True
    assert requests == []
