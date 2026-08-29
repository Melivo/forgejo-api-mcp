"""Stdio MCP tools for the spec-driven Forgejo API adapter."""

from __future__ import annotations

from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

from .catalog import OperationCatalog
from .client import ForgejoClient

catalog = OperationCatalog.bundled()
# Retain process-level environment configuration for every tool invocation.
client = ForgejoClient.from_environment(catalog)
server = MCPServer(
    name="forgejo-api",
    title="Forgejo OpenAPI",
    description="All Forgejo REST API operations from the bundled 1.25.4 Swagger snapshot.",
    version="0.1.0",
)


@server.tool(
    description=(
        "Discover Forgejo operations by optional text and exact tag filters. "
        "Results identify mutating and destructive operations; invoking either requires prior "
        "explicit user confirmation."
    ),
    annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=False),
)
async def list_operations(query: str | None = None, tag: str | None = None) -> dict[str, Any]:
    """Return compact invocation metadata for matching operations."""

    operations = catalog.list(query=query, tag=tag)
    return {
        "api_version": catalog.version,
        "count": len(operations),
        "operations": [
            {
                "operation_id": operation.operation_id,
                "method": operation.method,
                "path": operation.path,
                "summary": operation.summary,
                "tags": list(operation.tags),
                "parameters": {
                    location: sorted(names)
                    for location, names in operation.parameter_names.items()
                },
                "required_parameters": {
                    location: sorted(names)
                    for location, names in operation.required_parameters.items()
                },
                "consumes": list(operation.consumes),
                "response_content_types": list(operation.response_content_types),
                "is_mutating": operation.is_mutating,
                "is_destructive": operation.is_destructive,
            }
            for operation in operations
        ],
    }


@server.tool(
    description=(
        "Return the complete validated invocation contract for one Forgejo operation ID, "
        "including resolved schemas, effective media types, and mutation flags."
    ),
    annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=False),
)
async def get_operation(operation_id: str) -> dict[str, Any]:
    """Return the complete normalized contract for one operation."""

    return catalog.get(operation_id).to_dict()


@server.tool(
    description=(
        "Invoke one Forgejo REST API operation after validating path_params, query_params, "
        "header_params, body, form_params, and file_params against the bundled Swagger schema. "
        "File descriptors use content_base64, filename, and content_type. Write and destructive "
        "operations execute immediately; obtain explicit user confirmation before calling them."
    ),
    annotations=ToolAnnotations(
        readOnlyHint=False,
        destructiveHint=True,
        idempotentHint=False,
        openWorldHint=True,
    ),
)
async def invoke_operation(
    operation_id: str,
    path_params: dict[str, Any] | None = None,
    query_params: dict[str, Any] | None = None,
    header_params: dict[str, Any] | None = None,
    body: Any = None,
    form_params: dict[str, Any] | None = None,
    file_params: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Validate and dispatch an operation through the secure HTTP adapter."""

    return await client.invoke(
        operation_id=operation_id,
        path_params=path_params,
        query_params=query_params,
        header_params=header_params,
        body=body,
        form_params=form_params,
        file_params=file_params,
    )


@server.tool(
    description=(
        "Probe the STARTUP-snapshotted Forgejo credential with a strict-HTTPS, redirect-disabled, "
        "status-only GET /api/v1/user under an absolute <=30s deadline; the response body is never "
        "consumed. This tool does NOT re-read the platform credential store (Windows Credential "
        "Manager or Linux Secret Service). A 401 is classified as "
        "credential_rejected. Rotation ALWAYS requires restarting the MCP server "
        "(restartRequiredAfterRotation=true), even when the current snapshot returns HTTP 200. "
        "Never returns the token, header value, response body, or provider login."
    ),
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    ),
)
async def provider_auth_status() -> dict[str, Any]:
    """Return a redacted provider-auth status for the startup-snapshotted credential."""

    return await client.probe_auth()


def main() -> None:
    """Run only the MCP stdio transport; this process opens no HTTP listener."""

    server.run(transport="stdio")


if __name__ == "__main__":
    main()
