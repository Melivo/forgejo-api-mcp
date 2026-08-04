# Maintenance

This project exposes Forgejo through a bundled, reviewed Swagger/OpenAPI
snapshot. Runtime startup must be reproducible: the server loads
`src/forgejo_api_mcp/openapi.json` from the installed package and does not fetch
the specification from Forgejo on every launch.

## Installation and launch checks

1. Install dependencies from the repository root:

   ```powershell
   uv sync
   ```

2. Start the MCP server with a process environment that contains
   `FORGEJO_ACCESS_TOKEN`:

   ```powershell
   uv run forgejo-api-mcp
   ```

3. Prefer the Windows Credential Manager wrapper for OpenCode or other local MCP
   clients. The wrapper path and target are documented in
   [credential-launch.md](credential-launch.md). The launch configuration must
   contain no token value; only non-secret settings such as `FORGEJO_BASE_URL`
   may appear in client configuration.

4. The process speaks MCP over stdio only. Keep stdout reserved for protocol
   frames and route wrapper diagnostics to stderr.

## OpenCode operation workflow

Use discovery before invocation:

1. Call `list_operations` with optional `query` and `tag` filters. The response
   includes the bundled API version, result count, accepted parameter names,
   required parameter names, media types, and mutation/destruction flags.
2. Call `get_operation` for the chosen `operation_id` to review the full
   invocation contract, including path/query/header parameters, body schema,
   form/file inputs, effective consumes, and response content types.
3. Call `invoke_operation` with separated `path_params`, `query_params`,
   `header_params`, `body`, `form_params`, and `file_params`. File descriptors
   use bounded base64 content plus filename/content-type metadata.

Agents and MCP clients must obtain explicit user confirmation before invoking
any operation where `is_mutating` or `is_destructive` is true, or where the
operation will create, update, delete, administer, dispatch, upload, or otherwise
change server state. Confirmation should include the exact operation ID, target
owner/repository/resource, and intended effect. Do not treat discovery or schema
validation as consent to write.

## Runtime safety bounds

- `FORGEJO_BASE_URL` defaults to `https://forgejo.invalid` and is normalized
  once to the Forgejo `/api/v1` base path. Non-HTTPS URLs are rejected except for
  deliberate localhost testing with `FORGEJO_ALLOW_INSECURE_HTTP=1`.
- Operation inputs cannot override the resolved host or protected headers such
  as `Authorization`.
- The HTTP timeout defaults to 30 seconds and cannot be configured above 30
  seconds.
- JSON and text responses are capped at 1 MB and include an explicit truncation
  marker when shortened.
- Binary responses are represented as bounded base64 objects with `content_type`
  and `encoding` fields and a default 10 MB byte cap.
- Timeout, transport, validation, and non-2xx errors must remain structured and
  must not echo token values or sensitive headers.

## Reviewed OpenAPI snapshot update procedure

Use this checklist whenever `src/forgejo_api_mcp/openapi.json` changes.

1. Record the source Forgejo server version and where the snapshot came from.
   The current reviewed snapshot is Forgejo `1.25.4` with `467` operations.
2. Replace the snapshot only as a deliberate reviewed change. Do not add runtime
   fetching as a substitute for review.
3. Compute and record the operation-count diff:

   ```powershell
   uv run python -c "from forgejo_api_mcp.catalog import OperationCatalog; c=OperationCatalog.bundled(); print(c.version, len(c))"
   ```

   The review note should state the previous version/count, new version/count,
   and the numeric delta, for example `467 -> 468 (+1)`.
4. Review representative changed operations for parameter groups, body schemas,
   consumes/produces inheritance, response content types, and mutation flags.
5. Run the automated checks and record the results in the change review:

   ```powershell
   uv run ruff check .
   uv run pytest
   ```

6. If the package build path is affected, also verify the wheel and sdist load
   the bundled catalog from an isolated install.
7. Only after tests pass, perform any live smoke test as read-only or otherwise
   non-destructive. Never invoke create/update/delete/admin/workflow-dispatch
   operations during a snapshot smoke test without separate explicit approval.

The required review evidence is: server version, operation-count diff, notable
contract changes, and test results.
