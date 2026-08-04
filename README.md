# Forgejo API MCP

A local stdio MCP server that exposes all 467 operations in the bundled Forgejo
1.25.4 OpenAPI snapshot.

- `list_operations` finds operation IDs and accepted parameter names.
- `get_operation` returns the full invocation contract for one operation ID.
- `invoke_operation` invokes an operation after validating declared path, query,
  header, body, form, and file requirements.

Write and destructive operations execute immediately. An MCP client or agent
must obtain explicit user confirmation before calling them.

## Installation

Install with `uv` from the project checkout:

```powershell
uv sync
uv run forgejo-api-mcp
```

The server requires Python 3.12 or newer and runs only as a local MCP stdio
process. It does not open an HTTP listener.

## Launch without committing secrets

`FORGEJO_ACCESS_TOKEN` must be present in the child process environment. Do not
store the token in this repository, OpenCode config, command arguments, dotenv
files, shell history, examples, or logs.

For an ad-hoc local shell, set the variable only in the current process:

```powershell
$env:FORGEJO_ACCESS_TOKEN = "<token>"
uv run forgejo-api-mcp
```

`FORGEJO_BASE_URL` defaults to `https://forgejo.invalid`. HTTPS is required
unless `FORGEJO_ALLOW_INSECURE_HTTP=1` is deliberately set for local testing.
The base URL is normalized once to the Forgejo `/api/v1` path.

On Windows, launch through the existing Credential Manager wrapper instead of
placing the token in config. See [docs/credential-launch.md](docs/credential-launch.md)
for the reviewed OpenCode entry. The wrapper reads the existing Credential
Manager target, injects it as `FORGEJO_ACCESS_TOKEN` only for the child process,
and starts:

```powershell
uv --project <project-path>/forgejo-api-mcp run forgejo-api-mcp
```

## OpenCode integration

Register the server as a local MCP server whose command invokes the Windows
credential wrapper. The OpenCode entry may include non-secret environment such
as `FORGEJO_BASE_URL`, but it must not include `FORGEJO_ACCESS_TOKEN` or any
credential value. Configure a bounded client launch timeout, for example
`60000` ms, so failed starts do not hang indefinitely.

## Operation discovery and safe invocation

Use `list_operations` before invoking an operation:

```json
{"query":"repo","tag":"repository"}
```

Then inspect the selected contract:

```json
{"operation_id":"repoGet"}
```

Invoke with separated parameter groups only after checking the operation's
`is_mutating` and `is_destructive` flags:

```json
{
  "operation_id": "repoGet",
  "path_params": {"owner": "example", "repo": "project"},
  "query_params": {},
  "header_params": {},
  "body": null,
  "form_params": {},
  "file_params": {}
}
```

For every write, delete, admin, workflow-dispatch, or otherwise mutating
operation, the user must explicitly confirm the exact operation ID and intended
target before `invoke_operation` is called. Read-only discovery tools do not
perform network writes.

## Bounds and timeouts

Every Forgejo request uses an explicit bounded HTTP timeout: default 30 seconds,
with runtime values capped at 30 seconds. JSON and text responses are capped at
1 MB with a truncation marker. Binary responses are returned as bounded base64
objects with `content_type` and `encoding` metadata and a default 10 MB byte cap.
Timeouts, transport failures, and non-2xx responses are returned as structured,
non-sensitive results.

## Maintenance

The bundled OpenAPI snapshot is a reviewed artifact, not a runtime download. See
[docs/maintenance.md](docs/maintenance.md) for the required update procedure:
record the Forgejo server version, operation-count diff, and test results before
accepting a snapshot change.

## Development

```powershell
uv run ruff check .
uv run pytest
```
