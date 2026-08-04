# Credential-wrapper launch requirements

This server must be launched through the existing Windows Credential Manager wrapper. The
wrapper resolves the credential only for the child process and injects it as
`FORGEJO_ACCESS_TOKEN`; neither OpenCode nor this project stores the credential value.

## Prerequisites

- Windows PowerShell 5.1 or PowerShell 7 (`pwsh`).
- The existing wrapper at
  `C:/Users/<username>/AppData/Local/mcp/servers/forgejo-mcp/scripts/credential-exec.ps1`.
- The existing Windows Credential Manager target `mcp/forgejo-mcp/access-token`.
- `uv` on `PATH` and this project synchronized with `uv sync`.

The wrapper's `-Target` selects the Credential Manager entry. `-EnvName` names the child-process
environment variable; it is not a credential value. Do not add `FORGEJO_ACCESS_TOKEN` to an
OpenCode `environment` object, a dotenv file, command arguments, or project configuration.

## OpenCode local MCP launch

Add a local MCP entry equivalent to the following. Replace only `<username>` and `<project-path>`;
the example intentionally contains no credential value.

```jsonc
{
  "mcp": {
    "forgejo-api": {
      "type": "local",
      "command": [
        "pwsh",
        "-NoProfile",
        "-File",
        "C:/Users/<username>/AppData/Local/mcp/servers/forgejo-mcp/scripts/credential-exec.ps1",
        "-Target",
        "mcp/forgejo-mcp/access-token",
        "-EnvName",
        "FORGEJO_ACCESS_TOKEN",
        "-Command",
        "uv",
        "-CommandArgsJson",
        "[\"--project\",\"<project-path>/forgejo-api-mcp\",\"run\",\"forgejo-api-mcp\"]"
      ],
      "environment": {
        "FORGEJO_BASE_URL": "https://forgejo.invalid"
      },
      "enabled": true,
      "timeout": 60000
    }
  }
}
```

The child command starts the MCP server on **stdio**. It does not open an HTTP listener. Standard
output is reserved for MCP protocol frames; launch diagnostics and wrapper failures must remain on
standard error. `FORGEJO_BASE_URL` is non-secret and optional because the same HTTPS URL is the
application default.

## Launch flow and safety properties

1. OpenCode starts `credential-exec.ps1`.
2. The wrapper reads `mcp/forgejo-mcp/access-token` from Windows Credential Manager.
3. The wrapper places the value in `FORGEJO_ACCESS_TOKEN` only in its process environment and
   starts `uv --project <project-path>/forgejo-api-mcp run forgejo-api-mcp`.
4. The server inherits the variable, communicates over stdio, and sends it only as Forgejo's
   supported `Authorization: token ...` request header.
5. The wrapper restores its previous process environment when the child exits.

Never place the credential in the JSONC entry, shell history, test data, logs, or error reports.
