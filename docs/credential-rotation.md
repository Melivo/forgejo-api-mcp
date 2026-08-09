# Rotating the Forgejo access token

The MCP server snapshots `FORGEJO_ACCESS_TOKEN` once at process start
([`server.py`](../src/forgejo_api_mcp/server.py) constructs the client at import time). When a
Forgejo token expires or is rotated in Windows Credential Manager, the **running** server keeps
the stale token and Forgejo returns `401`. This project ships a project-owned rotation CLI and
an in-band status probe so a stale token can be replaced and diagnosed without editing config.

> Decision record: two approaches were considered. **A — project-owned Python rotation CLI +
> MCP status probe via the ctypes Win32 Credential API (no new dependency)** was chosen over
> **B — extending the external `credential-exec.ps1` wrapper** (not project-owned and not
> testable in this repository). Runtime hot reload is out of scope because the server deliberately
> retains its process-start snapshot.

## Prerequisites

- Windows with PowerShell 5.1 or `pwsh`.
- `uv` on `PATH` and this project synchronized with `uv sync`.
- The Windows Credential Manager generic target `mcp/forgejo-mcp/access-token` (created/updated
  by the rotation CLI below).

## Rotate the token (stdin only)

The rotation CLI reads the token **only from stdin** (a secure no-echo `getpass` prompt on a
TTY, or a single piped line for automation). It never accepts the token as a command-line
argument, environment value, or MCP tool argument, so it cannot leak into shell history, process
listings, or MCP transcripts.

```powershell
# Interactive (no-echo prompt):
uv run forgejo-api-mcp-rotate

# Piped input is supported, but keep the value out of scripts and shell history.
```

The command accepts no arguments and has no username option. The non-secret UserName is fixed
as `forgejo-api-mcp`. Set the non-secret `FORGEJO_BASE_URL` environment value when needed; it
defaults to `https://forgejo.invalid`. Secret-like environment variables are ignored by the
rotation command; the candidate credential is read from stdin only.

### What the CLI does, in order

1. Checks that the Windows credential store is available **before stdin or network access**.
2. Requires an HTTPS base URL before stdin or network access. Rotation never honors
   `FORGEJO_ALLOW_INSECURE_HTTP`.
3. Reads exactly one line from stdin and rejects empty or CR/LF/NUL-bearing input.
4. Validates the candidate with a redirect-disabled, no-proxy HTTPS
   `GET {base}/api/v1/user` (`follow_redirects=False`, `trust_env=False`) under an **absolute
   wall-clock deadline** of at most 30 seconds. Classification uses the HTTP status only. The
   response body is never consumed or parsed, and no provider login is processed.
5. Acquires a bounded, user-scoped Windows named mutex in the `Local\\` namespace. Same-user
   rotations serialize; different users do not block each other. An abandoned mutex is safely
   acquired because readback and verified rollback make the transaction self-checking.
6. Captures the full constrained prior record, then writes the candidate to the single target
   `mcp/forgejo-mcp/access-token` via the Win32 `CredWriteW` API (ctypes) — the `cmdkey /pass`
   route is deliberately avoided so the secret never reaches a process command line.
7. Reads back with `CredReadW` and compares in constant time. A mismatch or read failure triggers
   verified rollback: restore the prior `CredentialRecord`, or delete and verify absence when the
   entry was new. Failed rollback verification reports `credentialState: unknown`.
8. Releases the mutex in `finally` and prints one redacted JSON object.

### Redacted output

The raw token, credential blob, `Authorization` header value, response body, provider login, and
token fingerprints are never logged or returned. Only these fields are emitted:

```jsonc
{
  "target": "mcp/forgejo-mcp/access-token",
  "status": "rotated",
  "credentialState": "written",
  "validatedAt": "2026-08-08T01:57:31+00:00",
  "restartRequired": true,
  "detail": "Credential rotated. Restart the MCP server so the launch wrapper reloads it."
}
```

`restartRequired` is true only for a durable `rotated` result. The exact state table is:

| # | Phase and outcome | Status | Exit | credentialState | Restart |
|---:|---|---|---:|---|---|
| 1 | platform/store unavailable | `platform_unsupported` | 9 | `unavailable` | no |
| 2 | non-HTTPS base URL | `invalid_input` | 2 | `unchanged` | no |
| 3 | empty or multiline candidate | `invalid_input` | 2 | `unchanged` | no |
| 4 | any command argument, including token or username flags | `invalid_input` | 2 | `unchanged` | no |
| 5 | HTTP 401 | `credential_rejected` | 3 | `unchanged` | no |
| 6 | HTTP 403 | `forbidden` | 4 | `unchanged` | no |
| 7 | other non-2xx response | `provider_error` | 5 | `unchanged` | no |
| 8 | absolute deadline exceeded | `transport_or_timeout` | 6 | `unchanged` | no |
| 9 | transport error | `transport_or_timeout` | 6 | `unchanged` | no |
| 10 | user-scoped mutex wait times out; zero writes | `credential_store_error` | 7 | `unchanged` | no |
| 11 | prior-record capture fails; zero writes | `credential_store_error` | 7 | `unchanged` | no |
| 12 | credential write fails before commit | `credential_store_error` | 7 | `unchanged` | no |
| 13 | readback equals candidate | `rotated` | 0 | `written` | **yes** |
| 14 | mismatch; prior record restored and verified | `readback_mismatch` | 8 | `restored` | no |
| 15 | mismatch; new entry deleted and verified | `readback_mismatch` | 8 | `deleted_new` | no |
| 16 | readback fails; prior record restored and verified | `credential_store_error` | 7 | `restored` | no |
| 17 | readback fails; new entry deleted and verified | `credential_store_error` | 7 | `deleted_new` | no |
| 18 | rollback cannot be verified | `credential_store_error` | 7 | `unknown` | no |

The complete exit-code vocabulary is `0`, `2`, `3`, `4`, `5`, `6`, `7`, `8`, and `9` as mapped
above.

## Restart requirement (important)

Rotation updates the credential store; it does **not** change the already-running MCP server,
which keeps its startup snapshot. After a successful rotation (`status: rotated`), restart the
MCP server so the launch wrapper ([`credential-launch.md`](credential-launch.md)) reloads the
fresh token into the child-process environment.

## Diagnose the running server: `provider_auth_status`

Use the read-only `provider_auth_status` MCP tool to check whether the credential snapshotted at
startup still works. It reuses the strict HTTPS, status-only probe and never re-reads Credential
Manager. No snapshot credential returns `unconfigured` without a request. A non-HTTPS base URL
returns `insecure_base_url` without a request. A `401` returns `credential_rejected`.

```json
{"usesStartupSnapshot": true, "restartRequiredAfterRotation": true, "snapshotStatus": "authenticated", "status_code": 200, "detail": "token authenticated"}
```

```json
{"usesStartupSnapshot": true, "restartRequiredAfterRotation": true, "snapshotStatus": "credential_rejected", "status_code": 401, "detail": "Forgejo rejected the token (401)"}
```

`usesStartupSnapshot` and `restartRequiredAfterRotation` are always true. A current HTTP 200 never
means that a post-rotation restart can be skipped. Provider login data is never parsed or returned.

## Mandatory redacted local launcher verification

Before release acceptance, an operator must perform a **manual, redacted, local Windows**
verification that `credential-exec.ps1` reads its Credential Manager value and injects it into the
server. This checks injection interoperability only; it must never rotate a production credential.
Use either an explicitly authorized existing test/recovery credential or a documented manual
operator check.

Record only the target name and per-step `PASS`/`FAIL`; never record a token or `CredentialBlob`:

1. `PASS`/`FAIL`: operator authorizes the existing non-production test/recovery credential or
   documents the equivalent manual check.
2. `PASS`/`FAIL`: wrapper starts/reloads the local server and injects that credential.
3. `PASS`/`FAIL`: `provider_auth_status` reflects the startup credential's status without exposing
   it.
4. `PASS`/`FAIL`: an independent, redacted `CredReadW` check confirms the wrapper reads target
   `mcp/forgejo-mcp/access-token`; do not print the blob.

This manual local check is mandatory for the final gate. A non-production Forgejo CI verifier and
automated Windows CI-runner attestation are not required by this workflow; they remain follow-up
work in Serena todo
`global/todos/setup-github-hosted-windows-runner-forgejo-credential-interop-20260809`.

Never place credential material in JSON, shell history, test data, logs, or error reports.
