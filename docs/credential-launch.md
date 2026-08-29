# Credential launch (canonical guide)

This guide is the canonical setup for the package-owned launcher. It starts the MCP server
through local `stdio` only; it never opens HTTP, SSE, or Streamable HTTP. Replace angle-bracket
placeholders only. Never put a token, username, or other secret in source, arguments, files, logs,
or client configuration. The non-secret Forgejo base URL is the only permitted endpoint setting.

## Dependencies and setup

```bash
uv sync --locked
uv run forgejo-api-mcp-launch
uv run forgejo-api-mcp-rotate
uv run forgejo-api-mcp-quarantine check
```

```powershell
uv sync --locked
uv run forgejo-api-mcp-launch
uv run forgejo-api-mcp-rotate
uv run forgejo-api-mcp-quarantine check
```

`forgejo-api-mcp` is the direct server entry point; `forgejo-api-mcp-launch` reads the platform
store once and injects `FORGEJO_ACCESS_TOKEN` only into the child; `forgejo-api-mcp-rotate` reads
the replacement from stdin. Credential-bearing configuration is forbidden: never place
`FORGEJO_ACCESS_TOKEN` or a token in OpenCode settings, dotenv files, arguments, examples, or logs.
The non-secret `FORGEJO_BASE_URL` is permitted and must be an HTTPS URL whenever configured;
the examples below set it as `https://<forgejo-host>`.

## Linux: Secret Service

Linux installs `SecretStorage>=3.5,<4` with the exact marker
`SecretStorage>=3.5,<4; sys_platform == 'linux'`. Jeepney and cryptography are transitive.
Runtime requires a D-Bus **user session**, a running Secret Service daemon, and an existing,
unlocked collection addressable as the `default` alias. A trusted Secret Service manager must
provision exactly one item before runtime with:

| Field | Exact value |
|---|---|
| `application` | `forgejo-api-mcp` |
| `credential-kind` | `access-token` |
| `target` | `mcp/forgejo-mcp/access-token` |
| label | `Forgejo API MCP access token` |
| content type | `text/plain` |

Provision and unlock it outside product runtime with a trusted Secret Service manager; the product
path does not create collections/items or unlock, prompt, delete, call `secret-tool`, run an
external credential command, use raw D-Bus, or fall back to a file. For example, start an isolated manager/session
for an opt-in smoke test (synthetic data only):

```bash
dbus-run-session -- bash -lc 'eval "$(gnome-keyring-daemon --start --components=secrets)"; export RUN_LINUX_SECRETSERVICE_SMOKE=1 FORGEJO_LIVE_SECRET_SERVICE_ISOLATED=1; uv run pytest tests/smoke/test_linux_secretservice.py'
```

### Provisioning check

Verify provisioning without printing or exporting the secret. The operator's trusted Secret
Service manager must confirm every item below for the **current user** before launch:

1. The current user has an active D-Bus session and the Secret Service daemon is running in that
   session.
2. The existing `default` collection is present and unlocked; do not accept a newly created,
   arbitrary, or session-only collection.
3. Exactly one item matches all three immutable attributes, with no duplicate exact match:
   `application=forgejo-api-mcp`, `credential-kind=access-token`, and
   `target=mcp/forgejo-mcp/access-token`.
4. That same item has the exact fixed label `Forgejo API MCP access token` and content type
   `text/plain`.

The manager verification is noninteractive from the product's perspective: launcher and rotation
must not unlock, prompt, create, delete, or invoke a credential helper. Record only a redacted
pass/fail result; never copy the item secret or any secret-bearing field.

The package readiness check confirms only non-mutating service/collection availability and does
not replace the manager's exact-item verification:

```bash
export FORGEJO_BASE_URL="https://<forgejo-host>"
uv run python -c 'from forgejo_api_mcp.linux_credentials import _run_worker_operation; _run_worker_operation("availability", None); print("Secret Service prerequisites available")'
```

Run this inside the current user's D-Bus session. Do not use a shell credential helper or put item
content in the command.

## Launch

The normal launch is strict and noninteractive:

```bash
export FORGEJO_BASE_URL="https://<forgejo-host>"
uv run forgejo-api-mcp-launch
```

```powershell
$env:FORGEJO_BASE_URL = "https://<forgejo-host>"
uv run forgejo-api-mcp-launch
```

Each SecretStorage operation runs in a fresh spawn worker under one 5-second deadline. Worker
termination does not pretend to cancel an already dispatched D-Bus mutation. A fixed-content,
non-secret `0600` quarantine marker is atomically and durably installed under the anchored runtime
directory before every mutation. It is removed after a confirmed response, but remains after every
dispatched mutating timeout. Rotation performs bounded diagnostic read/restore/final-read evidence
under the same lock, yet the public result remains `credentialState: unknown`. A restore timeout
also receives a final diagnostic read and remains quarantined. Setup failures are stable and
redacted (`missing`, `locked`, `prompt_required`, `prompt_dismissed`, `service_unavailable`,
`timeout`, or `store_error`) and include only the trusted-manager setup guidance. A POSIX lock
uses the file named forgejo-api-mcp-rotate.lock under XDG_RUNTIME_DIR, requiring an effective-user-owned `0700`
runtime directory and a `0600` regular lock file; lock timeout is bounded to 30 seconds.

### Quarantine administration

The marker is `forgejo-api-mcp-quarantine` in that same private directory and contains only the
fixed version line `forgejo-api-mcp-linux-quarantine-v1`. Creation, validation, and removal use the
anchored directory descriptor, no-follow opens, owner/mode/type/device/inode checks, atomic replace,
and file/directory `fsync`. While present, launcher reads and future rotations stop before any
Secret Service call with stable `store_error/unknown` quarantine guidance.

Do not clear the marker merely because an immediate manager view looks old: a late commit can still
arrive. First externally verify the exact item, all immutable attributes, fixed label, and
`text/plain` content type with a trusted Secret Service manager. Also confirm the current-user
Secret Service daemon has settled or has been restarted. Only after those checks may the operator
run:

```bash
uv run forgejo-api-mcp-quarantine check
uv run forgejo-api-mcp-quarantine clear --operator-verified
```

The administration command is noninteractive, secret-free, bounded by the existing lock timeout,
and never accesses Secret Service. `check` returns exit `0` when clear or `10` when quarantined;
invalid input, marker/store failure, and unsupported platform return `2`, `7`, and `9`.

Normal, handled-error, and service-timeout paths discard the opaque snapshot while holding the
lock. On SIGKILL, Python `finally` blocks, snapshot discard, and mutable-buffer best-effort
zeroization may be skipped. Only kernel file-descriptor/lock release and OS address-space
reclamation are guaranteed; immutable `bytes` copies are not guaranteed to be erased.

## Windows: Credential Manager compatibility

PowerShell 5.1 and PowerShell 7 are supported. The existing wrapper reads the generic Windows
Credential Manager target `mcp/forgejo-mcp/access-token` and injects it only into the child:

```powershell
pwsh -NoProfile -File "C:/Users/<username>/AppData/Local/mcp/servers/forgejo-mcp/scripts/credential-exec.ps1" `
  -Target "mcp/forgejo-mcp/access-token" "-EnvName" "FORGEJO_ACCESS_TOKEN" `
  -Command "uv" -CommandArgsJson '["--project","<project-path>/forgejo-api-mcp","run","forgejo-api-mcp"]'
```

The project-owned launcher is also usable directly with a pre-existing compatible store entry.
The Windows rotation implementation remains Win32 `CredReadW`/`CredWriteW` based, uses the fixed
username `forgejo-api-mcp`, `CRED_PERSIST_LOCAL_MACHINE`, and a cross-session `Global\\` mutex named
with the current user SID. Its protected DACL grants only that SID and SYSTEM the required mutex
rights; username strings are not a security boundary.

## Troubleshooting and restart

The token and client are a process-start snapshot. After `status: rotated`, restart the MCP
server/host; rotation never hot-reloads a running process. Use `provider_auth_status` to inspect
the startup snapshot without exposing it. For Linux, repair the existing unlocked default item
with the trusted manager and retry. For Windows, verify the fixed target and wrapper path. Never
print or paste the credential blob while troubleshooting. See [`credential-rotation.md`](credential-rotation.md).

For dependency troubleshooting, run `uv sync --locked` and confirm Python 3.12+; on Linux also
confirm the D-Bus user session, running Secret Service daemon, unlocked default collection, and
exactly one item through the trusted manager. On Windows verify PowerShell, `uv`, the wrapper,
and target `mcp/forgejo-mcp/access-token`. Restart after every successful rotation.
