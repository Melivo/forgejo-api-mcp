# Credential rotation (canonical guide)

The common `forgejo-api-mcp-rotate` CLI reads one candidate from stdin, validates it before any
store write, performs verified readback/rollback, and emits one redacted JSON result. It accepts
no arguments and never accepts a token through argv, an environment variable, or an MCP tool.

## Rotation

```bash
uv sync --locked
printf '%s\n' '<token-placeholder>' | uv run forgejo-api-mcp-rotate
```

```powershell
uv sync --locked
"<token-placeholder>" | uv run forgejo-api-mcp-rotate
```

For interactive use, omit the pipe and answer the no-echo stdin prompt. Do not put real values in
scripts or shell history. Set only the non-secret `FORGEJO_BASE_URL` when needed; it must be HTTPS.

## Dependency checks

```bash
export FORGEJO_BASE_URL="https://<forgejo-host>"
uv run python -c 'import importlib.util; assert importlib.util.find_spec("secretstorage") is not None; print("SecretStorage installed")'
```

```powershell
$env:FORGEJO_BASE_URL = "https://<forgejo-host>"
uv run python -c "import sys; assert sys.version_info >= (3, 12); print('Python dependency check passed')"
```

## Setup and platform contracts

Windows uses Credential Manager target `mcp/forgejo-mcp/access-token`; UserName is fixed to
`forgejo-api-mcp`, with generic credentials and `CRED_PERSIST_LOCAL_MACHINE`. It uses Win32 APIs,
not `cmdkey /pass`, and serializes same-user rotations across logon sessions with a bounded
`Global\\forgejo-api-mcp-rotate-<current-user-SID>` mutex. The name is scoped only by the token SID,
never a username. `CreateMutexExW` receives a protected DACL granting only that SID and SYSTEM the
required synchronize/modify-state rights; the handle is non-inheritable.

Linux requires `SecretStorage>=3.5,<4; sys_platform == 'linux'`, a D-Bus user session, a running
Secret Service daemon, and one existing unlocked `default` collection. The exact one item is
`application=forgejo-api-mcp`, `credential-kind=access-token`,
`target=mcp/forgejo-mcp/access-token`, label `Forgejo API MCP access token`, content type
`text/plain`. Runtime is strictly noninteractive: no unlock, prompt, creation/deletion,
`secret-tool`, external command, raw D-Bus, or file fallback. A trusted manager provisions it.

Before launch or rotation, the operator must use that trusted Secret Service manager to verify the
current-user D-Bus session and running daemon, the existing unlocked `default` collection, exactly
one matching item, the three exact immutable attributes above, label `Forgejo API MCP access token`,
and content type `text/plain`. Record only redacted pass/fail results. The package path never
performs this provisioning, unlocks, prompts, creates, deletes, or invokes a credential helper.

Linux operations are fresh-worker, 5-second bounded operations. Before every mutating dispatch the
backend durably installs a fixed non-secret quarantine fence in the private runtime directory. A
confirmed worker response removes the provisional fence. A dispatched `replace_existing` or
`restore` timeout leaves it installed because terminating the worker cannot cancel a D-Bus request
already accepted by Secret Service. Rotation still performs one bounded diagnostic read, at most
one restore, and one final bounded diagnostic read while holding the lock, but **always** reports
`credentialState: unknown`; neither an immediate old-state read nor an apparent restore proves that
a late commit cannot overtake it. A timeout proven to occur before dispatch removes the provisional
fence and retains the prior unchanged-state contract. Stable
redacted states distinguish missing, locked, prompt-required/dismissed, service unavailable,
timeout, and store error. Candidate validation happens before the bounded per-user POSIX lock;
the lock covers snapshot, replacement, readback, rollback/commit cleanup, and discard.

While the fence is present, launcher reads and future rotations fail before Secret Service access
with `store_error`, `credentialState: unknown`, and guidance ID
`linux_secret_service_quarantine`. No automatic clear exists. After an operator has externally
verified the exact fixed item and all attributes in a trusted Secret Service manager, confirmed the
current-user daemon has settled or been restarted, and determined the intended credential value
without recording it, use the secret-free package command:

```bash
uv run forgejo-api-mcp-quarantine check
uv run forgejo-api-mcp-quarantine clear --operator-verified
```

`check` exits `0` for clear and `10` for quarantined. `clear --operator-verified` exits `0` after an
atomic verified removal (and is idempotent when already clear). Invalid syntax, marker/store error,
and unsupported platform exit `2`, `7`, and `9`. Output is one stable JSON object and never contains
the runtime path, item metadata, or a secret. The acknowledgement flag records only that external
verification was completed; this command deliberately does not read or mutate Secret Service.

## Result and rollback

Validation uses a redirect-disabled HTTPS status-only probe under an absolute wall-clock deadline.
Only redacted fields are emitted:
fixed `target`, status (including `credential_rejected`,
`forbidden`, `provider_error`, and `rotated`), `credentialState`, timestamp,
`restartRequired`, detail, and (where applicable) category/guidance ID. Successful `rotated`
means readback matched and is the only result with `restartRequired: true` (exit `0`). Invalid
input, provider rejection/error, timeout, store failure, rollback mismatch, and unsupported
platform use exits `2, 3, 4, 5, 6, 7, 8, 9` respectively as documented by the CLI. Rollback
restores and verifies the prior item, or deletes/verifies a newly created Windows entry. An
unverifiable rollback returns `credential_store_error`, exit `7`, and
`credentialState: unknown` without requiring a restart.

## Restart and troubleshooting

Rotation changes the store, not the running process. **Always restart the MCP server/host after
a successful rotation** so the launcher reads the new startup snapshot. Then use the read-only
`provider_auth_status` probe to check that snapshot. Troubleshooting must remain redacted; repair
Linux setup with a trusted Secret Service manager or verify the Windows target/wrapper, then retry.
The complete launch and provisioning guide is [`credential-launch.md`](credential-launch.md).

## Mandatory redacted local launcher verification

Before release acceptance on Windows, perform the existing non-production wrapper interoperability
check of `credential-exec.ps1` and record only the fixed target plus PASS/FAIL: the wrapper reads Credential Manager,
injects the child environment, and `provider_auth_status` reports the startup snapshot without
exposing it. Never rotate production credentials or record a blob.
