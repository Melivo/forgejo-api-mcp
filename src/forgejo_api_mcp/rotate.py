"""Project-owned Forgejo credential rotation CLI (single entry point).

Reads a candidate token ONLY from stdin (``getpass``, SecureString-equivalent, no echo),
validates it with a bounded redirect-disabled HTTPS ``GET /api/v1/user`` BEFORE writing
anything, writes it to the single Windows Credential Manager target
``mcp/forgejo-mcp/access-token``, verifies a local readback (restoring the prior value or
deleting the new entry on mismatch), and prints a single redacted JSON object plus
``restartRequired``. The base URL must be HTTPS (the rotation path is intentionally stricter
than the client and ignores ``FORGEJO_ALLOW_INSECURE_HTTP``). The raw token, the
``Authorization`` header value, and the response body are never logged or returned. The
running MCP server keeps its startup snapshot, so a restart is required after a successful
rotation.
"""

from __future__ import annotations

import asyncio
import getpass
import hmac
import json
import os
import sys
import types
from datetime import UTC, datetime
from urllib.parse import urlsplit

from .client import DEFAULT_BASE_URL
from .credentials import (
    TARGET_NAME,
    CredentialRecord,
    CredentialStoreError,
    CredentialStoreUnavailable,
    RotationMutexTimeout,
    _ensure_store_available,
    _rotation_lock,
    delete_credential,
    read_credential,
    restore_credential,
    write_credential,
)
from .errors import InputValidationError
from .provider_auth import AUTHENTICATED, INSECURE_BASE_URL, classify_token

API_BASE_PATH = "/api/v1"

EXIT_ROTATED = 0
EXIT_INVALID_INPUT = 2
EXIT_CREDENTIAL_REJECTED = 3
EXIT_FORBIDDEN = 4
EXIT_PROVIDER_ERROR = 5
EXIT_TRANSPORT_OR_TIMEOUT = 6
EXIT_CREDENTIAL_STORE_ERROR = 7
EXIT_READBACK_MISMATCH = 8
EXIT_PLATFORM_UNSUPPORTED = 9

_VALIDATION_OUTCOME = {
    "credential_rejected": ("credential_rejected", EXIT_CREDENTIAL_REJECTED),
    "forbidden": ("forbidden", EXIT_FORBIDDEN),
    "provider_error": ("provider_error", EXIT_PROVIDER_ERROR),
    "transport": ("transport_or_timeout", EXIT_TRANSPORT_OR_TIMEOUT),
    "timeout": ("transport_or_timeout", EXIT_TRANSPORT_OR_TIMEOUT),
}


def _now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def _default_store() -> types.SimpleNamespace:
    return types.SimpleNamespace(
        write=write_credential,
        read=read_credential,
        delete=delete_credential,
        restore=restore_credential,
        ensure_available=_ensure_store_available,
    )


def _redacted(
    *,
    status: str,
    credential_state: str,
    now: str,
    detail: str,
) -> dict[str, object]:
    return {
        "target": TARGET_NAME,
        "status": status,
        "credentialState": credential_state,
        "validatedAt": now,
        "restartRequired": status == "rotated",
        "detail": detail,
    }


def _run(
    token: str,
    *,
    base_url: str,
    transport: object | None = None,
    store: types.SimpleNamespace | None = None,
    lock_factory: object = _rotation_lock,
    lock_timeout: float = 30.0,
    platform_checked: bool = False,
) -> tuple[int, dict[str, object]]:
    """Validate, serialize the store transaction, verify readback, and roll back on failure."""

    store = store or _default_store()
    now = _now_iso()
    if not platform_checked:
        try:
            ensure_available = getattr(store, "ensure_available", None)
            if ensure_available is not None:
                ensure_available()
        except CredentialStoreUnavailable:
            return EXIT_PLATFORM_UNSUPPORTED, _redacted(
                status="platform_unsupported",
                credential_state="unavailable",
                now=now,
                detail="Windows Credential Manager is not available on this host.",
            )
        except CredentialStoreError:
            return EXIT_CREDENTIAL_STORE_ERROR, _redacted(
                status="credential_store_error",
                credential_state="unchanged",
                now=now,
                detail="Windows Credential Manager availability check failed.",
            )
    if (
        not isinstance(token, str)
        or not token
        or "\r" in token
        or "\n" in token
        or "\x00" in token
    ):
        return EXIT_INVALID_INPUT, _redacted(
            status="invalid_input",
            credential_state="unchanged",
            now=now,
            detail="token must be a single non-empty line without CR/LF/NUL",
        )

    if not isinstance(base_url, str) or urlsplit(base_url.strip()).scheme.casefold() != "https":
        return EXIT_INVALID_INPUT, _redacted(
            status="invalid_input",
            credential_state="unchanged",
            now=now,
            detail="Forgejo base URL must use HTTPS.",
        )
    try:
        result = asyncio.run(
            classify_token(token, base_url=base_url, transport=transport)  # type: ignore[arg-type]
        )
    except InputValidationError as error:
        return EXIT_INVALID_INPUT, _redacted(
            status="invalid_input", credential_state="unchanged", now=now, detail=str(error)
        )

    if result.status != AUTHENTICATED:
        if result.status == INSECURE_BASE_URL:
            return EXIT_INVALID_INPUT, _redacted(
                status="invalid_input",
                credential_state="unchanged",
                now=now,
                detail=result.detail,
            )
        output_status, exit_code = _VALIDATION_OUTCOME.get(
            result.status, ("provider_error", EXIT_PROVIDER_ERROR)
        )
        return exit_code, _redacted(
            status=output_status,
            credential_state="unchanged",
            now=now,
            detail=result.detail,
        )

    prior: object = None
    write_succeeded = False
    try:
        with lock_factory(timeout=lock_timeout):  # type: ignore[operator]
            try:
                prior = store.read()
            except CredentialStoreError:
                return EXIT_CREDENTIAL_STORE_ERROR, _redacted(
                    status="credential_store_error",
                    credential_state="unchanged",
                    now=now,
                    detail="Could not capture the prior credential before writing.",
                )

            try:
                store.write(token)
                write_succeeded = True
            except CredentialStoreError:
                return EXIT_CREDENTIAL_STORE_ERROR, _redacted(
                    status="credential_store_error",
                    credential_state="unchanged",
                    now=now,
                    detail="Credential Manager rejected the write.",
                )

            readback_failed = False
            try:
                stored = store.read()
            except CredentialStoreError:
                stored = None
                readback_failed = True

            if not readback_failed and _records_match(stored, token):
                return EXIT_ROTATED, _redacted(
                    status="rotated",
                    credential_state="written",
                    now=now,
                    detail="Credential rotated. Restart the MCP server so the launch wrapper reloads it.",
                )

            rollback_state = _verified_rollback(store, prior)
            if rollback_state == "unknown":
                return EXIT_CREDENTIAL_STORE_ERROR, _redacted(
                    status="credential_store_error",
                    credential_state="unknown",
                    now=now,
                    detail="Readback failed and rollback could not be verified.",
                )
            if readback_failed:
                return EXIT_CREDENTIAL_STORE_ERROR, _redacted(
                    status="credential_store_error",
                    credential_state=rollback_state,
                    now=now,
                    detail="Credential readback failed; the prior state was restored and verified.",
                )
            return EXIT_READBACK_MISMATCH, _redacted(
                status="readback_mismatch",
                credential_state=rollback_state,
                now=now,
                detail="Credential readback mismatched; the prior state was restored and verified.",
            )
    except RotationMutexTimeout:
        return EXIT_CREDENTIAL_STORE_ERROR, _redacted(
            status="credential_store_error",
            credential_state="unchanged",
            now=now,
            detail="Another same-user credential rotation is still in progress.",
        )
    except CredentialStoreUnavailable:
        return EXIT_PLATFORM_UNSUPPORTED, _redacted(
            status="platform_unsupported",
            credential_state="unavailable",
            now=now,
            detail="Windows Credential Manager is not available on this host.",
        )
    except CredentialStoreError:
        if write_succeeded:
            rollback_state = _verified_rollback(store, prior)
            return EXIT_CREDENTIAL_STORE_ERROR, _redacted(
                status="credential_store_error",
                credential_state=rollback_state,
                now=now,
                detail=(
                    "Credential transaction failed after writing; rollback was attempted and "
                    "verified."
                    if rollback_state != "unknown"
                    else "Credential transaction failed after writing and rollback is unverified."
                ),
            )
        return EXIT_CREDENTIAL_STORE_ERROR, _redacted(
            status="credential_store_error",
            credential_state="unchanged",
            now=now,
            detail="Credential Manager transaction failed.",
        )


def _records_match(record: object, token: str) -> bool:
    return isinstance(record, CredentialRecord) and hmac.compare_digest(
        record.credential_blob, token
    )


def _same_record(left: object, right: CredentialRecord) -> bool:
    return (
        isinstance(left, CredentialRecord)
        and left.target == right.target
        and left.username == right.username
        and left.persist_type == right.persist_type
        and hmac.compare_digest(left.credential_blob, right.credential_blob)
    )


def _verified_rollback(store: types.SimpleNamespace, prior: object) -> str:
    try:
        if isinstance(prior, CredentialRecord):
            store.restore(prior)
            return "restored" if _same_record(store.read(), prior) else "unknown"
        store.delete()
        return "deleted_new" if store.read() is None else "unknown"
    except CredentialStoreError:
        return "unknown"


def _read_token() -> str:
    if sys.stdin is not None and sys.stdin.isatty():
        try:
            token = getpass.getpass(prompt="Forgejo access token: ")
        except EOFError:
            return ""
    else:
        token = sys.stdin.read()
    if token.endswith("\r\n"):
        return token[:-2]
    if token.endswith(("\r", "\n")):
        return token[:-1]
    return token or ""


def _emit(output: dict[str, object]) -> None:
    sys.stdout.write(json.dumps(output, ensure_ascii=True, separators=(",", ":")))
    sys.stdout.write("\n")
    sys.stdout.flush()


def main(
    argv: list[str] | None = None,
    *,
    transport: object | None = None,
    store: types.SimpleNamespace | None = None,
) -> int:
    """Console-script entry point. Returns the rotation exit code."""

    store = store or _default_store()
    try:
        ensure_available = getattr(store, "ensure_available", None)
        if ensure_available is not None:
            ensure_available()
    except CredentialStoreUnavailable:
        _emit(
            _redacted(
                status="platform_unsupported",
                credential_state="unavailable",
                now=_now_iso(),
                detail="Windows Credential Manager is not available on this host.",
            )
        )
        return EXIT_PLATFORM_UNSUPPORTED
    except CredentialStoreError:
        _emit(
            _redacted(
                status="credential_store_error",
                credential_state="unchanged",
                now=_now_iso(),
                detail="Windows Credential Manager availability check failed.",
            )
        )
        return EXIT_CREDENTIAL_STORE_ERROR

    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments:
        _emit(
            _redacted(
                status="invalid_input",
                credential_state="unchanged",
                now=_now_iso(),
                detail="This command accepts no arguments; provide the token on stdin only.",
            )
        )
        return EXIT_INVALID_INPUT

    base_url = os.getenv("FORGEJO_BASE_URL", DEFAULT_BASE_URL)
    if urlsplit(base_url.strip()).scheme.casefold() != "https":
        _emit(
            _redacted(
                status="invalid_input",
                credential_state="unchanged",
                now=_now_iso(),
                detail="Forgejo base URL must use HTTPS.",
            )
        )
        return EXIT_INVALID_INPUT

    token = _read_token()
    if not token or "\r" in token or "\n" in token or "\x00" in token:
        _emit(
            _redacted(
                status="invalid_input",
                credential_state="unchanged",
                now=_now_iso(),
                detail="token must be a single non-empty line without CR/LF/NUL",
            )
        )
        return EXIT_INVALID_INPUT

    exit_code, output = _run(
        token,
        base_url=base_url,
        transport=transport,
        store=store,
        platform_checked=True,
    )
    _emit(output)
    return exit_code
