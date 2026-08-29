"""Project-owned Forgejo credential rotation CLI (single entry point).

Reads a candidate token ONLY from stdin (``getpass``, SecureString-equivalent, no echo),
validates it with a bounded redirect-disabled HTTPS ``GET /api/v1/user`` BEFORE writing
anything, writes it to the platform credential backend at the fixed target
``mcp/forgejo-mcp/access-token``, verifies a local readback (restoring the prior value or
removing a newly created entry where supported on mismatch), and prints a redacted JSON object plus
``restartRequired``. The base URL must be HTTPS (the rotation path is intentionally stricter
than the client and ignores ``FORGEJO_ALLOW_INSECURE_HTTP``). The raw token, the
``Authorization`` header value, and the response body are never logged or returned. The
running MCP server keeps its startup snapshot, so a restart is required after a successful
rotation.
"""

from __future__ import annotations

import asyncio
import getpass
import ipaddress
import json
import os
import sys
from datetime import UTC, datetime
from urllib.parse import urlsplit

import httpx

from .client import DEFAULT_BASE_URL
from .credential_backend import (
    TARGET_NAME,
    CredentialBackend,
    CredentialCategory,
    CredentialOperationError,
    CredentialSnapshot,
    PlatformUnsupported,
    select_credential_backend,
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


def _as_backend(store: object) -> CredentialBackend:
    if isinstance(store, CredentialBackend):
        return store
    raise TypeError("store must implement CredentialBackend")


def _default_store() -> CredentialBackend:
    """Select the platform adapter once at the credential boundary."""

    return select_credential_backend()


def _redacted(
    *,
    status: str,
    credential_state: str,
    now: str,
    detail: str,
    category: str | None = None,
    guidance_id: str | None = None,
) -> dict[str, object]:
    output: dict[str, object] = {
        "target": TARGET_NAME,
        "status": status,
        "credentialState": credential_state,
        "validatedAt": now,
        "restartRequired": status == "rotated",
        "detail": detail,
    }
    if category is not None:
        output["category"] = category
    if guidance_id is not None:
        output["guidanceId"] = guidance_id
    return output


def _credential_failure(
    error: CredentialOperationError,
    *,
    now: str,
    state: str | None = None,
) -> tuple[int, dict[str, object]]:
    lock_timeout = (
        error.category is CredentialCategory.TIMEOUT
        and error.operation == "lock"
        and error.guidance_id is None
    )
    detail = (
        "Another same-user credential rotation is still in progress."
        if lock_timeout
        else "Credential store operation failed; use the documented platform setup and retry."
    )
    return EXIT_CREDENTIAL_STORE_ERROR, _redacted(
        status="credential_store_error",
        category=error.category.value,
        credential_state=state or error.credential_state,
        now=now,
        detail=detail,
        guidance_id=error.guidance_id,
    )


def _rollback(backend: CredentialBackend, snapshot: CredentialSnapshot) -> str:
    try:
        backend.restore(snapshot)
    except CredentialOperationError as error:
        if error.indeterminate:
            try:
                backend.read()
            except CredentialOperationError:
                pass
            raise CredentialOperationError(
                error.category,
                credential_state="unknown",
                operation=error.operation,
                indeterminate=True,
                guidance_id=error.guidance_id,
            ) from None
        raise
    try:
        backend.read()
    except CredentialOperationError as error:
        if snapshot.present or error.category is not CredentialCategory.MISSING:
            raise
    return "restored" if snapshot.present else "deleted_new"


def _recover_indeterminate_write(
    backend: CredentialBackend,
    snapshot: CredentialSnapshot,
    write_error: CredentialOperationError,
    *,
    now: str,
) -> tuple[int, dict[str, object]]:
    """Collect bounded evidence and restore once without claiming D-Bus cancellation."""

    try:
        backend.read()
    except CredentialOperationError:
        pass
    outcome_error = write_error
    try:
        backend.restore(snapshot)
    except CredentialOperationError as restore_error:
        outcome_error = restore_error

    try:
        backend.read()
    except CredentialOperationError as final_read_error:
        if outcome_error is write_error:
            outcome_error = final_read_error

    unknown = CredentialOperationError(
        outcome_error.category,
        credential_state="unknown",
        operation=outcome_error.operation,
        indeterminate=True,
        guidance_id=write_error.guidance_id or outcome_error.guidance_id,
    )
    return _credential_failure(unknown, now=now)



def _valid_rotation_hostname(hostname: str) -> bool:
    if not hostname or any(character.isspace() or ord(character) < 32 for character in hostname):
        return False
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        pass
    try:
        ascii_hostname = hostname.encode("idna").decode("ascii")
    except UnicodeError:
        return False
    if len(ascii_hostname) > 253:
        return False
    labels = ascii_hostname.split(".")
    return bool(labels) and all(
        0 < len(label) <= 63
        and label[0].isalnum()
        and label[-1].isalnum()
        and all(character.isalnum() or character == "-" for character in label)
        for label in labels
    )


def _valid_rotation_base_url(value: object) -> bool:
    if not isinstance(value, str) or not value.strip():
        return False
    if any(ord(character) <= 0x1F or ord(character) == 0x7F for character in value):
        return False
    candidate = value.strip()
    try:
        parsed = urlsplit(candidate)
        hostname = parsed.hostname
        _port = parsed.port
    except (TypeError, ValueError):
        return False
    return bool(
        parsed.scheme.casefold() == "https"
        and parsed.netloc
        and hostname
        and _valid_rotation_hostname(hostname)
        and parsed.username is None
        and parsed.password is None
        and "?" not in candidate
        and "#" not in candidate
        and not parsed.query
        and not parsed.fragment
    )


def _run(
    token: str,
    *,
    base_url: str,
    transport: object | None = None,
    store: object | None = None,
    lock_factory: object | None = None,
    lock_timeout: float = 30.0,
) -> tuple[int, dict[str, object]]:
    """Validate outside the lock, then run one locked snapshot transaction."""
    now = _now_iso()
    try:
        selected = _default_store() if store is None else _as_backend(store)
    except PlatformUnsupported:
        return EXIT_PLATFORM_UNSUPPORTED, _redacted(
            status="platform_unsupported",
            credential_state="unavailable",
            now=now,
            detail="Credential storage is not supported on this platform.",
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

    if not _valid_rotation_base_url(base_url):
        return EXIT_INVALID_INPUT, _redacted(
            status="invalid_input",
            credential_state="unchanged",
            now=now,
            detail="Forgejo base URL is invalid.",
        )
    try:
        result = asyncio.run(
            classify_token(token, base_url=base_url, transport=transport)  # type: ignore[arg-type]
        )
    except (InputValidationError, httpx.InvalidURL):
        return EXIT_INVALID_INPUT, _redacted(
            status="invalid_input",
            credential_state="unchanged",
            now=now,
            detail="Forgejo base URL is invalid.",
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

    factory = lock_factory if lock_factory is not None else selected.lock
    snapshot: CredentialSnapshot | None = None
    try:
        with factory(timeout=lock_timeout):  # type: ignore[operator]
            try:
                snapshot = selected.snapshot()
            except CredentialOperationError as error:
                return _credential_failure(error, now=now)

            try:
                try:
                    selected.replace_existing(token)
                except CredentialOperationError as error:
                    if error.indeterminate:
                        return _recover_indeterminate_write(selected, snapshot, error, now=now)
                    return _credential_failure(error, now=now)

                try:
                    stored = selected.read()
                except CredentialOperationError as error:
                    try:
                        state = _rollback(selected, snapshot)
                    except CredentialOperationError as rollback_error:
                        return _credential_failure(rollback_error, now=now, state="unknown")
                    return _credential_failure(error, now=now, state=state)

                if stored == token:
                    return EXIT_ROTATED, _redacted(
                        status="rotated",
                        credential_state="written",
                        now=now,
                        detail=(
                            "Credential rotated. Restart the MCP server so the launch wrapper "
                            "reloads it."
                        ),
                    )

                try:
                    rollback_state = _rollback(selected, snapshot)
                except CredentialOperationError as error:
                    return _credential_failure(error, now=now, state="unknown")
                return EXIT_READBACK_MISMATCH, _redacted(
                    status="readback_mismatch",
                    credential_state=rollback_state,
                    now=now,
                    detail="Credential readback mismatched; the prior state was restored and verified.",
                )
            finally:
                if snapshot is not None:
                    selected.discard(snapshot)
    except CredentialOperationError as error:
        return _credential_failure(
            error,
            now=now,
            state="unknown" if snapshot is not None else None,
        )



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
    store: object | None = None,
) -> int:
    """Console-script entry point. Returns the rotation exit code."""

    try:
        selected: object = _default_store() if store is None else store
    except PlatformUnsupported:
        _emit(
            _redacted(
                status="platform_unsupported",
                credential_state="unavailable",
                now=_now_iso(),
                detail="Credential storage is not supported on this platform.",
            )
        )
        return EXIT_PLATFORM_UNSUPPORTED
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
    if not _valid_rotation_base_url(base_url):
        _emit(
            _redacted(
                status="invalid_input",
                credential_state="unchanged",
                now=_now_iso(),
                detail="Forgejo base URL is invalid.",
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
        store=selected,
    )
    _emit(output)
    return exit_code
