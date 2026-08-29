"""Secret-free administration for the Linux late-commit quarantine marker."""

from __future__ import annotations

import json
import sys
from typing import Any

from .credential_backend import (
    LINUX_QUARANTINE_GUIDANCE_ID,
    CredentialOperationError,
    PlatformUnsupported,
    select_quarantine_backend,
)

EXIT_OK = 0
EXIT_INVALID_INPUT = 2
EXIT_STORE_ERROR = 7
EXIT_PLATFORM_UNSUPPORTED = 9
EXIT_QUARANTINED = 10


def _emit(
    status: str,
    *,
    category: str | None = None,
    guidance_id: str | None = None,
) -> None:
    payload: dict[str, object] = {
        "status": status,
        "credentialState": "unknown",
    }
    if category is not None:
        payload["category"] = category
    if guidance_id is not None:
        payload["guidanceId"] = guidance_id
    sys.stdout.write(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def main(
    argv: list[str] | None = None,
    *,
    backend: Any | None = None,
) -> int:
    """Check or explicitly clear quarantine without accessing Secret Service or a token."""

    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments not in (["check"], ["clear", "--operator-verified"]):
        _emit("invalid_input")
        return EXIT_INVALID_INPUT
    try:
        selected = select_quarantine_backend() if backend is None else backend
    except PlatformUnsupported:
        _emit("platform_unsupported")
        return EXIT_PLATFORM_UNSUPPORTED

    try:
        present = bool(selected.quarantine_present())
        if arguments == ["check"]:
            if present:
                _emit("quarantined", guidance_id=LINUX_QUARANTINE_GUIDANCE_ID)
                return EXIT_QUARANTINED
            _emit("clear")
            return EXIT_OK

        if not present:
            _emit("clear")
            return EXIT_OK
        selected.clear_quarantine()
        _emit("cleared")
        return EXIT_OK
    except CredentialOperationError as error:
        _emit(
            "store_error",
            category=error.category.value,
            guidance_id=error.guidance_id or LINUX_QUARANTINE_GUIDANCE_ID,
        )
        return EXIT_STORE_ERROR
