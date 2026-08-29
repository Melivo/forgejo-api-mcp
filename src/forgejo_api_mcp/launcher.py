"""Package-owned credential launcher for the stdio MCP child process."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from collections.abc import Callable
from typing import Any

from .credential_backend import (
    CredentialBackend,
    CredentialOperationError,
    PlatformUnsupported,
    select_credential_backend,
)

EXIT_CREDENTIAL_STORE_ERROR = 7
EXIT_PLATFORM_UNSUPPORTED = 9

ProcessRunner = Callable[[list[str], dict[str, str]], int]


def _run_child(command: list[str], environment: dict[str, str]) -> int:
    completed = subprocess.run(command, env=environment, check=False)
    return int(completed.returncode)


def _emit_failure(error: CredentialOperationError) -> None:
    payload = {
        "category": error.category.value,
        "credentialState": error.credential_state,
        "guidanceId": error.guidance_id,
    }
    sys.stderr.write(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n")


def launch(
    *,
    backend: CredentialBackend | Any | None = None,
    process_runner: ProcessRunner = _run_child,
) -> int:
    """Read once, then inject the token only into the MCP child's environment."""

    try:
        selected = backend or select_credential_backend()
        token = selected.read()
    except PlatformUnsupported:
        sys.stderr.write(
            '{"category":"platform_unsupported","credentialState":"unavailable"}\n'
        )
        return EXIT_PLATFORM_UNSUPPORTED
    except CredentialOperationError as error:
        _emit_failure(error)
        return EXIT_CREDENTIAL_STORE_ERROR

    child_environment = os.environ.copy()
    child_environment["FORGEJO_ACCESS_TOKEN"] = token
    command = [sys.executable, "-m", "forgejo_api_mcp.server"]
    try:
        return process_runner(command, child_environment)
    finally:
        child_environment.pop("FORGEJO_ACCESS_TOKEN", None)
        token = ""


def main() -> int:
    return launch()
