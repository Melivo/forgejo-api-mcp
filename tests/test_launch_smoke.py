from __future__ import annotations

import hashlib
import os
import secrets
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_stdio_child_receives_injected_environment_without_stdout_noise() -> None:
    expected = secrets.token_urlsafe(24)
    environment = os.environ.copy()
    environment["FORGEJO_ACCESS_TOKEN"] = expected
    environment["FORGEJO_TEST_TOKEN_SHA256"] = hashlib.sha256(expected.encode()).hexdigest()
    source_path = str(PROJECT_ROOT / "src")
    environment["PYTHONPATH"] = os.pathsep.join(
        part for part in (source_path, environment.get("PYTHONPATH")) if part
    )
    probe = (
        "import hashlib, hmac, os; "
        "token = os.environ.get('FORGEJO_ACCESS_TOKEN', ''); "
        "actual = hashlib.sha256(token.encode()).hexdigest(); "
        "assert hmac.compare_digest(actual, os.environ['FORGEJO_TEST_TOKEN_SHA256']); "
        "from forgejo_api_mcp.server import main; main()"
    )
    command = [sys.executable, "-c", probe]

    assert expected not in subprocess.list2cmdline(command)

    completed = subprocess.run(
        command,
        input=b"",
        capture_output=True,
        cwd=PROJECT_ROOT,
        env=environment,
        timeout=15,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr.decode("utf-8", "replace")
    assert completed.stdout == b""


def test_launch_requirements_use_the_existing_wrapper_without_a_secret_value() -> None:
    document = (PROJECT_ROOT / "docs" / "credential-launch.md").read_text(encoding="utf-8")

    assert "credential-exec.ps1" in document
    assert "mcp/forgejo-mcp/access-token" in document
    assert '"-EnvName"' in document
    assert '"FORGEJO_ACCESS_TOKEN"' in document
    assert '"FORGEJO_ACCESS_TOKEN":' not in document
    assert "forgejo-api-mcp" in document
    assert "stdio" in document


def test_rotation_doc_documents_command_target_restart_and_redaction() -> None:
    document = (PROJECT_ROOT / "docs" / "credential-rotation.md").read_text(encoding="utf-8")

    assert "forgejo-api-mcp-rotate" in document
    assert "mcp/forgejo-mcp/access-token" in document
    assert "restart" in document.casefold()
    assert "credential_rejected" in document
    assert "tokenSha256" not in document
    assert "--username" not in document
    assert "UserName is fixed" in document
    assert "HTTPS" in document
    assert "status-only" in document
    assert "absolute" in document
    assert "| 18 |" in document
    assert "user-scoped Windows named mutex" in document
    assert "Mandatory redacted local launcher verification" in document
    assert "credential-exec.ps1" in document
    assert "PASS" in document and "FAIL" in document
    assert "provider_auth_status" in document
    assert "<token>" not in document
