from __future__ import annotations

import hashlib
import logging
import secrets
import sys
import traceback
from contextlib import nullcontext
from pathlib import Path

import httpx
import pytest

from forgejo_api_mcp.credential_backend import CredentialCategory, CredentialOperationError
from forgejo_api_mcp.launcher import launch
from forgejo_api_mcp.rotate import EXIT_ROTATED, _run

PROJECT_ROOT = Path(__file__).resolve().parents[1]


class _Snapshot:
    present = True

    def __repr__(self) -> str:
        return "Snapshot(<redacted>)"


class _Backend:
    def __init__(self, token: str) -> None:
        self.current = token
        self.snapshot_handle = _Snapshot()

    def availability(self) -> CredentialCategory:
        return CredentialCategory.AVAILABLE

    def read(self) -> str:
        return self.current

    def snapshot(self) -> _Snapshot:
        return self.snapshot_handle

    def replace_existing(self, token: str) -> None:
        self.current = token

    def restore(self, snapshot: _Snapshot) -> None:
        assert snapshot is self.snapshot_handle

    def discard(self, snapshot: _Snapshot) -> None:
        assert snapshot is self.snapshot_handle
        snapshot.present = False

    def lock(self, *, timeout: float):
        assert timeout > 0
        return nullcontext()


def _repository_text() -> str:
    roots = [PROJECT_ROOT / "src", PROJECT_ROOT / "tests", PROJECT_ROOT / "docs"]
    files = [
        PROJECT_ROOT / "pyproject.toml",
        PROJECT_ROOT / "uv.lock",
        PROJECT_ROOT / ".gitignore",
        *PROJECT_ROOT.glob("*.md"),
    ]
    files.extend(path for root in roots for path in root.rglob("*") if path.is_file())
    files.extend((PROJECT_ROOT / ".github").rglob("*.yml"))
    rendered: list[str] = []
    for path in files:
        try:
            rendered.append(path.read_text(encoding="utf-8"))
        except UnicodeDecodeError:
            continue
    return "\n".join(rendered)


@pytest.mark.parametrize(
    "channel",
    [
        "repository_files",
        "dotenv",
        "generated_config",
        "previews",
        "launcher_output",
        "argv",
        "public_stdout",
        "public_stderr",
        "logs",
        "exceptions_tracebacks",
        "test_output_diagnostics",
        "generated_filesystem_artifacts",
    ],
)
def test_synthetic_secrets_and_derived_values_cross_only_approved_private_channels(
    channel: str, tmp_path: Path, monkeypatch, capsys, caplog
) -> None:
    token = secrets.token_urlsafe(36)
    derived = hashlib.sha256(token.encode()).hexdigest()
    backend = _Backend(token)
    child: dict[str, object] = {}

    def runner(command: list[str], environment: dict[str, str]) -> int:
        child["argv"] = command.copy()
        child["approved_environment"] = environment.copy()
        child["environment_reference"] = environment
        return 0

    monkeypatch.chdir(tmp_path)
    with caplog.at_level(logging.DEBUG):
        assert launch(backend=backend, process_runner=runner) == 0
        code, output = _run(
            token,
            base_url="https://forgejo.example",
            transport=httpx.MockTransport(lambda request: httpx.Response(200, request=request)),
            store=_Backend("prior"),
        )
    assert code == EXIT_ROTATED

    approved_environment = child["approved_environment"]
    assert approved_environment["FORGEJO_ACCESS_TOKEN"] == token  # type: ignore[index]
    assert "FORGEJO_ACCESS_TOKEN" not in child["environment_reference"]  # type: ignore[operator]

    if sys.platform == "linux":
        from forgejo_api_mcp import linux_credentials

        mapped = linux_credentials._map_secretstorage_exception(RuntimeError(token), "read")
    else:
        mapped = CredentialOperationError(
            CredentialCategory.STORE_ERROR,
            credential_state="unchanged",
            operation="read",
        )
    rendered_error = "".join(traceback.format_exception(mapped))
    assert mapped.category is CredentialCategory.STORE_ERROR

    captured = capsys.readouterr()
    artifacts = [path for path in tmp_path.rglob("*") if path.is_file()]

    def render_files(paths: list[Path]) -> str:
        rendered: list[str] = []
        for path in paths:
            try:
                rendered.append(str(path))
                rendered.append(path.read_text(encoding="utf-8"))
            except UnicodeDecodeError:
                rendered.append(path.read_bytes().hex())
        return "\n".join(rendered)

    dotenv_files = [
        *(path for path in PROJECT_ROOT.glob(".env*") if path.is_file()),
        *(path for path in artifacts if path.name.startswith(".env")),
    ]
    generated_config_files = [
        path
        for path in artifacts
        if path.suffix.casefold() in {".json", ".jsonc", ".toml", ".yaml", ".yml"}
        or "config" in path.name.casefold()
    ]
    preview_files = [path for path in artifacts if "preview" in path.name.casefold()]
    diagnostics = "\n".join((repr(output), repr(backend.snapshot_handle), rendered_error))
    channels = {
        "repository_files": _repository_text(),
        "dotenv": render_files(dotenv_files),
        "generated_config": render_files(generated_config_files),
        "previews": render_files(preview_files),
        "launcher_output": captured.out + captured.err,
        "argv": " ".join(child["argv"]),  # type: ignore[arg-type]
        "public_stdout": captured.out,
        "public_stderr": captured.err,
        "logs": " ".join(record.getMessage() for record in caplog.records),
        "exceptions_tracebacks": rendered_error,
        "test_output_diagnostics": diagnostics,
        "generated_filesystem_artifacts": render_files(artifacts),
    }
    observed = channels[channel]
    for forbidden in (token, derived):
        if forbidden in observed:
            pytest.fail("a synthetic secret reached the parameterized public channel")
    assert artifacts == []


def test_public_credential_error_never_includes_an_attached_raw_payload() -> None:
    error = CredentialOperationError(
        CredentialCategory.STORE_ERROR,
        credential_state="unknown",
        operation="read",
    )
    assert str(error) == "credential operation failed: store_error"
    assert repr(error).startswith("CredentialOperationError(category='store_error'")
