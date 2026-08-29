from __future__ import annotations

import ast
import inspect
import sys
import tomllib
from pathlib import Path

import pytest

from forgejo_api_mcp.credential_backend import (
    CredentialBackend,
    CredentialCategory,
    CredentialOperationError,
    PlatformUnsupported,
    QuarantineBackend,
    select_credential_backend,
    select_quarantine_backend,
)
from forgejo_api_mcp.errors import ForgejoMCPError

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_backend_contract_is_narrow_and_has_no_generic_mutators() -> None:
    methods = {
        name
        for name, value in inspect.getmembers(CredentialBackend, inspect.isfunction)
        if not name.startswith("_")
    }
    assert methods == {
        "availability",
        "read",
        "snapshot",
        "replace_existing",
        "restore",
        "discard",
        "lock",
    }
    assert {member.value for member in CredentialCategory} == {
        "available",
        "missing",
        "locked",
        "prompt_required",
        "prompt_dismissed",
        "timeout",
        "service_unavailable",
        "store_error",
    }


def test_rotation_imports_only_the_platform_neutral_credential_boundary() -> None:
    package = PROJECT_ROOT / "src" / "forgejo_api_mcp"
    rotate_tree = ast.parse((package / "rotate.py").read_text(encoding="utf-8"))
    rotate_imports = [
        node
        for node in ast.walk(rotate_tree)
        if isinstance(node, ast.ImportFrom)
    ]
    assert all(node.module != "credentials" for node in rotate_imports)
    neutral_import = next(node for node in rotate_imports if node.module == "credential_backend")
    assert "TARGET_NAME" in {alias.name for alias in neutral_import.names}

    backend_tree = ast.parse((package / "credential_backend.py").read_text(encoding="utf-8"))
    assignments = {
        target.id
        for node in ast.walk(backend_tree)
        if isinstance(node, ast.Assign)
        for target in node.targets
        if isinstance(target, ast.Name)
    }
    assert "TARGET_NAME" in assignments

    for adapter_name in ("credentials.py", "linux_credentials.py"):
        adapter_tree = ast.parse((package / adapter_name).read_text(encoding="utf-8"))
        imports = [
            node
            for node in ast.walk(adapter_tree)
            if isinstance(node, ast.ImportFrom) and node.module == "credential_backend"
        ]
        assert any("TARGET_NAME" in {alias.name for alias in node.names} for node in imports)


def test_selector_fails_closed_for_an_unsupported_platform() -> None:
    with pytest.raises(PlatformUnsupported) as caught:
        select_credential_backend(platform="plan9")
    assert str(caught.value) == "credential backend is unsupported on this platform"


@pytest.mark.skipif(sys.platform != "linux", reason="Linux backend requires POSIX fcntl")
def test_quarantine_selector_reuses_linux_platform_selection() -> None:
    selected = select_quarantine_backend(platform="linux")
    assert isinstance(selected, QuarantineBackend)
    assert type(selected).__name__ == "LinuxCredentialBackend"


def test_quarantine_selector_fails_closed_on_windows() -> None:
    with pytest.raises(PlatformUnsupported) as caught:
        select_quarantine_backend(platform="win32")
    assert str(caught.value) == "credential backend is unsupported on this platform"


@pytest.mark.parametrize("module", ["catalog.py", "client.py", "server.py", "provider_auth.py"])
def test_shared_modules_do_not_import_platform_backends(module: str) -> None:
    source = (PROJECT_ROOT / "src" / "forgejo_api_mcp" / module).read_text(encoding="utf-8")
    imports = {
        alias.name
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        node.module or ""
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.ImportFrom)
    }
    assert not any("credentials" in imported for imported in imports)


def test_rotation_boundary_does_not_import_windows_exception_types() -> None:
    source = (PROJECT_ROOT / "src" / "forgejo_api_mcp" / "rotate.py").read_text(
        encoding="utf-8"
    )
    imported_names = {
        alias.name
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.ImportFrom) and node.module == "credentials"
        for alias in node.names
    }
    assert imported_names.isdisjoint(
        {"CredentialStoreError", "CredentialStoreUnavailable", "RotationMutexTimeout"}
    )


def test_linux_dependency_marker_and_launcher_entry_point_are_exact() -> None:
    metadata = tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert "SecretStorage>=3.5,<4; sys_platform == 'linux'" in metadata["project"][
        "dependencies"
    ]
    assert metadata["project"]["scripts"]["forgejo-api-mcp-launch"] == (
        "forgejo_api_mcp.launcher:main"
    )


def test_selector_uses_the_current_platform_backend_without_eager_cross_imports() -> None:
    selected = select_credential_backend(platform=sys.platform)
    expected = "WindowsCredentialBackend" if sys.platform == "win32" else "LinuxCredentialBackend"
    assert type(selected).__name__ == expected


def test_credential_errors_share_the_project_hierarchy_and_redact_causes() -> None:
    assert issubclass(PlatformUnsupported, ForgejoMCPError)
    assert issubclass(CredentialOperationError, ForgejoMCPError)
    error = CredentialOperationError(
        CredentialCategory.STORE_ERROR,
        credential_state="unknown",
        operation="read",
    )
    assert str(error) == "credential operation failed: store_error"
    assert "secret" not in repr(error).casefold()


def test_neutral_operation_error_has_no_platform_guidance_default() -> None:
    error = CredentialOperationError(
        CredentialCategory.STORE_ERROR,
        credential_state="unknown",
        operation="read",
    )
    assert error.guidance_id is None


def test_lockfile_keeps_secretstorage_linux_only_and_transitives_indirect() -> None:
    lock = tomllib.loads((PROJECT_ROOT / "uv.lock").read_text(encoding="utf-8"))
    packages = {package["name"]: package for package in lock["package"]}
    project = packages["forgejo-api-mcp"]
    secretstorage = packages["secretstorage"]

    assert {
        "name": "secretstorage",
        "marker": "sys_platform == 'linux'",
        "specifier": ">=3.5,<4",
    } in project["metadata"]["requires-dist"]
    assert {dependency["name"] for dependency in secretstorage["dependencies"]} == {
        "cryptography",
        "jeepney",
    }
    assert all(
        dependency["name"] not in {"cryptography", "jeepney"}
        for dependency in project["metadata"]["requires-dist"]
    )


def test_all_package_entry_points_are_exact() -> None:
    metadata = tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert metadata["project"]["scripts"] == {
        "forgejo-api-mcp": "forgejo_api_mcp.server:main",
        "forgejo-api-mcp-launch": "forgejo_api_mcp.launcher:main",
        "forgejo-api-mcp-quarantine": "forgejo_api_mcp.quarantine:main",
        "forgejo-api-mcp-rotate": "forgejo_api_mcp.rotate:main",
    }
