from __future__ import annotations

import ast
import re
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_github_ci_matrix_and_mandatory_gates_are_explicit() -> None:
    workflow = (PROJECT_ROOT / ".github" / "workflows" / "ci.yml").read_text(
        encoding="utf-8"
    )

    assert "os: [ubuntu-latest, windows-latest]" in workflow
    assert 'python: ["3.12", "3.13", "3.14"]' in workflow
    assert "uv sync --locked" in workflow
    assert "uv run ruff check ." in workflow
    assert "uv run pytest tests/test_packaged_install.py" in workflow
    assert "uv run pytest\n" in workflow
    assert "uv run pytest tests/integration/test_mcp_lifecycle.py" in workflow
    assert "import cryptography, jeepney, secretstorage" in workflow
    assert "find_spec('secretstorage') is None" in workflow
    assert workflow.count('version: "0.10.10"') == 2
    assert "timeout-minutes: 30" in workflow
    assert "timeout-minutes: 15" in workflow


def test_every_external_action_is_pinned_to_a_reviewed_full_sha() -> None:
    workflow = (PROJECT_ROOT / ".github" / "workflows" / "ci.yml").read_text(
        encoding="utf-8"
    )
    actions = re.findall(
        r"^\s*- uses: ([^@\s]+/[^@\s]+)@([0-9a-f]{40})\s+#\s+(v\d+)\s*$",
        workflow,
        flags=re.MULTILINE,
    )
    assert actions == [
        (
            "actions/checkout",
            "11d5960a326750d5838078e36cf38b85af677262",
            "v4",
        ),
        (
            "actions/setup-python",
            "ece7cb06caefa5fff74198d8649806c4678c61a1",
            "v6",
        ),
        (
            "astral-sh/setup-uv",
            "37802adc94f370d6bfd71619e3f0bf239e1f3b78",
            "v7",
        ),
    ] * 2
    uses_lines = [line.strip() for line in workflow.splitlines() if "uses:" in line]
    assert len(uses_lines) == len(actions) == 6
    assert all(re.search(r"@[0-9a-f]{40}\s+#\s+v\d+$", line) for line in uses_lines)


def test_windows_collection_never_imports_linux_fcntl_from_shared_contracts() -> None:
    shared_path = PROJECT_ROOT / "tests" / "test_rotation_backend_contract.py"
    shared_tree = ast.parse(shared_path.read_text(encoding="utf-8"))
    assert not any(
        isinstance(node, ast.ImportFrom)
        and node.module == "forgejo_api_mcp.linux_credentials"
        for node in shared_tree.body
    )

    linux_specific = {
        "test_restore_timeout_finishes_unknown_without_retry_loop",
        "test_linux_backend_reconciliation_controls_actual_restore_mutation_count",
        "test_real_late_commit_is_quarantined_until_explicit_administrative_clear",
        "test_standalone_restore_timeout_performs_final_read_and_stays_quarantined",
        "test_proven_pre_dispatch_mutating_timeout_clears_provisional_fence",
    }
    guarded: set[str] = set()
    shared_tests = 0
    for node in shared_tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) or not node.name.startswith(
            "test_"
        ):
            continue
        shared_tests += 1
        local_linux_import = any(
            isinstance(child, ast.ImportFrom)
            and child.module == "forgejo_api_mcp.linux_credentials"
            for child in ast.walk(node)
        )
        if local_linux_import:
            decorators = " ".join(ast.unparse(decorator) for decorator in node.decorator_list)
            assert "skipif" in decorators
            assert "sys.platform != 'linux'" in decorators
            guarded.add(node.name)
    assert guarded == linux_specific
    assert shared_tests > len(guarded)

    linux_path = PROJECT_ROOT / "tests" / "test_linux_credentials.py"
    linux_tree = ast.parse(linux_path.read_text(encoding="utf-8"))
    guard_line = next(
        node.lineno
        for node in linux_tree.body
        if isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Call)
        and ast.unparse(node.value.func) == "pytest.importorskip"
    )
    import_line = next(
        node.lineno
        for node in linux_tree.body
        if isinstance(node, ast.ImportFrom)
        and node.module == "forgejo_api_mcp.linux_credentials"
    )
    assert guard_line < import_line


def test_quarantine_capable_test_backends_use_private_runtime_directories() -> None:
    checked = 0
    for path in (PROJECT_ROOT / "tests").glob("test_*.py"):
        if path.name == "test_linux_secretservice.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = (
                node.func.id
                if isinstance(node.func, ast.Name)
                else node.func.attr
                if isinstance(node.func, ast.Attribute)
                else ""
            )
            if name != "LinuxCredentialBackend":
                continue
            checked += 1
            assert any(keyword.arg == "runtime_dir" for keyword in node.keywords), path
    assert checked >= 8


def test_live_store_smoke_is_opt_in_isolated_and_synthetic() -> None:
    workflow = (PROJECT_ROOT / ".github" / "workflows" / "ci.yml").read_text(
        encoding="utf-8"
    )
    smoke = (PROJECT_ROOT / "tests" / "smoke" / "test_linux_secretservice.py").read_text(
        encoding="utf-8"
    )

    assert "run_live_secret_service_smoke" in workflow
    assert "inputs.run_live_secret_service_smoke == true" in workflow
    assert "dbus-run-session" in workflow
    assert "FORGEJO_LIVE_SECRET_SERVICE_ISOLATED=1" in workflow
    assert "secrets.token_urlsafe" in smoke
    assert "FORGEJO_LIVE_SECRET_SERVICE_ISOLATED" in smoke
