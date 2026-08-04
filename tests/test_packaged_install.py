from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
PACKAGE_PROBE = """
import json
from importlib.resources import files
from pathlib import Path

import forgejo_api_mcp
from forgejo_api_mcp.catalog import OperationCatalog

resource = files("forgejo_api_mcp").joinpath("openapi.json")
catalog = OperationCatalog.bundled()
print(json.dumps({
    "count": len(catalog),
    "version": catalog.version,
    "resource_exists": resource.is_file(),
    "module_path": str(Path(forgejo_api_mcp.__file__).resolve()),
}))
"""


def _run(command: list[str], *, cwd: Path, environment: dict[str, str]) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        command,
        cwd=cwd,
        env=environment,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert completed.returncode == 0, (
        f"Command failed: {subprocess.list2cmdline(command)}\n"
        f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
    )
    return completed


@pytest.mark.parametrize("artifact_kind", ["wheel", "sdist"])
def test_built_artifact_installs_isolated_with_bundled_catalog(
    artifact_kind: str, tmp_path: Path
) -> None:
    uv = shutil.which("uv")
    assert uv is not None, "uv is required for reproducible package verification"

    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    environment.pop("VIRTUAL_ENV", None)
    dist_dir = tmp_path / "dist"
    _run([uv, "build", "--out-dir", str(dist_dir)], cwd=PROJECT_ROOT, environment=environment)

    artifacts = {
        "wheel": sorted(dist_dir.glob("*.whl")),
        "sdist": sorted(dist_dir.glob("*.tar.gz")),
    }
    assert len(artifacts["wheel"]) == 1
    assert len(artifacts["sdist"]) == 1

    environment_path = tmp_path / f"venv-{artifact_kind}"
    _run(
        [uv, "venv", "--python", sys.executable, str(environment_path)],
        cwd=tmp_path,
        environment=environment,
    )
    isolated_python = environment_path / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    _run(
        [
            uv,
            "pip",
            "install",
            "--python",
            str(isolated_python),
            "--no-deps",
            str(artifacts[artifact_kind][0]),
        ],
        cwd=tmp_path,
        environment=environment,
    )

    probe_dir = tmp_path / f"probe-{artifact_kind}"
    probe_dir.mkdir()
    completed = _run(
        [str(isolated_python), "-I", "-c", PACKAGE_PROBE],
        cwd=probe_dir,
        environment=environment,
    )
    result = json.loads(completed.stdout)

    assert result["resource_exists"] is True
    assert result["version"] == "1.25.4"
    assert result["count"] == 467
    assert not Path(result["module_path"]).is_relative_to(PROJECT_ROOT)
