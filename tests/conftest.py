from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

import pytest

QUARANTINE_FILENAME = "forgejo-api-mcp-quarantine"


def _marker_fingerprint(path: Path | None) -> tuple[object, ...] | None:
    if path is None:
        return None
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    content = path.read_bytes() if stat.S_ISREG(info.st_mode) and info.st_size <= 4096 else b""
    return (
        info.st_dev,
        info.st_ino,
        stat.S_IMODE(info.st_mode),
        info.st_uid,
        info.st_size,
        info.st_mtime_ns,
        content,
    )


@pytest.fixture(scope="session", autouse=True)
def isolate_real_quarantine_marker(tmp_path_factory: pytest.TempPathFactory):
    if sys.platform != "linux":
        yield
        return

    original_runtime = os.environ.get("XDG_RUNTIME_DIR")
    real_marker = (
        Path(original_runtime) / QUARANTINE_FILENAME if original_runtime is not None else None
    )
    original_fingerprint = _marker_fingerprint(real_marker)
    private_runtime = tmp_path_factory.mktemp("forgejo-api-mcp-xdg-runtime")
    private_runtime.chmod(0o700)
    os.environ["XDG_RUNTIME_DIR"] = str(private_runtime)
    try:
        yield
    finally:
        if original_runtime is None:
            os.environ.pop("XDG_RUNTIME_DIR", None)
        else:
            os.environ["XDG_RUNTIME_DIR"] = original_runtime
        assert _marker_fingerprint(real_marker) == original_fingerprint
