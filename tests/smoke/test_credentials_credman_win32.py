from __future__ import annotations

import os
import sys

import pytest

from forgejo_api_mcp import credentials

SMOKE_TARGET = "mcp/forgejo-mcp/access-token-smoke"

pytestmark = pytest.mark.skipif(
    sys.platform != "win32" or os.getenv("RUN_WIN32_CREDMAN_SMOKE") != "1",
    reason="opt-in Windows Credential Manager smoke is disabled",
)


def test_real_credman_round_trip_on_dedicated_nonproduction_target() -> None:
    prior = credentials._raw_read(SMOKE_TARGET)
    first = "credman-smoke-first"
    second = "credman-smoke-second"
    try:
        credentials._raw_write(SMOKE_TARGET, first)
        assert credentials._raw_read(SMOKE_TARGET).credential_blob == first
        credentials._raw_write(SMOKE_TARGET, second)
        assert credentials._raw_read(SMOKE_TARGET).credential_blob == second
        credentials._raw_delete(SMOKE_TARGET)
        assert credentials._raw_read(SMOKE_TARGET) is None
    finally:
        if prior is None:
            credentials._raw_delete(SMOKE_TARGET)
        else:
            credentials._win32_write(
                prior.target,
                prior.username,
                prior.credential_blob,
                prior.persist_type,
            )
