from __future__ import annotations

import json
import os
from contextlib import nullcontext
from typing import Never

import httpx
import pytest

from forgejo_api_mcp.credential_backend import (
    LINUX_GUIDANCE_ID,
    CredentialCategory,
    CredentialOperationError,
)
from forgejo_api_mcp.launcher import launch
from forgejo_api_mcp.rotate import EXIT_CREDENTIAL_STORE_ERROR, _run


class ReadBackend:
    def __init__(self, token: str) -> None:
        self.token = token

    def read(self) -> str:
        return self.token


def test_launcher_injects_secret_only_into_mcp_child_environment(
    monkeypatch,
) -> None:
    canary = "launcher-private-canary"
    observed: dict[str, object] = {}

    def runner(command: list[str], environment: dict[str, str]) -> int:
        observed["command"] = command
        observed["environment"] = environment.copy()
        observed["environment_reference"] = environment
        return 0

    monkeypatch.setenv("FORGEJO_ACCESS_TOKEN", "preexisting-parent-value")
    assert launch(backend=ReadBackend(canary), process_runner=runner) == 0
    assert observed["environment"]["FORGEJO_ACCESS_TOKEN"] == canary  # type: ignore[index]
    assert observed["command"][1:] == ["-m", "forgejo_api_mcp.server"]  # type: ignore[index]
    assert canary not in " ".join(observed["command"])  # type: ignore[arg-type]
    assert "FORGEJO_ACCESS_TOKEN" not in observed["environment_reference"]  # type: ignore[operator]
    assert os.environ["FORGEJO_ACCESS_TOKEN"] == "preexisting-parent-value"


@pytest.mark.parametrize(
    ("setup_state", "category"),
    [
        ("missing_default", CredentialCategory.MISSING),
        ("zero_item", CredentialCategory.MISSING),
        ("multiple_item", CredentialCategory.STORE_ERROR),
        ("locked_collection", CredentialCategory.LOCKED),
        ("locked_item", CredentialCategory.LOCKED),
        ("prompt_required", CredentialCategory.PROMPT_REQUIRED),
        ("prompt_dismissed", CredentialCategory.PROMPT_DISMISSED),
        ("unavailable_dbus", CredentialCategory.SERVICE_UNAVAILABLE),
        ("unavailable_secret_service", CredentialCategory.SERVICE_UNAVAILABLE),
        ("attributes_mismatch", CredentialCategory.STORE_ERROR),
        ("label_mismatch", CredentialCategory.STORE_ERROR),
        ("content_type_mismatch", CredentialCategory.STORE_ERROR),
    ],
)
def test_launcher_and_rotation_guidance_cover_every_concrete_setup_state(
    setup_state: str,
    category: CredentialCategory,
    capsys,
    caplog,
) -> None:
    raw_detail = f"{setup_state}: raw-library-path-and-payload"

    class FailingBackend:
        @staticmethod
        def _error(operation: str) -> Never:
            try:
                raise RuntimeError(raw_detail)
            except RuntimeError:
                raise CredentialOperationError(
                    category,
                    credential_state="unchanged",
                    operation=operation,
                    guidance_id=LINUX_GUIDANCE_ID,
                ) from None

        def availability(self) -> CredentialCategory:
            raise AssertionError("launcher and rotation must not issue an availability preflight")

        def read(self) -> str:
            self._error("read")

        def snapshot(self):
            self._error("snapshot")

        def replace_existing(self, _token: str) -> None:
            pytest.fail("setup failure must prevent replacement")

        def restore(self, _snapshot: object) -> None:
            pytest.fail("setup failure must prevent restore")

        def discard(self, _snapshot: object) -> None:
            pytest.fail("no snapshot exists to discard")

        def lock(self, *, timeout: float):
            assert timeout > 0
            return nullcontext()

    backend = FailingBackend()
    assert launch(
        backend=backend,
        process_runner=lambda *_args: pytest.fail("launcher child must not start"),
    ) == 7
    launcher_capture = capsys.readouterr()
    launcher_payload = json.loads(launcher_capture.err)
    assert launcher_payload == {
        "category": category.value,
        "credentialState": "unchanged",
        "guidanceId": "linux_secret_service_setup",
    }
    assert launcher_capture.out == ""

    code, rotation_payload = _run(
        "candidate",
        base_url="https://forgejo.example",
        transport=httpx.MockTransport(lambda request: httpx.Response(200, request=request)),
        store=backend,
    )
    assert code == EXIT_CREDENTIAL_STORE_ERROR
    assert rotation_payload["category"] == category.value
    assert rotation_payload["credentialState"] == "unchanged"
    assert rotation_payload["guidanceId"] == "linux_secret_service_setup"
    assert rotation_payload["detail"] == (
        "Credential store operation failed; use the documented platform setup and retry."
    )
    public = launcher_capture.out + launcher_capture.err + repr(rotation_payload)
    public += " ".join(record.getMessage() for record in caplog.records)
    assert raw_detail not in public
