from __future__ import annotations

import json
import sys

import pytest

from forgejo_api_mcp.credential_backend import CredentialCategory, CredentialOperationError
from forgejo_api_mcp.quarantine import (
    EXIT_INVALID_INPUT,
    EXIT_PLATFORM_UNSUPPORTED,
    EXIT_QUARANTINED,
    EXIT_STORE_ERROR,
    main,
)


class MarkerBackend:
    def __init__(self, present: bool = False) -> None:
        self.present = present
        self.clears = 0

    def quarantine_present(self) -> bool:
        return self.present

    def clear_quarantine(self) -> bool:
        self.clears += 1
        self.present = False
        return True


def test_check_has_stable_clear_and_quarantined_contract(capsys) -> None:
    clear = MarkerBackend()
    assert main(["check"], backend=clear) == 0
    assert json.loads(capsys.readouterr().out) == {
        "credentialState": "unknown",
        "status": "clear",
    }

    quarantined = MarkerBackend(present=True)
    assert main(["check"], backend=quarantined) == EXIT_QUARANTINED
    assert json.loads(capsys.readouterr().out) == {
        "credentialState": "unknown",
        "guidanceId": "linux_secret_service_quarantine",
        "status": "quarantined",
    }


def test_clear_requires_explicit_operator_verified_acknowledgement(capsys) -> None:
    backend = MarkerBackend(present=True)
    assert main(["clear"], backend=backend) == EXIT_INVALID_INPUT
    assert backend.present is True
    assert backend.clears == 0
    assert json.loads(capsys.readouterr().out)["status"] == "invalid_input"

    assert main(["clear", "--operator-verified"], backend=backend) == 0
    assert backend.present is False
    assert backend.clears == 1
    assert json.loads(capsys.readouterr().out)["status"] == "cleared"


def test_administration_redacts_store_errors(capsys) -> None:
    canary = "private-marker-path-canary"

    class FailingBackend:
        def quarantine_present(self) -> bool:
            try:
                raise OSError(canary)
            except OSError:
                raise CredentialOperationError(
                    CredentialCategory.STORE_ERROR,
                    credential_state="unknown",
                    operation="quarantine_check",
                    guidance_id="linux_secret_service_quarantine",
                ) from None

    assert main(["check"], backend=FailingBackend()) == EXIT_STORE_ERROR
    output = capsys.readouterr().out
    assert canary not in output
    assert json.loads(output) == {
        "category": "store_error",
        "credentialState": "unknown",
        "guidanceId": "linux_secret_service_quarantine",
        "status": "store_error",
    }


def test_administration_is_platform_fail_closed_without_importing_linux_backend(
    monkeypatch: pytest.MonkeyPatch,
    capsys,
) -> None:
    monkeypatch.setattr(sys, "platform", "win32")
    assert main(["check"]) == EXIT_PLATFORM_UNSUPPORTED
    assert json.loads(capsys.readouterr().out)["status"] == "platform_unsupported"
