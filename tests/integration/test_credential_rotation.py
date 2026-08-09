from __future__ import annotations

import io
import json
import sys

import httpx
import pytest

from forgejo_api_mcp.credentials import (
    CRED_PERSIST_LOCAL_MACHINE,
    TARGET_NAME,
    CredentialRecord,
)
from forgejo_api_mcp.rotate import (
    EXIT_CREDENTIAL_REJECTED,
    EXIT_READBACK_MISMATCH,
    EXIT_ROTATED,
    main,
)


class IntegrationStore:
    def __init__(self, initial: CredentialRecord | None = None, *, mismatch_once: bool = False) -> None:
        self.written: dict[str, object] = {}
        self.deleted = False
        self.record = initial
        self.mismatch_once = mismatch_once
        self.mismatch_used = False

    def write(self, token: str) -> None:
        self.written = {"target": TARGET_NAME, "token": token, "username": "forgejo-api-mcp"}
        self.record = CredentialRecord(
            TARGET_NAME, "forgejo-api-mcp", token, CRED_PERSIST_LOCAL_MACHINE
        )

    def read(self) -> CredentialRecord | None:
        if self.mismatch_once and self.written and not self.mismatch_used:
            self.mismatch_used = True
            return CredentialRecord(
                TARGET_NAME, "forgejo-api-mcp", "synthetic-mismatch", CRED_PERSIST_LOCAL_MACHINE
            )
        return self.record

    def delete(self) -> None:
        self.deleted = True
        self.written = {}
        self.record = None

    def restore(self, record: CredentialRecord) -> None:
        self.record = record


def _ok(request: httpx.Request) -> httpx.Response:
    assert request.url.path == "/api/v1/user"
    return httpx.Response(200, json={"login": "alice"}, request=request)


def _unauthorized(request: httpx.Request) -> httpx.Response:
    return httpx.Response(401, request=request)


def test_rotation_validates_writes_readback_and_redacts(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    token = "integration-good-token"
    monkeypatch.setenv("FORGEJO_BASE_URL", "https://forgejo.example")
    monkeypatch.setattr(sys, "stdin", io.StringIO(token + "\n"))
    store = IntegrationStore()

    code = main(
        [],
        transport=httpx.MockTransport(_ok),
        store=store,
    )

    payload = json.loads(capsys.readouterr().out.strip())
    assert code == EXIT_ROTATED
    assert payload["status"] == "rotated"
    assert payload["target"] == TARGET_NAME
    assert payload["credentialState"] == "written"
    assert "login" not in payload
    assert "tokenSha256" not in payload
    assert payload["restartRequired"] is True
    assert store.written["token"] == token
    assert token not in json.dumps(payload)


def test_rotation_writes_nothing_on_rejected_token(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    token = "integration-stale-token"
    monkeypatch.setenv("FORGEJO_BASE_URL", "https://forgejo.example/api/v1")
    monkeypatch.setattr(sys, "stdin", io.StringIO(token + "\n"))
    store = IntegrationStore()

    code = main(
        [],
        transport=httpx.MockTransport(_unauthorized),
        store=store,
    )

    payload = json.loads(capsys.readouterr().out.strip())
    assert code == EXIT_CREDENTIAL_REJECTED
    assert payload["status"] == "credential_rejected"
    assert payload["restartRequired"] is False
    assert store.written == {}
    assert store.deleted is False
    assert token not in json.dumps(payload)


def test_rotation_never_logs_authorization_header_value(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    token = "secret-header-token"
    monkeypatch.setenv("FORGEJO_BASE_URL", "https://forgejo.example")
    captured_auth: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured_auth.append(request.headers.get("authorization", ""))
        return httpx.Response(200, json={"login": "alice"}, request=request)

    monkeypatch.setattr(sys, "stdin", io.StringIO(token + "\n"))
    store = IntegrationStore()

    main([], transport=httpx.MockTransport(handler), store=store)

    out = capsys.readouterr()
    assert captured_auth == [f"token {token}"]
    assert f"token {token}" not in out.out
    assert token not in out.out


def test_rotation_mismatch_restores_prior_end_to_end(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    prior = CredentialRecord(
        TARGET_NAME, "forgejo-api-mcp", "prior-integration-value", CRED_PERSIST_LOCAL_MACHINE
    )
    store = IntegrationStore(prior, mismatch_once=True)
    monkeypatch.setenv("FORGEJO_BASE_URL", "https://forgejo.example")
    monkeypatch.setattr(sys, "stdin", io.StringIO("new-integration-value\n"))

    code = main([], transport=httpx.MockTransport(_ok), store=store)
    payload = json.loads(capsys.readouterr().out)

    assert code == EXIT_READBACK_MISMATCH
    assert payload["credentialState"] == "restored"
    assert payload["restartRequired"] is False
    assert store.record == prior
