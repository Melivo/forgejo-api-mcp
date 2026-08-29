from __future__ import annotations

import io
import json
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import nullcontext
from pathlib import Path

import httpx
import pytest

from forgejo_api_mcp.credential_backend import (
    TARGET_NAME,
    CredentialCategory,
    CredentialOperationError,
)
from forgejo_api_mcp.rotate import (
    EXIT_CREDENTIAL_REJECTED,
    EXIT_CREDENTIAL_STORE_ERROR,
    EXIT_FORBIDDEN,
    EXIT_INVALID_INPUT,
    EXIT_PLATFORM_UNSUPPORTED,
    EXIT_PROVIDER_ERROR,
    EXIT_READBACK_MISMATCH,
    EXIT_ROTATED,
    EXIT_TRANSPORT_OR_TIMEOUT,
    _run,
    main,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BASE_URL = "https://forgejo.example/api/v1"


class Snapshot:
    def __init__(self, token: str | None) -> None:
        self.token = token
        self.discarded = False

    @property
    def present(self) -> bool:
        return not self.discarded and self.token is not None

    def __repr__(self) -> str:
        return "Snapshot(<redacted>)"


class RotateFakeStore:
    def __init__(self, *, initial: str | None = None, readback: str | None = None) -> None:
        self.record = initial
        self._readback = readback
        self._forced_readback_used = False
        self.writes: list[str] = []
        self.deleted: list[str] = []

    def availability(self) -> CredentialCategory:
        return CredentialCategory.AVAILABLE

    def snapshot(self) -> Snapshot:
        return Snapshot(self.record)

    def replace_existing(self, token: str) -> None:
        self.writes.append(token)
        self.record = token

    def read(self) -> str:
        if self._readback is not None and self.writes and not self._forced_readback_used:
            self._forced_readback_used = True
            return self._readback
        if self.record is None:
            raise CredentialOperationError(
                CredentialCategory.MISSING,
                credential_state="unchanged",
                operation="read",
            )
        return self.record

    def restore(self, snapshot: Snapshot) -> None:
        if snapshot.token is None:
            self.deleted.append(TARGET_NAME)
            self.record = None
        else:
            self.writes.append(snapshot.token)
            self.record = snapshot.token

    def discard(self, snapshot: Snapshot) -> None:
        snapshot.token = None
        snapshot.discarded = True

    def lock(self, *, timeout: float):
        del timeout
        return nullcontext()

    @property
    def last_written(self) -> str | None:
        return self.writes[-1] if self.writes else None


def _ok_handler(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json={"login": "alice"}, request=request)


def _unauthorized_handler(request: httpx.Request) -> httpx.Response:
    return httpx.Response(401, request=request)


def _forbidden_handler(request: httpx.Request) -> httpx.Response:
    return httpx.Response(403, request=request)


def _provider_error_handler(request: httpx.Request) -> httpx.Response:
    return httpx.Response(500, request=request)


def _timeout_handler(request: httpx.Request) -> httpx.Response:
    raise httpx.ConnectTimeout("slow", request=request)


def _transport_handler(request: httpx.Request) -> httpx.Response:
    raise httpx.ConnectError("down", request=request)


def test_run_rotates_on_validated_token_and_readback() -> None:
    store = RotateFakeStore()
    code, output = _run(
        "good-token", base_url=BASE_URL, transport=httpx.MockTransport(_ok_handler), store=store
    )
    assert code == EXIT_ROTATED
    assert output["status"] == "rotated"
    assert output["credentialState"] == "written"
    assert output["target"] == TARGET_NAME
    assert "login" not in output
    assert "tokenSha256" not in output
    assert output["restartRequired"] is True
    assert store.last_written == "good-token"
    assert "good-token" not in json.dumps(output)


def test_run_writes_nothing_when_token_is_rejected() -> None:
    store = RotateFakeStore()
    code, output = _run(
        "stale-token",
        base_url=BASE_URL,
        transport=httpx.MockTransport(_unauthorized_handler),
        store=store,
    )
    assert code == EXIT_CREDENTIAL_REJECTED
    assert output["status"] == "credential_rejected"
    assert output["restartRequired"] is False
    assert store.writes == []
    assert "stale-token" not in json.dumps(output)


def test_run_maps_forbidden_and_provider_error() -> None:
    store = RotateFakeStore()
    code, output = _run(
        "t", base_url=BASE_URL, transport=httpx.MockTransport(_forbidden_handler), store=store
    )
    assert code == EXIT_FORBIDDEN
    assert output["status"] == "forbidden"

    code2, output2 = _run(
        "t", base_url=BASE_URL, transport=httpx.MockTransport(_provider_error_handler), store=store
    )
    assert code2 == EXIT_PROVIDER_ERROR
    assert output2["status"] == "provider_error"
    assert store.writes == []


def test_run_maps_timeout_to_transport_exit() -> None:
    store = RotateFakeStore()
    code, output = _run(
        "good-token", base_url=BASE_URL, transport=httpx.MockTransport(_timeout_handler), store=store
    )
    assert code == EXIT_TRANSPORT_OR_TIMEOUT
    assert output["status"] == "transport_or_timeout"
    assert store.writes == []

    code2, output2 = _run(
        "good-token",
        base_url=BASE_URL,
        transport=httpx.MockTransport(_transport_handler),
        store=store,
    )
    assert code2 == EXIT_TRANSPORT_OR_TIMEOUT
    assert output2["status"] == "transport_or_timeout"


def test_run_readback_mismatch_deletes_new_entry_when_no_prior() -> None:
    store = RotateFakeStore(readback="something-else")
    code, output = _run(
        "good-token", base_url=BASE_URL, transport=httpx.MockTransport(_ok_handler), store=store
    )
    assert code == EXIT_READBACK_MISMATCH
    assert output["status"] == "readback_mismatch"
    assert store.deleted == [TARGET_NAME]


def test_run_readback_mismatch_restores_prior_when_present() -> None:
    store = RotateFakeStore(initial="old-token", readback="something-else")
    code, _output = _run(
        "new-token", base_url=BASE_URL, transport=httpx.MockTransport(_ok_handler), store=store
    )
    assert code == EXIT_READBACK_MISMATCH
    assert store.last_written == "old-token"
    assert store.deleted == []


def test_run_reports_platform_unsupported(monkeypatch: pytest.MonkeyPatch) -> None:
    from forgejo_api_mcp import rotate
    from forgejo_api_mcp.credential_backend import PlatformUnsupported

    def boom() -> object:
        raise PlatformUnsupported("unsupported")

    monkeypatch.setattr(rotate, "_default_store", boom)
    code, output = _run(
        "good-token",
        base_url=BASE_URL,
        transport=httpx.MockTransport(_ok_handler),
    )
    assert code == EXIT_PLATFORM_UNSUPPORTED
    assert output["status"] == "platform_unsupported"


def test_run_rejects_empty_or_multiline_token_before_any_call() -> None:
    store = RotateFakeStore()
    code, output = _run("", base_url=BASE_URL, transport=httpx.MockTransport(_ok_handler), store=store)
    assert code == EXIT_INVALID_INPUT
    assert output["status"] == "invalid_input"
    assert store.writes == []

    code2, _ = _run(
        "with\nnewline", base_url=BASE_URL, transport=httpx.MockTransport(_ok_handler), store=store
    )
    assert code2 == EXIT_INVALID_INPUT
    assert store.writes == []


def test_run_never_emits_token_in_output_across_outcomes() -> None:
    secret = "tok-secret-xyz"
    for handler in (_ok_handler, _unauthorized_handler, _forbidden_handler, _timeout_handler):
        store = RotateFakeStore()
        _, output = _run(
            secret, base_url=BASE_URL, transport=httpx.MockTransport(handler), store=store
        )
        assert secret not in json.dumps(output)


def test_main_reads_token_from_stdin_only_and_emits_redacted_json(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    token = "stdin-only-token"
    argv: list[str] = []
    monkeypatch.setenv("FORGEJO_BASE_URL", BASE_URL)
    monkeypatch.setattr(sys, "stdin", io.StringIO(token + "\n"))
    store = RotateFakeStore()

    code = main(argv, transport=httpx.MockTransport(_ok_handler), store=store)

    captured = capsys.readouterr()
    payload = json.loads(captured.out.strip())
    assert code == EXIT_ROTATED
    assert payload["status"] == "rotated"
    assert payload["credentialState"] == "written"
    assert "tokenSha256" not in payload
    assert "login" not in payload
    assert store.last_written == token
    assert token not in captured.out
    assert token not in captured.err
    assert token not in " ".join(argv)


def test_main_writes_nothing_and_reports_rejection_on_401(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    token = "stale-stdin-token"
    monkeypatch.setenv("FORGEJO_BASE_URL", BASE_URL)
    monkeypatch.setattr(sys, "stdin", io.StringIO(token + "\n"))
    store = RotateFakeStore()

    code = main(
        [],
        transport=httpx.MockTransport(_unauthorized_handler),
        store=store,
    )

    captured = capsys.readouterr()
    payload = json.loads(captured.out.strip())
    assert code == EXIT_CREDENTIAL_REJECTED
    assert payload["status"] == "credential_rejected"
    assert store.writes == []
    assert token not in captured.out


def test_main_rejects_empty_stdin(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "stdin", io.StringIO("\n"))
    monkeypatch.setenv("FORGEJO_BASE_URL", BASE_URL)
    code = main([], transport=httpx.MockTransport(_ok_handler), store=RotateFakeStore())
    payload = json.loads(capsys.readouterr().out.strip())
    assert code == EXIT_INVALID_INPUT
    assert payload["status"] == "invalid_input"


def test_main_rejects_piped_multiline_stdin_before_network_or_write(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    piped_input = "first-secret-line\nsecond-secret-line\n"
    requests: list[httpx.Request] = []
    store = RotateFakeStore()

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"login": "alice"}, request=request)

    monkeypatch.setattr(sys, "stdin", io.StringIO(piped_input))
    monkeypatch.setenv("FORGEJO_BASE_URL", BASE_URL)

    code = main([], transport=httpx.MockTransport(handler), store=store)

    captured = capsys.readouterr()
    payload = json.loads(captured.out.strip())
    assert code == EXIT_INVALID_INPUT
    assert payload["status"] == "invalid_input"
    assert requests == []
    assert store.writes == []
    assert "first-secret-line" not in captured.out + captured.err
    assert "second-secret-line" not in captured.out + captured.err


def test_main_rejects_non_https_base_url_with_zero_requests_and_zero_writes(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "stdin", io.StringIO("good\n"))
    monkeypatch.setenv("FORGEJO_BASE_URL", "http://forgejo.example")
    requests: list[httpx.Request] = []
    store = RotateFakeStore()

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"login": "alice"}, request=request)

    code = main([], transport=httpx.MockTransport(handler), store=store)

    payload = json.loads(capsys.readouterr().out.strip())
    assert code == EXIT_INVALID_INPUT
    assert payload["status"] == "invalid_input"
    assert requests == []
    assert store.writes == []


@pytest.mark.parametrize(
    "base_url",
    [
        "https://[",
        "https:///missing-host",
        "https://user:password@forgejo.example",
        "https://forgejo.example?private=query",
        "https://forgejo.example?",
        "https://forgejo.example#private-fragment",
        "https://forgejo.example#",
        "https://bad host.example",
        "https://forgejo.example:not-a-port",
        "https://forgejo.example:99999",
    ],
)
def test_main_rejects_malformed_or_credential_bearing_base_url_redacted(
    base_url: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    class UnreadableStdin:
        def isatty(self) -> bool:
            raise AssertionError("invalid base URL must be rejected before stdin")

    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, request=request)

    monkeypatch.setattr(sys, "stdin", UnreadableStdin())
    monkeypatch.setenv("FORGEJO_BASE_URL", base_url)
    store = RotateFakeStore()
    code = main([], transport=httpx.MockTransport(handler), store=store)
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert code == EXIT_INVALID_INPUT
    assert payload["status"] == "invalid_input"
    assert payload["detail"] == "Forgejo base URL is invalid."
    assert base_url not in captured.out
    assert base_url not in captured.err
    assert requests == []
    assert store.writes == []


@pytest.mark.parametrize("codepoint", [*range(0x20), 0x7F])
def test_run_rejects_every_c0_and_del_character_anywhere_in_url(
    codepoint: int,
) -> None:
    base_url = f"https://forgejo.example/path{chr(codepoint)}segment"
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, request=request)

    store = RotateFakeStore()
    code, payload = _run(
        "candidate",
        base_url=base_url,
        transport=httpx.MockTransport(handler),
        store=store,
    )
    assert code == EXIT_INVALID_INPUT
    assert payload["status"] == "invalid_input"
    assert payload["detail"] == "Forgejo base URL is invalid."
    assert base_url not in json.dumps(payload)
    assert requests == []
    assert store.writes == []


def test_run_redacts_httpx_invalid_url_from_client_construction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from forgejo_api_mcp import rotate

    raw_url = "https://forgejo.example/raw-invalid-url-canary"

    async def invalid_url(*_args: object, **_kwargs: object) -> object:
        raise httpx.InvalidURL(raw_url)

    monkeypatch.setattr(rotate, "classify_token", invalid_url)
    code, output = rotate._run("candidate", base_url=BASE_URL, store=RotateFakeStore())
    rendered = json.dumps(output)
    assert code == EXIT_INVALID_INPUT
    assert output["status"] == "invalid_input"
    assert output["detail"] == "Forgejo base URL is invalid."
    assert raw_url not in rendered


def test_main_takes_no_token_argument(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "stdin", io.StringIO("\n"))
    code = main(["--token", "never-accepted"], store=RotateFakeStore())
    assert code == 2
    assert "never-accepted" not in capsys.readouterr().err


@pytest.mark.parametrize("argument", ["--username", "positional-secret-value"])
def test_main_rejects_every_argument_without_echoing_it(
    argument: str, capsys: pytest.CaptureFixture[str]
) -> None:
    code = main([argument], store=RotateFakeStore())
    captured = capsys.readouterr()
    assert code == EXIT_INVALID_INPUT
    assert argument not in captured.out
    assert argument not in captured.err


def test_main_does_not_read_secret_env(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("FORGEJO_ACCESS_TOKEN", "env-secret-leak")
    monkeypatch.setenv("FORGEJO_BASE_URL", BASE_URL)
    monkeypatch.setattr(sys, "stdin", io.StringIO("stdin-token\n"))
    store = RotateFakeStore()

    code = main([], transport=httpx.MockTransport(_ok_handler), store=store)

    out = capsys.readouterr().out
    assert code == EXIT_ROTATED
    assert store.last_written == "stdin-token"
    assert "env-secret-leak" not in out


class ContractStore:
    def __init__(self, initial: str | None = None) -> None:
        self.record = initial
        self.writes = 0

    def availability(self) -> CredentialCategory:
        return CredentialCategory.AVAILABLE

    def snapshot(self) -> Snapshot:
        return Snapshot(self.record)

    def read(self) -> str:
        if self.record is None:
            raise CredentialOperationError(
                CredentialCategory.MISSING,
                credential_state="unchanged",
                operation="read",
            )
        return self.record

    def replace_existing(self, token: str) -> None:
        self.writes += 1
        self.record = token

    def restore(self, snapshot: Snapshot) -> None:
        self.record = snapshot.token

    def discard(self, snapshot: Snapshot) -> None:
        snapshot.token = None
        snapshot.discarded = True

    def lock(self, *, timeout: float):
        del timeout
        return nullcontext()


class FaultStore(ContractStore):
    def __init__(
        self,
        initial: str | None = None,
        *,
        fail_read_numbers: set[int] | None = None,
        fail_write: bool = False,
        fail_restore: bool = False,
        fail_delete: bool = False,
    ) -> None:
        super().__init__(initial)
        self.read_number = 0
        self.fail_read_numbers = fail_read_numbers or set()
        self.fail_write = fail_write
        self.fail_restore = fail_restore
        self.fail_delete = fail_delete

    def _fail_read(self, operation: str) -> None:
        self.read_number += 1
        if self.read_number in self.fail_read_numbers:
            raise CredentialOperationError(
                CredentialCategory.STORE_ERROR,
                credential_state="unchanged",
                operation=operation,
            )

    def snapshot(self) -> Snapshot:
        self._fail_read("snapshot")
        return super().snapshot()

    def read(self) -> str:
        self._fail_read("read")
        return super().read()

    def replace_existing(self, token: str) -> None:
        if self.fail_write:
            raise CredentialOperationError(
                CredentialCategory.STORE_ERROR,
                credential_state="unchanged",
                operation="replace_existing",
            )
        super().replace_existing(token)

    def restore(self, snapshot: Snapshot) -> None:
        failed = self.fail_delete if snapshot.token is None else self.fail_restore
        if failed:
            raise CredentialOperationError(
                CredentialCategory.STORE_ERROR,
                credential_state="unknown",
                operation="restore",
            )
        super().restore(snapshot)


def test_run_lock_timeout_is_store_error_with_zero_writes() -> None:
    store = ContractStore()

    def lock_timeout(**_kwargs: object):
        raise CredentialOperationError(
            CredentialCategory.TIMEOUT,
            credential_state="unchanged",
            operation="lock",
        )

    code, output = _run(
        "candidate",
        base_url=BASE_URL,
        transport=httpx.MockTransport(_ok_handler),
        store=store,
        lock_factory=lock_timeout,
    )
    assert code == 7
    assert output["status"] == "credential_store_error"
    assert output["credentialState"] == "unchanged"
    assert output["restartRequired"] is False
    assert store.writes == 0


def test_run_uses_target_free_store_and_redacted_output() -> None:
    store = ContractStore()
    code, output = _run(
        "candidate",
        base_url=BASE_URL,
        transport=httpx.MockTransport(_ok_handler),
        store=store,
        lock_factory=lambda **_kwargs: nullcontext(),
    )
    assert code == EXIT_ROTATED
    assert output["credentialState"] == "written"
    assert "tokenSha256" not in output
    assert "login" not in output


def test_run_prewrite_read_failure_has_zero_writes() -> None:
    store = FaultStore(fail_read_numbers={1})
    code, output = _run(
        "candidate",
        base_url=BASE_URL,
        transport=httpx.MockTransport(_ok_handler),
        store=store,
        lock_factory=lambda **_kwargs: nullcontext(),
    )
    assert (code, output["status"], output["credentialState"], output["restartRequired"]) == (
        EXIT_CREDENTIAL_STORE_ERROR,
        "credential_store_error",
        "unchanged",
        False,
    )
    assert store.writes == 0


def test_run_write_failure_is_unchanged() -> None:
    store = FaultStore(fail_write=True)
    code, output = _run(
        "candidate",
        base_url=BASE_URL,
        transport=httpx.MockTransport(_ok_handler),
        store=store,
        lock_factory=lambda **_kwargs: nullcontext(),
    )
    assert code == EXIT_CREDENTIAL_STORE_ERROR
    assert output["credentialState"] == "unchanged"


@pytest.mark.parametrize(
    ("initial", "expected_state"),
    [
        (None, "deleted_new"),
        ("prior", "restored"),
    ],
)
def test_run_readback_failure_performs_verified_rollback(
    initial: str | None, expected_state: str
) -> None:
    store = FaultStore(initial, fail_read_numbers={2})
    code, output = _run(
        "candidate",
        base_url=BASE_URL,
        transport=httpx.MockTransport(_ok_handler),
        store=store,
        lock_factory=lambda **_kwargs: nullcontext(),
    )
    assert code == EXIT_CREDENTIAL_STORE_ERROR
    assert output["credentialState"] == expected_state
    assert store.record == initial


def test_run_rollback_verification_failure_reports_unknown() -> None:
    prior = "prior"
    store = FaultStore(prior, fail_read_numbers={2}, fail_restore=True)
    code, output = _run(
        "candidate",
        base_url=BASE_URL,
        transport=httpx.MockTransport(_ok_handler),
        store=store,
        lock_factory=lambda **_kwargs: nullcontext(),
    )
    assert code == EXIT_CREDENTIAL_STORE_ERROR
    assert output["credentialState"] == "unknown"
    assert output["restartRequired"] is False


def test_main_and_run_ignore_legacy_availability_preflight(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    requests: list[httpx.Request] = []
    store = RotateFakeStore()
    availability_calls = 0

    def forbidden_preflight() -> None:
        nonlocal availability_calls
        availability_calls += 1
        raise AssertionError("legacy availability preflight must not run")

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, request=request)

    store.ensure_available = forbidden_preflight  # type: ignore[attr-defined]
    monkeypatch.setattr(sys, "stdin", io.StringIO("candidate\n"))
    monkeypatch.setenv("FORGEJO_BASE_URL", BASE_URL)
    code = main([], transport=httpx.MockTransport(handler), store=store)
    output = json.loads(capsys.readouterr().out)
    assert code == EXIT_ROTATED
    assert output["credentialState"] == "written"
    assert availability_calls == 0
    assert len(requests) == 1


def test_two_rotations_serialize_the_store_transaction() -> None:
    validation_barrier = threading.Barrier(2)
    mutex = threading.Lock()
    state_guard = threading.Lock()
    store = ContractStore()
    store.write_order = []  # type: ignore[attr-defined]
    active = 0
    max_active = 0

    class TrackingLock:
        def __enter__(self):
            nonlocal active, max_active
            mutex.acquire()
            with state_guard:
                active += 1
                max_active = max(max_active, active)
            return self

        def __exit__(self, *_args: object) -> None:
            nonlocal active
            with state_guard:
                active -= 1
            mutex.release()

    original_write = store.replace_existing

    def tracked_write(token: str) -> None:
        store.write_order.append(token)  # type: ignore[attr-defined]
        original_write(token)

    store.replace_existing = tracked_write  # type: ignore[method-assign]

    def handler(request: httpx.Request) -> httpx.Response:
        validation_barrier.wait(timeout=2)
        return httpx.Response(200, request=request)

    def rotate(token: str) -> tuple[int, dict[str, object]]:
        return _run(
            token,
            base_url=BASE_URL,
            transport=httpx.MockTransport(handler),
            store=store,
            lock_factory=lambda **_kwargs: TrackingLock(),
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(rotate, ["candidate-a", "candidate-b"]))

    assert [result[0] for result in results] == [EXIT_ROTATED, EXIT_ROTATED]
    assert max_active == 1
    assert store.record is not None
    assert store.record == store.write_order[-1]  # type: ignore[attr-defined]
