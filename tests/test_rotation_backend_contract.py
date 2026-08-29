from __future__ import annotations

import json
import sys
import threading
from contextlib import AbstractContextManager
from typing import Self

import httpx
import pytest

from forgejo_api_mcp.credential_backend import (
    CredentialCategory,
    CredentialOperationError,
)
from forgejo_api_mcp.rotate import EXIT_CREDENTIAL_STORE_ERROR, EXIT_ROTATED, _run

BASE_URL = "https://forgejo.example"


class Snapshot:
    def __init__(self) -> None:
        self.present = True

    def __repr__(self) -> str:
        return "Snapshot(<redacted>)"


class Lock(AbstractContextManager["Lock"]):
    def __init__(self, trace: list[str]) -> None:
        self.trace = trace

    def __enter__(self) -> Self:
        self.trace.append("lock_enter")
        return self

    def __exit__(self, *_args: object) -> bool:
        self.trace.append("lock_exit")
        return False


class Backend:
    def __init__(self, trace: list[str], *, timeout_write: bool = False) -> None:
        self.trace = trace
        self.timeout_write = timeout_write
        self.current = "prior"
        self.pending_prior_verification = False

    def availability(self) -> CredentialCategory:
        raise AssertionError("rotation must not issue an availability preflight")

    def lock(self, *, timeout: float) -> Lock:
        assert timeout > 0
        return Lock(self.trace)

    def snapshot(self) -> Snapshot:
        self.trace.append("snapshot")
        return Snapshot()

    def replace_existing(self, token: str) -> None:
        self.trace.append("replace")
        if self.timeout_write:
            self.current = token
            self.pending_prior_verification = True
            raise CredentialOperationError(
                CredentialCategory.TIMEOUT,
                credential_state="unknown",
                operation="replace_existing",
                indeterminate=True,
            )
        self.current = token

    def read(self) -> str:
        self.trace.append("read")
        if self.pending_prior_verification:
            self.pending_prior_verification = False
            if self.current != "prior":
                raise CredentialOperationError(
                    CredentialCategory.STORE_ERROR,
                    credential_state="unknown",
                    operation="read",
                )
        return self.current

    def restore(self, snapshot: Snapshot) -> None:
        assert snapshot.present
        self.trace.append("restore")
        self.current = "prior"
        self.pending_prior_verification = True

    def discard(self, snapshot: Snapshot) -> None:
        self.trace.append("discard")
        snapshot.present = False


def _transport(trace: list[str]) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        trace.append("validate")
        return httpx.Response(200, request=request)

    return httpx.MockTransport(handler)


def test_rotation_validates_before_lock_and_discards_before_release() -> None:
    trace: list[str] = []
    backend = Backend(trace)
    code, output = _run(
        "candidate",
        base_url=BASE_URL,
        transport=_transport(trace),
        store=backend,
    )
    assert code == EXIT_ROTATED
    assert output["restartRequired"] is True
    assert trace == [
        "validate",
        "lock_enter",
        "snapshot",
        "replace",
        "read",
        "discard",
        "lock_exit",
    ]


def test_commit_before_hang_restores_once_then_finally_reconciles() -> None:
    trace: list[str] = []
    backend = Backend(trace, timeout_write=True)
    code, output = _run(
        "candidate",
        base_url=BASE_URL,
        transport=_transport(trace),
        store=backend,
    )
    assert code == EXIT_CREDENTIAL_STORE_ERROR
    assert output["category"] == "timeout"
    assert output["credentialState"] == "unknown"
    assert trace.count("restore") == 1
    assert trace == [
        "validate",
        "lock_enter",
        "snapshot",
        "replace",
        "read",
        "restore",
        "read",
        "discard",
        "lock_exit",
    ]


def test_readback_mismatch_rolls_back_and_discards_before_unlock() -> None:
    trace: list[str] = []

    class MismatchBackend(Backend):
        def read(self) -> str:
            self.trace.append("read")
            return "mismatch" if "restore" not in self.trace else "prior"

    code, output = _run(
        "candidate",
        base_url=BASE_URL,
        transport=_transport(trace),
        store=MismatchBackend(trace),
    )
    assert code != EXIT_ROTATED
    assert output["credentialState"] == "restored"
    assert trace == [
        "validate",
        "lock_enter",
        "snapshot",
        "replace",
        "read",
        "restore",
        "read",
        "discard",
        "lock_exit",
    ]


def test_snapshot_failure_releases_lock_without_discarding_nonexistent_handle() -> None:
    trace: list[str] = []

    class SnapshotFailureBackend(Backend):
        def snapshot(self) -> Snapshot:
            self.trace.append("snapshot")
            raise CredentialOperationError(
                CredentialCategory.STORE_ERROR,
                credential_state="unchanged",
                operation="snapshot",
            )

        def discard(self, snapshot: Snapshot) -> None:
            pytest.fail("there is no snapshot handle to discard")

    code, output = _run(
        "candidate",
        base_url=BASE_URL,
        transport=_transport(trace),
        store=SnapshotFailureBackend(trace),
    )
    assert code == EXIT_CREDENTIAL_STORE_ERROR
    assert output["credentialState"] == "unchanged"
    assert trace == ["validate", "lock_enter", "snapshot", "lock_exit"]


def test_replacement_error_discards_snapshot_and_releases_lock() -> None:
    trace: list[str] = []

    class ReplaceFailureBackend(Backend):
        def replace_existing(self, token: str) -> None:
            del token
            self.trace.append("replace")
            raise CredentialOperationError(
                CredentialCategory.STORE_ERROR,
                credential_state="unchanged",
                operation="replace_existing",
            )

    code, _output = _run(
        "candidate",
        base_url=BASE_URL,
        transport=_transport(trace),
        store=ReplaceFailureBackend(trace),
    )
    assert code == EXIT_CREDENTIAL_STORE_ERROR
    assert trace == [
        "validate",
        "lock_enter",
        "snapshot",
        "replace",
        "discard",
        "lock_exit",
    ]


@pytest.mark.skipif(sys.platform != "linux", reason="Linux backend requires POSIX flock")
def test_restore_timeout_finishes_unknown_without_retry_loop(tmp_path) -> None:
    from forgejo_api_mcp.linux_credentials import LinuxCredentialBackend

    trace: list[str] = []
    results = iter(
        [
            b"prior",
            CredentialOperationError(
                CredentialCategory.TIMEOUT,
                credential_state="unknown",
                operation="replace_existing",
                indeterminate=True,
            ),
            b"candidate",
            CredentialOperationError(
                CredentialCategory.TIMEOUT,
                credential_state="unknown",
                operation="restore",
                indeterminate=True,
            ),
            b"candidate",
        ]
    )

    def operation_runner(operation: str, _payload: bytes | None) -> bytes | None:
        trace.append(operation)
        result = next(results)
        if isinstance(result, CredentialOperationError):
            raise result
        return result

    runtime = tmp_path / "restore-timeout-runtime"
    runtime.mkdir(mode=0o700)
    runtime.chmod(0o700)
    backend = LinuxCredentialBackend(operation_runner=operation_runner, runtime_dir=runtime)
    original_discard = backend.discard

    def discard(snapshot) -> None:
        trace.append("discard")
        original_discard(snapshot)

    backend.discard = discard  # type: ignore[method-assign]
    code, output = _run(
        "candidate",
        base_url=BASE_URL,
        transport=_transport(trace),
        store=backend,
    )
    assert code == EXIT_CREDENTIAL_STORE_ERROR
    assert output["category"] == "timeout"
    assert output["credentialState"] == "unknown"
    assert backend.quarantine_present() is True
    assert trace == [
        "validate",
        "snapshot",
        "replace_existing",
        "read",
        "restore",
        "read",
        "discard",
    ]


def test_hang_before_commit_still_restores_and_finishes_unknown() -> None:
    trace: list[str] = []

    class TimeoutBeforeCommitBackend(Backend):
        def replace_existing(self, token: str) -> None:
            del token
            self.trace.append("replace")
            self.pending_prior_verification = True
            raise CredentialOperationError(
                CredentialCategory.TIMEOUT,
                credential_state="unknown",
                operation="replace_existing",
                indeterminate=True,
            )

    code, output = _run(
        "candidate",
        base_url=BASE_URL,
        transport=_transport(trace),
        store=TimeoutBeforeCommitBackend(trace),
    )
    assert code == EXIT_CREDENTIAL_STORE_ERROR
    assert output["category"] == "timeout"
    assert output["credentialState"] == "unknown"
    assert trace.count("restore") == 1
    assert trace.count("read") == 2
    assert trace[-2:] == ["discard", "lock_exit"]


def test_successful_write_with_lock_cleanup_failure_reports_unknown() -> None:
    trace: list[str] = []
    backend = Backend(trace)

    class CleanupFailureLock(Lock):
        def __exit__(self, exc_type, *_args: object) -> bool:
            self.trace.append("lock_exit_cleanup_failed")
            assert exc_type is None
            raise CredentialOperationError(
                CredentialCategory.STORE_ERROR,
                credential_state="unchanged",
                operation="lock",
            )

    code, output = _run(
        "candidate",
        base_url=BASE_URL,
        transport=_transport(trace),
        store=backend,
        lock_factory=lambda **_kwargs: CleanupFailureLock(trace),
    )
    assert code == EXIT_CREDENTIAL_STORE_ERROR
    assert output["credentialState"] == "unknown"
    assert output["restartRequired"] is False
    assert trace[-2:] == ["discard", "lock_exit_cleanup_failed"]


@pytest.mark.parametrize(
    ("commit_before_hang", "expected_state", "expected_restore_mutations"),
    [(False, "unknown", 0), (True, "unknown", 1)],
)
@pytest.mark.skipif(sys.platform != "linux", reason="Linux backend requires POSIX flock")
def test_linux_backend_reconciliation_controls_actual_restore_mutation_count(
    commit_before_hang: bool,
    expected_state: str,
    expected_restore_mutations: int,
    tmp_path,
) -> None:
    from forgejo_api_mcp.linux_credentials import LinuxCredentialBackend

    trace: list[str] = []
    secret = bytearray(b"prior")
    restore_mutations = 0

    def operation_runner(operation: str, payload: bytes | None) -> bytes | None:
        nonlocal restore_mutations
        trace.append(operation)
        if operation == "snapshot":
            return bytes(secret)
        if operation == "replace_existing":
            if commit_before_hang:
                secret[:] = payload or b""
            raise CredentialOperationError(
                CredentialCategory.TIMEOUT,
                credential_state="unknown",
                operation=operation,
                indeterminate=True,
            )
        if operation == "read":
            return bytes(secret)
        if operation == "restore":
            if bytes(secret) != payload:
                restore_mutations += 1
                secret[:] = payload or b""
            return None
        raise AssertionError(operation)

    runtime = tmp_path / f"reconciliation-{commit_before_hang}"
    runtime.mkdir(mode=0o700)
    runtime.chmod(0o700)
    backend = LinuxCredentialBackend(operation_runner=operation_runner, runtime_dir=runtime)
    code, output = _run(
        "candidate",
        base_url=BASE_URL,
        transport=_transport([]),
        store=backend,
    )
    assert code == EXIT_CREDENTIAL_STORE_ERROR
    assert output["credentialState"] == expected_state
    assert restore_mutations == expected_restore_mutations
    assert trace.count("restore") == 1
    assert trace == ["snapshot", "replace_existing", "read", "restore", "read"]
    assert backend.quarantine_present() is True


@pytest.mark.skipif(sys.platform != "linux", reason="Linux backend requires POSIX flock")
def test_real_late_commit_is_quarantined_until_explicit_administrative_clear(
    tmp_path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from forgejo_api_mcp.launcher import launch
    from forgejo_api_mcp.linux_credentials import LinuxCredentialBackend
    from forgejo_api_mcp.quarantine import EXIT_QUARANTINED
    from forgejo_api_mcp.quarantine import main as quarantine_main

    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    runtime.chmod(0o700)
    secret = bytearray(b"prior")
    final_read_done = threading.Event()
    late_commit_done = threading.Event()
    reads = 0
    mutations: list[bytes] = []

    def late_commit(payload: bytes) -> None:
        assert final_read_done.wait(timeout=2)
        secret[:] = payload
        late_commit_done.set()

    def operation_runner(operation: str, payload: bytes | None) -> bytes | None:
        nonlocal reads
        if operation == "snapshot":
            return bytes(secret)
        if operation == "replace_existing":
            candidate = bytes(payload or b"")
            threading.Thread(target=late_commit, args=(candidate,), daemon=True).start()
            raise CredentialOperationError(
                CredentialCategory.TIMEOUT,
                credential_state="unknown",
                operation=operation,
                indeterminate=True,
            )
        if operation == "read":
            reads += 1
            observed = bytes(secret)
            if reads == 2:
                final_read_done.set()
            return observed
        if operation == "restore":
            if bytes(secret) != payload:
                mutations.append(bytes(payload or b""))
                secret[:] = payload or b""
            return None
        raise AssertionError(operation)

    backend = LinuxCredentialBackend(operation_runner=operation_runner, runtime_dir=runtime)
    code, output = _run(
        "candidate",
        base_url=BASE_URL,
        transport=_transport([]),
        store=backend,
    )
    assert code == EXIT_CREDENTIAL_STORE_ERROR
    assert output["credentialState"] == "unknown"
    assert late_commit_done.wait(timeout=2)
    assert bytes(secret) == b"candidate"
    assert mutations == []

    blocked_calls: list[str] = []

    def blocked_runner(operation: str, _payload: bytes | None) -> bytes | None:
        blocked_calls.append(operation)
        return bytes(secret)

    blocked_backend = LinuxCredentialBackend(operation_runner=blocked_runner, runtime_dir=runtime)
    assert launch(
        backend=blocked_backend,
        process_runner=lambda *_args: pytest.fail("quarantined launcher must not start"),
    ) == EXIT_CREDENTIAL_STORE_ERROR
    launcher_error = json.loads(capsys.readouterr().err)
    assert launcher_error == {
        "category": "store_error",
        "credentialState": "unknown",
        "guidanceId": "linux_secret_service_quarantine",
    }
    assert blocked_calls == []

    blocked_code, blocked_output = _run(
        "next-candidate",
        base_url=BASE_URL,
        transport=_transport([]),
        store=blocked_backend,
    )
    assert blocked_code == EXIT_CREDENTIAL_STORE_ERROR
    assert blocked_output["category"] == "store_error"
    assert blocked_output["credentialState"] == "unknown"
    assert blocked_output["guidanceId"] == "linux_secret_service_quarantine"
    assert blocked_calls == []

    assert quarantine_main(["check"], backend=blocked_backend) == EXIT_QUARANTINED
    assert json.loads(capsys.readouterr().out)["status"] == "quarantined"
    assert quarantine_main(
        ["clear", "--operator-verified"],
        backend=blocked_backend,
    ) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "cleared"

    assert launch(
        backend=blocked_backend,
        process_runner=lambda _command, environment: (
            0 if environment["FORGEJO_ACCESS_TOKEN"] == "candidate" else 1
        ),
    ) == 0
    assert blocked_calls == ["read"]


@pytest.mark.parametrize(
    "failure_category",
    [CredentialCategory.TIMEOUT, CredentialCategory.SERVICE_UNAVAILABLE],
)
@pytest.mark.skipif(sys.platform != "linux", reason="Linux backend requires POSIX flock")
def test_standalone_restore_timeout_performs_final_read_and_stays_quarantined(
    failure_category: CredentialCategory,
    tmp_path,
) -> None:
    from forgejo_api_mcp.linux_credentials import LinuxCredentialBackend

    runtime = tmp_path / "standalone-restore-timeout"
    runtime.mkdir(mode=0o700)
    runtime.chmod(0o700)
    trace: list[str] = []
    read_count = 0

    def operation_runner(operation: str, _payload: bytes | None) -> bytes | None:
        nonlocal read_count
        trace.append(operation)
        if operation == "snapshot":
            return b"prior"
        if operation == "replace_existing":
            return None
        if operation == "read":
            read_count += 1
            return b"mismatch"
        if operation == "restore":
            raise CredentialOperationError(
                failure_category,
                credential_state="unknown",
                operation="restore",
                indeterminate=True,
            )
        raise AssertionError(operation)

    backend = LinuxCredentialBackend(operation_runner=operation_runner, runtime_dir=runtime)
    code, output = _run(
        "candidate",
        base_url=BASE_URL,
        transport=_transport([]),
        store=backend,
    )
    assert code == EXIT_CREDENTIAL_STORE_ERROR
    assert output["category"] == failure_category.value
    assert output["credentialState"] == "unknown"
    assert output["guidanceId"] == "linux_secret_service_quarantine"
    assert trace == ["snapshot", "replace_existing", "read", "restore", "read"]
    assert read_count == 2
    assert backend.quarantine_present() is True


@pytest.mark.skipif(sys.platform != "linux", reason="Linux backend requires POSIX flock")
def test_proven_pre_dispatch_mutating_timeout_clears_provisional_fence(tmp_path) -> None:
    from forgejo_api_mcp.linux_credentials import (
        QUARANTINE_CONTENT,
        QUARANTINE_FILENAME,
        LinuxCredentialBackend,
    )

    runtime = tmp_path / "pre-dispatch-timeout"
    runtime.mkdir(mode=0o700)
    runtime.chmod(0o700)

    def operation_runner(operation: str, _payload: bytes | None) -> bytes | None:
        if operation == "snapshot":
            return b"prior"
        if operation == "replace_existing":
            assert (runtime / QUARANTINE_FILENAME).read_bytes() == QUARANTINE_CONTENT
            raise CredentialOperationError(
                CredentialCategory.TIMEOUT,
                credential_state="unchanged",
                operation=operation,
                indeterminate=False,
            )
        raise AssertionError(operation)

    backend = LinuxCredentialBackend(operation_runner=operation_runner, runtime_dir=runtime)
    code, output = _run(
        "candidate",
        base_url=BASE_URL,
        transport=_transport([]),
        store=backend,
    )
    assert code == EXIT_CREDENTIAL_STORE_ERROR
    assert output["credentialState"] == "unchanged"
    assert backend.quarantine_present() is False
