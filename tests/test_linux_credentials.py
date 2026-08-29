from __future__ import annotations

import ast
import inspect
import os
import pickle
import signal
import stat
import threading
import time
import traceback
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

pytest.importorskip("fcntl", reason="Linux credential tests require POSIX flock")

from forgejo_api_mcp.credential_backend import (
    LINUX_GUIDANCE_ID,
    CredentialCategory,
    CredentialOperationError,
)
from forgejo_api_mcp.linux_credentials import (
    CONTENT_TYPE,
    ITEM_ATTRIBUTES,
    ITEM_LABEL,
    LinuxCredentialBackend,
    PosixRotationLock,
    _perform_secretstorage_operation,
)
from forgejo_api_mcp.rotate import EXIT_CREDENTIAL_STORE_ERROR, _run


class ItemNotFoundException(Exception):
    pass


class PromptDismissedException(ItemNotFoundException):
    pass


class LockedException(Exception):
    pass


class SecretServiceNotAvailableException(Exception):
    pass


class SecretStorageException(Exception):
    pass


class FakeItem:
    def __init__(
        self,
        secret: bytes = b"prior",
        *,
        locked: bool = False,
        attributes: dict[str, str] | None = None,
        label: str = ITEM_LABEL,
        content_type: str = CONTENT_TYPE,
    ) -> None:
        self.secret = secret
        self.locked = locked
        self.attributes = dict(ITEM_ATTRIBUTES if attributes is None else attributes)
        self.label = label
        self.content_type = content_type
        self.calls: list[str] = []

    def is_locked(self) -> bool:
        self.calls.append("is_locked")
        return self.locked

    def get_attributes(self) -> dict[str, str]:
        self.calls.append("get_attributes")
        return dict(self.attributes)

    def get_label(self) -> str:
        self.calls.append("get_label")
        return self.label

    def get_secret_content_type(self) -> str:
        self.calls.append("get_secret_content_type")
        return self.content_type

    def get_secret(self) -> bytes:
        self.calls.append("get_secret")
        return self.secret

    def set_secret(self, secret: bytes, content_type: str) -> None:
        self.calls.append("set_secret")
        assert content_type == CONTENT_TYPE
        self.secret = secret


class FakeCollection:
    def __init__(
        self,
        item: FakeItem | None = None,
        *,
        items: list[FakeItem] | None = None,
        locked: bool = False,
    ) -> None:
        self.items = list(items if items is not None else ([] if item is None else [item]))
        self.locked = locked
        self.calls: list[object] = []

    def is_locked(self) -> bool:
        self.calls.append("is_locked")
        return self.locked

    def search_items(self, attributes: dict[str, str]) -> list[FakeItem]:
        self.calls.append(("search_items", attributes))
        return list(self.items)


def _api(collection: FakeCollection, *, alias_error: Exception | None = None) -> object:
    def get_collection_by_alias(_connection: object, alias: str) -> FakeCollection:
        assert alias == "default"
        if alias_error is not None:
            raise alias_error
        return collection

    return SimpleNamespace(
        dbus_init=lambda: object(),
        get_collection_by_alias=get_collection_by_alias,
        exceptions=SimpleNamespace(
            PromptDismissedException=PromptDismissedException,
            ItemNotFoundException=ItemNotFoundException,
            LockedException=LockedException,
            SecretServiceNotAvailableException=SecretServiceNotAvailableException,
            SecretStorageException=SecretStorageException,
        ),
    )


def test_fixed_identity_and_direct_existing_item_operations() -> None:
    assert ITEM_ATTRIBUTES == {
        "application": "forgejo-api-mcp",
        "credential-kind": "access-token",
        "target": "mcp/forgejo-mcp/access-token",
    }
    assert ITEM_LABEL == "Forgejo API MCP access token"
    assert CONTENT_TYPE == "text/plain"

    item = FakeItem()
    collection = FakeCollection(item)
    api = _api(collection)

    assert _perform_secretstorage_operation("read", None, api=api) == b"prior"
    assert _perform_secretstorage_operation("replace_existing", b"candidate", api=api) is None
    assert item.secret == b"candidate"
    assert not any(call in item.calls for call in ("unlock", "delete", "create"))


def test_availability_is_nonmutating_and_uses_only_the_default_alias() -> None:
    item = FakeItem()
    collection = FakeCollection(item)
    assert _perform_secretstorage_operation("availability", None, api=_api(collection)) is None
    assert collection.calls == []
    assert item.calls == []


def test_restore_reuses_the_same_item_and_preserves_exact_metadata() -> None:
    item = FakeItem(secret=b"candidate")
    original_attributes = dict(item.attributes)
    _perform_secretstorage_operation("restore", b"prior", api=_api(FakeCollection(item)))
    assert item.secret == b"prior"
    assert item.attributes == original_attributes == ITEM_ATTRIBUTES
    assert item.label == ITEM_LABEL
    assert item.content_type == CONTENT_TYPE
    assert item.calls.count("set_secret") == 1


def test_prompt_dismissed_is_mapped_before_item_not_found_without_raw_details() -> None:
    canary = "raw-object-path-and-secret"
    api = _api(FakeCollection(FakeItem()), alias_error=PromptDismissedException(canary))
    with pytest.raises(CredentialOperationError) as caught:
        _perform_secretstorage_operation("read", None, api=api)
    assert caught.value.category is CredentialCategory.PROMPT_DISMISSED
    assert canary not in str(caught.value)
    assert canary not in repr(caught.value)


def test_snapshot_is_opaque_nonserializable_redacted_and_discard_zeroizes(tmp_path: Path) -> None:
    immutable_secret = b"prior"
    runtime = tmp_path / "snapshot-runtime"
    runtime.mkdir(mode=0o700)
    runtime.chmod(0o700)
    backend = LinuxCredentialBackend(
        operation_runner=lambda operation, _payload: immutable_secret,
        runtime_dir=runtime,
    )
    snapshot = backend.snapshot()
    mutable_buffer = snapshot._secret
    assert snapshot.present is True
    assert "prior" not in repr(snapshot)
    with pytest.raises((TypeError, pickle.PicklingError)):
        pickle.dumps(snapshot)
    backend.discard(snapshot)
    backend.discard(snapshot)
    assert snapshot.present is False
    assert mutable_buffer == bytearray()
    assert immutable_secret == b"prior"


def test_posix_lock_rejects_symlink_runtime_directory(tmp_path: Path) -> None:
    owned = tmp_path / "owned"
    owned.mkdir(mode=0o700)
    link = tmp_path / "runtime-link"
    link.symlink_to(owned, target_is_directory=True)
    with pytest.raises(CredentialOperationError) as caught, PosixRotationLock(
        timeout=0.01,
        runtime_dir=link,
    ):
        pytest.fail("symlink runtime directory must not be entered")
    assert caught.value.category is CredentialCategory.STORE_ERROR


def test_worker_ipc_redacts_raw_exception_and_forbidden_representations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from forgejo_api_mcp import linux_credentials

    canary = b"/org/freedesktop/secrets/collection/private-item raw-secret"

    def fail(_operation: str, _payload: bytes | None) -> bytes | None:
        raise RuntimeError(canary.decode())

    monkeypatch.setattr(linux_credentials, "_perform_secretstorage_operation", fail)
    response = linux_credentials._handle_worker_message(b"R")
    assert response.startswith(b"E")
    assert len(response) == 2
    assert canary not in response


@pytest.mark.parametrize(
    ("items", "collection_locked", "expected"),
    [
        ([], False, CredentialCategory.MISSING),
        ([FakeItem(), FakeItem()], False, CredentialCategory.STORE_ERROR),
        ([FakeItem()], True, CredentialCategory.LOCKED),
        ([FakeItem(locked=True)], False, CredentialCategory.LOCKED),
    ],
)
def test_exact_item_cardinality_and_lock_states_fail_closed(
    items: list[FakeItem], collection_locked: bool, expected: CredentialCategory
) -> None:
    collection = FakeCollection(items=items, locked=collection_locked)
    with pytest.raises(CredentialOperationError) as caught:
        _perform_secretstorage_operation("read", None, api=_api(collection))
    assert caught.value.category is expected
    assert all("set_secret" not in item.calls for item in items)


@pytest.mark.parametrize(
    "item",
    [
        FakeItem(attributes={**ITEM_ATTRIBUTES, "target": "other"}),
        FakeItem(label="other"),
        FakeItem(content_type="application/octet-stream"),
    ],
)
@pytest.mark.parametrize(
    ("operation", "payload"),
    [("read", None), ("replace_existing", b"candidate"), ("restore", b"prior")],
)
def test_every_operation_rejects_exact_metadata_mismatch(
    item: FakeItem, operation: str, payload: bytes | None
) -> None:
    with pytest.raises(CredentialOperationError) as caught:
        _perform_secretstorage_operation(operation, payload, api=_api(FakeCollection(item)))
    assert caught.value.category is CredentialCategory.STORE_ERROR
    assert "set_secret" not in item.calls


def test_fixed_metadata_has_exact_cardinality_and_no_sensitive_identity() -> None:
    assert len(ITEM_ATTRIBUTES) == 3
    rendered = " ".join([*ITEM_ATTRIBUTES, *ITEM_ATTRIBUTES.values(), ITEM_LABEL, CONTENT_TYPE])
    assert "http://" not in rendered and "https://" not in rendered
    assert "@" not in rendered
    assert "username" not in rendered.casefold()
    assert "secret=" not in rendered.casefold()


def test_noninteractive_adapter_has_no_forbidden_api_or_external_fallback() -> None:
    source_path = Path(__file__).parents[1] / "src" / "forgejo_api_mcp" / "linux_credentials.py"
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    imports = {
        alias.name.split(".", 1)[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        (node.module or "").split(".", 1)[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
    }
    called_attributes = {
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    assert imports.isdisjoint({"dbus", "jeepney", "subprocess"})
    assert called_attributes.isdisjoint(
        {"unlock", "create_collection", "create_item", "delete", "Popen", "run"}
    )
    source = source_path.read_text(encoding="utf-8")
    assert "secret-tool" not in source
    assert "get_default_collection" not in source
    assert "get_any_collection" not in source


def test_exception_hierarchy_maps_every_redacted_category() -> None:
    from forgejo_api_mcp import linux_credentials

    exceptions = _api(FakeCollection(FakeItem())).exceptions
    prompt_required = type("PromptRequiredException", (Exception,), {})
    cases = [
        (PromptDismissedException("raw"), "read", CredentialCategory.PROMPT_DISMISSED),
        (ItemNotFoundException("raw"), "read", CredentialCategory.MISSING),
        (ItemNotFoundException("raw"), "restore", CredentialCategory.STORE_ERROR),
        (LockedException("raw"), "read", CredentialCategory.LOCKED),
        (
            SecretServiceNotAvailableException("raw"),
            "read",
            CredentialCategory.SERVICE_UNAVAILABLE,
        ),
        (SecretStorageException("raw"), "read", CredentialCategory.STORE_ERROR),
        (TimeoutError("raw"), "read", CredentialCategory.TIMEOUT),
        (prompt_required("raw"), "read", CredentialCategory.PROMPT_REQUIRED),
        (ImportError("raw"), "read", CredentialCategory.SERVICE_UNAVAILABLE),
    ]
    for error, operation, expected in cases:
        mapped = linux_credentials._map_secretstorage_exception(error, operation, exceptions)
        assert mapped.category is expected
        assert "raw" not in str(mapped)
        assert "raw" not in repr(mapped)


@pytest.mark.parametrize(
    ("operation", "payload"),
    [
        ("availability", None),
        ("read", None),
        ("snapshot", None),
        ("replace_existing", b"candidate"),
        ("restore", b"prior"),
    ],
)
def test_each_worker_operation_has_deadline_and_no_surviving_worker(
    operation: str,
    payload: bytes | None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from forgejo_api_mcp import linux_credentials

    trace: list[object] = []

    class Request:
        def send_bytes(self, message: bytes) -> None:
            trace.append(("send", message[:1]))

        def close(self) -> None:
            trace.append("request_close")

    class Response:
        def poll(self, timeout: float) -> bool:
            trace.append(("poll", timeout))
            return False

        def close(self) -> None:
            trace.append("response_close")

    worker = SimpleNamespace(pid=12345, request=Request(), response=Response(), reaped=False)
    monkeypatch.setattr(
        linux_credentials,
        "_launch_posix_worker",
        lambda deadline, launched_operation, cleanup_deadline: worker,
    )
    monkeypatch.setattr(
        linux_credentials,
        "_close_spawned_worker",
        lambda _worker, deadline: True,
    )

    with pytest.raises(CredentialOperationError) as caught:
        linux_credentials._run_worker_operation(operation, payload, timeout_seconds=0.51)

    assert caught.value.category is CredentialCategory.TIMEOUT
    assert trace[0][0] == "send"  # type: ignore[index]
    assert "request_close" in trace
    poll_timeout = next(
        entry[1] for entry in trace if isinstance(entry, tuple) and entry[0] == "poll"
    )
    assert 0.0 <= poll_timeout <= 0.01


def test_real_posix_spawn_worker_wait_is_deadline_bounded() -> None:
    from forgejo_api_mcp import linux_credentials

    deadline = time.monotonic() + 0.2
    worker = linux_credentials._launch_posix_worker(deadline, "availability")
    started = time.monotonic()
    try:
        assert not linux_credentials._wait_worker_until(worker, deadline)
    finally:
        assert linux_credentials._close_spawned_worker(worker)
    assert time.monotonic() - started < 1.0


def test_real_posix_spawn_worker_gets_allowlisted_environment_and_pipe_only_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from forgejo_api_mcp import linux_credentials

    foreign_canary = "foreign-parent-environment-secret"
    request_secret = b"pipe-only-request-secret"
    monkeypatch.setenv("FORGEJO_ACCESS_TOKEN", "parent-token-canary")
    monkeypatch.setenv("FOREIGN_SECRET_CANARY", foreign_canary)
    deadline = time.monotonic() + 2.0
    worker = linux_credentials._launch_posix_worker(deadline, "replace_existing")
    try:
        process_environment = Path(f"/proc/{worker.pid}/environ")
        process_argv = Path(f"/proc/{worker.pid}/cmdline")
        environment = b""
        argv = b""
        while time.monotonic() < deadline and not argv:
            environment = process_environment.read_bytes()
            argv = process_argv.read_bytes()
            if not argv:
                time.sleep(0.01)
        environment_keys = {
            entry.split(b"=", 1)[0]
            for entry in environment.split(b"\x00")
            if b"=" in entry
        }
        expected_keys = {key.encode() for key in linux_credentials._WORKER_ENV_ALLOWLIST}
        assert environment_keys <= expected_keys
        assert foreign_canary.encode() not in environment
        assert b"parent-token-canary" not in environment
        assert request_secret not in environment
        assert request_secret not in argv
        assert foreign_canary.encode() not in argv
        argv_parts = [part for part in argv.split(b"\x00") if part]
        assert argv_parts[1:] == [
            b"-I",
            b"-B",
            b"-m",
            b"forgejo_api_mcp.secretstorage_worker",
        ]
        assert os.getpgid(worker.pid) == worker.pid

        worker.request.send_bytes(b"X" + request_secret)
        assert worker.response.poll(max(0.0, deadline - time.monotonic()))
        response = worker.response.recv_bytes(linux_credentials.MAX_RESPONSE_BYTES)
        assert response.startswith(b"E")
        assert request_secret not in response
        assert linux_credentials._wait_worker_until(worker, deadline)
    finally:
        linux_credentials._close_spawned_worker(worker)

    assert os.environ["FORGEJO_ACCESS_TOKEN"] == "parent-token-canary"
    assert os.environ["FOREIGN_SECRET_CANARY"] == foreign_canary


def test_posix_spawn_worker_cannot_observe_inheritable_parent_fd(tmp_path: Path) -> None:
    from forgejo_api_mcp import linux_credentials

    canary_path = tmp_path / "inheritable-parent-fd-canary"
    canary_path.write_text("fd-canary", encoding="utf-8")
    canary_fd = os.open(canary_path, os.O_RDONLY)
    os.set_inheritable(canary_fd, True)
    deadline = time.monotonic() + 2.0
    worker = linux_credentials._launch_posix_worker(deadline, "availability")
    try:
        child_fd_path = Path(f"/proc/{worker.pid}/fd/{canary_fd}")
        if child_fd_path.exists():
            assert child_fd_path.resolve() != canary_path.resolve()
        worker.request.send_bytes(b"Xfd-isolation-probe")
        worker.request.close()
        assert worker.response.poll(max(0.0, deadline - time.monotonic()))
        assert worker.response.recv_bytes(linux_credentials.MAX_RESPONSE_BYTES).startswith(b"E")
        assert linux_credentials._wait_worker_until(worker, deadline)
    finally:
        linux_credentials._close_spawned_worker(worker)
        os.close(canary_fd)


def test_posix_spawn_fails_closed_when_parent_fds_cannot_be_enumerated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from forgejo_api_mcp import linux_credentials

    monkeypatch.delattr(linux_credentials.os, "POSIX_SPAWN_CLOSEFROM", raising=False)
    monkeypatch.setattr(
        linux_credentials.os,
        "listdir",
        lambda _path: (_ for _ in ()).throw(OSError("fd-enumeration-canary")),
    )
    with pytest.raises(CredentialOperationError) as caught:
        linux_credentials._launch_posix_worker(
            time.monotonic() + 1.0,
            "availability",
        )
    assert caught.value.category is CredentialCategory.SERVICE_UNAVAILABLE


def test_posix_spawn_uses_closefrom_action_when_runtime_exposes_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from forgejo_api_mcp import linux_credentials

    closefrom = 987654
    captured: dict[str, object] = {}
    monkeypatch.setattr(linux_credentials.os, "POSIX_SPAWN_CLOSEFROM", closefrom, raising=False)
    monkeypatch.setattr(
        linux_credentials,
        "_inheritable_parent_descriptors",
        lambda _excluded: pytest.fail("closefrom must avoid fallback enumeration"),
    )

    def capture_spawn(
        _executable: str,
        _argv: list[str],
        _environment: dict[str, str],
        *,
        file_actions: list[tuple[object, ...]],
        setpgroup: int,
    ) -> int:
        captured["file_actions"] = file_actions
        captured["setpgroup"] = setpgroup
        raise OSError("capture only")

    monkeypatch.setattr(linux_credentials.os, "posix_spawn", capture_spawn)
    with pytest.raises(CredentialOperationError):
        linux_credentials._launch_posix_worker(time.monotonic() + 1.0, "availability")
    assert (closefrom, 5) in captured["file_actions"]  # type: ignore[operator]
    assert captured["setpgroup"] == 0


def test_posix_spawn_fallback_enumerates_and_closes_parent_descriptors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from forgejo_api_mcp import linux_credentials

    captured: dict[str, object] = {}
    monkeypatch.delattr(linux_credentials.os, "POSIX_SPAWN_CLOSEFROM", raising=False)
    monkeypatch.setattr(
        linux_credentials,
        "_inheritable_parent_descriptors",
        lambda _excluded: {73, 74},
    )

    def capture_spawn(
        _executable: str,
        _argv: list[str],
        _environment: dict[str, str],
        *,
        file_actions: list[tuple[object, ...]],
        setpgroup: int,
    ) -> int:
        captured["file_actions"] = file_actions
        captured["setpgroup"] = setpgroup
        raise OSError("capture only")

    monkeypatch.setattr(linux_credentials.os, "posix_spawn", capture_spawn)
    with pytest.raises(CredentialOperationError):
        linux_credentials._launch_posix_worker(time.monotonic() + 1.0, "availability")
    file_actions = captured["file_actions"]
    assert (linux_credentials.os.POSIX_SPAWN_CLOSE, 73) in file_actions  # type: ignore[operator]
    assert (linux_credentials.os.POSIX_SPAWN_CLOSE, 74) in file_actions  # type: ignore[operator]
    assert captured["setpgroup"] == 0


def test_worker_launch_has_no_fork_or_request_bootstrap_state() -> None:
    from forgejo_api_mcp import linux_credentials

    source = inspect.getsource(linux_credentials._launch_posix_worker)
    assert "posix_spawn" in source
    assert "fork" not in source
    assert "request" not in inspect.signature(linux_credentials._launch_posix_worker).parameters


def test_deadline_reserves_term_and_kill_windows_inside_total_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from forgejo_api_mcp import linux_credentials

    trace: list[object] = []

    class Request:
        def send_bytes(self, _message: bytes) -> None:
            trace.append("send")

        def close(self) -> None:
            trace.append("request_close")

    class Response:
        def poll(self, timeout: float) -> bool:
            trace.append(("poll", timeout))
            return False

        def close(self) -> None:
            trace.append("response_close")

    worker = SimpleNamespace(pid=12345, request=Request(), response=Response(), reaped=False)
    monkeypatch.setattr(linux_credentials.time, "monotonic", lambda: 100.0)

    def launch(service_deadline: float, _operation: str, cleanup_deadline: float):
        trace.append(("deadlines", service_deadline, cleanup_deadline))
        return worker

    monkeypatch.setattr(linux_credentials, "_launch_posix_worker", launch)
    monkeypatch.setattr(
        linux_credentials,
        "_close_spawned_worker",
        lambda _worker, deadline: trace.append(("cleanup", deadline)) or True,
    )
    with pytest.raises(CredentialOperationError) as caught:
        linux_credentials._run_worker_operation("availability", None, timeout_seconds=5.0)

    assert caught.value.category is CredentialCategory.TIMEOUT
    assert ("deadlines", 104.5, 105.0) in trace
    assert ("poll", 4.5) in trace
    assert ("cleanup", 105.0) in trace


def test_graceful_worker_response_reaps_without_signals(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from forgejo_api_mcp import linux_credentials

    trace: list[object] = []

    class Request:
        def send_bytes(self, message: bytes) -> None:
            trace.append(("send", message[:1]))

        def close(self) -> None:
            trace.append("request_close")

    class Response:
        def poll(self, timeout: float) -> bool:
            trace.append(("poll", timeout))
            return True

        def recv_bytes(self, _maximum: int) -> bytes:
            trace.append("recv")
            return b"O"

        def close(self) -> None:
            trace.append("response_close")

    worker = SimpleNamespace(pid=12345, request=Request(), response=Response(), reaped=False)
    monkeypatch.setattr(linux_credentials.time, "monotonic", lambda: 100.0)
    monkeypatch.setattr(linux_credentials, "_launch_posix_worker", lambda *_args: worker)

    def wait(reaped_worker, deadline: float) -> bool:
        trace.append(("wait", deadline))
        reaped_worker.reaped = True
        return True

    monkeypatch.setattr(linux_credentials, "_wait_worker_until", wait)
    monkeypatch.setattr(
        linux_credentials,
        "_signal_worker_group",
        lambda *_args: pytest.fail("graceful worker must not be signalled"),
    )
    assert linux_credentials._run_worker_operation("availability", None, timeout_seconds=5.0) is None
    assert worker.reaped is True
    assert ("wait", 104.5) in trace
    assert "request_close" in trace and "response_close" in trace


def test_cleanup_uses_term_path_for_exact_250ms_and_reaps(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from forgejo_api_mcp import linux_credentials

    trace: list[object] = []
    worker = SimpleNamespace(
        pid=12345,
        request=SimpleNamespace(close=lambda: trace.append("request_close")),
        response=SimpleNamespace(close=lambda: trace.append("response_close")),
        reaped=False,
    )
    clock = iter((100.0, 100.0))
    monkeypatch.setattr(linux_credentials.time, "monotonic", lambda: next(clock))
    waits = iter((False, True))

    def wait(reaped_worker, deadline: float) -> bool:
        trace.append(("wait", deadline))
        result = next(waits)
        reaped_worker.reaped = result
        return result

    monkeypatch.setattr(linux_credentials, "_wait_worker_until", wait)
    monkeypatch.setattr(
        linux_credentials,
        "_signal_worker_group",
        lambda _worker, sig: trace.append(("signal", sig)) or True,
    )
    assert linux_credentials._close_spawned_worker(worker, deadline=105.0)
    assert ("signal", signal.SIGTERM) in trace
    assert not any(entry == ("signal", signal.SIGKILL) for entry in trace)
    assert ("wait", 100.25) in trace
    assert worker.reaped is True


def test_cleanup_term_to_kill_fallback_has_two_250ms_bounds_and_reaps(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from forgejo_api_mcp import linux_credentials

    trace: list[object] = []
    worker = SimpleNamespace(
        pid=12345,
        request=SimpleNamespace(close=lambda: trace.append("request_close")),
        response=SimpleNamespace(close=lambda: trace.append("response_close")),
        reaped=False,
    )
    clock = iter((100.0, 100.0, 100.25))
    monkeypatch.setattr(linux_credentials.time, "monotonic", lambda: next(clock))
    waits = iter((False, False, True))

    def wait(reaped_worker, deadline: float) -> bool:
        trace.append(("wait", deadline))
        result = next(waits)
        reaped_worker.reaped = result
        return result

    monkeypatch.setattr(linux_credentials, "_wait_worker_until", wait)
    monkeypatch.setattr(
        linux_credentials,
        "_signal_worker_group",
        lambda _worker, sig: trace.append(("signal", sig)) or True,
    )
    assert linux_credentials._close_spawned_worker(worker, deadline=105.0)
    assert [entry for entry in trace if isinstance(entry, tuple) and entry[0] == "signal"] == [
        ("signal", signal.SIGTERM),
        ("signal", signal.SIGKILL),
    ]
    wait_deadlines = [
        entry[1] for entry in trace if isinstance(entry, tuple) and entry[0] == "wait"
    ]
    assert wait_deadlines == [100.0, 100.25, 100.5]
    assert wait_deadlines[-1] <= 105.0
    assert worker.reaped is True


def test_real_graceful_worker_is_reaped_without_zombie() -> None:
    from forgejo_api_mcp import linux_credentials

    deadline = time.monotonic() + 2.0
    worker = linux_credentials._launch_posix_worker(deadline, "availability")
    pid = worker.pid
    try:
        worker.request.send_bytes(b"Xgraceful-reap-probe")
        worker.request.close()
        assert worker.response.poll(max(0.0, deadline - time.monotonic()))
        assert worker.response.recv_bytes(linux_credentials.MAX_RESPONSE_BYTES).startswith(b"E")
        assert linux_credentials._wait_worker_until(worker, deadline)
        assert worker.reaped is True
        with pytest.raises(ChildProcessError):
            os.waitpid(pid, os.WNOHANG)
    finally:
        assert linux_credentials._close_spawned_worker(worker)


@pytest.mark.parametrize(
    ("operation", "payload", "stage"),
    [
        ("availability", None, "dbus_init"),
        ("availability", None, "get_collection_by_alias"),
        ("read", None, "collection.is_locked"),
        ("read", None, "collection.search_items"),
        ("read", None, "item.is_locked"),
        ("read", None, "item.get_attributes"),
        ("read", None, "item.get_label"),
        ("read", None, "item.get_secret_content_type"),
        ("read", None, "item.get_secret"),
        ("replace_existing", b"candidate", "item.set_secret"),
    ],
)
def test_each_secretstorage_service_stage_can_block_deterministically(
    operation: str, payload: bytes | None, stage: str
) -> None:
    entered = threading.Event()
    release = threading.Event()
    result: list[object] = []

    def block(name: str) -> None:
        if name == stage:
            entered.set()
            assert release.wait(timeout=1.0)

    class BlockingItem:
        def is_locked(self) -> bool:
            block("item.is_locked")
            return False

        def get_attributes(self) -> dict[str, str]:
            block("item.get_attributes")
            return dict(ITEM_ATTRIBUTES)

        def get_label(self) -> str:
            block("item.get_label")
            return ITEM_LABEL

        def get_secret_content_type(self) -> str:
            block("item.get_secret_content_type")
            return CONTENT_TYPE

        def get_secret(self) -> bytes:
            block("item.get_secret")
            return b"prior"

        def set_secret(self, _secret: bytes, _content_type: str) -> None:
            block("item.set_secret")

    class BlockingCollection:
        def is_locked(self) -> bool:
            block("collection.is_locked")
            return False

        def search_items(self, _attributes: dict[str, str]) -> list[BlockingItem]:
            block("collection.search_items")
            return [BlockingItem()]

    def dbus_init() -> object:
        block("dbus_init")
        return object()

    def get_collection_by_alias(_connection: object, _alias: str) -> BlockingCollection:
        block("get_collection_by_alias")
        return BlockingCollection()

    api = SimpleNamespace(
        dbus_init=dbus_init,
        get_collection_by_alias=get_collection_by_alias,
        exceptions=_api(FakeCollection(FakeItem())).exceptions,
    )

    def invoke() -> None:
        result.append(_perform_secretstorage_operation(operation, payload, api=api))

    thread = threading.Thread(target=invoke)
    thread.start()
    assert entered.wait(timeout=1.0)
    assert thread.is_alive()
    release.set()
    thread.join(timeout=1.0)
    assert not thread.is_alive()
    assert result == ([b"prior"] if operation == "read" else [None])


def test_worker_boundary_hides_paths_attributes_objects_and_raw_payloads(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], caplog: pytest.LogCaptureFixture
) -> None:
    from forgejo_api_mcp import linux_credentials

    forbidden = [
        "/org/freedesktop/secrets/collection/private",
        "/org/freedesktop/secrets/item/private",
        repr({"target": "private-target", "application": "private-app"}),
        "RawSecretStorageException(private)",
        "DBusPayload(sender=:1.44)",
        "Item(path=/private)",
        "Collection(path=/private)",
        "LinuxCredentialSnapshot(private)",
    ]
    for canary in forbidden:
        def fail(_operation: str, _payload: bytes | None, value: str = canary) -> bytes | None:
            raise RuntimeError(value)

        monkeypatch.setattr(linux_credentials, "_perform_secretstorage_operation", fail)
        response = linux_credentials._handle_worker_message(b"R")
        captured = capsys.readouterr()
        observed = response.decode("ascii") + captured.out + captured.err
        observed += " ".join(record.getMessage() for record in caplog.records)
        if canary in observed:
            pytest.fail("forbidden Linux representation crossed the worker boundary")
        assert response == b"E" + linux_credentials._CATEGORY_CODES[CredentialCategory.STORE_ERROR]


def test_real_worker_parent_backend_rotation_boundary_remains_redacted(
    capsys: pytest.CaptureFixture[str], caplog: pytest.LogCaptureFixture, tmp_path: Path
) -> None:
    from forgejo_api_mcp import linux_credentials

    canaries = (
        "/org/freedesktop/secrets/collection/private-canary",
        "/org/freedesktop/secrets/item/private-canary",
        "{'application': 'private-app', 'target': 'private-target'}",
        "RawSecretStorageException(private-canary)",
        "DBusPayload(sender=:1.404)",
        "Item(path=/private-item)",
        "Collection(path=/private-collection)",
        "LinuxCredentialSnapshot(private-canary)",
    )
    invalid_request = b"X" + " | ".join(canaries).encode()

    def operation_runner(_operation: str, _payload: bytes | None) -> bytes | None:
        deadline = time.monotonic() + 1.0
        worker = linux_credentials._launch_posix_worker(deadline, "snapshot")
        try:
            worker.request.send_bytes(invalid_request)
            worker.request.close()
            assert worker.response.poll(max(0.0, deadline - time.monotonic()))
            response = worker.response.recv_bytes(linux_credentials.MAX_RESPONSE_BYTES)
            assert response == b"E" + linux_credentials._CATEGORY_CODES[
                CredentialCategory.STORE_ERROR
            ]
            if any(canary.encode() in response for canary in canaries):
                pytest.fail("worker response leaked a private representation")
            assert linux_credentials._wait_worker_until(worker, deadline)
        finally:
            assert linux_credentials._close_spawned_worker(worker)
        raise CredentialOperationError(
            CredentialCategory.STORE_ERROR,
            credential_state="unchanged",
            operation="snapshot",
            guidance_id=LINUX_GUIDANCE_ID,
        )

    runtime = tmp_path / "boundary-runtime"
    runtime.mkdir(mode=0o700)
    runtime.chmod(0o700)
    backend = LinuxCredentialBackend(operation_runner=operation_runner, runtime_dir=runtime)
    with pytest.raises(CredentialOperationError) as caught:
        backend.snapshot()
    diagnostic = "".join(traceback.format_exception(caught.value))

    code, output = _run(
        "candidate",
        base_url="https://forgejo.example",
        transport=httpx.MockTransport(lambda request: httpx.Response(200, request=request)),
        store=backend,
    )
    captured = capsys.readouterr()
    public = "\n".join(
        (
            captured.out,
            captured.err,
            " ".join(record.getMessage() for record in caplog.records),
            str(caught.value),
            repr(caught.value),
            diagnostic,
            repr(output),
        )
    )
    if any(canary in public for canary in canaries):
        pytest.fail("a private representation crossed the public boundary")
    assert code == EXIT_CREDENTIAL_STORE_ERROR
    assert output["category"] == "store_error"
    assert output["credentialState"] == "unchanged"
    assert output["guidanceId"] == "linux_secret_service_setup"
    assert captured.out == ""
    assert captured.err == ""


def test_posix_lock_modes_serialization_and_cooperative_release(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    runtime.chmod(0o700)

    first = PosixRotationLock(timeout=0.1, runtime_dir=runtime)
    with first:
        assert (runtime.stat().st_mode & 0o777) == 0o700
        assert (first.path.stat().st_mode & 0o777) == 0o600
        with (
            pytest.raises(CredentialOperationError) as caught,
            PosixRotationLock(timeout=0.01, runtime_dir=runtime),
        ):
            pytest.fail("a second lock must not enter")
        assert caught.value.category is CredentialCategory.TIMEOUT

    with pytest.raises(RuntimeError), PosixRotationLock(timeout=0.1, runtime_dir=runtime):
        raise RuntimeError("cooperative failure")
    with PosixRotationLock(timeout=0.1, runtime_dir=runtime):
        pass


@pytest.mark.parametrize("failing_stage", ["unlock", "close"])
def test_posix_lock_cleanup_maps_oserror_and_always_resets_descriptor(
    failing_stage: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from forgejo_api_mcp import linux_credentials

    canary = "raw-posix-cleanup-canary"
    closed: list[int] = []
    lock = object.__new__(PosixRotationLock)
    lock._fd = 42
    lock._dir_fd = None

    def flock(_fd: int, _operation: int) -> None:
        if failing_stage == "unlock":
            raise OSError(canary)

    def close(fd: int) -> None:
        closed.append(fd)
        if failing_stage == "close":
            raise OSError(canary)

    monkeypatch.setattr(linux_credentials.fcntl, "flock", flock)
    monkeypatch.setattr(linux_credentials, "_close_descriptor", close)
    with pytest.raises(CredentialOperationError) as caught:
        lock.__exit__(None, None, None)
    assert caught.value.category is CredentialCategory.STORE_ERROR
    assert canary not in str(caught.value)
    assert canary not in repr(caught.value)
    assert lock._fd is None
    assert closed == [42]


def test_posix_lock_cleanup_does_not_replace_active_exception(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from forgejo_api_mcp import linux_credentials

    lock = object.__new__(PosixRotationLock)
    lock._fd = 43
    lock._dir_fd = 44
    closed: list[int] = []
    monkeypatch.setattr(
        linux_credentials.fcntl,
        "flock",
        lambda *_args: (_ for _ in ()).throw(OSError("raw-active-cleanup-canary")),
    )
    monkeypatch.setattr(linux_credentials, "_close_descriptor", closed.append)
    assert lock.__exit__(RuntimeError, RuntimeError("active"), None) is False
    assert lock._fd is None
    assert lock._dir_fd is None
    assert closed == [43, 44]


def test_posix_lock_runtime_directory_replacement_cannot_split_acquisition(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from forgejo_api_mcp import linux_credentials

    runtime = tmp_path / "runtime-race"
    displaced = tmp_path / "runtime-race-displaced"
    runtime.mkdir(mode=0o700)
    runtime.chmod(0o700)
    replaced = threading.Event()
    continue_first = threading.Event()
    first_entered = threading.Event()
    first_failed = threading.Event()
    real_open = linux_credentials.os.open
    replacement_done = False

    def racing_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal replacement_done
        if path == linux_credentials.LOCK_FILENAME and dir_fd is not None and not replacement_done:
            replacement_done = True
            runtime.rename(displaced)
            runtime.mkdir(mode=0o700)
            runtime.chmod(0o700)
            replaced.set()
            assert continue_first.wait(timeout=2)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(linux_credentials.os, "open", racing_open)

    def acquire_first() -> None:
        try:
            with PosixRotationLock(timeout=1.0, runtime_dir=runtime):
                first_entered.set()
        except CredentialOperationError:
            first_failed.set()

    thread = threading.Thread(target=acquire_first)
    thread.start()
    assert replaced.wait(timeout=2)
    with PosixRotationLock(timeout=1.0, runtime_dir=runtime):
        continue_first.set()
        thread.join(timeout=2)
        assert not thread.is_alive()
        assert not first_entered.is_set()
        assert first_failed.is_set()


@pytest.mark.parametrize(
    "unsafe",
    [
        "directory_mode",
        "foreign_owner",
        "lock_owner",
        "lock_mode",
        "lock_symlink",
        "lock_type",
    ]
)
def test_posix_lock_rejects_unsafe_owner_modes_symlinks_and_types(
    unsafe: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from forgejo_api_mcp import linux_credentials

    runtime = tmp_path / unsafe
    runtime.mkdir(mode=0o700)
    runtime.chmod(0o700)
    lock_path = runtime / linux_credentials.LOCK_FILENAME
    if unsafe == "directory_mode":
        runtime.chmod(0o755)
    elif unsafe == "foreign_owner":
        actual_uid = os.geteuid()
        monkeypatch.setattr(linux_credentials.os, "geteuid", lambda: actual_uid + 1)
    elif unsafe == "lock_owner":
        real_fstat = os.fstat

        def foreign_fstat(fd: int) -> os.stat_result:
            values = list(real_fstat(fd))
            values[4] = values[4] + 1
            return os.stat_result(values)

        monkeypatch.setattr(linux_credentials.os, "fstat", foreign_fstat)
    elif unsafe == "lock_mode":
        lock_path.write_text("", encoding="utf-8")
        lock_path.chmod(0o644)
    elif unsafe == "lock_symlink":
        target = tmp_path / "target"
        target.write_text("", encoding="utf-8")
        lock_path.symlink_to(target)
    else:
        lock_path.mkdir()

    with (
        pytest.raises(CredentialOperationError) as caught,
        PosixRotationLock(timeout=0.01, runtime_dir=runtime),
    ):
        pytest.fail("unsafe lock path must not enter")
    assert caught.value.category is CredentialCategory.STORE_ERROR


def test_sigkill_releases_only_the_kernel_lock(tmp_path: Path) -> None:
    import select

    runtime = tmp_path / "hard-abort"
    runtime.mkdir(mode=0o700)
    runtime.chmod(0o700)
    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(read_fd)
        try:
            with PosixRotationLock(timeout=1.0, runtime_dir=runtime):
                os.write(write_fd, b"1")
                signal.pause()
        finally:
            os._exit(0)

    os.close(write_fd)
    try:
        ready, _, _ = select.select([read_fd], [], [], 3.0)
        assert ready and os.read(read_fd, 1) == b"1"
        os.kill(pid, signal.SIGKILL)
        _, status = os.waitpid(pid, 0)
        assert os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGKILL
        with PosixRotationLock(timeout=1.0, runtime_dir=runtime):
            pass
    finally:
        os.close(read_fd)
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


def test_quarantine_marker_is_fixed_private_atomic_and_durable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from forgejo_api_mcp import linux_credentials

    runtime = tmp_path / "runtime-quarantine"
    runtime.mkdir(mode=0o700)
    runtime.chmod(0o700)
    fsync_calls: list[int] = []
    replace_calls: list[tuple[object, ...]] = []
    real_fsync = linux_credentials.os.fsync
    real_replace = linux_credentials.os.replace

    def tracked_fsync(fd: int) -> None:
        fsync_calls.append(fd)
        real_fsync(fd)

    def tracked_replace(*args: object, **kwargs: object) -> None:
        replace_calls.append((*args, kwargs))
        real_replace(*args, **kwargs)

    monkeypatch.setattr(linux_credentials.os, "fsync", tracked_fsync)
    monkeypatch.setattr(linux_credentials.os, "replace", tracked_replace)
    with PosixRotationLock(timeout=1.0, runtime_dir=runtime) as lock:
        assert lock.quarantine_present() is False
        lock.create_quarantine()
        assert lock.quarantine_present() is True

    marker = runtime / linux_credentials.QUARANTINE_FILENAME
    assert marker.read_bytes() == linux_credentials.QUARANTINE_CONTENT
    assert stat.S_IMODE(marker.stat().st_mode) == 0o600
    assert len(replace_calls) == 1
    assert len(fsync_calls) >= 2
    assert b"token" not in marker.read_bytes().lower()
    assert b"/org/freedesktop" not in marker.read_bytes()


def test_quarantine_marker_rejects_symlink_and_never_follows_it(tmp_path: Path) -> None:
    from forgejo_api_mcp import linux_credentials

    runtime = tmp_path / "runtime-quarantine-symlink"
    runtime.mkdir(mode=0o700)
    runtime.chmod(0o700)
    target = tmp_path / "foreign-marker-target"
    target.write_bytes(linux_credentials.QUARANTINE_CONTENT)
    (runtime / linux_credentials.QUARANTINE_FILENAME).symlink_to(target)
    with (
        PosixRotationLock(timeout=1.0, runtime_dir=runtime) as lock,
        pytest.raises(CredentialOperationError) as caught,
    ):
        lock.quarantine_present()
    assert caught.value.category is CredentialCategory.STORE_ERROR
    assert target.read_bytes() == linux_credentials.QUARANTINE_CONTENT


@pytest.mark.parametrize("unsafe", ["mode", "type", "owner"])
def test_quarantine_marker_rejects_unsafe_mode_type_and_owner(
    unsafe: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from forgejo_api_mcp import linux_credentials

    runtime = tmp_path / f"runtime-quarantine-{unsafe}"
    runtime.mkdir(mode=0o700)
    runtime.chmod(0o700)
    marker = runtime / linux_credentials.QUARANTINE_FILENAME
    if unsafe == "type":
        marker.mkdir(mode=0o700)
    else:
        marker.write_bytes(linux_credentials.QUARANTINE_CONTENT)
        marker.chmod(0o644 if unsafe == "mode" else 0o600)
    if unsafe == "owner":
        real_stat = linux_credentials.os.stat

        def foreign_marker_stat(path, *args, **kwargs):
            info = real_stat(path, *args, **kwargs)
            if path == linux_credentials.QUARANTINE_FILENAME:
                values = list(info)
                values[4] += 1
                return os.stat_result(values)
            return info

        monkeypatch.setattr(linux_credentials.os, "stat", foreign_marker_stat)

    with (
        PosixRotationLock(timeout=1.0, runtime_dir=runtime) as lock,
        pytest.raises(CredentialOperationError) as caught,
    ):
        lock.quarantine_present()
    assert caught.value.category is CredentialCategory.STORE_ERROR
    assert caught.value.credential_state == "unknown"


def test_quarantine_marker_rejects_device_inode_identity_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from forgejo_api_mcp import linux_credentials

    runtime = tmp_path / "runtime-quarantine-identity"
    runtime.mkdir(mode=0o700)
    runtime.chmod(0o700)
    marker = runtime / linux_credentials.QUARANTINE_FILENAME
    marker.write_bytes(linux_credentials.QUARANTINE_CONTENT)
    marker.chmod(0o600)
    real_stat = linux_credentials.os.stat
    marker_stats = 0

    def replaced_marker_stat(path, *args, **kwargs):
        nonlocal marker_stats
        info = real_stat(path, *args, **kwargs)
        if path == linux_credentials.QUARANTINE_FILENAME:
            marker_stats += 1
            if marker_stats > 1:
                values = list(info)
                values[1] += 1
                values[2] += 1
                return os.stat_result(values)
        return info

    monkeypatch.setattr(linux_credentials.os, "stat", replaced_marker_stat)
    with (
        PosixRotationLock(timeout=1.0, runtime_dir=runtime) as lock,
        pytest.raises(CredentialOperationError) as caught,
    ):
        lock.quarantine_present()
    assert caught.value.category is CredentialCategory.STORE_ERROR


def test_mutating_timeout_before_worker_dispatch_is_not_indeterminate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from forgejo_api_mcp import linux_credentials

    monkeypatch.setattr(
        linux_credentials,
        "_launch_posix_worker",
        lambda *_args: (_ for _ in ()).throw(
            CredentialOperationError(
                CredentialCategory.TIMEOUT,
                credential_state="unknown",
                operation="replace_existing",
                indeterminate=True,
            )
        ),
    )
    with pytest.raises(CredentialOperationError) as caught:
        linux_credentials._run_worker_operation("replace_existing", b"candidate")
    assert caught.value.category is CredentialCategory.TIMEOUT
    assert caught.value.indeterminate is False
    assert caught.value.credential_state == "unchanged"


@pytest.mark.parametrize(
    ("worker_outcome", "expected_category"),
    [
        ("commit_then_eof", CredentialCategory.SERVICE_UNAVAILABLE),
        ("worker_crash", CredentialCategory.SERVICE_UNAVAILABLE),
        ("malformed_response", CredentialCategory.STORE_ERROR),
        ("error_response", CredentialCategory.STORE_ERROR),
    ],
)
def test_dispatched_mutation_without_validated_success_is_indeterminate(
    worker_outcome: str,
    expected_category: CredentialCategory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from forgejo_api_mcp import linux_credentials

    item = FakeItem()
    api = _api(FakeCollection(item))

    class Request:
        def send_bytes(self, message: bytes) -> None:
            operation, payload = linux_credentials._decode_request(message)
            linux_credentials._perform_secretstorage_operation(operation, payload, api=api)

        def close(self) -> None:
            pass

    class Response:
        def poll(self, _timeout: float) -> bool:
            return True

        def recv_bytes(self, _maximum: int) -> bytes:
            if worker_outcome == "commit_then_eof":
                raise EOFError("private EOF detail")
            if worker_outcome == "worker_crash":
                raise ChildProcessError("private worker crash detail")
            if worker_outcome == "malformed_response":
                return b"Xprivate malformed response"
            return b"E" + linux_credentials._CATEGORY_CODES[CredentialCategory.STORE_ERROR]

        def close(self) -> None:
            pass

    worker = SimpleNamespace(pid=12345, request=Request(), response=Response(), reaped=False)
    monkeypatch.setattr(linux_credentials, "_launch_posix_worker", lambda *_args: worker)
    monkeypatch.setattr(linux_credentials, "_wait_worker_until", lambda *_args: True)
    monkeypatch.setattr(linux_credentials, "_close_spawned_worker", lambda *_args: True)

    with pytest.raises(CredentialOperationError) as caught:
        linux_credentials._run_worker_operation("replace_existing", b"candidate-secret")

    assert item.secret == b"candidate-secret"
    assert "set_secret" in item.calls
    assert caught.value.category is expected_category
    assert caught.value.credential_state == "unknown"
    assert caught.value.indeterminate is True
    public = f"{caught.value!s}\n{caught.value!r}"
    assert "candidate-secret" not in public
    assert "private" not in public


def test_non_timeout_indeterminate_commit_reconciles_and_retains_quarantine(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from forgejo_api_mcp.launcher import launch

    runtime = tmp_path / "commit-eof-runtime"
    runtime.mkdir(mode=0o700)
    runtime.chmod(0o700)
    secret = bytearray(b"prior")
    trace: list[str] = []

    def operation_runner(operation: str, payload: bytes | None) -> bytes | None:
        trace.append(operation)
        if operation == "snapshot":
            return bytes(secret)
        if operation == "replace_existing":
            secret[:] = payload or b""
            raise CredentialOperationError(
                CredentialCategory.SERVICE_UNAVAILABLE,
                credential_state="unknown",
                operation=operation,
                indeterminate=True,
            )
        if operation == "read":
            return bytes(secret)
        if operation == "restore":
            secret[:] = payload or b""
            return None
        raise AssertionError(operation)

    backend = LinuxCredentialBackend(operation_runner=operation_runner, runtime_dir=runtime)
    code, output = _run(
        "candidate-secret",
        base_url="https://forgejo.example",
        transport=httpx.MockTransport(lambda request: httpx.Response(200, request=request)),
        store=backend,
    )

    assert code == EXIT_CREDENTIAL_STORE_ERROR
    assert output["category"] == "service_unavailable"
    assert output["credentialState"] == "unknown"
    assert output["guidanceId"] == "linux_secret_service_quarantine"
    assert trace == ["snapshot", "replace_existing", "read", "restore", "read"]
    assert bytes(secret) == b"prior"
    assert backend.quarantine_present() is True

    blocked_trace: list[str] = []

    def blocked_runner(operation: str, _payload: bytes | None) -> bytes | None:
        blocked_trace.append(operation)
        return bytes(secret)

    blocked = LinuxCredentialBackend(operation_runner=blocked_runner, runtime_dir=runtime)
    assert launch(
        backend=blocked,
        process_runner=lambda *_args: pytest.fail("quarantined launcher must not run"),
    ) == EXIT_CREDENTIAL_STORE_ERROR
    launcher_error = capsys.readouterr().err
    blocked_code, blocked_output = _run(
        "future-secret",
        base_url="https://forgejo.example",
        transport=httpx.MockTransport(lambda request: httpx.Response(200, request=request)),
        store=blocked,
    )
    assert blocked_code == EXIT_CREDENTIAL_STORE_ERROR
    assert blocked_output["credentialState"] == "unknown"
    assert blocked_output["guidanceId"] == "linux_secret_service_quarantine"
    assert blocked_trace == []
    public = launcher_error + repr(output) + repr(blocked_output)
    assert "candidate-secret" not in public
    assert "future-secret" not in public
