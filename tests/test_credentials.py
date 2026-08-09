from __future__ import annotations

import ctypes
import inspect
import logging
import sys
from typing import Any

import pytest

from forgejo_api_mcp import credentials
from forgejo_api_mcp.credentials import (
    CRED_PERSIST_LOCAL_MACHINE,
    TARGET_NAME,
    CredentialRecord,
    CredentialStoreError,
    CredentialStoreUnavailable,
    delete_credential,
    read_credential,
    write_credential,
)


def test_public_api_is_target_free_and_override_free() -> None:
    assert list(inspect.signature(write_credential).parameters) == ["token"]
    assert list(inspect.signature(read_credential).parameters) == []
    assert list(inspect.signature(delete_credential).parameters) == []


def test_credential_record_redacts_secret_in_all_displays(
    caplog: pytest.LogCaptureFixture,
) -> None:
    secret = "known-sensitive-credential-value"
    record = CredentialRecord(TARGET_NAME, "forgejo-api-mcp", secret, CRED_PERSIST_LOCAL_MACHINE)

    displays = [repr(record), str(record), f"{record}"]
    try:
        raise RuntimeError(f"record={record}")
    except RuntimeError as error:
        displays.append(str(error))
    with caplog.at_level(logging.INFO):
        logging.getLogger(__name__).info("record=%s", record)
    displays.append(caplog.text)

    assert all(secret not in display for display in displays)
    assert all("credential_blob=<redacted>" in display for display in displays)


class FakeKernel32:
    def __init__(self, wait_result: int) -> None:
        self.wait_result = wait_result
        self.created_names: list[str] = []
        self.released = 0
        self.closed = 0

    def CreateMutexW(self, _attributes: object, _owner: bool, name: str) -> int:
        self.created_names.append(name)
        return 42

    def WaitForSingleObject(self, _handle: int, _milliseconds: int) -> int:
        return self.wait_result

    def ReleaseMutex(self, _handle: int) -> int:
        self.released += 1
        return 1

    def CloseHandle(self, _handle: int) -> int:
        self.closed += 1
        return 1


def test_rotation_lock_acquires_releases_and_is_local_user_scoped() -> None:
    kernel = FakeKernel32(credentials.WAIT_OBJECT_0)
    with credentials._rotation_lock(
        timeout=0.01, kernel32=kernel, name="Local\\forgejo-api-mcp-rotate-S-1-5-21-test"
    ) as lock:
        assert lock.abandoned is False
    assert kernel.created_names == ["Local\\forgejo-api-mcp-rotate-S-1-5-21-test"]
    assert kernel.released == 1
    assert kernel.closed == 1


def test_rotation_lock_abandoned_proceeds_and_finally_releases() -> None:
    kernel = FakeKernel32(credentials.WAIT_ABANDONED)
    with (
        pytest.raises(RuntimeError),
        credentials._rotation_lock(timeout=0.01, kernel32=kernel, name="Local\\test") as lock,
    ):
        assert lock.abandoned is True
        raise RuntimeError("synthetic failure")
    assert kernel.released == 1
    assert kernel.closed == 1


def test_rotation_lock_timeout_closes_without_releasing() -> None:
    kernel = FakeKernel32(credentials.WAIT_TIMEOUT)
    with (
        pytest.raises(credentials.RotationMutexTimeout),
        credentials._rotation_lock(timeout=0.001, kernel32=kernel, name="Local\\test"),
    ):
        pytest.fail("timed-out lock must not enter")
    assert kernel.released == 0
    assert kernel.closed == 1


class FakeStore:
    def __init__(self) -> None:
        self.store: dict[str, CredentialRecord] = {}

    def write(self, target: str, username: str, token: str, persist_type: int) -> None:
        self.store[target] = CredentialRecord(target, username, token, persist_type)

    def read(self, target: str) -> CredentialRecord | None:
        return self.store.get(target)

    def delete(self, target: str) -> None:
        self.store.pop(target, None)


@pytest.fixture
def fake_store(monkeypatch: pytest.MonkeyPatch) -> FakeStore:
    store = FakeStore()
    monkeypatch.setattr(credentials, "_win32_write", store.write)
    monkeypatch.setattr(credentials, "_win32_read", store.read)
    monkeypatch.setattr(credentials, "_win32_delete", store.delete)
    return store


def test_write_then_read_round_trips_the_token(fake_store: FakeStore) -> None:
    write_credential("tok-123")
    assert read_credential() == CredentialRecord(
        TARGET_NAME, "forgejo-api-mcp", "tok-123", CRED_PERSIST_LOCAL_MACHINE
    )


def test_read_returns_none_when_absent(fake_store: FakeStore) -> None:
    assert read_credential() is None


def test_delete_removes_and_is_idempotent_when_absent(fake_store: FakeStore) -> None:
    write_credential("tok-123")
    delete_credential()
    assert read_credential() is None
    delete_credential()


def test_write_rejects_any_other_target(fake_store: FakeStore) -> None:
    with pytest.raises(TypeError):
        write_credential("other/target", "tok")  # type: ignore[call-arg]


def test_read_rejects_any_other_target(fake_store: FakeStore) -> None:
    with pytest.raises(TypeError):
        read_credential("other/target")  # type: ignore[call-arg]


def test_write_rejects_empty_or_nul_token(fake_store: FakeStore) -> None:
    with pytest.raises(CredentialStoreError):
        write_credential("")
    with pytest.raises(CredentialStoreError):
        write_credential("bad\x00token")


def test_write_rejects_username_override(fake_store: FakeStore) -> None:
    with pytest.raises(TypeError):
        write_credential("tok", username="alice")  # type: ignore[call-arg]


def test_win32_write_raises_unavailable_on_non_windows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(credentials, "_advapi32", None)

    with pytest.raises(CredentialStoreUnavailable, match="only available on Windows"):
        write_credential("tok")


def test_load_advapi32_raises_unavailable_off_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(credentials, "_advapi32", None)
    monkeypatch.setattr(sys, "platform", "linux")
    with pytest.raises(CredentialStoreUnavailable):
        credentials._load_advapi32()


def test_win32_helpers_touch_only_injected_store(fake_store: FakeStore) -> None:
    write_credential("round-trip")
    record = read_credential()
    assert record is not None and record.credential_blob == "round-trip"
    assert fake_store.store[TARGET_NAME].username == "forgejo-api-mcp"


def test_restore_credential_round_trips_full_constrained_record(fake_store: FakeStore) -> None:
    prior = CredentialRecord(
        TARGET_NAME, "forgejo-api-mcp", "prior-value", CRED_PERSIST_LOCAL_MACHINE
    )
    credentials.restore_credential(prior)
    assert read_credential() == prior


def test_rotation_lock_is_unavailable_off_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    with pytest.raises(CredentialStoreUnavailable):
        credentials._rotation_lock()


def test_rotation_mutex_name_uses_local_namespace_and_current_user_sid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(credentials, "_current_user_sid", lambda: "S-1-5-21-1234")
    name = credentials._rotation_mutex_name()
    assert name == "Local\\forgejo-api-mcp-rotate-S-1-5-21-1234"
    assert not name.startswith("Global\\")


def test_encode_and_decode_blob_round_trip() -> None:
    assert credentials._decode_blob(credentials._encode_blob("tok-123")) == "tok-123"


def test_decode_blob_rejects_invalid_utf16() -> None:
    with pytest.raises(CredentialStoreError):
        credentials._decode_blob(b"\x00")  # odd length is not valid UTF-16-LE


def test_map_win32_error_carries_no_secret() -> None:
    error = credentials._map_win32_error("CredWriteW", 5)
    assert isinstance(error, CredentialStoreError)
    assert "CredWriteW" in str(error)
    assert "5" in str(error)


def test_build_credential_sets_all_fields() -> None:
    blob = credentials._encode_blob("secret-value")
    credential, buffer = credentials._build_credential(TARGET_NAME, "alice", blob)
    assert credential.Type == credentials.CRED_TYPE_GENERIC
    assert credential.TargetName == TARGET_NAME
    assert credential.UserName == "alice"
    assert credential.Persist == credentials.CRED_PERSIST_LOCAL_MACHINE
    assert credential.CredentialBlobSize == len(blob)
    assert buffer is not None


def test_credential_to_token_decodes_blob() -> None:
    blob = credentials._encode_blob("tok-abc")
    credential, _buffer = credentials._build_credential(TARGET_NAME, "alice", blob)
    assert credentials._credential_to_token(credential) == "tok-abc"


def test_credential_to_record_preserves_constrained_fields() -> None:
    blob = credentials._encode_blob("tok-abc")
    credential, _buffer = credentials._build_credential(
        TARGET_NAME,
        credentials.USERNAME,
        blob,
    )

    assert credentials._credential_to_record(credential) == CredentialRecord(
        target=TARGET_NAME,
        username=credentials.USERNAME,
        credential_blob="tok-abc",
        persist_type=CRED_PERSIST_LOCAL_MACHINE,
    )


class FakeWin32Library:
    def __init__(
        self,
        *,
        write_ok: bool = True,
        read_ok: bool = True,
        delete_ok: bool = True,
        last_error: int = 0,
    ) -> None:
        self.write_ok = write_ok
        self.read_ok = read_ok
        self.delete_ok = delete_ok
        self.last_error = last_error
        self.freed = 0

    def CredWriteW(self, _cred_ref: Any, _flags: int) -> int:
        ctypes.set_last_error(self.last_error)
        return 1 if self.write_ok else 0

    def CredReadW(self, _target: str, _cred_type: int, _flags: int, _out_ref: Any) -> int:
        ctypes.set_last_error(self.last_error)
        return 1 if self.read_ok else 0

    def CredDeleteW(self, _target: str, _cred_type: int, _flags: int) -> int:
        ctypes.set_last_error(self.last_error)
        return 1 if self.delete_ok else 0

    def CredFree(self, _pointer: Any) -> None:
        self.freed += 1


@pytest.fixture
def win32_env(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(credentials, "_advapi32", None)
    monkeypatch.setattr(sys, "platform", "win32")
    return monkeypatch


def test_win32_write_success_path(win32_env: pytest.MonkeyPatch, monkeypatch: pytest.MonkeyPatch) -> None:
    library = FakeWin32Library()
    monkeypatch.setattr(credentials, "_bind_advapi32", lambda: library)
    credentials._win32_write(TARGET_NAME, "alice", "tok")
    assert library is credentials._advapi32


def test_win32_write_failure_raises(win32_env: pytest.MonkeyPatch, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        credentials, "_bind_advapi32", lambda: FakeWin32Library(write_ok=False, last_error=5)
    )
    with pytest.raises(CredentialStoreError, match="CredWriteW"):
        credentials._win32_write(TARGET_NAME, "alice", "secret")


def test_win32_read_not_found_returns_none(
    win32_env: pytest.MonkeyPatch, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        credentials,
        "_bind_advapi32",
        lambda: FakeWin32Library(read_ok=False, last_error=credentials.ERROR_NOT_FOUND),
    )
    assert credentials._win32_read(TARGET_NAME) is None


def test_win32_read_other_error_raises(
    win32_env: pytest.MonkeyPatch, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        credentials, "_bind_advapi32", lambda: FakeWin32Library(read_ok=False, last_error=7)
    )
    with pytest.raises(CredentialStoreError, match="CredReadW"):
        credentials._win32_read(TARGET_NAME)


def test_win32_delete_success_and_not_found(
    win32_env: pytest.MonkeyPatch, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(credentials, "_bind_advapi32", lambda: FakeWin32Library(delete_ok=True))
    credentials._win32_delete(TARGET_NAME)

    monkeypatch.setattr(
        credentials,
        "_bind_advapi32",
        lambda: FakeWin32Library(delete_ok=False, last_error=credentials.ERROR_NOT_FOUND),
    )
    credentials._win32_delete(TARGET_NAME)


def test_win32_delete_other_error_raises(
    win32_env: pytest.MonkeyPatch, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        credentials, "_bind_advapi32", lambda: FakeWin32Library(delete_ok=False, last_error=7)
    )
    with pytest.raises(CredentialStoreError, match="CredDeleteW"):
        credentials._win32_delete(TARGET_NAME)


def test_load_advapi32_caches_the_bound_library(
    win32_env: pytest.MonkeyPatch, monkeypatch: pytest.MonkeyPatch
) -> None:
    sentinel = FakeWin32Library()
    calls = {"n": 0}

    def bind_once() -> FakeWin32Library:
        calls["n"] += 1
        return sentinel

    monkeypatch.setattr(credentials, "_bind_advapi32", bind_once)
    assert credentials._load_advapi32() is sentinel
    assert credentials._load_advapi32() is sentinel
    assert calls["n"] == 1
