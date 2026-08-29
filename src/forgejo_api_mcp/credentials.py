"""Windows Credential Manager store for the single Forgejo access-token target.

Only the generic-credential target ``mcp/forgejo-mcp/access-token`` is supported. The
credential blob (the token) is written and read through the Win32 ``CredWriteW`` /
``CredReadW`` API via :mod:`ctypes` so the secret never appears on a process command line
(the ``cmdkey /pass`` route is intentionally avoided). Nothing in this module logs or
returns the credential blob outside of :func:`read_credential`, which the rotation CLI
uses solely to verify a readback.
"""

from __future__ import annotations

import ctypes
import math
import sys
import types
from contextlib import AbstractContextManager
from ctypes import wintypes
from dataclasses import dataclass
from typing import Any, Self

from .credential_backend import (
    TARGET_NAME,
    CredentialBackendError,
    CredentialCategory,
    CredentialOperationError,
    CredentialSnapshot,
)

USERNAME = "forgejo-api-mcp"
CRED_TYPE_GENERIC = 1
CRED_PERSIST_LOCAL_MACHINE = 2
ERROR_NOT_FOUND = 1168
DEFAULT_LOCK_TIMEOUT_SECONDS = 30.0
WAIT_OBJECT_0 = 0x00000000
WAIT_ABANDONED = 0x00000080
WAIT_TIMEOUT = 0x00000102
WAIT_FAILED = 0xFFFFFFFF
TOKEN_QUERY = 0x0008
TOKEN_USER_CLASS = 1
SDDL_REVISION_1 = 1
MUTEX_MODIFY_STATE = 0x0001
SYNCHRONIZE = 0x00100000
MUTEX_REQUIRED_ACCESS = MUTEX_MODIFY_STATE | SYNCHRONIZE


class CredentialStoreUnavailable(CredentialBackendError):
    """Raised when the Windows Credential Manager is not available (non-Windows host)."""


class CredentialStoreError(CredentialBackendError):
    """Raised when a Windows Credential Manager operation fails."""


class RotationMutexTimeout(CredentialStoreError):
    """Raised when another same-user rotation holds the mutex past the bounded wait."""


@dataclass(frozen=True, repr=False)
class CredentialRecord:
    """The constrained generic-credential fields this product writes and restores."""

    target: str
    username: str
    credential_blob: str
    persist_type: int

    def __repr__(self) -> str:
        return (
            "CredentialRecord("
            f"target={self.target!r}, username={self.username!r}, "
            f"credential_blob=<redacted>, persist_type={self.persist_type!r})"
        )

    __str__ = __repr__


class _CREDENTIAL(ctypes.Structure):
    _fields_ = [
        ("Flags", wintypes.DWORD),
        ("Type", wintypes.DWORD),
        ("TargetName", wintypes.LPWSTR),
        ("Comment", wintypes.LPWSTR),
        ("LastWritten", wintypes.FILETIME),
        ("CredentialBlobSize", wintypes.DWORD),
        ("CredentialBlob", ctypes.POINTER(ctypes.c_char)),
        ("Persist", wintypes.DWORD),
        ("AttributeCount", wintypes.DWORD),
        ("Attributes", ctypes.c_void_p),
        ("TargetAlias", wintypes.LPWSTR),
        ("UserName", wintypes.LPWSTR),
    ]


class _SID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Sid", wintypes.LPVOID), ("Attributes", wintypes.DWORD)]


class _TOKEN_USER(ctypes.Structure):
    _fields_ = [("User", _SID_AND_ATTRIBUTES)]


class _SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("nLength", wintypes.DWORD),
        ("lpSecurityDescriptor", wintypes.LPVOID),
        ("bInheritHandle", wintypes.BOOL),
    ]


def write_credential(token: str) -> None:
    """Store ``token`` at the fixed product target with fixed metadata."""

    if not isinstance(token, str) or not token or "\x00" in token:
        raise CredentialStoreError("token must be a non-empty string without NUL bytes")
    _win32_write(TARGET_NAME, USERNAME, token, CRED_PERSIST_LOCAL_MACHINE)


def read_credential() -> CredentialRecord | None:
    """Return the full constrained fixed-target record, or ``None`` when absent."""

    return _win32_read(TARGET_NAME)


def delete_credential() -> None:
    """Delete the fixed-target record; a missing entry is a silent no-op."""

    _win32_delete(TARGET_NAME)


def restore_credential(record: CredentialRecord) -> None:
    """Restore a previously captured constrained record to the fixed target (internal)."""

    if not isinstance(record, CredentialRecord) or record.target != TARGET_NAME:
        raise CredentialStoreError("refusing to restore a credential for a foreign target")
    _validate_record_metadata(record)
    _win32_write(record.target, record.username, record.credential_blob, record.persist_type)


def _raw_write(target: str, token: str) -> None:
    """Write fixed metadata to an explicit test target (internal smoke-test helper)."""

    if not isinstance(target, str) or not target or "\x00" in target:
        raise CredentialStoreError("target must be a non-empty string without NUL bytes")
    if not isinstance(token, str) or not token or "\x00" in token:
        raise CredentialStoreError("token must be a non-empty string without NUL bytes")
    _win32_write(target, USERNAME, token, CRED_PERSIST_LOCAL_MACHINE)


def _raw_read(target: str) -> CredentialRecord | None:
    """Read an explicit test target (internal smoke-test helper)."""

    return _win32_read(target)


def _raw_delete(target: str) -> None:
    """Delete an explicit test target (internal smoke-test helper)."""

    _win32_delete(target)


def _validate_record_metadata(record: CredentialRecord) -> None:
    if not record.username or "\x00" in record.username:
        raise CredentialStoreError("stored username is invalid")
    if not record.credential_blob or "\x00" in record.credential_blob:
        raise CredentialStoreError("stored credential blob is invalid")
    if record.persist_type != CRED_PERSIST_LOCAL_MACHINE:
        raise CredentialStoreError("stored credential persistence is unsupported")


def _encode_blob(token: str) -> bytes:
    return token.encode("utf-16-le")


def _decode_blob(blob: bytes) -> str:
    try:
        return blob.decode("utf-16-le")
    except UnicodeDecodeError as error:
        raise CredentialStoreError("stored credential blob is not valid UTF-16LE") from error


def _map_win32_error(func: str, error: int) -> CredentialStoreError:
    return CredentialStoreError(f"{func} failed with Win32 error {error}")


def _build_credential(
    target: str,
    username: str,
    blob: bytes,
    persist_type: int = CRED_PERSIST_LOCAL_MACHINE,
) -> tuple[_CREDENTIAL, Any]:
    buffer = (ctypes.c_char * len(blob)).from_buffer_copy(blob)
    credential = _CREDENTIAL()
    credential.Type = CRED_TYPE_GENERIC
    credential.TargetName = target
    credential.CredentialBlobSize = len(blob)
    credential.CredentialBlob = buffer
    credential.Persist = persist_type
    credential.UserName = username
    return credential, buffer


def _credential_to_token(credential: _CREDENTIAL) -> str:
    size = credential.CredentialBlobSize
    blob = ctypes.string_at(credential.CredentialBlob, size) if size else b""
    return _decode_blob(blob)


def _credential_to_record(credential: _CREDENTIAL) -> CredentialRecord:
    target = credential.TargetName or ""
    username = credential.UserName or ""
    record = CredentialRecord(
        target=target,
        username=username,
        credential_blob=_credential_to_token(credential),
        persist_type=int(credential.Persist),
    )
    _validate_record_metadata(record)
    return record


def _win32_write(
    target: str,
    username: str,
    token: str,
    persist_type: int = CRED_PERSIST_LOCAL_MACHINE,
) -> None:
    credential, _buffer = _build_credential(target, username, _encode_blob(token), persist_type)
    library = _load_advapi32()
    if not library.CredWriteW(ctypes.byref(credential), 0):
        raise _map_win32_error("CredWriteW", ctypes.get_last_error())


def _win32_read(target: str) -> CredentialRecord | None:
    library = _load_advapi32()
    pointer = ctypes.POINTER(_CREDENTIAL)()
    if not library.CredReadW(target, CRED_TYPE_GENERIC, 0, ctypes.byref(pointer)):
        error = ctypes.get_last_error()
        if error == ERROR_NOT_FOUND:
            return None
        raise _map_win32_error("CredReadW", error)
    try:
        return _credential_to_record(pointer.contents)
    finally:
        library.CredFree(pointer)


def _win32_delete(target: str) -> None:
    library = _load_advapi32()
    if not library.CredDeleteW(target, CRED_TYPE_GENERIC, 0):
        error = ctypes.get_last_error()
        if error == ERROR_NOT_FOUND:
            return
        raise _map_win32_error("CredDeleteW", error)


def _load_advapi32() -> Any:
    global _advapi32
    if _advapi32 is None:
        if sys.platform != "win32":
            raise CredentialStoreUnavailable(
                "Windows Credential Manager is only available on Windows"
            )
        _advapi32 = _bind_advapi32()
    return _advapi32


def _bind_advapi32() -> Any:
    library = ctypes.WinDLL("advapi32", use_last_error=True)  # type: ignore[attr-defined]
    library.CredWriteW.argtypes = [ctypes.POINTER(_CREDENTIAL), wintypes.DWORD]
    library.CredWriteW.restype = wintypes.BOOL
    library.CredReadW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.POINTER(_CREDENTIAL)),
    ]
    library.CredReadW.restype = wintypes.BOOL
    library.CredDeleteW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD]
    library.CredDeleteW.restype = wintypes.BOOL
    library.CredFree.argtypes = [wintypes.LPVOID]
    library.CredFree.restype = None
    library.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPHANDLE]
    library.OpenProcessToken.restype = wintypes.BOOL
    library.GetTokenInformation.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.LPDWORD,
    ]
    library.GetTokenInformation.restype = wintypes.BOOL
    library.ConvertSidToStringSidW.argtypes = [wintypes.LPVOID, ctypes.POINTER(wintypes.LPWSTR)]
    library.ConvertSidToStringSidW.restype = wintypes.BOOL
    library.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPVOID),
        wintypes.LPDWORD,
    ]
    library.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
    return library


def _load_kernel32() -> Any:
    global _kernel32
    if _kernel32 is None:
        if sys.platform != "win32":
            raise CredentialStoreUnavailable(
                "Windows Credential Manager is only available on Windows"
            )
        _kernel32 = _bind_kernel32()
    return _kernel32


def _bind_kernel32() -> Any:
    library = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
    library.CreateMutexExW.argtypes = [
        ctypes.POINTER(_SECURITY_ATTRIBUTES),
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
    ]
    library.CreateMutexExW.restype = wintypes.HANDLE
    library.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    library.WaitForSingleObject.restype = wintypes.DWORD
    library.ReleaseMutex.argtypes = [wintypes.HANDLE]
    library.ReleaseMutex.restype = wintypes.BOOL
    library.CloseHandle.argtypes = [wintypes.HANDLE]
    library.CloseHandle.restype = wintypes.BOOL
    library.GetCurrentProcess.argtypes = []
    library.GetCurrentProcess.restype = wintypes.HANDLE
    library.LocalFree.argtypes = [wintypes.HLOCAL]
    library.LocalFree.restype = wintypes.HLOCAL
    return library


def _current_user_sid() -> str | None:
    """Return the current process user's string SID, or ``None`` for the safe fallback."""

    advapi32 = _load_advapi32()
    kernel32 = _load_kernel32()
    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(
        kernel32.GetCurrentProcess(), TOKEN_QUERY, ctypes.byref(token)
    ):
        return None
    try:
        required = wintypes.DWORD()
        advapi32.GetTokenInformation(
            token, TOKEN_USER_CLASS, None, 0, ctypes.byref(required)
        )
        if not required.value:
            return None
        buffer = ctypes.create_string_buffer(required.value)
        if not advapi32.GetTokenInformation(
            token,
            TOKEN_USER_CLASS,
            buffer,
            required.value,
            ctypes.byref(required),
        ):
            return None
        token_user = ctypes.cast(buffer, ctypes.POINTER(_TOKEN_USER)).contents
        sid_text = wintypes.LPWSTR()
        if not advapi32.ConvertSidToStringSidW(token_user.User.Sid, ctypes.byref(sid_text)):
            return None
        try:
            return sid_text.value
        finally:
            kernel32.LocalFree(sid_text)
    finally:
        kernel32.CloseHandle(token)


def _rotation_mutex_name(sid: str | None = None) -> str:
    identifier = _current_user_sid() if sid is None else sid
    if not identifier:
        raise CredentialStoreError("current Windows user SID is unavailable")
    return f"Global\\forgejo-api-mcp-rotate-{identifier}"


def _build_mutex_security_attributes(
    sid: str,
    *,
    advapi32: Any = None,
) -> tuple[_SECURITY_ATTRIBUTES, wintypes.LPVOID]:
    """Build a protected DACL granting only SYSTEM and the current SID mutex access."""

    if not sid or not sid.startswith("S-") or "\x00" in sid:
        raise CredentialStoreError("current Windows user SID is invalid")
    library = advapi32 or _load_advapi32()
    descriptor = wintypes.LPVOID()
    sddl = (
        "D:P"
        f"(A;;0x{MUTEX_REQUIRED_ACCESS:08x};;;SY)"
        f"(A;;0x{MUTEX_REQUIRED_ACCESS:08x};;;{sid})"
    )
    if not library.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl,
        SDDL_REVISION_1,
        ctypes.byref(descriptor),
        None,
    ):
        raise _map_win32_error(
            "ConvertStringSecurityDescriptorToSecurityDescriptorW",
            ctypes.get_last_error(),
        )
    attributes = _SECURITY_ATTRIBUTES(
        nLength=ctypes.sizeof(_SECURITY_ATTRIBUTES),
        lpSecurityDescriptor=descriptor,
        bInheritHandle=False,
    )
    return attributes, descriptor


class _RotationLock:
    """Bounded context manager around the user-scoped Windows named mutex."""

    def __init__(
        self,
        *,
        timeout: float,
        kernel32: Any = None,
        name: str | None = None,
        sid: str | None = None,
    ) -> None:
        self.timeout = max(0.0, min(float(timeout), DEFAULT_LOCK_TIMEOUT_SECONDS))
        self.kernel32 = kernel32
        self.name = name
        self.sid = sid
        self.handle: Any = None
        self.abandoned = False
        self._owned = False

    def __enter__(self) -> Self:
        library = self.kernel32 or _load_kernel32()
        sid = self.sid or _current_user_sid()
        if not sid:
            raise CredentialStoreError("current Windows user SID is unavailable")
        expected_name = _rotation_mutex_name(sid)
        name = self.name or expected_name
        if name != expected_name:
            raise CredentialStoreError("rotation mutex name must match the current user SID")
        attributes, descriptor = _build_mutex_security_attributes(sid)
        try:
            handle = library.CreateMutexExW(
                ctypes.byref(attributes),
                name,
                0,
                MUTEX_REQUIRED_ACCESS,
            )
        finally:
            library.LocalFree(descriptor)
        if not handle:
            raise _map_win32_error("CreateMutexExW", ctypes.get_last_error())
        self.kernel32 = library
        self.name = name
        self.handle = handle
        milliseconds = min(math.ceil(self.timeout * 1000), 0xFFFFFFFE)
        result = int(library.WaitForSingleObject(handle, milliseconds))
        if result == WAIT_TIMEOUT:
            library.CloseHandle(handle)
            self.handle = None
            raise RotationMutexTimeout("rotation mutex acquisition timed out")
        if result == WAIT_FAILED:
            error = ctypes.get_last_error()
            library.CloseHandle(handle)
            self.handle = None
            raise _map_win32_error("WaitForSingleObject", error)
        if result not in (WAIT_OBJECT_0, WAIT_ABANDONED):
            library.CloseHandle(handle)
            self.handle = None
            raise CredentialStoreError("WaitForSingleObject returned an unexpected result")
        self.abandoned = result == WAIT_ABANDONED
        self._owned = True
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: types.TracebackType | None,
    ) -> bool:
        release_error: CredentialStoreError | None = None
        try:
            if self._owned and not self.kernel32.ReleaseMutex(self.handle):
                release_error = _map_win32_error("ReleaseMutex", ctypes.get_last_error())
        finally:
            if self.handle is not None:
                self.kernel32.CloseHandle(self.handle)
            self.handle = None
            self._owned = False
        if release_error is not None and exc is None:
            raise release_error
        return False


def _rotation_lock(
    *,
    timeout: float = DEFAULT_LOCK_TIMEOUT_SECONDS,
    kernel32: Any = None,
    name: str | None = None,
    sid: str | None = None,
) -> _RotationLock:
    """Create the internal user-scoped rotation mutex context manager."""

    if kernel32 is None and sys.platform != "win32":
        raise CredentialStoreUnavailable("rotation mutex is only available on Windows")
    return _RotationLock(timeout=timeout, kernel32=kernel32, name=name, sid=sid)


def _ensure_store_available() -> None:
    """Fail before stdin/network when the Windows credential primitives are unavailable."""

    _load_advapi32()
    _load_kernel32()


class _WindowsSnapshot:
    """Opaque Windows rollback record owned by :class:`WindowsCredentialBackend`."""

    __slots__ = ("_discarded", "_record")

    def __init__(self, record: CredentialRecord | None) -> None:
        self._record = record
        self._discarded = False

    @property
    def present(self) -> bool:
        return not self._discarded and self._record is not None

    def _require_record(self) -> CredentialRecord | None:
        if self._discarded:
            raise CredentialOperationError(
                CredentialCategory.STORE_ERROR,
                credential_state="unknown",
                operation="restore",
                guidance_id=None,
            )
        return self._record

    def _discard(self) -> None:
        self._record = None
        self._discarded = True

    def __repr__(self) -> str:
        return "WindowsCredentialSnapshot(<redacted>)"

    __str__ = __repr__

    def __reduce__(self) -> tuple[Any, ...]:
        raise TypeError("credential snapshots are not serializable")


class _WindowsBackendRotationLock(AbstractContextManager["_WindowsBackendRotationLock"]):
    """Normalize private Win32 mutex failures at the backend boundary."""

    def __init__(self, lock: _RotationLock) -> None:
        self._lock = lock

    @staticmethod
    def _error(error: CredentialBackendError) -> CredentialOperationError:
        category = (
            CredentialCategory.TIMEOUT
            if isinstance(error, RotationMutexTimeout)
            else CredentialCategory.STORE_ERROR
        )
        return CredentialOperationError(
            category,
            credential_state="unchanged",
            operation="lock",
            guidance_id=None,
        )

    def __enter__(self) -> Self:
        try:
            self._lock.__enter__()
        except CredentialBackendError as error:
            raise self._error(error) from None
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: types.TracebackType | None,
    ) -> bool:
        try:
            return self._lock.__exit__(exc_type, exc, traceback)
        except CredentialBackendError as error:
            raise self._error(error) from None


class WindowsCredentialBackend:
    """Credential Manager with a SID-protected cross-session mutex behind the common contract."""

    @staticmethod
    def _error(operation: str, *, state: str = "unchanged") -> CredentialOperationError:
        return CredentialOperationError(
            CredentialCategory.STORE_ERROR,
            credential_state=state,
            operation=operation,
            guidance_id=None,
        )

    def availability(self) -> CredentialCategory:
        try:
            _ensure_store_available()
        except (CredentialStoreUnavailable, CredentialStoreError):
            raise self._error("availability") from None
        return CredentialCategory.AVAILABLE

    def read(self) -> str:
        try:
            record = read_credential()
        except (CredentialStoreUnavailable, CredentialStoreError):
            raise self._error("read") from None
        if record is None:
            raise CredentialOperationError(
                CredentialCategory.MISSING,
                credential_state="unchanged",
                operation="read",
                guidance_id=None,
            )
        return record.credential_blob

    def snapshot(self) -> CredentialSnapshot:
        try:
            return _WindowsSnapshot(read_credential())
        except (CredentialStoreUnavailable, CredentialStoreError):
            raise self._error("snapshot") from None

    def replace_existing(self, token: str) -> None:
        try:
            write_credential(token)
        except (CredentialStoreUnavailable, CredentialStoreError):
            raise self._error("replace_existing", state="unchanged") from None

    def restore(self, snapshot: CredentialSnapshot) -> None:
        if not isinstance(snapshot, _WindowsSnapshot):
            raise self._error("restore", state="unknown")
        record = snapshot._require_record()
        try:
            if record is None:
                delete_credential()
                if read_credential() is not None:
                    raise self._error("restore", state="unknown")
            else:
                restore_credential(record)
                restored = read_credential()
                if restored != record:
                    raise self._error("restore", state="unknown")
        except CredentialOperationError:
            raise
        except (CredentialStoreUnavailable, CredentialStoreError):
            raise self._error("restore", state="unknown") from None

    def discard(self, snapshot: CredentialSnapshot) -> None:
        if not isinstance(snapshot, _WindowsSnapshot):
            raise self._error("discard", state="unknown")
        snapshot._discard()

    def lock(self, *, timeout: float) -> AbstractContextManager[object]:
        try:
            lock = _rotation_lock(timeout=timeout)
        except CredentialBackendError as error:
            raise _WindowsBackendRotationLock._error(error) from None
        return _WindowsBackendRotationLock(lock)


_advapi32: Any = None
_kernel32: Any = None
