"""Strictly non-interactive Linux SecretStorage credential adapter.

The controlling process starts one static package worker with ``os.posix_spawn`` and an explicit
environment allowlist. No request exists in child memory at launch; typed secret-bearing bytes are
sent only afterward over a private anonymous pipe. The ``posix_spawn`` call itself is the one
unavoidable non-interruptible OS launch primitive. Once it returns a PID, request transfer,
SecretStorage/D-Bus work, response, teardown, and process-group termination share one absolute
monotonic deadline.
"""

from __future__ import annotations

import errno
import fcntl
import os
import signal
import stat
import sys
import time
import types
from collections.abc import Callable
from contextlib import AbstractContextManager
from multiprocessing.connection import Connection
from pathlib import Path
from typing import Any, Self

from .credential_backend import (
    LINUX_GUIDANCE_ID,
    LINUX_QUARANTINE_GUIDANCE_ID,
    TARGET_NAME,
    CredentialCategory,
    CredentialOperationError,
    CredentialSnapshot,
)

ITEM_ATTRIBUTES = {
    "application": "forgejo-api-mcp",
    "credential-kind": "access-token",
    "target": TARGET_NAME,
}
ITEM_LABEL = "Forgejo API MCP access token"
CONTENT_TYPE = "text/plain"

SERVICE_OPERATION_TIMEOUT_SECONDS = 5.0
TERMINATE_GRACE_SECONDS = 0.25
KILL_JOIN_SECONDS = 0.25
CLEANUP_RESERVE_SECONDS = TERMINATE_GRACE_SECONDS + KILL_JOIN_SECONDS
# Keep framed messages below POSIX PIPE_BUF so a ready Connection message is complete.
MAX_SECRET_BYTES = 2 * 1024
MAX_REQUEST_BYTES = MAX_SECRET_BYTES + 1
MAX_RESPONSE_BYTES = MAX_SECRET_BYTES + 2
DEFAULT_LOCK_TIMEOUT_SECONDS = 30.0
LOCK_FILENAME = "forgejo-api-mcp-rotate.lock"
QUARANTINE_FILENAME = "forgejo-api-mcp-quarantine"
QUARANTINE_TEMP_FILENAME = "forgejo-api-mcp-quarantine.tmp"
QUARANTINE_CONTENT = b"forgejo-api-mcp-linux-quarantine-v1\n"
WORKER_REQUEST_FD = 3
WORKER_RESPONSE_FD = 4
_WORKER_ENV_ALLOWLIST = (
    "DBUS_SESSION_BUS_ADDRESS",
    "XDG_RUNTIME_DIR",
)

_OPERATION_CODES = {
    "availability": b"A",
    "read": b"R",
    "snapshot": b"S",
    "replace_existing": b"W",
    "restore": b"B",
}
_CODE_OPERATIONS = {value: key for key, value in _OPERATION_CODES.items()}
_CATEGORY_CODES = {
    category: bytes((index,)) for index, category in enumerate(CredentialCategory, start=1)
}
_CODE_CATEGORIES = {value: key for key, value in _CATEGORY_CODES.items()}

OperationRunner = Callable[[str, bytes | None], bytes | None]


def _operation_error(
    category: CredentialCategory,
    operation: str,
    *,
    state: str | None = None,
    indeterminate: bool | None = None,
    guidance_id: str | None = LINUX_GUIDANCE_ID,
) -> CredentialOperationError:
    mutating = operation in {"replace_existing", "restore"}
    timed_out_mutation = mutating and category is CredentialCategory.TIMEOUT
    return CredentialOperationError(
        category,
        credential_state=state or ("unknown" if mutating else "unchanged"),
        operation=operation,
        indeterminate=timed_out_mutation if indeterminate is None else indeterminate,
        guidance_id=guidance_id,
    )


def _quarantine_error(operation: str) -> CredentialOperationError:
    return _operation_error(
        CredentialCategory.STORE_ERROR,
        operation,
        state="unknown",
        guidance_id=LINUX_QUARANTINE_GUIDANCE_ID,
    )


def _map_secretstorage_exception(
    error: BaseException,
    operation: str,
    exceptions: Any | None = None,
) -> CredentialOperationError:
    """Map by the real hierarchy, checking PromptDismissed before ItemNotFound."""

    if exceptions is None:
        try:
            import secretstorage

            exceptions = secretstorage.exceptions
        except ImportError:
            exceptions = None
    if exceptions is not None:
        if isinstance(error, exceptions.PromptDismissedException):
            return _operation_error(CredentialCategory.PROMPT_DISMISSED, operation)
        if isinstance(error, exceptions.ItemNotFoundException):
            category = (
                CredentialCategory.MISSING
                if operation in {"availability", "read", "snapshot"}
                else CredentialCategory.STORE_ERROR
            )
            return _operation_error(category, operation)
        if isinstance(error, exceptions.LockedException):
            return _operation_error(CredentialCategory.LOCKED, operation)
        if isinstance(error, exceptions.SecretServiceNotAvailableException):
            return _operation_error(CredentialCategory.SERVICE_UNAVAILABLE, operation)
        if isinstance(error, exceptions.SecretStorageException):
            return _operation_error(CredentialCategory.STORE_ERROR, operation)
    if isinstance(error, TimeoutError):
        return _operation_error(CredentialCategory.TIMEOUT, operation)
    if type(error).__name__ == "PromptRequiredException":
        return _operation_error(CredentialCategory.PROMPT_REQUIRED, operation)
    if isinstance(error, ImportError):
        return _operation_error(CredentialCategory.SERVICE_UNAVAILABLE, operation)
    return _operation_error(CredentialCategory.STORE_ERROR, operation)


def _raise_mapped(error: BaseException, operation: str, api: Any) -> None:
    exceptions = getattr(api, "exceptions", None)
    raise _map_secretstorage_exception(error, operation, exceptions) from None


def _resolve_item(api: Any, operation: str) -> Any:
    connection = api.dbus_init()
    collection = api.get_collection_by_alias(connection, "default")
    if collection is None:
        category = (
            CredentialCategory.MISSING
            if operation in {"availability", "read", "snapshot"}
            else CredentialCategory.STORE_ERROR
        )
        raise _operation_error(category, operation)
    if collection.is_locked():
        raise _operation_error(CredentialCategory.LOCKED, operation)
    items = list(collection.search_items(dict(ITEM_ATTRIBUTES)))
    if not items:
        category = (
            CredentialCategory.MISSING
            if operation in {"availability", "read", "snapshot"}
            else CredentialCategory.STORE_ERROR
        )
        raise _operation_error(category, operation)
    if len(items) != 1:
        raise _operation_error(CredentialCategory.STORE_ERROR, operation)
    item = items[0]
    if item.is_locked():
        raise _operation_error(CredentialCategory.LOCKED, operation)
    if (
        dict(item.get_attributes()) != ITEM_ATTRIBUTES
        or item.get_label() != ITEM_LABEL
        or item.get_secret_content_type() != CONTENT_TYPE
    ):
        raise _operation_error(CredentialCategory.STORE_ERROR, operation)
    return item


def _perform_secretstorage_operation(
    operation: str,
    payload: bytes | None,
    *,
    api: Any | None = None,
) -> bytes | None:
    """Execute one high-level operation using only SecretStorage's typed API."""

    if operation not in _OPERATION_CODES:
        raise _operation_error(CredentialCategory.STORE_ERROR, operation)
    try:
        if api is None:
            import secretstorage as api
        if operation == "availability":
            connection = api.dbus_init()
            collection = api.get_collection_by_alias(connection, "default")
            if collection is None:
                raise _operation_error(CredentialCategory.MISSING, operation)
            return None
        item = _resolve_item(api, operation)
        if operation in {"read", "snapshot"}:
            secret = item.get_secret()
            if not isinstance(secret, bytes) or not secret or len(secret) > MAX_SECRET_BYTES:
                raise _operation_error(CredentialCategory.STORE_ERROR, operation)
            return secret
        if payload is None or not payload or len(payload) > MAX_SECRET_BYTES:
            raise _operation_error(CredentialCategory.STORE_ERROR, operation)
        if operation != "restore" or item.get_secret() != payload:
            item.set_secret(payload, CONTENT_TYPE)
        if (
            dict(item.get_attributes()) != ITEM_ATTRIBUTES
            or item.get_label() != ITEM_LABEL
            or item.get_secret_content_type() != CONTENT_TYPE
            or (operation == "restore" and item.get_secret() != payload)
        ):
            raise _operation_error(CredentialCategory.STORE_ERROR, operation)
        return None
    except CredentialOperationError:
        raise
    except Exception as error:  # noqa: BLE001 - redact every library boundary failure
        _raise_mapped(error, operation, api)


def _encode_request(operation: str, payload: bytes | None) -> bytes:
    code = _OPERATION_CODES.get(operation)
    if code is None:
        raise _operation_error(CredentialCategory.STORE_ERROR, operation)
    body = payload or b""
    if len(body) > MAX_SECRET_BYTES:
        raise _operation_error(CredentialCategory.STORE_ERROR, operation)
    return code + body


def _decode_request(message: bytes) -> tuple[str, bytes | None]:
    if not message or len(message) > MAX_REQUEST_BYTES or message[:1] not in _CODE_OPERATIONS:
        raise ValueError("invalid request")
    operation = _CODE_OPERATIONS[message[:1]]
    payload = message[1:] or None
    if operation in {"availability", "read", "snapshot"} and payload is not None:
        raise ValueError("unexpected payload")
    if operation in {"replace_existing", "restore"} and payload is None:
        raise ValueError("missing payload")
    return operation, payload


def _handle_worker_message(message: bytes) -> bytes:
    """Return one fixed response without exposing raw objects or exceptions."""

    try:
        operation, payload = _decode_request(message)
        result = _perform_secretstorage_operation(operation, payload)
        return b"O" + (result or b"")
    except CredentialOperationError as error:
        return b"E" + _CATEGORY_CODES[error.category]
    except Exception:  # noqa: BLE001 - worker boundary must redact unknown library failures
        return b"E" + _CATEGORY_CODES[CredentialCategory.STORE_ERROR]


def worker_entrypoint() -> int:
    """Static package entry point using only the two inherited anonymous-pipe descriptors."""

    _close_unapproved_worker_fds()
    request = Connection(WORKER_REQUEST_FD, readable=True, writable=False)
    response = Connection(WORKER_RESPONSE_FD, readable=False, writable=True)
    try:
        message = request.recv_bytes(MAX_REQUEST_BYTES)
        response.send_bytes(_handle_worker_message(message))
    except (EOFError, OSError, ValueError):
        try:
            response.send_bytes(_error_response(CredentialCategory.STORE_ERROR))
        except (EOFError, OSError):
            return 1
    finally:
        request.close()
        response.close()
    return 0


def _remaining(deadline: float, operation: str) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise _operation_error(CredentialCategory.TIMEOUT, operation)
    return remaining


def _error_response(category: CredentialCategory) -> bytes:
    return b"E" + _CATEGORY_CODES[category]


class _SpawnedWorker:
    __slots__ = ("pid", "reaped", "request", "response")

    def __init__(self, pid: int, request: Connection, response: Connection) -> None:
        self.pid = pid
        self.request = request
        self.response = response
        self.reaped = False


def _worker_environment() -> dict[str, str]:
    return {
        key: value
        for key in _WORKER_ENV_ALLOWLIST
        if (value := os.environ.get(key)) is not None
    }


def _close_raw_descriptors(*descriptors: int) -> None:
    for descriptor in descriptors:
        try:
            os.close(descriptor)
        except OSError:
            continue


def _close_unapproved_worker_fds() -> None:
    """Close every descriptor except stdio and the exact two worker pipes before IPC."""

    allowed = {0, 1, 2, WORKER_REQUEST_FD, WORKER_RESPONSE_FD}
    try:
        descriptors = [int(name) for name in os.listdir("/proc/self/fd") if name.isdecimal()]
    except OSError:
        os.closerange(5, int(os.sysconf("SC_OPEN_MAX")))
        return
    for descriptor in descriptors:
        if descriptor in allowed:
            continue
        try:
            os.close(descriptor)
        except OSError:
            continue


def _inheritable_parent_descriptors(excluded: set[int]) -> set[int]:
    """Snapshot inheritable descriptors for posix_spawn close actions; fail closed on races."""

    names = os.listdir("/proc/self/fd")
    inherited: set[int] = set()
    for name in names:
        if not name.isdecimal():
            continue
        descriptor = int(name)
        if descriptor in excluded or descriptor < 3:
            continue
        try:
            if os.get_inheritable(descriptor):
                inherited.add(descriptor)
        except OSError:
            continue
    return inherited


def _relocate_reserved_descriptors(descriptors: list[int]) -> list[int]:
    reserved = {0, 1, 2, WORKER_REQUEST_FD, WORKER_RESPONSE_FD}
    relocated = list(descriptors)
    for index, descriptor in enumerate(relocated):
        if descriptor in reserved:
            replacement = fcntl.fcntl(
                descriptor,
                fcntl.F_DUPFD_CLOEXEC,
                max(reserved) + 1,
            )
            os.close(descriptor)
            relocated[index] = replacement
    return relocated


def _wait_pid_until(pid: int, deadline: float) -> bool:
    while True:
        try:
            waited, _status = os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            return True
        if waited == pid:
            return True
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(0.01, remaining))


def _terminate_pid_group(pid: int, deadline: float) -> bool:
    try:
        os.killpg(pid, signal.SIGTERM)
    except ProcessLookupError:
        return _wait_pid_until(pid, time.monotonic())
    except OSError:
        return False
    term_deadline = min(deadline, time.monotonic() + TERMINATE_GRACE_SECONDS)
    if _wait_pid_until(pid, term_deadline):
        return True
    try:
        os.killpg(pid, signal.SIGKILL)
    except ProcessLookupError:
        return _wait_pid_until(pid, time.monotonic())
    except OSError:
        return False
    kill_deadline = min(deadline, time.monotonic() + KILL_JOIN_SECONDS)
    return _wait_pid_until(pid, kill_deadline)


def _launch_posix_worker(
    deadline: float,
    operation: str,
    cleanup_deadline: float | None = None,
) -> _SpawnedWorker:
    """Launch the static package worker without request bytes or inherited arbitrary env."""

    _remaining(deadline, operation)
    request_read, request_write = os.pipe2(os.O_CLOEXEC)
    response_read, response_write = os.pipe2(os.O_CLOEXEC)
    descriptors = [request_read, request_write, response_read, response_write]
    pid: int | None = None
    try:
        request_read, request_write, response_read, response_write = (
            _relocate_reserved_descriptors(descriptors)
        )
        descriptors = [request_read, request_write, response_read, response_write]
        file_actions = [
            (os.POSIX_SPAWN_OPEN, 0, os.devnull, os.O_RDONLY, 0),
            (os.POSIX_SPAWN_OPEN, 1, os.devnull, os.O_WRONLY, 0),
            (os.POSIX_SPAWN_OPEN, 2, os.devnull, os.O_WRONLY, 0),
            (os.POSIX_SPAWN_DUP2, request_read, WORKER_REQUEST_FD),
            (os.POSIX_SPAWN_DUP2, response_write, WORKER_RESPONSE_FD),
        ]
        closefrom = getattr(os, "POSIX_SPAWN_CLOSEFROM", None)
        if closefrom is not None:
            file_actions.append((closefrom, 5))
        else:
            excluded = {0, 1, 2, WORKER_REQUEST_FD, WORKER_RESPONSE_FD}
            close_descriptors = set(descriptors)
            close_descriptors.update(_inheritable_parent_descriptors(excluded))
            file_actions.extend(
                (os.POSIX_SPAWN_CLOSE, descriptor)
                for descriptor in sorted(close_descriptors)
            )
        argv = [sys.executable, "-I", "-B", "-m", "forgejo_api_mcp.secretstorage_worker"]
        pid = os.posix_spawn(
            sys.executable,
            argv,
            _worker_environment(),
            file_actions=file_actions,
            setpgroup=0,
        )
        _remaining(deadline, operation)
        _close_raw_descriptors(request_read, response_write)
        request_read = response_write = -1
        worker = _SpawnedWorker(
            pid,
            Connection(request_write, readable=False, writable=True),
            Connection(response_read, readable=True, writable=False),
        )
        request_write = response_read = -1
        return worker
    except CredentialOperationError:
        if pid is not None:
            _terminate_pid_group(pid, cleanup_deadline or deadline)
        raise
    except Exception:  # noqa: BLE001 - launch failures cross only as stable taxonomy
        if pid is not None:
            _terminate_pid_group(pid, cleanup_deadline or deadline)
        raise _operation_error(CredentialCategory.SERVICE_UNAVAILABLE, operation) from None
    finally:
        _close_raw_descriptors(
            *(
                descriptor
                for descriptor in (request_read, request_write, response_read, response_write)
                if descriptor >= 0
            )
        )


def _wait_worker_until(worker: _SpawnedWorker, deadline: float) -> bool:
    if worker.reaped:
        return True
    worker.reaped = _wait_pid_until(worker.pid, deadline)
    return worker.reaped


def _signal_worker_group(worker: _SpawnedWorker, sig: signal.Signals) -> bool:
    try:
        os.killpg(worker.pid, sig)
    except ProcessLookupError:
        return True
    except OSError:
        return False
    return True


def _close_spawned_worker(worker: _SpawnedWorker, deadline: float | None = None) -> bool:
    cleanup_deadline = deadline or (time.monotonic() + CLEANUP_RESERVE_SECONDS)
    cleanup_ok = True
    for connection in (worker.request, worker.response):
        try:
            connection.close()
        except OSError:
            cleanup_ok = False
    if worker.reaped or _wait_worker_until(worker, time.monotonic()):
        return cleanup_ok
    if not _signal_worker_group(worker, signal.SIGTERM):
        cleanup_ok = False
    term_deadline = min(cleanup_deadline, time.monotonic() + TERMINATE_GRACE_SECONDS)
    if _wait_worker_until(worker, term_deadline):
        return cleanup_ok
    if not _signal_worker_group(worker, signal.SIGKILL):
        cleanup_ok = False
    kill_deadline = min(cleanup_deadline, time.monotonic() + KILL_JOIN_SECONDS)
    return _wait_worker_until(worker, kill_deadline) and cleanup_ok


def _run_worker_operation(
    operation: str,
    payload: bytes | None,
    *,
    timeout_seconds: float = SERVICE_OPERATION_TIMEOUT_SECONDS,
) -> bytes | None:
    """Run one operation under one deadline in the static posix-spawned package worker."""

    request = _encode_request(operation, payload)
    started = time.monotonic()
    timeout = min(timeout_seconds, SERVICE_OPERATION_TIMEOUT_SECONDS)
    deadline = started + timeout
    service_deadline = deadline - CLEANUP_RESERVE_SECONDS
    worker: _SpawnedWorker | None = None
    response: bytes | None = None
    dispatched = False
    validated_success = False
    mutating = operation in {"replace_existing", "restore"}
    try:
        try:
            worker = _launch_posix_worker(service_deadline, operation, deadline)
            dispatched = True
            worker.request.send_bytes(request)
            worker.request.close()
            if not worker.response.poll(_remaining(service_deadline, operation)):
                raise _operation_error(CredentialCategory.TIMEOUT, operation)
            response = worker.response.recv_bytes(MAX_RESPONSE_BYTES)
            if not _wait_worker_until(worker, service_deadline):
                raise _operation_error(CredentialCategory.TIMEOUT, operation)

            if not response:
                raise _operation_error(CredentialCategory.STORE_ERROR, operation)
            if (
                response[:1] == b"E"
                and response[1:2] in _CODE_CATEGORIES
                and len(response) == 2
            ):
                raise _operation_error(_CODE_CATEGORIES[response[1:2]], operation)
            if response[:1] != b"O":
                raise _operation_error(CredentialCategory.STORE_ERROR, operation)
            result = response[1:]
            if operation in {"read", "snapshot"}:
                if not result or len(result) > MAX_SECRET_BYTES:
                    raise _operation_error(CredentialCategory.STORE_ERROR, operation)
                validated_success = True
                return result
            if result:
                raise _operation_error(CredentialCategory.STORE_ERROR, operation)
            validated_success = True
            return None
        finally:
            if worker is not None and not _close_spawned_worker(worker, deadline):
                raise _operation_error(CredentialCategory.TIMEOUT, operation) from None
    except CredentialOperationError as error:
        if mutating and not dispatched and error.category is CredentialCategory.TIMEOUT:
            raise _operation_error(
                CredentialCategory.TIMEOUT,
                operation,
                state="unchanged",
                indeterminate=False,
            ) from None
        if mutating and dispatched and not validated_success:
            raise _operation_error(
                error.category,
                operation,
                state="unknown",
                indeterminate=True,
                guidance_id=error.guidance_id,
            ) from None
        raise
    except Exception:  # noqa: BLE001 - process failures are intentionally redacted
        raise _operation_error(
            CredentialCategory.SERVICE_UNAVAILABLE,
            operation,
            state="unknown" if mutating and dispatched else None,
            indeterminate=mutating and dispatched and not validated_success,
        ) from None


class _LinuxSnapshot:
    __slots__ = ("_discarded", "_secret")

    def __init__(self, secret: bytes) -> None:
        self._secret = bytearray(secret)
        self._discarded = False

    @property
    def present(self) -> bool:
        return not self._discarded

    def _copy_secret(self) -> bytes:
        if self._discarded:
            raise _operation_error(CredentialCategory.STORE_ERROR, "restore")
        return bytes(self._secret)

    def _discard(self) -> None:
        if self._discarded:
            return
        for index in range(len(self._secret)):
            self._secret[index] = 0
        self._secret.clear()
        self._discarded = True

    def __repr__(self) -> str:
        return "LinuxCredentialSnapshot(<redacted>)"

    __str__ = __repr__

    def __reduce__(self) -> tuple[Any, ...]:
        raise TypeError("credential snapshots are not serializable")


def _close_descriptor(fd: int) -> None:
    os.close(fd)


class PosixRotationLock(AbstractContextManager["PosixRotationLock"]):
    """Bounded flock anchored to a validated runtime-directory descriptor."""

    def __init__(self, *, timeout: float, runtime_dir: str | Path | None = None) -> None:
        self.timeout = max(0.0, min(float(timeout), DEFAULT_LOCK_TIMEOUT_SECONDS))
        configured = runtime_dir if runtime_dir is not None else os.environ.get("XDG_RUNTIME_DIR")
        if not configured:
            raise _operation_error(CredentialCategory.STORE_ERROR, "lock")
        self.runtime_dir = Path(configured)
        if not self.runtime_dir.is_absolute():
            raise _operation_error(CredentialCategory.STORE_ERROR, "lock")
        self.path = self.runtime_dir / LOCK_FILENAME
        self._dir_fd: int | None = None
        self._fd: int | None = None

    @staticmethod
    def _valid_directory(info: os.stat_result) -> bool:
        return bool(
            stat.S_ISDIR(info.st_mode)
            and info.st_uid == os.geteuid()
            and stat.S_IMODE(info.st_mode) == 0o700
        )

    @staticmethod
    def _valid_private_file(info: os.stat_result) -> bool:
        return bool(
            stat.S_ISREG(info.st_mode)
            and info.st_uid == os.geteuid()
            and stat.S_IMODE(info.st_mode) == 0o600
        )

    def _verify_runtime_identity(self, anchored: os.stat_result) -> None:
        try:
            configured = os.stat(self.runtime_dir, follow_symlinks=False)
        except OSError:
            raise _operation_error(CredentialCategory.STORE_ERROR, "lock") from None
        if (
            not self._valid_directory(configured)
            or configured.st_dev != anchored.st_dev
            or configured.st_ino != anchored.st_ino
        ):
            raise _operation_error(CredentialCategory.STORE_ERROR, "lock")

    def _verify_lock_identity(self, anchored: os.stat_result) -> None:
        if self._dir_fd is None:
            raise _operation_error(CredentialCategory.STORE_ERROR, "lock")
        try:
            configured = os.stat(
                LOCK_FILENAME,
                dir_fd=self._dir_fd,
                follow_symlinks=False,
            )
        except OSError:
            raise _operation_error(CredentialCategory.STORE_ERROR, "lock") from None
        if (
            not self._valid_private_file(configured)
            or configured.st_dev != anchored.st_dev
            or configured.st_ino != anchored.st_ino
        ):
            raise _operation_error(CredentialCategory.STORE_ERROR, "lock")

    def _verify_active_anchor(self) -> os.stat_result:
        if self._dir_fd is None or self._fd is None:
            raise _quarantine_error("quarantine")
        try:
            directory_info = os.fstat(self._dir_fd)
            lock_info = os.fstat(self._fd)
            if not self._valid_directory(directory_info) or not self._valid_private_file(lock_info):
                raise _quarantine_error("quarantine")
            self._verify_runtime_identity(directory_info)
            self._verify_lock_identity(lock_info)
            return directory_info
        except CredentialOperationError:
            raise
        except OSError:
            raise _quarantine_error("quarantine") from None

    @staticmethod
    def _same_file(first: os.stat_result, second: os.stat_result) -> bool:
        return first.st_dev == second.st_dev and first.st_ino == second.st_ino

    def _open_quarantine(self) -> tuple[int, os.stat_result] | None:
        self._verify_active_anchor()
        if self._dir_fd is None:
            raise _quarantine_error("quarantine_check")
        try:
            path_info = os.stat(
                QUARANTINE_FILENAME,
                dir_fd=self._dir_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            return None
        except OSError:
            raise _quarantine_error("quarantine_check") from None
        if not self._valid_private_file(path_info):
            raise _quarantine_error("quarantine_check")

        descriptor: int | None = None
        try:
            descriptor = os.open(
                QUARANTINE_FILENAME,
                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=self._dir_fd,
            )
            anchored = os.fstat(descriptor)
            configured = os.stat(
                QUARANTINE_FILENAME,
                dir_fd=self._dir_fd,
                follow_symlinks=False,
            )
            if (
                not self._valid_private_file(anchored)
                or not self._same_file(path_info, anchored)
                or not self._same_file(anchored, configured)
            ):
                raise _quarantine_error("quarantine_check")
            content = os.read(descriptor, len(QUARANTINE_CONTENT) + 1)
            if content != QUARANTINE_CONTENT:
                raise _quarantine_error("quarantine_check")
            return descriptor, anchored
        except CredentialOperationError:
            if descriptor is not None:
                _close_raw_descriptors(descriptor)
            raise
        except OSError:
            if descriptor is not None:
                _close_raw_descriptors(descriptor)
            raise _quarantine_error("quarantine_check") from None

    def quarantine_present(self) -> bool:
        opened = self._open_quarantine()
        if opened is None:
            return False
        descriptor, _info = opened
        _close_raw_descriptors(descriptor)
        return True

    def _remove_existing_temp(self) -> None:
        if self._dir_fd is None:
            raise _quarantine_error("quarantine_create")
        try:
            path_info = os.stat(
                QUARANTINE_TEMP_FILENAME,
                dir_fd=self._dir_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            return
        except OSError:
            raise _quarantine_error("quarantine_create") from None
        if not self._valid_private_file(path_info):
            raise _quarantine_error("quarantine_create")
        descriptor: int | None = None
        try:
            descriptor = os.open(
                QUARANTINE_TEMP_FILENAME,
                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=self._dir_fd,
            )
            anchored = os.fstat(descriptor)
            configured = os.stat(
                QUARANTINE_TEMP_FILENAME,
                dir_fd=self._dir_fd,
                follow_symlinks=False,
            )
            if (
                not self._valid_private_file(anchored)
                or not self._same_file(path_info, anchored)
                or not self._same_file(anchored, configured)
            ):
                raise _quarantine_error("quarantine_create")
            os.unlink(QUARANTINE_TEMP_FILENAME, dir_fd=self._dir_fd)
            os.fsync(self._dir_fd)
        except CredentialOperationError:
            raise
        except OSError:
            raise _quarantine_error("quarantine_create") from None
        finally:
            if descriptor is not None:
                _close_raw_descriptors(descriptor)

    def create_quarantine(self) -> None:
        if self.quarantine_present():
            return
        self._remove_existing_temp()
        if self._dir_fd is None:
            raise _quarantine_error("quarantine_create")
        descriptor: int | None = None
        anchored: os.stat_result | None = None
        installed = False
        try:
            descriptor = os.open(
                QUARANTINE_TEMP_FILENAME,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                0o600,
                dir_fd=self._dir_fd,
            )
            written = 0
            while written < len(QUARANTINE_CONTENT):
                count = os.write(descriptor, QUARANTINE_CONTENT[written:])
                if count <= 0:
                    raise OSError("quarantine marker write did not progress")
                written += count
            os.fsync(descriptor)
            anchored = os.fstat(descriptor)
            configured = os.stat(
                QUARANTINE_TEMP_FILENAME,
                dir_fd=self._dir_fd,
                follow_symlinks=False,
            )
            if (
                not self._valid_private_file(anchored)
                or not self._same_file(anchored, configured)
            ):
                raise _quarantine_error("quarantine_create")
            self._verify_active_anchor()
            os.replace(
                QUARANTINE_TEMP_FILENAME,
                QUARANTINE_FILENAME,
                src_dir_fd=self._dir_fd,
                dst_dir_fd=self._dir_fd,
            )
            installed = True
            os.fsync(self._dir_fd)
            installed = os.stat(
                QUARANTINE_FILENAME,
                dir_fd=self._dir_fd,
                follow_symlinks=False,
            )
            if not self._same_file(anchored, installed) or not self.quarantine_present():
                raise _quarantine_error("quarantine_create")
        except CredentialOperationError:
            raise
        except OSError:
            raise _quarantine_error("quarantine_create") from None
        finally:
            if descriptor is not None:
                _close_raw_descriptors(descriptor)
            if not installed:
                try:
                    self._remove_existing_temp()
                except CredentialOperationError:
                    pass

    def clear_quarantine(self) -> bool:
        opened = self._open_quarantine()
        if opened is None:
            return False
        descriptor, anchored = opened
        try:
            if self._dir_fd is None:
                raise _quarantine_error("quarantine_clear")
            configured = os.stat(
                QUARANTINE_FILENAME,
                dir_fd=self._dir_fd,
                follow_symlinks=False,
            )
            if not self._same_file(anchored, configured):
                raise _quarantine_error("quarantine_clear")
            os.unlink(QUARANTINE_FILENAME, dir_fd=self._dir_fd)
            os.fsync(self._dir_fd)
            try:
                os.stat(
                    QUARANTINE_FILENAME,
                    dir_fd=self._dir_fd,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                return True
            raise _quarantine_error("quarantine_clear")
        except CredentialOperationError:
            raise
        except OSError:
            raise _quarantine_error("quarantine_clear") from None
        finally:
            _close_raw_descriptors(descriptor)

    def __enter__(self) -> Self:
        directory_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
        file_flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW
        try:
            self._dir_fd = os.open(self.runtime_dir, directory_flags)
            directory_info = os.fstat(self._dir_fd)
            if not self._valid_directory(directory_info):
                raise _operation_error(CredentialCategory.STORE_ERROR, "lock")
            self._verify_runtime_identity(directory_info)

            self._fd = os.open(
                LOCK_FILENAME,
                file_flags,
                0o600,
                dir_fd=self._dir_fd,
            )
            lock_info = os.fstat(self._fd)
            if not self._valid_private_file(lock_info):
                raise _operation_error(CredentialCategory.STORE_ERROR, "lock")
            self._verify_lock_identity(lock_info)
            self._verify_runtime_identity(directory_info)

            deadline = time.monotonic() + self.timeout
            while True:
                try:
                    fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except OSError as error:
                    if error.errno not in {errno.EACCES, errno.EAGAIN}:
                        raise
                    if time.monotonic() >= deadline:
                        raise _operation_error(CredentialCategory.TIMEOUT, "lock")
                    time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))

            self._verify_runtime_identity(directory_info)
            self._verify_lock_identity(lock_info)
            return self
        except CredentialOperationError as error:
            self.__exit__(type(error), error, error.__traceback__)
            raise
        except OSError as error:
            self.__exit__(type(error), error, error.__traceback__)
            raise _operation_error(CredentialCategory.STORE_ERROR, "lock") from None

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        _exc: BaseException | None,
        _traceback: types.TracebackType | None,
    ) -> bool:
        fd = self._fd
        directory_fd = self._dir_fd
        self._fd = None
        self._dir_fd = None
        cleanup_failed = False

        if fd is not None and directory_fd is not None:
            try:
                directory_info = os.fstat(directory_fd)
                lock_info = os.fstat(fd)
                self._dir_fd = directory_fd
                self._verify_runtime_identity(directory_info)
                self._verify_lock_identity(lock_info)
            except (CredentialOperationError, OSError):
                cleanup_failed = True
            finally:
                self._dir_fd = None

        if fd is not None:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                cleanup_failed = True
            try:
                _close_descriptor(fd)
            except OSError:
                cleanup_failed = True

        if directory_fd is not None:
            try:
                _close_descriptor(directory_fd)
            except OSError:
                cleanup_failed = True

        if cleanup_failed and exc_type is None:
            raise _operation_error(CredentialCategory.STORE_ERROR, "lock") from None
        return False


class _BackendRotationLock(AbstractContextManager["_BackendRotationLock"]):
    """Expose one anchored lock to backend operations for the complete transaction."""

    def __init__(self, backend: LinuxCredentialBackend, lock: PosixRotationLock) -> None:
        self._backend = backend
        self._lock = lock

    def __enter__(self) -> Self:
        if self._backend._active_lock is not None:
            raise _operation_error(CredentialCategory.STORE_ERROR, "lock")
        self._lock.__enter__()
        self._backend._active_lock = self._lock
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: types.TracebackType | None,
    ) -> bool:
        try:
            return self._lock.__exit__(exc_type, exc, traceback)
        finally:
            self._backend._active_lock = None


class LinuxCredentialBackend:
    """SecretStorage backend with bounded workers and a durable late-commit fence."""

    def __init__(
        self,
        *,
        operation_runner: OperationRunner = _run_worker_operation,
        runtime_dir: str | Path | None = None,
    ) -> None:
        self._run_operation = operation_runner
        self._runtime_dir = runtime_dir
        self._active_snapshot: _LinuxSnapshot | None = None
        self._pending_verification: _LinuxSnapshot | None = None
        self._active_lock: PosixRotationLock | None = None
        self._transaction_lock: PosixRotationLock | None = None
        self._quarantine_permanent = False

    def _under_lock(self, callback: Callable[[PosixRotationLock], Any]) -> Any:
        active = self._active_lock
        if active is not None:
            return callback(active)
        with self.lock(timeout=DEFAULT_LOCK_TIMEOUT_SECONDS):
            if self._active_lock is None:
                raise _operation_error(CredentialCategory.STORE_ERROR, "lock")
            return callback(self._active_lock)

    def _transaction_may_reconcile(self, lock: PosixRotationLock) -> bool:
        return self._transaction_lock is lock and self._active_snapshot is not None

    def _require_clear_fence(self, lock: PosixRotationLock, operation: str) -> None:
        if not self._transaction_may_reconcile(lock) and lock.quarantine_present():
            raise _quarantine_error(operation)

    @staticmethod
    def _quarantined_error(error: CredentialOperationError) -> CredentialOperationError:
        return CredentialOperationError(
            error.category,
            credential_state="unknown",
            operation=error.operation,
            indeterminate=True,
            guidance_id=LINUX_QUARANTINE_GUIDANCE_ID,
        )

    def _begin_mutation_fence(
        self,
        lock: PosixRotationLock,
        operation: str,
        *,
        allow_permanent: bool = False,
    ) -> bool:
        present = lock.quarantine_present()
        if present:
            if (
                allow_permanent
                and self._quarantine_permanent
                and self._transaction_may_reconcile(lock)
            ):
                return False
            raise _quarantine_error(operation)
        lock.create_quarantine()
        return True

    @staticmethod
    def _finish_mutation_fence(lock: PosixRotationLock, provisional: bool, keep: bool) -> None:
        if provisional and not keep:
            lock.clear_quarantine()

    def availability(self) -> CredentialCategory:
        def available(lock: PosixRotationLock) -> CredentialCategory:
            self._require_clear_fence(lock, "availability")
            self._run_operation("availability", None)
            return CredentialCategory.AVAILABLE

        return self._under_lock(available)

    def read(self) -> str:
        def read_locked(lock: PosixRotationLock) -> str:
            self._require_clear_fence(lock, "read")
            result = self._run_operation("read", None)
            if not isinstance(result, bytes):
                raise _operation_error(CredentialCategory.STORE_ERROR, "read")
            pending = self._pending_verification
            if pending is not None:
                if result != pending._copy_secret():
                    raise _operation_error(CredentialCategory.STORE_ERROR, "read", state="unknown")
                self._pending_verification = None
            try:
                return result.decode("utf-8", "strict")
            except UnicodeDecodeError:
                raise _operation_error(CredentialCategory.STORE_ERROR, "read") from None

        return self._under_lock(read_locked)

    def snapshot(self) -> CredentialSnapshot:
        def snapshot_locked(lock: PosixRotationLock) -> CredentialSnapshot:
            self._require_clear_fence(lock, "snapshot")
            result = self._run_operation("snapshot", None)
            if not isinstance(result, bytes):
                raise _operation_error(CredentialCategory.STORE_ERROR, "snapshot")
            snapshot = _LinuxSnapshot(result)
            self._active_snapshot = snapshot
            self._transaction_lock = lock
            return snapshot

        return self._under_lock(snapshot_locked)

    def replace_existing(self, token: str) -> None:
        if not isinstance(token, str) or not token or "\x00" in token:
            raise _operation_error(CredentialCategory.STORE_ERROR, "replace_existing")
        payload = token.encode("utf-8", "strict")
        if len(payload) > MAX_SECRET_BYTES:
            raise _operation_error(CredentialCategory.STORE_ERROR, "replace_existing")

        def replace_locked(lock: PosixRotationLock) -> None:
            provisional = self._begin_mutation_fence(lock, "replace_existing")
            keep_fence = False
            self._pending_verification = None
            try:
                self._run_operation("replace_existing", payload)
            except CredentialOperationError as error:
                if error.indeterminate:
                    keep_fence = True
                    self._quarantine_permanent = True
                    self._pending_verification = self._active_snapshot
                    raise self._quarantined_error(error) from None
                raise
            finally:
                self._finish_mutation_fence(lock, provisional, keep_fence)

        self._under_lock(replace_locked)

    def restore(self, snapshot: CredentialSnapshot) -> None:
        if not isinstance(snapshot, _LinuxSnapshot):
            raise _operation_error(CredentialCategory.STORE_ERROR, "restore")

        def restore_locked(lock: PosixRotationLock) -> None:
            provisional = self._begin_mutation_fence(
                lock,
                "restore",
                allow_permanent=True,
            )
            keep_fence = self._quarantine_permanent
            self._pending_verification = snapshot
            try:
                self._run_operation("restore", snapshot._copy_secret())
            except CredentialOperationError as error:
                if error.indeterminate:
                    keep_fence = True
                    self._quarantine_permanent = True
                    raise self._quarantined_error(error) from None
                raise
            finally:
                self._finish_mutation_fence(lock, provisional, keep_fence)

        self._under_lock(restore_locked)

    def discard(self, snapshot: CredentialSnapshot) -> None:
        if not isinstance(snapshot, _LinuxSnapshot):
            raise _operation_error(CredentialCategory.STORE_ERROR, "discard")
        if self._active_snapshot is snapshot:
            self._active_snapshot = None
            self._transaction_lock = None
            self._quarantine_permanent = False
        if self._pending_verification is snapshot:
            self._pending_verification = None
        snapshot._discard()

    def quarantine_present(self) -> bool:
        return bool(self._under_lock(lambda lock: lock.quarantine_present()))

    def clear_quarantine(self) -> bool:
        return bool(self._under_lock(lambda lock: lock.clear_quarantine()))

    def lock(self, *, timeout: float) -> AbstractContextManager[object]:
        return _BackendRotationLock(
            self,
            PosixRotationLock(timeout=timeout, runtime_dir=self._runtime_dir),
        )
