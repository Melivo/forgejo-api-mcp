"""Narrow, platform-neutral credential persistence boundary.

The boundary intentionally has no generic create, write, or delete capability. Platform
selection happens only in :func:`select_credential_backend` and unsupported systems fail closed.
"""

from __future__ import annotations

import sys
from contextlib import AbstractContextManager
from enum import StrEnum
from typing import Protocol, runtime_checkable

from .errors import ForgejoMCPError

TARGET_NAME = "mcp/forgejo-mcp/access-token"
LINUX_GUIDANCE_ID = "linux_secret_service_setup"
LINUX_QUARANTINE_GUIDANCE_ID = "linux_secret_service_quarantine"


class CredentialCategory(StrEnum):
    AVAILABLE = "available"
    MISSING = "missing"
    LOCKED = "locked"
    PROMPT_REQUIRED = "prompt_required"
    PROMPT_DISMISSED = "prompt_dismissed"
    TIMEOUT = "timeout"
    SERVICE_UNAVAILABLE = "service_unavailable"
    STORE_ERROR = "store_error"


class PlatformUnsupported(ForgejoMCPError):
    """Raised when no credential backend is allowed for the current platform."""


class CredentialBackendError(ForgejoMCPError):
    """Internal adapter failure that concrete backends must normalize."""


class CredentialOperationError(ForgejoMCPError):
    """Stable, redacted failure crossing the platform credential boundary."""

    def __init__(
        self,
        category: CredentialCategory,
        *,
        credential_state: str,
        operation: str,
        indeterminate: bool = False,
        guidance_id: str | None = None,
    ) -> None:
        self.category = category
        self.credential_state = credential_state
        self.operation = operation
        self.indeterminate = indeterminate
        self.guidance_id = guidance_id
        super().__init__(f"credential operation failed: {category.value}")

    def __repr__(self) -> str:
        return (
            "CredentialOperationError("
            f"category={self.category.value!r}, credential_state={self.credential_state!r}, "
            f"operation={self.operation!r}, indeterminate={self.indeterminate!r})"
        )


@runtime_checkable
class CredentialSnapshot(Protocol):
    """Opaque rollback state; common code may inspect only presence."""

    @property
    def present(self) -> bool: ...


@runtime_checkable
class CredentialBackend(Protocol):
    """The complete credential-store capability exposed to common rotation."""

    def availability(self) -> CredentialCategory: ...

    def read(self) -> str:
        """Read the secret; after an indeterminate write, confirm the active opaque snapshot.

        A backend with an active indeterminate-write reconciliation must raise a stable
        ``CredentialOperationError`` unless both prior secret and backend-owned metadata match.
        Snapshot contents remain inaccessible to the common rotation layer.
        """

        ...

    def snapshot(self) -> CredentialSnapshot: ...

    def replace_existing(self, token: str) -> None: ...

    def restore(self, snapshot: CredentialSnapshot) -> None: ...

    def discard(self, snapshot: CredentialSnapshot) -> None: ...

    def lock(self, *, timeout: float) -> AbstractContextManager[object]: ...


@runtime_checkable
class QuarantineBackend(Protocol):
    """Secret-free quarantine administration supported by selected backends."""

    def quarantine_present(self) -> bool: ...

    def clear_quarantine(self) -> bool: ...


def select_credential_backend(*, platform: str | None = None) -> CredentialBackend:
    """Select one explicit platform adapter, or fail closed."""

    selected = sys.platform if platform is None else platform
    if selected == "win32":
        from .credentials import WindowsCredentialBackend

        return WindowsCredentialBackend()
    if selected == "linux":
        from .linux_credentials import LinuxCredentialBackend

        return LinuxCredentialBackend()
    raise PlatformUnsupported("credential backend is unsupported on this platform")


def select_quarantine_backend(*, platform: str | None = None) -> QuarantineBackend:
    """Select a backend with quarantine administration, or fail closed."""

    backend = select_credential_backend(platform=platform)
    if isinstance(backend, QuarantineBackend):
        return backend
    raise PlatformUnsupported("credential backend is unsupported on this platform")
