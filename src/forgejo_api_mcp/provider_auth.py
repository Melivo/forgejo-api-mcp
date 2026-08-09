"""Provider authentication classification for Forgejo access tokens.

Two entry points share one status vocabulary:

* :func:`classify_token` performs a bounded, redirect-disabled HTTPS ``GET /api/v1/user``
  with a candidate token and classifies the outcome (used by the rotation CLI before any
  credential is written).
Neither function ever returns or raises the raw token, the ``Authorization`` header value,
or the response body. Authentication is classified from the HTTP status only; the body is
closed without being consumed or parsed.
"""

from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass
from typing import Any
from urllib.parse import urlsplit

import httpx

from .errors import InputValidationError

DEFAULT_TIMEOUT_SECONDS = 30.0
USER_PATH_SUFFIX = "/api/v1"

AUTHENTICATED = "authenticated"
CREDENTIAL_REJECTED = "credential_rejected"
FORBIDDEN = "forbidden"
PROVIDER_ERROR = "provider_error"
TRANSPORT = "transport"
TIMEOUT = "timeout"
INSECURE_BASE_URL = "insecure_base_url"


@dataclass(frozen=True)
class ProviderAuthResult:
    status: str
    status_code: int
    detail: str

    def to_dict(self) -> dict[str, Any]:
        redacted = asdict(self)
        return redacted


def _validation_url(base_url: str) -> str:
    if not isinstance(base_url, str) or not base_url.strip():
        raise InputValidationError("base_url must be a non-empty string")
    normalized = base_url.strip().rstrip("/")
    if normalized.casefold().endswith(USER_PATH_SUFFIX):
        return f"{normalized}/user"
    return f"{normalized}{USER_PATH_SUFFIX}/user"


def _map_http_failure(status_code: int) -> ProviderAuthResult:
    if status_code == 401:
        return ProviderAuthResult(CREDENTIAL_REJECTED, 401, "Forgejo rejected the token (401)")
    if status_code == 403:
        return ProviderAuthResult(FORBIDDEN, 403, "Forgejo forbade the request (403)")
    return ProviderAuthResult(PROVIDER_ERROR, status_code, f"Forgejo returned HTTP {status_code}")


async def classify_token(
    token: str,
    *,
    base_url: str,
    transport: httpx.AsyncBaseTransport | None = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> ProviderAuthResult:
    """Classify ``token`` against ``GET {base_url}/api/v1/user`` without persisting it."""

    if not isinstance(base_url, str) or not base_url.strip():
        raise InputValidationError("base_url must be a non-empty string")
    if urlsplit(base_url.strip()).scheme.casefold() != "https":
        return ProviderAuthResult(
            INSECURE_BASE_URL, 0, "Forgejo authentication probes require an HTTPS base URL"
        )
    if not isinstance(token, str) or not token or "\r" in token or "\n" in token:
        raise InputValidationError("token must be a non-empty single-line string")
    bounded_timeout = max(0.001, min(float(timeout), DEFAULT_TIMEOUT_SECONDS))
    request_url = _validation_url(base_url)
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/json",
        "Accept-Encoding": "identity",
    }
    try:
        async with asyncio.timeout(bounded_timeout):
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(bounded_timeout),
                follow_redirects=False,
                transport=transport,
                trust_env=False,
            ) as client:
                async with client.stream("GET", request_url, headers=headers) as response:
                    status_code = response.status_code
    except (TimeoutError, httpx.TimeoutException):
        return ProviderAuthResult(TIMEOUT, 0, "Forgejo validation request timed out")
    except httpx.TransportError:
        return ProviderAuthResult(TRANSPORT, 0, "Forgejo validation request failed before a response")
    if status_code == 200:
        return ProviderAuthResult(AUTHENTICATED, 200, "token authenticated")
    return _map_http_failure(status_code)


def classify_invoke_result(result: dict[str, Any]) -> ProviderAuthResult:
    """Map a legacy invoke result without exposing response content (compatibility helper)."""

    status_code = int(result.get("status_code") or 0)
    if result.get("ok"):
        return ProviderAuthResult(AUTHENTICATED, status_code, "token authenticated")
    raw_error = result.get("error")
    error: dict[str, Any] = raw_error if isinstance(raw_error, dict) else {}
    kind = error.get("kind")
    if kind == "timeout":
        return ProviderAuthResult(TIMEOUT, status_code, "Forgejo probe timed out")
    if kind == "transport":
        return ProviderAuthResult(TRANSPORT, status_code, "Forgejo probe failed before a response")
    return _map_http_failure(status_code)
