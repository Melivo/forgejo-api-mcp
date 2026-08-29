from __future__ import annotations

import os
import secrets
import sys

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or os.getenv("RUN_LINUX_SECRETSERVICE_SMOKE") != "1",
    reason="opt-in isolated Linux Secret Service smoke is disabled",
)


def test_real_secret_service_round_trip_uses_only_a_synthetic_credential() -> None:
    assert os.environ.get("FORGEJO_LIVE_SECRET_SERVICE_ISOLATED") == "1"
    assert os.environ.get("DBUS_SESSION_BUS_ADDRESS")

    import secretstorage

    from forgejo_api_mcp.linux_credentials import (
        CONTENT_TYPE,
        ITEM_ATTRIBUTES,
        ITEM_LABEL,
        LinuxCredentialBackend,
    )

    connection = secretstorage.dbus_init()
    try:
        collection = secretstorage.get_collection_by_alias(connection, "default")
    except secretstorage.exceptions.ItemNotFoundException:
        collection = secretstorage.create_collection(
            connection,
            "Forgejo API MCP isolated smoke",
            alias="default",
        )
    if collection.is_locked():
        collection.unlock()

    assert collection.search_items(dict(ITEM_ATTRIBUTES)) == []
    first = secrets.token_urlsafe(32)
    second = secrets.token_urlsafe(32)
    item = collection.create_item(
        ITEM_LABEL,
        dict(ITEM_ATTRIBUTES),
        first.encode(),
        replace=False,
        content_type=CONTENT_TYPE,
    )
    backend = LinuxCredentialBackend()
    try:
        assert backend.read() == first
        backend.replace_existing(second)
        assert backend.read() == second
    finally:
        item.delete()
