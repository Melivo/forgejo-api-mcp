"""Static package-owned SecretStorage worker process entry point."""

from __future__ import annotations

from .linux_credentials import worker_entrypoint


def main() -> int:
    return worker_entrypoint()


if __name__ == "__main__":
    raise SystemExit(main())
