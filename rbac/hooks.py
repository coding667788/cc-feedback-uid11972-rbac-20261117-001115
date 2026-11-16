"""Opt-in synchronization points used by the race tests.

Hooks are *never* enabled unless the server was started with
``RBAC_TEST_HOOKS=1``.  A request may carry
``X-Test-Sync: <key>[:<point>]``:

* with only a key, the request pauses at every sync point it crosses;
* with a point suffix, it pauses only at that named point.

The server writes ``<key>.<point>.paused`` and blocks until
``<key>.<point>.go`` appears (or the timeout expires).  The marker directory is
``RBAC_TEST_HOOK_DIR``.

Markers are ordinary files, so a test can coordinate several independent
service processes without sharing Python objects.
"""

from __future__ import annotations

import os
import re
import tempfile
import time
from pathlib import Path

from .errors import HookTimeout

_KEY_RE = re.compile(r"^[A-Za-z0-9_.-]{1,80}$")
_SYNC_RE = re.compile(r"^(?P<key>[A-Za-z0-9_.-]{1,80})(?::(?P<point>[A-Za-z0-9_.-]{1,80}))?$")


class TestHooks:
    def __init__(self) -> None:
        self.enabled = os.environ.get("RBAC_TEST_HOOKS") == "1"
        directory = os.environ.get("RBAC_TEST_HOOK_DIR")
        self.directory = Path(directory) if directory else Path(tempfile.gettempdir()) / "rbac-hooks"
        if self.enabled:
            self.directory.mkdir(parents=True, exist_ok=True)
        self.timeout = float(os.environ.get("RBAC_TEST_HOOK_TIMEOUT", "30"))

    @staticmethod
    def parse_sync(value: str | None) -> tuple[str, str | None] | None:
        if not value:
            return None
        match = _SYNC_RE.match(value)
        if match is None:
            return None
        return match.group("key"), match.group("point")

    def sync(self, point: str, spec: tuple[str, str | None] | None) -> None:
        """Block at ``point`` for this request, if hooks are enabled."""
        if not self.enabled or spec is None:
            return
        key, only_point = spec
        if only_point is not None and only_point != point:
            return
        marker = self.directory / f"{key}.{point}.paused"
        resume = self.directory / f"{key}.{point}.go"
        payload = f"pid={os.getpid()}\ntime={time.time()}\n".encode("utf-8")
        deadline = time.monotonic() + self.timeout

        # Windows can briefly hold handles created by another process; retry
        # transient sharing violations instead of surfacing a 500.
        while True:
            try:
                marker.write_bytes(payload)
                break
            except OSError:
                if time.monotonic() >= deadline:
                    raise HookTimeout(
                        f"test hook could not create marker at {point}",
                        key=key,
                        point=point,
                    )
                time.sleep(0.01)

        while time.monotonic() < deadline:
            try:
                if resume.exists():
                    try:
                        resume.unlink()
                    except FileNotFoundError:
                        pass
                    except OSError:
                        # another process deleted it first; that counts as a go
                        pass
                    return
            except OSError:
                pass
            time.sleep(0.01)
        raise HookTimeout(f"test hook timed out at {point}", key=key, point=point)
