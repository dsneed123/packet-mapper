"""Bounded LRU cache with per-entry TTL for module-level singletons."""

import time
from collections import OrderedDict
from typing import Any

MAX_SIZE = 5_000
TTL = 3600.0  # seconds


class _BoundedCache:
    """LRU cache capped at *max_size* entries with per-entry *ttl* (seconds)."""

    def __init__(self, max_size: int = MAX_SIZE, ttl: float = TTL) -> None:
        self._max_size = max_size
        self._ttl = ttl
        self._store: OrderedDict[str, tuple[Any, float]] = OrderedDict()

    def __contains__(self, key: str) -> bool:
        if key not in self._store:
            return False
        _, ts = self._store[key]
        if time.monotonic() - ts > self._ttl:
            del self._store[key]
            return False
        return True

    def __getitem__(self, key: str) -> Any:
        value, _ = self._store[key]
        return value

    def __setitem__(self, key: str, value: Any) -> None:
        self._store.pop(key, None)
        self._store[key] = (value, time.monotonic())
        while len(self._store) > self._max_size:
            self._store.popitem(last=False)

    def pop(self, key: str, *args: Any) -> Any:
        if key in self._store:
            value, _ = self._store.pop(key)
            return value
        if args:
            return args[0]
        raise KeyError(key)
