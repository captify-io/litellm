import json
import os
import sqlite3
import time
from collections.abc import Callable, Generator
from contextlib import closing, contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

from .base_cache import BaseCache

if TYPE_CHECKING:
    from opentelemetry.trace import Span as _Span

    Span = _Span | Any
else:
    Span = Any


class _JsonDiskStore:
    def __init__(self, directory: str, *, clock: Callable[[], float] = time.time, size_limit: int = 2**30) -> None:
        root: Final = os.path.realpath(os.environ.get("LITELLM_DISK_CACHE_ROOT", os.getcwd()))
        resolved: Final = os.path.realpath(os.path.join(root, directory))
        if resolved != root and not resolved.startswith(root.rstrip(os.sep) + os.sep):
            raise ValueError("Disk cache directory must remain inside LITELLM_DISK_CACHE_ROOT")
        self.directory = Path(resolved)
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.path = self.directory / "litellm-json-cache.sqlite3"
        if self.path.is_symlink():
            raise ValueError("Disk cache database must not be a symbolic link")
        try:
            descriptor: Final = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
        except FileExistsError:
            pass
        else:
            os.close(descriptor)
        self.clock = clock
        self.size_limit = size_limit
        with self._transaction() as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS cache "
                "(key TEXT PRIMARY KEY, value TEXT NOT NULL, expires REAL, size INTEGER NOT NULL, updated REAL NOT NULL)"
            )

    @contextmanager
    def _transaction(self) -> Generator[sqlite3.Connection, None, None]:
        with closing(sqlite3.connect(self.path, timeout=60, isolation_level=None)) as connection:
            connection.execute("PRAGMA trusted_schema = OFF")
            connection.execute("BEGIN IMMEDIATE")
            try:
                yield connection
                connection.commit()
            except BaseException:
                connection.rollback()
                raise

    @staticmethod
    def _read(connection: sqlite3.Connection, key: str, now: float) -> object:
        row: Final = connection.execute(
            "SELECT value FROM cache WHERE key = ? AND (expires IS NULL OR expires > ?)", (key, now)
        ).fetchone()
        if row is None:
            return None
        try:
            return json.loads(row[0])
        except (ValueError, TypeError):
            return None

    def _write(self, connection: sqlite3.Connection, key: str, value: object, now: float, expire: float | None) -> None:
        encoded: Final = json.dumps(value, ensure_ascii=True, separators=(",", ":"))
        size: Final = len(key.encode("utf-8")) + len(encoded)
        connection.execute("DELETE FROM cache WHERE expires <= ? OR key = ?", (now, key))
        if size > self.size_limit:
            return
        connection.execute(
            "INSERT INTO cache(key, value, expires, size, updated) VALUES (?, ?, ?, ?, ?)",
            (key, encoded, None if expire is None else now + expire, size, now),
        )
        while connection.execute("SELECT COALESCE(SUM(size), 0) FROM cache").fetchone()[0] > self.size_limit:
            connection.execute("DELETE FROM cache WHERE key = (SELECT key FROM cache ORDER BY updated, rowid LIMIT 1)")

    def set(self, key: str, value: object, expire: float | None = None) -> None:
        with self._transaction() as connection:
            self._write(connection, key, value, self.clock(), expire)

    def get(self, key: str) -> object:
        with closing(sqlite3.connect(self.path, timeout=60)) as connection:
            connection.execute("PRAGMA trusted_schema = OFF")
            return self._read(connection, key, self.clock())

    def increment(self, key: str, value: int, expire: float | None = None) -> int:
        with self._transaction() as connection:
            now: Final = self.clock()
            cached: Final = self._read(connection, key, now)
            decoded: Final = _decode_response(cached)
            result: Final = (decoded if isinstance(decoded, int) else 0) + value
            self._write(connection, key, result, now, expire)
            return result

    def clear(self) -> None:
        with self._transaction() as connection:
            connection.execute("DELETE FROM cache")

    def pop(self, key: str) -> None:
        with self._transaction() as connection:
            connection.execute("DELETE FROM cache WHERE key = ?", (key,))


def _decode_response(value: object) -> object:
    if not isinstance(value, str):
        return value
    try:
        return json.loads(value)
    except ValueError:
        return value


class DiskCache(BaseCache):
    def __init__(self, disk_cache_dir: str | None = None):
        super().__init__()
        self.disk_cache = _JsonDiskStore(disk_cache_dir or ".litellm_cache")

    def set_cache(self, key, value, **kwargs):
        if "ttl" in kwargs:
            self.disk_cache.set(key, value, expire=kwargs["ttl"])
        else:
            self.disk_cache.set(key, value)

    async def async_set_cache(self, key, value, **kwargs):
        self.set_cache(key=key, value=value, **kwargs)

    async def async_set_cache_pipeline(self, cache_list, **kwargs):
        for cache_key, cache_value in cache_list:
            if "ttl" in kwargs:
                self.set_cache(key=cache_key, value=cache_value, ttl=kwargs["ttl"])
            else:
                self.set_cache(key=cache_key, value=cache_value)

    def get_cache(self, key, **kwargs):
        original_cached_response: Final = self.disk_cache.get(key)
        if original_cached_response:
            return _decode_response(original_cached_response)
        return None

    def batch_get_cache(self, keys: list, **kwargs):
        return_val: Final = []
        for k in keys:
            val = self.get_cache(key=k, **kwargs)
            return_val.append(val)
        return return_val

    def increment_cache(self, key, value: int, **kwargs) -> int:
        return self.disk_cache.increment(key, value, expire=kwargs.get("ttl"))

    async def async_get_cache(self, key, **kwargs):
        return self.get_cache(key=key, **kwargs)

    async def async_batch_get_cache(self, keys: list, **kwargs):
        return_val: Final = []
        for k in keys:
            val = self.get_cache(key=k, **kwargs)
            return_val.append(val)
        return return_val

    async def async_increment(self, key, value: int, **kwargs) -> int:
        return self.increment_cache(key=key, value=value, **kwargs)

    def flush_cache(self):
        self.disk_cache.clear()

    async def disconnect(self):
        pass

    def delete_cache(self, key):
        self.disk_cache.pop(key)
