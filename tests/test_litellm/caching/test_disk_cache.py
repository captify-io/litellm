import threading
import time
import sqlite3
from concurrent.futures import ThreadPoolExecutor

import pytest

from litellm.caching.disk_cache import DiskCache, _JsonDiskStore


@pytest.fixture(autouse=True)
def cache_root(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("LITELLM_DISK_CACHE_ROOT", raising=False)


class _SlowInt(int):
    def __add__(self, value: int) -> "_SlowInt":
        time.sleep(0.05)
        return _SlowInt(int(self) + value)


@pytest.fixture
def cache(tmp_path):
    return DiskCache(disk_cache_dir=str(tmp_path))


def test_increment_cache_starts_from_zero_when_key_missing(cache):
    assert cache.increment_cache("counter", 3) == 3
    assert cache.get_cache("counter") == 3


def test_increment_cache_adds_to_existing_int(cache):
    cache.set_cache("counter", 7)
    assert cache.increment_cache("counter", 5) == 12
    assert cache.get_cache("counter") == 12


def test_increment_cache_treats_non_int_cached_value_as_zero(cache):
    cache.set_cache("counter", "not-a-number")
    assert cache.increment_cache("counter", 4) == 4
    assert cache.get_cache("counter") == 4


def test_increment_cache_is_atomic_under_thread_concurrency(cache):
    seed = 1000
    cache.set_cache("counter", _SlowInt(seed))
    thread_count = 8
    barrier = threading.Barrier(thread_count)

    def increment(_: int) -> int:
        barrier.wait()
        return cache.increment_cache("counter", 1)

    with ThreadPoolExecutor(max_workers=thread_count) as executor:
        tuple(executor.map(increment, range(thread_count)))

    assert cache.get_cache("counter") == seed + thread_count


async def test_async_increment_starts_from_zero_when_key_missing(cache):
    assert await cache.async_increment("counter", 2) == 2


async def test_async_increment_adds_to_existing_int(cache):
    await cache.async_set_cache("counter", 10)
    assert await cache.async_increment("counter", 5) == 15


async def test_async_increment_treats_non_int_cached_value_as_zero(cache):
    await cache.async_set_cache("counter", "corrupt")
    assert await cache.async_increment("counter", 9) == 9


def test_cache_survives_reopening_and_decodes_response_json(tmp_path):
    first = DiskCache(str(tmp_path))
    first.set_cache("response", '{"choices":[{"message":{"content":"hello"}}]}')
    reopened = DiskCache(str(tmp_path))
    assert reopened.get_cache("response") == {"choices": [{"message": {"content": "hello"}}]}
    reopened.delete_cache("response")
    assert first.get_cache("response") is None


def test_expired_entry_is_absent_and_increment_restarts(tmp_path):
    now = [100.0]
    store = _JsonDiskStore(str(tmp_path), clock=lambda: now[0])
    store.set("counter", 8, expire=10)
    store.set("durable", {"valid": True})
    now[0] = 110.0
    assert store.get("counter") is None
    assert store.increment("counter", 2, expire=5) == 2
    now[0] = 115.0
    assert store.get("counter") is None
    assert store.get("durable") == {"valid": True}
    store.clear()
    assert store.get("durable") is None


def test_increment_is_atomic_across_independent_store_connections(tmp_path):
    stores = tuple(_JsonDiskStore(str(tmp_path)) for _ in range(8))
    barrier = threading.Barrier(len(stores))

    def increment(store):
        barrier.wait()
        for _ in range(30):
            store.increment("counter", 1)

    with ThreadPoolExecutor(max_workers=len(stores)) as executor:
        tuple(executor.map(increment, stores))
    assert stores[0].get("counter") == 240


def test_tampered_cache_content_is_never_unpickled(tmp_path):
    marker = tmp_path / "executed"
    payload = f"cos\nsystem\n(S'touch {marker}'\ntR."
    store = _JsonDiskStore(str(tmp_path))
    store.set("response", "safe")
    with sqlite3.connect(store.path) as connection:
        connection.execute("UPDATE cache SET value = ? WHERE key = ?", (payload, "response"))
    assert store.get("response") is None
    assert not marker.exists()


def test_legacy_pickle_database_is_not_opened(tmp_path):
    legacy = tmp_path / "cache.db"
    legacy.write_bytes(b"legacy pickle database must remain untouched")
    cache = DiskCache(str(tmp_path))
    cache.set_cache("fresh", {"message": "safe"})
    assert cache.get_cache("fresh") == {"message": "safe"}
    assert legacy.read_bytes() == b"legacy pickle database must remain untouched"


def test_size_limit_evicts_oldest_entries_and_refuses_oversized_values(tmp_path):
    now = [1.0]
    store = _JsonDiskStore(str(tmp_path), clock=lambda: now[0], size_limit=16)
    store.set("a", "12345")
    now[0] = 2.0
    store.set("b", "12345")
    now[0] = 3.0
    store.set("c", "12345")
    assert store.get("a") is None
    assert store.get("b") == "12345"
    assert store.get("c") == "12345"
    store.set("c", "x" * 17)
    assert store.get("c") is None


@pytest.mark.parametrize("value,expected", [(" 4 ", 6), ("-01", 2), ("null", 2), ("true", 3)])
def test_increment_retains_json_string_value_semantics(cache, value, expected):
    cache.set_cache("counter", value)
    assert cache.increment_cache("counter", 2) == expected


def test_new_cache_files_are_private(tmp_path):
    store = _JsonDiskStore(str(tmp_path / "private"))
    assert store.path.stat().st_mode & 0o777 == 0o600
    assert store.directory.stat().st_mode & 0o777 == 0o700


async def test_pipeline_and_batch_reads_keep_order(cache):
    await cache.async_set_cache_pipeline([("a", {"answer": 42}), ("b", "plain")])
    assert await cache.async_batch_get_cache(["b", "missing", "a"]) == ["plain", None, {"answer": 42}]
    assert cache.batch_get_cache(["a", "b"]) == [{"answer": 42}, "plain"]


def test_objects_requiring_pickle_are_rejected_without_serializing(cache):
    class PickleOnly:
        def __reduce__(self):
            raise AssertionError("must not call a pickle hook")

    with pytest.raises(TypeError, match="JSON serializable"):
        cache.set_cache("unsupported", PickleOnly())


@pytest.mark.parametrize("relative", [True, False])
def test_cache_rejects_paths_outside_the_operator_root(tmp_path, relative):
    outside = tmp_path.parent / f"{tmp_path.name}-outside"
    directory = f"../{outside.name}" if relative else str(outside)
    with pytest.raises(ValueError, match="inside LITELLM_DISK_CACHE_ROOT"):
        DiskCache(directory)
    assert not outside.exists()


def test_operator_root_accepts_normalized_descendants(tmp_path, monkeypatch):
    root = tmp_path / "persistent"
    monkeypatch.setenv("LITELLM_DISK_CACHE_ROOT", str(root))
    cache = DiskCache("tenant/../tenant/responses")
    cache.set_cache("response", {"answer": 42})
    assert cache.disk_cache.directory == root / "tenant/responses"
    assert DiskCache(str(root / "tenant/responses")).get_cache("response") == {"answer": 42}


def test_cache_rejects_directory_symlinks_leaving_the_root(tmp_path, monkeypatch):
    root = tmp_path / "allowed"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (root / "linked").symlink_to(outside, target_is_directory=True)
    monkeypatch.setenv("LITELLM_DISK_CACHE_ROOT", str(root))
    with pytest.raises(ValueError, match="inside LITELLM_DISK_CACHE_ROOT"):
        DiskCache("linked")
    assert not (outside / "litellm-json-cache.sqlite3").exists()


def test_cache_rejects_a_symlinked_database_without_changing_its_target(tmp_path):
    target = tmp_path / "protected"
    target.write_bytes(b"leave this untouched")
    (tmp_path / "litellm-json-cache.sqlite3").symlink_to(target)
    with pytest.raises(ValueError, match="must not be a symbolic link"):
        DiskCache(str(tmp_path))
    assert target.read_bytes() == b"leave this untouched"


def test_disk_cache_initializes_the_base_ttl(cache):
    assert cache.get_ttl(ttl="invalid") == 60
