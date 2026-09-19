# Caching on LiteLLM

LiteLLM supports multiple caching mechanisms. This allows users to choose the most suitable caching solution for their use case.

The following caching mechanisms are supported:

1. **RedisCache**
2. **RedisSemanticCache**
3. **QdrantSemanticCache**
4. **InMemoryCache**
5. **DiskCache**
6. **S3Cache**
7. **AzureBlobCache**
8. **DualCache** (updates both Redis and an in-memory cache simultaneously)

Disk caching stores JSON-compatible responses in SQLite using only the Python standard library
The `caching` installation extra remains accepted and no longer installs `diskcache`
Existing pickle-backed cache files are left untouched and are not read or migrated; the first
request after upgrading is a cache miss and repopulates `litellm-json-cache.sqlite3`
Expiry, atomic counters, batch reads and the 1 GiB serialized-content limit remain supported
Arbitrary Python objects are not accepted as cache values

Disk cache paths must stay inside `LITELLM_DISK_CACHE_ROOT`, which defaults to the
process working directory. Set this environment variable to an operator-owned cache
volume before using an absolute directory outside the working directory. Relative
paths are resolved beneath that root. Parent traversal, symlink escapes and symlinked
database files are rejected before cache writes

## Folder Structure

```
litellm/caching/
├── base_cache.py
├── caching.py
├── caching_handler.py
├── disk_cache.py
├── dual_cache.py
├── in_memory_cache.py
├── qdrant_semantic_cache.py
├── redis_cache.py
├── redis_semantic_cache.py
├── s3_cache.py
```

## Documentation
- [Caching on LiteLLM Gateway](https://docs.litellm.ai/docs/proxy/caching)
- [Caching on LiteLLM Python](https://docs.litellm.ai/docs/caching/all_caches)




