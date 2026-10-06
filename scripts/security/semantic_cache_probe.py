"""Exercise installed CVE-2026-89032 fixes without a provider, database, or server."""

import asyncio
import hashlib
import importlib
import importlib.metadata
import itertools
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Final
from unittest.mock import patch

SOURCE_HASHES: Final = {
    "litellm/caching/caching.py": "f27189528a4c5fbf6910ad1ceaf422c794666541d25a0d5686b65e9ee7862ccc",
    "litellm/proxy/litellm_pre_call_utils.py": "0f2815d73f139228a0e685e64d84c4d2869be0733bfd97ab205bfe88bb1dffec",
}
VERSION: Final = "1.100.0"
PATHS: Final = ("/v1/chat/completions", "/v1/responses", "/v1/messages", "/bedrock/model/test/converse")


def installed_files() -> dict[str, str]:
    distribution: Final = importlib.metadata.distribution("litellm")
    if distribution.version != VERSION:
        raise ValueError("The reviewed backport applies only to LiteLLM 1.100.0")
    for relative, digest in SOURCE_HASHES.items():
        module: Final = importlib.import_module(relative[:-3].replace("/", "."))
        expected: Final = Path(distribution.locate_file(relative)).resolve(strict=True)
        actual: Final = Path(module.__file__).resolve(strict=True)
        if expected != actual or hashlib.sha256(actual.read_bytes()).hexdigest() != digest:
            raise ValueError("Installed module differs from the reviewed distribution and source")
    return {relative: str(Path(distribution.locate_file(relative)).resolve()) for relative in SOURCE_HASHES}


async def behavior() -> dict[str, int]:
    from fastapi import Request

    from litellm.caching.caching import Cache
    from litellm.proxy._types import UserAPIKeyAuth
    from litellm.proxy.litellm_pre_call_utils import add_litellm_data_to_request
    from litellm.proxy.proxy_server import ProxyConfig
    from litellm.types.caching import LiteLLMCacheType

    for kind, metadata_name, nested, field in itertools.product(
        (LiteLLMCacheType.REDIS_SEMANTIC, LiteLLMCacheType.VALKEY_SEMANTIC, LiteLLMCacheType.QDRANT_SEMANTIC),
        ("metadata", "litellm_metadata"),
        (False, True),
        ("user_api_key", "user_api_key_team_id", "user_api_key_org_id"),
    ):
        cache: Final = Cache(type=LiteLLMCacheType.LOCAL)
        cache.type = kind
        scopes: Final = tuple({metadata_name: {field: identity}} for identity in ("tenant-a", "tenant-b", "tenant-a"))
        keys: Final = tuple(
            cache.get_cache_key(
                model="synthetic-model",
                input="Synthetic private question",
                **({"litellm_params": scope} if nested else scope),
            )
            for scope in scopes
        )
        if keys[0] == keys[1] or keys[0] != keys[2]:
            raise ValueError("Semantic cache does not isolate authenticated tenant scopes")

    for path, string_metadata in itertools.product(PATHS, (False, True)):
        request: Final = Request(
            {
                "type": "http",
                "method": "POST",
                "scheme": "http",
                "path": path,
                "query_string": b"",
                "headers": [],
                "server": ("synthetic.invalid", 80),
                "client": ("127.0.0.1", 1234),
            }
        )
        cache: Final = Cache(type=LiteLLMCacheType.LOCAL)
        cache.type = LiteLLMCacheType.VALKEY_SEMANTIC

        async def key(identity: str, current_request: Request, current_cache: Cache, as_string: bool) -> str:
            forged: Final = {"user_api_key": "forged-victim", "trace": "synthetic-trace"}
            data: Final = await add_litellm_data_to_request(
                data={
                    "model": "synthetic-model",
                    "input": "Synthetic private question",
                    "metadata": json.dumps(forged) if as_string else dict(forged),
                    "litellm_metadata": json.dumps(forged) if as_string else dict(forged),
                },
                request=current_request,
                user_api_key_dict=UserAPIKeyAuth(api_key=identity),
                proxy_config=ProxyConfig(),
                general_settings={},
                version="backport-proof",
            )
            return current_cache.get_cache_key(**data)

        first: Final = await key("synthetic-authenticated-a", request, cache, string_metadata)
        if first == await key("synthetic-authenticated-b", request, cache, string_metadata) or first != await key(
            "synthetic-authenticated-a", request, cache, string_metadata
        ):
            raise ValueError("Client metadata can shadow the authenticated route identity")

    shared: Final = Cache(type=LiteLLMCacheType.LOCAL)
    shared.type = LiteLLMCacheType.VALKEY_SEMANTIC
    shared_keys: Final = tuple(
        shared.get_cache_key(
            model="synthetic-model", metadata={"user_api_key": "shared-key", "user_api_key_end_user_id": user}
        )
        for user in ("alice", "bob")
    )
    if shared_keys[0] != shared_keys[1]:
        raise ValueError("Backport changed the existing shared-key semantics")
    await verify_http_cache_overrides()
    return {"tenantScopeCases": 36, "authenticatedRouteCases": 8, "sharedKeyCases": 1, "httpCacheOverrideCases": 8}


async def verify_http_cache_overrides() -> None:
    from fastapi import Request

    import litellm
    from litellm.caching.caching import Cache
    from litellm.caching.caching_handler import LLMCachingHandler
    from litellm.proxy._types import UserAPIKeyAuth
    from litellm.proxy.litellm_pre_call_utils import add_litellm_data_to_request
    from litellm.proxy.proxy_server import ProxyConfig
    from litellm.types.caching import LiteLLMCacheType

    def refuse_model(**_kwargs: object) -> None:
        raise ValueError("The installed cache proof must not call a model")

    for path, nested in itertools.product(PATHS, (False, True)):
        request: Final = Request(
            {
                "type": "http",
                "method": "POST",
                "scheme": "http",
                "path": path,
                "query_string": b"",
                "headers": [],
                "server": ("synthetic.invalid", 80),
                "client": ("127.0.0.1", 1234),
            }
        )
        cache: Final = Cache(type=LiteLLMCacheType.LOCAL)
        cache.type = LiteLLMCacheType.VALKEY_SEMANTIC

        async def key(identity: str, current_request: Request, nested_override: bool) -> str:
            override: Final = (
                {"litellm_params": {"preset_cache_key": "forged-shared", "metadata": {"trace_id": "retained"}}}
                if nested_override
                else {"cache_key": "forged-shared"}
            )
            data: Final = await add_litellm_data_to_request(
                data={"model": "synthetic-model", "messages": [{"role": "user", "content": "same"}], **override},
                request=current_request,
                user_api_key_dict=UserAPIKeyAuth(api_key=identity),
                proxy_config=ProxyConfig(),
                general_settings={},
                version="backport-proof",
            )
            if nested_override and data.get("litellm_params") != {"metadata": {"trace_id": "retained"}}:
                raise ValueError("HTTP cache sanitization lost unrelated nested parameters")
            handler: Final = LLMCachingHandler(
                original_function=refuse_model, request_kwargs=data, start_time=datetime.now()
            )
            await handler._retrieve_from_cache(call_type="acompletion", kwargs=data, args=())
            if handler.preset_cache_key is None or handler.preset_cache_key == "forged-shared":
                raise ValueError("HTTP cache override bypassed authenticated scope")
            return handler.preset_cache_key

        with patch.object(litellm, "cache", cache):
            first: Final = await key("synthetic-authenticated-a", request, nested)
            if first == await key("synthetic-authenticated-b", request, nested) or first != await key(
                "synthetic-authenticated-a", request, nested
            ):
                raise ValueError("HTTP cache overrides do not isolate authenticated identities")


def main() -> None:
    files: Final = installed_files()
    cases: Final = asyncio.run(behavior())
    if installed_files() != files:
        raise ValueError("Installed source changed during the proof")
    sys.stdout.write(
        json.dumps(
            {"version": VERSION, "sourceSha256": SOURCE_HASHES, "installedPaths": files, "cases": cases}, sort_keys=True
        )
        + "\n"
    )


if __name__ == "__main__":
    main()
