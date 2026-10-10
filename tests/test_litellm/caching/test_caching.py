import logging
import re
from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest
from starlette.requests import Request

import litellm
from litellm.caching.caching import Cache
from litellm.caching.caching_handler import LLMCachingHandler
from litellm.types.caching import LiteLLMCacheType
from litellm.types.utils import Embedding, EmbeddingResponse, Usage


def test_cache_key_debug_log_does_not_include_prompt_material(caplog):
    cache = Cache(type=LiteLLMCacheType.LOCAL)
    prompt_marker = "secret prompt material "

    with caplog.at_level(logging.DEBUG, logger="LiteLLM"):
        cache_key = cache.get_cache_key(
            model="gpt-4.1-mini",
            messages=[
                {"role": "system", "content": prompt_marker * 100},
                {"role": "user", "content": "hello"},
            ],
            tools=[
                {
                    "type": "function",
                    "function": {
                        "name": "lookup",
                        "parameters": {
                            "type": "object",
                            "properties": {"query": {"type": "string"}},
                        },
                    },
                }
            ],
            response_format={
                "type": "json_schema",
                "json_schema": {
                    "name": "lookup_response",
                    "schema": {"type": "object"},
                },
            },
            stream=True,
        )

    assert re.fullmatch(r"[0-9a-f]{64}", cache_key)

    created_cache_key_logs = [
        record.getMessage()
        for record in caplog.records
        if "Created cache key:" in record.getMessage()
    ]
    assert created_cache_key_logs
    assert all(prompt_marker not in message for message in created_cache_key_logs)
    assert any(cache_key in message for message in created_cache_key_logs)


def _embedding_response(prompt_tokens, num_items):
    return EmbeddingResponse(
        model="amazon.titan-embed-image-v1",
        data=[
            Embedding(embedding=[0.0], index=i, object="embedding")
            for i in range(num_items)
        ],
        usage=Usage(
            prompt_tokens=prompt_tokens, completion_tokens=0, total_tokens=prompt_tokens
        ),
    )


def test_get_per_item_prompt_tokens_single_item_returns_full_value():
    cache = Cache(type=LiteLLMCacheType.LOCAL)
    result = _embedding_response(prompt_tokens=0, num_items=1)
    assert cache._get_per_item_prompt_tokens(result, 0) == 0


def test_get_per_item_prompt_tokens_distributes_with_remainder():
    cache = Cache(type=LiteLLMCacheType.LOCAL)
    result = _embedding_response(prompt_tokens=10, num_items=3)
    per_item = [cache._get_per_item_prompt_tokens(result, i) for i in range(3)]
    assert sum(per_item) == 10  # 4 + 3 + 3
    assert per_item == [4, 3, 3]


def _semantic_cache():
    return Cache(
        type=LiteLLMCacheType.VALKEY_SEMANTIC,
        host="localhost",
        port="6379",
        similarity_threshold=0.8,
    )


@pytest.mark.parametrize(
    "cache_type",
    [LiteLLMCacheType.REDIS_SEMANTIC, LiteLLMCacheType.VALKEY_SEMANTIC],
)
def test_semantic_cache_embedding_max_input_tokens_reaches_backend(cache_type):
    cache = Cache(
        type=cache_type,
        redis_url="redis://localhost:6379",
        similarity_threshold=0.8,
        semantic_cache_embedding_max_input_tokens=2048,
    )
    assert cache.cache.embedding_max_input_tokens == 2048


def test_semantic_cache_key_excludes_prompt_so_paraphrases_share_a_bucket():
    cache = _semantic_cache()
    tenant = {"user_api_key": "hash-abc"}
    key_a = cache.get_cache_key(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": "What color is the sky?"}],
        metadata=dict(tenant),
    )
    key_b = cache.get_cache_key(
        model="gpt-4o-mini",
        messages=[
            {"role": "user", "content": "Tell me the colour of the daytime sky."}
        ],
        metadata=dict(tenant),
    )
    assert key_a == key_b


def test_semantic_cache_key_isolates_tenants():
    messages = [{"role": "user", "content": "What color is the sky?"}]
    cache = _semantic_cache()
    key_a = cache.get_cache_key(
        model="gpt-4o-mini", messages=messages, metadata={"user_api_key": "hash-A"}
    )
    key_b = cache.get_cache_key(
        model="gpt-4o-mini", messages=messages, metadata={"user_api_key": "hash-B"}
    )
    key_team = cache.get_cache_key(
        model="gpt-4o-mini",
        messages=messages,
        metadata={"user_api_key": "hash-A", "user_api_key_team_id": "team-1"},
    )
    assert key_a != key_b
    assert key_a != key_team


@pytest.mark.parametrize(
    "cache_type",
    [
        LiteLLMCacheType.REDIS_SEMANTIC,
        LiteLLMCacheType.VALKEY_SEMANTIC,
        LiteLLMCacheType.QDRANT_SEMANTIC,
    ],
)
@pytest.mark.parametrize("metadata_name", ["metadata", "litellm_metadata"])
@pytest.mark.parametrize("nested", [False, True])
@pytest.mark.parametrize("identity_field", ["user_api_key", "user_api_key_team_id", "user_api_key_org_id"])
def test_semantic_cache_key_isolates_both_metadata_containers(cache_type, metadata_name, nested, identity_field):
    cache = Cache(type=LiteLLMCacheType.LOCAL)
    cache.type = cache_type

    def cache_key(identity):
        metadata = {metadata_name: {identity_field: identity}}
        kwargs = {"litellm_params": metadata} if nested else metadata
        return cache.get_cache_key(model="test-model", input="A private question", **kwargs)

    assert cache_key("tenant-a") != cache_key("tenant-b")
    assert cache_key("tenant-a") == cache_key("tenant-a")


@pytest.mark.parametrize(
    "path", ["/v1/chat/completions", "/v1/responses", "/v1/messages", "/bedrock/model/test/converse"]
)
@pytest.mark.asyncio
async def test_semantic_cache_key_uses_authenticated_route_identity(path):
    from litellm.proxy._types import UserAPIKeyAuth
    from litellm.proxy.litellm_pre_call_utils import add_litellm_data_to_request

    cache = Cache(type=LiteLLMCacheType.LOCAL)
    cache.type = LiteLLMCacheType.VALKEY_SEMANTIC
    request = Request(
        {
            "type": "http",
            "method": "POST",
            "scheme": "http",
            "path": path,
            "query_string": b"",
            "headers": [],
            "server": ("testserver", 80),
            "client": ("127.0.0.1", 1234),
        }
    )

    async def cache_key(identity):
        data = await add_litellm_data_to_request(
            data={
                "model": "test-model",
                "input": "A private question",
                "metadata": {"user_api_key": "forged-victim"},
                "litellm_metadata": {"user_api_key": "forged-victim"},
            },
            request=request,
            user_api_key_dict=UserAPIKeyAuth(api_key=identity),
            proxy_config=MagicMock(),
            general_settings={},
            version="test-version",
        )
        return cache.get_cache_key(**data)

    key_a = await cache_key("authenticated-a")
    assert key_a != await cache_key("authenticated-b")
    assert key_a == await cache_key("authenticated-a")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "path", ["/v1/chat/completions", "/v1/responses", "/v1/messages", "/bedrock/model/test/converse"]
)
@pytest.mark.parametrize("nested", [False, True])
async def test_http_cache_overrides_cannot_bypass_authenticated_scope(path, nested):
    from litellm.proxy._types import UserAPIKeyAuth
    from litellm.proxy.litellm_pre_call_utils import add_litellm_data_to_request
    from litellm.proxy.proxy_server import ProxyConfig

    request = Request(
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
    cache = Cache(type=LiteLLMCacheType.LOCAL)
    cache.type = LiteLLMCacheType.VALKEY_SEMANTIC

    def refuse_model(**_kwargs):
        pytest.fail("the cache regression must not call a model")

    async def selected_key(identity):
        override = (
            {"litellm_params": {"preset_cache_key": "forged-shared", "metadata": {"trace_id": "retained"}}}
            if nested
            else {"cache_key": "forged-shared"}
        )
        data = await add_litellm_data_to_request(
            data={"model": "synthetic-model", "messages": [{"role": "user", "content": "same"}], **override},
            request=request,
            user_api_key_dict=UserAPIKeyAuth(api_key=identity),
            proxy_config=ProxyConfig(),
            general_settings={},
            version="cache-boundary-regression",
        )
        assert "cache_key" not in data
        if nested:
            assert data["litellm_params"] == {"metadata": {"trace_id": "retained"}}
        handler = LLMCachingHandler(original_function=refuse_model, request_kwargs=data, start_time=datetime.now())
        await handler._retrieve_from_cache(call_type="acompletion", kwargs=data, args=())
        return handler.preset_cache_key

    with patch.object(litellm, "cache", cache):  # test-quality-ok: TQ008: inject the real handler's cache dependency
        first = await selected_key("synthetic-a")
        assert first is not None and first != "forged-shared"
        assert first != await selected_key("synthetic-b")
        assert first == await selected_key("synthetic-a")


@pytest.mark.asyncio
@pytest.mark.parametrize("nested", [False, True])
async def test_trusted_sdk_cache_overrides_remain_supported(nested):
    cache = Cache(type=LiteLLMCacheType.LOCAL)
    cache.type = LiteLLMCacheType.VALKEY_SEMANTIC
    override = {"litellm_params": {"preset_cache_key": "trusted-scope"}} if nested else {"cache_key": "trusted-scope"}
    data = {"model": "synthetic-model", "metadata": {"user_api_key": "trusted-key"}, **override}

    def refuse_model(**_kwargs):
        pytest.fail("the cache regression must not call a model")

    with patch.object(litellm, "cache", cache):  # test-quality-ok: TQ008: inject the real handler's cache dependency
        handler = LLMCachingHandler(original_function=refuse_model, request_kwargs=data, start_time=datetime.now())
        await handler._retrieve_from_cache(call_type="acompletion", kwargs=data, args=())
    assert handler.preset_cache_key == "trusted-scope"


def test_semantic_cache_keeps_shared_key_end_user_behavior():
    cache = _semantic_cache()
    assert cache.get_cache_key(
        model="test-model", metadata={"user_api_key": "shared-key", "user_api_key_end_user_id": "alice"}
    ) == cache.get_cache_key(
        model="test-model", metadata={"user_api_key": "shared-key", "user_api_key_end_user_id": "bob"}
    )


def test_semantic_cache_key_still_separates_models_and_params():
    cache = _semantic_cache()
    messages = [{"role": "user", "content": "hi"}]
    tenant = {"user_api_key": "hash-A"}
    assert cache.get_cache_key(
        model="gpt-4o-mini", messages=messages, metadata=dict(tenant)
    ) != cache.get_cache_key(model="gpt-4o", messages=messages, metadata=dict(tenant))
    assert cache.get_cache_key(
        model="gpt-4o-mini", messages=messages, temperature=0, metadata=dict(tenant)
    ) != cache.get_cache_key(
        model="gpt-4o-mini", messages=messages, temperature=1, metadata=dict(tenant)
    )


def test_exact_cache_key_still_includes_prompt():
    cache = Cache(type=LiteLLMCacheType.LOCAL)
    key_a = cache.get_cache_key(
        model="gpt-4o-mini", messages=[{"role": "user", "content": "a"}]
    )
    key_b = cache.get_cache_key(
        model="gpt-4o-mini", messages=[{"role": "user", "content": "b"}]
    )
    assert key_a != key_b


@pytest.mark.parametrize(
    "anthropic_param",
    [
        {"system": "answer ALPHA"},
        {"top_k": 5},
        {"stop_sequences": ["STOP"]},
    ],
)
def test_exact_cache_key_includes_anthropic_messages_params(anthropic_param):
    """Anthropic /v1/messages params with no OpenAI equivalent must still key the
    cache; without them two requests that differ only by system prompt collide."""
    cache = Cache(type=LiteLLMCacheType.LOCAL)
    messages = [{"role": "user", "content": "which greek letter?"}]
    baseline = cache.get_cache_key(model="claude-sonnet-4-5", messages=messages)
    assert baseline != cache.get_cache_key(
        model="claude-sonnet-4-5", messages=messages, **anthropic_param
    )
