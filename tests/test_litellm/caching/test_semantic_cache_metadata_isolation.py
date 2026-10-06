"""CVE-2026-89032: route-specific auth metadata must isolate cache buckets."""

import copy
import datetime
import socket
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from litellm.caching.caching import Cache
from litellm.types.caching import LiteLLMCacheType


METADATA_LOCATIONS = (
    ("metadata",),
    ("litellm_metadata",),
    ("litellm_params", "metadata"),
    ("litellm_params", "litellm_metadata"),
)
TENANT_FIELDS = ("user_api_key", "user_api_key_team_id", "user_api_key_org_id")
SEMANTIC_BACKENDS = (
    LiteLLMCacheType.REDIS_SEMANTIC,
    LiteLLMCacheType.QDRANT_SEMANTIC,
    LiteLLMCacheType.VALKEY_SEMANTIC,
)


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def refuse(*_args, **_kwargs):
        pytest.fail("semantic scope tests must not use network or model providers")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket.socket, "connect_ex", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)


def scope_input(location, identity):
    result = copy.deepcopy(identity)
    for key in reversed(location):
        result = {key: result}
    return result


def semantic_cache(backend):
    # Initialize only an in-memory backend. The real get_cache_key method's
    # semantic branch needs the type, never a Redis/Qdrant connection.
    cache = Cache(type=LiteLLMCacheType.LOCAL)
    cache.type = backend
    return cache


def cache_key(cache, scope, prompt="How do I access the project?"):
    return cache.get_cache_key(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": prompt}],
        **copy.deepcopy(scope),
    )


@pytest.mark.parametrize("backend", SEMANTIC_BACKENDS)
@pytest.mark.parametrize("location", METADATA_LOCATIONS)
@pytest.mark.parametrize("field", TENANT_FIELDS)
def test_distinct_authenticated_tenants_never_share_semantic_bucket(backend, location, field):
    cache = semantic_cache(backend)
    tenant_a = scope_input(location, {field: "tenant-a"})
    tenant_b = scope_input(location, {field: "tenant-b"})
    assert cache_key(cache, tenant_a) != cache_key(cache, tenant_b)
    assert cache_key(cache, tenant_a) == cache_key(cache, tenant_a, "How can I open the project?")
    assert cache_key(cache, tenant_a) != cache_key(cache, {})


@pytest.mark.parametrize("backend", SEMANTIC_BACKENDS)
@pytest.mark.parametrize("location", METADATA_LOCATIONS)
def test_same_authenticated_identity_has_same_scope_across_route_metadata_shapes(backend, location):
    cache = semantic_cache(backend)
    identity = {field: f"identity-{index}" for index, field in enumerate(TENANT_FIELDS)}
    assert cache_key(cache, scope_input(location, identity)) == cache_key(cache, scope_input(("metadata",), identity))


@pytest.mark.parametrize("location", METADATA_LOCATIONS)
def test_empty_earlier_metadata_does_not_hide_nested_authenticated_identity(location):
    cache = semantic_cache(LiteLLMCacheType.VALKEY_SEMANTIC)
    scopes = {
        "metadata": {field: None for field in TENANT_FIELDS},
        "litellm_metadata": {},
        "litellm_params": {"metadata": None, "litellm_metadata": {}},
    }
    target = scopes
    for key in location[:-1]:
        target = target[key]
    target[location[-1]] = {"user_api_key": "authenticated-hash"}
    assert cache_key(cache, scopes) == cache_key(cache, {"metadata": {"user_api_key": "authenticated-hash"}})
    assert cache_key(cache, scopes) != cache_key(cache, {})


def test_scope_preserves_upstream_source_precedence_without_mutating_metadata():
    cache = semantic_cache(LiteLLMCacheType.VALKEY_SEMANTIC)
    scopes = {
        "metadata": {"user_api_key": "canonical-key"},
        "litellm_metadata": {"user_api_key": "alternate-key", "user_api_key_team_id": "top-team"},
        "litellm_params": {
            "metadata": {"user_api_key_team_id": "nested-team", "user_api_key_org_id": "canonical-org"},
            "litellm_metadata": {"user_api_key_org_id": "alternate-org"},
        },
    }
    before = copy.deepcopy(scopes)
    assert cache._get_semantic_cache_tenant_scope(scopes) == (
        "user_api_key: canonical-keyuser_api_key_team_id: top-teamuser_api_key_org_id: canonical-org"
    )
    assert scopes == before


def test_exact_cache_keeps_distinct_prompts_and_key_scope_does_not_add_end_user_policy():
    exact = Cache(type=LiteLLMCacheType.LOCAL)
    assert cache_key(exact, {}, "first prompt") != cache_key(exact, {}, "second prompt")
    semantic = semantic_cache(LiteLLMCacheType.VALKEY_SEMANTIC)
    assert cache_key(
        semantic, {"litellm_metadata": {"user_api_key": "same-key", "user_api_key_end_user_id": "a"}}
    ) == cache_key(semantic, {"litellm_metadata": {"user_api_key": "same-key", "user_api_key_end_user_id": "b"}})


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/v1/chat/completions", "/v1/responses", "/v1/messages", "/bedrock/model/invoke"])
async def test_proxy_stamped_identity_cannot_be_shadowed_by_request_metadata(path):
    from starlette.requests import Request

    from litellm.proxy._types import UserAPIKeyAuth
    from litellm.proxy.litellm_pre_call_utils import add_litellm_data_to_request

    request = MagicMock(spec=Request)
    request.url = MagicMock()
    request.url.path = path
    request.url.__str__.return_value = f"http://localhost{path}"
    request.method = "POST"
    request.query_params = {}
    request.headers = {"Content-Type": "application/json"}
    request.client = SimpleNamespace(host="127.0.0.1")
    request.state = SimpleNamespace()
    cache = semantic_cache(LiteLLMCacheType.VALKEY_SEMANTIC)
    keys = []
    for actual_key in ("real-key-a", "real-key-b"):
        data = await add_litellm_data_to_request(
            data={
                "model": "gpt-4o-mini",
                "messages": [{"role": "user", "content": "same prompt"}],
                "metadata": {field: "forged-shared-identity" for field in TENANT_FIELDS},
                "litellm_metadata": {field: "forged-shared-identity" for field in TENANT_FIELDS},
            },
            request=request,
            user_api_key_dict=UserAPIKeyAuth(api_key=actual_key, metadata={}, team_metadata={}),
            proxy_config=MagicMock(),
            general_settings={},
            version="test-version",
        )
        keys.append(cache.get_cache_key(**data))
    assert keys[0] != keys[1]


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/v1/chat/completions", "/v1/responses", "/v1/messages", "/bedrock/model/invoke"])
@pytest.mark.parametrize(
    "override",
    [
        {"cache_key": "forged-shared-scope"},
        {"litellm_params": {"preset_cache_key": "forged-shared-scope", "metadata": {"trace_id": "retained"}}},
    ],
)
async def test_http_cache_overrides_cannot_bypass_real_handler_tenant_scope(path, override):
    import litellm
    from starlette.requests import Request

    from litellm.caching.caching_handler import LLMCachingHandler
    from litellm.proxy._types import UserAPIKeyAuth
    from litellm.proxy.litellm_pre_call_utils import add_litellm_data_to_request

    def refuse_model(**_kwargs):
        pytest.fail("no model call permitted")

    scopes = []

    async def capture(**kwargs):
        scopes.append(kwargs["cache_key"])
        return None

    cache = semantic_cache(LiteLLMCacheType.VALKEY_SEMANTIC)
    with (
        patch.object(litellm, "cache", cache),  # test-quality-ok: TQ008: public cache setting for the real handler
        patch.object(cache, "_supports_async", return_value=True),
        patch.object(cache, "async_get_cache", side_effect=capture),
    ):
        for actual_key in ("real-key-a", "real-key-b"):
            request = MagicMock(spec=Request)
            request.url = MagicMock()
            request.url.path = path
            request.url.__str__.return_value = f"http://localhost{path}"
            request.method = "POST"
            request.query_params = {}
            request.headers = {"Content-Type": "application/json"}
            request.client = SimpleNamespace(host="127.0.0.1")
            request.state = SimpleNamespace()
            data = await add_litellm_data_to_request(
                data={
                    "model": "gpt-4o-mini",
                    "messages": [{"role": "user", "content": "same prompt"}],
                    **copy.deepcopy(override),
                },
                request=request,
                user_api_key_dict=UserAPIKeyAuth(api_key=actual_key, metadata={}, team_metadata={}),
                proxy_config=MagicMock(),
                general_settings={},
                version="test-version",
            )
            assert "cache_key" not in data
            if "litellm_params" in override:
                assert data["litellm_params"] == {"metadata": {"trace_id": "retained"}}
            handler = LLMCachingHandler(
                original_function=refuse_model, request_kwargs=data, start_time=datetime.datetime.now()
            )
            await handler._retrieve_from_cache(call_type="acompletion", kwargs=data, args=())
    assert len(scopes) == 2
    assert scopes[0] != scopes[1]
    assert "forged-shared-scope" not in scopes


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "override", [{"cache_key": "trusted-scope"}, {"litellm_params": {"preset_cache_key": "trusted-scope"}}]
)
async def test_trusted_in_process_sdk_cache_keys_remain_supported(override):
    import litellm
    from litellm.caching.caching_handler import LLMCachingHandler

    scopes = []

    async def capture(**kwargs):
        scopes.append(kwargs["cache_key"])
        return None

    def refuse_model(**_kwargs):
        pytest.fail("no model call permitted")

    cache = semantic_cache(LiteLLMCacheType.VALKEY_SEMANTIC)
    with (
        patch.object(litellm, "cache", cache),  # test-quality-ok: TQ008: public cache setting for the real handler
        patch.object(cache, "_supports_async", return_value=True),
        patch.object(cache, "async_get_cache", side_effect=capture),
    ):
        data = {"model": "gpt-4o-mini", "metadata": {"user_api_key": "trusted-key"}, **copy.deepcopy(override)}
        handler = LLMCachingHandler(
            original_function=refuse_model, request_kwargs=data, start_time=datetime.datetime.now()
        )
        await handler._retrieve_from_cache(call_type="acompletion", kwargs=data, args=())
    assert scopes == ["trusted-scope"]
