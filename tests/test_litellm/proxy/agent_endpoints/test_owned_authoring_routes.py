"""The normal lazy router exposes the owned protocol without opening other writes."""

from typing import Final

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from gateway.routes.allowlist import GATEWAY_EXACT_PATHS
from litellm.proxy._lazy_features import LAZY_FEATURES, LazyFeatureMiddleware
from litellm.proxy._types import LiteLLMRoutes, LitellmUserRoles, UserAPIKeyAuth
from litellm.proxy.agent_endpoints.endpoints import router
from litellm.proxy.auth.route_checks import RouteChecks
from litellm.proxy.auth.user_api_key_auth import user_api_key_auth

CAPABILITIES: Final = "/captify/v1/agent-authoring-capabilities"
EXPECTED: Final = {
    "schemaVersion": 1,
    "ownedCreate": True,
    "conditionalUpdate": True,
    "authoritativeRead": True,
    "versionHeader": "X-Captify-Agent-Version",
}


def client_for(role: LitellmUserRoles) -> TestClient:
    app: Final = FastAPI()
    feature: Final = next(feature for feature in LAZY_FEATURES if feature.name == "agents")
    app.add_middleware(LazyFeatureMiddleware, fastapi_app=app, features=(feature,))
    app.dependency_overrides[user_api_key_auth] = lambda: UserAPIKeyAuth(user_id="owner", user_role=role)
    return TestClient(app)


@pytest.mark.parametrize("role", tuple(LitellmUserRoles))
def test_first_request_loads_capability_for_authenticated_caller_without_database(role):
    client: Final = client_for(role)
    response: Final = client.get(CAPABILITIES)
    assert response.status_code == 200
    assert response.json() == EXPECTED
    assert response.headers["cache-control"] == "private, no-store"
    assert client.get(CAPABILITIES).json() == EXPECTED
    matches: Final = [route for route in client.app.routes if getattr(route, "path", None) == CAPABILITIES]
    assert len(matches) == 1


def test_capability_requires_authentication(monkeypatch):
    from litellm.proxy import proxy_server

    monkeypatch.setattr(proxy_server, "master_key", "sk-local-auth-required")
    app: Final = FastAPI()
    app.add_exception_handler(proxy_server.ProxyException, proxy_server.openai_exception_handler)
    app.include_router(router)
    response: Final = TestClient(app).get(CAPABILITIES)
    assert response.status_code == 401


@pytest.mark.parametrize("role", tuple(role for role in LitellmUserRoles if role != LitellmUserRoles.PROXY_ADMIN))
def test_protocol_discovery_does_not_grant_owned_create_or_patch(role):
    client: Final = client_for(role)
    assert client.get(CAPABILITIES).status_code == 200
    create: Final = client.post(
        "/captify/v1/agents",
        json={
            "agent_id": "owned-fixture",
            "actor_id": "owner",
            "tenant_id": "test",
            "owner_key_hash": "a" * 64,
            "record": {"agent_name": "owned-fixture", "litellm_params": {"model": "test"}},
        },
    )
    assert create.status_code == 403
    update: Final = client.patch(
        "/captify/v1/agents/owned-fixture",
        json={"expected_version": "sha256:" + "a" * 64, "patch": {"agent_name": "changed"}},
    )
    assert update.status_code == 403


def test_admin_requires_closed_owned_request_and_expected_patch_version():
    client: Final = client_for(LitellmUserRoles.PROXY_ADMIN)
    assert client.patch("/captify/v1/agents/fixture", json={"patch": {"agent_name": "changed"}}).status_code == 422
    assert client.post("/captify/v1/agents", json={"owner_key": "sk-never-accepted"}).status_code == 422


def test_exact_route_contract_survives_component_filter_and_key_route_ceiling():
    required: Final = {
        ("POST", "/captify/v1/agents"),
        ("PATCH", "/captify/v1/agents/{agent_id}"),
        ("GET", "/v1/agents/{agent_id}"),
        ("GET", CAPABILITIES),
    }
    actual: Final = {(method, route.path) for route in router.routes for method in route.methods}
    assert required <= actual
    assert all(path in GATEWAY_EXACT_PATHS for _, path in required)
    assert "/captify/" not in GATEWAY_EXACT_PATHS
    for _, path in required:
        assert RouteChecks.check_route_access(route=path, allowed_routes=LiteLLMRoutes.agent_management_routes.value)
        assert not RouteChecks.check_route_access(route=path, allowed_routes=("/chat/completions",))
