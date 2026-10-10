"""Real database qualification of bounded tool provisioning and retained revocations."""

from __future__ import annotations

import asyncio
import os
from collections.abc import AsyncIterator
from typing import Final

import pytest
import pytest_asyncio
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from pydantic import JsonValue, TypeAdapter, ValidationError

from litellm.proxy._types import LitellmUserRoles, UserAPIKeyAuth
from litellm.proxy.agent_endpoints.tool_access import (
    RECEIPT,
    ToolAccessRequest,
    ToolDatabase,
    reconcile_tool_access,
    router,
)
from litellm.proxy.auth.user_api_key_auth import user_api_key_auth

REQUEST: Final = ToolAccessRequest(
    actor_id="fixture-actor", tenant_id="fixture", owner_key_hash="a" * 64, app_permission_revision="policy-5"
)


@pytest.mark.parametrize("role", tuple(role for role in LitellmUserRoles if role != LitellmUserRoles.PROXY_ADMIN))
def test_only_operator_can_reconcile(role: LitellmUserRoles) -> None:
    app: Final = FastAPI()
    app.include_router(router)
    app.dependency_overrides[user_api_key_auth] = lambda: UserAPIKeyAuth(user_id="fixture-actor", user_role=role)
    response: Final = TestClient(app).post("/captify/v1/agent-tools-access", json=REQUEST.model_dump())
    assert response.status_code == 403


@pytest.mark.parametrize("extra", ({"server_id": "arbitrary"}, {"team_id": "other"}, {"owner_key_hash": "raw-secret"}))
def test_closed_request_cannot_select_grants(extra: dict[str, str]) -> None:
    with pytest.raises(ValidationError):
        ToolAccessRequest.model_validate({**REQUEST.model_dump(), **extra})


@pytest_asyncio.fixture(loop_scope="function")
async def database() -> AsyncIterator[ToolDatabase]:
    from prisma import Prisma

    url: Final = os.environ.get("AGENT_TOOLS_TEST_DATABASE")
    if not url:
        pytest.skip("Real transaction checks require the isolated agent_tools_test database")
    assert "/agent_tools_test" in url, "Never run the synthetic fixture against another database"
    native: Final = Prisma(datasource={"url": url})
    await native.connect()
    database: Final[ToolDatabase] = native  # pyright: ignore[reportAssignmentType]  # Generated Prisma methods satisfy the protocol at runtime.
    await native.litellm_verificationtoken.delete_many()
    await native.litellm_teamtable.delete_many()
    await native.litellm_mcpservertable.delete_many()
    await native.litellm_objectpermissiontable.delete_many()
    await native.litellm_objectpermissiontable.create(
        data={
            "object_permission_id": "shared",
            "agents": ["existing-agent"],
            "mcp_servers": ["other-server"],
            "vector_stores": ["existing-store"],
            "models": ["existing-model"],
        }
    )
    await native.litellm_objectpermissiontable.create(
        data={"object_permission_id": "ceiling", "mcp_access_groups": ["captify-tenant-fixture"]}
    )
    await native.litellm_teamtable.create(
        data={
            "team_id": "team",
            "team_alias": "captify-tenant-fixture",
            "object_permission_id": "ceiling",
            "admins": [],
            "members": [],
            "models": ["model"],
            "metadata": '{"preserve":"team"}',
        }
    )
    await native.litellm_mcpservertable.create(
        data={"server_id": "platform", "server_name": "captify_tools", "mcp_access_groups": ["captify-tenant-fixture"]}
    )
    await native.litellm_verificationtoken.create(
        data={
            "token": "a" * 64,
            "user_id": "fixture-actor",
            "team_id": "team",
            "models": ["model"],
            "max_budget": 2.5,
            "rpm_limit": 7,
            "metadata": '{"tenant":"fixture","preserve":"key"}',
            "object_permission_id": "shared",
        }
    )
    await native.litellm_verificationtoken.create(
        data={
            "token": "b" * 64,
            "user_id": "other",
            "team_id": "team",
            "models": ["other-model"],
            "object_permission_id": "shared",
        }
    )
    try:
        yield database
    finally:
        await native.disconnect()


@pytest.mark.asyncio
async def test_concurrent_grants_copy_shared_permission_and_preserve_limits(database: ToolDatabase) -> None:
    before: Final = await database.litellm_verificationtoken.find_unique(where={"token": "a" * 64})
    shared: Final = await database.litellm_objectpermissiontable.find_unique(where={"object_permission_id": "shared"})
    team: Final = await database.litellm_teamtable.find_unique(where={"team_id": "team"})
    outcomes: Final = await asyncio.gather(*(reconcile_tool_access(database, REQUEST) for _ in range(3)))
    assert sorted(outcome.status for outcome in outcomes) == ["admitted", "unchanged", "unchanged"]
    after: Final = await database.litellm_verificationtoken.find_unique(where={"token": "a" * 64})
    assert before is not None and after is not None and shared is not None
    granted: Final = await database.litellm_objectpermissiontable.find_unique(
        where={"object_permission_id": after.object_permission_id}
    )
    assert granted is not None and granted.mcp_servers == ["other-server", "platform"]
    assert granted.model_dump(exclude={"object_permission_id", "mcp_servers"}) == shared.model_dump(
        exclude={"object_permission_id", "mcp_servers"}
    )
    assert before.model_dump(exclude={"object_permission_id", "metadata", "updated_at"}) == after.model_dump(
        exclude={"object_permission_id", "metadata", "updated_at"}
    )
    metadata: Final = TypeAdapter(dict[str, JsonValue]).validate_python(after.metadata)
    receipt: Final = TypeAdapter(dict[str, str]).validate_python(metadata[RECEIPT])
    assert receipt["appPermissionRevision"] == "policy-5"
    assert metadata["preserve"] == "key"
    assert await database.litellm_objectpermissiontable.find_unique(where={"object_permission_id": "shared"}) == shared
    assert await database.litellm_teamtable.find_unique(where={"team_id": "team"}) == team
    other: Final = await database.litellm_verificationtoken.find_unique(where={"token": "b" * 64})
    assert other is not None and other.object_permission_id == "shared"


@pytest.mark.asyncio
async def test_revocation_survives_a_later_verified_sign_in(database: ToolDatabase) -> None:
    await reconcile_tool_access(database, REQUEST)
    key: Final = await database.litellm_verificationtoken.find_unique(where={"token": "a" * 64})
    assert key is not None
    await database.litellm_objectpermissiontable.update(
        where={"object_permission_id": key.object_permission_id}, data={"mcp_servers": ["other-server"]}
    )
    with pytest.raises(HTTPException) as refusal:
        await reconcile_tool_access(database, REQUEST)
    assert refusal.value.status_code == 409
    assert await database.litellm_verificationtoken.find_unique(where={"token": "a" * 64}) == key
    permission: Final = await database.litellm_objectpermissiontable.find_unique(
        where={"object_permission_id": key.object_permission_id}
    )
    assert permission is not None and permission.mcp_servers == ["other-server"]


@pytest.mark.asyncio
@pytest.mark.parametrize("field", ("actor_id", "tenant_id"))
async def test_identity_and_tenant_mismatch_never_mutate_key(database: ToolDatabase, field: str) -> None:
    before: Final = await database.litellm_verificationtoken.find_unique(where={"token": "a" * 64})
    with pytest.raises(HTTPException) as refusal:
        await reconcile_tool_access(database, REQUEST.model_copy(update={field: "other"}))
    assert refusal.value.status_code == 403
    assert await database.litellm_verificationtoken.find_unique(where={"token": "a" * 64}) == before


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mutation",
    (
        'UPDATE "LiteLLM_VerificationToken" SET blocked=true',
        "UPDATE \"LiteLLM_VerificationToken\" SET expires=NOW()-INTERVAL '1 hour'",
        'UPDATE "LiteLLM_TeamTable" SET blocked=true',
        "UPDATE \"LiteLLM_ObjectPermissionTable\" SET mcp_access_groups='{}' WHERE object_permission_id='ceiling'",
        "UPDATE \"LiteLLM_ObjectPermissionTable\" SET blocked_tools=ARRAY['tool'] WHERE object_permission_id='shared'",
        "UPDATE \"LiteLLM_MCPServerTable\" SET approval_status='pending'",
        "UPDATE \"LiteLLM_MCPServerTable\" SET mcp_access_groups='{}'",
    ),
)
async def test_current_restrictions_refuse_without_mutation(database: ToolDatabase, mutation: str) -> None:
    await database.query_raw(mutation + " RETURNING 1")
    before: Final = await database.litellm_verificationtoken.find_unique(where={"token": "a" * 64})
    with pytest.raises(HTTPException):
        await reconcile_tool_access(database, REQUEST)
    assert await database.litellm_verificationtoken.find_unique(where={"token": "a" * 64}) == before


@pytest.mark.asyncio
async def test_failed_key_binding_rolls_back_the_copied_permission(database: ToolDatabase) -> None:
    before: Final = await database.litellm_verificationtoken.find_unique(where={"token": "a" * 64})
    permissions: Final = await database.litellm_objectpermissiontable.find_many()
    await database.query_raw(
        'ALTER TABLE "LiteLLM_VerificationToken" ADD CONSTRAINT agent_tools_test_binding '
        "CHECK (object_permission_id = 'shared')"
    )
    try:
        with pytest.raises(Exception, match="agent_tools_test_binding"):
            await reconcile_tool_access(database, REQUEST)
        assert await database.litellm_verificationtoken.find_unique(where={"token": "a" * 64}) == before
        assert await database.litellm_objectpermissiontable.find_many() == permissions
    finally:
        await database.query_raw('ALTER TABLE "LiteLLM_VerificationToken" DROP CONSTRAINT agent_tools_test_binding')


@pytest.mark.asyncio
async def test_replacing_the_registered_server_requires_new_review(database: ToolDatabase) -> None:
    await reconcile_tool_access(database, REQUEST)
    before: Final = await database.litellm_verificationtoken.find_unique(where={"token": "a" * 64})
    await database.litellm_mcpservertable.update(where={"server_id": "platform"}, data={"server_name": "retired"})
    await database.litellm_mcpservertable.create(
        data={
            "server_id": "replacement",
            "server_name": "captify_tools",
            "mcp_access_groups": ["captify-tenant-fixture"],
        }
    )
    with pytest.raises(HTTPException) as refusal:
        await reconcile_tool_access(database, REQUEST)
    assert refusal.value.status_code == 409
    assert await database.litellm_verificationtoken.find_unique(where={"token": "a" * 64}) == before
