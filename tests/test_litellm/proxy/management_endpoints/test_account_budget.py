"""Allowance compare-and-set, isolation and replay over an isolated real ledger."""

from __future__ import annotations

import asyncio
import math
import os
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Final
from uuid import uuid4

import pytest
import pytest_asyncio
from fastapi import FastAPI, HTTPException
from httpx import ASGITransport, AsyncClient
from pydantic import ValidationError

from litellm.proxy._types import LitellmUserRoles, UserAPIKeyAuth
from litellm.proxy.auth.user_api_key_auth import user_api_key_auth
from litellm.proxy.management_endpoints.account_budget import (
    AccountBudgetChange,
    BudgetDatabase,
    BudgetSnapshot,
    change_budget,
    read_budget,
    router,
)


@pytest.mark.parametrize("role", tuple(role for role in LitellmUserRoles if role != LitellmUserRoles.PROXY_ADMIN))
@pytest.mark.asyncio
async def test_ordinary_and_read_only_keys_cannot_access_controls(role: LitellmUserRoles) -> None:
    app: Final = FastAPI()
    app.include_router(router)
    app.dependency_overrides[user_api_key_auth] = lambda: UserAPIKeyAuth(user_role=role)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://unit.test") as client:
        assert (await client.get("/captify/v1/accounts/fixture/budget?tenant_id=fixture")).status_code == 403
        assert (await client.patch("/captify/v1/accounts/fixture/budget", json={})).status_code == 403


def request(snapshot: BudgetSnapshot, **values: object) -> AccountBudgetChange:
    return AccountBudgetChange.model_validate(
        dict(
            tenant_id=snapshot.tenant_id,
            actor_id="fixture-staff",
            operation_id=uuid4().hex,
            expected_version=snapshot.version,
            max_budget=2.0,
            budget_duration="30d",
            reason="Isolated ledger qualification",
        )
        | values
    )


@pytest.mark.parametrize("amount", (True, "20", float("nan"), float("inf"), -1, 1_000_001))
def test_amounts_are_strict_finite_and_bounded(amount: object) -> None:
    with pytest.raises(ValidationError):
        AccountBudgetChange.model_validate(
            dict(
                tenant_id="fixture",
                actor_id="staff",
                operation_id="a" * 32,
                expected_version="sha256:" + "a" * 64,
                max_budget=amount,
                budget_duration="30d",
                reason="Isolated test",
            )
        )


@pytest_asyncio.fixture(loop_scope="function")
async def database() -> AsyncIterator[tuple[BudgetDatabase, str]]:
    from prisma import Json, Prisma
    from prisma.types import DatasourceOverride, LiteLLM_UserTableCreateInput

    url: Final = os.environ.get("ACCOUNT_BUDGET_TEST_DATABASE")
    if not url:
        pytest.skip("Requires the isolated account_budget_test database")
    assert url.split("?", 1)[0].endswith("/account_budget_test")
    native: Final = Prisma(datasource=DatasourceOverride(url=url))
    await native.connect()
    identifier: Final = "fixture-budget-" + uuid4().hex
    await native.litellm_usertable.create(
        data=LiteLLM_UserTableCreateInput(
            user_id=identifier,
            models=[],
            spend=0.05,
            max_budget=10.0,
            budget_duration="30d",
            budget_reset_at=datetime.now(UTC) + timedelta(days=12),
            metadata=Json(dict(tenant="fixture", retained="private-metadata")),
        )
    )
    typed: Final[BudgetDatabase] = native  # pyright: ignore[reportAssignmentType]  # Generated Prisma satisfies the protocol at runtime.
    try:
        yield typed, identifier
    finally:
        await native.litellm_auditlog.delete_many(where={"object_id": identifier})
        await native.litellm_usertable.delete(where={"user_id": identifier})
        await native.disconnect()


@pytest.mark.asyncio
async def test_amount_change_preserves_spend_period_and_private_metadata(database: tuple[BudgetDatabase, str]) -> None:
    db, identifier = database
    before: Final = await read_budget(db, identifier, "fixture")
    result: Final = await change_budget(db, identifier, request(before))
    current: Final = await read_budget(db, identifier, "fixture")
    assert result.account == BudgetSnapshot.model_validate(current.model_dump())
    assert current.spend == before.spend == 0.05
    assert current.budget_reset_at == before.budget_reset_at
    assert current.max_budget == 2.0 and current.remaining == 1.95
    assert current.last_change == result.audit
    assert current.last_change is not None
    assert current.last_change.before.max_budget == 10.0
    assert "private-metadata" not in current.model_dump_json()
    assert "request_digest" not in current.model_dump_json()
    saved: Final = await db.litellm_usertable.find_unique(where=dict(user_id=identifier))
    assert saved is not None and "private-metadata" in str(saved.metadata)
    assert await db.litellm_auditlog.count(where=dict(object_id=identifier)) == 1


@pytest.mark.asyncio
async def test_concurrent_edits_have_one_winner_and_one_audit(database: tuple[BudgetDatabase, str]) -> None:
    db, identifier = database
    before: Final = await read_budget(db, identifier, "fixture")
    outcomes: Final = await asyncio.gather(
        change_budget(db, identifier, request(before, max_budget=2.0)),
        change_budget(db, identifier, request(before, max_budget=3.0)),
        return_exceptions=True,
    )
    conflicts: Final = tuple(item for item in outcomes if isinstance(item, HTTPException))
    assert len(conflicts) == 1 and conflicts[0].status_code == 409
    assert await db.litellm_auditlog.count(where=dict(object_id=identifier)) == 1
    assert (await read_budget(db, identifier, "fixture")).max_budget in (2.0, 3.0)


@pytest.mark.asyncio
async def test_replay_returns_original_audit_without_restoring_old_limit(database: tuple[BudgetDatabase, str]) -> None:
    db, identifier = database
    original: Final = request(await read_budget(db, identifier, "fixture"))
    first: Final = await change_budget(db, identifier, original)
    await change_budget(db, identifier, request(first.account, max_budget=0.0))
    replay: Final = await change_budget(db, identifier, original)
    assert replay.replayed and replay.account.max_budget == 0.0 and replay.audit == first.audit
    assert await db.litellm_auditlog.count(where=dict(object_id=identifier)) == 2
    with pytest.raises(HTTPException) as conflict:
        await change_budget(db, identifier, original.model_copy(update=dict(max_budget=7.0)))
    assert conflict.value.status_code == 409


@pytest.mark.asyncio
async def test_tenant_and_self_edits_are_refused_without_changes(database: tuple[BudgetDatabase, str]) -> None:
    db, identifier = database
    before: Final = await read_budget(db, identifier, "fixture")
    for values, status in ((dict(tenant_id="foreign"), 404), (dict(actor_id=identifier), 403)):
        with pytest.raises(HTTPException) as refused:
            await change_budget(db, identifier, request(before, **values))
        assert refused.value.status_code == status
    with pytest.raises(HTTPException) as read_refusal:
        await read_budget(db, identifier, "foreign")
    assert read_refusal.value.status_code == 404
    assert await read_budget(db, identifier, "fixture") == before
    assert await db.litellm_auditlog.count(where=dict(object_id=identifier)) == 0


@pytest.mark.asyncio
async def test_new_spend_fences_a_stale_edit_without_losing_spend(database: tuple[BudgetDatabase, str]) -> None:
    db, identifier = database
    before: Final = await read_budget(db, identifier, "fixture")
    await db.litellm_usertable.update(where=dict(user_id=identifier), data=dict(spend=dict(increment=0.02)))
    with pytest.raises(HTTPException) as conflict:
        await change_budget(db, identifier, request(before))
    assert conflict.value.status_code == 409
    current: Final = await read_budget(db, identifier, "fixture")
    changed: Final = await change_budget(db, identifier, request(current))
    assert math.isclose(changed.account.spend, 0.07)


@pytest.mark.asyncio
async def test_failed_audit_rolls_back_the_allowance_and_version(database: tuple[BudgetDatabase, str]) -> None:
    db, identifier = database
    before: Final = await read_budget(db, identifier, "fixture")
    await db.query_raw(
        'ALTER TABLE "LiteLLM_AuditLog" ADD CONSTRAINT account_budget_test_audit CHECK (false) NOT VALID'
    )
    try:
        with pytest.raises(Exception, match="account_budget_test_audit"):
            await change_budget(db, identifier, request(before))
        assert await read_budget(db, identifier, "fixture") == before
        assert await db.litellm_auditlog.count(where=dict(object_id=identifier)) == 0
    finally:
        await db.query_raw('ALTER TABLE "LiteLLM_AuditLog" DROP CONSTRAINT account_budget_test_audit')


@pytest.mark.asyncio
async def test_period_changes_preserve_spend_and_reject_unrelated_fields(database: tuple[BudgetDatabase, str]) -> None:
    db, identifier = database
    before: Final = await read_budget(db, identifier, "fixture")
    changed: Final = await change_budget(db, identifier, request(before, budget_duration="1d"))
    assert changed.account.spend == before.spend
    assert changed.account.budget_reset_at is not None and before.budget_reset_at is not None
    assert datetime.now(UTC) < changed.account.budget_reset_at < before.budget_reset_at
    for values in (dict(spend=0.0), dict(reason="  "), dict(budget_duration="forever"), dict(key="unrelated")):
        with pytest.raises(ValidationError):
            request(changed.account, **values)
