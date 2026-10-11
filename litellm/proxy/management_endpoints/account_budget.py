"""Tenant-bound account allowance controls for the authenticated identity service."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from contextlib import AbstractAsyncContextManager
from datetime import UTC, datetime
from types import MappingProxyType
from typing import TYPE_CHECKING, Annotated, Final, Literal, Protocol

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, ConfigDict, Field, JsonValue, TypeAdapter

from litellm.proxy._types import LitellmUserRoles, UserAPIKeyAuth
from litellm.proxy.auth.user_api_key_auth import user_api_key_auth
from litellm.proxy.common_utils.auth_cache_invalidation_pubsub import publish_auth_cache_invalidation
from litellm.proxy.common_utils.timezone_utils import get_budget_reset_time
from litellm.repositories.prisma_protocols import TableActions

if TYPE_CHECKING:
    from prisma.models import LiteLLM_AuditLog, LiteLLM_UserTable

router: Final = APIRouter()
JSON_OBJECT: Final = TypeAdapter(dict[str, JsonValue])
VERSION: Final = r"^sha256:[a-f0-9]{64}$"


class AccountBudgetChange(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True, str_strip_whitespace=True)

    tenant_id: str = Field(min_length=1, max_length=200)
    actor_id: str = Field(min_length=1, max_length=200)
    operation_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    expected_version: str = Field(pattern=VERSION)
    max_budget: float = Field(ge=0, le=1_000_000, allow_inf_nan=False)
    budget_duration: Literal["1d", "7d", "30d", "1mo"] | None
    reason: str = Field(min_length=3, max_length=1000)


class BudgetSnapshot(BaseModel):
    model_config = ConfigDict(frozen=True)

    user_id: str
    tenant_id: str
    version: str = Field(pattern=VERSION)
    max_budget: float | None = Field(ge=0, allow_inf_nan=False)
    spend: float = Field(ge=0, allow_inf_nan=False)
    remaining: float | None = Field(ge=0, allow_inf_nan=False)
    currency: Literal["USD"] = "USD"
    budget_duration: str | None
    budget_reset_at: datetime | None


class BudgetAudit(BaseModel):
    model_config = ConfigDict(frozen=True)

    before: BudgetSnapshot
    account: BudgetSnapshot
    actor_id: str
    tenant_id: str
    at: datetime
    reason: str


class StoredAudit(BudgetAudit):
    request_digest: str


class BudgetRead(BudgetSnapshot):
    last_change: BudgetAudit | None


class BudgetResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    account: BudgetSnapshot
    operation_id: str
    replayed: bool
    audit: BudgetAudit


class BudgetDatabase(Protocol):
    @property
    def litellm_usertable(self) -> TableActions[LiteLLM_UserTable]: ...
    @property
    def litellm_auditlog(self) -> TableActions[LiteLLM_AuditLog]: ...
    def tx(self) -> AbstractAsyncContextManager[BudgetDatabase]: ...
    async def query_raw(self, query: str, *args: object) -> Sequence[Mapping[str, object]]: ...


def _metadata(value: object) -> Mapping[str, JsonValue]:
    return JSON_OBJECT.validate_python(json.loads(value) if isinstance(value, str) else value)


def budget_snapshot(row: LiteLLM_UserTable, tenant_id: str) -> BudgetSnapshot:
    fields: Final = row.model_dump(mode="json")
    versioned: Final = tuple(
        (name, fields.get(name))
        for name in ("user_id", "max_budget", "spend", "budget_duration", "budget_reset_at", "created_at", "updated_at")
    ) + (("tenant_id", tenant_id), ("revision", _metadata(row.metadata).get("captify_account_budget_revision")))
    digest: Final = hashlib.sha256(
        json.dumps(versioned, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()
    return BudgetSnapshot(
        user_id=row.user_id,
        tenant_id=tenant_id,
        version="sha256:" + digest,
        max_budget=row.max_budget,
        spend=row.spend,
        remaining=None if row.max_budget is None else max(0.0, row.max_budget - row.spend),
        budget_duration=row.budget_duration,
        budget_reset_at=row.budget_reset_at,
    )


def _owned(row: LiteLLM_UserTable | None, tenant_id: str) -> LiteLLM_UserTable:
    if row is None or _metadata(row.metadata).get("tenant") != tenant_id:
        raise HTTPException(404, "The managed account was not found in this tenant")
    return row


def _audit(row: LiteLLM_AuditLog, user_id: str, tenant_id: str) -> StoredAudit:
    receipt: Final = StoredAudit.model_validate(_metadata(row.updated_values))
    if (
        row.object_id != user_id
        or row.action != "captify.account-budget.update"
        or row.table_name != "LiteLLM_UserTable"
        or row.changed_by != receipt.actor_id
        or receipt.tenant_id != tenant_id
        or any(item.user_id != user_id or item.tenant_id != tenant_id for item in (receipt.before, receipt.account))
    ):
        raise HTTPException(503, "The account audit could not be verified")
    return receipt


def _public_audit(receipt: StoredAudit) -> BudgetAudit:
    excluded: Final = set[str](("request_digest",))  # mutable-ok: Pydantic exclusion input.
    return BudgetAudit.model_validate(receipt.model_dump(exclude=excluded))


async def read_budget(database: BudgetDatabase, user_id: str, tenant_id: str) -> BudgetRead:
    owner_key: Final = dict(user_id=user_id)  # mutable-ok: Prisma query input.
    row: Final = _owned(await database.litellm_usertable.find_unique(where=owner_key), tenant_id)
    events: Final = await database.litellm_auditlog.find_many(
        where=dict(  # mutable-ok: Prisma audit query input.
            object_id=user_id, action="captify.account-budget.update", table_name="LiteLLM_UserTable"
        ),
        order=dict(updated_at="desc"),  # mutable-ok: Prisma query input.
        take=1,
    )
    return BudgetRead.model_validate(
        MappingProxyType(
            dict(
                budget_snapshot(row, tenant_id).model_dump(),
                last_change=_public_audit(_audit(events[0], user_id, tenant_id)) if events else None,
            )
        )
    )


async def change_budget(database: BudgetDatabase, user_id: str, body: AccountBudgetChange) -> BudgetResult:
    if body.actor_id == user_id:
        raise HTTPException(403, "Ask another authorized staff member to change your allowance")
    operation: Final = "captify-budget:" + body.operation_id
    payload: Final = dict(_metadata(body.model_dump()), user_id=user_id)  # mutable-ok: JSON digest input.
    owner_key: Final = dict(user_id=user_id)  # mutable-ok: Prisma query input.
    digest: Final = hashlib.sha256(json.dumps(payload, sort_keys=True, allow_nan=False).encode()).hexdigest()
    async with database.tx() as tx:
        await tx.query_raw('SELECT user_id FROM "LiteLLM_UserTable" WHERE user_id=$1 FOR UPDATE', user_id)
        current: Final = _owned(await tx.litellm_usertable.find_unique(where=owner_key), body.tenant_id)
        previous: Final = await tx.litellm_auditlog.find_unique(
            where=dict(id=operation)  # mutable-ok: Prisma query input.
        )
        if previous is not None:
            if previous.object_id != user_id:
                raise HTTPException(409, "The change identifier already belongs to another account")
            receipt: Final = _audit(previous, user_id, body.tenant_id)
            if receipt.request_digest != digest:
                raise HTTPException(409, "The change identifier already belongs to another request")
            return BudgetResult(
                account=budget_snapshot(current, body.tenant_id),
                operation_id=body.operation_id,
                replayed=True,
                audit=_public_audit(receipt),
            )
        before: Final = budget_snapshot(current, body.tenant_id)
        if before.version != body.expected_version:
            raise HTTPException(409, "The account changed; reload its allowance before saving")
        period: Final[Mapping[str, object]] = (
            MappingProxyType(
                dict(
                    budget_duration=body.budget_duration,
                    budget_reset_at=get_budget_reset_time(body.budget_duration) if body.budget_duration else None,
                )
            )
            if current.budget_duration != body.budget_duration
            else MappingProxyType({})
        )
        saved: Final = _owned(
            await tx.litellm_usertable.update(
                where=dict(user_id=user_id),  # mutable-ok: Prisma query input.
                data=dict(  # mutable-ok: Prisma update input.
                    max_budget=body.max_budget,
                    metadata=json.dumps(
                        dict(  # mutable-ok: JSON serialization boundary.
                            _metadata(current.metadata), captify_account_budget_revision=body.operation_id
                        )
                    ),
                    **period,
                ),
            ),
            body.tenant_id,
        )
        committed: Final = StoredAudit(
            before=before,
            account=budget_snapshot(saved, body.tenant_id),
            actor_id=body.actor_id,
            tenant_id=body.tenant_id,
            reason=body.reason,
            at=datetime.now(UTC),
            request_digest=digest,
        )
        await tx.litellm_auditlog.create(
            data=dict(  # mutable-ok: Prisma audit insert input.
                id=operation,
                changed_by=body.actor_id,
                action="captify.account-budget.update",
                table_name="LiteLLM_UserTable",
                object_id=user_id,
                before_value=before.model_dump_json(),
                updated_values=committed.model_dump_json(),
            )
        )
        return BudgetResult(
            account=committed.account, operation_id=body.operation_id, replayed=False, audit=_public_audit(committed)
        )


def _operator(identity: Annotated[UserAPIKeyAuth, Depends(user_api_key_auth)]) -> None:
    if identity.user_role != LitellmUserRoles.PROXY_ADMIN:
        raise HTTPException(403, "Account budget administration requires the identity service")


def _database() -> BudgetDatabase:
    from litellm.proxy import proxy_server

    client: Final = proxy_server.prisma_client
    if client is None:
        raise HTTPException(503, "The account ledger is unavailable")
    database: Final[BudgetDatabase] = client.db  # pyright: ignore[reportAssignmentType]  # Prisma wrapper delegates generated tables and tx.
    return database


@router.get("/captify/v1/accounts/{user_id}/budget", dependencies=(Depends(_operator),), response_model=BudgetRead)
async def read_account_budget(
    user_id: str, tenant_id: str, response: Response, database: Annotated[BudgetDatabase, Depends(_database)]
) -> BudgetRead:
    response.headers["Cache-Control"] = "private, no-store"  # rebind-ok: FastAPI response headers.
    try:
        return await read_budget(database, user_id, tenant_id)
    except HTTPException:
        raise
    except Exception as error:
        raise HTTPException(503, "The account allowance could not be verified") from error


@router.patch("/captify/v1/accounts/{user_id}/budget", dependencies=(Depends(_operator),), response_model=BudgetResult)
async def change_account_budget(
    user_id: str, body: AccountBudgetChange, response: Response, database: Annotated[BudgetDatabase, Depends(_database)]
) -> BudgetResult:
    from litellm.proxy import proxy_server

    response.headers["Cache-Control"] = "private, no-store"  # rebind-ok: FastAPI response headers.
    try:
        result: Final = await change_budget(database, user_id, body)
    except HTTPException:
        raise
    except Exception as error:
        raise HTTPException(503, "The allowance change could not be confirmed; reload before retrying") from error
    try:
        await proxy_server.user_api_key_cache.async_delete_cache(key=user_id)
        await publish_auth_cache_invalidation(cache_key=user_id)
    except Exception as error:
        raise HTTPException(503, "The allowance was saved but refresh failed; retry the same change") from error
    return result
