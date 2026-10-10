"""Provision one tenant-bound tool server without replacing an owner's other grants."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from contextlib import AbstractAsyncContextManager
from datetime import UTC, datetime
from types import MappingProxyType
from typing import TYPE_CHECKING, Annotated, Final, Literal, Protocol
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field, JsonValue, TypeAdapter

from litellm.proxy import proxy_server
from litellm.proxy._types import LitellmUserRoles, UserAPIKeyAuth
from litellm.proxy.auth.auth_checks import (
    _delete_cache_key_object,  # pyright: ignore[reportPrivateUsage]  # Existing key-cache invalidation contract.
)
from litellm.proxy.auth.user_api_key_auth import user_api_key_auth
from litellm.repositories.prisma_protocols import TableActions

if TYPE_CHECKING:
    from prisma.models import (
        LiteLLM_MCPServerTable,
        LiteLLM_ObjectPermissionTable,
        LiteLLM_TeamTable,
        LiteLLM_VerificationToken,
    )

router: Final = APIRouter()
JSON_OBJECT: Final = TypeAdapter(dict[str, JsonValue])
RECEIPT: Final = "captify_agent_tools_v1"


class ToolAccessRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    actor_id: str = Field(min_length=1, max_length=200)
    tenant_id: str = Field(min_length=1, max_length=200)
    owner_key_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    app_permission_revision: str = Field(min_length=1, max_length=512)


class ToolAccessResult(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    status: Literal["admitted", "unchanged"]
    serverId: str


class ToolDatabase(Protocol):
    @property
    def litellm_verificationtoken(self) -> TableActions[LiteLLM_VerificationToken]: ...
    @property
    def litellm_teamtable(self) -> TableActions[LiteLLM_TeamTable]: ...
    @property
    def litellm_objectpermissiontable(self) -> TableActions[LiteLLM_ObjectPermissionTable]: ...
    @property
    def litellm_mcpservertable(self) -> TableActions[LiteLLM_MCPServerTable]: ...
    def tx(self) -> AbstractAsyncContextManager[ToolDatabase]: ...
    async def query_raw(self, query: str, *args: object) -> Sequence[Mapping[str, object]]: ...


def _json_object(value: object) -> Mapping[str, JsonValue]:
    parsed: Final = json.loads(value) if isinstance(value, str) else value
    return MappingProxyType(JSON_OBJECT.validate_python(parsed))


async def _permission(tx: ToolDatabase, identifier: str | None) -> LiteLLM_ObjectPermissionTable | None:
    if identifier is None:
        return None
    await tx.query_raw(
        'SELECT object_permission_id FROM "LiteLLM_ObjectPermissionTable" WHERE object_permission_id=$1 FOR UPDATE',
        identifier,
    )
    permission: Final = await tx.litellm_objectpermissiontable.find_unique(
        where={"object_permission_id": identifier}  # mutable-ok: Prisma input boundary.
    )
    if permission is None:
        raise HTTPException(409, "The declared permission record is unavailable")
    return permission


def _admits(permission: LiteLLM_ObjectPermissionTable | None, server: LiteLLM_MCPServerTable) -> bool:
    return permission is not None and (
        server.server_id in permission.mcp_servers
        or bool(frozenset(permission.mcp_access_groups) & frozenset(server.mcp_access_groups))
    )


async def reconcile_tool_access(database: ToolDatabase, body: ToolAccessRequest) -> ToolAccessResult:
    async with database.tx() as tx:
        await tx.query_raw(
            'SELECT token FROM "LiteLLM_VerificationToken" WHERE token=$1 FOR UPDATE', body.owner_key_hash
        )
        owner: Final = await tx.litellm_verificationtoken.find_unique(
            where={"token": body.owner_key_hash}  # mutable-ok: Prisma input boundary.
        )
        if (
            owner is None
            or owner.user_id != body.actor_id
            or owner.blocked
            or (owner.expires is not None and owner.expires <= datetime.now(UTC))
            or owner.team_id is None
            or _json_object(owner.metadata).get("tenant") != body.tenant_id
        ):
            raise HTTPException(403, "No active matching owner key and tenant binding")
        await tx.query_raw('SELECT team_id FROM "LiteLLM_TeamTable" WHERE team_id=$1 FOR UPDATE', owner.team_id)
        team: Final = await tx.litellm_teamtable.find_unique(
            where={"team_id": owner.team_id}  # mutable-ok: Prisma input boundary.
        )
        if team is None or team.blocked or team.team_alias != "captify-tenant-" + body.tenant_id:
            raise HTTPException(409, "The owner's current tenant team is unavailable")
        await tx.query_raw(
            'SELECT server_id FROM "LiteLLM_MCPServerTable" WHERE server_name=$1 FOR UPDATE', "captify_tools"
        )
        servers: Final = await tx.litellm_mcpservertable.find_many(
            where={"server_name": "captify_tools"}  # mutable-ok: Prisma input boundary.
        )
        if len(servers) != 1:
            raise HTTPException(409, "The fixed tool server must resolve uniquely")
        server: Final = servers[0]
        if server.approval_status != "active" or "captify-tenant-" + body.tenant_id not in server.mcp_access_groups:
            raise HTTPException(409, "The fixed tool server is not active for this tenant")
        team_permission: Final = await _permission(tx, team.object_permission_id)
        if not _admits(team_permission, server):
            raise HTTPException(409, "The team has not admitted the fixed tool server")
        permission: Final = await _permission(tx, owner.object_permission_id)
        metadata: Final = _json_object(owner.metadata)
        admitted: Final = _admits(permission, server)
        if RECEIPT in metadata:
            receipt: Final = _json_object(metadata[RECEIPT])
            if (
                receipt.get("serverId") != server.server_id
                or receipt.get("tenantId") != body.tenant_id
                or receipt.get("actorId") != body.actor_id
                or not admitted
            ):
                raise HTTPException(
                    409, "The earlier tool association changed or was revoked; explicit review is required"
                )
            return ToolAccessResult(status="unchanged", serverId=server.server_id)
        if not admitted and permission is not None and (permission.blocked_tools or permission.mcp_tool_permissions):
            raise HTTPException(409, "Existing tool restrictions require explicit provisioning")
        permission_id: Final[str | None]
        if admitted:
            permission_id = owner.object_permission_id
        else:
            source: Final = (
                _json_object(permission.model_dump(exclude_none=True)) if permission else MappingProxyType({})
            )
            excluded: Final = frozenset(
                (
                    "object_permission_id",
                    "mcp_servers",
                    "teams",
                    "projects",
                    "verification_tokens",
                    "organizations",
                    "users",
                    "end_users",
                    "agents_table",
                )
            )
            granted: Final = await tx.litellm_objectpermissiontable.create(
                data={  # mutable-ok: Prisma input boundary.
                    **{  # mutable-ok: Prisma fields preserve unrelated restrictions.
                        key: json.dumps(value) if key == "mcp_tool_permissions" else value
                        for key, value in source.items()
                        if key not in excluded
                    },
                    "object_permission_id": str(uuid4()),
                    "mcp_servers": (
                        *TypeAdapter(tuple[str, ...]).validate_python(source.get("mcp_servers", ())),
                        server.server_id,
                    ),
                }
            )
            permission_id = granted.object_permission_id  # pyright: ignore[reportGeneralTypeIssues]  # Exclusive branch initializes Final once.
        await tx.litellm_verificationtoken.update(
            where={"token": body.owner_key_hash},  # mutable-ok: Prisma input boundary.
            data={  # mutable-ok: Prisma input boundary.
                "object_permission_id": permission_id,
                "metadata": json.dumps(
                    {  # mutable-ok: JSON serialization boundary.
                        **metadata,
                        RECEIPT: {  # mutable-ok: JSON serialization boundary.
                            "actorId": body.actor_id,
                            "tenantId": body.tenant_id,
                            "serverId": server.server_id,
                            "appPermissionRevision": body.app_permission_revision,
                        },
                    }
                ),
            },
        )
        return ToolAccessResult(status="unchanged" if admitted else "admitted", serverId=server.server_id)


@router.post("/captify/v1/agent-tools-access", response_model=ToolAccessResult)
async def agent_tools_access(
    body: ToolAccessRequest,
    identity: Annotated[UserAPIKeyAuth, Depends(user_api_key_auth)],
) -> ToolAccessResult:
    if identity.user_role != LitellmUserRoles.PROXY_ADMIN:
        raise HTTPException(403, "Only the provisioning operator can associate tool access")
    client: Final = proxy_server.prisma_client
    if client is None:
        raise HTTPException(503, "The tool registry is unavailable")
    database: Final[ToolDatabase] = client.db  # pyright: ignore[reportAssignmentType]  # Prisma wrapper delegates generated tables and tx.
    try:
        result: Final = await reconcile_tool_access(database, body)
    except HTTPException:
        raise
    except Exception as error:
        raise HTTPException(503, "The tool association could not be confirmed") from error
    await _delete_cache_key_object(
        hashed_token=body.owner_key_hash,
        user_api_key_cache=proxy_server.user_api_key_cache,
        proxy_logging_obj=proxy_server.proxy_logging_obj,
    )
    return result
