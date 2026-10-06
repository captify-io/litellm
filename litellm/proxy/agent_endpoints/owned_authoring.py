"""Transactional owner-bound authoring over the existing agent registry."""

from __future__ import annotations

import asyncio
import hashlib
import json
from collections.abc import Mapping, Sequence
from contextlib import AbstractAsyncContextManager
from datetime import UTC, datetime
from types import MappingProxyType, SimpleNamespace
from typing import TYPE_CHECKING, Annotated, Final, Literal, Protocol
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field, JsonValue, TypeAdapter

from litellm.models.object_permission import LiteLLM_ObjectPermissionTable as CachedObjectPermission
from litellm.proxy import proxy_server
from litellm.proxy._types import (
    LiteLLM_ObjectPermissionBase,
    LitellmUserRoles,
    UserAPIKeyAuth,
    user_api_key_has_admin_view,
)
from litellm.proxy.agent_endpoints.agent_registry import AgentRegistry, global_agent_registry
from litellm.proxy.auth.auth_checks import (
    _delete_cache_key_object,  # pyright: ignore[reportPrivateUsage]  # Reuse the existing key-cache invalidation contract.
)
from litellm.proxy.auth.user_api_key_auth import user_api_key_auth
from litellm.proxy.common_utils.rbac_utils import check_feature_access_for_user
from litellm.repositories.prisma_protocols import TableActions
from litellm.types.agents import AgentResponse

if TYPE_CHECKING:
    from prisma.models import (
        LiteLLM_AccessGroupTable,
        LiteLLM_AgentsTable,
        LiteLLM_ObjectPermissionTable,
        LiteLLM_TeamTable,
        LiteLLM_VerificationToken,
    )

    from litellm.proxy.utils import PrismaClient

router: Final = APIRouter()
JSON_OBJECT: Final = TypeAdapter(dict[str, JsonValue])
EMPTY_JSON: Final[Mapping[str, JsonValue]] = MappingProxyType({})


class AgentDatabase(Protocol):
    @property
    def litellm_agentstable(self) -> TableActions[LiteLLM_AgentsTable]: ...
    @property
    def litellm_objectpermissiontable(self) -> TableActions[LiteLLM_ObjectPermissionTable]: ...
    @property
    def litellm_verificationtoken(self) -> TableActions[LiteLLM_VerificationToken]: ...
    @property
    def litellm_teamtable(self) -> TableActions[LiteLLM_TeamTable]: ...
    @property
    def litellm_accessgrouptable(self) -> TableActions[LiteLLM_AccessGroupTable]: ...
    def tx(self) -> AbstractAsyncContextManager[AgentDatabase]: ...
    async def query_raw(self, query: str, *args: object) -> Sequence[Mapping[str, object]]: ...


def _database(client: PrismaClient) -> AgentDatabase:
    database: Final[AgentDatabase] = client.db  # pyright: ignore[reportAssignmentType]  # Prisma wrappers delegate generated tables and tx through __getattr__.
    return database


async def _declared_agent_ids(
    permission: LiteLLM_ObjectPermissionBase | LiteLLM_ObjectPermissionTable | CachedObjectPermission | None,
    access_group_ids: Sequence[str] | None,
    client: PrismaClient,
) -> frozenset[str] | None:
    """Resolve key/team declarations without upstream's fail-open exception wrappers."""
    direct: Final = tuple(permission.agents or ()) if permission is not None else ()
    native_groups: Final = tuple(permission.agent_access_groups or ()) if permission is not None else ()
    unified_groups: Final = tuple(access_group_ids or ())
    if not direct and not native_groups and not unified_groups:
        return None
    native_ids: Final[frozenset[str]]
    if native_groups:
        rows: Final = await _database(client).litellm_agentstable.find_many(
            where={"agent_access_groups": {"hasSome": list(native_groups)}}  # mutable-ok: Prisma JSON query.
        )
        configured: Final = AgentRegistry()
        configured.load_agents_from_config(global_agent_registry.config_agents)
        native_ids = frozenset(row.agent_id for row in rows) | frozenset(
            agent.agent_id
            for agent in configured.get_agent_list()
            if frozenset(
                TypeAdapter(tuple[str, ...]).validate_python(agent.model_dump().get("agent_access_groups") or ())
            )
            & frozenset(native_groups)
        )
    else:
        native_ids = frozenset()  # pyright: ignore[reportGeneralTypeIssues]  # Mutually exclusive branches initialize this deferred Final once.
    groups: Final = await asyncio.gather(
        *(
            _database(client).litellm_accessgrouptable.find_unique(
                where={"access_group_id": group_id}  # mutable-ok: Prisma JSON query.
            )
            for group_id in unified_groups
        )
    )
    # Removed or empty declared groups grant nothing; they remain restricted.
    unified_ids: Final = frozenset(
        agent_id for group in groups if group is not None for agent_id in group.access_agent_ids or ()
    )
    return frozenset(
        global_agent_registry.stable_agent_id(agent_id) for agent_id in frozenset(direct) | native_ids | unified_ids
    )


async def admit_authoring_read(agent_id: str, identity: UserAPIKeyAuth) -> None:
    """Retain upstream feature/role rules and key/team intersection; refuse lookup failures."""
    await check_feature_access_for_user(identity, "agents")
    if user_api_key_has_admin_view(identity):
        return
    client: Final = proxy_server.prisma_client
    if client is None:
        raise HTTPException(503, "The agent permission registry is unavailable")
    try:
        permission: Final = identity.object_permission
        if identity.object_permission_id is not None and permission is None:
            # An unloaded declared permission is uncertainty, never unrestricted access.
            raise HTTPException(503, "The caller's agent permission could not be resolved")
        key_ids: Final = await _declared_agent_ids(permission, identity.access_group_ids, client)
        team_ids: Final[frozenset[str] | None]
        if identity.team_id is not None:
            team: Final = await _database(client).litellm_teamtable.find_unique(
                where={  # mutable-ok: Prisma/JSON codec boundary.
                    "team_id": identity.team_id
                },
                include={"object_permission": True},  # mutable-ok: Prisma JSON input.
            )
            if team is None:
                raise HTTPException(403, "The caller's team no longer exists")
            if team.object_permission_id is not None and team.object_permission is None:
                raise HTTPException(503, "The team's agent permission could not be resolved")
            team_ids = await _declared_agent_ids(team.object_permission, team.access_group_ids, client)
        else:
            team_ids = None  # pyright: ignore[reportGeneralTypeIssues]  # Mutually exclusive branches initialize this deferred Final once.
    except HTTPException:
        raise
    except Exception as error:
        raise HTTPException(503, "The agent permissions could not be read") from error
    stable_id: Final = global_agent_registry.stable_agent_id(agent_id)
    if (key_ids is not None and stable_id not in key_ids) or (team_ids is not None and stable_id not in team_ids):
        raise HTTPException(403, "The requested agent is not allowed for the caller's key and team")


async def read_agent_record(
    agent_id: str,
    response: Response,
    identity: Annotated[UserAPIKeyAuth, Depends(user_api_key_auth)],
) -> AgentResponse:
    """Read committed authoring state after upstream's caller-key admission.

    Upstream's GET uses the process registry for configuration, refreshing only
    spend from the database. A registry reload or a different serving worker can
    therefore supply an older configuration immediately after a successful PATCH.
    Authoring and draft creation must read the committed row, including permissions.
    """
    from litellm.proxy.agent_endpoints.endpoints import (
        _attach_keys_to_agents,  # pyright: ignore[reportPrivateUsage, reportUnknownVariableType]  # Preserve the existing admin-only masked-key projection.
        _redact_sensitive_agent_fields,  # pyright: ignore[reportPrivateUsage]  # Preserve the upstream caller-role redaction.
    )

    await admit_authoring_read(agent_id, identity)
    client: Final = proxy_server.prisma_client
    if client is None:
        raise HTTPException(503, "The agent registry is unavailable")
    try:
        row: Final = await _database(client).litellm_agentstable.find_unique(
            where={"agent_id": global_agent_registry.stable_agent_id(agent_id)},  # mutable-ok: Prisma JSON input.
            include={"object_permission": True},  # mutable-ok: Prisma JSON input.
        )
    except Exception as error:
        # Never substitute a cached configuration when the committed read fails.
        raise HTTPException(503, "The agent record could not be read") from error
    record: Final[AgentResponse]
    if row is not None:
        record = AgentResponse.model_validate(row.model_dump())
        response.headers["X-Captify-Agent-Version"] = agent_record_version(row)  # rebind-ok: FastAPI response headers.
    else:
        # Config-only agents remain readable. Reconstruct from the declaration,
        # not the live registry: a deleted database row must not become a ghost.
        configured: Final = AgentRegistry()
        configured.load_agents_from_config(global_agent_registry.config_agents)
        configured_record: Final = configured.get_agent_by_id(agent_id=agent_id)
        if configured_record is None:
            raise HTTPException(404, f"Agent with ID {agent_id} not found")
        record = configured_record  # pyright: ignore[reportGeneralTypeIssues]  # Mutually exclusive branches initialize this deferred Final once.
    if identity.user_role == LitellmUserRoles.PROXY_ADMIN:
        await _attach_keys_to_agents((record,), client)
    response.headers["Cache-Control"] = "private, no-store"  # rebind-ok: FastAPI response headers.
    if identity.user_role == LitellmUserRoles.PROXY_ADMIN:
        return record
    return _redact_sensitive_agent_fields((record,))[0].model_copy(
        update={"keys": None}  # mutable-ok: Pydantic field update.
    )


def agent_record_version(row: BaseModel) -> str:
    """Opaque fence over the complete committed row and its loaded permission relation.

    The header discloses no hidden configuration. Unlike a behavior digest this includes
    timestamps, so deletion/recreation or an intervening ordinary write invalidates a read.
    """
    value: Final = row.model_dump(mode="json")
    return (
        "sha256:"
        + hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()
    )


class ConditionalAgentPatch(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    expected_version: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    patch: Mapping[str, JsonValue]


async def patch_agent_transaction(
    agent_id: str, body: ConditionalAgentPatch, identity: UserAPIKeyAuth
) -> tuple[AgentResponse, str]:
    """Compare and mutate under the authoritative database's row locks.

    Ordinary stock writers also acquire these row locks when they update. A writer
    committing first changes the compared version; one arriving later waits until
    this transaction completes. No process-local lock or unlocked read is a fence.
    """
    client: Final = proxy_server.prisma_client
    if client is None:
        raise HTTPException(503, "The agent registry is unavailable")
    allowed: Final = frozenset(
        (
            "agent_name",
            "litellm_params",
            "agent_card_params",
            "object_permission",
            "tpm_limit",
            "rpm_limit",
            "session_tpm_limit",
            "session_rpm_limit",
            "static_headers",
            "extra_headers",
        )
    )
    if not body.patch or frozenset(body.patch) - allowed:
        raise HTTPException(422, "Only declared partial agent fields may be updated")
    try:
        async with _database(client).tx() as tx:
            await tx.query_raw(
                'SELECT agent_id FROM "LiteLLM_AgentsTable" WHERE agent_id=$1 FOR UPDATE',
                agent_id,
            )
            locked: Final = await tx.litellm_agentstable.find_unique(
                where={  # mutable-ok: Prisma/JSON codec boundary.
                    "agent_id": agent_id
                }
            )
            if locked is None:
                # A config declaration cannot become an implicit database insertion.
                raise HTTPException(409, "The previously read database agent no longer exists")
            if locked.object_permission_id is not None:
                await tx.query_raw(
                    'SELECT object_permission_id FROM "LiteLLM_ObjectPermissionTable" WHERE object_permission_id=$1 FOR UPDATE',
                    locked.object_permission_id,
                )
            current: Final = await tx.litellm_agentstable.find_unique(
                where={  # mutable-ok: Prisma/JSON codec boundary.
                    "agent_id": agent_id
                },
                include={"object_permission": True},  # mutable-ok: Prisma JSON input.
            )
            if current is not None and current.object_permission_id is not None and current.object_permission is None:
                raise HTTPException(409, "The agent permission record is unavailable")
            if current is None or agent_record_version(current) != body.expected_version:
                raise HTTPException(
                    409,
                    "The agent changed after it was read; review the current record",
                )
            patch: Final[Mapping[str, JsonValue]]
            if "agent_card_params" in body.patch:
                proposed: Final = body.patch["agent_card_params"]
                if not isinstance(proposed, dict):
                    raise HTTPException(422, "The agent card must be an object")
                # This is a partial update of an already fronted, committed card.
                # Retain security/interfaces and all other unrelated fields exactly.
                patch = {  # mutable-ok: Registry JSON update.
                    **body.patch,
                    "agent_card_params": {  # mutable-ok: JSON card.
                        **_json_object(current.agent_card_params),
                        **proposed,
                    },
                }
            else:
                patch = body.patch  # pyright: ignore[reportGeneralTypeIssues]  # Mutually exclusive branches initialize this deferred Final once.
            result: Final = await global_agent_registry.patch_agent_in_db(
                agent_id=agent_id,
                agent=patch,  # pyright: ignore[reportArgumentType]  # Retain JSON card extensions after the explicit field allowlist.
                prisma_client=SimpleNamespace(db=tx),  # pyright: ignore[reportArgumentType]  # The registry uses only db; this binds every write to the held transaction.
                updated_by=identity.user_id or "unknown",
            )
            confirmed: Final = await tx.litellm_agentstable.find_unique(
                where={  # mutable-ok: Prisma/JSON codec boundary.
                    "agent_id": agent_id
                },
                include={"object_permission": True},  # mutable-ok: Prisma JSON input.
            )
            if confirmed is None:
                raise HTTPException(503, "The updated agent could not be confirmed")
            version: Final = agent_record_version(confirmed)
    except HTTPException:
        raise
    except Exception as error:
        # Do not advertise a retry: transaction/commit acknowledgement can be uncertain.
        raise HTTPException(503, "The conditional agent update could not be confirmed") from error
    global_agent_registry.deregister_agent(agent_name=current.agent_name)
    global_agent_registry.register_agent(agent_config=result)
    return result, version


@router.patch(
    "/captify/v1/agents/{agent_id}",
    response_model=AgentResponse,
    tags=["Captify agent authoring"],  # mutable-ok: FastAPI requires list metadata.
)
async def patch_agent_conditionally(
    agent_id: str,
    body: ConditionalAgentPatch,
    response: Response,
    identity: Annotated[UserAPIKeyAuth, Depends(user_api_key_auth)],
) -> AgentResponse:
    from litellm.proxy.agent_endpoints.endpoints import (
        _check_agent_management_permission,  # pyright: ignore[reportPrivateUsage]  # Keep the upstream proxy-admin mutation gate.
    )

    await check_feature_access_for_user(identity, "agents")
    _check_agent_management_permission(identity)
    record, version = await patch_agent_transaction(agent_id, body, identity)
    response.headers["X-Captify-Agent-Version"] = version  # rebind-ok: FastAPI response headers.
    return record


class OwnedAgentCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    agent_id: str = Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$")
    actor_id: str = Field(min_length=1, max_length=200)
    tenant_id: str = Field(min_length=1, max_length=200)
    owner_key_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    record: Mapping[str, JsonValue]


def creation_record(body: OwnedAgentCreate) -> tuple[Mapping[str, JsonValue], str]:
    """Pin the original request independently of subsequent mutable edits."""
    if frozenset(body.record) - frozenset(
        (
            "agent_name",
            "agent_card_params",
            "litellm_params",
            "object_permission",
        )
    ):
        raise HTTPException(422, "Only the declared agent configuration can be created")
    name: Final = body.record.get("agent_name")
    params: Final = body.record.get("litellm_params")
    if not isinstance(name, str) or not name.strip() or len(name) > 256:
        raise HTTPException(422, "A nonempty agent name is required")
    if not isinstance(params, dict) or params.get("captify_created_by") != body.actor_id:
        raise HTTPException(422, "The record must name its admitted creator")
    if params.get("make_public") or params.get("is_public"):
        raise HTTPException(422, "Owned agent creation cannot grant public access")
    permissions: Final = body.record.get("object_permission", EMPTY_JSON)
    if not isinstance(permissions, Mapping) or frozenset(permissions) - frozenset(
        (
            "mcp_tool_permissions",
            "agents",
            "mcp_servers",
        )
    ):
        raise HTTPException(422, "Agent permissions contain an unsupported field")
    digest: Final = hashlib.sha256(
        json.dumps(
            {  # mutable-ok: Prisma/JSON codec boundary.
                "actor": body.actor_id,
                "tenant": body.tenant_id,
                "record": body.record,
            },
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode()
    ).hexdigest()
    return {  # mutable-ok: JSON serialization boundary.
        **body.record,
        "litellm_params": {  # mutable-ok: JSON serialization boundary.
            **params,
            "captify_tenant_id": body.tenant_id,
            "captify_creation_digest": digest,
        },
    }, digest


def _json_object(value: object) -> Mapping[str, JsonValue]:
    result: Final = json.loads(value) if isinstance(value, str) else value
    return MappingProxyType(JSON_OBJECT.validate_python(result)) if isinstance(result, dict) else MappingProxyType({})


async def _require_creation_team(tx: AgentDatabase, owner: LiteLLM_VerificationToken) -> None:
    # Team scope is an independent ceiling. An unrestricted, active team
    # already admits new agents; membership alone must not prevent authoring.
    # Lock both rows so an overlapping restriction cannot be missed. Never
    # change the team or its grants while provisioning an individual owner.
    if owner.team_id is not None:
        await tx.query_raw(
            'SELECT team_id FROM "LiteLLM_TeamTable" WHERE team_id=$1 FOR UPDATE',
            owner.team_id,
        )
        team: Final = await tx.litellm_teamtable.find_unique(
            where={  # mutable-ok: Prisma/JSON codec boundary.
                "team_id": owner.team_id
            }
        )
        if team is None or team.blocked:
            raise HTTPException(409, "The creator's team is unavailable")
        team_permission: Final[LiteLLM_ObjectPermissionTable | None]
        if team.object_permission_id is not None:
            await tx.query_raw(
                'SELECT object_permission_id FROM "LiteLLM_ObjectPermissionTable" WHERE object_permission_id=$1 FOR UPDATE',
                team.object_permission_id,
            )
            team_permission = await tx.litellm_objectpermissiontable.find_unique(
                where={"object_permission_id": team.object_permission_id}  # mutable-ok: Prisma JSON input.
            )
            if team_permission is None:
                raise HTTPException(409, "The team's permission record is unavailable")
        else:
            team_permission = None  # pyright: ignore[reportGeneralTypeIssues]  # Mutually exclusive branches initialize this deferred Final once.  # pyright: ignore[reportGeneralTypeIssues]  # Mutually exclusive branches initialize this deferred Final once.
        if team.access_group_ids or (
            team_permission and (team_permission.agents or team_permission.agent_access_groups)
        ):
            raise HTTPException(409, "The team's agent restrictions require explicit provisioning")


async def create_owned_agent_transaction(body: OwnedAgentCreate, http_request: Request) -> AgentResponse:
    from litellm.proxy.agent_endpoints.endpoints import (
        _build_merged_agent_card,  # pyright: ignore[reportPrivateUsage]  # Keep the standard public gateway card transformation.
    )

    record, digest = creation_record(body)
    agent_name: Final = record["agent_name"]
    if not isinstance(agent_name, str):
        raise HTTPException(422, "A nonempty agent name is required")
    client: Final = proxy_server.prisma_client
    if client is None:
        raise HTTPException(503, "The agent registry is unavailable")
    # One key lock serializes concurrent creations. Permission copies are linked
    # in the same transaction, so a shared permission row never grants a new
    # agent to a different key, team or user. No existing field is replaced.
    async with _database(client).tx() as tx:
        await tx.query_raw(
            'SELECT token FROM "LiteLLM_VerificationToken" WHERE token=$1 FOR UPDATE',
            body.owner_key_hash,
        )
        owner: Final = await tx.litellm_verificationtoken.find_unique(
            where={  # mutable-ok: Prisma/JSON codec boundary.
                "token": body.owner_key_hash
            }
        )
        if (
            owner is None
            or owner.user_id != body.actor_id
            or owner.blocked
            or (owner.expires is not None and owner.expires <= datetime.now(UTC))
        ):
            raise HTTPException(403, "The creator has no active matching gateway key")
        await _require_creation_team(tx, owner)
        await tx.query_raw(
            "SELECT 1 FROM pg_advisory_xact_lock(hashtextextended($1, 0))",
            "captify-agent:" + body.agent_id,
        )
        existing: Final = await tx.litellm_agentstable.find_unique(
            where={  # mutable-ok: Prisma/JSON codec boundary.
                "agent_id": body.agent_id
            }
        )
        result: Final[LiteLLM_AgentsTable]
        if existing is not None:
            params: Final = _json_object(existing.litellm_params)
            if (
                params.get("captify_created_by"),
                params.get("captify_tenant_id"),
                params.get("captify_creation_digest"),
            ) != (
                body.actor_id,
                body.tenant_id,
                digest,
            ):
                raise HTTPException(
                    409,
                    "The requested identity already belongs to a different creation",
                )
            # A replay never restores a grant somebody subsequently revoked.
            result = existing
        else:
            # Different creators can race on the global unique name. Serialize
            # that check too, so the loser gets a stable conflict, not a Prisma
            # uniqueness exception after beginning an ownership transaction.
            await tx.query_raw(
                "SELECT 1 FROM pg_advisory_xact_lock(hashtextextended($1, 0))",
                "captify-agent-name:" + agent_name,
            )
            collision: Final = await tx.litellm_agentstable.find_unique(
                where={  # mutable-ok: Prisma/JSON codec boundary.
                    "agent_name": agent_name
                }
            )
            if collision is not None or global_agent_registry.get_agent_by_name(agent_name=agent_name) is not None:
                raise HTTPException(409, "An agent with that name already exists")
            declared_card: Final = record.get("agent_card_params")
            card: Final = (
                _build_merged_agent_card(
                    declared_card,  # pyright: ignore[reportArgumentType]  # Preserve validated JSON card extension fields beyond the stock TypedDict.
                    agent_id=body.agent_id,
                    http_request=http_request,
                    agent_name=agent_name,
                )
                if declared_card is not None
                else None
            )
            declared_permissions: Final = _json_object(record.get("object_permission"))
            agent_permissions: Final = {  # mutable-ok: Prisma JSON fields.
                key: json.dumps(value) if key == "mcp_tool_permissions" else value
                for key, value in declared_permissions.items()
            }
            agent_grant: Final = (
                await tx.litellm_objectpermissiontable.create(data=agent_permissions) if agent_permissions else None
            )
            result = await tx.litellm_agentstable.create(  # pyright: ignore[reportGeneralTypeIssues]  # Mutually exclusive branches initialize this deferred Final once.
                data={  # mutable-ok: Prisma JSON input.
                    "agent_id": body.agent_id,
                    "agent_name": agent_name,
                    "litellm_params": json.dumps(record["litellm_params"]),
                    "agent_card_params": json.dumps(card or {}),  # mutable-ok: Prisma JSON input.
                    "created_by": body.actor_id,
                    "updated_by": body.actor_id,
                    **(
                        {  # mutable-ok: Prisma/JSON codec boundary.
                            "object_permission_id": agent_grant.object_permission_id
                        }
                        if agent_grant
                        else {  # mutable-ok: Prisma/JSON codec boundary.
                        }
                    ),
                },
                include={"object_permission": True},  # mutable-ok: Prisma JSON input.
            )
            permission: Final[LiteLLM_ObjectPermissionTable | None]
            if owner.object_permission_id is not None:
                await tx.query_raw(
                    'SELECT object_permission_id FROM "LiteLLM_ObjectPermissionTable" WHERE object_permission_id=$1 FOR UPDATE',
                    owner.object_permission_id,
                )
                permission = await tx.litellm_objectpermissiontable.find_unique(
                    where={"object_permission_id": owner.object_permission_id}  # mutable-ok: Prisma JSON input.
                )
                if permission is None:
                    raise HTTPException(409, "The creator's permission record is unavailable")
            else:
                permission = None  # pyright: ignore[reportGeneralTypeIssues]  # Mutually exclusive branches initialize this deferred Final once.
            # Upstream defines no agent declarations as unrestricted. Preserve
            # that pre-existing scope; adding one declaration would narrow it.
            restricted: Final = bool(
                owner.access_group_ids or (permission and (permission.agents or permission.agent_access_groups))
            )
            if restricted:
                source_permission: Final = (
                    _json_object(permission.model_dump(exclude_none=True)) if permission else EMPTY_JSON
                )
                relation_fields: Final = frozenset(
                    (
                        "teams",
                        "projects",
                        "verification_tokens",
                        "organizations",
                        "users",
                        "end_users",
                        "agents_table",
                        "object_permission_id",
                        "agents",
                    )
                )
                permission_data: Final = {  # mutable-ok: Prisma JSON row.
                    **{  # mutable-ok: Prisma JSON row fields.
                        key: json.dumps(value) if key == "mcp_tool_permissions" else value
                        for key, value in source_permission.items()
                        if key not in relation_fields
                    },
                    "object_permission_id": str(uuid4()),
                    "agents": tuple(
                        dict.fromkeys(
                            (
                                *TypeAdapter(tuple[str, ...]).validate_python(source_permission.get("agents", ())),
                                body.agent_id,
                            )
                        )
                    ),
                }
                granted: Final = await tx.litellm_objectpermissiontable.create(data=permission_data)
                await tx.litellm_verificationtoken.update(
                    where={"token": body.owner_key_hash},  # mutable-ok: Prisma JSON input.
                    data={"object_permission_id": granted.object_permission_id},  # mutable-ok: Prisma JSON input.
                )
    response: Final = AgentResponse.model_validate(result.model_dump())
    global_agent_registry.register_agent(agent_config=response)
    # Invalidate the serving worker and the shared cache, then notify peers.
    # Platform confirms access with a separate request under the caller key.
    await _delete_cache_key_object(
        hashed_token=body.owner_key_hash,
        user_api_key_cache=proxy_server.user_api_key_cache,
        proxy_logging_obj=proxy_server.proxy_logging_obj,
    )
    return response


@router.post(
    "/captify/v1/agents",
    response_model=AgentResponse,
    tags=["Captify agent authoring"],  # mutable-ok: FastAPI list metadata.
)
async def create_owned_agent(
    body: OwnedAgentCreate,
    request: Request,
    identity: Annotated[UserAPIKeyAuth, Depends(user_api_key_auth)],
) -> AgentResponse:
    from litellm.proxy.agent_endpoints.endpoints import (
        _check_agent_management_permission,  # pyright: ignore[reportPrivateUsage]  # Keep the upstream proxy-admin mutation gate.
    )

    _check_agent_management_permission(identity)
    return await create_owned_agent_transaction(body, request)


class AgentAuthoringCapabilities(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    schemaVersion: Literal[1] = 1
    ownedCreate: Literal[True] = True
    conditionalUpdate: Literal[True] = True
    authoritativeRead: Literal[True] = True
    versionHeader: Literal["X-Captify-Agent-Version"] = "X-Captify-Agent-Version"


@router.get("/captify/v1/agent-authoring-capabilities", response_model=AgentAuthoringCapabilities)
async def agent_authoring_capabilities(
    response: Response,
    identity: Annotated[UserAPIKeyAuth, Depends(user_api_key_auth)],
) -> AgentAuthoringCapabilities:
    response.headers["Cache-Control"] = "private, no-store"  # rebind-ok: FastAPI response headers.
    return AgentAuthoringCapabilities()
