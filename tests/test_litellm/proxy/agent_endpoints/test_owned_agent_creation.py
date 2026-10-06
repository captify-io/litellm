"""Owned creation preserves independent team/key grants in real PostgreSQL."""

import asyncio
import hashlib
import json
import os
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest import IsolatedAsyncioTestCase, skipUnless
from unittest.mock import AsyncMock, patch
from uuid import uuid4

from fastapi import HTTPException
from prisma import Prisma
from starlette.requests import Request

from litellm.proxy.agent_endpoints import owned_authoring as gateway
from litellm.proxy.common_utils import config_sync_pubsub
from tests.test_litellm.proxy.agent_endpoints.test_conditional_authoring import CommittedReadRedis

URL = os.environ.get("CAPTIFY_CAS_TEST_DATABASE_URL", "")
SAFE_URLS = (
    "postgresql://cas_review:synthetic-cas-test-only@127.0.0.1:55438/cas_review",
    "postgresql://cas_review:synthetic-cas-test-only@127.0.0.1:55446/cas_review",
    "postgresql://postgres:postgres@localhost:5432/litellm_test",
)


@skipUnless(URL in SAFE_URLS, "requires isolated test database")
class OwnedAgentCreationTests(IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.db = Prisma(datasource={"url": URL})
        await self.db.connect()
        self.addAsyncCleanup(self.db.disconnect)
        self.actor = "owned-test-" + uuid4().hex
        self.team_id = self.actor + "-team"
        self.agent_id = self.actor + "-agent"
        self.token = hashlib.sha256(self.actor.encode()).hexdigest()
        self.permission_ids = []
        self.enterContext(
            patch.object(  # test-quality-ok: Restored upstream singleton.
                gateway.proxy_server, "prisma_client", SimpleNamespace(db=self.db)
            )
        )
        self.enterContext(
            patch.object(  # test-quality-ok: Restored upstream singleton.
                gateway, "_delete_cache_key_object", AsyncMock()
            )
        )
        self.enterContext(
            patch.object(  # test-quality-ok: Restored upstream singleton.
                gateway.global_agent_registry, "register_agent"
            )
        )
        self.enterContext(
            patch.object(  # test-quality-ok: Restored upstream singleton.
                gateway.global_agent_registry, "get_agent_by_name", return_value=None
            )
        )
        team_permission = await self.permission(mcp_servers=["team-tools"])
        self.team = await self.db.litellm_teamtable.create(
            data={
                "team_id": self.team_id,
                "object_permission_id": team_permission.object_permission_id,
                "models": ["allowed-model"],
                "max_budget": 7,
                "members_with_roles": json.dumps([{"user_id": self.actor, "role": "user"}]),
            }
        )
        self.key_permission = await self.permission(mcp_servers=["personal-tools"])
        await self.db.litellm_verificationtoken.create(
            data={
                "token": self.token,
                "user_id": self.actor,
                "team_id": self.team_id,
                "models": ["allowed-model"],
                "object_permission_id": self.key_permission.object_permission_id,
            }
        )
        self.request = Request(
            {
                "type": "http",
                "method": "POST",
                "scheme": "http",
                "server": ("localhost", 80),
                "path": "/captify/v1/agents",
                "headers": [],
            }
        )
        self.body = gateway.OwnedAgentCreate(
            agent_id=self.agent_id,
            actor_id=self.actor,
            tenant_id="test",
            owner_key_hash=self.token,
            record={
                "agent_name": self.agent_id,
                "litellm_params": {"model": "allowed-model", "captify_created_by": self.actor},
            },
        )
        self.addAsyncCleanup(self.cleanup)

    async def permission(self, **data):
        permission = await self.db.litellm_objectpermissiontable.create(data=data)
        self.permission_ids.append(permission.object_permission_id)
        return permission

    async def cleanup(self):
        owner = await self.owner()
        if owner and owner.object_permission_id not in self.permission_ids:
            self.permission_ids.append(owner.object_permission_id)
        await self.db.litellm_verificationtoken.delete_many(where={"user_id": self.actor})
        await self.db.litellm_agentstable.delete_many(where={"created_by": self.actor})
        await self.db.litellm_teamtable.delete_many(where={"team_id": self.team_id})
        await self.db.litellm_objectpermissiontable.delete_many(
            where={"object_permission_id": {"in": self.permission_ids}}
        )

    async def owner(self):
        return await self.db.litellm_verificationtoken.find_unique(where={"token": self.token})

    async def create(self):
        return await gateway.create_owned_agent_transaction(self.body, self.request)

    async def test_creation_notification_observes_committed_agent_and_owner_grant(self):
        await self.db.litellm_objectpermissiontable.update(
            where={"object_permission_id": self.key_permission.object_permission_id},
            data={"agents": ["existing-fixture"]},
        )
        observed = []

        async def observe():
            row = await self.db.litellm_agentstable.find_unique(where={"agent_id": self.agent_id})
            owner = await self.owner()
            grant = await self.db.litellm_objectpermissiontable.find_unique(
                where={"object_permission_id": owner.object_permission_id}
            )
            observed.append((row.agent_id if row else None, self.agent_id in grant.agents))

        redis = CommittedReadRedis(observe)
        self.addAsyncCleanup(redis.aclose)
        cache = SimpleNamespace(namespace=None, init_async_client=lambda: redis)
        self.enterContext(
            patch.object(  # test-quality-ok: Redis transport boundary observes committed database state.
                config_sync_pubsub, "coordination_redis_cache", return_value=cache
            )
        )
        await self.create()
        self.assertTrue(observed)
        self.assertEqual(observed[-1], (self.agent_id, True))

    async def test_redis_failure_does_not_turn_committed_creation_into_an_error(self):
        observed = []

        async def unavailable():
            row = await self.db.litellm_agentstable.find_unique(where={"agent_id": self.agent_id})
            observed.append(row.agent_id if row else None)
            raise ConnectionError("isolated Redis transport failure")

        redis = CommittedReadRedis(unavailable)
        self.addAsyncCleanup(redis.aclose)
        cache = SimpleNamespace(namespace=None, init_async_client=lambda: redis)
        self.enterContext(
            patch.object(  # test-quality-ok: Fail the Redis transport while using real database writes.
                config_sync_pubsub, "coordination_redis_cache", return_value=cache
            )
        )
        response = await self.create()
        self.assertEqual(response.agent_id, self.agent_id)
        self.assertEqual(observed, [self.agent_id])
        self.assertIsNotNone(await self.db.litellm_agentstable.find_unique(where={"agent_id": self.agent_id}))

    async def assert_refused_without_write(self):
        before = (await self.owner()).model_dump()
        with self.assertRaises(HTTPException) as caught:
            await self.create()
        self.assertEqual(caught.exception.status_code, 409)
        self.assertIsNone(await self.db.litellm_agentstable.find_unique(where={"agent_id": self.agent_id}))
        self.assertEqual((await self.owner()).model_dump(), before)

    async def test_unrestricted_team_member_creates_without_changing_any_grant(self):
        before = (await self.owner()).model_dump()
        result = await self.create()
        self.assertEqual(result.agent_id, self.agent_id)
        self.assertEqual((await self.owner()).model_dump(), before)
        self.assertEqual(
            (await self.db.litellm_teamtable.find_unique(where={"team_id": self.team_id})).model_dump(),
            self.team.model_dump(),
        )
        permission = await self.db.litellm_objectpermissiontable.find_unique(
            where={"object_permission_id": self.key_permission.object_permission_id}
        )
        self.assertEqual(permission.model_dump(), self.key_permission.model_dump())

    async def test_restricted_personal_key_gets_only_its_owned_agent_without_widening_shared_permission(self):
        await self.db.litellm_objectpermissiontable.update(
            where={"object_permission_id": self.key_permission.object_permission_id},
            data={"agents": ["existing-agent"]},
        )
        await self.create()
        owner = await self.owner()
        self.assertNotEqual(owner.object_permission_id, self.key_permission.object_permission_id)
        permission = await self.db.litellm_objectpermissiontable.find_unique(
            where={"object_permission_id": owner.object_permission_id}
        )
        self.assertEqual(permission.agents, ["existing-agent", self.agent_id])
        self.assertEqual(permission.mcp_servers, ["personal-tools"])
        original = await self.db.litellm_objectpermissiontable.find_unique(
            where={"object_permission_id": self.key_permission.object_permission_id}
        )
        self.assertEqual(original.agents, ["existing-agent"])

    async def test_team_agent_allowlist_is_not_widened(self):
        await self.db.litellm_objectpermissiontable.update(
            where={"object_permission_id": self.team.object_permission_id}, data={"agents": ["only-admitted-agent"]}
        )
        await self.assert_refused_without_write()

    async def test_team_agent_access_group_is_not_widened(self):
        await self.db.litellm_objectpermissiontable.update(
            where={"object_permission_id": self.team.object_permission_id},
            data={"agent_access_groups": ["only-admitted-group"]},
        )
        await self.assert_refused_without_write()

    async def test_team_access_group_is_not_bypassed(self):
        await self.db.litellm_teamtable.update(
            where={"team_id": self.team_id}, data={"access_group_ids": ["restricted-group"]}
        )
        await self.assert_refused_without_write()

    async def test_blocked_team_is_refused(self):
        await self.db.litellm_teamtable.update(where={"team_id": self.team_id}, data={"blocked": True})
        await self.assert_refused_without_write()

    async def test_missing_team_is_refused(self):
        await self.db.litellm_teamtable.delete(where={"team_id": self.team_id})
        await self.assert_refused_without_write()

    async def test_concurrent_replay_creates_exactly_one_owned_agent(self):
        results = await asyncio.gather(self.create(), self.create())
        self.assertEqual([r.agent_id for r in results], [self.agent_id, self.agent_id])
        self.assertEqual(await self.db.litellm_agentstable.count(where={"created_by": self.actor}), 1)

    async def test_wrong_blocked_and_expired_owner_keys_leave_no_agent(self):
        for case in ("wrong-actor", "blocked", "expired"):
            with self.subTest(case=case):
                await self.db.litellm_verificationtoken.update(
                    where={"token": self.token},
                    data={
                        "blocked": case == "blocked",
                        "expires": datetime.now(UTC) - timedelta(minutes=1) if case == "expired" else None,
                    },
                )
                body = self.body.model_copy(update={"actor_id": "other-actor"}) if case == "wrong-actor" else self.body
                if case == "wrong-actor":
                    body = body.model_copy(
                        update={"record": {**body.record, "litellm_params": {"captify_created_by": "other-actor"}}}
                    )
                before = (await self.owner()).model_dump()
                with self.assertRaises(HTTPException) as caught:
                    await gateway.create_owned_agent_transaction(body, self.request)
                self.assertEqual(caught.exception.status_code, 403)
                self.assertIsNone(await self.db.litellm_agentstable.find_unique(where={"agent_id": self.agent_id}))
                self.assertEqual((await self.owner()).model_dump(), before)

    async def test_missing_permission_lookup_rolls_back_inserted_agent(self):
        await self.db.litellm_objectpermissiontable.update(
            where={"object_permission_id": self.key_permission.object_permission_id},
            data={"agents": ["existing-agent"]},
        )
        actions = type(self.db.litellm_objectpermissiontable)
        original = actions.find_unique
        reached_post_insert = []

        async def failed_permission_lookup(action, *args, **kwargs):
            if kwargs.get("where") == {"object_permission_id": self.key_permission.object_permission_id}:
                row = await action._client.litellm_agentstable.find_unique(where={"agent_id": self.agent_id})
                reached_post_insert.append(row is not None)
                return None
            return await original(action, *args, **kwargs)

        with patch.object(actions, "find_unique", failed_permission_lookup):
            await self.assert_refused_without_write()
        self.assertEqual(reached_post_insert, [True])
        self.assertIsNone(await self.db.litellm_agentstable.find_unique(where={"agent_id": self.agent_id}))

    async def test_exact_replay_preserves_revoked_creator_grant(self):
        await self.db.litellm_objectpermissiontable.update(
            where={"object_permission_id": self.key_permission.object_permission_id},
            data={"agents": ["existing-agent"]},
        )
        await self.create()
        owner = await self.owner()
        await self.db.litellm_objectpermissiontable.update(
            where={"object_permission_id": owner.object_permission_id}, data={"agents": ["existing-agent"]}
        )
        before_owner = (await self.owner()).model_dump()
        before_permission = await self.db.litellm_objectpermissiontable.find_unique(
            where={"object_permission_id": owner.object_permission_id}
        )
        result = await self.create()
        self.assertEqual(result.agent_id, self.agent_id)
        self.assertEqual((await self.owner()).model_dump(), before_owner)
        after_permission = await self.db.litellm_objectpermissiontable.find_unique(
            where={"object_permission_id": owner.object_permission_id}
        )
        self.assertEqual(after_permission.model_dump(), before_permission.model_dump())
        self.assertNotIn(self.agent_id, after_permission.agents)
        self.assertEqual(await self.db.litellm_agentstable.count(where={"created_by": self.actor}), 1)
