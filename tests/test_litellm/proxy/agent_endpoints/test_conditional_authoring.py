"""Real PostgreSQL concurrency; requires the explicitly isolated disposable test database."""

import asyncio
import json
import os
from types import SimpleNamespace
from unittest import IsolatedAsyncioTestCase, skipUnless
from unittest.mock import patch
from uuid import uuid4

from fastapi import HTTPException, Response
from litellm.proxy._types import LitellmUserRoles, UserAPIKeyAuth
from prisma import Prisma

from litellm.proxy.agent_endpoints import owned_authoring as gateway

TEST_URL = os.environ.get("CAPTIFY_CAS_TEST_DATABASE_URL", "")
SAFE_URLS = (
    "postgresql://cas_review:synthetic-cas-test-only@127.0.0.1:55438/cas_review",
    "postgresql://postgres:postgres@localhost:5432/litellm_test",
)


@skipUnless(TEST_URL in SAFE_URLS, "requires the disposable localhost CAS test database")
class ConditionalAuthoringPostgresTests(IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.db = Prisma(datasource={"url": TEST_URL})
        self.other = Prisma(datasource={"url": TEST_URL})
        await self.db.connect()
        await self.other.connect()
        self.addAsyncCleanup(self.db.disconnect)
        self.addAsyncCleanup(self.other.disconnect)
        self.enterContext(
            patch.object(  # test-quality-ok: Restored upstream singleton.
                gateway.proxy_server, "prisma_client", SimpleNamespace(db=self.db)
            )
        )
        self.enterContext(
            patch.object(  # test-quality-ok: Restored upstream singleton.
                gateway.proxy_server, "general_settings", {}
            )
        )
        self.identity = UserAPIKeyAuth(user_role=LitellmUserRoles.PROXY_ADMIN, user_id="synthetic-reviewer")
        self.id = "cas-" + str(uuid4())
        self.card = {
            "name": "Synthetic",
            "description": "Before",
            "version": "9.2",
            "provider": {"url": "https://example.invalid"},
            "security": [{"existing": []}],
            "customExtension": {"retained": True},
            "skills": [],
        }
        self.permission = await self.db.litellm_objectpermissiontable.create(data={"agents": ["existing-target"]})
        await self.db.litellm_agentstable.create(
            data={
                "agent_id": self.id,
                "agent_name": self.id,
                "litellm_params": json.dumps({"model": "synthetic", "tenant_id": "test"}),
                "agent_card_params": json.dumps(self.card),
                "created_by": "synthetic",
                "updated_by": "synthetic",
                "object_permission_id": self.permission.object_permission_id,
            }
        )
        self.addAsyncCleanup(self.cleanup)

    async def cleanup(self):
        await self.db.litellm_agentstable.delete_many(where={"agent_id": self.id})
        await self.db.litellm_objectpermissiontable.delete_many(
            where={"object_permission_id": self.permission.object_permission_id}
        )

    async def read(self):
        return await self.db.litellm_agentstable.find_unique(
            where={"agent_id": self.id}, include={"object_permission": True}
        )

    async def change(self, version, description):
        return await gateway.patch_agent_conditionally(
            self.id,
            gateway.ConditionalAgentPatch(
                expected_version=version,
                patch={"agent_card_params": {"description": description}},
            ),
            Response(),
            self.identity,
        )

    async def blocked_on_row(self):
        # Observe an actual backend waiting on a database lock, not a wall-clock guess.
        for _ in range(100):
            rows = await self.other.query_raw(
                "SELECT pid FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%LiteLLM_%' AND pid<>pg_backend_pid()"
            )
            if rows:
                return
            await asyncio.sleep(0.02)
        self.fail("No independent database connection was blocked on the row lock")

    async def test_two_guarded_writers_have_exactly_one_winner_and_preserve_card(self):
        version = gateway.agent_record_version(await self.read())
        outcomes = await asyncio.gather(
            self.change(version, "First"),
            self.change(version, "Second"),
            return_exceptions=True,
        )
        failures = [item for item in outcomes if isinstance(item, Exception)]
        self.assertEqual(len(failures), 1)
        self.assertIsInstance(failures[0], HTTPException)
        self.assertEqual(failures[0].status_code, 409)
        saved = await self.read()
        card = gateway._json_object(saved.agent_card_params)
        self.assertIn(card["description"], ["First", "Second"])
        self.assertEqual(
            {k: v for k, v in card.items() if k != "description"},
            {k: v for k, v in self.card.items() if k != "description"},
        )
        self.assertNotEqual(gateway.agent_record_version(saved), version)

    async def test_write_reply_names_the_committed_version_and_can_fence_a_second_edit(self):
        original = gateway.agent_record_version(await self.read())
        response = Response()
        await gateway.patch_agent_conditionally(
            self.id,
            gateway.ConditionalAgentPatch(
                expected_version=original,
                patch={"agent_card_params": {"description": "First edit"}},
            ),
            response,
            self.identity,
        )
        confirmed = response.headers["X-Captify-Agent-Version"]
        self.assertEqual(confirmed, gateway.agent_record_version(await self.read()))
        self.assertNotEqual(original, confirmed)
        await self.change(confirmed, "Second edit")
        self.assertEqual(
            gateway._json_object((await self.read()).agent_card_params)["description"],
            "Second edit",
        )
        with self.assertRaises(HTTPException) as stale:
            await self.change(confirmed, "Cannot reuse an old acknowledgement")
        self.assertEqual(stale.exception.status_code, 409)

    async def test_stock_row_writer_blocks_guarded_read_then_version_refuses(self):
        version = gateway.agent_record_version(await self.read())
        async with self.other.tx() as tx:
            await tx.litellm_agentstable.update(
                where={"agent_id": self.id},
                data={"litellm_params": json.dumps({"model": "stock-writer-won"})},
            )
            pending = asyncio.create_task(self.change(version, "Must refuse"))
            await self.blocked_on_row()
            self.assertFalse(pending.done())
        with self.assertRaises(HTTPException) as caught:
            await pending
        self.assertEqual(caught.exception.status_code, 409)
        saved = await self.read()
        self.assertEqual(gateway._json_object(saved.litellm_params)["model"], "stock-writer-won")
        self.assertEqual(gateway._json_object(saved.agent_card_params), self.card)

    async def test_permission_writer_is_also_fenced_before_version_comparison(self):
        version = gateway.agent_record_version(await self.read())
        async with self.other.tx() as tx:
            await tx.litellm_objectpermissiontable.update(
                where={"object_permission_id": self.permission.object_permission_id},
                data={"agents": ["changed-target"]},
            )
            pending = asyncio.create_task(self.change(version, "Must refuse"))
            await self.blocked_on_row()
        with self.assertRaises(HTTPException) as caught:
            await pending
        self.assertEqual(caught.exception.status_code, 409)
        self.assertEqual((await self.read()).object_permission.agents, ["changed-target"])

    async def test_guarded_tool_update_preserves_other_permission_fields(self):
        before = await self.read()
        response = Response()
        try:
            await gateway.patch_agent_conditionally(
                self.id,
                gateway.ConditionalAgentPatch(
                    expected_version=gateway.agent_record_version(before),
                    patch={
                        "object_permission": {
                            "mcp_tool_permissions": {"captify_tools": ["ontology_describe", "objectset_read"]}
                        }
                    },
                ),
                response,
                self.identity,
            )
        except HTTPException as error:
            # This isolated synthetic fixture has no credentials or private content.
            raise AssertionError(str(error.__cause__)) from error
        after = await self.read()
        self.assertEqual(after.object_permission_id, before.object_permission_id)
        self.assertEqual(after.object_permission.agents, ["existing-target"])
        self.assertEqual(
            gateway._json_object(after.object_permission.mcp_tool_permissions),
            {"captify_tools": ["ontology_describe", "objectset_read"]},
        )
        self.assertEqual(response.headers["X-Captify-Agent-Version"], gateway.agent_record_version(after))
        self.assertNotEqual(gateway.agent_record_version(before), gateway.agent_record_version(after))

    async def test_deleted_and_config_only_agents_never_insert_on_guarded_patch(self):
        version = gateway.agent_record_version(await self.read())
        await self.db.litellm_agentstable.delete(where={"agent_id": self.id})
        with self.assertRaises(HTTPException) as caught:
            await self.change(version, "No insert")
        self.assertEqual(caught.exception.status_code, 409)
        self.assertIsNone(await self.read())

    async def test_ordinary_caller_cannot_use_operator_update(self):
        before = await self.read()
        self.identity = UserAPIKeyAuth(user_role=LitellmUserRoles.INTERNAL_USER, user_id="synthetic-reviewer")
        with self.assertRaises(HTTPException) as caught:
            await self.change(gateway.agent_record_version(before), "No grant")
        self.assertEqual(caught.exception.status_code, 403)
        self.assertEqual(
            gateway.agent_record_version(await self.read()),
            gateway.agent_record_version(before),
        )
