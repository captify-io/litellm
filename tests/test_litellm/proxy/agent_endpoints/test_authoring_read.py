"""Read consistency against stock LiteLLM types; no live database or credentials."""

from types import SimpleNamespace
from unittest import IsolatedAsyncioTestCase
from unittest.mock import AsyncMock, patch

from fastapi import HTTPException, Response
from litellm.proxy._types import LitellmUserRoles, UserAPIKeyAuth
from litellm.types.agents import AgentResponse

from litellm.proxy.agent_endpoints import owned_authoring as gateway


class AuthoringReadTests(IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.identity = UserAPIKeyAuth(user_role=LitellmUserRoles.INTERNAL_USER)
        self.old = AgentResponse(
            agent_id="fixture",
            agent_name="Synthetic",
            agent_card_params={},
            litellm_params={"model": "old"},
        )
        self.new = AgentResponse(
            agent_id="fixture",
            agent_name="Synthetic",
            agent_card_params={},
            litellm_params={"model": "new"},
            static_headers={"Authorization": "synthetic-secret"},
        )
        self.read = AsyncMock(return_value=self.new)
        self.client = SimpleNamespace(db=SimpleNamespace(litellm_agentstable=SimpleNamespace(find_unique=self.read)))
        self.admit = AsyncMock(return_value=self.old)
        self.response = Response()
        self.enterContext(
            patch.object(  # test-quality-ok: Restored upstream singleton.
                gateway, "admit_authoring_read", self.admit
            )
        )
        self.enterContext(
            patch.object(  # test-quality-ok: Restored upstream singleton.
                gateway.proxy_server, "prisma_client", self.client
            )
        )
        self.enterContext(
            patch.object(  # test-quality-ok: Restored upstream singleton.
                gateway.global_agent_registry, "config_agents", ()
            )
        )

    async def test_committed_row_wins_over_stale_registry_and_is_redacted(self):
        actual = await gateway.read_agent_record("fixture", self.response, self.identity)
        self.admit.assert_awaited_once_with("fixture", self.identity)
        self.read.assert_awaited_once_with(where={"agent_id": "fixture"}, include={"object_permission": True})
        self.assertEqual(actual.litellm_params["model"], "new")
        self.assertIsNone(actual.static_headers)
        self.assertIsNone(actual.keys)
        self.assertEqual(self.old.litellm_params["model"], "old")
        self.assertEqual(self.new.static_headers["Authorization"], "synthetic-secret")
        self.assertEqual(self.response.headers["cache-control"], "private, no-store")
        self.assertEqual(self.response.headers["x-captify-agent-version"], gateway.agent_record_version(self.new))

    async def test_denied_caller_never_reaches_committed_row(self):
        self.admit.side_effect = HTTPException(403, "Denied")
        with self.assertRaises(HTTPException) as caught:
            await gateway.read_agent_record("fixture", self.response, self.identity)
        self.assertEqual(caught.exception.status_code, 403)
        self.read.assert_not_awaited()

    async def test_unavailable_database_never_returns_old_registry_record(self):
        self.read.side_effect = RuntimeError("Synthetic read failure")
        with self.assertRaises(HTTPException) as caught:
            await gateway.read_agent_record("fixture", self.response, self.identity)
        self.assertEqual(caught.exception.status_code, 503)

    async def test_deleted_database_record_never_returns_old_registry_record(self):
        self.read.return_value = None
        with self.assertRaises(HTTPException) as caught:
            await gateway.read_agent_record("fixture", self.response, self.identity)
        self.assertEqual(caught.exception.status_code, 404)

    async def test_config_only_agent_and_legacy_alias_remain_readable(self):
        config = {
            "agent_name": "Config fixture",
            "agent_card_params": {"name": "Config fixture"},
            "litellm_params": {"model": "configured"},
        }
        registry = gateway.AgentRegistry()
        registry.load_agents_from_config([config])
        stable = registry.get_agent_list()[0].agent_id
        legacy = next(iter(registry.config_agent_legacy_ids))
        self.read.return_value = None
        with patch.object(  # test-quality-ok: Restored upstream singleton boundary.
            gateway.global_agent_registry, "config_agents", (config,)
        ):
            for agent_id in [stable, legacy]:
                self.admit.return_value = registry.get_agent_by_id(agent_id=agent_id)
                actual = await gateway.read_agent_record(agent_id, self.response, self.identity)
                self.assertEqual(actual.agent_id, stable)
                self.assertEqual(actual.litellm_params["model"], "configured")
                self.assertNotIn("x-captify-agent-version", self.response.headers)

    async def test_same_get_route_preserves_upstream_auth_classification(self):
        from litellm.proxy.auth.route_checks import RouteChecks
        from litellm.proxy._types import LiteLLMRoutes
        from litellm.proxy.agent_endpoints.endpoints import get_agent_by_id, router

        matching = [
            r
            for r in router.routes
            if getattr(r, "path", None) == "/v1/agents/{agent_id}" and getattr(r, "methods", None) == {"GET"}
        ]
        self.assertEqual(len(matching), 1)
        self.assertIs(matching[0].endpoint, get_agent_by_id)
        self.assertTrue(
            RouteChecks.check_route_access(
                route="/v1/agents/fixture",
                allowed_routes=LiteLLMRoutes.agent_routes.value,
            )
        )


class AuthoringPermissionTests(IsolatedAsyncioTestCase):
    """Exercise real feature admission and permission resolution, including upstream failures."""

    async def asyncSetUp(self):
        self.record = AgentResponse(
            agent_id="fixture",
            agent_name="Synthetic",
            agent_card_params={},
            litellm_params={"model": "committed"},
        )
        self.read = AsyncMock(return_value=self.record)
        self.native_groups = AsyncMock(return_value=[])
        self.unified_groups = AsyncMock(return_value=None)
        self.team = AsyncMock(return_value=None)
        self.client = SimpleNamespace(
            db=SimpleNamespace(
                litellm_agentstable=SimpleNamespace(find_unique=self.read, find_many=self.native_groups),
                litellm_accessgrouptable=SimpleNamespace(find_unique=self.unified_groups),
                litellm_teamtable=SimpleNamespace(find_unique=self.team),
                litellm_verificationtoken=SimpleNamespace(find_many=AsyncMock(return_value=[])),
            )
        )
        self.enterContext(
            patch.object(  # test-quality-ok: Restored upstream singleton.
                gateway.proxy_server, "prisma_client", self.client
            )
        )
        self.enterContext(
            patch.object(  # test-quality-ok: Restored upstream singleton.
                gateway.proxy_server, "general_settings", {}
            )
        )
        self.enterContext(
            patch.object(  # test-quality-ok: Restored upstream singleton.
                gateway.global_agent_registry, "config_agents", ()
            )
        )

    def identity(self, *, agents=(), native_groups=(), unified_groups=(), team_id=None):
        return UserAPIKeyAuth(
            user_role=LitellmUserRoles.INTERNAL_USER,
            object_permission={
                "object_permission_id": "fixture-grants",
                "agents": list(agents),
                "agent_access_groups": list(native_groups),
            },
            access_group_ids=list(unified_groups),
            team_id=team_id,
        )

    async def refuse(self, identity, status):
        with self.assertRaises(HTTPException) as caught:
            await gateway.read_agent_record("fixture", Response(), identity)
        self.assertEqual(caught.exception.status_code, status)
        self.read.assert_not_awaited()

    async def test_real_upstream_fail_open_does_not_admit_committed_read(self):
        from litellm.proxy.agent_endpoints.auth.agent_permission_handler import (
            AgentRequestHandler,
        )

        identity = self.identity(native_groups=["restricted-group"])
        failure = AsyncMock(side_effect=RuntimeError("Synthetic permission lookup unavailable"))
        # The exact pinned upstream behavior is the regression trigger, not a mocked admission.
        with patch.object(  # test-quality-ok: Restored upstream singleton boundary.
            AgentRequestHandler, "_get_db_agent_ids_for_access_groups", failure
        ):
            self.assertTrue(await AgentRequestHandler.is_agent_allowed("fixture", identity))
        self.native_groups.side_effect = RuntimeError("Synthetic permission lookup unavailable")
        await self.refuse(identity, 503)
        self.assertEqual(self.record.litellm_params["model"], "committed")

    async def test_upstream_feature_gate_still_refuses_before_permission_reads(self):
        with patch.object(  # test-quality-ok: Restore the upstream singleton after simulating committed reads and independent key/team permission failures.
            gateway.proxy_server,
            "general_settings",
            {"disable_agents_for_internal_users": True},
        ):
            await self.refuse(self.identity(), 403)
        self.native_groups.assert_not_awaited()

    async def test_key_and_team_intersection_does_not_turn_empty_into_unrestricted(
        self,
    ):
        self.team.return_value = SimpleNamespace(
            object_permission_id="team-grants",
            object_permission=SimpleNamespace(agents=["other"], agent_access_groups=[]),
            access_group_ids=[],
        )
        await self.refuse(self.identity(agents=["fixture"], team_id="restricted-team"), 403)

    async def test_missing_or_empty_declared_groups_deny(self):
        for identity in [
            self.identity(native_groups=["empty"]),
            self.identity(unified_groups=["deleted"]),
        ]:
            await self.refuse(identity, 403)

    async def test_team_or_unified_group_lookup_failure_refuses_503(self):
        self.team.side_effect = RuntimeError("Synthetic team lookup failure")
        await self.refuse(self.identity(team_id="team"), 503)
        self.unified_groups.side_effect = RuntimeError("Synthetic access group lookup failure")
        await self.refuse(self.identity(unified_groups=["group"]), 503)

    async def test_existing_unrestricted_scope_and_explicit_grants_remain_readable(
        self,
    ):
        for identity in [self.identity(), self.identity(agents=["fixture"])]:
            result = await gateway.read_agent_record("fixture", Response(), identity)
            self.assertEqual(result.litellm_params["model"], "committed")

    async def test_deleted_team_and_unloaded_permission_refuse(self):
        await self.refuse(self.identity(team_id="deleted-team"), 403)
        identity = UserAPIKeyAuth(user_role=LitellmUserRoles.INTERNAL_USER, object_permission_id="unloaded")
        await self.refuse(identity, 503)

    async def test_config_alias_grants_are_compared_in_stable_identity_space(self):
        registry = gateway.AgentRegistry()
        registry.load_agents_from_config(
            [
                {
                    "agent_name": "Config fixture",
                    "agent_card_params": {"name": "Config fixture"},
                    "litellm_params": {"model": "configured"},
                }
            ]
        )
        stable = registry.get_agent_list()[0].agent_id
        legacy = next(iter(registry.config_agent_legacy_ids))
        with patch.object(  # test-quality-ok: Restored upstream singleton boundary.
            gateway.global_agent_registry, "stable_agent_id", registry.stable_agent_id
        ):
            await gateway.admit_authoring_read(legacy, self.identity(agents=[stable]))
            await gateway.admit_authoring_read(stable, self.identity(agents=[legacy]))

    async def test_native_key_group_and_unified_team_group_admit_the_intersection(self):
        self.native_groups.return_value = [
            SimpleNamespace(agent_id="fixture"),
            SimpleNamespace(agent_id="key-only"),
        ]
        self.unified_groups.return_value = SimpleNamespace(access_agent_ids=["fixture", "team-only"])
        self.team.return_value = SimpleNamespace(
            object_permission_id=None,
            object_permission=None,
            access_group_ids=["team-unified"],
        )
        identity = self.identity(native_groups=["key-native"], team_id="team")
        result = await gateway.read_agent_record("fixture", Response(), identity)
        self.assertEqual(result.litellm_params["model"], "committed")
        self.native_groups.assert_awaited_once_with(where={"agent_access_groups": {"hasSome": ["key-native"]}})
        self.unified_groups.assert_awaited_once_with(where={"access_group_id": "team-unified"})
        for agent_id in ["key-only", "team-only"]:
            with self.assertRaises(HTTPException) as caught:
                await gateway.admit_authoring_read(agent_id, identity)
            self.assertEqual(caught.exception.status_code, 403)

    async def test_unified_key_group_and_native_team_group_admit_the_intersection(self):
        self.unified_groups.return_value = SimpleNamespace(access_agent_ids=["fixture", "key-only"])
        self.native_groups.return_value = [
            SimpleNamespace(agent_id="fixture"),
            SimpleNamespace(agent_id="team-only"),
        ]
        self.team.return_value = SimpleNamespace(
            object_permission_id="team-grants",
            object_permission=SimpleNamespace(agents=[], agent_access_groups=["team-native"]),
            access_group_ids=[],
        )
        identity = self.identity(unified_groups=["key-unified"], team_id="team")
        result = await gateway.read_agent_record("fixture", Response(), identity)
        self.assertEqual(result.litellm_params["model"], "committed")
        self.unified_groups.assert_awaited_once_with(where={"access_group_id": "key-unified"})
        self.native_groups.assert_awaited_once_with(where={"agent_access_groups": {"hasSome": ["team-native"]}})
        for agent_id in ["key-only", "team-only"]:
            with self.assertRaises(HTTPException) as caught:
                await gateway.admit_authoring_read(agent_id, identity)
            self.assertEqual(caught.exception.status_code, 403)

    async def test_admin_and_admin_view_preserve_upstream_access_and_redaction(self):
        self.record.static_headers = {"Authorization": "synthetic-admin-secret"}
        self.native_groups.side_effect = RuntimeError("Must not resolve scoped admin grants")
        self.team.side_effect = RuntimeError("Must not resolve scoped admin team")
        with patch.object(  # test-quality-ok: Restore the upstream singleton after simulating committed reads and independent key/team permission failures.
            gateway.proxy_server,
            "general_settings",
            {"disable_agents_for_internal_users": True},
        ):
            for role in [
                LitellmUserRoles.PROXY_ADMIN,
                LitellmUserRoles.PROXY_ADMIN_VIEW_ONLY,
            ]:
                identity = self.identity(native_groups=["restricted"], team_id="team")
                identity.user_role = role
                self.assertTrue(gateway.user_api_key_has_admin_view(identity))
                result = await gateway.read_agent_record("fixture", Response(), identity)
                self.assertEqual(result.litellm_params["model"], "committed")
                self.assertIsNone(result.keys)
                if role == LitellmUserRoles.PROXY_ADMIN:
                    self.assertEqual(
                        result.static_headers,
                        {"Authorization": "synthetic-admin-secret"},
                    )
                else:
                    self.assertIsNone(result.static_headers)
        self.native_groups.assert_not_awaited()
        self.team.assert_not_awaited()

    async def test_star_is_a_literal_agent_id_in_pinned_upstream_permissions(self):
        from litellm.proxy.agent_endpoints.auth.agent_permission_handler import (
            AgentRequestHandler,
        )

        identity = self.identity(agents=["*"])
        self.assertFalse(await AgentRequestHandler.is_agent_allowed("fixture", identity))
        await self.refuse(identity, 403)
