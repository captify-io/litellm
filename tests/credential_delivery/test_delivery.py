"""Security regression tests use synthetic identities and never contact AWS."""

import base64
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "deploy/credential-delivery"


def load(name):
    spec = importlib.util.spec_from_file_location(name, SOURCE / (name + ".py"))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


CI, TARGET = load("publish"), load("target")
ACCOUNT = "123456789012"
INSTANCE = "i-" + "1" * 17
IMAGE = "sha256:" + "a" * 64
RELEASE = "registry.example.test/team/litellm@sha256:" + "b" * 64


class Delivery(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.config = {
            "accountId": ACCOUNT,
            "partition": "aws-us-gov",
            "region": "us-gov-west-1",
            "deployRoleArn": f"arn:aws-us-gov:iam::{ACCOUNT}:role/test-deployer",
            "secretArn": f"arn:aws-us-gov:secretsmanager:us-gov-west-1:{ACCOUNT}:secret:litellm/deployment-test-AbCdEf",
            "instanceId": INSTANCE,
            "expectedImageId": IMAGE,
            "healthPath": "/health/readiness",
            "network": "existing-test-network",
            "hostPort": "4000",
            "containerPort": "4000",
            "bindAddress": "127.0.0.1",
        }
        self.config_path = self.root / "deployment.json"
        self.config_path.write_text(json.dumps(self.config))
        self.env_path = self.root / "runtime.env"
        self.env_path.write_text("TEST_ACCESS_ID=synthetic-key\nTEST_ACCESS_SECRET=synthetic-secret\n")
        self.env = {
            "DEPLOY_CONFIG": str(self.config_path),
            "ENV_FILE": str(self.env_path),
            "LITELLM_IMAGE": RELEASE,
            "CI_REGISTRY": "registry.example.test",
            "CI_REGISTRY_IMAGE": "registry.example.test/team/litellm",
            "CI_PIPELINE_ID": "10",
            "CI_JOB_ID": "20",
            "LITELLM_DATABASE_PASSWORD": "synthetic-db-password",
            "CI_REGISTRY_USER": "test-user",
            "CI_REGISTRY_PASSWORD": "synthetic-password",
        }
        self.binding = CI.bindings(self.env)
        self.secret = CI.runtime_secret(self.binding, self.env)

    def test_boundaries_are_configured_in_each_supported_partition(self):
        for partition, region in [("aws", "eu-west-1"), ("aws-us-gov", "us-gov-east-1"), ("aws-cn", "cn-north-1")]:
            config = json.loads(
                json.dumps(self.config).replace("aws-us-gov", partition).replace("us-gov-west-1", region)
            )
            self.config_path.write_text(json.dumps(config))
            self.assertEqual(CI.bindings(self.env)["partition"], partition)

    def test_existing_private_address_is_preserved_without_widening_bindings(self):
        self.config_path.write_text(json.dumps({**self.config, "bindAddress": "10.20.30.40"}))
        binding = CI.bindings(self.env)
        self.assertEqual(binding["bindAddress"], "10.20.30.40")
        with self.assertRaises(ValueError):
            TARGET.validate_current(self.old_container(), binding)

    def test_mismatched_and_missing_boundaries_fail_closed(self):
        invalid = [
            ("accountId", "999999999999"),
            ("partition", "aws"),
            ("region", "us-gov-east-1"),
            ("instanceId", INSTANCE + ";echo x"),
            ("expectedImageId", "latest"),
            ("healthPath", "//outside.test"),
            ("healthPath", "/api/health?token=x"),
            ("secretArn", self.config["secretArn"].replace("litellm/", "unrelated/")),
            ("deployRoleArn", self.config["deployRoleArn"].replace(ACCOUNT, "999999999999")),
            ("bindAddress", "0.0.0.0"),
            ("bindAddress", "8.8.8.8"),
            ("bindAddress", "169.254.169.254"),
            ("hostPort", "0"),
            ("containerPort", "65536"),
            ("hostPort", "4000;evil"),
        ]
        for key, value in invalid:
            with self.subTest(key=key):
                self.config_path.write_text(json.dumps({**self.config, key: value}))
                with self.assertRaises(ValueError):
                    CI.bindings(self.env)
        for key in self.config:
            self.config_path.write_text(json.dumps({k: v for k, v in self.config.items() if k != key}))
            with self.assertRaises(ValueError):
                CI.bindings(self.env)

    def test_no_mutable_or_foreign_image_and_no_credential_image_change(self):
        for image in ["registry.example.test/team/litellm:latest", RELEASE.replace("team/litellm", "other/litellm")]:
            with self.assertRaises(ValueError):
                CI.bindings({**self.env, "LITELLM_IMAGE": image})
        with self.assertRaises(ValueError):
            CI.bindings({**self.env, "DEPLOY_MODE": "credentials"})
        binding = CI.bindings({**self.env, "DEPLOY_MODE": "credentials", "LITELLM_IMAGE": IMAGE})
        self.assertEqual(binding["releaseImage"], IMAGE)
        self.assertNotIn("registryPassword", CI.runtime_secret(binding, self.env))

    def test_environment_is_unique_explicit_and_not_shell_interpreted(self):
        for value in ["A=x\nA=y\n", "A\n", "A=x\r\n", "export A=x\n", "A=x\x00\n", ""]:
            self.env_path.write_bytes(value.encode())
            with self.assertRaises(ValueError):
                CI.runtime_secret(self.binding, self.env)
        self.env_path.write_text("VALUE=$(do-not-execute) `no-shell`\n")
        self.assertEqual(
            CI.runtime_secret(self.binding, self.env)["environmentUpdates"]["VALUE"], "$(do-not-execute) `no-shell`"
        )

    def test_readiness_requires_fresh_database_connected_response(self):
        for status, body, expected in [
            (200, b'{"status":"healthy","db":"connected"}', True),
            (200, b'{"status":"healthy","db":"disconnected"}', False),
            (503, b'{"status":"healthy","db":"connected"}', False),
            (200, b"not json", False),
        ]:
            connection = mock.Mock()
            connection.getresponse.return_value.status = status
            connection.getresponse.return_value.read.return_value = body
            with (
                self.subTest(status=status, body=body),
                mock.patch.object(TARGET.http.client, "HTTPConnection", return_value=connection) as factory,
            ):
                self.assertEqual(TARGET.healthy(self.binding), expected)
                factory.assert_called_once_with("127.0.0.1", 4000, timeout=5)
                connection.close.assert_called_once()

    def test_database_password_precedence_and_reader_fallback(self):
        self.env_path.write_text(
            "DATABASE_PASSWORD=stale\nDATABASE_PASSWORD_READ_REPLICA=stale-reader\nOTHER=preserve\n"
        )
        secret = CI.runtime_secret(self.binding, self.env)
        self.assertEqual(secret["environmentUpdates"]["DATABASE_PASSWORD"], "synthetic-db-password")
        self.assertEqual(secret["environmentUpdates"]["DATABASE_PASSWORD_READ_REPLICA"], "")
        self.assertEqual(secret["environmentUpdates"]["OTHER"], "preserve")
        explicit = CI.runtime_secret(
            self.binding, {**self.env, "LITELLM_DATABASE_PASSWORD_READ_REPLICA": "separate-reader"}
        )
        self.assertEqual(explicit["environmentUpdates"]["DATABASE_PASSWORD_READ_REPLICA"], "separate-reader")
        for changes in [
            {"LITELLM_DATABASE_PASSWORD": ""},
            {"LITELLM_DATABASE_PASSWORD": "bad\nvalue"},
            {"LITELLM_DATABASE_PASSWORD_READ_REPLICA": "bad\rvalue"},
        ]:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                CI.runtime_secret(self.binding, {**self.env, **changes})

    def test_password_debugging_is_refused(self):
        with (
            mock.patch.dict(os.environ, {**self.env, "DEBUG_DEPLOY_PASSWORD_FLOW": "true"}, clear=True),
            mock.patch.object(CI, "runtime_secret") as secret,
            mock.patch.object(CI, "aws") as aws,
            self.assertRaises(ValueError),
        ):
            CI.main()
        secret.assert_not_called()
        aws.assert_not_called()

    def test_ssm_payload_and_publication_keep_secrets_out_of_process_and_disk(self):
        parameters = CI.ssm_parameters(self.binding, SOURCE)
        rendered = json.dumps(parameters)
        for value in ("synthetic-key", "synthetic-secret", "synthetic-password", "synthetic-db-password"):
            self.assertNotIn(value, rendered)
            self.assertNotIn(base64.b64encode(value.encode()).decode(), rendered)
        command = parameters["commands"][0]
        compile(command.split("\n", 1)[1].rsplit("\nLITELLM_OPERATOR", 1)[0], "<ssm>", "exec")
        client = mock.Mock()
        client.put_secret_value.return_value = {
            "ARN": self.binding["secretArn"],
            "VersionId": self.binding["versionId"],
        }
        with (
            mock.patch.object(CI, "secret_client", return_value=client),
            mock.patch.object(subprocess, "run", side_effect=AssertionError("No process secret transport")),
        ):
            CI.put_secret(self.binding, self.secret, {}, self.binding["versionId"])
        self.assertEqual(json.loads(client.put_secret_value.call_args.kwargs["SecretString"]), self.secret)

    def fetch(self, secret=None, *, instance=INSTANCE, account=ACCOUNT, **response_changes):
        response = {
            "ARN": self.binding["secretArn"],
            "VersionId": self.binding["versionId"],
            "VersionStages": ["AWSCURRENT"],
            "SecretString": json.dumps(secret or self.secret),
            **response_changes,
        }
        identity = {"Account": account, "Arn": f"arn:aws-us-gov:sts::{account}:assumed-role/test/host"}
        instance_path = self.root / "instance-id"
        instance_path.write_text(instance)
        with mock.patch.object(TARGET, "execute", side_effect=[json.dumps(identity), json.dumps(response)]) as execute:
            result = TARGET.fetch(self.binding, instance_path)
        self.assertIn("AWSCURRENT", execute.call_args.args[0])
        self.assertIn(self.binding["versionId"], execute.call_args.args[0])
        return result

    def test_target_validates_current_version_binding_and_identity(self):
        self.assertEqual(self.fetch(), self.secret)
        for changes in [
            {"instance": "i-" + "2" * 17},
            {"account": "999999999999"},
            {"VersionId": "wrong"},
            {"VersionStages": ["AWSPREVIOUS"]},
            {"ARN": "wrong"},
        ]:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.fetch(**changes)
        for key, value in [
            ("expiresAt", time.time() - 1),
            ("expiresAt", time.time() + 7200),
            ("releaseImage", IMAGE),
            ("deploymentId", "other"),
            ("region", "eu-west-1"),
        ]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.fetch({**self.secret, key: value})

    def test_secret_expiry_is_atomic_against_a_new_publisher(self):
        client = mock.Mock()
        client.describe_secret.side_effect = [
            {"VersionIdsToStages": {self.binding["versionId"]: ["AWSCURRENT"]}},
            {"VersionIdsToStages": {"newer": ["AWSCURRENT"]}},
        ]
        client.update_secret_version_stage.side_effect = [RuntimeError("current changed"), None]
        with mock.patch.object(CI, "secret_client", return_value=client):
            CI.expire_secret(self.binding, {})
        self.assertNotIn("AWSCURRENT", client.put_secret_value.call_args.kwargs["VersionStages"])
        self.assertEqual(
            client.update_secret_version_stage.call_args_list[0].kwargs["RemoveFromVersionId"],
            self.binding["versionId"],
        )

    def test_secret_expiry_skips_newer_and_reports_failed_expiry(self):
        client = mock.Mock()
        client.describe_secret.return_value = {"VersionIdsToStages": {"newer": ["AWSCURRENT"]}}
        with mock.patch.object(CI, "secret_client", return_value=client):
            CI.expire_secret(self.binding, {})
        client.put_secret_value.assert_not_called()
        client.describe_secret.return_value = {"VersionIdsToStages": {self.binding["versionId"]: ["AWSCURRENT"]}}
        client.update_secret_version_stage.side_effect = [RuntimeError("denied"), None]
        with mock.patch.object(CI, "secret_client", return_value=client), self.assertRaises(RuntimeError):
            CI.expire_secret(self.binding, {})

    def test_errors_do_not_disclose_raw_output(self):
        client = mock.Mock()
        client.get_caller_identity.side_effect = RuntimeError("synthetic-secret")
        with (
            mock.patch.object(CI, "api_client", return_value=client),
            self.assertRaisesRegex(RuntimeError, "^AWS operation failed: sts get-caller-identity$"),
        ):
            CI.aws(["sts", "get-caller-identity"], {})
        failure = subprocess.CompletedProcess([], 1, "synthetic-secret", "synthetic-password")
        with (
            mock.patch.object(TARGET.subprocess, "run", return_value=failure),
            self.assertRaisesRegex(RuntimeError, "^Target operation failed$"),
        ):
            TARGET.execute(["docker", "login"])

    def test_only_missing_invocations_are_retryable(self):
        client = mock.Mock()
        for code in ("InvocationDoesNotExist", "AccessDeniedException"):
            error = RuntimeError("synthetic-secret")
            error.response = {"Error": {"Code": code}}
            client.get_command_invocation.side_effect = error
            with mock.patch.object(CI, "api_client", return_value=client):
                if code == "InvocationDoesNotExist":
                    self.assertEqual(
                        CI.aws(
                            ["ssm", "get-command-invocation", "--command-id", "test", "--instance-id", INSTANCE],
                            {},
                            missing_invocation_ok=True,
                        ),
                        {},
                    )
                else:
                    with self.assertRaises(RuntimeError):
                        CI.aws(
                            ["ssm", "get-command-invocation", "--command-id", "test", "--instance-id", INSTANCE],
                            {},
                            missing_invocation_ok=True,
                        )

    def test_debug_tracing_refused_before_secret_or_aws_reads(self):
        with (
            mock.patch.dict(os.environ, {**self.env, "CI_DEBUG_TRACE": "true"}, clear=True),
            mock.patch.object(CI, "runtime_secret") as secret,
            mock.patch.object(CI, "aws") as aws,
            self.assertRaises(ValueError),
        ):
            CI.main()
        secret.assert_not_called()
        aws.assert_not_called()

    def old_container(self):
        return {
            "Id": "c" * 64,
            "Name": "/litellm",
            "Image": IMAGE,
            "Mounts": [],
            "State": {"Running": True},
            "Config": {
                "Hostname": "c" * 12,
                "Image": IMAGE,
                "User": "",
                "Entrypoint": ["docker/prod_entrypoint.sh"],
                "Cmd": ["--port", "4000"],
                "WorkingDir": "/app",
                "Env": ["TEST_ACCESS_ID=old", "PRESERVE=unchanged"],
            },
            "HostConfig": {
                "NetworkMode": self.config["network"],
                "PortBindings": {"4000/tcp": [{"HostIp": "127.0.0.1", "HostPort": "4000"}]},
                "Privileged": False,
                "RestartPolicy": {"Name": "always", "MaximumRetryCount": 0},
                "Ulimits": [{"Name": "nofile", "Hard": 65536, "Soft": 32768}],
            },
            "NetworkSettings": {"Networks": {self.config["network"]: {"Aliases": ["c" * 12]}}},
        }

    def test_configuration_merge_preserves_limits_and_nonselected_environment(self):
        old = self.old_container()
        result = TARGET.replacement(old, IMAGE, self.secret["environmentUpdates"], self.config["network"])
        self.assertIn("PRESERVE=unchanged", result["Env"])
        self.assertEqual(result["HostConfig"], old["HostConfig"])
        self.assertEqual(result["Hostname"], "")
        self.assertEqual(old["Config"]["Env"][0], "TEST_ACCESS_ID=old")

    def rollout(self, failure=None, dependencies=False):
        old = self.old_container()
        original = copy.deepcopy(old)
        state = {old["Id"]: old}
        history = []
        candidate_id = "d" * 64

        def api(method, path, body=None):
            history.append((method, path, copy.deepcopy(body)))
            if path == "/containers/litellm/json":
                return copy.deepcopy(next(x for x in state.values() if x["Name"] == "/litellm"))
            if path.startswith("/containers/create"):
                if failure == "create":
                    raise RuntimeError("create failed")
                config = {k: copy.deepcopy(v) for k, v in body.items() if k not in ("HostConfig", "NetworkingConfig")}
                state[candidate_id] = {
                    **copy.deepcopy(original),
                    "Id": candidate_id,
                    "Name": "/" + path.split("name=")[1],
                    "Config": config,
                    "HostConfig": copy.deepcopy(body["HostConfig"]),
                    "State": {"Running": False},
                }
                return {"Id": candidate_id}
            identity = path.split("/")[2].split("?")[0]
            if method == "DELETE":
                del state[identity]
            elif path.endswith("/json"):
                return copy.deepcopy(state[identity])
            elif "/update" in path:
                state[identity]["HostConfig"].update(copy.deepcopy(body))
            elif "/stop" in path:
                state[identity]["State"]["Running"] = False
            elif "/rename" in path:
                state[identity]["Name"] = "/" + path.split("name=")[1]
            elif path.endswith("/start"):
                state[identity]["State"]["Running"] = True
            else:
                raise AssertionError(path)

        def before_switch():
            history.append(("DEPENDENCY", "rotate", None))
            if failure == "dependency":
                raise RuntimeError("Dependency transition failed")

        def rollback_dependency():
            history.append(("DEPENDENCY", "rollback", None))

        hooks = {"before_switch": before_switch, "rollback_dependency": rollback_dependency} if dependencies else {}
        binding = {**self.binding, "mode": "credentials", "releaseImage": IMAGE}
        runtime = self.root / "litellm.env"
        runtime.write_text("original-runtime-file")
        recovery = self.root / "recovery"
        recovery.mkdir()
        checks = [RuntimeError("candidate health failed"), None] if failure == "health" else [None]
        with (
            mock.patch.object(TARGET, "docker", side_effect=api),
            mock.patch.object(TARGET, "healthy", return_value=True),
            mock.patch.object(TARGET, "wait_healthy", side_effect=checks),
            mock.patch.object(
                TARGET,
                "execute",
                return_value=json.dumps([{"Id": IMAGE, "Config": {**original["Config"], "Cmd": None}}]),
            ),
        ):
            if failure:
                with self.assertRaises(RuntimeError):
                    TARGET.replace(binding, self.secret, recovery, runtime, **hooks)
            else:
                receipt = TARGET.replace(binding, self.secret, recovery, runtime, **hooks)
                self.assertEqual(receipt["imageId"], IMAGE)
                self.assertTrue(receipt["launchSettingsPreserved"])
                for name, value in self.secret["environmentUpdates"].items():
                    self.assertNotIn(name, json.dumps(receipt))
                    if value:
                        self.assertNotIn(value, json.dumps(receipt))
        return original, state, history, runtime

    def test_candidate_creation_failure_does_not_interrupt_original(self):
        original, state, history, runtime = self.rollout("create")
        self.assertEqual(state[original["Id"]], original)
        self.assertFalse(any("/stop" in p for _, p, _ in history))
        self.assertEqual(runtime.read_text(), "original-runtime-file")

    def test_health_failure_restores_original_and_restart_policy(self):
        original, state, history, runtime = self.rollout("health")
        self.assertEqual(state, {original["Id"]: original})
        self.assertEqual(runtime.read_text(), "original-runtime-file")

    def test_dependency_transition_happens_after_staging_and_before_service_stop(self):
        original, state, history, runtime = self.rollout(dependencies=True)
        paths = [path for _, path, _ in history]
        self.assertLess(
            next(i for i, p in enumerate(paths) if p.startswith("/containers/create")), paths.index("rotate")
        )
        self.assertLess(paths.index("rotate"), next(i for i, p in enumerate(paths) if "/stop" in p))
        self.assertNotIn("rollback", paths)

    def test_dependency_failure_restores_dependency_without_stopping_original(self):
        original, state, history, runtime = self.rollout("dependency", dependencies=True)
        self.assertEqual(state, {original["Id"]: original})
        paths = [path for _, path, _ in history]
        self.assertIn("rollback", paths)
        self.assertFalse(any("/stop" in p for p in paths))
        self.assertEqual(runtime.read_text(), "original-runtime-file")

    def test_health_failure_restores_dependency_before_original_service(self):
        original, state, history, runtime = self.rollout("health", dependencies=True)
        self.assertEqual(state, {original["Id"]: original})
        paths = [path for _, path, _ in history]
        self.assertLess(paths.index("rollback"), paths.index("/containers/" + original["Id"] + "/start"))

    def test_success_keeps_original_stopped_and_preserves_runtime_configuration(self):
        original, state, history, runtime = self.rollout()
        self.assertFalse(state[original["Id"]]["State"]["Running"])
        self.assertEqual(state[original["Id"]]["HostConfig"]["RestartPolicy"]["Name"], "no")
        self.assertIn("TEST_ACCESS_SECRET=synthetic-secret", runtime.read_text())
        self.assertIn("PRESERVE=unchanged", runtime.read_text())
        self.assertEqual(runtime.stat().st_mode & 0o777, 0o600)

    def test_changed_or_unsupported_live_container_refused(self):
        for transform in [
            lambda x: x.update(Image="changed"),
            lambda x: x.update(Mounts=[{}]),
            lambda x: x["State"].update(Running=False),
            lambda x: x["HostConfig"].update(Privileged=True),
            lambda x: x["HostConfig"].update(PortBindings={}),
        ]:
            old = self.old_container()
            transform(old)
            with self.assertRaises(ValueError):
                TARGET.validate_current(old, self.binding)

    def test_failed_target_fails_ci_and_expires_secret(self):
        def aws(arguments, environment, **kwargs):
            if arguments[:2] == ["sts", "assume-role"]:
                return {
                    "Credentials": {
                        "AccessKeyId": "synthetic-assumed",
                        "SecretAccessKey": "synthetic-assumed-secret",
                        "SessionToken": "synthetic-session",
                    }
                }
            if arguments[:2] == ["sts", "get-caller-identity"]:
                return {"Account": ACCOUNT, "Arn": f"arn:aws-us-gov:sts::{ACCOUNT}:assumed-role/test/job"}
            if arguments[:2] == ["ssm", "describe-instance-information"]:
                return {"InstanceInformationList": [{"InstanceId": INSTANCE, "PingStatus": "Online"}]}
            if arguments[:2] == ["ssm", "send-command"]:
                return {"Command": {"CommandId": "synthetic-command"}}
            if arguments[:2] == ["ssm", "get-command-invocation"]:
                return {"Status": "Failed"}
            raise AssertionError(arguments)

        with (
            mock.patch.dict(os.environ, self.env, clear=True),
            mock.patch.object(CI, "aws", side_effect=aws),
            mock.patch.object(CI, "put_secret"),
            mock.patch.object(CI, "expire_secret") as expire,
            mock.patch.object(CI.time, "sleep"),
            self.assertRaises(RuntimeError),
        ):
            CI.main()
        expire.assert_called_once()


if __name__ == "__main__":
    unittest.main()
