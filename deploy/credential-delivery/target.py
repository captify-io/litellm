"""Reviewed target operator. BINDING contains public deployment coordinates only."""

import copy
import datetime
import fcntl
import http.client
import json
import os
import re
import socket
import subprocess
import tempfile
import time
from collections.abc import Callable
from pathlib import Path


def execute(arguments, *, environment=None, input_text=None, timeout=90):
    result = subprocess.run(
        arguments, env=environment, input=input_text, text=True, capture_output=True, timeout=timeout
    )
    if result.returncode:
        raise RuntimeError("Target operation failed")
    return result.stdout


def fetch(binding, instance_path=Path("/var/lib/cloud/data/instance-id")):
    instance = instance_path.read_text().strip()
    if instance != binding["instanceId"]:
        raise ValueError("Unexpected deployment instance")
    region = binding["region"]
    identity = json.loads(execute(["aws", "sts", "get-caller-identity", "--region", region, "--output", "json"]))
    if identity["Account"] != binding["accountId"] or not identity["Arn"].startswith(
        "arn:" + binding["partition"] + ":"
    ):
        raise ValueError("Unexpected deployment account or partition")
    response = json.loads(
        execute(
            [
                "aws",
                "secretsmanager",
                "get-secret-value",
                "--region",
                region,
                "--secret-id",
                binding["secretArn"],
                "--version-id",
                binding["versionId"],
                "--version-stage",
                "AWSCURRENT",
                "--output",
                "json",
            ]
        )
    )
    if (
        response["ARN"] != binding["secretArn"]
        or response["VersionId"] != binding["versionId"]
        or "AWSCURRENT" not in response["VersionStages"]
    ):
        raise ValueError("Unexpected secret version")
    secret = json.loads(response["SecretString"])
    if any(secret.get(key) != value for key, value in binding.items()):
        raise ValueError("Secret differs from reviewed deployment")
    if secret.get("schemaVersion") != 1 or not 0 < secret["expiresAt"] - time.time() <= 1200:
        raise ValueError("Expired or invalid deployment secret")
    updates = secret.get("environmentUpdates")
    if not isinstance(updates, dict) or not updates:
        raise ValueError("Missing environment updates")
    for name, value in updates.items():
        if (
            not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name)
            or not isinstance(value, str)
            or any(c in value for c in "\r\n\x00")
        ):
            raise ValueError("Invalid environment update")
    return secret


def docker(method, path, body=None):
    connection = http.client.HTTPConnection("localhost", timeout=90)
    connection.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection.sock.settimeout(connection.timeout)
    try:
        connection.sock.connect("/var/run/docker.sock")
        connection.request(
            method, path, body=None if body is None else json.dumps(body), headers={"Content-Type": "application/json"}
        )
        response = connection.getresponse()
        data = response.read()
        if not 200 <= response.status < 300:
            raise RuntimeError("Local container operation failed")
        return json.loads(data) if data else None
    finally:
        connection.close()


def validate_current(old, binding):
    if not old["State"]["Running"] or old["Image"] != binding["expectedImageId"]:
        raise ValueError("Live container changed after review")
    if old["Mounts"] or set(old["NetworkSettings"]["Networks"]) != {binding["network"]}:
        raise ValueError("Unsupported storage or network configuration")
    host = old["HostConfig"]
    endpoint = old["NetworkSettings"]["Networks"][binding["network"]]
    if (
        host["NetworkMode"] != binding["network"]
        or endpoint.get("IPAMConfig")
        or endpoint.get("Links")
        or endpoint.get("DriverOpts")
    ):
        raise ValueError("Unsupported container network attachment")
    if (
        host["Privileged"]
        or host.get("CapAdd")
        or host.get("AutoRemove")
        or host.get("Binds")
        or host.get("VolumesFrom")
    ):
        raise ValueError("Unsupported privileged or storage configuration")
    if host["PortBindings"] != {
        binding["containerPort"] + "/tcp": [{"HostIp": binding["bindAddress"], "HostPort": binding["hostPort"]}]
    }:
        raise ValueError("Legacy operator requires the existing local HTTP port")
    startup = (old["Config"]["User"], old["Config"]["Entrypoint"])
    supported = [(user, ["docker/prod_entrypoint.sh"]) for user in ("", "0", "root")]
    supported.append(("65534", ["/app/docker/prod_entrypoint.sh"]))
    if (
        startup not in supported
        or old["Config"]["WorkingDir"] != "/app"
        or old["Config"]["Cmd"]
        != [
            "--port",
            binding["containerPort"],
        ]
    ):
        raise ValueError("Unexpected application startup command")
    environment = old["Config"]["Env"]
    if any("=" not in value or any(c in value for c in "\r\n\x00") for value in environment):
        raise ValueError("Unsupported runtime environment encoding")
    if len({value.split("=", 1)[0] for value in environment}) != len(environment):
        raise ValueError("Duplicate runtime environment names")


def replacement(old, image, updates, network):
    config = copy.deepcopy(old["Config"])
    if config["Hostname"] == old["Id"][:12]:
        config["Hostname"] = ""
    config["Image"] = image
    environment = dict(value.split("=", 1) for value in config["Env"])
    environment.update(updates)
    config["Env"] = [name + "=" + value for name, value in environment.items()]
    config["HostConfig"] = copy.deepcopy(old["HostConfig"])
    aliases = [
        alias
        for alias in old["NetworkSettings"]["Networks"][network].get("Aliases", []) or []
        if alias not in (old["Id"], old["Id"][:12])
    ]
    config["NetworkingConfig"] = {"EndpointsConfig": {network: {"Aliases": aliases}}}
    return config


def healthy(binding):
    connection = http.client.HTTPConnection(binding["bindAddress"], int(binding["hostPort"]), timeout=5)
    try:
        connection.request("GET", binding["healthPath"])
        response = connection.getresponse()
        data = response.read()
        if response.status != 200:
            return False
        try:
            result = json.loads(data)
        except (ValueError, UnicodeError):
            return False
        return isinstance(result, dict) and result.get("status") == "healthy" and result.get("db") == "connected"
    except (OSError, http.client.HTTPException):
        return False
    finally:
        connection.close()


def wait_healthy(binding):
    for _ in range(60):
        if healthy(binding):
            return
        time.sleep(2)
    raise RuntimeError("Service health did not recover")


def unchanged_dependency() -> None:
    return None


def replace(
    binding,
    secret,
    recovery,
    runtime=Path("/litellm.env"),
    before_switch: Callable[[], None] = unchanged_dependency,
    rollback_dependency: Callable[[], None] = unchanged_dependency,
):
    old = docker("GET", "/containers/litellm/json")
    validate_current(old, binding)
    if not healthy(binding):
        raise ValueError("Original service is unhealthy; replacement refused")
    (recovery / "previous-container.json").write_text(json.dumps(old))
    (recovery / "previous-container.json").chmod(0o600)
    if runtime.is_symlink() or (runtime.exists() and not runtime.is_file()):
        raise ValueError("Runtime environment path is not a regular file")
    prior_environment = runtime.read_bytes() if runtime.exists() else None
    if prior_environment is not None:
        (recovery / "previous.env").write_bytes(prior_environment)
        (recovery / "previous.env").chmod(0o600)
    with tempfile.TemporaryDirectory(prefix="registry-", dir=recovery) as temporary:
        if binding["mode"] == "release":
            process_env = {**os.environ, "DOCKER_CONFIG": temporary}
            execute(
                ["docker", "login", "--username", secret["registryUser"], "--password-stdin", binding["registry"]],
                environment=process_env,
                input_text=secret["registryPassword"] + "\n",
            )
            execute(["docker", "pull", binding["releaseImage"]], environment=process_env, timeout=360)
        elif binding["mode"] != "credentials" or binding["releaseImage"] != old["Image"]:
            raise ValueError("Credential-only transition cannot change the image")
    candidate_image = json.loads(execute(["docker", "image", "inspect", binding["releaseImage"]]))[0]
    prior_image = json.loads(execute(["docker", "image", "inspect", old["Image"]]))[0]
    startup_keys = ("User", "Entrypoint", "Cmd", "WorkingDir")
    startup_changed = any(candidate_image["Config"].get(key) != prior_image["Config"].get(key) for key in startup_keys)
    if binding.get("runtimeMigration", "preserve") != "preserve" and not startup_changed:
        raise ValueError("Requested runtime migration does not change the reviewed startup")
    candidate_body = replacement(old, binding["releaseImage"], secret["environmentUpdates"], binding["network"])
    if startup_changed:
        prior = prior_image["Config"]
        following = candidate_image["Config"]
        if (
            binding.get("runtimeMigration", "preserve") != "root-to-nonroot-v1"
            or binding["mode"] != "release"
            or prior.get("User") not in ("", "0", "root")
            or prior.get("Entrypoint") != ["docker/prod_entrypoint.sh"]
            or following.get("User") != "65534"
            or following.get("Entrypoint") != ["/app/docker/prod_entrypoint.sh"]
            or following.get("WorkingDir") != "/app"
            or prior.get("WorkingDir") != "/app"
            or following.get("Cmd") != prior.get("Cmd")
        ):
            raise ValueError("Candidate requires a separate runtime migration")
        old_defaults = dict(value.split("=", 1) for value in prior.get("Env", []))
        new_defaults = dict(value.split("=", 1) for value in following.get("Env", []))
        runtime_environment = dict(value.split("=", 1) for value in old["Config"]["Env"])
        for name in old_defaults.keys() | new_defaults.keys():
            if old_defaults.get(name) == new_defaults.get(name):
                continue
            if (
                name in runtime_environment
                and runtime_environment[name] != old_defaults.get(name)
                and runtime_environment[name] != new_defaults.get(name)
            ) or (
                name in secret["environmentUpdates"] and secret["environmentUpdates"][name] != new_defaults.get(name)
            ):
                raise ValueError("Runtime override conflicts with nonroot image defaults: " + name)
        preserved_environment = {
            name: value for name, value in runtime_environment.items() if value != old_defaults.get(name)
        }
        environment = {**new_defaults, **preserved_environment, **secret["environmentUpdates"]}
        candidate_body["Env"] = [name + "=" + value for name, value in environment.items()]
        candidate_body["User"] = following["User"]
        candidate_body["Entrypoint"] = following["Entrypoint"]
    candidate_name = "litellm-candidate-" + binding["deploymentId"]
    backup_name = "litellm-before-" + binding["deploymentId"]
    candidate_id = None
    interrupted = False
    runtime_changed = False
    dependency_attempted = False
    try:
        candidate_id = docker("POST", "/containers/create?name=" + candidate_name, candidate_body)["Id"]
        current = docker("GET", "/containers/litellm/json")
        if (
            current["Id"] != old["Id"]
            or current["Config"] != old["Config"]
            or current["HostConfig"] != old["HostConfig"]
        ):
            raise ValueError("Live container changed during candidate staging")
        dependency_attempted = True
        before_switch()
        interrupted = True
        docker("POST", "/containers/" + old["Id"] + "/update", {"RestartPolicy": {"Name": "no"}})
        docker("POST", "/containers/" + old["Id"] + "/stop?t=30")
        docker("POST", "/containers/" + old["Id"] + "/rename?name=" + backup_name)
        docker("POST", "/containers/" + candidate_id + "/rename?name=litellm")
        docker("POST", "/containers/" + candidate_id + "/start")
        wait_healthy(binding)
        live = docker("GET", "/containers/litellm/json")
        if live["Id"] != candidate_id or live["Image"] != candidate_image["Id"] or not live["State"]["Running"]:
            raise ValueError("Candidate image or running state differs")
        if any(live["Config"].get(key) != candidate_body.get(key) for key in startup_keys):
            raise ValueError("Candidate startup differs from the reviewed configuration")
        if dict(value.split("=", 1) for value in live["Config"]["Env"]) != dict(
            value.split("=", 1) for value in candidate_body["Env"]
        ):
            raise ValueError("Runtime environment differs from the reviewed updates")
        for key, value in old["HostConfig"].items():
            if live["HostConfig"].get(key) != value:
                raise ValueError("Container launch settings changed")
        staged = recovery / "current.env"
        staged.write_text("\n".join(candidate_body["Env"]) + "\n")
        staged.chmod(0o600)
        with tempfile.NamedTemporaryFile(prefix=".litellm-env-", dir=runtime.parent, delete=False) as handle:
            staged_path = Path(handle.name)
            handle.write(staged.read_bytes())
        try:
            os.replace(staged_path, runtime)
            runtime_changed = True
        finally:
            staged_path.unlink(missing_ok=True)
    except BaseException:
        if dependency_attempted:
            rollback_dependency()
        if candidate_id:
            docker("DELETE", "/containers/" + candidate_id + "?force=true")
        if interrupted:
            original = docker("GET", "/containers/" + old["Id"] + "/json")
            if original["Name"] != "/litellm":
                docker("POST", "/containers/" + old["Id"] + "/rename?name=litellm")
            docker(
                "POST", "/containers/" + old["Id"] + "/update", {"RestartPolicy": old["HostConfig"]["RestartPolicy"]}
            )
            if not original["State"]["Running"]:
                docker("POST", "/containers/" + old["Id"] + "/start")
            wait_healthy(binding)
        if runtime_changed:
            if prior_environment is None:
                runtime.unlink(missing_ok=True)
            else:
                runtime.write_bytes(prior_environment)
                runtime.chmod(0o600)
        raise
    return {
        "status": "success",
        "accountId": binding["accountId"],
        "region": binding["region"],
        "instanceId": binding["instanceId"],
        "deploymentId": binding["deploymentId"],
        "imageId": candidate_image["Id"],
        "containerId": candidate_id,
        "rollbackContainer": backup_name,
        "healthStatus": 200,
        "launchSettingsPreserved": not startup_changed,
        "hostSettingsPreserved": True,
        "runtimeMigration": "root-to-nonroot-v1" if startup_changed else "preserve",
        "runtimeUser": candidate_body["User"],
        "registryCredentialDirectoryRemoved": True,
    }


def deploy(binding, root=Path("/var/lib/litellm/credential-delivery")):
    os.umask(0o077)
    if any(path.is_symlink() for path in (root, *root.parents)):
        raise ValueError("Deployment root cannot traverse a symlink")
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    root.chmod(0o700)
    lock = root / "deployment.lock"
    if lock.is_symlink():
        raise ValueError("Deployment lock cannot be a symlink")
    with lock.open("a") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        secret = fetch(binding)
        recovery = root / binding["deploymentId"]
        recovery.mkdir(mode=0o700, exist_ok=False)
        receipt = replace(binding, secret, recovery)
        receipt["observedAt"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        (recovery / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
        print(json.dumps(receipt))


if __name__ == "__main__":
    try:
        deploy(globals()["BINDING"])
    except BaseException as error:
        print(
            json.dumps(
                {
                    "status": "failed",
                    "errorType": type(error).__name__,
                    "diagnostic": "Deployment refused; no secret or raw command output emitted.",
                }
            )
        )
        raise SystemExit(1)
