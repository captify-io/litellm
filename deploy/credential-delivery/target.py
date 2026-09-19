"""Reviewed target operator. BINDING contains public deployment coordinates only."""

import copy
import datetime
import fcntl
import hashlib
import http.client
import io
import json
import os
import re
import socket
import ssl
import subprocess
import tarfile
import tempfile
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Final, NamedTuple, Optional
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlsplit

DATABASE_CA_PATH: Final = "/tmp/litellm-database-ca.pem"
DATABASE_PASSWORD_FIELDS: Final = frozenset(("DATABASE_PASSWORD", "DATABASE_PASSWORD_READ_REPLICA"))


class DatabaseIdentity(NamedTuple):
    username: str
    role_arn: str
    ca_pem: str
    ca_sha256: str


class DatabaseEndpoint(NamedTuple):
    host: str
    port: str
    database: str


def database_identity(value: object, account: str, partition: str) -> Optional[DatabaseIdentity]:  # noqa: UP045  # Target runs Python 3.9
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != {"mode", "username", "roleArn", "caPem", "caSha256"}:
        raise ValueError("Explicit database authentication configuration is required")
    if not all(isinstance(item, str) for item in value.values()) or value["mode"] != "rds-iam":
        raise ValueError("Unsupported database authentication configuration")
    if not re.fullmatch(r"[a-z_][a-z0-9_]{0,62}", value["username"]):
        raise ValueError("Explicit database login is required")
    if not re.fullmatch(re.escape(f"arn:{partition}:iam::{account}:role/") + r"[A-Za-z0-9+=,.@_/-]+", value["roleArn"]):
        raise ValueError("Database role must belong to the selected account and partition")
    certificate: Final = value["caPem"]
    if len(certificate) > 8192 or not re.fullmatch(
        r"-----BEGIN CERTIFICATE-----\n[A-Za-z0-9+/=\n]+-----END CERTIFICATE-----\n?", certificate
    ):
        raise ValueError("Exactly one public CA certificate is required")
    if hashlib.sha256(certificate.encode()).hexdigest() != value["caSha256"]:
        raise ValueError("Database CA digest differs")
    ssl.create_default_context(cadata=certificate)
    return DatabaseIdentity(value["username"], value["roleArn"], certificate, value["caSha256"])


def database_endpoint(environment: Mapping[str, str], suffix: str = "") -> DatabaseEndpoint:
    url: Final = environment.get("DATABASE_URL" + suffix, "")
    parsed: Final = urlsplit(url)
    if url and (parsed.scheme not in ("postgres", "postgresql") or parsed.fragment):
        raise ValueError("Unsupported database URL")
    host: Final = parsed.hostname if url else environment.get("DATABASE_HOST" + suffix)
    port: Final = (
        str(parsed.port or 5432)
        if url
        else environment.get("DATABASE_PORT" + suffix) or environment.get("DATABASE_PORT", "5432")
    )
    name: Final = (
        unquote(parsed.path.removeprefix("/"))
        if url
        else environment.get("DATABASE_NAME" + suffix) or environment.get("DATABASE_NAME")
    )
    if not host or not re.fullmatch(r"[A-Za-z0-9.-]+", host) or not port.isdigit() or not 1 <= int(port) <= 65535:
        raise ValueError("Explicit database endpoint is required")
    if not name or not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,62}", name):
        raise ValueError("Explicit database name is required")
    return DatabaseEndpoint(host, port, name)


def database_iam_url(endpoint: DatabaseEndpoint, username: str, previous_url: str, schema: str) -> str:
    options: Final = parse_qsl(urlsplit(previous_url).query, keep_blank_values=True)
    if len({key for key, _ in options}) != len(options):
        raise ValueError("Duplicate database URL options require review")
    forbidden: Final = {"password", "user", "username", "host", "port", "dbname", "sslidentity", "sslpassword"}
    if any(key.lower() in forbidden for key, _ in options):
        raise ValueError("Conflicting database URL credentials require review")
    selected: Final = {
        **({"schema": schema} if schema else {}),
        **dict(options),
        "sslmode": "require",
        "sslaccept": "strict",
        "sslcert": DATABASE_CA_PATH,
    }
    return f"postgresql://{quote(username, safe='')}@{endpoint.host}:{endpoint.port}/{quote(endpoint.database, safe='')}?{urlencode(selected)}"


def database_environment(
    previous: Mapping[str, str],
    updates: Mapping[str, str],
    identity: Optional[DatabaseIdentity],  # noqa: UP045  # Target runs Python 3.9
    region: str,
) -> dict[str, str]:
    merged: Final = dict(updates)
    if identity is None:
        if any(
            source.get("IAM_TOKEN_DB_AUTH", "").lower() not in ("", "false", "0", "no", "off")
            for source in (previous, updates)
        ):
            raise ValueError("Existing IAM authentication requires its explicit deployment binding")
        return merged
    if merged.get("AZURE_POSTGRESQL_AUTH", "").lower() not in ("", "false", "0", "no", "off"):
        raise ValueError("Conflicting database authentication")
    for key, expected in (("DATABASE_AWS_ROLE_ARN", identity.role_arn), ("DATABASE_AWS_REGION_NAME", region)):
        if updates.get(key) and updates[key] != expected:
            raise ValueError("Database identity override differs from selected deployment")
    writer: Final = database_endpoint(previous)
    if database_endpoint(merged) != writer:
        raise ValueError("Database authentication change cannot change the writer endpoint")
    reader_enabled: Final = bool(
        previous.get("DATABASE_URL_READ_REPLICA") or previous.get("DATABASE_HOST_READ_REPLICA")
    )
    if bool(merged.get("DATABASE_URL_READ_REPLICA") or merged.get("DATABASE_HOST_READ_REPLICA")) != reader_enabled:
        raise ValueError("Database authentication change cannot change reader routing")
    reader: Final = database_endpoint(previous, "_READ_REPLICA") if reader_enabled else None
    if reader is not None and database_endpoint(merged, "_READ_REPLICA") != reader:
        raise ValueError("Database authentication change cannot change the reader endpoint")
    if previous.get("DIRECT_URL") or merged.get("DIRECT_URL"):
        raise ValueError("A direct migration URL requires separately qualified token renewal")
    return {
        **{key: value for key, value in merged.items() if key not in DATABASE_PASSWORD_FIELDS},
        "DATABASE_HOST": writer.host,
        "DATABASE_PORT": writer.port,
        "DATABASE_NAME": writer.database,
        "DATABASE_USER": identity.username,
        "DATABASE_USERNAME": identity.username,
        "IAM_TOKEN_DB_AUTH": "True",
        "DATABASE_AWS_ROLE_ARN": identity.role_arn,
        "DATABASE_AWS_REGION_NAME": region,
        "DATABASE_URL": database_iam_url(
            writer, identity.username, merged.get("DATABASE_URL", ""), merged.get("DATABASE_SCHEMA", "")
        ),
        **(
            {
                "DATABASE_HOST_READ_REPLICA": reader.host,
                "DATABASE_PORT_READ_REPLICA": reader.port,
                "DATABASE_NAME_READ_REPLICA": reader.database,
                "DATABASE_USER_READ_REPLICA": identity.username,
                "DATABASE_USERNAME_READ_REPLICA": identity.username,
                "DATABASE_URL_READ_REPLICA": database_iam_url(
                    reader,
                    identity.username,
                    merged.get("DATABASE_URL_READ_REPLICA", ""),
                    merged.get("DATABASE_SCHEMA_READ_REPLICA", merged.get("DATABASE_SCHEMA", "")),
                ),
            }
            if reader is not None
            else {}
        ),
    }


def stage_database_ca(container_id: str, identity: DatabaseIdentity) -> None:
    content: Final = identity.ca_pem.encode()
    entry: Final = tarfile.TarInfo(Path(DATABASE_CA_PATH).name)
    entry.size = len(content)
    entry.mode = 0o444
    with io.BytesIO() as buffer:
        with tarfile.open(fileobj=buffer, mode="w") as archive:
            archive.addfile(entry, io.BytesIO(content))
        docker("PUT", "/containers/" + container_id + "/archive?path=/tmp", buffer.getvalue())
    copied: Final = docker("GET", "/containers/" + container_id + "/archive?path=" + DATABASE_CA_PATH, raw=True)
    with tarfile.open(fileobj=io.BytesIO(copied), mode="r:") as archive:
        members: Final = archive.getmembers()
        if (
            len(members) != 1
            or not members[0].isfile()
            or members[0].name != Path(DATABASE_CA_PATH).name
            or (members[0].uid, members[0].gid, members[0].mode) != (0, 0, 0o444)
        ):
            raise ValueError("Candidate database certificate is not the selected regular file")
        file: Final = archive.extractfile(members[0])
        if file is None or hashlib.sha256(file.read(8193)).hexdigest() != identity.ca_sha256:
            raise ValueError("Candidate database certificate differs")


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
    database_identity(binding.get("databaseAuthentication"), binding["accountId"], binding["partition"])
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


def docker(method, path, body=None, *, raw=False):
    connection = http.client.HTTPConnection("localhost", timeout=90)
    connection.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection.sock.settimeout(connection.timeout)
    try:
        connection.sock.connect("/var/run/docker.sock")
        connection.request(
            method,
            path,
            body=body if isinstance(body, bytes) else None if body is None else json.dumps(body),
            headers={"Content-Type": "application/x-tar" if isinstance(body, bytes) else "application/json"},
        )
        response = connection.getresponse()
        data = response.read()
        if not 200 <= response.status < 300:
            raise RuntimeError("Local container operation failed")
        return data if raw else json.loads(data) if data else None
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
    identity = database_identity(binding.get("databaseAuthentication"), binding["accountId"], binding["partition"])
    previous_environment = dict(value.split("=", 1) for value in old["Config"]["Env"])
    candidate_environment = dict(value.split("=", 1) for value in candidate_body["Env"])
    reviewed_environment = database_environment(
        previous_environment, candidate_environment, identity, binding["region"]
    )
    candidate_body["Env"] = [name + "=" + value for name, value in reviewed_environment.items()]
    candidate_name = "litellm-candidate-" + binding["deploymentId"]
    backup_name = "litellm-before-" + binding["deploymentId"]
    candidate_id = None
    interrupted = False
    runtime_changed = False
    dependency_attempted = False
    try:
        candidate_id = docker("POST", "/containers/create?name=" + candidate_name, candidate_body)["Id"]
        if identity is not None:
            stage_database_ca(candidate_id, identity)
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
        "databaseAuthentication": "rds-iam" if identity is not None else "password",
        "databaseCaSha256": identity.ca_sha256 if identity is not None else None,
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
