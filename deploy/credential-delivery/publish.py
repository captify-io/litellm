"""Deliver runtime credentials through a pinned target-owned secret, never through SSM.

Only secret coordinates, reviewed source and non-secret release bindings enter Run Command.
AWS credentials stay in the subprocess environment; shared AWS profile files are untouched.
"""

import base64
import ipaddress
import json
import os
import re
import tempfile
import time
import uuid
from pathlib import Path


def api_client(service, environment):
    import boto3
    from botocore.config import Config

    session = boto3.Session(
        region_name=environment.get("AWS_REGION"),
        aws_access_key_id=environment.get("AWS_ACCESS_KEY_ID"),
        aws_secret_access_key=environment.get("AWS_SECRET_ACCESS_KEY"),
        aws_session_token=environment.get("AWS_SESSION_TOKEN"),
    )
    return session.client(service, config=Config(ignore_configured_endpoint_urls=True))


def aws(arguments, environment, *, missing_invocation_ok=False):
    service, operation = arguments[:2]
    options = dict(zip(arguments[2::2], arguments[3::2]))
    client = api_client(service, environment)
    try:
        if (service, operation) == ("sts", "assume-role"):
            return client.assume_role(RoleArn=options["--role-arn"], RoleSessionName=options["--role-session-name"])
        if (service, operation) == ("sts", "get-caller-identity"):
            return client.get_caller_identity()
        if (service, operation) == ("ssm", "describe-instance-information"):
            return client.describe_instance_information(Filters=json.loads(options["--filters"]))
        if (service, operation) == ("ssm", "send-command"):
            return client.send_command(
                InstanceIds=[options["--instance-ids"]],
                DocumentName=options["--document-name"],
                Comment=options["--comment"],
                Parameters=json.loads(Path(options["--parameters"].removeprefix("file://")).read_text()),
            )
        if (service, operation) == ("ssm", "get-command-invocation"):
            response = client.get_command_invocation(
                CommandId=options["--command-id"], InstanceId=options["--instance-id"]
            )
            return {"Status": response["Status"]}
        if (service, operation) == ("ssm", "cancel-command"):
            return client.cancel_command(CommandId=options["--command-id"], InstanceIds=[options["--instance-ids"]])
        raise ValueError("Unsupported deployment operation")
    except Exception as error:
        code = getattr(error, "response", {}).get("Error", {}).get("Code")
        if missing_invocation_ok and code == "InvocationDoesNotExist":
            return {}
        raise RuntimeError("AWS operation failed: " + service + " " + operation) from None


def bindings(environment):
    config = json.loads(Path(environment["DEPLOY_CONFIG"]).read_text())
    required = {
        "accountId",
        "partition",
        "region",
        "deployRoleArn",
        "secretArn",
        "instanceId",
        "expectedImageId",
        "healthPath",
        "network",
        "hostPort",
        "containerPort",
        "bindAddress",
    }
    if not required <= set(config) or set(config) - required - {"runtimeMigration"}:
        raise ValueError("Deployment configuration has missing or unknown fields")
    if config.get("runtimeMigration", "preserve") not in ("preserve", "root-to-nonroot-v1"):
        raise ValueError("Unsupported runtime migration")
    account, partition, region = (config[k] for k in ("accountId", "partition", "region"))
    if not re.fullmatch(r"[0-9]{12}", account) or partition not in ("aws", "aws-us-gov", "aws-cn"):
        raise ValueError("Explicit account and supported partition are required")
    if not re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-[0-9]+", region):
        raise ValueError("Explicit region is required")
    expected_partition = (
        "aws-us-gov" if region.startswith("us-gov-") else "aws-cn" if region.startswith("cn-") else "aws"
    )
    if partition != expected_partition:
        raise ValueError("Region and partition differ")
    prefix = f"arn:{partition}:"
    if not re.fullmatch(re.escape(prefix + f"iam::{account}:role/") + r"[A-Za-z0-9+=,.@_/-]+", config["deployRoleArn"]):
        raise ValueError("Deployment role must belong to the selected account and partition")
    if not re.fullmatch(
        re.escape(prefix + f"secretsmanager:{region}:{account}:secret:litellm/deployment-") + r"[A-Za-z0-9/_+=.@-]+",
        config["secretArn"],
    ):
        raise ValueError("Secret must belong to the selected account, region and purpose")
    if not re.fullmatch(r"i-[a-f0-9]{17}", config["instanceId"]):
        raise ValueError("Explicit target instance is required")
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", config["expectedImageId"]):
        raise ValueError("Expected current image ID is required")
    if not re.fullmatch(r"/[A-Za-z0-9/_-]+", config["healthPath"]) or config["healthPath"].startswith("//"):
        raise ValueError("A local HTTP health path is required")
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]*", config["network"]):
        raise ValueError("Explicit existing container network is required")
    address = ipaddress.IPv4Address(config["bindAddress"])
    allowed = ("127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
    if not any(address in ipaddress.IPv4Network(network) for network in allowed):
        raise ValueError("An explicit loopback or private IPv4 binding is required")
    if any(
        not isinstance(config[key], str) or not config[key].isdigit() or not 1 <= int(config[key]) <= 65535
        for key in ("hostPort", "containerPort")
    ):
        raise ValueError("Explicit TCP ports are required")
    mode = environment.get("DEPLOY_MODE", "release")
    if mode != "release" and config.get("runtimeMigration", "preserve") != "preserve":
        raise ValueError("Runtime migration requires a qualified release image")
    if mode not in ("release", "credentials"):
        raise ValueError("Unsupported deployment mode")
    image = environment["LITELLM_IMAGE"]
    registry = environment.get("CI_REGISTRY", "")
    if mode == "credentials":
        if image != config["expectedImageId"]:
            raise ValueError("Credential-only transition cannot change the image")
        registry = ""
    else:
        repository = environment["CI_REGISTRY_IMAGE"]
        if not re.fullmatch(r"[a-z0-9.-]+(?::[0-9]+)?", registry) or not repository.startswith(registry + "/"):
            raise ValueError("An explicit image registry and repository are required")
        if not re.fullmatch(r"[a-z0-9./:_-]+", repository) or not re.fullmatch(
            re.escape(repository) + r"@sha256:[a-f0-9]{64}", image
        ):
            raise ValueError("An immutable image in the configured repository is required")
    deployment = environment.get("DEPLOYMENT_ID") or environment["CI_PIPELINE_ID"] + "-" + environment["CI_JOB_ID"]
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", deployment):
        raise ValueError("Explicit safe deployment ID is required")
    return {
        **config,
        "versionId": str(uuid.uuid4()),
        "releaseImage": image,
        "registry": registry,
        "mode": mode,
        "deploymentId": deployment,
    }


def runtime_secret(binding, environment):
    content = Path(environment["ENV_FILE"]).read_bytes().decode("utf-8")
    updates = {}
    for line in content.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        name, separator, value = line.partition("=")
        if not separator or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) or name in updates or "\x00" in value:
            raise ValueError("Environment must have unique explicit KEY=value entries")
        updates[name] = value
    if not updates or "\r" in content or "\x00" in content:
        raise ValueError("Invalid or empty runtime environment")
    password = environment.get("LITELLM_DATABASE_PASSWORD", "")
    reader_password = environment.get("LITELLM_DATABASE_PASSWORD_READ_REPLICA", "")
    if not password or any(c in password + reader_password for c in "\r\n\x00"):
        raise ValueError("A single-line database password is required")
    updates["DATABASE_PASSWORD"] = password
    updates["DATABASE_PASSWORD_READ_REPLICA"] = reader_password
    secret = {"schemaVersion": 1, **binding, "expiresAt": int(time.time()) + 1200, "environmentUpdates": updates}
    if binding["mode"] == "release":
        secret.update(
            registryUser=environment["CI_REGISTRY_USER"], registryPassword=environment["CI_REGISTRY_PASSWORD"]
        )
        if not secret["registryUser"] or not secret["registryPassword"]:
            raise ValueError("Missing registry credentials")
    if len(json.dumps(secret).encode()) > 64000:
        raise ValueError("Oversized deployment secret")
    return secret


def ssm_parameters(binding, root):
    public = binding
    encoded = base64.b64encode(json.dumps(public).encode()).decode()
    source = (root / "target.py").read_text()
    command = (
        "python3 - <<'LITELLM_OPERATOR'\nimport base64,json\nBINDING=json.loads(base64.b64decode("
        + repr(encoded)
        + "))\n"
        + source
        + "\nLITELLM_OPERATOR"
    )
    return {"commands": [command], "executionTimeout": ["900"]}


def secret_client(environment):
    return api_client("secretsmanager", environment)


def put_secret(binding, body, environment, version):
    response = secret_client(environment).put_secret_value(
        SecretId=binding["secretArn"], ClientRequestToken=version, SecretString=json.dumps(body)
    )
    if response["ARN"] != binding["secretArn"] or response["VersionId"] != version:
        raise RuntimeError("Secret publication identity differs")


def expire_secret(binding, environment):
    client = secret_client(environment)
    metadata = client.describe_secret(SecretId=binding["secretArn"])
    if "AWSCURRENT" not in metadata.get("VersionIdsToStages", {}).get(binding["versionId"], []):
        return
    expired = str(uuid.uuid4())
    stage = "litellm-expired-" + expired
    client.put_secret_value(
        SecretId=binding["secretArn"],
        ClientRequestToken=expired,
        VersionStages=[stage],
        SecretString=json.dumps({"schemaVersion": 1, "state": "expired"}),
    )
    try:
        client.update_secret_version_stage(
            SecretId=binding["secretArn"],
            VersionStage="AWSCURRENT",
            MoveToVersionId=expired,
            RemoveFromVersionId=binding["versionId"],
        )
    except Exception:
        current = client.describe_secret(SecretId=binding["secretArn"])
        if "AWSCURRENT" in current.get("VersionIdsToStages", {}).get(binding["versionId"], []):
            raise
    finally:
        client.update_secret_version_stage(
            SecretId=binding["secretArn"], VersionStage=stage, RemoveFromVersionId=expired
        )


def main():
    environment = dict(os.environ)
    if any(environment.get(key, "").lower() == "true" for key in ("CI_DEBUG_TRACE", "DEBUG_DEPLOY_PASSWORD_FLOW")):
        raise ValueError("Secret delivery refuses CI debug tracing")
    binding = bindings(environment)
    environment.update(AWS_REGION=binding["region"], AWS_DEFAULT_REGION=binding["region"])
    body = runtime_secret(binding, environment)
    parameters = ssm_parameters(binding, Path(__file__).resolve().parent)
    assumed = aws(
        [
            "sts",
            "assume-role",
            "--role-arn",
            binding["deployRoleArn"],
            "--role-session-name",
            "LiteLLM-" + binding["deploymentId"][:56],
            "--region",
            binding["region"],
        ],
        environment,
    )["Credentials"]
    target = {
        **environment,
        "AWS_ACCESS_KEY_ID": assumed["AccessKeyId"],
        "AWS_SECRET_ACCESS_KEY": assumed["SecretAccessKey"],
        "AWS_SESSION_TOKEN": assumed["SessionToken"],
        "AWS_DEFAULT_REGION": binding["region"],
        "AWS_REGION": binding["region"],
    }
    for name in (
        "AWS_PROFILE",
        "AWS_DEFAULT_PROFILE",
        "AWS_ROLE_ARN",
        "AWS_WEB_IDENTITY_TOKEN_FILE",
        "AWS_ENDPOINT_URL",
        "AWS_ENDPOINT_URL_SECRETS_MANAGER",
    ):
        target.pop(name, None)
    identity = aws(["sts", "get-caller-identity"], target)
    if identity["Account"] != binding["accountId"] or not identity["Arn"].startswith(
        "arn:" + binding["partition"] + ":"
    ):
        raise RuntimeError("Assumed role belongs to a different account")
    online = aws(
        [
            "ssm",
            "describe-instance-information",
            "--filters",
            json.dumps([{"Key": "InstanceIds", "Values": [binding["instanceId"]]}]),
        ],
        target,
    )["InstanceInformationList"]
    if {i["InstanceId"] for i in online if i["PingStatus"] == "Online"} != {binding["instanceId"]}:
        raise RuntimeError("Not every requested instance is online")
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix="litellm-deploy-") as temporary:
        directory = Path(temporary)
        published = False
        try:
            published = True
            put_secret(binding, body, target, binding["versionId"])
            path = directory / "ssm-request.json"
            path.write_text(json.dumps(parameters))
            sent = aws(
                [
                    "ssm",
                    "send-command",
                    "--instance-ids",
                    binding["instanceId"],
                    "--document-name",
                    "AWS-RunShellScript",
                    "--comment",
                    "LiteLLM pinned target-side secret retrieval",
                    "--parameters",
                    "file://" + str(path),
                ],
                target,
            )
            command = sent["Command"]["CommandId"]
            print(
                json.dumps(
                    {
                        "commandId": command,
                        "deploymentId": binding["deploymentId"],
                        "releaseImage": binding["releaseImage"],
                    }
                ),
                flush=True,
            )
            deadline = time.monotonic() + 1000
            pending = {binding["instanceId"]}
            while pending and time.monotonic() < deadline:
                time.sleep(5)
                for instance in sorted(pending):
                    invocation = aws(
                        [
                            "ssm",
                            "get-command-invocation",
                            "--command-id",
                            command,
                            "--instance-id",
                            instance,
                            "--query",
                            "{Status:Status}",
                        ],
                        target,
                        missing_invocation_ok=True,
                    )
                    if not invocation or invocation["Status"] in ("Pending", "Delayed", "InProgress"):
                        continue
                    status = invocation["Status"]
                    print(json.dumps({"instanceId": instance, "commandId": command, "status": status}), flush=True)
                    if status != "Success":
                        raise RuntimeError("Target deployment failed; inspect its private operator diagnostic")
                    pending.remove(instance)
            if pending:
                aws(["ssm", "cancel-command", "--command-id", command, "--instance-ids", binding["instanceId"]], target)
                raise TimeoutError("Target deployment deadline exceeded; retained runtime must be inspected")
        finally:
            if published:
                expire_secret(binding, target)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(
            json.dumps(
                {
                    "status": "failed",
                    "errorType": type(error).__name__,
                    "diagnostic": "Deployment refused; inspect target-private diagnostics and AWS operation metadata.",
                }
            )
        )
        raise SystemExit(1)
