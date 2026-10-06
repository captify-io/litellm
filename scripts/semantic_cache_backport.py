#!/usr/bin/env python3
"""Attest the installed CVE-2026-89032 backport; never rewrite scan findings."""

import argparse
import asyncio
import contextlib
import copy
import hashlib
import importlib.metadata
import importlib.util
import json
import os
import re
import socket
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
from urllib.parse import quote

CVE = "CVE-2026-89032"
UPSTREAM = "16db51e2cfc28e02bd460481e634a8403ea9265e"
FILES = ("litellm/caching/caching.py", "litellm/proxy/litellm_pre_call_utils.py")
PACKAGE = {"name": "litellm", "version": "1.100.0"}
PACKAGE_PURL = "pkg:pypi/litellm@1.100.0"
FIELDS = ("user_api_key", "user_api_key_team_id", "user_api_key_org_id")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def manifest_of(value):
    require(set(value) == {"schemaVersion", "cve", "package", "upstreamCommit", "sourceSha256"}, "manifest fields")
    require(value["schemaVersion"] == 1 and value["cve"] == CVE, "manifest identity")
    require(value["package"] == PACKAGE and value["upstreamCommit"] == UPSTREAM, "manifest source")
    require(set(value["sourceSha256"]) == set(FILES), "manifest file set")
    require(all(re.fullmatch(r"[a-f0-9]{64}", x) for x in value["sourceSha256"].values()), "manifest hashes")
    return value


def probe(manifest):
    """Runs against the installed package in a network-disabled candidate image."""
    manifest_of(manifest)
    require(importlib.metadata.version("litellm") == PACKAGE["version"], "installed package version")
    spec = importlib.util.find_spec("litellm")
    require(spec is not None and spec.origin is not None, "installed package origin")
    package_root = Path(spec.origin).resolve().parent
    actual = {name: sha((package_root.parent / name).read_bytes()) for name in FILES}
    require(actual == manifest["sourceSha256"], "installed source differs from reviewed backport")

    def refuse(*_args, **_kwargs):
        raise RuntimeError("backport probe must never use network")

    socket.socket.connect = refuse
    socket.socket.connect_ex = refuse
    socket.create_connection = refuse
    os.environ["LITELLM_LOCAL_MODEL_COST_MAP"] = "True"
    with contextlib.redirect_stdout(sys.stderr):
        from starlette.requests import Request

        import litellm
        from litellm.caching.caching import Cache
        from litellm.caching.caching_handler import LLMCachingHandler
        from litellm.proxy._types import UserAPIKeyAuth
        from litellm.proxy.litellm_pre_call_utils import add_litellm_data_to_request
        from litellm.types.caching import LiteLLMCacheType

        cases = 0
        for backend in (
            LiteLLMCacheType.REDIS_SEMANTIC,
            LiteLLMCacheType.QDRANT_SEMANTIC,
            LiteLLMCacheType.VALKEY_SEMANTIC,
        ):
            cache = Cache(type=LiteLLMCacheType.LOCAL)
            cache.type = backend
            for nested in (False, True):
                for slot in ("metadata", "litellm_metadata"):
                    for field in FIELDS:
                        keys = []
                        for tenant in ("probe-a", "probe-b"):
                            scope = {slot: {field: tenant}}
                            if nested:
                                scope = {"litellm_params": scope}
                            keys.append(
                                cache.get_cache_key(
                                    model="gpt-4o-mini", messages=[{"role": "user", "content": "same"}], **scope
                                )
                            )
                        require(keys[0] != keys[1], "distinct authenticated cache scopes collide")
                        cases += 1

        async def proxy_cases():
            cache = Cache(type=LiteLLMCacheType.LOCAL)
            cache.type = LiteLLMCacheType.VALKEY_SEMANTIC

            def refuse_model(**_kwargs):
                raise RuntimeError("backport probe must never call a model")

            for path in ("/v1/chat/completions", "/v1/responses", "/v1/messages", "/bedrock/model/invoke"):
                request = MagicMock(spec=Request)
                request.url = MagicMock()
                request.url.path = path
                request.url.__str__.return_value = "http://localhost" + path
                request.method = "POST"
                request.query_params = {}
                request.headers = {"Content-Type": "application/json"}
                request.client = SimpleNamespace(host="127.0.0.1")
                request.state = SimpleNamespace()
                for override in (
                    {},
                    {"cache_key": "forged-shared"},
                    {"litellm_params": {"preset_cache_key": "forged-shared"}},
                ):
                    keys = []

                    async def capture(**kwargs):
                        keys.append(kwargs["cache_key"])

                    with (
                        patch.object(litellm, "cache", cache),
                        patch.object(cache, "_supports_async", return_value=True),
                        patch.object(cache, "async_get_cache", side_effect=capture),
                    ):
                        for identity in ("real-probe-a", "real-probe-b"):
                            body = {
                                "model": "gpt-4o-mini",
                                "messages": [{"role": "user", "content": "same"}],
                                **copy.deepcopy(override),
                            }
                            for slot in ("metadata", "litellm_metadata"):
                                body[slot] = {field: "forged-shared-value" for field in FIELDS}
                            stamped = await add_litellm_data_to_request(
                                data=body,
                                request=request,
                                user_api_key_dict=UserAPIKeyAuth(api_key=identity, metadata={}, team_metadata={}),
                                proxy_config=MagicMock(),
                                general_settings={},
                                version="backport-probe",
                            )
                            handler = LLMCachingHandler(
                                original_function=refuse_model, request_kwargs=stamped, start_time=datetime.now()
                            )
                            await handler._retrieve_from_cache(call_type="acompletion", kwargs=stamped, args=())
                    require(
                        len(keys) == 2 and keys[0] != keys[1] and "forged-shared" not in keys,
                        "HTTP controls bypass authenticated cache scope",
                    )

        asyncio.run(proxy_cases())
    return {"status": "PASS", "package": PACKAGE, "sourceSha256": actual, "scopeCases": cases, "proxyCases": 12}


def run(argv, **kwargs):
    return subprocess.run(argv, check=True, capture_output=True, text=True, timeout=120, **kwargs).stdout


def image_identity(image, revision):
    require(re.fullmatch(r"[a-f0-9]{40}", revision), "source revision")
    rows = json.loads(run(["docker", "image", "inspect", image]))
    require(len(rows) == 1, "one image required")
    row = rows[0]
    require(re.fullmatch(r"sha256:[a-f0-9]{64}", row["Id"]), "image ID")
    require(row["Config"].get("User") == "65534", "non-root image user")
    require(
        (row["Config"].get("Labels") or {}).get("org.opencontainers.image.revision") == revision, "image revision label"
    )
    if "@sha256:" in image:
        require(re.fullmatch(r"[a-z0-9][a-z0-9./:_-]*@sha256:[a-f0-9]{64}", image), "registry image reference")
        require(image in (row.get("RepoDigests") or []), "immutable registry digest missing")
        repository, digest = image.split("@", 1)
        require(re.fullmatch(r"sha256:[a-f0-9]{64}", digest), "registry digest")
        # Both scanners accept omitted qualifiers. The immutable digest and
        # repository leaf identify this exact OCI artifact, never all versions.
        product = "pkg:oci/" + quote(repository.rsplit("/", 1)[-1], safe="") + "@" + digest
        kind = "registry-manifest-digest"
    else:
        require(image == "litellm-image-scan:" + revision, "only exact local CI source tag supported")
        require(image in (row.get("RepoTags") or []), "local source tag missing")
        product = image
        kind = "local-source-tag-with-verified-config-id"
    return {"image": image, "imageId": row["Id"], "sourceRevision": revision, "product": product, "identityKind": kind}


def checked_probe(identity, manifest):
    result = json.loads(
        run(
            [
                "docker",
                "run",
                "--rm",
                "-i",
                "--network",
                "none",
                "--read-only",
                "--user",
                "65534:65534",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                "--pids-limit",
                "128",
                "--memory",
                "1g",
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,size=64m",
                "--env",
                "LITELLM_LOCAL_MODEL_COST_MAP=True",
                "--env",
                "PYTHONDONTWRITEBYTECODE=1",
                "--entrypoint",
                "/app/.venv/bin/python",
                identity["imageId"],
                "-B",
                "-",
                "probe",
                json.dumps(manifest, separators=(",", ":")),
            ],
            input=Path(__file__).read_text(),
        )
    )
    require(
        result
        == {
            "status": "PASS",
            "package": PACKAGE,
            "sourceSha256": manifest["sourceSha256"],
            "scopeCases": 36,
            "proxyCases": 12,
        },
        "in-image behavior proof",
    )
    require(image_identity(identity["image"], identity["sourceRevision"]) == identity, "image changed during probe")
    return result


def vex_for(identity, proof, timestamp):
    binding = sha(json.dumps(proof, sort_keys=True, separators=(",", ":")).encode())
    return {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": "https://github.com/captify-io/litellm/backports/" + binding,
        "author": "Captify",
        "role": "Document Creator",
        "timestamp": timestamp,
        "version": 1,
        "statements": [
            {
                "vulnerability": {"name": CVE},
                "products": [{"@id": identity["product"], "subcomponents": [{"@id": PACKAGE_PURL}]}],
                "status": "fixed",
                "timestamp": timestamp,
                "status_notes": "Verified upstream metadata-lookup backport "
                + UPSTREAM
                + " plus HTTP bare user_api_key, root cache_key and nested litellm_params.preset_cache_key stripping; "
                + "package version unchanged. Source "
                + identity["sourceRevision"]
                + "; Docker config "
                + identity["imageId"]
                + "; exact installed source and 48 network-blocked behavior cases verified. Proof SHA256 "
                + binding,
            }
        ],
    }


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "probe":
        sys.stdout.write(json.dumps(probe(manifest_of(json.loads(sys.argv[2]))), sort_keys=True) + "\n")
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("prepare", "verify"))
    parser.add_argument("--image", required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    manifest = manifest_of(json.loads((root / "security/backports/CVE-2026-89032.json").read_text()))
    require(run(["git", "rev-parse", "HEAD"], cwd=root).strip() == args.revision, "checkout revision")
    require(
        not run(["git", "status", "--porcelain", "--untracked-files=no"], cwd=root).strip(), "tracked checkout changed"
    )
    require(
        {name: sha((root / name).read_bytes()) for name in FILES} == manifest["sourceSha256"], "checkout backport drift"
    )
    identity = image_identity(args.image, args.revision)
    result = checked_probe(identity, manifest)
    proof = {
        "identity": identity,
        "manifest": manifest,
        "probe": result,
        "manifestSha256": sha((root / "security/backports/CVE-2026-89032.json").read_bytes()),
        "guardSha256": sha(Path(__file__).read_bytes()),
        "verifierSha256": sha((root / "scripts/verify_semantic_cache_backport.rb").read_bytes()),
    }
    if args.mode == "prepare":
        args.output_dir.mkdir(parents=True, exist_ok=False)
        timestamp = datetime.now(timezone.utc).isoformat()
        for name, data in (("proof.json", proof), ("fixed.vex.json", vex_for(identity, proof, timestamp))):
            (args.output_dir / name).write_text(json.dumps(data, indent=2) + "\n")
    else:
        require(json.loads((args.output_dir / "proof.json").read_text()) == proof, "proof/image/source binding changed")
        doc = json.loads((args.output_dir / "fixed.vex.json").read_text())
        require(doc == vex_for(identity, proof, doc["timestamp"]), "VEX document changed")
    sys.stdout.write("Backport source/image/behavior proof PASS; package version unchanged: " + args.image + "\n")


if __name__ == "__main__":
    main()
