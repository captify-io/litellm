"""Generate and verify image-scoped OpenVEX after an installed backport proof."""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Final, cast
from urllib.request import Request, urlopen

from semantic_cache_probe import SOURCE_HASHES, VERSION

type Json = None | bool | int | float | str | list[Json] | dict[str, Json]
type Object = dict[str, Json]

ROOT: Final = Path(__file__).resolve().parents[2]
PROBE: Final = Path(__file__).with_name("semantic_cache_probe.py")
CVE: Final = "CVE-2026-89032"
ALIASES: Final = frozenset((CVE, "GHSA-237m-2qxv-ww7c"))
PURL: Final = "pkg:pypi/litellm@1.100.0"
IMAGE_RE: Final = re.compile(r"127\.0\.0\.1:([0-9]{1,5})/litellm@sha256:([a-f0-9]{64})")
CASES: Final = {"tenantScopeCases": 36, "authenticatedRouteCases": 8, "sharedKeyCases": 1}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def obj(value: Json) -> Object:
    require(isinstance(value, dict), "Expected JSON object")
    return cast(Object, value)


def rows(value: Json) -> tuple[Object, ...]:
    require(isinstance(value, list), "Expected JSON array")
    return tuple(obj(item) for item in cast(list[Json], value))


def parse(raw: str | bytes) -> Object:
    return obj(cast(Json, json.loads(raw)))


def encoded(value: Json) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def command(arguments: tuple[str, ...], *, data: bytes | None = None, timeout: int = 900) -> bytes:
    result: Final = subprocess.run(
        arguments, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout
    )
    require(result.returncode == 0, f"Command failed: {arguments[0]} (exit {result.returncode})")
    return result.stdout


def validate_probe(proof: Object) -> Object:
    require(proof.get("version") == VERSION, "Wrong installed package version")
    require(proof.get("sourceSha256") == SOURCE_HASHES, "Wrong installed source hashes")
    require(proof.get("cases") == CASES, "Incomplete installed behavior proof")
    paths: Final = obj(proof.get("installedPaths"))
    require(set(paths) == set(SOURCE_HASHES), "Missing installed module location")
    for relative, path in paths.items():
        require(
            isinstance(path, str) and path.endswith("/site-packages/" + relative),
            "Module is not installed in site-packages",
        )
    require(len({str(path).split("/site-packages/")[0] for path in paths.values()}) == 1, "Mixed package installations")
    return proof


def inspect_image(reference: str, revision: str) -> Object:
    inspected: Final = rows(cast(Json, json.loads(command(("docker", "image", "inspect", reference)))))
    require(len(inspected) == 1, "Ambiguous image")
    image: Final = inspected[0]
    require(reference in cast(list[Json], image.get("RepoDigests", [])), "Image has no matching registry digest")
    labels: Final = obj(obj(image.get("Config")).get("Labels"))
    require(labels.get("org.opencontainers.image.revision") == revision, "Image source revision differs")
    return image


def validate_checkout(revision: str) -> None:
    require(re.fullmatch(r"[0-9a-f]{40}", revision) is not None, "Expected exact source revision")
    require(
        command(("git", "-C", str(ROOT), "rev-parse", "HEAD")).decode().strip() == revision, "Wrong source checkout"
    )
    for path in (PROBE, Path(__file__).resolve(), ROOT / ".github/workflows/image-scan.yml"):
        relative: Final = path.relative_to(ROOT).as_posix()
        require(
            path.read_bytes() == command(("git", "-C", str(ROOT), "show", f"{revision}:{relative}")),
            "Uncommitted proof or workflow source",
        )
    for relative, expected in SOURCE_HASHES.items():
        require(sha((ROOT / relative).read_bytes()) == expected, "Checkout lacks the reviewed backport")
        require(
            sha(command(("git", "-C", str(ROOT), "show", f"{revision}:{relative}"))) == expected,
            "Uncommitted source repair",
        )


def prove(reference: str, revision: str) -> Object:
    matched: Final = IMAGE_RE.fullmatch(reference)
    require(matched is not None and 0 < int(matched[1]) < 65536, "Expected job-local immutable registry reference")
    validate_checkout(revision)
    image: Final = inspect_image(reference, revision)
    registry, digest = reference.split("@")
    request: Final = Request(
        f"http://{registry.split('/')[0]}/v2/litellm/manifests/{digest}",
        headers={
            "Accept": "application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json"
        },
    )
    with urlopen(request, timeout=30) as response:
        manifest: Final = response.read(1024 * 1024 + 1)
        require(len(manifest) <= 1024 * 1024, "Oversized image manifest")
        require(response.headers.get("Docker-Content-Digest") == digest, "Registry digest header differs")
    require("sha256:" + sha(manifest) == digest, "Registry manifest digest differs")
    require(
        obj(parse(manifest).get("config")).get("digest") == image.get("Id"), "Manifest belongs to another Docker config"
    )
    probe_bytes: Final = PROBE.read_bytes()
    installed: Final = validate_probe(
        parse(
            command(
                (
                    "docker",
                    "run",
                    "--rm",
                    "--network",
                    "none",
                    "--read-only",
                    "--tmpfs",
                    "/tmp:rw,nosuid,nodev,size=128m",
                    "--env",
                    "LITELLM_LOCAL_MODEL_COST_MAP=True",
                    "--env",
                    "DO_NOT_TRACK=True",
                    "--entrypoint",
                    "python",
                    "--interactive",
                    str(image["Id"]),
                    "-I",
                    "-",
                ),
                data=probe_bytes,
            )
        )
    )
    require(inspect_image(reference, revision) == image, "Image custody changed during the proof")
    require(PROBE.read_bytes() == probe_bytes, "Probe changed during execution")
    return {
        "image": reference,
        "imageId": image["Id"],
        "sourceRevision": revision,
        "probeSha256": sha(probe_bytes),
        "installed": installed,
    }


def validate_report(report: Object, proof: Object) -> None:
    require(
        isinstance(proof.get("image"), str) and IMAGE_RE.fullmatch(str(proof["image"])) is not None,
        "VEX requires an exact image digest",
    )
    validate_probe(obj(proof.get("installed")))
    source: Final = obj(report.get("source"))
    target: Final = obj(source.get("target"))
    require(source.get("type") == "image", "Scan did not inspect an image")
    require(target.get("imageID") == proof["imageId"], "Scanner inspected a different Docker config")
    require(proof["image"] in cast(list[Json], target.get("repoDigests", [])), "Scanner omitted exact registry digest")
    descriptor: Final = obj(report.get("descriptor"))
    require(descriptor.get("name") == "grype" and descriptor.get("version") == "0.114.0", "Unreviewed scanner")
    rows(report.get("matches"))
    rows(report.get("ignoredMatches", []))


def is_backport(match: Object, proof: Object) -> bool:
    vulnerability: Final = obj(match.get("vulnerability"))
    artifact: Final = obj(match.get("artifact"))
    if vulnerability.get("id") not in ALIASES or artifact.get("purl") != PURL:
        return False
    require(artifact.get("name") == "litellm" and artifact.get("version") == VERSION, "Inconsistent package identity")
    installed: Final = obj(obj(proof.get("installed")).get("installedPaths"))
    prefix: Final = str(installed["litellm/caching/caching.py"]).removesuffix("litellm/caching/caching.py")
    metadata_path: Final = prefix + "litellm-1.100.0.dist-info/METADATA"
    locations: Final = rows(artifact.get("locations"))
    require(
        bool(locations)
        and any(
            location.get("path") == metadata_path and obj(location.get("annotations")).get("evidence") == "primary"
            for location in locations
        )
        and all(
            location.get("path")
            in (
                metadata_path,
                metadata_path.removesuffix("METADATA") + "RECORD",
                metadata_path.removesuffix("METADATA") + "direct_url.json",
            )
            and location.get("accessPath") == location.get("path")
            for location in locations
        ),
        "Scanned package is not the proven installation",
    )
    return True


def make_vex(report: Object, proof: Object) -> Object:
    validate_report(report, proof)
    matches: Final = tuple(match for match in rows(report["matches"]) if is_backport(match, proof))
    identifiers: Final = sorted({str(obj(match["vulnerability"])["id"]) for match in matches} or {CVE})
    product: Final = {"@id": proof["image"], "subcomponents": [{"@id": PURL}]}
    return {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": "urn:sha256:" + sha(encoded(proof)),
        "author": "https://github.com/captify-io/litellm",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": 1,
        "statements": [
            {
                "vulnerability": {"@id": identifier, "name": identifier},
                "products": [product],
                "status": "fixed",
                "status_notes": "LiteLLM remains 1.100.0. Exact installed cache-scope and authenticated metadata-strip "
                "backports passed the offline behavior proof. Evidence SHA256: " + sha(encoded(proof)),
            }
            for identifier in identifiers
        ],
    }


def fingerprint(match: Object) -> bytes:
    return encoded({key: value for key, value in match.items() if key != "appliedIgnoreRules"})


def validate_adjudication(raw: Object, filtered: Object, proof: Object) -> int:
    validate_report(raw, proof)
    validate_report(filtered, proof)
    require(obj(raw["descriptor"]).get("db") == obj(filtered["descriptor"]).get("db"), "Vulnerability database changed")
    before: Final = rows(raw["matches"])
    old_ignored: Final = rows(raw.get("ignoredMatches", []))
    after: Final = rows(filtered["matches"])
    new_ignored: Final = rows(filtered.get("ignoredMatches", []))
    require(
        Counter(fingerprint(row) for row in before + old_ignored)
        == Counter(fingerprint(row) for row in after + new_ignored),
        "Scan findings disappeared or changed",
    )
    require(all(row in new_ignored for row in old_ignored), "Existing only-fixed disposition changed")
    for row in new_ignored:
        if row in old_ignored:
            continue
        require(is_backport(row, proof), "VEX suppressed another package or vulnerability")
        rule: Final = {"namespace": "vex", "vex-status": "fixed"}
        require(
            row.get("appliedIgnoreRules") in ([rule], [{**rule, "vulnerability": obj(row["vulnerability"])["id"]}]),
            "Unexpected suppression rule",
        )
    require(not any(is_backport(row, proof) for row in after), "Exact image VEX did not match")
    return sum(obj(row["vulnerability"]).get("severity") in ("High", "Critical") for row in after)


def scan(reference: str, revision: str, grype: Path, output: Path) -> int:
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    proof: Final = prove(reference, revision)
    (output / "installed-proof.json").write_bytes(encoded(proof))
    config: Final = output / "grype-config.json"
    config.write_bytes(encoded({"ignore": [], "match": {"python": {"using-cpes": True}}}))
    environment: Final = {key: value for key, value in os.environ.items() if not key.startswith("GRYPE_")}
    target: Final = "registry:" + reference
    base: Final = (str(grype), target, "--config", str(config), "--only-fixed", "--output", "json")
    raw_path: Final = output / "grype-raw.json"
    with raw_path.open("wb") as stream:
        raw_result: Final = subprocess.run(
            base, env={**environment, "GRYPE_REGISTRY_INSECURE_USE_HTTP": "true"}, stdout=stream, timeout=1200
        )
    require(raw_result.returncode == 0, "Raw Grype scan failed")
    raw: Final = parse(raw_path.read_bytes())
    vex_path: Final = output / "backport.openvex.json"
    vex_path.write_bytes(encoded(make_vex(raw, proof)))
    filtered_path: Final = output / "grype-adjudicated.json"
    with filtered_path.open("wb") as stream:
        result: Final = subprocess.run(
            (*base, "--vex", str(vex_path), "--fail-on", "high"),
            env={**environment, "GRYPE_REGISTRY_INSECURE_USE_HTTP": "true", "GRYPE_DB_AUTO_UPDATE": "false"},
            stdout=stream,
            timeout=1200,
        )
    require(result.returncode in (0, 2), "Grype adjudication failed")
    filtered: Final = parse(filtered_path.read_bytes())
    remaining: Final = validate_adjudication(raw, filtered, proof)
    require((result.returncode == 0) == (remaining == 0), "Scanner threshold result contradicts report")
    (output / "summary.json").write_bytes(
        encoded(
            {
                "image": reference,
                "sourceRevision": revision,
                "policy": "--only-fixed --fail-on high",
                "rawMatches": len(rows(raw["matches"])),
                "remainingBlockingMatches": remaining,
                "fixedBackportMatches": sum(is_backport(row, proof) for row in rows(raw["matches"])),
                "sha256": {
                    path.name: sha(path.read_bytes())
                    for path in (raw_path, filtered_path, vex_path, output / "installed-proof.json")
                },
            }
        )
    )
    sys.stdout.write(f"Exact-image backport verified; {remaining} other policy-blocking findings remain\n")
    return result.returncode


def main() -> int:
    parser: Final = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--grype", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments: Final = parser.parse_args()
    return scan(arguments.image, arguments.source_revision, arguments.grype, arguments.output)


if __name__ == "__main__":
    sys.exit(main())
