"""Adversarial controls for the exact-image backport attestation and disposition."""

import ast
import copy
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch, MagicMock

ROOT = Path(__file__).resolve().parents[2]
PROBE_SPEC = importlib.util.spec_from_file_location(
    "semantic_cache_probe", ROOT / "scripts/security/semantic_cache_probe.py"
)
PROBE_MODULE = importlib.util.module_from_spec(PROBE_SPEC)
PROBE_SPEC.loader.exec_module(PROBE_MODULE)
SPEC = importlib.util.spec_from_file_location("image_backport", ROOT / "scripts/security/image_backport.py")
MODULE = importlib.util.module_from_spec(SPEC)
with patch.dict(sys.modules, {"semantic_cache_probe": PROBE_MODULE}):
    SPEC.loader.exec_module(MODULE)


def proof():
    return {
        "image": "127.0.0.1:5000/litellm@sha256:" + "a" * 64,
        "imageId": "sha256:" + "b" * 64,
        "sourceRevision": "c" * 40,
        "installed": {
            "version": "1.100.0",
            "sourceSha256": dict(MODULE.SOURCE_HASHES),
            "cases": dict(MODULE.CASES),
            "installedPaths": {
                name: "/app/.venv/lib/python3.14/site-packages/" + name for name in MODULE.SOURCE_HASHES
            },
        },
    }


def finding(identifier=MODULE.CVE, package="litellm", severity="High"):
    return {
        "vulnerability": {
            "id": identifier,
            "severity": severity,
            "fix": {"state": "fixed", "versions": ["1.101.0-rc.1"]},
        },
        "artifact": {
            "id": package,
            "name": package,
            "version": "1.100.0",
            "purl": f"pkg:pypi/{package}@1.100.0",
            "locations": [
                {
                    "path": f"/app/.venv/lib/python3.14/site-packages/{package}-1.100.0.dist-info/METADATA",
                    "accessPath": f"/app/.venv/lib/python3.14/site-packages/{package}-1.100.0.dist-info/METADATA",
                    "annotations": {"evidence": "primary"},
                }
            ],
        },
        "relatedVulnerabilities": [],
        "matchDetails": [],
    }


def report(matches, ignored=()):
    held = proof()
    return {
        "matches": list(matches),
        "ignoredMatches": list(ignored),
        "source": {"type": "image", "target": {"imageID": held["imageId"], "repoDigests": [held["image"]]}},
        "descriptor": {"name": "grype", "version": "0.114.0", "db": {"checksum": "held-database"}},
    }


def fixed(match):
    return {
        **copy.deepcopy(match),
        "appliedIgnoreRules": [{"namespace": "vex", "vex-status": "fixed"}],
    }


class ImageBackportTests(unittest.TestCase):
    def test_checkout_rejects_wrong_revision_and_changed_committed_bytes(self):
        revision = "c" * 40
        paths = dict(MODULE.SOURCE_HASHES)
        fixture_hashes = {name: MODULE.sha((ROOT / name).read_bytes()) for name in paths}
        for changed in (
            None,
            "HEAD",
            "scripts/security/semantic_cache_probe.py",
            "scripts/security/image_backport.py",
            ".github/workflows/image-scan.yml",
            "litellm/caching/caching.py",
            "litellm/proxy/litellm_pre_call_utils.py",
        ):

            def execute(arguments, *, change=changed, **kwargs):
                if arguments[-2:] == ("rev-parse", "HEAD"):
                    return (("d" * 40 if change == "HEAD" else revision) + "\n").encode()
                name = arguments[-1].split(":", 1)[1]
                return b"unreviewed change" if change == name else (ROOT / name).read_bytes()

            with (
                self.subTest(changed=changed),
                patch.object(MODULE, "command", execute),
                patch.object(MODULE, "SOURCE_HASHES", fixture_hashes),
            ):
                if changed is None:
                    MODULE.validate_checkout(revision)
                else:
                    with self.assertRaises(ValueError):
                        MODULE.validate_checkout(revision)

    def test_manifest_and_installed_probe_authority_boundaries(self):
        for changed in (None, "header", "body", "config", "revision", "probe", "probe-failure"):
            manifest = MODULE.encoded({"config": {"digest": "sha256:" + ("e" if changed == "config" else "b") * 64}})
            digest = "sha256:" + MODULE.sha(manifest)
            reference = "127.0.0.1:5000/litellm@" + digest
            image = {
                "Id": proof()["imageId"],
                "RepoDigests": [reference],
                "Config": {
                    "Labels": {"org.opencontainers.image.revision": ("e" * 40 if changed == "revision" else "c" * 40)}
                },
            }
            result = proof()["installed"]
            if changed == "probe":
                result["cases"]["authenticatedRouteCases"] = 0
            calls = []

            def execute(arguments, *, observed=calls, image_data=image, change=changed, probe=result, **kwargs):
                observed.append(arguments)
                if arguments[:3] == ("docker", "image", "inspect"):
                    return json.dumps([image_data]).encode()
                self.assertEqual(arguments[:3], ("docker", "run", "--rm"))
                self.assertIn(("--network", "none"), tuple(zip(arguments, arguments[1:])))
                self.assertIn("--read-only", arguments)
                self.assertEqual(arguments[-2:], ("-I", "-"))
                self.assertEqual(kwargs["data"], MODULE.PROBE.read_bytes())
                if change == "probe-failure":
                    raise ValueError("Installed behavior refused")
                return MODULE.encoded(probe)

            response = MagicMock()
            response.__enter__.return_value = response
            response.headers = {"Docker-Content-Digest": "sha256:" + "0" * 64 if changed == "header" else digest}
            response.read.return_value = b"changed bytes" if changed == "body" else manifest
            with (
                self.subTest(changed=changed),
                patch.object(MODULE, "validate_checkout"),
                patch.object(MODULE, "command", execute),
                patch.object(MODULE, "urlopen", return_value=response) as opened,
            ):
                if changed is None:
                    actual = MODULE.prove(reference, "c" * 40)
                    self.assertEqual(actual["image"], reference)
                    self.assertEqual(actual["installed"], result)
                    self.assertIn(
                        "application/vnd.oci.image.manifest.v1+json", opened.call_args.args[0].headers["Accept"]
                    )
                else:
                    with self.assertRaises(ValueError):
                        MODULE.prove(reference, "c" * 40)
            if changed in ("header", "body", "config", "revision"):
                self.assertFalse(any(call[:2] == ("docker", "run") for call in calls))

    def test_real_grype_metadata_record_and_direct_url_locations(self):
        match = finding()
        metadata = match["artifact"]["locations"][0]
        record = {
            "path": metadata["path"].replace("METADATA", "RECORD"),
            "accessPath": metadata["accessPath"].replace("METADATA", "RECORD"),
            "annotations": {"evidence": "supporting"},
        }
        match["artifact"]["locations"].append(record)
        direct_url = {
            "path": metadata["path"].replace("METADATA", "direct_url.json"),
            "accessPath": metadata["accessPath"].replace("METADATA", "direct_url.json"),
            "annotations": {"evidence": "supporting"},
        }
        match["artifact"]["locations"].append(direct_url)
        self.assertTrue(MODULE.is_backport(match, proof()))
        for index in (1, 2):
            for altered in ("path", "accessPath"):
                candidate = copy.deepcopy(match)
                candidate["artifact"]["locations"][index][altered] = "/another/installation/" + (
                    "RECORD" if index == 1 else "direct_url.json"
                )
                with self.subTest(index=index, altered=altered), self.assertRaises(ValueError):
                    MODULE.is_backport(candidate, proof())
        for metadata_locations in (
            [record, direct_url],
            [{**metadata, "annotations": {"evidence": "supporting"}}, record, direct_url],
        ):
            candidate = copy.deepcopy(match)
            candidate["artifact"]["locations"] = metadata_locations
            with self.subTest(metadata_locations=metadata_locations), self.assertRaises(ValueError):
                MODULE.is_backport(candidate, proof())

    def test_exact_image_and_subcomponent_only(self):
        evidence = proof()
        vex = MODULE.make_vex(report([finding()]), evidence)
        self.assertEqual(
            vex["statements"][0]["products"],
            [{"@id": evidence["image"], "subcomponents": [{"@id": "pkg:pypi/litellm@1.100.0"}]}],
        )
        self.assertEqual(vex["statements"][0]["status"], "fixed")
        self.assertIn(MODULE.sha(MODULE.encoded(evidence)), vex["statements"][0]["status_notes"])
        self.assertNotEqual(vex["statements"][0]["products"][0]["@id"], "pkg:pypi/litellm@1.100.0")

    def test_alias_is_bounded(self):
        vex = MODULE.make_vex(report([finding("GHSA-237m-2qxv-ww7c")]), proof())
        self.assertEqual([row["vulnerability"]["name"] for row in vex["statements"]], ["GHSA-237m-2qxv-ww7c"])

    def test_package_only_and_tag_only_products_are_refused(self):
        for product in ("pkg:pypi/litellm@1.100.0", "litellm:latest", "sha256:" + "a" * 64):
            evidence = proof()
            evidence["image"] = product
            raw = report([finding()])
            raw["source"]["target"]["repoDigests"] = [product]
            with self.subTest(product=product), self.assertRaises(ValueError):
                MODULE.make_vex(raw, evidence)

    def test_installed_proof_requires_both_sources_and_every_case(self):
        self.assertEqual(MODULE.validate_probe(proof()["installed"]), proof()["installed"])
        for key in MODULE.SOURCE_HASHES:
            candidate = proof()["installed"]
            candidate["sourceSha256"][key] = "0" * 64
            with self.subTest(key=key), self.assertRaises(ValueError):
                MODULE.validate_probe(candidate)
        for key in MODULE.CASES:
            candidate = proof()["installed"]
            candidate["cases"][key] -= 1
            with self.subTest(key=key), self.assertRaises(ValueError):
                MODULE.validate_probe(candidate)
        for change in ("version", "installedPaths"):
            candidate = proof()["installed"]
            candidate[change] = "unreviewed"
            with self.subTest(change=change), self.assertRaises(ValueError):
                MODULE.validate_probe(candidate)

    def test_source_overlay_and_mixed_installations_refused(self):
        for path in ("/app/litellm/caching/caching.py", "/another/site-packages/litellm/caching/caching.py"):
            candidate = proof()["installed"]
            candidate["installedPaths"]["litellm/caching/caching.py"] = path
            with self.subTest(path=path), self.assertRaises(ValueError):
                MODULE.validate_probe(candidate)

    def test_wrong_image_config_digest_scanner_refused(self):
        for field, value in (
            ("imageID", "sha256:" + "d" * 64),
            ("repoDigests", []),
            ("repoDigests", ["litellm:mutable"]),
        ):
            candidate = report([finding()])
            candidate["source"]["target"][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                MODULE.make_vex(candidate, proof())
        candidate = report([finding()])
        candidate["descriptor"]["version"] = "future"
        with self.assertRaises(ValueError):
            MODULE.make_vex(candidate, proof())

    def test_wrong_installed_package_location_refused(self):
        for value in ([], [{"path": "/unproven/litellm-1.100.0.dist-info/METADATA"}]):
            match = finding()
            match["artifact"]["locations"] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                MODULE.make_vex(report([match]), proof())

    def test_no_other_finding_is_suppressed(self):
        for match in (finding("CVE-OTHER"), finding(package="other-package")):
            with self.subTest(match=match), self.assertRaises(ValueError):
                MODULE.validate_adjudication(
                    report([finding(), match]), report([], [fixed(finding()), fixed(match)]), proof()
                )

    def test_existing_only_fixed_policy_is_preserved(self):
        unfixed = finding("CVE-UNFIXED")
        unfixed["vulnerability"]["fix"] = {"state": "not-fixed", "versions": []}
        ignored = {**unfixed, "appliedIgnoreRules": [{"namespace": "", "fix-state": "not-fixed"}]}
        self.assertEqual(
            MODULE.validate_adjudication(
                report([finding()], [ignored]), report([], [ignored, fixed(finding())]), proof()
            ),
            0,
        )

    def test_other_high_critical_still_block_and_medium_does_not(self):
        for severity, expected in (("High", 1), ("Critical", 1), ("Medium", 0)):
            other = finding("CVE-OTHER", severity=severity)
            with self.subTest(severity=severity):
                self.assertEqual(
                    MODULE.validate_adjudication(
                        report([finding(), other]), report([other], [fixed(finding())]), proof()
                    ),
                    expected,
                )

    def test_disappearing_or_duplicated_findings_refused(self):
        for after in (report([]), report([], [fixed(finding()), fixed(finding())])):
            with self.subTest(after=after), self.assertRaises(ValueError):
                MODULE.validate_adjudication(report([finding()]), after, proof())

    def test_scanner_database_or_suppression_rule_drift_refused(self):
        for mutation in ("db", "rule"):
            after = report([], [fixed(finding())])
            if mutation == "db":
                after["descriptor"]["db"] = {"checksum": "changed"}
            else:
                after["ignoredMatches"][0]["appliedIgnoreRules"][0]["vex-status"] = "not_affected"
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                MODULE.validate_adjudication(report([finding()]), after, proof())

    def test_unmatched_vex_cannot_pass(self):
        with self.assertRaises(ValueError):
            MODULE.validate_adjudication(report([finding()]), report([finding()]), proof())

    def test_workflow_keeps_threshold_and_offline_proof(self):
        workflow = (ROOT / ".github/workflows/image-scan.yml").read_text()
        source = (ROOT / "scripts/security/image_backport.py").read_text()
        literals = tuple(node.value for node in ast.walk(ast.parse(source)) if isinstance(node, ast.Constant))
        self.assertIn("test_offline_image_migration.py", workflow)
        steps = (
            "python tests/code_coverage_tests/test_image_backport.py -v",
            "python scripts/semantic_cache_backport.py prepare",
            "> backport-proof/grype-raw.json",
            "python scripts/semantic_cache_backport.py verify",
            "--vex backport-proof/fixed.vex.json --show-suppressed",
            "--only-fixed --fail-on high --output json > backport-proof/grype-gated.json",
            "name: runtime-image-backport-${{ github.sha }}",
        )
        for step in steps:
            self.assertEqual(workflow.count(step), 1)
        positions = tuple(workflow.index(step) for step in steps)
        self.assertEqual(positions, tuple(sorted(positions)))
        self.assertEqual(workflow.count('"$RUNNER_TEMP/grype" "docker:$BACKPORT_IMAGE_ID"'), 2)
        self.assertIn('GRYPE_DB_AUTO_UPDATE: "false"', workflow)
        self.assertNotIn("<<<<<<<", workflow)
        self.assertIn('"--only-fixed"', source)
        self.assertIn('"--fail-on", "high"', source)
        self.assertIn("--network", literals)
        self.assertIn("none", literals)
        self.assertIn("-I", literals)
        self.assertNotIn("--vex", (ROOT / "scripts/gate-container-vulnerabilities.sh").read_text())


if __name__ == "__main__":
    unittest.main()
