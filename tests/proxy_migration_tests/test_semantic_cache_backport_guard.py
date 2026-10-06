"""Fail-closed artifact binding, without Docker, AWS or provider calls."""

import copy
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("backport_guard", ROOT / "scripts/semantic_cache_backport.py")
g = importlib.util.module_from_spec(spec)
spec.loader.exec_module(g)
REV = "a" * 40
IMAGE = "registry.example.test/litellm@sha256:" + "b" * 64
ID = "sha256:" + "c" * 64
MANIFEST = json.loads((ROOT / "security/backports/CVE-2026-89032.json").read_text())


def row():
    return {
        "Id": ID,
        "Config": {"User": "65534", "Labels": {"org.opencontainers.image.revision": REV}},
        "RepoDigests": [IMAGE],
        "RepoTags": ["litellm-image-scan:" + REV],
    }


@pytest.mark.parametrize(
    "case, message",
    [
        ("extra", "manifest fields"),
        ("schema", "manifest identity"),
        ("cve", "manifest identity"),
        ("package", "manifest source"),
        ("upstream", "manifest source"),
        ("file", "manifest file set"),
        ("hash", "manifest hashes"),
    ],
)
def test_manifest_refuses_unreviewed_material(case, message):
    m = copy.deepcopy(MANIFEST)
    if case == "extra":
        m["extra"] = True
    elif case == "schema":
        m["schemaVersion"] = 2
    elif case == "cve":
        m["cve"] = "CVE-2000-0000"
    elif case == "package":
        m["package"]["version"] = "1.101.0"
    elif case == "upstream":
        m["upstreamCommit"] = "b" * 40
    elif case == "file":
        m["sourceSha256"]["other.py"] = "a" * 64
    else:
        m["sourceSha256"][g.FILES[0]] = "bad"
    with pytest.raises(ValueError, match=f"^{message}$"):
        g.manifest_of(m)


@pytest.mark.parametrize(
    "case, message",
    [
        ("rows", "one image required"),
        ("id", "image ID"),
        ("user", "non-root image user"),
        ("label", "image revision label"),
        ("digest", "immutable registry digest missing"),
        ("tag", "local source tag missing"),
        ("reference", "only exact local CI source tag supported"),
    ],
)
def test_identity_refusals(monkeypatch, case, message):
    r = row()
    image = IMAGE
    rows = [r]
    if case == "rows":
        rows = [r, r]
    elif case == "id":
        r["Id"] = "latest"
    elif case == "user":
        r["Config"]["User"] = "0"
    elif case == "label":
        r["Config"]["Labels"] = {}
    elif case == "digest":
        r["RepoDigests"] = []
    elif case == "tag":
        image = "litellm-image-scan:" + REV
        r["RepoTags"] = []
    elif case == "reference":
        image = "litellm:latest"
    monkeypatch.setattr(g, "run", lambda *_a, **_k: json.dumps(rows))
    with pytest.raises(ValueError, match=f"^{message}$"):
        g.image_identity(image, REV)


@pytest.mark.parametrize("image", [IMAGE, "litellm-image-scan:" + REV])
def test_identity_distinguishes_manifest_from_config_id(monkeypatch, image):
    monkeypatch.setattr(g, "run", lambda *_a, **_k: json.dumps([row()]))
    identity = g.image_identity(image, REV)
    assert identity["imageId"] == ID
    assert identity["product"] == ("pkg:oci/litellm@sha256:" + "b" * 64 if image == IMAGE else image)


def passed_probe():
    return {
        "status": "PASS",
        "package": g.PACKAGE,
        "sourceSha256": MANIFEST["sourceSha256"],
        "scopeCases": 36,
        "proxyCases": 12,
    }


def test_probe_hardening_and_exact_image_id(monkeypatch):
    identity = {"image": IMAGE, "imageId": ID, "sourceRevision": REV}
    calls = []

    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        return json.dumps(passed_probe())

    monkeypatch.setattr(g, "run", run)
    monkeypatch.setattr(g, "image_identity", lambda *_: identity)
    assert g.checked_probe(identity, MANIFEST) == passed_probe()
    argv = calls[0][0]
    assert argv[argv.index("--network") + 1] == "none"
    assert "--read-only" in argv and argv[argv.index("--user") + 1] == "65534:65534"
    assert argv[argv.index("--entrypoint") + 2] == ID
    assert "probe" in argv and "no-new-privileges" in argv


@pytest.mark.parametrize("case", ["status", "source", "scope", "proxy", "retag"])
def test_probe_refuses_mismatch_or_retag(monkeypatch, case):
    identity = {"image": IMAGE, "imageId": ID, "sourceRevision": REV}
    result = passed_probe()
    if case == "status":
        result["status"] = "FAIL"
    if case == "source":
        result["sourceSha256"] = {}
    if case == "scope":
        result["scopeCases"] = 35
    if case == "proxy":
        result["proxyCases"] = 4
    monkeypatch.setattr(g, "run", lambda *_a, **_k: json.dumps(result))
    monkeypatch.setattr(g, "image_identity", lambda *_: {} if case == "retag" else identity)
    message = "image changed during probe" if case == "retag" else "in-image behavior proof"
    with pytest.raises(ValueError, match=f"^{message}$"):
        g.checked_probe(identity, MANIFEST)


def test_vex_is_single_fixed_package_and_mentions_all_closures():
    identity = {"product": "pkg:oci/litellm@sha256:" + "b" * 64, "sourceRevision": REV, "imageId": ID}
    vex = g.vex_for(identity, {"actual": "proof"}, "2026-10-06T20:00:00+00:00")
    assert len(vex["statements"]) == 1
    statement = vex["statements"][0]
    assert statement["status"] == "fixed" and statement["vulnerability"]["name"] == g.CVE
    assert statement["products"][0]["subcomponents"] == [{"@id": g.PACKAGE_PURL}]
    for term in ("user_api_key", "root cache_key", "litellm_params.preset_cache_key", "package version unchanged"):
        assert term in statement["status_notes"]
