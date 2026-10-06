"""
Static checks on docker/Dockerfile.non_root.

The non_root image is intended for deployment into hardened Kubernetes
clusters where `securityContext.runAsNonRoot: true` is enforced. The
kubelet validates non-root status by parsing the image's USER field as
an integer — a string name like "nobody" is rejected with
CreateContainerConfigError because the kubelet cannot resolve
/etc/passwd inside the image at admission time.
"""

import os
import re
import subprocess
from pathlib import Path

import pytest

DOCKERFILE_PATH = os.path.join(
    os.path.dirname(__file__),
    "..",
    "..",
    "docker",
    "Dockerfile.non_root",
)


def _final_user_directive(dockerfile_text: str) -> str:
    """Return the value of the last `USER` directive in the file."""
    matches = re.findall(r"^USER\s+(\S+)\s*$", dockerfile_text, re.MULTILINE)
    assert matches, "Dockerfile.non_root has no USER directive"
    return matches[-1]


@pytest.mark.skipif(
    not os.path.exists(DOCKERFILE_PATH),
    reason="Dockerfile.non_root not present in this checkout",
)
def test_final_user_directive_is_numeric():
    """The runtime USER must be a numeric UID so kubelet's runAsNonRoot
    admission check (strconv.Atoi) succeeds."""
    with open(DOCKERFILE_PATH, "r", encoding="utf-8") as f:
        contents = f.read()

    final_user = _final_user_directive(contents)

    assert final_user.isdigit(), (
        f"Dockerfile.non_root final USER is {final_user!r}; must be a numeric UID "
        "so Kubernetes' runAsNonRoot admission check can verify non-root status. "
        "See https://kubernetes.io/docs/tasks/configure-pod-container/security-context/"
    )

    assert int(final_user) != 0, (
        f"Dockerfile.non_root final USER is {final_user} (root); the non_root image must run as a non-zero UID."
    )


@pytest.mark.parametrize(
    "dockerfile",
    ("Dockerfile", "docker/Dockerfile.non_root", "gateway/Dockerfile", "backend/Dockerfile", "migrations/Dockerfile"),
)
@pytest.mark.parametrize("failed_command", ("add", "upgrade", ""))
def test_wolfi_package_install_requires_fixed_legacy_libraries_and_fails_closed(
    dockerfile: str, failed_command: str, tmp_path: Path
):
    contents = (Path(__file__).resolve().parents[2] / dockerfile).read_text()
    commands = tuple(
        command
        for command in re.findall(r"^RUN (.+)$", contents.replace("\\\n", ""), re.MULTILINE)
        if "apk add --no-cache" in command and "python3" in command
    )
    assert len(commands) == 2
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    apk = fake_bin / "apk"
    apk.write_text(
        '#!/bin/sh\nprintf "%s\\n" "$*" >> "$APK_CALLS"\nif [ "$1" = "$APK_FAIL_COMMAND" ]; then exit 1; fi\nexit 0\n'
    )
    apk.chmod(0o755)
    sleep = fake_bin / "sleep"
    sleep.write_text("#!/bin/sh\nexit 0\n")
    sleep.chmod(0o755)
    for index, command in enumerate(commands):
        calls = tmp_path / f"calls-{index}.txt"
        result = subprocess.run(
            ("sh", "-c", command),
            env={
                **os.environ,
                "PATH": f"{fake_bin}{os.pathsep}{os.environ['PATH']}",
                "APK_CALLS": str(calls),
                "APK_FAIL_COMMAND": failed_command,
            },
            capture_output=True,
            text=True,
            timeout=5,
        )
        assert (result.returncode != 0) == bool(failed_command and f"apk {failed_command} " in command), (
            result.stdout,
            result.stderr,
        )
        if failed_command != "upgrade" or "apk upgrade " not in command:
            added = tuple(line.split() for line in calls.read_text().splitlines() if line.startswith("add "))
            assert added
            assert all("libcrypto3=3.6.5-r1" in call and "libssl3=3.6.5-r1" in call for call in added)
