"""Choose how the patched repository's tests are executed.

Running pytest executes the repository's own code, which may be untrusted.
In ``docker`` mode it runs inside a throw-away container with:

* no network            (--network none)
* memory / CPU / process limits
* a read-only root filesystem and all Linux capabilities dropped

``SANDBOX_MODE`` controls the behaviour:

* ``auto``   (default) - Docker when the daemon and sandbox image are
               available, otherwise a local subprocess.
* ``docker`` - always Docker (fails the validation if unavailable).
* ``local``  - always a local subprocess (e.g. when the backend itself
               already runs inside a container).
"""

from __future__ import annotations

import os
import subprocess
import sys
from functools import lru_cache
from pathlib import Path

SANDBOX_IMAGE = os.getenv("SANDBOX_IMAGE", "securepatch-sandbox:latest")
SANDBOX_MEMORY = os.getenv("SANDBOX_MEMORY", "1g")
SANDBOX_CPUS = os.getenv("SANDBOX_CPUS", "1")
PYTEST_ARGS = ["-m", "pytest", "tests", "-q", "-p", "no:cacheprovider"]


def sandbox_mode() -> str:
    mode = os.getenv("SANDBOX_MODE", "auto").strip().lower()
    return mode if mode in {"auto", "docker", "local"} else "auto"


@lru_cache(maxsize=1)
def _docker_ready(image: str) -> bool:
    try:
        result = subprocess.run(
            ["docker", "image", "inspect", image],
            capture_output=True,
            timeout=15,
            stdin=subprocess.DEVNULL,
        )
        return result.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def docker_ready() -> bool:
    return _docker_ready(SANDBOX_IMAGE)


def docker_command(sandbox: Path) -> list[str]:
    return [
        "docker", "run", "--rm",
        "--network", "none",
        "--memory", SANDBOX_MEMORY,
        "--memory-swap", SANDBOX_MEMORY,
        "--cpus", SANDBOX_CPUS,
        "--pids-limit", "256",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--read-only",
        "--tmpfs", "/tmp:rw,size=64m",
        "-e", "PYTHONDONTWRITEBYTECODE=1",
        "-v", f"{sandbox.resolve()}:/workspace",
        "-w", "/workspace",
        SANDBOX_IMAGE,
        "python", *PYTEST_ARGS,
    ]


def pytest_command(sandbox: Path) -> tuple[list[str], str]:
    """Return (command, isolation) where isolation is 'docker' or 'process'."""

    mode = sandbox_mode()
    if mode == "docker" or (mode == "auto" and docker_ready()):
        return docker_command(sandbox), "docker"
    return [sys.executable, *PYTEST_ARGS], "process"


def describe() -> dict:
    mode = sandbox_mode()
    ready = docker_ready() if mode != "local" else False
    return {
        "mode": mode,
        "image": SANDBOX_IMAGE,
        "docker_ready": ready,
        "isolation": "docker" if mode == "docker" or (mode == "auto" and ready) else "process",
        "limits": {
            "network": "none",
            "memory": SANDBOX_MEMORY,
            "cpus": SANDBOX_CPUS,
            "pids": 256,
        },
    }
