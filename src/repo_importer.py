"""Import a remote repository: git clone, with a ZIP-archive fallback.

If ``git clone`` fails (git missing, flaky network, proxy blocking the git
protocol), the repository snapshot is downloaded as a ZIP over plain HTTPS
from GitHub's codeload service or GitLab's archive endpoint instead.

A ZIP snapshot has no ``.git`` folder, so the original URL is recorded in a
sibling ``<folder>.source`` file. Publishing uses it to know where the code
came from.
"""

from __future__ import annotations

import io
import os
import shutil
import subprocess
import zipfile
from pathlib import Path
from typing import Optional

import requests

from src.git_publisher import RemoteRepo, remove_tree

MAX_ARCHIVE_BYTES = 200 * 1024 * 1024
CLONE_TIMEOUT = 120


class ImportFailed(Exception):
    pass


def source_marker(repo: Path) -> Path:
    return repo.parent / f"{repo.name}.source"


def read_source_marker(repo: Path) -> Optional[str]:
    marker = source_marker(repo)
    if marker.is_file():
        return marker.read_text(encoding="utf-8").strip() or None
    return None


def archive_urls(remote: RemoteRepo) -> list[str]:
    if remote.provider == "github":
        return [f"https://codeload.github.com/{remote.path}/zip/HEAD"]
    return [
        f"https://{remote.host}/{remote.path}/-/archive/{ref}/{remote.name}-{ref}.zip"
        for ref in ("HEAD", "main", "master")
    ]


def git_clone(remote: RemoteRepo, destination: Path) -> None:
    try:
        result = subprocess.run(
            ["git", "clone", "--depth", "1", remote.clone_url, str(destination)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=CLONE_TIMEOUT,
            stdin=subprocess.DEVNULL,
            env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
        )
    except FileNotFoundError as exc:
        raise ImportFailed("git is not installed") from exc
    except subprocess.TimeoutExpired as exc:
        raise ImportFailed("git clone timed out") from exc
    if result.returncode != 0:
        raise ImportFailed(result.stderr.strip()[-500:] or "git clone failed")


def extract_archive(content: bytes, destination: Path) -> None:
    """Safely extract a repo ZIP, flattening its single top-level folder."""

    staging = destination.parent / f"{destination.name}.extract"
    remove_tree(staging)
    staging.mkdir(parents=True)
    try:
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            root = staging.resolve()
            for member in archive.infolist():
                target = (staging / member.filename).resolve()
                if target != root and root not in target.parents:
                    raise ImportFailed("Unsafe path inside repository archive.")
            archive.extractall(staging)
        entries = list(staging.iterdir())
        inner = entries[0] if len(entries) == 1 and entries[0].is_dir() else staging
        shutil.move(str(inner), str(destination))
    except zipfile.BadZipFile as exc:
        raise ImportFailed("Downloaded archive is not a valid ZIP.") from exc
    finally:
        remove_tree(staging)


def download_archive(
    remote: RemoteRepo,
    destination: Path,
    session: Optional[requests.Session] = None,
) -> str:
    session = session or requests.Session()
    errors = []
    for url in archive_urls(remote):
        try:
            response = session.get(url, timeout=CLONE_TIMEOUT, stream=True)
        except requests.RequestException as exc:
            errors.append(f"{url}: {exc}")
            continue
        if response.status_code != 200:
            errors.append(f"{url}: HTTP {response.status_code}")
            continue
        chunks, size = [], 0
        for chunk in response.iter_content(1024 * 256):
            size += len(chunk)
            if size > MAX_ARCHIVE_BYTES:
                raise ImportFailed("Repository archive is larger than 200 MB.")
            chunks.append(chunk)
        extract_archive(b"".join(chunks), destination)
        return url
    raise ImportFailed("; ".join(errors) or "archive download failed")


def import_remote(remote: RemoteRepo, destination: Path) -> dict:
    """Clone, or fall back to the ZIP archive. Returns how it was imported."""

    log = []
    try:
        git_clone(remote, destination)
        return {"method": "git", "log": ["git clone succeeded"]}
    except ImportFailed as exc:
        log.append(f"git clone failed: {exc}")
        remove_tree(destination)

    try:
        url = download_archive(remote, destination)
    except ImportFailed as exc:
        remove_tree(destination)
        log.append(f"ZIP download failed: {exc}")
        raise ImportFailed(" | ".join(log)) from exc

    source_marker(destination).write_text(remote.web_url, encoding="utf-8")
    log.append(f"Downloaded snapshot from {url}")
    return {"method": "zip", "log": log}
