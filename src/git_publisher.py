"""Publish a verified SecurePatch fix to GitHub or GitLab.

Three publishing modes are supported:

* ``branch``   - push a ``securepatch/fix-...`` branch to the source
                 repository and open a Pull/Merge Request. Requires write
                 access to the source repository.
* ``fork``     - fork the source repository into the token owner's
                 account, push the fix branch to the fork and (optionally)
                 open a PR/MR - inside the fork by default, or back to the
                 original project only when explicitly requested.
* ``new_repo`` - create a brand-new repository in the token owner's
                 account. The original code is pushed to ``main`` and the
                 fix to a separate branch with a PR/MR, so the change is
                 reviewable as a diff. Used for ZIP uploads.

``auto`` picks ``branch`` when the token can push to the source, ``fork``
when it cannot, and ``new_repo`` when the code has no GitHub/GitLab origin.

The access token is only used for the duration of a request: it is never
written to disk, never stored in ``.git/config`` and scrubbed from every
error message.
"""

from __future__ import annotations

import difflib
import os
import re
import shutil
import stat
import subprocess
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional
from urllib.parse import quote, urlparse

import requests

SUPPORTED_HOSTS = {
    "github.com": "github",
    "www.github.com": "github",
    "gitlab.com": "gitlab",
    "www.gitlab.com": "gitlab",
}

MODES = {"auto", "branch", "fork", "new_repo"}

IGNORED_DIRS = {
    ".git",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".venv",
    "venv",
    "node_modules",
}

GIT_TIMEOUT = 180
HTTP_TIMEOUT = 30


class PublishError(Exception):
    """A user-facing publishing failure (safe to show in the UI)."""

    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.status_code = status_code


# =========================================================
# REMOTE URL HANDLING
# =========================================================


@dataclass(frozen=True)
class RemoteRepo:
    provider: str  # "github" | "gitlab"
    host: str  # "github.com" | "gitlab.com"
    path: str  # "owner/name" or "group/subgroup/name" (GitLab)

    @property
    def name(self) -> str:
        return self.path.rsplit("/", 1)[-1]

    @property
    def owner(self) -> str:
        return self.path.rsplit("/", 1)[0]

    @property
    def web_url(self) -> str:
        return f"https://{self.host}/{self.path}"

    @property
    def clone_url(self) -> str:
        return f"{self.web_url}.git"

    def to_dict(self) -> dict:
        return {
            "provider": self.provider,
            "host": self.host,
            "path": self.path,
            "owner": self.owner,
            "name": self.name,
            "web_url": self.web_url,
            "clone_url": self.clone_url,
        }


_SCP_STYLE = re.compile(r"^git@(?P<host>[^:]+):(?P<path>.+)$")


def parse_remote_url(url: str) -> RemoteRepo:
    """Parse a GitHub/GitLab web, HTTPS or SSH URL into a RemoteRepo."""

    url = (url or "").strip()
    if not url:
        raise PublishError("Repository URL is required.")

    scp = _SCP_STYLE.match(url)
    if scp:
        host = scp.group("host").lower()
        raw_path = scp.group("path")
    else:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https", "ssh"}:
            raise PublishError("Repository URL must use https.")
        # Drop any credentials embedded in the URL.
        host = (parsed.hostname or "").lower()
        raw_path = parsed.path

    provider = SUPPORTED_HOSTS.get(host)
    if not provider:
        raise PublishError(
            "Only github.com and gitlab.com repositories are supported."
        )
    host = host.removeprefix("www.")

    path = raw_path.strip("/")
    # GitLab web URLs: group/project/-/tree/main/...
    path = path.split("/-/", 1)[0]
    if path.endswith(".git"):
        path = path[:-4]

    parts = [p for p in path.split("/") if p]
    if provider == "github":
        # github.com/owner/repo/tree/main/... -> owner/repo
        parts = parts[:2]
    if len(parts) < 2:
        raise PublishError("Repository URL must include owner and name.")

    safe = re.compile(r"^[A-Za-z0-9_.-]+$")
    if not all(safe.match(p) for p in parts) or any(
        p in {".", ".."} for p in parts
    ):
        raise PublishError("Repository URL contains invalid characters.")

    return RemoteRepo(provider=provider, host=host, path="/".join(parts))


def authenticated_url(remote: RemoteRepo, token: str) -> str:
    user = "x-access-token" if remote.provider == "github" else "oauth2"
    return f"https://{user}:{quote(token, safe='')}@{remote.host}/{remote.path}.git"


def scrub(text: str, token: Optional[str]) -> str:
    """Remove a token (raw or URL-encoded) from text before showing it."""

    if not text:
        return ""
    if token:
        text = text.replace(token, "***")
        text = text.replace(quote(token, safe=""), "***")
    # Defensive: hide any other credentials embedded in URLs.
    return re.sub(r"(https?://)[^/\s:@]+:[^@\s]+@", r"\1***@", text)


def make_branch_name(test_id: str, function_name: str) -> str:
    slug = re.sub(
        r"[^a-z0-9]+",
        "-",
        f"{test_id or 'issue'}-{function_name or 'patch'}".lower(),
    ).strip("-")[:50]
    return f"securepatch/fix-{slug}-{time.strftime('%Y%m%d-%H%M%S')}"


# =========================================================
# GIT HELPERS
# =========================================================


def run_git(
    args: list[str],
    cwd: Path,
    token: Optional[str] = None,
) -> str:
    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GCM_INTERACTIVE"] = "never"
    command = [
        "git",
        # Never let a credential helper store the token.
        "-c",
        "credential.helper=",
        "-c",
        "core.autocrlf=false",
        *args,
    ]
    try:
        result = subprocess.run(
            command,
            cwd=str(cwd),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=GIT_TIMEOUT,
            env=env,
            stdin=subprocess.DEVNULL,
        )
    except FileNotFoundError as exc:
        raise PublishError("git is not installed on the server.", 500) from exc
    except subprocess.TimeoutExpired as exc:
        raise PublishError(f"git {args[0]} timed out.", 504) from exc

    if result.returncode != 0:
        output = scrub((result.stderr or result.stdout).strip(), token)
        raise PublishError(f"git {args[0]} failed: {output[-800:]}", 502)
    return result.stdout.strip()


def detect_source_remote(repo: Path) -> Optional[RemoteRepo]:
    """Return the GitHub/GitLab origin of a local clone, if any."""

    if not (repo / ".git").exists():
        # ZIP-fallback imports record their origin in a sibling file.
        marker = repo.parent / f"{repo.name}.source"
        try:
            return parse_remote_url(marker.read_text(encoding="utf-8"))
        except (OSError, PublishError):
            return None
    try:
        url = run_git(["remote", "get-url", "origin"], cwd=repo)
        return parse_remote_url(url)
    except PublishError:
        return None


def _force_remove(func, path, _exc_info):
    # Git object files are read-only on Windows.
    os.chmod(path, stat.S_IWRITE)
    func(path)


def remove_tree(path: Path) -> None:
    if not path.exists():
        return
    try:
        shutil.rmtree(path, onexc=_force_remove)  # Python 3.12+
    except TypeError:
        shutil.rmtree(path, onerror=_force_remove)
    except OSError:
        shutil.rmtree(path, ignore_errors=True)


def _ignore(directory: str, names: list[str]) -> set[str]:
    return {n for n in names if n in IGNORED_DIRS or n.endswith(".pyc")}


def _ignore_keep_git(directory: str, names: list[str]) -> set[str]:
    return _ignore(directory, names) - {".git"}


def _write_files(workdir: Path, files: dict[str, bytes]) -> None:
    root = workdir.resolve()
    for relative, content in files.items():
        target = (workdir / relative).resolve()
        target.relative_to(root)  # refuse path traversal
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)


def _commit(
    workdir: Path,
    message: str,
    author: tuple[str, str],
) -> None:
    name, email = author
    run_git(["add", "-A"], cwd=workdir)
    run_git(
        [
            "-c",
            f"user.name={name}",
            "-c",
            f"user.email={email}",
            "commit",
            "--no-verify",
            "-m",
            message,
        ],
        cwd=workdir,
    )


def prepare_fix_on_clone(
    repo: Path,
    workdir: Path,
    branch: str,
    files: dict[str, bytes],
    message: str,
    author: tuple[str, str],
    clone_url: Optional[str] = None,
    token: Optional[str] = None,
) -> None:
    """Commit the fix on a branch on top of the remote's history.

    Uses the local clone when it has ``.git``; otherwise (ZIP snapshot)
    makes a fresh shallow clone of ``clone_url``.
    """

    if (repo / ".git").exists():
        shutil.copytree(repo, workdir, ignore=_ignore_keep_git)
    else:
        if not clone_url:
            raise PublishError("No Git history available to branch from.")
        workdir.parent.mkdir(parents=True, exist_ok=True)
        run_git(
            ["clone", "-q", "--depth", "1", clone_url, str(workdir)],
            cwd=workdir.parent,
            token=token,
        )
    run_git(["checkout", "-B", branch], cwd=workdir)
    _write_files(workdir, files)
    _commit(workdir, message, author)


def prepare_fresh_repo(
    repo: Path,
    workdir: Path,
    base_branch: str,
    fix_branch: Optional[str],
    files: dict[str, bytes],
    message: str,
    author: tuple[str, str],
) -> None:
    """Create a new history: original code on base_branch, fix on top.

    With ``fix_branch`` the fix goes to a separate branch (for a PR);
    without it the fix is committed directly on ``base_branch``.
    """

    shutil.copytree(repo, workdir, ignore=_ignore)
    run_git(["init", "-q"], cwd=workdir)
    run_git(["checkout", "-q", "-b", base_branch], cwd=workdir)
    _commit(workdir, "Import original code (before SecurePatch)", author)
    if fix_branch:
        run_git(["checkout", "-q", "-b", fix_branch], cwd=workdir)
    _write_files(workdir, files)
    _commit(workdir, message, author)


def push_branches(
    workdir: Path,
    url: str,
    branches: list[str],
    token: Optional[str],
    attempts: int = 3,
) -> None:
    refspecs = [f"refs/heads/{b}:refs/heads/{b}" for b in branches]
    for attempt in range(attempts):
        try:
            run_git(["push", url, *refspecs], cwd=workdir, token=token)
            return
        except PublishError:
            # A freshly created fork may need a few seconds to be ready.
            if attempt == attempts - 1:
                raise
            time.sleep(3 * (attempt + 1))


# =========================================================
# PROVIDER API CLIENTS
# =========================================================


class _ApiClient:
    provider = ""

    def __init__(self, token: str, session: Optional[requests.Session] = None):
        if not token or not token.strip():
            raise PublishError("An access token is required.", 401)
        self.token = token.strip()
        self.session = session or requests.Session()

    def _request(self, method: str, url: str, **kwargs) -> requests.Response:
        try:
            response = self.session.request(
                method,
                url,
                headers=self._headers(),
                timeout=HTTP_TIMEOUT,
                **kwargs,
            )
        except requests.RequestException as exc:
            raise PublishError(
                f"Could not reach {self.provider}: {scrub(str(exc), self.token)}",
                502,
            ) from exc
        return response

    def _fail(self, response: requests.Response, action: str):
        try:
            data = response.json()
            detail = data.get("message") or data.get("error") or data
            if isinstance(data, dict) and data.get("errors"):
                detail = f"{detail} {data['errors']}"
        except ValueError:
            detail = response.text[:300]
        status = response.status_code
        if status == 401:
            message = f"{action}: the token is invalid or expired."
        elif status == 403:
            message = (
                f"{action}: the token does not have enough permissions "
                f"({scrub(str(detail), self.token)})."
            )
        elif status == 404:
            message = (
                f"{action}: repository not found, or the token cannot see it."
            )
        else:
            message = f"{action} failed ({status}): {scrub(str(detail), self.token)}"
        raise PublishError(message, 400 if status >= 500 else status)

    def _headers(self) -> dict:
        raise NotImplementedError


class GitHubClient(_ApiClient):
    provider = "github"
    api = "https://api.github.com"

    def _headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "SecurePatch",
        }

    def current_user(self) -> dict:
        r = self._request("GET", f"{self.api}/user")
        if r.status_code != 200:
            self._fail(r, "Checking the token")
        data = r.json()
        login = data["login"]
        return {
            "username": login,
            "name": data.get("name") or login,
            "email": f"{data['id']}+{login}@users.noreply.github.com",
            "avatar_url": data.get("avatar_url"),
            "profile_url": data.get("html_url") or f"https://github.com/{login}",
        }

    def get_repo(self, remote: RemoteRepo) -> dict:
        r = self._request("GET", f"{self.api}/repos/{remote.path}")
        if r.status_code != 200:
            self._fail(r, f"Reading {remote.path}")
        data = r.json()
        return {
            "id": data["id"],
            "path": data["full_name"],
            "default_branch": data.get("default_branch") or "main",
            "can_push": bool((data.get("permissions") or {}).get("push")),
            "private": bool(data.get("private")),
        }

    def fork(self, remote: RemoteRepo) -> RemoteRepo:
        r = self._request("POST", f"{self.api}/repos/{remote.path}/forks")
        if r.status_code not in (200, 202):
            self._fail(r, f"Forking {remote.path}")
        fork = RemoteRepo("github", remote.host, r.json()["full_name"])
        # Forking is asynchronous: wait until the fork is readable.
        for _ in range(15):
            if self._request(
                "GET", f"{self.api}/repos/{fork.path}"
            ).status_code == 200:
                break
            time.sleep(2)
        return fork

    def create_repo(self, name: str, private: bool) -> RemoteRepo:
        r = self._request(
            "POST",
            f"{self.api}/user/repos",
            json={
                "name": name,
                "private": private,
                "auto_init": False,
                "description": "Security fixes generated and verified by SecurePatch",
            },
        )
        if r.status_code != 201:
            self._fail(r, f"Creating repository '{name}'")
        return RemoteRepo("github", "github.com", r.json()["full_name"])

    def open_pull_request(
        self,
        target: RemoteRepo,
        source: RemoteRepo,
        branch: str,
        base: str,
        title: str,
        body: str,
    ) -> str:
        head = (
            branch
            if source.path == target.path
            else f"{source.owner}:{branch}"
        )
        r = self._request(
            "POST",
            f"{self.api}/repos/{target.path}/pulls",
            json={"title": title, "head": head, "base": base, "body": body},
        )
        if r.status_code != 201:
            self._fail(r, "Opening the pull request")
        return r.json()["html_url"]


class GitLabClient(_ApiClient):
    provider = "gitlab"

    def __init__(
        self,
        token: str,
        host: str = "gitlab.com",
        session: Optional[requests.Session] = None,
    ):
        super().__init__(token, session)
        self.host = host
        self.api = f"https://{host}/api/v4"

    def _headers(self) -> dict:
        return {"PRIVATE-TOKEN": self.token, "User-Agent": "SecurePatch"}

    def _project_url(self, remote_or_id) -> str:
        key = (
            quote(remote_or_id.path, safe="")
            if isinstance(remote_or_id, RemoteRepo)
            else str(remote_or_id)
        )
        return f"{self.api}/projects/{key}"

    def current_user(self) -> dict:
        r = self._request("GET", f"{self.api}/user")
        if r.status_code != 200:
            self._fail(r, "Checking the token")
        data = r.json()
        username = data["username"]
        return {
            "username": username,
            "name": data.get("name") or username,
            "email": f"{data['id']}-{username}@users.noreply.{self.host}",
            "avatar_url": data.get("avatar_url"),
            "profile_url": data.get("web_url") or f"https://{self.host}/{username}",
        }

    def get_repo(self, remote: RemoteRepo) -> dict:
        r = self._request("GET", self._project_url(remote))
        if r.status_code != 200:
            self._fail(r, f"Reading {remote.path}")
        data = r.json()
        permissions = data.get("permissions") or {}
        levels = [
            (permissions.get(k) or {}).get("access_level") or 0
            for k in ("project_access", "group_access")
        ]
        return {
            "id": data["id"],
            "path": data["path_with_namespace"],
            "default_branch": data.get("default_branch") or "main",
            # 30 = Developer: allowed to push new branches.
            "can_push": max(levels) >= 30,
            "private": data.get("visibility") != "public",
        }

    def fork(self, remote: RemoteRepo) -> RemoteRepo:
        r = self._request("POST", f"{self._project_url(remote)}/fork")
        if r.status_code in (200, 201):
            fork = RemoteRepo("gitlab", self.host, r.json()["path_with_namespace"])
        elif r.status_code == 409:
            # A fork already exists in the user's namespace.
            user = self.current_user()["username"]
            fork = RemoteRepo("gitlab", self.host, f"{user}/{remote.name}")
        else:
            self._fail(r, f"Forking {remote.path}")
        for _ in range(30):
            check = self._request("GET", self._project_url(fork))
            if (
                check.status_code == 200
                and check.json().get("import_status") in (None, "none", "finished")
            ):
                break
            time.sleep(2)
        return fork

    def create_repo(self, name: str, private: bool) -> RemoteRepo:
        r = self._request(
            "POST",
            f"{self.api}/projects",
            json={
                "name": name,
                "visibility": "private" if private else "public",
                "initialize_with_readme": False,
                "description": "Security fixes generated and verified by SecurePatch",
            },
        )
        if r.status_code != 201:
            self._fail(r, f"Creating project '{name}'")
        return RemoteRepo("gitlab", self.host, r.json()["path_with_namespace"])

    def open_pull_request(
        self,
        target: RemoteRepo,
        source: RemoteRepo,
        branch: str,
        base: str,
        title: str,
        body: str,
    ) -> str:
        payload = {
            "source_branch": branch,
            "target_branch": base,
            "title": title,
            "description": body,
            "remove_source_branch": True,
        }
        if source.path != target.path:
            payload["target_project_id"] = self.get_repo(target)["id"]
        r = self._request(
            "POST",
            f"{self._project_url(source)}/merge_requests",
            json=payload,
        )
        if r.status_code != 201:
            self._fail(r, "Opening the merge request")
        return r.json()["web_url"]


def make_client(provider: str, token: str):
    if provider == "github":
        return GitHubClient(token)
    if provider == "gitlab":
        return GitLabClient(token)
    raise PublishError("Provider must be 'github' or 'gitlab'.")


# =========================================================
# MODE RESOLUTION
# =========================================================


def resolve_mode(
    requested: str,
    source: Optional[RemoteRepo],
    provider: str,
    client,
) -> dict:
    """Decide how to publish and explain the decision."""

    if requested not in MODES:
        raise PublishError(f"Unknown publish mode '{requested}'.")

    user = client.current_user()
    plan = {
        "user": user["username"],
        "profile": {
            "username": user["username"],
            "name": user.get("name"),
            "avatar_url": user.get("avatar_url"),
            "profile_url": user.get("profile_url"),
        },
        "author": (user["name"], user["email"]),
        "provider": provider,
        "source": source.to_dict() if source else None,
        "can_push": False,
        "default_branch": None,
    }

    same_provider = source is not None and source.provider == provider
    if same_provider:
        info = client.get_repo(source)
        plan["can_push"] = info["can_push"]
        plan["default_branch"] = info["default_branch"]
        plan["is_own_repo"] = source.owner.lower() == user["username"].lower()

    mode = requested
    if mode == "auto":
        if not same_provider:
            mode = "new_repo"
        elif plan["can_push"]:
            mode = "branch"
        else:
            mode = "fork"

    if mode in {"branch", "fork"} and not same_provider:
        raise PublishError(
            "This code was not imported from a "
            f"{provider} repository, so it can only be published as a new "
            "repository."
        )
    if mode == "branch" and not plan["can_push"]:
        raise PublishError(
            f"@{user['username']} cannot push to {source.path}. "
            "Use 'Fork' instead - the fix will go to your own fork.",
            403,
        )
    if mode == "fork" and plan.get("is_own_repo"):
        raise PublishError(
            "You own this repository, so it cannot be forked. "
            "Use 'Branch' instead.",
        )

    reasons = {
        "branch": (
            f"@{user['username']} has write access to {source.path if source else ''}: "
            "a fix branch will be pushed there and a "
            f"{'pull' if provider == 'github' else 'merge'} request opened."
        ),
        "fork": (
            f"@{user['username']} cannot push to {source.path if source else ''}: "
            "it will be forked into your account and the fix pushed to "
            "the fork. The original project is not touched unless you "
            "choose to open a request to it."
        ),
        "new_repo": (
            "A new repository will be created in your account with the "
            "original code on 'main' and the fix on a separate branch."
        ),
    }
    plan["mode"] = mode
    plan["reason"] = reasons[mode]
    return plan


# =========================================================
# PUBLISH
# =========================================================


def build_pr_body(summary: dict) -> str:
    finding = summary.get("finding") or {}
    regression = summary.get("regression") or {}
    security = summary.get("security") or {}
    cwe = (finding.get("issue_cwe") or {}).get("id")
    lines = [
        "## SecurePatch verified security fix",
        "",
        "| | |",
        "|---|---|",
        f"| Bandit rule | `{finding.get('test_id', '?')}` {finding.get('test_name', '')} |",
        f"| Severity / confidence | {finding.get('issue_severity', '?')} / {finding.get('issue_confidence', '?')} |",
    ]
    if cwe:
        lines.append(
            f"| CWE | [CWE-{cwe}](https://cwe.mitre.org/data/definitions/{cwe}.html) |"
        )
    lines += [
        f"| Location | `{summary.get('target_file', '?')}` line {finding.get('line_number', '?')} |",
        f"| Function | `{summary.get('function', '?')}` |",
        "",
        f"**Issue:** {finding.get('issue_text', '')}",
        "",
        "### Verification",
        f"- Regression tests (pytest): {regression.get('passed_count', 0)} passed, "
        f"{regression.get('failed_count', 0)} failed",
        f"- Bandit re-scan: target rule `{finding.get('test_id', '?')}` "
        f"{'removed' if security.get('target_removed') else 'still present'}; "
        f"{security.get('findings_after', '?')} findings remain in the repository",
    ]
    comparison = summary.get("comparison") or {}
    if comparison:
        before = comparison.get("before") or {}
        after = comparison.get("after") or {}
        lines.append(
            f"- Bandit totals: {before.get('total', '?')} before -> "
            f"{after.get('total', '?')} after "
            f"(HIGH {before.get('HIGH', 0)} -> {after.get('HIGH', 0)}); "
            f"{len(comparison.get('removed') or [])} removed, "
            f"{len(comparison.get('introduced') or [])} introduced"
        )
    lines += [
        "",
        "_The patch was generated with repository-aware RAG + LLM, checked by "
        "AST guardrails, and validated in an isolated sandbox before this "
        "request was opened. Please review it before merging._",
    ]
    return "\n".join(lines)


REPORT_FILE = "SECURITY_REMEDIATION_REPORT.md"


def unified_diff(repo: Path, files: dict[str, bytes]) -> str:
    """Unified diff of each changed file against the original repository."""

    chunks = []
    for relative, content in files.items():
        before_path = repo / relative
        before = (
            before_path.read_bytes().decode("utf-8", "replace")
            if before_path.is_file()
            else ""
        )
        after = content.decode("utf-8", "replace")
        chunks.extend(
            difflib.unified_diff(
                before.replace("\r\n", "\n").splitlines(keepends=True),
                after.replace("\r\n", "\n").splitlines(keepends=True),
                fromfile=f"a/{relative}",
                tofile=f"b/{relative}",
            )
        )
    return "".join(chunks)


def build_report(summary: dict, diff: str) -> str:
    """Markdown remediation report committed next to the fix."""

    finding = summary.get("finding") or {}
    lines = [
        "# Security Remediation Report",
        "",
        f"_Generated by SecurePatch on {time.strftime('%Y-%m-%d %H:%M:%S %Z')}_",
        "",
        build_pr_body(summary).replace(
            "## SecurePatch verified security fix", "## Summary"
        ),
        "",
        "## Pipeline",
        "",
        "1. **Detect** - Bandit static analysis (SAST) found the issue.",
        "2. **Understand** - AST analysis located the vulnerable function; "
        "the source graph mapped its callers and tests.",
        "3. **Retrieve** - RAG pulled related repository code as context.",
        "4. **Repair** - a local LLM generated a minimal patch for that function only.",
        "5. **Guardrails** - the patch was checked to be one valid function with the "
        "same name and no `eval`/`exec`/`os.system`/`shell=True`.",
        "6. **Verify** - the patch was applied in an isolated sandbox, the test suite "
        "was run, and Bandit re-scanned the code.",
        "",
        "## Change",
        "",
        "```diff",
        diff.rstrip() or "(no textual change)",
        "```",
        "",
        "## References",
        "",
    ]
    if finding.get("more_info"):
        lines.append(f"- Bandit documentation: {finding['more_info']}")
    cwe = (finding.get("issue_cwe") or {}).get("id")
    if cwe:
        lines.append(f"- CWE-{cwe}: https://cwe.mitre.org/data/definitions/{cwe}.html")
    lines.append("- Bandit: https://bandit.readthedocs.io/")
    return "\n".join(lines) + "\n"


def publish(
    *,
    repo: Path,
    work_root: Path,
    files: dict[str, bytes],
    summary: dict,
    provider: str,
    token: str,
    mode: str = "auto",
    new_repo_name: Optional[str] = None,
    private: bool = True,
    open_request: bool = True,
    request_to_upstream: bool = False,
    include_report: bool = True,
    client=None,
    url_for: Callable[[RemoteRepo, str], str] = authenticated_url,
) -> dict:
    """Push the verified fix and return links for the UI."""

    client = client or make_client(provider, token)
    source = detect_source_remote(repo)
    plan = resolve_mode(mode, source, provider, client)
    mode = plan["mode"]

    author = plan["author"]
    finding = summary.get("finding") or {}
    test_id = finding.get("test_id", "issue")
    function = summary.get("function", "patch")
    branch = make_branch_name(test_id, function)
    title = f"SecurePatch: fix {test_id} in {function}()"
    message = (
        f"{title}\n\n"
        f"{finding.get('issue_text', '')}\n"
        "Verified by SecurePatch (pytest + Bandit re-scan)."
    )
    diff = unified_diff(repo, files)
    body = build_pr_body(summary)
    if diff:
        body += (
            "\n\n<details><summary>Code change (diff)</summary>\n\n"
            f"```diff\n{diff.rstrip()}\n```\n</details>"
        )
    if include_report:
        files = {
            **files,
            REPORT_FILE: build_report(summary, diff).encode("utf-8"),
        }
        body += f"\n\nFull report: `{REPORT_FILE}` in this branch."
    noun = "pull request" if provider == "github" else "merge request"

    work_root.mkdir(parents=True, exist_ok=True)
    workdir = work_root / f"publish_{uuid.uuid4().hex[:8]}"
    result = {
        "mode": mode,
        "reason": plan["reason"],
        "provider": provider,
        "user": plan["user"],
        "profile": plan["profile"],
        "diff": diff,
        "branch": branch,
        "request_url": None,
        "request_type": noun,
    }

    try:
        if mode in {"branch", "fork"}:
            base = plan["default_branch"]
            target = source if mode == "branch" else client.fork(source)
            prepare_fix_on_clone(
                repo,
                workdir,
                branch,
                files,
                message,
                author,
                clone_url=url_for(target, token),
                token=token,
            )
            push_branches(workdir, url_for(target, token), [branch], token)
            if open_request:
                pr_target = (
                    source
                    if mode == "branch" or request_to_upstream
                    else target
                )
                result["request_url"] = client.open_pull_request(
                    pr_target, target, branch, base, title, body
                )
        else:
            name = _clean_repo_name(
                new_repo_name
                or f"{(source.name if source else repo.name)}-securepatch"
            )
            target = client.create_repo(name, private)
            base = "main"
            prepare_fresh_repo(
                repo,
                workdir,
                base,
                branch if open_request else None,
                files,
                message,
                author,
            )
            push_branches(
                workdir,
                url_for(target, token),
                [base, branch] if open_request else [base],
                token,
            )
            if open_request:
                result["request_url"] = client.open_pull_request(
                    target, target, branch, base, title, body
                )
            else:
                result["branch"] = base
    finally:
        remove_tree(workdir)

    sep = "/-/tree/" if provider == "gitlab" else "/tree/"
    result.update(
        {
            "repository": target.to_dict(),
            "branch_url": f"{target.web_url}{sep}{result['branch']}",
            "clone_command": (
                f"git clone --branch {result['branch']} {target.clone_url}"
            ),
        }
    )
    return result


def _clean_repo_name(name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "-", name).strip("-.")[:90]
    if not cleaned:
        raise PublishError("Invalid repository name.")
    return cleaned


def collect_changed_files(
    original: Path,
    sandbox: Path,
    relative_paths: list[str],
) -> dict[str, bytes]:
    """Read the patched files from the sandbox, keeping only real changes."""

    changed = {}
    for relative in relative_paths:
        patched = sandbox / relative
        if not patched.is_file():
            continue
        content = patched.read_bytes()
        before = original / relative
        if not before.is_file() or before.read_bytes() != content:
            changed[relative.replace("\\", "/")] = content
    return changed
