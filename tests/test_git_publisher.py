"""Tests for publishing verified fixes (no network: fake API + local bare repos)."""

import subprocess
from pathlib import Path

import pytest

from src.git_publisher import (
    PublishError,
    RemoteRepo,
    build_pr_body,
    collect_changed_files,
    make_branch_name,
    parse_remote_url,
    publish,
    resolve_mode,
    scrub,
)

GIT_ID = ["-c", "user.name=Test", "-c", "user.email=test@example.com"]


def git(cwd: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *GIT_ID, *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


# ---------------------------------------------------------
# URL parsing / helpers
# ---------------------------------------------------------


@pytest.mark.parametrize(
    "url, provider, path",
    [
        ("https://github.com/alice/demo", "github", "alice/demo"),
        ("https://github.com/alice/demo.git", "github", "alice/demo"),
        ("https://www.github.com/alice/demo/tree/main/src", "github", "alice/demo"),
        ("git@github.com:alice/demo.git", "github", "alice/demo"),
        ("https://gitlab.com/group/sub/demo", "gitlab", "group/sub/demo"),
        ("https://gitlab.com/group/demo/-/tree/main", "gitlab", "group/demo"),
        ("https://user:secret@github.com/alice/demo.git", "github", "alice/demo"),
    ],
)
def test_parse_remote_url(url, provider, path):
    remote = parse_remote_url(url)
    assert remote.provider == provider
    assert remote.path == path


@pytest.mark.parametrize(
    "url",
    [
        "",
        "https://bitbucket.org/alice/demo",
        "https://github.com/alice",
        "ftp://github.com/alice/demo",
        "https://github.com/alice/de mo",
    ],
)
def test_parse_remote_url_rejects_bad_urls(url):
    with pytest.raises(PublishError):
        parse_remote_url(url)


def test_scrub_hides_token_everywhere():
    token = "ghp_secret/123"
    text = (
        "fatal: https://x-access-token:ghp_secret%2F123@github.com/a/b.git "
        "token ghp_secret/123"
    )
    cleaned = scrub(text, token)
    assert "secret" not in cleaned


def test_branch_name_is_safe():
    name = make_branch_name("B602", "Run Command!")
    assert name.startswith("securepatch/fix-b602-run-command-")
    assert " " not in name and "!" not in name


def test_pr_body_contains_verification():
    body = build_pr_body(
        {
            "finding": {
                "test_id": "B602",
                "issue_severity": "HIGH",
                "issue_confidence": "HIGH",
                "issue_cwe": {"id": 78},
            },
            "target_file": "app.py",
            "function": "run",
            "regression": {"passed_count": 5, "failed_count": 0},
            "security": {"target_removed": True, "findings_after": 2},
        }
    )
    assert "B602" in body and "CWE-78" in body
    assert "5 passed" in body and "removed" in body


def test_collect_changed_files(tmp_path):
    original, sandbox = tmp_path / "orig", tmp_path / "sandbox"
    for root in (original, sandbox):
        (root / "pkg").mkdir(parents=True)
        (root / "pkg" / "same.py").write_bytes(b"x = 1\n")
    (sandbox / "pkg" / "fixed.py").write_bytes(b"safe = True\n")
    (original / "pkg" / "fixed.py").write_bytes(b"safe = False\n")

    changed = collect_changed_files(
        original, sandbox, ["pkg/same.py", "pkg/fixed.py", "missing.py"]
    )
    assert changed == {"pkg/fixed.py": b"safe = True\n"}


# ---------------------------------------------------------
# Mode resolution
# ---------------------------------------------------------


class FakeClient:
    def __init__(self, can_push=False, user="bob"):
        self.can_push = can_push
        self.user = user
        self.pull_requests = []
        self.created = []
        self.forked = []

    def current_user(self):
        return {"username": self.user, "name": self.user, "email": "bob@x"}

    def get_repo(self, remote):
        return {
            "id": 1,
            "path": remote.path,
            "default_branch": "main",
            "can_push": self.can_push,
        }

    def fork(self, remote):
        self.forked.append(remote.path)
        return RemoteRepo(remote.provider, remote.host, f"{self.user}/{remote.name}")

    def create_repo(self, name, private):
        self.created.append((name, private))
        return RemoteRepo("github", "github.com", f"{self.user}/{name}")

    def open_pull_request(self, target, source, branch, base, title, body):
        self.pull_requests.append(
            {"target": target.path, "source": source.path, "branch": branch, "base": base}
        )
        return f"https://github.com/{target.path}/pull/1"


SOURCE = RemoteRepo("github", "github.com", "alice/demo")


def test_auto_uses_branch_with_write_access():
    plan = resolve_mode("auto", SOURCE, "github", FakeClient(can_push=True))
    assert plan["mode"] == "branch"


def test_auto_forks_someone_elses_repo():
    plan = resolve_mode("auto", SOURCE, "github", FakeClient(can_push=False))
    assert plan["mode"] == "fork"


def test_auto_creates_new_repo_for_zip_upload():
    plan = resolve_mode("auto", None, "github", FakeClient())
    assert plan["mode"] == "new_repo"


def test_auto_creates_new_repo_for_other_provider():
    plan = resolve_mode("auto", SOURCE, "gitlab", FakeClient())
    assert plan["mode"] == "new_repo"


def test_branch_mode_refused_without_write_access():
    with pytest.raises(PublishError, match="cannot push"):
        resolve_mode("branch", SOURCE, "github", FakeClient(can_push=False))


def test_cannot_fork_own_repo():
    with pytest.raises(PublishError, match="own this repository"):
        resolve_mode("fork", SOURCE, "github", FakeClient(can_push=True, user="alice"))


def test_branch_mode_refused_for_zip_upload():
    with pytest.raises(PublishError):
        resolve_mode("branch", None, "github", FakeClient(can_push=True))


# ---------------------------------------------------------
# End-to-end publishing against local bare repositories
# ---------------------------------------------------------


@pytest.fixture
def source_repo(tmp_path):
    repo = tmp_path / "clone"
    repo.mkdir()
    git(repo, "init", "-q", "-b", "main")
    (repo / "app.py").write_text("import os\nos.system(cmd)\n")
    (repo / "README.md").write_text("demo\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "initial")
    git(repo, "remote", "add", "origin", "https://github.com/alice/demo.git")
    return repo


SUMMARY = {
    "finding": {"test_id": "B605", "issue_text": "os.system call"},
    "function": "run",
    "target_file": "app.py",
}
FIXED = {"app.py": b"import subprocess\nsubprocess.run(['ls'])\n"}


def bare_copy(repo: Path, destination: Path) -> Path:
    subprocess.run(
        ["git", "clone", "-q", "--bare", str(repo), str(destination)],
        check=True,
    )
    return destination


def test_publish_fork_pushes_branch_and_opens_pr_in_fork(source_repo, tmp_path):
    remote = bare_copy(source_repo, tmp_path / "fork.git")
    client = FakeClient(can_push=False)

    result = publish(
        repo=source_repo,
        work_root=tmp_path / "work",
        files=FIXED,
        summary=SUMMARY,
        provider="github",
        token="tok",
        client=client,
        url_for=lambda target, token: str(remote),
    )

    assert result["mode"] == "fork"
    assert client.forked == ["alice/demo"]
    # PR stays inside the user's fork unless upstream is requested.
    assert client.pull_requests[0]["target"] == "bob/demo"
    branch = result["branch"]
    assert git(remote, "show", f"{branch}:app.py") == FIXED["app.py"].decode().strip()
    # main of the remote is untouched.
    assert "os.system" in git(remote, "show", "main:app.py")
    # Original local clone is never modified.
    assert "os.system" in (source_repo / "app.py").read_text()
    assert not list((tmp_path / "work").iterdir())


def test_publish_fork_can_target_upstream(source_repo, tmp_path):
    remote = bare_copy(source_repo, tmp_path / "fork.git")
    client = FakeClient(can_push=False)
    publish(
        repo=source_repo,
        work_root=tmp_path / "work",
        files=FIXED,
        summary=SUMMARY,
        provider="github",
        token="tok",
        request_to_upstream=True,
        client=client,
        url_for=lambda target, token: str(remote),
    )
    assert client.pull_requests[0] == {
        "target": "alice/demo",
        "source": "bob/demo",
        "branch": client.pull_requests[0]["branch"],
        "base": "main",
    }


def test_publish_new_repo_for_zip_upload(tmp_path):
    upload = tmp_path / "upload"
    upload.mkdir()
    (upload / "app.py").write_text("import os\nos.system(cmd)\n")
    (upload / "__pycache__").mkdir()
    (upload / "__pycache__" / "junk.pyc").write_bytes(b"x")
    remote = tmp_path / "new.git"
    subprocess.run(["git", "init", "-q", "--bare", str(remote)], check=True)
    client = FakeClient()

    result = publish(
        repo=upload,
        work_root=tmp_path / "work",
        files=FIXED,
        summary=SUMMARY,
        provider="github",
        token="tok",
        new_repo_name="my fixed repo",
        client=client,
        url_for=lambda target, token: str(remote),
    )

    assert result["mode"] == "new_repo"
    assert client.created == [("my-fixed-repo", True)]
    assert "os.system" in git(remote, "show", "main:app.py")
    assert "subprocess.run" in git(remote, "show", f"{result['branch']}:app.py")
    files = git(remote, "ls-tree", "-r", "--name-only", "main")
    assert "__pycache__" not in files
    assert result["request_url"].endswith("/pull/1")


def test_publish_adds_report_and_diff(source_repo, tmp_path):
    remote = bare_copy(source_repo, tmp_path / "fork.git")
    result = publish(
        repo=source_repo,
        work_root=tmp_path / "work",
        files=FIXED,
        summary=SUMMARY,
        provider="github",
        token="tok",
        client=FakeClient(can_push=True),
        url_for=lambda target, token: str(remote),
    )
    assert "-os.system(cmd)" in result["diff"]
    assert "+subprocess.run(['ls'])" in result["diff"]
    report = git(remote, "show", f"{result['branch']}:SECURITY_REMEDIATION_REPORT.md")
    assert "Security Remediation Report" in report
    assert "```diff" in report


def test_publish_zip_snapshot_clones_remote(source_repo, tmp_path):
    """A ZIP-fallback import has no .git: publish clones the remote instead."""
    remote = bare_copy(source_repo, tmp_path / "origin.git")
    snapshot = tmp_path / "snapshots" / "alice_demo_1"
    snapshot.parent.mkdir()
    (snapshot).mkdir()
    (snapshot / "app.py").write_text("import os\nos.system(cmd)\n")
    (snapshot.parent / "alice_demo_1.source").write_text(
        "https://github.com/alice/demo"
    )
    client = FakeClient(can_push=True)
    result = publish(
        repo=snapshot,
        work_root=tmp_path / "work",
        files=FIXED,
        summary=SUMMARY,
        provider="github",
        token="tok",
        client=client,
        url_for=lambda target, token: remote.as_uri(),
    )
    assert result["mode"] == "branch"
    assert "subprocess.run" in git(remote, "show", f"{result['branch']}:app.py")
