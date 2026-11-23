"""Tests for repository import (git clone with ZIP fallback) and model fallback."""

import io
import subprocess
import zipfile

import pytest

import src.repo_importer as importer
from src.git_publisher import RemoteRepo, detect_source_remote
from src.llm_adapter import fallback_chain


def make_zip(entries: dict[str, str]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, content in entries.items():
            archive.writestr(name, content)
    return buffer.getvalue()


def test_extract_archive_flattens_top_folder(tmp_path):
    content = make_zip({"demo-main/app.py": "x = 1\n", "demo-main/pkg/a.py": ""})
    destination = tmp_path / "repo"
    importer.extract_archive(content, destination)
    assert (destination / "app.py").read_text() == "x = 1\n"
    assert (destination / "pkg" / "a.py").exists()
    assert not (tmp_path / "repo.extract").exists()


def test_extract_archive_blocks_path_traversal(tmp_path):
    content = make_zip({"../evil.py": "boom"})
    with pytest.raises(importer.ImportFailed):
        importer.extract_archive(content, tmp_path / "repo")
    assert not (tmp_path / "evil.py").exists()


def test_archive_urls():
    gh = RemoteRepo("github", "github.com", "alice/demo")
    assert importer.archive_urls(gh) == [
        "https://codeload.github.com/alice/demo/zip/HEAD"
    ]
    gl = RemoteRepo("gitlab", "gitlab.com", "group/demo")
    assert importer.archive_urls(gl)[0].startswith(
        "https://gitlab.com/group/demo/-/archive/HEAD/"
    )


def test_import_falls_back_to_zip(tmp_path, monkeypatch):
    remote = RemoteRepo("github", "github.com", "alice/demo")

    def failing_clone(remote, destination):
        destination.mkdir()  # partial clone left behind
        raise importer.ImportFailed("network unreachable")

    def fake_download(remote, destination, session=None):
        importer.extract_archive(
            make_zip({"demo-HEAD/app.py": "print(1)\n"}), destination
        )
        return "https://codeload.github.com/alice/demo/zip/HEAD"

    monkeypatch.setattr(importer, "git_clone", failing_clone)
    monkeypatch.setattr(importer, "download_archive", fake_download)

    destination = tmp_path / "alice_demo_1234"
    result = importer.import_remote(remote, destination)

    assert result["method"] == "zip"
    assert "network unreachable" in result["log"][0]
    assert (destination / "app.py").exists()
    # The origin is remembered so publishing can find it.
    assert detect_source_remote(destination) == remote


def test_import_reports_both_failures(tmp_path, monkeypatch):
    remote = RemoteRepo("github", "github.com", "alice/demo")

    def failing_clone(remote, destination):
        raise importer.ImportFailed("clone failed")

    def failing_download(remote, destination, session=None):
        raise importer.ImportFailed("404")

    monkeypatch.setattr(importer, "git_clone", failing_clone)
    monkeypatch.setattr(importer, "download_archive", failing_download)
    with pytest.raises(importer.ImportFailed, match="clone failed.*404"):
        importer.import_remote(remote, tmp_path / "x")


def test_git_clone_of_local_repo(tmp_path, monkeypatch):
    source = tmp_path / "src"
    source.mkdir()
    subprocess.run(["git", "init", "-q", str(source)], check=True)
    (source / "a.py").write_text("x = 1\n")
    subprocess.run(["git", "-C", str(source), "add", "-A"], check=True)
    subprocess.run(
        ["git", "-C", str(source), "-c", "user.name=t", "-c", "user.email=t@t",
         "commit", "-q", "-m", "init"],
        check=True,
    )
    remote = RemoteRepo("github", "github.com", "alice/demo")
    monkeypatch.setattr(
        RemoteRepo, "clone_url", property(lambda self: source.as_uri())
    )
    importer.git_clone(remote, tmp_path / "dest")
    assert (tmp_path / "dest" / "a.py").exists()


# ---------------------------------------------------------
# LLM fallback chain
# ---------------------------------------------------------


def test_fallback_chain_starts_with_requested_model():
    chain = fallback_chain("llama3.1")
    assert chain[0] == "llama3.1"
    assert chain.count("llama3.1") == 1
    assert "qwen2.5-1.5b" in chain


def test_fallback_chain_only_uses_installed_models():
    chain = fallback_chain("qwen2.5-coder", ["qwen2.5-coder:7b", "phi3:mini"])
    assert chain == ["qwen2.5-coder", "phi3-mini"]
