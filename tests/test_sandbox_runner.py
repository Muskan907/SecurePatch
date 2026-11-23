import sys
from pathlib import Path

import src.sandbox_runner as runner


def test_docker_command_is_locked_down(tmp_path):
    command = runner.docker_command(tmp_path)
    joined = " ".join(command)
    assert command[:3] == ["docker", "run", "--rm"]
    assert "--network none" in joined
    assert "--read-only" in command
    assert "--cap-drop ALL" in joined
    assert "no-new-privileges" in joined
    assert "--pids-limit" in command
    assert f"{tmp_path.resolve()}:/workspace" in command
    assert command[-7:] == [
        "python", "-m", "pytest", "tests", "-q", "-p", "no:cacheprovider",
    ]


def test_local_mode_uses_current_python(monkeypatch):
    monkeypatch.setenv("SANDBOX_MODE", "local")
    command, isolation = runner.pytest_command(Path("."))
    assert isolation == "process"
    assert command[0] == sys.executable


def test_auto_mode_falls_back_without_docker(monkeypatch):
    monkeypatch.setenv("SANDBOX_MODE", "auto")
    monkeypatch.setattr(runner, "docker_ready", lambda: False)
    _, isolation = runner.pytest_command(Path("."))
    assert isolation == "process"


def test_auto_mode_prefers_docker(monkeypatch):
    monkeypatch.setenv("SANDBOX_MODE", "auto")
    monkeypatch.setattr(runner, "docker_ready", lambda: True)
    command, isolation = runner.pytest_command(Path("."))
    assert isolation == "docker"
    assert command[0] == "docker"


def test_invalid_mode_defaults_to_auto(monkeypatch):
    monkeypatch.setenv("SANDBOX_MODE", "banana")
    assert runner.sandbox_mode() == "auto"
