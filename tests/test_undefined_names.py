from backend.main import undefined_names

MODULE = '''import hashlib
import secrets
from os import path

SALT = "x"


def helper():
    return 1


def ok(data, n=3):
    total = len(data) + n + helper()
    def inner():
        return hashlib.sha256(SALT.encode()).hexdigest()
    return [path.basename(d) for d in data], inner(), secrets.token_hex(8), total


def missing_import():
    return token_urlsafe(16)


def missing_module():
    return shlex.quote("a")
'''


def check(tmp_path, name):
    f = tmp_path / "m.py"
    f.write_text(MODULE, encoding="utf-8")
    return undefined_names(f, name)


def test_defined_names_pass(tmp_path):
    assert check(tmp_path, "ok") == []


def test_missing_function_import_detected(tmp_path):
    assert check(tmp_path, "missing_import") == ["token_urlsafe"]


def test_missing_module_import_detected(tmp_path):
    assert check(tmp_path, "missing_module") == ["shlex"]


def test_star_import_is_not_guessed(tmp_path):
    f = tmp_path / "s.py"
    f.write_text("from os.path import *\n\ndef f():\n    return basename('a')\n", encoding="utf-8")
    assert undefined_names(f, "f") == []
