"""Imports a model writes above the repaired function must not be lost."""
import ast

from backend.main import carry_over_imports, normalize_function_output, undefined_names

MODULE = "import hashlib\nimport yaml\n\n\ndef other():\n    return 1\n"

# Real Qwen2.5-Coder outputs from the benchmark run.
SECRETS_OUT = '''import secrets

def vulnerable_password():
    # INTENTIONAL B105
    password = secrets.token_urlsafe(16)

    return password'''

AST_OUT = '''import ast

def vulnerable_eval(expression):
    # INTENTIONAL B307
    try:
        return ast.literal_eval(expression)
    except (ValueError, SyntaxError):
        raise ValueError("Invalid expression")'''

YAML_OUT = '''import yaml

def vulnerable_yaml(data):
    """Load YAML."""
    return yaml.safe_load(data)'''


def repair(text, name):
    return carry_over_imports(text, normalize_function_output(text, name), MODULE)


def test_missing_import_moved_inside_function(tmp_path):
    fixed = repair(SECRETS_OUT, "vulnerable_password")
    stripped = [line.strip() for line in fixed.splitlines()]
    assert stripped.index("import secrets") < stripped.index("password = secrets.token_urlsafe(16)")
    ast.parse(fixed)
    f = tmp_path / "m.py"
    f.write_text(MODULE + "\n\n" + fixed + "\n", encoding="utf-8")
    assert undefined_names(f, "vulnerable_password") == []


def test_import_shadowing_builtin_module_name(tmp_path):
    fixed = repair(AST_OUT, "vulnerable_eval")
    assert "import ast" in fixed
    ast.parse(fixed)


def test_already_imported_module_not_repeated_and_docstring_kept_first():
    fixed = repair(YAML_OUT, "vulnerable_yaml")
    assert "import yaml" not in fixed
    assert fixed.splitlines()[1].strip() == '"""Load YAML."""'


def test_unused_imports_are_ignored():
    text = "import os\nimport secrets\n\ndef f():\n    return secrets.token_hex(4)\n"
    fixed = carry_over_imports(text, normalize_function_output(text, "f"), "")
    assert "import secrets" in fixed and "import os" not in fixed


def test_import_inserted_after_docstring():
    text = 'import secrets\n\ndef f():\n    """Doc."""\n    return secrets.token_hex(4)\n'
    lines = carry_over_imports(text, normalize_function_output(text, "f"), "").splitlines()
    assert lines[1].strip() == '"""Doc."""' and lines[2].strip() == "import secrets"
