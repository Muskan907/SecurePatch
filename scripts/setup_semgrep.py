"""Install Semgrep for SecurePatch in an isolated environment.

Semgrep pins library versions (opentelemetry) that conflict with ChromaDB,
so it must NOT be installed into the project's main venv. This script:

  1. creates .tools/semgrep (a separate virtual environment)
  2. installs Semgrep into it
  3. downloads the Python security rules into .tools/python-rules.yml
     (after this, scans work offline)

Run from the project root:   python scripts/setup_semgrep.py
"""

import subprocess
import sys
import venv
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SEMGREP_VERSION = "1.186.0"


def main() -> None:
    sys.path.insert(0, str(ROOT))
    env_dir = ROOT / ".tools" / "semgrep"
    if not env_dir.exists():
        print(f"Creating {env_dir} ...")
        venv.create(env_dir, with_pip=True)
    python = env_dir / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
    print(f"Installing semgrep=={SEMGREP_VERSION} ...")
    subprocess.run(
        [str(python), "-m", "pip", "install", "-q", f"semgrep=={SEMGREP_VERSION}"],
        check=True,
    )

    from src.semgrep_scanner import build_rules, rules_path, semgrep_bin

    print("Downloading Python security rules (p/default, p/python, p/flask) ...")
    path = build_rules(rules_path())
    print(f"Rules saved to {path}")
    print(f"Semgrep ready: {semgrep_bin()}")


if __name__ == "__main__":
    main()
