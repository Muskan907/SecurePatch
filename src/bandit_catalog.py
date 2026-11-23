"""Plain-English catalog of Bandit rules shown in the SecurePatch UI.

Each entry explains what the rule detects, why it matters, and shows a
minimal vulnerable vs fixed example so non-security users can understand
a finding. Rules not listed here fall back to Bandit's own metadata.
"""

from __future__ import annotations

DOCS_INDEX = "https://bandit.readthedocs.io/en/latest/plugins/index.html"

SEVERITY_LEVELS = {
    "HIGH": "Directly exploitable or very damaging if exploited (e.g. command or code injection).",
    "MEDIUM": "Exploitable in the right conditions, or exposes sensitive data.",
    "LOW": "Weak practice or hardening issue. Rarely exploitable on its own.",
}

CONFIDENCE_LEVELS = {
    "HIGH": "Bandit is sure the pattern is present (e.g. literally shell=True).",
    "MEDIUM": "The pattern is probably a problem but depends on context.",
    "LOW": "A heuristic match; review it manually, it may be a false positive.",
}

CATEGORIES = {
    "injection": "Injection",
    "crypto": "Cryptography",
    "secrets": "Secrets",
    "deserialization": "Unsafe deserialization",
    "config": "Insecure configuration",
    "network": "Network / TLS",
    "files": "Files & permissions",
    "quality": "Error handling",
}


def _rule(name, cwe, category, why, vulnerable, fixed, fix):
    return {
        "name": name,
        "cwe": cwe,
        "category": category,
        "why": why,
        "vulnerable": vulnerable.strip("\n"),
        "fixed": fixed.strip("\n"),
        "fix": fix,
    }


RULES: dict[str, dict] = {
    "B102": _rule(
        "Use of exec()", 78, "injection",
        "exec() runs any string as Python code. If any part of that string comes "
        "from a user, they can run arbitrary code on the server.",
        "exec(request.args['code'])",
        "ALLOWED = {'add': add, 'sub': sub}\nresult = ALLOWED[request.args['op']](a, b)",
        "Never execute dynamic code; map allowed inputs to known functions instead.",
    ),
    "B103": _rule(
        "Permissive file permissions", 732, "files",
        "chmod with world-writable bits (e.g. 0o777) lets every user on the machine "
        "modify or replace the file.",
        "os.chmod('/app/config.ini', 0o777)",
        "os.chmod('/app/config.ini', 0o600)",
        "Grant only the owner the permissions it needs.",
    ),
    "B104": _rule(
        "Binding to all interfaces", 605, "network",
        "Listening on 0.0.0.0 exposes the service on every network interface, "
        "including public ones.",
        "app.run(host='0.0.0.0')",
        "app.run(host=os.getenv('HOST', '127.0.0.1'))",
        "Bind to localhost by default and make public binding explicit.",
    ),
    "B105": _rule(
        "Hardcoded password string", 259, "secrets",
        "A password written in source code ends up in git history, logs and every "
        "copy of the code. Anyone who can read the repo can log in.",
        "DB_PASSWORD = 'admin123'",
        "DB_PASSWORD = os.environ['DB_PASSWORD']",
        "Load secrets from environment variables or a secret manager.",
    ),
    "B106": _rule(
        "Hardcoded password in function argument", 259, "secrets",
        "A literal password passed to a function is a secret stored in code.",
        "connect(user='app', password='secret')",
        "connect(user='app', password=os.environ['DB_PASSWORD'])",
        "Read the secret from configuration at runtime.",
    ),
    "B107": _rule(
        "Hardcoded password as default argument", 259, "secrets",
        "A default password value is used whenever callers forget to pass one.",
        "def login(user, password='changeme'): ...",
        "def login(user, password): ...",
        "Remove secret defaults; require the value explicitly.",
    ),
    "B108": _rule(
        "Insecure temporary file/directory", 377, "files",
        "Hardcoded paths like /tmp/data are predictable. Another user can create the "
        "file first (or a symlink) and read or tamper with your data.",
        "open('/tmp/report.txt', 'w')",
        "with tempfile.NamedTemporaryFile('w', delete=False) as f: ...",
        "Use the tempfile module, which creates unique files securely.",
    ),
    "B110": _rule(
        "try / except / pass", 703, "quality",
        "Silently swallowing every exception hides errors, including security "
        "failures such as a failed permission check.",
        "try:\n    check_access(user)\nexcept Exception:\n    pass",
        "try:\n    check_access(user)\nexcept PermissionError:\n    log.warning('denied')\n    raise",
        "Catch specific exceptions and log or re-raise them.",
    ),
    "B112": _rule(
        "try / except / continue", 703, "quality",
        "Like try/except/pass inside a loop: errors are ignored without a trace.",
        "for f in files:\n    try:\n        load(f)\n    except Exception:\n        continue",
        "for f in files:\n    try:\n        load(f)\n    except ValueError as exc:\n        log.warning('skip %s: %s', f, exc)",
        "Handle specific exceptions and log them.",
    ),
    "B113": _rule(
        "HTTP request without timeout", 400, "network",
        "Without a timeout, a slow or malicious server can hang the request forever "
        "and exhaust your workers (denial of service).",
        "requests.get(url)",
        "requests.get(url, timeout=10)",
        "Always pass timeout= to requests calls.",
    ),
    "B201": _rule(
        "Flask debug mode enabled", 94, "config",
        "Flask's debugger lets anyone who can reach an error page run Python code "
        "on the server.",
        "app.run(debug=True)",
        "app.run(debug=os.getenv('FLASK_DEBUG') == '1')",
        "Never enable debug mode in production.",
    ),
    "B301": _rule(
        "Unsafe pickle deserialization", 502, "deserialization",
        "pickle.loads() can execute code embedded in the data. Unpickling untrusted "
        "input = remote code execution.",
        "obj = pickle.loads(request.data)",
        "obj = json.loads(request.data)",
        "Use a data-only format such as JSON for untrusted input.",
    ),
    "B303": _rule(
        "Weak hash (MD5 / SHA1)", 327, "crypto",
        "MD5 and SHA1 are broken: collisions are cheap and they are far too fast "
        "for password hashing.",
        "hashlib.md5(password).hexdigest()",
        "hashlib.pbkdf2_hmac('sha256', password, salt, 600_000)",
        "Use SHA-256+ for integrity and a slow KDF (PBKDF2, bcrypt, argon2) for passwords.",
    ),
    "B304": _rule(
        "Insecure cipher", 327, "crypto",
        "Ciphers such as DES, RC4 or Blowfish are broken or too weak.",
        "Cipher(algorithms.ARC4(key), mode=None)",
        "AESGCM(key).encrypt(nonce, data, None)",
        "Use AES-GCM or ChaCha20-Poly1305.",
    ),
    "B305": _rule(
        "Insecure cipher mode (ECB)", 327, "crypto",
        "ECB mode encrypts identical blocks identically, leaking patterns in the data.",
        "Cipher(algorithms.AES(key), modes.ECB())",
        "AESGCM(key).encrypt(nonce, data, None)",
        "Use an authenticated mode such as GCM.",
    ),
    "B306": _rule(
        "Insecure mktemp()", 377, "files",
        "tempfile.mktemp() returns a name without creating the file, so an attacker "
        "can create it first.",
        "path = tempfile.mktemp()",
        "fd, path = tempfile.mkstemp()",
        "Use mkstemp() or NamedTemporaryFile().",
    ),
    "B307": _rule(
        "Use of eval()", 78, "injection",
        "eval() executes any expression. User-controlled input becomes code execution.",
        "value = eval(request.args['value'])",
        "value = ast.literal_eval(request.args['value'])",
        "Use ast.literal_eval() for literals, or parse the input explicitly.",
    ),
    "B308": _rule(
        "mark_safe() may allow XSS", 79, "injection",
        "mark_safe() disables HTML escaping, so user input can inject scripts.",
        "mark_safe(f'<b>{user.name}</b>')",
        "format_html('<b>{}</b>', user.name)",
        "Let the template engine escape values (format_html in Django).",
    ),
    "B310": _rule(
        "urllib urlopen with arbitrary scheme", 22, "network",
        "urlopen() also accepts file:// and custom schemes, which can read local files.",
        "urllib.request.urlopen(user_url)",
        "if urlparse(user_url).scheme in ('http', 'https'):\n    requests.get(user_url, timeout=10)",
        "Allow only http/https URLs.",
    ),
    "B311": _rule(
        "Non-cryptographic random generator", 330, "crypto",
        "The random module is predictable. Tokens, passwords or keys made with it "
        "can be guessed.",
        "token = ''.join(random.choice(chars) for _ in range(16))",
        "token = secrets.token_urlsafe(16)",
        "Use the secrets module for anything security-related.",
    ),
    "B312": _rule(
        "Telnet usage", 319, "network",
        "Telnet sends everything, including passwords, in clear text.",
        "telnetlib.Telnet(host)",
        "paramiko.SSHClient()  # with host key verification",
        "Use SSH instead.",
    ),
    "B314": _rule(
        "Unsafe XML parsing", 20, "deserialization",
        "The standard XML parsers are vulnerable to XXE and 'billion laughs' attacks.",
        "xml.etree.ElementTree.fromstring(data)",
        "defusedxml.ElementTree.fromstring(data)",
        "Parse untrusted XML with defusedxml.",
    ),
    "B321": _rule(
        "FTP usage", 319, "network",
        "FTP transmits credentials and data unencrypted.",
        "ftplib.FTP(host).login(user, pw)",
        "ftplib.FTP_TLS(host).login(user, pw)",
        "Use FTPS or SFTP.",
    ),
    "B323": _rule(
        "Unverified SSL context", 295, "network",
        "Disabling certificate checks allows man-in-the-middle attacks.",
        "ssl._create_unverified_context()",
        "ssl.create_default_context()",
        "Always verify certificates.",
    ),
    "B324": _rule(
        "Weak hash function (hashlib)", 327, "crypto",
        "MD4/MD5/SHA1 are broken. Passwords hashed with them are cracked almost "
        "instantly.",
        "hash_pass = hashlib.md5(password.encode()).hexdigest()",
        "salt = os.urandom(16)\nhash_pass = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 600_000)",
        "Use SHA-256+ (or usedforsecurity=False for non-security checksums); "
        "use a slow KDF for passwords and store the salt.",
    ),
    "B403": _rule(
        "pickle module imported", 502, "deserialization",
        "Importing pickle is a warning sign: unpickling untrusted data runs code.",
        "import pickle",
        "import json",
        "Prefer JSON; only unpickle data you created yourself.",
    ),
    "B404": _rule(
        "subprocess module imported", 78, "injection",
        "Informational: subprocess can run OS commands. Check how it is called.",
        "import subprocess",
        "import subprocess  # used only with argument lists, never shell=True",
        "Review every call; use argument lists and no shell.",
    ),
    "B501": _rule(
        "Certificate verification disabled", 295, "network",
        "verify=False accepts any certificate, so traffic can be intercepted.",
        "requests.get(url, verify=False)",
        "requests.get(url, timeout=10)  # verify=True is the default",
        "Keep certificate verification on.",
    ),
    "B502": _rule(
        "Insecure SSL/TLS version", 327, "network",
        "SSLv2/v3 and TLS 1.0/1.1 have known attacks.",
        "ssl.wrap_socket(sock, ssl_version=ssl.PROTOCOL_SSLv3)",
        "ssl.create_default_context().wrap_socket(sock, server_hostname=host)",
        "Use the default context (TLS 1.2+).",
    ),
    "B505": _rule(
        "Weak cryptographic key", 326, "crypto",
        "RSA/DSA keys below 2048 bits can be factored.",
        "rsa.generate_private_key(65537, 1024)",
        "rsa.generate_private_key(65537, 3072)",
        "Use at least 2048-bit (preferably 3072-bit) RSA keys.",
    ),
    "B506": _rule(
        "Unsafe yaml.load()", 20, "deserialization",
        "yaml.load() with the default loader can construct arbitrary Python objects "
        "and run code.",
        "config = yaml.load(data)",
        "config = yaml.safe_load(data)",
        "Use yaml.safe_load().",
    ),
    "B507": _rule(
        "SSH host key not verified", 295, "network",
        "AutoAddPolicy trusts any server key, enabling man-in-the-middle attacks.",
        "client.set_missing_host_key_policy(paramiko.AutoAddPolicy())",
        "client.load_system_host_keys()\nclient.set_missing_host_key_policy(paramiko.RejectPolicy())",
        "Verify host keys against known_hosts.",
    ),
    "B601": _rule(
        "Shell injection via paramiko", 78, "injection",
        "exec_command() runs a shell command on the remote host; user input can inject commands.",
        "client.exec_command('ls ' + path)",
        "client.exec_command('ls ' + shlex.quote(path))",
        "Quote or validate every value placed into a remote command.",
    ),
    "B602": _rule(
        "subprocess with shell=True", 78, "injection",
        "With shell=True the command goes through /bin/sh. A value like "
        "'file.txt; rm -rf /' runs a second command (command injection).",
        "subprocess.call('ping -c 1 ' + host, shell=True)",
        "subprocess.run(['ping', '-c', '1', host], check=True)",
        "Pass a list of arguments and leave shell=False.",
    ),
    "B603": _rule(
        "subprocess call - check for untrusted input", 78, "injection",
        "No shell is used, which is good, but if the program name or arguments come "
        "from users they still control what runs.",
        "subprocess.run([user_tool, arg])",
        "TOOLS = {'ping': '/bin/ping'}\nsubprocess.run([TOOLS[name], arg], check=True)",
        "Allow-list executables; validate arguments.",
    ),
    "B604": _rule(
        "Function call with shell=True", 78, "injection",
        "A wrapper that runs commands through a shell is open to command injection.",
        "run_cmd(cmd, shell=True)",
        "run_cmd(shlex.split(cmd))",
        "Avoid shells; pass argument lists.",
    ),
    "B605": _rule(
        "Process started with a shell (os.system)", 78, "injection",
        "os.system() always uses a shell, so user input in the string is command injection.",
        "os.system('convert ' + filename)",
        "subprocess.run(['convert', filename], check=True)",
        "Replace os.system/os.popen with subprocess and an argument list.",
    ),
    "B606": _rule(
        "Process started without a shell", 78, "injection",
        "os.exec*/spawn* without a shell; still check that the program and "
        "arguments are trusted.",
        "os.execv(user_path, args)",
        "os.execv('/usr/bin/tool', ['tool', validated_arg])",
        "Use fixed executable paths and validated arguments.",
    ),
    "B607": _rule(
        "Process started with a partial path", 78, "injection",
        "'git' instead of '/usr/bin/git' is resolved through PATH, which an attacker "
        "may be able to modify.",
        "subprocess.run(['git', 'pull'])",
        "subprocess.run([shutil.which('git') or '/usr/bin/git', 'pull'], check=True)",
        "Use absolute paths for executables in sensitive code.",
    ),
    "B608": _rule(
        "SQL injection (string-built query)", 89, "injection",
        "Building SQL with + or f-strings lets input such as ' OR '1'='1 change the "
        "query, read other users' data or drop tables.",
        "cur.execute(f\"SELECT * FROM users WHERE name = '{name}'\")",
        "cur.execute('SELECT * FROM users WHERE name = ?', (name,))",
        "Use parameterized queries (placeholders) - never format SQL strings.",
    ),
    "B609": _rule(
        "Wildcard injection", 78, "injection",
        "Shell wildcards like * in commands can be abused with crafted file names "
        "(e.g. a file named '--checkpoint-action=exec=sh').",
        "os.system('tar cf backup.tar *')",
        "subprocess.run(['tar', 'cf', 'backup.tar', '--', *files], check=True)",
        "Pass explicit file lists and use -- to end options.",
    ),
    "B610": _rule(
        "Django extra() SQL injection", 89, "injection",
        "QuerySet.extra() inserts raw SQL fragments.",
        "User.objects.extra(where=[f\"name = '{name}'\"])",
        "User.objects.filter(name=name)",
        "Use the ORM's filters or params=.",
    ),
    "B611": _rule(
        "Django RawSQL injection", 89, "injection",
        "RawSQL with formatted strings is SQL injection.",
        "RawSQL(f\"SELECT id FROM t WHERE x = '{x}'\", [])",
        "RawSQL('SELECT id FROM t WHERE x = %s', [x])",
        "Pass values as parameters.",
    ),
    "B701": _rule(
        "Jinja2 autoescape disabled", 94, "injection",
        "With autoescape off, user data rendered into HTML can inject scripts (XSS).",
        "Environment(loader=loader)",
        "Environment(loader=loader, autoescape=select_autoescape())",
        "Enable autoescaping.",
    ),
    "B702": _rule(
        "Mako templates (no autoescape)", 80, "injection",
        "Mako does not escape HTML by default, allowing XSS.",
        "Template(text)",
        "Template(text, default_filters=['h'])",
        "Enable HTML escaping filters.",
    ),
    "B703": _rule(
        "Django mark_safe XSS", 80, "injection",
        "Marking user-controlled HTML as safe bypasses escaping.",
        "mark_safe(user_html)",
        "format_html('{}', user_html)",
        "Escape user values; avoid mark_safe on user data.",
    ),
}

# Aliases: rules that share an explanation.
for _alias, _target in {
    "B315": "B314", "B316": "B314", "B317": "B314", "B318": "B314",
    "B319": "B314", "B320": "B314", "B405": "B314", "B406": "B314",
    "B407": "B314", "B408": "B314", "B409": "B314", "B410": "B314",
    "B401": "B312", "B402": "B321", "B503": "B502", "B504": "B502",
}.items():
    RULES[_alias] = {**RULES[_target]}


def docs_url(test_id: str) -> str:
    try:
        from bandit.core import docs_utils

        return docs_utils.get_url(test_id)
    except Exception:
        return DOCS_INDEX


def explain(test_id: str, finding: dict | None = None) -> dict:
    """Catalog entry for a rule, falling back to the finding's own metadata."""

    finding = finding or {}
    entry = RULES.get(test_id)
    cwe = (finding.get("issue_cwe") or {}).get("id")
    if entry is None:
        entry = {
            "name": (finding.get("test_name") or test_id).replace("_", " "),
            "cwe": cwe,
            "category": "other",
            "why": finding.get("issue_text") or "See the Bandit documentation.",
            "vulnerable": finding.get("code", "").strip(),
            "fixed": "",
            "fix": "See the Bandit documentation for remediation guidance.",
        }
    return {
        "test_id": test_id,
        **entry,
        "cwe": entry.get("cwe") or cwe,
        "cwe_url": (
            f"https://cwe.mitre.org/data/definitions/{entry.get('cwe') or cwe}.html"
            if (entry.get("cwe") or cwe)
            else None
        ),
        "category_label": CATEGORIES.get(entry.get("category"), "Other"),
        "docs_url": finding.get("more_info") or docs_url(test_id),
        "known": test_id in RULES,
    }


def catalog() -> dict:
    return {
        "rules": {test_id: explain(test_id) for test_id in sorted(RULES)},
        "severity_levels": SEVERITY_LEVELS,
        "confidence_levels": CONFIDENCE_LEVELS,
        "categories": CATEGORIES,
    }


# ---------------------------------------------------------
# Before / after comparison
# ---------------------------------------------------------


def _relative(filename: str, root) -> str:
    from pathlib import Path

    try:
        return Path(filename).resolve().relative_to(Path(root).resolve()).as_posix()
    except ValueError:
        return str(filename).replace("\\", "/")


def compare_findings(before: list[dict], after: list[dict], before_root, after_root) -> dict:
    """Which findings the patch removed or introduced.

    Line numbers shift when code changes, so findings are matched by
    (file, rule, flagged code) and then by (file, rule) counts.
    """

    def summarize(f, root):
        return {
            "test_id": f.get("test_id"),
            "file": _relative(f.get("filename", ""), root),
            "line": f.get("line_number"),
            "severity": f.get("issue_severity"),
            "confidence": f.get("issue_confidence"),
            "text": f.get("issue_text"),
        }

    remaining_after = [summarize(f, after_root) for f in after]
    removed, unchanged = [], []
    pool = list(remaining_after)
    for f in before:
        item = summarize(f, before_root)
        match = next(
            (
                a for a in pool
                if a["file"] == item["file"] and a["test_id"] == item["test_id"]
            ),
            None,
        )
        if match is None:
            removed.append(item)
        else:
            pool.remove(match)
            unchanged.append(item)
    introduced = pool

    def count(items):
        result = {"total": len(items), "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for i in items:
            if i["severity"] in result:
                result[i["severity"]] += 1
        return result

    return {
        "before": count([summarize(f, before_root) for f in before]),
        "after": count(remaining_after),
        "removed": removed,
        "introduced": introduced,
        "unchanged_count": len(unchanged),
    }
