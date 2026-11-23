# SecurePatch DevOps Guide

How SecurePatch is built, tested, secured, packaged and delivered.

## 1. End-to-end flow

```text
Import (GitHub/GitLab URL · ZIP · local folder)
   │   git clone --depth 1  ──fails──►  ZIP archive download (codeload / GitLab archive)
   ▼
Live SAST scan (Bandit, streamed per file over Server-Sent Events)
   ▼
AST analysis + source graph + RAG context (LangChain splitter, ChromaDB)
   ▼
LLM repair (Ollama) ──error / wrong output / guardrail block──► next model in fallback chain
   ▼
Guardrails (AST: one function, same name, no eval/exec/os.system/shell=True)
   ▼
Sandbox validation
   ├─ pytest in Docker (no network, 1 GB RAM, 1 CPU, 256 PIDs, read-only FS)
   └─ Bandit re-scan → before/after comparison
   ▼
VERIFIED ──► Download ZIP  or  Publish: branch / fork / new repo + PR/MR + remediation report
```

## 2. Continuous Integration — `.github/workflows/ci.yml`

Runs on every push and pull request.

| Job | What it enforces |
|---|---|
| **Backend** | `ruff` lint (syntax errors, undefined names, unused code) · `pytest` with coverage (fails under 30 %) · JUnit + coverage XML artifacts |
| **Security** | Bandit SARIF uploaded to GitHub code scanning · **build fails on any HIGH-severity finding** in `backend/` or `src/` · `pip-audit` dependency CVE report · demo scan of `sample_repo` |
| **Frontend** | `npm ci` · ESLint · production build · `dist` artifact |
| **Compose** | `docker compose config` for dev and prod stacks |

SecurePatch scans its own code in CI. The one HIGH finding it reported, SHA1 in RAG chunk IDs (B324), was fixed with `usedforsecurity=False`.

## 3. Continuous Delivery — `.github/workflows/cd.yml`

| Trigger | Result |
|---|---|
| Pull request to `main` | Build all images + smoke test, **nothing pushed** |
| Push to `main` | Smoke test → push `ghcr.io/<owner>/securepatch-{backend,frontend,sandbox}` tagged `main`, `sha-<commit>`, `latest` |
| Tag `v1.2.3` | Same, plus tags `1.2.3` / `1.2` and a **GitHub Release** with notes and compose files |
| Push + `DEPLOY_HOST` secret set | SSH deploy: `docker compose pull && up -d` on the server |

**Smoke test:** the backend image is started, `/api/health` must answer, and a real scan of `sample_repo` through the API must return findings before any image is published.

**Optional deployment secrets** (repository → Settings → Secrets → Actions): `DEPLOY_HOST`, `DEPLOY_USER`, `DEPLOY_SSH_KEY`. Without them the deploy job is skipped.

Release a version:

```bash
git tag v1.0.0 && git push origin v1.0.0
```

## 4. Containers

| File | Purpose |
|---|---|
| `backend/Dockerfile` | Python 3.11 slim, CPU-only PyTorch, non-root user, health check |
| `frontend/Dockerfile` | Vite build → nginx with SPA routing and security headers; `VITE_API_URL` build arg |
| `sandbox/Dockerfile` | Minimal, non-root pytest runner with common web test dependencies |
| `docker-compose.yml` | Local stack: Ollama + backend + frontend (+ `setup` profile: model pull, sandbox image) |
| `docker-compose.prod.yml` | Same stack from the published GHCR images |

Run the whole stack:

```bash
docker compose up -d --build
docker compose --profile setup run --rm model-pull     # first time: download qwen2.5-coder:7b
# Frontend http://localhost:8080 · API docs http://localhost:8000/docs
```

## 5. Sandbox isolation

Running a repository's tests executes untrusted code. `SANDBOX_MODE` selects how:

| Mode | Behaviour |
|---|---|
| `auto` (default) | Docker if the daemon and `securepatch-sandbox` image exist, else a local subprocess |
| `docker` | Always Docker |
| `local` | Always a subprocess (used inside the backend container, which is itself the boundary) |

Docker runs use `--network none --memory 1g --cpus 1 --pids-limit 256 --read-only --cap-drop ALL --security-opt no-new-privileges`. Build the image once with `docker compose --profile setup build sandbox-image`. `/api/health` and every validation result report which isolation was used.

## 6. Publishing verified fixes

| Source | `auto` mode does |
|---|---|
| Repo you can push to | Branch `securepatch/fix-<rule>-<function>-<time>` + PR/MR |
| Someone else's repo | Fork into your account, branch + PR **inside the fork**. A PR to the original project is opt-in |
| ZIP / folder upload | New repository: original code on `main`, fix on a branch + PR |

Every publish commits `SECURITY_REMEDIATION_REPORT.md`, which contains the finding, CWE, test results, Bandit before/after counts and the diff. The PR description contains the same summary. Tokens are only used for the request: they are never written to disk or `.git/config`, Git credential helpers are disabled, and tokens are scrubbed from errors.

## 7. Developer workflow

```bash
pip install pre-commit && pre-commit install   # ruff, bandit, secret & YAML checks on commit
pytest -q tests --cov=src --cov=backend         # local test run
```

Dependabot opens weekly update PRs for pip, npm, GitHub Actions and Docker base images.
