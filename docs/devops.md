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
| **Kubernetes** | Every Kustomize overlay rendered and validated against the Kubernetes schemas (`kubeconform`) |

SecurePatch scans its own code in CI. The one HIGH finding it reported, SHA1 in RAG chunk IDs (B324), was fixed with `usedforsecurity=False`.

## 3. Continuous Delivery — `.github/workflows/cd.yml`

| Trigger | Result |
|---|---|
| Pull request to `main` | Build all images + smoke test, **nothing pushed** |
| Push to `main` | Smoke test → push `ghcr.io/<owner>/securepatch-{backend,frontend,sandbox}` tagged `main`, `sha-<commit>`, `latest` |
| Tag `v1.2.3` | Same, plus tags `1.2.3` / `1.2` and a **GitHub Release** with notes and compose files |
| Push + `DEPLOY_HOST` secret set | SSH deploy: `docker compose pull && up -d` on the server |

**Smoke tests:** the backend image is started, `/api/health` must answer, and a real scan of `sample_repo` through the API must return findings. The same checks then run on a throwaway Kubernetes (kind) cluster. Images are only published if both pass.

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
| `docker-compose.yml` | Local stack: backend + frontend, using the Ollama already installed on the computer (`host.docker.internal`). `ollama` profile: run Ollama in Docker instead. `setup` profile: model pull, sandbox image |
| `docker-compose.prod.yml` | Same stack from the published GHCR images |

Run the whole stack:

```bash
docker compose up -d --build
# Uses the Ollama on this computer. Ollama inside Docker instead:
#   OLLAMA_BASE_URL=http://ollama:11434 docker compose --profile ollama up -d --build
#   docker compose --profile ollama --profile setup run --rm model-pull
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

## 8. Second SAST engine: Semgrep

Bandit matches risky **patterns**. Semgrep adds rules that follow **data flow**, e.g. request data reaching an SQL string or `render_template_string`. Both run on every scan: Bandit streams instantly and Semgrep runs in parallel.

| Tag in the UI | Meaning |
|---|---|
| `BANDIT` | Only Bandit reports it |
| `SEMGREP` | Only Semgrep reports it (Bandit missed it) |
| `BANDIT + SEMGREP` | Both agree: high confidence |

Measured on the demo repositories: on `sample_repo`, Semgrep confirms 8 Bandit findings. On *Vulnerable Flask App* it adds 5 issues Bandit misses: template injection (SSTI) and raw-HTML XSS.

Semgrep findings go through the same pipeline (AI patch, sandbox, verdict). For a Semgrep target, **Semgrep must confirm the rule is gone from the patched function**. Every validation also shows a Semgrep before/after panel for the patched file.

**Setup (once):** `python scripts/setup_semgrep.py`

Semgrep goes into its own environment, `.tools/semgrep`, because it pins `opentelemetry` versions that break ChromaDB. About 270 Python rules from the registry packs `p/default`, `p/python` and `p/flask` are cached in `.tools/python-rules.yml`, so later scans work offline. Telemetry is disabled with `--metrics=off`. The Docker image installs Semgrep the same way and bakes the rules in. Without Semgrep, SecurePatch automatically falls back to Bandit only.

## 9. Kubernetes

The same stack as Docker Compose, written as Kubernetes manifests and managed with Kustomize.

```text
k8s/
├── base/              namespace, config, volumes, ollama, backend, frontend, network policy
├── overlays/
│   ├── ghcr/          use the images published by CD (ghcr.io/...) instead of local builds
│   └── ci/            used by the CD pipeline on a throwaway kind cluster (no Ollama)
├── jobs/model-pull    one-off Job that downloads the LLM into the Ollama volume
└── extras/            optional frontend autoscaler (needs metrics-server), Prometheus + Grafana
```

| Component | Kubernetes object | Why |
|---|---|---|
| Ollama | Deployment + ClusterIP Service + 20 Gi volume | Internal only; models survive restarts |
| Backend | Deployment (1 replica, `Recreate`) + LoadBalancer :8000 + 2 volumes | Startup/readiness/liveness probes, non-root user 10001, all Linux capabilities dropped, CPU/RAM limits |
| Frontend | Deployment (2 replicas, rolling update) + LoadBalancer :8080 | Stateless, zero-downtime updates; optional autoscaling 2–5 pods |
| Settings | ConfigMap | Same values as `docker-compose.yml`; no secrets stored (Git tokens are per request) |
| Security | Namespace Pod Security `baseline`, NetworkPolicy | Only the backend may reach Ollama (enforced on clusters with Calico/Cilium) |

The backend runs one replica on purpose: validation state is kept in memory and the workspace volume is `ReadWriteOnce`. It could scale out after that state moves to a shared store, such as Redis or a database.

**Run on Docker Desktop** (Settings → Kubernetes → Enable, *kubeadm*):

```bash
docker compose build backend frontend          # build the images Kubernetes will use
kubectl apply -k k8s/base                      # deploy
kubectl apply -f k8s/jobs/model-pull.yaml      # first time: download the LLM
kubectl -n securepatch get pods                # wait until all are Running / READY
# Frontend http://localhost:8080 · API http://localhost:8000/docs
kubectl delete namespace securepatch           # remove everything (incl. volumes)
```

Stop `docker compose` first: both use ports 8000 and 8080.

**Pipelines:** CI validates every overlay against the Kubernetes API schemas (`kubeconform`). CD deploys `k8s/overlays/ci` to a real `kind` cluster, waits for the rollouts, then runs a health check and a sample scan inside the cluster before any image is published.

## 10. Live monitoring (Prometheus + Grafana)

**What the live dashboard shows.** While SecurePatch is in use, a Grafana page updates every 5 seconds. It shows:

- whether the backend and the local LLM (Ollama) are up
- how many scans ran and how many vulnerabilities they found, by severity
- how many patches each model generated, and whether each one succeeded, was blocked by the safety guardrails or failed
- what share of patches passed validation (VERIFIED)
- how often the fallback model was needed
- how long the LLM takes per patch and how many tokens it uses
- how fast each API endpoint answers

It is the same kind of operations dashboard used for production services.

**How it works:**

1. The backend exposes **`/metrics`** in the Prometheus text format, implemented in `src/metrics.py` with no extra dependency.
2. **Prometheus** reads it every 5 s and stores the history.
3. **Grafana** draws the provisioned dashboard *SecurePatch — Live* (`monitoring/grafana/dashboards/securepatch.json`).

| Metric | Meaning |
|---|---|
| `securepatch_http_requests_total`, `securepatch_http_request_duration_seconds` | Requests and latency per API route and status |
| `securepatch_scans_total`, `securepatch_findings_total{severity}` | Scans run and findings found |
| `securepatch_patch_generations_total{model,outcome}` | LLM attempts: `success`, `guardrail_blocked`, `failed` |
| `securepatch_llm_generation_seconds{model}`, `securepatch_llm_tokens_total{model,direction}` | LLM speed and token use |
| `securepatch_fallback_used_total` | Patches produced by a fallback model |
| `securepatch_validations_total{verdict}` | Validation results (`VERIFIED`, `REJECTED`, …) |
| `securepatch_ollama_up` | 1 when Ollama answers (checked at most every 15 s) |

Counters start from zero whenever the backend restarts.

**Run with Docker Compose.** Monitoring is an opt-in profile, so the normal `docker compose up` is unchanged:

```bash
docker compose --profile monitoring up -d --build
# Grafana    http://localhost:3000  (opens the dashboard; view without login, admin/admin to edit)
# Prometheus http://localhost:9090  (Status → Targets shows what is being scraped)
```

**With the backend running on this computer** (`uvicorn backend.main:app --port 8000`), start only the monitoring containers:

```bash
docker compose --profile monitoring up -d prometheus grafana
```

Prometheus scrapes both `backend:8000` (Compose) and `host.docker.internal:8000` (host). The one that is not running simply shows as *down* under Status → Targets, and the dashboard uses whichever is up.

**On Kubernetes:**

```bash
kubectl -n securepatch create configmap grafana-dashboards \
  --from-file=monitoring/grafana/dashboards/securepatch.json
kubectl apply -f k8s/extras/monitoring.yaml      # Grafana http://localhost:3000
```

**Demo:** open the dashboard, then scan a repository and generate and validate a patch in the SecurePatch UI. The panels change within a few seconds.
