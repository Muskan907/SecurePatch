# SecurePatch backend (FastAPI + Bandit + RAG).
# Build from the repository root:  docker build -f backend/Dockerfile .
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    HF_HOME=/home/app/.cache/huggingface

# git: repository import/publish. curl: container health check.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# CPU-only PyTorch keeps the image small (sentence-transformers needs torch).
# The pip cache mount keeps finished downloads between builds (it is not part
# of the image), and the longer timeout/retries survive slow connections.
COPY requirements.txt .
RUN --mount=type=cache,target=/root/.cache/pip \
    PIP_NO_CACHE_DIR=0 pip install --timeout 120 --retries 10 \
        --index-url https://download.pytorch.org/whl/cpu torch \
    && PIP_NO_CACHE_DIR=0 pip install --timeout 120 --retries 10 -r requirements.txt

# Semgrep in its own venv: it pins libraries that conflict with ChromaDB.
RUN --mount=type=cache,target=/root/.cache/pip \
    python -m venv /opt/semgrep \
    && PIP_NO_CACHE_DIR=0 /opt/semgrep/bin/pip install --timeout 120 --retries 10 semgrep==1.186.0

COPY backend/ backend/
COPY src/ src/
COPY sample_repo/ sample_repo/

# Bake the Python security rules into the image (offline scans).
ENV SEMGREP_BIN=/opt/semgrep/bin/semgrep \
    SEMGREP_RULES=/opt/semgrep/python-rules.yml
RUN python -c "from pathlib import Path; from src.semgrep_scanner import build_rules; build_rules(Path('/opt/semgrep/python-rules.yml'))"

RUN useradd --create-home --uid 10001 app \
    && mkdir -p workspace /home/app/.cache/huggingface \
    && chown -R app:app /app /home/app/.cache
USER app

# Runs tests in-process: the container itself is the isolation boundary.
ENV SANDBOX_MODE=local \
    OLLAMA_BASE_URL=http://ollama:11434

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD curl -fs http://localhost:8000/api/health || exit 1

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
