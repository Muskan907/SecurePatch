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
COPY requirements.txt .
RUN pip install --index-url https://download.pytorch.org/whl/cpu torch \
    && pip install -r requirements.txt

COPY backend/ backend/
COPY src/ src/
COPY sample_repo/ sample_repo/

RUN useradd --create-home --uid 10001 app \
    && mkdir -p workspace \
    && chown -R app:app /app
USER app

# Runs tests in-process: the container itself is the isolation boundary.
ENV SANDBOX_MODE=local \
    OLLAMA_BASE_URL=http://ollama:11434

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD curl -fs http://localhost:8000/api/health || exit 1

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
