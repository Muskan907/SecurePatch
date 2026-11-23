# Isolated test runner used by SANDBOX_MODE=docker/auto.
# Build:  docker build -t securepatch-sandbox:latest sandbox
#
# SecurePatch runs it with --network none, memory/CPU/PID limits, a
# read-only root filesystem and all capabilities dropped, so code from an
# untrusted repository cannot reach the network or the host.
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# The network is disabled at run time, so common test dependencies of
# Python web projects are pre-installed here.
COPY requirements.txt /tmp/requirements.txt
RUN pip install -r /tmp/requirements.txt && rm /tmp/requirements.txt

RUN useradd --create-home --uid 10001 runner
USER runner
WORKDIR /workspace

CMD ["python", "-m", "pytest", "tests", "-q", "-p", "no:cacheprovider"]
