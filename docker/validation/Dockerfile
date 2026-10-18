# AutoPatch Validation Sandbox Dockerfile
# Pinned, reproducible base image for safe candidate patch validation.
#
# Provides isolated environment with Python, pytest, Bandit, and Semgrep.
# Runs as non-root user (validator:10001) with strict network isolation.

FROM python:3.11-slim

# Prevent Python from writing .pyc files and enable unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONPYCACHEPREFIX=/tmp/autopatch-pycache

# Security: Create unprivileged non-root user and group
RUN groupadd -g 10001 validator && \
    useradd -u 10001 -g validator -m -s /bin/bash validator

# Install security scanners and test tooling with pinned versions
RUN pip install --no-cache-dir \
    pytest==9.1.1 \
    bandit==1.9.4 \
    semgrep==1.177.0

# Offline rules are baked into the image, outside the writable target workspace.
# Build from repository root: docker build -f docker/validation/Dockerfile -t autopatch-validator .
COPY backend/tools/semgrep_rules /opt/autopatch/rules
ENV SEMGREP_SEND_METRICS=off

# pip populated this cache as root; the runtime UID must be able to compile in /tmp.
RUN mkdir -p /tmp/autopatch-pycache && chown -R 10001:10001 /tmp/autopatch-pycache

# Set workspace directory inside container
WORKDIR /workspace

# Switch to non-root user
USER 10001:10001

# Default command
CMD ["python", "-m", "pytest", "-q"]
