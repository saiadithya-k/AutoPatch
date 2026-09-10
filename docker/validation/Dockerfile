# AutoPatch Validation Sandbox Dockerfile
# Pinned, reproducible base image for safe candidate patch validation.
#
# Provides isolated environment with Python, pytest, Bandit, and Semgrep.
# Runs as non-root user (validator:10001) with strict network isolation.

FROM python:3.11-slim

# Prevent Python from writing .pyc files and enable unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Security: Create unprivileged non-root user and group
RUN groupadd -g 10001 validator && \
    useradd -u 10001 -g validator -m -s /bin/bash validator

# Install security scanners and test tooling with pinned versions
RUN pip install --no-cache-dir \
    pytest==7.4.3 \
    bandit==1.7.5 \
    semgrep==1.50.0

# Set workspace directory inside container
WORKDIR /workspace

# Switch to non-root user
USER 10001:10001

# Default command
CMD ["python", "-m", "pytest", "-q"]
