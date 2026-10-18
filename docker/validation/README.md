# Validator environment

Build the offline Python 3.11 validator from the repository root:

```powershell
docker build -f docker/validation/Dockerfile -t autopatch-validator .
```

The image contains pytest, Bandit, and the bundled Semgrep Python rules. Validation
executes every command with networking disabled, so no scanner registry download
is needed. The bundled rules cover shell execution, eval, interpolated SQL, and
pickle deserialization; they are a deliberately small versioned ruleset, not a
replacement for the entire Semgrep security registry.

The submitted project's dependencies must already exist in the validator image.
AutoPatch never installs from a submitted repository or runs its install scripts.
For a project that needs packages, build a derived image using a separately
reviewed, pinned requirements file:

```dockerfile
FROM autopatch-validator
USER root
COPY trusted-requirements.txt /opt/autopatch/trusted-requirements.txt
RUN pip install --no-cache-dir -r /opt/autopatch/trusted-requirements.txt
USER 10001:10001
```

Set `DOCKER_IMAGE` to that image and enable Docker. Missing imports are reported
as infrastructure failures rather than retryable patch regressions. Building
the image is a trusted preparation step with network access; candidate validation
remains offline.

Compilation uses `/tmp/autopatch-pycache`, owned by UID 10001. Scanners disable
version checks as well as metrics, and validator runs use `--pull never` so a
missing image fails instead of starting an implicit registry download.

On native Linux, the executor adds the host process's GID as a supplementary
container group. Disposable validation copies grant that group access and inherit
the group for newly created files; the image entrypoint uses umask `0002` so the
host can remove container-created artifacts. The workspace root grants no world
access, UID 10001 remains non-root, and source permissions are unchanged. Derived
images should preserve this entrypoint for reliable cleanup.

The repository's `.dockerignore` includes only validator build assets. Build
custom derived images in a separate trusted build directory containing their
Dockerfile and reviewed requirements file.

For the checked-in dependency acceptance fixture:

```powershell
docker build -f docker/validation/acceptance.Dockerfile -t autopatch-validator-acceptance:latest .
.\.venv\Scripts\python.exe -m pytest -q -m docker --run-docker
```

This layer explicitly declares HTTPX 0.28.1. It does not read requirements from
submitted repositories. Actual Docker acceptance passed 12 checks on hosted Linux
on 2026-10-18, including native ownership and cleanup (11 earlier local checks);
see [the verification report](../../docs/MILESTONE_ACCEPTANCE.md).

Local execution requires `ALLOW_LOCAL_FALLBACK=true` and is intended for trusted
development repositories. Temporary copies protect source files from patch
application; local execution does not sandbox the project's test code.
