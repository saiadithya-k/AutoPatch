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

Local execution requires `ALLOW_LOCAL_FALLBACK=true` and is intended for trusted
development repositories. Temporary copies protect source files from patch
application; local execution does not sandbox the project's test code.
