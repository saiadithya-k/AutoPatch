# AutoPatch

AutoPatch scans a local Python repository with Bandit and Semgrep, prioritizes findings, generates candidate patches, and validates them with compilation, project tests, and differential security scans. A React dashboard displays progress, diffs, retry history, evidence, reports, and approval or rejection decisions. Candidates are tested in temporary copies; approval records a decision and does not apply changes to the submitted repository.

## Run locally on Windows

Use **Python 3.11** and Node.js 22 or newer. From the project directory:

```powershell
if (-not (Test-Path .venv)) { py -3.11 -m venv .venv }
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
.\.venv\Scripts\python.exe scripts/readiness.py
```

An existing Python 3.11 environment can be reused. The setup helper preserves existing environments and configuration:

```powershell
.\scripts\setup.ps1 -Python 'C:\path\to\python311\python.exe'
```

Readiness checks report the interpreter, scanners, execution mode, Docker, and configured model availability without printing secrets. A missing model service causes readiness to fail; scans still work, and generation failures remain visible in workflow history. The supplied configuration uses a local Ollama service at `http://localhost:11434/v1` with `qwen2.5-coder:7b`. Ensure that service and model are available before requesting live generation. The mock provider is for controlled tests and is not a general repository remediator.

Model requests use `LLM_TIMEOUT=120` seconds by default to allow local model startup; configure it in `.env` when needed (maximum 600 seconds). AutoPatch computes diffs from verified structured replacements. Dedented model blocks are reindented only when their explicit coordinates and all non-indentation source text match. See [live Ollama verification](docs/OLLAMA_VERIFICATION.md) for the tested workflow and evidence.

Start the API in one terminal:

```powershell
.\.venv\Scripts\python.exe -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

Start the dashboard in another:

```powershell
Set-Location frontend
npm ci
npm run dev
```

Open [the dashboard](http://127.0.0.1:5173) or [API documentation](http://127.0.0.1:8000/docs). Submit an absolute repository path, for example `D:\projects\AutoPatch\tests\vulnerable_project`. Repository access defaults to the API's working directory and descendants; set `ALLOWED_REPOSITORY_ROOT` in `.env` to allow a different root. Development CORS permits localhost and 127.0.0.1 on port 5173. `VITE_API_BASE_URL` can select another API; the default development proxy sends `/api` to port 8000.

## Reproducible demo without a model service

This demo uses scripted model responses but real scanners, compilation, and pytest. The first candidate fails the behavior tests; a retry uses `ast.literal_eval` and becomes available for review. All demo files and its database are kept inside `.test-artifacts`.

```powershell
.\.venv\Scripts\python.exe scripts/demo_workflow.py
$env:DATABASE_URL = 'sqlite:///./.test-artifacts/demo.db'
.\.venv\Scripts\python.exe -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

Use the workflow link printed by the demo after starting the dashboard. Inspect the failed attempt and passing retry, then approve or reject the latest proposal. Stop any API already using port 8000 before launching the demo API. The normal project database is preserved.

## Execution and evidence

Local validation requires `DOCKER_ENABLED=false` and `ALLOW_LOCAL_FALLBACK=true`. It executes project tests on this machine and is intended for trusted development repositories. For isolated validation, build the Python 3.11 validator and set `DOCKER_ENABLED=true`:

```powershell
docker build -f docker/validation/Dockerfile -t autopatch-validator .
```

Docker validation disables networking and requires the image and project dependencies to be prepared beforehand. Required Docker failures do not silently fall back to local execution. See [validator setup](docker/validation/README.md) for dependency preparation.

Semgrep uses a bundled, versioned ruleset for shell execution, dynamic eval, selected interpolated SQL, and unsafe pickle. This is a limited Python ruleset. Complete coverage means both configured scanners succeeded, not that every possible vulnerability was ruled out. Missing or degraded scanner coverage cannot pass candidate validation. Candidates must pass syntax, at least one project test, and security checks; newly added scanner suppression comments are rejected.

Workflows run in a bounded local background executor. Restarting the API marks interrupted runs as failed with inspectable history. Each candidate is validated independently against the original source; approved proposals may need reconciliation before manual application. Reviewer labels are descriptive metadata for this local application.

## Verification

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m pytest -q -m 'not scanners'
.\.venv\Scripts\python.exe -m pytest -q tests/integration/test_workflow_end_to_end.py
Set-Location frontend
npm run build
```

Tests use isolated databases and controlled model responses. Scanner tests require the pinned scanner dependencies. Docker and live model verification are separate environment checks; they are not implied by passing the deterministic suite.

See [workflow API contracts](docs/MVP_API.md) and [implementation plan and verification status](docs/WORKING_MVP_PLAN.md). Remote cloning, patch application, pull requests, authentication, distributed workers, and broader language support remain later work.
