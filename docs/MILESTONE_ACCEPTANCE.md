# Docker, model acceptance, and CI milestone

Verification date: **2026-10-18**. Python runtime: **3.11.9**.

Docker, automated regression gates and all four live-model acceptance cases
are verified locally. Each live candidate must pass independent compilation,
behavioral tests and security re-scans.

## Verified checks

| Gate | Result |
| --- | --- |
| Deterministic Python/API/scanner regression suite | 322 passed; external-service gates deselected |
| Real Docker acceptance | 11 passed |
| Browser workflow/review regression suite | 5 passed in installed Chrome; no uncaught page errors |
| Frontend production build | Passed |
| GitHub-hosted workflow execution | Pending first push or manual dispatch; not run remotely in this task |
| Previously successful literal-parser fixture, live Ollama | Rechecked successfully; both candidates ready for review |
| Combined real Ollama + Docker matrix | All four cases passed; all original source files unchanged |

Docker tests use actual containers, not mocked Docker responses. They verify
Python 3.11, UID 10001, loopback-only networking, zero effective capabilities,
`no-new-privileges`, no Docker socket, timeout cleanup, and missing-image failure.
All four reference remediation cases pass compilation, project tests and both
scanners inside Docker. Additional cases reject syntax errors, broken behavior,
unresolved findings and missing project dependencies. Source hashes remain
unchanged. The missing-image check uses `--pull never` and does not fetch images.

Browser tests start the real API on port 8765 and dashboard on 5174, with a new
SQLite database under `.test-artifacts` for each run. Scripted model responses
prepare genuine scanner/test evidence. Tests cover clean workflow submission,
selection after reload, superseded proposals, approval/rejection persistence,
required rejection comments, incomplete coverage, and mobile layout. No test
endpoints were added to the production application.

## Broader live-model acceptance

The reproducible corpus contains:

| Case | Required behavior |
| --- | --- |
| `command_injection` | Preserve a diagnostic function while removing shell execution |
| `sql_injection` | Preserve lookups and treat an SQL injection payload as literal data |
| `multifile_sql` | Fix query construction and its caller across two modules |
| `httpx_dependency` | Preserve a request-building API with HTTPX installed, without sending network requests |

Live tests call the configured local Ollama model. Reference fixes are never
placed in those repositories or sent in the model prompt. A case passes only
when every recorded finding has a reviewable candidate, every candidate has
passing persisted validation with complete scanner coverage, and original
source hashes match. Partial success, rejected generation, failed tests,
repeated candidates and timeouts return a nonzero exit code.

The initial broad run with `qwen2.5-coder:7b` passed only 1 of 4 cases. After
introducing source-bound edits, the complete matrix passed **4 of 4 cases** both
with local development validation and with real offline Docker validation:

| Case | Final result |
| --- | --- |
| `command_injection` | Passed; shell execution removed while preserving behavior |
| `sql_injection` | Passed; query template and bound execution arguments included |
| `multifile_sql` | Passed; helper and execution caller fixed together |
| `httpx_dependency` | Passed; every finding had a validated proposal |

All four original repositories remained unchanged in both runs. Earlier failed
generation and validation evidence is retained separately for traceability.
No validation criteria, tests, scanner rules or review gates were weakened.

Ollama now receives a compact JSON edit contract: select a supplied block ID and
return its complete replacement. The server owns original text, paths and line
numbers, splits bounded redacted context into source blocks, and rejects unknown
or repeated IDs. Tests remain read-only context. Retry prompts place the original
editable source after failure evidence. Exact source matching still rejects
stale or redacted originals. Other providers retain the existing edit contract.

The established JSON response mode and 4096-token output bound remain. New
regressions cover stale source, invented destinations, duplicate IDs, source/test
budgets, caller edits and original-source retries. This corpus demonstrates
working behavior for these cases; other repositories still require independent
validation and developer review.

Current evidence:

- `.test-artifacts/ollama-source-blocks-20261018/summary.json`: local, 4/4 passed.
- `.test-artifacts/ollama-source-blocks-docker-20261018/summary.json`: Docker, 4/4
  passed; approximately 19, 14, 15 and 27 seconds respectively.
- `.test-artifacts/source-edit-full.xml`: Python regression evidence.
- `.test-artifacts/source-edit-docker.xml`: real Docker regression evidence.

## Run the checks

From the project root, using the Python 3.11 environment:

```powershell
# Unit, API and actual local-scanner regressions; no live model or Docker required.
.\.venv\Scripts\python.exe -m pytest -q -m "not docker and not live_model"

# Four reference fixes, actual scanners/tests, isolated database and saved reports.
.\.venv\Scripts\python.exe scripts/run_acceptance.py
```

Prepare the trusted Docker images, then require actual Docker execution:

```powershell
docker build -f docker/validation/Dockerfile -t autopatch-validator:latest .
docker build -f docker/validation/acceptance.Dockerfile -t autopatch-validator-acceptance:latest .
.\.venv\Scripts\python.exe -m pytest -q -m docker --run-docker

# Equivalent case reports with a persistent isolated evidence database.
.\.venv\Scripts\python.exe scripts/run_acceptance.py --docker
```

Run live model acceptance explicitly:

```powershell
.\.venv\Scripts\python.exe scripts/run_acceptance.py --live-model
.\.venv\Scripts\python.exe scripts/run_acceptance.py --live-model --case sql_injection
.\.venv\Scripts\python.exe -m pytest -q -m live_model --run-live-model
```

`--live-model --docker` combines local Ollama generation with offline container
validation. Live commands require `LLM_PROVIDER=ollama` and the configured model
to be installed. They refuse a cloud-provider configuration. Requested Docker
or live prerequisites fail visibly when unavailable; they are not silently
skipped. Normal pytest runs skip these external gates unless their opt-in flags
are supplied. `LLM_TIMEOUT` defaults to 120 seconds and
`LLM_MAX_OUTPUT_TOKENS` to 4096.

The CLI creates a new `.test-artifacts/acceptance-*` directory containing a
summary, per-case reports, vulnerable source fixtures and an isolated SQLite
database. It refuses to overwrite an existing evidence directory. Exit codes
are 0 for all cases passing, 1 for failed acceptance, 2 for missing prerequisites,
and 130 for a handled interruption. Completed summaries are saved after each
case. A requested interruption is never recorded as success.

For browser checks:

```powershell
Set-Location frontend
npm ci
npx playwright install chromium
npm run test:e2e
```

On Windows, an installed Chrome can be used instead of downloading Chromium:

```powershell
$env:AUTOPATCH_BROWSER_CHANNEL = 'chrome'
npm run test:e2e
```

Set `AUTOPATCH_PYTHON` if Python 3.11 is outside the usual `.venv` location.
Browser diagnostics are in `frontend/playwright-report/` and
`frontend/test-results/`; traces and screenshots are retained on failure.

## CI behavior

[The GitHub Actions workflow](../.github/workflows/ci.yml) runs on pushes,
pull requests and manual dispatch. It runs Python 3.11 regressions on Ubuntu and
Windows, a Linux frontend build and browser suite, and a Linux Docker image
build plus real container tests. Reports are uploaded even when a gate fails.
Jobs have read-only repository permissions and do not deploy or publish images.

Hosted CI does not pretend to have the user's Ollama service. Live acceptance
remains an explicit local gate. The checked-in workflow is ready for its first
remote run after the changes are pushed; local verification is not a claimed
GitHub Actions result.

## Reliability fixes exposed by this milestone

- New scanner findings now serialize timestamps safely, preserving the actual
  security failure instead of raising a JSON serialization error.
- Retry distinguishes rejected generation from a recorded human rejection;
  reviewed proposals remain immutable.
- Related caller and test source snippets reach the model within the configured
  context budget and receive secret redaction.
- Scanners disable online Semgrep version checks and use one worker for bounded
  offline execution.
- Docker compilation caches are writable by the non-root validator without
  changing source ownership. Missing images fail closed without implicit pulls.
- Timeouts and Python-handled interruptions remove their temporary Docker containers.
- Model provenance identifies Ollama correctly and model output has a token cap.
