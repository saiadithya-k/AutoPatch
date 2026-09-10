# AutoPatch — Workspace Audit

## 1. Existing Workspace Structure

The initial workspace inspection revealed the following files in `c:\Users\saiad\Downloads\AutoPatch_Project_Documents`:

- `PRD.md` — Product Requirements Document for AutoPatch (multi-agent architecture, safety boundaries, user stories, success criteria).
- `TRD.md` — Technical Requirements Document (component specs, tool boundaries, isolated sandbox, SQLite/PostgreSQL schema, API endpoints).
- `FLOW.md` — System Flow Specification (master sequence, state flow, patch attempt cycle, data handoffs).
- `BACKEND_SCHEMA.md` — Database schemas (Workflows, Vulnerabilities, PatchAttempts, ValidationResults, RiskAssessments, AuditEvents) and API schemas.
- `IMPLEMENTATION_PLAN.md` — Phased rollout plan (Phase 0 through Phase 20).

No `.git` directory was initialized, and no source code packages (backend/frontend) existed in the workspace prior to Phase 1.

## 2. Existing Technologies Detected

- **Operating System**: Windows
- **Python Runtime**: Python 3.14.3
- **Installed Packages**: FastAPI (0.141.1), Pydantic (2.12.5), SQLAlchemy (2.0.36), Starlette (1.6.0), Uvicorn (0.52.4), Pytest (7.4.3), PyYAML (6.0.3), Python-Dotenv (1.0.1), HTTPX (0.28.1), Rich, Click.
- **Required Additional Packages**: `bandit`, `semgrep`.

## 3. Existing Functionality

- The workspace contains complete and detailed design specifications covering the end-to-end agentic workflow, data structures, tool execution rules, and security isolation requirements.
- No executable Python application code, scanner wrappers, or database models exist yet.

## 4. Missing Functionality (Phase 1 Scope)

To achieve the Phase 1 objective (`Vulnerable Python Repo -> AutoPatch Scanner -> Bandit + Semgrep -> Normalized Findings -> SQLite DB -> API Response`), the following core components are missing and must be built:

1. **Configuration Layer**: `backend/config.py` using `pydantic_settings` / environment variables.
2. **Vulnerability & Workflow Models**: `backend/models/vulnerability.py` (Pydantic models with enums: Severity, Status, WorkflowStatus).
3. **Database & ORM Layer**: `backend/database/database.py` and `backend/database/models.py` (SQLAlchemy SQLite database with auto-initialization).
4. **Tool Runners**:
   - `backend/tools/bandit_runner.py`: Safe subprocess wrapper running Bandit with JSON reporting, error/timeout handling, and command isolation.
   - `backend/tools/semgrep_runner.py`: Safe subprocess wrapper running Semgrep with JSON reporting, rule sets, error/timeout handling.
5. **Finding Normalization & Deduplication Layer**: Deduplicates and converts scanner-specific payloads into standard `VulnerabilityFinding` records with deterministic IDs.
6. **Scanning Agent**: `backend/agents/scanning_agent.py` orchestrating path validation, tool runners, normalization, and persistence.
7. **Repository Service**: `backend/services/repository.py` validating local filesystem repository paths against traversal and invalid inputs.
8. **FastAPI Application & Routes**:
   - `GET /health`
   - `POST /api/scan`
9. **Demo Vulnerable Project**: `tests/vulnerable_project/` with intentionally vulnerable code patterns detectable by both Bandit and Semgrep, and basic functional tests.
10. **Test Suite**: Unit and integration tests in `tests/unit/` and `tests/integration/` validating runners, models, deduplication, agent orchestration, and API endpoints.

## 5. Conflicts with AutoPatch Architecture

- None. The workspace is a fresh greenfield implementation aligned 100% with the provided specifications (`PRD.md`, `TRD.md`, `FLOW.md`, `BACKEND_SCHEMA.md`, `IMPLEMENTATION_PLAN.md`).

## 6. Files to be Created

```
backend/
├── __init__.py
├── main.py
├── config.py
├── agents/
│   ├── __init__.py
│   └── scanning_agent.py
├── tools/
│   ├── __init__.py
│   ├── bandit_runner.py
│   └── semgrep_runner.py
├── models/
│   ├── __init__.py
│   └── vulnerability.py
├── database/
│   ├── __init__.py
│   ├── database.py
│   └── models.py
├── services/
│   ├── __init__.py
│   └── repository.py
└── api/
    ├── __init__.py
    └── routes/
        ├── __init__.py
        └── scan.py

tests/
├── __init__.py
├── conftest.py
├── unit/
│   ├── __init__.py
│   ├── test_models.py
│   ├── test_bandit_runner.py
│   ├── test_semgrep_runner.py
│   ├── test_normalization.py
│   ├── test_repository_service.py
│   └── test_scanning_agent.py
├── integration/
│   ├── __init__.py
│   ├── test_scan_integration.py
│   └── test_api_scan.py
└── vulnerable_project/
    ├── app.py
    ├── database.py
    └── test_app.py

prompts/
    └── .gitkeep

docs/
    ├── workspace_audit.md
    └── .gitkeep

.env.example
.gitignore
requirements.txt
README.md
```

## 7. Files to be Modified

- None of the 5 specification documents (`PRD.md`, `TRD.md`, `FLOW.md`, `BACKEND_SCHEMA.md`, `IMPLEMENTATION_PLAN.md`) will be overwritten or broken. They remain the living architectural specification.
