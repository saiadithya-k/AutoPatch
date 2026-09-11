# AutoPatch — Agentic AI Automated Vulnerability Remediation Platform

AutoPatch is an agentic AI system for automated software vulnerability detection, risk assessment, patch generation, isolated sandbox validation, feedback-driven retry, and developer-guided remediation.

---

## 📌 Implementation Status

- **Phase 1**: Backend Foundation & Static Security **Scanning Agent** (**COMPLETED & FINALIZED**).
- **Phase 2**: Deterministic Security **Risk-Assessment Agent** (**COMPLETED & FINALIZED**).
- **Phase 3**: Provider-Independent **LLM Service & Structured Output** (**COMPLETED & FINALIZED**).
- **Phase 4**: **Repository Context Service** (**COMPLETED & FINALIZED**).
- **Phase 5**: **Patch-Generation Agent & Unified Diff Synthesis** (**COMPLETED & FINALIZED**).
- **Phase 6–8**: **Validation Agent & Tooling** (**COMPLETED & FINALIZED**).
- **Phase 9**: **Production Docker Sandbox & Security Hardening** (**COMPLETED & FINALIZED**).
- **Phase 10**: **Bounded Patch Retry Loop & Audit Lineage** (**COMPLETED & FINALIZED**).
- **Phase 11**: **Database & Persistent Audit Lineage** (**COMPLETED & FINALIZED**).
- **Active Pipeline**:
  $$\text{Repository} \longrightarrow \text{Scanning Agent} \longrightarrow \text{Risk Assessment} \longrightarrow \text{Context Service} \longrightarrow \text{Patch Generation} \longrightarrow \text{Validation Agent (Sandbox)} \longrightarrow \begin{cases} \text{PASS} \implies \text{READY\_FOR\_REVIEW} \\ \text{FAIL} \implies \text{RetryAgent} \longrightarrow \text{Patch Generation} \longrightarrow \text{Re-Validate} \end{cases}$$

---

## 🏗 System Architecture

```text
                               ┌──────────────────────────┐
                               │  Target Repository Path  │
                               └────────────┬─────────────┘
                                            │
                                            ▼
                               ┌──────────────────────────┐
                               │    RepositoryService     │
                               │  Path Traversal Guards   │
                               └────────────┬─────────────┘
                                            │
                                            ▼
                               ┌──────────────────────────┐
                               │      Scanning Agent      │
                               │  (Graceful Degradation)  │
                               └──────┬────────────┬──────┘
                                      │            │
                         ┌────────────┴──┐      ┌──┴─────────────┐
                         │ BanditRunner  │      │ SemgrepRunner  │
                         └────────────┬──┘      └──┬─────────────┘
                                      │            │
                                      ▼            ▼
                               ┌──────────────────────────┐
                               │  Finding Normalization   │
                               │  VulnerabilityFinding[]  │
                               └────────────┬─────────────┘
                                            │
                                            ▼
                               ┌──────────────────────────┐
                               │  Risk-Assessment Agent   │
                               │  (Deterministic Engine)  │
                               └────────────┬─────────────┘
                                            │
                                            ▼
                               ┌──────────────────────────┐
                               │ Prioritized Vulnerability│
                               └────────────┬─────────────┘
                                            │
                                            ▼
                               ┌──────────────────────────┐
                               │ Repository Context Serv. │
                               │ • Bounded line windows   │
                               │ • Python AST scopes      │
                               │ • Import extraction      │
                               │ • Related file detection │
                               │ • Related test discovery │
                               └────────────┬─────────────┘
                                            │
                                            ▼
                               ┌──────────────────────────┐
                               │  Patch-Generation Agent  │
                               │  • Prompt Injection Def. │
                               │  • LLM Structured Schema │
                               │  • Unified Diff Synth.   │
                               │  • Scope & Size Limits   │
                               │  • Read-Only / Immutable │
                               └────────────┬─────────────┘
                                            │
                                            ▼
                               ┌──────────────────────────┐
                               │ Candidate Patch Object   │
                               │  (PatchGenerationResult) │
                               └────────────┬─────────────┘
                                            │
                                            ▼
                               ┌──────────────────────────┐
                               │ SQLite Database Layer    │
                               │ • workflows              │
                               │ • vulnerabilities        │
                               │ • risk_assessments       │
                               │ • patch_attempts         │
                               │ • validation_results     │
                               │ • audit_events           │
                               └────────────┬─────────────┘
                                            │
                                            ▼
                               ┌──────────────────────────┐
                               │    FastAPI HTTP API      │
                               │  POST /api/scan          │
                               │  POST .../assess-risk    │
                               │  GET  .../context        │
                               │  POST .../generate-patch │
                               │  GET  .../patches        │
                               │  POST .../validate       │
                               │  GET  .../validation     │
                               └──────────────────────────┘
```

---

## 🛡️ Validation Agent & Sandboxing Tooling

The **`ValidationAgent`** orchestrates an isolated, multi-stage verification pipeline to validate candidate patches before any human review or merge consideration.

### Core Validation Pipeline
```text
Candidate Patch
      │
      ▼
1. Structural Patch Validation (Patch header regex, relative paths, no test modifications)
      │
      ▼
2. Isolated Temporary Workspace (Symlink breakout protection, pristine host repository)
      │
      ▼
3. Patch Application (Pure-Python hunk parser, line offset adjustment, exact diff application)
      │
      ▼
4. Syntax / Build Check (Controlled python -m compileall, shell=False)
      │
      ▼
5. Test Runner (Controlled python -m pytest -q, timeout enforcement, failure diagnosis)
      │
      ▼
6. Differential Security Re-scan (Bandit + Semgrep re-scans in sandbox)
      │
      ▼
7. Security Comparison (Rule ID + proximity matching: resolved vs remaining vs new findings)
      │
      ▼
8. Validation Verdict & Persistence (PASS / FAIL / ERROR / TIMEOUT + audit record in DB)
```

### Key Validation Safety Guarantees:
- **No Arbitrary Execution**: Tests and syntax compilation never execute LLM-generated shell strings. Subprocess commands are strictly constrained lists (`[sys.executable, "-m", "pytest", "-q"]`) executed with `shell=False`.
- **Repository Immutability**: The target repository is never touched or modified. Verification SHA-256 hashes confirm zero bytes changed in the original codebase.
- **Docker Sandbox Ready**: The `SandboxExecutor` interface isolates workspace execution and allows seamless switching to `DockerSandboxExecutor` for production containerized sandboxing.
- **Differential Security Verification**: A patch is only marked `PASS` if:
  1. Patch applies cleanly.
  2. Syntax check succeeds.
  3. All project tests pass.
  4. The target vulnerability is confirmed resolved.
  5. Zero new security vulnerabilities are introduced.

---

## 🩹 Patch-Generation Agent

The **`PatchGenerationAgent`** consumes prioritized vulnerability findings, risk assessments, and extracted repository context to generate minimal, safe candidate patches formatted as standard unified diffs.

### Core Principles & Architecture
1. **Candidate Patches Only**: The agent proposes candidate changes. Patches are marked with status `GENERATED` or `REJECTED` and are **NEVER** marked `VALIDATED` or `APPROVED` until executed by the future Validation Agent.
2. **Provider-Independent LLM Integration**: Operates exclusively through `LLMService`, supporting OpenAI models (`gpt-4o`) and offline `MockLLMProvider` without direct SDK coupling.
3. **Structured Pydantic Validation**: Model output is strictly enforced via the `LLMPatchGeneration` and `LLMCodeChange` schemas.
4. **Prompt Injection Defense**: Repository code, comments, and strings are encapsulated inside `<untrusted_source_context>` delimiters. System instructions explicitly command the model never to execute code instructions embedded within source files.
5. **Absolute Repository Immutability**: Patch generation is **100% read-only** against the target repository. Files on disk are never modified during generation.
6. **Unified Diff Synthesis**: Computes standard unified diffs (`--- a/file.py\n+++ b/file.py`) from structured replacement blocks.

### Patch Safety & Boundary Checks
- **Path Traversal Protection**: Rejects `../`, absolute paths (`/etc/passwd`, `C:\...`), UNC paths, and drive escapes.
- **Change Scope Control**: Only allows modifications to the vulnerable file or identified related files.
- **Test File Protection**: Rejects patches that modify test files (`tests/`, `test_*.py`) to prevent artificial test bypasses.
- **Patch Size Bounding**:
  - `MAX_PATCH_FILES` (Default: 3 files)
  - `MAX_PATCH_LINES` (Default: 200 lines)
  - `MAX_PATCH_CHARS` (Default: 20,000 characters)

---

## 🔍 Repository Context Service

AutoPatch strictly avoids sending entire repositories to LLMs to prevent token exhaustion, hallucinations, prompt pollution, and security leaks. Instead, the **`RepositoryContextService`** extracts a targeted, bounded context payload around each finding:

```text
Finding (file_path, line_start, line_end)
   │
   ├── 1. Path Containment & Traversal Validation
   ├── 2. Safe Bounded File Slicing (e.g. ±50 lines)
   ├── 3. Static Python AST Scope Analysis (Enclosing function/class/docstring)
   ├── 4. Static Import Resolution (Imported packages & symbols)
   ├── 5. Heuristic Related File Discovery (Siblings & imported local modules)
   ├── 6. Associated Test File Matching (pytest/unittest test functions)
   └── 7. Passive Secret Redaction (Leaves disk intact)
   │
   ▼
RepositoryContext (Bounded Pydantic Object)
```

### Context Limits & Bounding:
- **`CONTEXT_LINES_BEFORE`** (Default: 50): Number of code lines preceding the vulnerability.
- **`CONTEXT_LINES_AFTER`** (Default: 50): Number of code lines following the vulnerability.
- **`MAX_CONTEXT_FILE_SIZE`** (Default: 1MB): Files larger than this threshold generate a `file_too_large` warning without crashing.
- **`MAX_CONTEXT_FILES`** (Default: 5): Maximum number of related files returned.
- **`MAX_CONTEXT_LINES`** (Default: 500): Upper cap on total lines in the surrounding window.

---

## 🤖 Provider-Independent LLM Service

AutoPatch implements a clean, provider-independent LLM service layer decoupled from specific provider SDKs:

```text
                 LLMProvider (Abstract Base)
                     │
          ┌──────────┴──────────┐
          │                     │
    OpenAIProvider        MockLLMProvider (Offline/Testing)
          │
          ▼
     Structured Response Validation (Pydantic Schema: LLMPatchGeneration, LLMRiskAnalysis)
          │
          ▼
    PatchGenerationAgent / RiskAssessmentAgent
```

---

## 📊 Deterministic Risk Scoring Formula

The Risk Engine calculates transparent, bounded, and repeatable scores without requiring external LLM API keys:

$$\text{Risk Score} = \min\left(10.0, \max\left(0.0, 0.35 \times S + 0.25 \times E + 0.25 \times I + 0.15 \times C\right)\right)$$

### Priority Thresholds
| Risk Score Range | Priority Tier |
| :--- | :--- |
| **8.50 – 10.00** | `CRITICAL` |
| **7.00 – 8.49** | `HIGH` |
| **4.00 – 6.99** | `MEDIUM` |
| **0.00 – 3.99** | `LOW` |

---

## ⚙️ Environment Configuration

Configuration is loaded from environment variables or a local `.env` file:

```dotenv
# Application
APP_NAME=AutoPatch
ENVIRONMENT=development
LOG_LEVEL=INFO

# Database
DATABASE_URL=sqlite:///./autopatch.db

# Scanning Configuration
SCAN_TIMEOUT=120
TEST_TIMEOUT=60
MAX_PATCH_RETRIES=3
DOCKER_ENABLED=false

# Repository Context Configuration
CONTEXT_LINES_BEFORE=50
CONTEXT_LINES_AFTER=50
MAX_CONTEXT_FILE_SIZE=1048576
MAX_CONTEXT_FILES=5
MAX_CONTEXT_LINES=500

# Patch Generation Configuration
MAX_PATCH_FILES=3
MAX_PATCH_LINES=200
MAX_PATCH_CHARS=20000

# LLM Configuration
LLM_PROVIDER=openai
LLM_MODEL=gpt-4o
# OPENAI_API_KEY=sk-your-openai-api-key-here
```

---

## 🚀 Quick Start

### 1. Requirements
- **Python**: 3.10+ (tested on Python 3.14.3)
- **Bandit**: `python -m pip install bandit`
- **Semgrep**: `python -m pip install semgrep`

### 2. Installation
```powershell
python -m pip install -r requirements.txt
Copy-Item .env.example .env
```

---

## 🏃 Running AutoPatch

### Option A: FastAPI Web Server

```powershell
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```

Interactive OpenAPI documentation: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

#### Key Endpoints:
- `GET /health` — Health check probe.
- `POST /api/scan` — Run static security scan on target repository.
- `POST /api/workflows/{workflow_id}/assess-risk` — Assess risk and return prioritized findings.
- `GET /api/vulnerabilities/{vulnerability_id}/risk` — Get detailed risk assessment for a finding.
- `GET /api/vulnerabilities/{vulnerability_id}/context` — Get bounded repository context for a finding.
- `POST /api/vulnerabilities/{vulnerability_id}/generate-patch` — Synthesize candidate patch proposal.
- `GET /api/vulnerabilities/{vulnerability_id}/patches` — Chronological history of patch attempts for a finding.
- `GET /api/patches/{patch_id}` — Get single patch attempt record with diff and explanation.
- `POST /api/patches/{patch_id}/validate` — Execute isolated validation on a candidate patch proposal.
- `GET /api/patches/{patch_id}/validation` — Get latest validation outcome for a patch attempt.
- `GET /api/validations/{validation_id}` — Get detailed validation audit record with test and scan output.
- `GET /api/risk-assessments` — List and filter risk assessments.
- `POST /api/patches/{patch_id}/retry` — Execute bounded patch retry loop.
- `GET /api/patches/{patch_id}/retry-history` — Retrieve full ancestral lineage chain of retry attempts.
- `GET /api/audit/events` — Query and filter lifecycle audit events across all phases.
- `GET /api/audit/events/{event_id}` — Retrieve detailed audit event record with sanitized metadata.
- `GET /api/workflows/{workflow_id}/audit` — Retrieve complete chronological audit timeline for a workflow.

---

## 📜 Phase 11 — Persistent Lifecycle Audit & Lineage

AutoPatch records every lifecycle transition to the `audit_events` table via the centralized `AuditService`.

### Core Lifecycle Event Types
| Phase | Event Types | Description |
| :--- | :--- | :--- |
| **Workflow** | `WORKFLOW_CREATED`, `SYSTEM_ERROR` | Workflow orchestration checkpoints |
| **Scanning** | `SCAN_STARTED`, `SCAN_COMPLETED`, `SCAN_DEGRADED`, `SCAN_FAILED` | SAST scan execution status and finding counts |
| **Risk Assessment**| `RISK_ASSESSMENT_STARTED`, `RISK_ASSESSMENT_COMPLETED`, `RISK_ASSESSMENT_FAILED` | Prioritization metrics and duration |
| **Context** | `CONTEXT_CREATED`, `CONTEXT_FAILED` | AST and bounded window retrieval |
| **Patch Generation**| `PATCH_GENERATION_STARTED`, `PATCH_GENERATED`, `PATCH_GENERATION_FAILED` | Candidate synthesis and diff safety gating |
| **Validation** | `PATCH_VALIDATION_STARTED`, `PATCH_APPLIED`, `PATCH_VALIDATION_FAILED`, `PATCH_VALIDATED` | Sandbox compilation, pytest, and differential SAST |
| **Retry Loop** | `RETRY_DECISION`, `RETRY_STARTED`, `RETRY_EXHAUSTED`, `NO_PROGRESS` | Deterministic retry evaluation and recursion protection |
| **Human Review** | `READY_FOR_REVIEW` | **Hard Boundary**: Signals developer review required (no auto-merge/PR) |

### Automated Secret Redaction
All audit event metadata passes through recursive key sanitization before persistence:
- Sensitive keys matching `password`, `passwd`, `secret`, `token`, `api_key`, `apikey`, `authorization`, `cookie`, `private_key` are replaced with `"[REDACTED]"`.
- Raw prompt texts, credentials, and full environment variables are strictly prevented from database persistence.

---

## 🧪 Testing

The complete test suite runs 100% offline without requiring a live `OPENAI_API_KEY`:

```powershell
# Run full unit & integration test suite (185 tests)
python -m pytest -q

# Run unit tests only (166 tests)
python -m pytest -q tests/unit

# Run integration tests only (19 tests)
python -m pytest -q tests/integration
```

### Scanner & Sandbox Prerequisites
- **Bandit & Semgrep**: The static analysis tests require Bandit and Semgrep in the environment:
  ```powershell
  python -m pip install bandit semgrep
  ```
- **Docker Validation Sandbox (Optional)**:
  Build the containerized sandbox image to run isolated validations in production mode:
  ```powershell
  docker build -t autopatch-validator:latest -f docker/Dockerfile .
  ```

---

## 🔭 Future Phases Roadmap

- **Phase 12**: Clean Orchestration Pipeline (single workflow invocation).
- **Phase 13**: End-to-End FastAPI Workflow Lifecycle.
- **Phase 14**: Developer Security Dashboard (React UI).
- **Phase 15**: Human Review & Approval Flow.
