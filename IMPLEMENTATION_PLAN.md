# AutoPatch --- Implementation Plan

## 1. Strategy

Build incrementally. Do not build the dashboard first and fake the
backend.

The implementation order is:

``` text
Foundation
   ↓
Scanner
   ↓
Risk Assessment
   ↓
LLM Service
   ↓
Patch Generation
   ↓
Validation
   ↓
Retry Loop
   ↓
Persistence + Audit
   ↓
Orchestration
   ↓
FastAPI
   ↓
Frontend
   ↓
Git/GitHub
   ↓
Docker Hardening
   ↓
GitHub Actions
   ↓
End-to-End Demo
```

## Phase 0 --- Workspace Audit

### Tasks

-   Inspect existing workspace.
-   Identify existing source code.
-   Identify existing frontend/backend.
-   Do not overwrite working code blindly.
-   Compare current implementation with the AutoPatch requirements.

### Deliverable

`workspace_audit.md`

### Exit Criteria

A clear list of existing components, missing components, broken
components, and planned changes.

------------------------------------------------------------------------

## Phase 1 --- Project Foundation

### Tasks

-   Create backend package.
-   Create agent package.
-   Create tool wrappers.
-   Create model package.
-   Create database package.
-   Create tests.
-   Add `.env.example`.
-   Add `.gitignore`.
-   Add dependency management.
-   Add logging.
-   Add basic configuration.

### Initial structure

``` text
autopatch/
├── backend/
│   ├── main.py
│   ├── agents/
│   ├── orchestrator/
│   ├── tools/
│   ├── models/
│   ├── database/
│   ├── services/
│   └── api/
├── frontend/
├── prompts/
├── tests/
├── .github/workflows/
├── requirements.txt
├── .env.example
├── Dockerfile
└── README.md
```

### Exit Criteria

Application imports successfully and base tests pass.

------------------------------------------------------------------------

## Phase 2 --- Vulnerable Demo Repository

### Tasks

Create a controlled Python project under:

``` text
tests/vulnerable_project/
```

Include intentionally vulnerable examples and tests.

The purpose is repeatable demonstration and automated testing.

### Exit Criteria

Bandit/Semgrep can detect at least one controlled finding.

------------------------------------------------------------------------

## Phase 3 --- Scanning Agent

### Tasks

-   Implement Bandit runner.
-   Implement Semgrep runner.
-   Normalize scanner output.
-   Create `VulnerabilityFinding`.
-   Persist findings.
-   Add scanner error handling.
-   Add scanner unit tests.

### Exit Criteria

``` text
Repository
 → Bandit/Semgrep
 → Normalized Findings
 → Database
```

A real finding is visible through an API/test.

------------------------------------------------------------------------

## Phase 4 --- Risk-Assessment Agent

### Tasks

-   Define deterministic risk model.
-   Map severity/exploitability/context/impact into a priority score.
-   Add optional LLM reasoning.
-   Store risk assessment.
-   Sort vulnerabilities by priority.
-   Add tests for deterministic scoring.

### Exit Criteria

The same input produces a stable score and priority.

------------------------------------------------------------------------

## Phase 5 --- LLM Service

### Tasks

-   Implement provider abstraction.
-   Add environment-based configuration.
-   Implement structured responses.
-   Add prompt templates:
    -   risk assessment
    -   patch generation
    -   retry
-   Add API failure handling.
-   Add response validation.

### Exit Criteria

The Patch Agent can request a structured model response without
hardcoded secrets.

------------------------------------------------------------------------

## Phase 6 --- Repository Context Service

### Tasks

Implement contextual retrieval.

Start with: - vulnerable file - surrounding lines - relevant
function/class - imports - related test files where identifiable

Avoid sending entire repositories unnecessarily.

### Exit Criteria

Patch generation receives a controlled context object.

------------------------------------------------------------------------

## Phase 7 --- Patch-Generation Agent

### Tasks

-   Consume prioritized vulnerability.
-   Consume repository context.
-   Generate candidate patch.
-   Return unified diff or equivalent patch representation.
-   Store patch attempt.
-   Include explanation.
-   Support validation feedback.

### Exit Criteria

``` text
Vulnerability
 + Context
 + Risk
 → LLM
 → Real Patch/Diff
```

------------------------------------------------------------------------

## Phase 8 --- Validation Agent

### Tasks

-   Create temporary workspace.
-   Copy/checkout repository.
-   Apply candidate patch.
-   Run tests.
-   Capture exit code/stdout/stderr.
-   Re-run security scanner.
-   Check original vulnerability.
-   Return structured validation result.

### Exit Criteria

A valid patch passes tests and removes the target finding.

------------------------------------------------------------------------

## Phase 9 --- Sandbox

### Tasks

-   Add Docker execution.
-   Limit execution time.
-   Control filesystem scope.
-   Control network where practical.
-   Capture logs.
-   Clean up temporary resources.
-   Clearly mark development fallback if Docker is unavailable.

### Exit Criteria

Generated patch code is validated in an isolated environment.

------------------------------------------------------------------------

## Phase 10 --- Retry Loop [COMPLETED]

### Tasks

Implement:

``` text
Generate
   ↓
Validate
   ↓
PASS → READY_FOR_REVIEW

FAIL
 ↓
Analyze validation evidence
 ↓
Evaluate RetryDecision policy
 ↓
Send structured untrusted feedback
 ↓
Generate improved candidate
 ↓
Validate again
```

Added:
- `backend/agents/retry_agent.py` (Bounded Retry Loop & deterministic RetryDecision policy)
- `backend/models/retry.py` (`RetryStatus`, `FailureCategory`, `RetryDecision`, `RetryAttemptRecord`, `RetryLoopResult`)
- Extended `PatchAttemptModel` schema: `parent_patch_id`, `attempt_number`, `retry_reason`, `validation_id`, `retryable`
- Prompt injection defense: structured untrusted data encapsulation (`<untrusted_validation_evidence>`)
- API endpoints: `POST /api/patches/{patch_id}/retry` and `GET /api/patches/{patch_id}/retry-history`
- Strict upper bound: `MAX_PATCH_RETRIES = 3` (1 initial + up to 3 retries = max 4 attempts)
- Identical patch detection (`NO_PROGRESS` / `RETRY_EXHAUSTED`)
- Immutability preservation and human-review boundary (`READY_FOR_REVIEW`, no auto-merge/PR)

### Exit Criteria

Automated test suite demonstrates:
- First validation PASS -> no retry
- Multi-attempt failure -> improvement -> PASS (`Attempt 1 -> FAIL, Attempt 2 -> PASS`)
- Retry limit termination (`RETRY_EXHAUSTED` after `MAX_PATCH_RETRIES`)
- Identical patch recursion prevention (`NO_PROGRESS`)
- Non-retryable infrastructure / Docker failures halt cleanly
- 21/21 Phase 10 unit tests passing, full suite 211 tests passing.

------------------------------------------------------------------------

## Phase 11 --- Database + Audit

### Tasks

Implement: - workflows - vulnerabilities - risk assessments - patch
attempts - validation results - audit events

Add database migrations/schema initialization.

### Exit Criteria

A complete workflow can be reconstructed from persisted records.

------------------------------------------------------------------------

## Phase 12 --- Orchestration

### Tasks

Create shared typed workflow state.

Implement workflow:

``` text
SCAN
 ↓
ASSESS
 ↓
PRIORITIZE
 ↓
GENERATE
 ↓
VALIDATE
 ↓
PASS / RETRY
 ↓
REVIEW
```

Use LangGraph if it provides value; otherwise maintain a clean
orchestration abstraction compatible with later LangGraph adoption.

### Exit Criteria

A single workflow invocation completes end-to-end without manual agent
calls.

------------------------------------------------------------------------

## Phase 13 --- FastAPI

### Tasks

Implement: - workflow endpoints - scan endpoint - vulnerability
endpoints - patch endpoints - approval/rejection endpoints - report
endpoint - health endpoint

Long-running work should execute without blocking normal HTTP requests.

### Exit Criteria

The entire core workflow can be started and inspected through the API.

------------------------------------------------------------------------

## Phase 14 --- Frontend

### Tasks

Create distinctive AutoPatch security dashboard.

Screens: 1. Dashboard 2. Scan Repository 3. Findings 4. Vulnerability
Details 5. Patch Review 6. Validation History 7. Agent Activity 8.
Reports

### Exit Criteria

No fake UI states. Every important button maps to a working backend
operation.

------------------------------------------------------------------------

## Phase 15 --- Human Approval

### Tasks

-   Add review status.
-   Add approve endpoint.
-   Add reject endpoint.
-   Store decision.
-   Create audit event.
-   Prevent approval before successful validation.
-   Prevent automatic merge.

### Exit Criteria

``` text
VALIDATED
    ↓
READY_FOR_REVIEW
    ↓
APPROVE / REJECT
```

------------------------------------------------------------------------

## Phase 16 --- Git/GitHub Integration

### Tasks

-   Accept repository URL.
-   Clone to temporary location.
-   Support branch selection.
-   Generate patch branch/worktree where appropriate.
-   Produce diff.
-   Add optional pull request creation.

### Exit Criteria

A remote repository can enter the same core workflow.

------------------------------------------------------------------------

## Phase 17 --- GitHub Actions

### Tasks

-   Add workflow YAML.
-   Support push.
-   Support pull request.
-   Support manual trigger.
-   Send repository/workflow information to AutoPatch.

### Exit Criteria

A controlled repository event can trigger analysis.

------------------------------------------------------------------------

## Phase 18 --- Testing

### Unit

-   scanner normalization
-   risk scoring
-   repository context
-   LLM schema handling
-   patch parsing
-   validation logic

### Integration

-   scanner → risk
-   risk → patch
-   patch → validation
-   validation → retry

### API

-   workflow creation
-   status retrieval
-   findings
-   patch review
-   approval/rejection
-   reports

### End-to-End

Test:

``` text
Vulnerable Project
 → Scan
 → Risk
 → Patch
 → Validation
 → Re-scan
 → Ready for Review
```

Also test:

``` text
Patch
 → Validation FAIL
 → Feedback
 → Retry
 → Validation PASS
```

------------------------------------------------------------------------

## Phase 19 --- Final Security Review

Check: - no API keys in repository - no unrestricted shell execution
from LLM output - path traversal defenses - subprocess argument
validation - sandbox isolation - timeouts - cleanup - log redaction -
approval gate - retry limit - original repository protection

------------------------------------------------------------------------

## Phase 20 --- Final Demo

Prepare one complete demonstration.

### Demo scenario

Use a small intentionally vulnerable Python repository.

Show:

1.  Repository input.
2.  Scan starts.
3.  Vulnerability appears.
4.  Risk score appears.
5.  Finding becomes prioritized.
6.  Patch is generated.
7.  Patch diff is displayed.
8.  Validation starts.
9.  Tests run.
10. Security re-scan runs.
11. If needed, retry is shown.
12. Successful patch becomes `READY_FOR_REVIEW`.
13. Developer reviews diff and evidence.
14. Developer approves/rejects.
15. Audit history/report is displayed.

## Definition of Done

AutoPatch is considered complete for the project demonstration when the
system provides a real, traceable implementation of:

``` text
SOURCE
  ↓
SCAN
  ↓
ASSESS
  ↓
PRIORITIZE
  ↓
GENERATE
  ↓
VALIDATE
  ↓
RETRY IF FAILED
  ↓
READY FOR REVIEW
  ↓
APPROVE / REJECT
  ↓
REPORT + AUDIT
```

No feature should be represented as complete merely through a mock UI or
hardcoded response.
