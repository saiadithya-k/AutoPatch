# AutoPatch --- Technical Requirements Document (TRD)

## 1. Technical Architecture

AutoPatch uses a pipeline-style multi-agent architecture.

``` text
Repository Input
      |
      v
Scanning Agent
      |
      v
Risk-Assessment Agent
      |
      v
Patch-Generation Agent
      |
      v
Validation Agent
      |
   +--+--+
   |     |
 PASS   FAIL
   |     |
   v     v
Review  Retry
         |
         +----> Patch Generation
```

The Orchestration Layer manages the complete workflow and shared state.

## 2. Components

### 2.1 Scanning Agent

Responsibilities: - Receive repository/workspace. - Run security
analysis. - Collect Bandit and Semgrep findings. - Optionally perform
custom AST analysis. - Normalize findings into an internal vulnerability
model. - Persist findings.

### 2.2 Risk-Assessment Agent

Responsibilities: - Receive normalized findings. - Inspect relevant
source context. - Evaluate severity, exploitability, context, and
potential impact. - Produce a priority score. - Return an ordered
vulnerability list.

The report permits CVSS-based scoring logic together with LLM reasoning.

### 2.3 Patch-Generation Agent

Responsibilities: - Receive a prioritized vulnerability. - Retrieve
relevant repository context. - Generate a candidate code-level patch. -
Return a structured patch/diff and explanation. - Incorporate validation
feedback on retries.

### 2.4 Validation Agent

Responsibilities: - Create an isolated working copy. - Apply candidate
patch. - Run project tests. - Capture test/build/execution results. -
Re-scan the modified repository. - Determine whether the original
vulnerability remains. - Detect functional regression where possible. -
Return PASS/FAIL with evidence.

### 2.5 Orchestration Layer

Responsibilities: - Start workflows. - Sequence agents. - Maintain
shared state. - Route findings and patches. - Manage retries. - Record
actions. - Coordinate external tools. - Generate final reports.

## 3. Repository Context

The Patch-Generation Agent should receive relevant context rather than
blindly sending an entire repository to the LLM.

Relevant context can include: - vulnerable file - surrounding code -
relevant function/class - imports - related source files -
configuration - dependency information - relevant tests

The project report identifies context retrieval as important because
vulnerabilities can depend on multiple files, dependencies,
configuration, and documentation.

## 4. Tool Boundaries

External tools must be wrapped behind dedicated services.

``` text
tools/
  bandit_runner
  semgrep_runner
  test_runner
  sandbox
```

The application should not scatter direct subprocess execution
throughout the agents.

Tool wrappers should: - validate inputs - execute with controlled
arguments - capture stdout/stderr - enforce timeouts - expose structured
results - handle missing tools - report execution failures

## 5. LLM Integration

Create a provider-independent LLM service.

``` text
LLMProvider
   |
   +-- OpenAI implementation
   +-- Other provider implementation later
```

Requirements: - API keys from environment variables. - No secrets in
source code. - Structured output validation. - Separate prompts for risk
assessment, patch generation, and retry. - Graceful handling of API
errors and malformed responses.

The LLM should assist reasoning and code generation, but validation
remains the safety gate.

## 6. Sandboxed Validation

Generated code can be unsafe.

Preferred implementation: Docker.

Validation should operate against a temporary/isolated workspace rather
than the original repository.

The sandbox should provide, where practical: - temporary workspace -
restricted permissions - controlled network behavior - execution
timeout - captured stdout/stderr - cleanup after execution

Development-only non-sandboxed execution must be clearly distinguished
from safe validation.

## 7. Data Persistence

Initial database: SQLite.

The persistence layer should be abstracted sufficiently to allow
PostgreSQL later.

Two core logical stores are required:

### D1 --- Vulnerability Records

Stores: - vulnerability identity - repository - vulnerability type -
severity - file/location - description - risk information - priority -
status - timestamps

### D2 --- Patch History

Stores: - patch identity - vulnerability ID - attempt number -
patch/diff - files changed - validation status - test results - scan
results - failure reason - final status - timestamps

Audit events should also be retained.

## 8. Backend

FastAPI is the proposed backend.

Required API surface:

``` text
GET  /health

POST /api/workflows
GET  /api/workflows/{workflow_id}

POST /api/scan

GET  /api/vulnerabilities
GET  /api/vulnerabilities/{vulnerability_id}

GET  /api/patches
GET  /api/patches/{patch_id}

POST /api/patches/{patch_id}/approve
POST /api/patches/{patch_id}/reject

GET  /api/reports/{workflow_id}
```

Long-running workflows should not unnecessarily block HTTP requests.

## 9. Frontend

React is the preferred direction in the project report.

Primary views: - Dashboard - Repository/Scan - Vulnerability Findings -
Vulnerability Details - Patch Review - Validation History -
Agent/Workflow Activity - Reports

The Patch Review view must expose enough evidence for human approval: -
vulnerability - severity - risk - code location - diff - explanation -
test results - security re-scan - retry history - approval/rejection
actions

## 10. Git/GitHub

The repository service should support: - local repository input - Git
repository URL - temporary cloning - branch/worktree handling for
patches - patch diff - optional pull-request workflow later

The system must not automatically merge patches.

## 11. CI/CD

GitHub Actions is the proposed CI/CD integration.

Potential triggers: - push - pull request - manual workflow dispatch

The CI/CD layer should trigger security analysis without being required
for local development.

## 12. Security Requirements

The architecture must defend against: - prompt injection - malicious
repository content - command injection - path traversal - arbitrary file
access - unsafe generated code - unauthorized tool invocation - secret
leakage - excessive resource use

LLM output must never directly become an unrestricted shell command.

## 13. Testing Requirements

Required test categories: - unit tests - scanner tests - risk scoring
tests - patch-generation tests - validation tests - retry-loop tests -
API tests - integration tests - end-to-end tests

A controlled vulnerable Python project should be included for repeatable
demonstrations.

## 14. Technical Acceptance Criteria

A build is technically acceptable when: - scanner output is normalized -
risk assessment is reproducible - patches are represented as real
diffs - patches are tested outside the original repository - re-scanning
verifies remediation - validation failures generate retry feedback -
retry count is bounded - audit information persists - human approval is
required after successful validation - APIs expose workflow state and
results
