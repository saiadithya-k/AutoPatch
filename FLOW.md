# AutoPatch --- System Flow Specification

## 1. Master Flow

``` text
                    ┌──────────────────────┐
                    │  Repository / Files  │
                    └──────────┬───────────┘
                               │
                               v
                    ┌──────────────────────┐
                    │   Orchestration      │
                    │       Layer          │
                    └──────────┬───────────┘
                               │
                               v
                    ┌──────────────────────┐
                    │   1. SCAN CODE       │
                    │   Scanning Agent     │
                    │ Bandit + Semgrep     │
                    └──────────┬───────────┘
                               │
                               v
                    ┌──────────────────────┐
                    │ 2. ASSESS RISK       │
                    │ Risk Agent           │
                    │ Severity/Context     │
                    └──────────┬───────────┘
                               │
                         prioritize
                               │
                               v
                    ┌──────────────────────┐
                    │ 3. GENERATE PATCH    │
                    │ Patch Agent + LLM    │
                    └──────────┬───────────┘
                               │
                               v
                    ┌──────────────────────┐
                    │ 4. VALIDATE PATCH    │
                    │ Validation Agent     │
                    │ Sandbox + Tests      │
                    │ + Security Re-scan   │
                    └──────────┬───────────┘
                               │
                       ┌───────┴────────┐
                       │                │
                     PASS              FAIL
                       │                │
                       v                v
             ┌────────────────┐   ┌──────────────┐
             │ READY FOR      │   │ Validation   │
             │ REVIEW         │   │ Feedback     │
             └───────┬────────┘   └──────┬───────┘
                     │                   │
                     v                   │
             ┌────────────────┐          │
             │ Human Review   │          │
             └───────┬────────┘          │
                     │                   │
                ┌────┴────┐             │
                │         │             │
             APPROVE    REJECT          │
                │         │             │
                v         v              │
             Final      Final            │
             Status     Status            │
                                          │
                         retry < max? ----┘
```

## 2. Step-by-Step Flow

### Step 1 --- Source Code Input

The orchestration layer receives a repository through manual input or a
CI/CD event.

### Step 2 --- Vulnerability Scanning

The Scanning Agent runs static analysis and produces normalized
vulnerability findings.

### Step 3 --- Risk Assessment

The Risk-Assessment Agent evaluates severity, exploitability, context,
and potential impact.

### Step 4 --- Prioritization

Findings are ordered by assessed risk. High-priority findings are
selected first for remediation.

### Step 5 --- Patch Generation

The Patch-Generation Agent receives vulnerability and repository context
and generates a candidate patch.

### Step 6 --- Isolated Patch Application

The candidate patch is applied to an isolated copy of the repository.

### Step 7 --- Testing

The Validation Agent runs the existing test suite and captures failures,
errors, and regression evidence.

### Step 8 --- Security Re-scan

The modified copy is scanned again to determine whether the original
vulnerability remains.

### Step 9 --- Validation Decision

PASS when the configured validation gates succeed.

FAIL when: - patch cannot be applied - tests fail - execution/build
fails - regression is detected - original vulnerability remains -
another configured validation gate fails

### Step 10 --- Retry

``` text
FAIL
 ↓
Capture failure evidence
 ↓
Store patch attempt
 ↓
Send feedback to Patch Agent
 ↓
Generate improved patch
 ↓
Validate again
```

The retry count is bounded by configuration.

### Step 11 --- Human Review

Successful validation changes the patch state to `READY_FOR_REVIEW`.

The developer inspects: - finding - risk - patch diff - test evidence -
security re-scan - retry history

The developer chooses `APPROVE` or `REJECT`.

## 3. State Flow

Recommended workflow states:

``` text
CREATED
  ↓
SCANNING
  ↓
RISK_ASSESSMENT
  ↓
PATCH_GENERATION
  ↓
VALIDATING
  ├──→ READY_FOR_REVIEW
  │         ├──→ APPROVED
  │         └──→ REJECTED
  │
  └──→ RETRYING
           ↓
      PATCH_GENERATION
```

Terminal/error states should include:

``` text
FAILED
CANCELLED
```

## 4. Patch Attempt Flow

Each attempt must be independently traceable:

``` text
Attempt N
  ↓
Generated Diff
  ↓
Apply
  ↓
Tests
  ↓
Security Re-scan
  ↓
Validation Result
  ↓
PASS / FAIL
```

If failed:

``` text
Failure Evidence
  +
Previous Patch
  +
Original Vulnerability
  ↓
Next Patch Attempt
```

## 5. Data Flow

The project report defines two key logical data stores:

### D1 --- Vulnerability Records

``` text
Scanning → Vulnerability Records
Risk Assessment → Vulnerability Records
```

### D2 --- Patch History

``` text
Patch Generation → Patch History
Validation → Patch History
Retry → Patch History
```

## 6. Agent Handoff Contracts

``` text
Scanner
  OUTPUT: VulnerabilityFinding[]

Risk Agent
  INPUT: VulnerabilityFinding[]
  OUTPUT: PrioritizedVulnerability[]

Patch Agent
  INPUT: PrioritizedVulnerability + RepositoryContext + ValidationFeedback?
  OUTPUT: CandidatePatch

Validation Agent
  INPUT: CandidatePatch + Repository
  OUTPUT: ValidationResult

Orchestrator
  INPUT: Repository
  OUTPUT: WorkflowResult
```

## 7. Critical Safety Rule

The original repository is never treated as the validation workspace.

Validation should operate on an isolated copy. Successful automated
validation does not equal automatic merge.
