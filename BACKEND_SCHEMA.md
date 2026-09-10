# AutoPatch --- Backend & Database Schema

## 1. Schema Overview

The backend uses FastAPI and a persistence layer based initially on
SQLite.

Core entities:

``` text
Workflow
   |
   +---- Vulnerability
   |         |
   |         +---- RiskAssessment
   |
   +---- PatchAttempt
   |         |
   |         +---- ValidationResult
   |
   +---- AuditEvent
```

The schema implements the two logical stores described in the project
report:

-   D1: Vulnerability Records
-   D2: Patch History

## 2. Workflow

``` text
workflows
---------
id                TEXT PK
repository_path   TEXT
repository_url    TEXT NULL
branch            TEXT NULL
status            TEXT
current_stage     TEXT NULL
max_retries       INTEGER
created_at        DATETIME
started_at        DATETIME NULL
completed_at      DATETIME NULL
error_message     TEXT NULL
```

Suggested status values:

``` text
CREATED
SCANNING
RISK_ASSESSMENT
PATCH_GENERATION
VALIDATING
RETRYING
READY_FOR_REVIEW
APPROVED
REJECTED
FAILED
CANCELLED
```

## 3. Vulnerability

``` text
vulnerabilities
---------------
id                    TEXT PK
workflow_id           TEXT FK
tool                  TEXT
rule_id               TEXT NULL
type                  TEXT
cwe                   TEXT NULL
severity              TEXT
confidence            TEXT NULL
file_path             TEXT
line_start            INTEGER NULL
line_end              INTEGER NULL
code_snippet          TEXT NULL
description           TEXT
raw_finding           JSON/TEXT NULL
exploitability        REAL NULL
business_impact       REAL NULL
risk_score            REAL NULL
priority              TEXT NULL
risk_reasoning        TEXT NULL
status                TEXT
created_at            DATETIME
updated_at            DATETIME
```

Suggested vulnerability status values:

``` text
DETECTED
ASSESSED
PRIORITIZED
PATCHING
VALIDATED
REMEDIATED
REJECTED
UNRESOLVED
```

## 4. Patch Attempts

``` text
patch_attempts
-------------
id                    TEXT PK
workflow_id           TEXT FK
vulnerability_id      TEXT FK
attempt_number        INTEGER
patch_format          TEXT
patch_content         TEXT
explanation           TEXT NULL
files_changed         JSON/TEXT NULL
generation_model      TEXT NULL
generation_metadata   JSON/TEXT NULL
status                TEXT
created_at             DATETIME
```

Suggested status values:

``` text
GENERATED
VALIDATING
VALIDATED
FAILED_VALIDATION
READY_FOR_REVIEW
APPROVED
REJECTED
```

## 5. Validation Results

``` text
validation_results
------------------
id                         TEXT PK
patch_attempt_id           TEXT FK
status                     TEXT
patch_applied              BOOLEAN
tests_passed               BOOLEAN
tests_run                  INTEGER NULL
test_exit_code             INTEGER NULL
test_stdout                TEXT NULL
test_stderr                TEXT NULL
security_scan_passed       BOOLEAN
original_vulnerability_resolved BOOLEAN
regression_detected        BOOLEAN NULL
failure_reason             TEXT NULL
validation_logs            TEXT NULL
sandbox_type               TEXT NULL
started_at                 DATETIME
completed_at               DATETIME
```

Suggested status:

``` text
RUNNING
PASSED
FAILED
TIMEOUT
ERROR
```

## 6. Risk Assessments

A separate table is useful for traceability even though the latest
values can also be kept on the vulnerability record.

``` text
risk_assessments
----------------
id                    TEXT PK
vulnerability_id      TEXT FK
severity              TEXT
exploitability        REAL
business_impact       REAL
context_score         REAL NULL
risk_score            REAL
priority              TEXT
reasoning             TEXT
model                 TEXT NULL
created_at            DATETIME
```

## 7. Audit Events

``` text
audit_events
------------
id                    TEXT PK
workflow_id           TEXT FK
agent                 TEXT NULL
event_type             TEXT
status                 TEXT NULL
entity_type            TEXT NULL
entity_id              TEXT NULL
message               TEXT NULL
metadata               JSON/TEXT NULL
created_at             DATETIME
```

Example event types:

``` text
WORKFLOW_STARTED
SCAN_STARTED
VULNERABILITY_DETECTED
RISK_ASSESSED
PATCH_GENERATED
VALIDATION_STARTED
TESTS_COMPLETED
SECURITY_RESCAN_COMPLETED
VALIDATION_FAILED
RETRY_STARTED
PATCH_VALIDATED
PATCH_APPROVED
PATCH_REJECTED
WORKFLOW_COMPLETED
WORKFLOW_FAILED
```

## 8. API Schemas

### Create Workflow

`POST /api/workflows`

Request:

``` json
{
  "repository_path": "/path/to/repository",
  "repository_url": null,
  "branch": null,
  "max_retries": 3
}
```

Response:

``` json
{
  "workflow_id": "wf-001",
  "status": "CREATED"
}
```

### Vulnerability Response

``` json
{
  "id": "VULN-001",
  "workflow_id": "wf-001",
  "type": "SQL Injection",
  "severity": "HIGH",
  "file_path": "app/database.py",
  "line_start": 42,
  "line_end": 42,
  "description": "...",
  "risk_score": 8.7,
  "priority": "CRITICAL",
  "status": "PRIORITIZED"
}
```

### Patch Response

``` json
{
  "id": "PATCH-001",
  "vulnerability_id": "VULN-001",
  "attempt_number": 1,
  "patch_content": "...",
  "files_changed": [
    "app/database.py"
  ],
  "status": "READY_FOR_REVIEW"
}
```

### Validation Response

``` json
{
  "id": "VAL-001",
  "patch_attempt_id": "PATCH-001",
  "status": "PASSED",
  "patch_applied": true,
  "tests_passed": true,
  "tests_run": 47,
  "security_scan_passed": true,
  "original_vulnerability_resolved": true,
  "regression_detected": false
}
```

## 9. Relationships

``` text
Workflow 1 ─── N Vulnerabilities
Workflow 1 ─── N PatchAttempts
Workflow 1 ─── N AuditEvents

Vulnerability 1 ─── N RiskAssessments
Vulnerability 1 ─── N PatchAttempts

PatchAttempt 1 ─── N ValidationResults
```

## 10. Indexes

Recommended indexes:

``` text
vulnerabilities(workflow_id)
vulnerabilities(status)
vulnerabilities(priority)
vulnerabilities(risk_score)

patch_attempts(workflow_id)
patch_attempts(vulnerability_id)
patch_attempts(status)

validation_results(patch_attempt_id)

audit_events(workflow_id)
audit_events(entity_type, entity_id)
```

## 11. Data Rules

1.  `attempt_number` must increase for each vulnerability.
2.  A vulnerability cannot become `REMEDIATED` without successful
    validation.
3.  A patch cannot become `APPROVED` without successful validation.
4.  Approval/rejection must create an audit event.
5.  Failed attempts must remain in patch history.
6.  Secrets/API keys must never be stored in these fields.
7.  Original repository content must not be overwritten by validation.
