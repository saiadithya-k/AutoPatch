# Local workflow API

Run the API from the project directory. Repository access defaults to that directory and its descendants; set `ALLOWED_REPOSITORY_ROOT` to explicitly choose another allowed root. Both `/api/scan` and `/api/workflows` enforce this policy.

Submit `POST /api/workflows` with:

```json
{"repository_path":"D:/projects/AutoPatch/tests/vulnerable_project","max_retries":0,"max_findings":10,"minimum_priority":"LOW"}
```

The response is HTTP 202 with `{id,status,detail_url}`. Retry limits count additional attempts after the initial candidate. Omit `max_retries` to use configuration. Findings below the chosen priority or beyond the finding limit remain in the report as unresolved. Each candidate is checked independently against the submitted repository; proposals are not combined or applied.

Poll `GET /api/workflows/{id}` for `status`, `current_stage`, `processed_findings`, `total_findings`, `reviewable_count`, `failed_count`, `errors`, and `outcome`. Execution finishes at `COMPLETED`, `FAILED`, or `READY_FOR_REVIEW`. A reviewable workflow may have `PARTIAL_SUCCESS`; this means other findings remain unresolved. `NO_FINDINGS` requires complete scanner coverage. Scanner failure or degradation produces `SCAN_INCONCLUSIVE`.

`GET /api/workflows?limit=20&offset=0` and `GET /api/patches?workflow_id=...&limit=20&offset=0` return `{items,total,limit,offset}`. Patch listing also supports `vulnerability_id` and `status`. Existing findings, risk, context, patch-history, validation, retry-history, and audit endpoints remain available. `GET /api/vulnerabilities/{id}` returns the finding and its latest patch reference.

`POST /api/patches/{id}/approve` or `/reject` accepts `{reviewer_label,comment}`. Rejection requires a nonblank comment. Approval requires persisted passing validation, complete scanner coverage, and no regression or new finding. Review waits until an orchestrated workflow finishes. The latest candidate is determined by creation time and ID as a deterministic tie-breaker; stale proposals cannot be decided even when their attempt numbers match. An identical repeated decision returns the existing review; conflicting decisions return 409. Decided proposals cannot be validated or retried again. Reviewer labels are local descriptive metadata and are not authenticated accounts. Approval records a proposal decision and never applies code.

`GET /api/reports/{workflow_id}` returns persisted `{workflow,findings,patches,validations,reviews,audit_events,unresolved_findings,evidence_errors}`. Validation scanner metadata and new findings are decoded JSON objects/lists. `unresolved_findings` contains finding IDs and uses the latest proposal for each finding. Review decisions link the exact patch and validation. Malformed legacy JSON produces safe empty values and explicit `evidence_errors` rather than losing the entire report; malformed approval evidence fails closed with 409.

The local job manager uses `WORKFLOW_WORKERS` workers and at most `WORKFLOW_QUEUE_LIMIT` active/queued jobs. Requests exceeding capacity receive 503. Each job opens its own database session. In-process jobs interrupted by a restart become `FAILED` with `INTERRUPTED` outcome and an audit event; submit a new run to retry. This is a bounded local executor, not a durable distributed queue.

Startup creates the review table and applies idempotent additive SQLite migrations for progress fields and scanner metadata. Existing rows are preserved. Migration errors stop startup. New-table creation and schema migration should precede restart recovery.
