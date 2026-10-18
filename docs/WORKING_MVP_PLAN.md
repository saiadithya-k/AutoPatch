# AutoPatch working MVP implementation plan

## Objective and scope

Deliver a local application where a developer submits a Python repository, tracks scanning and remediation, inspects a tested candidate diff and its evidence, and approves or rejects the proposal. Preserve the source repository and all attempt history. Approval records a review decision; applying changes, creating pull requests, and merging remain later integrations.

This plan supplements IMPLEMENTATION_PLAN.md with execution priorities based on the initial assessment. The implementation uses Python 3.11, as requested. The original environment works when execution permissions allow it; it was preserved. Runtime, workflow, review, reports, and dashboard changes are implemented. The delivery checks below distinguish verified local behavior from environment gates still outstanding.

## Implementation status (2026-10-07)

- Implemented pinned Python 3.11 setup/readiness, offline scanner rules, sandbox-aware tool execution, complete-coverage validation, source integrity checks, reliable diff generation, and bounded retries.
- Implemented background workflows, persistent lifecycle counts and failures, additive migrations, review decisions, report APIs, and the React dashboard.
- Python 3.11.9 launches the API; Bandit and Semgrep execute successfully. Browser checks verified real vulnerable and clean scans, visible model failures, polling, refresh persistence, and disabled review for failed or superseded candidates. Separate controlled-model runs verified approval and rejection of real validated proposals, persisted reports, retry history, scanner provenance, and required rejection comments. Desktop and mobile layouts were checked. Frontend production build passes.
- Complete Python 3.11.9 suite after live Ollama integration fixes: **297 tests passed** (65.69 seconds), with two dependency deprecation warnings. Dependency consistency and Git whitespace checks pass. Real-tool end-to-end coverage verifies first-attempt test failure, successful retry, persistent idempotent approval, conflicting-decision rejection, audit/report evidence, and unchanged source.
- Ollama is now reachable. A real `qwen2.5-coder:7b` workflow produced two reviewable candidates on the literal-parser fixture; both passed compilation, two project tests, and complete Bandit/Semgrep re-scans. Cold-start timeout, malformed model diff headers, and dedented source blocks were corrected with regression coverage. See [live verification evidence](OLLAMA_VERIFICATION.md).
- Docker was unavailable during the initial verification. Actual Docker acceptance was completed on 2026-10-18; see the milestone below. The controlled demo does not require a model service.

The initial baseline and phase acceptance criteria below are retained for traceability. Initial live Ollama verification covered the documented literal-parser fixture.

## Next milestone verification (2026-10-18)

- Real Docker verification: **12 checks passed on hosted Linux**, including offline/non-root execution, all four reference remediation cases, missing images/dependencies, bad candidates, timeout cleanup, and native Linux workspace ownership/cleanup. The preceding local Docker Desktop run passed 11 checks.
- Browser automation: **5 checks passed**, covering real workflow/review APIs, refresh persistence, superseded attempts, incomplete coverage, and mobile layout.
- Python 3.11 deterministic/API/scanner suite: **324 passed on hosted Ubuntu; 322 passed on hosted Windows**, which skips two Linux-specific permission checks. Docker and live-model gates are explicit separate runs.
- Added GitHub Actions jobs for Windows/Ubuntu Python 3.11, frontend build and browser tests, and real Linux Docker acceptance. All four jobs passed in [hosted run 39095355977](https://github.com/saiadithya-k/AutoPatch/actions/runs/39095355977), after correcting native Linux access to the disposable workspace. The implementation is published on `codex/ollama-acceptance-ci` for review.
- Added four reproducible live-model acceptance cases. Source-bound local-model edits resolved the three initially failing cases: the complete matrix now passes **4 of 4** with real Ollama, both locally and with offline Docker validation. The server supplies exact original source and destinations; model responses select block IDs and replacements. Tests remain read-only, unknown IDs and stale originals fail closed, and retries use original source.
- All original repositories remained unchanged. Incomplete fixes, invalid replacements, repeated candidates and timeouts remain explicit failures; no validation or review gates were weakened.
- See [the milestone report](MILESTONE_ACCEPTANCE.md) for commands, evidence, fixes, and limitations.

## Initial assessment

- Existing: FastAPI routes, scanner normalization, deterministic risk engine, bounded repository context, OpenAI-compatible/Ollama and mock providers, candidate generation, validation, retries, SQLAlchemy persistence, and audit queries.
- Existing endpoints include findings listing and GET /api/workflows/{workflow_id}; extend these rather than register duplicates.
- Missing: one complete workflow invocation, background execution and consistent lifecycle state, review decisions, reports, and frontend.
- Verified gaps: degraded re-scans can pass validation; scanners bypass the Docker executor; ALLOW_LOCAL_FALLBACK is not enforced; the retry-loop override differs from the policy's limit; diff synthesis mishandles shifted replacement coordinates and multiple files; validation retrieval omits failure_category.
- Documentation contains historical phase descriptions, differing test counts, inconsistent application versions, and an incorrect README Docker build path.

## Work allocation

Three implementation subagents and the coordinating agent executed the allocation below. The coordinator handled Python setup, shared contracts, documentation, and integration; Agent A handled scanner/validation reliability, Agent B workflow/review/report persistence, and Agent C the dashboard and browser checks.

| Owner | Primary responsibility | Exclusive file ownership |
| --- | --- | --- |
| Agent A: runtime and validation | Setup, dependencies, scanner execution, sandbox policy, patch correctness, retries | requirements and setup scripts; docker/validation; backend/tools; backend/agents/validation_agent.py, patch_generation_agent.py, retry_agent.py; corresponding tests |
| Agent B: workflow and persistence | Workflow orchestration, background jobs, lifecycle, review/report APIs and schema | backend/orchestrator; backend/models workflow/review/report schemas; backend/services review/report; database files; workflow/review/report routes; corresponding tests |
| Agent C: frontend and experience | React dashboard, API client, workflow and patch review views, user-facing errors | frontend; frontend tests and documentation |
| Coordinator | Shared contracts, review, integration and acceptance | backend/main.py, shared enum changes, README.md, this plan; integrates cross-owner changes |

Agent A carries the initial critical path. Agent B can define contracts and persistence while A restores runtime. Agent C starts the UI skeleton and API client against the agreed contracts, then connects real endpoints. After Agent A finishes reliability work, it owns real-tool end-to-end verification while B and C finish integration. Split Agent B's work into workflow first, then review/report, to keep concurrent load bounded.

Ownership rules: one writer per file; publish proposed shared-schema changes before editing; communicate public interface changes immediately; the coordinator mounts routes and reconciles enums. Keep commits or reviewable changes scoped to work packages. No automated git pushes or deployment are required by this plan.

## Phase 1: restore runtime and establish baseline

**Owner:** Agent A. **Independent parallel work:** B and C prepare contracts and UI structure.

1. Locate a supported Python interpreter and preserve the existing environment before recreating .venv. Preserve .env and autopatch.db.
2. Choose and document one tested Python/dependency combination; pin a reproducible dependency set and align the validation image with it.
3. Add setup and readiness scripts that report Python, scanner, Docker, database, and model-service availability without printing credentials.
4. Verify imports, server startup, /health, and local Ollama model availability. Normalize version reporting with the coordinator.
5. Run deterministic unit tests with mock model responses and an isolated database, then real-scanner integration tests. Record actual results and failures rather than historical counts.
6. Classify deterministic, scanner, Docker, and optional live-model tests with explicit prerequisites. Inspect demo subprocess assumptions across Windows and Linux.

**Acceptance:** a fresh setup can start FastAPI and run the deterministic suite; both scanners distinguish a clean fixture from the vulnerable demo; readiness failures name the unavailable prerequisite.

## Phase 2: make patch validation reliable

**Owner:** Agent A. **Depends on:** Phase 1 for execution, but code changes can begin earlier.

1. Execute compilation, pytest, Bandit, and Semgrep through the selected sandbox interface. Preserve structured results and timeouts for every step.
2. Require complete expected scanner coverage before declaring a vulnerability resolved. Degraded or failed coverage yields an inconclusive/error outcome, never a successful verdict.
3. Bundle versioned local Semgrep rules for network-disabled validation. Capture ruleset provenance so baseline and re-scan use comparable coverage.
4. Enforce ALLOW_LOCAL_FALLBACK. Docker-required execution fails closed. Expose the actual execution mode in evidence.
5. Define a trusted target-dependency preparation mechanism before offline container execution; do not automatically run arbitrary repository install scripts. Report missing dependencies separately from patch regressions.
6. Generate diffs independently per file, verify original blocks and coordinates, reject overlapping or ambiguous replacements, and apply replacements in an order that cannot shift subsequent coordinates.
7. Use one effective retry limit throughout policy and execution, including zero retries. Reject failed/rejected generation outcomes before validation. Preserve every attempt and no-progress decision.
8. Return stored failure_category and lineage fields through retrieval APIs. Make persist=False avoid database mutations. Preserve source integrity checks and workspace cleanup.
9. Add focused regressions for degraded scans, sandbox routing, fallback policy, multiple replacements/files, retry overrides, rejected candidates, and source immutability.

**Acceptance:** a real Docker run performs compilation, tests, and both scanners with networking disabled; valid remediation passes; missing coverage, bad patches, regressions, and unavailable required infrastructure cannot pass; retry limits hold; original source remains unchanged.

## Phase 3: orchestrate complete background workflows

**Owner:** Agent B. **Depends on:** agreed agent interfaces and Phase 2 before reliable end-to-end acceptance.

1. Introduce typed workflow state and explicit transitions. Distinguish scan completion from entire-workflow completion, and distinguish no findings from scanner failure.
2. Implement scan -> assess -> prioritize -> generate -> validate/retry for selected findings. Reuse the existing retry loop, which validates the initial candidate, instead of validating it twice. Start with sequential remediation within a workflow to keep baselines and evidence understandable; each candidate remains independently tested against its recorded source baseline.
3. Isolate failures by finding, continue where appropriate, and persist summary counts and actionable errors. Define workflow results for no findings, reviewable patches, partial success, and total failure.
4. Add POST /api/workflows returning 202 and an ID, GET /api/workflows with pagination, and extend the existing detail route with progress and outcome counts.
5. Use a bounded local background executor with separate database sessions per job. Avoid passing request-scoped sessions into background work. Prevent duplicate starts for the same job.
6. On restart, explicitly mark interrupted in-process jobs rather than leaving them running indefinitely. A durable queue and automatic resumption can follow the local MVP.
7. Persist stage events and provide progress through polling. Define an allowed repository root for the local API and enforce containment consistently.

**Acceptance:** one API request starts the whole workflow promptly; health and read APIs remain responsive; the workflow reaches an honest terminal/remediation state; errors and restarts leave inspectable persisted history.

## Phase 4: implement review decisions and reports

**Owner:** Agent B. **Depends on:** shared lifecycle contracts; may proceed alongside Phase 3 once schema is agreed.

1. Add a persistent review decision linked to an exact patch and successful validation record, with decision time, reviewer label, and optional comment.
2. Persist READY_FOR_REVIEW consistently instead of relying only on an audit message. Require successful validation for approval; do not mark source code REMEDIATED merely because a proposal was approved.
3. Add approve/reject endpoints with validated transitions, repeated-request behavior, and transaction-safe competing-decision handling. Preserve previous evidence.
4. Add vulnerability detail and paginated patch-list APIs, using existing findings/history APIs where suitable.
5. Add GET /api/reports/{workflow_id} with findings, priorities, attempts, validation evidence, retry outcomes, review decisions, and unresolved items. Derive reports from persisted records.
6. Extend lifecycle audit events and use explicit, tested schema migration steps for new persistence fields.

**Acceptance:** unvalidated patches cannot be approved; decisions survive restart and appear in audit/report queries; rejected and approved proposals never modify the submitted repository automatically.

## Phase 5: connect a minimal dashboard

**Owner:** Agent C. **Depends on:** contracts first, working APIs for final integration.

Build a React application with repository submission, workflow progress, findings sorted by risk, finding detail, patch diff, compilation/test/scanner evidence, retry history, audit timeline, report summary, and review controls. Choose a lightweight build setup after checking the available Node runtime.

Use typed API models, a configurable backend URL, bounded polling with cleanup, and explicit loading/empty/error states. Stop polling completed jobs. Disable review controls when validation or review state does not permit the action. Clearly identify inconclusive scans and development execution mode. Product text should explain outcomes without exposing internal implementation details.

Fixtures may support frontend development and tests, but the delivered dashboard must show actual backend results. Configure development CORS for the chosen frontend origin instead of relying on wildcard credentials.

**Acceptance:** submit the demo repository from the browser, follow real progress, inspect the diff and evidence, record a review decision, and reopen its persisted history after refresh.

## Shared API and lifecycle decisions

Freeze these contracts before parallel implementation:

| Endpoint | Behavior |
| --- | --- |
| POST /api/workflows | Start background remediation; return 202 |
| GET /api/workflows | Paginated run summaries |
| GET /api/workflows/{id} | Extend existing route with progress and aggregate outcomes |
| GET /api/vulnerabilities/{id} | Finding detail, risk, and latest candidate reference |
| GET /api/patches | Paginated candidates filtered by workflow, finding, or status |
| POST /api/patches/{id}/approve | Record an eligible candidate's approval |
| POST /api/patches/{id}/reject | Record rejection with a reason |
| GET /api/reports/{workflow_id} | Persisted workflow report as JSON |

Reuse existing context, risk, patch history/detail, validation, retry-history, and audit routes. Use 404 for absent resources, 409 for conflicting/ineligible review transitions, and 422 for invalid input. Reviewer labels in the local MVP are descriptive metadata, not authenticated identities.

- Workflow creation: repository_path, selected findings/priority policy, and bounded retry settings. Return ID, current status, and detail URL.
- Workflow detail: stage, processed/total findings, reviewable/failed counts, timestamps, error summaries, and terminal outcome.
- Patch detail: exact diff, changed files, explanation, status, parent ID, attempt number, latest validation reference, and review reference.
- Validation evidence: status, execution mode, compile/test outputs, scanner coverage/results, resolved/new findings, failure category, and duration.
- Review operation: exact patch ID plus decision metadata; server verifies eligibility against persisted evidence.
- A successful validation is evidence about a candidate. READY_FOR_REVIEW, APPROVED, and REJECTED describe proposal lifecycle; none implies source application.
- Define stable error responses, pagination, timestamp format, and frontend origin once. Existing enums and routes must remain compatible or have a documented migration.

## Phase 6: integration and delivery gate

**Owner:** Coordinator, with Agent A on real tools, B on persistence/API fixes, and C on browser verification.

Run a deterministic full workflow with scripted model responses, including first-attempt failure followed by success. Then run the controlled demo with real scanners and a real Docker sandbox. Perform an optional live Ollama generation smoke test without making external model availability a prerequisite for deterministic CI tests.

Verify: clean repository; complete remediation; partial remediation; scanner degradation; model failure; invalid diff; test failure; unresolved/new vulnerability; zero/default/overridden retry limits; repeated patch; unavailable required Docker; API reads during jobs; competing review decisions; application restart; and original source integrity. Test only relevant paths rather than repeating already-passing suites without new changes.

Update README setup/build/run instructions and API documentation with observed results. Provide one reproducible demo command or script and the dashboard startup command.

**Release gate:** fresh documented setup -> repository submission -> real progress -> tested candidate -> human decision -> persistent report/audit works. Every failure case has an explicit outcome; no automatic source writes or merges occur.

## Execution order and later work

Critical path: environment baseline -> trustworthy validation -> orchestrated workflow -> integrated review/dashboard -> demonstrated release gate.

Run schema/contracts and UI preparation alongside environment work, review/report development alongside orchestration, and frontend integration as endpoints land. Review each milestone before widening scope.

Defer remote cloning, GitHub pull requests, CI/CD triggers, automatic patch application, distributed workers, multi-user authentication, and broader language support until the local MVP is verified. Before exposing the service beyond a local development machine, add authentication/authorization, repository access policy, and deployment-specific isolation and queue durability.
