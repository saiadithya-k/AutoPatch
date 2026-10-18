# AutoPatch dashboard

React + TypeScript dashboard backed by the AutoPatch API. It uses actual persisted workflows, findings, patch proposals, validation evidence, retry history, audit events and reports.

## Development

Use Node.js 20.19+ or 22+. Start the backend on `http://127.0.0.1:8000`, then:

```powershell
cd frontend
npm ci
npm run dev
```

Open `http://127.0.0.1:5173`. Vite proxies `/api` and `/health` to the backend, so development does not require cross-origin requests. Submit an absolute Python repository path allowed by the backend's repository policy.

Workflow creation returns immediately. Active workflows poll every three seconds; terminal jobs stop polling. Refresh reopens persisted results, and `?workflow=ID` retains the selected run in the URL. Requests time out after 30 seconds; consecutive polling failures stop after three attempts and expose retry controls.

## Build

```powershell
npm run build
```

The build is generated in `dist/`. For separate hosting, set `VITE_API_BASE_URL` to the backend origin before building and allow that frontend origin in backend CORS. `npm run preview` serves the production build locally; it does not proxy API requests, so use the configured backend URL or serve the build behind a reverse proxy.

## Review

Approval and rejection controls require the latest candidate to be `READY_FOR_REVIEW` and have complete successful validation evidence. The backend independently enforces eligibility. Reviewer labels are metadata for this local MVP. Rejection requires a comment. Neither action changes source files. Candidates and structured reports can be downloaded for review.

This dashboard uses modern browser APIs (`AbortSignal.any`, `AbortSignal.timeout`) and React's standard escaped rendering for source code, diff content and logs. It contains no demo data or simulated outcomes.

## Browser regression tests

```powershell
npx playwright install chromium
npm run test:e2e
```

Tests run against the real API, actual scanners/tests and controlled model
responses using isolated databases. They use ports 8765 and 5174 and refuse to
reuse unrelated servers. Python 3.11 and backend requirements must be installed.
On Windows, set `AUTOPATCH_BROWSER_CHANNEL=chrome` to use installed Chrome; set
`AUTOPATCH_PYTHON` when the interpreter is outside the standard project `.venv`.
Coverage includes workflow submission, refresh persistence, review eligibility,
approval/rejection reports, and mobile layout. See
[milestone verification](../docs/MILESTONE_ACCEPTANCE.md) for exact commands and results.
