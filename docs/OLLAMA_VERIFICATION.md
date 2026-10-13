# Live Ollama verification — 2026-10-07

Verified with Python 3.11.9, Ollama 0.34.3, `qwen2.5-coder:7b`, and the configured local OpenAI-compatible endpoint `http://localhost:11434/v1`. No mock model responses were used for this workflow.

Workflow: `wf-7c4b6ca5eac94aa98e5b1efd98056863`.

The API accepted a background run against `.test-artifacts/demo-repository`, a controlled literal-parser fixture with two behavior tests. Bandit and Semgrep each reported its unsafe `eval` call. Ollama generated two independently validated proposals replacing it with `ast.literal_eval`.

| Evidence | Result |
| --- | --- |
| Workflow outcome | `READY_FOR_REVIEW / REVIEWABLE` |
| Generated candidates | 2, both passed on the first attempt in the final run |
| Compilation | Passed for both |
| Project tests | 2 passed for each candidate |
| Bandit and Semgrep re-scans | Both completed for each candidate |
| Target finding | Resolved for each candidate |
| New findings | 0 |
| Original source | Preserved; original `eval` remains on disk |
| Execution mode | Local development workspace |
| Final regression suite | 297 passed; 2 dependency deprecation warnings |

The final live workflow took approximately 23 seconds. Its proposals remain awaiting human review; they were not applied or approved automatically. These are two scanner findings for the same code, with independent proposals rather than a combined patch.

Initial live runs exposed a 30-second cold-start timeout, malformed model-written hunk counts, and dedented source blocks. Fixes added configurable `LLM_TIMEOUT` (default 120 seconds), authoritative diffs computed from structured changes, and indentation restoration only at explicit matching source coordinates. Existing patch safety constraints, test protection, and full validation remain enforced.

The runtime evidence is saved in `.test-artifacts/ollama-live-report.json`, and the workflow is stored in the isolated `.test-artifacts/browser-demo.db`. Open [the live workflow](http://127.0.0.1:5173/?workflow=wf-7c4b6ca5eac94aa98e5b1efd98056863) while the local dashboard and API are running.

This verifies the integration on the fixture above. Real Docker execution remains unverified because Docker is unavailable on this machine.
